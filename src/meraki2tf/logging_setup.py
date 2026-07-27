"""Logging controls with mandatory secret redaction.

Two profiles are exposed: a clean INFO-level console format for normal
and scheduled (cron) runs, and a verbose DEBUG format for diagnosis.
An alternative ``json`` output format emits one JSON object per line
for log aggregators (Splunk, ELK, Cloud Logging). Every combination
attaches :class:`SecretRedactionFilter` to the root handler so that
raw ``Authorization`` headers or API token values can never reach the
console or log files, regardless of verbosity or format.
"""

from __future__ import annotations

import json
import logging
import os
import re
import traceback

from meraki2tf.config import API_KEY_ENV_VAR

_CLEAN_FORMAT = "%(asctime)s %(levelname)s %(message)s"
_VERBOSE_FORMAT = "%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s"
_REDACTED = "[REDACTED]"

#: Control characters that let Meraki-controlled free text (network
#: names, notes, tags) forge whole log records or drive the terminal: a
#: ``\n``/``\r`` starts a byte-perfect fake line, ``\x1b`` opens an ANSI
#: escape (screen-clear, colour). Every C0 control (incl. TAB), DEL, and
#: the C1 range are neutralized. Printable text and normal Unicode are
#: untouched.
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CONTROL_CHAR_NAMES = {"\n": "\\n", "\r": "\\r", "\t": "\\t", "\x1b": "\\x1b"}


def sanitize_control_chars(text: str) -> str:
    """Render control characters as their visible ``\\x`` escapes.

    ``\\n``, ``\\r``, ``\\t`` and ``\\x1b`` (ESC) become their familiar
    two-/four-character escapes; every other C0/C1 control and DEL
    becomes ``\\xNN``. The result contains no control characters, so it
    cannot forge a log line or emit a terminal escape sequence. The
    transformation is idempotent — its own output (plain backslashes and
    hex digits) contains nothing left to escape — so applying it after
    JSON encoding, or twice, stays consistent.
    """

    def _replace(match: re.Match[str]) -> str:
        char = match.group(0)
        return _CONTROL_CHAR_NAMES.get(char, f"\\x{ord(char):02x}")

    return _CONTROL_CHAR_RE.sub(_replace, text)


class ControlCharFilter(logging.Filter):
    """Neutralize control characters in every record before emission.

    Installed centrally in :func:`configure_logging` alongside
    :class:`SecretRedactionFilter` so no call site that logs raw tenant
    text (network names in critical scope/heal messages, ``str(exc)``
    from the SDK) can forge log records or inject ANSI escapes. In JSON
    format the escapes stay valid JSON (backslash/hex only) and
    ``json.dumps`` never sees a raw control character; in text format
    each record stays a single line.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            # Mirror SecretRedactionFilter: a malformed %-arg call must
            # degrade rather than crash the caller (filters are not
            # wrapped by Handler.handleError). Clear args so a later
            # formatter cannot re-raise on the same broken template.
            record.msg = sanitize_control_chars(str(record.msg))
            record.args = None
        else:
            neutralized = sanitize_control_chars(message)
            # Only rewrite when something actually changed, so benign
            # records keep their ``msg``/``args`` untouched (log records
            # are shared with other handlers, e.g. pytest's caplog).
            if neutralized != message:
                record.msg = neutralized
                record.args = None
        if record.exc_text:
            neutralized_exc = sanitize_control_chars(record.exc_text)
            if neutralized_exc != record.exc_text:
                record.exc_text = neutralized_exc
        return True


# Matches Authorization / X-Cisco-Meraki-API-Key header values however they
# were interpolated into a message (e.g. by HTTP debug logging). Quoted
# values are consumed wholly, and unquoted scheme-prefixed values
# ("Bearer xyz", "Token xyz") include the credential after the scheme,
# so multi-word tokens never leak.
_HEADER_PATTERN = re.compile(
    r"(?i)((?:authorization|x-cisco-meraki-api-key)['\"]?\s*[:=]\s*)"
    r"('[^']*'|\"[^\"]*\"|(?:bearer\s+|token\s+)?[^,'\"\s]+)",
)


class SecretRedactionFilter(logging.Filter):
    """Strip credential material from every record before it is emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            # A malformed log call (mismatched %-args) raises here —
            # and logging does NOT catch exceptions from filters, so it
            # would crash the caller instead of landing in
            # Handler.handleError like every other formatting fault.
            # Degrade to the unformatted template (still redacted).
            message = str(record.msg)
            record.args = None
        redacted = self._redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = None
        # Exception tracebacks (logger.exception) are rendered separately
        # by the Formatter; pre-render and scrub them so a secret-bearing
        # exception message (e.g. a webhook URL in a chained error) can
        # never bypass redaction.
        if record.exc_text:
            record.exc_text = self._redact(record.exc_text)
        elif record.exc_info and record.exc_info[1] is not None:
            record.exc_text = self._redact(
                "".join(traceback.format_exception(*record.exc_info)).rstrip("\n")
            )
        return True

    @staticmethod
    def _redact(text: str) -> str:
        redacted = _HEADER_PATTERN.sub(rf"\g<1>{_REDACTED}", text)
        # Both credential variables: the dashboard key and the provider
        # convention's MERAKI_API_KEY, which an operator may set to a
        # *different* token (the runner respects it and never overrides).
        for env_var in (API_KEY_ENV_VAR, "MERAKI_API_KEY"):
            token = os.environ.get(env_var, "").strip()
            if token:
                redacted = redacted.replace(token, _REDACTED)
        return redacted


#: Accepted values for the console log output format.
LOG_FORMATS = ("text", "json")


class JsonLineFormatter(logging.Formatter):
    """One JSON object per line — machine-parseable structured logs.

    Runs downstream of :class:`SecretRedactionFilter` (redaction
    happens on the record before any formatter sees it), so the JSON
    stream carries the same guarantees as the text stream. Exception
    text arrives pre-rendered in ``exc_text`` because the filter scrubs
    it there; it is carried as a plain field, never re-rendered.
    """

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_text:
            entry["exception"] = record.exc_text
        return json.dumps(entry, default=str)


def configure_logging(verbose: bool = False, log_format: str = "text") -> None:
    """Install the console handler for this process.

    ``verbose`` widens the level to DEBUG and (in text format) the
    layout to include logger origin; ``log_format`` selects the plain
    console layout or one-JSON-object-per-line output. Redaction is
    applied unconditionally in every combination.
    """
    handler = logging.StreamHandler()
    if log_format == "json":
        handler.setFormatter(JsonLineFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(_VERBOSE_FORMAT if verbose else _CLEAN_FORMAT)
        )
    handler.addFilter(SecretRedactionFilter())
    # Runs after redaction so tenant-controlled free text can neither
    # forge a log line nor drive the terminal, in every format.
    handler.addFilter(ControlCharFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
