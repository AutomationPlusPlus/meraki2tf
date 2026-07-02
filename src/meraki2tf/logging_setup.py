"""Logging controls with mandatory secret redaction.

Two profiles are exposed: a clean INFO-level console format for normal
and scheduled (cron) runs, and a verbose DEBUG format for diagnosis.
Both attach :class:`SecretRedactionFilter` to the root handler so that
raw ``Authorization`` headers or API token values can never reach the
console or log files, regardless of verbosity.
"""

from __future__ import annotations

import logging
import os
import re
import traceback

from meraki2tf.config import API_KEY_ENV_VAR

_CLEAN_FORMAT = "%(asctime)s %(levelname)s %(message)s"
_VERBOSE_FORMAT = "%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s"
_REDACTED = "[REDACTED]"

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
        message = record.getMessage()
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
        token = os.environ.get(API_KEY_ENV_VAR, "").strip()
        if token:
            redacted = redacted.replace(token, _REDACTED)
        return redacted


def configure_logging(verbose: bool = False) -> None:
    """Install the console handler for this process.

    ``verbose`` widens the level to DEBUG and the format to include
    logger origin; redaction is applied unconditionally.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(_VERBOSE_FORMAT if verbose else _CLEAN_FORMAT)
    )
    handler.addFilter(SecretRedactionFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
