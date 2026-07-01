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

from meraki2tf.config import API_KEY_ENV_VAR

_CLEAN_FORMAT = "%(asctime)s %(levelname)s %(message)s"
_VERBOSE_FORMAT = "%(asctime)s %(levelname)s [%(name)s:%(lineno)d] %(message)s"
_REDACTED = "[REDACTED]"

# Matches Authorization / X-Cisco-Meraki-API-Key header values however they
# were interpolated into a message (e.g. by HTTP debug logging). Quoted
# values are consumed wholly so multi-word tokens ("Bearer xyz") never leak.
_HEADER_PATTERN = re.compile(
    r"(?i)((?:authorization|x-cisco-meraki-api-key)['\"]?\s*[:=]\s*)"
    r"('[^']*'|\"[^\"]*\"|[^,'\"\s]+)",
)


class SecretRedactionFilter(logging.Filter):
    """Strip credential material from every record before it is emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = _HEADER_PATTERN.sub(rf"\g<1>{_REDACTED}", message)
        token = os.environ.get(API_KEY_ENV_VAR, "").strip()
        if token:
            redacted = redacted.replace(token, _REDACTED)
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True


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
