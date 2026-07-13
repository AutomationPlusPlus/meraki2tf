"""STARTTLS verification tests for the email notifier.

An unverified STARTTLS handshake (smtplib's fallback when no context
is passed) accepts any certificate, so an active MITM defeats it
trivially. The notifier must hand ``starttls()`` a verified default
context: certificate chain validated against the system trust store
AND hostname checked.
"""

from __future__ import annotations

import ssl
from typing import Any

from meraki2tf.alerts.email import EmailNotifier
from meraki2tf.alerts.models import AlertEvent, EventSeverity, EventType


def _event() -> AlertEvent:
    return AlertEvent(
        event_type=EventType.RUN_SUCCESS,
        severity=EventSeverity.INFO,
        summary="clean run",
    )


class RecordingSmtp:
    """Minimal smtplib.SMTP stand-in that records starttls arguments."""

    last_instance: "RecordingSmtp | None" = None

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.starttls_calls: list[dict[str, Any]] = []
        self.ehlo_count = 0
        RecordingSmtp.last_instance = self

    def __enter__(self) -> "RecordingSmtp":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def ehlo(self) -> None:
        self.ehlo_count += 1

    def has_extn(self, name: str) -> bool:
        return name == "starttls"

    def starttls(self, *, context: ssl.SSLContext | None = None) -> None:
        self.starttls_calls.append({"context": context})

    def send_message(self, message: Any) -> dict[str, Any]:
        return {}


def _notifier() -> EmailNotifier:
    return EmailNotifier(
        host="smtp.contoso.example",
        port=587,
        sender="meraki2tf@contoso.example",
        recipients=["netops@contoso.example"],
        smtp_factory=RecordingSmtp,  # type: ignore[arg-type]
    )


def test_starttls_receives_a_verified_default_context() -> None:
    _notifier().send(_event())
    smtp = RecordingSmtp.last_instance
    assert smtp is not None
    assert len(smtp.starttls_calls) == 1
    context = smtp.starttls_calls[0]["context"]
    assert isinstance(context, ssl.SSLContext)
    # The point of the fix: certificate AND hostname validation. An
    # unverified context (CERT_NONE / no hostname check) only defends
    # against passive sniffing, not an active MITM.
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_ehlo_is_reissued_after_the_tls_handshake() -> None:
    """RFC 3207: the pre-TLS EHLO response must be discarded; a second
    EHLO after starttls() refreshes the extension list."""
    _notifier().send(_event())
    smtp = RecordingSmtp.last_instance
    assert smtp is not None
    assert smtp.ehlo_count == 2
