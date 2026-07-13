"""Email notifier: standard-library smtplib delivery of JSON payloads."""

from __future__ import annotations

import json
import logging
import smtplib
from collections.abc import Callable, Sequence
from email.message import EmailMessage

from meraki2tf.alerts.base import Notifier
from meraki2tf.alerts.models import AlertEvent

logger = logging.getLogger(__name__)

#: Ceiling on connect/delivery so a black-holed relay cannot wedge a
#: scheduled run inside the alert dispatcher.
DEFAULT_SMTP_TIMEOUT = 30.0

SmtpFactory = Callable[[str, int, float], smtplib.SMTP]


def _default_smtp_factory(host: str, port: int, timeout: float) -> smtplib.SMTP:
    return smtplib.SMTP(host, port, timeout=timeout)


class EmailNotifier(Notifier):
    """Sends each event as a plaintext JSON report over SMTP.

    ``smtp_factory`` is injectable so tests (and future TLS/relay
    variants) can substitute the transport without touching sockets.

    Partial recipient refusals (``smtplib`` raises only when *every*
    recipient is refused) still count as delivered — at least one
    recipient got the alert — but the refused addresses are logged at
    ERROR so a silently dropped on-call recipient is visible in the
    run log.
    """

    channel = "email"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: Sequence[str],
        smtp_factory: SmtpFactory = _default_smtp_factory,
        timeout: float = DEFAULT_SMTP_TIMEOUT,
    ) -> None:
        self._host = host
        self._port = port
        self._sender = sender
        self._recipients = list(recipients)
        self._smtp_factory = smtp_factory
        self._timeout = timeout

    def build_message(self, event: AlertEvent) -> EmailMessage:
        message = EmailMessage()
        # Summaries embed externally sourced strings (spec-derived
        # api_path, dump/CLI org IDs); a stray CR/LF would make
        # EmailMessage raise and drop the whole alert (and, on a laxer
        # library, enable header injection). Collapse whitespace so the
        # Subject is always a single safe line.
        summary = " ".join(event.summary.split())
        message["Subject"] = f"[meraki2tf] {event.event_type.value}: {summary}"
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message.set_content(json.dumps(event.to_payload(), indent=2))
        return message

    def send(self, event: AlertEvent) -> None:
        message = self.build_message(event)
        with self._smtp_factory(self._host, self._port, self._timeout) as smtp:
            # Opportunistic STARTTLS: alert bodies carry the full
            # resource inventory and drift diffs, so encrypt the hop
            # whenever the relay advertises it. Relays that don't are
            # left as plaintext (the contract designates email a
            # placeholder) rather than failing the alert.
            try:
                if smtp.has_extn("starttls"):
                    smtp.starttls()
                    smtp.ehlo()
            except (smtplib.SMTPException, OSError) as exc:
                logger.warning(
                    "STARTTLS negotiation failed for event %s; sending over "
                    "an unencrypted connection: %s", event.event_type.value, exc,
                )
            refused = smtp.send_message(message)
        if refused:
            logger.error(
                "SMTP relay refused %d of %d recipient(s) for event %s: %s "
                "— the alert did NOT reach them.",
                len(refused),
                len(self._recipients),
                event.event_type.value,
                ", ".join(sorted(refused)),
            )
        logger.debug(
            "Email dispatched for event %s to %d recipient(s).",
            event.event_type.value,
            len(self._recipients),
        )
