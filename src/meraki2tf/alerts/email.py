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

SmtpFactory = Callable[[str, int], smtplib.SMTP]


class EmailNotifier(Notifier):
    """Sends each event as a plaintext JSON report over SMTP.

    ``smtp_factory`` is injectable so tests (and future TLS/relay
    variants) can substitute the transport without touching sockets.
    """

    channel = "email"

    def __init__(
        self,
        host: str,
        port: int,
        sender: str,
        recipients: Sequence[str],
        smtp_factory: SmtpFactory = smtplib.SMTP,
    ) -> None:
        self._host = host
        self._port = port
        self._sender = sender
        self._recipients = list(recipients)
        self._smtp_factory = smtp_factory

    def build_message(self, event: AlertEvent) -> EmailMessage:
        message = EmailMessage()
        message["Subject"] = f"[meraki2tf] {event.event_type.value}: {event.summary}"
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message.set_content(json.dumps(event.to_payload(), indent=2))
        return message

    def send(self, event: AlertEvent) -> None:
        message = self.build_message(event)
        with self._smtp_factory(self._host, self._port) as smtp:
            smtp.send_message(message)
        logger.debug(
            "Email dispatched for event %s to %d recipient(s).",
            event.event_type.value,
            len(self._recipients),
        )
