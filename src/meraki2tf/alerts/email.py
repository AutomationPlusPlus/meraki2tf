"""Email notifier: standard-library smtplib delivery of JSON payloads."""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
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
            # Opportunistic STARTTLS with a VERIFIED context: alert
            # bodies carry the full resource inventory and drift diffs,
            # so when the relay advertises STARTTLS the hop is encrypted
            # with certificate and hostname validation (the ssl-module
            # default context). Without verification an active MITM can
            # present any certificate, so an unverified handshake would
            # protect against passive sniffing only. Note the honest
            # limits: relays that never advertise STARTTLS still get
            # plaintext (the contract designates email a placeholder),
            # and relays whose certificate fails validation (e.g.
            # self-signed internal relays) fail the handshake and the
            # delivery with it. Once STARTTLS is advertised, a failed
            # negotiation must fail the send: an active MITM can answer
            # the STARTTLS command with a 454 while keeping the
            # plaintext session usable, so "warn and send anyway" would
            # hand the full drift diff to exactly the attacker TLS is
            # for. The dispatcher logs the failure and isolates the
            # channel.
            #
            # EHLO first: has_extn() reads esmtp_features, which is
            # only populated by ehlo() — connect() does not send it,
            # so without this has_extn("starttls") is always False
            # and the hop is never encrypted.
            smtp.ehlo()
            if smtp.has_extn("starttls"):
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
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
