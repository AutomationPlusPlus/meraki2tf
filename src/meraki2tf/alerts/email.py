"""Email notifier: standard-library smtplib delivery of JSON payloads."""

from __future__ import annotations

import json
import logging
import os
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

#: SMTP AUTH credentials for authenticated relays — environment-only,
#: like every other credential (never flags, never config-file keys).
SMTP_USERNAME_ENV_VAR = "MERAKI2TF_SMTP_USERNAME"
SMTP_PASSWORD_ENV_VAR = "MERAKI2TF_SMTP_PASSWORD"


class EmailConfigError(ValueError):
    """The email channel's environment configuration is unusable."""


def _read_smtp_credentials() -> tuple[str, str] | None:
    """The AUTH credential pair from the environment, or None.

    Read at send time and held only on the stack — the notifier object
    never stores a credential. Half a pair is a configuration mistake
    that must fail loudly, not silently skip authentication.
    """
    username = os.environ.get(SMTP_USERNAME_ENV_VAR, "").strip()
    password = os.environ.get(SMTP_PASSWORD_ENV_VAR, "")
    if not username and not password:
        return None
    if not username or not password:
        raise EmailConfigError(
            f"SMTP AUTH needs both {SMTP_USERNAME_ENV_VAR} and "
            f"{SMTP_PASSWORD_ENV_VAR} set; exactly one of them is present."
        )
    return username, password


def validate_smtp_credentials() -> None:
    """Fail fast on a half-set AUTH pair before any work starts.

    Send time still re-reads the environment (`_read_smtp_credentials`),
    but a misconfiguration that is knowable at startup must not surface
    only after a full discovery sweep, as a delivery failure.
    """
    _read_smtp_credentials()


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
        """Email the event to the configured recipients over SMTP.

        Alert bodies carry the full resource inventory and drift diffs,
        so the hop opportunistically upgrades to STARTTLS with a verified
        context when the relay advertises it; a relay that advertises
        STARTTLS but then fails to negotiate fails the send rather than
        falling back to plaintext, closing the active-MITM downgrade. SMTP
        credentials are read from the environment at send time and never
        held. Raises the SMTP client's errors when connection,
        authentication, or delivery fails.
        """
        message = self.build_message(event)
        credentials = _read_smtp_credentials()
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
            tls_established = False
            if smtp.has_extn("starttls"):
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
                tls_established = True
            if credentials is not None:
                # AUTH only ever inside the verified TLS session: over a
                # cleartext hop the credential would cross the network
                # readable, and an active MITM that suppressed STARTTLS
                # would harvest it. Fail the send instead.
                if not tls_established:
                    raise EmailConfigError(
                        "SMTP AUTH credentials are configured but the "
                        f"relay {self._host} never advertised STARTTLS; "
                        "refusing to authenticate over cleartext."
                    )
                smtp.login(*credentials)
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
