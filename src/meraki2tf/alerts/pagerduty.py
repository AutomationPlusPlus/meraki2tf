"""PagerDuty notifier: Events API v2 incidents for problem events.

Paging semantics differ from the fan-out channels: a clean-run
notification must not open an incident at 3 AM. The notifier therefore
handles only WARNING and CRITICAL events (drift, unsupported coverage
gaps, deletions awaiting confirmation, processing faults, failed DR
actions); INFO events (RUN_SUCCESS, successful DR confirmations) are
declared unhandled so the dispatcher routes them to the other channels
without counting PagerDuty as an outage.

The routing key is a credential: it is read from the
``MERAKI2TF_PAGERDUTY_ROUTING_KEY`` environment variable at send time,
held only on the stack, and scrubbed from any exception text.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from typing import Any

from meraki2tf.alerts.base import Notifier
from meraki2tf.alerts.models import AlertEvent, EventSeverity

logger = logging.getLogger(__name__)

ROUTING_KEY_ENV_VAR = "MERAKI2TF_PAGERDUTY_ROUTING_KEY"

_EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"
_DEFAULT_TIMEOUT_SECONDS = 10.0

#: Events API v2 caps ``payload.summary`` at 1024 characters.
_SUMMARY_CHAR_LIMIT = 1024

#: meraki2tf severities → Events API v2 severities (which lack a
#: dedicated "info"; INFO events never reach send() anyway).
_PD_SEVERITY = {
    EventSeverity.WARNING: "warning",
    EventSeverity.CRITICAL: "critical",
    EventSeverity.INFO: "info",
}


class PagerDutyConfigError(ValueError):
    """The PagerDuty channel is enabled but unusable."""


class PagerDutyDeliveryError(RuntimeError):
    """The Events API refused or failed to accept the event."""


def routing_key_present() -> bool:
    """Whether the routing key is available in the environment."""
    return bool(os.environ.get(ROUTING_KEY_ENV_VAR, "").strip())


def _read_routing_key() -> str:
    key = os.environ.get(ROUTING_KEY_ENV_VAR, "").strip()
    if not key:
        raise PagerDutyConfigError(
            f"PagerDuty alerting requires the {ROUTING_KEY_ENV_VAR} "
            "environment variable (an Events API v2 routing key)."
        )
    return key


def _open(request: urllib.request.Request, timeout: float) -> Any:
    """Module seam over urlopen (tests patch this; the URL is fixed
    to the https Events API endpoint, so no scheme validation rides
    on the caller)."""
    return urllib.request.urlopen(request, timeout=timeout)


class PagerDutyNotifier(Notifier):
    """Triggers a PagerDuty incident per WARNING/CRITICAL event."""

    channel = "pagerduty"

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT_SECONDS) -> None:
        self._timeout = timeout

    def handles(self, event: AlertEvent) -> bool:
        return event.severity is not EventSeverity.INFO

    def send(self, event: AlertEvent) -> None:
        key = _read_routing_key()
        summary = f"[meraki2tf] {event.event_type.value}: {event.summary}"
        body = json.dumps(
            {
                "routing_key": key,
                "event_action": "trigger",
                "payload": {
                    "summary": summary[:_SUMMARY_CHAR_LIMIT],
                    "source": "meraki2tf",
                    "severity": _PD_SEVERITY[event.severity],
                    "custom_details": event.details,
                },
            },
            default=str,
        ).encode("utf-8")
        request = urllib.request.Request(
            _EVENTS_API_URL,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _open(request, self._timeout) as response:
                status = int(getattr(response, "status", 202))
        except Exception as exc:
            # Exception text could echo request internals; scrub the
            # routing key and drop the chain so the dispatcher's
            # traceback logging cannot leak it either.
            detail = str(exc).replace(key, "<routing-key>")
            raise PagerDutyDeliveryError(
                f"PagerDuty delivery failed ({type(exc).__name__}): {detail}"
            ) from None
        if status >= 300:
            raise PagerDutyDeliveryError(
                f"PagerDuty Events API answered HTTP {status}."
            )
        logger.debug(
            "PagerDuty incident triggered for event %s (HTTP %d).",
            event.event_type.value,
            status,
        )
