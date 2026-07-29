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

#: Events API v2 rejects any event body past 512 KB outright. A drift
#: event carries the whole speculative plan, which passes that on its
#: own for even a small organization — so an unbudgeted ``custom_details``
#: means the DRIFT_DETECTED page never fires, the one alert the DR
#: mission most depends on. The details are trimmed to fit instead: an
#: excerpt plus the workdir pointer pages someone, where a rejected
#: event pages nobody.
_BODY_BYTE_LIMIT = 512_000

#: Headroom under the hard limit for the envelope (routing key, summary,
#: severity) and for the truncation marker appended to the details.
_BODY_SAFETY_MARGIN = 8_192

#: Keys whose value is a locator or a count rather than bulk text. They
#: are what an on-call responder acts on, so they survive trimming even
#: when the bulky diff/list fields do not.
_ESSENTIAL_DETAIL_KEYS = frozenset(
    {
        "organization_id",
        "origin",
        "workspace",
        "apply_aborted",
        "unsupported_count",
        "stage",
        "error",
        "action",
    }
)

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


def _encoded_size(value: Any) -> int:
    """Byte length of ``value`` as the notifier would serialize it."""
    return len(json.dumps(value, default=str).encode("utf-8"))


def _shrink(value: Any, budget: int) -> tuple[Any, str] | None:
    """``value`` reduced to roughly ``budget`` bytes, plus a note.

    Returns ``None`` when the value is already small enough to be worth
    keeping whole. Strings keep a leading excerpt (a plan diff's first
    lines carry the actionable resource names); sequences keep a leading
    slice of their elements; anything else is dropped to a placeholder.
    """
    if _encoded_size(value) <= budget:
        return None
    if isinstance(value, str):
        keep = max(budget - 64, 0)
        return value[:keep], f"{len(value) - keep} more characters"
    if isinstance(value, (list, tuple)):
        kept = list(value)
        while kept and _encoded_size(kept) > budget:
            kept = kept[: len(kept) // 2]
        return kept, f"{len(value) - len(kept)} more item(s)"
    return "<omitted: too large for PagerDuty delivery>", "value omitted"


def _budgeted_details(details: dict[str, Any], budget: int) -> dict[str, Any]:
    """``details`` trimmed so its JSON encoding fits ``budget`` bytes.

    Bulk fields (the plan diff, the unsupported list) are shrunk largest
    first until the payload fits, and every cut is recorded under
    ``truncated_for_delivery`` so the responder knows the excerpt is an
    excerpt and where the full copy lives.
    """
    total = _encoded_size(details)
    if total <= budget:
        return details
    trimmed = dict(details)
    sizes = {key: _encoded_size(value) for key, value in details.items()}
    omissions: dict[str, str] = {}
    # Largest first: one oversized field is what blows the budget, not
    # the dozens of small locators an on-call responder actually reads.
    # The running total is adjusted per field rather than re-encoding the
    # whole mapping each pass, so a details dict with many thousands of
    # keys stays linear.
    for key in sorted(sizes, key=lambda k: sizes[k], reverse=True):
        if total <= budget:
            break
        if key in _ESSENTIAL_DETAIL_KEYS:
            continue
        result = _shrink(trimmed[key], max(budget // 4, 1024))
        if result is None:
            continue
        trimmed[key], omissions[key] = result
        shrunk_size = _encoded_size(trimmed[key])
        total += shrunk_size - sizes[key]
        sizes[key] = shrunk_size
    if omissions:
        trimmed["truncated_for_delivery"] = {
            "omitted": omissions,
            "note": (
                "Trimmed to fit PagerDuty's 512 KB event limit; the full "
                "payload is in the run log and the workdir artifacts."
            ),
        }
    # Last resort: thousands of small keys can still overflow, and a
    # rejected event is worse than a lossy one.
    if _encoded_size(trimmed) > budget:
        essential = {
            key: value
            for key, value in trimmed.items()
            if key in _ESSENTIAL_DETAIL_KEYS
        }
        essential["truncated_for_delivery"] = {
            "omitted": {"details": f"{len(trimmed)} field(s)"},
            "note": (
                "Details exceeded PagerDuty's 512 KB event limit even "
                "after trimming; see the run log and workdir artifacts."
            ),
        }
        return essential
    return trimmed


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
        """Trigger a PagerDuty Events API v2 incident for the event.

        Maps the event's :class:`EventSeverity` onto PagerDuty's severity
        vocabulary and posts a ``trigger`` action keyed by a routing key
        read from the environment at send time. The details are budgeted
        down to the Events API's 512 KB body limit first (see
        :func:`_budgeted_details`) so a large drift diff cannot cost the
        incident entirely. Raises
        :class:`PagerDutyDeliveryError` when the request fails or the API
        answers HTTP >= 300; the routing key is scrubbed from any error
        text and the exception chain dropped so it cannot leak into a
        log or traceback.
        """
        key = _read_routing_key()
        summary = f"[meraki2tf] {event.event_type.value}: {event.summary}"
        details = _budgeted_details(
            event.details, _BODY_BYTE_LIMIT - _BODY_SAFETY_MARGIN
        )
        body = json.dumps(
            {
                "routing_key": key,
                "event_action": "trigger",
                "payload": {
                    "summary": summary[:_SUMMARY_CHAR_LIMIT],
                    "source": "meraki2tf",
                    "severity": _PD_SEVERITY[event.severity],
                    "custom_details": details,
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
