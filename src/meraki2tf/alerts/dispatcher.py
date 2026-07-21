"""Fan-out dispatcher decoupling the pipeline from delivery channels."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from meraki2tf.alerts.base import Notifier
from meraki2tf.alerts.models import AlertEvent

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """Delivers each event to every registered channel with failure isolation."""

    def __init__(self, notifiers: Iterable[Notifier] = ()) -> None:
        self._notifiers: list[Notifier] = list(notifiers)
        self._failed_events = 0
        #: Stamped into every dispatched event's details so alert
        #: consumers can attribute the event to an organization — vital
        #: when a multi-org fan-out interleaves several organizations'
        #: alerts on one channel. The CLI sets it per organization as
        #: soon as the ID is known (flag value or snapshot resolution).
        self.organization_id: str | None = None

    def register(self, notifier: Notifier) -> None:
        self._notifiers.append(notifier)

    @property
    def channel_count(self) -> int:
        """Number of registered delivery channels."""
        return len(self._notifiers)

    @property
    def failed_event_count(self) -> int:
        """Events that reached no configured channel (total delivery
        failure). Zero channels is a deliberate setup, not a failure —
        the counter only moves when configured channels all refuse an
        event, so callers can turn a silent notifier outage into a
        nonzero exit code."""
        return self._failed_events

    def dispatch(self, event: AlertEvent) -> int:
        """Send ``event`` to every channel that handles it; returns the
        count delivered.

        A failing channel is logged and skipped so one broken endpoint
        never suppresses drift or success alerts on the others. When
        every *handling* channel fails, an ERROR makes the total
        delivery failure unmissable in the run log — a drift alert that
        reached nobody must never look like a delivered one. Channels
        that decline the event by design (a paging channel skipping
        RUN_SUCCESS) are not failures; an event no configured channel
        wants is logged so a paging-only setup knows routine events
        reach the run log alone.
        """
        if self.organization_id is not None:
            # setdefault: events that already carry their own value
            # (the DR actions name their org explicitly) win.
            event.details.setdefault("organization_id", self.organization_id)
        handlers = [
            notifier for notifier in self._notifiers
            if notifier.handles(event)
        ]
        if self._notifiers and not handlers:
            logger.info(
                "No configured alert channel handles event %s (paging-only "
                "channels decline routine events); it reaches the run log "
                "only.",
                event.event_type.value,
            )
            return 0
        delivered = 0
        for notifier in handlers:
            try:
                notifier.send(event)
                delivered += 1
            except Exception:
                logger.exception(
                    "Alert delivery failed on channel %r for event %s",
                    notifier.channel,
                    event.event_type.value,
                )
        if handlers and not delivered:
            self._failed_events += 1
            logger.error(
                "Alert delivery failed on ALL %d configured channel(s) for "
                "event %s — nobody was notified. Check the notifier "
                "endpoints/configuration.",
                len(handlers),
                event.event_type.value,
            )
        return delivered
