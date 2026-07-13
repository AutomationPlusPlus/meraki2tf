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

    def register(self, notifier: Notifier) -> None:
        self._notifiers.append(notifier)

    def dispatch(self, event: AlertEvent) -> int:
        """Send ``event`` to all channels; returns the count delivered.

        A failing channel is logged and skipped so one broken endpoint
        never suppresses drift or success alerts on the others. When
        every configured channel fails, an ERROR makes the total
        delivery failure unmissable in the run log — a drift alert that
        reached nobody must never look like a delivered one.
        """
        delivered = 0
        for notifier in self._notifiers:
            try:
                notifier.send(event)
                delivered += 1
            except Exception:
                logger.exception(
                    "Alert delivery failed on channel %r for event %s",
                    notifier.channel,
                    event.event_type.value,
                )
        if self._notifiers and not delivered:
            logger.error(
                "Alert delivery failed on ALL %d configured channel(s) for "
                "event %s — nobody was notified. Check the notifier "
                "endpoints/configuration.",
                len(self._notifiers),
                event.event_type.value,
            )
        return delivered
