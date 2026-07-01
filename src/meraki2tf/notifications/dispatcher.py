"""Fan-out dispatcher decoupling the pipeline from delivery channels."""

from __future__ import annotations

import logging
from collections.abc import Iterable

from meraki2tf.notifications.base import Notifier
from meraki2tf.notifications.models import NotificationEvent

logger = logging.getLogger(__name__)


class NotificationDispatcher:
    """Delivers each event to every registered channel with failure isolation."""

    def __init__(self, notifiers: Iterable[Notifier] = ()) -> None:
        self._notifiers: list[Notifier] = list(notifiers)

    def register(self, notifier: Notifier) -> None:
        self._notifiers.append(notifier)

    def dispatch(self, event: NotificationEvent) -> int:
        """Send ``event`` to all channels; returns the count delivered.

        A failing channel is logged and skipped so one broken endpoint
        never suppresses drift or success alerts on the others.
        """
        delivered = 0
        for notifier in self._notifiers:
            try:
                notifier.send(event)
                delivered += 1
            except Exception:
                logger.exception(
                    "Notification delivery failed on channel %r for event %s",
                    notifier.channel,
                    event.event_type.value,
                )
        return delivered
