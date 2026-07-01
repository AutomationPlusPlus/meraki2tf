"""Email notifier placeholder (SMTP transport lands in a later iteration)."""

from __future__ import annotations

import logging

from meraki2tf.notifications.base import Notifier
from meraki2tf.notifications.models import NotificationEvent

logger = logging.getLogger(__name__)


class EmailNotifier(Notifier):
    """Renders events into a plaintext body for an SMTP relay."""

    channel = "email"

    def __init__(self, recipients: list[str]) -> None:
        self._recipients = list(recipients)

    def send(self, event: NotificationEvent) -> None:
        logger.debug(
            "Prepared email for %d recipient(s), event %s",
            len(self._recipients),
            event.event_type.value,
        )
        raise NotImplementedError(
            "SMTP delivery is wired in with the alerting engine iteration."
        )
