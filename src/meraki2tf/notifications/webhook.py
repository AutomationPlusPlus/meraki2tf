"""Webhook notifier plugin (delivery transport lands in a later iteration)."""

from __future__ import annotations

import logging

from meraki2tf.notifications.base import Notifier
from meraki2tf.notifications.models import NotificationEvent

logger = logging.getLogger(__name__)


class WebhookNotifier(Notifier):
    """POSTs event payloads to a configured HTTP endpoint.

    The URL may carry an embedded secret, so it is never logged in full.
    """

    channel = "webhook"

    def __init__(self, url: str) -> None:
        self._url = url

    def send(self, event: NotificationEvent) -> None:
        payload = event.to_payload()
        logger.debug("Prepared webhook payload for event %s", payload["event_type"])
        raise NotImplementedError(
            "Webhook HTTP delivery is wired in with the alerting engine iteration."
        )
