"""Generic webhook notifier: structured JSON via built-in urllib.request."""

from __future__ import annotations

import json
import logging
import urllib.request

from meraki2tf.alerts.base import Notifier
from meraki2tf.alerts.models import AlertEvent

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS = 10.0


class WebhookDeliveryError(RuntimeError):
    """The endpoint refused or failed to accept the payload."""


class WebhookNotifier(Notifier):
    """POSTs the event payload as JSON to a configured HTTP endpoint.

    The URL may carry an embedded secret, so it is never logged in full.
    """

    channel = "webhook"

    def __init__(self, url: str, timeout: float = _DEFAULT_TIMEOUT_SECONDS) -> None:
        self._url = url
        self._timeout = timeout

    def send(self, event: AlertEvent) -> None:
        body = json.dumps(event.to_payload()).encode("utf-8")
        try:
            request = urllib.request.Request(
                self._url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                status = int(getattr(response, "status", 200))
        except Exception as exc:
            # Some urllib exceptions (e.g. a scheme-less URL's ValueError)
            # embed the full URL; scrub it and drop the exception chain so
            # the dispatcher's traceback logging cannot echo the secret.
            detail = str(exc).replace(self._url, "<webhook-url>")
            raise WebhookDeliveryError(
                f"Webhook delivery failed ({type(exc).__name__}): {detail}"
            ) from None
        if status >= 300:
            raise WebhookDeliveryError(f"Webhook endpoint answered HTTP {status}.")
        logger.debug(
            "Webhook delivered event %s (HTTP %d).", event.event_type.value, status
        )
