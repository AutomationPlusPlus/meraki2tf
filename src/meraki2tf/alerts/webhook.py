"""Generic webhook notifier: structured JSON via built-in urllib.request."""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Any
from urllib.parse import urlsplit

from meraki2tf.alerts.base import Notifier
from meraki2tf.alerts.formats import WEBHOOK_FORMATS, render_payload
from meraki2tf.alerts.models import AlertEvent

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT_SECONDS = 10.0


class WebhookDeliveryError(RuntimeError):
    """The endpoint refused or failed to accept the payload."""


class WebhookConfigError(ValueError):
    """The configured webhook URL is unusable (e.g. an insecure scheme)."""


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Turn any 3xx into an error instead of following it.

    urllib re-issues a redirected POST as a *bodyless GET*, so a
    redirecting endpoint (auth proxy, moved tenant) would swallow the
    alert while the final 200 reads as delivered — and the server-chosen
    target could even downgrade to http. A drift alert that reached
    nobody must never look like a delivered one.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


_OPENER = urllib.request.build_opener(_RefuseRedirects)


def _open(request: urllib.request.Request, timeout: float) -> Any:
    """Module seam over the redirect-refusing opener (tests patch this)."""
    return _OPENER.open(request, timeout=timeout)


class WebhookNotifier(Notifier):
    """POSTs the event payload as JSON to a configured HTTPS endpoint.

    The URL may carry an embedded secret (Slack/Teams incoming-webhook
    tokens live in the path), so it is never logged in full and only
    ``https`` is accepted — payloads and any URL-embedded credential
    must never cross the network in cleartext.
    """

    channel = "webhook"

    def __init__(
        self,
        url: str,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
        payload_format: str = "json",
    ) -> None:
        if payload_format not in WEBHOOK_FORMATS:
            raise WebhookConfigError(
                f"unknown webhook payload format {payload_format!r}; "
                f"expected one of {', '.join(WEBHOOK_FORMATS)}."
            )
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme != "https":
            raise WebhookConfigError(
                f"webhook URL must use https (got {scheme or 'no'} scheme); "
                "the payload and any token embedded in the URL would "
                "otherwise cross the network in cleartext."
            )
        if "@" in parts.netloc:
            # Never accepted downstream anyway (webhook tokens live in
            # the path, not userinfo), and a malformed userinfo URL makes
            # urllib raise errors that embed the credential fragment.
            raise WebhookConfigError(
                "webhook URL must not embed userinfo credentials; put the "
                "token in the path or query as the provider issued it."
            )
        self._url = url
        #: URL pieces long enough to be a secret; scrubbed out of any
        #: exception text so partial-URL echoes cannot leak the token.
        self._sensitive_fragments = tuple(
            fragment
            for fragment in (url, parts.netloc, parts.path, parts.query)
            if len(fragment) > 1
        )
        self._timeout = timeout
        self._payload_format = payload_format

    def _scrub(self, text: str) -> str:
        for fragment in self._sensitive_fragments:
            text = text.replace(fragment, "<webhook-url>")
        return text

    def send(self, event: AlertEvent) -> None:
        """POST the event as JSON to the configured webhook endpoint.

        The body is rendered in the channel's payload format (a generic
        JSON envelope, or a Slack/Teams message card), so one notifier
        drives every webhook-shaped target. Raises
        :class:`WebhookDeliveryError` when the request fails or the
        endpoint answers HTTP >= 300; the message and exception chain are
        scrubbed first so a URL carrying an embedded secret never reaches
        a log or traceback.
        """
        body = json.dumps(
            render_payload(event, self._payload_format)
        ).encode("utf-8")
        try:
            request = urllib.request.Request(
                self._url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _open(request, self._timeout) as response:
                status = int(getattr(response, "status", 200))
        except Exception as exc:
            # Some urllib exceptions (e.g. a scheme-less URL's ValueError)
            # embed the URL or fragments of it; scrub them and drop the
            # exception chain so the dispatcher's traceback logging
            # cannot echo the secret.
            detail = self._scrub(str(exc))
            raise WebhookDeliveryError(
                f"Webhook delivery failed ({type(exc).__name__}): {detail}"
            ) from None
        if status >= 300:
            raise WebhookDeliveryError(f"Webhook endpoint answered HTTP {status}.")
        logger.debug(
            "Webhook delivered event %s (HTTP %d).", event.event_type.value, status
        )
