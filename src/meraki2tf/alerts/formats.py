"""Channel-native webhook payload renderings.

The default webhook body is the raw, stable event payload
(:meth:`AlertEvent.to_payload`) — machine-readable and lossless. Slack
and Microsoft Teams incoming webhooks refuse or mis-render that shape:
Slack expects a ``{"text": ...}`` object and Teams Workflows expect an
Adaptive Card ``message`` attachment. These renderers produce those
shapes from the same event, headed by the event type and summary and
carrying the details as a (budgeted) JSON block — identifiers and
locators only, never secret values, exactly like the raw payload.
"""

from __future__ import annotations

import json
from typing import Any

from meraki2tf.alerts.models import AlertEvent

#: Accepted values for the webhook payload format selection.
WEBHOOK_FORMATS = ("json", "slack", "teams")

#: Ceiling on the rendered details block. Slack truncates ``text`` past
#: ~40k characters and Teams rejects Adaptive Cards past ~28KB total, so
#: chat-facing formats carry a budgeted excerpt; the run log, the workdir
#: artifacts, and the raw ``json`` format keep the full picture.
_DETAIL_CHAR_BUDGET = 6000


def _details_block(event: AlertEvent) -> str:
    rendered = json.dumps(event.details, indent=2, default=str)
    if len(rendered) <= _DETAIL_CHAR_BUDGET:
        return rendered
    omitted = len(rendered) - _DETAIL_CHAR_BUDGET
    return (
        rendered[:_DETAIL_CHAR_BUDGET]
        + f"\n… truncated for chat delivery ({omitted} more characters; "
        "the full payload is in the run log and workdir artifacts)"
    )


def _headline(event: AlertEvent) -> str:
    return f"[meraki2tf] {event.event_type.value} ({event.severity.value})"


def render_slack(event: AlertEvent) -> dict[str, Any]:
    """Slack incoming-webhook body: mrkdwn ``text`` with a code block."""
    return {
        "text": (
            f"*{_headline(event)}*\n{event.summary}\n"
            f"```{_details_block(event)}```"
        )
    }


def render_teams(event: AlertEvent) -> dict[str, Any]:
    """Teams Workflows incoming-webhook body: an Adaptive Card message.

    Targets the Power Automate "when a Teams webhook request is
    received" flow — the successor of the retired Office 365
    connectors — which expects a ``message`` carrying an
    ``application/vnd.microsoft.card.adaptive`` attachment.
    """
    return {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": (
                        "http://adaptivecards.io/schemas/adaptive-card.json"
                    ),
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": [
                        {
                            "type": "TextBlock",
                            "size": "Medium",
                            "weight": "Bolder",
                            "wrap": True,
                            "text": _headline(event),
                        },
                        {
                            "type": "TextBlock",
                            "wrap": True,
                            "text": event.summary,
                        },
                        {
                            "type": "TextBlock",
                            "wrap": True,
                            "fontType": "Monospace",
                            "text": _details_block(event),
                        },
                    ],
                },
            }
        ],
    }


def render_payload(event: AlertEvent, payload_format: str) -> dict[str, Any]:
    """The webhook body for ``event`` in the configured format."""
    if payload_format == "json":
        return event.to_payload()
    if payload_format == "slack":
        return render_slack(event)
    if payload_format == "teams":
        return render_teams(event)
    raise ValueError(
        f"unknown webhook payload format {payload_format!r}; expected one "
        f"of {', '.join(WEBHOOK_FORMATS)}."
    )
