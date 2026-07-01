"""Structured event payloads carried to every notification channel.

Channels serialize these models however their transport requires; the
schema itself is channel-agnostic. Payloads must never contain
credentials — only resource identifiers and structural diff data.
"""

from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any


class EventType(enum.Enum):
    DRIFT_DETECTED = "drift_detected"
    RUN_SUCCESS = "run_success"
    UNSUPPORTED_FEATURE = "unsupported_feature"
    PROCESSING_FAULT = "processing_fault"


class EventSeverity(enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class NotificationEvent:
    """Envelope shared by all alert payloads."""

    event_type: EventType
    severity: EventSeverity
    summary: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        """Render a JSON-serializable payload for transport layers."""
        payload = asdict(self)
        payload["event_type"] = self.event_type.value
        payload["severity"] = self.severity.value
        return payload


@dataclass(frozen=True)
class ResourceDiff:
    """One drifted resource: the discovered value versus recorded state."""

    resource_type: str
    resource_id: str
    attribute: str
    expected: Any
    actual: Any


def drift_alert(diffs: list[ResourceDiff]) -> NotificationEvent:
    """Build the drift event emitted by the comparison phase."""
    return NotificationEvent(
        event_type=EventType.DRIFT_DETECTED,
        severity=EventSeverity.WARNING,
        summary=f"Configuration drift detected across {len(diffs)} attribute(s).",
        details={"diffs": [asdict(diff) for diff in diffs]},
    )


def run_success(resources_synced: int) -> NotificationEvent:
    """Build the confirmation event dispatched after clean state aggregation."""
    return NotificationEvent(
        event_type=EventType.RUN_SUCCESS,
        severity=EventSeverity.INFO,
        summary=f"Run completed cleanly; {resources_synced} resource(s) in sync.",
        details={"resources_synced": resources_synced},
    )


def unsupported_feature(feature: str, context: dict[str, Any]) -> NotificationEvent:
    """Build the audit event for parameters the Terraform provider cannot express."""
    return NotificationEvent(
        event_type=EventType.UNSUPPORTED_FEATURE,
        severity=EventSeverity.WARNING,
        summary=f"Unsupported Meraki feature flagged: {feature}",
        details=context,
    )


# Aliases documenting the three contract-mandated payload shapes.
DriftAlert = NotificationEvent
RunSuccessReport = NotificationEvent
UnsupportedFeatureReport = NotificationEvent
