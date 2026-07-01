"""Explicit payload contracts for every alert the pipeline can emit.

Three execution events are mandated by the project contract —
``DRIFT_DETECTED``, ``RUN_SUCCESS``, and ``UNSUPPORTED_FEATURE_FLAGGED``
— plus ``PROCESSING_FAULT`` for critical script failures. Each has a
builder that fixes its payload schema, so channels receive a stable,
channel-agnostic JSON structure. Payloads carry only resource
identifiers and structural data: never credentials.
"""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Any


class EventType(enum.Enum):
    DRIFT_DETECTED = "DRIFT_DETECTED"
    RUN_SUCCESS = "RUN_SUCCESS"
    UNSUPPORTED_FEATURE_FLAGGED = "UNSUPPORTED_FEATURE_FLAGGED"
    PROCESSING_FAULT = "PROCESSING_FAULT"


class EventSeverity(enum.Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AlertEvent:
    """Envelope shared by all alert payloads."""

    event_type: EventType
    severity: EventSeverity
    summary: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        """Render the JSON-serializable payload every transport sends."""
        payload = asdict(self)
        payload["event_type"] = self.event_type.value
        payload["severity"] = self.severity.value
        return payload


def drift_detected(diff: str, workspace: str) -> AlertEvent:
    """Contract payload for drift discovered during state comparison.

    Schema: ``details = {"diff": <plan output>, "workspace": <dir>}``.
    """
    return AlertEvent(
        event_type=EventType.DRIFT_DETECTED,
        severity=EventSeverity.WARNING,
        summary="Configuration drift detected between discovery and Terraform state.",
        details={"diff": diff, "workspace": workspace},
    )


def run_success(imports_written: int, drift_was_detected: bool, workspace: str) -> AlertEvent:
    """Contract payload for a flawless state-aggregation run.

    Schema: ``details = {"imports_written", "drift_was_detected", "workspace"}``.
    """
    return AlertEvent(
        event_type=EventType.RUN_SUCCESS,
        severity=EventSeverity.INFO,
        summary=(
            f"meraki2tf run completed cleanly; {imports_written} import(s) aggregated "
            "into state."
        ),
        details={
            "imports_written": imports_written,
            "drift_was_detected": drift_was_detected,
            "workspace": workspace,
        },
    )


def unsupported_feature_flagged(
    api_path: str, reason: str, identifiers: Sequence[str]
) -> AlertEvent:
    """Contract payload for a discovered asset the provider cannot express.

    Schema: ``details = {"api_path", "reason", "identifiers"}``.
    """
    return AlertEvent(
        event_type=EventType.UNSUPPORTED_FEATURE_FLAGGED,
        severity=EventSeverity.WARNING,
        summary=f"Unsupported Meraki feature flagged: {api_path}",
        details={
            "api_path": api_path,
            "reason": reason,
            "identifiers": list(identifiers),
        },
    )


def processing_fault(stage: str, error: str) -> AlertEvent:
    """Contract payload for a critical pipeline failure.

    Schema: ``details = {"stage", "error"}``.
    """
    return AlertEvent(
        event_type=EventType.PROCESSING_FAULT,
        severity=EventSeverity.CRITICAL,
        summary=f"meraki2tf pipeline fault during {stage}.",
        details={"stage": stage, "error": error},
    )
