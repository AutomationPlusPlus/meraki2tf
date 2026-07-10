"""Explicit payload contracts for every alert the pipeline can emit.

The execution events mandated by the project contract —
``DRIFT_DETECTED`` (including aborted sync-mode auto-applies),
``RUN_SUCCESS``, ``UNSUPPORTED_FEATURE_FLAGGED``, and
``DELETION_PENDING_CONFIRMATION`` — plus ``PROCESSING_FAULT`` for
critical script failures. Each has a builder that fixes its payload
schema, so channels receive a stable, channel-agnostic JSON structure.
Success and drift payloads always carry the count and list of objects
Terraform cannot rebuild, so the manual-rebuild runbook reaches the
operator on every run. Payloads carry only resource identifiers and
structural data: never credentials.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any


class EventType(enum.Enum):
    DRIFT_DETECTED = "DRIFT_DETECTED"
    RUN_SUCCESS = "RUN_SUCCESS"
    UNSUPPORTED_FEATURE_FLAGGED = "UNSUPPORTED_FEATURE_FLAGGED"
    PROCESSING_FAULT = "PROCESSING_FAULT"
    #: Resources in the DR kit that discovery no longer sees in Meraki;
    #: never auto-removed — a human confirms via --confirm-deletions.
    DELETION_PENDING_CONFIRMATION = "DELETION_PENDING_CONFIRMATION"
    #: A human-invoked --replay-gaps --confirm wrote unsupported
    #: objects/secret attributes back to Meraki from a snapshot.
    GAP_REPLAY_EXECUTED = "GAP_REPLAY_EXECUTED"
    #: A human-invoked --restore --confirm rebuilt a target organization
    #: from a snapshot (never the source organization).
    RESTORE_EXECUTED = "RESTORE_EXECUTED"


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


def drift_detected(
    diff: str,
    workspace: str,
    unsupported: Sequence[Mapping[str, Any]] = (),
    apply_aborted: bool = False,
    regenerated_addresses: Sequence[str] = (),
    deferred_addresses: Sequence[str] = (),
    origin: str = "terraform-plan",
) -> AlertEvent:
    """Contract payload for drift discovered during state comparison.

    ``apply_aborted`` marks a sync-mode run whose guarded auto-apply was
    refused because the plan proposed mutations — a human decides what
    happens next. ``regenerated_addresses`` lists modified objects whose
    HCL baseline was regenerated to mirror current Meraki (Meraki is
    truth in DR mode). ``deferred_addresses`` lists pending imports that
    kept drifting during the run's plan windows and were pulled from
    this run's kit so the rest could apply — they import on the next
    run. The unsupported list rides along on every drift alert so the
    manual-rebuild runbook always reaches the operator.
    """
    return AlertEvent(
        event_type=EventType.DRIFT_DETECTED,
        severity=EventSeverity.WARNING,
        summary=(
            "Configuration drift detected; sync-mode auto-apply aborted — "
            "a human must review the diff."
            if apply_aborted
            else "Configuration drift detected between discovery and Terraform state."
        ),
        details={
            "diff": diff,
            "workspace": workspace,
            "origin": origin,
            "apply_aborted": apply_aborted,
            "regenerated_addresses": list(regenerated_addresses),
            "deferred_addresses": list(deferred_addresses),
            "unsupported_count": len(unsupported),
            "unsupported": [dict(entry) for entry in unsupported],
        },
    )


def run_success(
    imports_written: int,
    drift_was_detected: bool,
    workspace: str,
    discovered_assets: int,
    imports_already_tracked: int,
    unsupported: Sequence[Mapping[str, Any]],
    pending_imports: int | None,
    comparison_performed: bool,
    resources_added_to_state: Sequence[str] = (),
    coverage_percent: float | None = None,
    deletions_pending: Sequence[str] = (),
    unmanaged_secret_attributes: Mapping[str, Sequence[str]] | None = None,
    deferred_addresses: Sequence[str] = (),
) -> AlertEvent:
    """Contract payload for a flawless snapshot-generation run.

    Carries the Terraform coverage picture so receivers can verify that
    everything discovered is captured: total assets, new import blocks,
    already-tracked resources, the count *and list* of unsupported
    assets (the manual DR runbook), the resources this run added to
    state (sync mode), the coverage percentage, deletions awaiting
    confirmation, secret attributes the kit cannot carry (restore them
    manually after a rebuild), and — when the plan comparison ran — how
    many imports are still pending aggregation into state (None when
    unknown).
    """
    return AlertEvent(
        event_type=EventType.RUN_SUCCESS,
        severity=EventSeverity.INFO,
        summary=(
            f"meraki2tf run completed cleanly; {imports_written} import block(s) "
            f"generated, {len(resources_added_to_state)} resource(s) added to state."
        ),
        details={
            "imports_written": imports_written,
            "drift_was_detected": drift_was_detected,
            "workspace": workspace,
            "discovered_assets": discovered_assets,
            "imports_already_tracked": imports_already_tracked,
            "unsupported_count": len(unsupported),
            "unsupported": [dict(entry) for entry in unsupported],
            "pending_imports": pending_imports,
            "comparison_performed": comparison_performed,
            "resources_added_to_state": list(resources_added_to_state),
            "coverage_percent": coverage_percent,
            "deletions_pending_confirmation": list(deletions_pending),
            "unmanaged_secret_attribute_count": sum(
                len(attrs)
                for attrs in (unmanaged_secret_attributes or {}).values()
            ),
            "unmanaged_secret_attributes": {
                address: list(attrs)
                for address, attrs in (unmanaged_secret_attributes or {}).items()
            },
            "deferred_addresses": list(deferred_addresses),
        },
    )


def deletion_pending_confirmation(
    addresses: Sequence[str], workspace: str
) -> AlertEvent:
    """Contract payload for Meraki deletions awaiting human confirmation.

    Deletions are never silently synced out of the DR kit — an
    accidental clickops deletion must not quietly poison the rebuild
    baseline. The listed resources stay in the kit and the state until
    a human confirms their removal with ``--confirm-deletions``.
    """
    return AlertEvent(
        event_type=EventType.DELETION_PENDING_CONFIRMATION,
        severity=EventSeverity.WARNING,
        summary=(
            f"{len(addresses)} resource(s) deleted in Meraki await human "
            "confirmation before removal from the DR kit."
        ),
        details={
            "addresses": list(addresses),
            "workspace": workspace,
            "remediation": (
                "Review the deletions; if intentional, re-run with "
                "--confirm-deletions to remove them from the baseline and state."
            ),
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


def restore_executed(
    target_organization_id: str,
    executed: Sequence[str],
    failed: Sequence[Sequence[str]],
    skipped: Sequence[Mapping[str, Any]],
) -> AlertEvent:
    """Contract payload for a human-invoked full restore into a target
    organization. Entries are value-free action labels — restored
    payloads and secret values never leave the process."""
    severity = EventSeverity.WARNING if failed else EventSeverity.INFO
    return AlertEvent(
        event_type=EventType.RESTORE_EXECUTED,
        severity=severity,
        summary=(
            f"Restore into organization {target_organization_id}: "
            f"{len(executed)} restored, {len(failed)} failed, "
            f"{len(skipped)} skipped."
        ),
        details={
            "target_organization_id": target_organization_id,
            "executed": list(executed),
            "failed": [list(item) for item in failed],
            "skipped": [dict(item) for item in skipped],
        },
    )


def gap_replay_executed(
    organization_id: str,
    executed: Sequence[str],
    failed: Sequence[Sequence[str]],
    skipped: Sequence[Mapping[str, Any]],
) -> AlertEvent:
    """Contract payload for a human-invoked gap replay against Meraki.

    Schema: ``details = {"organization_id", "executed", "failed",
    "skipped"}``. Entries are value-free target labels — replayed
    payloads and secret values never leave the process.
    """
    severity = EventSeverity.WARNING if failed else EventSeverity.INFO
    return AlertEvent(
        event_type=EventType.GAP_REPLAY_EXECUTED,
        severity=severity,
        summary=(
            f"Gap replay against organization {organization_id}: "
            f"{len(executed)} restored, {len(failed)} failed, "
            f"{len(skipped)} skipped."
        ),
        details={
            "organization_id": organization_id,
            "executed": list(executed),
            "failed": [list(item) for item in failed],
            "skipped": [dict(item) for item in skipped],
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
