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
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from meraki2tf.sanitizer import SECRET_KEY_PATTERN

#: Terraform's per-resource progress chatter in ``-no-color`` plan/apply
#: output. These lines open at column 0 with the resource address, so
#: they cannot be confused with diff hunks (always indented) or with the
#: plan summary/header lines (which never start with an address-colon).
_PLAN_PROGRESS_RE = re.compile(
    r"^\S+: (?:"
    r"Refreshing state|Still refreshing|Preparing import"
    r"|Reading|Still reading|Read complete"
    r")\.*(?:\s|$)"
)


def condense_diff(text: str) -> str:
    """Drop terraform's progress chatter from a plan diff.

    A refresh over a large state emits one ``address: Refreshing
    state...`` line per tracked resource — tens of thousands of lines
    on a production organization — burying the actual change hunks an
    operator must review and inflating alert payloads past what many
    webhook receivers accept. Only the progress lines go; hunks,
    headers, and the plan summary stay untouched.
    """
    kept: list[str] = []
    for line in text.splitlines():
        if _PLAN_PROGRESS_RE.match(line):
            continue
        if not line.strip() and kept and not kept[-1].strip():
            continue  # collapse the blank runs the removals leave behind
        kept.append(line)
    while kept and not kept[0].strip():
        kept.pop(0)
    return "\n".join(kept)


#: Quoted HCL string (escapes included) — stripped before counting
#: brackets so a bracket *inside* a rendered value cannot open or close
#: a masked block.
_QUOTED_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
_HEREDOC_OPENER_RE = re.compile(r"<<[-~]?\s*(\w+)")


def _bracket_delta(fragment: str) -> int:
    cleaned = _QUOTED_STRING_RE.sub('""', fragment)
    return sum(
        cleaned.count(opener) - cleaned.count(closer)
        for opener, closer in (("[", "]"), ("{", "}"), ("(", ")"))
    )


def redact_diff(text: str) -> str:
    """Mask attribute *values* on secret-named lines of a plan diff.

    Terraform masks attributes the provider declares ``sensitive``, but
    the alert contract ("names and locators, never values") must not
    depend on the provider's schema being complete: any diff line whose
    attribute name is secret-shaped loses everything after the ``=``
    (or ``:``) before the diff leaves the process. Values terraform
    renders across multiple lines (lists, maps, heredocs) are masked to
    their closing delimiter — a line-local redactor would strip only
    the name line and pass every continuation line through raw.
    """
    redacted: list[str] = []
    depth = 0
    heredoc_tag: str | None = None
    for line in text.splitlines():
        if heredoc_tag is not None:
            if line.strip() == heredoc_tag:
                heredoc_tag = None
            continue
        if depth > 0:
            depth += _bracket_delta(line)
            continue
        for separator in ("=", ":"):
            head, sep, value = line.partition(separator)
            tokens = head.split()
            if sep and tokens and SECRET_KEY_PATTERN.search(tokens[-1]):
                opener = _HEREDOC_OPENER_RE.search(value)
                if opener is not None:
                    heredoc_tag = opener.group(1)
                else:
                    depth = max(0, _bracket_delta(value))
                line = f"{head}{separator} (value redacted)"
                break
        redacted.append(line)
    return "\n".join(redacted)


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
    #: A human-invoked --heal --confirm recreated accidentally deleted
    #: objects in the snapshot's OWN organization (additive-only).
    HEAL_EXECUTED = "HEAL_EXECUTED"
    #: A human-invoked --wipe-org --confirm tore down a hardware-free
    #: drill organization after a restore rehearsal.
    ORG_WIPE_EXECUTED = "ORG_WIPE_EXECUTED"
    #: A human-invoked --rebuild --confirm ran terraform apply of the
    #: generated DR kit against the organization.
    REBUILD_EXECUTED = "REBUILD_EXECUTED"


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
            else (
                "Configuration drift detected between the snapshot and "
                "the drift baseline."
                if origin == "snapshot-diff"
                else "Configuration drift detected between discovery and "
                "Terraform state."
            )
        ),
        details={
            "diff": redact_diff(condense_diff(diff)),
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
    reconciliation_drop_categories: Mapping[str, int] | None = None,
    partial_scope: Sequence[str] = (),
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
    unknown). Reconciliation drops additionally arrive aggregated by
    diagnostic title, so a provider regression names the resource class
    it broke. ``partial_scope`` carries the covered network IDs of a
    partial (``--only``) run, so the receiver can never mistake a
    one-network export for a full-organization capture.
    """
    summary = (
        f"meraki2tf run completed cleanly; {imports_written} import block(s) "
        f"generated, {len(resources_added_to_state)} resource(s) added to state."
    )
    if partial_scope:
        summary += (
            f" PARTIAL run scoped to {len(partial_scope)} network(s)."
        )
    return AlertEvent(
        event_type=EventType.RUN_SUCCESS,
        severity=EventSeverity.INFO,
        summary=summary,
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
            "reconciliation_drop_categories": dict(
                reconciliation_drop_categories or {}
            ),
            "partial_scope": list(partial_scope),
        },
    )


def deletion_pending_confirmation(
    addresses: Sequence[str], workspace: str, note: str | None = None
) -> AlertEvent:
    """Contract payload for Meraki deletions awaiting human confirmation.

    Deletions are never silently synced out of the DR kit — an
    accidental clickops deletion must not quietly poison the rebuild
    baseline. The listed resources stay in the kit and the state until
    a human confirms their removal with ``--confirm-deletions``.

    ``note`` carries an optional diagnosis hint (round-9 finding G3):
    when every tracked resource vanishes at once the state may be
    foreign or mis-pointed rather than the org having emptied.
    """
    details: dict[str, Any] = {
        "addresses": list(addresses),
        "workspace": workspace,
        "remediation": (
            "Review the deletions; if intentional, re-run with "
            "--confirm-deletions to remove them from the baseline and state."
        ),
    }
    if note:
        details["note"] = note
    return AlertEvent(
        event_type=EventType.DELETION_PENDING_CONFIRMATION,
        severity=EventSeverity.WARNING,
        summary=(
            f"{len(addresses)} resource(s) deleted in Meraki await human "
            "confirmation before removal from the DR kit."
        ),
        details=details,
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


def heal_executed(
    organization_id: str,
    surviving: int,
    executed: Sequence[str],
    failed: Sequence[Sequence[str]],
    skipped: Sequence[Mapping[str, Any]],
    only: Sequence[str] = (),
    snapshot_scope: Sequence[str] = (),
    verified_alive: int = 0,
) -> AlertEvent:
    """Contract payload for a human-invoked same-org heal: accidentally
    deleted objects recreated from a snapshot, surviving objects never
    touched. Entries are value-free action labels. ``only`` carries the
    --only selectors of a selective heal, so the operator reading the
    alert knows the run deliberately covered a subset of the missing
    objects. ``snapshot_scope`` carries the covered network IDs when
    the heal ran from a partial (selective-backup) snapshot — the
    counts then describe that scope, not the organization.
    ``verified_alive`` counts the planned actions the pre-write
    verification found alive and skipped (additive-only): a nonzero
    value means the discovery sweep undercounted survivors and deserves
    its own line in the alert."""
    severity = EventSeverity.WARNING if failed else EventSeverity.INFO
    summary = (
        f"Heal of organization {organization_id}: {len(executed)} "
        f"missing object(s) recreated, {len(failed)} failed, "
        f"{len(skipped)} skipped; {surviving} surviving object(s) "
        "untouched."
    )
    details: dict[str, Any] = {
        "organization_id": organization_id,
        "surviving_untouched": surviving,
        "executed": list(executed),
        "failed": [list(item) for item in failed],
        "skipped": [dict(item) for item in skipped],
    }
    if verified_alive:
        summary += (
            f" {verified_alive} planned action(s) were verified alive "
            "at execution time and skipped (additive-only)."
        )
        details["verified_alive_skips"] = verified_alive
    if only:
        summary += (
            " Selective heal (--only "
            + ", ".join(repr(value) for value in only)
            + ")."
        )
        details["only_filters"] = list(only)
    if snapshot_scope:
        summary += (
            f" Healed from a PARTIAL snapshot scoped to "
            f"{len(snapshot_scope)} network(s)."
        )
        details["snapshot_scope"] = list(snapshot_scope)
    return AlertEvent(
        event_type=EventType.HEAL_EXECUTED,
        severity=severity,
        summary=summary,
        details=details,
    )


def org_wipe_executed(
    organization_id: str,
    deleted_networks: int,
    organization_deleted: bool,
    failed: Sequence[Sequence[str]],
) -> AlertEvent:
    """Contract payload for a human-invoked drill-organization wipe."""
    severity = EventSeverity.WARNING if failed else EventSeverity.INFO
    return AlertEvent(
        event_type=EventType.ORG_WIPE_EXECUTED,
        severity=severity,
        summary=(
            f"Drill organization {organization_id} wiped: "
            f"{deleted_networks} network(s) deleted, organization "
            f"{'deleted' if organization_deleted else 'NOT deleted'}, "
            f"{len(failed)} failure(s)."
        ),
        details={
            "organization_id": organization_id,
            "deleted_networks": deleted_networks,
            "organization_deleted": organization_deleted,
            "failed": [list(item) for item in failed],
        },
    )


def rebuild_executed(workspace: str, succeeded: bool, error: str = "") -> AlertEvent:
    """Contract payload for a human-invoked terraform rebuild apply.

    The largest write path of all (a full ``terraform apply``) must
    reach the notification channels like every other DR action — a
    mid-incident half-applied rebuild that only the local terminal saw
    would leave the on-call channel blind. ``error`` carries the
    (already value-free) failure text when ``succeeded`` is False.
    """
    return AlertEvent(
        event_type=EventType.REBUILD_EXECUTED,
        severity=EventSeverity.INFO if succeeded else EventSeverity.CRITICAL,
        summary=(
            f"Terraform rebuild apply from workspace {workspace} "
            + ("completed." if succeeded else "FAILED — the organization "
               "may be partially rebuilt.")
        ),
        details={
            "workspace": workspace,
            "succeeded": succeeded,
            "error": error,
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
