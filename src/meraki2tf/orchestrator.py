"""Lifecycle coordinator: one full extraction/translation/comparison cycle.

Wires the pipeline end to end — discovery, HCL generation with
exception auditing, deletion review, speculative drift comparison,
optional sync-mode state materialization, and the per-run coverage
manifest — and fires the contract alerts at each mandated trigger
point. Suitable for ad-hoc terminal runs and headless scheduled (cron)
execution alike: every failure path resolves to an alert plus a raised
:class:`PipelineError` for the CLI to convert into an exit code.

Meraki read-only guarantee: no run mutates the Meraki organization.
The default pipeline never executes ``terraform apply`` at all; opt-in
sync mode (the scheduled DR job) may apply **state-only** import plans
through :meth:`TerraformRunner.apply_import_plan`, which independently
re-verifies the plan as 100% imports (0 to add, 0 to change,
0 to destroy) immediately before applying. Rebuilding Meraki from the
generated artifacts is an explicit, human-invoked CLI action
(``--rebuild --confirm``) that does not pass through this orchestrator.

Sync-mode drift defaults (Meraki is the source of truth):

- New objects: auto-generated, auto-imported into state, reported.
- Modified objects: the HCL baseline is regenerated to mirror current
  Meraki (local state surgery + re-import — Meraki untouched) and the
  diff is dispatched via a DRIFT_DETECTED alert.
- Deleted objects: alert-only in every mode. Nothing leaves the DR kit
  until a human confirms with ``--confirm-deletions``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import dataclasses

from meraki2tf.alerts import (
    AlertDispatcher,
    deletion_pending_confirmation,
    drift_detected,
    processing_fault,
    run_success,
    unsupported_feature_flagged,
)
from meraki2tf.alerts.models import condense_diff, redact_diff
from meraki2tf.config import API_KEY_ENV_VAR, api_key_present
from meraki2tf.fileio import atomic_write_text
from meraki2tf.coverage import build_manifest, unsupported_payload, write_manifest
from meraki2tf.hcl_generator import (
    GenerationReport,
    HclImportGenerator,
    UnsupportedAsset,
)
from meraki2tf.models import NetworkGraph
from meraki2tf.plan_reconciler import (
    drop_reason_categories,
    duplicate_set_reason,
    payload_carries_duplicate,
)
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.runbook import (
    payload_index,
    secret_attribute_union,
    write_runbook,
)
from meraki2tf.providers.discovery_checkpoint import CheckpointMismatchError
from meraki2tf.scope import ScopeFilterError, scoped_plan_targets
from meraki2tf.terraform_runner import (
    ImportGuardViolation,
    ReconciledPlanResult,
    TerraformError,
    TerraformRunner,
)
from meraki2tf.workdir_lock import WorkdirLock, WorkdirLockError

logger = logging.getLogger(__name__)

#: Plan actions that do not mutate anything (imports plan as no-op).
_HARMLESS_ACTIONS = frozenset({"no-op", "read"})

#: Cap on how many items a single log line enumerates inline. At ~200k
#: discovered objects the full unsupported / uncaptured-secret lists would
#: each be one enormous single-line record (hundreds of KB) that
#: journald/aggregators truncate exactly when the enumeration matters. The
#: full lists stay durable in coverage.json / coverage.txt / runbook.md;
#: only the LOG line is capped. Mirrors snapshot_diff.render_diff's limit.
LOG_ENUMERATION_CAP = 50


def cap_log_enumeration(
    entries: Sequence[str],
    sep: str = "; ",
    cap: int = LOG_ENUMERATION_CAP,
) -> str:
    """Join ``entries`` for a log line, capping the inline enumeration.

    Beyond ``cap`` items the tail collapses to "... and N more (see
    coverage.txt / runbook.md)" so one log record stays bounded even at
    ~200k objects. The full list lives durably in the coverage manifest and
    runbook — this only shapes the transient log line, never those.
    """
    shown = sep.join(entries[:cap])
    hidden = len(entries) - cap
    if hidden > 0:
        tail = f"... and {hidden} more (see coverage.txt / runbook.md)"
        shown = f"{shown}{sep}{tail}" if shown else tail
    return shown


#: Workdir file carrying the deletion addresses a DELETION_PENDING_
#: CONFIRMATION alert already reached the operator with. A later
#: ``--confirm-deletions`` may only remove addresses from this set —
#: the human confirms what they reviewed, not whatever happens to be
#: missing on the confirmation run. Plain address list, no secrets.
PENDING_DELETIONS_FILENAME = "pending-deletions.json"

#: Diagnosis note (round-9 finding G3) attached to the deletion alert
#: when EVERY tracked resource is missing in one run: a foreign or
#: mis-pointed state reads as a mass deletion. The org guard (G1) catches
#: the common case first; this covers a disjoint state with no org
#: attribute to compare. It changes no deletion semantics — nothing is
#: removed without --confirm-deletions — it only warns before confirming.
FOREIGN_STATE_DELETION_NOTE = (
    "Every state-tracked resource is missing this run — the state may not "
    "correspond to this organization/kit; verify --state-file before "
    "confirming."
)


class PipelineError(RuntimeError):
    """The run failed; a PROCESSING_FAULT alert has already been dispatched."""


class PreflightRefusalError(RuntimeError):
    """An expected precondition refusal, detected before any work ran.

    Not a pipeline fault: nothing broke, the operator asked for a
    combination the tool refuses by design (e.g. --rebaseline over a
    populated state). No PROCESSING_FAULT alert is dispatched.
    """


@dataclass(frozen=True)
class RunSummary:
    """Outcome of one completed pipeline cycle."""

    organization_id: str
    discovered_assets: int
    imports_written: int
    imports_skipped_existing: int
    unsupported_count: int
    drift_detected: bool
    #: True when the terraform plan comparison was skipped because no
    #: API key was available (typical for offline dump-mode runs).
    comparison_skipped: bool
    #: Imports the plan reports as not yet aggregated into state; None
    #: when the comparison was skipped or the plan summary was absent.
    pending_imports: int | None
    #: Resources the sync-mode guarded apply added to the state.
    resources_added_to_state: tuple[str, ...] = ()
    #: True when sync mode refused to auto-apply a mutating plan.
    apply_aborted: bool = False
    #: Meraki deletions detected and alerted, awaiting confirmation.
    deletions_pending: tuple[str, ...] = ()
    #: Deletions removed from kit + state via --confirm-deletions.
    deletions_removed: tuple[str, ...] = ()
    #: Modified objects whose HCL baseline was regenerated (sync mode).
    regenerated_addresses: tuple[str, ...] = ()
    #: Racy pending imports pulled from this run's kit so the rest could
    #: apply; they import on the next run (sync mode).
    deferred_addresses: tuple[str, ...] = ()
    #: Share of discovered objects Terraform can rebuild, per manifest.
    coverage_percent: float = 100.0
    #: Resources reconciliation dropped because the provider rejects its
    #: own generated configuration (reported as unsupported).
    reconciliation_dropped: tuple[str, ...] = ()
    #: The same drops aggregated by diagnostic title → count, so a
    #: provider regression names the class it broke, not just a number.
    reconciliation_drop_categories: dict[str, int] = dataclasses.field(
        default_factory=dict
    )
    #: address → secret attributes excluded from management; the DR kit
    #: cannot carry them, restore manually after a rebuild.
    unmanaged_secret_attributes: dict[str, tuple[str, ...]] = dataclasses.field(
        default_factory=dict
    )
    #: Resources whose generated values were normalized to round-trip
    #: (state formatting/omissions or provider enum casing).
    normalized_addresses: tuple[str, ...] = ()
    #: Human summary of snapshot-vs-baseline drift (--drift-baseline),
    #: None when no baseline was supplied or nothing changed.
    snapshot_drift: str | None = None


class PipelineOrchestrator:
    """Executes the full meraki2tf cycle against injected components."""

    #: Bounded Meraki-is-truth regeneration rounds per sync run. Each
    #: round converts the previous round's clickops edits into clean
    #: imports; the cap (plus the no-new-addresses progress guard)
    #: keeps a busy organization from looping the run forever.
    _MAX_HEAL_ROUNDS = 3
    #: Bounded deferral rounds after the heal budget is spent: racy
    #: pending imports are pulled from the kit so the import-only
    #: remainder applies (monotone state growth); they import next run.
    _MAX_DEFER_ROUNDS = 2
    #: Chunk size for batched state materialization. A full-kit plan
    #: over tens of thousands of resources is a multi-hour sampling
    #: window that a busy organization races with fresh clickops edits;
    #: a chunk this size plans in minutes, making the per-window race
    #: probability small instead of near-certain.
    _MATERIALIZE_CHUNK_SIZE = 1000

    def __init__(
        self,
        provider: MerakiDataProvider,
        generator: HclImportGenerator,
        runner: TerraformRunner,
        dispatcher: AlertDispatcher,
        rebaseline: bool = False,
        sync: bool = False,
        confirm_deletions: bool = False,
        drift_baseline: Any = None,
    ) -> None:
        self._provider = provider
        self._generator = generator
        self._runner = runner
        self._dispatcher = dispatcher
        self._rebaseline = rebaseline
        self._sync = sync
        self._confirm_deletions = confirm_deletions
        #: Optional prior snapshot: API-to-API drift detection right
        #: after discovery, independent of the terraform comparison.
        self._drift_baseline = drift_baseline
        #: Addresses already alerted as unsupported by reconciliation
        #: this run — regeneration re-plans must not duplicate alerts.
        self._reconciliation_alerted: set[str] = set()

    def run(self, organization_id: str | None = None) -> RunSummary:
        # Terraform locks only its state; the DR kit itself has none, so
        # two overlapping runs on one workdir would clobber each other and
        # could leave a coverage manifest vouching for resources absent
        # from imports.tf (Cardinal Rule 2). Take an exclusive workdir lock
        # for the whole run and refuse a second concurrent kit-writing run.
        # On contention nothing in the workdir is touched, so the holding
        # run keeps sole ownership — and the refusal is an expected
        # preflight, not a fault (no PROCESSING_FAULT alert, no traceback).
        lock = WorkdirLock(self._runner.workdir)
        try:
            lock.acquire()
        except WorkdirLockError as exc:
            raise PreflightRefusalError(str(exc)) from exc
        try:
            return self._run(organization_id)
        finally:
            lock.release()

    def _run(self, organization_id: str | None = None) -> RunSummary:
        stage = "startup"
        try:
            if self._rebaseline:
                # Both refusal conditions are knowable now; a live
                # discovery pass costs minutes of API budget, so refuse
                # before spending it. reset_baseline re-checks at the
                # actual reset (belt-and-suspenders).
                stage = "rebaseline preflight"
                if not api_key_present():
                    raise PreflightRefusalError(
                        f"--rebaseline requires {API_KEY_ENV_VAR} to be "
                        "set: the configuration baseline is regenerated "
                        "by the terraform plan comparison, which is "
                        "skipped without an API key, so the baseline "
                        "would be lost."
                    )
                self._runner.prepare_workspace()
                try:
                    self._runner.ensure_baseline_resettable(
                        self._runner.existing_addresses()
                    )
                except TerraformError as exc:
                    raise PreflightRefusalError(str(exc)) from exc

            stage = "configuration discovery"
            with self._provider as provider:
                graph = provider.fetch_network_graph(organization_id)
            # Live discovery hands back side facts (suspect endpoints,
            # prefilter skips) for the coverage manifest; dump providers
            # have none.
            diagnostics = getattr(self._provider, "discovery_diagnostics", None)
            # Dump-mode runs learn their organization only here; stamp
            # the dispatcher so every subsequent alert is attributable.
            self._dispatcher.organization_id = graph.organization_id
            # A partial (--only) snapshot input stamps every artifact
            # of this run — the manifest/runbook then describe a scope,
            # not the organization (Cardinal Rule 2). Live providers
            # carry no snapshot_scope.
            partial = getattr(self._provider, "snapshot_scope", None)
            scope_networks = (
                tuple(partial.network_ids) if partial is not None else None
            )
            logger.info(
                "Discovered %d asset(s) for organization %s via %s mode.",
                graph.asset_count(), graph.organization_id, self._provider.mode,
            )

            pending_drift: tuple[str, str] | None = None
            if self._drift_baseline is not None:
                stage = "snapshot drift comparison"
                pending_drift = self._compare_snapshot_baseline(graph)
            snapshot_drift = pending_drift[0] if pending_drift else None

            stage = "workspace preparation"
            self._runner.prepare_workspace()

            stage = "state inspection"
            existing = self._runner.existing_addresses()
            self._guard_state_organization(graph)
            if existing:
                logger.info(
                    "%d resource(s) already tracked in state; only the delta "
                    "will be imported.",
                    len(existing),
                )
                if not self._runner.has_config_baseline():
                    logger.warning(
                        "State tracks %d resource(s) but the workspace has no "
                        "accumulated configuration baseline (resources.tf); "
                        "the plan will propose destroying them. Restore "
                        "resources.tf from your DR backup or reset the state.",
                        len(existing),
                    )

            if self._rebaseline:
                stage = "baseline reset"
                self._runner.reset_baseline(existing)

            stage = "HCL construction"
            report = self._generator.generate(
                graph, self._runner.workdir, existing_addresses=existing
            )

            # A Duplicate Set Element that breaks the provider's own
            # Read fails before terraform generates any configuration,
            # so the plan loop cannot attribute it from config text —
            # only the discovered payloads still carry the duplicate.
            self._runner.set_duplicate_value_locator(
                _payload_duplicate_locator(graph, report)
            )

            stage = "coverage audit"
            if report.unsupported:
                logger.warning(
                    "%d asset(s) cannot be expressed by the Terraform provider "
                    "and would need MANUAL rebuild in a DR event: %s",
                    len(report.unsupported),
                    cap_log_enumeration(
                        [
                            f"{item.api_path} "
                            f"(ids={','.join(item.identifiers) or '<none>'})"
                            for item in report.unsupported
                        ]
                    ),
                )
            logger.info(
                "Terraform coverage: %d/%d discovered asset(s) captured "
                "(%d new import block(s), %d already tracked in state), "
                "%d unsupported.",
                report.imports_written + report.skipped_existing,
                graph.asset_count(),
                report.imports_written,
                report.skipped_existing,
                len(report.unsupported),
            )
            unsupported_details = unsupported_payload(report.unsupported)
            if pending_drift is not None:
                stage = "snapshot drift alert"
                self._dispatch_snapshot_drift(
                    pending_drift, unsupported_details
                )

            stage = "deletion review"
            deletions_pending: tuple[str, ...]
            deletions_removed: tuple[str, ...]
            if scope_networks is not None:
                # A scoped (--only) run discovers only its networks, so
                # absence from this run's capture proves nothing about
                # deletion: out-of-scope state stays untouched — never
                # flagged, alerted, or removed — and the pending-
                # deletions review record of full runs is left as-is.
                deletions_pending, deletions_removed = (), ()
                out_of_scope = tuple(
                    sorted(existing - report.captured_addresses)
                )
                if out_of_scope:
                    logger.info(
                        "Scoped run: deletion review skipped; %d state-"
                        "tracked resource(s) not captured this run are "
                        "out-of-scope (or scope-undetermined), not "
                        "missing: %s",
                        len(out_of_scope), ", ".join(out_of_scope),
                    )
            else:
                deletions_pending, deletions_removed = (
                    self._review_deletions(existing, report)
                )

            drift = False
            pending_imports: int | None = None
            added: tuple[str, ...] = ()
            apply_aborted = False
            regenerated: tuple[str, ...] = ()
            deferred: tuple[str, ...] = ()
            recon_dropped: tuple[str, ...] = ()
            recon_drop_categories: dict[str, int] = {}
            unmanaged_secrets: dict[str, tuple[str, ...]] = {}
            normalized_addresses: tuple[str, ...] = ()
            self._reconciliation_alerted.clear()
            comparison_skipped = not api_key_present()
            if comparison_skipped:
                # The Meraki provider needs a token to read live resources
                # during plan; without one (offline/air-gapped dump runs)
                # the generated artifacts are still the full deliverable.
                logger.info(
                    "%s is not set; skipping the read-only terraform plan "
                    "comparison. Import blocks and previously generated "
                    "resources remain the disaster-recovery artifacts.",
                    API_KEY_ENV_VAR,
                )
            else:
                stage = "terraform init"
                self._runner.init()

                stage = "state comparison"
                # A scoped run plans exactly the captured (in-scope)
                # addresses: out-of-scope kit/state resources are never
                # read, drifted, or (in sync mode) imported/mutated.
                scope_targets = (
                    scoped_plan_targets(report.captured_addresses)
                    if scope_networks is not None
                    else None
                )
                plan = self._runner.plan_with_generation(
                    save_plan=self._sync, targets=scope_targets
                )
                stage = "plan reconciliation audit"
                report, unsupported_details = self._report_reconciliation(
                    plan, report
                )
                counts = plan.plan_counts
                if counts is not None:
                    pending_imports = counts.imports
                    logger.info(
                        "Plan summary: %d to import (pending state "
                        "aggregation), %d to add, %d to change, %d to destroy.",
                        counts.imports, counts.add, counts.change, counts.destroy,
                    )
                drift = plan.has_drift
                if drift:
                    logger.warning(
                        "Configuration drift detected; dispatching "
                        "DRIFT_DETECTED alert."
                    )
                    # Same masking the alert payloads get: the log is a
                    # transport too, and a debug run must not be the one
                    # place a secret-named value survives unredacted.
                    logger.debug(
                        "Full drift diff:\n%s",
                        redact_diff(condense_diff(plan.stdout)),
                    )
                    if self._sync:
                        stage = "sync drift handling"
                        (
                            plan,
                            report,
                            regenerated,
                            deferred,
                            apply_aborted,
                        ) = self._handle_sync_drift(
                            plan, graph, report, unsupported_details,
                            scoped=scope_networks is not None,
                        )
                        # regeneration re-plans, so reconciliation may
                        # have dropped/suppressed again — re-audit.
                        report, unsupported_details = (
                            self._report_reconciliation(plan, report)
                        )
                        counts = plan.plan_counts
                        if counts is not None:
                            pending_imports = counts.imports
                    else:
                        self._dispatcher.dispatch(
                            drift_detected(
                                diff=plan.stdout,
                                workspace=str(self._runner.workdir),
                                unsupported=unsupported_details,
                            )
                        )
                else:
                    logger.info("State comparison found no drift.")

                if self._sync and plan.has_changes:
                    stage = "state materialization (guarded import-only apply)"
                    if not apply_aborted and not plan.has_drift:
                        # Converged full plan: one guarded apply covers
                        # everything.
                        added, apply_aborted = self._materialize_state(
                            unsupported_details
                        )
                        if added:
                            pending_imports = 0
                    else:
                        # The full plan still carries update pressure (a
                        # busy org races every multi-hour window): bank
                        # each clean import through short targeted
                        # windows instead of waiting for one globally
                        # clean plan that may never come.
                        stage = (
                            "state materialization (guarded targeted applies)"
                        )
                        added, batch_deferred, pending_imports = (
                            self._materialize_state_batched(
                                report, plan, deferred, unsupported_details
                            )
                        )
                        deferred = tuple(
                            dict.fromkeys((*deferred, *batch_deferred))
                        )

                recon_dropped = tuple(sorted(plan.dropped))
                recon_drop_categories = drop_reason_categories(plan.dropped)
                unmanaged_secrets = dict(sorted(plan.ignored_secrets.items()))
                normalized_addresses = tuple(sorted(plan.normalized))

            stage = "coverage manifest"
            # Union in a direct payload scan: the plan only mentions
            # secrets until the resources are in state, and air-gapped
            # runs never plan — the manifest, notification, and summary
            # must report the same stable set the runbook does.
            unmanaged_secrets = secret_attribute_union(
                report.captured, unmanaged_secrets, payload_index(graph)
            )
            final_state = self._runner.existing_addresses()
            # The direct-API restore verdict for every asset — computed
            # offline from spec + snapshot, so the weekly manifest
            # answers "will the API rebuild it?" alongside "will
            # Terraform import it?".
            from meraki2tf.restorer import plan_restore, restore_verdicts

            restore_via = restore_verdicts(
                plan_restore(graph, self._generator.parser)
            )
            surfaces = self._generator.spec_surfaces()
            manifest = build_manifest(
                organization_id=graph.organization_id,
                captured=report.captured,
                unsupported=report.unsupported,
                state_addresses=final_state,
                deletions_pending=deletions_pending,
                unmanaged_secret_attributes=unmanaged_secrets,
                restore_via=restore_via,
                scope_networks=scope_networks,
                duplicates=report.duplicates,
                discovered_assets=graph.asset_count(),
                spec_gap_count=report.spec_gap_count,
                relationship_gap_count=report.relationship_gap_count,
                excluded_rpc_paths=surfaces.rpc_only_paths,
                api_read_only_paths=surfaces.api_read_only_paths,
                suspect_endpoints=(
                    diagnostics.suspect_endpoints
                    if diagnostics is not None
                    else ()
                ),
            )
            write_manifest(manifest, self._runner.workdir)
            coverage_percent = float(manifest["coverage_percent"])

            stage = "DR runbook"
            write_runbook(
                workdir=self._runner.workdir,
                organization_id=graph.organization_id,
                graph=graph,
                captured=report.captured,
                unsupported=report.unsupported,
                unmanaged_secret_attributes=unmanaged_secrets,
                parser=self._generator.parser,
                scope_networks=scope_networks,
            )

            logger.info(
                "Snapshot generation complete; dispatching RUN_SUCCESS "
                "notification. The Meraki organization was not modified — "
                "every run is read-only toward Meraki."
            )
            self._dispatcher.dispatch(
                run_success(
                    imports_written=report.imports_written,
                    drift_was_detected=drift,
                    workspace=str(self._runner.workdir),
                    discovered_assets=graph.asset_count(),
                    imports_already_tracked=report.skipped_existing,
                    unsupported=unsupported_details,
                    pending_imports=pending_imports,
                    comparison_performed=not comparison_skipped,
                    resources_added_to_state=added,
                    coverage_percent=coverage_percent,
                    deletions_pending=deletions_pending,
                    unmanaged_secret_attributes=unmanaged_secrets,
                    deferred_addresses=deferred,
                    reconciliation_drop_categories=recon_drop_categories,
                    partial_scope=scope_networks or (),
                )
            )
            return RunSummary(
                organization_id=graph.organization_id,
                discovered_assets=graph.asset_count(),
                imports_written=report.imports_written,
                imports_skipped_existing=report.skipped_existing,
                # Discovered objects Terraform cannot rebuild. Spec-level
                # write-only findings are permanent API facts, not run
                # findings — counting them here would wedge the
                # --fail-on-gaps scheduler gate at exit 3 forever; they
                # stay visible in the manifest, runbook, and alerts.
                unsupported_count=(
                    len(report.unsupported) - report.spec_gap_count
                ),
                drift_detected=drift,
                comparison_skipped=comparison_skipped,
                pending_imports=pending_imports,
                resources_added_to_state=added,
                apply_aborted=apply_aborted,
                deletions_pending=deletions_pending,
                deletions_removed=deletions_removed,
                regenerated_addresses=regenerated,
                deferred_addresses=deferred,
                coverage_percent=coverage_percent,
                reconciliation_dropped=recon_dropped,
                reconciliation_drop_categories=recon_drop_categories,
                unmanaged_secret_attributes=unmanaged_secrets,
                normalized_addresses=normalized_addresses,
                snapshot_drift=snapshot_drift,
            )
        except PreflightRefusalError:
            raise  # an expected refusal, not a fault — no alert, no traceback
        except (ScopeFilterError, CheckpointMismatchError) as exc:
            # Operator input errors surfaced mid-startup (a --only
            # selector matching no network, a stale/foreign discovery
            # checkpoint): refuse cleanly like the other preflights —
            # nothing broke, so no PROCESSING_FAULT alert.
            raise PreflightRefusalError(str(exc)) from exc
        except Exception as exc:
            # The one-line ERROR is the operator-facing record; the
            # traceback is debugging detail — a gracefully-handled
            # fault (an unreachable backend, a dead endpoint) must not
            # spray a stack trace over every scheduled-run log.
            logger.error("Pipeline fault during %s: %s", stage, exc)
            logger.debug("Pipeline fault traceback:", exc_info=True)
            self._dispatcher.dispatch(processing_fault(stage=stage, error=str(exc)))
            raise PipelineError(f"Pipeline failed during {stage}: {exc}") from exc
        finally:
            # The saved sync plan embeds refreshed sensitive values just
            # like the state file. Applies consume-and-delete it, but any
            # path that plans and then never applies (aborted heal,
            # skipped window, converged plan, fault) must not leave a
            # third secret-bearing artifact in the workspace.
            self._runner.discard_saved_plan()

    def _report_reconciliation(
        self, plan: ReconciledPlanResult, report: GenerationReport
    ) -> tuple[GenerationReport, list[dict[str, Any]]]:
        """Fold reconciliation outcomes into the coverage picture.

        Resources dropped because the provider rejects its own generated
        configuration move from *captured* to *unsupported* — they are
        part of the manual-rebuild runbook (Cardinal Rule 2) and get the
        mandated UNSUPPORTED_FEATURE_FLAGGED alert exactly once per run.
        """
        if plan.dropped:
            dropped_assets = tuple(
                asset for asset in report.captured if asset.address in plan.dropped
            )
            flagged: list[UnsupportedAsset] = []
            for asset in dropped_assets:
                reason = (
                    "Provider cannot express this configuration: "
                    f"{plan.dropped[asset.address]}"
                )
                # Raw path values, not the import ID: the import ID may
                # carry injected org-prefix/force_delete components, and
                # the coverage manifest's restore_via join is keyed on
                # the discovered path values.
                identifiers = asset.identifiers or tuple(
                    asset.import_id.split(",")
                )
                flagged.append(
                    UnsupportedAsset(
                        api_path=asset.api_path,
                        reason=reason,
                        identifiers=identifiers,
                    )
                )
                if asset.address not in self._reconciliation_alerted:
                    logger.error(
                        "UNSUPPORTED FEATURE: %s (ids=%s) — %s",
                        asset.api_path, ",".join(identifiers), reason,
                    )
                    self._dispatcher.dispatch(
                        unsupported_feature_flagged(
                            api_path=asset.api_path,
                            reason=reason,
                            identifiers=identifiers,
                        )
                    )
                    self._reconciliation_alerted.add(asset.address)
            logger.warning(
                "Unexpressible drop categories: %s",
                "; ".join(
                    f"{count} × {title}"
                    for title, count in drop_reason_categories(
                        plan.dropped
                    ).items()
                ),
            )
            report = dataclasses.replace(
                report,
                captured=tuple(
                    asset
                    for asset in report.captured
                    if asset.address not in plan.dropped
                ),
                unsupported=report.unsupported + tuple(flagged),
                # Drops accumulate across the whole plan loop while a
                # heal regeneration rewrites a much smaller kit, so the
                # subtraction can undershoot; a negative "imports
                # written" is meaningless to report — floor at zero (the
                # coverage manifest carries the exact per-asset truth).
                imports_written=max(
                    0,
                    report.imports_written
                    - sum(
                        1
                        for asset in dropped_assets
                        if not asset.already_in_state
                    ),
                ),
            )
        if plan.ignored_secrets:
            logger.warning(
                "%d resource(s) hold secret attributes the DR kit cannot "
                "carry (%s); restore them manually after any rebuild.",
                len(plan.ignored_secrets),
                "; ".join(
                    f"{address}: {', '.join(attrs)}"
                    for address, attrs in sorted(plan.ignored_secrets.items())
                ),
            )
        return report, unsupported_payload(report.unsupported)

    def _load_alerted_deletions(self) -> frozenset[str]:
        """The deletion addresses a previous run alerted the operator on."""
        path = self._runner.workdir / PENDING_DELETIONS_FILENAME
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            addresses = payload["addresses"]
            if not isinstance(addresses, list):
                raise TypeError("'addresses' is not a list")
        except FileNotFoundError:
            return frozenset()
        except (OSError, json.JSONDecodeError, TypeError, KeyError) as exc:
            # An unreadable reviewed set must not authorize removals:
            # degrade to "nothing was reviewed" so everything missing is
            # re-alerted instead of removed on a corrupt file.
            logger.warning(
                "Pending-deletion record %s is unreadable (%s); treating "
                "no deletions as reviewed — they will be re-alerted.",
                path, exc,
            )
            return frozenset()
        return frozenset(str(address) for address in addresses)

    def _persist_alerted_deletions(self, addresses: tuple[str, ...]) -> None:
        """Record (or clear) the alerted set the next confirmation covers.

        Atomic like every other artifact: this file *authorizes* future
        removals, so a torn write must never leave a half-list a
        ``--confirm-deletions`` run would act on (the reader degrades a
        corrupt file to "nothing reviewed", losing the review instead).
        """
        path = self._runner.workdir / PENDING_DELETIONS_FILENAME
        if not addresses:
            path.unlink(missing_ok=True)
            return
        atomic_write_text(
            path,
            json.dumps({"addresses": sorted(addresses)}, indent=2) + "\n",
        )

    def _guard_state_organization(self, graph: NetworkGraph) -> None:
        """Refuse a Terraform state belonging to a different organization
        than the one just discovered (round-9 finding G1).

        The state-inspection path keys tracked resources by address
        string (``type.name``) alone; a foreign organization's state
        whose addresses collide — trivially true between two sanitized
        kits, which share the ``net_0001`` pseudonym space — would report
        every asset "already imported", write a clean ``coverage.json``,
        and fire RUN_SUCCESS while the state actually holds another
        organization's resource IDs and cannot rebuild THIS one. Meraki
        is never contacted on an offline weekly run, so nothing corrects
        it — the "what is covered?" answer is silently wrong.

        The state's organization is resolved from the same
        ``organization_id`` attribute ``--rebuild`` / ``--expect-org``
        already trust (unanimous across managed instances). A fresh or
        ambiguous state names no organization and is allowed through so
        the legitimate first run still works. Being attribute-based, this
        also catches a foreign disjoint state (finding G3) before it is
        misread as a mass deletion.
        """
        state_org = self._runner.state_organization()
        if state_org is None:
            return
        discovered = str(graph.organization_id or "").strip()
        if discovered and state_org != discovered:
            raise TerraformError(
                f"Terraform state belongs to organization {state_org} but "
                f"this run discovered organization {discovered} — wrong "
                "--state-file/--workdir? Refusing to avoid a false coverage "
                "report."
            )

    def _review_deletions(
        self, existing: frozenset[str], report: GenerationReport
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Handle state-tracked resources discovery no longer sees in Meraki.

        Alert-only by default: an accidental clickops deletion must not
        quietly poison the rebuild baseline, so nothing is removed until
        a human passes ``--confirm-deletions`` — and even then only the
        addresses a DELETION_PENDING_CONFIRMATION alert already carried
        (persisted in the workdir). Anything that went missing *after*
        the alert is a new event: it is alerted, recorded as the next
        reviewed set, and left untouched this run.

        Resources whose endpoint could not be *read* this run are
        indistinguishable from deletions by absence alone — a transient
        5xx during discovery must not flag (or, worse, remove via
        ``--confirm-deletions``) hundreds of live objects. Tracked
        resources of unreadable types are therefore exempt until a run
        that reads their endpoint cleanly.
        """
        missing = existing - report.captured_addresses
        deleted = frozenset(
            address
            for address in missing
            if address.split(".", 1)[0] not in report.unreadable_types
        )
        exempt = missing - deleted
        if exempt:
            logger.warning(
                "%d state-tracked resource(s) were not discovered, but "
                "their endpoint(s) were unreadable this run — deletion "
                "review is deferred until the endpoint reads cleanly: %s",
                len(exempt), ", ".join(sorted(exempt)),
            )
        if not deleted:
            # Nothing is missing anymore (recreated, or the absence was
            # transient): a stale reviewed set must not authorize a
            # removal on some later run.
            self._persist_alerted_deletions(())
            return (), ()
        # Finding G3: every tracked resource vanishing in one run is the
        # fingerprint of a foreign/mis-pointed state, not a real mass
        # deletion. Attach a verify-the-state note to the alert (the org
        # guard already refuses the case where the state names a
        # different org; this covers a disjoint state with no org to
        # compare). Deletion semantics are unchanged.
        note = FOREIGN_STATE_DELETION_NOTE if deleted == existing else None
        if self._confirm_deletions:
            alerted = self._load_alerted_deletions()
            confirmed = tuple(sorted(deleted & alerted))
            unalerted = tuple(sorted(deleted - alerted))
            if confirmed:
                logger.warning(
                    "Removing %d human-confirmed deletion(s) from the DR "
                    "kit and state (alerted for review on a previous run): "
                    "%s",
                    len(confirmed), ", ".join(confirmed),
                )
                self._runner.init()  # `state rm` needs an initialized backend
                self._runner.remove_resources(frozenset(confirmed))
            if unalerted:
                logger.warning(
                    "%d deletion(s) were first seen on this run and are NOT "
                    "covered by --confirm-deletions (the operator reviewed "
                    "an earlier alert, not these): %s. Alert-only — re-run "
                    "with --confirm-deletions after review to remove them.%s",
                    len(unalerted), ", ".join(unalerted),
                    f" {note}" if note else "",
                )
                self._dispatcher.dispatch(
                    deletion_pending_confirmation(
                        addresses=unalerted,
                        workspace=str(self._runner.workdir),
                        note=note,
                    )
                )
            self._persist_alerted_deletions(unalerted)
            return unalerted, confirmed
        pending = tuple(sorted(deleted))
        logger.warning(
            "%d resource(s) tracked in the DR kit were not discovered in "
            "Meraki (deleted?): %s. Alert-only — re-run with "
            "--confirm-deletions after review to remove them.%s",
            len(pending), ", ".join(pending),
            f" {note}" if note else "",
        )
        self._dispatcher.dispatch(
            deletion_pending_confirmation(
                addresses=pending, workspace=str(self._runner.workdir),
                note=note,
            )
        )
        self._persist_alerted_deletions(pending)
        return pending, ()

    def _handle_sync_drift(
        self,
        plan: ReconciledPlanResult,
        graph: NetworkGraph,
        report: GenerationReport,
        unsupported_details: list[dict[str, Any]],
        scoped: bool = False,
    ) -> tuple[
        ReconciledPlanResult,
        GenerationReport,
        tuple[str, ...],
        tuple[str, ...],
        bool,
    ]:
        """DR-mode drift decision: regenerate modified objects, abort the rest.

        Meraki is the source of truth, so purely *modified* objects get
        their HCL baseline regenerated via local state surgery
        (``state rm`` + baseline prune + re-import — Meraki untouched).
        Any other mutation (creates from Meraki deletions, destroys from
        baseline corruption, replaces, or an unclassifiable plan) aborts
        the auto-apply and leaves the decision to a human.

        On an actively-administered organization, new clickops edits land
        while each multi-hour plan round runs — a single regeneration
        pass would race those edits forever and the weekly job would
        never materialize state. The regen cycle therefore repeats up to
        ``_MAX_HEAL_ROUNDS`` times, but only while it makes progress:
        a round whose modified set contains nothing new means the last
        regeneration did not take, and a human must look.

        When the heal budget is spent and everything still drifting is
        update-only on *not-yet-imported* resources, those few are
        deferred — pulled from this run's kit so the import-only
        remainder can apply (monotone state growth); they import on the
        next run. Tracked-resource drift and non-update mutations are
        never deferred.

        Returns ``(plan, report, regenerated_addresses,
        deferred_addresses, apply_aborted)``.
        """
        workspace = str(self._runner.workdir)
        regenerated: list[str] = []
        for _ in range(self._MAX_HEAL_ROUNDS):
            actions = self._runner.plan_resource_actions()
            mutated = {
                address: acts
                for address, acts in actions.items()
                if not set(acts) <= _HARMLESS_ACTIONS
            }
            modified = tuple(
                sorted(
                    address
                    for address, acts in mutated.items()
                    if acts == ("update",)
                )
            )
            blocking = {
                address: acts
                for address, acts in mutated.items()
                if acts != ("update",)
            }
            if blocking or not modified:
                logger.error(
                    "Sync full-kit auto-apply ABORTED: the plan proposes "
                    "mutations that cannot be resolved by baseline "
                    "regeneration (%s). A human must review the drift "
                    "alert; import-only chunks may still be applied "
                    "through targeted windows this run.",
                    ", ".join(
                        f"{address}={'+'.join(acts)}"
                        for address, acts in sorted(blocking.items())
                    )
                    or "unclassifiable plan",
                )
                self._dispatcher.dispatch(
                    drift_detected(
                        diff=plan.stdout,
                        workspace=workspace,
                        unsupported=unsupported_details,
                        apply_aborted=True,
                        regenerated_addresses=tuple(regenerated),
                    )
                )
                return plan, report, tuple(regenerated), (), True
            if not set(modified) - set(regenerated):
                # Every drifting resource was already regenerated this
                # run: the regeneration did not take, so another round
                # would loop, not converge. Deferral is the remaining
                # move before a human has to look.
                logger.warning(
                    "Drift persists on already-regenerated resource(s) "
                    "(%s); attempting deferral.",
                    ", ".join(modified),
                )
                break
            logger.warning(
                "Meraki is truth: regenerating the HCL baseline for %d "
                "modified resource(s): %s",
                len(modified), ", ".join(modified),
            )
            self._dispatcher.dispatch(
                drift_detected(
                    diff=plan.stdout,
                    workspace=workspace,
                    unsupported=unsupported_details,
                    regenerated_addresses=modified,
                )
            )
            self._runner.remove_resources(modified)
            refreshed = self._runner.existing_addresses()
            report = self._generator.generate(
                graph,
                self._runner.workdir,
                existing_addresses=refreshed,
                audit=False,
                suppress_addresses=frozenset(plan.dropped),
            )
            # Regeneration just returned the modified addresses to
            # pending, so the set is normally non-empty; `or None`
            # makes the degenerate full replan an explicit choice —
            # except on a scoped run, where an untargeted replan would
            # pull out-of-scope kit/state into the saved plan: there
            # the fallback stays targeted at the captured (in-scope)
            # set instead.
            replan_targets: tuple[str, ...] | None = self._pending_targets(
                report, plan
            )
            if not replan_targets:
                replan_targets = (
                    scoped_plan_targets(report.captured_addresses)
                    if scoped
                    else None
                )
            plan = self._runner.plan_with_generation(
                save_plan=True,
                targets=replan_targets,
            ).merged_with_earlier(plan)
            regenerated.extend(modified)
            if not plan.has_drift:
                return plan, report, tuple(regenerated), (), False
        plan, deferred, defer_aborted = self._defer_racy_pending(
            plan, report, unsupported_details, tuple(regenerated), workspace
        )
        if not defer_aborted:
            return plan, report, tuple(regenerated), deferred, False
        logger.error(
            "Drift persists after %d baseline regeneration round(s) and "
            "deferral; aborting the full-kit sync auto-apply for human "
            "review. Import-only chunks may still be applied through "
            "targeted windows this run.",
            self._MAX_HEAL_ROUNDS,
        )
        self._dispatcher.dispatch(
            drift_detected(
                diff=plan.stdout,
                workspace=workspace,
                unsupported=unsupported_details,
                apply_aborted=True,
                regenerated_addresses=tuple(regenerated),
                deferred_addresses=deferred,
            )
        )
        return plan, report, tuple(regenerated), deferred, True

    def _pending_targets(
        self,
        report: GenerationReport,
        plan: ReconciledPlanResult,
        extra_excluded: tuple[str, ...] = (),
    ) -> tuple[str, ...]:
        """Addresses still pending import — the only resources a heal or
        deferral replan needs to verify (the run's first, untargeted
        plan already took the full-kit drift picture)."""
        tracked = self._runner.existing_addresses()
        excluded = set(plan.dropped) | set(extra_excluded)
        return tuple(
            sorted(
                asset.address
                for asset in report.captured
                if asset.address not in tracked
                and asset.address not in excluded
            )
        )

    def _defer_racy_pending(
        self,
        plan: ReconciledPlanResult,
        report: GenerationReport,
        unsupported_details: list[dict[str, Any]],
        regenerated: tuple[str, ...],
        workspace: str,
    ) -> tuple[ReconciledPlanResult, tuple[str, ...], bool]:
        """Pull racy pending imports from the kit so the rest can apply.

        Eligible only when every remaining mutation is an update on a
        resource that is *not yet in state* — those cannot poison
        anything by waiting one more run, whereas blocking their 22k
        import-only siblings forever starves the weekly job. Tracked
        drift and non-update mutations abort as before.

        Returns ``(plan, deferred_addresses, aborted)``.
        """
        tracked = self._runner.existing_addresses()
        deferred: list[str] = []
        for _ in range(self._MAX_DEFER_ROUNDS):
            actions = self._runner.plan_resource_actions()
            mutated = {
                address: acts
                for address, acts in actions.items()
                if not set(acts) <= _HARMLESS_ACTIONS
            }
            racy = tuple(
                sorted(
                    address
                    for address, acts in mutated.items()
                    if acts == ("update",) and address not in tracked
                )
            )
            blocking = {
                address: acts
                for address, acts in mutated.items()
                if acts != ("update",) or address in tracked
            }
            if blocking or not racy:
                return plan, tuple(deferred), True
            if not set(racy) - set(deferred):
                # Deferral removed these from the kit yet they still
                # plan as updates — the surgery did not take; a human
                # must look rather than loop.
                return plan, tuple(deferred), True
            logger.warning(
                "Deferring %d drift-racy pending import(s) so the "
                "import-only remainder can apply this run: %s",
                len(racy), ", ".join(racy),
            )
            self._dispatcher.dispatch(
                drift_detected(
                    diff=plan.stdout,
                    workspace=workspace,
                    unsupported=unsupported_details,
                    regenerated_addresses=regenerated,
                    deferred_addresses=racy,
                )
            )
            self._runner.defer_resources(frozenset(racy))
            deferred.extend(racy)
            remaining = self._pending_targets(report, plan, tuple(deferred))
            if not remaining:
                # Deferral removed every remaining pending import;
                # replanning would degenerate to a full untargeted plan
                # (the multi-hour race window targeting exists to
                # close) just to confirm there is nothing left. The
                # saved plan predates the deferral surgery, so it must
                # not survive to the guarded apply; downstream, batched
                # materialization sees zero pending imports and
                # finishes immediately.
                self._runner.discard_saved_plan()
                return plan, tuple(deferred), False
            plan = self._runner.plan_with_generation(
                save_plan=True,
                targets=remaining,
            ).merged_with_earlier(plan)
            if not plan.has_drift:
                return plan, tuple(deferred), False
        return plan, tuple(deferred), True

    def _materialize_state_batched(
        self,
        report: GenerationReport,
        plan: ReconciledPlanResult,
        already_deferred: tuple[str, ...],
        unsupported_details: list[dict[str, Any]],
    ) -> tuple[tuple[str, ...], tuple[str, ...], int]:
        """Bank clean imports through short targeted plan windows.

        Waiting for one globally clean full-kit plan is a race a busy
        organization wins: every multi-hour window catches a few fresh
        clickops edits somewhere in tens of thousands of resources.
        Chunked targeted plans shrink the window to minutes, so each
        chunk independently passes the import-only guard and applies. A
        chunk that catches an edit defers the racy pending import and
        retries once; a chunk that still is not pure imports is skipped
        and its resources stay honestly pending for the next run. State
        growth is monotone and nothing mutating is ever applied.

        Returns ``(added, deferred, still_pending_count)``.
        """
        tracked = self._runner.existing_addresses()
        excluded = set(plan.dropped) | set(already_deferred)
        pending = [
            asset.address
            for asset in report.captured
            if asset.address not in tracked and asset.address not in excluded
        ]
        size = self._MATERIALIZE_CHUNK_SIZE
        chunk_list = [pending[i:i + size] for i in range(0, len(pending), size)]
        logger.info(
            "Materializing state through %d targeted window(s) of up to %d "
            "import(s) each (%d pending).",
            len(chunk_list), size, len(pending),
        )
        added: list[str] = []
        deferred: list[str] = []
        skipped_members: list[str] = []
        skipped = 0
        for index, chunk in enumerate(chunk_list, start=1):
            chunk_added = self._apply_targeted_chunk(
                index, len(chunk_list), chunk, deferred, unsupported_details
            )
            if chunk_added is None:
                skipped += 1
                skipped_members.extend(chunk)
                continue
            added.extend(chunk_added)
        if skipped:
            logger.warning(
                "%d targeted window(s) could not be applied cleanly this "
                "run; their imports stay pending and import on the next run.",
                skipped,
            )
        # Genuinely still pending = deferred resources (they import on
        # the next run) plus every member of a skipped window. Members
        # of a COMPLETED window that were neither imported nor deferred
        # were already in state — their plan proposed nothing for them —
        # and counting them (the old `pending - added` arithmetic) kept
        # RUN_SUCCESS.pending_imports from ever converging to 0 on a
        # fully-imported organization.
        still_pending = len(dict.fromkeys((*deferred, *skipped_members)))
        logger.info(
            "Batched materialization added %d resource(s) to state "
            "(%d deferred, %d still pending).",
            len(added), len(deferred), still_pending,
        )
        return tuple(added), tuple(deferred), still_pending

    def _apply_targeted_chunk(
        self,
        index: int,
        total: int,
        chunk: list[str],
        deferred: list[str],
        unsupported_details: list[dict[str, Any]],
    ) -> tuple[str, ...] | None:
        """One targeted window: plan, guard, apply; defer-and-retry once.

        Returns the addresses applied, or ``None`` when the chunk was
        skipped (its resources stay pending).
        """
        workspace = str(self._runner.workdir)
        for attempt in range(2):
            result = self._runner.plan_targeted(chunk)
            counts = result.plan_counts
            if counts is None:
                logger.warning(
                    "Targeted window %d/%d produced no readable plan "
                    "summary; skipping it this run.", index, total,
                )
                return None
            if not counts.has_real_changes:
                if counts.imports == 0:
                    return ()
                try:
                    applied = self._runner.apply_import_plan()
                except ImportGuardViolation as exc:
                    logger.error(
                        "Targeted window %d/%d refused by the apply "
                        "guard: %s", index, total, exc,
                    )
                    self._dispatcher.dispatch(
                        drift_detected(
                            diff=exc.plan_output or str(exc),
                            workspace=workspace,
                            unsupported=unsupported_details,
                            apply_aborted=True,
                        )
                    )
                    return None
                logger.info(
                    "Targeted window %d/%d: %d import(s) applied.",
                    index, total, len(applied),
                )
                return applied
            if attempt == 0:
                tracked = self._runner.existing_addresses()
                actions = self._runner.plan_resource_actions()
                racy = tuple(
                    sorted(
                        address
                        for address, acts in actions.items()
                        if not set(acts) <= _HARMLESS_ACTIONS
                        and acts == ("update",)
                        and address not in tracked
                    )
                )
                if racy:
                    logger.warning(
                        "Targeted window %d/%d caught %d clickops-racy "
                        "pending import(s); deferring and retrying: %s",
                        index, total, len(racy), ", ".join(racy),
                    )
                    self._dispatcher.dispatch(
                        drift_detected(
                            diff=result.stdout,
                            workspace=workspace,
                            unsupported=unsupported_details,
                            deferred_addresses=racy,
                        )
                    )
                    self._runner.defer_resources(frozenset(racy))
                    deferred.extend(racy)
                    # The deferred addresses no longer exist in config
                    # or state; retrying with them still in -target
                    # would error the replan and skip the whole chunk.
                    chunk = [a for a in chunk if a not in set(racy)]
                    if not chunk:
                        return ()
                    continue
            logger.warning(
                "Targeted window %d/%d still proposes mutations after "
                "deferral; skipping it this run.", index, total,
            )
            return None
        return None  # pragma: no cover - every loop arm returns/continues

    def _compare_snapshot_baseline(
        self, graph: NetworkGraph
    ) -> tuple[str, str] | None:
        """API-to-API drift: fresh discovery vs the baseline snapshot.

        Sees drift classes the terraform comparison cannot (provider-
        inexpressible objects, secret values) in seconds, offline.

        Returns ``(summary, rendered diff)`` for
        :meth:`_dispatch_snapshot_drift`, or ``None`` when the org is
        unchanged. The comparison runs here — early, offline, before the
        expensive generation pass — but the alert cannot be sent until
        the coverage gaps it must carry are known.
        """
        from meraki2tf.snapshot_diff import baseline_drift, render_diff

        drift = baseline_drift(
            graph, self._drift_baseline, self._generator.parser
        )
        if drift.is_empty:
            logger.info("Snapshot drift vs baseline: none.")
            return None
        summary = drift.summary()
        logger.warning("Snapshot drift vs baseline (%s).", summary)
        return summary, render_diff(drift)

    def _dispatch_snapshot_drift(
        self,
        drift: tuple[str, str],
        unsupported_details: list[dict[str, Any]],
    ) -> None:
        """Send the snapshot-diff DRIFT_DETECTED alert with its gaps.

        Deliberately deferred until generation has classified the org:
        the drift alert is the WARNING-severity event that pages someone
        on a drifted week (RUN_SUCCESS is INFO and never pages), so it
        is the one payload that must carry the manual-rebuild list. Sent
        at comparison time it reported ``unsupported_count: 0`` on an
        organization with dozens of gaps — not an omission but a false
        statement, to the operator and to anything triaging the payload.
        """
        summary, diff = drift
        logger.warning(
            "Dispatching DRIFT_DETECTED alert for snapshot drift (%s) "
            "with %d coverage gap(s).", summary, len(unsupported_details),
        )
        self._dispatcher.dispatch(
            drift_detected(
                diff=diff,
                workspace=str(self._runner.workdir),
                unsupported=unsupported_details,
                origin="snapshot-diff",
            )
        )

    def _materialize_state(
        self, unsupported_details: list[dict[str, Any]]
    ) -> tuple[tuple[str, ...], bool]:
        """Run the guarded import-only apply; abort (never fail) on refusal.

        The guard lives in the runner itself — this wrapper only decides
        what an abort means for the run: dispatch the mandated drift
        alert with the offending plan and carry on read-only.
        """
        try:
            added = self._runner.apply_import_plan()
        except ImportGuardViolation as exc:
            logger.error("Guarded apply refused by the runner: %s", exc)
            self._dispatcher.dispatch(
                drift_detected(
                    diff=exc.plan_output or str(exc),
                    workspace=str(self._runner.workdir),
                    unsupported=unsupported_details,
                    apply_aborted=True,
                )
            )
            return (), True
        if added:
            logger.info(
                "State grew by %d resource(s) this run: %s",
                len(added), ", ".join(added),
            )
        return added, False


def _payload_duplicate_locator(
    graph: NetworkGraph, report: GenerationReport
) -> Any:
    """Resolver mapping duplicate-set literals to resource addresses.

    Captured assets carry the (api_path, identifiers) key straight back
    to the discovered payload, so a duplicated element the provider
    cannot decode is attributed by scanning those payloads — the only
    place it exists when the provider's Read fails before terraform
    generates configuration for the resource.
    """
    address_by_key = {
        (asset.api_path, asset.identifiers): asset.address
        for asset in report.captured
    }

    def locate(values: tuple[str, ...]) -> dict[str, str]:
        found: dict[str, str] = {}
        for feature in graph.features:
            address = address_by_key.get(
                (feature.api_path, feature.path_values)
            )
            if address is None:
                continue
            for value in values:
                if payload_carries_duplicate(feature.payload, value):
                    found.setdefault(address, duplicate_set_reason(value))
                    break
        return found

    return locate
