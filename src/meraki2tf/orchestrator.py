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

import logging
from dataclasses import dataclass
from typing import Any

from meraki2tf.alerts import (
    AlertDispatcher,
    deletion_pending_confirmation,
    drift_detected,
    processing_fault,
    run_success,
)
from meraki2tf.config import API_KEY_ENV_VAR, api_key_present
from meraki2tf.coverage import build_manifest, unsupported_payload, write_manifest
from meraki2tf.hcl_generator import GenerationReport, HclImportGenerator
from meraki2tf.models import NetworkGraph
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.terraform_runner import (
    ImportGuardViolation,
    TerraformCommandResult,
    TerraformError,
    TerraformRunner,
)

logger = logging.getLogger(__name__)

#: Plan actions that do not mutate anything (imports plan as no-op).
_HARMLESS_ACTIONS = frozenset({"no-op", "read"})


class PipelineError(RuntimeError):
    """The run failed; a PROCESSING_FAULT alert has already been dispatched."""


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
    #: Share of discovered objects Terraform can rebuild, per manifest.
    coverage_percent: float = 100.0


class PipelineOrchestrator:
    """Executes the full meraki2tf cycle against injected components."""

    def __init__(
        self,
        provider: MerakiDataProvider,
        generator: HclImportGenerator,
        runner: TerraformRunner,
        dispatcher: AlertDispatcher,
        rebaseline: bool = False,
        sync: bool = False,
        confirm_deletions: bool = False,
    ) -> None:
        self._provider = provider
        self._generator = generator
        self._runner = runner
        self._dispatcher = dispatcher
        self._rebaseline = rebaseline
        self._sync = sync
        self._confirm_deletions = confirm_deletions

    def run(self, organization_id: str | None = None) -> RunSummary:
        stage = "startup"
        try:
            stage = "configuration discovery"
            with self._provider as provider:
                graph = provider.fetch_network_graph(organization_id)
            logger.info(
                "Discovered %d asset(s) for organization %s via %s mode.",
                graph.asset_count(), graph.organization_id, self._provider.mode,
            )

            stage = "workspace preparation"
            self._runner.prepare_workspace()

            stage = "state inspection"
            existing = self._runner.existing_addresses()
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
                if not api_key_present():
                    # The plan comparison is the only path that regenerates
                    # resources.tf; discarding it in a keyless run would
                    # destroy the DR baseline with nothing to rebuild it.
                    raise TerraformError(
                        f"--rebaseline requires {API_KEY_ENV_VAR} to be set: "
                        "the configuration baseline is regenerated by the "
                        "terraform plan comparison, which is skipped without "
                        "an API key, so the baseline would be lost."
                    )
                self._runner.reset_baseline(existing)

            stage = "HCL construction"
            report = self._generator.generate(
                graph, self._runner.workdir, existing_addresses=existing
            )

            stage = "coverage audit"
            if report.unsupported:
                logger.warning(
                    "%d asset(s) cannot be expressed by the Terraform provider "
                    "and would need MANUAL rebuild in a DR event: %s",
                    len(report.unsupported),
                    "; ".join(
                        f"{item.api_path} "
                        f"(ids={','.join(item.identifiers) or '<none>'})"
                        for item in report.unsupported
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

            stage = "deletion review"
            deletions_pending, deletions_removed = self._review_deletions(
                existing, report
            )

            drift = False
            pending_imports: int | None = None
            added: tuple[str, ...] = ()
            apply_aborted = False
            regenerated: tuple[str, ...] = ()
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
                plan = self._runner.plan_with_generation(save_plan=self._sync)
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
                    logger.debug("Full drift diff:\n%s", plan.stdout)
                    if self._sync:
                        stage = "sync drift handling"
                        plan, report, regenerated, apply_aborted = (
                            self._handle_sync_drift(
                                plan, graph, report, unsupported_details
                            )
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

                if self._sync and not apply_aborted and plan.has_changes:
                    stage = "state materialization (guarded import-only apply)"
                    added, apply_aborted = self._materialize_state(
                        unsupported_details
                    )
                    if added:
                        pending_imports = 0

            stage = "coverage manifest"
            final_state = self._runner.existing_addresses()
            manifest = build_manifest(
                organization_id=graph.organization_id,
                captured=report.captured,
                unsupported=report.unsupported,
                state_addresses=final_state,
                deletions_pending=deletions_pending,
            )
            write_manifest(manifest, self._runner.workdir)
            coverage_percent = float(manifest["coverage_percent"])

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
                )
            )
            return RunSummary(
                organization_id=graph.organization_id,
                discovered_assets=graph.asset_count(),
                imports_written=report.imports_written,
                imports_skipped_existing=report.skipped_existing,
                unsupported_count=len(report.unsupported),
                drift_detected=drift,
                comparison_skipped=comparison_skipped,
                pending_imports=pending_imports,
                resources_added_to_state=added,
                apply_aborted=apply_aborted,
                deletions_pending=deletions_pending,
                deletions_removed=deletions_removed,
                regenerated_addresses=regenerated,
                coverage_percent=coverage_percent,
            )
        except Exception as exc:
            logger.exception("Pipeline fault during %s.", stage)
            self._dispatcher.dispatch(processing_fault(stage=stage, error=str(exc)))
            raise PipelineError(f"Pipeline failed during {stage}: {exc}") from exc

    def _review_deletions(
        self, existing: frozenset[str], report: GenerationReport
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Handle state-tracked resources discovery no longer sees in Meraki.

        Alert-only by default: an accidental clickops deletion must not
        quietly poison the rebuild baseline, so nothing is removed until
        a human passes ``--confirm-deletions``.
        """
        deleted = existing - report.captured_addresses
        if not deleted:
            return (), ()
        if self._confirm_deletions:
            logger.warning(
                "Removing %d human-confirmed deletion(s) from the DR kit and "
                "state: %s",
                len(deleted), ", ".join(sorted(deleted)),
            )
            self._runner.init()  # `state rm` needs an initialized backend
            self._runner.remove_resources(deleted)
            return (), tuple(sorted(deleted))
        pending = tuple(sorted(deleted))
        logger.warning(
            "%d resource(s) tracked in the DR kit were not discovered in "
            "Meraki (deleted?): %s. Alert-only — re-run with "
            "--confirm-deletions after review to remove them.",
            len(pending), ", ".join(pending),
        )
        self._dispatcher.dispatch(
            deletion_pending_confirmation(
                addresses=pending, workspace=str(self._runner.workdir)
            )
        )
        return pending, ()

    def _handle_sync_drift(
        self,
        plan: TerraformCommandResult,
        graph: NetworkGraph,
        report: GenerationReport,
        unsupported_details: list[dict[str, Any]],
    ) -> tuple[TerraformCommandResult, GenerationReport, tuple[str, ...], bool]:
        """DR-mode drift decision: regenerate modified objects, abort the rest.

        Meraki is the source of truth, so purely *modified* objects get
        their HCL baseline regenerated via local state surgery
        (``state rm`` + baseline prune + re-import — Meraki untouched).
        Any other mutation (creates from Meraki deletions, destroys from
        baseline corruption, replaces, or an unclassifiable plan) aborts
        the auto-apply and leaves the decision to a human.

        Returns ``(plan, report, regenerated_addresses, apply_aborted)``.
        """
        actions = self._runner.plan_resource_actions()
        mutated = {
            address: acts
            for address, acts in actions.items()
            if not set(acts) <= _HARMLESS_ACTIONS
        }
        modified = tuple(
            sorted(
                address for address, acts in mutated.items() if acts == ("update",)
            )
        )
        blocking = {
            address: acts for address, acts in mutated.items() if acts != ("update",)
        }
        workspace = str(self._runner.workdir)
        if blocking or not modified:
            logger.error(
                "Sync auto-apply ABORTED: the plan proposes mutations that "
                "cannot be resolved by baseline regeneration (%s). A human "
                "must review the drift alert.",
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
                )
            )
            return plan, report, (), True
        logger.warning(
            "Meraki is truth: regenerating the HCL baseline for %d modified "
            "resource(s): %s",
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
            graph, self._runner.workdir, existing_addresses=refreshed, audit=False
        )
        plan = self._runner.plan_with_generation(save_plan=True)
        if plan.has_drift:
            logger.error(
                "Drift persists after baseline regeneration; aborting the "
                "sync auto-apply for human review."
            )
            self._dispatcher.dispatch(
                drift_detected(
                    diff=plan.stdout,
                    workspace=workspace,
                    unsupported=unsupported_details,
                    apply_aborted=True,
                    regenerated_addresses=modified,
                )
            )
            return plan, report, modified, True
        return plan, report, modified, False

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
