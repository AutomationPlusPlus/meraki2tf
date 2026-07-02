"""Lifecycle coordinator: one full extraction/translation/comparison cycle.

Wires the pipeline end to end — discovery, HCL generation with
exception auditing, speculative drift comparison — and fires the
contract alerts at each mandated trigger point. Suitable for ad-hoc
terminal runs and headless scheduled (cron) execution alike: every
failure path resolves to an alert plus a raised :class:`PipelineError`
for the CLI to convert into an exit code.

Read-only guarantee: this is a disaster-recovery snapshotting tool, so
the pipeline never executes ``terraform apply`` and never mutates the
Meraki organization. Rebuilding from the generated artifacts is an
explicit, human-invoked CLI action (``--rebuild --confirm``) that does
not pass through this orchestrator.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from meraki2tf.alerts import (
    AlertDispatcher,
    drift_detected,
    processing_fault,
    run_success,
)
from meraki2tf.config import API_KEY_ENV_VAR, api_key_present
from meraki2tf.hcl_generator import HclImportGenerator
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.terraform_runner import TerraformRunner

logger = logging.getLogger(__name__)


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


class PipelineOrchestrator:
    """Executes the full meraki2tf cycle against injected components."""

    def __init__(
        self,
        provider: MerakiDataProvider,
        generator: HclImportGenerator,
        runner: TerraformRunner,
        dispatcher: AlertDispatcher,
        rebaseline: bool = False,
    ) -> None:
        self._provider = provider
        self._generator = generator
        self._runner = runner
        self._dispatcher = dispatcher
        self._rebaseline = rebaseline

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

            drift = False
            pending_imports: int | None = None
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
                plan = self._runner.plan_with_generation()
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
                    self._dispatcher.dispatch(
                        drift_detected(
                            diff=plan.stdout, workspace=str(self._runner.workdir)
                        )
                    )
                else:
                    logger.info("State comparison found no drift.")

            logger.info(
                "Snapshot generation complete; dispatching RUN_SUCCESS "
                "notification. No terraform apply was executed — this "
                "pipeline is read-only."
            )
            self._dispatcher.dispatch(
                run_success(
                    imports_written=report.imports_written,
                    drift_was_detected=drift,
                    workspace=str(self._runner.workdir),
                    discovered_assets=graph.asset_count(),
                    imports_already_tracked=report.skipped_existing,
                    unsupported_count=len(report.unsupported),
                    pending_imports=pending_imports,
                    comparison_performed=not comparison_skipped,
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
            )
        except Exception as exc:
            logger.exception("Pipeline fault during %s.", stage)
            self._dispatcher.dispatch(processing_fault(stage=stage, error=str(exc)))
            raise PipelineError(f"Pipeline failed during {stage}: {exc}") from exc
