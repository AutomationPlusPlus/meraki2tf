"""Lifecycle coordinator: one full extraction/translation/aggregation cycle.

Wires the pipeline end to end — discovery, HCL generation with
exception auditing, speculative drift comparison, state aggregation —
and fires the contract alerts at each mandated trigger point. Suitable
for ad-hoc terminal runs and headless scheduled (cron) execution alike:
every failure path resolves to an alert plus a raised
:class:`PipelineError` for the CLI to convert into an exit code.
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
    imports_written: int
    imports_skipped_existing: int
    unsupported_count: int
    drift_detected: bool


class PipelineOrchestrator:
    """Executes the full meraki2tf cycle against injected components."""

    def __init__(
        self,
        provider: MerakiDataProvider,
        generator: HclImportGenerator,
        runner: TerraformRunner,
        dispatcher: AlertDispatcher,
    ) -> None:
        self._provider = provider
        self._generator = generator
        self._runner = runner
        self._dispatcher = dispatcher

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

            stage = "HCL construction"
            report = self._generator.generate(
                graph, self._runner.workdir, existing_addresses=existing
            )

            stage = "terraform init"
            self._runner.init()

            stage = "state comparison"
            plan = self._runner.plan_with_generation()
            drift = plan.has_changes
            if drift:
                logger.warning(
                    "Configuration drift detected; dispatching DRIFT_DETECTED alert."
                )
                logger.debug("Full drift diff:\n%s", plan.stdout)
                self._dispatcher.dispatch(
                    drift_detected(diff=plan.stdout, workspace=str(self._runner.workdir))
                )
            else:
                logger.info("State comparison found no drift.")

            stage = "state aggregation"
            self._runner.apply()
            logger.info(
                "State aggregation complete; dispatching RUN_SUCCESS notification."
            )
            self._dispatcher.dispatch(
                run_success(
                    imports_written=report.imports_written,
                    drift_was_detected=drift,
                    workspace=str(self._runner.workdir),
                )
            )
            return RunSummary(
                organization_id=graph.organization_id,
                imports_written=report.imports_written,
                imports_skipped_existing=report.skipped_existing,
                unsupported_count=len(report.unsupported),
                drift_detected=drift,
            )
        except Exception as exc:
            logger.exception("Pipeline fault during %s.", stage)
            self._dispatcher.dispatch(processing_fault(stage=stage, error=str(exc)))
            raise PipelineError(f"Pipeline failed during {stage}: {exc}") from exc
