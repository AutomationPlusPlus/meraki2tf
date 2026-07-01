"""Lifecycle coordinator: alert triggers and failure semantics."""

from pathlib import Path

import pytest

from meraki2tf.alerts import AlertDispatcher, AlertEvent, EventType, Notifier
from meraki2tf.models import NetworkGraph
from meraki2tf.orchestrator import PipelineError, PipelineOrchestrator
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.terraform_runner import TerraformCommandResult, TerraformError


class RecordingNotifier(Notifier):
    channel = "recording"

    def __init__(self) -> None:
        self.events: list[AlertEvent] = []

    def send(self, event: AlertEvent) -> None:
        self.events.append(event)


class StubProvider(MerakiDataProvider):
    mode = "stub"

    def __init__(self) -> None:
        self.closed = False

    def fetch_network_graph(self, organization_id: str | None = None) -> NetworkGraph:
        return NetworkGraph(
            organization_id=organization_id or "org-123",
            networks=(),
            devices=(),
            features=(),
        )

    def close(self) -> None:
        self.closed = True


class StubGenerator:
    def __init__(self, imports_written: int = 2) -> None:
        self.imports_written = imports_written
        self.unsupported: tuple = ()  # type: ignore[type-arg]
        self.skipped_existing = 0
        self.received_existing: frozenset[str] | None = None

    def generate(
        self,
        graph: NetworkGraph,
        workdir: Path,
        existing_addresses: frozenset[str] = frozenset(),
    ) -> "StubGenerator":
        self.received_existing = existing_addresses
        self.skipped_existing = len(existing_addresses)
        return self


class StubRunner:
    def __init__(self, workdir: Path, plan_exit: int = 0, fail_stage: str = "") -> None:
        self.workdir = workdir
        self.plan_exit = plan_exit
        self.fail_stage = fail_stage
        self.applied = False
        self.state_addresses: frozenset[str] = frozenset()

    def _result(self, code: int) -> TerraformCommandResult:
        return TerraformCommandResult(
            command=("terraform",), returncode=code, stdout="~ delta", stderr=""
        )

    def prepare_workspace(self) -> Path:
        return self.workdir

    def existing_addresses(self) -> frozenset[str]:
        return self.state_addresses

    def init(self) -> TerraformCommandResult:
        if self.fail_stage == "init":
            raise TerraformError("terraform init failed with exit code 1: boom")
        return self._result(0)

    def plan_with_generation(self) -> TerraformCommandResult:
        return self._result(self.plan_exit)

    def apply(self) -> TerraformCommandResult:
        self.applied = True
        return self._result(0)


def _orchestrator(
    tmp_path: Path,
    plan_exit: int = 0,
    fail_stage: str = "",
    generator: StubGenerator | None = None,
) -> tuple[PipelineOrchestrator, RecordingNotifier, StubProvider, StubRunner]:
    recorder = RecordingNotifier()
    provider = StubProvider()
    runner = StubRunner(tmp_path, plan_exit=plan_exit, fail_stage=fail_stage)
    orchestrator = PipelineOrchestrator(
        provider=provider,
        generator=generator or StubGenerator(),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        dispatcher=AlertDispatcher([recorder]),
    )
    return orchestrator, recorder, provider, runner


def test_clean_run_fires_only_run_success(tmp_path: Path) -> None:
    orchestrator, recorder, provider, runner = _orchestrator(tmp_path, plan_exit=0)
    summary = orchestrator.run("org-123")

    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]
    assert recorder.events[0].details["drift_was_detected"] is False
    assert summary.drift_detected is False
    assert summary.imports_written == 2
    assert summary.organization_id == "org-123"
    assert provider.closed  # context-managed discovery
    assert runner.applied


def test_drift_fires_alert_then_still_aggregates(tmp_path: Path) -> None:
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, plan_exit=2)
    summary = orchestrator.run("org-123")

    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,
        EventType.RUN_SUCCESS,
    ]
    drift = recorder.events[0]
    assert drift.details["diff"] == "~ delta"
    assert drift.details["workspace"] == str(runner.workdir)
    assert summary.drift_detected is True
    assert runner.applied


def test_existing_state_addresses_flow_into_generation(tmp_path: Path) -> None:
    generator = StubGenerator()
    orchestrator, _, _, runner = _orchestrator(tmp_path, generator=generator)
    runner.state_addresses = frozenset({"meraki_networks.n_1"})

    summary = orchestrator.run("org-123")

    assert generator.received_existing == frozenset({"meraki_networks.n_1"})
    assert summary.imports_skipped_existing == 1


def test_fault_dispatches_processing_fault_and_raises(tmp_path: Path) -> None:
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, fail_stage="init")
    with pytest.raises(PipelineError, match="terraform init"):
        orchestrator.run("org-123")

    assert [e.event_type for e in recorder.events] == [EventType.PROCESSING_FAULT]
    fault = recorder.events[0]
    assert fault.details["stage"] == "terraform init"
    assert "boom" in fault.details["error"]
    assert not runner.applied
