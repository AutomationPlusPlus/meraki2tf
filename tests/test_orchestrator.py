"""Lifecycle coordinator: alert triggers, failure semantics, read-only contract."""

from pathlib import Path

import pytest

from meraki2tf.alerts import AlertDispatcher, AlertEvent, EventType, Notifier
from meraki2tf.config import API_KEY_ENV_VAR
from meraki2tf.hcl_generator import UnsupportedAsset
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
    def __init__(
        self,
        workdir: Path,
        plan_exit: int = 0,
        fail_stage: str = "",
        plan_stdout: str = "~ delta",
    ) -> None:
        self.workdir = workdir
        self.plan_exit = plan_exit
        self.fail_stage = fail_stage
        self.plan_stdout = plan_stdout
        self.initialized = False
        self.planned = False
        self.applied = False
        self.baseline_reset = False
        self.config_baseline = True
        self.state_addresses: frozenset[str] = frozenset()

    def _result(self, code: int) -> TerraformCommandResult:
        return TerraformCommandResult(
            command=("terraform",), returncode=code, stdout=self.plan_stdout, stderr=""
        )

    def prepare_workspace(self) -> Path:
        return self.workdir

    def existing_addresses(self) -> frozenset[str]:
        return self.state_addresses

    def has_config_baseline(self) -> bool:
        return self.config_baseline

    def reset_baseline(self, existing_addresses: frozenset[str]) -> None:
        if existing_addresses:
            raise TerraformError("cannot rebaseline with tracked resources")
        self.baseline_reset = True

    def init(self) -> TerraformCommandResult:
        self.initialized = True
        if self.fail_stage == "init":
            raise TerraformError("terraform init failed with exit code 1: boom")
        return self._result(0)

    def plan_with_generation(self) -> TerraformCommandResult:
        self.planned = True
        return self._result(self.plan_exit)

    def rebuild_apply(self) -> TerraformCommandResult:
        self.applied = True
        return self._result(0)


def _orchestrator(
    tmp_path: Path,
    plan_exit: int = 0,
    fail_stage: str = "",
    generator: StubGenerator | None = None,
    plan_stdout: str = "~ delta",
    rebaseline: bool = False,
) -> tuple[PipelineOrchestrator, RecordingNotifier, StubProvider, StubRunner]:
    recorder = RecordingNotifier()
    provider = StubProvider()
    runner = StubRunner(
        tmp_path, plan_exit=plan_exit, fail_stage=fail_stage, plan_stdout=plan_stdout
    )
    orchestrator = PipelineOrchestrator(
        provider=provider,
        generator=generator or StubGenerator(),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        dispatcher=AlertDispatcher([recorder]),
        rebaseline=rebaseline,
    )
    return orchestrator, recorder, provider, runner


@pytest.fixture()
def api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")


def test_clean_run_fires_only_run_success(tmp_path: Path, api_key: None) -> None:
    orchestrator, recorder, provider, runner = _orchestrator(tmp_path, plan_exit=0)
    summary = orchestrator.run("org-123")

    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]
    success = recorder.events[0]
    assert success.details["drift_was_detected"] is False
    assert success.details["comparison_performed"] is True
    assert success.details["discovered_assets"] == 0
    assert success.details["unsupported_count"] == 0
    assert summary.drift_detected is False
    assert summary.comparison_skipped is False
    assert summary.imports_written == 2
    assert summary.pending_imports is None  # stub plan has no summary line
    assert summary.organization_id == "org-123"
    assert provider.closed  # context-managed discovery
    assert runner.planned
    assert not runner.applied  # read-only: the pipeline never applies


def test_plan_summary_counts_flow_into_run_summary(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, recorder, _, _ = _orchestrator(
        tmp_path,
        plan_exit=2,
        plan_stdout="Plan: 875 to import, 0 to add, 0 to change, 0 to destroy.",
    )
    summary = orchestrator.run("org-123")

    # Import-only plans are pending aggregation, not drift.
    assert summary.drift_detected is False
    assert summary.pending_imports == 875
    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]
    assert recorder.events[0].details["pending_imports"] == 875


def test_drift_fires_alert_but_never_applies(tmp_path: Path, api_key: None) -> None:
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
    assert not runner.applied


def test_missing_api_key_skips_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Offline dump runs still produce artifacts; terraform is not touched."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    orchestrator, recorder, _, runner = _orchestrator(tmp_path)
    summary = orchestrator.run("org-123")

    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]
    assert summary.comparison_skipped is True
    assert summary.drift_detected is False
    assert not runner.initialized
    assert not runner.planned
    assert not runner.applied


def test_existing_state_addresses_flow_into_generation(
    tmp_path: Path, api_key: None
) -> None:
    generator = StubGenerator()
    orchestrator, _, _, runner = _orchestrator(tmp_path, generator=generator)
    runner.state_addresses = frozenset({"meraki_networks.n_1"})

    summary = orchestrator.run("org-123")

    assert generator.received_existing == frozenset({"meraki_networks.n_1"})
    assert summary.imports_skipped_existing == 1


def test_unsupported_assets_warn_for_manual_dr_rebuild(
    tmp_path: Path, api_key: None, caplog: pytest.LogCaptureFixture
) -> None:
    generator = StubGenerator()
    generator.unsupported = (
        UnsupportedAsset(
            api_path="/networks/{networkId}/mystery",
            reason="No Terraform resource maps to this API path.",
            identifiers=("N_1",),
        ),
    )
    orchestrator, recorder, _, _ = _orchestrator(tmp_path, generator=generator)
    with caplog.at_level("WARNING", logger="meraki2tf.orchestrator"):
        summary = orchestrator.run("org-123")

    assert summary.unsupported_count == 1
    assert any(
        "MANUAL rebuild" in record.message and "mystery" in record.message
        for record in caplog.records
    )
    assert recorder.events[-1].details["unsupported_count"] == 1


def test_rebaseline_resets_before_generation(tmp_path: Path, api_key: None) -> None:
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, rebaseline=True)
    orchestrator.run("org-123")
    assert runner.baseline_reset
    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]


def test_rebaseline_with_tracked_state_is_a_fault(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, rebaseline=True)
    runner.state_addresses = frozenset({"meraki_networks.n_1"})
    with pytest.raises(PipelineError, match="baseline reset"):
        orchestrator.run("org-123")
    assert recorder.events[0].details["stage"] == "baseline reset"
    assert not runner.baseline_reset


def test_tracked_state_without_baseline_warns(
    tmp_path: Path, api_key: None, caplog: pytest.LogCaptureFixture
) -> None:
    """State-tracked resources with no resources.tf will plan as destroys."""
    orchestrator, _, _, runner = _orchestrator(tmp_path)
    runner.state_addresses = frozenset({"meraki_networks.n_1"})
    runner.config_baseline = False
    with caplog.at_level("WARNING", logger="meraki2tf.orchestrator"):
        orchestrator.run("org-123")
    assert any(
        "no accumulated configuration baseline" in record.message
        for record in caplog.records
    )


def test_fault_dispatches_processing_fault_and_raises(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, fail_stage="init")
    with pytest.raises(PipelineError, match="terraform init"):
        orchestrator.run("org-123")

    assert [e.event_type for e in recorder.events] == [EventType.PROCESSING_FAULT]
    fault = recorder.events[0]
    assert fault.details["stage"] == "terraform init"
    assert "boom" in fault.details["error"]
    assert not runner.applied
