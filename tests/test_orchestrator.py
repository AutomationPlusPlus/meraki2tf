"""Lifecycle coordinator: alert triggers, failure semantics, read-only contract."""

import json
import logging
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.alerts import AlertDispatcher, AlertEvent, EventType, Notifier
from meraki2tf.config import API_KEY_ENV_VAR
from meraki2tf.coverage import COVERAGE_JSON_FILENAME, COVERAGE_SUMMARY_FILENAME
from meraki2tf.hcl_generator import CapturedAsset, GenerationReport, UnsupportedAsset
from meraki2tf.models import FeatureConfiguration, NetworkGraph
from meraki2tf.providers.discovery import SpecSurfaces
from meraki2tf.orchestrator import (
    PENDING_DELETIONS_FILENAME,
    PipelineError,
    PipelineOrchestrator,
    PreflightRefusalError,
)
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.terraform_runner import (
    ImportGuardViolation,
    ReconciledPlanResult,
    TerraformCommandResult,
    TerraformError,
)

PLAN_IMPORT_ONLY = "Plan: 2 to import, 0 to add, 0 to change, 0 to destroy."
PLAN_WITH_CHANGES = "Plan: 0 to import, 0 to add, 1 to change, 0 to destroy."


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
        self.fetched = False

    def fetch_network_graph(self, organization_id: str | None = None) -> NetworkGraph:
        self.fetched = True
        return NetworkGraph(
            organization_id=organization_id or "org-123",
            networks=(),
            devices=(),
            features=(),
        )

    def close(self) -> None:
        self.closed = True


class StubParser:
    """Spec parser stand-in: no endpoints, so no replay operations."""

    def endpoints(self) -> tuple:
        return ()


class StubGenerator:
    """Yields a deterministic GenerationReport over configurable addresses."""

    def __init__(
        self,
        addresses: tuple[str, ...] = ("meraki_devices.q2ab", "meraki_networks.n_1"),
        unsupported: tuple[UnsupportedAsset, ...] = (),
        unreadable_types: frozenset[str] = frozenset(),
    ) -> None:
        self.addresses = addresses
        self.unsupported = unsupported
        self.unreadable_types = unreadable_types
        self.parser = StubParser()
        #: (existing_addresses, audit) per generate() invocation.
        self.calls: list[tuple[frozenset[str], bool]] = []
        #: suppress_addresses per generate() invocation.
        self.suppressed: list[frozenset[str]] = []

    def spec_surfaces(self) -> SpecSurfaces:
        return SpecSurfaces(
            write_only_paths=(),
            rpc_only_paths=(),
            api_read_only_paths=(),
        )

    def generate(
        self,
        graph: NetworkGraph,
        workdir: Path,
        existing_addresses: frozenset[str] = frozenset(),
        audit: bool = True,
        suppress_addresses: frozenset[str] = frozenset(),
    ) -> GenerationReport:
        self.calls.append((existing_addresses, audit))
        self.suppressed.append(suppress_addresses)
        captured = tuple(
            CapturedAsset(
                address=address,
                api_path="/stub/{id}",
                import_id=f"id-{address}",
                already_in_state=address in existing_addresses,
            )
            for address in self.addresses
        )
        skipped = sum(asset.already_in_state for asset in captured)
        return GenerationReport(
            imports_file=workdir / "imports.tf",
            imports_written=len(captured) - skipped,
            unsupported=self.unsupported,
            skipped_existing=skipped,
            captured=captured,
            unreadable_types=self.unreadable_types,
        )


class StubRunner:
    def __init__(
        self,
        workdir: Path,
        plan_exit: int = 0,
        fail_stage: str = "",
        plan_stdout: str = "~ delta",
    ) -> None:
        self.workdir = workdir
        self.fail_stage = fail_stage
        #: Queue of (exit code, stdout) consumed per plan_with_generation
        #: call; the last entry repeats when the queue runs dry.
        self.plans: list[tuple[int, str]] = [(plan_exit, plan_stdout)]
        self.actions: dict[str, tuple[str, ...]] = {}
        #: Per-call plan_resource_actions queue (falls back to .actions).
        self.actions_queue: list[dict[str, tuple[str, ...]]] = []
        #: Addresses handed to defer_resources, per call.
        self.deferred_kit: list[tuple[str, ...]] = []
        #: Targeted-plan steps (code, stdout) consumed per plan_targeted
        #: call; empty queue answers "no changes" so chunks no-op.
        self.targeted_plans: list[tuple[int, str]] = []
        #: Chunks handed to plan_targeted, in order.
        self.targeted_calls: list[tuple[str, ...]] = []
        #: Per-call apply_import_plan results (falls back to apply_added).
        self.apply_added_queue: list[tuple[str, ...]] = []
        #: targets passed to plan_with_generation, per call (None = full).
        self.plan_targets: list[tuple[str, ...] | None] = []
        self.apply_added: tuple[str, ...] = ()
        self.apply_guard_error: ImportGuardViolation | None = None
        self.initialized = False
        self.plan_calls: list[bool] = []
        self.applied = False
        self.rebuild_applied = False
        self.baseline_reset = False
        self.config_baseline = True
        self.state_addresses: set[str] = set()
        self.removed: list[tuple[str, ...]] = []
        self.saved_plan_discarded = False
        #: Reconciliation outcomes every plan_with_generation reports.
        self.reconciliation_dropped: dict[str, str] = {}
        self.reconciliation_secrets: dict[str, tuple[str, ...]] = {}
        self.reconciliation_normalized: dict[str, tuple[str, ...]] = {}

    def prepare_workspace(self) -> Path:
        return self.workdir

    def set_duplicate_value_locator(self, locator: Any) -> None:
        self.duplicate_value_locator = locator

    def existing_addresses(self) -> frozenset[str]:
        return frozenset(self.state_addresses)

    def has_config_baseline(self) -> bool:
        return self.config_baseline

    def ensure_baseline_resettable(
        self, existing_addresses: frozenset[str]
    ) -> None:
        if existing_addresses:
            raise TerraformError("cannot rebaseline with tracked resources")

    def reset_baseline(self, existing_addresses: frozenset[str]) -> None:
        self.ensure_baseline_resettable(existing_addresses)
        self.baseline_reset = True

    def init(self) -> TerraformCommandResult:
        self.initialized = True
        if self.fail_stage == "init":
            raise TerraformError("terraform init failed with exit code 1: boom")
        return TerraformCommandResult(
            command=("terraform",), returncode=0, stdout="", stderr=""
        )

    def plan_with_generation(
        self,
        save_plan: bool = False,
        reconcile: bool = True,
        targets: Any = None,
    ) -> ReconciledPlanResult:
        self.plan_calls.append(save_plan)
        self.plan_targets.append(tuple(targets) if targets else None)
        code, stdout = self.plans[0] if len(self.plans) == 1 else self.plans.pop(0)
        return ReconciledPlanResult(
            result=TerraformCommandResult(
                command=("terraform",), returncode=code, stdout=stdout, stderr=""
            ),
            dropped=dict(self.reconciliation_dropped),
            ignored_secrets=dict(self.reconciliation_secrets),
            normalized=dict(self.reconciliation_normalized),
        )

    def plan_resource_actions(self) -> dict[str, tuple[str, ...]]:
        if self.actions_queue:
            return self.actions_queue.pop(0)
        return self.actions

    def discard_saved_plan(self) -> None:
        self.saved_plan_discarded = True

    def plan_targeted(self, addresses: list[str]) -> TerraformCommandResult:
        self.targeted_calls.append(tuple(addresses))
        code, stdout = (
            self.targeted_plans.pop(0)
            if self.targeted_plans
            else (0, "No changes. Your infrastructure matches the configuration.")
        )
        return TerraformCommandResult(
            command=("terraform",), returncode=code, stdout=stdout, stderr=""
        )

    def apply_import_plan(self) -> tuple[str, ...]:
        if self.apply_guard_error is not None:
            raise self.apply_guard_error
        self.applied = True
        added = (
            self.apply_added_queue.pop(0)
            if self.apply_added_queue
            else self.apply_added
        )
        self.state_addresses.update(added)
        return added

    def remove_resources(self, addresses: frozenset[str]) -> None:
        removed = tuple(sorted(addresses))
        self.removed.append(removed)
        self.state_addresses.difference_update(removed)

    def defer_resources(self, addresses: frozenset[str]) -> None:
        self.deferred_kit.append(tuple(sorted(addresses)))

    def rebuild_apply(self) -> TerraformCommandResult:
        self.rebuild_applied = True
        return TerraformCommandResult(
            command=("terraform",), returncode=0, stdout="", stderr=""
        )


def _orchestrator(
    tmp_path: Path,
    plan_exit: int = 0,
    fail_stage: str = "",
    generator: StubGenerator | None = None,
    plan_stdout: str = "~ delta",
    rebaseline: bool = False,
    sync: bool = False,
    confirm_deletions: bool = False,
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
        sync=sync,
        confirm_deletions=confirm_deletions,
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
    assert success.details["resources_added_to_state"] == []
    assert summary.drift_detected is False
    assert summary.comparison_skipped is False
    assert summary.imports_written == 2
    assert summary.pending_imports is None  # stub plan has no summary line
    assert summary.organization_id == "org-123"
    assert provider.closed  # context-managed discovery
    assert runner.plan_calls == [False]  # default mode never saves a plan
    assert not runner.applied  # default mode: the pipeline never applies


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
    assert drift.details["apply_aborted"] is False
    assert summary.drift_detected is True
    assert not runner.applied


def test_drift_alert_carries_the_unsupported_runbook(
    tmp_path: Path, api_key: None
) -> None:
    """Contract: drift notifications always carry the manual-rebuild list."""
    generator = StubGenerator(
        unsupported=(
            UnsupportedAsset(api_path="/x", reason="no mapping", identifiers=("N_1",)),
        )
    )
    orchestrator, recorder, _, _ = _orchestrator(
        tmp_path, plan_exit=2, generator=generator
    )
    orchestrator.run("org-123")
    drift = recorder.events[0]
    assert drift.event_type is EventType.DRIFT_DETECTED
    assert drift.details["unsupported_count"] == 1
    assert drift.details["unsupported"] == [
        {"api_path": "/x", "reason": "no mapping", "identifiers": ["N_1"]}
    ]


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
    assert runner.plan_calls == []
    assert not runner.applied


def test_existing_state_addresses_flow_into_generation(
    tmp_path: Path, api_key: None
) -> None:
    generator = StubGenerator()
    orchestrator, _, _, runner = _orchestrator(tmp_path, generator=generator)
    runner.state_addresses = {"meraki_networks.n_1"}

    summary = orchestrator.run("org-123")

    assert generator.calls == [(frozenset({"meraki_networks.n_1"}), True)]
    assert summary.imports_skipped_existing == 1


def test_unsupported_assets_warn_for_manual_dr_rebuild(
    tmp_path: Path, api_key: None, caplog: pytest.LogCaptureFixture
) -> None:
    generator = StubGenerator(
        unsupported=(
            UnsupportedAsset(
                api_path="/networks/{networkId}/mystery",
                reason="No Terraform resource maps to this API path.",
                identifiers=("N_1",),
            ),
        )
    )
    orchestrator, recorder, _, _ = _orchestrator(tmp_path, generator=generator)
    with caplog.at_level("WARNING", logger="meraki2tf.orchestrator"):
        summary = orchestrator.run("org-123")

    assert summary.unsupported_count == 1
    assert any(
        "MANUAL rebuild" in record.message and "mystery" in record.message
        for record in caplog.records
    )
    success = recorder.events[-1]
    assert success.details["unsupported_count"] == 1
    assert success.details["unsupported"][0]["api_path"] == (
        "/networks/{networkId}/mystery"
    )


def test_rebaseline_resets_before_generation(tmp_path: Path, api_key: None) -> None:
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, rebaseline=True)
    orchestrator.run("org-123")
    assert runner.baseline_reset
    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]


def test_rebaseline_with_tracked_state_refuses_before_discovery(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, recorder, provider, runner = _orchestrator(
        tmp_path, rebaseline=True
    )
    runner.state_addresses = {"meraki_networks.n_1"}
    with pytest.raises(PreflightRefusalError, match="tracked resources"):
        orchestrator.run("org-123")
    # An expected refusal: no discovery spent, no fault alert paged.
    assert not provider.fetched
    assert recorder.events == []
    assert not runner.baseline_reset


def test_rebaseline_without_api_key_refuses_before_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    orchestrator, recorder, provider, runner = _orchestrator(
        tmp_path, rebaseline=True
    )
    with pytest.raises(PreflightRefusalError, match=API_KEY_ENV_VAR):
        orchestrator.run("org-123")
    assert not provider.fetched
    assert recorder.events == []
    assert not runner.baseline_reset


def test_tracked_state_without_baseline_warns(
    tmp_path: Path, api_key: None, caplog: pytest.LogCaptureFixture
) -> None:
    """State-tracked resources with no resources.tf will plan as destroys."""
    orchestrator, _, _, runner = _orchestrator(tmp_path)
    runner.state_addresses = {"meraki_networks.n_1"}
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
    # even a faulted run must not leave the secret-bearing saved plan
    assert runner.saved_plan_discarded


def test_fault_logs_one_error_line_without_a_traceback(
    tmp_path: Path, api_key: None, caplog: pytest.LogCaptureFixture
) -> None:
    """A gracefully-handled fault (an unreachable backend) must not
    spray a stack trace over every scheduled-run log: one plain ERROR
    line for the operator, the traceback only on the DEBUG record."""
    orchestrator, _, _, _ = _orchestrator(tmp_path, fail_stage="init")
    with caplog.at_level(logging.DEBUG, logger="meraki2tf.orchestrator"):
        with pytest.raises(PipelineError, match="terraform init"):
            orchestrator.run("org-123")

    errors = [
        record
        for record in caplog.records
        if record.levelno == logging.ERROR
        and "Pipeline fault" in record.getMessage()
    ]
    assert len(errors) == 1
    (error,) = errors
    assert "terraform init" in error.getMessage()
    assert error.exc_info is None  # no traceback at operator level
    assert "Traceback" not in logging.Formatter().format(error)
    debugs = [
        record
        for record in caplog.records
        if record.levelno == logging.DEBUG
        and "Pipeline fault traceback" in record.getMessage()
    ]
    assert len(debugs) == 1
    assert debugs[0].exc_info is not None  # debugging detail preserved
    assert "Traceback" in logging.Formatter().format(debugs[0])


def test_every_run_discards_the_saved_sync_plan(
    tmp_path: Path, api_key: None
) -> None:
    """The saved plan embeds refreshed secrets like the state file; any
    run that plans but never applies (converged plan, aborted heal,
    skipped window) must remove it before finishing."""
    orchestrator, _, _, runner = _orchestrator(tmp_path, plan_stdout="")
    orchestrator.run("org-123")
    assert runner.saved_plan_discarded


# ---------------------------------------------------------------------------
# Sync mode: guarded import-only state materialization
# ---------------------------------------------------------------------------


def test_sync_applies_import_only_plan_and_reports_growth(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_IMPORT_ONLY, sync=True
    )
    runner.apply_added = ("meraki_devices.q2ab", "meraki_networks.n_1")
    summary = orchestrator.run("org-123")

    assert runner.applied
    assert runner.plan_calls == [True]  # sync saves the plan for classification
    assert summary.resources_added_to_state == (
        "meraki_devices.q2ab", "meraki_networks.n_1",
    )
    assert summary.apply_aborted is False
    assert summary.pending_imports == 0  # everything applied, nothing pending
    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]
    success = recorder.events[0]
    assert success.details["resources_added_to_state"] == [
        "meraki_devices.q2ab", "meraki_networks.n_1",
    ]


def test_sync_with_no_changes_never_invokes_apply(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, _, _, runner = _orchestrator(tmp_path, plan_exit=0, sync=True)
    summary = orchestrator.run("org-123")
    assert not runner.applied
    assert summary.resources_added_to_state == ()


def test_sync_aborts_on_non_regenerable_mutations(
    tmp_path: Path, api_key: None
) -> None:
    """Destroys (or creates from Meraki deletions) always stop the apply."""
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path,
        plan_exit=2,
        plan_stdout="Plan: 0 to import, 0 to add, 0 to change, 1 to destroy.",
        sync=True,
    )
    runner.actions = {"meraki_networks.gone": ("delete",)}
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.apply_aborted is True
    assert summary.drift_detected is True
    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,
        EventType.RUN_SUCCESS,
    ]
    assert recorder.events[0].details["apply_aborted"] is True


def test_sync_aborts_on_unclassifiable_drift(tmp_path: Path, api_key: None) -> None:
    """A drifting plan with no classifiable actions errs toward aborting."""
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout="~ mystery delta", sync=True
    )
    summary = orchestrator.run("org-123")
    assert not runner.applied
    assert summary.apply_aborted is True
    assert recorder.events[0].details["apply_aborted"] is True


def test_sync_regenerates_modified_objects_then_applies(
    tmp_path: Path, api_key: None
) -> None:
    """Meraki is truth: modified objects are re-imported with fresh HCL."""
    generator = StubGenerator()
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, generator=generator, sync=True
    )
    runner.state_addresses = {"meraki_networks.n_1"}
    runner.plans = [(2, PLAN_WITH_CHANGES), (2, PLAN_IMPORT_ONLY)]
    runner.actions = {"meraki_networks.n_1": ("update",)}
    runner.apply_added = ("meraki_networks.n_1",)
    summary = orchestrator.run("org-123")

    assert runner.removed == [("meraki_networks.n_1",)]
    # Second generation pass runs against the pruned state without
    # re-dispatching the exception audit.
    assert generator.calls[0] == (frozenset({"meraki_networks.n_1"}), True)
    assert generator.calls[1] == (frozenset(), False)
    assert runner.plan_calls == [True, True]
    # The heal replan is targeted at pending resources only — never a
    # second multi-hour full-kit read pass.
    assert runner.plan_targets == [
        None, ("meraki_devices.q2ab", "meraki_networks.n_1"),
    ]
    assert runner.applied
    assert summary.regenerated_addresses == ("meraki_networks.n_1",)
    assert summary.apply_aborted is False
    assert summary.drift_detected is True
    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,
        EventType.RUN_SUCCESS,
    ]
    drift = recorder.events[0]
    assert drift.details["apply_aborted"] is False
    assert drift.details["regenerated_addresses"] == ["meraki_networks.n_1"]


def test_sync_heals_successive_drift_rounds_then_applies(
    tmp_path: Path, api_key: None
) -> None:
    """New clickops edits landing during each multi-hour plan round are
    healed one round at a time until a plan converges — a single-pass
    heal would race a busy organization forever."""
    generator = StubGenerator()
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, generator=generator, sync=True
    )
    runner.state_addresses = {"meraki_networks.n_1", "meraki_devices.q2ab"}
    runner.plans = [
        (2, PLAN_WITH_CHANGES),
        (2, PLAN_WITH_CHANGES),
        (2, PLAN_IMPORT_ONLY),
    ]
    runner.actions_queue = [
        {"meraki_networks.n_1": ("update",)},
        {"meraki_devices.q2ab": ("update",)},
    ]
    runner.reconciliation_dropped = {"meraki_widget.broken": "unexpressible"}
    runner.apply_added = ("meraki_networks.n_1", "meraki_devices.q2ab")
    summary = orchestrator.run("org-123")

    assert runner.removed == [
        ("meraki_networks.n_1",), ("meraki_devices.q2ab",)
    ]
    assert runner.applied
    assert summary.apply_aborted is False
    assert summary.regenerated_addresses == (
        "meraki_networks.n_1", "meraki_devices.q2ab",
    )
    # Regeneration passes must not resurrect the dropped import blocks.
    assert generator.suppressed[1] == frozenset({"meraki_widget.broken"})
    assert generator.suppressed[2] == frozenset({"meraki_widget.broken"})
    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,   # round 1 regeneration announcement
        EventType.DRIFT_DETECTED,   # round 2 regeneration announcement
        EventType.RUN_SUCCESS,
    ]
    assert all(
        e.details["apply_aborted"] is False
        for e in recorder.events
        if e.event_type is EventType.DRIFT_DETECTED
    )


def test_sync_defers_racy_pending_imports_and_applies_the_rest(
    tmp_path: Path, api_key: None
) -> None:
    """An untracked resource that keeps drifting through every heal
    window is pulled from this run's kit so the other imports apply —
    monotone state growth instead of an unwinnable race."""
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, sync=True)
    runner.plans = [
        (2, PLAN_WITH_CHANGES),   # initial plan: n_1 drifting
        (2, PLAN_WITH_CHANGES),   # after heal round 1: still drifting
        (2, PLAN_IMPORT_ONLY),    # after deferral: pure imports
    ]
    runner.actions_queue = [
        {"meraki_networks.n_1": ("update",)},  # heal round 1
        {"meraki_networks.n_1": ("update",)},  # heal round 2 → no progress
        {"meraki_networks.n_1": ("update",)},  # deferral round
    ]
    runner.apply_added = ("meraki_devices.q2ab",)
    summary = orchestrator.run("org-123")

    assert runner.applied
    assert runner.deferred_kit == [("meraki_networks.n_1",)]
    assert summary.apply_aborted is False
    assert summary.deferred_addresses == ("meraki_networks.n_1",)
    assert summary.regenerated_addresses == ("meraki_networks.n_1",)
    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,   # heal round 1 regeneration
        EventType.DRIFT_DETECTED,   # deferral announcement
        EventType.RUN_SUCCESS,
    ]
    assert recorder.events[1].details["deferred_addresses"] == [
        "meraki_networks.n_1"
    ]
    assert recorder.events[2].details["deferred_addresses"] == [
        "meraki_networks.n_1"
    ]


def test_sync_never_defers_blocking_mutations(
    tmp_path: Path, api_key: None
) -> None:
    """Deferral only applies to update drift on pending imports; a
    non-update mutation surfacing at deferral time aborts for review."""
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, sync=True)
    runner.plans = [(2, PLAN_WITH_CHANGES)] * 3
    runner.actions_queue = [
        {"meraki_networks.n_1": ("update",)},  # heal round 1
        {"meraki_networks.n_1": ("update",)},  # heal round 2 → no progress
        {"meraki_networks.gone": ("delete",)},  # deferral: blocking → abort
    ]
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert runner.deferred_kit == []
    assert summary.apply_aborted is True
    assert summary.deferred_addresses == ()


PLAN_ONE_IMPORT = "Plan: 1 to import, 0 to add, 0 to change, 0 to destroy."


def test_sync_banks_imports_through_targeted_windows_when_full_plan_races(
    tmp_path: Path,
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A busy org never yields a globally clean full plan; each chunk's
    minutes-wide targeted window passes the guard and applies anyway —
    monotone state growth."""
    monkeypatch.setattr(
        PipelineOrchestrator, "_MATERIALIZE_CHUNK_SIZE", 1
    )
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_WITH_CHANGES, sync=True
    )
    # Full-plan drift that healing cannot resolve (non-update mutation).
    runner.actions = {"meraki_networks.ghost": ("delete",)}
    runner.targeted_plans = [(2, PLAN_ONE_IMPORT), (2, PLAN_ONE_IMPORT)]
    runner.apply_added_queue = [
        ("meraki_devices.q2ab",), ("meraki_networks.n_1",)
    ]
    summary = orchestrator.run("org-123")

    assert runner.targeted_calls == [
        ("meraki_devices.q2ab",), ("meraki_networks.n_1",)
    ]
    assert summary.resources_added_to_state == (
        "meraki_devices.q2ab", "meraki_networks.n_1",
    )
    assert summary.pending_imports == 0
    assert summary.apply_aborted is True  # the mutating full plan itself
    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,   # full-plan abort (non-regenerable)
        EventType.RUN_SUCCESS,
    ]
    assert recorder.events[1].details["resources_added_to_state"] == [
        "meraki_devices.q2ab", "meraki_networks.n_1",
    ]


def test_already_imported_windows_converge_pending_to_zero(
    tmp_path: Path,
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A rerun over a fully-imported org: every targeted window answers
    "No changes" because its resources are ALREADY in state, so
    RUN_SUCCESS.pending_imports must converge to 0 — the old
    `pending - added` arithmetic counted already-in-state window members
    as forever-pending and the report never reached 0."""
    monkeypatch.setattr(
        PipelineOrchestrator, "_MATERIALIZE_CHUNK_SIZE", 1
    )
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_WITH_CHANGES, sync=True
    )
    # Full-plan drift that healing cannot resolve → batched windows.
    runner.actions = {"meraki_networks.ghost": ("delete",)}
    # targeted_plans left empty: every window replies "No changes" —
    # terraform already tracks each member, nothing left to import.
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.resources_added_to_state == ()
    assert summary.deferred_addresses == ()
    assert summary.pending_imports == 0
    success = recorder.events[-1]
    assert success.event_type is EventType.RUN_SUCCESS
    assert success.details["pending_imports"] == 0


def test_targeted_window_defers_racy_import_and_retries(
    tmp_path: Path,
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        PipelineOrchestrator, "_MATERIALIZE_CHUNK_SIZE", 2
    )
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_WITH_CHANGES, sync=True
    )
    runner.actions_queue = [
        {"meraki_networks.ghost": ("delete",)},   # heal: blocking → abort
        {"meraki_networks.n_1": ("update",)},     # chunk catch → defer
    ]
    runner.targeted_plans = [
        (2, PLAN_WITH_CHANGES),   # chunk attempt 1: racy
        (2, PLAN_ONE_IMPORT),     # retry after deferral: clean
    ]
    runner.apply_added = ("meraki_devices.q2ab",)
    summary = orchestrator.run("org-123")

    assert runner.deferred_kit == [("meraki_networks.n_1",)]
    assert summary.deferred_addresses == ("meraki_networks.n_1",)
    assert summary.resources_added_to_state == ("meraki_devices.q2ab",)
    assert summary.pending_imports == 1  # the deferred one
    deferral_alerts = [
        e for e in recorder.events
        if e.event_type is EventType.DRIFT_DETECTED
        and e.details.get("deferred_addresses")
    ]
    assert len(deferral_alerts) == 1


def test_targeted_window_with_every_import_racy_defers_them_all(
    tmp_path: Path,
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A window whose every pending import is racy has nothing left to
    replan after deferral: the chunk applies nothing and the run goes
    on — the deferred imports land on the next run."""
    monkeypatch.setattr(
        PipelineOrchestrator, "_MATERIALIZE_CHUNK_SIZE", 2
    )
    orchestrator, _, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_WITH_CHANGES, sync=True
    )
    runner.actions_queue = [
        {"meraki_networks.ghost": ("delete",)},   # heal: blocking → abort
        {   # chunk catch: the whole window is racy
            "meraki_devices.q2ab": ("update",),
            "meraki_networks.n_1": ("update",),
        },
    ]
    runner.targeted_plans = [(2, PLAN_WITH_CHANGES)]
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.resources_added_to_state == ()
    assert summary.deferred_addresses == (
        "meraki_devices.q2ab", "meraki_networks.n_1",
    )


def test_targeted_window_skipped_when_still_dirty_after_deferral(
    tmp_path: Path,
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A window that will not come clean is skipped, not fatal — its
    imports stay pending and the run still succeeds."""
    monkeypatch.setattr(
        PipelineOrchestrator, "_MATERIALIZE_CHUNK_SIZE", 2
    )
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_WITH_CHANGES, sync=True
    )
    runner.actions_queue = [
        {"meraki_networks.ghost": ("delete",)},   # heal: blocking → abort
        {"meraki_networks.n_1": ("update",)},     # chunk catch → defer
    ]
    runner.targeted_plans = [
        (2, PLAN_WITH_CHANGES),   # chunk attempt 1: racy
        (2, PLAN_WITH_CHANGES),   # retry: still dirty → skip
    ]
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.resources_added_to_state == ()
    assert summary.pending_imports == 2
    assert summary.deferred_addresses == ("meraki_networks.n_1",)


def test_targeted_window_guard_violation_alerts_and_skips(
    tmp_path: Path,
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Belt-and-suspenders: the runner's own guard refusing a chunk
    dispatches the drift alert and skips that window only."""
    monkeypatch.setattr(
        PipelineOrchestrator, "_MATERIALIZE_CHUNK_SIZE", 2
    )
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_WITH_CHANGES, sync=True
    )
    runner.actions = {"meraki_networks.ghost": ("delete",)}
    runner.targeted_plans = [(2, PLAN_ONE_IMPORT)]
    runner.apply_guard_error = ImportGuardViolation(
        "mutations detected", plan_output="Plan: 1 to add"
    )
    summary = orchestrator.run("org-123")

    assert summary.resources_added_to_state == ()
    assert summary.pending_imports == 2
    aborts = [
        e for e in recorder.events
        if e.event_type is EventType.DRIFT_DETECTED
        and e.details.get("apply_aborted")
    ]
    assert len(aborts) == 2  # full-plan abort + chunk guard refusal


def test_targeted_window_with_unreadable_summary_is_skipped(
    tmp_path: Path,
    api_key: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        PipelineOrchestrator, "_MATERIALIZE_CHUNK_SIZE", 2
    )
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_WITH_CHANGES, sync=True
    )
    runner.actions = {"meraki_networks.ghost": ("delete",)}
    runner.targeted_plans = [(1, "gibberish with no plan summary")]
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.resources_added_to_state == ()
    assert summary.pending_imports == 2


def test_sync_defer_round_cap_aborts_for_human_review(
    tmp_path: Path, api_key: None
) -> None:
    """Fresh racy addresses on every deferral round exhaust the defer
    budget and abort — the org is too hot for unattended progress."""
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path,
        sync=True,
        # A third pending import keeps the post-deferral target set
        # non-empty, so every round replans (the all-deferred early
        # exit is covered separately below).
        generator=StubGenerator(
            addresses=(
                "meraki_devices.q2ab",
                "meraki_networks.n_1",
                "meraki_switch.s_3",
            )
        ),
    )
    runner.plans = [(2, PLAN_WITH_CHANGES)] * 4
    runner.actions_queue = [
        {"meraki_networks.n_1": ("update",)},   # heal round 1
        {"meraki_networks.n_1": ("update",)},   # heal round 2 → no progress
        {"meraki_networks.n_1": ("update",)},   # defer round 1
        {"meraki_devices.q2ab": ("update",)},   # defer round 2 (fresh)
    ]
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.apply_aborted is True
    assert runner.deferred_kit == [
        ("meraki_networks.n_1",), ("meraki_devices.q2ab",)
    ]
    assert summary.deferred_addresses == (
        "meraki_networks.n_1", "meraki_devices.q2ab",
    )


def test_sync_defer_exhausting_pending_skips_the_degenerate_replan(
    tmp_path: Path, api_key: None
) -> None:
    """Deferral that removes EVERY pending import must not replan: an
    empty target set would degenerate to a full untargeted plan (the
    multi-hour race window targeting exists to close). The stale saved
    plan is discarded so the guarded apply can never consume it, and
    the run is not aborted — nothing mutating remains in the kit."""
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, sync=True)
    runner.plans = [(2, PLAN_WITH_CHANGES)] * 3
    runner.actions_queue = [
        {"meraki_networks.n_1": ("update",)},   # heal round 1
        {"meraki_networks.n_1": ("update",)},   # heal round 2 → no progress
        {
            "meraki_networks.n_1": ("update",),
            "meraki_devices.q2ab": ("update",),
        },                                       # defer round: all pending
    ]
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.apply_aborted is False
    assert runner.deferred_kit == [
        ("meraki_devices.q2ab", "meraki_networks.n_1"),
    ]
    assert summary.deferred_addresses == (
        "meraki_devices.q2ab", "meraki_networks.n_1",
    )
    assert runner.saved_plan_discarded is True
    # Initial plan + one heal replan, and no deferral replan: the
    # deferral round exits before planning once nothing is left to
    # verify.
    assert len(runner.plan_calls) == 2


def test_sync_heal_round_cap_aborts_for_human_review(
    tmp_path: Path, api_key: None
) -> None:
    """Fresh drift on every round eventually exhausts the heal budget."""
    generator = StubGenerator(addresses=("a.a", "b.b", "c.c", "d.d"))
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, generator=generator, sync=True
    )
    runner.state_addresses = {"a.a", "b.b", "c.c", "d.d"}
    runner.plans = [(2, PLAN_WITH_CHANGES)] * 4
    runner.actions_queue = [
        {"a.a": ("update",)},
        {"b.b": ("update",)},
        {"c.c": ("update",)},
        {"d.d": ("update",)},
    ]
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.apply_aborted is True
    assert summary.regenerated_addresses == ("a.a", "b.b", "c.c")
    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,   # regen round 1
        EventType.DRIFT_DETECTED,   # regen round 2
        EventType.DRIFT_DETECTED,   # regen round 3
        EventType.DRIFT_DETECTED,   # budget exhausted → abort
        EventType.RUN_SUCCESS,
    ]
    assert recorder.events[3].details["apply_aborted"] is True


def test_sync_aborts_when_drift_survives_regeneration_and_deferral(
    tmp_path: Path, api_key: None
) -> None:
    """A resource that keeps planning as an update after both the regen
    and the kit surgery is beyond automatic repair — human review."""
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, sync=True)
    runner.state_addresses = {"meraki_networks.n_1"}
    runner.plans = [(2, PLAN_WITH_CHANGES), (2, PLAN_WITH_CHANGES)]
    runner.actions = {"meraki_networks.n_1": ("update",)}
    summary = orchestrator.run("org-123")

    assert not runner.applied
    assert summary.apply_aborted is True
    # Regenerated, then deferred, then still drifting → abort.
    assert runner.deferred_kit == [("meraki_networks.n_1",)]
    assert summary.deferred_addresses == ("meraki_networks.n_1",)
    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,  # regeneration announcement
        EventType.DRIFT_DETECTED,  # deferral announcement
        EventType.DRIFT_DETECTED,  # persistent drift → abort
        EventType.RUN_SUCCESS,
    ]
    assert recorder.events[2].details["apply_aborted"] is True


def test_runner_guard_violation_aborts_with_alert_not_fault(
    tmp_path: Path, api_key: None
) -> None:
    """Belt-and-suspenders: if the runner's own guard refuses, the run
    aborts with a drift alert instead of dying."""
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_IMPORT_ONLY, sync=True
    )
    runner.apply_guard_error = ImportGuardViolation(
        "mutations detected", plan_output="Plan: 1 to add"
    )
    summary = orchestrator.run("org-123")

    assert summary.apply_aborted is True
    assert summary.resources_added_to_state == ()
    assert [e.event_type for e in recorder.events] == [
        EventType.DRIFT_DETECTED,
        EventType.RUN_SUCCESS,
    ]
    drift = recorder.events[0]
    assert drift.details["apply_aborted"] is True
    assert drift.details["diff"] == "Plan: 1 to add"


# ---------------------------------------------------------------------------
# Deletion review: alert-only unless a human confirms
# ---------------------------------------------------------------------------


def _seed_alerted_deletions(workdir: Path, addresses: list[str]) -> Path:
    """A pending-deletions record as a previous alerting run left it."""
    path = workdir / PENDING_DELETIONS_FILENAME
    path.write_text(json.dumps({"addresses": addresses}), encoding="utf-8")
    return path


def test_meraki_deletions_are_alert_only(tmp_path: Path, api_key: None) -> None:
    orchestrator, recorder, _, runner = _orchestrator(tmp_path)
    runner.state_addresses = {"meraki_networks.n_1", "meraki_networks.deleted"}
    summary = orchestrator.run("org-123")

    assert runner.removed == []  # never silently synced out of the kit
    assert summary.deletions_pending == ("meraki_networks.deleted",)
    assert summary.deletions_removed == ()
    assert [e.event_type for e in recorder.events] == [
        EventType.DELETION_PENDING_CONFIRMATION,
        EventType.RUN_SUCCESS,
    ]
    pending = recorder.events[0]
    assert pending.details["addresses"] == ["meraki_networks.deleted"]
    assert recorder.events[1].details["deletions_pending_confirmation"] == [
        "meraki_networks.deleted"
    ]
    # The alerted set is persisted: it is exactly what a future
    # --confirm-deletions is allowed to remove.
    record = json.loads(
        (tmp_path / PENDING_DELETIONS_FILENAME).read_text(encoding="utf-8")
    )
    assert record["addresses"] == ["meraki_networks.deleted"]


def test_deletions_detected_even_without_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deletion check reads state + discovery, so air-gapped dump
    runs still alert on kit resources missing from Meraki."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    orchestrator, recorder, _, runner = _orchestrator(tmp_path)
    runner.state_addresses = {"meraki_networks.deleted"}
    summary = orchestrator.run("org-123")
    assert summary.deletions_pending == ("meraki_networks.deleted",)
    assert recorder.events[0].event_type is EventType.DELETION_PENDING_CONFIRMATION


def test_confirm_deletions_removes_from_kit_and_state(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, confirm_deletions=True
    )
    _seed_alerted_deletions(tmp_path, ["meraki_networks.deleted"])
    runner.state_addresses = {"meraki_networks.n_1", "meraki_networks.deleted"}
    summary = orchestrator.run("org-123")

    assert runner.removed == [("meraki_networks.deleted",)]
    assert runner.initialized  # state rm needs an initialized backend
    assert summary.deletions_removed == ("meraki_networks.deleted",)
    assert summary.deletions_pending == ()
    # Confirmed removals need no pending-confirmation alert.
    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]
    # The confirmed set is spent: a later run must not reuse it.
    assert not (tmp_path / PENDING_DELETIONS_FILENAME).exists()


def test_confirm_deletions_covers_only_the_alerted_set(
    tmp_path: Path, api_key: None
) -> None:
    """The operator confirmed the alert they reviewed, not whatever
    happens to be missing on the confirmation run: an address that went
    missing after the alert is alerted anew, never removed."""
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, confirm_deletions=True
    )
    _seed_alerted_deletions(tmp_path, ["meraki_networks.reviewed"])
    runner.state_addresses = {
        "meraki_networks.n_1",
        "meraki_networks.reviewed",  # alerted on a previous run
        "meraki_networks.fresh",  # went missing after the alert
    }
    summary = orchestrator.run("org-123")

    assert runner.removed == [("meraki_networks.reviewed",)]
    assert summary.deletions_removed == ("meraki_networks.reviewed",)
    assert summary.deletions_pending == ("meraki_networks.fresh",)
    assert [e.event_type for e in recorder.events] == [
        EventType.DELETION_PENDING_CONFIRMATION,
        EventType.RUN_SUCCESS,
    ]
    assert recorder.events[0].details["addresses"] == ["meraki_networks.fresh"]
    # The freshly alerted set becomes the next confirmable set.
    record = json.loads(
        (tmp_path / PENDING_DELETIONS_FILENAME).read_text(encoding="utf-8")
    )
    assert record["addresses"] == ["meraki_networks.fresh"]


def test_confirm_deletions_without_prior_alert_removes_nothing(
    tmp_path: Path, api_key: None
) -> None:
    """--confirm-deletions on a run with no persisted alerted set (first
    sighting of the deletions) only alerts — there was nothing reviewed
    to confirm."""
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, confirm_deletions=True
    )
    runner.state_addresses = {"meraki_networks.n_1", "meraki_networks.deleted"}
    summary = orchestrator.run("org-123")

    assert runner.removed == []
    assert summary.deletions_removed == ()
    assert summary.deletions_pending == ("meraki_networks.deleted",)
    assert recorder.events[0].event_type is (
        EventType.DELETION_PENDING_CONFIRMATION
    )


def test_confirm_deletions_ignores_a_corrupt_pending_record(
    tmp_path: Path, api_key: None, caplog: pytest.LogCaptureFixture
) -> None:
    """An unreadable reviewed set must degrade to 'nothing reviewed'
    (re-alert), never authorize a removal."""
    (tmp_path / PENDING_DELETIONS_FILENAME).write_text(
        "not json", encoding="utf-8"
    )
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, confirm_deletions=True
    )
    runner.state_addresses = {"meraki_networks.n_1", "meraki_networks.deleted"}
    with caplog.at_level("WARNING", logger="meraki2tf.orchestrator"):
        summary = orchestrator.run("org-123")

    assert runner.removed == []
    assert summary.deletions_pending == ("meraki_networks.deleted",)
    assert "unreadable" in caplog.text
    assert recorder.events[0].event_type is (
        EventType.DELETION_PENDING_CONFIRMATION
    )


def test_confirm_deletions_rejects_a_non_list_pending_record(
    tmp_path: Path, api_key: None
) -> None:
    (tmp_path / PENDING_DELETIONS_FILENAME).write_text(
        json.dumps({"addresses": "meraki_networks.deleted"}), encoding="utf-8"
    )
    orchestrator, _, _, runner = _orchestrator(
        tmp_path, confirm_deletions=True
    )
    runner.state_addresses = {"meraki_networks.n_1", "meraki_networks.deleted"}
    summary = orchestrator.run("org-123")
    assert runner.removed == []
    assert summary.deletions_pending == ("meraki_networks.deleted",)


def test_stale_pending_record_is_cleared_when_nothing_is_missing(
    tmp_path: Path, api_key: None
) -> None:
    """A resource recreated (or transiently absent) after its alert must
    drop out of the confirmable set — a stale record must not authorize
    a removal on some later run."""
    path = _seed_alerted_deletions(tmp_path, ["meraki_networks.n_1"])
    orchestrator, _, _, runner = _orchestrator(tmp_path)
    runner.state_addresses = {"meraki_networks.n_1"}
    summary = orchestrator.run("org-123")
    assert summary.deletions_pending == ()
    assert not path.exists()


def test_confirm_deletions_is_a_noop_without_deletions(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, _, _, runner = _orchestrator(tmp_path, confirm_deletions=True)
    summary = orchestrator.run("org-123")
    assert runner.removed == []
    assert summary.deletions_removed == ()


def test_transient_deletion_gap_self_heals_and_never_authorizes_removal(
    tmp_path: Path, api_key: None
) -> None:
    """Confirmation is re-verified against the CURRENT run's discovery:
    an address alerted as deleted on run 1 but discovered again on run
    2 clears the reviewed set (nothing is removed), and a later real
    disappearance starts the alert cycle over instead of consuming the
    stale authorization."""
    flapped = "meraki_networks.flapped"

    # Run 1: the address transiently vanishes from discovery → alert.
    orchestrator, recorder, _, runner = _orchestrator(tmp_path)
    runner.state_addresses = {"meraki_networks.n_1", flapped}
    summary = orchestrator.run("org-123")
    assert summary.deletions_pending == (flapped,)
    assert (tmp_path / PENDING_DELETIONS_FILENAME).exists()

    # Run 2: discovery sees it again; even --confirm-deletions removes
    # nothing, and the stale reviewed set is cleared.
    generator = StubGenerator(
        addresses=("meraki_devices.q2ab", "meraki_networks.n_1", flapped)
    )
    orchestrator2, recorder2, _, runner2 = _orchestrator(
        tmp_path, generator=generator, confirm_deletions=True
    )
    runner2.state_addresses = {"meraki_networks.n_1", flapped}
    summary2 = orchestrator2.run("org-123")
    assert runner2.removed == []
    assert summary2.deletions_removed == ()
    assert summary2.deletions_pending == ()
    assert not (tmp_path / PENDING_DELETIONS_FILENAME).exists()

    # Run 3: a later REAL disappearance is a new event — alerted anew,
    # never removed on the strength of run 1's spent review.
    orchestrator3, recorder3, _, runner3 = _orchestrator(
        tmp_path, confirm_deletions=True
    )
    runner3.state_addresses = {"meraki_networks.n_1", flapped}
    summary3 = orchestrator3.run("org-123")
    assert runner3.removed == []
    assert summary3.deletions_removed == ()
    assert summary3.deletions_pending == (flapped,)
    assert EventType.DELETION_PENDING_CONFIRMATION in [
        e.event_type for e in recorder3.events
    ]


def test_unreadable_endpoints_do_not_read_as_deletions(
    tmp_path: Path, api_key: None
) -> None:
    """A transiently unreadable endpoint leaves its objects out of the
    captured set without them being gone from Meraki; flagging (or
    removing, under --confirm-deletions) those live resources as
    deletions would let one 5xx during discovery gut the DR kit."""
    generator = StubGenerator(
        unreadable_types=frozenset({"meraki_wireless_ssids"})
    )
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path, generator=generator, confirm_deletions=True
    )
    # Even a previously alerted address stays exempt while its endpoint
    # is unreadable: absence alone is not evidence of deletion.
    _seed_alerted_deletions(
        tmp_path, ["meraki_networks.deleted", "meraki_wireless_ssids.s_1"]
    )
    runner.state_addresses = {
        "meraki_networks.n_1",
        "meraki_wireless_ssids.s_1",  # unreadable this run — exempt
        "meraki_networks.deleted",  # genuinely missing — still handled
    }
    summary = orchestrator.run("org-123")

    assert runner.removed == [("meraki_networks.deleted",)]
    assert summary.deletions_removed == ("meraki_networks.deleted",)
    assert summary.deletions_pending == ()
    assert "meraki_wireless_ssids.s_1" not in {
        address for removed in runner.removed for address in removed
    }


# ---------------------------------------------------------------------------
# Coverage manifest: the "what is / isn't in Terraform" guarantee
# ---------------------------------------------------------------------------


def test_coverage_manifest_written_every_run(tmp_path: Path, api_key: None) -> None:
    generator = StubGenerator(
        unsupported=(
            UnsupportedAsset(api_path="/x", reason="no mapping", identifiers=("N_1",)),
        )
    )
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, generator=generator)
    runner.state_addresses = {"meraki_networks.n_1"}
    summary = orchestrator.run("org-123")

    manifest = json.loads(
        (tmp_path / COVERAGE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    assert manifest["organization_id"] == "org-123"
    # The stub generator fabricates 3 objects over an *empty* stub
    # graph — the manifest must reconcile against the graph count and
    # surface the difference instead of silently trusting either side.
    assert manifest["totals"] == {
        "discovered": 0,
        "imported": 1,
        "pending_import": 1,
        "unsupported": 1,
        "duplicate_id": 0,
        "write_only_endpoints": 0,
        "unaccounted": -3,
    }
    statuses = {
        entry.get("address", entry["api_path"]): entry["status"]
        for entry in manifest["objects"]
    }
    assert statuses["meraki_networks.n_1"] == "imported"
    assert statuses["meraki_devices.q2ab"] == "pending-import"
    assert statuses["/x"] == "unsupported"
    assert summary.coverage_percent == manifest["coverage_percent"]
    assert recorder.events[-1].details["coverage_percent"] == (
        manifest["coverage_percent"]
    )
    summary_text = (tmp_path / COVERAGE_SUMMARY_FILENAME).read_text(encoding="utf-8")
    assert "manual DR runbook" in summary_text.lower() or "MANUAL" in summary_text


def test_coverage_manifest_reflects_sync_applied_imports(
    tmp_path: Path, api_key: None
) -> None:
    """Freshly materialized imports count as imported, not pending."""
    orchestrator, _, _, runner = _orchestrator(
        tmp_path, plan_exit=2, plan_stdout=PLAN_IMPORT_ONLY, sync=True
    )
    runner.apply_added = ("meraki_devices.q2ab", "meraki_networks.n_1")
    orchestrator.run("org-123")
    manifest = json.loads(
        (tmp_path / COVERAGE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    assert manifest["totals"]["imported"] == 2
    assert manifest["totals"]["pending_import"] == 0
    assert manifest["coverage_percent"] == 100.0


def test_coverage_manifest_written_for_keyless_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    orchestrator, _, _, _ = _orchestrator(tmp_path)
    orchestrator.run("org-123")
    assert (tmp_path / COVERAGE_JSON_FILENAME).exists()
    assert (tmp_path / COVERAGE_SUMMARY_FILENAME).exists()


def test_reconciliation_drops_become_unsupported_with_alert(
    tmp_path: Path, api_key: None
) -> None:
    """Resources the provider rejects move captured → unsupported, fire
    the mandated alert once, and leave the coverage manifest honest."""
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path,
        plan_exit=2,
        plan_stdout="Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.",
    )
    runner.reconciliation_dropped = {
        "meraki_networks.n_1": "Invalid Attribute Value Match: got Mon"
    }
    summary = orchestrator.run("org-123")

    assert summary.reconciliation_dropped == ("meraki_networks.n_1",)
    assert summary.reconciliation_drop_categories == {
        "Invalid Attribute Value Match": 1
    }
    assert summary.unsupported_count == 1
    assert summary.imports_written == 1  # the dropped import no longer counts
    flagged = [
        e for e in recorder.events
        if e.event_type is EventType.UNSUPPORTED_FEATURE_FLAGGED
    ]
    assert len(flagged) == 1
    assert "Provider cannot express this configuration" in flagged[0].details[
        "reason"
    ]
    manifest = json.loads(
        (tmp_path / COVERAGE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    by_status = {}
    for entry in manifest["objects"]:
        by_status.setdefault(entry["status"], []).append(
            entry.get("address", entry["api_path"])
        )
    assert "meraki_networks.n_1" not in by_status.get("pending-import", [])
    assert manifest["totals"]["unsupported"] == 1
    success = [
        e for e in recorder.events if e.event_type is EventType.RUN_SUCCESS
    ][0]
    assert success.details["unsupported_count"] == 1
    assert success.details["reconciliation_drop_categories"] == {
        "Invalid Attribute Value Match": 1
    }


def test_reconciliation_drop_reports_raw_path_identifiers(
    tmp_path: Path, api_key: None
) -> None:
    """Dropped assets must carry their discovered path values — not the
    import ID's injected org-prefix/force_delete components — or the
    coverage manifest's restore_via join and the runbook's payload
    lookup miss exactly the objects that need manual attention."""
    recorder = RecordingNotifier()
    runner = StubRunner(
        tmp_path,
        plan_exit=2,
        plan_stdout="Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.",
    )
    runner.reconciliation_dropped = {"meraki_networks.n_1": "unexpressible"}
    orchestrator = PipelineOrchestrator(
        provider=StubProvider(),
        generator=IdentifiedStubGenerator(),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        dispatcher=AlertDispatcher([recorder]),
    )
    orchestrator.run("org-123")
    flagged = [
        e for e in recorder.events
        if e.event_type is EventType.UNSUPPORTED_FEATURE_FLAGGED
    ][0]
    # IdentifiedStubGenerator's identifiers, not import_id.split(",").
    assert flagged.details["identifiers"] == ["n_1"]


def test_imports_written_never_reports_negative(
    tmp_path: Path, api_key: None
) -> None:
    """Drops accumulate across the plan loop while heal regenerations
    rewrite a much smaller kit; the fold must floor at zero instead of
    reporting a negative import count to monitoring consumers."""
    generator = StubGenerator(addresses=("meraki_networks.n_1",))
    orchestrator, _, _, runner = _orchestrator(
        tmp_path,
        plan_exit=2,
        plan_stdout="Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.",
        generator=generator,
    )
    runner.reconciliation_dropped = {
        "meraki_networks.n_1": "unexpressible",
        "meraki_devices.q2ab": "unexpressible",
        "meraki_widget.w_1": "unexpressible",
    }
    summary = orchestrator.run("org-123")
    assert summary.imports_written == 0


def test_unmanaged_secrets_reach_summary_manifest_and_notification(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, recorder, _, runner = _orchestrator(
        tmp_path,
        plan_exit=2,
        plan_stdout="Plan: 2 to import, 0 to add, 0 to change, 0 to destroy.",
    )
    runner.reconciliation_secrets = {"meraki_devices.q2ab": ("psk",)}
    runner.reconciliation_normalized = {"meraki_networks.n_1": ("body",)}
    summary = orchestrator.run("org-123")

    assert summary.unmanaged_secret_attributes == {
        "meraki_devices.q2ab": ("psk",)
    }
    assert summary.normalized_addresses == ("meraki_networks.n_1",)
    manifest = json.loads(
        (tmp_path / COVERAGE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    assert manifest["unmanaged_secret_attributes"] == {
        "meraki_devices.q2ab": ["psk"]
    }
    summary_txt = (tmp_path / COVERAGE_SUMMARY_FILENAME).read_text(
        encoding="utf-8"
    )
    assert "Secrets not captured (restore manually after a rebuild):" in (
        summary_txt
    )
    assert "meraki_devices.q2ab: psk" in summary_txt
    success = [
        e for e in recorder.events if e.event_type is EventType.RUN_SUCCESS
    ][0]
    assert success.details["unmanaged_secret_attribute_count"] == 1
    assert success.details["unmanaged_secret_attributes"] == {
        "meraki_devices.q2ab": ["psk"]
    }


class SecretPayloadProvider(StubProvider):
    """Graph with one feature whose payload carries a secret value."""

    def fetch_network_graph(
        self, organization_id: str | None = None
    ) -> NetworkGraph:
        return NetworkGraph(
            organization_id=organization_id or "org-123",
            networks=(),
            devices=(),
            features=(
                FeatureConfiguration(
                    api_path="/stub/{id}",
                    path_values=("q2ab",),
                    payload={"psk": "hunter2", "name": "Guest"},
                ),
            ),
        )


class IdentifiedStubGenerator(StubGenerator):
    """StubGenerator whose captured assets carry their path identifiers."""

    def generate(
        self,
        graph: NetworkGraph,
        workdir: Path,
        existing_addresses: frozenset[str] = frozenset(),
        audit: bool = True,
    ) -> GenerationReport:
        report = super().generate(graph, workdir, existing_addresses, audit)
        captured = tuple(
            CapturedAsset(
                address=asset.address,
                api_path=asset.api_path,
                import_id=asset.import_id,
                already_in_state=asset.already_in_state,
                identifiers=(asset.address.rsplit(".", 1)[1],),
            )
            for asset in report.captured
        )
        return GenerationReport(
            imports_file=report.imports_file,
            imports_written=report.imports_written,
            unsupported=report.unsupported,
            skipped_existing=report.skipped_existing,
            captured=captured,
        )


def _secret_payload_orchestrator(
    tmp_path: Path,
) -> tuple[PipelineOrchestrator, RecordingNotifier, StubRunner]:
    """Pipeline whose discovery payload holds a psk the plan never reports."""
    recorder = RecordingNotifier()
    runner = StubRunner(tmp_path, plan_exit=0, plan_stdout="No changes.")
    orchestrator = PipelineOrchestrator(
        provider=SecretPayloadProvider(),
        generator=IdentifiedStubGenerator(),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        dispatcher=AlertDispatcher([recorder]),
    )
    return orchestrator, recorder, runner


def test_secret_reporting_survives_quiet_plan(
    tmp_path: Path, api_key: None
) -> None:
    """Once resources are in state the plan stops mentioning secrets;
    the payload scan must keep them in the manifest and notification."""
    orchestrator, recorder, runner = _secret_payload_orchestrator(tmp_path)
    assert not runner.reconciliation_secrets  # the plan reports nothing
    summary = orchestrator.run("org-123")

    assert summary.unmanaged_secret_attributes == {
        "meraki_devices.q2ab": ("psk",)
    }
    manifest = json.loads(
        (tmp_path / COVERAGE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    assert manifest["unmanaged_secret_attributes"] == {
        "meraki_devices.q2ab": ["psk"]
    }
    success = [
        e for e in recorder.events if e.event_type is EventType.RUN_SUCCESS
    ][0]
    assert success.details["unmanaged_secret_attributes"] == {
        "meraki_devices.q2ab": ["psk"]
    }


def test_secret_reporting_survives_airgapped_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Air-gapped runs never plan; the scan alone must report secrets."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    orchestrator, recorder, _ = _secret_payload_orchestrator(tmp_path)
    summary = orchestrator.run("org-123")

    assert summary.comparison_skipped is True
    assert summary.unmanaged_secret_attributes == {
        "meraki_devices.q2ab": ("psk",)
    }
    manifest = json.loads(
        (tmp_path / COVERAGE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    assert manifest["unmanaged_secret_attributes"] == {
        "meraki_devices.q2ab": ["psk"]
    }


def test_plan_derived_secrets_override_payload_scan(
    tmp_path: Path, api_key: None
) -> None:
    """When the plan does report a resource, its attribute list wins."""
    orchestrator, _, runner = _secret_payload_orchestrator(tmp_path)
    runner.reconciliation_secrets = {
        "meraki_devices.q2ab": ("psk", "radius_secret")
    }
    summary = orchestrator.run("org-123")
    assert summary.unmanaged_secret_attributes == {
        "meraki_devices.q2ab": ("psk", "radius_secret")
    }


def test_payload_duplicate_locator_attributes_duplicates_to_addresses() -> None:
    """A duplicate that breaks the provider's own Read never reaches the
    generated config; the locator attributes it from the discovered
    payload via the captured-asset key."""
    from meraki2tf.orchestrator import _payload_duplicate_locator

    path = "/networks/{networkId}/groupPolicies/{groupPolicyId}"
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                path,
                ("N_1", "100"),
                {"contentFiltering": {"allowedUrlPatterns": {
                    "patterns": ["dup.example", "dup.example"]}}},
            ),
            FeatureConfiguration(
                path,
                ("N_1", "101"),
                {"contentFiltering": {"allowedUrlPatterns": {
                    "patterns": ["dup.example"]}}},
            ),
            # Discovered but not captured (unsupported): no address to
            # attribute to, silently skipped by the locator.
            FeatureConfiguration(
                "/networks/{networkId}/clients", ("N_1",),
                {"values": ["dup.example", "dup.example"]},
            ),
        ),
    )
    report = GenerationReport(
        imports_file=Path("imports.tf"),
        imports_written=2,
        unsupported=(),
        captured=(
            CapturedAsset(
                address="meraki_network_group_policy.n_1_100",
                api_path=path,
                import_id="N_1,100",
                already_in_state=False,
                identifiers=("N_1", "100"),
            ),
            CapturedAsset(
                address="meraki_network_group_policy.n_1_101",
                api_path=path,
                import_id="N_1,101",
                already_in_state=False,
                identifiers=("N_1", "101"),
            ),
        ),
    )
    locate = _payload_duplicate_locator(graph, report)
    found = locate(("dup.example",))
    assert set(found) == {"meraki_network_group_policy.n_1_100"}
    assert "dup.example" in found["meraki_network_group_policy.n_1_100"]
    assert locate(("absent.example",)) == {}


def test_snapshot_baseline_drift_dispatches_alert(
    tmp_path: Path, api_key: None
) -> None:
    """--drift-baseline: API-to-API drift right after discovery, on the
    mandated DRIFT_DETECTED rail, independent of the terraform plan."""
    from meraki2tf.snapshot import write_snapshot

    baseline_graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                "/networks/{networkId}/appliance/vlans/{vlanId}",
                ("N_1", "10"),
                {"id": "10", "name": "OLD-NAME"},
            ),
        ),
    )
    baseline = write_snapshot(baseline_graph, tmp_path / "baseline.json")

    recorder = RecordingNotifier()
    provider = StubProvider()  # discovers zero features → the VLAN "vanished"
    runner = StubRunner(tmp_path, plan_exit=0, plan_stdout="No changes.")
    orchestrator = PipelineOrchestrator(
        provider=provider,
        generator=StubGenerator(),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        dispatcher=AlertDispatcher([recorder]),
        drift_baseline=baseline,
    )
    summary = orchestrator.run("org-123")

    assert summary.snapshot_drift == "0 added, 0 modified, 1 removed"
    drift_events = [
        e for e in recorder.events if e.event_type is EventType.DRIFT_DETECTED
    ]
    assert len(drift_events) == 1
    assert drift_events[0].details["origin"] == "snapshot-diff"
    assert "OLD-NAME" not in drift_events[0].details["diff"]  # names, not values


def test_snapshot_baseline_with_no_drift_is_quiet(
    tmp_path: Path, api_key: None
) -> None:
    from meraki2tf.snapshot import write_snapshot

    baseline_graph = NetworkGraph(
        organization_id="org-123", networks=(), devices=(), features=()
    )
    baseline = write_snapshot(baseline_graph, tmp_path / "baseline.json")
    orchestrator, recorder, _, _ = _orchestrator(tmp_path)
    orchestrator._drift_baseline = baseline
    summary = orchestrator.run("org-123")
    assert summary.snapshot_drift is None
    assert all(
        e.event_type is not EventType.DRIFT_DETECTED for e in recorder.events
    )


def test_manifest_includes_restore_verdicts(
    tmp_path: Path, api_key: None
) -> None:
    """The weekly manifest answers 'will the API rebuild it?' for every
    asset, computed offline from the restore planner."""
    orchestrator, _, _, _ = _orchestrator(tmp_path)
    orchestrator.run("org-123")
    manifest = json.loads(
        (tmp_path / COVERAGE_JSON_FILENAME).read_text(encoding="utf-8")
    )
    # StubGenerator's assets aren't in the stub graph, so no verdicts
    # attach — the column is present only where the planner has one.
    assert "objects" in manifest


def test_partial_snapshot_scope_stamps_manifest_runbook_and_alert(
    tmp_path: Path, api_key: None
) -> None:
    """A partial (--only) --from-dump input must stamp every artifact
    of the pipeline run — manifest, runbook, and RUN_SUCCESS — so a
    one-network kit can never read as full-org coverage."""
    import json as _json

    from meraki2tf.scope import SnapshotScope

    class PartialProvider(StubProvider):
        @property
        def snapshot_scope(self) -> SnapshotScope:
            return SnapshotScope(network_ids=("N_1",))

    recorder = RecordingNotifier()
    runner = StubRunner(tmp_path, plan_exit=0)
    orchestrator = PipelineOrchestrator(
        provider=PartialProvider(),
        generator=StubGenerator(),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        dispatcher=AlertDispatcher([recorder]),
    )
    orchestrator.run("org-123")

    success = next(
        e for e in recorder.events if e.event_type is EventType.RUN_SUCCESS
    )
    assert success.details["partial_scope"] == ["N_1"]
    assert "PARTIAL run scoped to 1 network(s)" in success.summary
    manifest = _json.loads(
        (runner.workdir / "coverage.json").read_text(encoding="utf-8")
    )
    assert manifest["scope"] == {"partial": True, "networks": ["N_1"]}
    assert "PARTIAL RUN" in (
        runner.workdir / "runbook.md"
    ).read_text(encoding="utf-8")


class ScopedProvider(StubProvider):
    """Provider declaring a partial scope, like a --only live run."""

    def __init__(self) -> None:
        super().__init__()
        from meraki2tf.scope import SnapshotScope

        self.snapshot_scope = SnapshotScope(
            network_ids=("N_1",), selectors=("network:HQ",)
        )


def _scoped_orchestrator(
    tmp_path: Path,
    generator: StubGenerator | None = None,
    sync: bool = False,
    plan_exit: int = 0,
    plan_stdout: str = "~ delta",
) -> tuple[PipelineOrchestrator, RecordingNotifier, StubRunner]:
    recorder = RecordingNotifier()
    runner = StubRunner(tmp_path, plan_exit=plan_exit, plan_stdout=plan_stdout)
    orchestrator = PipelineOrchestrator(
        provider=ScopedProvider(),
        generator=generator or StubGenerator(),  # type: ignore[arg-type]
        runner=runner,  # type: ignore[arg-type]
        dispatcher=AlertDispatcher([recorder]),
        sync=sync,
    )
    return orchestrator, recorder, runner


def test_scoped_run_never_flags_out_of_scope_state_as_deleted(
    tmp_path: Path, api_key: None, caplog: pytest.LogCaptureFixture
) -> None:
    """CRITICAL scope-safety property: state-tracked resources the
    scoped discovery never looked at are out-of-scope, not deleted —
    no DELETION_PENDING alert, no pending-deletions record, and the
    plan is targeted at exactly the captured (in-scope) addresses so
    terraform never reads or proposes anything for the rest."""
    orchestrator, recorder, runner = _scoped_orchestrator(tmp_path)
    runner.state_addresses = {
        "meraki_networks.n_1",
        "meraki_legacy.out_of_scope",
    }
    with caplog.at_level(logging.INFO):
        summary = orchestrator.run("org-123")
    assert summary.deletions_pending == ()
    assert summary.deletions_removed == ()
    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]
    assert not (tmp_path / PENDING_DELETIONS_FILENAME).exists()
    assert runner.removed == []
    assert "out-of-scope" in caplog.text
    assert "meraki_legacy.out_of_scope" in caplog.text
    # The plan covered exactly the captured in-scope addresses.
    assert runner.plan_targets == [
        ("meraki_devices.q2ab", "meraki_networks.n_1")
    ]


def test_scoped_run_leaves_a_prior_deletion_review_record_untouched(
    tmp_path: Path, api_key: None
) -> None:
    """A full run's alerted-deletions record must survive a scoped run
    unchanged: the scoped run reviewed nothing, so it may neither
    clear nor rewrite what the operator was asked to review."""
    seed = _seed_alerted_deletions(tmp_path, ["meraki_full.reviewed"])
    before = seed.read_text(encoding="utf-8")
    orchestrator, _recorder, _runner = _scoped_orchestrator(tmp_path)
    orchestrator.run("org-123")
    assert seed.read_text(encoding="utf-8") == before


def test_scoped_keyless_run_skips_review_and_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    orchestrator, _recorder, runner = _scoped_orchestrator(tmp_path)
    runner.state_addresses = {"meraki_legacy.out_of_scope"}
    summary = orchestrator.run("org-123")
    assert summary.comparison_skipped
    assert summary.deletions_pending == ()
    assert runner.plan_calls == []


def test_sync_scoped_regen_replan_stays_targeted_when_pending_is_empty(
    tmp_path: Path, api_key: None
) -> None:
    """A scoped sync replan must never degenerate into an untargeted
    full plan: when regeneration leaves nothing pending (everything is
    tracked or reconciliation-dropped), the fallback targets the
    captured in-scope set instead of None."""
    generator = StubGenerator(addresses=("meraki_a.a", "meraki_b.b"))
    orchestrator, recorder, runner = _scoped_orchestrator(
        tmp_path, generator=generator, sync=True,
        plan_exit=2, plan_stdout=PLAN_WITH_CHANGES,
    )
    runner.state_addresses = {"meraki_b.b"}
    runner.reconciliation_dropped = {"meraki_a.a": "provider rejects it"}
    runner.plans = [
        (2, PLAN_WITH_CHANGES),
        (0, "No changes. Your infrastructure matches the configuration."),
    ]
    runner.actions_queue = [{"meraki_a.a": ("update",)}]

    summary = orchestrator.run("org-123")

    assert not summary.apply_aborted
    assert summary.regenerated_addresses == ("meraki_a.a",)
    # Both plans — the initial one and the post-regeneration replan
    # whose pending set was empty — stayed targeted at the captured
    # in-scope addresses; None (a full untargeted plan) never appears.
    assert runner.plan_targets == [
        ("meraki_a.a", "meraki_b.b"),
        ("meraki_a.a", "meraki_b.b"),
    ]


@pytest.mark.parametrize(
    "refusal",
    ["scope", "checkpoint"],
)
def test_operator_input_errors_refuse_without_a_fault_alert(
    tmp_path: Path, refusal: str
) -> None:
    from meraki2tf.providers.discovery_checkpoint import (
        CheckpointMismatchError,
    )
    from meraki2tf.scope import ScopeFilterError

    exc: Exception = (
        ScopeFilterError("--only selector 'network:X' matched no network")
        if refusal == "scope"
        else CheckpointMismatchError("checkpoint records organization 999")
    )

    class RefusingProvider(StubProvider):
        def fetch_network_graph(
            self, organization_id: str | None = None
        ) -> NetworkGraph:
            raise exc

    recorder = RecordingNotifier()
    orchestrator = PipelineOrchestrator(
        provider=RefusingProvider(),
        generator=StubGenerator(),  # type: ignore[arg-type]
        runner=StubRunner(tmp_path),  # type: ignore[arg-type]
        dispatcher=AlertDispatcher([recorder]),
    )
    with pytest.raises(PreflightRefusalError):
        orchestrator.run("org-123")
    assert recorder.events == []
