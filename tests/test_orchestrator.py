"""Lifecycle coordinator: alert triggers, failure semantics, read-only contract."""

import json
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.alerts import AlertDispatcher, AlertEvent, EventType, Notifier
from meraki2tf.config import API_KEY_ENV_VAR
from meraki2tf.coverage import COVERAGE_JSON_FILENAME, COVERAGE_SUMMARY_FILENAME
from meraki2tf.hcl_generator import CapturedAsset, GenerationReport, UnsupportedAsset
from meraki2tf.models import FeatureConfiguration, NetworkGraph
from meraki2tf.orchestrator import PipelineError, PipelineOrchestrator
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

    def fetch_network_graph(self, organization_id: str | None = None) -> NetworkGraph:
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
    ) -> None:
        self.addresses = addresses
        self.unsupported = unsupported
        self.parser = StubParser()
        #: (existing_addresses, audit) per generate() invocation.
        self.calls: list[tuple[frozenset[str], bool]] = []
        #: suppress_addresses per generate() invocation.
        self.suppressed: list[frozenset[str]] = []

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

    def reset_baseline(self, existing_addresses: frozenset[str]) -> None:
        if existing_addresses:
            raise TerraformError("cannot rebaseline with tracked resources")
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


def test_rebaseline_with_tracked_state_is_a_fault(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, rebaseline=True)
    runner.state_addresses = {"meraki_networks.n_1"}
    with pytest.raises(PipelineError, match="baseline reset"):
        orchestrator.run("org-123")
    assert recorder.events[0].details["stage"] == "baseline reset"
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
    orchestrator, recorder, _, runner = _orchestrator(tmp_path, sync=True)
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
    runner.state_addresses = {"meraki_networks.n_1", "meraki_networks.deleted"}
    summary = orchestrator.run("org-123")

    assert runner.removed == [("meraki_networks.deleted",)]
    assert runner.initialized  # state rm needs an initialized backend
    assert summary.deletions_removed == ("meraki_networks.deleted",)
    assert summary.deletions_pending == ()
    # Confirmed removals need no pending-confirmation alert.
    assert [e.event_type for e in recorder.events] == [EventType.RUN_SUCCESS]


def test_confirm_deletions_is_a_noop_without_deletions(
    tmp_path: Path, api_key: None
) -> None:
    orchestrator, _, _, runner = _orchestrator(tmp_path, confirm_deletions=True)
    summary = orchestrator.run("org-123")
    assert runner.removed == []
    assert summary.deletions_removed == ()


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
    assert manifest["totals"] == {
        "discovered": 3,
        "imported": 1,
        "pending_import": 1,
        "unsupported": 1,
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
