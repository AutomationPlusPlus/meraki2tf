"""Terraform CLI runner: workspace management and subprocess contracts."""

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

import pytest

from meraki2tf import terraform_runner
from meraki2tf.terraform_runner import (
    AGGREGATED_CONFIG_FILENAME,
    DEFAULT_STATE_FILENAME,
    GENERATED_CONFIG_FILENAME,
    PROVIDER_FILENAME,
    SYNC_PLAN_FILENAME,
    ImportGuardViolation,
    TerraformError,
    TerraformRunner,
)

PLAN_IMPORT_ONLY = "Plan: 2 to import, 0 to add, 0 to change, 0 to destroy."


class FakeSubprocess:
    def __init__(
        self,
        returncode: int = 0,
        stdout: str = "",
        stderr: str = "",
        on_run: Any = None,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.on_run = on_run
        self.calls: list[dict[str, Any]] = []

    def run(self, command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        self.calls.append({"command": command, **kwargs})
        if self.on_run is not None:
            self.on_run()
        return SimpleNamespace(
            returncode=self.returncode, stdout=self.stdout, stderr=self.stderr
        )


class ScriptedSubprocess:
    """One (returncode, stdout, side-effect) triple consumed per call."""

    def __init__(
        self, *steps: tuple[int, str, Callable[[], None] | None]
    ) -> None:
        self.steps = list(steps)
        self.calls: list[tuple[str, ...]] = []

    def run(self, command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        self.calls.append(command)
        returncode, stdout, side_effect = self.steps.pop(0)
        if side_effect is not None:
            side_effect()
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


@pytest.fixture()
def runner(tmp_path: Path) -> TerraformRunner:
    return TerraformRunner(tmp_path / "workspace", executable="terraform")


def test_prepare_workspace_writes_credential_free_provider_anchor(
    runner: TerraformRunner,
) -> None:
    provider_file = runner.prepare_workspace()
    assert runner.workdir.is_dir()
    assert provider_file.name == PROVIDER_FILENAME
    content = provider_file.read_text(encoding="utf-8")
    assert 'source = "CiscoDevNet/meraki"' in content
    assert 'provider "meraki"' in content
    assert "MERAKI_DASHBOARD_API_KEY" in content  # documented, never templated
    assert "api_key" not in content


def test_state_defaults_into_workdir_backend(runner: TerraformRunner) -> None:
    provider_file = runner.prepare_workspace()
    expected = (runner.workdir / DEFAULT_STATE_FILENAME).resolve()
    assert runner.state_path == expected
    content = provider_file.read_text(encoding="utf-8")
    assert 'backend "local"' in content
    assert f'path = "{expected}"' in content


def test_custom_state_location_is_anchored_and_parent_created(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state-store" / "org-123.tfstate"
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    provider_file = runner.prepare_workspace()
    assert runner.state_path == state.resolve()
    assert state.parent.is_dir()  # created so terraform can write the file
    assert f'path = "{state.resolve()}"' in provider_file.read_text(encoding="utf-8")


def test_existing_addresses_empty_when_no_state(runner: TerraformRunner) -> None:
    assert runner.existing_addresses() == frozenset()


def test_existing_addresses_reads_managed_resources(tmp_path: Path) -> None:
    state = tmp_path / "terraform.tfstate"
    state.write_text(
        '{"resources": ['
        '{"mode": "managed", "type": "meraki_networks", "name": "n_1"},'
        '{"mode": "managed", "type": "meraki_devices", "name": "q2ab"},'
        '{"mode": "data", "type": "meraki_networks", "name": "lookup"},'
        '"garbage-entry"'
        "]}",
        encoding="utf-8",
    )
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    assert runner.existing_addresses() == frozenset(
        {"meraki_networks.n_1", "meraki_devices.q2ab"}
    )


def test_existing_addresses_tolerates_non_object_state(tmp_path: Path) -> None:
    state = tmp_path / "terraform.tfstate"
    state.write_text("[]", encoding="utf-8")
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    assert runner.existing_addresses() == frozenset()


def test_unreadable_state_is_a_hard_error(tmp_path: Path) -> None:
    state = tmp_path / "terraform.tfstate"
    state.write_text("{corrupt", encoding="utf-8")
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    with pytest.raises(TerraformError, match="unreadable"):
        runner.existing_addresses()


def test_init_invokes_terraform_with_safe_flags(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    result = runner.init()
    call = fake.calls[0]
    assert call["command"] == (
        "terraform", "init", "-input=false", "-no-color", "-reconfigure",
    )
    assert call["cwd"] == runner.workdir
    assert call["capture_output"] is True
    assert result.returncode == 0


def test_plan_reports_no_changes_on_exit_zero(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    assert runner.plan_with_generation().has_changes is False


def test_plan_reports_drift_on_detailed_exit_two(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=2, stdout="~ resource delta")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    result = runner.plan_with_generation()
    assert result.has_changes is True
    assert "-detailed-exitcode" in fake.calls[0]["command"]
    assert f"-generate-config-out={GENERATED_CONFIG_FILENAME}" in fake.calls[0]["command"]


def test_import_only_plan_is_not_drift(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pending imports are normal snapshot growth, never a drift alert."""
    fake = FakeSubprocess(
        returncode=2,
        stdout="Plan: 875 to import, 0 to add, 0 to change, 0 to destroy.",
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    result = runner.plan_with_generation()
    assert result.has_changes is True  # imports still need aggregation
    assert result.has_drift is False


def test_real_changes_in_plan_summary_are_drift(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(
        returncode=2,
        stdout="Plan: 3 to import, 0 to add, 2 to change, 1 to destroy.",
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    assert runner.plan_with_generation().has_drift is True


def test_summary_without_import_count_still_parses(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(
        returncode=2, stdout="Plan: 1 to add, 0 to change, 0 to destroy."
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    assert runner.plan_with_generation().has_drift is True


def test_unparseable_plan_falls_back_to_exit_code(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=2, stdout="~ resource delta")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    result = runner.plan_with_generation()
    assert result.has_drift is True
    assert result.plan_counts is None


def test_plan_counts_expose_pending_imports_and_changes(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(
        returncode=2,
        stdout="Plan: 875 to import, 1 to add, 2 to change, 3 to destroy.",
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    counts = runner.plan_with_generation().plan_counts
    assert counts is not None
    assert (counts.imports, counts.add, counts.change, counts.destroy) == (875, 1, 2, 3)
    assert counts.has_real_changes is True


def test_stale_generated_config_is_absorbed_not_deleted(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deleting generated config would leave state-tracked resources
    configless — every later plan would propose destroying them."""
    runner.prepare_workspace()
    stale = runner.workdir / GENERATED_CONFIG_FILENAME
    stale.write_text('resource "meraki_networks" "n_1" {}', encoding="utf-8")
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.plan_with_generation()
    assert not stale.exists()
    aggregated = runner.workdir / AGGREGATED_CONFIG_FILENAME
    assert 'resource "meraki_networks" "n_1"' in aggregated.read_text(
        encoding="utf-8"
    )
    assert runner.has_config_baseline()


def test_freshly_generated_config_is_absorbed_after_plan(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    generated = runner.workdir / GENERATED_CONFIG_FILENAME

    fake = FakeSubprocess(
        returncode=2,
        stdout="Plan: 2 to import, 0 to add, 0 to change, 0 to destroy.",
        on_run=lambda: generated.write_text(
            'resource "meraki_devices" "q2ab" {}\n', encoding="utf-8"
        ),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.plan_with_generation()

    assert not generated.exists()
    aggregated = runner.workdir / AGGREGATED_CONFIG_FILENAME
    assert 'resource "meraki_devices" "q2ab"' in aggregated.read_text(
        encoding="utf-8"
    )


def test_absorption_accumulates_across_runs(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    generated = runner.workdir / GENERATED_CONFIG_FILENAME
    aggregated = runner.workdir / AGGREGATED_CONFIG_FILENAME
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)

    generated.write_text("resource_one {}", encoding="utf-8")
    runner.plan_with_generation()
    generated.write_text("resource_two {}", encoding="utf-8")
    runner.plan_with_generation()

    content = aggregated.read_text(encoding="utf-8")
    assert "resource_one" in content and "resource_two" in content


def test_reset_baseline_discards_config(runner: TerraformRunner) -> None:
    runner.prepare_workspace()
    aggregated = runner.workdir / AGGREGATED_CONFIG_FILENAME
    aggregated.write_text("resource_old {}", encoding="utf-8")
    runner.reset_baseline(frozenset())
    assert not aggregated.exists()
    assert not runner.has_config_baseline()
    runner.reset_baseline(frozenset())  # idempotent when already absent


def test_reset_baseline_refuses_with_tracked_state(
    runner: TerraformRunner,
) -> None:
    """Discarding config of state-tracked resources would plan their
    destruction — the guard must refuse."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        "resource_old {}", encoding="utf-8"
    )
    with pytest.raises(TerraformError, match="rebaseline"):
        runner.reset_baseline(frozenset({"meraki_networks.n_1"}))
    assert runner.has_config_baseline()  # nothing was deleted


def test_provider_anchor_escapes_hcl_specials_in_state_path(
    tmp_path: Path,
) -> None:
    state = tmp_path / 'st"ate' / "terraform.tfstate"
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    provider_file = runner.prepare_workspace()
    content = provider_file.read_text(encoding="utf-8")
    assert 'st\\"ate' in content  # quote escaped, backend block stays valid


def test_hcl_quote_escapes_control_characters() -> None:
    assert terraform_runner._hcl_quote("a\nb\rc\td") == "a\\nb\\rc\\td"


def test_plan_preview_never_generates_config(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=2, stdout="Plan: 1 to add")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    result = runner.plan_preview()
    assert result.has_changes is True
    command = fake.calls[0]["command"]
    assert command[:2] == ("terraform", "plan")
    assert "-detailed-exitcode" in command
    assert not any("generate-config-out" in part for part in command)


def test_rebuild_apply_uses_auto_approve(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(stdout="Apply complete")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.rebuild_apply()
    assert fake.calls[0]["command"] == (
        "terraform", "apply", "-input=false", "-no-color", "-auto-approve",
    )


def test_pipeline_surface_has_no_generic_apply() -> None:
    """The read-only contract: apply exists solely as rebuild_apply."""
    assert not hasattr(TerraformRunner, "apply")


def test_failures_raise_with_cli_diagnostics(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=1, stderr="Error: provider not found")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with pytest.raises(TerraformError, match="provider not found"):
        runner.init()


def test_plan_exit_one_is_still_an_error(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=1, stdout="Error in configuration")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with pytest.raises(TerraformError, match="exit code 1"):
        runner.plan_with_generation()


def test_real_subprocess_module_is_used() -> None:
    assert terraform_runner.subprocess is subprocess


# ---------------------------------------------------------------------------
# Sync-mode guard: import-only verification lives in the runner itself
# ---------------------------------------------------------------------------


def _write_state(path: Path, *addresses: str) -> None:
    resources = [
        {
            "mode": "managed",
            "type": address.split(".", 1)[0],
            "name": address.split(".", 1)[1],
        }
        for address in addresses
    ]
    path.write_text(json.dumps({"resources": resources}), encoding="utf-8")


def test_apply_import_plan_verifies_then_applies_the_saved_plan(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    scripted = ScriptedSubprocess(
        (2, PLAN_IMPORT_ONLY, None),
        (
            0,
            "Apply complete!",
            lambda: _write_state(
                runner.state_path, "meraki_networks.n_1", "meraki_devices.q2ab"
            ),
        ),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    added = runner.apply_import_plan()

    plan_command, apply_command = scripted.calls
    assert plan_command[1] == "plan"
    assert f"-out={SYNC_PLAN_FILENAME}" in plan_command
    # The verified plan file is applied verbatim — no TOCTOU window.
    assert apply_command == (
        "terraform", "apply", "-input=false", "-no-color", SYNC_PLAN_FILENAME,
    )
    assert added == ("meraki_devices.q2ab", "meraki_networks.n_1")
    assert not (runner.workdir / SYNC_PLAN_FILENAME).exists()


def test_apply_import_plan_noop_when_state_is_current(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    scripted = ScriptedSubprocess((0, "No changes.", None))
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    assert runner.apply_import_plan() == ()
    assert len(scripted.calls) == 1  # plan only; nothing to apply


def test_guard_refuses_plans_with_mutations(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    scripted = ScriptedSubprocess(
        (2, "Plan: 5 to import, 1 to add, 0 to change, 0 to destroy.", None)
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(ImportGuardViolation, match="1 to add") as excinfo:
        runner.apply_import_plan()
    assert len(scripted.calls) == 1  # refused before any apply
    assert "1 to add" in excinfo.value.plan_output


def test_guard_refuses_unverifiable_plans(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No parseable summary → fail safe, never apply."""
    runner.prepare_workspace()
    scripted = ScriptedSubprocess((2, "~ mystery delta", None))
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(ImportGuardViolation, match="could not be parsed"):
        runner.apply_import_plan()
    assert len(scripted.calls) == 1


def test_guard_violation_is_a_terraform_error() -> None:
    """Callers that only know TerraformError still fail closed."""
    assert issubclass(ImportGuardViolation, TerraformError)


def test_plan_with_generation_saves_plan_on_request(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.plan_with_generation(save_plan=True)
    assert f"-out={SYNC_PLAN_FILENAME}" in fake.calls[0]["command"]
    runner.plan_with_generation()
    assert f"-out={SYNC_PLAN_FILENAME}" not in fake.calls[1]["command"]


def test_plan_resource_actions_parses_show_json(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    document = {
        "resource_changes": [
            {"address": "meraki_networks.n_1", "change": {"actions": ["update"]}},
            {"address": "meraki_devices.q2ab", "change": {"actions": ["no-op"]}},
            {"change": {"actions": ["delete"]}},  # no address → skipped
            "garbage-entry",
        ]
    }
    fake = FakeSubprocess(returncode=0, stdout=json.dumps(document))
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    actions = runner.plan_resource_actions()
    assert fake.calls[0]["command"] == ("terraform", "show", "-json", SYNC_PLAN_FILENAME)
    assert actions == {
        "meraki_networks.n_1": ("update",),
        "meraki_devices.q2ab": ("no-op",),
    }


def test_plan_resource_actions_rejects_unparseable_output(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=0, stdout="{not json")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with pytest.raises(TerraformError, match="unparseable"):
        runner.plan_resource_actions()


def test_plan_resource_actions_tolerates_non_object_document(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=0, stdout="[]")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    assert runner.plan_resource_actions() == {}


# ---------------------------------------------------------------------------
# Local removal surgery: confirmed deletions and baseline regeneration
# ---------------------------------------------------------------------------

BASELINE = """\
resource "meraki_networks" "n_1" {
  name = "HQ"
  tags = {
    site = "hq"
  }
}

resource "meraki_devices" "q2ab" {
  name = "edge"
}

resource "meraki_networks" "oneliner" {}
"""


def test_remove_resources_prunes_baseline_and_state(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        BASELINE, encoding="utf-8"
    )
    _write_state(runner.state_path, "meraki_networks.n_1", "meraki_devices.q2ab")
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)

    runner.remove_resources({"meraki_networks.n_1", "meraki_networks.oneliner"})

    content = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(encoding="utf-8")
    assert 'resource "meraki_networks" "n_1"' not in content
    assert 'site = "hq"' not in content  # nested braces stay inside the block
    assert 'resource "meraki_networks" "oneliner"' not in content
    assert 'resource "meraki_devices" "q2ab"' in content  # untouched neighbor
    # Only the state-tracked address reaches `state rm`.
    assert fake.calls[0]["command"] == (
        "terraform", "state", "rm", "-no-color", "meraki_networks.n_1",
    )


def test_remove_resources_without_tracked_state_skips_state_rm(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        BASELINE, encoding="utf-8"
    )
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.remove_resources({"meraki_devices.q2ab"})
    assert fake.calls == []  # nothing tracked → no terraform invocation
    content = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(encoding="utf-8")
    assert 'resource "meraki_devices" "q2ab"' not in content


def test_remove_resources_with_no_targets_is_a_noop(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.remove_resources(())
    assert fake.calls == []


def test_remove_resources_tolerates_missing_baseline(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.remove_resources({"meraki_networks.n_1"})  # no resources.tf, no state
    assert fake.calls == []


def test_prune_leaves_unrelated_addresses_intact(runner: TerraformRunner) -> None:
    runner.prepare_workspace()
    baseline = runner.workdir / AGGREGATED_CONFIG_FILENAME
    baseline.write_text(BASELINE, encoding="utf-8")
    runner.remove_resources({"meraki_networks.unknown"})
    assert baseline.read_text(encoding="utf-8") == BASELINE
