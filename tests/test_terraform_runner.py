"""Terraform CLI runner: workspace management and subprocess contracts."""

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from meraki2tf import terraform_runner
from meraki2tf.terraform_runner import (
    DEFAULT_STATE_FILENAME,
    GENERATED_CONFIG_FILENAME,
    PROVIDER_FILENAME,
    TerraformError,
    TerraformRunner,
)


class FakeSubprocess:
    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.calls: list[dict[str, Any]] = []

    def run(self, command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        self.calls.append({"command": command, **kwargs})
        return SimpleNamespace(
            returncode=self.returncode, stdout=self.stdout, stderr=self.stderr
        )


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
    assert 'source = "cisco-open/meraki"' in content
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


def test_plan_clears_stale_generated_config(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    stale = runner.workdir / GENERATED_CONFIG_FILENAME
    stale.write_text("# stale", encoding="utf-8")
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.plan_with_generation()
    assert not stale.exists()


def test_apply_uses_auto_approve(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(stdout="Apply complete")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.apply()
    assert fake.calls[0]["command"] == (
        "terraform", "apply", "-input=false", "-no-color", "-auto-approve",
    )


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
