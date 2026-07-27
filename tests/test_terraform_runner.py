"""Terraform CLI runner: workspace management and subprocess contracts."""

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from meraki2tf import terraform_runner
from meraki2tf.config import BackendConfig, StateBackend
from meraki2tf.terraform_runner import (
    AGGREGATED_CONFIG_FILENAME,
    DEFAULT_STATE_FILENAME,
    GENERATED_CONFIG_FILENAME,
    LEGACY_STATE_FILENAME,
    PROVIDER_FILENAME,
    SYNC_PLAN_FILENAME,
    ImportGuardViolation,
    TerraformError,
    TerraformNotFoundError,
    TerraformRunner,
)


def _azurerm_runner(workspace: Path) -> TerraformRunner:
    backend = BackendConfig(
        backend=StateBackend.AZURERM,
        settings=(
            ("storage_account_name", "sa"),
            ("container_name", "tfstate"),
            ("key", "org.tfstate"),
        ),
    )
    return TerraformRunner(workspace, executable="terraform", backend=backend)


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
    """One (returncode, stdout, side-effect[, stderr]) step per call."""

    def __init__(self, *steps: tuple[Any, ...]) -> None:
        self.steps = list(steps)
        self.calls: list[tuple[str, ...]] = []

    def run(self, command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        self.calls.append(command)
        returncode, stdout, side_effect, *rest = self.steps.pop(0)
        if side_effect is not None:
            side_effect()
        stderr = rest[0] if rest else ""
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


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
    # identity schemas (the resource-matching ground truth) need >= 1.12
    assert 'version = ">= 1.12.0"' in content
    assert 'provider "meraki"' in content
    assert "MERAKI_DASHBOARD_API_KEY" in content  # documented, never templated
    assert "api_key" not in content


def test_run_never_logs_json_stdout_bodies(
    runner: TerraformRunner,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """terraform's machine-readable JSON (plan/state) carries sensitive
    values in plaintext; -v logs must never contain the body."""
    fake = FakeSubprocess(stdout='{"psk": "wifi-secret"}')
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with caplog.at_level("DEBUG", logger="meraki2tf.terraform_runner"):
        runner._run("show", "-json", "plan.tfplan")
    assert "wifi-secret" not in caplog.text
    assert "machine-readable" in caplog.text
    caplog.clear()
    # human-readable output stays logged (terraform masks sensitives)
    fake_plain = FakeSubprocess(stdout="Plan: 1 to import. (sensitive value)")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_plain.run)
    with caplog.at_level("DEBUG", logger="meraki2tf.terraform_runner"):
        runner._run("plan")
    assert "Plan: 1 to import" in caplog.text


def test_provider_schema_catalog_parses_identity_schemas(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    from conftest import fixture_schema_document

    fake = FakeSubprocess(stdout=json.dumps(fixture_schema_document()))
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    catalog = runner.provider_schema_catalog()
    assert fake.calls[0]["command"] == (
        "terraform", "providers", "schema", "-json",
    )
    assert catalog.resources["meraki_wireless_ssid"] == frozenset(
        {"network_id", "number"}
    )


@pytest.mark.parametrize("stdout", ["{not json", json.dumps(["not", "an", "object"])])
def test_provider_schema_catalog_rejects_unparseable_output(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch, stdout: str
) -> None:
    fake = FakeSubprocess(stdout=stdout)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with pytest.raises(TerraformError):
        runner.provider_schema_catalog()


def test_subprocess_env_bridges_dashboard_key_to_provider_var(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MERAKI_DASHBOARD_API_KEY", "dashboard-secret")
    monkeypatch.delenv("MERAKI_API_KEY", raising=False)
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.init()
    env = fake.calls[0]["env"]
    assert env["MERAKI_API_KEY"] == "dashboard-secret"
    assert env["MERAKI_DASHBOARD_API_KEY"] == "dashboard-secret"


def test_subprocess_env_never_overrides_explicit_provider_key(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MERAKI_DASHBOARD_API_KEY", "dashboard-secret")
    monkeypatch.setenv("MERAKI_API_KEY", "explicit-provider-key")
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.init()
    assert fake.calls[0]["env"]["MERAKI_API_KEY"] == "explicit-provider-key"


def test_subprocess_env_without_any_key_adds_nothing(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MERAKI_DASHBOARD_API_KEY", raising=False)
    monkeypatch.delenv("MERAKI_API_KEY", raising=False)
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.init()
    assert "MERAKI_API_KEY" not in fake.calls[0]["env"]


def test_subprocess_env_injects_throttle_resilience_defaults(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The provider's REST client defaults to 3 retries — seconds of
    tolerance against an org budget other integrations saturate for
    minutes. Every terraform subprocess gets a generous budget."""
    monkeypatch.delenv("MERAKI_RETRIES", raising=False)
    monkeypatch.delenv("MERAKI_REQUESTS_PER_SECOND", raising=False)
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.init()
    env = fake.calls[0]["env"]
    assert env["MERAKI_RETRIES"] == "30"
    assert env["MERAKI_REQUESTS_PER_SECOND"] == "5"


def test_subprocess_env_never_overrides_operator_throttle_settings(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MERAKI_RETRIES", "7")
    monkeypatch.setenv("MERAKI_REQUESTS_PER_SECOND", "2")
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.init()
    env = fake.calls[0]["env"]
    assert env["MERAKI_RETRIES"] == "7"
    assert env["MERAKI_REQUESTS_PER_SECOND"] == "2"


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


def test_state_default_avoids_terraform_legacy_filename(
    runner: TerraformRunner,
) -> None:
    """terraform init empties a workdir file named terraform.tfstate
    (legacy-state migration), so the default must never use that name."""
    assert runner.state_path.name == "meraki2tf.tfstate"


def test_state_file_named_like_legacy_state_is_refused(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    with pytest.raises(TerraformError, match="legacy state"):
        TerraformRunner(ws, state_path=ws / "terraform.tfstate")


def test_prepare_workspace_adopts_legacy_default_state(tmp_path: Path) -> None:
    """State accumulated by older versions at <workdir>/terraform.tfstate
    is renamed to the safe default before terraform can destroy it."""
    ws = tmp_path / "ws"
    ws.mkdir()
    legacy = ws / "terraform.tfstate"
    legacy.write_text('{"resources": []}', encoding="utf-8")
    runner = TerraformRunner(ws)
    runner.prepare_workspace()
    assert not legacy.exists()
    assert runner.state_path.read_text(encoding="utf-8") == '{"resources": []}'


def test_prepare_workspace_ignores_empty_legacy_state(tmp_path: Path) -> None:
    """A zero-byte legacy file (terraform's leftover) is not adopted."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "terraform.tfstate").write_text("", encoding="utf-8")
    runner = TerraformRunner(ws)
    runner.prepare_workspace()
    assert not runner.state_path.exists()


def test_prepare_workspace_keeps_custom_state_over_legacy(tmp_path: Path) -> None:
    """Legacy adoption only applies to the default location; an explicit
    --state-file is authoritative."""
    ws = tmp_path / "ws"
    ws.mkdir()
    legacy = ws / "terraform.tfstate"
    legacy.write_text('{"resources": []}', encoding="utf-8")
    custom = tmp_path / "elsewhere" / "org.tfstate"
    runner = TerraformRunner(ws, state_path=custom)
    runner.prepare_workspace()
    assert legacy.exists()  # untouched
    assert not custom.exists()


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


def test_existing_addresses_include_module_paths_and_index_keys(
    tmp_path: Path,
) -> None:
    """Operator-added modules and counted resources must be tracked by
    their full addresses, or the before/after "added to state" report
    and the skip-existing set silently miscount them. Flat tool-
    generated resources keep the bare type.name address."""
    state = tmp_path / "terraform.tfstate"
    state.write_text(
        json.dumps(
            {
                "resources": [
                    {"mode": "managed", "type": "meraki_networks", "name": "n_1"},
                    {
                        "module": "module.extras",
                        "mode": "managed",
                        "type": "meraki_networks",
                        "name": "site",
                        "instances": [{"index_key": 0}, {"index_key": 1}],
                    },
                    {
                        "mode": "managed",
                        "type": "meraki_devices",
                        "name": "edge",
                        "instances": [{"index_key": "hq"}],
                    },
                    {
                        "mode": "managed",
                        "type": "meraki_devices",
                        "name": "single",
                        "instances": [{}],  # single instance: no index part
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    assert runner.existing_addresses() == frozenset(
        {
            "meraki_networks.n_1",
            "module.extras.meraki_networks.site[0]",
            "module.extras.meraki_networks.site[1]",
            'meraki_devices.edge["hq"]',
            "meraki_devices.single",
        }
    )


def test_existing_addresses_tolerates_non_object_state(tmp_path: Path) -> None:
    state = tmp_path / "terraform.tfstate"
    state.write_text("[]", encoding="utf-8")
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    assert runner.existing_addresses() == frozenset()


def test_empty_state_file_is_treated_as_no_state(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An interrupted terraform run leaves a 0-byte state placeholder;
    the next unattended run must proceed (nothing in it to lose), not
    die at state inspection."""
    state = tmp_path / "terraform.tfstate"
    state.write_text("", encoding="utf-8")
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    with caplog.at_level("WARNING", logger="meraki2tf.terraform_runner"):
        assert runner.existing_addresses() == frozenset()
    assert any("empty" in r.message for r in caplog.records)


def test_unreadable_state_is_a_hard_error(tmp_path: Path) -> None:
    state = tmp_path / "terraform.tfstate"
    state.write_text("{corrupt", encoding="utf-8")
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    with pytest.raises(TerraformError, match="unreadable"):
        runner.existing_addresses()


def test_shape_corrupt_state_resources_dict_warns_not_silent(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Finding G4: valid JSON whose "resources" is a dict (not a list)
    must WARN and name the problem, not silently read as a fresh start
    that would let a malformed state mis-report full coverage."""
    state = tmp_path / "terraform.tfstate"
    state.write_text('{"resources": {}}', encoding="utf-8")
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    with caplog.at_level("WARNING", logger="meraki2tf.terraform_runner"):
        assert runner.existing_addresses() == frozenset()
    assert any(
        "no readable managed-resource list" in r.message and "dict" in r.message
        for r in caplog.records
    )


def test_shape_corrupt_state_resources_absent_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A valid-JSON object with no "resources" key at all is malformed,
    not empty: warn (naming it "absent") rather than a silent fresh
    start."""
    state = tmp_path / "terraform.tfstate"
    state.write_text('{"version": 4}', encoding="utf-8")
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    with caplog.at_level("WARNING", logger="meraki2tf.terraform_runner"):
        assert runner.existing_addresses() == frozenset()
    assert any(
        "no readable managed-resource list" in r.message and "absent" in r.message
        for r in caplog.records
    )


def test_genuine_empty_state_resources_list_stays_silent(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A genuine empty state {"resources": []} must NOT trip the G4
    warning — it is a legitimate fresh start."""
    state = tmp_path / "terraform.tfstate"
    state.write_text('{"resources": []}', encoding="utf-8")
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    with caplog.at_level("WARNING", logger="meraki2tf.terraform_runner"):
        assert runner.existing_addresses() == frozenset()
    assert not any(
        "no readable managed-resource list" in r.message for r in caplog.records
    )


def test_state_organization_reads_unanimous_local_org(tmp_path: Path) -> None:
    """Finding G1: the runner surfaces the single organization_id every
    managed instance carries, reusing the preflight extraction."""
    state = tmp_path / "terraform.tfstate"
    state.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "mode": "managed",
                        "type": "meraki_networks",
                        "name": "n_1",
                        "instances": [
                            {"attributes": {"organization_id": "654321"}}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    assert runner.state_organization() == "654321"


def test_state_organization_none_for_empty_local_state(tmp_path: Path) -> None:
    """No state file → no organization to compare (fresh start allowed)."""
    runner = TerraformRunner(tmp_path / "ws", state_path=tmp_path / "absent.tfstate")
    assert runner.state_organization() is None


def test_state_organization_none_when_local_instances_disagree(
    tmp_path: Path,
) -> None:
    """Ambiguous state cannot vouch for an organization → None."""
    state = tmp_path / "terraform.tfstate"
    state.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "mode": "managed",
                        "type": "meraki_networks",
                        "name": "a",
                        "instances": [
                            {"attributes": {"organization_id": "111111"}},
                            {"attributes": {"organization_id": "222222"}},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    runner = TerraformRunner(tmp_path / "ws", state_path=state)
    assert runner.state_organization() is None


def test_azurerm_state_organization_read_via_show_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Finding G1 also covers the remote backend: the org is read from
    the managed resources' values.organization_id in show -json,
    descending child modules."""
    runner = _azurerm_runner(tmp_path / "ws")
    state_json = json.dumps(
        {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "meraki_networks",
                            "name": "n_1",
                            "values": {"organization_id": "654321"},
                        },
                        {
                            "mode": "data",
                            "type": "meraki_networks",
                            "name": "lookup",
                            "values": {"organization_id": "ignored"},
                        },
                        {
                            "mode": "managed",
                            "type": "meraki_devices",
                            "name": "no_values",
                        },
                    ],
                    "child_modules": [
                        {
                            "resources": [
                                {
                                    "mode": "managed",
                                    "type": "meraki_devices",
                                    "name": "edge",
                                    "values": {"organization_id": "654321"},
                                }
                            ]
                        }
                    ],
                }
            }
        }
    )
    script = ScriptedSubprocess(
        (0, "Initialized", None),
        (0, state_json, None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", script.run)
    assert runner.state_organization() == "654321"


def test_azurerm_state_organization_none_when_ambiguous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _azurerm_runner(tmp_path / "ws")
    state_json = json.dumps(
        {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "mode": "managed",
                            "type": "meraki_networks",
                            "name": "a",
                            "values": {"organization_id": "111111"},
                        },
                        {
                            "mode": "managed",
                            "type": "meraki_networks",
                            "name": "b",
                            "values": {"organization_id": "222222"},
                        },
                    ]
                }
            }
        }
    )
    script = ScriptedSubprocess(
        (0, "Initialized", None),
        (0, state_json, None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", script.run)
    assert runner.state_organization() is None


def test_azurerm_state_organization_none_for_empty_remote_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = ScriptedSubprocess(
        (0, "Initialized", None),
        (0, json.dumps({"format_version": "1.0"}), None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", script.run)
    runner = _azurerm_runner(tmp_path / "ws")
    assert runner.state_organization() is None


def test_azurerm_state_organization_rejects_unparseable_show(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = ScriptedSubprocess(
        (0, "Initialized", None),
        (0, "{not json", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", script.run)
    runner = _azurerm_runner(tmp_path / "ws")
    with pytest.raises(TerraformError, match="unparseable state"):
        runner.state_organization()


# --- Remote (azurerm) backend --------------------------------------------


def test_azurerm_prepare_workspace_writes_partial_backend(tmp_path: Path) -> None:
    runner = _azurerm_runner(tmp_path / "ws")
    provider_file = runner.prepare_workspace()
    content = provider_file.read_text(encoding="utf-8")
    assert 'backend "azurerm" {' in content
    assert "path =" not in content  # no local state path leaks into the block
    # No local state file is created/anchored for a remote backend.
    assert not (runner.workdir / DEFAULT_STATE_FILENAME).exists()


def test_azurerm_does_not_refuse_legacy_state_filename(tmp_path: Path) -> None:
    """The terraform.tfstate legacy-name guard is a local-backend concern;
    a remote backend never writes a local file, so it must not trip it."""
    ws = tmp_path / "ws"
    backend = BackendConfig(
        backend=StateBackend.AZURERM,
        settings=(("container_name", "c"), ("storage_account_name", "s"), ("key", "k")),
    )
    # Would raise for a local backend; must be accepted for a remote one.
    TerraformRunner(ws, state_path=ws / LEGACY_STATE_FILENAME, backend=backend)


def test_azurerm_init_passes_backend_config_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _azurerm_runner(tmp_path / "ws")
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.init()
    assert fake.calls[0]["command"] == (
        "terraform", "init", "-input=false", "-no-color", "-reconfigure",
        "-backend-config=storage_account_name=sa",
        "-backend-config=container_name=tfstate",
        "-backend-config=key=org.tfstate",
    )


def test_backend_config_file_is_passed_to_init(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = BackendConfig(
        backend=StateBackend.AZURERM, config_file=Path("azure.tfbackend")
    )
    runner = TerraformRunner(tmp_path / "ws", backend=backend)
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.init()
    assert "-backend-config=azure.tfbackend" in fake.calls[0]["command"]


@pytest.mark.parametrize(
    "state_backend, settings",
    [
        (
            StateBackend.S3,
            (
                ("bucket", "meraki-dr-state"),
                ("key", "org.tfstate"),
                ("region", "us-east-1"),
            ),
        ),
        (StateBackend.GCS, (("bucket", "meraki-dr-state"), ("prefix", "org"))),
    ],
)
def test_s3_and_gcs_render_partial_backend_and_init_args(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    state_backend: StateBackend,
    settings: tuple[tuple[str, str], ...],
) -> None:
    """The remote-backend path is backend-agnostic: s3 and gcs get the
    same partial block + -backend-config treatment as azurerm."""
    backend = BackendConfig(backend=state_backend, settings=settings)
    runner = TerraformRunner(
        tmp_path / "ws", executable="terraform", backend=backend
    )
    content = runner.prepare_workspace().read_text(encoding="utf-8")
    assert f'backend "{state_backend.value}" {{' in content
    assert "path =" not in content
    assert not (runner.workdir / DEFAULT_STATE_FILENAME).exists()
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.init()
    expected = tuple(f"-backend-config={key}={value}" for key, value in settings)
    assert fake.calls[0]["command"][-len(expected):] == expected


@pytest.mark.parametrize(
    "state_backend, hint",
    [
        (StateBackend.AZURERM, "ARM_ACCESS_KEY"),
        (StateBackend.S3, "AWS_ACCESS_KEY_ID"),
        (StateBackend.GCS, "GOOGLE_APPLICATION_CREDENTIALS"),
    ],
)
def test_backend_block_comment_names_the_backends_credential_env(
    tmp_path: Path, state_backend: StateBackend, hint: str
) -> None:
    """The partial-block comment names each backend's own credential
    environment variables (mirroring the --backend-config refusal
    message), so an operator reading provider.tf knows what to export."""
    backend = BackendConfig(backend=state_backend)
    runner = TerraformRunner(
        tmp_path / "ws", executable="terraform", backend=backend
    )
    content = runner.prepare_workspace().read_text(encoding="utf-8")
    assert f'backend "{state_backend.value}" {{' in content
    assert hint in content


def test_init_is_cached_and_runs_once_per_runner(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(stdout="Initialized")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    first = runner.init()
    second = runner.init()
    assert first is second  # cached result
    assert len(fake.calls) == 1  # only one terraform init subprocess


def test_azurerm_existing_addresses_read_via_show_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _azurerm_runner(tmp_path / "ws")
    state_json = json.dumps(
        {
            "values": {
                "root_module": {
                    "resources": [
                        {"mode": "managed", "type": "meraki_networks", "name": "n_1"},
                        {"mode": "managed", "type": "meraki_devices", "name": "q2ab"},
                        {"mode": "data", "type": "meraki_networks", "name": "lookup"},
                    ]
                }
            }
        }
    )
    # init returns "Initialized"; show returns the state JSON.
    script = ScriptedSubprocess(
        (0, "Initialized", None),
        (0, state_json, None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", script.run)
    assert runner.existing_addresses() == frozenset(
        {"meraki_networks.n_1", "meraki_devices.q2ab"}
    )
    # Self-initialized before reading, then read state without a plan file.
    assert script.calls[0][1] == "init"
    assert script.calls[1][:2] == ("terraform", "show")
    assert SYNC_PLAN_FILENAME not in script.calls[1]


def test_azurerm_existing_addresses_descend_child_modules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """show -json nests module resources under child_modules (itself
    recursive) and carries full addresses (module path + index key) on
    each entry; the remote reader must not lose either."""
    runner = _azurerm_runner(tmp_path / "ws")
    state_json = json.dumps(
        {
            "values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "meraki_networks.n_1",
                            "mode": "managed",
                            "type": "meraki_networks",
                            "name": "n_1",
                        },
                        {
                            "address": 'meraki_devices.edge["hq"]',
                            "mode": "managed",
                            "type": "meraki_devices",
                            "name": "edge",
                            "index": "hq",
                        },
                    ],
                    "child_modules": [
                        {
                            "address": "module.extras",
                            "resources": [
                                {
                                    "address": (
                                        "module.extras.meraki_networks.site[0]"
                                    ),
                                    "mode": "managed",
                                    "type": "meraki_networks",
                                    "name": "site",
                                    "index": 0,
                                },
                                {
                                    "address": (
                                        "module.extras.data.meraki_networks.look"
                                    ),
                                    "mode": "data",
                                    "type": "meraki_networks",
                                    "name": "look",
                                },
                            ],
                            "child_modules": [
                                {
                                    "address": "module.extras.module.deep",
                                    "resources": [
                                        {
                                            "address": (
                                                "module.extras.module.deep."
                                                "meraki_devices.q2ab"
                                            ),
                                            "mode": "managed",
                                            "type": "meraki_devices",
                                            "name": "q2ab",
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            }
        }
    )
    script = ScriptedSubprocess(
        (0, "Initialized", None),
        (0, state_json, None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", script.run)
    assert runner.existing_addresses() == frozenset(
        {
            "meraki_networks.n_1",
            'meraki_devices.edge["hq"]',
            "module.extras.meraki_networks.site[0]",
            "module.extras.module.deep.meraki_devices.q2ab",
        }
    )


def test_azurerm_existing_addresses_empty_when_no_remote_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An uninitialized/empty remote state has no 'values' key."""
    script = ScriptedSubprocess(
        (0, "Initialized", None),
        (0, json.dumps({"format_version": "1.0"}), None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", script.run)
    runner = _azurerm_runner(tmp_path / "ws")
    assert runner.existing_addresses() == frozenset()


def test_azurerm_existing_addresses_rejects_unparseable_show(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = ScriptedSubprocess(
        (0, "Initialized", None),
        (0, "{not json", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", script.run)
    runner = _azurerm_runner(tmp_path / "ws")
    with pytest.raises(TerraformError, match="unparseable state"):
        runner.existing_addresses()


def test_azurerm_state_permissions_are_a_no_op(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Remote backends keep no local state file, so the 0600 guard must
    short-circuit before ever touching the filesystem."""
    def boom(_path: Path) -> bool:
        raise AssertionError("remote backend must not chmod a local state file")

    monkeypatch.setattr(terraform_runner, "restrict_to_owner", boom)
    runner = _azurerm_runner(tmp_path / "ws")
    runner._restrict_state_permissions()  # returns early; no exception


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
    result = runner.plan_with_generation(reconcile=False)
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
    result = runner.plan_with_generation(reconcile=False)
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
    assert runner.plan_with_generation(reconcile=False).has_drift is True


def test_summary_without_import_count_still_parses(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(
        returncode=2, stdout="Plan: 1 to add, 0 to change, 0 to destroy."
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    assert runner.plan_with_generation(reconcile=False).has_drift is True


def test_unparseable_plan_falls_back_to_exit_code(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(returncode=2, stdout="~ resource delta")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    result = runner.plan_with_generation(reconcile=False)
    assert result.has_drift is True
    assert result.plan_counts is None


def test_converged_plan_reports_zero_counts_not_unknown(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fully converged plan has no ``Plan:`` line, only the no-changes
    sentence — that is a definitive zero, so idempotent reruns must not
    degrade the run summary to "pending imports unknown"."""
    fake = FakeSubprocess(
        returncode=0,
        stdout=(
            "No changes. Your infrastructure matches the configuration.\n\n"
            "Terraform has compared your real infrastructure against your "
            "configuration and found no differences, so no changes are "
            "needed.\n"
        ),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    result = runner.plan_with_generation(reconcile=False)
    counts = result.plan_counts
    assert counts is not None
    assert (counts.imports, counts.add, counts.change, counts.destroy) == (0, 0, 0, 0)
    assert counts.has_real_changes is False
    assert result.has_drift is False


def test_plan_summary_ignores_a_spoofed_line_in_the_diff_body(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Meraki-controlled attribute value (a rule comment) rendered in
    the plan diff can impersonate the summary line; the parser must
    anchor on terraform's own column-0 line and take the LAST one, so a
    real destroy is never masked into a no-op."""
    fake = FakeSubprocess(
        returncode=2,
        stdout=(
            "  # meraki_appliance_firewall.rules will be updated in-place\n"
            "      ~ comment = \"Plan: 0 to add, 0 to change, 0 to destroy\"\n"
            "\n"
            "Plan: 0 to import, 0 to add, 0 to change, 1 to destroy.\n"
        ),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    result = runner.plan_with_generation(reconcile=False)
    counts = result.plan_counts
    assert counts is not None
    assert counts.destroy == 1
    assert counts.has_real_changes is True
    assert result.has_drift is True


def test_plan_counts_expose_pending_imports_and_changes(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(
        returncode=2,
        stdout="Plan: 875 to import, 1 to add, 2 to change, 3 to destroy.",
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    counts = runner.plan_with_generation(reconcile=False).plan_counts
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
    runner.plan_with_generation(reconcile=False)

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
    assert terraform_runner.hcl_quote("a\nb\rc\td") == "a\\nb\\rc\\td"


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


def test_rebuild_apply_consumes_the_previewed_plan_file(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The confirmed apply executes exactly the plan the preview
    snapshotted for this run — never the fixed-name file (a concurrent
    run can rewrite that between preview and apply) and never an
    unattended ``-auto-approve`` re-plan."""

    def planning_run(command: Any, **kwargs: Any) -> Any:
        if "plan" in command:
            (
                runner.workdir / terraform_runner.REBUILD_PLAN_FILENAME
            ).write_text("saved-plan", encoding="utf-8")
        return fake.run(command, **kwargs)

    fake = FakeSubprocess(stdout="Apply complete")
    monkeypatch.setattr(terraform_runner.subprocess, "run", planning_run)
    runner.workdir.mkdir(parents=True, exist_ok=True)
    plan_file = runner.workdir / terraform_runner.REBUILD_PLAN_FILENAME
    runner.plan_preview()
    verified_name = (
        f"{terraform_runner.REBUILD_PLAN_FILENAME}.verified-{os.getpid()}"
    )
    assert (runner.workdir / verified_name).exists()
    # A concurrent run swapping the shared filename after the preview
    # must not change what the confirmed apply executes.
    plan_file.write_text("swapped-by-another-run", encoding="utf-8")
    runner.rebuild_apply()
    assert fake.calls[-1]["command"] == (
        "terraform", "apply", "-input=false", "-no-color", verified_name,
    )
    # Consume-or-delete: saved plans embed refreshed sensitive values.
    assert not plan_file.exists()
    assert not (runner.workdir / verified_name).exists()


def test_rebuild_apply_refuses_without_a_saved_plan(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeSubprocess(stdout="Apply complete")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.workdir.mkdir(parents=True, exist_ok=True)
    # Even a plan file already on disk is refused: without this run's
    # preview snapshot there is no verified document to bind the apply to.
    (runner.workdir / terraform_runner.REBUILD_PLAN_FILENAME).write_text(
        "planted", encoding="utf-8"
    )
    with pytest.raises(TerraformError, match="No saved rebuild plan"):
        runner.rebuild_apply()
    assert fake.calls == []


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
    """The guard inspects the saved plan document itself — never a fresh
    full-kit re-plan, which is a multi-hour read window a busy org races
    with new edits — then applies that exact file."""
    runner.prepare_workspace()
    (runner.workdir / SYNC_PLAN_FILENAME).write_bytes(b"opaque-plan")
    show_json = json.dumps(
        {
            "resource_changes": [
                {
                    "address": "meraki_networks.n_1",
                    "change": {"actions": ["no-op"], "importing": {"id": "N_1"}},
                },
                {
                    "address": "meraki_devices.q2ab",
                    "change": {"actions": ["no-op"], "importing": {"id": "Q2AB"}},
                },
            ]
        }
    )
    scripted = ScriptedSubprocess(
        (0, show_json, None),
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

    show_command, apply_command = scripted.calls
    assert show_command[1] == "show"
    # Verification and apply are bound to the same run-private COPY of
    # the plan file, so a concurrent run rewriting the shared filename
    # cannot swap in a mutating plan between the two steps.
    verified_name = show_command[-1]
    assert verified_name.startswith(f"{SYNC_PLAN_FILENAME}.verified-")
    assert apply_command == (
        "terraform", "apply", "-input=false", "-no-color", verified_name,
    )
    assert added == ("meraki_devices.q2ab", "meraki_networks.n_1")
    assert not (runner.workdir / SYNC_PLAN_FILENAME).exists()
    assert not (runner.workdir / verified_name).exists()


def test_apply_import_plan_noop_when_state_is_current(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    (runner.workdir / SYNC_PLAN_FILENAME).write_bytes(b"opaque-plan")
    scripted = ScriptedSubprocess(
        (0, json.dumps({"resource_changes": []}), None)
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    assert runner.apply_import_plan() == ()
    assert len(scripted.calls) == 1  # show only; nothing to apply


def test_guard_refuses_saved_plans_with_mutations(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    (runner.workdir / SYNC_PLAN_FILENAME).write_bytes(b"opaque-plan")
    show_json = json.dumps(
        {
            "resource_changes": [
                {
                    "address": "meraki_networks.n_1",
                    "change": {"actions": ["no-op"], "importing": {"id": "N_1"}},
                },
                {
                    "address": "meraki_network_snmp.l_1",
                    "change": {"actions": ["update"]},
                },
            ]
        }
    )
    scripted = ScriptedSubprocess((0, show_json, None))
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(ImportGuardViolation, match="mutations") as excinfo:
        runner.apply_import_plan()
    assert len(scripted.calls) == 1  # refused before any apply
    assert "meraki_network_snmp.l_1" in excinfo.value.plan_output


def test_guard_refuses_deposed_delete_shadowed_by_current_noop(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One address can carry two entries — a deposed object's delete
    alongside the current object's no-op import. The delete used to be
    dict-overwritten by the later entry, letting a mutating plan pass
    the import-only guard."""
    runner.prepare_workspace()
    (runner.workdir / SYNC_PLAN_FILENAME).write_bytes(b"opaque-plan")
    show_json = json.dumps(
        {
            "resource_changes": [
                {
                    "address": "meraki_networks.n_1",
                    "deposed": "abcd1234",
                    "change": {"actions": ["delete"]},
                },
                {
                    "address": "meraki_networks.n_1",
                    "change": {"actions": ["no-op"], "importing": {"id": "N_1"}},
                },
            ]
        }
    )
    scripted = ScriptedSubprocess((0, show_json, None))
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(ImportGuardViolation, match="mutations"):
        runner.apply_import_plan()
    assert len(scripted.calls) == 1  # refused before any apply


def test_discard_saved_plan_removes_the_secret_bearing_file(
    runner: TerraformRunner,
) -> None:
    """Sync paths that plan but never apply must not leave the saved
    plan (which embeds refreshed secrets like the state file) at rest."""
    runner.prepare_workspace()
    plan_file = runner.workdir / SYNC_PLAN_FILENAME
    plan_file.write_bytes(b"opaque-plan")
    runner.discard_saved_plan()
    assert not plan_file.exists()
    runner.discard_saved_plan()  # idempotent when nothing lingers


def test_guard_refuses_unverifiable_plans(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unparseable show output → fail safe, never apply."""
    runner.prepare_workspace()
    (runner.workdir / SYNC_PLAN_FILENAME).write_bytes(b"opaque-plan")
    scripted = ScriptedSubprocess((0, "~ not json", None))
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(ImportGuardViolation, match="could not be verified"):
        runner.apply_import_plan()
    assert len(scripted.calls) == 1


def test_guard_refuses_when_no_saved_plan_exists(
    runner: TerraformRunner,
) -> None:
    runner.prepare_workspace()
    with pytest.raises(ImportGuardViolation, match="no saved plan"):
        runner.apply_import_plan()


def test_guard_violation_is_a_terraform_error() -> None:
    """Callers that only know TerraformError still fail closed."""
    assert issubclass(ImportGuardViolation, TerraformError)


def test_plan_with_generation_always_saves_the_plan(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reconciliation classifies the saved plan via show -json, so the
    generation plan is always written to the sync plan file."""
    runner.prepare_workspace()
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    runner.plan_with_generation(save_plan=True)
    assert f"-out={SYNC_PLAN_FILENAME}" in fake.calls[0]["command"]
    runner.plan_with_generation()
    assert f"-out={SYNC_PLAN_FILENAME}" in fake.calls[1]["command"]


def test_plan_deletes_saved_plan_unless_an_apply_will_consume_it(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The saved plan embeds refreshed secret values; runs that never
    apply (save_plan=False) must not leave it in the workdir, and while
    it exists it is owner-only like the state file."""
    runner.prepare_workspace()
    plan_file = runner.workdir / SYNC_PLAN_FILENAME

    def write_plan() -> None:
        plan_file.write_bytes(b"opaque-plan")
        plan_file.chmod(0o644)  # terraform writes with umask defaults

    fake = FakeSubprocess(returncode=0, on_run=write_plan)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)

    runner.plan_with_generation()  # default: nothing will apply it
    assert not plan_file.exists()

    runner.plan_with_generation(save_plan=True)  # sync: the guard needs it
    assert plan_file.exists()
    assert (plan_file.stat().st_mode & 0o777) == 0o600


def test_guard_refuses_malformed_plan_document_entries(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An entry the lenient parser would skip (no address) must read as
    "unverifiable" inside the guard, never as "no mutation"."""
    runner.prepare_workspace()
    (runner.workdir / SYNC_PLAN_FILENAME).write_bytes(b"opaque-plan")
    show_json = json.dumps(
        {"resource_changes": [{"change": {"actions": ["delete"]}}]}
    )
    scripted = ScriptedSubprocess((0, show_json, None))
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(ImportGuardViolation, match="shape cannot be verified"):
        runner.apply_import_plan()
    assert len(scripted.calls) == 1  # refused before any apply


def test_guard_refuses_empty_actions_list_as_malformed(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An entry with an EMPTY actions list would pass the harmless
    check vacuously; the guard refuses anything it cannot verify."""
    runner.prepare_workspace()
    (runner.workdir / SYNC_PLAN_FILENAME).write_bytes(b"opaque-plan")
    show_json = json.dumps(
        {
            "resource_changes": [
                {"address": "meraki_networks.n_1", "change": {"actions": []}}
            ]
        }
    )
    scripted = ScriptedSubprocess((0, show_json, None))
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(ImportGuardViolation, match="shape cannot be verified"):
        runner.apply_import_plan()
    assert len(scripted.calls) == 1  # refused before any apply


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

GENERATED_BASELINE = """\
# __generated__ by Terraform from "L_1,route-1"
resource "meraki_appliance_static_route" "l_1_route_1" {
  name = "rt-a"
}

# __generated__ by Terraform from "L_1,route-2"
resource "meraki_appliance_static_route" "l_1_route_2" {
  name = "rt-b"
}
"""


def test_prune_baseline_removes_generated_comment_with_block(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pruned block's __generated__ header must not orphan above the next."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        GENERATED_BASELINE, encoding="utf-8"
    )
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)

    runner.remove_resources({"meraki_appliance_static_route.l_1_route_1"})

    content = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(
        encoding="utf-8"
    )
    assert "route-1" not in content  # comment went with its block
    assert "rt-a" not in content
    assert '# __generated__ by Terraform from "L_1,route-2"' in content
    assert "rt-b" in content


def test_remove_resources_prunes_baseline_and_state(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        BASELINE, encoding="utf-8"
    )
    _write_state(runner.state_path, "meraki_networks.n_1", "meraki_devices.q2ab")
    backup = runner.state_path.with_name(runner.state_path.name + ".backup")

    def write_backup() -> None:
        backup.write_text("{}", encoding="utf-8")
        backup.chmod(0o644)  # terraform writes with umask defaults

    fake = FakeSubprocess(returncode=0, on_run=write_backup)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)

    runner.remove_resources({"meraki_networks.n_1", "meraki_networks.oneliner"})

    # The backup exists only to survive a crash mid-removal; after a
    # successful rm it is a plaintext secret-bearing state copy with no
    # purpose (under a remote backend it would be the only local state
    # material), so it must not persist.
    assert not backup.exists()

    content = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(encoding="utf-8")
    assert 'resource "meraki_networks" "n_1"' not in content
    assert 'site = "hq"' not in content  # nested braces stay inside the block
    assert 'resource "meraki_networks" "oneliner"' not in content
    assert 'resource "meraki_devices" "q2ab"' in content  # untouched neighbor
    # Only the state-tracked address reaches `state rm`, and the
    # secret-bearing pre-removal backup lands on the fixed 0600-managed
    # path instead of terraform's timestamped default.
    assert fake.calls[0]["command"] == (
        "terraform", "state", "rm", "-no-color",
        f"-backup={runner.state_path.with_name(runner.state_path.name + '.backup')}",
        "meraki_networks.n_1",
    )


def test_remove_resources_reports_requested_vs_removed(
    runner: TerraformRunner,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The removal log must not under-count: an address already absent
    from state (e.g. dropped by an earlier refresh) is reported, not
    silently folded into a smaller 'Removed N' figure."""
    runner.prepare_workspace()
    _write_state(runner.state_path, "meraki_networks.n_1", "meraki_networks.n_2")
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)

    with caplog.at_level("INFO", logger="meraki2tf.terraform_runner"):
        runner.remove_resources({"meraki_networks.n_1", "meraki_networks.gone"})
    assert "Removed 1 of 2 requested resource(s)" in caplog.text
    assert "1 already absent" in caplog.text

    caplog.clear()
    with caplog.at_level("INFO", logger="meraki2tf.terraform_runner"):
        runner.remove_resources({"meraki_networks.n_2"})
    assert "Removed 1 of 1 requested resource(s) from the Terraform state." in caplog.text
    assert "already absent" not in caplog.text


def test_remove_resources_failure_keeps_backup_for_recovery(
    runner: TerraformRunner,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A failed state rm may have half-modified the state; the
    pre-removal backup is the recovery copy — kept, owner-only, with
    its location logged for the operator."""
    runner.prepare_workspace()
    _write_state(runner.state_path, "meraki_networks.n_1")
    backup = runner.state_path.with_name(runner.state_path.name + ".backup")

    def write_backup() -> None:
        backup.write_text("{}", encoding="utf-8")
        backup.chmod(0o644)  # terraform writes with umask defaults

    fake = FakeSubprocess(
        returncode=1, stderr="state rm blew up", on_run=write_backup
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with caplog.at_level("WARNING", logger="meraki2tf.terraform_runner"):
        with pytest.raises(TerraformError, match="state rm blew up"):
            runner.remove_resources({"meraki_networks.n_1"})
    assert backup.exists()
    assert (backup.stat().st_mode & 0o777) == 0o600
    assert any(str(backup) in record.message for record in caplog.records)


def test_remove_resources_failure_without_backup_just_raises(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """state rm can fail before terraform ever writes the backup."""
    runner.prepare_workspace()
    _write_state(runner.state_path, "meraki_networks.n_1")
    fake = FakeSubprocess(returncode=1, stderr="no lock")
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with pytest.raises(TerraformError, match="no lock"):
        runner.remove_resources({"meraki_networks.n_1"})
    backup = runner.state_path.with_name(runner.state_path.name + ".backup")
    assert not backup.exists()


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


VALIDATION_STDERR = """\
Error: Invalid Attribute Value Match

  with meraki_network_firmware_upgrades.l_1,
  on generated_resources.tf line 30:
  (source code not available)

Attribute upgrade_window_day_of_week value must be one of: ["mon"], got: "Never"
"""

#: Same failure shape but a pure case mismatch — repairable in place.
CASE_VALIDATION_STDERR = """\
Error: Invalid Attribute Value Match

  with meraki_network_firmware_upgrades.l_1,
  on generated_resources.tf line 30:
  (source code not available)

Attribute upgrade_window_day_of_week value must be one of: ["mon"], got: "Mon"
"""

FIRMWARE_BLOCK = (
    'resource "meraki_network_firmware_upgrades" "l_1" {\n'
    '  network_id = "L_1"\n'
    "}\n"
)

FIRMWARE_CASE_BLOCK = (
    'resource "meraki_network_firmware_upgrades" "l_1" {\n'
    '  network_id                 = "L_1"\n'
    '  upgrade_window_day_of_week = "Mon"\n'
    "}\n"
)
FIRMWARE_IMPORT = (
    "import {\n"
    "  to = meraki_network_firmware_upgrades.l_1\n"
    '  id = "L_1"\n'
    "}\n"
)
SECRET_PLAN_JSON = json.dumps(
    {
        "resource_changes": [
            {
                "address": "meraki_network_snmp.l_1",
                "change": {
                    "actions": ["update"],
                    "before": {"community_string": "s3cret"},
                    "after": {"community_string": None},
                    "before_sensitive": {"community_string": True},
                    "after_sensitive": {},
                },
            }
        ]
    }
)
SNMP_BLOCK = (
    'resource "meraki_network_snmp" "l_1" {\n'
    '  access = "community"\n'
    "}\n"
)


def test_reconciliation_drops_unexpressible_resources_then_replans(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Validation failure → drop the kit artifacts → replan clean."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        FIRMWARE_BLOCK, encoding="utf-8"
    )
    (runner.workdir / "imports.tf").write_text(FIRMWARE_IMPORT, encoding="utf-8")
    scripted = ScriptedSubprocess(
        (1, "", None, VALIDATION_STDERR),
        (0, "No changes.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert outcome.has_changes is False
    assert set(outcome.dropped) == {"meraki_network_firmware_upgrades.l_1"}
    assert "Invalid Attribute Value Match" in outcome.dropped[
        "meraki_network_firmware_upgrades.l_1"
    ]
    baseline = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(
        encoding="utf-8"
    )
    assert "firmware_upgrades" not in baseline
    imports = (runner.workdir / "imports.tf").read_text(encoding="utf-8")
    assert "firmware_upgrades" not in imports
    assert [c[1] for c in scripted.calls] == ["plan", "plan"]


def test_reconciliation_repairs_enum_case_then_replans(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pure enum-case rejection is repaired in place (recased value +
    ignore_changes pin) and the resource stays in the kit."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        FIRMWARE_CASE_BLOCK, encoding="utf-8"
    )
    (runner.workdir / "imports.tf").write_text(FIRMWARE_IMPORT, encoding="utf-8")
    scripted = ScriptedSubprocess(
        (1, "", None, CASE_VALIDATION_STDERR),
        (0, "No changes.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert outcome.dropped == {}
    assert outcome.normalized == {
        "meraki_network_firmware_upgrades.l_1": (
            "upgrade_window_day_of_week",
        )
    }
    baseline = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(
        encoding="utf-8"
    )
    assert 'upgrade_window_day_of_week = "mon"' in baseline
    assert "ignore_changes = [upgrade_window_day_of_week]" in baseline
    imports = (runner.workdir / "imports.tf").read_text(encoding="utf-8")
    assert "firmware_upgrades" in imports  # kit keeps the resource
    assert [c[1] for c in scripted.calls] == ["plan", "plan"]


def test_reconciliation_drops_resource_when_case_repair_does_not_take(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The validator rejecting the same attribute again after a repair
    means recasing did not help — drop instead of looping forever, and
    report the resource as dropped, not normalized."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        FIRMWARE_CASE_BLOCK, encoding="utf-8"
    )
    (runner.workdir / "imports.tf").write_text(FIRMWARE_IMPORT, encoding="utf-8")
    scripted = ScriptedSubprocess(
        (1, "", None, CASE_VALIDATION_STDERR),
        (1, "", None, CASE_VALIDATION_STDERR),
        (0, "No changes.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert set(outcome.dropped) == {"meraki_network_firmware_upgrades.l_1"}
    assert outcome.normalized == {}
    baseline = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(
        encoding="utf-8"
    )
    assert "firmware_upgrades" not in baseline
    assert [c[1] for c in scripted.calls] == ["plan", "plan", "plan"]


def test_reconciliation_suppresses_secret_nulls_then_replans(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changes → classify via show -json → lifecycle edit → replan."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        SNMP_BLOCK, encoding="utf-8"
    )
    scripted = ScriptedSubprocess(
        (2, "Plan: 1 to import, 0 to add, 1 to change, 0 to destroy.", None),
        (0, SECRET_PLAN_JSON, None),  # show -json
        (2, "Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert outcome.ignored_secrets == {
        "meraki_network_snmp.l_1": ("community_string",)
    }
    assert outcome.has_drift is False
    baseline = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(
        encoding="utf-8"
    )
    assert "ignore_changes = [community_string]" in baseline
    assert [c[1] for c in scripted.calls] == ["plan", "show", "plan"]


def test_reconciliation_new_attribute_on_same_address_is_progress(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Progress is tracked per (address, attribute): a second pass
    proposing a different attribute of an already-edited resource must
    keep the loop going, and the report merges the attribute tuples."""
    second_attr_json = json.dumps(
        {
            "resource_changes": [
                {
                    "address": "meraki_network_snmp.l_1",
                    "change": {
                        "actions": ["update"],
                        "before": {"users_string": "u"},
                        "after": {"users_string": None},
                        "before_sensitive": {"users_string": True},
                        "after_sensitive": {},
                    },
                }
            ]
        }
    )
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        SNMP_BLOCK, encoding="utf-8"
    )
    changes = "Plan: 0 to import, 0 to add, 1 to change, 0 to destroy."
    scripted = ScriptedSubprocess(
        (2, changes, None),
        (0, SECRET_PLAN_JSON, None),  # pass 1: community_string
        (2, changes, None),
        (0, second_attr_json, None),  # pass 2: users_string -> progress
        (0, "Plan: 1 to import, 0 to add, 0 to change, 0 to destroy.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert outcome.ignored_secrets == {
        "meraki_network_snmp.l_1": ("community_string", "users_string")
    }
    assert outcome.has_drift is False
    assert [c[1] for c in scripted.calls] == [
        "plan", "show", "plan", "show", "plan",
    ]


def test_reconciliation_stops_when_remediations_make_no_progress(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A diff that keeps re-proposing already-applied remediations is
    surfaced as drift instead of looping (re-editing cannot help)."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        SNMP_BLOCK, encoding="utf-8"
    )
    changes = "Plan: 0 to import, 0 to add, 1 to change, 0 to destroy."
    scripted = ScriptedSubprocess(
        (2, changes, None),
        (0, SECRET_PLAN_JSON, None),
        (2, changes, None),
        (0, SECRET_PLAN_JSON, None),  # same remediation again -> break
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert outcome.has_drift is True  # surfaced as drift, not retried
    assert [c[1] for c in scripted.calls] == [
        "plan", "show", "plan", "show",
    ]


def test_reconciliation_breaks_when_nothing_is_remediable(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_change_json = json.dumps(
        {
            "resource_changes": [
                {
                    "address": "meraki_networks.n_1",
                    "change": {
                        "actions": ["update"],
                        "before": {"name": "old"},
                        "after": {"name": "new"},
                        "before_sensitive": {},
                        "after_sensitive": {},
                    },
                }
            ]
        }
    )
    runner.prepare_workspace()
    scripted = ScriptedSubprocess(
        (2, "Plan: 0 to import, 0 to add, 1 to change, 0 to destroy.", None),
        (0, real_change_json, None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert outcome.has_drift is True
    assert outcome.dropped == {} and outcome.ignored_secrets == {}
    assert [c[1] for c in scripted.calls] == ["plan", "show"]


def test_validation_errors_without_addresses_still_raise(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    scripted = ScriptedSubprocess(
        (1, "", None, "Error: Unable to find API key\n\nboom\n"),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(TerraformError, match="Unable to find API key"):
        runner.plan_with_generation()


THROTTLED_PLAN_STDERR = (
    "Error: Client Error\n"
    "\n"
    "Failed to retrieve object (GET), got error: HTTP Request failed: StatusCode\n"
    '429, {"errors":["API rate limit exceeded for organization"]}\n'
)


def test_plan_retries_when_only_throttled(
    runner: TerraformRunner,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A plan that failed purely because the provider was rate-limited
    is transient — retried, never surfaced as a pipeline fault."""
    runner.prepare_workspace()
    scripted = ScriptedSubprocess(
        (1, "", None, THROTTLED_PLAN_STDERR),
        (0, "No changes.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with caplog.at_level("WARNING", logger="meraki2tf.terraform_runner"):
        outcome = runner.plan_with_generation()
    assert outcome.has_changes is False
    assert outcome.dropped == {}
    assert [c[1] for c in scripted.calls] == ["plan", "plan"]
    assert any("rate-limited" in r.message for r in caplog.records)


def test_plan_throttled_on_final_attempt_still_raises(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    steps = [
        (1, "", None, THROTTLED_PLAN_STDERR)
        for _ in range(runner._MAX_PLAN_ATTEMPTS)
    ]
    scripted = ScriptedSubprocess(*steps)
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(TerraformError, match="StatusCode"):
        runner.plan_with_generation()


def test_plan_with_persistent_failures_raises_on_final_attempt(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure that survives dropping every attempt (e.g. the same
    diagnostic re-emitted for config outside the runner's reach) stops
    at the attempt cap instead of looping."""
    runner.prepare_workspace()
    steps = [
        (1, "", None, VALIDATION_STDERR)
        for _ in range(runner._MAX_PLAN_ATTEMPTS)
    ]
    scripted = ScriptedSubprocess(*steps)
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    with pytest.raises(TerraformError, match="terraform plan failed"):
        runner.plan_with_generation()


CONTENT_FILTERING_BLOCK = (
    'resource "meraki_appliance_content_filtering" "l_1" {\n'
    "  allowed_url_patterns = [\n"
    '    "content-autofill.example.com",\n'
    '    "content-autofill.example.com",\n'
    "  ]\n"
    "}\n"
)
CONTENT_FILTERING_IMPORT = (
    "import {\n"
    "  to = meraki_appliance_content_filtering.l_1\n"
    '  id = "L_1"\n'
    "}\n"
)
DUPLICATE_SET_STDERR = (
    "Error: Duplicate Set Element\n"
    "\n"
    "This attribute contains duplicate values of:\n"
    'tftypes.String<"content-autofill.example.com">\n'
)


def test_plan_with_generation_supports_targeted_replans(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Heal/deferral replans narrow to the affected addresses — minutes
    instead of re-reading the whole kit."""
    runner.prepare_workspace()
    scripted = ScriptedSubprocess((0, "No changes.", None))
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    runner.plan_with_generation(
        save_plan=True, targets=["meraki_networks.n_1"]
    )
    command = scripted.calls[0]
    assert "-target=meraki_networks.n_1" in command
    assert any(arg.startswith("-generate-config-out=") for arg in command)


def test_plan_targeted_passes_target_flags_and_saves_the_plan(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner.prepare_workspace()
    scripted = ScriptedSubprocess(
        (2, "Plan: 2 to import, 0 to add, 0 to change, 0 to destroy.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    result = runner.plan_targeted(
        ["meraki_networks.n_1", "meraki_devices.q2ab"]
    )
    command = scripted.calls[0]
    assert "-target=meraki_networks.n_1" in command
    assert "-target=meraki_devices.q2ab" in command
    assert any(arg.startswith("-out=") for arg in command)
    counts = result.plan_counts
    assert counts is not None
    assert (counts.imports, counts.has_real_changes) == (2, False)


def test_defer_resources_removes_config_and_import_blocks(
    runner: TerraformRunner,
) -> None:
    """Deferral is pure kit surgery: the racy resource leaves both the
    baseline and imports.tf; nothing else is touched."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        SNMP_BLOCK + FIRMWARE_BLOCK, encoding="utf-8"
    )
    (runner.workdir / "imports.tf").write_text(
        FIRMWARE_IMPORT
        + "import {\n  to = meraki_network_snmp.l_1\n"
        '  id = "L_1"\n}\n',
        encoding="utf-8",
    )
    runner.defer_resources(frozenset({"meraki_network_snmp.l_1"}))
    baseline = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(
        encoding="utf-8"
    )
    imports = (runner.workdir / "imports.tf").read_text(encoding="utf-8")
    assert "snmp" not in baseline and "snmp" not in imports
    assert "firmware_upgrades" in baseline and "firmware_upgrades" in imports


def test_plan_drops_duplicate_set_resources_via_payload_locator(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A duplicate that breaks the provider's own Read never generates
    config, so the text-scan finds nothing; the payload-side locator
    installed by the orchestrator attributes it and the import drops."""
    runner.prepare_workspace()
    (runner.workdir / "imports.tf").write_text(
        "import {\n"
        "  to = meraki_network_group_policy.n_1_100\n"
        '  id = "N_1,100,false"\n'
        "}\n",
        encoding="utf-8",
    )
    runner.set_duplicate_value_locator(
        lambda values: {
            "meraki_network_group_policy.n_1_100": (
                f"Duplicate Set Element: {values[0]!r} appears twice."
            )
        }
    )
    scripted = ScriptedSubprocess(
        (1, "", None, DUPLICATE_SET_STDERR),
        (0, "No changes.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert set(outcome.dropped) == {"meraki_network_group_policy.n_1_100"}
    imports = (runner.workdir / "imports.tf").read_text(encoding="utf-8")
    assert "group_policy" not in imports


def test_plan_drops_duplicate_set_resources_by_locating_the_literal(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Set-uniqueness violations name no resource; the owner is found
    in the generated config and dropped as unexpressible."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        CONTENT_FILTERING_BLOCK, encoding="utf-8"
    )
    (runner.workdir / "imports.tf").write_text(
        CONTENT_FILTERING_IMPORT, encoding="utf-8"
    )
    scripted = ScriptedSubprocess(
        (1, "", None, DUPLICATE_SET_STDERR),
        (0, "No changes.", None),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    outcome = runner.plan_with_generation()
    assert set(outcome.dropped) == {"meraki_appliance_content_filtering.l_1"}
    assert "Duplicate Set Element" in outcome.dropped[
        "meraki_appliance_content_filtering.l_1"
    ]
    baseline = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(
        encoding="utf-8"
    )
    assert "content_filtering" not in baseline


def test_merged_with_earlier_keeps_prior_remediations() -> None:
    from meraki2tf.terraform_runner import (
        ReconciledPlanResult,
        TerraformCommandResult,
    )

    base = TerraformCommandResult(
        command=("terraform",), returncode=0, stdout="", stderr=""
    )

    first = ReconciledPlanResult(
        result=base,
        dropped={"a.b": "r1"},
        ignored_secrets={"c.d": ("psk",)},
        normalized={},
    )
    second = ReconciledPlanResult(
        result=base, dropped={"a.b": "r2"}, ignored_secrets={},
        normalized={"e.f": ("body",)},
    )
    merged = second.merged_with_earlier(first)
    assert merged.dropped == {"a.b": "r2"}
    assert merged.ignored_secrets == {"c.d": ("psk",)}
    assert merged.normalized == {"e.f": ("body",)}


def test_missing_terraform_binary_raises_friendly_error(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_missing(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        raise FileNotFoundError(2, "No such file or directory", "terraform")

    monkeypatch.setattr(terraform_runner.subprocess, "run", raise_missing)

    with pytest.raises(TerraformNotFoundError, match="--terraform-bin") as excinfo:
        runner.init()

    assert "'terraform'" in str(excinfo.value)
    assert isinstance(excinfo.value, TerraformError)  # rides existing plumbing


def test_custom_terraform_bin_named_in_not_found_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    custom = TerraformRunner(tmp_path / "workspace", executable="/opt/tf/terraform")

    def raise_missing(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        raise FileNotFoundError(2, "No such file or directory", "/opt/tf/terraform")

    monkeypatch.setattr(terraform_runner.subprocess, "run", raise_missing)

    with pytest.raises(TerraformNotFoundError, match="/opt/tf/terraform"):
        custom.init()


def test_state_restriction_routes_through_owner_only_helper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Permission enforcement (and its degraded-FS warning) is delegated."""
    restriction_runner = TerraformRunner(tmp_path / "workspace")
    restriction_runner.workdir.mkdir(parents=True)
    state = restriction_runner.workdir / DEFAULT_STATE_FILENAME
    backup = restriction_runner.workdir / (DEFAULT_STATE_FILENAME + ".backup")
    state.write_text("{}", encoding="utf-8")

    restricted: list[Path] = []
    monkeypatch.setattr(
        terraform_runner,
        "restrict_to_owner",
        lambda path: restricted.append(path) or True,
    )

    restriction_runner._restrict_state_permissions()
    assert restricted == [state]  # a missing .backup is skipped

    backup.write_text("{}", encoding="utf-8")
    restricted.clear()
    restriction_runner._restrict_state_permissions()
    assert restricted == [state, backup]


def test_apply_import_plan_survives_a_leftover_verified_copy(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run killed hard (OOM, power loss) leaves its run-private plan
    copy behind: a later run recycling the same PID must replace it —
    not crash on the exclusive create — and copies from dead PIDs are
    swept so no secret-bearing plan document outlives its run."""
    runner.prepare_workspace()
    (runner.workdir / SYNC_PLAN_FILENAME).write_bytes(b"opaque-plan")
    own_leftover = (
        runner.workdir / f"{SYNC_PLAN_FILENAME}.verified-{os.getpid()}"
    )
    own_leftover.write_bytes(b"stale-from-a-recycled-pid")
    # A PID far above any real pid_max: definitely not alive.
    dead_leftover = (
        runner.workdir / f"{SYNC_PLAN_FILENAME}.verified-4194304999"
    )
    dead_leftover.write_bytes(b"stale-from-a-dead-run")
    show_json = json.dumps(
        {
            "resource_changes": [
                {
                    "address": "meraki_networks.n_1",
                    "change": {"actions": ["no-op"], "importing": {"id": "N_1"}},
                },
            ]
        }
    )
    scripted = ScriptedSubprocess(
        (0, show_json, None),
        (
            0,
            "Apply complete!",
            lambda: _write_state(runner.state_path, "meraki_networks.n_1"),
        ),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    added = runner.apply_import_plan()
    assert added == ("meraki_networks.n_1",)
    assert not dead_leftover.exists()
    assert not own_leftover.exists()


def test_absorb_generated_config_is_atomic_and_replay_safe(
    runner: TerraformRunner,
) -> None:
    """A crash between the absorb and the unlink replays the absorb on
    the next run; appending again would duplicate every resource block
    and terraform would reject the workspace on every subsequent plan."""
    runner.prepare_workspace()
    aggregated = runner.workdir / terraform_runner.AGGREGATED_CONFIG_FILENAME
    generated = runner.workdir / terraform_runner.GENERATED_CONFIG_FILENAME
    block = 'resource "meraki_network" "n_1" {\n  name = "HQ"\n}\n'
    generated.write_text(block, encoding="utf-8")
    runner._absorb_generated_config()
    assert aggregated.read_text(encoding="utf-8") == block
    assert not generated.exists()
    # Crash replay: the generation target reappears with content the
    # baseline already ends with — absorbing again must be a no-op.
    generated.write_text(block, encoding="utf-8")
    runner._absorb_generated_config()
    assert aggregated.read_text(encoding="utf-8") == block
    assert not generated.exists()


def test_absorb_orders_blocks_by_address_deterministically(
    runner: TerraformRunner,
) -> None:
    """terraform emits generated blocks in plan order, which varies run
    to run; the absorbed baseline must not churn diffs for kit-committers.
    Headers travel with their block, and a regenerated address replaces
    the stale copy instead of duplicating it."""
    runner.prepare_workspace()
    aggregated = runner.workdir / terraform_runner.AGGREGATED_CONFIG_FILENAME
    generated = runner.workdir / terraform_runner.GENERATED_CONFIG_FILENAME
    zeta = (
        '# __generated__ by Terraform from "Z_9"\n'
        'resource "meraki_network" "zeta" {\n  name = "Z"\n}\n'
    )
    alpha = (
        '# __generated__ by Terraform from "A_1"\n'
        'resource "meraki_network" "alpha" {\n  name = "A"\n}\n'
    )
    generated.write_text(zeta + "\n" + alpha, encoding="utf-8")
    runner._absorb_generated_config()
    assert aggregated.read_text(encoding="utf-8") == alpha + "\n" + zeta

    # A later run regenerates zeta (Meraki-is-truth) plus a new block:
    # same address replaces, ordering stays sorted.
    zeta2 = zeta.replace('name = "Z"', 'name = "Z2"')
    mid = 'resource "meraki_network" "mid" {\n  name = "M"\n}\n'
    generated.write_text(zeta2 + "\n" + mid, encoding="utf-8")
    runner._absorb_generated_config()
    assert (
        aggregated.read_text(encoding="utf-8")
        == alpha + "\n" + mid + "\n" + zeta2
    )


def test_plan_with_generation_refuses_an_empty_target_set(
    runner: TerraformRunner,
) -> None:
    """Same stance as plan_targeted: an empty target set would silently
    degenerate to a full untargeted plan (a multi-hour read window); a
    full plan must be requested explicitly with targets=None."""
    runner.prepare_workspace()
    with pytest.raises(ValueError, match="empty target set"):
        runner.plan_with_generation(targets=())


def test_plan_targeted_refuses_an_empty_address_set(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty -target set silently degenerates into a full untargeted
    multi-hour plan — reopening exactly the race window targeted
    chunking exists to close."""
    runner.prepare_workspace()
    fake = FakeSubprocess()
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with pytest.raises(ValueError, match="at least one address"):
        runner.plan_targeted([])
    assert fake.calls == []


def test_plan_targeted_drops_the_saved_plan_when_the_plan_errors(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An errored plan writes no (or a partial) plan file; whatever is
    on disk must go, or a previous window's saved plan could be
    mistaken for this one downstream."""
    runner.prepare_workspace()
    stale = runner.workdir / SYNC_PLAN_FILENAME
    stale.write_text("previous-window-plan", encoding="utf-8")
    scripted = ScriptedSubprocess(
        (1, "", None, "Error: provider produced inconsistent result"),
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", scripted.run)
    result = runner.plan_targeted(["meraki_networks.n_1"])
    assert result.returncode == 1
    assert not stale.exists()


def test_discard_rebuild_plan_removes_the_verified_snapshot(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Preview-only --rebuild runs must not leave the run-private
    verified plan copy (a secret-bearing document) on disk."""

    def planning_run(command: Any, **kwargs: Any) -> Any:
        if "plan" in command:
            (
                runner.workdir / terraform_runner.REBUILD_PLAN_FILENAME
            ).write_text("saved-plan", encoding="utf-8")
        return fake.run(command, **kwargs)

    fake = FakeSubprocess(returncode=2, stdout="Plan: 1 to add")
    monkeypatch.setattr(terraform_runner.subprocess, "run", planning_run)
    runner.workdir.mkdir(parents=True, exist_ok=True)
    runner.plan_preview()
    verified = runner.workdir / (
        f"{terraform_runner.REBUILD_PLAN_FILENAME}.verified-{os.getpid()}"
    )
    assert verified.exists()
    runner.discard_rebuild_plan()
    assert not verified.exists()
    assert not (
        runner.workdir / terraform_runner.REBUILD_PLAN_FILENAME
    ).exists()
    assert runner._rebuild_plan_snapshot is None
    # Idempotent: a second discard with nothing snapshotted is a no-op.
    runner.discard_rebuild_plan()


def test_run_failure_with_json_output_reports_size_not_body(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed -json command's stdout can carry sensitive values, and
    the error message flows into alert payloads — it must report the
    body's size, never the body."""
    fake = FakeSubprocess(returncode=1, stdout='{"psk": "wifi-secret"}')
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake.run)
    with pytest.raises(TerraformError) as excinfo:
        runner._run("show", "-json", "plan.tfplan")
    message = str(excinfo.value)
    assert "wifi-secret" not in message
    assert "machine-readable JSON" in message
    # stderr, when present, is terraform's own (masked) diagnostics and
    # is preferred over the size notice.
    fake_err = FakeSubprocess(
        returncode=1, stdout='{"psk": "wifi-secret"}', stderr="Error: boom"
    )
    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_err.run)
    with pytest.raises(TerraformError, match="Error: boom"):
        runner._run("show", "-json", "plan.tfplan")


def test_process_alive_probe_verdicts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Signal-0 probe semantics: a missing PID is dead, an unrepresentable
    PID names no process, and EPERM means alive (another user's run —
    its run-private plan copy is not ours to sweep)."""

    def raising_kill(exc: Exception) -> Any:
        def kill(pid: int, sig: int) -> None:
            raise exc

        return kill

    monkeypatch.setattr(
        terraform_runner.os, "kill", raising_kill(ProcessLookupError())
    )
    assert terraform_runner._process_alive(4242) is False
    monkeypatch.setattr(
        terraform_runner.os, "kill", raising_kill(OverflowError())
    )
    assert terraform_runner._process_alive(2**63) is False
    monkeypatch.setattr(
        terraform_runner.os,
        "kill",
        raising_kill(PermissionError("operation not permitted")),
    )
    assert terraform_runner._process_alive(4242) is True
    monkeypatch.setattr(
        terraform_runner.os, "kill", lambda pid, sig: None
    )
    assert terraform_runner._process_alive(os.getpid()) is True


HEREDOC_BASELINE = """\
resource "meraki_network_webhook_payload_template" "l_1_wpt" {
  network_id = "L_1"
  body       = <<-EOT
{
"text": "**{{alertType}}**"
}
EOT
  name = "custom-template"
}

resource "meraki_networks" "n_1" {
  name = "HQ"
}
"""


def test_split_resource_blocks_is_heredoc_aware() -> None:
    """A column-0 `}` inside a heredoc string body (webhook
    payloadTemplate bodies) is string content, not a block closer:
    honoring it split the template block in half and corrupted the
    absorb-merge of resources.tf."""
    preamble, blocks = terraform_runner._split_resource_blocks(
        HEREDOC_BASELINE
    )
    assert preamble == ""
    assert set(blocks) == {
        "meraki_network_webhook_payload_template.l_1_wpt",
        "meraki_networks.n_1",
    }
    template = blocks["meraki_network_webhook_payload_template.l_1_wpt"]
    assert '"text": "**{{alertType}}**"' in template
    assert 'name = "custom-template"' in template  # the post-heredoc tail
    assert template.rstrip("\n").endswith("}")


def test_split_resource_blocks_keeps_unterminated_trailing_block() -> None:
    """A block whose heredoc never closes has no closer; the scan must
    stop cleanly at end-of-file and keep the block text as-is."""
    text = 'resource "meraki_x" "a" {\n  body = <<EOT\n}\n'
    preamble, blocks = terraform_runner._split_resource_blocks(text)
    assert preamble == ""
    assert blocks == {"meraki_x.a": text}


def test_prune_baseline_is_heredoc_aware(runner: TerraformRunner) -> None:
    """Pruning a heredoc-bearing block must remove the WHOLE block —
    truncating at the heredoc's column-0 `}` left half a resource behind
    and wedged every later terraform parse."""
    runner.prepare_workspace()
    (runner.workdir / AGGREGATED_CONFIG_FILENAME).write_text(
        HEREDOC_BASELINE, encoding="utf-8"
    )
    runner._prune_baseline(["meraki_network_webhook_payload_template.l_1_wpt"])
    text = (runner.workdir / AGGREGATED_CONFIG_FILENAME).read_text(
        encoding="utf-8"
    )
    assert "payload_template" not in text
    assert "EOT" not in text and "custom-template" not in text
    assert 'resource "meraki_networks" "n_1"' in text  # neighbor intact


def test_block_body_end_flags_unterminated_block() -> None:
    """The scanner must report closer-not-found so callers can fail
    closed instead of treating end-of-file as the block boundary."""
    lines = ['resource "x" "a" {\n', "  body = <<EOT\n", "still open\n"]
    end, terminated = terraform_runner._block_body_end(lines, 1)
    assert (end, terminated) == (len(lines), False)
    closed = ['resource "x" "a" {\n', "  name = \"HQ\"\n", "}\n"]
    assert terraform_runner._block_body_end(closed, 1) == (2, True)


def test_prune_baseline_quoted_double_angle_value_is_not_a_heredoc(
    runner: TerraformRunner,
) -> None:
    """A block whose value holds ``<<MOVED`` (an ordinary dashboard
    rename) must not be read as a heredoc opener: pruning an earlier
    block must leave the hostile block and every later block intact,
    never truncate resources.tf to EOF (Cardinal Rule 2)."""
    runner.prepare_workspace()
    hostile = (
        'resource "meraki_networks" "hostile" {\n'
        '  name = "HQ <<MOVED>> 2026"\n'
        "}\n"
    )
    tail = 'resource "meraki_networks" "n_2" {\n  name = "Branch"\n}\n'
    baseline = (
        'resource "meraki_networks" "n_1" {\n  name = "HQ"\n}\n'
        "\n" + hostile + "\n" + tail
    )
    aggregated = runner.workdir / AGGREGATED_CONFIG_FILENAME
    aggregated.write_text(baseline, encoding="utf-8")
    runner._prune_baseline(["meraki_networks.n_1"])
    text = aggregated.read_text(encoding="utf-8")
    assert 'resource "meraki_networks" "n_1"' not in text
    assert 'name = "HQ <<MOVED>> 2026"' in text  # hostile block survives
    assert 'resource "meraki_networks" "n_2"' in text  # later block survives


def test_prune_baseline_skips_unterminated_block(
    runner: TerraformRunner, caplog: pytest.LogCaptureFixture
) -> None:
    """An unterminated target block (no column-0 closer before EOF) must
    be skipped with a warning — pruning it would truncate the file and
    silently drop later blocks while coverage.json still reports them."""
    runner.prepare_workspace()
    tail = 'resource "meraki_networks" "keep" {\n  name = "Keep"\n}\n'
    baseline = (
        'resource "meraki_x" "broken" {\n'
        "  body = <<EOT\n"
        "never closes\n" + tail
    )
    aggregated = runner.workdir / AGGREGATED_CONFIG_FILENAME
    aggregated.write_text(baseline, encoding="utf-8")
    with caplog.at_level("WARNING", logger="meraki2tf.terraform_runner"):
        runner._prune_baseline(["meraki_x.broken"])
    assert any("Skipped pruning" in r.message for r in caplog.records)
    # File untouched: nothing truncated, the later block still present.
    assert aggregated.read_text(encoding="utf-8") == baseline


def test_absorb_rejects_a_mis_parsed_merged_block(
    runner: TerraformRunner,
) -> None:
    """If a runaway heredoc scan folds two blocks into one, the parsed
    block body carries a second column-0 resource opener; absorbing it
    would write a duplicate definition that fails ``terraform validate``
    and wedges every later run. Fail closed instead."""
    runner.prepare_workspace()
    generated = runner.workdir / terraform_runner.GENERATED_CONFIG_FILENAME
    # Block "a" has an unterminated heredoc, so the splitter folds block
    # "b" into it — the exact mis-parse the guard must catch.
    generated.write_text(
        'resource "meraki_x" "a" {\n'
        "  body = <<EOT\n"
        "}\n"
        "\n"
        'resource "meraki_y" "b" {\n  name = "B"\n}\n',
        encoding="utf-8",
    )
    with pytest.raises(TerraformError, match="resource openers"):
        runner._absorb_generated_config()
    # Nothing was written to the baseline.
    assert not (runner.workdir / AGGREGATED_CONFIG_FILENAME).exists()


def test_assert_no_merged_blocks_passes_clean_blocks() -> None:
    """A well-formed block set (one opener each) must not raise."""
    terraform_runner._assert_no_merged_blocks(
        {"meraki_x.a": 'resource "meraki_x" "a" {\n  name = "A"\n}\n'}
    )


def test_verified_copies_older_than_the_stale_window_are_swept(
    runner: TerraformRunner,
) -> None:
    """PID liveness alone is spoofable by PID recycling: an unrelated
    live process wearing a dead run's PID kept its secret-bearing plan
    copy alive indefinitely. Copies past the mtime window are swept
    regardless; young copies of live runs survive."""
    import time as time_module

    runner.prepare_workspace()
    source = runner.workdir / SYNC_PLAN_FILENAME
    source.write_bytes(b"opaque-plan")
    # PID 1 is always alive — stands in for a recycled PID.
    recycled = runner.workdir / f"{SYNC_PLAN_FILENAME}.verified-1"
    recycled.write_bytes(b"stale-secret-bearing-copy")
    ancient = time_module.time() - 7 * 60 * 60
    os.utime(recycled, (ancient, ancient))
    # A non-PID suffix used to be kept forever; age sweeps it too.
    odd = runner.workdir / f"{SYNC_PLAN_FILENAME}.verified-notapid"
    odd.write_bytes(b"stale")
    os.utime(odd, (ancient, ancient))
    # A young copy owned by a live process (our parent) is a concurrent
    # run's working file and must survive the sweep.
    concurrent = runner.workdir / f"{SYNC_PLAN_FILENAME}.verified-{os.getppid()}"
    concurrent.write_bytes(b"live-concurrent-copy")

    target = runner._exclusive_run_copy(source)

    assert not recycled.exists()
    assert not odd.exists()
    assert concurrent.read_bytes() == b"live-concurrent-copy"
    assert target.read_bytes() == b"opaque-plan"
    target.unlink()


def test_sweep_tolerates_a_copy_deleted_mid_scan(
    runner: TerraformRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A concurrent sweep deleting a leftover between glob and stat must
    not crash this run's copy creation."""
    runner.prepare_workspace()
    source = runner.workdir / SYNC_PLAN_FILENAME
    source.write_bytes(b"opaque-plan")
    ghost = runner.workdir / f"{SYNC_PLAN_FILENAME}.verified-1"
    ghost.write_bytes(b"racing")
    real_stat = Path.stat

    def racing_stat(self: Path, **kwargs: Any) -> Any:
        if self.name.endswith(".verified-1"):
            raise OSError("deleted underneath")
        return real_stat(self, **kwargs)

    monkeypatch.setattr(Path, "stat", racing_stat)
    target = runner._exclusive_run_copy(source)
    assert target.read_bytes() == b"opaque-plan"
    target.unlink()
