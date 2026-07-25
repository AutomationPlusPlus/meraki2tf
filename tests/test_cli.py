"""CLI entry point: argument surface, assembly, and dump-mode integration."""

import json
import logging
import os
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from conftest import PIPELINE_SPEC
from conftest import fixture_schema_document

from meraki2tf import spec_resolver, terraform_runner
from meraki2tf.alerts.email import SMTP_PASSWORD_ENV_VAR, SMTP_USERNAME_ENV_VAR
from meraki2tf.cli import build_dispatcher, build_parser, build_provider, main
from meraki2tf.config import API_KEY_ENV_VAR, RuntimeConfig
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers import LiveApiDataProvider, StaticJsonDataProvider
from meraki2tf.spec_resolver import SpecResolutionError


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the spec resolver onto its offline/local-fallback path."""

    def offline(url: str) -> str:
        raise SpecResolutionError(f"offline test environment ({url})")

    monkeypatch.setattr(spec_resolver, "_download", offline)


def _config(argv: list[str]) -> RuntimeConfig:
    return RuntimeConfig.from_args(build_parser().parse_args(argv))


def test_parser_defaults(spec_file: Path) -> None:
    config = _config(["--spec", str(spec_file)])
    assert config.org_id is None
    assert config.dump_path is None
    assert config.dump_to is None
    assert not config.sanitize
    assert not config.rebuild
    assert not config.confirm
    assert not config.rebaseline
    assert config.workdir == Path("generated")
    assert config.state_file is None
    assert config.webhook_urls == ()
    assert config.alert_emails == ()
    assert config.smtp_host == "localhost"
    assert config.smtp_port == 25
    assert config.terraform_bin == "terraform"
    assert not config.verbose


def test_parser_collects_repeated_alert_destinations(spec_file: Path) -> None:
    config = _config(
        [
            "--spec", str(spec_file),
            "--org-id", "org-123",
            "--webhook-url", "https://hooks.example/a",
            "--webhook-url", "https://hooks.example/b",
            "--alert-email", "netops@example.com",
            "--smtp-host", "smtp.example",
            "--smtp-port", "2525",
            "--email-from", "bot@example.com",
            "-v",
        ]
    )
    assert config.webhook_urls == ("https://hooks.example/a", "https://hooks.example/b")
    assert config.alert_emails == ("netops@example.com",)
    assert config.smtp_port == 2525
    assert config.verbose


def test_spec_flag_is_optional() -> None:
    config = _config([])
    assert config.spec_path is None


def test_live_mode_requires_org_id(spec_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--spec", str(spec_file)])


def test_build_dispatcher_registers_configured_channels(spec_file: Path) -> None:
    config = _config(
        [
            "--spec", str(spec_file),
            "--webhook-url", "https://hooks.example/a",
            "--alert-email", "netops@example.com",
        ]
    )
    dispatcher = build_dispatcher(config)
    channels = [notifier.channel for notifier in dispatcher._notifiers]
    assert channels == ["webhook", "email"]


def test_build_dispatcher_refuses_half_set_smtp_credentials(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A half-set AUTH pair must refuse at startup, like --pagerduty
    without its routing key — not after the discovery sweep, as a
    delivery failure on every alert."""
    monkeypatch.setenv(SMTP_USERNAME_ENV_VAR, "alert-bot")
    monkeypatch.delenv(SMTP_PASSWORD_ENV_VAR, raising=False)
    with pytest.raises(SystemExit) as excinfo:
        build_dispatcher(
            _config(
                ["--spec", str(spec_file),
                 "--alert-email", "netops@example.com"]
            )
        )
    assert "exactly one of them is present" in str(excinfo.value)


def test_build_provider_selects_modality(
    spec_file: Path, dump_file: Path, spec_parser: OpenApiParser
) -> None:
    live = build_provider(_config(["--spec", str(spec_file)]), spec_parser)
    assert isinstance(live, LiveApiDataProvider)
    dump = build_provider(
        _config(["--spec", str(spec_file), "--from-dump", str(dump_file)]), spec_parser
    )
    assert isinstance(dump, StaticJsonDataProvider)


def test_sanitize_requires_dump_to(spec_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--spec", str(spec_file), "--org-id", "org-123", "--sanitize"])


def test_state_file_rejected_with_remote_backend(spec_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "--spec", str(spec_file), "--org-id", "org-123",
                "--state-backend", "azurerm",
                "--backend-config", "storage_account_name=sa",
                "--backend-config", "container_name=tfstate",
                "--backend-config", "key=org.tfstate",
                "--state-file", "/var/lib/meraki2tf/org.tfstate",
            ]
        )


def test_backend_config_error_surfaces_as_usage_error(spec_file: Path) -> None:
    # A credential in --backend-config must abort as a usage error (exit 2),
    # never reach a run that could log or transmit it.
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "--spec", str(spec_file), "--org-id", "org-123",
                "--state-backend", "azurerm",
                "--backend-config", "storage_account_name=sa",
                "--backend-config", "container_name=tfstate",
                "--backend-config", "key=org.tfstate",
                "--backend-config", "access_key=super-secret",
            ]
        )
    assert excinfo.value.code == 2


def test_dump_to_exports_snapshot_without_running_terraform(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)

    def forbidden_run(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("terraform must not run during a snapshot export")

    monkeypatch.setattr(terraform_runner.subprocess, "run", forbidden_run)
    out = tmp_path / "exports" / "snapshot.json"
    workdir = tmp_path / "workspace"

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(out), "--workdir", str(workdir)]
    )

    assert exit_code == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["organizationId"] == "org-123"
    assert document["networks"][0]["id"] == "N_1"
    assert any(
        feature["apiPath"] == "/networks/{networkId}/appliance/vlans/{vlanId}"
        for feature in document["features"]
    )
    # The coverage guarantee holds on export runs too — classified via
    # the bundled catalog, without ever invoking terraform.
    manifest = json.loads((workdir / "coverage.json").read_text(encoding="utf-8"))
    assert manifest["totals"]["discovered"] == 4
    assert manifest["totals"]["unsupported"] == 0
    assert (workdir / "coverage.txt").exists()


def test_dump_to_failure_dispatches_processing_fault(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The weekly DR job is a --dump-to invocation; a failed export must
    reach the notification channels, not just the local log."""
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    _no_network(monkeypatch)
    out = tmp_path / "already-a-directory"
    out.mkdir()  # write_snapshot cannot write text over a directory

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(out), "--webhook-url", "https://hooks.example/dr"]
    )

    assert exit_code == 1
    assert [event["event_type"] for event in delivered] == ["PROCESSING_FAULT"]
    assert "--dump-to" in delivered[0]["details"]["stage"]


def test_dump_to_with_sanitize_strips_identity(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    out = tmp_path / "sanitized.json"

    exit_code = main(
        [
            "--spec", str(spec_file),
            "--from-dump", str(dump_file),
            "--dump-to", str(out),
            "--sanitize",
            "--workdir", str(tmp_path / "workspace"),
        ]
    )

    assert exit_code == 0
    raw = out.read_text(encoding="utf-8")
    assert "Q2AB-CDEF-GHIJ" not in raw
    assert '"HQ"' not in raw
    document = json.loads(raw)
    assert document["organizationId"] == "org-0001"
    assert document["networks"][0]["id"] == "net-0001"
    assert document["devices"][0]["serial"] == "dev-0001"
    # The sanitized snapshot is itself a valid --from-dump input.
    assert document["features"][0]["pathValues"][0] == "net-0001"


class FakeResponse:
    status = 200

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def test_dump_mode_end_to_end(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full pipeline: snapshot in, imports.tf out, drift + success alerts."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    terraform_calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        terraform_calls.append(command)
        if command[1] == "providers":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(fixture_schema_document()),
                stderr="",
            )
        if command[1] == "show":
            # reconciliation classifies the saved plan; an empty change
            # set means nothing to remediate (the delta is real drift)
            return SimpleNamespace(
                returncode=0, stdout='{"resource_changes": []}', stderr=""
            )
        exit_code = 2 if command[1] == "plan" else 0
        return SimpleNamespace(
            returncode=exit_code,
            stdout=(
                "~ plan delta\n"
                "Plan: 4 to import, 0 to add, 1 to change, 0 to destroy."
            ),
            stderr="",
        )

    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)
    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    _no_network(monkeypatch)
    workdir = tmp_path / "workspace"

    exit_code = main(
        [
            "--spec", str(spec_file),
            "--from-dump", str(dump_file),
            "--workdir", str(workdir),
            "--webhook-url", "https://hooks.example/alerts",
            "--verbose",
        ]
    )

    assert exit_code == 0
    # Read-only pipeline: terraform apply is never part of a run. The
    # catalog resolution initializes (once per run — later init calls are
    # cached no-ops) and dumps the provider schema before generation; the
    # comparison stage plans and reconciliation classifies the
    # changes-present plan via show.
    # The leading "version" call is the pre-discovery terraform probe
    # (fail-fast on a missing/old binary before the sweep starts).
    assert [call[1] for call in terraform_calls] == [
        "version", "init", "providers", "plan", "show",
    ]

    imports = (workdir / "imports.tf").read_text(encoding="utf-8")
    assert "to = meraki_network.n_1\n" in imports
    assert "to = meraki_device.q2ab_cdef_ghij\n" in imports
    assert 'id = "N_1,10"' in imports
    provider_tf = (workdir / "provider.tf").read_text(encoding="utf-8")
    assert 'source = "CiscoDevNet/meraki"' in provider_tf

    assert [event["event_type"] for event in delivered] == [
        "DRIFT_DETECTED",
        "RUN_SUCCESS",
    ]
    assert "~ plan delta" in delivered[0]["details"]["diff"]
    success = delivered[1]["details"]
    assert success["imports_written"] == 4
    assert success["drift_was_detected"] is True
    assert success["pending_imports"] == 4
    assert success["comparison_performed"] is True
    assert success["unsupported_count"] == 0


def test_pipeline_fault_exits_one_and_alerts(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def failing_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=1, stdout="", stderr="Error: no terraform")

    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr(terraform_runner.subprocess, "run", failing_run)
    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    _no_network(monkeypatch)

    exit_code = main(
        [
            "--spec", str(spec_file),
            "--from-dump", str(dump_file),
            "--workdir", str(tmp_path / "workspace"),
            "--webhook-url", "https://hooks.example/alerts",
        ]
    )
    assert exit_code == 1
    assert delivered[-1]["event_type"] == "PROCESSING_FAULT"
    assert delivered[-1]["details"]["stage"] == "terraform init"


def test_startup_failure_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    exit_code = main(
        [
            "--spec", str(tmp_path / "missing-spec.json"),
            "--from-dump", str(tmp_path / "missing-dump.json"),
        ]
    )
    assert exit_code == 1


def test_consecutive_run_reuses_existing_state(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-existing state file means only the delta gets import blocks."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    state = tmp_path / "state-store" / "org-123.tfstate"
    state.parent.mkdir()
    state.write_text(
        json.dumps(
            {
                "resources": [
                    {"mode": "managed", "type": "meraki_network", "name": "n_1"},
                ]
            }
        ),
        encoding="utf-8",
    )
    workdir = tmp_path / "workspace"

    exit_code = main(
        [
            "--spec", str(spec_file),
            "--from-dump", str(dump_file),
            "--workdir", str(workdir),
            "--state-file", str(state),
        ]
    )

    assert exit_code == 0
    imports = (workdir / "imports.tf").read_text(encoding="utf-8")
    assert "meraki_network.n_1" not in imports  # already tracked in state
    assert "to = meraki_device.q2ab_cdef_ghij\n" in imports
    provider_tf = (workdir / "provider.tf").read_text(encoding="utf-8")
    assert f'path = "{state.resolve()}"' in provider_tf


def test_omitted_spec_downloads_latest_and_runs(
    dump_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No --spec and no local file: the latest release is fetched and used."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    remote_spec = {**PIPELINE_SPEC, "info": {"version": "1.56.0"}}
    monkeypatch.setattr(
        spec_resolver, "_download", lambda url: json.dumps(remote_spec)
    )

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)

    exit_code = main(
        ["--from-dump", str(dump_file), "--workdir", str(tmp_path / "workspace")]
    )
    assert exit_code == 0
    downloaded = tmp_path / "spec3.json"
    assert downloaded.exists()
    assert json.loads(downloaded.read_text(encoding="utf-8"))["info"] == {
        "version": "1.56.0"
    }
    assert (tmp_path / "workspace" / "imports.tf").exists()


def test_offline_run_without_api_key_skips_terraform(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Air-gapped dump runs generate artifacts without ever invoking terraform."""
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)

    def forbidden_run(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("terraform must not run without an API key")

    monkeypatch.setattr(terraform_runner.subprocess, "run", forbidden_run)
    workdir = tmp_path / "workspace"

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(workdir)]
    )

    assert exit_code == 0
    assert (workdir / "imports.tf").exists()
    assert (workdir / "provider.tf").exists()
    # Ad-hoc (non---sync) runs end with a printed next-step pointer.
    out = capsys.readouterr().out
    assert "DR kit written to" in out
    assert "terraform init" in out


def _rebuild_workspace(tmp_path: Path) -> Path:
    """A workdir that looks like a previous pipeline run populated it."""
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    (workdir / "provider.tf").write_text('provider "meraki" {}\n', encoding="utf-8")
    return workdir


def test_confirm_without_rebuild_is_a_usage_error() -> None:
    with pytest.raises(SystemExit):
        main(["--confirm"])


def test_rebuild_rejects_dump_flags(dump_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--rebuild", "--from-dump", str(dump_file)])


def test_rebuild_requires_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    workdir = _rebuild_workspace(tmp_path)
    assert main(["--rebuild", "--workdir", str(workdir)]) == 1


def test_rebuild_requires_existing_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    assert main(["--rebuild", "--workdir", str(tmp_path / "empty")]) == 1


def test_rebuild_reports_missing_terraform_binary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A missing binary surfaces install guidance, not a raw OSError."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)

    def raise_missing(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        raise FileNotFoundError(2, "No such file or directory", "terraform")

    monkeypatch.setattr(terraform_runner.subprocess, "run", raise_missing)

    assert main(["--rebuild", "--workdir", str(workdir)]) == 1

    stderr = capsys.readouterr().err
    assert "Install Terraform" in stderr
    assert "--terraform-bin" in stderr


def test_rebuild_without_confirm_is_preview_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        exit_code = 2 if command[1] == "plan" else 0
        return SimpleNamespace(returncode=exit_code, stdout="Plan: 5 to add", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)

    assert main(["--rebuild", "--workdir", str(workdir)]) == 0
    assert [call[1] for call in calls] == ["init", "plan"]  # no apply


def test_rebuild_with_confirm_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        exit_code = 0
        if command[1] == "plan":
            exit_code = 2
            for part in command:  # terraform writes the -out plan file
                if part.startswith("-out="):
                    (Path(kwargs["cwd"]) / part[5:]).write_text(
                        "saved-plan", encoding="utf-8"
                    )
        return SimpleNamespace(returncode=exit_code, stdout="Plan: 5 to add", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)

    assert main(["--rebuild", "--confirm", "--workdir", str(workdir)]) == 0
    assert [call[1] for call in calls] == ["init", "plan", "apply"]
    # The apply consumed this run's verified snapshot of the previewed
    # plan (never the swappable fixed-name file, never -auto-approve).
    apply_command = calls[-1]
    assert (
        f"{terraform_runner.REBUILD_PLAN_FILENAME}.verified-{os.getpid()}"
        in apply_command
    )
    assert "-auto-approve" not in apply_command


def test_rebuild_with_nothing_to_do_never_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="No changes.", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)

    assert main(["--rebuild", "--confirm", "--workdir", str(workdir)]) == 0
    assert [call[1] for call in calls] == ["init", "plan"]


def test_rebuild_with_explicit_state_file_reanchors_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--rebuild --state-file must not silently apply against the state
    path a previous pipeline run baked into provider.tf."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    provider_tf = workdir / "provider.tf"
    provider_tf.write_text('path = "/old/state.tfstate"', encoding="utf-8")
    requested_state = tmp_path / "backups" / "B.tfstate"
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    exit_code = main(
        ["--rebuild", "--workdir", str(workdir), "--state-file", str(requested_state)]
    )

    assert exit_code == 0
    content = provider_tf.read_text(encoding="utf-8")
    assert str(requested_state.resolve()) in content
    assert "/old/state.tfstate" not in content


def test_rebaseline_discards_accumulated_config(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout="No changes.", stderr=""
        ),
    )
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    stale_baseline = workdir / "resources.tf"
    stale_baseline.write_text("resource_old {}", encoding="utf-8")

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(workdir), "--rebaseline"]
    )

    assert exit_code == 0
    assert not stale_baseline.exists()


def test_rebaseline_without_api_key_refuses_and_keeps_baseline(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a key the plan never regenerates resources.tf, so a
    keyless --rebaseline would silently destroy the DR baseline."""
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    baseline = workdir / "resources.tf"
    baseline.write_text("resource_old {}", encoding="utf-8")

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(workdir), "--rebaseline"]
    )

    # 2 = clean precondition refusal (same class as the other guarded
    # actions), detected before any pipeline work runs.
    assert exit_code == 2
    assert baseline.read_text(encoding="utf-8") == "resource_old {}"


def test_rebuild_planning_failure_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=1, stdout="", stderr="Error: init failed"
        ),
    )
    assert main(["--rebuild", "--workdir", str(workdir)]) == 1


def test_rebuild_apply_failure_exits_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        if command[1] == "apply":
            return SimpleNamespace(returncode=1, stdout="", stderr="Error: apply boom")
        exit_code = 2 if command[1] == "plan" else 0
        return SimpleNamespace(returncode=exit_code, stdout="Plan: 5 to add", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)

    assert main(["--rebuild", "--confirm", "--workdir", str(workdir)]) == 1


def test_rebuild_legacy_state_filename_is_a_clean_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A workspace-relative terraform.tfstate is refused with a clean
    diagnostic, not an unhandled traceback."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    exit_code = main(
        ["--rebuild", "--workdir", str(workdir),
         "--state-file", str(workdir / "terraform.tfstate")]
    )
    console = capsys.readouterr().err
    assert exit_code == 1
    assert "terraform.tfstate" in console


# ---------------------------------------------------------------------------
# Mode gating: --sync, --confirm-deletions, --fail-on-gaps
# ---------------------------------------------------------------------------


def test_new_flags_default_off(spec_file: Path) -> None:
    """The default invocation stays the strictly read-only ad-hoc mode."""
    config = _config(["--spec", str(spec_file)])
    assert not config.sync
    assert not config.confirm_deletions
    assert not config.fail_on_gaps


def test_sync_rejected_with_dump_to(dump_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--from-dump", str(dump_file), "--dump-to", "out.json", "--sync"])


def test_rebuild_rejects_pipeline_flags() -> None:
    for flag in ("--sync", "--confirm-deletions", "--fail-on-gaps"):
        with pytest.raises(SystemExit):
            main(["--rebuild", flag])


def test_sync_without_api_key_fails_loudly(
    dump_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Silently skipping the apply would let the weekly DR job believe it
    materialized state; sync must fail so the scheduler notices."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    assert main(["--from-dump", str(dump_file), "--sync"]) == 1


def test_fail_on_gaps_exits_three_when_unsupported_objects_exist(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    from conftest import DUMP_DOCUMENT

    document = json.loads(json.dumps(DUMP_DOCUMENT))
    document["features"].append(
        {"apiPath": "/networks/{networkId}/unknownFeature", "pathValues": ["N_1"]}
    )
    dump = tmp_path / "gappy.json"
    dump.write_text(json.dumps(document), encoding="utf-8")
    workdir = tmp_path / "workspace"

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(workdir), "--fail-on-gaps"]
    )

    assert exit_code == 3
    manifest = json.loads((workdir / "coverage.json").read_text(encoding="utf-8"))
    assert manifest["totals"]["unsupported"] == 1


def test_fail_on_gaps_passes_a_fully_covered_run(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    workdir = tmp_path / "workspace"
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(workdir), "--fail-on-gaps"]
    )
    assert exit_code == 0


def test_fail_on_gaps_gates_a_snapshot_export_run(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The weekly job is snapshot-only since the terraform demotion
    (2026-07-17); its coverage gate rides the --dump-to invocation."""
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    from conftest import DUMP_DOCUMENT

    document = json.loads(json.dumps(DUMP_DOCUMENT))
    document["features"].append(
        {"apiPath": "/networks/{networkId}/unknownFeature", "pathValues": ["N_1"]}
    )
    dump = tmp_path / "gappy.json"
    dump.write_text(json.dumps(document), encoding="utf-8")
    workdir = tmp_path / "workspace"
    out = tmp_path / "snapshot.json"

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--dump-to", str(out), "--workdir", str(workdir), "--fail-on-gaps"]
    )

    assert exit_code == 3
    # The gate does not truncate the run: snapshot, manifest, and the
    # DR runbook are complete before the nonzero exit.
    assert out.exists()
    assert (workdir / "runbook.md").exists()
    manifest = json.loads((workdir / "coverage.json").read_text(encoding="utf-8"))
    assert manifest["totals"]["unsupported"] == 1


def test_fail_on_gaps_passes_a_fully_covered_snapshot_export(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(tmp_path / "snapshot.json"),
         "--workdir", str(tmp_path / "workspace"), "--fail-on-gaps"]
    )
    assert exit_code == 0


def test_coverage_manifest_is_part_of_every_kit(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    workdir = tmp_path / "workspace"
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(workdir)]
    ) == 0
    manifest = json.loads((workdir / "coverage.json").read_text(encoding="utf-8"))
    assert manifest["totals"]["discovered"] == 4
    assert manifest["totals"]["pending_import"] == 4
    assert (workdir / "coverage.txt").exists()


def test_sync_end_to_end_applies_import_only_plan(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The weekly DR job: plan → verify import-only → apply → report growth."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _no_network(monkeypatch)
    workdir = tmp_path / "workspace"
    state = workdir / "meraki2tf.tfstate"
    terraform_calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        terraform_calls.append(command)
        if command[1] == "providers":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(fixture_schema_document()),
                stderr="",
            )
        if command[1] == "plan":
            # terraform writes the -out plan file; the guard verifies it.
            (workdir / "meraki2tf-sync.tfplan").write_bytes(b"opaque-plan")
            return SimpleNamespace(
                returncode=2,
                stdout="Plan: 4 to import, 0 to add, 0 to change, 0 to destroy.",
                stderr="",
            )
        if command[1] == "show":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "resource_changes": [
                            {
                                "address": "meraki_network.n_1",
                                "change": {
                                    "actions": ["no-op"],
                                    "importing": {"id": "N_1"},
                                },
                            }
                        ]
                    }
                ),
                stderr="",
            )
        if command[1] == "apply":
            state.write_text(
                json.dumps(
                    {
                        "resources": [
                            {"mode": "managed", "type": "meraki_network",
                             "name": "n_1"},
                            {"mode": "managed", "type": "meraki_device",
                             "name": "q2ab_cdef_ghij"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)
    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(workdir), "--sync",
         "--webhook-url", "https://hooks.example/alerts"]
    )

    assert exit_code == 0
    # catalog (init once + schema) → generation plan (import-only, so
    # reconciliation classifies nothing) → guard verification of the
    # saved plan document (show -json, no fresh read window) → apply.
    # The comparison stage's init is a cached no-op after the catalog
    # init.
    assert [call[1] for call in terraform_calls] == [
        "version", "init", "providers", "plan", "show", "apply",
    ]
    # The apply consumes the run-private verified copy of the plan.
    assert terraform_calls[-1][-1].startswith("meraki2tf-sync.tfplan.verified-")
    assert [event["event_type"] for event in delivered] == ["RUN_SUCCESS"]
    success = delivered[0]["details"]
    assert success["resources_added_to_state"] == [
        "meraki_device.q2ab_cdef_ghij", "meraki_network.n_1",
    ]
    assert success["pending_imports"] == 0
    manifest = json.loads((workdir / "coverage.json").read_text(encoding="utf-8"))
    assert manifest["totals"]["imported"] == 2
    assert manifest["totals"]["pending_import"] == 2


def test_sync_end_to_end_aborts_mutating_plan(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A destroy in the plan must abort the auto-apply with a drift alert."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _no_network(monkeypatch)
    workdir = tmp_path / "workspace"
    terraform_calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        terraform_calls.append(command)
        if command[1] == "plan":
            return SimpleNamespace(
                returncode=2,
                stdout="Plan: 0 to import, 0 to add, 0 to change, 1 to destroy.",
                stderr="",
            )
        if command[1] == "show":
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    {
                        "resource_changes": [
                            {"address": "meraki_networks.n_1",
                             "change": {"actions": ["delete"]}}
                        ]
                    }
                ),
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)
    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(workdir), "--sync",
         "--webhook-url", "https://hooks.example/alerts"]
    )

    # An aborted sync auto-apply exits 4 (not 0): the scheduler must be
    # able to page on a run that materialized no state.
    assert exit_code == 4
    assert "apply" not in [call[1] for call in terraform_calls]
    assert [event["event_type"] for event in delivered] == [
        "DRIFT_DETECTED", "RUN_SUCCESS",
    ]
    assert delivered[0]["details"]["apply_aborted"] is True


def test_report_surfaces_every_dr_outcome(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from meraki2tf.cli import _report
    from meraki2tf.orchestrator import RunSummary

    summary = RunSummary(
        organization_id="org-123",
        discovered_assets=5,
        imports_written=1,
        imports_skipped_existing=2,
        unsupported_count=1,
        drift_detected=True,
        comparison_skipped=False,
        pending_imports=0,
        resources_added_to_state=("meraki_networks.n_1",),
        apply_aborted=True,
        deletions_pending=("meraki_devices.gone",),
        deletions_removed=("meraki_devices.confirmed",),
        regenerated_addresses=("meraki_networks.n_1",),
        deferred_addresses=("meraki_wireless_ssid.racy_1",),
        coverage_percent=80.0,
        snapshot_drift="1 added, 2 modified, 0 removed",
    )
    with caplog.at_level(logging.INFO, logger="meraki2tf.cli"):
        _report(summary)
    text = " ".join(record.getMessage() for record in caplog.records)
    assert "sync auto-apply ABORTED" in text
    assert "State grew by 1 resource(s)" in text
    assert "regenerated to mirror Meraki" in text
    assert "deferred to the next run" in text
    assert "meraki_wireless_ssid.racy_1" in text
    assert "Snapshot drift vs baseline" in text
    assert "meraki_devices.confirmed" in text
    assert "--confirm-deletions" in text and "meraki_devices.gone" in text
    assert "80.00% coverage" in text


def test_report_logs_reconciliation_outcomes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from meraki2tf.cli import _report
    from meraki2tf.orchestrator import RunSummary

    summary = RunSummary(
        organization_id="org-123",
        discovered_assets=3,
        imports_written=2,
        imports_skipped_existing=0,
        unsupported_count=1,
        drift_detected=False,
        comparison_skipped=False,
        pending_imports=2,
        reconciliation_dropped=("meraki_network_firmware_upgrades.l_1",),
        unmanaged_secret_attributes={"meraki_wireless_ssid.s_0": ("psk",)},
        normalized_addresses=("meraki_network_alerts_settings.l_1",),
    )
    with caplog.at_level("INFO", logger="meraki2tf.cli"):
        _report(summary)
    text = caplog.text
    assert "1 resource(s) dropped as unexpressible" in text
    assert "1 resource(s) with unmanaged secret attribute(s)" in text
    assert (
        "1 resource(s) with values normalized for provider round-trip"
        in text
    )
    assert "meraki_wireless_ssid.s_0: psk" in text


# ------------------------------------------ alerting & exit-code contract


def _failing_urlopen(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every webhook delivery attempt fails (total notifier outage)."""

    def down(*args: Any, **kwargs: Any) -> None:
        raise OSError("endpoint unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", down)


def _stub_pipeline_summary(
    monkeypatch: pytest.MonkeyPatch, summary: Any
) -> None:
    """Route main() through a stub orchestrator returning ``summary``."""
    from meraki2tf import cli as cli_module

    class StubOrchestrator:
        def __init__(self, **kwargs: Any) -> None:
            pass

        def run(self, organization_id: str | None) -> Any:
            return summary

    monkeypatch.setattr(cli_module, "PipelineOrchestrator", StubOrchestrator)


def test_zero_alert_channels_warns_loudly(
    spec_file: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A scheduled DR job with no channels would drop every alert on the
    floor; the gap must be unmissable in the run log."""
    with caplog.at_level(logging.WARNING, logger="meraki2tf.cli"):
        build_dispatcher(_config(["--spec", str(spec_file)]))
    assert "No alert channels are configured" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="meraki2tf.cli"):
        build_dispatcher(
            _config(
                ["--spec", str(spec_file),
                 "--webhook-url", "https://hooks.example/a"]
            )
        )
    assert "No alert channels are configured" not in caplog.text


def test_startup_failure_dispatches_processing_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Spec resolution / provider construction failures happen before the
    orchestrator's alerting exists; the CLI itself must attempt the
    mandated PROCESSING_FAULT before exiting 1."""
    _no_network(monkeypatch)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        [
            "--spec", str(tmp_path / "missing-spec.json"),
            "--from-dump", str(tmp_path / "missing-dump.json"),
            "--webhook-url", "https://hooks.example/alerts",
        ]
    )
    assert exit_code == 1
    assert [event["event_type"] for event in delivered] == ["PROCESSING_FAULT"]
    assert delivered[0]["details"]["stage"] == "startup"


def test_sync_without_api_key_alerts_the_scheduler(
    dump_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The weekly job's most likely misconfiguration (a lost key) must
    reach the notification channels, not just the local log."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        ["--from-dump", str(dump_file), "--sync",
         "--webhook-url", "https://hooks.example/alerts"]
    )
    assert exit_code == 1
    assert [event["event_type"] for event in delivered] == ["PROCESSING_FAULT"]
    assert delivered[0]["details"]["stage"] == "startup"
    assert "--sync requires" in delivered[0]["details"]["error"]


def test_total_alert_delivery_failure_exits_five(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A run whose work product is intact but whose alerts reached nobody
    must not exit 0 — the scheduler is the only observer left."""
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _failing_urlopen(monkeypatch)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(tmp_path / "workspace"),
         "--webhook-url", "https://hooks.example/alerts"]
    )
    assert exit_code == 5
    # The kit itself was still produced — 5 marks a notifier outage,
    # not a pipeline failure.
    assert (tmp_path / "workspace" / "imports.tf").exists()


def test_export_alert_outage_exits_five(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    _failing_urlopen(monkeypatch)
    out = tmp_path / "export.json"
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(out), "--workdir", str(tmp_path / "workspace"),
         "--webhook-url", "https://hooks.example/alerts"]
    )
    assert exit_code == 5
    assert out.exists()  # the snapshot itself was written


def test_fail_on_gaps_outranks_alert_outage(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exit-code priority: known coverage gaps (3) over notifier outage
    (5) — 5 is the lowest-priority nonzero of the 3/4/5 group."""
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _failing_urlopen(monkeypatch)
    from conftest import DUMP_DOCUMENT

    document = json.loads(json.dumps(DUMP_DOCUMENT))
    document["features"].append(
        {"apiPath": "/networks/{networkId}/unknownFeature", "pathValues": ["N_1"]}
    )
    dump = tmp_path / "gappy.json"
    dump.write_text(json.dumps(document), encoding="utf-8")

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "workspace"), "--fail-on-gaps",
         "--webhook-url", "https://hooks.example/alerts"]
    )
    assert exit_code == 3


def test_apply_abort_outranks_fail_on_gaps_and_reports_chunk_growth(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exit-code priority: a stalled full-kit materialization (4) over
    coverage gaps (3) — and the abort message must reflect that
    import-only chunks may still have grown state."""
    from meraki2tf.orchestrator import RunSummary

    _no_network(monkeypatch)
    _stub_pipeline_summary(
        monkeypatch,
        RunSummary(
            organization_id="org-123",
            discovered_assets=5,
            imports_written=2,
            imports_skipped_existing=0,
            unsupported_count=1,
            drift_detected=True,
            comparison_skipped=False,
            pending_imports=1,
            resources_added_to_state=("meraki_networks.a", "meraki_networks.b"),
            apply_aborted=True,
        ),
    )
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(tmp_path / "workspace"), "--fail-on-gaps"]
    )
    console = capsys.readouterr().err
    assert exit_code == 4
    assert "mutations blocked the full apply" in console
    assert (
        "2 import-only resource(s) were still applied through targeted "
        "chunks" in console
    )


def test_apply_abort_without_growth_reports_the_stall(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from meraki2tf.orchestrator import RunSummary

    _no_network(monkeypatch)
    _stub_pipeline_summary(
        monkeypatch,
        RunSummary(
            organization_id="org-123",
            discovered_assets=5,
            imports_written=2,
            imports_skipped_existing=0,
            unsupported_count=0,
            drift_detected=True,
            comparison_skipped=False,
            pending_imports=2,
            apply_aborted=True,
        ),
    )
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(tmp_path / "workspace")]
    )
    assert exit_code == 4
    assert "no state was materialized this run" in capsys.readouterr().err


def test_export_flags_unsupported_and_notifies_success(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scheduled export run must answer 'what is/isn't covered' like
    every other run: coverage manifest in the workdir, unsupported list
    pushed with the success notification."""
    _no_network(monkeypatch)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    from conftest import DUMP_DOCUMENT

    document = json.loads(json.dumps(DUMP_DOCUMENT))
    document["features"].append(
        {"apiPath": "/networks/{networkId}/unknownFeature", "pathValues": ["N_1"]}
    )
    dump = tmp_path / "gappy.json"
    dump.write_text(json.dumps(document), encoding="utf-8")
    out = tmp_path / "export.json"
    workdir = tmp_path / "workspace"

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--dump-to", str(out), "--workdir", str(workdir),
         "--webhook-url", "https://hooks.example/dr"]
    )
    assert exit_code == 0
    assert [event["event_type"] for event in delivered] == [
        "UNSUPPORTED_FEATURE_FLAGGED", "RUN_SUCCESS",
    ]
    success = delivered[1]["details"]
    assert success["unsupported_count"] == 1
    assert success["discovered_assets"] == 5
    assert success["comparison_performed"] is False
    assert success["pending_imports"] is None
    manifest = json.loads((workdir / "coverage.json").read_text(encoding="utf-8"))
    assert manifest["totals"]["unsupported"] == 1
    assert manifest["totals"]["imported"] == 0  # exports never read state
    assert success["coverage_percent"] == manifest["coverage_percent"]


def test_export_classifies_via_workdir_catalog_cache(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A catalog cache left by a keyed pipeline run wins over the bundled
    fallback — proven by a cache that maps nothing."""
    _no_network(monkeypatch)
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    (workdir / "provider_catalog.json").write_text(
        json.dumps({"resources": {"meraki_unrelated": ["id"]}}),
        encoding="utf-8",
    )
    out = tmp_path / "export.json"
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(out), "--workdir", str(workdir)]
    )
    assert exit_code == 0
    manifest = json.loads((workdir / "coverage.json").read_text(encoding="utf-8"))
    assert manifest["totals"]["unsupported"] == manifest["totals"]["discovered"]


def test_export_recovers_from_a_corrupt_catalog_cache(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    (workdir / "provider_catalog.json").write_text("not json", encoding="utf-8")
    out = tmp_path / "export.json"
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(out), "--workdir", str(workdir)]
    )
    assert exit_code == 0
    assert "falling back to the bundled catalog" in capsys.readouterr().err
    manifest = json.loads((workdir / "coverage.json").read_text(encoding="utf-8"))
    assert manifest["totals"]["unsupported"] == 0


def test_sanitize_with_drift_baseline_is_a_usage_error(
    spec_file: Path, dump_file: Path, tmp_path: Path
) -> None:
    """A sanitized export can never serve as the next run's baseline, so
    the combination structurally fails from run 2 onward — refuse it up
    front instead."""
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--from-dump", str(dump_file),
             "--dump-to", str(tmp_path / "out.json"), "--sanitize",
             "--drift-baseline", str(tmp_path / "last-week.json")]
        )
    assert excinfo.value.code == 2


def test_rebuild_preview_log_redacts_secret_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The rebuild plan echoes attribute values into the log; secret-
    named lines get the same masking the alert payloads do."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        exit_code = 2 if command[1] == "plan" else 0
        return SimpleNamespace(
            returncode=exit_code,
            stdout='  ~ psk = "hunter2"\nPlan: 1 to add',
            stderr="",
        )

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)
    assert main(["--rebuild", "--workdir", str(workdir)]) == 0
    console = capsys.readouterr().err
    assert "hunter2" not in console
    assert "(value redacted)" in console


# ----------------------------------------------------------- --replay-gaps


def _secret_dump(tmp_path: Path) -> Path:
    """DUMP_DOCUMENT plus an SSID whose payload carries a PSK."""
    from conftest import DUMP_DOCUMENT

    document = json.loads(json.dumps(DUMP_DOCUMENT))
    document["features"].append(
        {
            "apiPath": "/networks/{networkId}/wireless/ssids/{number}",
            "pathValues": ["N_1", "0"],
            "payload": {
                "number": 0,
                "name": "Corp",
                "authMode": "psk",
                "psk": "wifi-secret",
            },
        }
    )
    # read-only endpoint: unsupported by the provider AND replayable by
    # no write operation, so replay planning must skip it loudly
    document["features"].append(
        {
            "apiPath": "/networks/{networkId}/clients",
            "pathValues": ["N_1"],
            "payload": {"usage": 42},
        }
    )
    path = tmp_path / "secret-snapshot.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _install_fake_meraki_module(
    monkeypatch: pytest.MonkeyPatch, fail: bool = False
) -> dict[str, Any]:
    """Stub the SDK for replay execution; returns the call recorder."""
    import sys
    import types

    recorded: dict[str, Any] = {"ssid": [], "admin": [], "networks": 0}

    class Wireless:
        @staticmethod
        def updateNetworkWirelessSsid(**kwargs: Any) -> dict[str, Any]:
            if fail:
                raise RuntimeError("ssid update rejected")
            recorded["ssid"].append(kwargs)
            return kwargs

        @staticmethod
        def getNetworkWirelessSsids(**kwargs: Any) -> list[dict[str, Any]]:
            # Serves the executor's item-ID verification read-back.
            return [{"number": 0, "name": "Corp"}]

    def get_networks(org: str, total_pages: str) -> list[dict[str, str]]:
        recorded["networks"] += 1
        return [{"id": "N_1", "name": "HQ"}]

    def get_admins(**kwargs: Any) -> list[dict[str, Any]]:
        # Verification read-back for the admin item write.
        return [{"id": "A_1", "name": "Jordan Sample"}]

    def update_admin(**kwargs: Any) -> dict[str, Any]:
        recorded["admin"].append(kwargs)
        return kwargs

    dashboard = SimpleNamespace(
        wireless=Wireless(),
        organizations=SimpleNamespace(
            getOrganizationNetworks=get_networks,
            getOrganizationAdmins=get_admins,
            updateOrganizationAdmin=update_admin,
        ),
    )
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard
    monkeypatch.setitem(sys.modules, "meraki", stub)
    return recorded


def test_replay_gaps_requires_a_snapshot(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["--spec", str(spec_file), "--replay-gaps"])
    assert excinfo.value.code == 2


def test_replay_gaps_rejects_incompatible_flags(
    spec_file: Path, dump_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    for extra in (["--sync"], ["--dump-to", "x.json"], ["--fail-on-gaps"],
                  ["--rebuild"], ["--confirm-deletions"], ["--rebaseline"]):
        with pytest.raises(SystemExit) as excinfo:
            main(
                ["--spec", str(spec_file), "--from-dump", str(dump_file),
                 "--replay-gaps", *extra]
            )
        assert excinfo.value.code == 2


def test_confirm_requires_a_dr_action(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    with pytest.raises(SystemExit) as excinfo:
        main(["--spec", str(spec_file), "--confirm"])
    assert excinfo.value.code == 2


def test_orphan_mode_scoped_flags_are_usage_errors(spec_file: Path) -> None:
    """Mode-scoped flags outside their parent mode are refused, never
    silently ignored — a no-op flag would let the operator believe an
    effect happened when it did not."""
    for extra in (
        ["--target-org", "org-999"],
        ["--serial-map", "serials.json"],
        ["--wipe-org-name", "Drill Org"],
    ):
        with pytest.raises(SystemExit) as excinfo:
            main(["--spec", str(spec_file), "--org-id", "org-123", *extra])
        assert excinfo.value.code == 2


def test_wipe_org_rejects_skip_claims(spec_file: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--wipe-org", "org-drill",
             "--wipe-org-name", "Drill Org", "--skip-claims"]
        )
    assert excinfo.value.code == 2


def test_drift_baseline_rejected_with_dr_actions(
    spec_file: Path, dump_file: Path
) -> None:
    """--drift-baseline only means something to pipeline/export runs;
    every DR action refuses it instead of silently skipping the diff."""
    for action in (
        ["--rebuild"],
        ["--replay-gaps", "--from-dump", str(dump_file)],
        ["--restore", "--from-dump", str(dump_file), "--target-org", "org-999"],
        ["--wipe-org", "org-drill", "--wipe-org-name", "Drill Org"],
    ):
        with pytest.raises(SystemExit) as excinfo:
            main(
                ["--spec", str(spec_file), *action,
                 "--drift-baseline", "last-week.jsonl"]
            )
        assert excinfo.value.code == 2


def test_rebuild_rejects_rebaseline_and_sanitize(spec_file: Path) -> None:
    for extra in (["--rebaseline"], ["--sanitize"]):
        with pytest.raises(SystemExit) as excinfo:
            main(["--spec", str(spec_file), "--rebuild", *extra])
        assert excinfo.value.code == 2


def test_replay_gaps_preview_writes_nothing(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    dump = _secret_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Preview only" in console
    assert "meraki_wireless_ssid" in console
    assert "Cannot replay /networks/{networkId}/clients" in console
    assert "wifi-secret" not in console  # previews never print values


def test_replay_gaps_reports_nothing_to_replay(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps"]
    )
    assert exit_code == 0
    assert "Nothing to replay" in capsys.readouterr().err


def test_replay_gaps_confirm_requires_api_key(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    dump = _secret_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps", "--confirm"]
    )
    assert exit_code == 1


def test_replay_gaps_confirm_restores_secrets_via_sdk(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    recorded = _install_fake_meraki_module(monkeypatch)
    dump = _secret_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps", "--confirm"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert recorded["networks"] == 1  # live networks enumerated for the map
    (call,) = recorded["ssid"]
    assert call["networkId"] == "N_1" and call["number"] == "0"
    assert call["psk"] == "wifi-secret"
    assert "Gap replay complete" in console
    assert "wifi-secret" not in console


def test_replay_gaps_confirm_reports_failures_nonzero(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _install_fake_meraki_module(monkeypatch, fail=True)
    dump = _secret_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps", "--confirm"]
    )
    assert exit_code == 1


def test_replay_gaps_fails_cleanly_when_live_networks_unreachable(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys
    import types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def explode(org: str, total_pages: str) -> list[dict[str, str]]:
        raise RuntimeError("api unreachable")

    dashboard = SimpleNamespace(
        organizations=SimpleNamespace(getOrganizationNetworks=explode)
    )
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard
    monkeypatch.setitem(sys.modules, "meraki", stub)
    dump = _secret_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps", "--confirm"]
    )
    assert exit_code == 1


def test_replay_gaps_fails_cleanly_on_unreadable_snapshot(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(tmp_path / "missing.json"),
         "--replay-gaps"]
    )
    assert exit_code == 1


def test_replay_gaps_org_id_remaps_org_scoped_writes_to_target(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--org-id names the rebuilt TARGET org; the remap must key on the
    snapshot's recorded source org, so an org-scoped write lands in the
    target — never back in the snapshot's own organization."""
    from conftest import DUMP_DOCUMENT

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    recorded = _install_fake_meraki_module(monkeypatch)
    document = json.loads(json.dumps(DUMP_DOCUMENT))
    document["features"].append(
        {
            "apiPath": "/organizations/{organizationId}/admins/{adminId}",
            "pathValues": ["org-123", "A_1"],
            "payload": {
                "id": "A_1",
                "name": "Jordan Sample",
                "email": "jdoe@corp.example",
                "apiKey": "fixture-secret",
            },
        }
    )
    dump = tmp_path / "org-scoped-snapshot.json"
    dump.write_text(json.dumps(document), encoding="utf-8")
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--org-id", "org-999", "--workdir", str(tmp_path / "ws"),
         "--replay-gaps", "--confirm"]
    )
    assert exit_code == 0
    (call,) = recorded["admin"]
    assert call["organizationId"] == "org-999"  # target, not the source org
    assert call["adminId"] == "A_1"


def test_replay_gaps_warns_on_sanitized_snapshots(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    document = json.loads((_secret_dump(tmp_path)).read_text(encoding="utf-8"))
    document["sanitized"] = True
    dump = tmp_path / "sanitized-snapshot.json"
    dump.write_text(json.dumps(document), encoding="utf-8")
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "SANITIZED" in console


def test_replay_gaps_legacy_state_filename_is_a_clean_error(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A workspace-relative terraform.tfstate is refused with a clean
    diagnostic, not an unhandled traceback."""
    _no_network(monkeypatch)
    dump = _secret_dump(tmp_path)
    workdir = tmp_path / "ws"
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(workdir), "--replay-gaps",
         "--state-file", str(workdir / "terraform.tfstate")]
    )
    console = capsys.readouterr().err
    assert exit_code == 1
    assert "terraform.tfstate" in console


def test_runbook_is_part_of_every_kit(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    dump = _secret_dump(tmp_path)
    workdir = tmp_path / "workspace"
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(workdir)]
    ) == 0
    runbook = (workdir / "runbook.md").read_text(encoding="utf-8")
    assert "Disaster-Recovery Runbook — organization org-123" in runbook
    assert "wifi-secret" not in runbook


def test_snapshot_exports_are_owner_only_and_warned(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    out = tmp_path / "export.json"
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(out), "--workdir", str(tmp_path / "workspace")]
    ) == 0
    assert out.stat().st_mode & 0o777 == 0o600
    assert "UNSANITIZED" in capsys.readouterr().err

    sanitized = tmp_path / "sanitized.json"
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(sanitized), "--sanitize",
         "--workdir", str(tmp_path / "workspace")]
    ) == 0
    assert "UNSANITIZED" not in capsys.readouterr().err


def test_export_with_drift_baseline_reports_snapshot_drift(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--dump-to + --drift-baseline: the weekly-job shape — export the
    fresh snapshot and diff it against last week's, no terraform."""
    _no_network(monkeypatch)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {"organizationId": "org-123", "networks": [], "devices": [],
             "features": []}
        ),
        encoding="utf-8",
    )
    out = tmp_path / "current.jsonl.gz"
    exit_code = main(
        [
            "--spec", str(spec_file),
            "--from-dump", str(dump_file),
            "--dump-to", str(out),
            "--drift-baseline", str(baseline),
            "--workdir", str(tmp_path / "workspace"),
            "--webhook-url", "https://hooks.example/dr",
        ]
    )
    assert exit_code == 0
    assert out.exists()
    assert [event["event_type"] for event in delivered] == [
        "DRIFT_DETECTED", "RUN_SUCCESS",
    ]
    event = delivered[0]
    assert event["details"]["origin"] == "snapshot-diff"
    assert "added" in event["details"]["diff"]
    assert delivered[1]["details"]["drift_was_detected"] is True


def test_export_with_identical_drift_baseline_is_quiet(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    first = tmp_path / "first.json"
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(first), "--workdir", str(tmp_path / "workspace")]
    ) == 0
    out = tmp_path / "second.jsonl.gz"
    assert main(
        [
            "--spec", str(spec_file), "--from-dump", str(dump_file),
            "--dump-to", str(out),
            "--drift-baseline", str(first),
            "--workdir", str(tmp_path / "workspace"),
            "--webhook-url", "https://hooks.example/dr",
        ]
    ) == 0
    # No drift → no DRIFT_DETECTED; the success notification (with the
    # coverage picture) still goes out on every clean export.
    assert [event["event_type"] for event in delivered] == ["RUN_SUCCESS"]
    assert delivered[0]["details"]["drift_was_detected"] is False


# ------------------------------------------------------------- --restore


def _restore_dump(tmp_path: Path) -> Path:
    dump = tmp_path / "restore-snapshot.json"
    dump.write_text(
        json.dumps(
            {
                "organizationId": "org-123",
                "networks": [
                    {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                     "productTypes": ["wireless"], "timeZone": "UTC"}
                ],
                "devices": [],
                "features": [
                    {
                        "apiPath": "/networks/{networkId}/wireless/ssids/{number}",
                        "pathValues": ["N_1", "0"],
                        "payload": {"number": 0, "name": "Corp"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return dump


def test_restore_requires_snapshot_and_target(spec_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--spec", str(spec_file), "--restore"])


def test_dr_actions_never_fetch_the_spec(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A DR write action runs on exactly the spec on disk — the mutable
    remote tip must never swap the dispatch table under a write run."""

    def never(url: str) -> str:
        raise AssertionError("a DR action must never fetch the spec")

    monkeypatch.setattr(spec_resolver, "_download", never)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 0
    console = capsys.readouterr().err
    assert "never auto-refresh the spec" in console


def test_warn_snapshot_spec_skew(
    spec_file: Path,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from meraki2tf.cli import _warn_snapshot_spec_skew
    from meraki2tf.spec_resolver import spec_fingerprint

    def snapshot_with(**extra: Any) -> StaticJsonDataProvider:
        doc = {
            "organizationId": "123456",
            "networks": [], "devices": [], "features": [],
            **extra,
        }
        path = tmp_path / f"snap-{len(extra)}-{extra.get('specSha256', 'x')[:6]}.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return StaticJsonDataProvider(path)

    version, digest = spec_fingerprint(spec_file)

    with caplog.at_level(logging.WARNING, logger="meraki2tf.cli"):
        # Version skew warns.
        _warn_snapshot_spec_skew(
            snapshot_with(specVersion="0.9", specSha256="ff" * 32),
            spec_file, "--restore",
        )
    assert "may classify assets differently" in caplog.text
    caplog.clear()

    with caplog.at_level(logging.WARNING, logger="meraki2tf.cli"):
        # Same version, different bytes (mutable master tip) warns too.
        _warn_snapshot_spec_skew(
            snapshot_with(specSha256="ee" * 32), spec_file, "--heal"
        )
    assert "may classify assets differently" in caplog.text
    caplog.clear()

    with caplog.at_level(logging.WARNING, logger="meraki2tf.cli"):
        # Matching fingerprint: silence.
        stamped = {"specSha256": digest}
        if version is not None:
            stamped["specVersion"] = version
        _warn_snapshot_spec_skew(
            snapshot_with(**stamped), spec_file, "--restore"
        )
        # Pre-stamping snapshots: nothing to compare, silence.
        _warn_snapshot_spec_skew(snapshot_with(), spec_file, "--restore")
    assert "may classify assets differently" not in caplog.text
    with pytest.raises(SystemExit):
        main(
            ["--spec", str(spec_file), "--restore",
             "--from-dump", "whatever.json"]
        )


def test_restore_rejects_pipeline_flags(spec_file: Path, tmp_path: Path) -> None:
    dump = _restore_dump(tmp_path)
    with pytest.raises(SystemExit):
        main(
            ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
             "--target-org", "org-999", "--sync"]
        )


def test_restore_refuses_the_source_organization(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The restore engine must never write to the org the snapshot was
    captured from."""
    _no_network(monkeypatch)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-123"]
    )
    assert exit_code == 2


def test_restore_refuses_a_multi_org_snapshot(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The executor can only remap ONE source org onto the target, so a
    nested multi-org export is refused outright — even when the target
    is a fresh org outside every recorded source (which would otherwise
    slip past the source-org interlock and mutate source orgs #2..N)."""
    _no_network(monkeypatch)
    dump = tmp_path / "multi-org.json"
    dump.write_text(
        json.dumps(
            {
                "organizations": [
                    {"info": {"id": "org-123", "name": "One"}, "networks": []},
                    {"info": {"id": "org-456", "name": "Two"}, "networks": []},
                ]
            }
        ),
        encoding="utf-8",
    )
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-fresh-scratch"]
    )
    assert exit_code == 2


def test_restore_execution_fault_alerts_and_exits_1(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exception escaping the restore executor (here: SDK client
    construction) must alert and exit cleanly, never die as an
    unhandled traceback — the journal preserves completed work."""
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def exploding_client(**kwargs: Any) -> None:
        raise RuntimeError("sdk client construction failed")

    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = exploding_client  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws"),
         "--confirm", "--webhook-url", "https://hooks.example/dr"]
    )
    assert exit_code == 1
    (event,) = delivered
    assert event["event_type"] == "PROCESSING_FAULT"
    assert "--restore --confirm" in event["details"]["stage"]
    assert "sdk client construction failed" in event["details"]["error"]


def test_restore_unreadable_journal_exits_2(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A corrupted journal (malformed non-final line) refuses the
    restore instead of silently re-creating completed objects."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = tmp_path / "ws"
    workdir.mkdir()
    (workdir / "restore-journal.jsonl").write_text(
        'not-json\n{"kind": "done", "key": "x"}\n', encoding="utf-8"
    )
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(workdir), "--confirm"]
    )
    assert exit_code == 2


def test_restore_journal_mismatch_exits_2(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A journal bound to a different restore refuses to be reused."""
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = (  # type: ignore[attr-defined]
        lambda **kwargs: SimpleNamespace()
    )
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    workdir = tmp_path / "ws"
    workdir.mkdir()
    (workdir / "restore-journal.jsonl").write_text(
        json.dumps({"kind": "meta", "target": "org-888", "source": "org-123"})
        + "\n",
        encoding="utf-8",
    )
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(workdir), "--confirm"]
    )
    assert exit_code == 2


def test_restore_rejects_org_id_override(
    spec_file: Path, tmp_path: Path
) -> None:
    """--org-id would replace the snapshot's recorded source org — the
    value the never-restore-into-the-source-org interlock compares
    against — so the combination is refused outright."""
    dump = _restore_dump(tmp_path)
    with pytest.raises(SystemExit):
        main(
            ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
             "--target-org", "org-123", "--org-id", "org-999"]
        )


def test_restore_warns_on_sanitized_snapshots(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--sanitize exports carry a marker; a restore from one must warn
    that the source-org interlock is vacuous (pseudonymized IDs) and
    that secrets will be re-entry pointers, not values."""
    _no_network(monkeypatch)
    dump = _restore_dump(tmp_path)
    document = json.loads(dump.read_text(encoding="utf-8"))
    document["sanitized"] = True
    dump.write_text(json.dumps(document), encoding="utf-8")

    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "SANITIZED" in console
    assert "scratch organization" in console


def test_sanitize_export_stamps_the_snapshot(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    out = tmp_path / "sanitized.json"
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(out), "--sanitize",
         "--workdir", str(tmp_path / "workspace")]
    ) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["sanitized"] is True


def test_restore_preview_writes_nothing(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)

    def forbidden(**kwargs: Any) -> None:
        raise AssertionError("preview must not construct an SDK client")

    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = forbidden  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Preview only" in console
    assert "configure" in console or "create" in console


def test_restore_confirm_requires_api_key(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws")]
        + ["--confirm"]
    )
    assert exit_code == 1


def test_restore_rejects_bad_serial_map(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    bad = tmp_path / "serials.json"
    bad.write_text("[]", encoding="utf-8")
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--serial-map", str(bad)]
    )
    assert exit_code == 2


def test_restore_confirm_executes_and_alerts(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    calls: list[tuple[str, tuple, dict]] = []

    class Section:
        def __getattr__(self, operation_id: str):  # noqa: ANN204
            def _dispatch(*args: Any, **kwargs: Any) -> dict:
                calls.append((operation_id, args, kwargs))
                if operation_id == "createOrganizationNetwork":
                    return {"id": "L_NEW"}
                return {}

            return _dispatch

    section = Section()
    dashboard = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)

    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    dump = _restore_dump(tmp_path)
    workdir = tmp_path / "ws"
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(workdir), "--confirm",
         "--webhook-url", "https://hooks.example/dr"]
    )
    assert exit_code == 0
    ops = [c[0] for c in calls]
    assert ops.index("createOrganizationNetwork") < ops.index(
        "updateNetworkWirelessSsid"
    )
    ssid = next(c for c in calls if c[0] == "updateNetworkWirelessSsid")
    assert ssid[1] == ("L_NEW", "0")  # remapped to the rebuilt network
    (event,) = delivered
    assert event["event_type"] == "RESTORE_EXECUTED"
    assert event["details"]["target_organization_id"] == "org-999"
    assert (workdir / "restore-journal.jsonl").exists()


def test_restore_refuses_a_bad_webhook_before_any_write(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dispatcher is built before anything else: a misconfigured
    channel must stop the restore up front, never leave the target org
    written with the mandated executed-alert undeliverable."""
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def forbidden(**kwargs: Any) -> None:
        raise AssertionError("no SDK client may be built with a bad webhook")

    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = forbidden  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    dump = _restore_dump(tmp_path)
    with pytest.raises(SystemExit):
        main(
            ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
             "--target-org", "org-999", "--workdir", str(tmp_path / "ws"),
             "--confirm", "--webhook-url", "http://insecure.example/hook"]
        )


def test_restore_fails_cleanly_on_unreadable_snapshot(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    exit_code = main(
        ["--spec", str(spec_file), "--restore",
         "--from-dump", str(tmp_path / "missing.json"),
         "--target-org", "org-999"]
    )
    assert exit_code == 1


def test_restore_rejects_combination_with_rebuild(
    spec_file: Path, tmp_path: Path
) -> None:
    with pytest.raises(SystemExit):
        main(
            ["--spec", str(spec_file), "--restore", "--rebuild",
             "--from-dump", str(tmp_path / "x.json"), "--target-org", "o"]
        )


def test_restore_preview_reports_unrestorables_and_serial_map(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    dump = tmp_path / "gapd.json"
    dump.write_text(
        json.dumps(
            {
                "organizationId": "org-123",
                "networks": [],
                "devices": [],
                "features": [
                    {
                        "apiPath": "/networks/{networkId}/clients",
                        "pathValues": ["N_1"],
                        "payload": {"usage": 1},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    serial_map = tmp_path / "serials.json"
    serial_map.write_text('{"Q2AB-CDEF-GHIJ": "Q9ZZ-NEWW-HWSN"}', encoding="utf-8")
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--serial-map", str(serial_map)]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Cannot restore /networks/{networkId}/clients" in console


def test_restore_unreadable_serial_map_exits_2(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999",
         "--serial-map", str(tmp_path / "no-such-map.json")]
    )
    assert exit_code == 2


def test_restore_confirm_reports_failures_nonzero(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    class FailingSection:
        def __getattr__(self, operation_id: str):  # noqa: ANN204
            def _dispatch(*args: Any, **kwargs: Any) -> dict:
                raise RuntimeError("simulated failure")

            return _dispatch

    section = FailingSection()
    dashboard = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws"),
         "--confirm"]
    )
    assert exit_code == 1


def test_skip_claims_requires_restore(spec_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--spec", str(spec_file), "--org-id", "org-123", "--skip-claims"])


def test_restore_drill_preview_notes_skip_claims(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--skip-claims"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Drill mode" in console


def _sanitized_restore_dump(tmp_path: Path) -> Path:
    dump = _restore_dump(tmp_path)
    document = json.loads(dump.read_text(encoding="utf-8"))
    document["sanitized"] = True
    dump.write_text(json.dumps(document), encoding="utf-8")
    return dump


def test_sanitized_restore_refuses_a_populated_target(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A sanitized snapshot's org ID is a pseudonym, so the source-org
    interlock is blind; a populated --target-org is refused outright —
    it could BE the source organization."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    counted: list[str] = []

    def fake_count(target_org: str) -> int:
        counted.append(target_org)
        return 3

    monkeypatch.setattr("meraki2tf.cli._target_network_count", fake_count)
    dump = _sanitized_restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws"),
         "--confirm"]
    )
    console = capsys.readouterr().err
    assert exit_code == 2
    assert counted == ["org-999"]
    assert "only writes it into an EMPTY organization" in console


def test_sanitized_restore_proceeds_into_an_empty_target(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    monkeypatch.setattr(
        "meraki2tf.cli._target_network_count", lambda target_org: 0
    )
    calls: list[tuple[str, tuple, dict]] = []

    class Section:
        def __getattr__(self, operation_id: str):  # noqa: ANN204
            def _dispatch(*args: Any, **kwargs: Any) -> dict:
                calls.append((operation_id, args, kwargs))
                if operation_id == "createOrganizationNetwork":
                    return {"id": "L_NEW"}
                return {}

            return _dispatch

    section = Section()
    dashboard = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    dump = _sanitized_restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws"),
         "--confirm"]
    )
    assert exit_code == 0
    assert "createOrganizationNetwork" in [c[0] for c in calls]


def test_sanitized_restore_resume_skips_the_empty_target_check(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A journaled resume's earlier waves populated the target; the
    empty-target interlock must not even consult the network count."""
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def forbidden(target_org: str) -> int:
        raise AssertionError("a journaled resume must not count networks")

    monkeypatch.setattr("meraki2tf.cli._target_network_count", forbidden)
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = (  # type: ignore[attr-defined]
        lambda **kwargs: SimpleNamespace()
    )
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    workdir = tmp_path / "ws"
    workdir.mkdir()
    (workdir / "restore-journal.jsonl").write_text(
        json.dumps({"kind": "meta", "target": "org-999", "source": "org-123"})
        + "\n"
        + json.dumps(
            {"kind": "done",
             "key": "/organizations/{organizationId}/networks::N_1"}
        )
        + "\n"
        + json.dumps(
            {"kind": "done",
             "key": "/networks/{networkId}/wireless/ssids/{number}::N_1,0"}
        )
        + "\n",
        encoding="utf-8",
    )
    dump = _sanitized_restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(workdir), "--confirm"]
    )
    assert exit_code == 0


def test_target_network_count_reads_the_live_network_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys as _sys
    import types as _types

    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    constructed: list[dict[str, Any]] = []

    class Organizations:
        def __init__(self, networks: Any) -> None:
            self._networks = networks

        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> Any:
            assert organizationId == "org-999"
            assert total_pages == "all"
            return self._networks

    def install(networks: Any) -> None:
        def factory(**kwargs: Any) -> SimpleNamespace:
            constructed.append(kwargs)
            return SimpleNamespace(organizations=Organizations(networks))

        stub = _types.ModuleType("meraki")
        stub.DashboardAPI = factory  # type: ignore[attr-defined]
        monkeypatch.setitem(_sys.modules, "meraki", stub)

    from meraki2tf.cli import _target_network_count

    install([{"id": "L_1"}, {"id": "L_2"}])
    assert _target_network_count("org-999") == 2
    # A non-list response counts as empty rather than crashing.
    install({"unexpected": "shape"})
    assert _target_network_count("org-999") == 0
    # The throwaway client is quiet and keyed from the environment.
    assert constructed[0]["api_key"] == "test-token"
    assert constructed[0]["suppress_logging"] is True


def test_sanitized_restore_count_failure_fails_closed(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def exploding(target_org: str) -> int:
        raise RuntimeError("dashboard unreachable")

    monkeypatch.setattr("meraki2tf.cli._target_network_count", exploding)
    dump = _sanitized_restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws"),
         "--confirm"]
    )
    console = capsys.readouterr().err
    assert exit_code == 1
    assert "Cannot verify that target organization org-999 is empty" in console
    assert "dashboard unreachable" in console


# ------------------------------------------------------------- --wipe-org


def _install_wipe_dashboard(
    monkeypatch: pytest.MonkeyPatch, devices: int = 0, name: str = "Drill Org"
) -> dict:
    import sys as _sys
    import types as _types

    deleted: dict = {"networks": [], "orgs": []}

    class Organizations:
        def getOrganization(self, organizationId: str) -> dict:
            return {"id": organizationId, "name": name}

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return [{"serial": f"Q{i}"} for i in range(devices)]

        def getOrganizationInventoryDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return [{"serial": f"Q{i}"} for i in range(devices)]

        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return [{"id": "L_1"}]

        def deleteOrganization(self, organizationId: str) -> dict:
            deleted["orgs"].append(organizationId)
            return {}

    class Networks:
        def deleteNetwork(self, networkId: str) -> dict:
            deleted["networks"].append(networkId)
            return {}

    dashboard = SimpleNamespace(organizations=Organizations(), networks=Networks())
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    return deleted


def test_wipe_requires_name_second_factor(spec_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--spec", str(spec_file), "--wipe-org", "org-drill"])


def test_wipe_rejects_other_modes_and_org_id(spec_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(
            ["--spec", str(spec_file), "--wipe-org", "org-x",
             "--wipe-org-name", "X", "--sync"]
        )
    # --org-id is refused with --wipe-org whether it matches the wipe
    # target (production-shaped) or differs (it would be silently
    # ignored, violating the no-silent-orphans policy).
    for org_id in ("org-x", "org-other"):
        with pytest.raises(SystemExit) as excinfo:
            main(
                ["--spec", str(spec_file), "--org-id", org_id,
                 "--wipe-org", "org-x", "--wipe-org-name", "X"]
            )
        assert excinfo.value.code == 2


def test_wipe_refuses_production_shaped_orgs(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    deleted = _install_wipe_dashboard(monkeypatch, devices=5)
    exit_code = main(
        ["--spec", str(spec_file), "--wipe-org", "org-prod",
         "--wipe-org-name", "Drill Org", "--confirm"]
    )
    assert exit_code == 2
    assert deleted["networks"] == [] and deleted["orgs"] == []


def test_wipe_preview_deletes_nothing(
    spec_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    deleted = _install_wipe_dashboard(monkeypatch)
    exit_code = main(
        ["--spec", str(spec_file), "--wipe-org", "org-drill",
         "--wipe-org-name", "Drill Org"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Preview only" in console
    assert "data-deletion request" in console  # retention honesty
    assert deleted["networks"] == [] and deleted["orgs"] == []


def test_wipe_confirm_executes_and_alerts(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    deleted = _install_wipe_dashboard(monkeypatch)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        ["--spec", str(spec_file), "--wipe-org", "org-drill",
         "--wipe-org-name", "Drill Org", "--confirm",
         "--webhook-url", "https://hooks.example/dr"]
    )
    assert exit_code == 0
    assert deleted["networks"] == ["L_1"]
    assert deleted["orgs"] == ["org-drill"]
    (event,) = delivered
    assert event["event_type"] == "ORG_WIPE_EXECUTED"
    assert event["details"]["organization_deleted"] is True


def test_wipe_refuses_a_bad_webhook_before_any_write(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The dispatcher is built before the teardown: a misconfigured
    channel must stop the wipe up front, never leave the org deleted
    with the mandated executed-alert undeliverable."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    deleted = _install_wipe_dashboard(monkeypatch)
    with pytest.raises(SystemExit):
        main(
            ["--spec", str(spec_file), "--wipe-org", "org-drill",
             "--wipe-org-name", "Drill Org", "--confirm",
             "--webhook-url", "http://insecure.example/hook"]
        )
    assert deleted["networks"] == [] and deleted["orgs"] == []


def test_wipe_confirm_requires_api_key(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    exit_code = main(
        ["--spec", str(spec_file), "--wipe-org", "org-drill",
         "--wipe-org-name", "Drill Org"]
    )
    assert exit_code == 1


def test_wipe_inspection_failure_exits_1(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    class Exploding:
        def getOrganization(self, organizationId: str) -> dict:
            raise RuntimeError("api unreachable")

    dashboard = SimpleNamespace(organizations=Exploding())
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    exit_code = main(
        ["--spec", str(spec_file), "--wipe-org", "org-x",
         "--wipe-org-name", "X"]
    )
    assert exit_code == 1


def test_wipe_execution_recheck_refusal_exits_2(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A device claimed between preview and --confirm still stops the
    wipe: the interlocks are re-verified at execution time."""
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    device_state = {"count": 0}

    class Organizations:
        def getOrganization(self, organizationId: str) -> dict:
            return {"id": organizationId, "name": "Drill Org"}

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            count = device_state["count"]
            device_state["count"] += 1  # second call sees a claim
            return [] if count == 0 else [{"serial": "Q1"}]

        def getOrganizationInventoryDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return []

        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return []

    dashboard = SimpleNamespace(organizations=Organizations())
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    exit_code = main(
        ["--spec", str(spec_file), "--wipe-org", "org-drill",
         "--wipe-org-name", "Drill Org", "--confirm"]
    )
    assert exit_code == 2


def test_wipe_confirm_reports_failures_nonzero(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    class Organizations:
        def getOrganization(self, organizationId: str) -> dict:
            return {"id": organizationId, "name": "Drill Org"}

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return []

        def getOrganizationInventoryDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return []

        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return [{"id": "L_1"}]

    class Networks:
        def deleteNetwork(self, networkId: str) -> dict:
            raise RuntimeError("bound to template")

    dashboard = SimpleNamespace(
        organizations=Organizations(), networks=Networks()
    )
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    exit_code = main(
        ["--spec", str(spec_file), "--wipe-org", "org-drill",
         "--wipe-org-name", "Drill Org", "--confirm"]
    )
    assert exit_code == 1


def test_wipe_execution_fault_alerts_and_exits_1(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A transient API fault mid-teardown must alert and exit cleanly,
    never die as an unhandled traceback."""
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    listings = {"count": 0}

    class Organizations:
        def getOrganization(self, organizationId: str) -> dict:
            return {"id": organizationId, "name": "Drill Org"}

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return []

        def getOrganizationInventoryDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return []

        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            listings["count"] += 1
            if listings["count"] > 2:  # both interlock previews passed
                raise RuntimeError("api unreachable mid-wipe")
            return [{"id": "L_1"}]

    dashboard = SimpleNamespace(organizations=Organizations())
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        ["--spec", str(spec_file), "--wipe-org", "org-drill",
         "--wipe-org-name", "Drill Org", "--confirm",
         "--webhook-url", "https://hooks.example/dr"]
    )
    assert exit_code == 1
    (event,) = delivered
    assert event["event_type"] == "PROCESSING_FAULT"
    assert "--wipe-org --confirm" in event["details"]["stage"]
    assert "api unreachable mid-wipe" in event["details"]["error"]


def _heal_dump(tmp_path: Path, sanitized: bool = False) -> Path:
    dump = tmp_path / "heal-snapshot.json"
    document = {
        "organizationId": "org-123",
        "networks": [
            {"id": "N_1", "organizationId": "org-123", "name": "HQ",
             "productTypes": ["wireless"], "timeZone": "UTC"}
        ],
        "devices": [],
        "features": [
            {
                "apiPath": "/networks/{networkId}/wireless/ssids/{number}",
                "pathValues": ["N_1", "0"],
                "payload": {"number": 0, "name": "Corp"},
            }
        ],
    }
    if sanitized:
        document["sanitized"] = True
    dump.write_text(json.dumps(document), encoding="utf-8")
    return dump


class _StubLiveProvider:
    """Injectable stand-in for LiveApiDataProvider in heal tests."""

    graph: Any = None
    #: The network_scope the heal path constructed, for assertions.
    last_network_scope: Any = None

    #: Mirrors the real provider's post-fetch scope declaration; the
    #: stub never sets it (tests inject a StaticJson-shaped graph).
    snapshot_scope: Any = None

    def __init__(
        self,
        parser: Any = None,
        *,
        network_scope: Any = None,
        checkpoint_path: Any = None,
        spec_sha256: Any = None,
        progress_clock: Any = None,
    ) -> None:
        type(self).last_network_scope = network_scope

    def __enter__(self) -> "_StubLiveProvider":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def fetch_network_graph(self, organization_id: str | None = None) -> Any:
        return type(self).graph


def test_heal_requires_snapshot_and_org(spec_file: Path) -> None:
    with pytest.raises(SystemExit):
        main(["--spec", str(spec_file), "--heal"])
    with pytest.raises(SystemExit):
        main(["--spec", str(spec_file), "--heal", "--from-dump", "x.json"])


def test_heal_rejects_pipeline_flags(spec_file: Path, tmp_path: Path) -> None:
    dump = _heal_dump(tmp_path)
    with pytest.raises(SystemExit):
        main(
            ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
             "--org-id", "org-123", "--sync"]
        )


def test_heal_refuses_sanitized_snapshots(
    spec_file: Path, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    dump = _heal_dump(tmp_path, sanitized=True)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 2


def test_heal_refuses_a_foreign_org(
    spec_file: Path, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The inverse of --restore's interlock: heal writes only into the
    snapshot's own source organization."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    dump = _heal_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-999", "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 2


def test_heal_requires_api_key_even_for_preview(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    dump = _heal_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 1


def test_heal_preview_lists_missing_and_writes_nothing(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import sys as _sys
    import types as _types

    from meraki2tf import cli as cli_module
    from meraki2tf.models import MerakiNetwork, NetworkGraph

    _no_network(monkeypatch)

    def forbidden(**kwargs: Any) -> None:
        raise AssertionError("preview must not construct an SDK client")

    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = forbidden  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    # Live discovery sees an org with the network but WITHOUT the SSID
    # feature key — the SSID counts as missing.
    _StubLiveProvider.graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(),
    )
    monkeypatch.setattr(cli_module, "LiveApiDataProvider", _StubLiveProvider)
    dump = _heal_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Preview only" in console
    assert "1 missing" in console or "missing and planned" in console


def test_heal_with_nothing_missing_exits_zero(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from meraki2tf import cli as cli_module
    from meraki2tf.models import (
        FeatureConfiguration,
        MerakiNetwork,
        NetworkGraph,
    )

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _StubLiveProvider.graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(
            FeatureConfiguration(
                "/networks/{networkId}/wireless/ssids/{number}",
                ("N_1", "0"),
                {"number": 0, "name": "Corp"},
            ),
        ),
    )
    monkeypatch.setattr(cli_module, "LiveApiDataProvider", _StubLiveProvider)
    dump = _heal_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--confirm", "--from-dump",
         str(dump), "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Nothing to heal" in console


def test_rebuild_refuses_an_org_id() -> None:
    """Orphaned mode-scoped flags are refused, never silently ignored:
    the rebuild applies whatever kit the workdir holds — it is not
    scoped or verified against an organization ID."""
    with pytest.raises(SystemExit) as excinfo:
        main(["--rebuild", "--org-id", "999"])
    assert excinfo.value.code == 2


def test_rebuild_dispatcher_refusal_leaves_no_saved_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A misconfigured alert channel must refuse --rebuild --confirm
    BEFORE terraform plans: otherwise the secret-embedding saved plan
    outlives the failed run — a third secret-at-rest artifact."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)
    with pytest.raises(SystemExit):
        main(
            ["--rebuild", "--confirm", "--workdir", str(workdir),
             "--webhook-url", "ftp://not-a-webhook"]
        )
    assert calls == []  # refused before init/plan ever ran
    assert not (workdir / terraform_runner.REBUILD_PLAN_FILENAME).exists()


def test_replay_gaps_refuses_multi_org_snapshots(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same stance as --restore: the network-name join spans every
    recorded org, so a second org's same-named network would remap its
    objects and secrets onto the target — cross-tenant bleed."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    document = {
        "organizations": [
            {"info": {"id": "org-123", "name": "A"}, "networks": []},
            {"info": {"id": "org-456", "name": "B"}, "networks": []},
        ]
    }
    dump = tmp_path / "multi-org.json"
    dump.write_text(json.dumps(document), encoding="utf-8")
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps"]
    )
    assert exit_code == 2


def test_replay_gaps_alert_outage_exits_five(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DR write happened and the mandated GAP_REPLAY_EXECUTED alert
    reached nobody: that is the notifier-outage exit, exactly like the
    pipeline paths — never a clean 0."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _install_fake_meraki_module(monkeypatch)
    _failing_urlopen(monkeypatch)
    dump = _secret_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws"), "--replay-gaps", "--confirm",
         "--webhook-url", "https://hooks.example/alerts"]
    )
    assert exit_code == 5


def test_sanitized_restore_resume_honors_an_attempt_only_journal(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run that died inside its very first create/journal window left
    only meta + attempt records — but it may already have written into
    the target. Refusing that resume as 'populated target' would wedge
    it forever; the write-ahead attempt record is exactly the proof
    this workdir's restore touched the target."""
    import sys as _sys
    import types as _types

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def forbidden(target_org: str) -> int:
        raise AssertionError("a journaled resume must not count networks")

    monkeypatch.setattr("meraki2tf.cli._target_network_count", forbidden)
    calls: list[str] = []

    class Section:
        def __getattr__(self, operation_id: str):  # noqa: ANN204
            def _dispatch(*args: Any, **kwargs: Any) -> dict:
                calls.append(operation_id)
                if operation_id == "createOrganizationNetwork":
                    return {"id": "L_NEW"}
                if operation_id == "getOrganizationNetworks":
                    return []
                return {}

            return _dispatch

    section = Section()
    dashboard = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    workdir = tmp_path / "ws"
    workdir.mkdir()
    (workdir / "restore-journal.jsonl").write_text(
        json.dumps({"kind": "meta", "target": "org-999", "source": "org-123"})
        + "\n"
        + json.dumps(
            {"kind": "attempt",
             "key": "/organizations/{organizationId}/networks::N_1"}
        )
        + "\n",
        encoding="utf-8",
    )
    dump = _sanitized_restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(workdir), "--confirm"]
    )
    assert exit_code == 0


# ---------------------------------------------------------------------------
# First-run ergonomics: --version, python -m, --list-orgs, fast key failure.
# ---------------------------------------------------------------------------


def test_version_flag_prints_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith("meraki2tf ")
    assert out.strip() != "meraki2tf"


def test_module_entrypoint_matches_console_script() -> None:
    import importlib
    import subprocess
    import sys as _sys

    # Importing the module covers its assembly; the subprocess proves the
    # `python -m meraki2tf` surface end to end.
    importlib.import_module("meraki2tf.__main__")
    result = subprocess.run(
        [_sys.executable, "-m", "meraki2tf", "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert result.stdout.startswith("meraki2tf ")


def _stub_meraki_orgs(
    monkeypatch: pytest.MonkeyPatch, organizations: Any
) -> dict[str, Any]:
    """Fake meraki module whose getOrganizations returns (or raises) as told."""
    import sys as _sys
    import types as _types

    captured: dict[str, Any] = {}

    def get_orgs() -> Any:
        if isinstance(organizations, Exception):
            raise organizations
        return organizations

    def dashboard(**kwargs: Any) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(
            organizations=SimpleNamespace(getOrganizations=get_orgs)
        )

    stub = _types.ModuleType("meraki")
    stub.DashboardAPI = dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(_sys.modules, "meraki", stub)
    return captured


def test_list_orgs_prints_sorted_table(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    captured = _stub_meraki_orgs(
        monkeypatch,
        [
            {"id": "222333", "name": "Zeta Networks"},
            {"id": "111222", "name": "Acme Corp"},
        ],
    )
    exit_code = main(["--list-orgs"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "ORG ID" in out
    assert out.index("Acme Corp") < out.index("Zeta Networks")  # name-sorted
    assert "111222" in out and "222333" in out
    assert "--org-id" in out  # the next-step pointer
    assert captured["api_key"] == "test-token"
    assert captured["suppress_logging"] is True


def test_list_orgs_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main(["--list-orgs"])
    assert excinfo.value.code == 2


def test_list_orgs_refuses_companion_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    for extra in (["--org-id", "123456"], ["--sync"], ["--rebuild"]):
        with pytest.raises(SystemExit) as excinfo:
            main(["--list-orgs", *extra])
        assert excinfo.value.code == 2


def test_list_orgs_api_failure_exits_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_meraki_orgs(monkeypatch, RuntimeError("403 forbidden"))
    assert main(["--list-orgs"]) == 1


def test_list_orgs_reports_an_empty_key(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_meraki_orgs(monkeypatch, [])
    assert main(["--list-orgs"]) == 0
    assert "sees no organizations" in capsys.readouterr().out


def test_live_run_without_api_key_fails_fast(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """No key + live mode dies immediately with a purposeful pointer."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    exit_code = main(["--org-id", "123456"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert API_KEY_ENV_VAR in err
    assert "--list-orgs" in err
    assert "--from-dump" in err


# ---------------------------------------------------------------------------
# Notification channel wiring: --webhook-format and --pagerduty.
# ---------------------------------------------------------------------------


def test_webhook_format_reaches_the_notifier(spec_file: Path) -> None:
    config = _config(
        [
            "--spec", str(spec_file),
            "--webhook-url", "https://hooks.example/a",
            "--webhook-format", "slack",
        ]
    )
    dispatcher = build_dispatcher(config)
    (notifier,) = dispatcher._notifiers
    assert notifier._payload_format == "slack"  # type: ignore[attr-defined]


def test_pagerduty_flag_registers_the_channel(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from meraki2tf.alerts.pagerduty import ROUTING_KEY_ENV_VAR

    monkeypatch.setenv(ROUTING_KEY_ENV_VAR, "rk-test-0001")
    dispatcher = build_dispatcher(
        _config(["--spec", str(spec_file), "--pagerduty"])
    )
    assert [n.channel for n in dispatcher._notifiers] == ["pagerduty"]


def test_pagerduty_flag_without_routing_key_refuses_loudly(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from meraki2tf.alerts.pagerduty import ROUTING_KEY_ENV_VAR

    monkeypatch.delenv(ROUTING_KEY_ENV_VAR, raising=False)
    with pytest.raises(SystemExit) as excinfo:
        build_dispatcher(_config(["--spec", str(spec_file), "--pagerduty"]))
    assert ROUTING_KEY_ENV_VAR in str(excinfo.value)


# ---------------------------------------------------------------------------
# Multi-organization fan-out.
# ---------------------------------------------------------------------------


def test_repeated_org_id_collects_and_dedupes(spec_file: Path) -> None:
    config = _config(
        ["--spec", str(spec_file), "--org-id", "111222",
         "--org-id", "333444", "--org-id", "111222"]
    )
    assert config.org_ids == ("111222", "333444")
    assert config.org_id is None  # ambiguous with several orgs
    single = _config(["--spec", str(spec_file), "--org-id", "111222"])
    assert single.org_ids == ("111222",)
    assert single.org_id == "111222"


def test_multi_org_refuses_snapshot_and_state_file_modes(
    spec_file: Path, dump_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    multi = ["--org-id", "111222", "--org-id", "333444"]
    for extra in (
        ["--from-dump", str(dump_file)],
        ["--dump-to", "snap.json"],
        ["--drift-baseline", str(dump_file)],
        ["--state-file", "state.tfstate"],
    ):
        with pytest.raises(SystemExit) as excinfo:
            main(["--spec", str(spec_file), *multi, *extra])
        assert excinfo.value.code == 2


def test_multi_org_refuses_path_shaped_org_ids(spec_file: Path) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--spec", str(spec_file), "--org-id", "111222",
              "--org-id", "../evil"])
    assert excinfo.value.code == 2


def test_multi_org_remote_backend_requires_placeholder(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    base = [
        "--spec", str(spec_file), "--org-id", "111222", "--org-id", "333444",
        "--state-backend", "s3", "--backend-config", "bucket=example-state",
    ]
    with pytest.raises(SystemExit) as excinfo:
        main([*base, "--backend-config", "key=meraki2tf.tfstate"])
    assert excinfo.value.code == 2
    # With the placeholder the validation passes and each derived
    # per-org config substitutes its own state address.
    from meraki2tf.cli import _single_org_config

    config = _config(
        [*base, "--backend-config", "key=meraki2tf/{org-id}.tfstate"]
    )
    derived = _single_org_config(config, "333444")
    assert derived.org_ids == ("333444",)
    assert derived.workdir == config.workdir / "333444"
    assert ("key", "meraki2tf/333444.tfstate") in derived.backend.settings


def test_heal_requires_exactly_one_org(
    spec_file: Path, dump_file: Path
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--spec", str(spec_file), "--heal",
              "--from-dump", str(dump_file),
              "--org-id", "111222", "--org-id", "333444"])
    assert excinfo.value.code == 2


def test_aggregate_exit_prefers_most_severe() -> None:
    from meraki2tf.cli import _aggregate_exit

    assert _aggregate_exit([0, 0]) == 0
    assert _aggregate_exit([0, 3, 5]) == 3
    assert _aggregate_exit([5, 4]) == 4
    assert _aggregate_exit([3, 1, 4]) == 1
    assert _aggregate_exit([0, 5]) == 5


def test_multi_org_fan_out_builds_per_org_kits(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Two organizations, one invocation: per-org workdirs, aggregate 0."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout="", stderr=""
        ),
    )
    monkeypatch.setattr(
        "meraki2tf.cli.build_provider",
        lambda config, parser, spec_file=None: StaticJsonDataProvider(
            dump_file, parser=parser
        ),
    )
    workdir = tmp_path / "orgs"

    exit_code = main(
        ["--spec", str(spec_file), "--workdir", str(workdir),
         "--org-id", "111222", "--org-id", "333444"]
    )

    assert exit_code == 0
    for org in ("111222", "333444"):
        assert (workdir / org / "imports.tf").exists()
        assert (workdir / org / "provider.tf").exists()
    out = capsys.readouterr().out
    assert "Per-organization DR kits" in out
    assert "111222" in out and "333444" in out


# ---------------------------------------------------------------------------
# Heal execution (--heal --confirm) and remaining DR-surface edges.
# ---------------------------------------------------------------------------


def test_heal_rejects_combination_with_restore(
    spec_file: Path, tmp_path: Path
) -> None:
    """--heal is a standalone DR action; pairing it with another DR
    write mode is refused as a usage error."""
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--heal",
             "--from-dump", str(tmp_path / "x.json"),
             "--org-id", "org-123", "--restore"]
        )
    assert excinfo.value.code == 2


def test_multi_org_remote_backend_rejects_backend_config_file(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single --backend-config-file names ONE state address, so it
    cannot serve several organizations; the placeholder form must be
    used instead."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--org-id", "111222",
             "--org-id", "333444", "--state-backend", "azurerm",
             "--backend-config-file", "azure.tfbackend"]
        )
    assert excinfo.value.code == 2


def test_report_names_reconciliation_drop_categories(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Drop categories are named with counts so a provider regression
    identifies the class it broke, not just a number."""
    from meraki2tf.cli import _report
    from meraki2tf.orchestrator import RunSummary

    summary = RunSummary(
        organization_id="org-123",
        discovered_assets=3,
        imports_written=1,
        imports_skipped_existing=0,
        unsupported_count=2,
        drift_detected=False,
        comparison_skipped=False,
        pending_imports=1,
        reconciliation_dropped=(
            "meraki_network_firmware_upgrades.l_1",
            "meraki_network_firmware_upgrades.l_2",
        ),
        reconciliation_drop_categories={
            "Invalid Attribute Combination": 2,
        },
    )
    with caplog.at_level("INFO", logger="meraki2tf.cli"):
        _report(summary)
    assert "Unexpressible drop categories" in caplog.text
    assert "2 × Invalid Attribute Combination" in caplog.text


def test_restore_confirm_reports_drill_placeholders(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Placeholder secrets written during a sanitized-snapshot drill are
    surfaced per action so the operator knows to re-enter real values if
    the organization is ever kept."""
    from meraki2tf import restorer as restorer_module

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def placeholder_result(
        self: Any, graph: Any, plan: Any
    ) -> restorer_module.RestoreResult:
        return restorer_module.RestoreResult(
            executed=("networks|create|N_1",),
            drill_placeholders=(
                ("wireless-ssids|update|N_1,0", "payload.psk"),
            ),
        )

    monkeypatch.setattr(
        restorer_module.OrgRestorer, "execute", placeholder_result
    )
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    dump = _restore_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-999", "--workdir", str(tmp_path / "ws"),
         "--confirm", "--webhook-url", "https://hooks.example/dr"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Drill placeholder secret(s) written" in console
    assert "payload.psk" in console
    (event,) = delivered
    assert event["event_type"] == "RESTORE_EXECUTED"


def test_heal_fails_cleanly_on_unreadable_snapshot(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    exit_code = main(
        ["--spec", str(spec_file), "--heal",
         "--from-dump", str(tmp_path / "missing.json"),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 1
    assert "Heal could not load the snapshot" in console


def test_heal_live_discovery_fault_exits_1(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A live-API failure mid-discovery must exit cleanly: without the
    live picture there is no way to decide what is missing."""
    from meraki2tf import cli as cli_module

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    class ExplodingLiveProvider(_StubLiveProvider):
        def fetch_network_graph(
            self, organization_id: str | None = None
        ) -> Any:
            raise RuntimeError("api unreachable mid-discovery")

    monkeypatch.setattr(
        cli_module, "LiveApiDataProvider", ExplodingLiveProvider
    )
    dump = _heal_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 1
    assert "Heal could not discover the live organization" in console


def test_heal_preview_reports_unrestorables(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Missing objects the API cannot recreate are named with a reason —
    that list is the operator's manual-recovery runbook."""
    from meraki2tf import cli as cli_module
    from meraki2tf.models import MerakiNetwork, NetworkGraph

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _StubLiveProvider.graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(),
    )
    monkeypatch.setattr(cli_module, "LiveApiDataProvider", _StubLiveProvider)
    dump = tmp_path / "heal-snapshot.json"
    dump.write_text(
        json.dumps(
            {
                "organizationId": "org-123",
                "networks": [
                    {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                     "productTypes": ["wireless"], "timeZone": "UTC"}
                ],
                "devices": [],
                "features": [
                    {
                        "apiPath": (
                            "/networks/{networkId}/wireless/ssids/{number}"
                        ),
                        "pathValues": ["N_1", "0"],
                        "payload": {"number": 0, "name": "Corp"},
                    },
                    {
                        "apiPath": "/networks/{networkId}/clients",
                        "pathValues": ["N_1"],
                        "payload": {"usage": 1},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Cannot heal /networks/{networkId}/clients" in console
    assert "Preview only" in console


def _heal_confirm_setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    """Snapshot + live stub where exactly the SSID is missing live."""
    from meraki2tf import cli as cli_module
    from meraki2tf.models import MerakiNetwork, NetworkGraph

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _StubLiveProvider.graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(),
    )
    monkeypatch.setattr(cli_module, "LiveApiDataProvider", _StubLiveProvider)
    return _heal_dump(tmp_path)


def test_heal_unreadable_journal_exits_2(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A corrupted heal journal refuses the run instead of silently
    re-creating already-recreated objects."""
    dump = _heal_confirm_setup(monkeypatch, tmp_path)
    workdir = tmp_path / "ws"
    workdir.mkdir()
    (workdir / "heal-journal.jsonl").write_text(
        'not-json\n{"kind": "done", "key": "x"}\n', encoding="utf-8"
    )
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(workdir), "--confirm"]
    )
    assert exit_code == 2


def test_heal_journal_mismatch_exits_2(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from meraki2tf import restorer as restorer_module

    dump = _heal_confirm_setup(monkeypatch, tmp_path)

    def mismatch(self: Any, graph: Any, plan: Any) -> Any:
        raise restorer_module.RestoreJournalMismatchError(
            "journal bound to a different organization"
        )

    monkeypatch.setattr(restorer_module.OrgRestorer, "execute", mismatch)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--confirm"]
    )
    assert exit_code == 2


def test_heal_execution_fault_alerts_and_exits_1(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exception escaping the heal executor must alert and exit
    cleanly — completed writes stay journaled for a resume."""
    from meraki2tf import restorer as restorer_module

    dump = _heal_confirm_setup(monkeypatch, tmp_path)

    def exploding(self: Any, graph: Any, plan: Any) -> Any:
        raise RuntimeError("api unreachable mid-heal")

    monkeypatch.setattr(restorer_module.OrgRestorer, "execute", exploding)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--confirm", "--webhook-url", "https://hooks.example/dr"]
    )
    assert exit_code == 1
    (event,) = delivered
    assert event["event_type"] == "PROCESSING_FAULT"
    assert "--heal --confirm" in event["details"]["stage"]
    assert "api unreachable mid-heal" in event["details"]["error"]


def test_heal_confirm_executes_and_alerts(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from meraki2tf import restorer as restorer_module

    dump = _heal_confirm_setup(monkeypatch, tmp_path)

    def succeed(self: Any, graph: Any, plan: Any) -> Any:
        return restorer_module.RestoreResult(
            executed=("wireless-ssids|update|N_1,0",),
            skipped=(
                {"target": "devices|claim", "reason": "drill mode"},
            ),
        )

    monkeypatch.setattr(restorer_module.OrgRestorer, "execute", succeed)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--confirm", "--webhook-url", "https://hooks.example/dr"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Heal skipped devices|claim: drill mode" in console
    assert "1 recreated, 0 failed, 1 skipped" in console
    (event,) = delivered
    assert event["event_type"] == "HEAL_EXECUTED"
    assert event["details"]["organization_id"] == "org-123"


def test_heal_confirm_reports_failures_nonzero(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from meraki2tf import restorer as restorer_module

    dump = _heal_confirm_setup(monkeypatch, tmp_path)

    def fail(self: Any, graph: Any, plan: Any) -> Any:
        return restorer_module.RestoreResult(
            failed=(("wireless-ssids|update|N_1,0", "simulated failure"),),
        )

    monkeypatch.setattr(restorer_module.OrgRestorer, "execute", fail)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--confirm", "--webhook-url", "https://hooks.example/dr"]
    )
    console = capsys.readouterr().err
    assert exit_code == 1
    assert (
        "Heal FAILED for wireless-ssids|update|N_1,0: simulated failure"
        in console
    )


# ---------------------------------------------------------------------------
# Selective heal (--heal --only).
# ---------------------------------------------------------------------------


def _heal_dump_two_ssids(tmp_path: Path) -> Path:
    dump = tmp_path / "heal-snapshot.json"
    dump.write_text(
        json.dumps(
            {
                "organizationId": "org-123",
                "networks": [
                    {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                     "productTypes": ["wireless"], "timeZone": "UTC"}
                ],
                "devices": [],
                "features": [
                    {
                        "apiPath": (
                            "/networks/{networkId}/wireless/ssids/{number}"
                        ),
                        "pathValues": ["N_1", "0"],
                        "payload": {"number": 0, "name": "Corp"},
                    },
                    {
                        "apiPath": (
                            "/networks/{networkId}/wireless/ssids/{number}"
                        ),
                        "pathValues": ["N_1", "1"],
                        "payload": {"number": 1, "name": "Guest"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    return dump


def test_only_with_dr_actions_is_a_usage_error(spec_file: Path) -> None:
    """--only silently doing nothing on a DR action would let an
    operator believe the write was scoped; it is refused instead."""
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--rebuild",
             "--only", "network:HQ"]
        )
    assert excinfo.value.code == 2


def test_heal_only_preview_filters_and_hints_the_selective_rerun(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The filtered preview reports match/skip accounting, previews only
    the selection, and the re-run hint carries the --only selectors —
    recommending a bare '--heal --confirm' would escalate the write to
    every missing object."""
    _heal_confirm_setup(monkeypatch, tmp_path)
    dump = _heal_dump_two_ssids(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--only", "ssid:Corp"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "--only 'ssid:Corp' matched 1 missing object(s)" in console
    assert "Skipped by --only: 1 recreatable object(s)" in console
    assert "Preview only" in console
    assert "--heal --only 'ssid:Corp' --confirm" in console
    assert "recreate the 1 missing object(s)" in console


def test_heal_only_zero_match_exits_2(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _heal_confirm_setup(monkeypatch, tmp_path)
    dump = _heal_dump_two_ssids(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--only", "ssid:Nope"]
    )
    console = capsys.readouterr().err
    assert exit_code == 2
    assert "matched no missing object" in console


def test_heal_only_confirm_executes_subset_and_alert_names_filters(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from meraki2tf import restorer as restorer_module

    _heal_confirm_setup(monkeypatch, tmp_path)
    dump = _heal_dump_two_ssids(tmp_path)
    dispatched_plans: list[Any] = []

    def succeed(self: Any, graph: Any, plan: Any) -> Any:
        dispatched_plans.append(plan)
        return restorer_module.RestoreResult(
            executed=("wireless-ssids|update|N_1,0",),
        )

    monkeypatch.setattr(restorer_module.OrgRestorer, "execute", succeed)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--only", "ssid:Corp", "--confirm",
         "--webhook-url", "https://hooks.example/dr"]
    )
    assert exit_code == 0
    (plan,) = dispatched_plans
    # Only the selected SSID reaches the executor.
    assert [a.path_values for a in plan.actions] == [("N_1", "0")]
    (event,) = delivered
    assert event["event_type"] == "HEAL_EXECUTED"
    assert event["details"]["only_filters"] == ["ssid:Corp"]
    assert "Selective heal" in event["summary"]


def test_heal_only_matching_solely_unrestorable_heals_nothing(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A selection covering only API-unrestorable objects is a clean
    no-op with the verdict on the console, not a typo error."""
    _heal_confirm_setup(monkeypatch, tmp_path)
    dump = tmp_path / "heal-snapshot.json"
    dump.write_text(
        json.dumps(
            {
                "organizationId": "org-123",
                "networks": [
                    {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                     "productTypes": ["wireless"], "timeZone": "UTC"}
                ],
                "devices": [],
                "features": [
                    {
                        "apiPath": (
                            "/networks/{networkId}/wireless/ssids/{number}"
                        ),
                        "pathValues": ["N_1", "0"],
                        "payload": {"number": 0, "name": "Corp"},
                    },
                    {
                        "apiPath": "/networks/{networkId}/clients",
                        "pathValues": ["N_1"],
                        "payload": {"usage": 1},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--only", "client:*"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Nothing to heal within the --only selection" in console
    assert "Cannot heal /networks/{networkId}/clients" in console


def test_heal_only_preview_reports_auto_included_dependencies(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Selecting an SSID inside a deleted network shows the network's
    create being pulled in — the operator sees exactly what a partial
    heal will really write before confirming."""
    _heal_confirm_setup(monkeypatch, tmp_path)
    dump = tmp_path / "heal-snapshot.json"
    dump.write_text(
        json.dumps(
            {
                "organizationId": "org-123",
                "networks": [
                    {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                     "productTypes": ["wireless"], "timeZone": "UTC"},
                    {"id": "N_2", "organizationId": "org-123",
                     "name": "Annex", "productTypes": ["wireless"],
                     "timeZone": "UTC"},
                ],
                "devices": [],
                "features": [
                    {
                        "apiPath": (
                            "/networks/{networkId}/wireless/ssids/{number}"
                        ),
                        "pathValues": ["N_2", "0"],
                        "payload": {"number": 0, "name": "Corp"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws"),
         "--only", "ssid:Corp"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "Auto-included 1 missing object(s)" in console
    assert "recreate the 2 missing object(s)" in console


# ---------------------------------------------------------------------------
# Selective backup (--dump-to --only) and partial-snapshot consumers.


def _partial_dump(tmp_path: Path, name: str = "partial.json") -> Path:
    """A canonical partial snapshot: one scoped network + its SSID."""
    dump = tmp_path / name
    dump.write_text(
        json.dumps(
            {
                "organizationId": "org-123",
                "scope": {
                    "networks": ["N_1"],
                    "selectors": ["network:HQ"],
                },
                "networks": [
                    {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                     "productTypes": ["wireless"], "timeZone": "UTC"}
                ],
                "devices": [],
                "features": [
                    {
                        "apiPath": (
                            "/networks/{networkId}/wireless/ssids/{number}"
                        ),
                        "pathValues": ["N_1", "0"],
                        "payload": {"number": 0, "name": "Corp"},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return dump


def test_scoped_pipeline_only_accepts_network_selectors(
    spec_file: Path,
) -> None:
    """A scoped pipeline run takes network:PATTERN selectors only — an
    ssid:/untyped selector must refuse up front, before discovery."""
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--org-id", "org-123",
             "--only", "ssid:Guest*"]
        )
    assert excinfo.value.code == 2


def test_only_export_refuses_drift_baseline(
    spec_file: Path, tmp_path: Path
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--org-id", "org-123",
             "--dump-to", str(tmp_path / "snap.json"),
             "--drift-baseline", str(tmp_path / "base.json"),
             "--only", "network:HQ"]
        )
    assert excinfo.value.code == 2


def test_only_export_refuses_from_dump_reslicing(
    spec_file: Path, dump_file: Path, tmp_path: Path
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--from-dump", str(dump_file),
             "--dump-to", str(tmp_path / "snap.json"),
             "--only", "network:HQ"]
        )
    assert excinfo.value.code == 2


def test_only_export_refuses_non_network_selectors(
    spec_file: Path, tmp_path: Path
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--org-id", "org-123",
             "--dump-to", str(tmp_path / "snap.json"),
             "--only", "ssid:Guest*"]
        )
    assert excinfo.value.code == 2


def test_scoped_export_writes_partial_snapshot_and_stamps_artifacts(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from meraki2tf import cli as cli_module
    from meraki2tf.models import MerakiNetwork, NetworkGraph
    from meraki2tf.scope import LiveNetworkScope

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _StubLiveProvider.graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(),
    )
    monkeypatch.setattr(cli_module, "LiveApiDataProvider", _StubLiveProvider)
    out = tmp_path / "partial.json"
    workdir = tmp_path / "ws"
    exit_code = main(
        ["--spec", str(spec_file), "--org-id", "org-123",
         "--dump-to", str(out), "--workdir", str(workdir),
         "--only", "network:HQ", "--only", "network:N_9*"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    # build_provider handed the selectors to the live provider.
    scope = _StubLiveProvider.last_network_scope
    assert isinstance(scope, LiveNetworkScope)
    assert scope.selectors == ("network:HQ", "network:N_9*")
    # The snapshot records its scope (IDs from the exported graph).
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["scope"] == {
        "networks": ["N_1"],
        "selectors": ["network:HQ", "network:N_9*"],
    }
    assert "PARTIAL export" in console
    # Coverage manifest and runbook are stamped, not plausible-full.
    manifest = json.loads((workdir / "coverage.json").read_text("utf-8"))
    assert manifest["scope"] == {"partial": True, "networks": ["N_1"]}
    assert "PARTIAL RUN" in (workdir / "coverage.txt").read_text("utf-8")
    assert "PARTIAL RUN" in (workdir / "runbook.md").read_text("utf-8")


def test_scoped_export_zero_match_exits_2_without_fault_alert(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from meraki2tf import cli as cli_module
    from meraki2tf.scope import ScopeFilterError

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> Any:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse(200)

    from meraki2tf.alerts import webhook as webhook_module

    monkeypatch.setattr(webhook_module, "_open", fake_urlopen)

    class ZeroMatchProvider(_StubLiveProvider):
        def fetch_network_graph(self, organization_id: str | None = None) -> Any:
            raise ScopeFilterError(
                "--only selector 'network:Nowhere' matched no network"
            )

    monkeypatch.setattr(cli_module, "LiveApiDataProvider", ZeroMatchProvider)
    exit_code = main(
        ["--spec", str(spec_file), "--org-id", "org-123",
         "--dump-to", str(tmp_path / "snap.json"),
         "--webhook-url", "https://hooks.example/dr",
         "--only", "network:Nowhere"]
    )
    assert exit_code == 2
    # Operator input error, not a processing fault: no alert fired.
    assert delivered == []


def test_partial_from_dump_refused_with_sync(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    dump = _partial_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump), "--sync",
         "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 2


def test_input_refusals_precede_terraform_probe(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pure input mistakes refuse even where terraform is absent.

    CI regression: the environment probe used to run before the
    partial-snapshot gating, so a runner without terraform reported a
    terraform fault (exit 1 + alert) instead of the input refusal
    (exit 2, no alert). The probe must lose to every input refusal.
    """
    import meraki2tf.cli as cli_module
    from meraki2tf.terraform_runner import TerraformError

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def broken_probe(_executable: str) -> None:
        raise TerraformError("terraform binary not found (simulated)")

    monkeypatch.setattr(
        cli_module, "ensure_supported_terraform", broken_probe
    )
    dump = _partial_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump), "--sync",
         "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 2


def test_checkpoint_mismatch_precedes_terraform_probe(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A foreign checkpoint refuses (exit 2) before the probe fires."""
    import meraki2tf.cli as cli_module
    from meraki2tf.providers.discovery_checkpoint import DiscoveryCheckpoint
    from meraki2tf.terraform_runner import TerraformError

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def broken_probe(_executable: str) -> None:
        raise TerraformError("terraform binary not found (simulated)")

    monkeypatch.setattr(
        cli_module, "ensure_supported_terraform", broken_probe
    )
    checkpoint = tmp_path / "sweep.ckpt.jsonl"
    DiscoveryCheckpoint(checkpoint, "999999", "other-sha").close()
    exit_code = main(
        ["--spec", str(spec_file), "--org-id", "123456",
         "--workdir", str(tmp_path / "ws"),
         "--discovery-checkpoint", str(checkpoint)]
    )
    assert exit_code == 2


def test_terraform_probe_still_fires_on_clean_inputs(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no input mistakes, a broken terraform is still a fast
    exit-1 preflight fault — before any discovery runs."""
    import meraki2tf.cli as cli_module
    from meraki2tf.terraform_runner import TerraformError

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def broken_probe(_executable: str) -> None:
        raise TerraformError("terraform binary not found (simulated)")

    monkeypatch.setattr(
        cli_module, "ensure_supported_terraform", broken_probe
    )
    exit_code = main(
        ["--spec", str(spec_file), "--org-id", "123456",
         "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 1


def test_partial_from_dump_refused_with_confirm_deletions(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    dump = _partial_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--confirm-deletions", "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 2


def test_partial_from_dump_default_pipeline_warns_and_proceeds(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Generating a one-network kit from a selective backup is a
    legitimate ad-hoc use — warn loudly, never refuse."""
    _no_network(monkeypatch)
    summary = SimpleNamespace(
        organization_id="org-123", discovered_assets=2, imports_written=1,
        imports_skipped_existing=0, unsupported_count=0,
        drift_detected=False, comparison_skipped=True, pending_imports=None,
        resources_added_to_state=(), apply_aborted=False,
        deletions_pending=(), deletions_removed=(),
        regenerated_addresses=(), deferred_addresses=(),
        coverage_percent=100.0, reconciliation_dropped=(),
        reconciliation_drop_categories={}, unmanaged_secret_attributes={},
        normalized_addresses=(), snapshot_drift=None,
    )
    _stub_pipeline_summary(monkeypatch, summary)
    dump = _partial_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "PARTIAL export" in console


def test_restore_refuses_partial_snapshots(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A partial snapshot cannot rebuild an organization — refused for
    preview and confirm alike, before any planning."""
    _no_network(monkeypatch)
    dump = _partial_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--restore", "--from-dump", str(dump),
         "--target-org", "org-fresh-scratch"]
    )
    assert exit_code == 2
    assert "PARTIAL export" in capsys.readouterr().err


def test_replay_gaps_refuses_partial_snapshots(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    dump = _partial_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--replay-gaps",
         "--from-dump", str(dump), "--org-id", "org-123",
         "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 2
    assert "PARTIAL export" in capsys.readouterr().err


def test_heal_scopes_live_discovery_to_partial_snapshots(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Heal from a selective backup narrows its live sweep to the
    snapshot's recorded networks — the speed the workflow exists for —
    and stamps the preview with the partial scope."""
    from meraki2tf import cli as cli_module
    from meraki2tf.models import MerakiNetwork, NetworkGraph
    from meraki2tf.scope import LiveNetworkScope

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    # Live discovery: the scoped network survived but its SSID did not.
    _StubLiveProvider.graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(),
    )
    _StubLiveProvider.last_network_scope = None
    monkeypatch.setattr(cli_module, "LiveApiDataProvider", _StubLiveProvider)
    dump = _partial_dump(tmp_path)
    exit_code = main(
        ["--spec", str(spec_file), "--heal", "--from-dump", str(dump),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    scope = _StubLiveProvider.last_network_scope
    assert isinstance(scope, LiveNetworkScope)
    assert scope.network_ids == frozenset({"N_1"})
    assert "PARTIAL export scoped to 1 network(s)" in console
    assert "partial snapshot: scope covers 1 network(s)" in console


def test_heal_full_snapshots_keep_unscoped_discovery(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from meraki2tf import cli as cli_module
    from meraki2tf.models import MerakiNetwork, NetworkGraph

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _StubLiveProvider.graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(),
    )
    _StubLiveProvider.last_network_scope = "sentinel"
    monkeypatch.setattr(cli_module, "LiveApiDataProvider", _StubLiveProvider)
    exit_code = main(
        ["--spec", str(spec_file), "--heal",
         "--from-dump", str(_heal_dump(tmp_path)),
         "--org-id", "org-123", "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 0
    assert _StubLiveProvider.last_network_scope is None


# ------------------------------------------------- scoped pipeline runs


@pytest.mark.parametrize(
    "extra",
    [
        ["--confirm-deletions"],
        ["--rebaseline"],
        ["--org-id", "234567"],
        ["--drift-baseline", "base.json"],
    ],
)
def test_scoped_pipeline_refuses_unsafe_companions(
    spec_file: Path, extra: list[str]
) -> None:
    """--only on a pipeline run refuses deletion confirmation (a scoped
    run cannot tell deleted from out-of-scope), rebaseline (would
    discard out-of-scope config), multi-org, and drift baselines."""
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--org-id", "123456",
             "--only", "network:HQ", *extra]
        )
    assert excinfo.value.code == 2


def test_scoped_pipeline_refuses_from_dump_reslicing(
    spec_file: Path, dump_file: Path
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--from-dump", str(dump_file),
             "--only", "network:HQ"]
        )
    assert excinfo.value.code == 2


def test_scoped_pipeline_run_scopes_discovery_and_stamps_artifacts(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The single-site onboarding case: a default live run with --only
    scopes discovery, warns PARTIAL, and stamps the artifacts."""
    from meraki2tf import cli as cli_module
    from meraki2tf.models import MerakiNetwork, NetworkGraph
    from meraki2tf.scope import LiveNetworkScope, SnapshotScope

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout="", stderr=""
        ),
    )

    class ScopedStub(_StubLiveProvider):
        mode = "live"

        def fetch_network_graph(
            self, organization_id: str | None = None
        ) -> Any:
            # Mirrors the real provider: a scoped fetch declares its
            # partial scope for the pipeline to stamp.
            self.snapshot_scope = SnapshotScope(
                network_ids=("N_1",), selectors=("network:HQ",)
            )
            return type(self).graph

    ScopedStub.graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"]}
            ),
        ),
        devices=(),
        features=(),
    )
    monkeypatch.setattr(cli_module, "LiveApiDataProvider", ScopedStub)
    workdir = tmp_path / "ws"
    exit_code = main(
        ["--spec", str(spec_file), "--org-id", "123456",
         "--workdir", str(workdir), "--only", "network:HQ"]
    )
    console = capsys.readouterr().err
    assert exit_code == 0
    assert "PARTIAL run" in console
    scope = ScopedStub.last_network_scope
    assert isinstance(scope, LiveNetworkScope)
    assert scope.selectors == ("network:HQ",)
    manifest = json.loads((workdir / "coverage.json").read_text("utf-8"))
    assert manifest["scope"] == {"partial": True, "networks": ["N_1"]}


# ------------------------------------------------ discovery checkpoint


@pytest.mark.parametrize(
    "argv",
    [
        ["--from-dump", "snap.json", "--discovery-checkpoint", "c.jsonl"],
        ["--heal", "--discovery-checkpoint", "c.jsonl"],
        ["--org-id", "123456", "--org-id", "234567",
         "--discovery-checkpoint", "c.jsonl"],
    ],
)
def test_discovery_checkpoint_refused_outside_live_sweeps(
    spec_file: Path, argv: list[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--spec", str(spec_file), *argv])
    assert excinfo.value.code == 2


def test_build_provider_wires_checkpoint_path_and_spec_sha(
    spec_file: Path, spec_parser: OpenApiParser, tmp_path: Path
) -> None:
    from meraki2tf.spec_resolver import spec_fingerprint

    checkpoint = tmp_path / "sweep.ckpt.jsonl"
    provider = build_provider(
        _config(
            ["--spec", str(spec_file), "--org-id", "123456",
             "--discovery-checkpoint", str(checkpoint)]
        ),
        spec_parser,
        spec_file,
    )
    assert isinstance(provider, LiveApiDataProvider)
    assert provider._checkpoint_path == checkpoint
    assert provider._spec_sha256 == spec_fingerprint(spec_file)[1]


@pytest.mark.parametrize("export", [True, False])
def test_mismatched_checkpoint_exits_2_without_fault_alert(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    export: bool,
) -> None:
    """A stale/foreign checkpoint is an operator input error on both
    the export and pipeline paths: exit 2, no PROCESSING_FAULT."""
    from meraki2tf.providers.discovery_checkpoint import DiscoveryCheckpoint

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(request: Any, timeout: float) -> Any:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    from meraki2tf.alerts import webhook as webhook_module

    monkeypatch.setattr(webhook_module, "_open", fake_urlopen)
    checkpoint = tmp_path / "sweep.ckpt.jsonl"
    DiscoveryCheckpoint(checkpoint, "999999", "other-sha").close()
    argv = [
        "--spec", str(spec_file), "--org-id", "123456",
        "--workdir", str(tmp_path / "ws"),
        "--discovery-checkpoint", str(checkpoint),
        "--webhook-url", "https://hooks.example/dr",
    ]
    if export:
        argv += ["--dump-to", str(tmp_path / "snap.json")]
    exit_code = main(argv)
    assert exit_code == 2
    assert delivered == []
    assert checkpoint.exists()  # never destroyed by a refusal


# ------------------------------------------------------ --diff-networks


def _diff_dump(tmp_path: Path) -> Path:
    dump = tmp_path / "diff-snapshot.json"
    document = {
        "organizationId": "org-123",
        "networks": [
            {"id": "N_1", "organizationId": "org-123", "name": "HQ",
             "productTypes": ["appliance"]},
            {"id": "N_2", "organizationId": "org-123", "name": "Branch",
             "productTypes": ["appliance"]},
        ],
        "devices": [],
        "features": [
            {
                "apiPath": "/networks/{networkId}/appliance/trafficShaping",
                "pathValues": ["N_1"],
                "payload": {"globalBandwidthLimits": {"limitUp": 0}},
            },
            {
                "apiPath": "/networks/{networkId}/appliance/trafficShaping",
                "pathValues": ["N_2"],
                "payload": {"globalBandwidthLimits": {"limitUp": 512}},
            },
            {
                "apiPath": "/networks/{networkId}/appliance/vlans/{vlanId}",
                "pathValues": ["N_1", "10"],
                "payload": {"id": 10, "name": "Data"},
            },
        ],
    }
    dump.write_text(json.dumps(document), encoding="utf-8")
    return dump


def test_diff_networks_offline_reports_and_writes_json(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    diff_out = tmp_path / "reports" / "diff.json"
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(_diff_dump(tmp_path)),
         "--diff-networks", "HQ", "Branch", "--diff-out", str(diff_out)]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Cross-network configuration diff: HQ (N_1) vs Branch (N_2)" in out
    assert "globalBandwidthLimits" in out
    assert "only in HQ (N_1)" in out and "(10)" in out
    payload = json.loads(diff_out.read_text(encoding="utf-8"))
    assert payload["modified"][0]["attributes"] == [
        {"name": "globalBandwidthLimits", "orderChanged": False}
    ]
    # Names and locators only — never configuration values.
    assert "512" not in diff_out.read_text(encoding="utf-8")


def test_diff_networks_ambiguous_or_same_pattern_exits_2(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    dump = _diff_dump(tmp_path)
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--diff-networks", "N_*", "Branch"]
    ) == 2
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump),
         "--diff-networks", "HQ", "N_1"]
    ) == 2


def test_diff_networks_unreadable_snapshot_exits_1(
    spec_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_network(monkeypatch)
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(tmp_path / "no.json"),
         "--diff-networks", "HQ", "Branch"]
    ) == 1


@pytest.mark.parametrize(
    "argv",
    [
        # Orphaned --diff-out (house rule: no silently ignored flags).
        ["--org-id", "123456", "--diff-out", "d.json"],
        # Standalone mode: no pipeline/DR companions.
        ["--org-id", "123456", "--diff-networks", "A", "B", "--sync"],
        ["--org-id", "123456", "--diff-networks", "A", "B",
         "--only", "network:HQ"],
        # --expect-org pins a --rebuild/--replay-gaps target; alongside
        # a standalone comparison it did nothing at all, which the
        # no-silent-orphans rule forbids (every sibling helper — and
        # --list-orgs, --check, --estimate — already refuses it).
        ["--org-id", "123456", "--diff-networks", "A", "B",
         "--expect-org", "123456"],
        # One organization at most.
        ["--org-id", "123456", "--org-id", "234567",
         "--diff-networks", "A", "B"],
        # Live mode needs an --org-id.
        ["--diff-networks", "A", "B"],
    ],
)
def test_diff_networks_usage_errors(
    spec_file: Path, argv: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    with pytest.raises(SystemExit) as excinfo:
        main(["--spec", str(spec_file), *argv])
    assert excinfo.value.code == 2


def test_diff_networks_live_requires_api_key(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--spec", str(spec_file), "--org-id", "123456",
             "--diff-networks", "A", "B"]
        )
    assert excinfo.value.code == 2


def test_diff_networks_live_scopes_discovery_to_both_patterns(
    spec_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from meraki2tf import cli as cli_module
    from meraki2tf.providers import StaticJsonDataProvider as _Static
    from meraki2tf.scope import LiveNetworkScope

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    dump = _diff_dump(tmp_path)

    class DiffLiveStub(_StubLiveProvider):
        def fetch_network_graph(
            self, organization_id: str | None = None
        ) -> Any:
            with _Static(dump) as source:
                return source.fetch_network_graph(organization_id)

    monkeypatch.setattr(cli_module, "LiveApiDataProvider", DiffLiveStub)
    exit_code = main(
        ["--spec", str(spec_file), "--org-id", "org-123",
         "--diff-networks", "HQ", "Branch"]
    )
    assert exit_code == 0
    scope = DiffLiveStub.last_network_scope
    assert isinstance(scope, LiveNetworkScope)
    assert scope.selectors == ("HQ", "Branch")
    assert "Cross-network configuration diff" in capsys.readouterr().out


def test_diff_networks_live_zero_match_exits_2(
    spec_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from meraki2tf import cli as cli_module
    from meraki2tf.scope import ScopeFilterError

    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    class ZeroMatch(_StubLiveProvider):
        def fetch_network_graph(
            self, organization_id: str | None = None
        ) -> Any:
            raise ScopeFilterError("selector 'Nowhere' matched no network")

    monkeypatch.setattr(cli_module, "LiveApiDataProvider", ZeroMatch)
    assert main(
        ["--spec", str(spec_file), "--org-id", "123456",
         "--diff-networks", "Nowhere", "AlsoNowhere"]
    ) == 2
