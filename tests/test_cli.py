"""CLI entry point: argument surface, assembly, and dump-mode integration."""

import json
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from conftest import PIPELINE_SPEC
from meraki2tf import spec_resolver, terraform_runner
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

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file), "--dump-to", str(out)]
    )

    assert exit_code == 0
    document = json.loads(out.read_text(encoding="utf-8"))
    assert document["organizationId"] == "org-123"
    assert document["networks"][0]["id"] == "N_1"
    assert any(
        feature["apiPath"] == "/networks/{networkId}/appliance/vlans/{vlanId}"
        for feature in document["features"]
    )


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
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
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
    # Read-only pipeline: terraform apply is never part of a run.
    assert [call[1] for call in terraform_calls] == ["init", "plan"]

    imports = (workdir / "imports.tf").read_text(encoding="utf-8")
    assert "to = meraki_networks.n_1\n" in imports
    assert "to = meraki_devices.q2ab_cdef_ghij\n" in imports
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
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
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
                    {"mode": "managed", "type": "meraki_networks", "name": "n_1"},
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
    assert "meraki_networks.n_1" not in imports  # already tracked in state
    assert "to = meraki_devices.q2ab_cdef_ghij\n" in imports
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
        exit_code = 2 if command[1] == "plan" else 0
        return SimpleNamespace(returncode=exit_code, stdout="Plan: 5 to add", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)

    assert main(["--rebuild", "--confirm", "--workdir", str(workdir)]) == 0
    assert [call[1] for call in calls] == ["init", "plan", "apply"]


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

    assert exit_code == 1
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
