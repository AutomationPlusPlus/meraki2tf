"""CLI entry point: argument surface, assembly, and dump-mode integration."""

import json
import logging
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from conftest import PIPELINE_SPEC
from conftest import fixture_schema_document

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
    # Read-only pipeline: terraform apply is never part of a run. The
    # catalog resolution initializes (once per run — later init calls are
    # cached no-ops) and dumps the provider schema before generation; the
    # comparison stage plans and reconciliation classifies the
    # changes-present plan via show.
    assert [call[1] for call in terraform_calls] == [
        "init", "providers", "plan", "show",
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
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

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
        "init", "providers", "plan", "show", "apply",
    ]
    assert terraform_calls[-1][-1] == "meraki2tf-sync.tfplan"
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
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(workdir), "--sync",
         "--webhook-url", "https://hooks.example/alerts"]
    )

    assert exit_code == 0
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

    recorded: dict[str, Any] = {"ssid": [], "networks": 0}

    class Wireless:
        @staticmethod
        def updateNetworkWirelessSsid(**kwargs: Any) -> dict[str, Any]:
            if fail:
                raise RuntimeError("ssid update rejected")
            recorded["ssid"].append(kwargs)
            return kwargs

    def get_networks(org: str, total_pages: str) -> list[dict[str, str]]:
        recorded["networks"] += 1
        return [{"id": "N_1", "name": "HQ"}]

    dashboard = SimpleNamespace(
        wireless=Wireless(),
        organizations=SimpleNamespace(getOrganizationNetworks=get_networks),
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
         "--dump-to", str(out)]
    ) == 0
    assert out.stat().st_mode & 0o777 == 0o600
    assert "UNSANITIZED" in capsys.readouterr().err

    sanitized = tmp_path / "sanitized.json"
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(sanitized), "--sanitize"]
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

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
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
            "--webhook-url", "https://hooks.example/dr",
        ]
    )
    assert exit_code == 0
    assert out.exists()
    (event,) = delivered
    assert event["event_type"] == "DRIFT_DETECTED"
    assert event["details"]["origin"] == "snapshot-diff"
    assert "added" in event["details"]["diff"]


def test_export_with_identical_drift_baseline_is_quiet(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _no_network(monkeypatch)

    def forbidden_urlopen(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("no alert may fire when nothing drifted")

    monkeypatch.setattr(urllib.request, "urlopen", forbidden_urlopen)
    first = tmp_path / "first.json"
    assert main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--dump-to", str(first)]
    ) == 0
    out = tmp_path / "second.jsonl.gz"
    assert main(
        [
            "--spec", str(spec_file), "--from-dump", str(dump_file),
            "--dump-to", str(out),
            "--drift-baseline", str(first),
            "--webhook-url", "https://hooks.example/dr",
        ]
    ) == 0


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

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
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
