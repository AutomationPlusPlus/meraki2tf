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
from meraki2tf.config import RuntimeConfig
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
    terraform_calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        terraform_calls.append(command)
        exit_code = 2 if command[1] == "plan" else 0
        return SimpleNamespace(returncode=exit_code, stdout="~ plan delta", stderr="")

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
    assert [call[1] for call in terraform_calls] == ["init", "plan", "apply"]

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
    assert delivered[0]["details"]["diff"] == "~ plan delta"
    assert delivered[1]["details"]["imports_written"] == 4
    assert delivered[1]["details"]["drift_was_detected"] is True


def test_pipeline_fault_exits_one_and_alerts(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
