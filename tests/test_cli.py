"""CLI entry point: argument surface, assembly, and dump-mode integration."""

import json
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from meraki2tf import terraform_runner
from meraki2tf.cli import build_dispatcher, build_parser, build_provider, main
from meraki2tf.config import RuntimeConfig
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers import LiveApiDataProvider, StaticJsonDataProvider


def _config(argv: list[str]) -> RuntimeConfig:
    return RuntimeConfig.from_args(build_parser().parse_args(argv))


def test_parser_defaults(spec_file: Path) -> None:
    config = _config(["--spec", str(spec_file)])
    assert config.org_id is None
    assert config.dump_path is None
    assert config.workdir == Path("generated")
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


def test_spec_is_required() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


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
    assert 'source = "cisco-open/meraki"' in provider_tf

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


def test_startup_failure_exits_one(tmp_path: Path) -> None:
    exit_code = main(
        [
            "--spec", str(tmp_path / "missing-spec.json"),
            "--from-dump", str(tmp_path / "missing-dump.json"),
        ]
    )
    assert exit_code == 1
