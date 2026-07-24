"""CLI wiring for the preflight helpers: --check, --estimate,
--expect-org, pre-discovery validation, and the bare-run hint."""

import json
import sys
import types
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from test_cli import FakeResponse, _no_network, _rebuild_workspace

from meraki2tf import terraform_runner
from meraki2tf.cli import main
from meraki2tf.config import API_KEY_ENV_VAR


def _stub_meraki_module(
    monkeypatch: pytest.MonkeyPatch, organizations: Any
) -> None:
    def dashboard(**kwargs: Any) -> Any:
        return SimpleNamespace(
            organizations=SimpleNamespace(getOrganizations=lambda: organizations)
        )

    stub = types.ModuleType("meraki")
    stub.DashboardAPI = dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)


def _fake_terraform_version(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout="Terraform v1.7.5\n", stderr=""
        ),
    )


def test_check_command_via_main(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_meraki_module(monkeypatch, [{"id": "123456", "name": "Acme"}])
    _fake_terraform_version(monkeypatch)
    exit_code = main(
        ["--check", "--org-id", "123456", "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 0
    assert "Preflight PASS" in capsys.readouterr().out
    # And a failing flag set exits nonzero through the same wiring.
    monkeypatch.delenv(API_KEY_ENV_VAR)
    exit_code = main(
        ["--check", "--org-id", "123456", "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 1
    assert "Preflight FAIL" in capsys.readouterr().out


def test_check_and_estimate_refuse_dr_and_each_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    for argv in (
        ["--check", "--estimate"],
        ["--check", "--rebuild"],
        ["--check", "--confirm"],
        ["--check", "--expect-org", "123456"],
        ["--estimate", "--restore"],
        ["--estimate", "--org-id", "123456", "--sync"],
        ["--list-orgs", "--check"],
        ["--list-orgs", "--estimate"],
    ):
        with pytest.raises(SystemExit) as excinfo:
            main(argv)
        assert excinfo.value.code == 2


def test_estimate_usage_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    with pytest.raises(SystemExit) as excinfo:
        main(["--estimate"])  # live mode needs exactly one --org-id
    assert excinfo.value.code == 2
    monkeypatch.delenv(API_KEY_ENV_VAR)
    with pytest.raises(SystemExit) as excinfo:
        main(["--estimate", "--org-id", "123456"])  # live mode needs a key
    assert excinfo.value.code == 2


def test_estimate_command_via_main_from_dump(
    spec_file: Path,
    dump_file: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    exit_code = main(
        ["--estimate", "--from-dump", str(dump_file), "--spec", str(spec_file)]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "discovery cost estimate" in out
    assert "TOTAL" in out
    assert "req/s" in out


def test_expect_org_requires_rebuild_or_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    with pytest.raises(SystemExit) as excinfo:
        main(["--expect-org", "123456", "--org-id", "123456"])
    assert excinfo.value.code == 2


def test_bare_run_error_points_at_helpers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2
    stderr = capsys.readouterr().err
    assert "--list-orgs" in stderr
    assert "--check" in stderr


def test_pipeline_validates_drift_baseline_before_discovery(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A sanitized baseline fails the run in the validation stage —
    before any provider is even built — and still alerts."""
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"organizationId": "org-123", "sanitized": True}),
        encoding="utf-8",
    )
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(
        request: urllib.request.Request, timeout: float
    ) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)

    def no_discovery(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("discovery must not start on a bad baseline")

    monkeypatch.setattr("meraki2tf.cli.build_provider", no_discovery)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(tmp_path / "ws"),
         "--drift-baseline", str(baseline),
         "--webhook-url", "https://hooks.example/alerts"]
    )
    assert exit_code == 1
    assert "sanitized snapshot" in capsys.readouterr().err
    assert delivered[-1]["event_type"] == "PROCESSING_FAULT"
    assert delivered[-1]["details"]["stage"] == "drift-baseline validation"


def test_pipeline_probes_terraform_before_discovery(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A keyed pipeline run fails on a missing terraform binary before
    discovery starts (the sweep must never be spent first)."""
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")

    def raise_missing(command: tuple[str, ...], **kwargs: Any) -> None:
        raise FileNotFoundError(2, "No such file or directory", "terraform")

    monkeypatch.setattr(terraform_runner.subprocess, "run", raise_missing)

    def no_discovery(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("discovery must not start without terraform")

    monkeypatch.setattr("meraki2tf.cli.build_provider", no_discovery)
    delivered: list[dict[str, Any]] = []

    def fake_urlopen(
        request: urllib.request.Request, timeout: float
    ) -> FakeResponse:
        delivered.append(json.loads(request.data.decode("utf-8")))
        return FakeResponse()

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", fake_urlopen)
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(tmp_path / "ws"),
         "--webhook-url", "https://hooks.example/alerts"]
    )
    assert exit_code == 1
    assert "--terraform-bin" in capsys.readouterr().err
    assert delivered[-1]["details"]["stage"] == "terraform preflight"


def test_pipeline_refuses_old_terraform_early(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _no_network(monkeypatch)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout="Terraform v1.4.6\n", stderr=""
        ),
    )
    exit_code = main(
        ["--spec", str(spec_file), "--from-dump", str(dump_file),
         "--workdir", str(tmp_path / "ws")]
    )
    assert exit_code == 1
    assert "too old" in capsys.readouterr().err


def test_rebuild_prints_resolved_target_org(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    (workdir / "coverage.json").write_text(
        json.dumps({"organization_id": "123456"}), encoding="utf-8"
    )
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout="No changes.", stderr=""
        ),
    )
    assert main(["--rebuild", "--workdir", str(workdir)]) == 0
    stderr = capsys.readouterr().err
    assert "Rebuild target organization: 123456" in stderr
    assert "coverage.json" in stderr


def test_rebuild_prints_unknown_target_loudly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout="No changes.", stderr=""
        ),
    )
    assert main(["--rebuild", "--workdir", str(workdir)]) == 0
    assert "Rebuild target organization: UNKNOWN" in capsys.readouterr().err


def test_rebuild_expect_org_mismatch_refuses_before_planning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    (workdir / "coverage.json").write_text(
        json.dumps({"organization_id": "123456"}), encoding="utf-8"
    )
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)
    exit_code = main(
        ["--rebuild", "--expect-org", "999999", "--workdir", str(workdir)]
    )
    assert exit_code == 2
    assert calls == []  # refused before terraform ever ran
    assert "does not match" in capsys.readouterr().err


def test_rebuild_expect_org_unverifiable_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)
    exit_code = main(
        ["--rebuild", "--expect-org", "123456", "--workdir", str(workdir)]
    )
    assert exit_code == 2
    assert calls == []
    assert "cannot be verified" in capsys.readouterr().err


def test_rebuild_expect_org_match_proceeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    workdir = _rebuild_workspace(tmp_path)
    (workdir / "coverage.json").write_text(
        json.dumps({"organization_id": "123456"}), encoding="utf-8"
    )
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout="No changes.", stderr="")

    monkeypatch.setattr(terraform_runner.subprocess, "run", fake_run)
    exit_code = main(
        ["--rebuild", "--expect-org", "123456", "--workdir", str(workdir)]
    )
    assert exit_code == 0
    assert [call[1] for call in calls] == ["init", "plan"]


def test_replay_gaps_expect_org_mismatch_refuses(
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
         "--workdir", str(tmp_path / "ws"), "--replay-gaps",
         "--expect-org", "999999"]
    )
    assert exit_code == 2
    stderr = capsys.readouterr().err
    assert "Gap replay target organization: org-123" in stderr
    assert "--expect-org 999999 does not match" in stderr


def test_replay_gaps_expect_org_match_proceeds(
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
         "--workdir", str(tmp_path / "ws"), "--replay-gaps",
         "--org-id", "555555", "--expect-org", "555555"]
    )
    assert exit_code == 0
    stderr = capsys.readouterr().err
    assert "Gap replay target organization: 555555 (from --org-id)" in stderr
