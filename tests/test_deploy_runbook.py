"""Tests for the Azure Automation wrapper (deploy/azure/runbook.py).

The wrapper is not part of the installed package, so it is loaded
straight from its file path. These tests pin the two-invocation job
shape (--dump-to and --sync are mutually exclusive at the meraki2tf
CLI), credential redaction in both argparse spellings, the
failure short-circuit, the failed-run archive prefix, and the
streaming blob upload.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from meraki2tf.cli import build_parser

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNBOOK_PATH = REPO_ROOT / "deploy" / "azure" / "runbook.py"


def _load_runbook() -> ModuleType:
    spec = importlib.util.spec_from_file_location("azure_runbook", RUNBOOK_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["azure_runbook"] = module
    spec.loader.exec_module(module)
    return module


runbook = _load_runbook()


# ----------------------------------------------------------------------
# Command construction: the two-invocation job
# ----------------------------------------------------------------------


def test_export_and_sync_commands_are_disjoint_and_cli_parseable() -> None:
    """--dump-to and --sync must never share an invocation (the CLI
    rejects the combination at argparse, exit 2, before any alert
    dispatcher exists), and each constructed argv must be accepted by
    the real meraki2tf parser."""
    workdir = Path("/var/lib/meraki2tf")
    extra = [
        "--webhook-url", "https://hooks.contoso.example/t0ken",
        "--fail-on-gaps",
        "--drift-baseline", "snapshots/last-week.jsonl.gz",
    ]
    export_args, sync_args = runbook.split_extra_args(extra)
    export_cmd = runbook.build_export_command(
        "meraki2tf", "123456", workdir, export_args
    )
    sync_cmd = runbook.build_sync_command("meraki2tf", workdir, sync_args)

    assert "--dump-to" in export_cmd and "--sync" not in export_cmd
    assert "--sync" in sync_cmd and "--dump-to" not in sync_cmd
    # The sync stage consumes the snapshot the export stage just wrote.
    snapshot = str(workdir / runbook.SNAPSHOT_FILENAME)
    assert export_cmd[export_cmd.index("--dump-to") + 1] == snapshot
    assert sync_cmd[sync_cmd.index("--from-dump") + 1] == snapshot
    # Stage-scoped extra args land on exactly the stage that accepts
    # them; shared args (--webhook-url) land on both.
    assert "--drift-baseline" in export_cmd
    assert "--drift-baseline" not in sync_cmd
    assert "--fail-on-gaps" in sync_cmd
    assert "--fail-on-gaps" not in export_cmd
    assert export_cmd.count("--webhook-url") == 1
    assert sync_cmd.count("--webhook-url") == 1
    # Both argvs (minus the binary) pass the real CLI's argparse layer.
    parser = build_parser()
    parser.parse_args(export_cmd[1:])
    parser.parse_args(sync_cmd[1:])


def test_sync_command_omits_org_id_dump_mode_reads_it_from_snapshot() -> None:
    """Dump mode falls back to the snapshot's recorded organization —
    which is exactly the org the export stage discovered."""
    sync_cmd = runbook.build_sync_command("meraki2tf", Path("/w"), [])
    assert "--org-id" not in sync_cmd


def test_snapshot_filename_selects_the_v2_stream_format() -> None:
    from meraki2tf.snapshot import _V2_SUFFIXES

    assert any(
        runbook.SNAPSHOT_FILENAME.endswith(suffix) for suffix in _V2_SUFFIXES
    )


def test_split_extra_args_routes_equals_spellings_and_flag_values() -> None:
    export_args, sync_args = runbook.split_extra_args(
        [
            "--drift-baseline=old.jsonl.gz",
            "--sanitize",
            "--confirm-deletions",
            "--rebaseline",
            "--spec", "spec3.json",
        ]
    )
    assert export_args == [
        "--drift-baseline=old.jsonl.gz", "--sanitize", "--spec", "spec3.json"
    ]
    assert sync_args == [
        "--confirm-deletions", "--rebaseline", "--spec", "spec3.json"
    ]


def test_run_meraki2tf_runs_both_stages_and_keeps_key_off_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    class Completed:
        returncode = 0

    def fake_run(command: list[str], env: dict[str, str], check: bool) -> Completed:
        calls.append({"command": list(command), "env": dict(env)})
        return Completed()

    monkeypatch.setattr(runbook.subprocess, "run", fake_run)
    exit_code = runbook.run_meraki2tf(
        "meraki2tf", "123456", Path("/w"), "sekrit-key", []
    )
    assert exit_code == 0
    assert len(calls) == 2
    assert "--dump-to" in calls[0]["command"]
    assert "--sync" in calls[1]["command"]
    for call in calls:
        # The key travels via the child env only, never argv.
        assert "sekrit-key" not in " ".join(call["command"])
        assert call["env"][runbook.API_KEY_ENV_VAR] == "sekrit-key"


def test_run_meraki2tf_short_circuits_when_the_export_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed export must return its own exit code without running
    the sync stage — never sync from a stale or half-written snapshot."""
    calls: list[list[str]] = []

    class Completed:
        returncode = 1

    def fake_run(command: list[str], env: dict[str, str], check: bool) -> Completed:
        calls.append(list(command))
        return Completed()

    monkeypatch.setattr(runbook.subprocess, "run", fake_run)
    exit_code = runbook.run_meraki2tf(
        "meraki2tf", "123456", Path("/w"), "k", []
    )
    assert exit_code == 1
    assert len(calls) == 1
    assert "--dump-to" in calls[0]


def test_run_meraki2tf_returns_the_sync_stages_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codes = iter([0, 3])  # export clean, sync exits 3 (--fail-on-gaps)

    def fake_run(command: list[str], env: dict[str, str], check: bool) -> Any:
        class Completed:
            returncode = next(codes)

        return Completed()

    monkeypatch.setattr(runbook.subprocess, "run", fake_run)
    assert runbook.run_meraki2tf("meraki2tf", "1", Path("/w"), "k", []) == 3


# ----------------------------------------------------------------------
# Credential redaction (both argparse spellings)
# ----------------------------------------------------------------------


def test_redact_command_masks_the_two_token_spelling() -> None:
    redacted = runbook._redact_command(
        ["meraki2tf", "--webhook-url", "https://hooks.contoso.example/t0ken"]
    )
    assert redacted == ["meraki2tf", "--webhook-url", "<redacted>"]


def test_redact_command_masks_the_equals_spelling() -> None:
    redacted = runbook._redact_command(
        ["meraki2tf", "--webhook-url=https://hooks.contoso.example/t0ken", "--sync"]
    )
    assert redacted == ["meraki2tf", "--webhook-url=<redacted>", "--sync"]
    assert "t0ken" not in " ".join(redacted)


def test_redact_command_leaves_non_credential_flags_alone() -> None:
    command = ["meraki2tf", "--org-id", "123456", "--workdir=/w"]
    assert runbook._redact_command(command) == command


# ----------------------------------------------------------------------
# Archive-on-failure prefix
# ----------------------------------------------------------------------


def _capture_archive(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    uploaded: list[str] = []
    monkeypatch.setattr(runbook, "acquire_token", lambda resource: "tok")
    monkeypatch.setattr(
        runbook,
        "upload_blob",
        lambda account, container, blob_name, path, token: uploaded.append(
            blob_name
        ),
    )
    return uploaded


def test_archive_artifacts_marks_failed_runs_in_the_prefix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A failed run's workdir holds (partly) the PREVIOUS run's
    artifacts; archiving under a clean prefix would fake a healthy
    weekly cadence."""
    (tmp_path / "coverage.json").write_text("{}")
    uploaded = _capture_archive(monkeypatch)
    failures = runbook.archive_artifacts("st", "c", tmp_path, run_failed=True)
    assert failures == []
    assert uploaded == [
        name for name in uploaded if name.startswith("runs/") and "-failed/" in name
    ]
    assert len(uploaded) == 1


def test_archive_artifacts_uses_a_clean_prefix_for_healthy_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "coverage.json").write_text("{}")
    uploaded = _capture_archive(monkeypatch)
    runbook.archive_artifacts("st", "c", tmp_path, run_failed=False)
    assert len(uploaded) == 1
    assert uploaded[0].startswith("runs/") and "-failed" not in uploaded[0]


def test_main_archives_under_the_failed_prefix_when_the_job_dies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        runbook, "fetch_key_vault_secret", lambda vault, secret: "k"
    )
    monkeypatch.setattr(
        runbook, "run_meraki2tf", lambda *args, **kwargs: 1
    )

    def fake_archive(
        account: str, container: str, workdir: Path, run_failed: bool = False
    ) -> list[str]:
        seen["run_failed"] = run_failed
        return []

    monkeypatch.setattr(runbook, "archive_artifacts", fake_archive)
    exit_code = runbook.main(
        [
            "--vault-name", "kv-contoso",
            "--org-id", "123456",
            "--workdir", str(tmp_path),
            "--storage-account", "stcontoso",
        ]
    )
    assert exit_code == 1
    assert seen["run_failed"] is True


def test_main_treats_fail_on_gaps_exit_3_as_a_completed_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit 3 is the --fail-on-gaps coverage gate on a fully completed
    run: its artifacts are fresh and belong under the clean prefix."""
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        runbook, "fetch_key_vault_secret", lambda vault, secret: "k"
    )
    monkeypatch.setattr(runbook, "run_meraki2tf", lambda *args, **kwargs: 3)

    def fake_archive(
        account: str, container: str, workdir: Path, run_failed: bool = False
    ) -> list[str]:
        seen["run_failed"] = run_failed
        return []

    monkeypatch.setattr(runbook, "archive_artifacts", fake_archive)
    exit_code = runbook.main(
        [
            "--vault-name", "kv-contoso",
            "--org-id", "123456",
            "--workdir", str(tmp_path),
            "--storage-account", "stcontoso",
        ]
    )
    assert exit_code == 3
    assert seen["run_failed"] is False


# ----------------------------------------------------------------------
# Streaming blob upload
# ----------------------------------------------------------------------


def test_upload_blob_streams_the_file_instead_of_buffering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    artifact = tmp_path / "snapshot.jsonl.gz"
    artifact.write_bytes(b"x" * 4096)
    captured: dict[str, Any] = {}

    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *exc: Any) -> None:
            return None

    def fake_urlopen(request: Any, timeout: float) -> FakeResponse:
        captured["data"] = request.data
        captured["length"] = request.get_header("Content-length")
        captured["read_during_request"] = request.data.read(10)
        return FakeResponse()

    monkeypatch.setattr(runbook.urllib.request, "urlopen", fake_urlopen)
    runbook.upload_blob("st", "c", "runs/x/snapshot.jsonl.gz", artifact, "tok")
    # The body is a readable file object (http.client streams those in
    # fixed-size blocks), not a bytes buffer of the whole artifact.
    assert not isinstance(captured["data"], (bytes, bytearray))
    assert captured["read_during_request"] == b"x" * 10
    assert captured["length"] == "4096"


def test_upload_blob_refuses_artifacts_over_the_single_put_guard(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    artifact = tmp_path / "big.bin"
    artifact.write_bytes(b"xx")
    monkeypatch.setattr(runbook, "MAX_SINGLE_PUT_BYTES", 1)
    called = []
    monkeypatch.setattr(
        runbook.urllib.request,
        "urlopen",
        lambda *args, **kwargs: called.append(True),
    )
    with pytest.raises(OSError, match="single-shot Put Blob guard"):
        runbook.upload_blob("st", "c", "runs/x/big.bin", artifact, "tok")
    assert called == []
