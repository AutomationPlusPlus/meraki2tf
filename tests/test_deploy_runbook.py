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


def _record_runs(
    monkeypatch: pytest.MonkeyPatch, codes: list[int] | None = None
) -> list[list[str]]:
    """Install a subprocess.run stub and return the recorded argv list.

    ``codes`` supplies per-call exit codes (default: 0 for every call).
    """
    calls: list[list[str]] = []
    remaining = list(codes or [])

    def fake_run(command: list[str], env: dict[str, str], check: bool) -> Any:
        calls.append(list(command))

        class Completed:
            returncode = remaining.pop(0) if remaining else 0

        return Completed()

    monkeypatch.setattr(runbook.subprocess, "run", fake_run)
    return calls


def _write_v2_snapshot(path: Path, header: dict[str, Any]) -> None:
    """Write a minimal gzipped v2 snapshot: just the header line."""
    import gzip as _gzip
    import json as _json

    with _gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write(_json.dumps(header) + "\n")


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
    export_args, sync_args = runbook.split_extra_args(extra, with_terraform=True)
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


def test_split_routes_fail_on_gaps_to_the_final_stage() -> None:
    """The coverage gate must govern the job's exit code: on the weekly
    snapshot-only shape it rides the export (which the CLI accepts
    alongside --dump-to); on a --with-terraform run it rides the sync
    stage so an exit-3 export cannot short-circuit the rehearsal."""
    export_args, sync_args = runbook.split_extra_args(["--fail-on-gaps"])
    assert export_args == ["--fail-on-gaps"]
    assert sync_args == []
    # The snapshot-only argv passes the real CLI parser with the gate on.
    export_cmd = runbook.build_export_command(
        "meraki2tf", "123456", Path("/w"), export_args
    )
    build_parser().parse_args(export_cmd[1:])

    export_args, sync_args = runbook.split_extra_args(
        ["--fail-on-gaps"], with_terraform=True
    )
    assert export_args == []
    assert sync_args == ["--fail-on-gaps"]


def test_run_meraki2tf_with_terraform_runs_both_stages_and_keeps_key_off_argv(
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
        "meraki2tf", "123456", Path("/w"), "sekrit-key", [],
        with_terraform=True,
    )
    assert exit_code == 0
    assert len(calls) == 2
    assert "--dump-to" in calls[0]["command"]
    assert "--sync" in calls[1]["command"]
    for call in calls:
        # The key travels via the child env only, never argv.
        assert "sekrit-key" not in " ".join(call["command"])
        assert call["env"][runbook.API_KEY_ENV_VAR] == "sekrit-key"


def test_run_meraki2tf_defaults_to_the_snapshot_only_weekly_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Terraform was demoted from the weekly loop (2026-07-17): the
    default job is one snapshot-export invocation, no --sync stage."""
    calls = _record_runs(monkeypatch)
    exit_code = runbook.run_meraki2tf("meraki2tf", "123456", Path("/w"), "k", [])
    assert exit_code == 0
    assert len(calls) == 1
    assert "--dump-to" in calls[0]
    assert "--sync" not in calls[0]


def test_run_meraki2tf_rotates_the_snapshot_into_the_drift_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Week-over-week drift detection must survive the loss of the
    terraform plan: last run's snapshot becomes this run's
    --drift-baseline automatically."""
    calls = _record_runs(monkeypatch)
    _write_v2_snapshot(
        tmp_path / runbook.SNAPSHOT_FILENAME,
        {"meraki2tfSnapshot": 2, "organizationId": "123456"},
    )

    runbook.run_meraki2tf("meraki2tf", "123456", tmp_path, "k", [])

    previous = tmp_path / runbook.SNAPSHOT_PREVIOUS_FILENAME
    assert previous.exists()
    assert not (tmp_path / runbook.SNAPSHOT_FILENAME).exists()
    command = calls[0]
    assert command[command.index("--drift-baseline") + 1] == str(previous)


def test_run_meraki2tf_keeps_an_operator_supplied_drift_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An operator-supplied baseline means they own the drift chain:
    no second flag is injected AND the workdir snapshot is not rotated
    (their baseline may point at that very file)."""
    calls = _record_runs(monkeypatch)
    (tmp_path / runbook.SNAPSHOT_FILENAME).write_bytes(b"x")

    runbook.run_meraki2tf(
        "meraki2tf", "123456", tmp_path, "k",
        ["--drift-baseline", str(tmp_path / runbook.SNAPSHOT_FILENAME)],
    )
    command = calls[0]
    assert command.count("--drift-baseline") == 1
    # The file the operator's flag points at is still there.
    assert (tmp_path / runbook.SNAPSHOT_FILENAME).read_bytes() == b"x"
    assert not (tmp_path / runbook.SNAPSHOT_PREVIOUS_FILENAME).exists()


def test_run_meraki2tf_first_run_has_no_drift_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _record_runs(monkeypatch)
    runbook.run_meraki2tf("meraki2tf", "123456", tmp_path, "k", [])
    assert "--drift-baseline" not in calls[0]


def test_run_meraki2tf_sanitize_skips_rotation_and_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A sanitized export can never serve as the next run's drift
    baseline (the CLI refuses --sanitize with --drift-baseline, and
    snapshot-diff refuses sanitized baselines), so a --sanitize weekly
    schedule must neither rotate nor inject — otherwise run 2 bricks
    the job permanently."""
    calls = _record_runs(monkeypatch)
    _write_v2_snapshot(
        tmp_path / runbook.SNAPSHOT_FILENAME,
        {"meraki2tfSnapshot": 2, "organizationId": "123456"},
    )
    exit_code = runbook.run_meraki2tf(
        "meraki2tf", "123456", tmp_path, "k", ["--sanitize"]
    )
    assert exit_code == 0
    assert "--drift-baseline" not in calls[0]
    assert "--sanitize" in calls[0]
    # Nothing rotated: the snapshot stays at the canonical path.
    assert (tmp_path / runbook.SNAPSHOT_FILENAME).exists()
    assert not (tmp_path / runbook.SNAPSHOT_PREVIOUS_FILENAME).exists()


def test_run_meraki2tf_skips_a_sanitized_rotated_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A leftover sanitized snapshot (operator ran --sanitize by hand)
    must not be injected — the CLI would refuse it and every weekly
    run would fail until a human deletes the file."""
    calls = _record_runs(monkeypatch)
    _write_v2_snapshot(
        tmp_path / runbook.SNAPSHOT_FILENAME,
        {"meraki2tfSnapshot": 2, "organizationId": "123456", "sanitized": True},
    )
    exit_code = runbook.run_meraki2tf("meraki2tf", "123456", tmp_path, "k", [])
    assert exit_code == 0
    assert "--drift-baseline" not in calls[0]


def test_run_meraki2tf_skips_a_foreign_org_rotated_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Repointing the schedule at another org while reusing the workdir
    must not diff two unrelated organizations into one giant false
    drift alert; the baseline chain restarts with this run's export."""
    calls = _record_runs(monkeypatch)
    _write_v2_snapshot(
        tmp_path / runbook.SNAPSHOT_FILENAME,
        {"meraki2tfSnapshot": 2, "organizationId": "999999"},
    )
    exit_code = runbook.run_meraki2tf("meraki2tf", "123456", tmp_path, "k", [])
    assert exit_code == 0
    assert "--drift-baseline" not in calls[0]


def test_run_meraki2tf_gate_codes_do_not_stop_the_sync_stage(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit 3 (coverage gate) and 5 (notifier outage) are completed
    runs — a --with-terraform job must still run its sync stage, and
    the job returns the highest-priority gate code (3 outranks 5)."""
    calls = _record_runs(monkeypatch, codes=[5, 0])
    exit_code = runbook.run_meraki2tf(
        "meraki2tf", "123456", tmp_path, "k", [], with_terraform=True
    )
    assert exit_code == 5
    assert len(calls) == 2  # the sync stage ran despite export exit 5

    calls = _record_runs(monkeypatch, codes=[5, 3])
    exit_code = runbook.run_meraki2tf(
        "meraki2tf", "123456", tmp_path, "k", [], with_terraform=True
    )
    assert exit_code == 3


def test_run_meraki2tf_restores_the_snapshot_when_the_export_dies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A hard-failed export must not leave the canonical DR snapshot
    path empty: the rotated last-good snapshot is moved back so
    '--restore --from-dump <workdir>/snapshot.jsonl.gz' keeps working
    after the disaster the failed run may be a symptom of."""
    _record_runs(monkeypatch, codes=[1])
    _write_v2_snapshot(
        tmp_path / runbook.SNAPSHOT_FILENAME,
        {"meraki2tfSnapshot": 2, "organizationId": "123456"},
    )
    exit_code = runbook.run_meraki2tf("meraki2tf", "123456", tmp_path, "k", [])
    assert exit_code == 1
    assert (tmp_path / runbook.SNAPSHOT_FILENAME).exists()
    assert not (tmp_path / runbook.SNAPSHOT_PREVIOUS_FILENAME).exists()


def test_run_meraki2tf_refuses_stranded_sync_only_flags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """--confirm-deletions / --rebaseline carry a human decision;
    silently dropping them on a snapshot-only run would report a clean
    run while the confirmed action never happened."""
    calls = _record_runs(monkeypatch)
    for flag in ("--confirm-deletions", "--rebaseline"):
        exit_code = runbook.run_meraki2tf(
            "meraki2tf", "123456", tmp_path, "k", [flag]
        )
        assert exit_code == 2
    assert calls == []


def test_run_meraki2tf_refuses_sanitize_with_terraform(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The sync stage would consume the pseudonymized snapshot and
    build a kit of fake identifiers against the real org."""
    calls = _record_runs(monkeypatch)
    exit_code = runbook.run_meraki2tf(
        "meraki2tf", "123456", tmp_path, "k", ["--sanitize"],
        with_terraform=True,
    )
    assert exit_code == 2
    assert calls == []


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
        "meraki2tf", "123456", Path("/w"), "k", [], with_terraform=True
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
    assert runbook.run_meraki2tf(
        "meraki2tf", "1", Path("/w"), "k", [], with_terraform=True
    ) == 3


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
        account: str, container: str, workdir: Path, run_failed: bool = False,
        filenames: tuple[str, ...] = runbook.ARTIFACT_FILENAMES,
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
        account: str, container: str, workdir: Path, run_failed: bool = False,
        filenames: tuple[str, ...] = runbook.ARTIFACT_FILENAMES,
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


def test_main_archives_only_snapshot_artifacts_without_terraform(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A snapshot-only run must not re-upload the kit files: they are
    the last terraform rehearsal's output, and archiving them under
    this run's prefix would misdate them as fresh."""
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        runbook, "fetch_key_vault_secret", lambda vault, secret: "k"
    )
    monkeypatch.setattr(runbook, "run_meraki2tf", lambda *args, **kwargs: 0)

    def fake_archive(
        account: str, container: str, workdir: Path, run_failed: bool = False,
        filenames: tuple[str, ...] = runbook.ARTIFACT_FILENAMES,
    ) -> list[str]:
        seen["filenames"] = filenames
        return []

    monkeypatch.setattr(runbook, "archive_artifacts", fake_archive)
    base_argv = [
        "--vault-name", "kv-contoso",
        "--org-id", "123456",
        "--workdir", str(tmp_path),
        "--storage-account", "stcontoso",
    ]
    runbook.main(base_argv)
    assert seen["filenames"] == runbook.SNAPSHOT_RUN_ARTIFACTS
    runbook.main([*base_argv, "--with-terraform"])
    assert seen["filenames"] == runbook.ARTIFACT_FILENAMES


def test_main_treats_notifier_outage_exit_5_as_a_completed_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit 5 means the run's work product is intact but alerts reached
    no channel — fresh artifacts belong under the clean prefix."""
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        runbook, "fetch_key_vault_secret", lambda vault, secret: "k"
    )
    monkeypatch.setattr(runbook, "run_meraki2tf", lambda *args, **kwargs: 5)

    def fake_archive(
        account: str, container: str, workdir: Path, run_failed: bool = False,
        filenames: tuple[str, ...] = runbook.ARTIFACT_FILENAMES,
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
    assert exit_code == 5
    assert seen["run_failed"] is False


def test_main_refuses_usage_errors_before_touching_key_vault(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A pure-argv usage error must exit 2 before the managed-identity
    round-trip, the Key Vault fetch, and any artifact (re)upload."""

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("nothing may run on a usage error")

    monkeypatch.setattr(runbook, "fetch_key_vault_secret", forbidden)
    monkeypatch.setattr(runbook, "archive_artifacts", forbidden)
    for extra, with_terraform in (
        (["--confirm-deletions"], False),
        (["--rebaseline"], False),
        (["--sanitize"], True),
    ):
        argv = [
            "--vault-name", "kv-contoso",
            "--org-id", "123456",
            "--workdir", str(tmp_path),
            "--storage-account", "stcontoso",
        ]
        if with_terraform:
            argv.append("--with-terraform")
        with pytest.raises(SystemExit) as excinfo:
            runbook.main([*argv, "--", *extra])
        assert excinfo.value.code == 2


def test_main_refuses_concurrent_runs_on_one_workdir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Weekly and monthly schedules share the workdir; an overlapping
    second run would rotate the snapshot out from under the first."""
    import fcntl

    holder = (tmp_path / ".meraki2tf-wrapper.lock").open("w")
    fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a locked-out run must not fetch the key")

    monkeypatch.setattr(runbook, "fetch_key_vault_secret", forbidden)
    try:
        exit_code = runbook.main(
            [
                "--vault-name", "kv-contoso",
                "--org-id", "123456",
                "--workdir", str(tmp_path),
                "--storage-account", "stcontoso",
            ]
        )
    finally:
        holder.close()
    assert exit_code == 1


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
