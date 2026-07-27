"""Atomic artifact writes: torn documents must be impossible."""

import os
from pathlib import Path

import pytest

from meraki2tf.fileio import _fsync_directory, atomic_write_text


def test_atomic_write_replaces_content(tmp_path: Path) -> None:
    target = tmp_path / "coverage.json"
    target.write_text("old document", encoding="utf-8")
    atomic_write_text(target, "new document")
    assert target.read_text(encoding="utf-8") == "new document"
    assert list(tmp_path.iterdir()) == [target]


def test_failed_replace_cleans_temp_and_preserves_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash mid-replace (here: the rename itself fails) must leave
    the previous intact document in place and no temp litter behind."""
    target = tmp_path / "runbook.md"
    target.write_text("intact runbook", encoding="utf-8")

    def broken_replace(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken_replace)
    with pytest.raises(OSError, match="disk full"):
        atomic_write_text(target, "half-written replacement")
    monkeypatch.undo()
    assert target.read_text(encoding="utf-8") == "intact runbook"
    assert list(tmp_path.iterdir()) == [target]


def test_write_fsyncs_file_and_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The durable path flushes the file before the rename and the
    containing directory after it, so a crash cannot expose a rolled-back
    or zero-length artifact."""
    fsynced: list[object] = []
    real_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        fsynced.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", recording_fsync)
    target = tmp_path / "coverage.json"
    atomic_write_text(target, "durable document")
    # One fsync for the temp file, one for the directory handle.
    assert len(fsynced) == 2
    assert target.read_text(encoding="utf-8") == "durable document"


def test_directory_fsync_is_best_effort(tmp_path: Path) -> None:
    """Platforms/filesystems that cannot open a directory must not raise
    (mirrors the snapshot writer's guarantee)."""
    _fsync_directory(tmp_path / "does-not-exist")  # no raise
    _fsync_directory(tmp_path)  # the happy path is quiet too
