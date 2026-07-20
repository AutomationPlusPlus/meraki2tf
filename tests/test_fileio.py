"""Atomic artifact writes: torn documents must be impossible."""

import os
from pathlib import Path

import pytest

from meraki2tf.fileio import atomic_write_text


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
