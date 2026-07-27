"""Atomic text-file writes for run artifacts.

Artifacts like ``coverage.json`` and ``runbook.md`` are the operator's
disaster-recovery deliverables: a crash or full disk mid-rewrite must
never truncate last week's intact copy in place, and two runs sharing a
workdir must never interleave halves of each other's documents. Writes
land in a same-directory temp file and ``os.replace`` it over the
target — readers see either the old document or the new one, never a
torn one.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def atomic_write_text(path: Path, content: str) -> None:
    """Replace ``path`` with ``content`` atomically and durably.

    The content lands in a same-directory temp file that is flushed and
    fsync'd before ``os.replace`` swaps it over the target, then the
    containing directory is fsync'd after the rename. Without those
    fsyncs a crash right after the rename can roll the directory entry
    back to the previous copy — or, on some filesystems, expose a
    zero-length file — silently corrupting a DR artifact. Readers only
    ever see the whole old document or the whole new one, never a torn
    one. The temp file is unlinked if anything raises before the rename.
    """
    descriptor, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def _fsync_directory(directory: Path) -> None:
    """Flush a completed rename to disk, where the platform allows it."""
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - platform/filesystem dependent
        pass
    finally:
        os.close(dir_fd)
