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
    """Replace ``path`` with ``content`` atomically."""
    descriptor, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
