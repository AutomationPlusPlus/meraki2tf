"""Exclusive advisory lock over a meraki2tf workdir.

Terraform locks only its *state*; the DR kit (``resources.tf``,
``imports.tf``, ``coverage.json``, ``runbook.md`` ...) has no lock of its
own. Two runs sharing one workdir would therefore silently clobber each
other's artifacts, and under scheduling skew (the monthly
``--with-terraform`` rehearsal overrunning into an ad-hoc run) the result is
an internally inconsistent kit whose ``coverage.json`` vouches for resources
absent from ``imports.tf`` — a direct hole in the Cardinal-Rule-2 guarantee
that the operator can answer "what is / isn't covered by Terraform?" with
100% certainty.

This module takes a whole-run exclusive advisory lock on the workdir so a
second concurrent kit-writing run refuses cleanly instead of corrupting the
kit. The lock is an OS advisory lock (:func:`fcntl.flock` with
``LOCK_EX | LOCK_NB``) on ``<workdir>/.meraki2tf.lock``. The kernel releases
it automatically when the holding process dies, so there is no stale-pid
file to reap. The holder pid is written into the file purely for diagnostics
(so the refusal message can name it); it is never used to decide ownership.
"""
from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
from types import TracebackType

LOCK_FILENAME = ".meraki2tf.lock"


class WorkdirLockError(RuntimeError):
    """Raised when another run already holds the workdir lock."""


class WorkdirLock:
    """Context manager holding an exclusive advisory lock on a workdir."""

    def __init__(self, workdir: Path) -> None:
        self._workdir = Path(workdir)
        self._path = self._workdir / LOCK_FILENAME
        self._fd: int | None = None

    def acquire(self) -> "WorkdirLock":
        """Take the lock, or raise :class:`WorkdirLockError` if held.

        On success the workdir exists and the holder pid is recorded in the
        lock file for diagnostics. On contention nothing in the workdir is
        touched beyond the lock file itself, so the holding run keeps sole
        ownership of the kit.
        """
        # The lock lives inside the workdir, so the directory must exist
        # before the kit's first write; mirror prepare_workspace's mode.
        self._workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            holder = _read_holder(fd)
            os.close(fd)
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise WorkdirLockError(
                    f"another meraki2tf run is using this workdir "
                    f"({self._workdir}) (pid {holder}); refusing to avoid "
                    "corrupting the kit."
                ) from exc
            raise
        # Stamp our pid for diagnostics, discarding any pid a prior holder
        # left behind (flock is what enforces exclusion, not this value).
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode())
        os.fsync(fd)
        self._fd = fd
        return self

    def release(self) -> None:
        """Release the lock if held; a no-op otherwise (idempotent)."""
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> "WorkdirLock":
        return self.acquire()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.release()


def _read_holder(fd: int) -> str:
    """Best-effort read of the pid a contending holder recorded."""
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, 64).decode(errors="replace").strip()
    except OSError:
        return "unknown"
    return data or "unknown"
