"""Exclusive workdir lock guarding a DR kit against concurrent runs."""

import errno
import os
from pathlib import Path

import pytest

from meraki2tf.workdir_lock import (
    LOCK_FILENAME,
    WorkdirLock,
    WorkdirLockError,
    _read_holder,
)


def test_second_run_on_same_workdir_refuses(tmp_path: Path) -> None:
    """A second concurrent run refuses with a message naming the workdir
    and the holding pid — instead of clobbering the kit."""
    first = WorkdirLock(tmp_path)
    first.acquire()
    try:
        with pytest.raises(WorkdirLockError) as exc:
            WorkdirLock(tmp_path).acquire()
        message = str(exc.value)
        assert str(tmp_path) in message
        assert str(os.getpid()) in message
        assert "refusing" in message
    finally:
        first.release()


def test_release_lets_a_later_run_succeed(tmp_path: Path) -> None:
    """The lock is a whole-run guard, not a permanent one: once released a
    sequential rerun on the same workdir acquires cleanly."""
    first = WorkdirLock(tmp_path)
    first.acquire()
    first.release()

    second = WorkdirLock(tmp_path)
    second.acquire()  # must not raise
    second.release()


def test_dead_holder_does_not_block(tmp_path: Path) -> None:
    """flock is released by the kernel when the holding process dies, so a
    crashed run never leaves a stale lock wedging every future run. Death
    is simulated by closing the holder's fd without an explicit release."""
    dead = WorkdirLock(tmp_path)
    dead.acquire()
    assert dead._fd is not None
    os.close(dead._fd)  # process death: fd closed, no LOCK_UN
    dead._fd = None

    live = WorkdirLock(tmp_path)
    live.acquire()  # kernel already released the dead lock
    live.release()


def test_context_manager_records_pid_and_releases(tmp_path: Path) -> None:
    with WorkdirLock(tmp_path):
        recorded = (tmp_path / LOCK_FILENAME).read_text(encoding="utf-8")
        assert recorded.strip() == str(os.getpid())
    # Exiting the block released the lock, so a fresh acquire succeeds.
    with WorkdirLock(tmp_path):
        pass


def test_acquire_creates_missing_workdir(tmp_path: Path) -> None:
    target = tmp_path / "nested" / "workdir"
    lock = WorkdirLock(target)
    lock.acquire()
    try:
        assert target.is_dir()
        assert (target / LOCK_FILENAME).exists()
    finally:
        lock.release()


def test_release_without_acquire_is_a_noop(tmp_path: Path) -> None:
    # Never-acquired and double-release must both be harmless (the
    # orchestrator's finally releases unconditionally).
    lock = WorkdirLock(tmp_path)
    lock.release()
    lock.acquire()
    lock.release()
    lock.release()


def test_stale_pid_is_overwritten_on_reacquire(tmp_path: Path) -> None:
    """A prior holder's pid left in the file is discarded — flock, not the
    recorded value, is what enforces exclusion."""
    (tmp_path / LOCK_FILENAME).write_text("999999\n", encoding="utf-8")
    lock = WorkdirLock(tmp_path)
    lock.acquire()
    try:
        recorded = (tmp_path / LOCK_FILENAME).read_text(encoding="utf-8")
        assert recorded.strip() == str(os.getpid())
    finally:
        lock.release()


def test_unexpected_flock_error_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only real contention (EACCES/EAGAIN) becomes a clean refusal; any
    other OS error surfaces as-is rather than masquerading as a busy
    workdir."""
    def boom(fd: int, operation: int) -> None:
        raise OSError(errno.ENOSYS, "flock unsupported")

    monkeypatch.setattr("meraki2tf.workdir_lock.fcntl.flock", boom)
    with pytest.raises(OSError) as exc:
        WorkdirLock(tmp_path).acquire()
    assert exc.value.errno == errno.ENOSYS
    assert not isinstance(exc.value, WorkdirLockError)


def test_read_holder_on_empty_file_returns_unknown(tmp_path: Path) -> None:
    path = tmp_path / "empty.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        assert _read_holder(fd) == "unknown"
    finally:
        os.close(fd)


def test_read_holder_on_unreadable_fd_returns_unknown(tmp_path: Path) -> None:
    path = tmp_path / "closed.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    os.close(fd)  # a closed fd makes lseek/read raise OSError
    assert _read_holder(fd) == "unknown"
