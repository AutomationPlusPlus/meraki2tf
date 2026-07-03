"""Owner-only enforcement: 0600 verification and degraded-filesystem warnings."""

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from meraki2tf import fsperms
from meraki2tf.fsperms import restrict_to_owner


def test_restrict_to_owner_enforces_0600(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / "secret.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o644)

    with caplog.at_level(logging.WARNING, logger="meraki2tf.fsperms"):
        assert restrict_to_owner(target) is True

    assert target.stat().st_mode & 0o777 == 0o600
    assert not caplog.records


def test_warns_when_filesystem_ignores_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SMB/Azure Files mounts accept chmod but the mode never sticks."""
    target = tmp_path / "secret.json"
    target.write_text("{}", encoding="utf-8")
    real_stat = fsperms.os.stat

    def fake_stat(path: Any, *args: Any, **kwargs: Any) -> Any:
        if str(path) == str(target):
            return SimpleNamespace(st_mode=0o100644)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(fsperms.os, "stat", fake_stat)

    with caplog.at_level(logging.WARNING, logger="meraki2tf.fsperms"):
        assert restrict_to_owner(target) is False

    assert str(target) in caplog.text
    assert "0644" in caplog.text


def test_warns_unconditionally_on_non_posix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    target = tmp_path / "secret.json"
    target.write_text("{}", encoding="utf-8")
    target.chmod(0o644)
    monkeypatch.setattr(fsperms.os, "name", "nt")

    with caplog.at_level(logging.WARNING, logger="meraki2tf.fsperms"):
        assert restrict_to_owner(target) is False

    assert str(target) in caplog.text
    assert "'nt'" in caplog.text
    # chmod is still attempted before the platform bail-out.
    assert target.stat().st_mode & 0o777 == 0o600
