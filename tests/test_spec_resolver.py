"""Spec resolution: local freshness checks and GitHub fallback rules."""

import json
import logging
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from meraki2tf import spec_resolver
from meraki2tf.spec_resolver import (
    DEFAULT_SPEC_FILENAME,
    SpecResolutionError,
    fetch_latest_spec,
    resolve_spec,
)


def _spec(version: str) -> dict[str, Any]:
    return {"openapi": "3.0.1", "info": {"version": version}, "paths": {}}


def _write_spec(path: Path, version: str) -> None:
    path.write_text(json.dumps(_spec(version)), encoding="utf-8")


def _patch_remote(monkeypatch: pytest.MonkeyPatch, text: str) -> list[str]:
    requested: list[str] = []

    def fake_download(url: str) -> str:
        requested.append(url)
        return text

    monkeypatch.setattr(spec_resolver, "_download", fake_download)
    return requested


def _patch_remote_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(url: str) -> str:
        raise SpecResolutionError(f"Could not download spec from {url}: no route")

    monkeypatch.setattr(spec_resolver, "_download", fail)


def test_up_to_date_local_spec_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    _write_spec(path, "1.56.0")
    original = path.read_text(encoding="utf-8")
    _patch_remote(monkeypatch, json.dumps(_spec("1.56.0")))

    assert resolve_spec(path) == path
    assert path.read_text(encoding="utf-8") == original


def test_outdated_local_spec_is_refreshed_from_github(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    _write_spec(path, "1.40.0")
    remote_text = json.dumps(_spec("1.56.0"))
    _patch_remote(monkeypatch, remote_text)

    assert resolve_spec(path) == path
    assert path.read_text(encoding="utf-8") == remote_text


def test_unreadable_local_spec_is_treated_as_outdated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    path.write_text("{not json", encoding="utf-8")
    remote_text = json.dumps(_spec("1.56.0"))
    _patch_remote(monkeypatch, remote_text)

    resolve_spec(path)
    assert path.read_text(encoding="utf-8") == remote_text


def test_non_utf8_local_spec_is_treated_as_outdated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    path.write_bytes(b"\xff\xfe{}")
    remote_text = json.dumps(_spec("1.56.0"))
    _patch_remote(monkeypatch, remote_text)

    resolve_spec(path)
    assert path.read_text(encoding="utf-8") == remote_text


def test_offline_with_local_spec_falls_back_with_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    path = tmp_path / "spec3.json"
    _write_spec(path, "1.40.0")
    _patch_remote_offline(monkeypatch)

    with caplog.at_level(logging.WARNING, logger="meraki2tf.spec_resolver"):
        assert resolve_spec(path) == path
    assert any("using local" in record.message for record in caplog.records)
    assert json.loads(path.read_text(encoding="utf-8"))["info"]["version"] == "1.40.0"


def test_missing_spec_is_downloaded_from_github(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    remote_text = json.dumps(_spec("1.56.0"))
    requested = _patch_remote(monkeypatch, remote_text)

    assert resolve_spec(path) == path
    assert path.read_text(encoding="utf-8") == remote_text
    assert requested == [spec_resolver.SPEC_REMOTE_URL]


def test_omitted_spec_flag_defaults_to_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    _patch_remote(monkeypatch, json.dumps(_spec("1.56.0")))

    resolved = resolve_spec(None)
    assert resolved == Path(DEFAULT_SPEC_FILENAME)
    assert (tmp_path / DEFAULT_SPEC_FILENAME).exists()


def test_missing_spec_and_offline_is_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_remote_offline(monkeypatch)
    with pytest.raises(SpecResolutionError):
        resolve_spec(tmp_path / "absent.json")


def test_unparseable_remote_document_is_never_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    _patch_remote(monkeypatch, "<html>rate limited</html>")
    with pytest.raises(SpecResolutionError):
        resolve_spec(path)
    assert not path.exists()


def test_non_object_remote_document_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_remote(monkeypatch, json.dumps(["not", "an", "object"]))
    with pytest.raises(SpecResolutionError):
        fetch_latest_spec()


def test_remote_without_version_still_refreshes_local(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    _write_spec(path, "1.40.0")
    remote_text = json.dumps({"openapi": "3.0.1", "paths": {}})
    _patch_remote(monkeypatch, remote_text)

    resolve_spec(path)
    assert path.read_text(encoding="utf-8") == remote_text


def test_download_uses_urllib_and_wraps_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *exc_info: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps(_spec("1.56.0")).encode("utf-8")

    captured = SimpleNamespace(url=None, timeout=None)

    def fake_urlopen(url: str, timeout: float) -> FakeResponse:
        captured.url = url
        captured.timeout = timeout
        return FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    spec = fetch_latest_spec()
    assert spec["info"]["version"] == "1.56.0"
    assert captured.url == spec_resolver.SPEC_REMOTE_URL
    assert captured.timeout == 60.0

    def failing_urlopen(url: str, timeout: float) -> FakeResponse:
        raise OSError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", failing_urlopen)
    with pytest.raises(SpecResolutionError, match="connection refused"):
        fetch_latest_spec()
