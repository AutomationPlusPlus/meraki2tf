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


#: A structurally usable stand-in: resolution cares about versions and
#: freshness, but an EMPTY paths object is a refused document (it maps
#: nothing to Terraform), so the fixture carries one real endpoint.
_MINIMAL_PATHS: dict[str, Any] = {
    "/organizations": {
        "get": {"operationId": "getOrganizations", "tags": ["organizations"]}
    }
}


def _spec(version: str) -> dict[str, Any]:
    return {
        "openapi": "3.0.1",
        "info": {"version": version},
        "paths": dict(_MINIMAL_PATHS),
    }


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


def test_outdated_default_spec_is_refreshed_from_github(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--spec omitted: the tool owns ./spec3.json and refreshes it."""
    monkeypatch.chdir(tmp_path)
    path = tmp_path / DEFAULT_SPEC_FILENAME
    _write_spec(path, "1.40.0")
    remote_text = json.dumps(_spec("1.56.0"))
    _patch_remote(monkeypatch, remote_text)

    assert resolve_spec(None) == Path(DEFAULT_SPEC_FILENAME)
    assert path.read_text(encoding="utf-8") == remote_text


def test_user_supplied_spec_is_never_overwritten(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An explicit --spec file (hand-curated or a deliberate downgrade
    pin) must survive every run: a version difference against the
    latest release only warns and the user's file is used as-is."""
    path = tmp_path / "pinned.json"
    _write_spec(path, "1.40.0")
    original = path.read_text(encoding="utf-8")
    _patch_remote(monkeypatch, json.dumps(_spec("1.56.0")))

    with caplog.at_level(logging.WARNING, logger="meraki2tf.spec_resolver"):
        assert resolve_spec(path) == path
    assert path.read_text(encoding="utf-8") == original
    assert any(
        "user-supplied" in record.message for record in caplog.records
    )


def test_user_supplied_downgrade_pin_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A user spec *newer* than the published release (a downgrade of
    the remote, e.g. a pre-release) is also kept untouched."""
    path = tmp_path / "pinned.json"
    _write_spec(path, "2.0.0")
    original = path.read_text(encoding="utf-8")
    _patch_remote(monkeypatch, json.dumps(_spec("1.56.0")))

    assert resolve_spec(path) == path
    assert path.read_text(encoding="utf-8") == original


def test_unreadable_default_spec_is_treated_as_outdated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / DEFAULT_SPEC_FILENAME
    path.write_text("{not json", encoding="utf-8")
    remote_text = json.dumps(_spec("1.56.0"))
    _patch_remote(monkeypatch, remote_text)

    resolve_spec(None)
    assert path.read_text(encoding="utf-8") == remote_text


def test_non_utf8_default_spec_is_treated_as_outdated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / DEFAULT_SPEC_FILENAME
    path.write_bytes(b"\xff\xfe{}")
    remote_text = json.dumps(_spec("1.56.0"))
    _patch_remote(monkeypatch, remote_text)

    resolve_spec(None)
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


def test_structurally_empty_remote_never_clobbers_a_good_local_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any JSON object (an error body, wrong file) parses fine; writing
    it over the working local spec would kill this run at ingestion and
    leave every scheduled rerun re-downloading the same broken document
    with no good copy left."""
    monkeypatch.chdir(tmp_path)
    path = tmp_path / DEFAULT_SPEC_FILENAME
    _write_spec(path, "1.40.0")
    original = path.read_text(encoding="utf-8")
    _patch_remote(monkeypatch, json.dumps({"message": "rate limited"}))

    assert resolve_spec(None) == Path(DEFAULT_SPEC_FILENAME)
    assert path.read_text(encoding="utf-8") == original


def test_empty_paths_remote_never_clobbers_a_good_local_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty 'paths' object is as unusable as a missing one.

    A truncated download can parse cleanly and still describe zero
    endpoints. Writing that over the working spec would leave the next
    run mapping nothing to Terraform — an empty DR kit — with no good
    copy left on disk.
    """
    monkeypatch.chdir(tmp_path)
    path = tmp_path / DEFAULT_SPEC_FILENAME
    _write_spec(path, "1.40.0")
    original = path.read_text(encoding="utf-8")
    _patch_remote(
        monkeypatch,
        json.dumps({"openapi": "3.0.1", "info": {"version": "9.9.9"}, "paths": {}}),
    )

    assert resolve_spec(None) == Path(DEFAULT_SPEC_FILENAME)
    assert path.read_text(encoding="utf-8") == original


def test_empty_paths_remote_is_never_written_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    _patch_remote(
        monkeypatch, json.dumps({"openapi": "3.0.1", "paths": {}})
    )
    with pytest.raises(SpecResolutionError, match="paths"):
        resolve_spec(path)
    assert not path.exists()


def test_structurally_empty_remote_is_never_written_fresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "spec3.json"
    _patch_remote(monkeypatch, json.dumps({"message": "rate limited"}))
    with pytest.raises(SpecResolutionError, match="paths"):
        resolve_spec(path)
    assert not path.exists()


def test_remote_without_version_still_refreshes_default_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / DEFAULT_SPEC_FILENAME
    _write_spec(path, "1.40.0")
    remote_text = json.dumps({"openapi": "3.0.1", "paths": dict(_MINIMAL_PATHS)})
    _patch_remote(monkeypatch, remote_text)

    resolve_spec(None)
    assert path.read_text(encoding="utf-8") == remote_text


def test_download_uses_urllib_and_wraps_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeResponse:
        def __enter__(self) -> "FakeResponse":
            return self

        def __exit__(self, *exc_info: object) -> None:
            return None

        def __init__(self) -> None:
            self._sent = False

        def read(self, amount: int | None = None) -> bytes:
            # File-object contract: the body once, then EOF (b"").
            if self._sent:
                return b""
            self._sent = True
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


def test_download_refuses_an_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A poisoned or wrong endpoint returning an unbounded body must not
    OOM the unattended DR job — the read is capped and over-limit
    responses are refused."""
    over = spec_resolver._MAX_SPEC_BYTES + 1

    class HugeResponse:
        def __enter__(self) -> "HugeResponse":
            return self

        def __exit__(self, *exc_info: object) -> None:
            return None

        def read(self, amount: int | None = None) -> bytes:
            # Honor the caller's cap so the test stays cheap, but return
            # the full requested amount so the over-limit check trips.
            return b"x" * (amount if amount is not None else over)

    monkeypatch.setattr(
        urllib.request, "urlopen", lambda url, timeout: HugeResponse()
    )
    with pytest.raises(SpecResolutionError, match="ceiling"):
        fetch_latest_spec()


class _GarbledResponse:
    """A body that is not valid UTF-8 (a truncated CDN error, say)."""

    def __init__(self) -> None:
        self._sent = False

    def __enter__(self) -> "_GarbledResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def read(self, amount: int | None = None) -> bytes:
        # File-object contract: the body once, then EOF (b"").
        if self._sent:
            return b""
        self._sent = True
        return b"\xff\xfe{}"


def test_download_translates_undecodable_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A garbled remote body must raise SpecResolutionError, not a raw
    UnicodeDecodeError — callers rely on that type for fallbacks."""
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda url, timeout: _GarbledResponse()
    )
    with pytest.raises(SpecResolutionError, match="UTF-8"):
        fetch_latest_spec()


def test_garbled_remote_body_falls_back_to_the_local_spec(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """End-to-end: undecodable download → the designed use-local-copy
    fallback instead of crashing the run."""
    path = tmp_path / "spec3.json"
    _write_spec(path, "1.40.0")
    original = path.read_text(encoding="utf-8")
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda url, timeout: _GarbledResponse()
    )

    with caplog.at_level(logging.WARNING, logger="meraki2tf.spec_resolver"):
        assert resolve_spec(path) == path
    assert path.read_text(encoding="utf-8") == original
    assert any("using local" in record.message for record in caplog.records)


# --------------------------------------- DR (no-refresh) mode & fingerprint


def test_no_refresh_uses_the_local_spec_without_any_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """DR write actions run on exactly the spec on disk: no fetch, no
    clobber, and the version + sha256 they used is on record."""
    import hashlib

    path = tmp_path / "spec3.json"
    _write_spec(path, "1.44.0")
    original = path.read_text(encoding="utf-8")

    def never(url: str) -> str:
        raise AssertionError("a DR run must never fetch the spec")

    monkeypatch.setattr(spec_resolver, "_download", never)
    with caplog.at_level(logging.INFO, logger="meraki2tf.spec_resolver"):
        assert resolve_spec(path, refresh=False) == path
    assert path.read_text(encoding="utf-8") == original
    digest = hashlib.sha256(original.encode("utf-8")).hexdigest()
    record = next(
        r.getMessage()
        for r in caplog.records
        if "never auto-refresh" in r.getMessage()
    )
    assert "1.44.0" in record and digest in record
    assert "user-supplied" in record


def test_no_refresh_with_the_tool_owned_default_names_it_local(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_spec(tmp_path / DEFAULT_SPEC_FILENAME, "1.44.0")
    monkeypatch.setattr(
        spec_resolver, "_download",
        lambda url: (_ for _ in ()).throw(AssertionError("no fetch")),
    )
    with caplog.at_level(logging.INFO, logger="meraki2tf.spec_resolver"):
        resolve_spec(None, refresh=False)
    record = next(
        r.getMessage()
        for r in caplog.records
        if "never auto-refresh" in r.getMessage()
    )
    assert "local spec" in record


def test_no_refresh_with_a_missing_spec_bootstraps_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Nothing local to be deterministic about: the one case a DR run
    still downloads, loudly."""
    path = tmp_path / "spec3.json"
    requested = _patch_remote(monkeypatch, json.dumps(_spec("1.60.0")))
    with caplog.at_level(logging.WARNING, logger="meraki2tf.spec_resolver"):
        assert resolve_spec(path, refresh=False) == path
    assert requested  # downloaded exactly because nothing existed
    assert json.loads(path.read_text(encoding="utf-8"))["info"][
        "version"
    ] == "1.60.0"
    assert any(
        "otherwise never fetch" in r.getMessage() for r in caplog.records
    )


def test_spec_fingerprint_reports_version_and_sha256(tmp_path: Path) -> None:
    import hashlib

    from meraki2tf.spec_resolver import spec_fingerprint

    path = tmp_path / "spec3.json"
    _write_spec(path, "1.52.0")
    version, digest = spec_fingerprint(path)
    assert version == "1.52.0"
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()

    # Unparseable documents still fingerprint (version unknown): the
    # sha256 identifies the bytes either way.
    garbled = tmp_path / "garbled.json"
    garbled.write_bytes(b"\xff\xfenot-json")
    g_version, g_digest = spec_fingerprint(garbled)
    assert g_version is None
    assert g_digest == hashlib.sha256(garbled.read_bytes()).hexdigest()
