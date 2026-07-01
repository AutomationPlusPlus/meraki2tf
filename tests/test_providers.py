"""Provider interface parity: offline dump loading and live-mode guards."""

import json
from pathlib import Path

import pytest

from meraki2tf.config import API_KEY_ENV_VAR, MissingApiKeyError
from meraki2tf.providers import DumpProvider, LiveProvider, OperationNotInSnapshotError
from meraki2tf.providers.dump import MalformedDumpError


def _write_snapshot(tmp_path: Path, document: object) -> Path:
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_dump_provider_serves_captured_operations(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, {
        "operations": {
            "getOrganizations": [{"id": "123"}],
            "getOrganizationNetworks/123": [{"id": "N_1"}],
        }
    })
    with DumpProvider(snapshot) as provider:
        assert provider.execute("getOrganizations") == [{"id": "123"}]
        networks = provider.execute("getOrganizationNetworks", organizationId="123")
        assert networks == [{"id": "N_1"}]


def test_dump_provider_flags_missing_operation(tmp_path: Path) -> None:
    snapshot = _write_snapshot(tmp_path, {"operations": {}})
    with pytest.raises(OperationNotInSnapshotError):
        DumpProvider(snapshot).execute("getOrganizations")


@pytest.mark.parametrize("document", [[], {"nope": 1}, {"operations": "bad"}])
def test_dump_provider_rejects_malformed_snapshots(
    tmp_path: Path, document: object
) -> None:
    with pytest.raises(MalformedDumpError):
        DumpProvider(_write_snapshot(tmp_path, document))


def test_dump_provider_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(MalformedDumpError):
        DumpProvider(path)


def test_live_provider_requires_env_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    provider = LiveProvider()
    with pytest.raises(MissingApiKeyError):
        provider.execute("getOrganizations")
    provider.close()


def test_live_provider_builds_suppressed_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """The SDK client is built lazily with key logging suppressed."""
    import sys
    import types

    captured: dict[str, object] = {}

    def fake_dashboard_api(**kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    stub = types.ModuleType("meraki")
    stub.DashboardAPI = fake_dashboard_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")

    provider = LiveProvider()
    with pytest.raises(NotImplementedError):
        provider.execute("getOrganizations")
    assert captured["api_key"] == "unit-test-token"
    assert captured["suppress_logging"] is True
    assert captured["print_console"] is False
    assert captured["output_log"] is False
    provider.close()
