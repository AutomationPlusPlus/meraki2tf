"""Dual-modality provider engine: parity, offline loading, live dispatch."""

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.config import API_KEY_ENV_VAR, MissingApiKeyError
from meraki2tf.models import FeatureConfiguration, NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers import (
    LiveApiDataProvider,
    LiveDispatchError,
    MalformedDumpError,
    StaticJsonDataProvider,
)

NETWORK_PAYLOAD = {
    "id": "N_1",
    "organizationId": "org-123",
    "name": "HQ",
    "productTypes": ["appliance"],
}
DEVICE_PAYLOAD = {
    "serial": "Q2AB-CDEF-GHIJ",
    "networkId": "N_1",
    "model": "MX64",
    "name": "edge",
}


class FakeOrganizations:
    def getOrganizationNetworks(self, org_id: str, total_pages: str) -> list[dict[str, Any]]:
        assert total_pages == "all"
        return [dict(NETWORK_PAYLOAD)]

    def getOrganizationDevices(self, org_id: str, total_pages: str) -> list[dict[str, Any]]:
        assert total_pages == "all"
        return [dict(DEVICE_PAYLOAD)]


class FakeAppliance:
    def getNetworkApplianceVlans(self, networkId: str) -> list[Any]:
        return [{"id": 10, "name": "Data"}, {"unidentifiable": True}, "not-a-dict"]

    def getNetworkApplianceTrafficShaping(self, networkId: str) -> dict[str, Any]:
        return {"globalBandwidthLimits": {"limitUp": 0, "limitDown": 0}}


class FakeNetworksSection:
    def getNetworkSyslogServers(self, networkId: str) -> list[dict[str, Any]]:
        return [{"host": "10.0.0.1"}]


class FakeSensor:
    def getNetworkSensorRelationships(self, networkId: str) -> list[dict[str, Any]]:
        raise RuntimeError("400 Bad Request: sensor not available for this network")


class FakeDashboard:
    def __init__(self) -> None:
        self.organizations = FakeOrganizations()
        self.appliance = FakeAppliance()
        self.networks = FakeNetworksSection()
        self.sensor = FakeSensor()


@pytest.fixture()
def live_provider(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> LiveApiDataProvider:
    constructed: list[dict[str, Any]] = []

    def fake_dashboard_api(**kwargs: Any) -> FakeDashboard:
        constructed.append(kwargs)
        assert kwargs["suppress_logging"] is True
        assert kwargs["print_console"] is False
        return FakeDashboard()

    stub = types.ModuleType("meraki")
    stub.DashboardAPI = fake_dashboard_api  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    return LiveApiDataProvider(parser=spec_parser)


def test_dump_provider_builds_full_graph(dump_file: Path) -> None:
    with StaticJsonDataProvider(dump_file) as provider:
        graph = provider.fetch_network_graph()
    assert graph.organization_id == "org-123"
    assert graph.networks[0].network_id == "N_1"
    assert graph.devices[0].serial == "Q2AB-CDEF-GHIJ"
    assert graph.features[0].path_values == ("N_1", "10")


def test_dump_provider_honors_org_override(dump_file: Path) -> None:
    graph = StaticJsonDataProvider(dump_file).fetch_network_graph("org-999")
    assert graph.organization_id == "org-999"


def test_dump_provider_requires_some_org_id(tmp_path: Path) -> None:
    path = tmp_path / "no-org.json"
    path.write_text(json.dumps({"networks": []}), encoding="utf-8")
    with pytest.raises(MalformedDumpError):
        StaticJsonDataProvider(path).fetch_network_graph()


@pytest.mark.parametrize("content", ["{not json", json.dumps(["not", "an", "object"])])
def test_dump_provider_rejects_malformed_documents(tmp_path: Path, content: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(MalformedDumpError):
        StaticJsonDataProvider(path)


def test_dump_provider_rejects_feature_without_api_path(tmp_path: Path) -> None:
    path = tmp_path / "feature.json"
    path.write_text(
        json.dumps({"organizationId": "org-1", "features": [{"pathValues": ["N_1"]}]}),
        encoding="utf-8",
    )
    with pytest.raises(MalformedDumpError):
        StaticJsonDataProvider(path).fetch_network_graph()


NESTED_DUMP_DOCUMENT = {
    "organizations": [
        {
            "info": {"id": "org-777", "name": "Sanitized Org"},
            "admins": [{"id": "A_1", "name": "ops"}, {"email": "no-id@x"}],
            "uplink_statuses": [{"status": "active"}],
            "networks": [
                {
                    "info": {
                        "id": "N_1",
                        "organizationId": "org-777",
                        "name": "HQ",
                        "productTypes": ["appliance", "wireless"],
                    },
                    "devices": [dict(DEVICE_PAYLOAD)],
                    "clients": [{"id": "k1", "ip": "10.0.0.9"}],
                    "vlans": [{"id": 10, "name": "Data"}],
                    "traffic_shaping": {"globalBandwidthLimits": {"limitUp": 0}},
                    "syslog": {"servers": [{"host": "10.0.0.1"}]},
                    "ssids": [
                        {"number": 0, "authMode": "psk", "splashPage": "None"}
                    ],
                    "frobnicators": {"mystery": True},
                    "empty_section": [],
                    "scalar_section": "not-a-payload",
                },
            ],
        },
    ],
}


@pytest.fixture()
def nested_dump_file(tmp_path: Path) -> Path:
    path = tmp_path / "nested.json"
    path.write_text(json.dumps(NESTED_DUMP_DOCUMENT), encoding="utf-8")
    return path


def test_nested_dump_builds_graph_from_export_layout(
    nested_dump_file: Path, spec_parser: OpenApiParser
) -> None:
    provider = StaticJsonDataProvider(nested_dump_file, parser=spec_parser)
    graph = provider.fetch_network_graph()
    assert graph.organization_id == "org-777"
    assert [n.network_id for n in graph.networks] == ["N_1"]
    assert [d.serial for d in graph.devices] == ["Q2AB-CDEF-GHIJ"]

    by_path = {(f.api_path, f.path_values): f for f in graph.features}
    # List section expanded onto the item path, like live discovery.
    vlan = by_path[("/networks/{networkId}/appliance/vlans/{vlanId}", ("N_1", "10"))]
    assert vlan.payload["name"] == "Data"
    # Singleton dict section recorded at the endpoint's own path.
    assert ("/networks/{networkId}/appliance/trafficShaping", ("N_1",)) in by_path
    # Dict-shaped collection response stays a singleton (syslogServers).
    assert ("/networks/{networkId}/syslogServers", ("N_1",)) in by_path
    # Lexical tie (wireless vs appliance ssids) broken by payload schema.
    assert ("/networks/{networkId}/wireless/ssids/{number}", ("N_1", "0")) in by_path
    # Org-scoped section expanded via its PUT/DELETE-only item endpoint;
    # the element without an ID is skipped.
    admin = by_path[
        ("/organizations/{organizationId}/admins/{adminId}", ("org-777", "A_1"))
    ]
    assert admin.payload["name"] == "ops"
    assert len(graph.features) == 5


def test_nested_dump_skips_unmatched_sections_with_warning(
    nested_dump_file: Path,
    spec_parser: OpenApiParser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = StaticJsonDataProvider(nested_dump_file, parser=spec_parser)
    with caplog.at_level("WARNING"):
        graph = provider.fetch_network_graph()
    matched_paths = {f.api_path for f in graph.features}
    assert not any("clients" in path for path in matched_paths)
    skipped = {
        record.args[0]
        for record in caplog.records
        if "resolves to no spec-derived" in record.message
    }
    assert skipped == {"clients", "uplink_statuses", "frobnicators", "scalar_section"}


def test_nested_dump_org_override_warns_but_processes_snapshot(
    nested_dump_file: Path,
    spec_parser: OpenApiParser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = StaticJsonDataProvider(nested_dump_file, parser=spec_parser)
    with caplog.at_level("WARNING"):
        graph = provider.fetch_network_graph("org-override")
    assert graph.organization_id == "org-override"
    assert graph.networks  # the snapshot's own data is still processed
    assert any("processing the" in r.message for r in caplog.records)


def test_nested_dump_without_parser_yields_no_features(
    nested_dump_file: Path,
) -> None:
    graph = StaticJsonDataProvider(nested_dump_file).fetch_network_graph()
    assert graph.features == ()
    assert graph.networks and graph.devices


def test_nested_dump_rejects_structural_violations(
    tmp_path: Path, spec_parser: OpenApiParser
) -> None:
    cases = [
        {"organizations": ["not-an-object"]},
        {"organizations": [{"info": {"id": "o"}, "networks": ["not-an-object"]}]},
        {"organizations": [{"networks": []}]},  # no info.id, no --org-id
        {"organizations": []},  # nothing recorded, no --org-id
    ]
    for document in cases:
        path = tmp_path / "bad-nested.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(MalformedDumpError):
            StaticJsonDataProvider(path, parser=spec_parser).fetch_network_graph()


def test_live_provider_requires_env_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    with pytest.raises(MissingApiKeyError):
        LiveApiDataProvider().fetch_network_graph("org-123")


def test_live_provider_requires_org_id(live_provider: LiveApiDataProvider) -> None:
    with pytest.raises(ValueError):
        live_provider.fetch_network_graph()


def test_live_provider_builds_graph_with_spec_driven_features(
    live_provider: LiveApiDataProvider,
) -> None:
    graph = live_provider.fetch_network_graph("org-123")
    assert graph.networks[0].name == "HQ"
    assert graph.devices[0].model == "MX64"
    by_path = {(f.api_path, f.path_values): f for f in graph.features}

    # List payload expanded to the item path; unidentifiable element skipped.
    vlan = by_path[("/networks/{networkId}/appliance/vlans/{vlanId}", ("N_1", "10"))]
    assert vlan.payload["name"] == "Data"

    # Singleton config recorded at its own endpoint path.
    shaping = by_path[("/networks/{networkId}/appliance/trafficShaping", ("N_1",))]
    assert "globalBandwidthLimits" in shaping.payload

    # Collection without an item endpoint kept as one record.
    syslog = by_path[("/networks/{networkId}/syslogServers", ("N_1",))]
    assert syslog.payload == {"items": [{"host": "10.0.0.1"}]}

    # The refusing sensor endpoint is skipped, not fatal.
    assert len(graph.features) == 3


def test_live_provider_without_parser_skips_features(
    live_provider: LiveApiDataProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = LiveApiDataProvider(parser=None)
    bare._client = FakeDashboard()
    graph = bare.fetch_network_graph("org-123")
    assert graph.features == ()
    bare.close()
    assert bare._client is None


def test_live_provider_client_is_lazy_and_cached(
    live_provider: LiveApiDataProvider,
) -> None:
    first = live_provider._dashboard()
    assert live_provider._dashboard() is first


def test_live_dispatch_errors_on_unresolvable_operations(
    live_provider: LiveApiDataProvider, spec_parser: OpenApiParser
) -> None:
    vlan_op = next(
        op for op in spec_parser.endpoints()
        if op.operation_id == "getNetworkApplianceVlans"
    )
    dashboard = types.SimpleNamespace()  # no sections at all
    with pytest.raises(LiveDispatchError):
        live_provider._call(dashboard, vlan_op, networkId="N_1")

    untagged = next(iter(spec_parser.endpoints()))
    object.__setattr__(untagged, "tags", ())
    with pytest.raises(LiveDispatchError):
        live_provider._call(FakeDashboard(), untagged, networkId="N_1")


def test_provider_parity_between_live_and_dump(
    live_provider: LiveApiDataProvider, tmp_path: Path
) -> None:
    """Both modalities must emit identical domain object models."""
    live_graph = live_provider.fetch_network_graph("org-123")
    snapshot = {
        "organizationId": "org-123",
        "networks": [dict(NETWORK_PAYLOAD)],
        "devices": [dict(DEVICE_PAYLOAD)],
        "features": [
            {
                "apiPath": f.api_path,
                "pathValues": list(f.path_values),
                "payload": dict(f.payload),
            }
            for f in live_graph.features
        ],
    }
    path = tmp_path / "mirror.json"
    path.write_text(json.dumps(snapshot), encoding="utf-8")
    dump_graph = StaticJsonDataProvider(path).fetch_network_graph()

    assert isinstance(live_graph, NetworkGraph)
    assert isinstance(dump_graph, NetworkGraph)
    assert dump_graph.networks == live_graph.networks
    assert dump_graph.devices == live_graph.devices
    assert all(isinstance(f, FeatureConfiguration) for f in dump_graph.features)
    assert [
        (f.api_path, f.path_values, dict(f.payload)) for f in dump_graph.features
    ] == [
        (f.api_path, f.path_values, dict(f.payload)) for f in live_graph.features
    ]
