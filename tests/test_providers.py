"""Dual-modality provider engine: parity, offline loading, live dispatch."""

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.config import API_KEY_ENV_VAR, MissingApiKeyError
from meraki2tf.models import UNREADABLE_MARKER, FeatureConfiguration, NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers import (
    LiveApiDataProvider,
    LiveDispatchError,
    LiveRetryExhaustedError,
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

    def getOrganizationAdmins(self, organizationId: str) -> list[dict[str, Any]]:
        return [{"id": "A_1", "email": "ops@example.com"}]


class FakeAppliance:
    def getNetworkApplianceVlans(self, networkId: str) -> list[Any]:
        return [{"id": 10, "name": "Data"}, {"unidentifiable": True}, "not-a-dict"]

    def getNetworkApplianceTrafficShaping(self, networkId: str) -> dict[str, Any]:
        return {"globalBandwidthLimits": {"limitUp": 0, "limitDown": 0}}

    def getNetworkApplianceSsids(self, networkId: str) -> list[dict[str, Any]]:
        return []


class FakeWireless:
    def getNetworkWirelessSsids(self, networkId: str) -> list[dict[str, Any]]:
        return []

    def getOrganizationWirelessAirMarshalSettingsByNetwork(
        self, organizationId: str
    ) -> dict[str, Any]:
        # The org-scoped aggregation source for the GET-less per-network
        # Air Marshal settings entity: enveloped, one row per network.
        return {
            "items": [{"networkId": "N_1", "defaultPolicy": "blocked"}],
            "meta": {"counts": {"items": {"total": 1}}},
        }

    def getOrganizationWirelessSsidsOpenRoamingByNetwork(
        self, organizationId: str
    ) -> dict[str, Any]:
        # Nested-element aggregation row scoped by a per-product CHILD
        # network id (the live-observed phantom-scope shape): resolved
        # back to the parent network "HQ" via its " - wireless" name.
        return {
            "items": [
                {
                    "networkId": "N_777",
                    "networkName": "HQ - wireless",
                    "ssids": [
                        {
                            "name": "corp-wifi",
                            "number": 0,
                            "enabled": True,
                            "openRoaming": {"enabled": False},
                        },
                    ],
                },
            ],
            "meta": {"counts": {"items": {"total": 1}}},
        }


class FakeNetworksSection:
    def getNetworkSyslogServers(self, networkId: str) -> list[dict[str, Any]]:
        return [{"host": "10.0.0.1"}]


class FakeSensor:
    def getNetworkSensorRelationships(self, networkId: str) -> list[dict[str, Any]]:
        # Mimics meraki.APIError's shape for a product-type refusal:
        # a genuine 400 is "does not apply to this scope", not a gap.
        error = RuntimeError("400 Bad Request: sensor not available for this network")
        error.status = 400  # type: ignore[attr-defined]
        raise error


class FakeSwitch:
    def getDeviceSwitchPorts(self, serial: str) -> list[dict[str, Any]]:
        return [{"portId": "1", "name": "Uplink", "enabled": True}]


class FakeDashboard:
    def __init__(self) -> None:
        self.organizations = FakeOrganizations()
        self.appliance = FakeAppliance()
        self.networks = FakeNetworksSection()
        self.sensor = FakeSensor()
        self.switch = FakeSwitch()
        self.wireless = FakeWireless()


@pytest.fixture()
def live_provider(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> LiveApiDataProvider:
    constructed: list[dict[str, Any]] = []

    def fake_dashboard_api(**kwargs: Any) -> FakeDashboard:
        constructed.append(kwargs)
        assert kwargs["suppress_logging"] is True
        assert kwargs["print_console"] is False
        # The primary client waits out 429s; worker clients turn SDK
        # waiting OFF because the shared AIMD bucket owns all pacing.
        assert kwargs["wait_on_rate_limit"] in (True, False)
        assert kwargs["maximum_retries"] == 10
        # Discovery's shared AdaptiveTokenBucket owns all pacing, so the
        # redundant SDK smart-flow limiter — which re-probes getNetwork
        # for every unresolved (config-template) URL — is turned off.
        assert kwargs["smart_flow_enabled"] is False
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


def test_recorded_organization_ids_canonical(dump_file: Path) -> None:
    provider = StaticJsonDataProvider(dump_file)
    assert provider.recorded_organization_ids == ("org-123",)
    # An --org-id override never rewrites the recorded source org — the
    # restore interlock and the replay org remap both depend on it.
    provider.fetch_network_graph("org-999")
    assert provider.recorded_organization_ids == ("org-123",)


def test_recorded_organization_ids_nested_lists_every_org(tmp_path: Path) -> None:
    path = tmp_path / "multi-org.json"
    path.write_text(
        json.dumps(
            {
                "organizations": [
                    {"info": {"id": "org-123", "name": "One"}, "networks": []},
                    {"info": {"id": "org-456", "name": "Two"}, "networks": []},
                    {"info": {"id": "org-123", "name": "Dup"}, "networks": []},
                    {"networks": []},  # info-less entries carry no org ID
                ]
            }
        ),
        encoding="utf-8",
    )
    provider = StaticJsonDataProvider(path)
    assert provider.recorded_organization_ids == ("org-123", "org-456")


def test_recorded_organization_ids_absent(tmp_path: Path) -> None:
    bare = tmp_path / "bare.json"
    bare.write_text(
        json.dumps({"networks": [], "devices": [], "features": []}),
        encoding="utf-8",
    )
    assert StaticJsonDataProvider(bare).recorded_organization_ids == ()
    weird = tmp_path / "weird.json"
    weird.write_text(json.dumps({"organizations": "not-a-list"}), encoding="utf-8")
    assert StaticJsonDataProvider(weird).recorded_organization_ids == ()


def _canonical_snapshot(tmp_path: Path, features: list[dict[str, Any]]) -> Path:
    path = tmp_path / "canonical.json"
    path.write_text(
        json.dumps(
            {"organizationId": "org-123", "networks": [], "devices": [],
             "features": features}
        ),
        encoding="utf-8",
    )
    return path


def test_dump_provider_heals_stored_envelope_collections(
    tmp_path: Path, spec_parser: OpenApiParser
) -> None:
    """Canonical snapshots written before {items, meta} envelopes were
    understood store a whole collection as one scope-addressed asset;
    replaying features through the shared expansion yields the per-item
    assets live discovery now produces."""
    path = _canonical_snapshot(
        tmp_path,
        [
            {
                "apiPath": "/organizations/{organizationId}/admins",
                "pathValues": ["org-123"],
                "payload": {
                    "items": [{"id": "A_1", "name": "Jordan Sample"}],
                    "meta": {"counts": {"items": {"total": 1}}},
                },
            },
            {
                "apiPath": "/organizations/{organizationId}/admins",
                "pathValues": ["org-123"],
                "payload": {"items": [], "meta": {}},
            },
        ],
    )
    graph = StaticJsonDataProvider(path, parser=spec_parser).fetch_network_graph()
    # The populated envelope became one per-item asset; the empty one vanished.
    assert [(f.api_path, f.path_values) for f in graph.features] == [
        ("/organizations/{organizationId}/admins/{adminId}", ("org-123", "A_1")),
    ]


def test_dump_provider_preserves_unreadable_gap_records(
    tmp_path: Path, spec_parser: OpenApiParser
) -> None:
    """An unreadable-endpoint coverage gap captured live must survive the
    snapshot round trip verbatim — not be expanded like an envelope —
    so offline runs keep reporting the same gap."""
    marker_payload = {UNREADABLE_MARKER: "HTTP 500 from the Meraki API after every retry"}
    path = _canonical_snapshot(
        tmp_path,
        [
            {
                "apiPath": "/organizations/{organizationId}/admins",
                "pathValues": ["org-123"],
                "payload": marker_payload,
            }
        ],
    )
    graph = StaticJsonDataProvider(path, parser=spec_parser).fetch_network_graph()
    assert [(f.api_path, f.path_values, dict(f.payload)) for f in graph.features] == [
        ("/organizations/{organizationId}/admins", ("org-123",), marker_payload),
    ]


def test_dump_provider_keeps_stored_features_verbatim_without_parser(
    tmp_path: Path,
) -> None:
    envelope = {"items": [], "meta": {}}
    path = _canonical_snapshot(
        tmp_path,
        [
            {
                "apiPath": "/organizations/{organizationId}/admins",
                "pathValues": ["org-123"],
                "payload": envelope,
            }
        ],
    )
    graph = StaticJsonDataProvider(path).fetch_network_graph()
    assert len(graph.features) == 1
    assert graph.features[0].payload == envelope


def test_dump_provider_keeps_item_and_singleton_features_intact(
    tmp_path: Path, spec_parser: OpenApiParser
) -> None:
    path = _canonical_snapshot(
        tmp_path,
        [
            {
                "apiPath": "/networks/{networkId}/appliance/vlans/{vlanId}",
                "pathValues": ["N_1", "10"],
                "payload": {"id": 10, "name": "Data"},
            },
            {
                "apiPath": "/networks/{networkId}/appliance/trafficShaping",
                "pathValues": ["N_1"],
                "payload": {"globalBandwidthLimits": {"limitUp": 0}},
            },
        ],
    )
    graph = StaticJsonDataProvider(path, parser=spec_parser).fetch_network_graph()
    assert [(f.api_path, f.path_values) for f in graph.features] == [
        ("/networks/{networkId}/appliance/vlans/{vlanId}", ("N_1", "10")),
        ("/networks/{networkId}/appliance/trafficShaping", ("N_1",)),
    ]


def test_dump_provider_requires_some_org_id(tmp_path: Path) -> None:
    path = tmp_path / "no-org.json"
    path.write_text(json.dumps({"networks": []}), encoding="utf-8")
    with pytest.raises(MalformedDumpError):
        StaticJsonDataProvider(path).fetch_network_graph()


def test_dump_provider_treats_null_org_id_as_missing(tmp_path: Path) -> None:
    """An explicit JSON null must not become the organization ID "None"."""
    path = tmp_path / "null-org.json"
    path.write_text(
        json.dumps({"organizationId": None, "networks": []}), encoding="utf-8"
    )
    with pytest.raises(MalformedDumpError):
        StaticJsonDataProvider(path).fetch_network_graph()


def test_nested_dump_null_info_id_falls_back_to_override(tmp_path: Path) -> None:
    path = tmp_path / "nested-null.json"
    path.write_text(
        json.dumps({"organizations": [{"info": {"id": None}}]}), encoding="utf-8"
    )
    graph = StaticJsonDataProvider(path).fetch_network_graph("org-supplied")
    assert graph.organization_id == "org-supplied"
    with pytest.raises(MalformedDumpError):
        StaticJsonDataProvider(path).fetch_network_graph()


def test_dump_provider_rejects_null_api_path(tmp_path: Path) -> None:
    path = tmp_path / "null-api-path.json"
    path.write_text(
        json.dumps(
            {"organizationId": "org-1",
             "features": [{"apiPath": None, "pathValues": []}]}
        ),
        encoding="utf-8",
    )
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


def test_dump_provider_rejects_string_path_values(tmp_path: Path) -> None:
    """A bare string would explode character-by-character into garbage IDs."""
    path = tmp_path / "feature.json"
    path.write_text(
        json.dumps(
            {
                "organizationId": "org-1",
                "features": [
                    {"apiPath": "/networks/{networkId}", "pathValues": "N_1"}
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(MalformedDumpError, match="pathValues"):
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
                    "devices": [
                        # Structured form: per-device configuration sections.
                        {
                            "info": dict(DEVICE_PAYLOAD),
                            "switch_ports": [
                                {"portId": "1", "name": "Uplink", "enabled": True}
                            ],
                            "device_telemetry": [{"metric": "noise"}],
                        },
                        # Flat form: the raw device payload, as before.
                        {"serial": "Q2ZZ-FLAT-0001", "networkId": "N_1"},
                    ],
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
    # Structured and flat device entries both load.
    assert [d.serial for d in graph.devices] == ["Q2AB-CDEF-GHIJ", "Q2ZZ-FLAT-0001"]

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
    # the element without an ID surfaces at the collection path so the
    # coverage audit reports it instead of dropping it.
    admin = by_path[
        ("/organizations/{organizationId}/admins/{adminId}", ("org-777", "A_1"))
    ]
    assert admin.payload["name"] == "ops"
    no_id_admin = by_path[
        ("/organizations/{organizationId}/admins", ("org-777",))
    ]
    assert no_id_admin.payload == {"email": "no-id@x"}
    # Device-scoped section resolved onto the serial-scoped endpoint.
    port = by_path[
        ("/devices/{serial}/switch/ports/{portId}", ("Q2AB-CDEF-GHIJ", "1"))
    ]
    assert port.payload["name"] == "Uplink"
    assert len(graph.features) == 7


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
    assert skipped == {
        "clients",
        "uplink_statuses",
        "frobnicators",
        "scalar_section",
        "device_telemetry",  # device section with no config endpoint
    }


def test_nested_dump_preserves_empty_whole_collection_sections(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Live/dump parity: an empty section at an endpoint whose PUT
    replaces the whole collection is one real — empty — config object,
    recorded as the same {"items": []} asset the live path produces.
    Empty sections matching nothing are still skipped, quietly."""
    from conftest import _op
    from meraki2tf.providers.discovery import expand_endpoint_payload

    whole_put = _op("updateNetworkVpnSlas", "appliance")
    whole_put["requestBody"] = {
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "properties": {"items": {"type": "array"}},
                }
            }
        }
    }
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "slas", "version": "1"},
        "paths": {
            "/networks/{networkId}/vpn/slas": {
                "get": _op("getNetworkVpnSlas", "appliance"),
                "put": whole_put,
            },
        },
    }
    spec_path = tmp_path / "slas-spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(spec_path)
    dump_path = tmp_path / "empty-slas.json"
    dump_path.write_text(
        json.dumps(
            {
                "organizations": [
                    {
                        "info": {"id": "org-1"},
                        "networks": [
                            {
                                "info": {
                                    "id": "N_1",
                                    "organizationId": "org-1",
                                    "name": "HQ",
                                    "productTypes": ["appliance"],
                                },
                                "slas": [],
                                "empty_unmatched": [],
                                "null_section": None,
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    with caplog.at_level("WARNING"):
        graph = StaticJsonDataProvider(
            dump_path, parser=parser
        ).fetch_network_graph()
    (asset,) = graph.features
    assert asset.api_path == "/networks/{networkId}/vpn/slas"
    assert asset.path_values == ("N_1",)
    assert asset.payload == {"items": []}
    # Byte-identical to what live-path expansion records for the same
    # (empty) collection.
    op = next(
        o for o in parser.endpoints()
        if o.path == asset.api_path and o.method == "get"
    )
    assert expand_endpoint_payload(parser, op, "N_1", []) == [asset]
    # The empty section matching no endpoint carried no data: skipped
    # without joining the loud unmatched-section warning.
    assert not any(
        "resolves to no spec-derived" in r.message for r in caplog.records
    )


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
        {
            "organizations": [
                {
                    "info": {"id": "o"},
                    "networks": [{"info": {"id": "N"}, "devices": ["not-an-object"]}],
                }
            ]
        },
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

    # List payload expanded to the item path; the unidentifiable element
    # surfaces at the collection path for the coverage audit.
    vlan = by_path[("/networks/{networkId}/appliance/vlans/{vlanId}", ("N_1", "10"))]
    assert vlan.payload["name"] == "Data"
    assert ("/networks/{networkId}/appliance/vlans", ("N_1",)) in by_path

    # Singleton config recorded at its own endpoint path.
    shaping = by_path[("/networks/{networkId}/appliance/trafficShaping", ("N_1",))]
    assert "globalBandwidthLimits" in shaping.payload

    # Collection without an item endpoint kept as one record.
    syslog = by_path[("/networks/{networkId}/syslogServers", ("N_1",))]
    assert syslog.payload == {"items": [{"host": "10.0.0.1"}]}

    # Organization-scoped configuration is discovered too (dump parity).
    admin = by_path[
        ("/organizations/{organizationId}/admins/{adminId}", ("org-123", "A_1"))
    ]
    assert admin.payload["email"] == "ops@example.com"

    # Device-scoped configuration is discovered per serial.
    port = by_path[
        ("/devices/{serial}/switch/ports/{portId}", ("Q2AB-CDEF-GHIJ", "1"))
    ]
    assert port.payload["name"] == "Uplink"

    # The GET-less Air Marshal settings entity is discovered through its
    # org-scoped byNetwork aggregation, exploded to the network-scoped
    # canonical path with the scope identifier consumed.
    air_marshal = by_path[
        ("/networks/{networkId}/wireless/airMarshal/settings", ("N_1",))
    ]
    assert air_marshal.payload == {"defaultPolicy": "blocked"}

    # The GET-less nested-element openRoaming entity: its byNetwork row
    # is scoped by a phantom per-product child network id, re-scoped to
    # the parent "HQ" by name, and exploded per SSID at the entity's own
    # two-parameter path with the config sub-object as the payload.
    open_roaming = by_path[
        (
            "/networks/{networkId}/wireless/ssids/{number}/openRoaming",
            ("N_1", "0"),
        )
    ]
    assert open_roaming.payload == {"enabled": False}

    # Folded collection aliases (/organizations/{organizationId}/networks
    # lists first-class network assets) are not re-emitted as features,
    # and the refusing sensor endpoint is skipped, not fatal. The two
    # unidentifiable VLAN elements surface as collection-path assets.
    assert len(graph.features) == 9

    # The genuine 400 sensor refusal was a single scope — visibility
    # diagnostics carry no suspects and nothing was prefiltered (the
    # fixture spec declares no productTypes enum).
    diagnostics = live_provider.discovery_diagnostics
    assert diagnostics is not None
    assert diagnostics.suspect_endpoints == ()
    assert diagnostics.skipped_out_of_scope == 0


def test_live_dispatch_gap_warns_once_and_records_gap_features(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An SDK missing an operation is missing DR coverage — loud, not
    DEBUG, and every affected scope becomes an unreadable-marker gap
    feature instead of silently vanishing from the snapshot."""
    monkeypatch.delattr(FakeOrganizations, "getOrganizationAdmins")
    with caplog.at_level("WARNING", logger="meraki2tf.providers.live"):
        graph = live_provider.fetch_network_graph("org-123")
    admin_warnings = [
        record for record in caplog.records
        if "Upgrade the SDK" in record.message and "admins" in record.message
    ]
    assert len(admin_warnings) == 1  # warned once, not per scope/network
    gaps = [f for f in graph.features if UNREADABLE_MARKER in f.payload]
    assert [
        (gap.api_path, gap.path_values) for gap in gaps
    ] == [("/organizations/{organizationId}/admins", ("org-123",))]
    assert "cannot be dispatched" in gaps[0].payload[UNREADABLE_MARKER]
    # Everything else still discovered, plus the explicit gap record.
    assert len(graph.features) == 9


def test_try_call_gaps_operations_already_known_undispatchable(
    live_provider: LiveApiDataProvider, spec_parser: OpenApiParser
) -> None:
    """A known-undispatchable operation must gap every later scope too —
    returning None here would leave those scopes silently absent."""
    from meraki2tf.providers.live import _EndpointUnreadable

    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )
    undispatchable = {op.operation_id}
    lock, bucket, abort = _try_call_args()
    with pytest.raises(_EndpointUnreadable, match="cannot be dispatched"):
        live_provider._try_call(
            op, {"organizationId": "org-123"}, undispatchable, lock, bucket, abort
        )


@pytest.fixture(autouse=True)
def _instant_pacing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Discovery tests must not sleep on real AIMD pacing; the bucket's
    own behavior is unit-tested in test_ratelimit.py."""
    monkeypatch.setattr(
        "meraki2tf.providers.live.AdaptiveTokenBucket", _NullBucket
    )


class _NullBucket:
    """Pacing stub: tests must not sleep; throttle notifications counted."""

    def __init__(self) -> None:
        self.throttles = 0

    def acquire(self) -> None:
        pass

    def on_success(self) -> None:
        pass

    def on_throttle(self) -> None:
        self.throttles += 1


def _try_call_args() -> tuple[Any, Any, Any]:
    import threading

    return threading.Lock(), _NullBucket(), threading.Event()


class _FakeApiError(Exception):
    """Mimics meraki.exceptions.APIError's ``status`` attribute."""

    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


def test_try_call_aborts_when_throttle_survives_paced_attempts(
    live_provider: LiveApiDataProvider,
    spec_parser: OpenApiParser,
) -> None:
    """A 429 that outlasts the whole paced attempt budget is missing
    data, not an inapplicable feature — swallowing it would ship a
    snapshot that is silently incomplete but looks complete."""
    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )

    class Throttled:
        def getOrganizationAdmins(self, organizationId: str) -> list[dict[str, Any]]:
            raise _FakeApiError(429)

    live_provider._client = types.SimpleNamespace(organizations=Throttled())
    lock, bucket, abort = _try_call_args()
    with pytest.raises(LiveRetryExhaustedError, match="paced attempts"):
        live_provider._try_call(
            op, {"organizationId": "org-123"}, set(), lock, bucket, abort
        )
    from meraki2tf.providers.live import _MAX_THROTTLE_ATTEMPTS

    assert bucket.throttles == _MAX_THROTTLE_ATTEMPTS


def test_try_call_rides_out_throttle_bursts_under_bucket_pacing(
    live_provider: LiveApiDataProvider,
    spec_parser: OpenApiParser,
) -> None:
    """Throttles back the shared bucket off and retry under its pacing;
    the burst passes and the call succeeds."""
    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )
    attempts = {"n": 0}

    class BurstThrottled:
        def getOrganizationAdmins(self, organizationId: str) -> list[dict[str, Any]]:
            attempts["n"] += 1
            if attempts["n"] <= 2:
                raise _FakeApiError(429)
            return [{"id": "A_1"}]

    live_provider._client = types.SimpleNamespace(organizations=BurstThrottled())
    lock, bucket, abort = _try_call_args()
    result = live_provider._try_call(
        op, {"organizationId": "org-123"}, set(), lock, bucket, abort
    )
    assert result == [{"id": "A_1"}]
    assert bucket.throttles == 2


def test_try_call_returns_nothing_once_aborted(
    live_provider: LiveApiDataProvider,
    spec_parser: OpenApiParser,
) -> None:
    """After a fatal failure elsewhere in the pool, workers stand down
    immediately — the run is aborting, partial results are discarded."""
    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )
    calls = {"n": 0}

    class Counting:
        def getOrganizationAdmins(self, organizationId: str) -> list[dict[str, Any]]:
            calls["n"] += 1
            return []

    live_provider._client = types.SimpleNamespace(organizations=Counting())
    lock, bucket, abort = _try_call_args()
    abort.set()
    assert live_provider._try_call(
        op, {"organizationId": "org-123"}, set(), lock, bucket, abort
    ) is None
    assert calls["n"] == 0


def test_null_body_on_success_becomes_coverage_gap(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A 200 whose body is a bare ``null`` yields no object, but it is NOT
    a scope refusal (those arrive as a 400/404). Treating it as one would
    silently drop a discoverable, rebuildable object from the snapshot AND
    the coverage manifest — the exact Cardinal-Rule-2 under-capture a
    transient API glitch or captive-portal proxy could cause. It must ride
    the unreadable-coverage rail, just like a body that never parsed."""

    def _null(self: Any, organizationId: str) -> None:
        return None

    monkeypatch.setattr(FakeOrganizations, "getOrganizationAdmins", _null)
    with caplog.at_level("WARNING", logger="meraki2tf.providers.live"):
        graph = live_provider.fetch_network_graph("org-123")

    gaps = [f for f in graph.features if UNREADABLE_MARKER in f.payload]
    assert len(gaps) == 1
    assert gaps[0].api_path.endswith("/admins")
    assert gaps[0].path_values == ("org-123",)
    assert "null body" in gaps[0].payload[UNREADABLE_MARKER]
    assert any("could not be read" in r.message for r in caplog.records)
    # The rest of discovery survived the anomalous endpoint.
    assert len(graph.features) > 1


@pytest.mark.parametrize("status", [500, 502, 503, 504])
def test_persistent_server_error_becomes_coverage_gap(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    status: int,
) -> None:
    """Meraki returns deterministic 500s for some endpoints on some
    network configurations; that must not abort the run (waiting cannot
    cure it) nor be swallowed (the objects exist). The endpoint becomes
    an unreadable-marker asset so it rides the unsupported-coverage rail."""

    def _explode(self: Any, organizationId: str) -> list[dict[str, Any]]:
        raise _FakeApiError(status)

    monkeypatch.setattr(FakeOrganizations, "getOrganizationAdmins", _explode)
    with caplog.at_level("WARNING", logger="meraki2tf.providers.live"):
        graph = live_provider.fetch_network_graph("org-123")

    gaps = [
        f for f in graph.features if UNREADABLE_MARKER in f.payload
    ]
    assert len(gaps) == 1
    assert gaps[0].api_path.endswith("/admins")
    assert gaps[0].path_values == ("org-123",)
    assert f"HTTP {status}" in gaps[0].payload[UNREADABLE_MARKER]
    assert any("could not be read" in r.message for r in caplog.records)
    # The rest of discovery survived the broken endpoint.
    assert len(graph.features) > 1


@pytest.mark.parametrize("status", [401, 403])
def test_auth_refusals_become_coverage_gaps(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    """A rotated key or scope-limited admin is 'the API refused this
    attempt', never 'this feature does not apply' — swallowing it at
    DEBUG would vanish whole endpoints from the snapshot behind a
    success notification."""

    def _refuse(self: Any, organizationId: str) -> list[dict[str, Any]]:
        raise _FakeApiError(status)

    monkeypatch.setattr(FakeOrganizations, "getOrganizationAdmins", _refuse)
    graph = live_provider.fetch_network_graph("org-123")

    gaps = [f for f in graph.features if UNREADABLE_MARKER in f.payload]
    assert len(gaps) == 1
    assert gaps[0].api_path.endswith("/admins")
    assert f"HTTP {status}" in gaps[0].payload[UNREADABLE_MARKER]


def test_unparseable_200_response_becomes_coverage_gap(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SDK raises an APIError carrying status 200 when a 200 body
    never parses as JSON (truncated body, intercepting proxy). That is
    an API failure, not a scope refusal — swallowing it at DEBUG would
    silently drop the endpoint's objects behind a success notification."""

    def _garble(self: Any, organizationId: str) -> list[dict[str, Any]]:
        raise _FakeApiError(200)

    monkeypatch.setattr(FakeOrganizations, "getOrganizationAdmins", _garble)
    graph = live_provider.fetch_network_graph("org-123")

    gaps = [f for f in graph.features if UNREADABLE_MARKER in f.payload]
    assert len(gaps) == 1
    assert gaps[0].api_path.endswith("/admins")
    assert "HTTP 200" in gaps[0].payload[UNREADABLE_MARKER]


def test_statusless_exception_becomes_coverage_gap(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exception with no HTTP status (a transport failure the SDK
    re-raised, an unexpected SDK-internal error) is never 'this feature
    does not apply' — refusals are data, API failures never are."""

    def _explode(self: Any, organizationId: str) -> list[dict[str, Any]]:
        raise RuntimeError("boom: no status attribute at all")

    monkeypatch.setattr(FakeOrganizations, "getOrganizationAdmins", _explode)
    graph = live_provider.fetch_network_graph("org-123")

    gaps = [f for f in graph.features if UNREADABLE_MARKER in f.payload]
    assert len(gaps) == 1
    assert gaps[0].api_path.endswith("/admins")
    assert "RuntimeError" in gaps[0].payload[UNREADABLE_MARKER]
    # The genuine 400 product-type refusal (sensor) stayed a quiet
    # skip: exactly one gap, and the rest of discovery survived.
    assert len(graph.features) > 1


def test_empty_org_manufactures_no_phantom_nested_gaps(tmp_path: Path) -> None:
    """An organization with zero networks and zero devices has genuinely
    nothing on network-/serial-scoped surfaces — nested surfaces must
    not be recorded as coverage gaps, or --fail-on-gaps would refuse a
    perfectly healthy (empty) drill org."""
    import json as _json

    from conftest import _op

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "empty", "version": "1"},
        "paths": {
            "/networks/{networkId}/wireless/ssids": {
                "get": _op("getNetworkWirelessSsids", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}": {
                "get": _op("getNetworkWirelessSsid", "wireless"),
                "put": _op("updateNetworkWirelessSsid", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}/identityPsks": {
                "get": _op("getNetworkWirelessSsidIdentityPsks", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}/identityPsks"
            "/{identityPskId}": {
                "get": _op("getNetworkWirelessSsidIdentityPsk", "wireless"),
                "put": _op("updateNetworkWirelessSsidIdentityPsk", "wireless"),
            },
        },
    }
    spec_path = tmp_path / "empty-spec.json"
    spec_path.write_text(_json.dumps(spec), encoding="utf-8")

    class EmptyOrganizations:
        def getOrganizationNetworks(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return []

        def getOrganizationDevices(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return []

    provider = LiveApiDataProvider(parser=OpenApiParser(spec_path))
    provider._client = types.SimpleNamespace(organizations=EmptyOrganizations())
    graph = provider.fetch_network_graph("org-123")

    assert graph.networks == () and graph.devices == ()
    assert graph.features == ()  # no phantom UNREADABLE gap records


def test_empty_parent_collection_does_not_cascade_phantom_gaps(
    tmp_path: Path,
) -> None:
    """A swept-but-empty parent collection (a network with zero SSIDs)
    marks its nested surfaces as swept too — deeper levels must not
    degrade into 'parent not discoverable' gap records."""
    import json as _json

    from conftest import _op

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "empty-parent", "version": "1"},
        "paths": {
            "/networks/{networkId}/wireless/ssids": {
                "get": _op("getNetworkWirelessSsids", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}": {
                "get": _op("getNetworkWirelessSsid", "wireless"),
                "put": _op("updateNetworkWirelessSsid", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}/identityPsks": {
                "get": _op("getNetworkWirelessSsidIdentityPsks", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}/identityPsks"
            "/{identityPskId}": {
                "get": _op("getNetworkWirelessSsidIdentityPsk", "wireless"),
                "put": _op("updateNetworkWirelessSsidIdentityPsk", "wireless"),
            },
        },
    }
    spec_path = tmp_path / "empty-parent-spec.json"
    spec_path.write_text(_json.dumps(spec), encoding="utf-8")

    class Organizations:
        def getOrganizationNetworks(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return [dict(NETWORK_PAYLOAD)]

        def getOrganizationDevices(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return []

    class Wireless:
        def getNetworkWirelessSsids(self, networkId: str) -> list[dict[str, Any]]:
            return []

    provider = LiveApiDataProvider(parser=OpenApiParser(spec_path))
    provider._client = types.SimpleNamespace(
        organizations=Organizations(), wireless=Wireless()
    )
    graph = provider.fetch_network_graph("org-123")

    assert [f for f in graph.features if UNREADABLE_MARKER in f.payload] == []


def test_undiscoverable_nested_parents_become_coverage_gaps(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A nested surface whose parent collection can never be discovered
    (read-only telemetry parent, filtered-out collection) must land in
    the coverage manifest — 'no query, no warning, no record' would be
    a silent DR blind spot."""
    import json as _json

    from conftest import _op

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "blind", "version": "1"},
        "paths": {
            # Read-only parent: no write op anywhere at its entity key,
            # so the mutable-entity filter excludes the collection.
            "/networks/{networkId}/clients": {
                "get": _op("getNetworkClients", "networks"),
            },
            "/networks/{networkId}/clients/{clientId}/policy": {
                "get": _op("getNetworkClientPolicy", "networks"),
                "put": _op("updateNetworkClientPolicy", "networks"),
            },
        },
    }
    spec_path = tmp_path / "blind-spec.json"
    spec_path.write_text(_json.dumps(spec), encoding="utf-8")

    provider = LiveApiDataProvider(parser=OpenApiParser(spec_path))
    provider._client = types.SimpleNamespace(organizations=FakeOrganizations())
    graph = provider.fetch_network_graph("org-123")

    (gap,) = [f for f in graph.features if UNREADABLE_MARKER in f.payload]
    assert gap.api_path == "/networks/{networkId}/clients/{clientId}/policy"
    assert gap.path_values == ()
    assert "not discoverable" in gap.payload[UNREADABLE_MARKER]


def test_config_template_contents_are_swept_as_network_scopes(
    tmp_path: Path,
) -> None:
    """Template-held configuration reads through the same
    /networks/{networkId}/... endpoints scoped by the template ID;
    getOrganizationNetworks never lists templates, so without the
    template sweep that configuration would vanish from the snapshot."""
    import json as _json

    from conftest import _op

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "templates", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/configTemplates": {
                "get": _op("getOrganizationConfigTemplates", "organizations"),
                "post": _op("createOrganizationConfigTemplate", "organizations"),
            },
            "/organizations/{organizationId}/configTemplates/{configTemplateId}": {
                "get": _op("getOrganizationConfigTemplate", "organizations"),
                "put": _op("updateOrganizationConfigTemplate", "organizations"),
            },
            "/networks/{networkId}/appliance/vlans": {
                "get": _op("getNetworkApplianceVlans", "appliance"),
            },
            "/networks/{networkId}/appliance/vlans/{vlanId}": {
                "get": _op("getNetworkApplianceVlan", "appliance"),
                "put": _op("updateNetworkApplianceVlan", "appliance"),
            },
        },
    }
    spec_path = tmp_path / "template-spec.json"
    spec_path.write_text(_json.dumps(spec), encoding="utf-8")

    vlan_scopes: list[str] = []

    class Organizations:
        def getOrganizationNetworks(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return [dict(NETWORK_PAYLOAD)]

        def getOrganizationDevices(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return []

        def getOrganizationConfigTemplates(
            self, organizationId: str
        ) -> list[dict[str, Any]]:
            return [{"id": "T_1", "name": "Branch Template"}]

    class Appliance:
        def getNetworkApplianceVlans(
            self, networkId: str
        ) -> list[dict[str, Any]]:
            vlan_scopes.append(networkId)
            if networkId == "T_1":
                return [{"id": 77, "name": "Template-Data"}]
            return [{"id": 10, "name": "Data"}]

    provider = LiveApiDataProvider(parser=OpenApiParser(spec_path))
    provider._client = types.SimpleNamespace(
        organizations=Organizations(), appliance=Appliance()
    )
    graph = provider.fetch_network_graph("org-123")

    assert set(vlan_scopes) == {"N_1", "T_1"}
    template_vlans = [
        f for f in graph.features
        if f.api_path == "/networks/{networkId}/appliance/vlans/{vlanId}"
        and f.path_values[0] == "T_1"
    ]
    assert [f.path_values for f in template_vlans] == [("T_1", "77")]


def test_aggregation_resolution_universe_includes_config_templates(
    tmp_path: Path,
) -> None:
    """A byNetwork row scoped by a CONFIG TEMPLATE's per-product child
    id (named "<template name> - <product>") must resolve onto the
    template, exactly like network children — observed live as
    scope-less gap records ("seed2-template - wireless") before the
    template list was threaded into the resolution universe. A row
    resolvable neither way still stays an auditable gap record."""
    import json as _json

    from conftest import AIR_MARSHAL_BY_NETWORK_SCHEMA, _op

    marshal_path = "/networks/{networkId}/wireless/airMarshal/settings"
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "template-aggregation", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/configTemplates": {
                "get": _op("getOrganizationConfigTemplates", "organizations"),
            },
            "/organizations/{organizationId}/configTemplates"
            "/{configTemplateId}": {
                "get": _op("getOrganizationConfigTemplate", "organizations"),
                "put": _op(
                    "updateOrganizationConfigTemplate", "organizations"
                ),
            },
            marshal_path: {
                "put": _op(
                    "updateNetworkWirelessAirMarshalSettings", "wireless"
                ),
            },
            "/organizations/{organizationId}/wireless/airMarshal/settings"
            "/byNetwork": {
                "get": _op(
                    "getOrganizationWirelessAirMarshalSettingsByNetwork",
                    "wireless",
                    response_schema=AIR_MARSHAL_BY_NETWORK_SCHEMA,
                ),
            },
        },
    }
    spec_path = tmp_path / "template-aggregation-spec.json"
    spec_path.write_text(_json.dumps(spec), encoding="utf-8")

    class Organizations:
        def getOrganizationNetworks(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return [dict(NETWORK_PAYLOAD)]

        def getOrganizationDevices(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return []

        def getOrganizationConfigTemplates(
            self, organizationId: str
        ) -> list[dict[str, Any]]:
            return [{"id": "T_1", "name": "seed2-template"}]

    class Wireless:
        def getOrganizationWirelessAirMarshalSettingsByNetwork(
            self, organizationId: str
        ) -> dict[str, Any]:
            return {
                "items": [
                    {
                        "networkId": "N_555",
                        "networkName": "seed2-template - wireless",
                        "defaultPolicy": "blocked",
                    },
                    {
                        "networkId": "N_666",
                        "networkName": "vanished - wireless",
                        "defaultPolicy": "allowed",
                    },
                ],
                "meta": {},
            }

    provider = LiveApiDataProvider(parser=OpenApiParser(spec_path))
    provider._client = types.SimpleNamespace(
        organizations=Organizations(), wireless=Wireless()
    )
    graph = provider.fetch_network_graph("org-123")
    marshal = [f for f in graph.features if f.api_path == marshal_path]
    assert [(f.path_values, dict(f.payload)) for f in marshal] == [
        (
            ("T_1",),
            {
                "networkName": "seed2-template - wireless",
                "defaultPolicy": "blocked",
            },
        ),
        (
            (),
            {
                "networkId": "N_666",
                "networkName": "vanished - wireless",
                "defaultPolicy": "allowed",
            },
        ),
    ]


def test_try_call_still_skips_scope_refusals_with_status(
    live_provider: LiveApiDataProvider, spec_parser: OpenApiParser
) -> None:
    """A 400 product-type refusal stays a quiet skip even when the
    exception carries an HTTP status attribute like APIError does."""
    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )

    class Refusing:
        def getOrganizationAdmins(self, organizationId: str) -> list[dict[str, Any]]:
            raise _FakeApiError(400)

    live_provider._client = types.SimpleNamespace(organizations=Refusing())
    lock, bucket, abort = _try_call_args()
    result = live_provider._try_call(
        op, {"organizationId": "org-123"}, set(), lock, bucket, abort
    )
    assert result is None


def test_live_provider_without_parser_skips_features(
    live_provider: LiveApiDataProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    bare = LiveApiDataProvider(parser=None)
    bare._client = FakeDashboard()
    graph = bare.fetch_network_graph("org-123")
    assert graph.features == ()
    bare.close()
    assert bare._client is None


def test_live_call_requests_all_pages_when_method_paginates(
    live_provider: LiveApiDataProvider, spec_parser: OpenApiParser
) -> None:
    """Paginated SDK methods default to one page; dynamic dispatch must
    ask for all of them or large collections are silently truncated."""
    captured: dict[str, Any] = {}

    class PagedOrganizations:
        def getOrganizationAdmins(
            self, organizationId: str, total_pages: Any = 1
        ) -> list[dict[str, Any]]:
            captured["total_pages"] = total_pages
            return []

    dashboard = types.SimpleNamespace(organizations=PagedOrganizations())
    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )
    live_provider._call(dashboard, op, organizationId="org-1")
    assert captured["total_pages"] == "all"


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


def _nested_spec(tmp_path: Path) -> Path:
    """Minimal spec with a two-parameter configuration surface."""
    from conftest import _op

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "nested", "version": "1"},
        "paths": {
            "/networks/{networkId}/wireless/ssids": {
                "get": _op("getNetworkWirelessSsids", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}": {
                "get": _op("getNetworkWirelessSsid", "wireless"),
                "put": _op("updateNetworkWirelessSsid", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}/identityPsks": {
                "get": _op("getNetworkWirelessSsidIdentityPsks", "wireless"),
            },
            "/networks/{networkId}/wireless/ssids/{number}/identityPsks/{identityPskId}": {
                "get": _op("getNetworkWirelessSsidIdentityPsk", "wireless"),
                "put": _op("updateNetworkWirelessSsidIdentityPsk", "wireless"),
            },
        },
    }
    path = tmp_path / "nested-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return path


def test_nested_collections_discovered_from_parent_elements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Multi-parameter configuration surfaces (per-SSID identity PSKs,
    switch-stack routing, template switch profiles, ...) scope off
    elements discovered at the enclosing item path. They were previously
    skipped entirely — a Cardinal Rule 2 violation."""
    calls: list[tuple[str, ...]] = []

    class Wireless:
        def getNetworkWirelessSsids(self, networkId: str) -> list[dict[str, Any]]:
            return [{"number": 0, "name": "Corp"}]

        def getNetworkWirelessSsidIdentityPsks(
            self, networkId: str, number: str
        ) -> list[dict[str, Any]]:
            calls.append((networkId, number))
            return [{"id": "psk-1", "name": "kiosk"}]

    class Organizations:
        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list[dict[str, Any]]:
            return [{"id": "N_1", "organizationId": organizationId}]

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list[dict[str, Any]]:
            return []

    provider = LiveApiDataProvider(parser=OpenApiParser(_nested_spec(tmp_path)))
    provider._client = types.SimpleNamespace(
        organizations=Organizations(), wireless=Wireless()
    )
    graph = provider.fetch_network_graph("org-123")

    assert calls == [("N_1", "0")]  # scoped off the discovered SSID element
    addressed = {(f.api_path, f.path_values) for f in graph.features}
    assert (
        "/networks/{networkId}/wireless/ssids/{number}",
        ("N_1", "0"),
    ) in addressed
    assert (
        "/networks/{networkId}/wireless/ssids/{number}/identityPsks/{identityPskId}",
        ("N_1", "0", "psk-1"),
    ) in addressed


def test_parent_item_path_and_nested_ordering(tmp_path: Path) -> None:
    from meraki2tf.providers.discovery import (
        nested_collection_operations,
        parent_item_path,
    )

    assert parent_item_path(
        "/networks/{networkId}/wireless/ssids/{number}/identityPsks"
    ) == "/networks/{networkId}/wireless/ssids/{number}"
    parser = OpenApiParser(_nested_spec(tmp_path))
    nested = nested_collection_operations(parser)
    assert [op.path for op in nested] == [
        "/networks/{networkId}/wireless/ssids/{number}/identityPsks"
    ]


def test_pool_aborts_run_when_a_worker_exhausts_throttle_budget(
    tmp_path: Path,
) -> None:
    """Fail fast and loud: one exhausted worker cancels the level and
    the whole discovery aborts — a partial snapshot must never look
    complete."""

    class AlwaysThrottled:
        def getNetworkWirelessSsids(self, networkId: str) -> list[dict[str, Any]]:
            raise _FakeApiError(429)

    class Organizations:
        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list[dict[str, Any]]:
            return [{"id": "N_1", "organizationId": organizationId}]

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list[dict[str, Any]]:
            return []

    provider = LiveApiDataProvider(parser=OpenApiParser(_nested_spec(tmp_path)))
    provider._client = types.SimpleNamespace(
        organizations=Organizations(), wireless=AlwaysThrottled()
    )
    with pytest.raises(LiveRetryExhaustedError):
        provider.fetch_network_graph("org-123")


def test_empty_nested_level_is_a_noop(tmp_path: Path) -> None:
    """A nested surface whose parent produced no elements dispatches
    nothing (and manufactures no phantom coverage)."""

    class Wireless:
        def getNetworkWirelessSsids(self, networkId: str) -> list[dict[str, Any]]:
            return []

    class Organizations:
        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list[dict[str, Any]]:
            return [{"id": "N_1", "organizationId": organizationId}]

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list[dict[str, Any]]:
            return []

    provider = LiveApiDataProvider(parser=OpenApiParser(_nested_spec(tmp_path)))
    provider._client = types.SimpleNamespace(
        organizations=Organizations(), wireless=Wireless()
    )
    graph = provider.fetch_network_graph("org-123")
    assert graph.features == ()


def test_parent_item_path_tolerates_paramless_nested_shapes() -> None:
    """A malformed/hostile spec can carry parameters only embedded
    mid-segment; there is no enclosing item path, and discovery must
    record a coverage gap instead of crashing the whole run on max()."""
    from meraki2tf.providers.discovery import parent_item_path

    assert parent_item_path("/foo/x{a}/y{b}") == ""


def test_contract_dump_refuses_non_object_network_elements(
    tmp_path: Path,
) -> None:
    """A hand-corrupted snapshot with a bare string in 'networks' must
    surface the contract diagnostic, not an AttributeError."""
    from meraki2tf.providers.dump import (
        MalformedDumpError,
        StaticJsonDataProvider,
    )

    path = tmp_path / "broken.json"
    path.write_text(
        json.dumps(
            {"organizationId": "org-123", "networks": ["oops"],
             "devices": [], "features": []}
        ),
        encoding="utf-8",
    )
    provider = StaticJsonDataProvider(path)
    with pytest.raises(MalformedDumpError, match="'networks'"):
        with provider as source:
            source.fetch_network_graph(None)


def test_live_dispatch_refuses_methods_that_are_not_verifiably_read_only(
    live_provider: LiveApiDataProvider, spec_parser: OpenApiParser
) -> None:
    """A stale or tampered spec can label a mutating SDK method as a
    GET; the resolved method's own source is the ground truth, and a
    real meraki-package method that calls mutating session verbs must
    be refused at dispatch (Cardinal Rule 1)."""

    def poisoned_admins(self: Any, organizationId: str) -> Any:
        return self._session.put({}, "/x")

    # Only real meraki-package methods carry the fingerprint check.
    poisoned_admins.__module__ = "meraki.api.organizations"

    class PoisonedOrganizations:
        getOrganizationAdmins = poisoned_admins

    dashboard = types.SimpleNamespace(organizations=PoisonedOrganizations())
    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )
    with pytest.raises(LiveDispatchError, match="not verifiably read-only"):
        live_provider._call(dashboard, op, organizationId="123456")


class _RecordingScopedDashboard:
    """Two networks / three devices; records which scopes were queried."""

    def __init__(self) -> None:
        self.network_calls: list[str] = []
        self.serial_calls: list[str] = []
        self.admin_calls = 0
        outer = self

        class Organizations:
            def getOrganizationNetworks(
                self, org_id: str, total_pages: str
            ) -> list[dict[str, Any]]:
                return [
                    dict(NETWORK_PAYLOAD),
                    {
                        "id": "N_2",
                        "organizationId": "org-123",
                        "name": "Branch-07",
                        "productTypes": ["appliance"],
                    },
                ]

            def getOrganizationDevices(
                self, org_id: str, total_pages: str
            ) -> list[dict[str, Any]]:
                return [
                    dict(DEVICE_PAYLOAD),
                    {
                        "serial": "Q2XY-1234-5678",
                        "networkId": "N_2",
                        "model": "MX64",
                        "name": "branch-edge",
                    },
                    # Unclaimed: outside every network scope.
                    {"serial": "Q2ZZ-0000-0000", "networkId": "",
                     "model": "MR36", "name": "spare"},
                ]

            def getOrganizationAdmins(
                self, organizationId: str
            ) -> list[dict[str, Any]]:
                outer.admin_calls += 1
                return [{"id": "A_1", "email": "ops@example.com"}]

        class Appliance:
            def getNetworkApplianceVlans(self, networkId: str) -> list[Any]:
                outer.network_calls.append(networkId)
                return [{"id": 10, "name": "Data"}]

            def getNetworkApplianceTrafficShaping(
                self, networkId: str
            ) -> dict[str, Any]:
                outer.network_calls.append(networkId)
                return {"globalBandwidthLimits": {"limitUp": 1, "limitDown": 1}}

        class Networks:
            def getNetworkSyslogServers(
                self, networkId: str
            ) -> list[dict[str, Any]]:
                outer.network_calls.append(networkId)
                return [{"host": "10.0.0.1"}]

        class Sensor:
            def getNetworkSensorRelationships(
                self, networkId: str
            ) -> list[dict[str, Any]]:
                outer.network_calls.append(networkId)
                return []

        class Switch:
            def getDeviceSwitchPorts(
                self, serial: str
            ) -> list[dict[str, Any]]:
                outer.serial_calls.append(serial)
                return [{"portId": "1", "name": "Uplink", "enabled": True}]

        class Wireless:
            def getNetworkWirelessSsids(
                self, networkId: str
            ) -> list[dict[str, Any]]:
                outer.network_calls.append(networkId)
                return []

            def getOrganizationWirelessAirMarshalSettingsByNetwork(
                self, organizationId: str
            ) -> dict[str, Any]:
                # Rows for both networks: the scoped run must keep only
                # the selected network's row.
                return {
                    "items": [
                        {"networkId": "N_1", "defaultPolicy": "blocked"},
                        {"networkId": "N_2", "defaultPolicy": "allowed"},
                    ],
                    "meta": {},
                }

            def getOrganizationWirelessSsidsOpenRoamingByNetwork(
                self, organizationId: str
            ) -> dict[str, Any]:
                # Both rows are scoped by phantom per-product child ids;
                # resolution must use the FULL network universe (HQ is
                # outside the --only scope), then the scope filter drops
                # the out-of-scope parent's assets — never gap-records
                # them.
                return {
                    "items": [
                        {
                            "networkId": "N_888",
                            "networkName": "HQ - wireless",
                            "ssids": [
                                {"number": 0, "openRoaming": {"enabled": True}},
                            ],
                        },
                        {
                            "networkId": "N_999",
                            "networkName": "Branch-07 - wireless",
                            "ssids": [
                                {"number": 1, "openRoaming": {"enabled": False}},
                            ],
                        },
                    ],
                    "meta": {},
                }

        class ApplianceSsids:
            def getNetworkApplianceSsids(
                self, networkId: str
            ) -> list[dict[str, Any]]:
                outer.network_calls.append(networkId)
                return []

        self.organizations = Organizations()
        self.appliance = Appliance()
        self.appliance.getNetworkApplianceSsids = (  # type: ignore[attr-defined]
            ApplianceSsids().getNetworkApplianceSsids
        )
        self.networks = Networks()
        self.sensor = Sensor()
        self.switch = Switch()
        self.wireless = Wireless()


def test_live_scoped_fetch_narrows_networks_and_devices(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    from meraki2tf.scope import LiveNetworkScope

    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    provider = LiveApiDataProvider(
        parser=spec_parser,
        network_scope=LiveNetworkScope(selectors=("network:Branch-*",)),
    )
    dashboard = _RecordingScopedDashboard()
    provider._client = dashboard
    graph = provider.fetch_network_graph("org-123")
    assert [n.network_id for n in graph.networks] == ["N_2"]
    # Devices narrow to the selected networks; unclaimed devices fall
    # outside every network scope.
    assert [d.serial for d in graph.devices] == ["Q2XY-1234-5678"]
    # Network-scoped ops ran only for the selected network, serial ops
    # only for its device, and org-level ops still ran (once).
    assert set(dashboard.network_calls) == {"N_2"}
    assert dashboard.serial_calls == ["Q2XY-1234-5678"]
    assert dashboard.admin_calls == 1
    # The org-scoped aggregation returned rows for both networks; the
    # scoped run keeps only the selected network's exploded assets.
    air_marshal = [
        f
        for f in graph.features
        if f.api_path == "/networks/{networkId}/wireless/airMarshal/settings"
    ]
    assert [f.path_values for f in air_marshal] == [("N_2",)]
    # Nested-element aggregation rows scoped by phantom child ids: the
    # in-scope parent's row survives (re-scoped to N_2), while the
    # out-of-scope parent's row is filtered out entirely — resolution
    # ran against the full network universe, so it never degraded into
    # a scope-less gap record.
    open_roaming = [
        f
        for f in graph.features
        if f.api_path
        == "/networks/{networkId}/wireless/ssids/{number}/openRoaming"
    ]
    assert [f.path_values for f in open_roaming] == [("N_2", "1")]
    assert dict(open_roaming[0].payload) == {"enabled": False}


def test_live_scoped_fetch_id_form_tolerates_missing_network(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    from meraki2tf.scope import LiveNetworkScope

    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    provider = LiveApiDataProvider(
        parser=spec_parser,
        network_scope=LiveNetworkScope(
            network_ids=frozenset({"N_2", "N_deleted"})
        ),
    )
    provider._client = _RecordingScopedDashboard()
    graph = provider.fetch_network_graph("org-123")
    assert [n.network_id for n in graph.networks] == ["N_2"]


def test_live_scoped_fetch_zero_match_selector_raises(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    from meraki2tf.scope import LiveNetworkScope, ScopeFilterError

    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    provider = LiveApiDataProvider(
        parser=spec_parser,
        network_scope=LiveNetworkScope(selectors=("network:Warehouse*",)),
    )
    provider._client = _RecordingScopedDashboard()
    with pytest.raises(ScopeFilterError, match="Warehouse"):
        provider.fetch_network_graph("org-123")


def test_snapshot_scope_property_absent_on_legacy_snapshots(
    dump_file: Path,
) -> None:
    assert StaticJsonDataProvider(dump_file).snapshot_scope is None


def test_snapshot_scope_property_reads_v1_and_v2(tmp_path: Path) -> None:
    from meraki2tf.models import MerakiNetwork
    from meraki2tf.snapshot import write_snapshot

    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork(
                network_id="N_1", organization_id="org-123",
                name="HQ", product_types=("appliance",),
            ),
        ),
        devices=(),
        features=(),
    )
    for name in ("scoped.json", "scoped.jsonl"):
        path = tmp_path / name
        write_snapshot(graph, path, scope_selectors=("network:HQ",))
        scope = StaticJsonDataProvider(path).snapshot_scope
        assert scope is not None, name
        assert scope.network_ids == ("N_1",)
        assert scope.selectors == ("network:HQ",)


def test_snapshot_scope_property_refuses_malformed_header(
    tmp_path: Path,
) -> None:
    path = tmp_path / "bad-scope.jsonl"
    path.write_text(
        json.dumps(
            {"meraki2tfSnapshot": 2, "organizationId": "org-123",
             "scope": {"networks": "N_1"}}
        )
        + "\n",
        encoding="utf-8",
    )
    provider = StaticJsonDataProvider(path)
    with pytest.raises(MalformedDumpError, match="scope"):
        provider.snapshot_scope


# ---------------------------------------------------------------------------
# Aggregation execution, product-type prefiltering, suspect endpoints
# ---------------------------------------------------------------------------


def test_aggregation_endpoint_unreadable_gaps_the_entity(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dead aggregation GET must gap the adopted entity's own
    collection path so heal/deletion flows exempt it through the
    ordinary unreadable-marker mechanism."""

    def _explode(self: Any, organizationId: str) -> dict[str, Any]:
        raise _FakeApiError(500)

    monkeypatch.setattr(
        FakeWireless,
        "getOrganizationWirelessAirMarshalSettingsByNetwork",
        _explode,
    )
    graph = live_provider.fetch_network_graph("org-123")
    gaps = [f for f in graph.features if UNREADABLE_MARKER in f.payload]
    assert [(g.api_path, g.path_values) for g in gaps] == [
        ("/networks/{networkId}/wireless/airMarshal/settings", ()),
    ]
    assert "HTTP 500" in gaps[0].payload[UNREADABLE_MARKER]


def test_aggregation_org_scope_refusal_is_absence_by_design(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 400/404 at org scope means the organization does not carry the
    product family at all — genuine absence, no gap record."""

    def _refuse(self: Any, organizationId: str) -> dict[str, Any]:
        raise _FakeApiError(404)

    monkeypatch.setattr(
        FakeWireless,
        "getOrganizationWirelessAirMarshalSettingsByNetwork",
        _refuse,
    )
    graph = live_provider.fetch_network_graph("org-123")
    assert not any(
        f.api_path == "/networks/{networkId}/wireless/airMarshal/settings"
        for f in graph.features
    )
    assert not any(UNREADABLE_MARKER in f.payload for f in graph.features)


def _prefilter_spec(tmp_path: Path) -> OpenApiParser:
    """Spec with a createNetwork productTypes enum plus one endpoint per
    product family and scope kind."""
    from conftest import _op

    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": {
                    **_op("createOrganizationNetwork", "organizations"),
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "productTypes": {
                                            "type": "array",
                                            "items": {
                                                "type": "string",
                                                "enum": [
                                                    "appliance",
                                                    "wireless",
                                                    "switch",
                                                    "camera",
                                                ],
                                            },
                                        }
                                    }
                                }
                            }
                        }
                    },
                },
            },
            "/organizations/{organizationId}/devices": {
                "get": _op("getOrganizationDevices", "organizations"),
            },
            "/networks/{networkId}": {
                "get": _op("getNetwork", "networks"),
                "put": _op("updateNetwork", "networks"),
            },
            "/devices/{serial}": {
                "get": _op("getDevice", "devices"),
                "put": _op("updateDevice", "devices"),
            },
            "/networks/{networkId}/appliance/settings": {
                "get": _op("getNetworkApplianceSettings", "appliance"),
                "put": _op("updateNetworkApplianceSettings", "appliance"),
            },
            "/networks/{networkId}/wireless/settings": {
                "get": _op("getNetworkWirelessSettings", "wireless"),
                "put": _op("updateNetworkWirelessSettings", "wireless"),
            },
            # 'sm' is not a productTypes value — never filtered.
            "/networks/{networkId}/sm/targetGroups": {
                "get": _op("getNetworkSmTargetGroups", "sm"),
                "put": _op("updateNetworkSmTargetGroups", "sm"),
            },
            "/devices/{serial}/switch/routing": {
                "get": _op("getDeviceSwitchRouting", "switch"),
                "put": _op("updateDeviceSwitchRouting", "switch"),
            },
        },
    }
    path = tmp_path / "prefilter-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    from meraki2tf.openapi_parser import OpenApiParser

    return OpenApiParser(path)


class _PrefilterDashboard:
    """Two networks / three devices; records which endpoint hit which
    scope so prefiltering is observable."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        outer = self

        class Organizations:
            def getOrganizationNetworks(
                self, org_id: str, total_pages: str
            ) -> list[dict[str, Any]]:
                return [
                    {
                        "id": "N_APP",
                        "organizationId": "org-123",
                        "name": "HQ",
                        "productTypes": ["appliance"],
                    },
                    {
                        "id": "N_UNKNOWN",
                        "organizationId": "org-123",
                        "name": "Legacy",
                        "productTypes": [],
                    },
                ]

            def getOrganizationDevices(
                self, org_id: str, total_pages: str
            ) -> list[dict[str, Any]]:
                return [
                    {"serial": "Q2SW-0000-0001", "networkId": "N_APP",
                     "model": "MS120", "productType": "switch"},
                    {"serial": "Q2CA-0000-0002", "networkId": "N_APP",
                     "model": "MV12", "productType": "camera"},
                    {"serial": "Q2NA-0000-0003", "networkId": "N_APP",
                     "model": "MX64"},
                ]

        class Networks:
            def getNetwork(self, networkId: str) -> dict[str, Any]:
                outer.calls.append(("network", networkId))
                return {"id": networkId}

        class Appliance:
            def getNetworkApplianceSettings(
                self, networkId: str
            ) -> dict[str, Any]:
                outer.calls.append(("appliance", networkId))
                return {"clientTrackingMethod": "MAC address"}

        class Wireless:
            def getNetworkWirelessSettings(
                self, networkId: str
            ) -> dict[str, Any]:
                outer.calls.append(("wireless", networkId))
                return {"meshingEnabled": False}

        class Sm:
            def getNetworkSmTargetGroups(
                self, networkId: str
            ) -> list[dict[str, Any]]:
                outer.calls.append(("sm", networkId))
                return []

        class Switch:
            def getDeviceSwitchRouting(self, serial: str) -> dict[str, Any]:
                outer.calls.append(("switch", serial))
                return {"enabled": True}

        class Devices:
            def getDevice(self, serial: str) -> dict[str, Any]:
                outer.calls.append(("device", serial))
                return {"serial": serial}

        self.organizations = Organizations()
        self.networks = Networks()
        self.appliance = Appliance()
        self.wireless = Wireless()
        self.sm = Sm()
        self.switch = Switch()
        self.devices = Devices()


def test_product_type_prefilter_skips_provably_out_of_scope_calls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A wireless endpoint on an appliance-only network can only
    400/404: skip the call, count it, and treat it exactly like the
    refusal it would have been. Unknown product types (networks or
    devices) never filter — under-filtering is safe, over-filtering is
    coverage loss."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    provider = LiveApiDataProvider(parser=_prefilter_spec(tmp_path))
    dashboard = _PrefilterDashboard()
    provider._client = dashboard
    provider.fetch_network_graph("org-123")

    # The appliance-only network skipped only the wireless family call;
    # the unknown-product network was never filtered.
    assert ("wireless", "N_APP") not in dashboard.calls
    assert ("appliance", "N_APP") in dashboard.calls
    assert ("sm", "N_APP") in dashboard.calls  # 'sm' is not a product type
    assert ("wireless", "N_UNKNOWN") in dashboard.calls
    assert ("appliance", "N_UNKNOWN") in dashboard.calls
    # Devices: exact productType match required; unknown never filters.
    assert ("switch", "Q2SW-0000-0001") in dashboard.calls
    assert ("switch", "Q2CA-0000-0002") not in dashboard.calls  # camera
    assert ("switch", "Q2NA-0000-0003") in dashboard.calls  # unknown
    diagnostics = provider.discovery_diagnostics
    assert diagnostics is not None
    # One network-level skip (wireless@N_APP) + one device-level skip.
    assert diagnostics.skipped_out_of_scope == 2


def test_endpoints_refused_by_every_scope_become_suspects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Feature-not-enabled 400s stay quiet absence, but an endpoint
    that refuses EVERY scope (>= 3 tried) is a visible diagnostic — an
    SDK/spec skew could otherwise hide a whole surface behind
    plausible-looking refusals."""
    from conftest import _op
    from meraki2tf.openapi_parser import OpenApiParser

    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/organizations/{organizationId}/devices": {
                "get": _op("getOrganizationDevices", "organizations"),
            },
            "/networks/{networkId}/alwaysRefused": {
                "get": _op("getNetworkAlwaysRefused", "networks"),
                "put": _op("updateNetworkAlwaysRefused", "networks"),
            },
            "/networks/{networkId}/sometimesRefused": {
                "get": _op("getNetworkSometimesRefused", "networks"),
                "put": _op("updateNetworkSometimesRefused", "networks"),
            },
        },
    }
    path = tmp_path / "suspect-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")

    class Networks:
        def getNetworkAlwaysRefused(self, networkId: str) -> dict[str, Any]:
            raise _FakeApiError(400)

        def getNetworkSometimesRefused(self, networkId: str) -> dict[str, Any]:
            if networkId == "N_3":
                return {"enabled": True}
            raise _FakeApiError(404)

    class Organizations:
        def getOrganizationNetworks(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return [
                {"id": network_id, "organizationId": "org-123",
                 "name": network_id, "productTypes": ["appliance"]}
                for network_id in ("N_1", "N_2", "N_3")
            ]

        def getOrganizationDevices(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return []

    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    provider = LiveApiDataProvider(parser=OpenApiParser(path))
    provider._client = types.SimpleNamespace(
        organizations=Organizations(), networks=Networks()
    )
    graph = provider.fetch_network_graph("org-123")
    diagnostics = provider.discovery_diagnostics
    assert diagnostics is not None
    assert [
        (s.api_path, s.scopes_tried) for s in diagnostics.suspect_endpoints
    ] == [("/networks/{networkId}/alwaysRefused", 3)]
    # The mixed endpoint discovered its one available scope normally.
    assert any(
        f.api_path == "/networks/{networkId}/sometimesRefused"
        and f.path_values == ("N_3",)
        for f in graph.features
    )


def test_organization_mismatch_explains_the_relabelling(
    dump_file: Path,
) -> None:
    """The diagnostic has to name both organizations and say why a
    relabelled artifact matters — --rebuild resolves its target from
    coverage.json, so --expect-org would pass on the wrong kit."""
    provider = StaticJsonDataProvider(dump_file)

    assert provider.organization_mismatch(None) is None
    assert provider.organization_mismatch("org-123") is None
    conflict = provider.organization_mismatch("org-999")
    assert conflict is not None
    assert "org-123" in conflict and "org-999" in conflict
    assert "--expect-org" in conflict
