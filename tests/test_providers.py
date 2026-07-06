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


class FakeNetworksSection:
    def getNetworkSyslogServers(self, networkId: str) -> list[dict[str, Any]]:
        return [{"host": "10.0.0.1"}]


class FakeSensor:
    def getNetworkSensorRelationships(self, networkId: str) -> list[dict[str, Any]]:
        raise RuntimeError("400 Bad Request: sensor not available for this network")


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


@pytest.fixture()
def live_provider(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> LiveApiDataProvider:
    constructed: list[dict[str, Any]] = []

    def fake_dashboard_api(**kwargs: Any) -> FakeDashboard:
        constructed.append(kwargs)
        assert kwargs["suppress_logging"] is True
        assert kwargs["print_console"] is False
        # The org-wide rate budget is shared with other API consumers;
        # the SDK must wait out 429s far past its 2-retry default.
        assert kwargs["wait_on_rate_limit"] is True
        assert kwargs["maximum_retries"] == 10
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

    # Folded collection aliases (/organizations/{organizationId}/networks
    # lists first-class network assets) are not re-emitted as features,
    # and the refusing sensor endpoint is skipped, not fatal. The two
    # unidentifiable VLAN elements surface as collection-path assets.
    assert len(graph.features) == 7


def test_live_dispatch_gap_warns_once_and_skips(
    live_provider: LiveApiDataProvider,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An SDK missing an operation is missing DR coverage — loud, not DEBUG."""
    monkeypatch.delattr(FakeOrganizations, "getOrganizationAdmins")
    with caplog.at_level("WARNING", logger="meraki2tf.providers.live"):
        graph = live_provider.fetch_network_graph("org-123")
    admin_warnings = [
        record for record in caplog.records
        if "cannot be dispatched" in record.message and "admins" in record.message
    ]
    assert len(admin_warnings) == 1  # warned once, not per scope/network
    assert len(graph.features) == 6  # everything else still discovered


def test_try_call_skips_operations_already_known_undispatchable(
    live_provider: LiveApiDataProvider, spec_parser: OpenApiParser
) -> None:
    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )
    undispatchable = {op.operation_id}
    result = live_provider._try_call(
        object(), op, "organizationId", "org-123", undispatchable
    )
    assert result is None  # short-circuited, no dispatch attempted


class _FakeApiError(Exception):
    """Mimics meraki.exceptions.APIError's ``status`` attribute."""

    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


def test_try_call_aborts_when_throttle_survives_retries(
    live_provider: LiveApiDataProvider,
    spec_parser: OpenApiParser,
) -> None:
    """A 429 that escapes the SDK's generous waits is missing data, not
    an inapplicable feature — swallowing it would ship a snapshot that
    is silently incomplete but looks complete."""
    op = next(
        o for o in spec_parser.endpoints()
        if o.operation_id == "getOrganizationAdmins"
    )

    class Throttled:
        def getOrganizationAdmins(self, organizationId: str) -> list[dict[str, Any]]:
            raise _FakeApiError(429)

    dashboard = types.SimpleNamespace(organizations=Throttled())
    with pytest.raises(LiveRetryExhaustedError, match="HTTP 429"):
        live_provider._try_call(
            dashboard, op, "organizationId", "org-123", set()
        )


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

    dashboard = types.SimpleNamespace(organizations=Refusing())
    result = live_provider._try_call(
        dashboard, op, "organizationId", "org-123", set()
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
