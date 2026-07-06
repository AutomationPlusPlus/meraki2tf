"""Gap replayer: planning branches, ID remapping, and SDK dispatch."""

import sys
import types
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.config import API_KEY_ENV_VAR
from meraki2tf.hcl_generator import (
    CapturedAsset,
    GenerationReport,
    UnsupportedAsset,
)
from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.replayer import (
    GapReplayer,
    ReplayAction,
    ReplayDispatchError,
    _collection_items,
    _single_array_body_field,
    plan_replay,
)
from meraki2tf.sanitizer import REDACTED
from meraki2tf.spec.engine import OperationSpec

VLAN_PATH = "/networks/{networkId}/appliance/vlans/{vlanId}"
SSID_PATH = "/networks/{networkId}/wireless/ssids/{number}"
CLIENTS_PATH = "/networks/{networkId}/clients"


def _graph(*features: FeatureConfiguration, networks=()) -> NetworkGraph:
    return NetworkGraph(
        organization_id="org-123",
        networks=networks,
        devices=(),
        features=features,
    )


def _report(
    captured: tuple[CapturedAsset, ...] = (),
    unsupported: tuple[UnsupportedAsset, ...] = (),
) -> GenerationReport:
    return GenerationReport(
        imports_file=Path("imports.tf"),
        imports_written=0,
        unsupported=unsupported,
        captured=captured,
    )


def _captured(api_path: str, ids: tuple[str, ...], address: str) -> CapturedAsset:
    return CapturedAsset(
        address=address,
        api_path=api_path,
        import_id=",".join(ids),
        already_in_state=False,
        identifiers=ids,
    )


class _FakeSection:
    """SDK section stub recording calls; methods accept **kwargs."""

    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._fail = fail or set()

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        def method(**kwargs: Any) -> dict[str, Any]:
            if name in self._fail:
                raise RuntimeError(f"{name} rejected by API")
            self.calls.append((name, kwargs))
            return kwargs

        return method


class _FakeDashboard:
    def __init__(self, networks: list[dict[str, str]], fail: set[str] | None = None):
        self._networks = networks
        self.appliance = _FakeSection(fail)
        self.wireless = _FakeSection(fail)
        self.organizations = types.SimpleNamespace(
            getOrganizationNetworks=lambda org, total_pages: list(self._networks)
        )


def _install_fake_meraki(
    monkeypatch: pytest.MonkeyPatch, dashboard: _FakeDashboard
) -> None:
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")


# ---------------------------------------------------------------- planning


def test_plan_replay_object_with_write_operation(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"id": 10, "name": "Data"})
    )
    report = _report(
        unsupported=(UnsupportedAsset(VLAN_PATH, "no match", ("N_1", "10")),)
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert skipped == ()
    (action,) = actions
    assert action.kind == "object"
    assert action.operation.operation_id == "updateNetworkApplianceVlan"
    assert action.payload == {"id": 10, "name": "Data"}
    assert "meraki_" not in action.target and "updateNetworkApplianceVlan" in action.target


def test_plan_replay_skips_dashboard_only_and_payloadless(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(FeatureConfiguration(CLIENTS_PATH, ("N_1",), {"usage": 1}))
    report = _report(
        unsupported=(
            UnsupportedAsset(CLIENTS_PATH, "no match", ("N_1",)),
            UnsupportedAsset(VLAN_PATH, "no match", ("N_1", "99")),
        )
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    reasons = {item.api_path: item.reason for item in skipped}
    assert "dashboard-only" in reasons[CLIENTS_PATH]
    assert "No payload" in reasons[VLAN_PATH]


def test_plan_replay_skips_unreadable_gap_records(
    spec_parser: OpenApiParser,
) -> None:
    """An endpoint that server-errored at capture recorded no payload —
    there is nothing to write back, only a manual-verification pointer."""
    graph = _graph(
        FeatureConfiguration(
            VLAN_PATH,
            ("N_1", "10"),
            {UNREADABLE_MARKER: "HTTP 500 from the Meraki API after every retry"},
        )
    )
    report = _report(
        unsupported=(UnsupportedAsset(VLAN_PATH, "unreadable", ("N_1", "10")),)
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    (skip,) = skipped
    assert "unreadable at capture" in skip.reason


def test_plan_replay_skips_empty_collection_envelopes(
    spec_parser: OpenApiParser,
) -> None:
    """A paginated GET that returned no items leaves nothing to write."""
    path = "/organizations/{organizationId}/networks"
    graph = _graph(
        FeatureConfiguration(
            path,
            ("org-123",),
            {"items": [], "meta": {"counts": {"items": {"total": 0}}}},
        )
    )
    report = _report(unsupported=(UnsupportedAsset(path, "no match", ("org-123",)),))
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    (skip,) = skipped
    assert "empty at capture" in skip.reason


def test_plan_replay_restores_secrets_from_captured_assets(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(
        FeatureConfiguration(
            SSID_PATH, ("N_1", "0"), {"number": 0, "name": "Corp", "psk": "wifi-secret"}
        ),
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"id": 10, "name": "Data"}),
    )
    report = _report(
        captured=(
            _captured(SSID_PATH, ("N_1", "0"), "meraki_wireless_ssid.n_1_0"),
            _captured(VLAN_PATH, ("N_1", "10"), "meraki_appliance_vlan.n_1_10"),
        )
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert skipped == ()
    (action,) = actions  # the secretless VLAN produces nothing
    assert action.kind == "secrets"
    assert action.address == "meraki_wireless_ssid.n_1_0"
    assert action.payload == {"psk": "wifi-secret"}  # only the secret fields
    assert action.operation.operation_id == "updateNetworkWirelessSsid"
    assert "meraki_wireless_ssid.n_1_0" in action.target


def test_plan_replay_skips_sanitized_and_updateless_secrets(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(
        FeatureConfiguration(SSID_PATH, ("N_1", "0"), {"number": 0, "psk": REDACTED}),
        FeatureConfiguration(CLIENTS_PATH, ("N_1",), {"password": "x"}),
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"id": 10}),
    )
    report = _report(
        captured=(
            _captured(SSID_PATH, ("N_1", "0"), "meraki_wireless_ssid.n_1_0"),
            _captured(CLIENTS_PATH, ("N_1",), "meraki_clients.n_1"),
            # captured without a snapshot payload is silently fine
            _captured(VLAN_PATH, ("N_1", "77"), "meraki_appliance_vlan.n_1_77"),
        )
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    reasons = {item.api_path: item.reason for item in skipped}
    assert "--sanitize" in reasons[SSID_PATH]
    assert "no update operation" in reasons[CLIENTS_PATH]


# ------------------------------------------------------------- id mapping


def test_network_id_map_prefers_identity_then_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dashboard = _FakeDashboard(
        networks=[{"id": "N_1", "name": "HQ"}, {"id": "N_9", "name": "Branch"}]
    )
    _install_fake_meraki(monkeypatch, dashboard)
    graph = _graph(
        networks=(
            MerakiNetwork("N_1", "org-123", "HQ", ()),
            MerakiNetwork("N_2", "org-123", "Branch", ()),
            MerakiNetwork("N_3", "org-123", "Ghost", ()),
        )
    )
    mapping = GapReplayer().network_id_map("org-123", graph)
    assert mapping == {"N_1": "N_1", "N_2": "N_9"}  # N_3 stays unmapped


# -------------------------------------------------------------- execution


def _vlan_action(spec_parser: OpenApiParser, network: str = "N_2") -> ReplayAction:
    op = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "updateNetworkApplianceVlan"
    )
    return ReplayAction(
        kind="object",
        api_path=VLAN_PATH,
        path_values=(network, "10"),
        payload={"id": 10, "name": "Data", "networkId": "N_2"},
        operation=op,
    )


def test_execute_remaps_ids_and_prefers_path_params(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    executed, failed = GapReplayer().execute(
        (_vlan_action(spec_parser),),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={"N_2": "N_9"},
    )
    assert failed == ()
    assert len(executed) == 1
    (name, kwargs) = dashboard.appliance.calls[0]
    assert name == "updateNetworkApplianceVlan"
    assert kwargs["networkId"] == "N_9"  # remapped path parameter wins
    assert kwargs["vlanId"] == "10"
    assert kwargs["name"] == "Data"
    assert kwargs["id"] == 10  # payload field that is not a path param


def test_execute_isolates_failures_per_action(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    dashboard = _FakeDashboard(networks=[], fail={"updateNetworkApplianceVlan"})
    _install_fake_meraki(monkeypatch, dashboard)
    ssid_op = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "updateNetworkWirelessSsid"
    )
    ssid = ReplayAction(
        kind="secrets",
        api_path=SSID_PATH,
        path_values=("N_2", "0"),
        payload={"psk": "wifi-secret"},
        operation=ssid_op,
        address="meraki_wireless_ssid.n_2_0",
    )
    executed, failed = GapReplayer().execute(
        (_vlan_action(spec_parser), ssid),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={"N_2": "N_9"},
    )
    assert len(failed) == 1 and "rejected by API" in failed[0][1]
    assert len(executed) == 1  # the SSID still went through
    assert dashboard.wireless.calls[0][1]["psk"] == "wifi-secret"
    assert "wifi-secret" not in failed[0][0]  # targets carry no values


def test_execute_refuses_unmapped_network(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    executed, failed = GapReplayer().execute(
        (_vlan_action(spec_parser, network="N_GONE"),),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={"N_2": "N_9"},
    )
    assert executed == ()
    assert "no live counterpart" in failed[0][1]
    assert dashboard.appliance.calls == []


def test_parameters_rejects_arity_and_unknown_placeholders(
    spec_parser: OpenApiParser,
) -> None:
    action = _vlan_action(spec_parser)
    broken = ReplayAction(
        kind="object",
        api_path=VLAN_PATH,
        path_values=("N_2",),  # one value for two placeholders
        payload={},
        operation=action.operation,
    )
    with pytest.raises(ReplayDispatchError, match="parameter"):
        GapReplayer._parameters(broken, "org", "org-123", {})

    device_op = next(
        op for op in spec_parser.endpoints() if op.operation_id == "updateDevice"
    )
    foreign = ReplayAction(
        kind="object",
        api_path=VLAN_PATH,
        path_values=("N_2", "10"),
        payload={},
        operation=device_op,  # needs {serial}, which a VLAN cannot supply
    )
    with pytest.raises(ReplayDispatchError, match="serial"):
        GapReplayer._parameters(foreign, "org", "org-123", {"N_2": "N_9"})


def test_parameters_injects_organization_for_org_scoped_writes(
    spec_parser: OpenApiParser,
) -> None:
    create = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "createOrganizationNetwork"
    )
    action = ReplayAction(
        kind="object",
        api_path="/organizations/{organizationId}/networks",
        path_values=("org-123",),
        payload={"name": "HQ"},
        operation=create,
    )
    params = GapReplayer._parameters(action, "org-999", "org-123", {})
    assert params == {"organizationId": "org-999"}  # snapshot org remapped


def test_call_filters_body_to_explicit_signatures(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    calls: list[dict[str, Any]] = []

    class StrictSection:
        @staticmethod
        def updateNetworkApplianceVlan(
            networkId: str, vlanId: str, name: str = ""
        ) -> None:
            calls.append({"networkId": networkId, "vlanId": vlanId, "name": name})

    dashboard = types.SimpleNamespace(appliance=StrictSection())
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")

    action = _vlan_action(spec_parser)
    replayer = GapReplayer()
    replayer._call(
        action.operation,
        {"networkId": "N_9", "vlanId": "10"},
        {"id": 10, "name": "Data"},  # "id" is not in the strict signature
    )
    assert calls == [{"networkId": "N_9", "vlanId": "10", "name": "Data"}]


def _staged_stages_op() -> OperationSpec:
    """A write op whose body is a single array field, like the real
    updateNetworkFirmwareUpgradesStagedStages."""
    return OperationSpec(
        operation_id="updateNetworkFirmwareUpgradesStagedStages",
        method="put",
        path="/networks/{networkId}/firmwareUpgrades/staged/stages",
        path_params=("networkId",),
        tags=("networks",),
        raw={
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "_json": {"type": "array", "items": {}}
                            },
                        }
                    }
                }
            }
        },
    )


def test_call_maps_collection_envelope_to_array_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    section = _FakeSection()
    dashboard = types.SimpleNamespace(networks=section)
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")

    GapReplayer()._call(
        _staged_stages_op(),
        {"networkId": "N_9"},
        {"items": [{"group": {"id": "-1", "description": None}}]},
    )
    (name, kwargs) = section.calls[0]
    assert name == "updateNetworkFirmwareUpgradesStagedStages"
    # envelope unwrapped onto the spec's array field, nulls stripped
    assert kwargs["_json"] == [{"group": {"id": "-1"}}]
    assert "items" not in kwargs


def test_call_strips_null_payload_fields(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    """GET echoes unset fields as null; write endpoints reject them."""
    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    op = next(
        o
        for o in spec_parser.endpoints()
        if o.operation_id == "updateNetworkApplianceVlan"
    )
    GapReplayer()._call(
        op,
        {"networkId": "N_9", "vlanId": "10"},
        {"name": "Data", "description": None, "nested": [{"x": None, "y": 1}]},
    )
    (_, kwargs) = dashboard.appliance.calls[0]
    assert kwargs["name"] == "Data"
    assert "description" not in kwargs
    assert kwargs["nested"] == [{"y": 1}]


def test_collection_and_array_body_helpers_reject_non_matches() -> None:
    # a real object payload that merely has an "items" key is no envelope
    assert _collection_items({"items": [], "name": "x"}) is None
    assert _collection_items({"name": "x"}) is None
    assert _collection_items({"items": ["a"], "meta": {}}) == ["a"]
    # multi-property or non-array bodies never get the envelope mapping
    multi = OperationSpec(
        operation_id="op", method="put", path="/p", path_params=(),
        tags=("t",),
        raw={
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "properties": {
                                "a": {"type": "array"},
                                "b": {"type": "string"},
                            }
                        }
                    }
                }
            }
        },
    )
    assert _single_array_body_field(multi) is None
    scalar = OperationSpec(
        operation_id="op", method="put", path="/p", path_params=(),
        tags=("t",),
        raw={
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {"properties": {"name": {"type": "string"}}}
                    }
                }
            }
        },
    )
    assert _single_array_body_field(scalar) is None
    assert _single_array_body_field(_staged_stages_op()) == "_json"


def test_call_raises_on_missing_sdk_method(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    dashboard = types.SimpleNamespace()  # no sections at all
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")
    op = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "updateNetworkApplianceVlan"
    )
    with pytest.raises(ReplayDispatchError, match="no method"):
        GapReplayer()._call(op, {}, {})
