"""Restore planner: waves, create-vs-configure classification, audit."""

import json
from pathlib import Path

from conftest import _op

from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.restorer import (
    WAVE_DEVICE_CLAIM,
    WAVE_DEVICE_FEATURES,
    WAVE_NETWORK_FEATURES,
    WAVE_NETWORKS,
    WAVE_ORG_FEATURES,
    plan_restore,
    render_restore_plan,
)
from meraki2tf.sanitizer import REDACTED

GP_COLLECTION = "/networks/{networkId}/groupPolicies"
GP_ITEM = "/networks/{networkId}/groupPolicies/{groupPolicyId}"
SSID_ITEM = "/networks/{networkId}/wireless/ssids/{number}"
SNMP_PATH = "/networks/{networkId}/snmp"
ADMINS_ITEM = "/organizations/{organizationId}/admins/{adminId}"
CLIENTS_PATH = "/networks/{networkId}/clients"
PORT_ITEM = "/devices/{serial}/switch/ports/{portId}"


def _restore_spec(tmp_path: Path) -> OpenApiParser:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "restore", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            "/organizations/{organizationId}/admins": {
                "get": _op("getOrganizationAdmins", "organizations"),
                "post": _op("createOrganizationAdmin", "organizations"),
            },
            ADMINS_ITEM: {
                "get": _op("getOrganizationAdmin", "organizations"),
                "put": _op("updateOrganizationAdmin", "organizations"),
            },
            GP_COLLECTION: {
                "get": _op("getNetworkGroupPolicies", "networks"),
                "post": _op("createNetworkGroupPolicy", "networks"),
            },
            GP_ITEM: {
                "get": _op("getNetworkGroupPolicy", "networks"),
                "put": _op("updateNetworkGroupPolicy", "networks"),
            },
            "/networks/{networkId}/wireless/ssids": {
                "get": _op("getNetworkWirelessSsids", "wireless"),
            },
            SSID_ITEM: {
                "get": _op("getNetworkWirelessSsid", "wireless"),
                "put": _op("updateNetworkWirelessSsid", "wireless"),
            },
            SNMP_PATH: {
                "get": _op("getNetworkSnmp", "networks"),
                "put": _op("updateNetworkSnmp", "networks"),
            },
            CLIENTS_PATH: {
                "get": _op("getNetworkClients", "networks"),
            },
            PORT_ITEM: {
                "get": _op("getDeviceSwitchPort", "switch"),
                "put": _op("updateDeviceSwitchPort", "switch"),
            },
        },
    }
    path = tmp_path / "restore-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def _graph(*features: FeatureConfiguration) -> NetworkGraph:
    return NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"], "timeZone": "UTC"}
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1",
                 "model": "MX68", "name": "edge"}
            ),
        ),
        features=features,
    )


def test_plan_orders_waves_and_classifies_kinds(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(PORT_ITEM, ("Q2AB-CDEF-GHIJ", "1"),
                                 {"portId": "1", "name": "uplink"}),
            FeatureConfiguration(GP_ITEM, ("N_1", "100"),
                                 {"groupPolicyId": "100", "name": "kiosk"}),
            FeatureConfiguration(SSID_ITEM, ("N_1", "0"),
                                 {"number": 0, "name": "Corp"}),
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
            FeatureConfiguration(ADMINS_ITEM, ("org-123", "A_1"),
                                 {"id": "A_1", "name": "Jordan Sample"}),
        ),
        parser,
    )
    assert plan.unrestorable == ()
    waves = [action.wave for action in plan.actions]
    assert waves == sorted(waves)  # strictly wave-ordered output

    by_path = {action.api_path: action for action in plan.actions}
    # Networks are created; devices claimed.
    assert by_path["/organizations/{organizationId}/networks"].kind == "create"
    assert by_path["/organizations/{organizationId}/networks"].wave == WAVE_NETWORKS
    assert by_path["/networks/{networkId}/devices/claim"].kind == "claim"
    assert by_path["/networks/{networkId}/devices/claim"].wave == WAVE_DEVICE_CLAIM
    # Server-assigned-ID items (collection POST exists) are creates.
    assert by_path[GP_ITEM].kind == "create"
    assert by_path[GP_ITEM].operation.operation_id == "createNetworkGroupPolicy"
    assert by_path[GP_ITEM].wave == WAVE_NETWORK_FEATURES
    # Fixed-slot items (no collection POST) are configured in place.
    assert by_path[SSID_ITEM].kind == "configure"
    assert by_path[SSID_ITEM].operation.operation_id == "updateNetworkWirelessSsid"
    # Singletons are configured.
    assert by_path[SNMP_PATH].kind == "configure"
    # Org features run in the first wave.
    assert by_path[ADMINS_ITEM].wave == WAVE_ORG_FEATURES
    # Device features run last.
    assert by_path[PORT_ITEM].wave == WAVE_DEVICE_FEATURES


def test_unrestorable_reasons_are_spec_derived(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(CLIENTS_PATH, ("N_1",), {"usage": 1}),
            FeatureConfiguration(SNMP_PATH, ("N_1",), {}),
            FeatureConfiguration(
                GP_ITEM, ("N_1", "9"), {UNREADABLE_MARKER: "HTTP 500"}
            ),
        ),
        parser,
    )
    reasons = {u.api_path: u.reason for u in plan.unrestorable}
    assert "dashboard-only" in reasons[CLIENTS_PATH]
    assert "No payload captured" in reasons[SNMP_PATH]
    assert "unreadable at capture" in reasons[GP_ITEM]


def test_redacted_secrets_become_reentry_pointers(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"),
                {"number": 0, "name": "Corp", "psk": REDACTED},
            ),
        ),
        parser,
    )
    ssid = next(a for a in plan.actions if a.api_path == SSID_ITEM)
    assert ssid.secret_reentry == ("psk",)
    assert "psk" not in ssid.payload  # never write the redaction marker
    assert ssid.payload["name"] == "Corp"


def test_fully_redacted_asset_is_unrestorable(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(FeatureConfiguration(SSID_ITEM, ("N_1", "0"), {"psk": REDACTED})),
        parser,
    )
    (item,) = plan.unrestorable
    assert "sanitized snapshot" in item.reason


def test_unsanitized_secrets_stay_in_the_payload(tmp_path: Path) -> None:
    """Restoring real secret values from the unsanitized snapshot is the
    point of the DR vault copy."""
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"),
                {"number": 0, "name": "Corp", "psk": "hunter2"},
            ),
        ),
        parser,
    )
    ssid = next(a for a in plan.actions if a.api_path == SSID_ITEM)
    assert ssid.payload["psk"] == "hunter2"
    assert ssid.secret_reentry == ()


def test_render_restore_plan_is_bounded_and_value_free(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    features = tuple(
        FeatureConfiguration(
            GP_ITEM, ("N_1", str(i)),
            {"groupPolicyId": str(i), "secretSauce": "s3cr3t"},
        )
        for i in range(40)
    )
    plan = plan_restore(_graph(*features), parser)
    text = render_restore_plan(plan, limit=5)
    assert "s3cr3t" not in text
    assert "more action(s)" in text
    assert plan.summary() in text


def test_action_key_and_operation_fallbacks(tmp_path: Path) -> None:
    """A spec slice without the network/claim endpoints still plans —
    the synthesized operations carry the real operationIds."""
    import json as _json

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "tiny", "version": "1"},
        "paths": {
            SNMP_PATH: {
                "get": _op("getNetworkSnmp", "networks"),
                "put": _op("updateNetworkSnmp", "networks"),
            },
        },
    }
    path = tmp_path / "tiny-spec.json"
    path.write_text(_json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    plan = plan_restore(_graph(), parser)
    create = next(a for a in plan.actions if a.kind == "create")
    claim = next(a for a in plan.actions if a.kind == "claim")
    assert create.operation.operation_id == "createOrganizationNetwork"
    assert claim.operation.operation_id == "claimNetworkDevices"
    assert create.key == "/organizations/{organizationId}/networks::N_1"


def test_render_restore_plan_lists_and_bounds_unrestorable(
    tmp_path: Path,
) -> None:
    parser = _restore_spec(tmp_path)
    features = tuple(
        FeatureConfiguration(CLIENTS_PATH, (f"N_{i}",), {"usage": 1})
        for i in range(10)
    )
    plan = plan_restore(_graph(*features), parser)
    text = render_restore_plan(plan, limit=3)
    assert "UNRESTORABLE" in text
    assert "more unrestorable" in text
