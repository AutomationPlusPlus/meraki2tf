"""Heal planner and executor: same-org additive-only partial recovery."""

import json
from pathlib import Path
from types import SimpleNamespace

from conftest import _op

from meraki2tf.healer import live_asset_keys, plan_heal
from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser

GP_ITEM = "/networks/{networkId}/groupPolicies/{groupPolicyId}"
VLAN_ITEM = "/networks/{networkId}/appliance/vlans/{vlanId}"
SNMP_PATH = "/networks/{networkId}/snmp"
#: Adaptive-policy-style class: captured at its collection, but the
#: only update writer lives on the item path — plan_restore synthesizes
#: the item-path action key for it.
APG_COLLECTION = "/networks/{networkId}/adaptivePolicy/groups"
APG_ITEM = "/networks/{networkId}/adaptivePolicy/groups/{groupId}"


def _heal_spec(tmp_path: Path) -> OpenApiParser:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "heal", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            "/networks/{networkId}/groupPolicies": {
                "get": _op("getNetworkGroupPolicies", "networks"),
                "post": _op("createNetworkGroupPolicy", "networks"),
            },
            GP_ITEM: {
                "get": _op("getNetworkGroupPolicy", "networks"),
                "put": _op("updateNetworkGroupPolicy", "networks"),
            },
            VLAN_ITEM: {
                "get": _op("getNetworkApplianceVlan", "appliance"),
                "put": _op("updateNetworkApplianceVlan", "appliance"),
            },
            SNMP_PATH: {
                "get": _op("getNetworkSnmp", "networks"),
                "put": _op("updateNetworkSnmp", "networks"),
            },
            APG_COLLECTION: {
                "get": _op("getNetworkAdaptivePolicyGroups", "networks"),
                "post": _op("createNetworkAdaptivePolicyGroup", "networks"),
            },
            APG_ITEM: {
                "put": _op("updateNetworkAdaptivePolicyGroup", "networks"),
            },
        },
    }
    path = tmp_path / "heal-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def _network(net_id: str, name: str) -> MerakiNetwork:
    return MerakiNetwork.from_payload(
        {"id": net_id, "organizationId": "org-123", "name": name,
         "productTypes": ["appliance"], "timeZone": "UTC"}
    )


def _snapshot() -> NetworkGraph:
    """Two networks; N_1 carries a group policy and a VLAN that
    references it, N_2 carries only its SNMP singleton."""
    return NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"), _network("N_2", "Branch")),
        devices=(),
        features=(
            FeatureConfiguration(
                GP_ITEM, ("N_1", "100"),
                {"groupPolicyId": "100", "name": "gp"},
            ),
            FeatureConfiguration(
                VLAN_ITEM, ("N_1", "10"),
                {"id": "10", "groupPolicyId": "100", "subnet": "10.0.0.0/24"},
            ),
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
            FeatureConfiguration(SNMP_PATH, ("N_2",), {"access": "none"}),
        ),
    )


def _live_after_accident() -> NetworkGraph:
    """N_2 was deleted entirely; N_1 survived but lost its VLAN."""
    return NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(),
        features=(
            FeatureConfiguration(
                GP_ITEM, ("N_1", "100"),
                {"groupPolicyId": "100", "name": "gp"},
            ),
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
        ),
    )


def test_plan_heal_classifies_missing_vs_surviving(tmp_path: Path) -> None:
    plan = plan_heal(_snapshot(), _live_after_accident(), _heal_spec(tmp_path))
    missing = {a.key for a in plan.missing.actions}
    assert missing == {
        "/organizations/{organizationId}/networks::N_2",  # deleted network
        f"{VLAN_ITEM}::N_1,10",  # deleted leaf under a surviving parent
        f"{SNMP_PATH}::N_2",  # child of the deleted network
    }
    # Survivors: N_1's create, its group policy, its SNMP singleton.
    assert plan.surviving_count == 3
    assert plan.snapshot_asset_count == 6
    # Identity mappings cover every surviving created object.
    assert ("network", "N_1", "N_1", ()) in plan.identity_mappings
    assert ("grouppolicy", "100", "100", ("N_1",)) in plan.identity_mappings
    assert "untouched" in plan.summary()


def test_live_asset_keys_mirror_plan_key_shapes(tmp_path: Path) -> None:
    live = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1",
                 "model": "MX68", "name": "edge"}
            ),
        ),
        features=(
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
        ),
    )
    keys = live_asset_keys(live, _heal_spec(tmp_path))
    assert "/organizations/{organizationId}/networks::N_1" in keys
    assert "/networks/{networkId}/devices/claim::N_1,Q2AB-CDEF-GHIJ" in keys
    assert f"{SNMP_PATH}::N_1" in keys


def test_surviving_synthesized_item_path_asset_is_never_missing(
    tmp_path: Path,
) -> None:
    """Additive-only regression guard for the item-path rewrite.

    plan_restore rewrites adaptive-policy-style features onto a
    synthesized ITEM path (key ``.../groups/{groupId}::N_1,7``) while
    live discovery captures them at their COLLECTION path. A hand-built
    live-key mirror missed that rewrite, so the surviving object's key
    never matched, it classified as missing, and heal would re-create —
    or adopt-and-align, i.e. modify — a survivor."""
    parser = _heal_spec(tmp_path)
    apg = FeatureConfiguration(
        APG_COLLECTION, ("N_1",), {"groupId": "7", "name": "employees"}
    )
    snapshot = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(),
        features=(apg,),
    )
    live = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(),
        features=(apg,),
    )
    plan = plan_heal(snapshot, live, parser)
    assert plan.missing.actions == ()
    assert plan.surviving_count == plan.snapshot_asset_count


def test_heal_executor_recreates_only_missing_with_identity_refs(
    tmp_path: Path,
) -> None:
    """The executor must (a) never dispatch survivors, (b) write into
    the surviving parent under its ORIGINAL id — resolve_scope raises
    ForeignScopeError for unmapped network scopes, so this only works
    through the identity mappings — and (c) rewire the deleted
    network's children to its new server-assigned id."""
    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _heal_spec(tmp_path)
    plan = plan_heal(_snapshot(), _live_after_accident(), parser)

    calls: list = []

    class Section:
        def __getattr__(self, operation_id: str):  # noqa: ANN204
            def _dispatch(*args: object, **kwargs: object) -> dict:
                calls.append((operation_id, args, kwargs))
                if operation_id == "createOrganizationNetwork":
                    return {"id": "L_NEW2"}
                return {}

            return _dispatch

    section = Section()
    restorer = OrgRestorer(
        "org-123",
        RestoreJournal(tmp_path / "heal.jsonl"),
        preset_mappings=plan.identity_mappings,
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, appliance=section
    )
    result = restorer.execute(_snapshot(), plan.missing)

    assert result.failed == ()
    ops = [c[0] for c in calls]
    # (a) additive-only: the surviving group policy and N_1's SNMP are
    # never written.
    assert "createNetworkGroupPolicy" not in ops
    assert ops.count("updateNetworkSnmp") == 1
    # (b) the recreated VLAN lands in the SURVIVING network under its
    # original id, with the surviving group-policy reference intact.
    vlan = next(c for c in calls if c[0] == "updateNetworkApplianceVlan")
    assert vlan[1] == ("N_1", "10")
    assert vlan[2]["groupPolicyId"] == "100"
    # (c) the deleted network is recreated and its child rewired to the
    # new server-assigned id.
    snmp = next(c for c in calls if c[0] == "updateNetworkSnmp")
    assert snmp[1] == ("L_NEW2",)


def test_plan_heal_with_nothing_missing_is_empty(tmp_path: Path) -> None:
    snapshot = _snapshot()
    plan = plan_heal(snapshot, snapshot, _heal_spec(tmp_path))
    assert plan.missing.actions == ()
    assert plan.missing.unrestorable == ()
    assert plan.surviving_count == plan.snapshot_asset_count == 6
