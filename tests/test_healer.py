"""Heal planner and executor: same-org additive-only partial recovery."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import _op

from meraki2tf.healer import (
    HealFilterError,
    filter_heal_plan,
    live_asset_keys,
    plan_heal,
)
from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser

GP_ITEM = "/networks/{networkId}/groupPolicies/{groupPolicyId}"
VLAN_ITEM = "/networks/{networkId}/appliance/vlans/{vlanId}"
SNMP_PATH = "/networks/{networkId}/snmp"
SSID_ITEM = "/networks/{networkId}/wireless/ssids/{number}"
SPLASH_PATH = "/networks/{networkId}/wireless/ssids/{number}/splash/settings"
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
            SSID_ITEM: {
                "get": _op("getNetworkWirelessSsid", "wireless"),
                "put": _op("updateNetworkWirelessSsid", "wireless"),
            },
            SPLASH_PATH: {
                "get": _op("getNetworkWirelessSsidSplashSettings", "wireless"),
                "put": _op(
                    "updateNetworkWirelessSsidSplashSettings", "wireless"
                ),
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


def test_live_default_state_protects_survivor_from_heal(
    tmp_path: Path,
) -> None:
    """A live empty capture means the object exists at Meraki defaults.
    Its key must count as alive — otherwise the snapshot-configured
    counterpart classifies as missing and heal would MODIFY a survivor,
    violating additive-only."""
    snapshot = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(),
        features=(
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
        ),
    )
    live = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(),
        features=(FeatureConfiguration(SNMP_PATH, ("N_1",), {}),),
    )
    plan = plan_heal(snapshot, live, _heal_spec(tmp_path))
    assert plan.missing.actions == ()
    assert plan.surviving_count == plan.snapshot_asset_count == 2


def test_missing_defaults_are_accounted_not_recreated(
    tmp_path: Path,
) -> None:
    """A snapshot asset captured at defaults whose parent vanished has
    nothing to write, but the accounting must still surface it."""
    snapshot = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"), _network("N_2", "Branch")),
        devices=(),
        features=(FeatureConfiguration(SNMP_PATH, ("N_2",), {}),),
    )
    live = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(),
        features=(),
    )
    plan = plan_heal(snapshot, live, _heal_spec(tmp_path))
    assert [a.kind for a in plan.missing.actions] == ["create"]  # N_2 itself
    assert [d.api_path for d in plan.missing.defaults] == [SNMP_PATH]
    assert "1 missing asset(s) were at Meraki defaults" in plan.summary()

# ---------------------------------------------------------------------------
# Selective heal: filter_heal_plan (--only).
# ---------------------------------------------------------------------------


def _org(networks: tuple, features: tuple) -> NetworkGraph:
    return NetworkGraph(
        organization_id="org-123", networks=networks, devices=(),
        features=features,
    )


_EMPTY_LIVE = _org((), ())


def test_only_network_selects_its_subtree_and_nothing_else(
    tmp_path: Path,
) -> None:
    """Two deleted networks, one selected: the selection is the named
    network plus its own missing children — the other network and every
    child of it stays out, and nothing needed auto-inclusion."""
    plan = plan_heal(_snapshot(), _EMPTY_LIVE, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("network:Branch",))
    assert {a.key for a in selection.plan.missing.actions} == {
        "/organizations/{organizationId}/networks::N_2",
        f"{SNMP_PATH}::N_2",
    }
    assert selection.auto_included == ()
    assert selection.selector_matches == (("network:Branch", 1),)
    assert selection.excluded_actions == 4
    # The original plan is untouched (purely subtractive filtering).
    assert len(plan.missing.actions) == 6
    assert selection.plan.identity_mappings == plan.identity_mappings
    assert selection.plan.surviving_count == plan.surviving_count


def test_only_ssid_selects_nested_surfaces_not_cross_network_twins(
    tmp_path: Path,
) -> None:
    """Partial SSID recovery: the named SSID and its nested splash join;
    the OTHER deleted SSIDs — including the same slot number in another
    network — stay out (the resolver's scoped-containment rule)."""
    snapshot = _org(
        (_network("N_1", "HQ"), _network("N_2", "Branch")),
        (
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"), {"number": "0", "name": "Guest"}
            ),
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "1"), {"number": "1", "name": "Corp"}
            ),
            FeatureConfiguration(
                SSID_ITEM, ("N_2", "0"), {"number": "0", "name": "Lobby"}
            ),
            FeatureConfiguration(
                SPLASH_PATH, ("N_1", "0"), {"splashPage": "Click-through"}
            ),
            FeatureConfiguration(
                SPLASH_PATH, ("N_2", "0"), {"splashPage": "Click-through"}
            ),
        ),
    )
    live = _org((_network("N_1", "HQ"), _network("N_2", "Branch")), ())
    plan = plan_heal(snapshot, live, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("ssid:Guest",))
    assert {a.key for a in selection.plan.missing.actions} == {
        f"{SSID_ITEM}::N_1,0",
        f"{SPLASH_PATH}::N_1,0",
    }
    assert selection.auto_included == ()


def test_only_auto_includes_deleted_parent_without_its_subtree(
    tmp_path: Path,
) -> None:
    """Selecting an SSID whose network was ALSO deleted pulls the
    network in (the write needs a parent to land in) — but the parent's
    other children are not dragged along."""
    snapshot = _org(
        (_network("N_2", "Branch"),),
        (
            FeatureConfiguration(
                SSID_ITEM, ("N_2", "0"), {"number": "0", "name": "Guest"}
            ),
            FeatureConfiguration(SNMP_PATH, ("N_2",), {"access": "none"}),
        ),
    )
    plan = plan_heal(snapshot, _EMPTY_LIVE, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("ssid:Guest",))
    network_key = "/organizations/{organizationId}/networks::N_2"
    assert {a.key for a in selection.plan.missing.actions} == {
        f"{SSID_ITEM}::N_2,0",
        network_key,
    }
    assert selection.auto_included == (network_key,)


def test_only_auto_includes_referenced_missing_object(
    tmp_path: Path,
) -> None:
    """A selected VLAN referencing a missing group policy pulls the
    policy in — dispatching the reference unresolved would fail."""
    plan = plan_heal(
        _snapshot(), _live_after_accident(), _heal_spec(tmp_path)
    )
    # Missing: N_2 create, its SNMP, and N_1's VLAN. Live N_1 kept its
    # group policy, so start from a variant where the policy is gone too.
    live = _org((_network("N_1", "HQ"),), ())
    plan = plan_heal(_snapshot(), live, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("vlan:10",))
    assert {a.key for a in selection.plan.missing.actions} == {
        f"{VLAN_ITEM}::N_1,10",
        f"{GP_ITEM}::N_1,100",
    }
    assert selection.auto_included == (f"{GP_ITEM}::N_1,100",)


def test_only_flat_reference_needs_a_unique_missing_owner(
    tmp_path: Path,
) -> None:
    """Bare id/ids references carry no type: a value owned by exactly
    one missing object auto-includes it; an ambiguous value (the same
    slot number in two networks) is never guessed."""
    linked = "/networks/{networkId}/linked"
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "flat", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            GP_ITEM: {
                "get": _op("getNetworkGroupPolicy", "networks"),
                "put": _op("updateNetworkGroupPolicy", "networks"),
            },
            SSID_ITEM: {
                "get": _op("getNetworkWirelessSsid", "wireless"),
                "put": _op("updateNetworkWirelessSsid", "wireless"),
            },
            linked: {
                "get": _op("getNetworkLinked", "networks"),
                "put": _op("updateNetworkLinked", "networks"),
            },
        },
    }
    path = tmp_path / "flat-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    snapshot = _org(
        (_network("N_1", "HQ"), _network("N_2", "Branch")),
        (
            FeatureConfiguration(
                linked, ("N_1",), {"ids": ["77", "0"]}
            ),
            FeatureConfiguration(
                GP_ITEM, ("N_1", "77"), {"groupPolicyId": "77", "name": "gp"}
            ),
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"), {"number": "0", "name": "A"}
            ),
            FeatureConfiguration(
                SSID_ITEM, ("N_2", "0"), {"number": "0", "name": "B"}
            ),
        ),
    )
    live = _org((_network("N_1", "HQ"), _network("N_2", "Branch")), ())
    plan = plan_heal(snapshot, live, parser)
    selection = filter_heal_plan(plan, ("linked:*",))
    keys = {a.key for a in selection.plan.missing.actions}
    assert f"{linked}::N_1" in keys
    assert f"{GP_ITEM}::N_1,77" in keys  # unique flat owner: included
    assert not any("ssids" in key for key in keys)  # ambiguous: never


def test_only_zero_match_raises_and_names_whats_available(
    tmp_path: Path,
) -> None:
    plan = plan_heal(_snapshot(), _EMPTY_LIVE, _heal_spec(tmp_path))
    with pytest.raises(HealFilterError) as excinfo:
        filter_heal_plan(plan, ("network:Branch", "network:Nope"))
    message = str(excinfo.value)
    assert "'network:Nope'" in message
    assert "matched no missing object" in message
    assert "network:HQ" in message  # named by natural identity
    assert "snmp:N_1" in message  # no natural key: named by own ID


def test_only_zero_match_message_truncates_and_handles_empty(
    tmp_path: Path,
) -> None:
    networks = tuple(
        _network(f"N_{i}", f"Site-{i:02d}") for i in range(17)
    )
    plan = plan_heal(_org(networks, ()), _EMPTY_LIVE, _heal_spec(tmp_path))
    with pytest.raises(HealFilterError) as excinfo:
        filter_heal_plan(plan, ("nope",))
    assert "… and 2 more" in str(excinfo.value)

    snapshot = _snapshot()
    empty = plan_heal(snapshot, snapshot, _heal_spec(tmp_path))
    with pytest.raises(HealFilterError) as excinfo:
        filter_heal_plan(empty, ("anything",))
    assert "<none>" in str(excinfo.value)


def test_only_empty_selector_raises(tmp_path: Path) -> None:
    plan = plan_heal(_snapshot(), _EMPTY_LIVE, _heal_spec(tmp_path))
    with pytest.raises(HealFilterError, match="empty selector"):
        filter_heal_plan(plan, ("  ",))


def test_only_grammar_bare_case_plural_and_dedupe(tmp_path: Path) -> None:
    plan = plan_heal(_snapshot(), _EMPTY_LIVE, _heal_spec(tmp_path))
    # Bare glob (no TYPE), case-insensitive.
    bare = filter_heal_plan(plan, ("branch",))
    assert any(
        a.key.endswith("::N_2") for a in bare.plan.missing.actions
    )
    # Plural/singular and case both normalize on the TYPE side too.
    typed = filter_heal_plan(plan, ("NETWORKS:BR*",))
    assert {a.key for a in typed.plan.missing.actions} == {
        a.key for a in bare.plan.missing.actions
    }
    plural = filter_heal_plan(plan, ("groupPolicies:gp",))
    assert any(
        a.api_path == GP_ITEM for a in plural.plan.missing.actions
    )
    # Duplicate selectors collapse to one reported entry.
    deduped = filter_heal_plan(plan, ("branch", "branch"))
    assert len(deduped.selector_matches) == 1


def test_only_colon_in_name_falls_back_to_bare_glob(
    tmp_path: Path,
) -> None:
    snapshot = _org((_network("N_9", "Guest:Floor2"),), ())
    plan = plan_heal(snapshot, _EMPTY_LIVE, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("Guest:Floor2",))
    assert len(selection.plan.missing.actions) == 1


def test_only_union_of_selectors_and_match_counts(tmp_path: Path) -> None:
    plan = plan_heal(_snapshot(), _EMPTY_LIVE, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("network:HQ", "network:Branch"))
    keys = {a.key for a in selection.plan.missing.actions}
    assert "/organizations/{organizationId}/networks::N_1" in keys
    assert "/organizations/{organizationId}/networks::N_2" in keys
    assert selection.selector_matches == (
        ("network:HQ", 1), ("network:Branch", 1),
    )


def test_only_scopes_unrestorable_and_defaults_reporting(
    tmp_path: Path,
) -> None:
    """Unrestorable and at-defaults assets follow the operator's
    selection: kept when directly matched or inside a selected
    container, counted as excluded otherwise."""
    snapshot = _org(
        (_network("N_1", "HQ"), _network("N_2", "Branch")),
        (
            FeatureConfiguration(SNMP_PATH, ("N_1",), {}),
            FeatureConfiguration(SNMP_PATH, ("N_2",), {}),
            FeatureConfiguration(
                GP_ITEM, ("N_1", "8"), {UNREADABLE_MARKER: "HTTP 500"}
            ),
            FeatureConfiguration(
                GP_ITEM, ("N_2", "9"), {UNREADABLE_MARKER: "HTTP 500"}
            ),
        ),
    )
    plan = plan_heal(snapshot, _EMPTY_LIVE, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("network:Branch",))
    assert [
        item.path_values for item in selection.plan.missing.unrestorable
    ] == [("N_2", "9")]
    assert [
        entry.path_values for entry in selection.plan.missing.defaults
    ] == [("N_2",)]
    assert selection.excluded_unrestorable == 1
    assert selection.excluded_defaults == 1
    assert selection.excluded_actions == 1  # N_1's create


def test_only_matching_solely_unrestorable_is_not_an_error(
    tmp_path: Path,
) -> None:
    """A selector naming an object the API cannot recreate matched
    SOMETHING — the result is an empty executable selection carrying
    the unrestorable verdict, not a typo error."""
    snapshot = _org(
        (_network("N_1", "HQ"),),
        (
            FeatureConfiguration(
                GP_ITEM, ("N_1", "8"), {UNREADABLE_MARKER: "HTTP 500"}
            ),
        ),
    )
    live = _org((_network("N_1", "HQ"),), ())
    plan = plan_heal(snapshot, live, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("grouppolicy:8",))
    assert selection.plan.missing.actions == ()
    assert len(selection.plan.missing.unrestorable) == 1
    assert selection.selector_matches == (("grouppolicy:8", 1),)


def test_only_helper_edges() -> None:
    """Direct edges of the matching helpers that no realistic plan
    reaches: stemming, placeholder-only paths, reference scavenging."""
    from meraki2tf.healer import (
        _iter_ref_values,
        _payload_refs,
        _pattern_hits,
        _stem_plural,
        _type_stems,
    )

    assert _stem_plural("groupPolicies") == "grouppolicy"
    assert _stem_plural("ssids") == "ssid"
    assert _stem_plural("access") == "access"  # 'ss' is not a plural
    assert _stem_plural("snmp") == "snmp"

    assert _type_stems("/{a}/{b}") == frozenset()
    assert _type_stems("/networks/{networkId}/devices/claim") == {
        "device", "claim",
    }

    assert list(_iter_ref_values(["77", 5, True, {"id": "x"}])) == [
        "77", "5",
    ]

    refs: set = set()
    _payload_refs(
        {"rules": [{"srcCidr": "GRP(100)", "destCidr": "OBJ(obj-1)"}]},
        refs,
    )
    assert ("policyobjectgroup", "100") in refs
    assert ("policyobject", "obj-1") in refs

    import re as _re

    glob = _re.compile(".*")
    assert not _pattern_hits(_re.compile(r"x\Z"), {"name": 5}, "")
    assert _pattern_hits(glob, {}, "N_1")


def test_only_directly_matching_a_defaults_entry_keeps_it(
    tmp_path: Path,
) -> None:
    """An at-defaults asset named by a selector counts as a match (no
    typo error) and stays in the filtered accounting."""
    snapshot = _org(
        (_network("N_1", "HQ"), _network("N_2", "Branch")),
        (
            FeatureConfiguration(SNMP_PATH, ("N_1",), {}),
            FeatureConfiguration(SNMP_PATH, ("N_2",), {}),
        ),
    )
    plan = plan_heal(snapshot, _EMPTY_LIVE, _heal_spec(tmp_path))
    selection = filter_heal_plan(plan, ("network:HQ", "snmp:N_2"))
    assert selection.selector_matches == (
        ("network:HQ", 1), ("snmp:N_2", 1),
    )
    assert {
        entry.path_values for entry in selection.plan.missing.defaults
    } == {("N_1",), ("N_2",)}  # N_1 via scope, N_2 via direct match
    assert selection.excluded_defaults == 0


def test_partial_snapshot_universe_ignores_out_of_scope_live_assets(
    tmp_path: Path,
) -> None:
    """A selective-backup snapshot narrows the heal universe to its own
    assets: live objects outside the scope are never examined, never
    classified, and can never be touched — heal stays additive-only and
    partial-safe by construction."""
    parser = _heal_spec(tmp_path)
    partial_snapshot = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(),
        features=(
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
        ),
    )
    # Live: the scoped network lost its SNMP config; an out-of-scope
    # network N_9 (absent from the snapshot) is thriving.
    live = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"), _network("N_9", "Elsewhere")),
        devices=(),
        features=(
            FeatureConfiguration(SNMP_PATH, ("N_9",), {"access": "users"}),
        ),
    )
    plan = plan_heal(partial_snapshot, live, parser)
    missing_keys = {action.key for action in plan.missing.actions}
    assert missing_keys == {f"{SNMP_PATH}::N_1"}
    assert plan.snapshot_asset_count == 2  # N_1's create + its SNMP
    assert not any("N_9" in key for key in missing_keys)


def test_partial_snapshot_whole_scope_deleted_heals_full_subtree(
    tmp_path: Path,
) -> None:
    """The maximal selective-backup heal: the scoped network itself was
    deleted live — its create and every child come back."""
    parser = _heal_spec(tmp_path)
    partial_snapshot = NetworkGraph(
        organization_id="org-123",
        networks=(_network("N_1", "HQ"),),
        devices=(),
        features=(
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
        ),
    )
    live = NetworkGraph(
        organization_id="org-123", networks=(), devices=(), features=()
    )
    plan = plan_heal(partial_snapshot, live, parser)
    kinds = sorted(
        (action.api_path, action.kind) for action in plan.missing.actions
    )
    assert (
        "/organizations/{organizationId}/networks", "create"
    ) in kinds
    assert (SNMP_PATH, "configure") in kinds
    assert plan.surviving_count == 0
