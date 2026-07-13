"""Resource matcher: identity fit, word equivalence, scoring, assignment."""

import json
from pathlib import Path
from typing import Any

import pytest

from conftest import fixture_catalog

from meraki2tf.openapi_parser import OpenApiParser, snake_case
from meraki2tf.provider_catalog import ProviderCatalog
from meraki2tf.resource_matcher import (
    MatchedResource,
    _identity_fit,
    _is_subsequence,
    _path_params,
    _same_word,
    _split_words,
    match_resources,
    path_matches,
)

REPO_SPEC = Path(__file__).resolve().parent.parent / "spec3.json"


def _parser(tmp_path: Path, paths: dict[str, Any]) -> OpenApiParser:
    spec = tmp_path / "spec.json"
    spec.write_text(
        json.dumps({"openapi": "3.0.1", "paths": paths}), encoding="utf-8"
    )
    return OpenApiParser(spec)


def _catalog(resources: dict[str, set[str]]) -> ProviderCatalog:
    return ProviderCatalog(
        resources={name: frozenset(attrs) for name, attrs in resources.items()},
        source="test",
    )


def _get_put(operation_id: str) -> dict[str, Any]:
    return {
        "get": {"operationId": f"get{operation_id}", "tags": ["test"]},
        "put": {"operationId": f"update{operation_id}", "tags": ["test"]},
    }


# ---------------------------------------------------------------- word logic


def test_camel_splitting_handles_acronyms_and_digits() -> None:
    assert _split_words("thirdPartyVPNPeers") == ["third", "party", "vpn", "peers"]
    assert _split_words("hotspot20") == ["hotspot", "20"]
    assert _split_words("l3FirewallRules") == ["l3", "firewall", "rules"]
    assert _split_words("trafficShaping") == ["traffic", "shaping"]


@pytest.mark.parametrize(
    "a, b",
    [
        ("licenses", "license"),
        ("statuses", "status"),
        ("policies", "policy"),
        ("ssids", "ssid"),
        ("settings", "settings"),
    ],
)
def test_variant_equivalence_matches_plural_forms(a: str, b: str) -> None:
    assert _same_word(a, b)
    assert _same_word(b, a)


def test_variant_equivalence_rejects_unrelated_words() -> None:
    assert not _same_word("network", "networking")
    assert not _same_word("vlan", "vpn")


def test_subsequence_requires_order() -> None:
    assert _is_subsequence(["one", "to", "many"], ["one", "to", "many", "nat"])
    assert not _is_subsequence(["one", "to", "one"], ["one", "to", "many"])


def test_path_params_use_the_parsers_snake_case_tokenizer() -> None:
    """The generator's import-ID guard compares the matcher's expected
    components against provided ones it derives with the parser's
    ``snake_case``; both sides must share the one tokenizer, or a
    digit-boundary parameter like ``{hotspot20RuleId}`` would tokenize
    differently and falsely mark every asset of its entity unsupported."""
    path = "/networks/{networkId}/wireless/rules/{hotspot20RuleId}"
    provided = tuple(
        snake_case(name) for name in ("networkId", "hotspot20RuleId")
    )
    assert _path_params(path) == provided
    # today's spec params are unaffected by the unification
    assert _path_params(
        "/networks/{networkId}/appliance/vlans/{vlanId}"
    ) == ("network_id", "vlan_id")
    assert _path_params("/devices/{serial}") == ("serial",)


# -------------------------------------------------------------- identity fit


def test_identity_fit_consumes_scope_then_item() -> None:
    assert _identity_fit(
        frozenset({"id", "network_id"}), ("network_id", "vlan_id")
    ) == (True, False)
    assert _identity_fit(
        frozenset({"network_id", "number"}), ("network_id", "number")
    ) == (True, False)
    # blob resources import by their scope alone
    assert _identity_fit(frozenset({"network_id"}), ("network_id",)) == (
        True,
        False,
    )


def test_identity_fit_injects_only_the_organization_id() -> None:
    # meraki_network: /networks/{networkId} + identity {id, organization_id}
    assert _identity_fit(
        frozenset({"id", "organization_id"}), ("network_id",)
    ) == (True, True)
    # an unrelated leftover scope attr is not injectable
    assert _identity_fit(
        frozenset({"id", "network_id"}), ("organization_id",)
    ) == (False, False)


def test_identity_fit_rejects_bulk_variants_and_misfits() -> None:
    assert _identity_fit(
        frozenset({"item_ids", "network_id", "organization_id"}), ("network_id",)
    ) == (False, False)
    assert _identity_fit(frozenset({"network_id"}), ()) == (False, False)
    # scope param missing from the identity
    assert _identity_fit(
        frozenset({"id"}), ("network_id", "vlan_id")
    ) == (False, False)
    # two non-scope attrs and no generic id: unconsumable trailing param
    assert _identity_fit(
        frozenset({"number", "port_id"}), ("network_id",)
    ) == (False, False)


def test_identity_fit_force_delete_is_transparent() -> None:
    assert _identity_fit(
        frozenset({"force_delete", "id", "network_id"}),
        ("network_id", "group_policy_id"),
    ) == (True, False)


# ------------------------------------------------------- matching + scoring


def test_coverage_beats_scope_generic_names(tmp_path: Path) -> None:
    """meraki_switch_settings must win /switch/settings even though
    meraki_network_settings also fits the identity."""
    parser = _parser(
        tmp_path,
        {
            "/networks/{networkId}/settings": _get_put("NetworkSettings"),
            "/networks/{networkId}/switch/settings": _get_put("SwitchSettings"),
        },
    )
    catalog = _catalog(
        {
            "meraki_network_settings": {"network_id"},
            "meraki_switch_settings": {"network_id"},
        }
    )
    matches = match_resources(parser, catalog)
    by_name = {
        match.terraform_name
        for match in matches.values()
        if match is not None
    }
    assert by_name == {"meraki_network_settings", "meraki_switch_settings"}
    assert (
        matches[("networks", "switch", "settings")].terraform_name
        == "meraki_switch_settings"
    )


def test_ordered_subsequence_separates_one_to_many_from_one_to_one(
    tmp_path: Path,
) -> None:
    parser = _parser(
        tmp_path,
        {
            "/networks/{networkId}/appliance/firewall/oneToManyNatRules":
                _get_put("OneToMany"),
            "/networks/{networkId}/appliance/firewall/oneToOneNatRules":
                _get_put("OneToOne"),
        },
    )
    catalog = _catalog(
        {
            "meraki_appliance_one_to_many_nat_rules": {"network_id"},
            "meraki_appliance_one_to_one_nat_rules": {"network_id"},
        }
    )
    matches = match_resources(parser, catalog)
    assert (
        matches[("networks", "appliance", "firewall", "one_to_many_nat_rules")]
        .terraform_name
        == "meraki_appliance_one_to_many_nat_rules"
    )
    assert (
        matches[("networks", "appliance", "firewall", "one_to_one_nat_rules")]
        .terraform_name
        == "meraki_appliance_one_to_one_nat_rules"
    )


def test_greedy_assignment_keeps_the_best_fitting_entity(
    tmp_path: Path,
) -> None:
    """staged/events (no provider resource) must not steal the blob
    resource from the real firmwareUpgrades entity."""
    parser = _parser(
        tmp_path,
        {
            "/networks/{networkId}/firmwareUpgrades": _get_put("Fw"),
            "/networks/{networkId}/firmwareUpgrades/staged/events":
                _get_put("FwStagedEvents"),
        },
    )
    catalog = _catalog({"meraki_network_firmware_upgrades": {"network_id"}})
    matches = match_resources(parser, catalog)
    assert (
        matches[("networks", "firmware_upgrades")].terraform_name
        == "meraki_network_firmware_upgrades"
    )
    assert matches[("networks", "firmware_upgrades", "staged", "events")] is None


def test_unresolvable_tie_maps_to_none(tmp_path: Path) -> None:
    """Two equal-confidence resources for one entity: report a gap, do
    not guess."""
    parser = _parser(
        tmp_path,
        {"/networks/{networkId}/wireless/alpha/gamma": _get_put("AlphaGamma")},
    )
    catalog = _catalog(
        {
            # symmetric candidates: equal coverage, order, and length
            "meraki_alpha_wireless": {"network_id"},
            "meraki_gamma_wireless": {"network_id"},
        }
    )
    matches = match_resources(parser, catalog)
    assert matches[("networks", "wireless", "alpha", "gamma")] is None


def test_telemetry_entities_are_not_matched(tmp_path: Path) -> None:
    parser = _parser(
        tmp_path,
        {
            "/networks/{networkId}/clients": {
                "get": {"operationId": "getClients", "tags": ["test"]}
            },
            "/networks/{networkId}/settings": _get_put("Settings"),
        },
    )
    catalog = _catalog({"meraki_network_settings": {"network_id"}})
    matches = match_resources(parser, catalog)
    assert ("networks", "clients") not in matches
    assert ("networks", "settings") in matches


def test_path_matches_covers_folded_aliases(
    spec_parser: OpenApiParser,
) -> None:
    lookup = path_matches(spec_parser, fixture_catalog())
    network = lookup["/networks/{networkId}"]
    assert network is not None
    assert network.terraform_name == "meraki_network"
    assert network.needs_org_prefix is True
    assert network.import_id_components == ("network_id",)
    # the folded org-scoped collection alias resolves to the same match
    assert lookup["/organizations/{organizationId}/networks"] is network
    vlan = lookup["/networks/{networkId}/appliance/vlans/{vlanId}"]
    assert vlan is not None
    assert vlan.terraform_name == "meraki_appliance_vlan"
    assert vlan.import_id_components == ("network_id", "vlan_id")


# ------------------------------------------------- real-spec validation run


@pytest.mark.skipif(not REPO_SPEC.exists(), reason="repo spec3.json not present")
def test_bundled_catalog_matches_the_real_spec() -> None:
    """Integration-grade validation against the real Meraki OpenAPI spec
    and the bundled v1.12.2 identity schemas (the ground truth this
    matcher was tuned on: 149 verified pairs, 0 wrong, 0 collisions)."""
    parser = OpenApiParser(REPO_SPEC)
    catalog = ProviderCatalog.bundled()
    matches = match_resources(parser, catalog)
    matched = {
        key: match for key, match in matches.items() if match is not None
    }
    assert len(matched) >= 149
    names = [match.terraform_name for match in matched.values()]
    assert len(names) == len(set(names))  # one-to-one, no collisions

    lookup = path_matches(parser, catalog)

    def resolved(path: str) -> MatchedResource:
        match = lookup[path]
        assert match is not None, path
        return match

    spot_checks = {
        "/networks/{networkId}/appliance/vlans/{vlanId}":
            "meraki_appliance_vlan",
        "/networks/{networkId}/wireless/ssids/{number}": "meraki_wireless_ssid",
        "/networks/{networkId}/groupPolicies/{groupPolicyId}":
            "meraki_network_group_policy",
        "/networks/{networkId}/appliance/firewall/cellularFirewallRules":
            "meraki_appliance_cellular_firewall_rules",
        "/organizations/{organizationId}/appliance/dns/local/records/{recordId}":
            "meraki_appliance_dns_local_record",
        "/networks/{networkId}/sensor/mqttBrokers/{mqttBrokerId}":
            "meraki_sensor_mqtt_broker",
        "/networks/{networkId}/switch/settings": "meraki_switch_settings",
        "/organizations/{organizationId}/appliance/vpn/thirdPartyVPNPeers":
            "meraki_appliance_third_party_vpn_peers",
        "/networks/{networkId}/wireless/ssids/{number}/hotspot20":
            "meraki_wireless_ssid_hotspot_20",
        "/organizations/{organizationId}/licenses/{licenseId}":
            "meraki_organization_license",
    }
    for path, expected in spot_checks.items():
        assert resolved(path).terraform_name == expected

    group_policy = resolved("/networks/{networkId}/groupPolicies/{groupPolicyId}")
    assert group_policy.has_force_delete is True
    network = resolved("/networks/{networkId}")
    assert network.terraform_name == "meraki_network"
    assert network.needs_org_prefix is True
    device = resolved("/devices/{serial}")
    assert device.terraform_name == "meraki_device"
    assert device.needs_org_prefix is False
