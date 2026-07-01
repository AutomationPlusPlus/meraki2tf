"""OpenApiParser: dynamic Terraform mapping derived from a mock spec fixture."""

import json
from pathlib import Path

import pytest

from meraki2tf.openapi_parser import (
    OpenApiParser,
    TerraformResourceMapping,
    entity_key,
    is_item_path,
    snake_case,
)
from meraki2tf.spec.engine import MalformedSpecError


def _op(operation_id: str, *tags: str) -> dict[str, object]:
    return {"operationId": operation_id, "tags": list(tags)}


# Minimized fixture mirroring real Meraki OpenAPI structure: a top-level
# organization entity, networks listed under organizations but addressed
# top-level, a deeply nested VLAN entity, a camelCase singleton config,
# and an action-only RPC endpoint that must not become a resource.
MOCK_SPEC = {
    "openapi": "3.0.1",
    "paths": {
        "/organizations": {
            "get": _op("getOrganizations", "organizations"),
            "post": _op("createOrganization", "organizations"),
        },
        "/organizations/{organizationId}": {
            "get": _op("getOrganization", "organizations"),
            "put": _op("updateOrganization", "organizations"),
            "delete": _op("deleteOrganization", "organizations"),
        },
        "/organizations/{organizationId}/networks": {
            "get": _op("getOrganizationNetworks", "networks"),
            "post": _op("createOrganizationNetwork", "networks"),
        },
        "/networks/{networkId}": {
            "get": _op("getNetwork", "networks"),
            "put": _op("updateNetwork", "networks"),
            "delete": _op("deleteNetwork", "networks"),
        },
        "/networks/{networkId}/appliance/vlans": {
            "get": _op("getNetworkApplianceVlans", "vlans"),
            "post": _op("createNetworkApplianceVlan", "vlans"),
        },
        "/networks/{networkId}/appliance/vlans/{vlanId}": {
            "get": _op("getNetworkApplianceVlan", "vlans"),
            "put": _op("updateNetworkApplianceVlan", "vlans"),
            "delete": _op("deleteNetworkApplianceVlan", "vlans"),
        },
        "/networks/{networkId}/appliance/trafficShaping": {
            "get": _op("getNetworkApplianceTrafficShaping", "trafficShaping"),
            "put": _op("updateNetworkApplianceTrafficShaping", "trafficShaping"),
        },
        "/devices/{serial}/blinkLeds": {
            "post": _op("blinkDeviceLeds", "devices"),
        },
    },
}


@pytest.fixture()
def parser(tmp_path: Path) -> OpenApiParser:
    spec_path = tmp_path / "openapi.json"
    spec_path.write_text(json.dumps(MOCK_SPEC), encoding="utf-8")
    return OpenApiParser(spec_path)


def test_all_endpoints_are_discovered(parser: OpenApiParser) -> None:
    endpoints = parser.endpoints()
    assert len(endpoints) == 18
    gets = [op for op in endpoints if op.method == "get"]
    assert {op.operation_id for op in gets} == {
        "getOrganizations",
        "getOrganization",
        "getOrganizationNetworks",
        "getNetwork",
        "getNetworkApplianceVlans",
        "getNetworkApplianceVlan",
        "getNetworkApplianceTrafficShaping",
    }


def test_org_scoped_collection_maps_to_canonical_networks_resource(
    parser: OpenApiParser,
) -> None:
    """/organizations/{organizationId}/networks must resolve to meraki_networks."""
    lookup = parser.endpoint_lookup()
    assert lookup["/organizations/{organizationId}/networks"] == "meraki_networks"
    assert lookup["/networks/{networkId}"] == "meraki_networks"

    networks = parser.resource_mappings()["meraki_networks"]
    assert networks.entity_key == ("networks",)
    assert networks.import_id_format == "network_id"
    assert set(networks.paths) == {
        "/networks/{networkId}",
        "/organizations/{organizationId}/networks",
    }


def test_top_level_entity_mapping(parser: OpenApiParser) -> None:
    orgs = parser.resource_mappings()["meraki_organizations"]
    assert orgs.id_components == ("organization_id",)
    assert orgs.import_id_format == "organization_id"
    assert set(orgs.paths) == {"/organizations", "/organizations/{organizationId}"}
    assert {op.method for op in orgs.operations} == {"get", "post", "put", "delete"}


def test_deep_entity_builds_composite_import_id(parser: OpenApiParser) -> None:
    vlans = parser.resource_mappings()["meraki_networks_appliance_vlans"]
    assert vlans.id_components == ("network_id", "vlan_id")
    assert vlans.import_id_format == "network_id,vlan_id"
    assert vlans.entity_key == ("networks", "appliance", "vlans")


def test_camelcase_singleton_config_becomes_snake_case_resource(
    parser: OpenApiParser,
) -> None:
    """A singleton config path has no item endpoint yet is its own resource."""
    mapping = parser.resource_mappings()["meraki_networks_appliance_traffic_shaping"]
    assert mapping.paths == ("/networks/{networkId}/appliance/trafficShaping",)
    assert mapping.import_id_format == "network_id"


def test_action_only_endpoints_are_not_resources(parser: OpenApiParser) -> None:
    mappings = parser.resource_mappings()
    assert not any("blink" in name for name in mappings)
    assert "/devices/{serial}/blinkLeds" not in parser.endpoint_lookup()


def test_lookup_table_is_fully_derived(parser: OpenApiParser) -> None:
    """Every mapped path traces back to a discovered endpoint — nothing injected."""
    discovered_paths = {op.path for op in parser.endpoints()}
    lookup = parser.endpoint_lookup()
    assert set(lookup) <= discovered_paths
    assert all(name.startswith("meraki_") for name in lookup.values())
    assert isinstance(
        parser.resource_mappings()["meraki_networks"], TerraformResourceMapping
    )


def test_parser_propagates_malformed_spec_errors(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(MalformedSpecError):
        OpenApiParser(bad)


def test_snake_case_helper() -> None:
    assert snake_case("trafficShaping") == "traffic_shaping"
    assert snake_case("organizationId") == "organization_id"
    assert snake_case("serial") == "serial"


def test_path_helpers() -> None:
    assert entity_key("/networks/{networkId}/appliance/vlans/{vlanId}") == (
        "networks",
        "appliance",
        "vlans",
    )
    assert is_item_path("/networks/{networkId}")
    assert not is_item_path("/organizations")
    assert not is_item_path("/networks/{networkId}/appliance/vlans")
