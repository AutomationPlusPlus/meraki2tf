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


def test_terraform_name_collision_keeps_first_and_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """snake_casing can make distinct entities collide on one provider
    name; silent overwrite would drop the first entity's endpoints."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/networks/{networkId}/trafficShaping": {
                "get": _op("getA", "networks"),
                "put": _op("putA", "networks"),
            },
            "/networks/{networkId}/traffic/shaping": {
                "get": _op("getB", "networks"),
                "put": _op("putB", "networks"),
            },
        },
    }
    path = tmp_path / "colliding.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)

    with caplog.at_level("WARNING", logger="meraki2tf.openapi_parser"):
        mappings = parser.resource_mappings()

    assert any("collision" in record.message for record in caplog.records)
    mapping = mappings["meraki_networks_traffic_shaping"]
    # First in spec order wins; the loser's paths stay out of the lookup
    # so its assets are audited as unsupported instead of mis-imported.
    assert mapping.paths == ("/networks/{networkId}/trafficShaping",)
    assert "/networks/{networkId}/traffic/shaping" not in parser.endpoint_lookup()


# ---------------------------------------------------------------------------
# Aggregation adoption: GET-less mutable entities with an org-level GET
# ---------------------------------------------------------------------------


def _parser_for(spec: dict, tmp_path: Path) -> OpenApiParser:
    path = tmp_path / "agg-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def _agg_schema(*item_properties: str) -> dict:
    return {
        "responses": {
            "200": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    name: {} for name in item_properties
                                },
                            },
                        }
                    }
                }
            }
        }
    }


def test_getless_put_entity_adopts_bynetwork_aggregation_get(
    tmp_path: Path,
) -> None:
    """The Meraki "per-network PUT + org byNetwork GET" pattern (Air
    Marshal, RRM, uplink NAT, ...) must yield a resource mapping whose
    canonical addressing stays network-scoped while the aggregation GET
    becomes the collection source — previously the whole entity class
    silently vanished."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/networks/{networkId}/wireless/zigbee": {
                "put": _op("updateNetworkWirelessZigbee", "wireless"),
            },
            "/organizations/{organizationId}/wireless/zigbee/byNetwork": {
                "get": _op(
                    "getOrganizationWirelessZigbeeByNetwork", "wireless"
                ),
            },
        },
    }
    mappings = _parser_for(spec, tmp_path).resource_mappings()
    mapping = mappings["meraki_networks_wireless_zigbee"]
    assert mapping.paths == ("/networks/{networkId}/wireless/zigbee",)
    assert mapping.id_components == ("network_id",)
    assert mapping.aggregation_get is not None
    assert mapping.aggregation_get.path == (
        "/organizations/{organizationId}/wireless/zigbee/byNetwork"
    )


def test_pipeline_fixture_adopts_air_marshal_settings(
    spec_parser: OpenApiParser,
) -> None:
    mapping = spec_parser.resource_mappings()[
        "meraki_networks_wireless_air_marshal_settings"
    ]
    assert mapping.aggregation_get is not None
    assert mapping.aggregation_get.operation_id == (
        "getOrganizationWirelessAirMarshalSettingsByNetwork"
    )
    # Ordinary GET-backed entities carry no aggregation source.
    vlans = spec_parser.resource_mappings()["meraki_networks_appliance_vlans"]
    assert vlans.aggregation_get is None


def test_same_tail_org_aggregation_adopted_with_scope_identifier(
    tmp_path: Path,
) -> None:
    """campusGateway-clusters shape: no byNetwork suffix, but the org
    GET's response items declare a network identifier, so the entity is
    adopted — including its item path for per-element addressing."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/networks/{networkId}/campusGateway/clusters": {
                "post": _op("createNetworkCampusGatewayCluster", "campusGateway"),
            },
            "/networks/{networkId}/campusGateway/clusters/{clusterId}": {
                "put": _op("updateNetworkCampusGatewayCluster", "campusGateway"),
            },
            "/organizations/{organizationId}/campusGateway/clusters": {
                "get": {
                    **_op("getOrganizationCampusGatewayClusters", "campusGateway"),
                    **_agg_schema("network", "clusterId", "name"),
                },
            },
        },
    }
    mappings = _parser_for(spec, tmp_path).resource_mappings()
    mapping = mappings["meraki_networks_campus_gateway_clusters"]
    assert mapping.aggregation_get is not None
    assert mapping.id_components == ("network_id", "cluster_id")


def test_same_tail_org_aggregation_requires_scope_identifier(
    tmp_path: Path,
) -> None:
    """Without a declared per-network identifier the org GET could be a
    same-named but unrelated surface; the entity must stay unadopted
    (it surfaces via the spec-surface write-only accounting instead)."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/networks/{networkId}/foo/bar": {
                "put": _op("updateNetworkFooBar", "foo"),
            },
            "/organizations/{organizationId}/foo/bar": {
                "get": {
                    **_op("getOrganizationFooBar", "foo"),
                    **_agg_schema("name", "value"),
                },
            },
        },
    }
    mappings = _parser_for(spec, tmp_path).resource_mappings()
    assert "meraki_networks_foo_bar" not in mappings


def test_same_tail_org_aggregation_without_schema_is_not_adopted(
    tmp_path: Path,
) -> None:
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/networks/{networkId}/foo/bar": {
                "put": _op("updateNetworkFooBar", "foo"),
            },
            "/organizations/{organizationId}/foo/bar": {
                "get": _op("getOrganizationFooBar", "foo"),
            },
        },
    }
    mappings = _parser_for(spec, tmp_path).resource_mappings()
    assert "meraki_networks_foo_bar" not in mappings


def test_same_tail_aggregation_with_scalar_items_is_not_adopted(
    tmp_path: Path,
) -> None:
    """An org GET listing bare scalars declares no per-item properties
    at all — nothing to explode, so no adoption."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/networks/{networkId}/foo/bar": {
                "put": _op("updateNetworkFooBar", "foo"),
            },
            "/organizations/{organizationId}/foo/bar": {
                "get": {
                    **_op("getOrganizationFooBar", "foo"),
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    }
                                }
                            }
                        }
                    },
                },
            },
        },
    }
    mappings = _parser_for(spec, tmp_path).resource_mappings()
    assert "meraki_networks_foo_bar" not in mappings


def test_post_only_action_entities_are_never_adopted(tmp_path: Path) -> None:
    """RPC actions (claim, remove, blinkLeds, ...) carry no PUT; even a
    name-matching org GET must not turn them into resources."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/networks/{networkId}/devices/remove": {
                "post": _op("removeNetworkDevices", "networks"),
            },
            "/organizations/{organizationId}/devices/remove/byNetwork": {
                "get": _op("getOrganizationDevicesRemoveByNetwork", "organizations"),
            },
        },
    }
    mappings = _parser_for(spec, tmp_path).resource_mappings()
    assert "meraki_networks_devices_remove" not in mappings


def test_device_scoped_getless_entities_are_not_adopted(
    tmp_path: Path,
) -> None:
    """Only ``networks``-rooted entities follow the byNetwork pattern in
    the published spec; a device-scoped GET-less PUT stays unadopted
    (conservative: under-adoption surfaces as write-only accounting,
    over-adoption would fabricate wrong per-scope assets)."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/devices/{serial}/cellular/geolocations": {
                "put": _op("updateDeviceCellularGeolocations", "cellular"),
            },
            "/organizations/{organizationId}/cellular/geolocations/byNetwork": {
                "get": _op(
                    "getOrganizationCellularGeolocationsByNetwork", "cellular"
                ),
            },
        },
    }
    mappings = _parser_for(spec, tmp_path).resource_mappings()
    assert "meraki_devices_cellular_geolocations" not in mappings


def test_enveloped_aggregation_schema_declares_scope_identifier(
    tmp_path: Path,
) -> None:
    """The {items: [...]} envelope form of the response schema counts
    for the same-tail scope-identifier guard too."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/networks/{networkId}/foo/bar": {
                "put": _op("updateNetworkFooBar", "foo"),
            },
            "/organizations/{organizationId}/foo/bar": {
                "get": {
                    **_op("getOrganizationFooBar", "foo"),
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "items": {
                                                "type": "array",
                                                "items": {
                                                    "type": "object",
                                                    "properties": {
                                                        "networkId": {},
                                                        "value": {},
                                                    },
                                                },
                                            },
                                            "meta": {"type": "object"},
                                        },
                                    }
                                }
                            }
                        }
                    },
                },
            },
        },
    }
    mappings = _parser_for(spec, tmp_path).resource_mappings()
    mapping = mappings["meraki_networks_foo_bar"]
    assert mapping.aggregation_get is not None
