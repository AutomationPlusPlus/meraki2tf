"""Spec-driven feature discovery: endpoint filtering, expansion, matching."""

import json
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers.discovery import (
    FeatureSectionMatcher,
    _collection_id_key,
    aggregation_collection_path,
    aggregation_mappings,
    config_collection_operations,
    element_id,
    expand_endpoint_payload,
    explode_aggregation_payload,
    item_operation_for,
    network_product_types,
    product_segment,
    spec_surface_report,
)


@pytest.fixture()
def parser(spec_file: Path) -> OpenApiParser:
    return OpenApiParser(spec_file)


def _write_spec(tmp_path: Path, paths: dict[str, Any]) -> OpenApiParser:
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"openapi": "3.0.1", "paths": paths}), encoding="utf-8")
    return OpenApiParser(path)


def _get_op(parser: OpenApiParser, path: str) -> Any:
    return next(
        op for op in parser.endpoints() if op.path == path and op.method == "get"
    )


def test_read_only_entities_are_not_configuration(parser: OpenApiParser) -> None:
    """Telemetry like client lists has no mutating verb → not discoverable."""
    paths = {op.path for op in config_collection_operations(parser)}
    assert "/networks/{networkId}/clients" not in paths
    assert "/networks/{networkId}/appliance/vlans" in paths
    assert "/networks/{networkId}/appliance/trafficShaping" in paths


def test_scope_param_selects_organization_endpoints(parser: OpenApiParser) -> None:
    paths = {op.path for op in config_collection_operations(parser, "organizationId")}
    # The networks collection qualifies (mutable via POST) but is a
    # folded alias of the first-class networks entity — consumers skip
    # it (see the live provider's _folds_elsewhere guard).
    assert paths == {
        "/organizations/{organizationId}/admins",
        "/organizations/{organizationId}/networks",
    }


def test_scope_param_selects_device_endpoints(parser: OpenApiParser) -> None:
    paths = {op.path for op in config_collection_operations(parser, "serial")}
    assert paths == {"/devices/{serial}/switch/ports"}


def test_item_operation_prefers_get_then_any_mutating_verb(
    parser: OpenApiParser,
) -> None:
    vlans = _get_op(parser, "/networks/{networkId}/appliance/vlans")
    assert item_operation_for(parser, vlans).method == "get"

    admins = _get_op(parser, "/organizations/{organizationId}/admins")
    item = item_operation_for(parser, admins)
    assert item is not None
    assert item.path == "/organizations/{organizationId}/admins/{adminId}"

    syslog = _get_op(parser, "/networks/{networkId}/syslogServers")
    assert item_operation_for(parser, syslog) is None


def test_element_id_derives_collection_keyed_field(tmp_path: Path) -> None:
    """A generic {id} placeholder still finds `<singular>Id` elements
    (adaptive policy groups carry groupId, not id)."""
    parser = _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}/adaptivePolicy/groups": {
                "get": {"operationId": "getGroups", "tags": ["organizations"]},
                "post": {"operationId": "createGroup", "tags": ["organizations"]},
            },
            "/organizations/{organizationId}/adaptivePolicy/groups/{id}": {
                "get": {"operationId": "getGroup", "tags": ["organizations"]},
                "put": {"operationId": "updateGroup", "tags": ["organizations"]},
            },
        },
    )
    collection = _get_op(
        parser, "/organizations/{organizationId}/adaptivePolicy/groups"
    )
    item = item_operation_for(parser, collection)
    assert item is not None
    assert element_id(item, {"groupId": "3661426497", "name": "x"}) == "3661426497"
    # The endpoint's own placeholder and conventional fields still win.
    assert element_id(item, {"id": "direct", "groupId": "later"}) == "direct"


def test_unidentifiable_elements_surface_as_collection_assets(
    tmp_path: Path,
) -> None:
    """Discovered objects without an ID are never dropped silently; they
    are recorded at the collection path so the unsupported-asset audit
    reports them (coverage manifest + alerts)."""
    parser = _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}/adaptivePolicy/groups": {
                "get": {"operationId": "getGroups", "tags": ["organizations"]},
                "post": {"operationId": "createGroup", "tags": ["organizations"]},
            },
            "/organizations/{organizationId}/adaptivePolicy/groups/{id}": {
                "get": {"operationId": "getGroup", "tags": ["organizations"]},
                "put": {"operationId": "updateGroup", "tags": ["organizations"]},
            },
        },
    )
    op = _get_op(parser, "/organizations/{organizationId}/adaptivePolicy/groups")
    assets = expand_endpoint_payload(
        parser, op, "123456", [{"name": "no-id-here"}, {"groupId": "42424242"}]
    )
    assert len(assets) == 2
    unidentifiable, identified = assets
    assert unidentifiable.api_path == op.path
    assert unidentifiable.path_values == ("123456",)
    assert unidentifiable.payload == {"name": "no-id-here"}
    assert identified.path_values == ("123456", "42424242")


def test_collection_id_key_shapes_and_guards(tmp_path: Path) -> None:
    """Derived <singular>Id fields handle plural forms; non-item and
    parameter-only shapes derive nothing."""
    parser = _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}/adaptivePolicy/policies/{id}": {
                "get": {"operationId": "getPolicy", "tags": ["organizations"]},
            },
            "/networks/{networkId}/appliance/trafficShaping": {
                "get": {"operationId": "getShaping", "tags": ["appliance"]},
            },
            "/organizations/{organizationId}/{itemId}": {
                "get": {"operationId": "getOpaque", "tags": ["organizations"]},
            },
        },
    )
    policy = _get_op(
        parser, "/organizations/{organizationId}/adaptivePolicy/policies/{id}"
    )
    assert _collection_id_key(policy) == "policyId"  # ies -> y
    shaping = _get_op(parser, "/networks/{networkId}/appliance/trafficShaping")
    assert _collection_id_key(shaping) is None  # not an item path
    opaque = _get_op(parser, "/organizations/{organizationId}/{itemId}")
    assert _collection_id_key(opaque) is None  # collection segment is a param


def test_element_id_uses_param_name_then_fallbacks(parser: OpenApiParser) -> None:
    vlan_item = next(
        op for op in parser.endpoints()
        if op.path == "/networks/{networkId}/appliance/vlans/{vlanId}"
        and op.method == "get"
    )
    assert element_id(vlan_item, {"vlanId": "20", "id": "ignored"}) == "20"
    assert element_id(vlan_item, {"id": 10}) == "10"
    assert element_id(vlan_item, {"name": "unidentifiable"}) is None
    assert element_id(vlan_item, "not-a-dict") is None
    # A JSON null is "missing", not the literal ID "None".
    assert element_id(vlan_item, {"vlanId": None, "id": 10}) == "10"
    assert element_id(vlan_item, {"id": None}) is None
    # Whitespace padding never reaches the import ID.
    assert element_id(vlan_item, {"id": " 10 "}) == "10"


def test_expand_endpoint_payload_shapes(parser: OpenApiParser) -> None:
    vlans = _get_op(parser, "/networks/{networkId}/appliance/vlans")
    expanded = expand_endpoint_payload(
        parser, vlans, "N_1", [{"id": 10}, {"nameless": True}]
    )
    assert [(f.api_path, f.path_values) for f in expanded] == [
        ("/networks/{networkId}/appliance/vlans/{vlanId}", ("N_1", "10")),
        # Unidentifiable elements surface at the collection path (they
        # become unsupported-asset coverage entries, never dropped).
        ("/networks/{networkId}/appliance/vlans", ("N_1",)),
    ]
    assert expanded[1].payload == {"nameless": True}

    shaping = _get_op(parser, "/networks/{networkId}/appliance/trafficShaping")
    singleton = expand_endpoint_payload(parser, shaping, "N_1", {"limitUp": 0})
    assert singleton[0].path_values == ("N_1",)
    assert singleton[0].api_path == shaping.path

    syslog = _get_op(parser, "/networks/{networkId}/syslogServers")
    kept = expand_endpoint_payload(parser, syslog, "N_1", [{"host": "10.0.0.1"}])
    assert kept[0].payload == {"items": [{"host": "10.0.0.1"}]}
    # An empty per-item collection discovers zero objects.
    assert expand_endpoint_payload(parser, vlans, "N_1", []) == []


@pytest.mark.parametrize("scalar", ["oops-a-string", 42, 3.5, True])
def test_scalar_payloads_become_coverage_gaps(
    parser: OpenApiParser, scalar: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A scalar endpoint body is a malformed response: a bare string
    must not expand per-character into garbage records, and a bare
    number must not raise and abort the whole discovery run. Both are
    recorded like unreadable endpoints — a visible coverage gap."""
    from meraki2tf.models import UNREADABLE_MARKER

    vlans = _get_op(parser, "/networks/{networkId}/appliance/vlans")
    with caplog.at_level("WARNING"):
        (gap,) = expand_endpoint_payload(parser, vlans, "N_1", scalar)
    assert gap.api_path == vlans.path
    assert gap.path_values == ("N_1",)
    assert UNREADABLE_MARKER in gap.payload
    assert type(scalar).__name__ in gap.payload[UNREADABLE_MARKER]
    assert any("non-collection" in r.message for r in caplog.records)


def _envelope_spec(tmp_path: Path) -> OpenApiParser:
    """An org-scoped collection using the paginated {items, meta} envelope."""
    envelope_schema = {
        "type": "object",
        "properties": {
            "items": {"type": "array", "items": {"properties": {"profileId": {}}}},
            "meta": {"type": "object"},
        },
    }
    return _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}/appliance/dns/local/profiles": {
                "get": {
                    "operationId": "getProfiles",
                    "tags": ["appliance"],
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {"schema": envelope_schema}
                            }
                        }
                    },
                },
                "post": {"operationId": "createProfile", "tags": ["appliance"]},
            },
            "/organizations/{organizationId}/appliance/dns/local/profiles/{profileId}": {
                "put": {"operationId": "updateProfile", "tags": ["appliance"]},
                "delete": {"operationId": "deleteProfile", "tags": ["appliance"]},
            },
        },
    )


def test_envelope_collections_expand_to_item_assets(tmp_path: Path) -> None:
    """{items, meta} pagination envelopes are collections, not singletons:
    each element becomes an addressable per-item asset."""
    parser = _envelope_spec(tmp_path)
    op = _get_op(
        parser, "/organizations/{organizationId}/appliance/dns/local/profiles"
    )
    assets = expand_endpoint_payload(
        parser,
        op,
        "123456",
        {
            "items": [{"profileId": "10", "name": "a"}, {"profileId": "11"}],
            "meta": {"counts": {"items": {"total": 2}}},
        },
    )
    assert [(f.api_path, f.path_values) for f in assets] == [
        (
            "/organizations/{organizationId}/appliance/dns/local/profiles/{profileId}",
            ("123456", "10"),
        ),
        (
            "/organizations/{organizationId}/appliance/dns/local/profiles/{profileId}",
            ("123456", "11"),
        ),
    ]
    assert assets[0].payload == {"profileId": "10", "name": "a"}


def test_envelope_without_item_list_stays_singleton(tmp_path: Path) -> None:
    """A declared envelope whose payload carries no list is left intact
    (never guessed into an empty collection)."""
    parser = _envelope_spec(tmp_path)
    op = _get_op(
        parser, "/organizations/{organizationId}/appliance/dns/local/profiles"
    )
    assets = expand_endpoint_payload(parser, op, "123456", {"items": "oops"})
    assert len(assets) == 1
    assert assets[0].api_path == op.path
    assert assets[0].payload == {"items": "oops"}


def test_items_key_among_real_attributes_stays_singleton(
    tmp_path: Path,
) -> None:
    """A dict payload carrying ``items`` next to other real attributes is
    a singleton config, not an envelope."""
    parser = _write_spec(
        tmp_path,
        {
            "/networks/{networkId}/wireless/billing": {
                "get": {"operationId": "getBilling", "tags": ["wireless"]},
                "put": {"operationId": "updateBilling", "tags": ["wireless"]},
            },
        },
    )
    op = _get_op(parser, "/networks/{networkId}/wireless/billing")
    assets = expand_endpoint_payload(
        parser, op, "N_1", {"items": [{"id": "1"}], "currency": "USD"}
    )
    assert len(assets) == 1
    assert assets[0].api_path == op.path


def test_undeclared_envelope_recognized_by_exact_shape(tmp_path: Path) -> None:
    """Several endpoints respond enveloped although the spec declares a
    plain array (observed live for org DNS profiles/records); the exact
    {items, meta} wrapper shape is unwrapped even without schema help."""
    parser = _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}/appliance/dns/local/records": {
                "get": {"operationId": "getRecords", "tags": ["appliance"]},
                "post": {"operationId": "createRecord", "tags": ["appliance"]},
            },
            "/organizations/{organizationId}/appliance/dns/local/records/{recordId}": {
                "put": {"operationId": "updateRecord", "tags": ["appliance"]},
                "delete": {"operationId": "deleteRecord", "tags": ["appliance"]},
            },
        },
    )
    op = _get_op(
        parser, "/organizations/{organizationId}/appliance/dns/local/records"
    )
    assets = expand_endpoint_payload(
        parser,
        op,
        "123456",
        {
            "items": [{"recordId": "7", "hostname": "a.corp.example"}],
            "meta": {"counts": {"items": {"total": 1, "remaining": 0}}},
        },
    )
    assert [(f.api_path, f.path_values) for f in assets] == [
        (
            "/organizations/{organizationId}/appliance/dns/local/records/{recordId}",
            ("123456", "7"),
        ),
    ]
    # An empty envelope expands to zero assets rather than one
    # unimportable collection blob.
    empty = expand_endpoint_payload(
        parser, op, "123456",
        {"items": [], "meta": {"counts": {"items": {"total": 0}}}},
    )
    assert empty == []


def test_empty_collections_kept_only_for_whole_collection_puts(
    tmp_path: Path,
) -> None:
    """An empty list at an endpoint whose PUT replaces the whole
    collection (VPN peer SLAs, staged stages) is one real — empty —
    config object; an empty per-item collection discovers nothing."""
    whole_put = {
        "operationId": "updateSlas",
        "tags": ["appliance"],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"items": {"type": "array"}},
                    }
                }
            }
        },
    }
    per_item_put = {
        "operationId": "updateStatuses",
        "tags": ["camera"],
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"serial": {}, "sent": {}},
                    }
                }
            }
        },
    }
    parser = _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}/vpn/slas": {
                "get": {"operationId": "getSlas", "tags": ["appliance"]},
                "put": whole_put,
            },
            "/organizations/{organizationId}/onboarding/statuses": {
                "get": {"operationId": "getStatuses", "tags": ["camera"]},
                "put": per_item_put,
            },
        },
    )
    slas = _get_op(parser, "/organizations/{organizationId}/vpn/slas")
    kept = expand_endpoint_payload(
        parser, slas, "123456", {"items": [], "meta": {}}
    )
    assert [(f.api_path, f.path_values, f.payload) for f in kept] == [
        ("/organizations/{organizationId}/vpn/slas", ("123456",), {"items": []}),
    ]
    statuses = _get_op(
        parser, "/organizations/{organizationId}/onboarding/statuses"
    )
    assert expand_endpoint_payload(parser, statuses, "123456", {"items": []}) == []


def test_matcher_resolves_exact_and_tokenized_sections(
    parser: OpenApiParser,
) -> None:
    matcher = FeatureSectionMatcher(parser, "networkId")
    assert matcher.match("vlans").path == "/networks/{networkId}/appliance/vlans"
    assert (
        matcher.match("traffic_shaping").path
        == "/networks/{networkId}/appliance/trafficShaping"
    )
    assert matcher.match("syslog").path == "/networks/{networkId}/syslogServers"


def test_matcher_rejects_unknown_and_read_only_sections(
    parser: OpenApiParser,
) -> None:
    matcher = FeatureSectionMatcher(parser, "networkId")
    assert matcher.match("frobnicators") is None
    assert matcher.match("clients") is None  # read-only telemetry
    assert matcher.match("") is None


def test_matcher_breaks_lexical_ties_by_response_schema(
    parser: OpenApiParser,
) -> None:
    matcher = FeatureSectionMatcher(parser, "networkId")
    wireless_sample = {"number", "authMode", "splashPage"}
    resolved = matcher.match("ssids", wireless_sample)
    assert resolved is not None
    assert resolved.path == "/networks/{networkId}/wireless/ssids"

    appliance_sample = {"number", "wpaEncryptionMode"}
    resolved = matcher.match("ssids", appliance_sample)
    assert resolved is not None
    assert resolved.path == "/networks/{networkId}/appliance/ssids"

    # No observed keys → the tie cannot be broken → skipped, not guessed.
    assert matcher.match("ssids") is None


def test_matcher_caps_distance_between_section_and_endpoint(
    tmp_path: Path,
) -> None:
    """A section must not latch onto a far-away endpoint that merely
    contains its tokens (e.g. ``inventory`` → ``esims/inventory``)."""
    parser = _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}/cellularGateway/esims/inventory": {
                "get": {"operationId": "getInventory", "tags": ["organizations"]},
                "put": {"operationId": "updateInventory", "tags": ["organizations"]},
            },
        },
    )
    matcher = FeatureSectionMatcher(parser, "organizationId")
    assert matcher.match("inventory") is None


def test_matcher_reads_object_response_schemas(tmp_path: Path) -> None:
    """Singleton (object) schemas participate in tie-breaking too."""
    schema = {"type": "object", "properties": {"meshingEnabled": {}}}
    parser = _write_spec(
        tmp_path,
        {
            "/networks/{networkId}/wireless/settings": {
                "get": {
                    "operationId": "getWirelessSettings",
                    "tags": ["wireless"],
                    "responses": {
                        "200": {"content": {"application/json": {"schema": schema}}}
                    },
                },
                "put": {"operationId": "updateWirelessSettings", "tags": ["wireless"]},
            },
            "/networks/{networkId}/switch/settings": {
                "get": {"operationId": "getSwitchSettings", "tags": ["switch"]},
                "put": {"operationId": "updateSwitchSettings", "tags": ["switch"]},
            },
        },
    )
    matcher = FeatureSectionMatcher(parser, "networkId")
    resolved = matcher.match("settings", {"meshingEnabled"})
    assert resolved is not None
    assert resolved.path == "/networks/{networkId}/wireless/settings"
    assert matcher.match("wireless_settings").path == (
        "/networks/{networkId}/wireless/settings"
    )


def test_parent_scope_id_key_requires_a_family_nested_item(
    tmp_path: Path,
) -> None:
    """The <parentSegment>Id fallback only exists for family-nested
    item paths; shallow or non-item shapes derive nothing, and a
    parameter parent segment names no field."""
    from meraki2tf.providers.discovery import _parent_scope_id_key

    parser = _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}": {
                "get": {"operationId": "getOrg", "tags": ["organizations"]},
            },
            "/networks/{networkId}/appliance/trafficShaping": {
                "get": {"operationId": "getShaping", "tags": ["appliance"]},
            },
            "/organizations/{organizationId}/{scope}/{itemId}": {
                "get": {"operationId": "getScoped", "tags": ["organizations"]},
            },
        },
    )
    shallow = _get_op(parser, "/organizations/{organizationId}")
    assert _parent_scope_id_key(shallow) is None  # too shallow
    shaping = _get_op(parser, "/networks/{networkId}/appliance/trafficShaping")
    assert _parent_scope_id_key(shaping) is None  # not an item path
    scoped = _get_op(parser, "/organizations/{organizationId}/{scope}/{itemId}")
    assert _parent_scope_id_key(scoped) is None  # parent is a parameter


# ---------------------------------------------------------------------------
# Aggregation explosion: byNetwork responses back into per-scope assets
# ---------------------------------------------------------------------------


def _air_marshal_mapping(spec_parser: OpenApiParser) -> Any:
    return spec_parser.resource_mappings()[
        "meraki_networks_wireless_air_marshal_settings"
    ]


def test_explode_aggregation_rows_with_flat_scope_identifier(
    spec_parser: OpenApiParser,
) -> None:
    mapping = _air_marshal_mapping(spec_parser)
    features = explode_aggregation_payload(
        mapping,
        {
            "items": [
                {"networkId": "N_1", "defaultPolicy": "blocked"},
                {"networkId": "N_2", "defaultPolicy": "allowed"},
            ],
            "meta": {"counts": {}},
        },
    )
    assert [
        (f.api_path, f.path_values, dict(f.payload)) for f in features
    ] == [
        (
            "/networks/{networkId}/wireless/airMarshal/settings",
            ("N_1",),
            {"defaultPolicy": "blocked"},
        ),
        (
            "/networks/{networkId}/wireless/airMarshal/settings",
            ("N_2",),
            {"defaultPolicy": "allowed"},
        ),
    ]


def test_explode_aggregation_rows_with_object_scope_identifier(
    spec_parser: OpenApiParser,
) -> None:
    """zigbee/syslog-style rows carry ``network: {id: ...}`` instead of
    a flat networkId; the whole scope object is consumed."""
    mapping = _air_marshal_mapping(spec_parser)
    features = explode_aggregation_payload(
        mapping,
        {
            "items": [
                {"network": {"id": "N_1", "name": "HQ"}, "enabled": True},
            ],
            "meta": {},
        },
    )
    assert features[0].api_path == (
        "/networks/{networkId}/wireless/airMarshal/settings"
    )
    assert features[0].path_values == ("N_1",)
    assert dict(features[0].payload) == {"enabled": True}


def test_explode_aggregation_rows_without_scope_become_gap_records(
    spec_parser: OpenApiParser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A row with no scope identifier cannot be addressed, but it was
    discovered — it must reach the exception auditor, never vanish."""
    mapping = _air_marshal_mapping(spec_parser)
    with caplog.at_level("WARNING"):
        features = explode_aggregation_payload(
            mapping,
            {"items": [{"defaultPolicy": "blocked"}, "not-an-object"]},
        )
    assert [(f.api_path, f.path_values) for f in features] == [
        ("/networks/{networkId}/wireless/airMarshal/settings", ()),
        ("/networks/{networkId}/wireless/airMarshal/settings", ()),
    ]
    assert dict(features[0].payload) == {"defaultPolicy": "blocked"}
    assert dict(features[1].payload) == {"value": "not-an-object"}
    assert any("scope identifier" in r.message for r in caplog.records)


def test_explode_aggregation_non_collection_payload_is_unreadable(
    spec_parser: OpenApiParser,
) -> None:
    from meraki2tf.models import UNREADABLE_MARKER

    mapping = _air_marshal_mapping(spec_parser)
    features = explode_aggregation_payload(mapping, {"defaultPolicy": "x"})
    assert len(features) == 1
    assert features[0].path_values == ()
    assert UNREADABLE_MARKER in features[0].payload


def test_explode_aggregation_plain_array_payload(
    spec_parser: OpenApiParser,
) -> None:
    """zigbee-style aggregations respond as a plain array, no envelope."""
    mapping = _air_marshal_mapping(spec_parser)
    features = explode_aggregation_payload(
        mapping, [{"networkId": "N_1", "defaultPolicy": "blocked"}]
    )
    assert features[0].path_values == ("N_1",)


def test_explode_aggregation_item_entities_address_elements(
    tmp_path: Path,
) -> None:
    """Air-Marshal-rules shape: rows carry the element ID too, so they
    explode onto the entity's own item path; a row without the element
    ID falls back to the collection path."""
    parser = _write_spec(
        tmp_path,
        {
            "/networks/{networkId}/wireless/airMarshal/rules": {
                "post": {"operationId": "createRule", "tags": ["wireless"]},
            },
            "/networks/{networkId}/wireless/airMarshal/rules/{ruleId}": {
                "put": {"operationId": "updateRule", "tags": ["wireless"]},
                "delete": {"operationId": "deleteRule", "tags": ["wireless"]},
            },
            "/organizations/{organizationId}/wireless/airMarshal/rules": {
                "get": {
                    "operationId": "getOrgRules",
                    "tags": ["wireless"],
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
                                                        "network": {},
                                                        "ruleId": {},
                                                    },
                                                },
                                            },
                                            "meta": {},
                                        },
                                    }
                                }
                            }
                        }
                    },
                },
            },
        },
    )
    mapping = parser.resource_mappings()[
        "meraki_networks_wireless_air_marshal_rules"
    ]
    features = explode_aggregation_payload(
        mapping,
        {
            "items": [
                {"network": {"id": "N_1"}, "ruleId": "R_1", "type": "block"},
                {"network": {"id": "N_1"}, "type": "allow"},
            ],
            "meta": {},
        },
    )
    assert [(f.api_path, f.path_values) for f in features] == [
        (
            "/networks/{networkId}/wireless/airMarshal/rules/{ruleId}",
            ("N_1", "R_1"),
        ),
        ("/networks/{networkId}/wireless/airMarshal/rules", ("N_1",)),
    ]


def test_aggregation_collection_path_falls_back_to_item_parent(
    tmp_path: Path,
) -> None:
    """An adopted entity exposing only item endpoints derives its
    collection path from the item path's enclosing collection."""
    parser = _write_spec(
        tmp_path,
        {
            "/networks/{networkId}/foo/things/{thingId}": {
                "put": {"operationId": "updateThing", "tags": ["foo"]},
            },
            "/organizations/{organizationId}/foo/things/byNetwork": {
                "get": {"operationId": "getThingsByNetwork", "tags": ["foo"]},
            },
        },
    )
    mapping = parser.resource_mappings()["meraki_networks_foo_things"]
    assert aggregation_collection_path(mapping) == (
        "/networks/{networkId}/foo/things"
    )


def test_aggregation_mappings_lists_only_adopted_entities(
    spec_parser: OpenApiParser,
) -> None:
    mappings = aggregation_mappings(spec_parser)
    assert [m.terraform_name for m in mappings] == [
        "meraki_networks_wireless_air_marshal_settings",
        "meraki_networks_wireless_ssids_open_roaming",
    ]


# ---------------------------------------------------------------------------
# Nested-element aggregations (…/{element}/config shape) and phantom-scope
# healing (byNetwork rows scoped by per-product child network ids)
# ---------------------------------------------------------------------------


OPEN_ROAMING_PATH = "/networks/{networkId}/wireless/ssids/{number}/openRoaming"


def _open_roaming_mapping(spec_parser: OpenApiParser) -> Any:
    return spec_parser.resource_mappings()[
        "meraki_networks_wireless_ssids_open_roaming"
    ]


def test_nested_element_param_recognizes_only_the_nested_shape() -> None:
    from meraki2tf.providers.discovery import _nested_element_param

    assert _nested_element_param(OPEN_ROAMING_PATH) == "number"
    # Item path: the second parameter is trailing — a different shape.
    assert (
        _nested_element_param("/networks/{networkId}/appliance/vlans/{vlanId}")
        is None
    )
    # Single-parameter collection/singleton paths.
    assert _nested_element_param("/networks/{networkId}/syslogServers") is None
    # A malformed segment carrying an unclosed brace must not be
    # miscounted as the element parameter.
    assert (
        _nested_element_param("/networks/{networkId}/{x/things/{id}/conf")
        is None
    )


def test_aggregation_collection_path_is_the_entitys_own_nested_path(
    spec_parser: OpenApiParser,
) -> None:
    """The canonical path of a nested-element entity is its own
    two-parameter write path — deriving a shorter prefix would collide
    with the enclosing collection entity (…/wireless/ssids)."""
    mapping = _open_roaming_mapping(spec_parser)
    assert aggregation_collection_path(mapping) == OPEN_ROAMING_PATH


def test_explode_nested_aggregation_rows_per_element(
    spec_parser: OpenApiParser,
) -> None:
    """Each row's nested element list explodes to one feature per
    element at the entity's own path; the payload is the config
    sub-object named after the trailing path segment when present,
    else the element minus its identifier."""
    mapping = _open_roaming_mapping(spec_parser)
    features = explode_aggregation_payload(
        mapping,
        {
            "items": [
                {
                    "networkId": "N_1",
                    "networkName": "site-a - wireless",
                    "ssids": [
                        {
                            "name": "wifi-x",
                            "number": 0,
                            "enabled": True,
                            "openRoaming": {"enabled": False},
                        },
                        {"name": "wifi-y", "number": 1, "enabled": True},
                    ],
                },
            ],
            "meta": {},
        },
    )
    assert [
        (f.api_path, f.path_values, dict(f.payload)) for f in features
    ] == [
        (OPEN_ROAMING_PATH, ("N_1", "0"), {"enabled": False}),
        (
            OPEN_ROAMING_PATH,
            ("N_1", "1"),
            {"name": "wifi-y", "enabled": True},
        ),
    ]


def test_explode_nested_aggregation_unaddressable_pieces_stay_auditable(
    spec_parser: OpenApiParser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Rows without an element list, non-object elements, and elements
    without the identifier all surface as gap records carrying their
    scope — discovered objects never vanish (Cardinal Rule 2). A row
    whose element list is empty holds zero objects, not a gap."""
    mapping = _open_roaming_mapping(spec_parser)
    with caplog.at_level("WARNING"):
        features = explode_aggregation_payload(
            mapping,
            {
                "items": [
                    {
                        "networkId": "N_1",
                        "ssids": [
                            {"number": 2, "openRoaming": {"enabled": True}},
                            "not-an-object",
                            {"name": "no-identifier"},
                        ],
                    },
                    {"networkId": "N_1", "notes": "no element list"},
                    {"networkId": "N_1", "ssids": []},
                ],
                "meta": {},
            },
        )
    assert [
        (f.api_path, f.path_values, dict(f.payload)) for f in features
    ] == [
        (OPEN_ROAMING_PATH, ("N_1", "2"), {"enabled": True}),
        (
            OPEN_ROAMING_PATH,
            (),
            {"networkId": "N_1", "value": "not-an-object"},
        ),
        (
            OPEN_ROAMING_PATH,
            (),
            {"networkId": "N_1", "name": "no-identifier"},
        ),
        (
            OPEN_ROAMING_PATH,
            (),
            {"networkId": "N_1", "notes": "no element list"},
        ),
    ]
    messages = [record.message for record in caplog.records]
    assert any("is not an object" in message for message in messages)
    assert any("no 'number' identifier" in message for message in messages)
    assert any("no 'number' element list" in message for message in messages)


def test_explode_rescopes_phantom_child_network_ids_by_name(
    spec_parser: OpenApiParser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A row scoped by an unknown (per-product child) network id is
    re-scoped to the parent network its name resolves to: exact name
    match, one stripped " - <suffix>", and a parent name that itself
    contains " - "."""
    mapping = _open_roaming_mapping(spec_parser)
    known = {"N_1": "site-a", "N_2": "alpha - beta"}
    with caplog.at_level("INFO"):
        features = explode_aggregation_payload(
            mapping,
            {
                "items": [
                    {
                        "networkId": "N_901",
                        "networkName": "site-a",
                        "ssids": [{"number": 0, "openRoaming": {"x": 1}}],
                    },
                    {
                        "networkId": "N_902",
                        "networkName": "site-a - wireless",
                        "ssids": [{"number": 1, "openRoaming": {"x": 2}}],
                    },
                    {
                        "networkId": "N_903",
                        "networkName": "alpha - beta - wireless",
                        "ssids": [{"number": 2, "openRoaming": {"x": 3}}],
                    },
                ],
                "meta": {},
            },
            known_networks=known,
        )
    assert [(f.path_values, dict(f.payload)) for f in features] == [
        (("N_1", "0"), {"x": 1}),
        (("N_1", "1"), {"x": 2}),
        (("N_2", "2"), {"x": 3}),
    ]
    assert any(
        "re-scoped 3 row(s)" in record.message for record in caplog.records
    )


def test_explode_known_scope_ids_pass_through_unchanged(
    spec_parser: OpenApiParser,
) -> None:
    """A row whose scope id IS a discovered network is never re-scoped,
    even when its name field points at a different network."""
    mapping = _air_marshal_mapping(spec_parser)
    features = explode_aggregation_payload(
        mapping,
        {
            "items": [
                {
                    "networkId": "N_1",
                    "networkName": "site-b",
                    "defaultPolicy": "blocked",
                },
            ],
            "meta": {},
        },
        known_networks={"N_1": "site-a", "N_2": "site-b"},
    )
    assert [f.path_values for f in features] == [("N_1",)]


def test_explode_rescopes_object_form_scope_by_nested_name(
    spec_parser: OpenApiParser,
) -> None:
    """Flat (non-nested) aggregation rows heal the same way, including
    the ``network: {id, name}`` object form."""
    mapping = _air_marshal_mapping(spec_parser)
    features = explode_aggregation_payload(
        mapping,
        {
            "items": [
                {
                    "network": {"id": "N_904", "name": "site-a - appliance"},
                    "defaultPolicy": "allowed",
                },
            ],
            "meta": {},
        },
        known_networks={"N_1": "site-a"},
    )
    assert [
        (f.api_path, f.path_values, dict(f.payload)) for f in features
    ] == [
        (
            "/networks/{networkId}/wireless/airMarshal/settings",
            ("N_1",),
            {"defaultPolicy": "allowed"},
        ),
    ]


def test_explode_unresolvable_scope_becomes_gap_record(
    spec_parser: OpenApiParser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unknown scope id whose name resolves to nothing must never be
    emitted as a feature address — the whole row stays an auditable
    scope-less gap record instead."""
    mapping = _open_roaming_mapping(spec_parser)
    rows = [
        # Name matches nothing, with and without a strippable suffix.
        {
            "networkId": "N_905",
            "networkName": "unrelated - wireless",
            "ssids": [{"number": 0}],
        },
        # No name field at all.
        {"networkId": "N_906", "ssids": [{"number": 1}]},
    ]
    with caplog.at_level("WARNING"):
        features = explode_aggregation_payload(
            mapping,
            {"items": [dict(row) for row in rows], "meta": {}},
            known_networks={"N_1": "site-a"},
        )
    assert [
        (f.api_path, f.path_values, dict(f.payload)) for f in features
    ] == [(OPEN_ROAMING_PATH, (), row) for row in rows]
    assert (
        sum(
            "matches no discovered network" in record.message
            for record in caplog.records
        )
        == 2
    )


def test_explode_flat_and_item_shapes_unchanged_by_known_networks(
    tmp_path: Path,
) -> None:
    """Regression: real-parent-scoped flat rows and item-path rows
    (air-marshal-rules shape with ruleId) behave identically whether or
    not the network universe is supplied."""
    parser = _write_spec(
        tmp_path,
        {
            "/networks/{networkId}/wireless/airMarshal/rules": {
                "post": {"operationId": "createRule", "tags": ["wireless"]},
            },
            "/networks/{networkId}/wireless/airMarshal/rules/{ruleId}": {
                "put": {"operationId": "updateRule", "tags": ["wireless"]},
                "delete": {"operationId": "deleteRule", "tags": ["wireless"]},
            },
            "/organizations/{organizationId}/wireless/airMarshal/rules": {
                "get": {
                    "operationId": "getOrgRules",
                    "tags": ["wireless"],
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
                                                        "network": {},
                                                        "ruleId": {},
                                                    },
                                                },
                                            },
                                            "meta": {},
                                        },
                                    }
                                }
                            }
                        }
                    },
                },
            },
        },
    )
    mapping = parser.resource_mappings()[
        "meraki_networks_wireless_air_marshal_rules"
    ]
    payload = {
        "items": [
            {"network": {"id": "N_1"}, "ruleId": "R_1", "type": "block"},
            {"network": {"id": "N_1"}, "type": "allow"},
        ],
        "meta": {},
    }
    baseline = explode_aggregation_payload(mapping, payload)
    healed = explode_aggregation_payload(
        mapping, payload, known_networks={"N_1": "site-a"}
    )
    assert [
        (f.api_path, f.path_values, dict(f.payload)) for f in baseline
    ] == [(f.api_path, f.path_values, dict(f.payload)) for f in healed]
    assert [(f.api_path, f.path_values) for f in baseline] == [
        (
            "/networks/{networkId}/wireless/airMarshal/rules/{ruleId}",
            ("N_1", "R_1"),
        ),
        ("/networks/{networkId}/wireless/airMarshal/rules", ("N_1",)),
    ]


# ---------------------------------------------------------------------------
# Spec-surface accounting: write-only, RPC-only, read-only entities
# ---------------------------------------------------------------------------


def test_spec_surface_report_classifies_uncaptured_entities(
    tmp_path: Path,
) -> None:
    parser = _write_spec(
        tmp_path,
        {
            # Ordinary readable config entity — in none of the lists.
            "/networks/{networkId}/appliance/trafficShaping": {
                "get": {"operationId": "getShaping", "tags": ["appliance"]},
                "put": {"operationId": "updateShaping", "tags": ["appliance"]},
            },
            # Write-only configuration: PUT with no readable counterpart.
            "/networks/{networkId}/appliance/sdwan/internetPolicies": {
                "put": {"operationId": "updateSdwan", "tags": ["appliance"]},
            },
            # RPC-only actions.
            "/devices/{serial}/blinkLeds": {
                "post": {"operationId": "blinkLeds", "tags": ["devices"]},
            },
            "/networks/{networkId}/devices/claim": {
                "post": {"operationId": "claimDevices", "tags": ["networks"]},
            },
            # Read-only API surface (SM-profile style).
            "/networks/{networkId}/sm/profiles": {
                "get": {"operationId": "getSmProfiles", "tags": ["sm"]},
            },
            # Adopted byNetwork pair — neither write-only nor read-only.
            "/networks/{networkId}/wireless/zigbee": {
                "put": {"operationId": "updateZigbee", "tags": ["wireless"]},
            },
            "/organizations/{organizationId}/wireless/zigbee/byNetwork": {
                "get": {"operationId": "getZigbeeByNetwork", "tags": ["wireless"]},
            },
        },
    )
    surfaces = spec_surface_report(parser)
    assert surfaces.write_only_paths == (
        "/networks/{networkId}/appliance/sdwan/internetPolicies",
    )
    assert surfaces.rpc_only_paths == (
        "/devices/{serial}/blinkLeds",
        "/networks/{networkId}/devices/claim",
    )
    # The zigbee aggregation source is the adopted entity's collection
    # source, not an unrestorable read-only surface.
    assert surfaces.api_read_only_paths == (
        "/networks/{networkId}/sm/profiles",
    )


def test_spec_surface_report_on_pipeline_fixture(
    spec_parser: OpenApiParser,
) -> None:
    surfaces = spec_surface_report(spec_parser)
    assert surfaces.write_only_paths == ()
    assert surfaces.rpc_only_paths == ()
    assert surfaces.api_read_only_paths == ("/networks/{networkId}/clients",)


# ---------------------------------------------------------------------------
# Product-type derivation for conservative prefiltering
# ---------------------------------------------------------------------------


def test_network_product_types_derived_from_create_network_enum(
    tmp_path: Path,
) -> None:
    parser = _write_spec(
        tmp_path,
        {
            "/organizations/{organizationId}/networks": {
                "get": {"operationId": "getNetworks", "tags": ["organizations"]},
                "post": {
                    "operationId": "createNetwork",
                    "tags": ["organizations"],
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
        },
    )
    assert network_product_types(parser) == frozenset(
        {"appliance", "wireless", "switch"}
    )


def test_network_product_types_absent_enum_disables_filtering(
    spec_parser: OpenApiParser,
) -> None:
    # The pipeline fixture declares no requestBody enum: conservative
    # default is the empty set, i.e. nothing is ever prefiltered.
    assert network_product_types(spec_parser) == frozenset()


def test_product_segment_shapes(spec_parser: OpenApiParser) -> None:
    by_path = {op.path: op for op in spec_parser.endpoints()}
    assert product_segment(
        by_path["/networks/{networkId}/wireless/ssids"]
    ) == "wireless"
    assert product_segment(by_path["/devices/{serial}/switch/ports"]) == "switch"
    # Scope parameter is the trailing segment — no product family.
    assert product_segment(by_path["/networks/{networkId}"]) is None
    # No parameter at all (defensive).
    from meraki2tf.spec.engine import OperationSpec

    assert (
        product_segment(
            OperationSpec(
                operation_id="x", method="get", path="/organizations",
                path_params=(), tags=(),
            )
        )
        is None
    )
    # A parameter immediately followed by another parameter.
    assert (
        product_segment(
            OperationSpec(
                operation_id="y", method="get", path="/networks/{networkId}/{oddId}",
                path_params=("networkId", "oddId"), tags=(),
            )
        )
        is None
    )
