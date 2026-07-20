"""Spec-driven feature discovery: endpoint filtering, expansion, matching."""

import json
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers.discovery import (
    FeatureSectionMatcher,
    _collection_id_key,
    config_collection_operations,
    element_id,
    expand_endpoint_payload,
    item_operation_for,
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
