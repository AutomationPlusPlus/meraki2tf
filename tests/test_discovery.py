"""Spec-driven feature discovery: endpoint filtering, expansion, matching."""

import json
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers.discovery import (
    FeatureSectionMatcher,
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


def test_expand_endpoint_payload_shapes(parser: OpenApiParser) -> None:
    vlans = _get_op(parser, "/networks/{networkId}/appliance/vlans")
    expanded = expand_endpoint_payload(
        parser, vlans, "N_1", [{"id": 10}, {"nameless": True}]
    )
    assert [(f.api_path, f.path_values) for f in expanded] == [
        ("/networks/{networkId}/appliance/vlans/{vlanId}", ("N_1", "10")),
    ]

    shaping = _get_op(parser, "/networks/{networkId}/appliance/trafficShaping")
    singleton = expand_endpoint_payload(parser, shaping, "N_1", {"limitUp": 0})
    assert singleton[0].path_values == ("N_1",)
    assert singleton[0].api_path == shaping.path

    syslog = _get_op(parser, "/networks/{networkId}/syslogServers")
    kept = expand_endpoint_payload(parser, syslog, "N_1", [{"host": "10.0.0.1"}])
    assert kept[0].payload == {"items": [{"host": "10.0.0.1"}]}


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
