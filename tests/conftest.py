"""Shared fixtures: mock OpenAPI spec and offline snapshot documents.

All pipeline tests run against local fixture dictionaries — no network
sockets — per the project coverage/mocking policy.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.provider_catalog import ProviderCatalog


def _op(
    operation_id: str, *tags: str, response_schema: dict[str, Any] | None = None
) -> dict[str, object]:
    op: dict[str, object] = {"operationId": operation_id, "tags": list(tags)}
    if response_schema is not None:
        op["responses"] = {
            "200": {"content": {"application/json": {"schema": response_schema}}}
        }
    return op


#: Response schemas for the two ambiguous ``ssids`` collections; the
#: section matcher must tell them apart by observed payload keys.
WIRELESS_SSIDS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {"number": {}, "name": {}, "authMode": {}, "splashPage": {}},
    },
}
APPLIANCE_SSIDS_SCHEMA: dict[str, Any] = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {"number": {}, "authMode": {}, "wpaEncryptionMode": {}},
    },
}


#: Minimized spec mirroring real Meraki OpenAPI structure: canonical
#: network/device entities, an org-scoped network collection, a nested
#: VLAN entity, a camelCase singleton, a collection without an item
#: endpoint, and an endpoint that live networks typically refuse.
PIPELINE_SPEC: dict[str, Any] = {
    "openapi": "3.0.1",
    "paths": {
        "/organizations/{organizationId}/networks": {
            "get": _op("getOrganizationNetworks", "organizations"),
            "post": _op("createOrganizationNetwork", "organizations"),
        },
        "/organizations/{organizationId}/devices": {
            "get": _op("getOrganizationDevices", "organizations"),
        },
        "/networks/{networkId}": {
            "get": _op("getNetwork", "networks"),
            "put": _op("updateNetwork", "networks"),
        },
        "/devices/{serial}": {
            "get": _op("getDevice", "devices"),
            "put": _op("updateDevice", "devices"),
        },
        "/networks/{networkId}/appliance/vlans": {
            "get": _op("getNetworkApplianceVlans", "appliance"),
        },
        "/networks/{networkId}/appliance/vlans/{vlanId}": {
            "get": _op("getNetworkApplianceVlan", "appliance"),
            "put": _op("updateNetworkApplianceVlan", "appliance"),
        },
        "/networks/{networkId}/appliance/trafficShaping": {
            "get": _op("getNetworkApplianceTrafficShaping", "appliance"),
            "put": _op("updateNetworkApplianceTrafficShaping", "appliance"),
        },
        "/networks/{networkId}/syslogServers": {
            "get": _op("getNetworkSyslogServers", "networks"),
            "put": _op("updateNetworkSyslogServers", "networks"),
        },
        "/networks/{networkId}/sensor/relationships": {
            "get": _op("getNetworkSensorRelationships", "sensor"),
            "put": _op("updateNetworkSensorRelationships", "sensor"),
        },
        "/networks/{networkId}/clients": {
            "get": _op("getNetworkClients", "networks"),
        },
        "/networks/{networkId}/wireless/ssids": {
            "get": _op(
                "getNetworkWirelessSsids",
                "wireless",
                response_schema=WIRELESS_SSIDS_SCHEMA,
            ),
        },
        "/networks/{networkId}/wireless/ssids/{number}": {
            "get": _op("getNetworkWirelessSsid", "wireless"),
            "put": _op("updateNetworkWirelessSsid", "wireless"),
        },
        "/networks/{networkId}/appliance/ssids": {
            "get": _op(
                "getNetworkApplianceSsids",
                "appliance",
                response_schema=APPLIANCE_SSIDS_SCHEMA,
            ),
        },
        "/networks/{networkId}/appliance/ssids/{number}": {
            "get": _op("getNetworkApplianceSsid", "appliance"),
            "put": _op("updateNetworkApplianceSsid", "appliance"),
        },
        "/devices/{serial}/switch/ports": {
            "get": _op("getDeviceSwitchPorts", "switch"),
        },
        "/devices/{serial}/switch/ports/{portId}": {
            "get": _op("getDeviceSwitchPort", "switch"),
            "put": _op("updateDeviceSwitchPort", "switch"),
        },
        "/organizations/{organizationId}/admins": {
            "get": _op("getOrganizationAdmins", "organizations"),
        },
        "/organizations/{organizationId}/admins/{adminId}": {
            "put": _op("updateOrganizationAdmin", "organizations"),
            "delete": _op("deleteOrganizationAdmin", "organizations"),
        },
    },
}


#: Offline snapshot equivalent of the live fixture data used in tests.
DUMP_DOCUMENT: dict[str, Any] = {
    "organizationId": "org-123",
    "networks": [
        {
            "id": "N_1",
            "organizationId": "org-123",
            "name": "HQ",
            "productTypes": ["appliance"],
        },
    ],
    "devices": [
        {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1", "model": "MX64", "name": "edge"},
    ],
    "features": [
        {
            "apiPath": "/networks/{networkId}/appliance/vlans/{vlanId}",
            "pathValues": ["N_1", "10"],
            "payload": {"id": 10, "name": "Data"},
        },
        {
            "apiPath": "/networks/{networkId}/appliance/trafficShaping",
            "pathValues": ["N_1"],
            "payload": {"globalBandwidthLimits": {"limitUp": 0, "limitDown": 0}},
        },
    ],
}


#: Identity-schema catalog mirroring how CiscoDevNet/meraki names the
#: PIPELINE_SPEC entities. Keys are the provider's resource types; the
#: attribute sets drive identity-fit matching and import-ID composition
#: (org prefix for meraki_network, per-item vs blob arity, …).
FIXTURE_CATALOG_RESOURCES: dict[str, list[str]] = {
    "meraki_organization": ["id"],
    "meraki_network": ["id", "organization_id"],
    "meraki_device": ["serial"],
    "meraki_appliance_vlan": ["id", "network_id"],
    "meraki_appliance_traffic_shaping": ["network_id"],
    "meraki_network_syslog_servers": ["network_id"],
    "meraki_sensor_relationships": ["network_id"],
    "meraki_wireless_ssid": ["network_id", "number"],
    "meraki_appliance_ssid": ["network_id", "number"],
    "meraki_switch_port": ["port_id", "serial"],
    "meraki_organization_admin": ["id", "organization_id"],
}


def fixture_catalog() -> ProviderCatalog:
    return ProviderCatalog(
        resources={
            name: frozenset(attrs)
            for name, attrs in FIXTURE_CATALOG_RESOURCES.items()
        },
        source="fixture",
    )


def fixture_schema_document() -> dict[str, Any]:
    """``terraform providers schema -json`` shape for the fixture catalog."""
    return {
        "provider_schemas": {
            "registry.terraform.io/ciscodevnet/meraki": {
                "resource_identity_schemas": {
                    name: {"version": 0, "attributes": {attr: {} for attr in attrs}}
                    for name, attrs in FIXTURE_CATALOG_RESOURCES.items()
                },
            },
        },
    }


@pytest.fixture()
def provider_catalog() -> ProviderCatalog:
    return fixture_catalog()


@pytest.fixture()
def spec_file(tmp_path: Path) -> Path:
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(PIPELINE_SPEC), encoding="utf-8")
    return path


@pytest.fixture()
def spec_parser(spec_file: Path) -> OpenApiParser:
    return OpenApiParser(spec_file)


@pytest.fixture()
def dump_file(tmp_path: Path) -> Path:
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(DUMP_DOCUMENT), encoding="utf-8")
    return path
