"""Shared fixtures: mock OpenAPI spec and offline snapshot documents.

All pipeline tests run against local fixture dictionaries — no network
sockets — per the project coverage/mocking policy.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.openapi_parser import OpenApiParser


def _op(operation_id: str, *tags: str) -> dict[str, object]:
    return {"operationId": operation_id, "tags": list(tags)}


#: Minimized spec mirroring real Meraki OpenAPI structure: canonical
#: network/device entities, an org-scoped network collection, a nested
#: VLAN entity, a camelCase singleton, a collection without an item
#: endpoint, and an endpoint that live networks typically refuse.
PIPELINE_SPEC: dict[str, Any] = {
    "openapi": "3.0.1",
    "paths": {
        "/organizations/{organizationId}/networks": {
            "get": _op("getOrganizationNetworks", "organizations"),
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
        },
        "/networks/{networkId}/syslogServers": {
            "get": _op("getNetworkSyslogServers", "networks"),
        },
        "/networks/{networkId}/sensor/relationships": {
            "get": _op("getNetworkSensorRelationships", "sensor"),
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
