"""Dynamic OpenAPI ingestion: discovery driven purely by document content."""

import json
from pathlib import Path

import pytest

from meraki2tf.spec import SpecIngestionEngine
from meraki2tf.spec.engine import MalformedSpecError

# Local mock spec fragment — mirrors real Meraki OpenAPI structure without
# touching the network, per the coverage/mocking policy.
MOCK_SPEC = {
    "openapi": "3.0.1",
    "paths": {
        "/organizations": {
            "get": {"operationId": "getOrganizations", "tags": ["organizations"]},
        },
        "/networks/{networkId}/appliance/vlans/{vlanId}": {
            "get": {
                "operationId": "getNetworkApplianceVlan",
                "tags": ["appliance", "vlans"],
            },
            "put": {
                "operationId": "updateNetworkApplianceVlan",
                "tags": ["appliance", "vlans"],
            },
            "x-not-a-method": {"operationId": "ignored"},
        },
        "/broken": "not-an-object",
        "/no-op-id": {"get": {"tags": ["orphan"]}},
    },
}


def test_operations_are_discovered_dynamically() -> None:
    ops = {op.operation_id: op for op in SpecIngestionEngine(MOCK_SPEC).operations()}
    assert set(ops) == {
        "getOrganizations",
        "getNetworkApplianceVlan",
        "updateNetworkApplianceVlan",
    }
    vlan_get = ops["getNetworkApplianceVlan"]
    assert vlan_get.method == "get"
    assert vlan_get.path_params == ("networkId", "vlanId")
    assert vlan_get.tags == ("appliance", "vlans")


def test_resource_groups_cluster_by_path_template() -> None:
    groups = SpecIngestionEngine(MOCK_SPEC).resource_groups()
    vlan = groups["/networks/{networkId}/appliance/vlans/{vlanId}"]
    assert vlan.methods == frozenset({"get", "put"})
    assert groups["/organizations"].methods == frozenset({"get"})


def test_from_file_round_trip(tmp_path: Path) -> None:
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(MOCK_SPEC), encoding="utf-8")
    engine = SpecIngestionEngine.from_file(spec_path)
    assert len(engine.resource_groups()) == 2


def test_from_file_rejects_invalid_json(tmp_path: Path) -> None:
    spec_path = tmp_path / "bad.json"
    spec_path.write_text("{oops", encoding="utf-8")
    with pytest.raises(MalformedSpecError):
        SpecIngestionEngine.from_file(spec_path)


def test_rejects_document_without_paths() -> None:
    with pytest.raises(MalformedSpecError):
        SpecIngestionEngine({"openapi": "3.0.1"})


def test_unimplemented_stages_are_explicit() -> None:
    engine = SpecIngestionEngine(MOCK_SPEC)
    with pytest.raises(NotImplementedError):
        engine.build_registry()


def test_from_latest_release_builds_from_remote_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from meraki2tf import spec_resolver

    monkeypatch.setattr(spec_resolver, "fetch_latest_spec", lambda: MOCK_SPEC)
    engine = SpecIngestionEngine.from_latest_release()
    assert len(engine.resource_groups()) == 2
