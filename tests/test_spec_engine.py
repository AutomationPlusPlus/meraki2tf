"""Dynamic OpenAPI ingestion: discovery driven purely by document content."""

import json
import logging
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
        "get_no_op_id",  # synthesized: the spec left it anonymous
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
    assert len(engine.resource_groups()) == 3


def test_from_file_rejects_invalid_json(tmp_path: Path) -> None:
    spec_path = tmp_path / "bad.json"
    spec_path.write_text("{oops", encoding="utf-8")
    with pytest.raises(MalformedSpecError):
        SpecIngestionEngine.from_file(spec_path)


def test_from_file_rejects_non_object_document(tmp_path: Path) -> None:
    spec_path = tmp_path / "bad.json"
    spec_path.write_text("[]", encoding="utf-8")
    with pytest.raises(MalformedSpecError):
        SpecIngestionEngine.from_file(spec_path)


def test_from_file_rejects_non_utf8_bytes(tmp_path: Path) -> None:
    spec_path = tmp_path / "bad.json"
    spec_path.write_bytes(b"\xff\xfe{}")
    with pytest.raises(MalformedSpecError):
        SpecIngestionEngine.from_file(spec_path)


def test_rejects_document_without_paths() -> None:
    with pytest.raises(MalformedSpecError):
        SpecIngestionEngine({"openapi": "3.0.1"})


def test_null_or_string_tags_do_not_crash_ingestion() -> None:
    """Hand-trimmed specs carry `tags: null` (TypeError before) or a
    bare string (which would decompose into single-character tags)."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/organizations": {
                "get": {"operationId": "getOrganizations", "tags": None},
            },
            "/networks/{networkId}/snmp": {
                "get": {"operationId": "getNetworkSnmp", "tags": "networks"},
            },
        },
    }
    ops = {op.operation_id: op for op in SpecIngestionEngine(spec).operations()}
    assert ops["getOrganizations"].tags == ()
    assert ops["getNetworkSnmp"].tags == ()


def test_missing_operation_id_synthesizes_a_deterministic_fallback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """operationId is optional per OpenAPI; skipping such an operation
    would make its entity invisible to discovery and coverage. The
    synthesized id keeps the operation flowing (live SDK dispatch then
    reports it undispatchable, loudly) and warns at ingestion."""
    with caplog.at_level(logging.WARNING, logger="meraki2tf.spec.engine"):
        ops = {
            op.operation_id: op
            for op in SpecIngestionEngine(MOCK_SPEC).operations()
        }
    orphan = ops["get_no_op_id"]
    assert orphan.method == "get"
    assert orphan.path == "/no-op-id"
    assert orphan.tags == ("orphan",)
    assert any(
        "no operationId" in record.message and "get_no_op_id" in record.getMessage()
        for record in caplog.records
    )


def test_ref_path_items_resolve_within_the_document() -> None:
    """A path item that is a $ref (valid OpenAPI 3.x) must not silently
    drop every operation under that path."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/organizations": {"$ref": "#/components/pathItems/orgs"},
        },
        "components": {
            "pathItems": {
                "orgs": {
                    "get": {
                        "operationId": "getOrganizations",
                        "tags": ["organizations"],
                    },
                },
            },
        },
    }
    ops = list(SpecIngestionEngine(spec).operations())
    assert [op.operation_id for op in ops] == ["getOrganizations"]
    assert ops[0].path == "/organizations"


def test_ref_path_items_honor_json_pointer_escaping() -> None:
    """RFC 6901: ``~1`` is ``/`` and ``~0`` is ``~`` inside a token."""
    spec = {
        "openapi": "3.0.1",
        "paths": {
            "/organizations": {"$ref": "#/x~1y/a~0b"},
        },
        "x/y": {
            "a~b": {
                "get": {"operationId": "getOrganizations", "tags": []},
            },
        },
    }
    ops = list(SpecIngestionEngine(spec).operations())
    assert [op.operation_id for op in ops] == ["getOrganizations"]


@pytest.mark.parametrize(
    "ref",
    [
        "https://example.com/shared.json#/pathItems/orgs",  # external
        "#/components/pathItems/absent",  # dangling
        123,  # not even a string
    ],
)
def test_unresolvable_ref_path_items_warn_by_path(
    ref: object, caplog: pytest.LogCaptureFixture
) -> None:
    """External or dangling $refs cannot be followed from a local
    document — a coverage hole that must be loud, naming the path."""
    spec = {"openapi": "3.0.1", "paths": {"/organizations": {"$ref": ref}}}
    with caplog.at_level(logging.WARNING, logger="meraki2tf.spec.engine"):
        ops = list(SpecIngestionEngine(spec).operations())
    assert ops == []
    assert any(
        "/organizations" in record.getMessage() and "$ref" in record.message
        for record in caplog.records
    )


def test_from_latest_release_builds_from_remote_spec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from meraki2tf import spec_resolver

    monkeypatch.setattr(spec_resolver, "fetch_latest_spec", lambda: MOCK_SPEC)
    engine = SpecIngestionEngine.from_latest_release()
    assert len(engine.resource_groups()) == 3
