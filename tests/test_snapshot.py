"""Snapshot writer: canonical serialization and dump-provider round trip."""

import json
from pathlib import Path

import pytest

from meraki2tf import snapshot
from meraki2tf.providers import StaticJsonDataProvider
from meraki2tf.snapshot import graph_to_snapshot, write_snapshot


def test_snapshot_round_trips_through_the_dump_provider(dump_file: Path, tmp_path: Path) -> None:
    """write_snapshot output must reload into an identical graph."""
    graph = StaticJsonDataProvider(dump_file).fetch_network_graph()
    out = tmp_path / "exports" / "snapshot.json"  # parent dir is created

    write_snapshot(graph, out)
    reloaded = StaticJsonDataProvider(out).fetch_network_graph()

    assert reloaded == graph


def test_snapshot_document_uses_the_canonical_contract(dump_file: Path) -> None:
    graph = StaticJsonDataProvider(dump_file).fetch_network_graph()
    document = graph_to_snapshot(graph)
    assert document["organizationId"] == "org-123"
    assert document["networks"][0] == {
        "id": "N_1",
        "organizationId": "org-123",
        "name": "HQ",
        "productTypes": ["appliance"],
    }
    assert document["devices"][0]["serial"] == "Q2AB-CDEF-GHIJ"
    assert {f["apiPath"] for f in document["features"]} == {
        "/networks/{networkId}/appliance/vlans/{vlanId}",
        "/networks/{networkId}/appliance/trafficShaping",
    }
    json.dumps(document)  # fully JSON-serializable


def test_snapshot_routes_through_owner_only_helper(
    dump_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Permission enforcement (and its degraded-FS warning) is delegated."""
    restricted: list[Path] = []
    monkeypatch.setattr(
        snapshot, "restrict_to_owner", lambda path: restricted.append(path) or True
    )
    graph = StaticJsonDataProvider(dump_file).fetch_network_graph()
    out = tmp_path / "snapshot.json"

    write_snapshot(graph, out)

    assert restricted == [out]
