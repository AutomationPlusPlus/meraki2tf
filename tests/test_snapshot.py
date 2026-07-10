"""Snapshot writer: canonical serialization and dump-provider round trip."""

import json
from pathlib import Path
from typing import Any

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


def test_snapshot_carries_full_network_and_device_payloads(tmp_path: Path) -> None:
    """Restore-grade contract: fields beyond the identity surface
    (timezone, tags, device placement) survive the snapshot round trip."""
    from meraki2tf.models import MerakiDevice, MerakiNetwork, NetworkGraph
    from meraki2tf.providers import StaticJsonDataProvider

    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {
                    "id": "N_1",
                    "organizationId": "org-123",
                    "name": "HQ",
                    "productTypes": ["appliance"],
                    "timeZone": "Europe/Berlin",
                    "tags": ["core"],
                }
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {
                    "serial": "Q2AB-CDEF-GHIJ",
                    "networkId": "N_1",
                    "model": "MX68",
                    "name": "edge",
                    "address": "1 Main St",
                    "floorPlanId": "fp-9",
                }
            ),
        ),
        features=(),
    )
    document = graph_to_snapshot(graph)
    assert document["networks"][0]["timeZone"] == "Europe/Berlin"
    assert document["devices"][0]["floorPlanId"] == "fp-9"

    path = write_snapshot(graph, tmp_path / "snap.json")
    loaded = StaticJsonDataProvider(path).fetch_network_graph()
    assert loaded.networks[0].payload["timeZone"] == "Europe/Berlin"
    assert loaded.devices[0].payload["address"] == "1 Main St"


def _payload_graph() -> Any:
    from meraki2tf.models import (
        FeatureConfiguration,
        MerakiDevice,
        MerakiNetwork,
        NetworkGraph,
    )

    return NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {
                    "id": "N_1",
                    "organizationId": "org-123",
                    "name": "HQ",
                    "productTypes": ["appliance"],
                    "timeZone": "Europe/Berlin",
                }
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1", "model": "MX68",
                 "name": "edge", "address": "1 Main St"}
            ),
        ),
        features=(
            FeatureConfiguration(
                "/networks/{networkId}/appliance/vlans/{vlanId}",
                ("N_1", "10"),
                {"id": 10, "name": "Data"},
            ),
        ),
    )


@pytest.mark.parametrize("name", ["snap.jsonl.gz", "snap.jsonl"])
def test_snapshot_v2_stream_round_trips(tmp_path: Path, name: str) -> None:
    """The v2 stream format (JSONL, optionally gzipped) round-trips the
    full graph and is detected by content, not filename."""
    graph = _payload_graph()
    path = write_snapshot(graph, tmp_path / name)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    if name.endswith(".gz"):
        assert path.read_bytes()[:2] == b"\x1f\x8b"

    # Rename away the meaningful suffix: detection must be content-based.
    renamed = path.rename(tmp_path / "renamed.dat")
    loaded = StaticJsonDataProvider(renamed).fetch_network_graph()
    assert loaded.organization_id == "org-123"
    assert loaded.networks[0].payload["timeZone"] == "Europe/Berlin"
    assert loaded.devices[0].payload["address"] == "1 Main St"
    assert [(f.api_path, f.path_values) for f in loaded.features] == [
        ("/networks/{networkId}/appliance/vlans/{vlanId}", ("N_1", "10")),
    ]


def test_snapshot_v2_is_dramatically_smaller_than_v1(tmp_path: Path) -> None:
    graph = _payload_graph()
    v1 = write_snapshot(graph, tmp_path / "snap.json")
    v2 = write_snapshot(graph, tmp_path / "snap.jsonl.gz")
    assert v2.stat().st_size < v1.stat().st_size


def test_snapshot_v2_loader_tolerates_stray_lines(tmp_path: Path) -> None:
    """Blank lines, non-object records, and unknown kinds are skipped —
    a hand-edited or partially-corrupt stream degrades loudly at the
    model layer, not with a parser crash here."""
    path = tmp_path / "stray.jsonl"
    path.write_text(
        '{"meraki2tfSnapshot": 2, "organizationId": "org-123"}\n'
        "\n"
        '"just-a-string"\n'
        '{"kind": "mystery", "x": 1}\n'
        '{"kind": "network", "id": "N_1", "organizationId": "org-123"}\n',
        encoding="utf-8",
    )
    loaded = StaticJsonDataProvider(path).fetch_network_graph()
    assert [n.network_id for n in loaded.networks] == ["N_1"]
    assert loaded.devices == () and loaded.features == ()
