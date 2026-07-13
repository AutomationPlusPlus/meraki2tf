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


def test_snapshot_write_preserves_the_prior_baseline_on_failure(
    dump_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The snapshot is the org's only rebuild source of truth: a crash
    mid-write must leave last week's good snapshot intact, never a
    truncated file."""
    graph = StaticJsonDataProvider(dump_file).fetch_network_graph()
    out = tmp_path / "snapshot.json"
    write_snapshot(graph, out)
    good = out.read_text(encoding="utf-8")

    real_replace = snapshot.os.replace

    def boom(src: Any, dst: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(snapshot.os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        write_snapshot(graph, out)
    monkeypatch.setattr(snapshot.os, "replace", real_replace)

    # The previous good snapshot survived, and no temp file was left.
    assert out.read_text(encoding="utf-8") == good
    assert list(tmp_path.glob(out.name + ".*")) == []


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

    # Enforcement targets the temp file the content lands in; the final
    # path inherits its 0600 mode through os.replace. The temp name is
    # unique per process (mkstemp) so concurrent runs never interleave.
    (tmp,) = restricted
    assert tmp.parent == out.parent
    assert tmp.name.startswith(out.name + ".") and tmp.name.endswith(".tmp")
    assert out.exists() and not tmp.exists()


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


def test_snapshot_v2_loader_tolerates_stray_lines(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Blank lines, non-object records, and unknown kinds are skipped —
    a hand-edited or partially-corrupt stream degrades loudly at the
    model layer, not with a parser crash here. Every skipped record
    (non-objects included) counts toward the loud record-loss warning."""
    path = tmp_path / "stray.jsonl"
    path.write_text(
        '{"meraki2tfSnapshot": 2, "organizationId": "org-123"}\n'
        "\n"
        '"just-a-string"\n'
        '{"kind": "mystery", "x": 1}\n'
        '{"kind": "network", "id": "N_1", "organizationId": "org-123"}\n',
        encoding="utf-8",
    )
    with caplog.at_level("WARNING", logger="meraki2tf.providers.dump"):
        loaded = StaticJsonDataProvider(path).fetch_network_graph()
    assert [n.network_id for n in loaded.networks] == ["N_1"]
    assert loaded.devices == () and loaded.features == ()
    (loss,) = [r for r in caplog.records if "unusable record" in r.message]
    # Both the string record AND the unknown kind count as dropped.
    assert loss.args[1] == 2


def test_snapshot_v2_survives_payload_key_named_kind(tmp_path: Path) -> None:
    """A payload field named "kind" must not overwrite the record
    discriminator — the reader would silently drop the whole object
    from the DR snapshot."""
    from meraki2tf.models import MerakiNetwork, NetworkGraph

    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "kind": "template-child"}
            ),
        ),
        devices=(),
        features=(),
    )
    path = write_snapshot(graph, tmp_path / "kindful.jsonl")
    loaded = StaticJsonDataProvider(path).fetch_network_graph()
    assert [n.network_id for n in loaded.networks] == ["N_1"]


def test_snapshot_v2_warns_when_kind_payload_field_is_displaced(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The v2 stream reserves "kind" for its record discriminator, so a
    payload's own "kind" field is not preserved — that loss must be
    loud, never silent (the snapshot is the restore-grade source of
    truth). v1 keeps the field and stays quiet."""
    from meraki2tf.models import MerakiDevice, MerakiNetwork, NetworkGraph

    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"], "kind": "template-child"}
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1",
                 "model": "MX68", "name": "edge", "kind": "spare"}
            ),
        ),
        features=(),
    )
    with caplog.at_level("WARNING", logger="meraki2tf.snapshot"):
        write_snapshot(graph, tmp_path / "kindful.jsonl")
    collisions = [r for r in caplog.records if "discriminator" in r.message]
    assert len(collisions) == 2
    assert any("Network N_1" in r.message for r in collisions)
    assert any("Device Q2AB-CDEF-GHIJ" in r.message for r in collisions)

    caplog.clear()
    with caplog.at_level("WARNING", logger="meraki2tf.snapshot"):
        v1 = write_snapshot(graph, tmp_path / "kindful.json")
    assert not [r for r in caplog.records if "discriminator" in r.message]
    loaded = StaticJsonDataProvider(v1).fetch_network_graph()
    assert loaded.networks[0].payload["kind"] == "template-child"


def test_gzip_stream_is_complete_before_the_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gzip trailer (final block + CRC) is written on close; the
    fsync-then-replace sequence must therefore run AFTER the gzip layer
    is closed, or a crash window could rename a truncated stream over
    the previous good snapshot."""
    import gzip

    graph = _payload_graph()
    seen: list[bytes] = []
    real_replace = snapshot.os.replace

    def capture(src: Any, dst: Any) -> None:
        # At replace time the temp file must already be a fully
        # decodable gzip stream, trailer included.
        seen.append(gzip.decompress(Path(src).read_bytes()))
        real_replace(src, dst)

    monkeypatch.setattr(snapshot.os, "replace", capture)
    write_snapshot(graph, tmp_path / "snap.jsonl.gz")
    (content,) = seen
    assert content.startswith(b'{"meraki2tfSnapshot": 2')


def test_concurrent_runs_get_distinct_temp_files(
    dump_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A fixed temp name would let two concurrent runs interleave writes
    and rename a garbled file into place; every write must land in its
    own uniquely named temp file."""
    graph = StaticJsonDataProvider(dump_file).fetch_network_graph()
    out = tmp_path / "snapshot.json"
    temp_names: list[str] = []
    real_replace = snapshot.os.replace

    def capture(src: Any, dst: Any) -> None:
        temp_names.append(Path(src).name)
        real_replace(src, dst)

    monkeypatch.setattr(snapshot.os, "replace", capture)
    write_snapshot(graph, out)
    write_snapshot(graph, out)
    first, second = temp_names
    assert first != second


def test_directory_fsync_is_best_effort(tmp_path: Path) -> None:
    """Platforms/filesystems that cannot open or fsync a directory must
    never fail the snapshot write."""
    snapshot._fsync_directory(tmp_path / "does-not-exist")  # no raise
    snapshot._fsync_directory(tmp_path)  # the happy path is quiet too


def test_sanitized_marker_round_trips_in_both_formats(tmp_path: Path) -> None:
    """A sanitized snapshot must be distinguishable from the real one:
    its identifiers are pseudonyms, so the restore source-org interlock
    is vacuous against it and consumers need to know."""
    graph = _payload_graph()
    for name in ("marked.json", "marked.jsonl"):
        path = write_snapshot(graph, tmp_path / name, sanitized=True)
        assert StaticJsonDataProvider(path).snapshot_sanitized is True
    for name in ("plain.json", "plain.jsonl"):
        path = write_snapshot(graph, tmp_path / name)
        assert StaticJsonDataProvider(path).snapshot_sanitized is False
