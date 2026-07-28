"""Snapshot writer: serialize a discovered graph to the dump contract.

Backs the ``--dump-to`` flag. The output is the canonical offline
snapshot format consumed by ``--from-dump`` (see
:mod:`meraki2tf.providers.dump`), so a graph discovered live — or read
from a nested third-party export — can be captured once and replayed in
air-gapped runtimes, scheduled offline parsing, and regression tests.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TextIO

from meraki2tf.fsperms import restrict_to_owner
from meraki2tf.models import NetworkGraph

logger = logging.getLogger(__name__)


def graph_to_snapshot(graph: NetworkGraph) -> dict[str, Any]:
    """Serialize a domain graph into the canonical snapshot document."""
    return {
        "organizationId": graph.organization_id,
        # Full API payloads (restore-grade), with the canonical identity
        # fields normalized on top so legacy consumers keep working.
        "networks": [
            {
                **dict(network.payload),
                "id": network.network_id,
                "organizationId": network.organization_id,
                "name": network.name,
                "productTypes": list(network.product_types),
            }
            for network in graph.networks
        ],
        "devices": [
            {
                **dict(device.payload),
                "serial": device.serial,
                "networkId": device.network_id,
                "model": device.model,
                "name": device.name,
            }
            for device in graph.devices
        ],
        "features": [
            {
                "apiPath": feature.api_path,
                "pathValues": list(feature.path_values),
                "payload": feature.payload,
            }
            for feature in graph.features
        ],
    }


#: First line of a v2 snapshot: a header object carrying this marker.
SNAPSHOT_V2_MARKER = "meraki2tfSnapshot"
SNAPSHOT_V2_VERSION = 2

#: ``kind`` of the v2 stream's final record — the end-of-stream proof.
#:
#: Local writes are already crash-safe (temp file + rename + fsync), but
#: a snapshot is a *transported* artifact: uploaded to blob storage,
#: rotated in as next week's ``--drift-baseline``, copied to an
#: air-gapped host. Any of those can deliver a well-formed prefix — a
#: complete gzip member holding half the records, or a ``.jsonl`` cut on
#: a line boundary — and every line-oriented reader would accept it as a
#: whole-organization capture. Nothing in the format said "this is the
#: end", so a half-captured org read as a small org: coverage reported a
#: confident percentage of the fraction that survived, and --restore
#: would rebuild that fraction and call it a success.
SNAPSHOT_V2_TRAILER_KIND = "meraki2tfSnapshotEnd"

#: Header flag announcing that this writer emits the trailer above.
#:
#: Readers need it to tell "truncated" from "written by an older
#: meraki2tf": snapshots in the field predate the trailer, and the
#: weekly job feeds last week's snapshot to this week's run, so a blanket
#: refusal would break the first run after an upgrade. Flag present ⇒
#: the trailer is mandatory and a missing one is corruption.
SNAPSHOT_V2_TRAILER_FLAG = "trailer"

#: Suffixes selecting the v2 stream format from --dump-to paths.
_V2_SUFFIXES = (".jsonl.gz", ".jsonl")


def _wants_v2(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in _V2_SUFFIXES)


def _scope_header(
    graph: NetworkGraph,
    scope_selectors: tuple[str, ...] | None,
    sanitized: bool,
) -> dict[str, Any] | None:
    """The header's ``scope`` object for a partial (``--only``) export.

    Network IDs come from the graph actually being written, so a
    sanitized export records pseudonymized IDs automatically. The raw
    selector strings are omitted from sanitized snapshots — they can
    carry real network names, an identity leak in a shareable artifact.
    """
    if scope_selectors is None:
        return None
    scope: dict[str, Any] = {
        "networks": [network.network_id for network in graph.networks],
    }
    if not sanitized:
        scope["selectors"] = list(scope_selectors)
    return scope


def write_snapshot(
    graph: NetworkGraph,
    path: Path,
    sanitized: bool = False,
    scope_selectors: tuple[str, ...] | None = None,
    spec_version: str | None = None,
    spec_sha256: str | None = None,
) -> Path:
    """Write the canonical snapshot for later ``--from-dump`` runs.

    Written owner-only (0600): an unsanitized snapshot carries every
    credential Meraki returns on GET (SSID PSKs, SNMP community
    strings, …) — it is the DR kit's secret-bearing artifact.

    ``sanitized`` stamps the document so downstream consumers can tell
    a pseudonymized drill snapshot from the real one: the restore
    source-org interlock compares against the recorded org ID, and a
    pseudonym can never match the production org it stands for.

    Paths ending in ``.jsonl`` / ``.jsonl.gz`` select the v2 stream
    format: a header line followed by one object per line, gzip-
    compressed when the name says so. At 200k-object scale the v1
    pretty-printed document costs gigabytes and three in-memory copies;
    v2 streams one small line at a time and compresses ~10-20×.

    ``scope_selectors`` marks a **partial** export (``--dump-to`` with
    ``--only``): the document gains a ``scope`` header naming the
    covered networks, so downstream consumers can honor, stamp, or
    refuse it — a partial snapshot must never read as a full-org
    capture (see :mod:`meraki2tf.scope`).

    ``spec_version``/``spec_sha256`` record the OpenAPI document the
    discovery ran against (optional header fields, ignored by older
    readers): a later ``--restore``/``--heal`` compares them against
    its own runtime spec and warns about skew before writing.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename: the snapshot is the org's only rebuild source
    # of truth, so a crash or full disk mid-write must corrupt the
    # temporary file, never the previous good snapshot. mkstemp gives a
    # per-process unique name in the target directory (same filesystem,
    # so the rename stays atomic; two concurrent runs can never
    # interleave writes into one temp file) and creates it 0600
    # *before* any secret bytes land in it; os.replace carries that
    # mode onto the final path.
    fd, tmp_name = tempfile.mkstemp(
        dir=path.parent, prefix=path.name + ".", suffix=".tmp"
    )
    os.close(fd)
    tmp = Path(tmp_name)
    restrict_to_owner(tmp)
    scope = _scope_header(graph, scope_selectors, sanitized)
    try:
        if _wants_v2(path):
            _write_snapshot_v2(
                graph, path, tmp, sanitized=sanitized, scope=scope,
                spec_version=spec_version, spec_sha256=spec_sha256,
            )
        else:
            document = graph_to_snapshot(graph)
            if sanitized:
                document["sanitized"] = True
            if scope is not None:
                document["scope"] = scope
            if spec_version is not None:
                document["specVersion"] = spec_version
            if spec_sha256 is not None:
                document["specSha256"] = spec_sha256
            _write_v1_document(document, path, tmp)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    # Make the rename itself durable: without a directory fsync a crash
    # can roll the directory entry back to the previous snapshot — or,
    # on some filesystems, to a zero-length file. Best-effort: not every
    # platform/filesystem supports fsync on a directory handle.
    _fsync_directory(path.parent)
    logger.info(
        "Snapshot written to %s: %d network(s), %d device(s), %d feature(s).",
        path, len(graph.networks), len(graph.devices), len(graph.features),
    )
    return path


def _fsync_directory(directory: Path) -> None:
    """Flush a completed rename to disk, where the platform allows it."""
    try:
        dir_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:  # pragma: no cover - platform/filesystem dependent
        pass
    finally:
        os.close(dir_fd)


def _warn_kind_collision(
    record_kind: str, identifier: str, payload: Any
) -> None:
    """WARN loudly when a payload's own ``kind`` field is displaced.

    The v2 stream reserves ``kind`` for its record discriminator, so a
    network/device payload that legitimately carries one loses it in
    this format — the loss must never be silent (the snapshot is the
    restore-grade source of truth). Preserving the field would need a
    versioned format migration; until then, the v1 ``.json`` format
    keeps it.
    """
    if isinstance(payload, Mapping) and "kind" in payload:
        logger.warning(
            "%s %s: payload field 'kind' collides with the v2 stream's "
            "record discriminator and is NOT preserved in this snapshot. "
            "Write a v1 (.json) snapshot to keep it.",
            record_kind.capitalize(), identifier,
        )


def _write_v1_document(
    document: dict[str, Any], path: Path, target: Path
) -> None:
    """Write the v1 pretty-printed document, honoring a ``.gz`` name.

    Format selection keys on the *final* path's name (bytes land in the
    temporary file the caller renames into place), matching the v2
    writer. Without this a ``--dump-to snapshot.json.gz`` produced plain
    JSON under a ``.gz`` name: the content-sniffing reader still loaded
    it, but every external ``gzip``/``zcat`` consumer failed on it and,
    at scale, a user who asked for compression silently got none.
    """
    body = json.dumps(document, indent=2) + "\n"
    with target.open("wb") as raw:
        if path.name.lower().endswith(".gz"):
            # Close the gzip layer before the fsync: the final deflate
            # block and CRC trailer are written on close, so an earlier
            # fsync could persist — then atomically rename into place — a
            # truncated stream.
            with gzip.GzipFile(fileobj=raw, mode="wb") as compressed:
                compressed.write(body.encode("utf-8"))
        else:
            raw.write(body.encode("utf-8"))
        raw.flush()
        os.fsync(raw.fileno())


def _write_snapshot_v2(
    graph: NetworkGraph,
    path: Path,
    target: Path,
    sanitized: bool = False,
    scope: dict[str, Any] | None = None,
    spec_version: str | None = None,
    spec_sha256: str | None = None,
) -> None:
    # Format selection keys on the *final* path's name; bytes land in
    # the temporary file the caller renames into place.
    header: dict[str, Any] = {
        SNAPSHOT_V2_MARKER: SNAPSHOT_V2_VERSION,
        "organizationId": graph.organization_id,
        SNAPSHOT_V2_TRAILER_FLAG: True,
    }
    if sanitized:
        header["sanitized"] = True
    if scope is not None:
        header["scope"] = scope
    if spec_version is not None:
        header["specVersion"] = spec_version
    if spec_sha256 is not None:
        header["specSha256"] = spec_sha256
    with target.open("wb") as raw:
        if path.name.lower().endswith(".gz"):
            # The gzip layer must be CLOSED before the fsync below: the
            # final deflate block and CRC trailer are written on close,
            # so an earlier fsync could persist — and then atomically
            # rename into place — a truncated stream.
            with gzip.GzipFile(fileobj=raw, mode="wb") as compressed:
                with io.TextIOWrapper(compressed, encoding="utf-8") as handle:
                    _write_v2_records(handle, graph, header)
        else:
            plain = io.TextIOWrapper(raw, encoding="utf-8")
            _write_v2_records(plain, graph, header)
            plain.flush()
            plain.detach()  # keep `raw` open for the fsync below
        raw.flush()
        os.fsync(raw.fileno())


def _write_v2_records(
    handle: TextIO, graph: NetworkGraph, header: dict[str, Any]
) -> None:
    handle.write(json.dumps(header) + "\n")
    for network in graph.networks:
        _warn_kind_collision("network", network.network_id, network.payload)
        handle.write(
            json.dumps(
                {
                    # Spread first: a payload key named "kind" must
                    # never overwrite the record discriminator (the
                    # reader silently drops unknown kinds).
                    **dict(network.payload),
                    "kind": "network",
                    "id": network.network_id,
                    "organizationId": network.organization_id,
                    "name": network.name,
                    "productTypes": list(network.product_types),
                }
            )
            + "\n"
        )
    for device in graph.devices:
        _warn_kind_collision("device", device.serial, device.payload)
        handle.write(
            json.dumps(
                {
                    **dict(device.payload),
                    "kind": "device",
                    "serial": device.serial,
                    "networkId": device.network_id,
                    "model": device.model,
                    "name": device.name,
                }
            )
            + "\n"
        )
    for feature in graph.features:
        handle.write(
            json.dumps(
                {
                    "kind": "feature",
                    "apiPath": feature.api_path,
                    "pathValues": list(feature.path_values),
                    "payload": feature.payload,
                }
            )
            + "\n"
        )
    # End-of-stream proof, written last on purpose: reaching this line
    # means every record above it made it out of the writer. The count
    # catches the subtler corruption a bare marker misses — records lost
    # from the middle of a stream that still ends correctly.
    handle.write(
        json.dumps(
            {
                "kind": SNAPSHOT_V2_TRAILER_KIND,
                "records": (
                    len(graph.networks)
                    + len(graph.devices)
                    + len(graph.features)
                ),
            }
        )
        + "\n"
    )
