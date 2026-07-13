"""Snapshot writer: serialize a discovered graph to the dump contract.

Backs the ``--dump-to`` flag. The output is the canonical offline
snapshot format consumed by ``--from-dump`` (see
:mod:`meraki2tf.providers.dump`), so a graph discovered live — or read
from a nested third-party export — can be captured once and replayed in
air-gapped runtimes, scheduled offline parsing, and regression tests.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

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

#: Suffixes selecting the v2 stream format from --dump-to paths.
_V2_SUFFIXES = (".jsonl.gz", ".jsonl")


def _wants_v2(path: Path) -> bool:
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in _V2_SUFFIXES)


def write_snapshot(
    graph: NetworkGraph, path: Path, sanitized: bool = False
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
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename: the snapshot is the org's only rebuild source
    # of truth, so a crash or full disk mid-write must corrupt the
    # temporary file, never the previous good snapshot. The temp file
    # is created 0600 *before* any secret bytes land in it, and
    # os.replace carries that mode onto the final path.
    tmp = path.with_name(path.name + ".tmp")
    tmp.touch(mode=0o600, exist_ok=True)
    restrict_to_owner(tmp)
    try:
        if _wants_v2(path):
            _write_snapshot_v2(graph, path, tmp, sanitized=sanitized)
        else:
            document = graph_to_snapshot(graph)
            if sanitized:
                document["sanitized"] = True
            with tmp.open("w", encoding="utf-8") as handle:
                handle.write(json.dumps(document, indent=2) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    logger.info(
        "Snapshot written to %s: %d network(s), %d device(s), %d feature(s).",
        path, len(graph.networks), len(graph.devices), len(graph.features),
    )
    return path


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


def _write_snapshot_v2(
    graph: NetworkGraph, path: Path, target: Path, sanitized: bool = False
) -> None:
    # Format selection keys on the *final* path's name; bytes land in
    # the temporary file the caller renames into place.
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    header: dict[str, Any] = {
        SNAPSHOT_V2_MARKER: SNAPSHOT_V2_VERSION,
        "organizationId": graph.organization_id,
    }
    if sanitized:
        header["sanitized"] = True
    with opener(target, "wt", encoding="utf-8") as handle:
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
        handle.flush()
        os.fsync(handle.fileno())
