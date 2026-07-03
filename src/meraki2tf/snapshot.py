"""Snapshot writer: serialize a discovered graph to the dump contract.

Backs the ``--dump-to`` flag. The output is the canonical offline
snapshot format consumed by ``--from-dump`` (see
:mod:`meraki2tf.providers.dump`), so a graph discovered live — or read
from a nested third-party export — can be captured once and replayed in
air-gapped runtimes, scheduled offline parsing, and regression tests.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from meraki2tf.fsperms import restrict_to_owner
from meraki2tf.models import NetworkGraph

logger = logging.getLogger(__name__)


def graph_to_snapshot(graph: NetworkGraph) -> dict[str, Any]:
    """Serialize a domain graph into the canonical snapshot document."""
    return {
        "organizationId": graph.organization_id,
        "networks": [
            {
                "id": network.network_id,
                "organizationId": network.organization_id,
                "name": network.name,
                "productTypes": list(network.product_types),
            }
            for network in graph.networks
        ],
        "devices": [
            {
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


def write_snapshot(graph: NetworkGraph, path: Path) -> Path:
    """Write the canonical snapshot document for later ``--from-dump`` runs.

    Written owner-only (0600): an unsanitized snapshot carries every
    credential Meraki returns on GET (SSID PSKs, SNMP community
    strings, …) — it is the DR kit's secret-bearing artifact.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600, exist_ok=True)
    restrict_to_owner(path)
    path.write_text(
        json.dumps(graph_to_snapshot(graph), indent=2) + "\n", encoding="utf-8"
    )
    logger.info(
        "Snapshot written to %s: %d network(s), %d device(s), %d feature(s).",
        path, len(graph.networks), len(graph.devices), len(graph.features),
    )
    return path
