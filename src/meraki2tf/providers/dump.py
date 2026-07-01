"""StaticJsonDataProvider: offline ingestion from a JSON snapshot file.

Backs the ``--from-dump`` flag for air-gapped runtimes, scheduled
offline parsing, and regression validation. Snapshot contract::

    {
      "organizationId": "123456",
      "networks":  [ ...raw Meraki network payloads... ],
      "devices":   [ ...raw Meraki device payloads... ],
      "features":  [
        {
          "apiPath": "/networks/{networkId}/appliance/vlans/{vlanId}",
          "pathValues": ["N_1", "10"],
          "payload": { ... }
        }
      ]
    }

``networks``/``devices`` entries use the exact shapes the cloud API
returns, and features address themselves by OpenAPI path template —
which is what guarantees structural parity with the live provider.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
    coerce_sequence,
)
from meraki2tf.providers.base import MerakiDataProvider

logger = logging.getLogger(__name__)


class MalformedDumpError(ValueError):
    """The snapshot file is unreadable or violates the snapshot contract."""


class StaticJsonDataProvider(MerakiDataProvider):
    """Serves the domain graph from an offline snapshot file."""

    mode = "dump"

    def __init__(self, dump_path: Path) -> None:
        self._path = dump_path
        try:
            document = json.loads(dump_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MalformedDumpError(f"Cannot read snapshot {dump_path}: {exc}") from exc
        if not isinstance(document, dict):
            raise MalformedDumpError(f"Snapshot {dump_path} must be a JSON object.")
        self._document: dict[str, Any] = document
        logger.debug("Loaded offline snapshot from %s", dump_path)

    def fetch_network_graph(self, organization_id: str | None = None) -> NetworkGraph:
        org_id = organization_id or str(self._document.get("organizationId", "")).strip()
        if not org_id:
            raise MalformedDumpError(
                f"Snapshot {self._path} records no organizationId and none was supplied."
            )
        networks = tuple(
            MerakiNetwork.from_payload(item)
            for item in coerce_sequence(self._document.get("networks"), "'networks'")
        )
        devices = tuple(
            MerakiDevice.from_payload(item)
            for item in coerce_sequence(self._document.get("devices"), "'devices'")
        )
        features = tuple(
            self._feature(item)
            for item in coerce_sequence(self._document.get("features"), "'features'")
        )
        graph = NetworkGraph(
            organization_id=org_id,
            networks=networks,
            devices=devices,
            features=features,
        )
        logger.info(
            "Snapshot graph loaded: %d network(s), %d device(s), %d feature(s)",
            len(networks), len(devices), len(features),
        )
        return graph

    def _feature(self, item: Any) -> FeatureConfiguration:
        if not isinstance(item, dict) or not str(item.get("apiPath", "")).strip():
            raise MalformedDumpError(
                f"Snapshot {self._path}: each feature needs an 'apiPath' template."
            )
        return FeatureConfiguration(
            api_path=str(item["apiPath"]),
            path_values=tuple(str(v) for v in item.get("pathValues") or ()),
            payload=item.get("payload") or {},
        )

    def close(self) -> None:
        """Nothing to release for a file-backed snapshot."""
