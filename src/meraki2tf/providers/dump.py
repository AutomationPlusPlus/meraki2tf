"""StaticJsonDataProvider: offline ingestion from a JSON snapshot file.

Backs the ``--from-dump`` flag for air-gapped runtimes, scheduled
offline parsing, and regression validation. Two snapshot layouts are
accepted.

**Canonical contract** — features address themselves by OpenAPI path
template, which guarantees structural parity with the live provider::

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

**Nested export layout** — the shape produced by common Meraki
export/backup scripts, detected by a top-level ``organizations`` array::

    {
      "organizations": [
        {
          "info": { ...organization payload... },
          "networks": [
            {
              "info": { ...network payload... },
              "devices": [ ...device payloads... ],
              "vlans": [ ... ], "ssids": [ ... ], "firewall_l3": { ... }
            }
          ],
          "admins": [ ... ], "snmp": { ... }
        }
      ]
    }

Nested section names (``vlans``, ``firewall_l3``, …) carry no API path,
so each one is resolved onto its OpenAPI endpoint dynamically via
:class:`~meraki2tf.providers.discovery.FeatureSectionMatcher` and then
expanded through the same code path the live provider uses — no
hard-coded section registry. Sections that resolve to no configuration
endpoint (operational telemetry such as client or status lists, or
names the spec cannot disambiguate) are reported and skipped.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
    coerce_sequence,
)
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.providers.discovery import (
    FeatureSectionMatcher,
    expand_endpoint_payload,
)

logger = logging.getLogger(__name__)

_NESTED_MARKER = "organizations"
#: Keys of a nested entry that are structural, not feature sections.
_ORG_STRUCTURAL_KEYS = frozenset({"info", "networks"})
_NETWORK_STRUCTURAL_KEYS = frozenset({"info", "devices"})


class MalformedDumpError(ValueError):
    """The snapshot file is unreadable or violates the snapshot contract."""


class StaticJsonDataProvider(MerakiDataProvider):
    """Serves the domain graph from an offline snapshot file."""

    mode = "dump"

    def __init__(self, dump_path: Path, parser: OpenApiParser | None = None) -> None:
        self._path = dump_path
        self._parser = parser
        self._matchers: dict[str, FeatureSectionMatcher] = {}
        try:
            document = json.loads(dump_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MalformedDumpError(f"Cannot read snapshot {dump_path}: {exc}") from exc
        if not isinstance(document, dict):
            raise MalformedDumpError(f"Snapshot {dump_path} must be a JSON object.")
        self._document: dict[str, Any] = document
        logger.debug("Loaded offline snapshot from %s", dump_path)

    def fetch_network_graph(self, organization_id: str | None = None) -> NetworkGraph:
        if _NESTED_MARKER in self._document:
            return self._graph_from_nested(organization_id)
        return self._graph_from_contract(organization_id)

    # ------------------------------------------------------------------
    # Canonical snapshot contract
    # ------------------------------------------------------------------

    def _graph_from_contract(self, organization_id: str | None) -> NetworkGraph:
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
        self._log_graph(graph)
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

    # ------------------------------------------------------------------
    # Nested export layout
    # ------------------------------------------------------------------

    def _graph_from_nested(self, organization_id: str | None) -> NetworkGraph:
        organizations = coerce_sequence(
            self._document.get(_NESTED_MARKER), f"'{_NESTED_MARKER}'"
        )
        networks: list[MerakiNetwork] = []
        devices: list[MerakiDevice] = []
        features: list[FeatureConfiguration] = []
        unmatched: Counter[str] = Counter()
        recorded_org_ids: list[str] = []

        for entry in organizations:
            if not isinstance(entry, dict):
                raise MalformedDumpError(
                    f"Snapshot {self._path}: each organization entry must be an object."
                )
            info = entry.get("info")
            org_id = (
                str(info.get("id", "")).strip() if isinstance(info, dict) else ""
            ) or (organization_id or "")
            if not org_id:
                raise MalformedDumpError(
                    f"Snapshot {self._path}: an organization entry records no "
                    "info.id and no --org-id was supplied."
                )
            recorded_org_ids.append(org_id)
            for section, payload in entry.items():
                if section in _ORG_STRUCTURAL_KEYS:
                    continue
                features.extend(
                    self._section_features(
                        section, payload, "organizationId", org_id, unmatched
                    )
                )
            for network_entry in coerce_sequence(entry.get("networks"), "'networks'"):
                if not isinstance(network_entry, dict):
                    raise MalformedDumpError(
                        f"Snapshot {self._path}: each network entry must be an object."
                    )
                network = MerakiNetwork.from_payload(network_entry.get("info") or {})
                networks.append(network)
                devices.extend(
                    MerakiDevice.from_payload(item)
                    for item in coerce_sequence(
                        network_entry.get("devices"), "'devices'"
                    )
                )
                for section, payload in network_entry.items():
                    if section in _NETWORK_STRUCTURAL_KEYS:
                        continue
                    features.extend(
                        self._section_features(
                            section, payload, "networkId", network.network_id, unmatched
                        )
                    )

        if organization_id and recorded_org_ids and organization_id not in recorded_org_ids:
            logger.warning(
                "Snapshot %s records organization(s) %s, not %r; processing the "
                "snapshot's own organizations.",
                self._path, recorded_org_ids, organization_id,
            )
        for section, count in sorted(unmatched.items()):
            logger.warning(
                "Dump section %r resolves to no spec-derived configuration "
                "endpoint; skipped (%d occurrence(s)).",
                section, count,
            )
        graph_org = organization_id or (recorded_org_ids[0] if recorded_org_ids else "")
        if not graph_org:
            raise MalformedDumpError(
                f"Snapshot {self._path} records no organizations and no "
                "--org-id was supplied."
            )
        graph = NetworkGraph(
            organization_id=graph_org,
            networks=tuple(networks),
            devices=tuple(devices),
            features=tuple(features),
        )
        self._log_graph(graph)
        return graph

    def _section_features(
        self,
        section: str,
        payload: Any,
        scope_param: str,
        scope_value: str,
        unmatched: Counter[str],
    ) -> list[FeatureConfiguration]:
        if payload is None or payload == []:
            return []
        if not isinstance(payload, (dict, list)):
            unmatched[section] += 1
            return []
        if self._parser is None:
            unmatched[section] += 1
            return []
        sample_keys = self._sample_keys(payload)
        op = self._matcher(scope_param).match(section, sample_keys)
        if op is None:
            unmatched[section] += 1
            return []
        return expand_endpoint_payload(self._parser, op, scope_value, payload)

    @staticmethod
    def _sample_keys(payload: Any) -> frozenset[str]:
        """Observed payload field names, used only to break lexical ties."""
        if isinstance(payload, dict):
            return frozenset(payload)
        return frozenset(
            key
            for element in payload
            if isinstance(element, dict)
            for key in element
        )

    def _matcher(self, scope_param: str) -> FeatureSectionMatcher:
        assert self._parser is not None  # guarded by _section_features
        if scope_param not in self._matchers:
            self._matchers[scope_param] = FeatureSectionMatcher(
                self._parser, scope_param
            )
        return self._matchers[scope_param]

    def _log_graph(self, graph: NetworkGraph) -> None:
        logger.info(
            "Snapshot graph loaded: %d network(s), %d device(s), %d feature(s)",
            len(graph.networks), len(graph.devices), len(graph.features),
        )

    def close(self) -> None:
        """Nothing to release for a file-backed snapshot."""
