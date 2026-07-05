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
              "devices": [
                ...device payloads, or per-device section objects:
                { "info": { ...device payload... },
                  "switch_ports": [ ... ], "management_interface": { ... } }
              ],
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
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)

_NESTED_MARKER = "organizations"
#: Keys of a nested entry that are structural, not feature sections.
_ORG_STRUCTURAL_KEYS = frozenset({"info", "networks"})
_NETWORK_STRUCTURAL_KEYS = frozenset({"info", "devices"})
_DEVICE_STRUCTURAL_KEYS = frozenset({"info"})


class MalformedDumpError(ValueError):
    """The snapshot file is unreadable or violates the snapshot contract."""


class StaticJsonDataProvider(MerakiDataProvider):
    """Serves the domain graph from an offline snapshot file."""

    mode = "dump"

    def __init__(self, dump_path: Path, parser: OpenApiParser | None = None) -> None:
        self._path = dump_path
        self._parser = parser
        self._matchers: dict[str, FeatureSectionMatcher] = {}
        self._get_ops: dict[str, OperationSpec] | None = None
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
        # `or ""` also folds an explicit JSON null into "missing" — str(None)
        # would otherwise yield the truthy organization ID "None".
        org_id = organization_id or str(self._document.get("organizationId") or "").strip()
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
            normalized
            for item in coerce_sequence(self._document.get("features"), "'features'")
            for normalized in self._normalized_contract_features(self._feature(item))
        )
        graph = NetworkGraph(
            organization_id=org_id,
            networks=networks,
            devices=devices,
            features=features,
        )
        self._log_graph(graph)
        return graph

    def _normalized_contract_features(
        self, feature: FeatureConfiguration
    ) -> list[FeatureConfiguration]:
        """Replay a stored feature through the shared expansion path.

        Canonical snapshots written before paginated ``{items, meta}``
        envelopes were understood store whole envelope collections as one
        scope-addressed asset. Re-expanding dict payloads recorded at a
        single-scope collection endpoint heals those snapshots into the
        per-item assets live discovery now produces — and is an identity
        transform for snapshots captured after the fix (genuine singleton
        payloads expand to themselves).
        """
        if self._parser is None or not isinstance(feature.payload, dict):
            return [feature]
        if len(feature.path_values) != 1:
            return [feature]
        op = self._collection_get_ops().get(feature.api_path)
        if op is None:
            return [feature]
        return expand_endpoint_payload(
            self._parser, op, feature.path_values[0], feature.payload
        )

    def _collection_get_ops(self) -> dict[str, OperationSpec]:
        """Single-scope GET operations by path, built once per snapshot."""
        if self._get_ops is None:
            assert self._parser is not None  # guarded by the caller
            self._get_ops = {
                op.path: op
                for op in self._parser.endpoints()
                if op.method == "get" and len(op.path_params) == 1
            }
        return self._get_ops

    def _feature(self, item: Any) -> FeatureConfiguration:
        if not isinstance(item, dict) or not str(item.get("apiPath") or "").strip():
            raise MalformedDumpError(
                f"Snapshot {self._path}: each feature needs an 'apiPath' template."
            )
        raw_values = item.get("pathValues") or ()
        if not isinstance(raw_values, (list, tuple)):
            # A bare string would iterate character by character and
            # silently produce garbage compound import IDs.
            raise MalformedDumpError(
                f"Snapshot {self._path}: feature 'pathValues' must be an "
                f"array of ID components, got {type(raw_values).__name__}."
            )
        return FeatureConfiguration(
            api_path=str(item["apiPath"]),
            path_values=tuple(str(v) for v in raw_values),
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
                str(info.get("id") or "").strip() if isinstance(info, dict) else ""
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
                for device_entry in coerce_sequence(
                    network_entry.get("devices"), "'devices'"
                ):
                    device, device_features = self._device_entry(
                        device_entry, unmatched
                    )
                    devices.append(device)
                    features.extend(device_features)
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

    def _device_entry(
        self, entry: Any, unmatched: Counter[str]
    ) -> tuple[MerakiDevice, list[FeatureConfiguration]]:
        """One nested device: a flat payload, or ``{info, <sections>…}``.

        The structured form carries per-device configuration sections
        (``switch_ports``, ``management_interface``, …) which resolve
        onto serial-scoped spec endpoints — the same surfaces live
        discovery queries per device.
        """
        if not isinstance(entry, dict):
            raise MalformedDumpError(
                f"Snapshot {self._path}: each device entry must be an object."
            )
        if "info" not in entry:
            return MerakiDevice.from_payload(entry), []
        device = MerakiDevice.from_payload(entry.get("info") or {})
        features: list[FeatureConfiguration] = []
        for section, payload in entry.items():
            if section in _DEVICE_STRUCTURAL_KEYS:
                continue
            features.extend(
                self._section_features(
                    section, payload, "serial", device.serial, unmatched
                )
            )
        return device, features

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
