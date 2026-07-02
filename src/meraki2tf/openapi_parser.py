"""OpenApiParser: derive the API-to-Terraform lookup table from the spec.

First core intelligence layer of the pipeline. Everything here is
computed from the OpenAPI document itself using only standard-library
parsing (``json`` via the spec engine, ``re`` for name shaping) — no
hard-coded endpoint dictionaries or mapping tables, per the project
contract.

Derivation rules (all dynamic):

* **Entity key** — a path template's non-parameter segments, snake_cased
  (``/networks/{networkId}/appliance/vlans/{vlanId}`` →
  ``('networks', 'appliance', 'vlans')``). Collection and item endpoints
  of one entity share a key and collapse into one resource.
* **Canonicalization** — a collection-only key is folded into the
  longest suffix that exists elsewhere in the spec as an entity with its
  own item endpoint. That is how
  ``/organizations/{organizationId}/networks`` resolves to the
  ``networks`` entity (canonical item path ``/networks/{networkId}``)
  rather than a phantom ``organizations_networks`` resource.
* **Terraform name** — ``meraki_`` + the canonical key joined with
  underscores, matching the CiscoDevNet/meraki provider convention
  (``meraki_networks``, ``meraki_networks_appliance_vlans``).
* **Composite import ID** — the ordered path parameters of the entity's
  most specific endpoint, snake_cased and comma-joined
  (``network_id,vlan_id``), ready for Terraform ``import`` blocks.
* **Resource eligibility** — an entity must expose at least one GET
  endpoint; action-only RPC paths (e.g. ``blinkLeds``) are excluded.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from meraki2tf.spec.engine import OperationSpec, SpecIngestionEngine

logger = logging.getLogger(__name__)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_PARAM_SEGMENT = re.compile(r"^\{.+\}$")

TERRAFORM_PROVIDER_PREFIX = "meraki"


def snake_case(name: str) -> str:
    """``trafficShaping`` → ``traffic_shaping``; ``organizationId`` → ``organization_id``."""
    return _CAMEL_BOUNDARY.sub("_", name).lower()


def _segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def entity_key(path: str) -> tuple[str, ...]:
    """Non-parameter segments of a path template, snake_cased."""
    return tuple(
        snake_case(segment)
        for segment in _segments(path)
        if not _PARAM_SEGMENT.match(segment)
    )


def is_item_path(path: str) -> bool:
    """True when the template addresses one entity instance (ends in a parameter)."""
    segments = _segments(path)
    return bool(segments) and bool(_PARAM_SEGMENT.match(segments[-1]))


@dataclass(frozen=True)
class TerraformResourceMapping:
    """One derived Terraform resource and how to import it."""

    #: Provider resource type, e.g. ``meraki_networks_appliance_vlans``.
    terraform_name: str
    #: Canonical entity key the name was derived from.
    entity_key: tuple[str, ...]
    #: Ordered, snake_cased path parameters forming the compound ID.
    id_components: tuple[str, ...]
    #: Comma-joined composite import string, e.g. ``network_id,vlan_id``.
    import_id_format: str
    #: Every contributing path template, in spec order.
    paths: tuple[str, ...]
    #: Every contributing operation, in spec order.
    operations: tuple[OperationSpec, ...]


class OpenApiParser:
    """Parses a Meraki ``openapi.json`` file into a Terraform resource lookup."""

    def __init__(self, spec_path: Path) -> None:
        self._engine = SpecIngestionEngine.from_file(spec_path)
        self._endpoints: tuple[OperationSpec, ...] = tuple(self._engine.operations())
        logger.debug("Parsed %d operation(s) from %s", len(self._endpoints), spec_path)

    def endpoints(self) -> tuple[OperationSpec, ...]:
        """Every operation discovered in the document, in spec order."""
        return self._endpoints

    def resource_mappings(self) -> dict[str, TerraformResourceMapping]:
        """Derive all Terraform resources, keyed by provider resource name."""
        grouped = self._group_by_entity()
        canonical_keys = {
            key
            for key, ops in grouped.items()
            if any(is_item_path(op.path) for op in ops)
        }
        merged: dict[tuple[str, ...], list[OperationSpec]] = {}
        for key, ops in grouped.items():
            merged.setdefault(self._canonicalize(key, canonical_keys), []).extend(ops)

        mappings: dict[str, TerraformResourceMapping] = {}
        for key, ops in merged.items():
            if not any(op.method == "get" for op in ops):
                logger.debug("Skipping non-resource entity %r (no GET endpoint)", key)
                continue
            id_components = self._id_components(ops)
            paths: list[str] = []
            for op in ops:
                if op.path not in paths:
                    paths.append(op.path)
            name = "_".join([TERRAFORM_PROVIDER_PREFIX, *key])
            mappings[name] = TerraformResourceMapping(
                terraform_name=name,
                entity_key=key,
                id_components=id_components,
                import_id_format=",".join(id_components),
                paths=tuple(paths),
                operations=tuple(ops),
            )
        return mappings

    def endpoint_lookup(self) -> dict[str, str]:
        """Operational lookup table: API path template → Terraform resource name."""
        return {
            path: mapping.terraform_name
            for mapping in self.resource_mappings().values()
            for path in mapping.paths
        }

    def _group_by_entity(self) -> dict[tuple[str, ...], list[OperationSpec]]:
        grouped: dict[tuple[str, ...], list[OperationSpec]] = {}
        for op in self._endpoints:
            grouped.setdefault(entity_key(op.path), []).append(op)
        return grouped

    @staticmethod
    def _canonicalize(
        key: tuple[str, ...], canonical_keys: set[tuple[str, ...]]
    ) -> tuple[str, ...]:
        """Fold a collection-only key into the entity it lists or creates.

        The longest proper suffix that names an entity with its own item
        endpoint wins; a key with no such suffix is its own resource
        (covers singleton configuration endpoints like ``.../settings``).
        """
        if key in canonical_keys:
            return key
        for start in range(1, len(key)):
            suffix = key[start:]
            if suffix in canonical_keys:
                return suffix
        return key

    @staticmethod
    def _id_components(ops: list[OperationSpec]) -> tuple[str, ...]:
        """Ordered compound-ID parts from the entity's most specific endpoint."""
        best = max(ops, key=lambda op: (is_item_path(op.path), len(op.path_params)))
        return tuple(snake_case(param) for param in best.path_params)
