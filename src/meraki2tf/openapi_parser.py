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
* **Entity name** — ``meraki_`` + the canonical key joined with
  underscores (``meraki_networks_appliance_vlans``). This is an
  *internal entity identifier*, not the provider's resource type: the
  authoritative CiscoDevNet/meraki type (``meraki_appliance_vlan``) is
  resolved by matching entities against the installed provider's
  identity schemas — see :mod:`~meraki2tf.resource_matcher`.
* **Composite import ID** — the ordered path parameters of the entity's
  most specific endpoint, snake_cased and comma-joined
  (``network_id,vlan_id``), ready for Terraform ``import`` blocks.
* **Resource eligibility** — an entity must expose at least one GET
  endpoint; action-only RPC paths (e.g. ``blinkLeds``) are excluded.
* **Aggregation adoption** — a mutable network-scoped entity with *no*
  GET of its own (Meraki's "per-network PUT" surfaces: Air Marshal,
  RRM, warm-spare redundancy, uplink NAT, …) is adopted when the spec
  carries an org-scoped aggregation GET for it — the same path tail
  under ``/organizations/{organizationId}`` plus ``byNetwork``, or the
  bare tail at org scope when its response items declare a per-network
  scope identifier. The aggregation GET becomes the entity's collection
  source (``aggregation_get``) while the entity keeps its own
  network-scoped paths as the canonical addressing scheme. Without this
  the whole surface class would silently vanish from discovery.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from meraki2tf.spec.engine import OperationSpec, SpecIngestionEngine

logger = logging.getLogger(__name__)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_PARAM_SEGMENT = re.compile(r"^\{.+\}\Z")

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


#: Response-item properties that identify the per-scope owner of one
#: aggregation row (``networkId``/``network`` for per-network surfaces,
#: ``serial`` for per-device ones).
_SCOPE_IDENTIFIER_PROPERTIES = frozenset({"network", "networkId", "serial"})


def _declares_scope_identifier(op: OperationSpec) -> bool:
    """Whether ``op``'s declared response items carry a scope identifier.

    Guards bare same-tail aggregation adoption: an org-scoped GET whose
    element schema names no per-network/per-device owner cannot be
    exploded back into per-scope assets, so it is never adopted.
    """
    node: object = op.raw
    for step in ("responses", "200", "content", "application/json", "schema"):
        node = node.get(step) if isinstance(node, dict) else None
    if not isinstance(node, dict):
        return False
    # Enveloped collections declare {items: {type: array, items: ...}};
    # plain collections declare {type: array, items: ...} directly.
    properties = node.get("properties")
    if isinstance(properties, dict) and isinstance(properties.get("items"), dict):
        node = properties["items"]
    element = node.get("items") if isinstance(node, dict) else None
    element_properties = (
        element.get("properties") if isinstance(element, dict) else None
    )
    if not isinstance(element_properties, dict):
        return False
    return bool(_SCOPE_IDENTIFIER_PROPERTIES & element_properties.keys())


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
    #: Org-scoped aggregation GET adopted as the collection source for a
    #: GET-less mutable entity (Meraki's "per-network PUT + org-level
    #: byNetwork GET" pattern). ``None`` for entities with their own GET.
    aggregation_get: OperationSpec | None = None


class OpenApiParser:
    """Parses a Meraki ``openapi.json`` file into a Terraform resource lookup."""

    def __init__(self, spec_path: Path) -> None:
        self._engine = SpecIngestionEngine.from_file(spec_path)
        self._endpoints: tuple[OperationSpec, ...] = tuple(self._engine.operations())
        logger.debug("Parsed %d operation(s) from %s", len(self._endpoints), spec_path)

    def endpoints(self) -> tuple[OperationSpec, ...]:
        """Every operation discovered in the document, in spec order."""
        return self._endpoints

    def entity_operations(self) -> dict[tuple[str, ...], list[OperationSpec]]:
        """Every operation, grouped by canonicalized entity key.

        The complete entity universe — including GET-less action/config
        entities that never become resource mappings — so coverage
        accounting can classify what discovery does not capture.
        """
        grouped = self._group_by_entity()
        canonical_keys = {
            key
            for key, ops in grouped.items()
            if any(is_item_path(op.path) for op in ops)
        }
        merged: dict[tuple[str, ...], list[OperationSpec]] = {}
        for key, ops in grouped.items():
            merged.setdefault(self._canonicalize(key, canonical_keys), []).extend(ops)
        return merged

    def resource_mappings(self) -> dict[str, TerraformResourceMapping]:
        """Derive all Terraform resources, keyed by provider resource name."""
        merged = self.entity_operations()
        aggregation_sources = self._aggregation_candidates()
        mappings: dict[str, TerraformResourceMapping] = {}
        for key, ops in merged.items():
            aggregation_get: OperationSpec | None = None
            if not any(op.method == "get" for op in ops):
                aggregation_get = self._find_aggregation_get(
                    key, ops, aggregation_sources
                )
                if aggregation_get is None:
                    logger.debug(
                        "Skipping non-resource entity %r (no GET endpoint)", key
                    )
                    continue
                logger.debug(
                    "Adopted org-scoped aggregation GET %s as the "
                    "collection source for GET-less entity %r.",
                    aggregation_get.path, key,
                )
            id_components = self._id_components(ops)
            paths: list[str] = []
            for op in ops:
                if op.path not in paths:
                    paths.append(op.path)
            name = "_".join([TERRAFORM_PROVIDER_PREFIX, *key])
            if name in mappings:
                # snake_casing can make distinct entity keys collide on
                # one provider name; overwriting would silently drop the
                # first entity's endpoints from the lookup table. Keep
                # the first (spec order) and let the exception auditor
                # flag the loser's assets visibly.
                logger.warning(
                    "Terraform name collision: %r derived from both %r and "
                    "%r; keeping the first — assets of the second will be "
                    "audited as unsupported.",
                    name, mappings[name].entity_key, key,
                )
                continue
            mappings[name] = TerraformResourceMapping(
                terraform_name=name,
                entity_key=key,
                id_components=id_components,
                import_id_format=",".join(id_components),
                paths=tuple(paths),
                operations=tuple(ops),
                aggregation_get=aggregation_get,
            )
        return mappings

    def _aggregation_candidates(
        self,
    ) -> dict[tuple[str, ...], OperationSpec]:
        """Org-scoped collection GETs by entity key — aggregation sources.

        Only single-parameter ``{organizationId}`` collection GETs can
        aggregate per-network configuration; the first such operation
        per key wins (spec order), matching how the rest of the parser
        resolves duplicates.
        """
        candidates: dict[tuple[str, ...], OperationSpec] = {}
        for op in self._endpoints:
            if (
                op.method == "get"
                and op.path_params == ("organizationId",)
                and not is_item_path(op.path)
            ):
                candidates.setdefault(entity_key(op.path), op)
        return candidates

    @staticmethod
    def _find_aggregation_get(
        key: tuple[str, ...],
        ops: list[OperationSpec],
        candidates: dict[tuple[str, ...], OperationSpec],
    ) -> OperationSpec | None:
        """The org-scoped aggregation GET listing a GET-less entity.

        Purely spec-derived: the entity must be network-scoped
        configuration (a ``networks``-rooted key carrying a PUT — the
        POST-only remainder is RPC actions like ``blinkLeds``), and the
        spec must expose an org-scoped GET whose path tail matches the
        entity's tail plus ``byNetwork`` — or the bare tail at org scope
        (campusGateway clusters), accepted only when its response items
        declare a per-network scope identifier, so a same-named but
        unrelated org surface can never be adopted.
        """
        if not key or key[0] != "networks":
            return None
        if not any(op.method == "put" for op in ops):
            return None
        tail = key[1:]
        by_network = candidates.get(("organizations", *tail, "by_network"))
        if by_network is not None:
            return by_network
        same_tail = candidates.get(("organizations", *tail))
        if same_tail is not None and _declares_scope_identifier(same_tail):
            return same_tail
        return None

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
