"""Spec-driven feature discovery shared by both ingestion modalities.

Everything here is derived from the OpenAPI document at runtime — which
endpoints are configuration surfaces, how a listed collection expands to
addressable elements, and how a raw snapshot section name resolves to an
endpoint. No endpoint names, section names, or mapping tables are
hard-coded, per the project contract.

Two consumers:

* the live provider asks for the configuration-shaped collection
  endpoints to call per network, and expands each response;
* the dump provider resolves raw snapshot section names (for snapshots
  that predate the tool's own contract) onto the same endpoints and
  expands their payloads through the identical code path — which is what
  keeps the two modalities structurally identical.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from meraki2tf.models import FeatureConfiguration
from meraki2tf.openapi_parser import OpenApiParser, entity_key, is_item_path
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)

#: Payload keys probed, in order, to identify one element of a listed
#: collection (after the endpoint's own item parameter name).
_ITEM_ID_FALLBACK_KEYS = ("id", "serial", "number")

_MUTATING_METHODS = frozenset({"put", "post", "delete"})

#: How many path tokens beyond the section's own tokens a candidate
#: endpoint may carry and still count as a name match. Keeps
#: ``firewall_l3`` → ``appliance/firewall/l3FirewallRules`` (two extra
#: tokens) while rejecting far-fetched matches deeper in the tree.
_MAX_EXTRA_TOKENS = 2


def mutable_entity_keys(parser: OpenApiParser) -> frozenset[tuple[str, ...]]:
    """Entity keys that expose at least one mutating verb in the spec.

    An entity nobody can PUT/POST/DELETE is operational telemetry
    (client lists, uplink statuses, …), not configuration — Terraform
    cannot manage it, so discovery skips it.
    """
    return frozenset(
        entity_key(op.path)
        for op in parser.endpoints()
        if op.method in _MUTATING_METHODS
    )


def config_collection_operations(
    parser: OpenApiParser, scope_param: str = "networkId"
) -> tuple[OperationSpec, ...]:
    """GET endpoints scoped by exactly ``scope_param`` that list or read
    a configurable entity."""
    mutable = mutable_entity_keys(parser)
    return tuple(
        op
        for op in parser.endpoints()
        if op.method == "get"
        and op.path_params == (scope_param,)
        and not is_item_path(op.path)
        and entity_key(op.path) in mutable
    )


def item_operation_for(
    parser: OpenApiParser, op: OperationSpec
) -> OperationSpec | None:
    """The endpoint addressing one element of ``op``'s collection.

    A GET item endpoint is preferred; entities that only expose PUT or
    DELETE on the item path (e.g. organization admins) still yield the
    path template needed to address elements for import.
    """
    fallback: OperationSpec | None = None
    for candidate in parser.endpoints():
        if (
            is_item_path(candidate.path)
            and candidate.path.startswith(op.path + "/{")
            and len(candidate.path_params) == 2
        ):
            if candidate.method == "get":
                return candidate
            fallback = fallback or candidate
    return fallback


def _collection_id_key(item_op: OperationSpec) -> str | None:
    """Conventional ``<singular>Id`` field named after the collection.

    Some Meraki collections key their elements this way while the item
    endpoint's own placeholder is a generic ``{id}`` — adaptive policy
    ``groups/{id}`` elements carry ``groupId``, not ``id``.
    """
    segments = [s for s in item_op.path.split("/") if s]
    if len(segments) < 2 or not segments[-1].startswith("{"):
        return None
    collection = segments[-2]
    if collection.startswith("{"):
        return None
    if collection.endswith("ies"):
        singular = collection[:-3] + "y"
    else:
        singular = collection.removesuffix("s")
    return f"{singular}Id"


def element_id(item_op: OperationSpec, element: Any) -> str | None:
    """Identify one collection element by the item endpoint's own
    parameter name, falling back to conventional ID fields."""
    if not isinstance(element, Mapping):
        return None
    derived = _collection_id_key(item_op)
    candidates = (
        item_op.path_params[-1],
        *_ITEM_ID_FALLBACK_KEYS,
        *((derived,) if derived else ()),
    )
    for key in candidates:
        value = element.get(key)
        if value is None:
            # A JSON null must not become the literal ID "None".
            continue
        text = str(value).strip()
        if text:
            return text
    return None


def expand_endpoint_payload(
    parser: OpenApiParser, op: OperationSpec, scope_value: str, payload: Any
) -> list[FeatureConfiguration]:
    """Normalize one endpoint payload into importable feature assets.

    Singleton configs (dict payloads) address themselves at the
    endpoint's own path; listed collections expand to one asset per
    element at the corresponding item path. Paginated ``{items, meta}``
    envelopes (the newer Meraki collection shape) are unwrapped to their
    element list first — recognized from the operation's declared
    response schema, so a genuine singleton that happens to carry an
    ``items`` field is never misread. Both ingestion modalities run
    their raw data through this one function, which is what guarantees
    structural parity between them.
    """
    if isinstance(payload, Mapping):
        elements = _envelope_elements(op, payload)
        if elements is None:
            return [
                FeatureConfiguration(
                    api_path=op.path, path_values=(scope_value,), payload=payload
                )
            ]
        payload = elements
    item_op = item_operation_for(parser, op)
    if item_op is None:
        logger.debug("Collection %s has no item endpoint; keeping one record.", op.path)
        return [
            FeatureConfiguration(
                api_path=op.path,
                path_values=(scope_value,),
                payload={"items": payload},
            )
        ]
    expanded: list[FeatureConfiguration] = []
    for element in payload:
        item_id = element_id(item_op, element)
        if item_id is None:
            # Never drop a discovered object silently: without an ID it
            # cannot become an import block, but recording it at the
            # collection path routes it through the unsupported-asset
            # audit so it reaches the coverage manifest and alerts.
            logger.warning(
                "Element of %s has no identifiable ID field; it will be "
                "reported as a coverage gap.",
                op.path,
            )
            expanded.append(
                FeatureConfiguration(
                    api_path=op.path,
                    path_values=(scope_value,),
                    payload=(
                        element
                        if isinstance(element, Mapping)
                        else {"value": element}
                    ),
                )
            )
            continue
        expanded.append(
            FeatureConfiguration(
                api_path=item_op.path,
                path_values=(scope_value, item_id),
                payload=element,
            )
        )
    return expanded


def _response_schema(op: OperationSpec) -> Mapping[str, Any] | None:
    """The operation's declared 200-response JSON schema, if any."""
    node: Any = op.raw
    for key in ("responses", "200", "content", "application/json", "schema"):
        node = node.get(key) if isinstance(node, Mapping) else None
        if node is None:
            return None
    return node if isinstance(node, Mapping) else None


def _envelope_elements(op: OperationSpec, payload: Mapping[str, Any]) -> Any:
    """The element list of a paginated ``{items, meta}`` envelope, or None.

    Newer Meraki collection endpoints wrap their elements in an object
    whose ``items`` property is the real collection. Two signals
    identify it: the response schema declared in the spec (an object
    schema declaring ``items`` as an array), or — because the published
    spec still declares a plain array for several endpoints that
    actually respond enveloped (observed live: the org DNS profile and
    record collections) — the payload being exactly the wrapper shape:
    nothing but ``items`` (a list) and optionally ``meta`` (an object).
    A singleton config carrying an ``items`` field among other real
    attributes matches neither signal and stays a singleton.
    """
    elements = payload.get("items")
    if not isinstance(elements, list):
        return None
    schema = _response_schema(op)
    if schema is not None:
        properties = schema.get("properties")
        if isinstance(properties, Mapping):
            items_schema = properties.get("items")
            if (
                isinstance(items_schema, Mapping)
                and items_schema.get("type") == "array"
            ):
                return elements
    if set(payload) <= {"items", "meta"} and isinstance(
        payload.get("meta", {}), Mapping
    ):
        return elements
    return None


def _response_schema_properties(op: OperationSpec) -> frozenset[str]:
    """Top-level property names of the operation's 200-response schema."""
    node = _response_schema(op)
    if node is None:
        return frozenset()
    properties = node.get("properties")
    if not isinstance(properties, Mapping):
        items = node.get("items")
        properties = items.get("properties") if isinstance(items, Mapping) else None
    return frozenset(properties) if isinstance(properties, Mapping) else frozenset()


class FeatureSectionMatcher:
    """Resolves raw snapshot section names onto spec endpoints.

    Matching is purely lexical + schema-driven: a section name's tokens
    (``firewall_l3`` → ``{firewall, l3}``) must all appear among the
    candidate endpoint's snake_cased path tokens, closest endpoint wins,
    and lexical ties are broken by comparing the observed payload keys
    against each candidate's declared response schema.
    """

    def __init__(self, parser: OpenApiParser, scope_param: str) -> None:
        self._scope_param = scope_param
        self._candidates = tuple(
            (op, self._path_tokens(op), _response_schema_properties(op))
            for op in config_collection_operations(parser, scope_param)
        )

    @staticmethod
    def _path_tokens(op: OperationSpec) -> frozenset[str]:
        # Drop the leading scope segment (networks/organizations): it
        # is the scope, not part of the entity's name.
        segments = entity_key(op.path)[1:]
        return frozenset(token for segment in segments for token in segment.split("_"))

    def match(
        self, section: str, sample_keys: Iterable[str] = ()
    ) -> OperationSpec | None:
        """The endpoint a section maps to, or ``None`` when nothing
        (or nothing unambiguous) fits."""
        section_tokens = {token for token in section.lower().split("_") if token}
        if not section_tokens:
            return None
        best_extras: int | None = None
        best: list[tuple[OperationSpec, frozenset[str]]] = []
        for op, tokens, schema_props in self._candidates:
            if not section_tokens <= tokens:
                continue
            extras = len(tokens - section_tokens)
            if extras > _MAX_EXTRA_TOKENS:
                continue
            if best_extras is None or extras < best_extras:
                best_extras, best = extras, [(op, schema_props)]
            elif extras == best_extras:
                best.append((op, schema_props))
        if not best:
            logger.debug(
                "Section %r matches no %s-scoped configuration endpoint.",
                section, self._scope_param,
            )
            return None
        if len(best) == 1:
            return best[0][0]
        observed = frozenset(sample_keys)
        overlaps = [(len(props & observed), op) for op, props in best]
        top_overlap = max(overlap for overlap, _ in overlaps)
        top = [op for overlap, op in overlaps if overlap == top_overlap]
        if top_overlap > 0 and len(top) == 1:
            return top[0]
        logger.debug(
            "Section %r is ambiguous between %s; skipping.",
            section, [op.path for op, _ in best],
        )
        return None
