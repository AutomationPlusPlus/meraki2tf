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
from dataclasses import dataclass
from typing import Any
from weakref import WeakKeyDictionary

from meraki2tf.models import UNREADABLE_MARKER, FeatureConfiguration
from meraki2tf.openapi_parser import (
    OpenApiParser,
    TerraformResourceMapping,
    entity_key,
    is_item_path,
)
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


def nested_collection_operations(
    parser: OpenApiParser,
) -> tuple[OperationSpec, ...]:
    """Configuration GETs scoped by two or more path parameters.

    Their parent scopes are elements the single-parameter pass already
    discovers (SSID numbers, switch-stack IDs, config-template IDs, per-
    device interface IDs, …). Ordered by parameter count so a deeper
    surface can scope off elements a shallower one just produced.
    """
    mutable = mutable_entity_keys(parser)
    ops = [
        op
        for op in parser.endpoints()
        if op.method == "get"
        and len(op.path_params) >= 2
        and not is_item_path(op.path)
        and entity_key(op.path) in mutable
    ]
    return tuple(sorted(ops, key=lambda op: (len(op.path_params), op.path)))


def parent_item_path(path: str) -> str:
    """The enclosing item path a nested collection hangs off.

    ``/networks/{networkId}/wireless/ssids/{number}/identityPsks`` →
    ``/networks/{networkId}/wireless/ssids/{number}`` — the prefix up to
    the last path parameter, which is exactly the item path whose
    discovered elements provide the nested collection's scope values.
    """
    segments = path.split("/")
    last_param = max(
        (
            index
            for index, segment in enumerate(segments)
            if segment.startswith("{")
        ),
        default=-1,
    )
    if last_param < 0:
        # A malformed/hostile spec can carry parameters only embedded
        # mid-segment (`/x{a}/y{b}`), which counts as nested by
        # parameter count yet owns no whole-segment parameter. No
        # enclosing item path exists; the caller records the surface as
        # a coverage gap instead of the whole run crashing.
        return ""
    return "/".join(segments[: last_param + 1])


#: Per-parser memo for :func:`item_operation_for`. The lookup scans all
#: ~957 spec endpoints and, at ~200k discovered objects, is called once per
#: (collection-endpoint × scope) — ~1.1s of graph-build spent re-deriving a
#: result that depends only on the collection path. Keyed on the parser
#: instance (weakly, so a runner processing several specs never leaks one
#: spec's answers into another and the cache dies with its parser), then on
#: the collection path.
_ITEM_OP_CACHE: WeakKeyDictionary[
    OpenApiParser, dict[str, OperationSpec | None]
] = WeakKeyDictionary()


def item_operation_for(
    parser: OpenApiParser, op: OperationSpec
) -> OperationSpec | None:
    """The endpoint addressing one element of ``op``'s collection.

    A GET item endpoint is preferred; entities that only expose PUT or
    DELETE on the item path (e.g. organization admins) still yield the
    path template needed to address elements for import.

    Memoized per parser on ``op.path`` (the sole determinant): repeated
    lookups for the same collection are O(1) instead of re-scanning every
    endpoint. See :func:`_resolve_item_operation` for the un-memoized body.
    """
    cache = _ITEM_OP_CACHE.get(parser)
    if cache is None:
        cache = {}
        _ITEM_OP_CACHE[parser] = cache
    key = op.path
    if key not in cache:
        cache[key] = _resolve_item_operation(parser, op)
    return cache[key]


def _resolve_item_operation(
    parser: OpenApiParser, op: OperationSpec
) -> OperationSpec | None:
    """Un-memoized item-endpoint resolution (see item_operation_for)."""
    fallback: OperationSpec | None = None
    for candidate in parser.endpoints():
        if (
            is_item_path(candidate.path)
            and candidate.path.startswith(op.path + "/{")
            and len(candidate.path_params) == len(op.path_params) + 1
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


def _parent_scope_id_key(item_op: OperationSpec) -> str | None:
    """Conventional ``<parentSegment>Id`` for family-nested collections.

    Adaptive policy ``adaptivePolicy/policies/{id}`` elements carry
    ``adaptivePolicyId`` — named after the FAMILY segment, not the
    collection. Without this candidate the element ID is unknowable,
    the item is captured at its collection path, and restore cannot
    address it.
    """
    segments = [s for s in item_op.path.split("/") if s]
    if len(segments) < 3 or not segments[-1].startswith("{"):
        return None
    parent = segments[-3]
    if parent.startswith("{"):
        return None
    return f"{parent}Id"


def element_id(item_op: OperationSpec, element: Any) -> str | None:
    """Identify one collection element by the item endpoint's own
    parameter name, falling back to conventional ID fields."""
    if not isinstance(element, Mapping):
        return None
    derived = _collection_id_key(item_op)
    family = _parent_scope_id_key(item_op)
    candidates = (
        item_op.path_params[-1],
        *_ITEM_ID_FALLBACK_KEYS,
        *((derived,) if derived else ()),
        *((family,) if family else ()),
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
    parser: OpenApiParser,
    op: OperationSpec,
    scope_value: str | tuple[str, ...],
    payload: Any,
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
    scopes = (
        (scope_value,) if isinstance(scope_value, str) else tuple(scope_value)
    )
    if isinstance(payload, Mapping):
        elements = _envelope_elements(op, payload)
        if elements is None:
            return [
                FeatureConfiguration(
                    api_path=op.path, path_values=scopes, payload=payload
                )
            ]
        payload = elements
    if not isinstance(payload, (list, tuple)):
        # A scalar body (bare string, number, …) is a malformed endpoint
        # response: iterating it would expand a string per-character
        # into garbage records and crash on a number, aborting the whole
        # discovery run. Record it the way unreadable endpoints are
        # recorded, so it surfaces as a coverage gap instead.
        logger.warning(
            "Endpoint %s returned a non-collection %s payload; it is "
            "recorded as a coverage gap.",
            op.path, type(payload).__name__,
        )
        return [
            FeatureConfiguration(
                api_path=op.path,
                path_values=scopes,
                payload={
                    UNREADABLE_MARKER: (
                        "malformed endpoint response: expected an object "
                        f"or list, got {type(payload).__name__}"
                    )
                },
            )
        ]
    if not payload:
        if _whole_collection_put(parser, op):
            # The collection itself is one config object (its PUT
            # replaces the whole list), so even an empty list is a real,
            # importable configuration.
            return [
                FeatureConfiguration(
                    api_path=op.path,
                    path_values=scopes,
                    payload={"items": []},
                )
            ]
        # A per-item collection with zero items discovers zero objects;
        # keeping a placeholder record would manufacture phantom
        # coverage gaps.
        return []
    item_op = item_operation_for(parser, op)
    if item_op is None:
        logger.debug("Collection %s has no item endpoint; keeping one record.", op.path)
        return [
            FeatureConfiguration(
                api_path=op.path,
                path_values=scopes,
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
                    path_values=scopes,
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
                path_values=(*scopes, item_id),
                payload=element,
            )
        )
    return expanded


def aggregation_mappings(
    parser: OpenApiParser,
) -> tuple[TerraformResourceMapping, ...]:
    """Entities whose collection source is an org-scoped aggregation GET.

    These are the GET-less mutable surfaces (Air Marshal, RRM, uplink
    NAT, …) the parser adopted via the ``byNetwork`` pattern; live
    discovery executes each aggregation once at org scope and explodes
    the response into per-scope assets.
    """
    return tuple(
        mapping
        for mapping in parser.resource_mappings().values()
        if mapping.aggregation_get is not None
    )


def aggregation_collection_path(mapping: TerraformResourceMapping) -> str:
    """The entity's own single-scope collection path template.

    Exploded aggregation rows address themselves here (or at the item
    path below it), keeping the network-scoped path canonical exactly
    as if the entity had its own per-network GET.
    """
    for path in mapping.paths:
        if not is_item_path(path) and _path_param_count(path) == 1:
            return path
    # Nested-element entities (``…/ssids/{number}/openRoaming``): the
    # entity's own two-parameter write path IS the canonical path.
    # Deriving anything shorter would address the features at a
    # *different* entity's collection path and collide with its assets.
    for path in mapping.paths:
        if _nested_element_param(path) is not None:
            return path
    # Entities exposing only item endpoints (PUT/DELETE on
    # ``.../{id}``): the enclosing collection is the item path minus its
    # trailing parameter.
    return parent_item_path(mapping.paths[0]).rsplit("/", 1)[0] or mapping.paths[0]


def _nested_element_param(path: str) -> str | None:
    """Element parameter of a scope+element path with a trailing literal
    config segment, else ``None``.

    ``/networks/{networkId}/wireless/ssids/{number}/openRoaming`` →
    ``number``: the path addresses one nested element's config object
    (an SSID's openRoaming settings), so an aggregation row for it must
    explode per listed element, never per row. Purely shape-derived —
    exactly two path parameters, the second followed by at least one
    literal segment.
    """
    segments = _path_segments(path)
    params = [
        (index, segment[1:-1])
        for index, segment in enumerate(segments)
        if segment.startswith("{") and segment.endswith("}")
    ]
    if len(params) != 2 or _path_param_count(path) != 2:
        return None
    index, name = params[1]
    if index >= len(segments) - 1:
        return None
    return name


def _path_param_count(path: str) -> int:
    return sum(1 for s in _path_segments(path) if s.startswith("{"))


def _path_segments(path: str) -> list[str]:
    return [segment for segment in path.split("/") if segment]


def _aggregation_item_operation(
    mapping: TerraformResourceMapping,
) -> OperationSpec | None:
    """The entity's own item endpoint, when its elements are addressable."""
    for op in mapping.operations:
        if is_item_path(op.path) and len(op.path_params) == 2:
            return op
    return None


def _row_scope_value(
    row: Mapping[str, Any], scope_param: str
) -> tuple[str | None, str | None]:
    """Extract one aggregation row's owning scope: ``(value, consumed_key)``.

    Rows carry either the flat identifier (``networkId``/``serial``) or
    the object form (``network: {id: …}``) — both shapes appear in the
    published spec's byNetwork responses.
    """
    flat = row.get(scope_param)
    if isinstance(flat, (str, int)) and str(flat).strip():
        return str(flat).strip(), scope_param
    if scope_param.endswith("Id"):
        object_key = scope_param[: -len("Id")]
        nested = row.get(object_key)
        if isinstance(nested, Mapping):
            inner = nested.get("id")
            if isinstance(inner, (str, int)) and str(inner).strip():
                return str(inner).strip(), object_key
    return None, None


def explode_aggregation_payload(
    mapping: TerraformResourceMapping,
    payload: Any,
    known_networks: Mapping[str, str] | None = None,
) -> list[FeatureConfiguration]:
    """One org-scoped aggregation response → per-scope feature assets.

    Each row is re-addressed at the entity's own network-scoped path
    with the row's scope identifier consumed out of the payload — the
    exact shape a per-network GET would have produced, which is what
    keeps snapshots, HCL generation, and restore agnostic of how the
    collection was sourced. Rows lacking a scope identifier are kept as
    scope-less records so the exception auditor reports them instead of
    dropping discovered objects (Cardinal Rule 2).

    ``known_networks`` (id → name) enables phantom-scope healing: some
    byNetwork rows are scoped by a per-product *child* network id (named
    ``"<parent> - <product>"``) that no other API surface can resolve.
    The mapping is the full resolution universe — networks AND config
    templates, whose per-product children appear in byNetwork rows the
    same way ("<template name> - <product>"). A known scope id passes
    through untouched; an unknown one is re-scoped to the parent its
    name field resolves to (exact match first, then trailing
    ``" - <suffix>"`` parts stripped one at a time); a row resolvable
    neither way stays an auditable scope-less gap record — a feature
    must never be addressed by an id nothing can resolve. ``None`` (the
    default) disables the check entirely.
    """
    agg_op = mapping.aggregation_get
    assert agg_op is not None  # only called for adopted mappings
    collection_path = aggregation_collection_path(mapping)
    if isinstance(payload, Mapping):
        payload = _envelope_elements(agg_op, payload)
    if not isinstance(payload, (list, tuple)):
        logger.warning(
            "Aggregation endpoint %s returned a non-collection payload; "
            "entity %s is recorded as a coverage gap.",
            agg_op.path, collection_path,
        )
        return [
            FeatureConfiguration(
                api_path=collection_path,
                path_values=(),
                payload={
                    UNREADABLE_MARKER: (
                        "malformed aggregation response from "
                        f"{agg_op.path}: expected a collection"
                    )
                },
            )
        ]
    scope_param = next(
        (
            segment[1:-1]
            for segment in _path_segments(collection_path)
            if segment.startswith("{")
        ),
        "networkId",
    )
    item_op = _aggregation_item_operation(mapping)
    element_param = _nested_element_param(collection_path)
    networks_by_name = (
        {name: network_id for network_id, name in known_networks.items()}
        if known_networks is not None
        else {}
    )
    rescoped = 0
    features: list[FeatureConfiguration] = []
    for row in payload:
        if not isinstance(row, Mapping):
            logger.warning(
                "Aggregation row of %s is not an object; it will be "
                "reported as a coverage gap.", agg_op.path,
            )
            features.append(
                FeatureConfiguration(
                    api_path=collection_path,
                    path_values=(),
                    payload={"value": row},
                )
            )
            continue
        scope_value, consumed = _row_scope_value(row, scope_param)
        if scope_value is None:
            logger.warning(
                "Aggregation row of %s carries no %s scope identifier; "
                "it will be reported as a coverage gap.",
                agg_op.path, scope_param,
            )
            features.append(
                FeatureConfiguration(
                    api_path=collection_path,
                    path_values=(),
                    payload=dict(row),
                )
            )
            continue
        if known_networks is not None and scope_value not in known_networks:
            parent = _parent_by_name(row, scope_param, networks_by_name)
            if parent is None:
                logger.warning(
                    "Aggregation row of %s is scoped to an id that matches "
                    "no discovered network by id or name; it will be "
                    "reported as a coverage gap.",
                    agg_op.path,
                )
                features.append(
                    FeatureConfiguration(
                        api_path=collection_path,
                        path_values=(),
                        payload=dict(row),
                    )
                )
                continue
            scope_value = parent
            rescoped += 1
        remainder = {key: value for key, value in row.items() if key != consumed}
        if element_param is not None:
            features.extend(
                _explode_row_elements(
                    collection_path, element_param,
                    scope_param, scope_value, remainder,
                )
            )
            continue
        if item_op is not None:
            item_id = element_id(item_op, remainder)
            if item_id is not None:
                features.append(
                    FeatureConfiguration(
                        api_path=item_op.path,
                        path_values=(scope_value, item_id),
                        payload=remainder,
                    )
                )
                continue
        features.append(
            FeatureConfiguration(
                api_path=collection_path,
                path_values=(scope_value,),
                payload=remainder,
            )
        )
    if rescoped:
        logger.info(
            "Aggregation endpoint %s: re-scoped %d row(s) from "
            "per-product child network ids to their parent network, "
            "matched by name.",
            agg_op.path, rescoped,
        )
    return features


def _row_scope_name(row: Mapping[str, Any], scope_param: str) -> str:
    """The row's scope-name field, empty when absent.

    Derived from the scope parameter (``networkId`` → ``networkName``
    flat form, or ``network: {name: …}`` object form) — never the row's
    bare ``name``, which names the entity's own object and could
    coincidentally equal a network name and mis-scope the row.
    """
    base = (
        scope_param[: -len("Id")] if scope_param.endswith("Id") else scope_param
    )
    nested = row.get(base)
    for value in (
        row.get(f"{base}Name"),
        nested.get("name") if isinstance(nested, Mapping) else None,
    ):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _parent_by_name(
    row: Mapping[str, Any],
    scope_param: str,
    networks_by_name: Mapping[str, str],
) -> str | None:
    """Resolve a phantom row scope onto a discovered parent network.

    An exact name match wins; otherwise trailing ``" - <suffix>"``
    parts are stripped one at a time (the child-network naming scheme is
    ``"<parent name> - <product>"``, and the parent name may itself
    contain ``" - "``) until a discovered network's name matches.
    """
    candidate = _row_scope_name(row, scope_param)
    while candidate:
        parent = networks_by_name.get(candidate)
        if parent is not None:
            return parent
        if " - " not in candidate:
            return None
        candidate = candidate.rsplit(" - ", 1)[0]
    return None


def _element_value(item: Mapping[str, Any], element_param: str) -> str | None:
    """The element's identifier under the path's own parameter name."""
    value = item.get(element_param)
    if value is None:
        # A JSON null must not become the literal ID "None".
        return None
    text = str(value).strip()
    return text or None


def _row_element_list(
    remainder: Mapping[str, Any], element_param: str
) -> list[Any] | None:
    """The row's nested element list, spec-identified by content.

    The first list-valued key whose items carry the element identifier
    (the entity path's second parameter name) is the element list. A row
    with only empty candidate lists legitimately holds zero elements;
    ``None`` means no element list exists at all.
    """
    fallback: list[Any] | None = None
    for value in remainder.values():
        if not isinstance(value, list):
            continue
        if any(
            isinstance(item, Mapping)
            and _element_value(item, element_param) is not None
            for item in value
        ):
            return value
        if fallback is None and not value:
            fallback = value
    return fallback


def _explode_row_elements(
    collection_path: str,
    element_param: str,
    scope_param: str,
    scope_value: str,
    remainder: Mapping[str, Any],
) -> list[FeatureConfiguration]:
    """One nested-shape aggregation row → per-element feature assets.

    The entity's canonical path addresses one element's config object
    (``…/ssids/{number}/openRoaming``), so the row must not become one
    feature: each entry of its nested element list becomes a feature at
    the entity's own path with ``(scope, element)`` values. The payload
    is the element's config sub-object — the key named after the path's
    trailing config segment — when present, else the element minus its
    identifier. Elements that cannot be addressed stay auditable gap
    records (Cardinal Rule 2).
    """
    config_key = _path_segments(collection_path)[-1]
    elements = _row_element_list(remainder, element_param)
    if elements is None:
        logger.warning(
            "Aggregation row for %s carries no %r element list; it will "
            "be reported as a coverage gap.",
            collection_path, element_param,
        )
        return [
            FeatureConfiguration(
                api_path=collection_path,
                path_values=(),
                payload={scope_param: scope_value, **remainder},
            )
        ]
    features: list[FeatureConfiguration] = []
    for item in elements:
        if not isinstance(item, Mapping):
            logger.warning(
                "Element of aggregation row for %s is not an object; it "
                "will be reported as a coverage gap.",
                collection_path,
            )
            features.append(
                FeatureConfiguration(
                    api_path=collection_path,
                    path_values=(),
                    payload={scope_param: scope_value, "value": item},
                )
            )
            continue
        item_id = _element_value(item, element_param)
        if item_id is None:
            logger.warning(
                "Element of aggregation row for %s has no %r identifier; "
                "it will be reported as a coverage gap.",
                collection_path, element_param,
            )
            features.append(
                FeatureConfiguration(
                    api_path=collection_path,
                    path_values=(),
                    payload={scope_param: scope_value, **item},
                )
            )
            continue
        config = item.get(config_key)
        features.append(
            FeatureConfiguration(
                api_path=collection_path,
                path_values=(scope_value, item_id),
                payload=(
                    dict(config)
                    if isinstance(config, Mapping)
                    else {
                        key: value
                        for key, value in item.items()
                        if key != element_param
                    }
                ),
            )
        )
    return features


@dataclass(frozen=True)
class SpecSurfaces:
    """Spec-level coverage accounting no graph object can carry.

    Cardinal Rule 2 demands that even API surfaces discovery can never
    read stay visible: configuration that is write-only in the API,
    RPC-style action endpoints excluded by design, and read-only API
    surfaces no tool can restore.
    """

    #: Mutable, GET-less, non-adopted entities that carry a PUT — real
    #: configuration the API offers no way to read back.
    write_only_paths: tuple[str, ...]
    #: POST/DELETE-only action endpoints (blinkLeds, claim, reboot, …):
    #: excluded from discovery by design, countable in the manifest.
    rpc_only_paths: tuple[str, ...]
    #: Canonical paths of GET-only entities — readable, never
    #: restorable by any tool (SM profiles, VPP accounts, licensing, …).
    api_read_only_paths: tuple[str, ...]


def spec_surface_report(parser: OpenApiParser) -> SpecSurfaces:
    """Classify every spec entity discovery does not capture."""
    mappings = parser.resource_mappings()
    adopted_keys = {
        mapping.entity_key
        for mapping in mappings.values()
        if mapping.aggregation_get is not None
    }
    adopted_source_paths = {
        mapping.aggregation_get.path
        for mapping in mappings.values()
        if mapping.aggregation_get is not None
    }
    write_only: list[str] = []
    rpc_only: list[str] = []
    read_only: list[str] = []
    for key, ops in parser.entity_operations().items():
        methods = {op.method for op in ops}
        if "get" in methods:
            if not (methods & _MUTATING_METHODS) and not any(
                op.path in adopted_source_paths for op in ops
            ):
                read_only.append(next(op.path for op in ops if op.method == "get"))
            continue
        if not (methods & _MUTATING_METHODS) or key in adopted_keys:
            continue
        if "put" in methods:
            write_only.append(next(op.path for op in ops if op.method == "put"))
        else:
            paths = [op.path for op in ops if op.method in _MUTATING_METHODS]
            rpc_only.extend(dict.fromkeys(paths))
    return SpecSurfaces(
        write_only_paths=tuple(sorted(write_only)),
        rpc_only_paths=tuple(sorted(rpc_only)),
        api_read_only_paths=tuple(sorted(read_only)),
    )


def network_product_types(parser: OpenApiParser) -> frozenset[str]:
    """Valid network product types, derived from the createNetwork enum.

    The set drives conservative product-type prefiltering: a
    network-scoped endpoint whose first path segment exactly equals one
    of these values only applies to networks carrying that product.
    An absent or unreadable enum yields the empty set — no filtering.
    """
    for op in parser.endpoints():
        if op.method != "post" or entity_key(op.path) != (
            "organizations", "networks",
        ):
            continue
        node: Any = op.raw
        for step in (
            "requestBody", "content", "application/json", "schema",
            "properties", "productTypes", "items", "enum",
        ):
            node = node.get(step) if isinstance(node, Mapping) else None
        if isinstance(node, list):
            return frozenset(
                value for value in node if isinstance(value, str) and value
            )
    return frozenset()


def product_segment(op: OperationSpec) -> str | None:
    """The path segment immediately after the operation's scope parameter.

    ``/networks/{networkId}/wireless/ssids`` → ``wireless`` (raw
    camelCase, so it compares exactly against the createNetwork enum);
    ``None`` when the scope parameter is the trailing segment.
    """
    segments = _path_segments(op.path)
    for index, segment in enumerate(segments):
        if segment.startswith("{"):
            if index + 1 < len(segments) and not segments[index + 1].startswith("{"):
                return segments[index + 1]
            return None
    return None


def _whole_collection_put(parser: OpenApiParser, op: OperationSpec) -> bool:
    """Whether ``op``'s path carries a PUT that replaces the whole list.

    Such endpoints (VPN peer SLAs, staged upgrade stages, …) declare a
    request body with exactly one array-typed property — the collection
    itself is a single configuration object. Per-item endpoints instead
    PUT individual selector fields (a serial, a network, …).
    """
    for candidate in parser.endpoints():
        if candidate.path != op.path or candidate.method != "put":
            continue
        node: Any = candidate.raw
        for key in ("requestBody", "content", "application/json", "schema"):
            node = node.get(key) if isinstance(node, Mapping) else None
        properties = node.get("properties") if isinstance(node, Mapping) else None
        if not isinstance(properties, Mapping) or len(properties) != 1:
            return False
        only = next(iter(properties.values()))
        return isinstance(only, Mapping) and only.get("type") == "array"
    return False


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
