"""Match spec-derived entities onto the provider's real resource types.

The ``CiscoDevNet/meraki`` provider hand-curates its resource names
(scope nouns inserted only to disambiguate, segments deduped,
singularization only before path parameters), so no pure path-to-name
formula reproduces them. Instead of a formula — or a forbidden
hard-coded table — this module *matches* each OpenAPI-derived entity
against the provider's own identity-schema catalog
(:class:`~meraki2tf.provider_catalog.ProviderCatalog`) and lets two
independent signals confirm every pairing:

1. **Identity fit** — the resource's identity attributes must be
   satisfiable by the entity's ordered path parameters (scope IDs by
   name, the trailing parameter by a same-name attribute, the single
   non-scope attribute, or the generic ``id``). A resource whose
   identity carries only an extra ``organization_id`` still fits — the
   organization ID is always known, so it is injected into the import
   ID (that is how ``meraki_network`` imports as
   ``"<organization_id>,<network_id>"``). Resources with an
   ``item_ids`` attribute are netascode bulk-collection variants and
   never targeted.
2. **Name compatibility** — every underscore token of the resource
   name must appear among the path's words (camelCase split, with
   singular/plural variant equivalence), so an identity-compatible but
   semantically unrelated resource can never be selected.

Candidates are scored coverage-first (how much of the path's wording
the name explains), which is what keeps ``meraki_switch_settings`` from
losing ``/networks/{networkId}/switch/settings`` to the scope-generic
``meraki_network_settings``. Finally a **global greedy one-to-one
assignment** guarantees no two entities claim the same resource: a
better-fitting entity always wins, and an entity whose best candidates
tie unresolvably maps to ``None`` (reported as an unsupported coverage
gap rather than guessed).

Validated against the provider's own generator definitions at v1.12.2:
149 matchable spec entities, 0 wrong assignments, 0 collisions. Re-run
against the v1.13.0 catalog: still 0 collisions — its one added type
(``meraki_network_firmware_upgrades_rollback``) is a POST-only action
with no discoverable surface, so it is correctly matched by nothing and
cannot steal ``meraki_network_firmware_upgrades``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from meraki2tf.openapi_parser import OpenApiParser, is_item_path, snake_case
from meraki2tf.provider_catalog import ProviderCatalog
from meraki2tf.providers.discovery import mutable_entity_keys

logger = logging.getLogger(__name__)

#: camelCase boundaries for *name/word matching only*: ``aB``,
#: ``ACRONYMWord``, and letter-pair→digit (``hotspot20`` →
#: ``hotspot 20``; single-letter prefixes like ``l3`` stay intact,
#: matching the provider's own tokenization). Path *parameters* are
#: snake_cased with the parser's ``snake_case`` instead — see
#: :func:`_path_params`.
_CAMEL_BOUNDARY = re.compile(
    r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|(?<=[a-z][a-z])(?=[0-9])"
)
_PARAM_SEGMENT = re.compile(r"^\{.+\}\Z")

#: Identity attributes that scope a resource rather than identify one
#: item of it.
_SCOPE_ATTRS = frozenset({"network_id", "organization_id", "serial"})

#: Path parameter → the noun the provider uses for that scope in names.
_SCOPE_NOUNS = {"network_id": "network", "organization_id": "organization",
                "serial": "device"}

#: Identity attribute marking netascode bulk-collection variants (whole
#: collections as one resource, imported org-first) — never a target.
_BULK_MARKER = "item_ids"

#: The one non-path identity attribute in the provider (group policies);
#: import IDs carry a literal boolean for it, defaulting to "false" so
#: an import can never cascade into a delete.
FORCE_DELETE_ATTR = "force_delete"


@dataclass(frozen=True)
class MatchedResource:
    """One provider resource an entity resolved to, ready for import."""

    #: Authoritative provider resource type, e.g. ``meraki_appliance_vlan``.
    terraform_name: str
    #: True when the identity needs the (always-known) organization ID
    #: prepended to the import ID.
    needs_org_prefix: bool
    #: True when the identity carries ``force_delete``; a literal
    #: ``"false"`` is inserted before the item ID on import.
    has_force_delete: bool
    #: Ordered snake_case path parameters of the matched endpoint — the
    #: components an asset must provide to be importable.
    import_id_components: tuple[str, ...]


def _split_words(segment: str) -> list[str]:
    return [word.lower() for word in _CAMEL_BOUNDARY.sub(" ", segment).split()]


def _variants(word: str) -> frozenset[str]:
    """Singular/plural variant set for one lowercase word.

    Two words are equivalent when their variant sets intersect. Naive
    single-rule stemming fails both ways (``licenses``→``licens`` vs
    ``license``; ``statuses``→``statuse`` vs ``status``), so every
    plausible reduction is generated instead.
    """
    out = {word}
    if word.endswith("ies"):
        out.add(word[:-3] + "y")
    if word.endswith("es"):
        out.add(word[:-2])
    if word.endswith("s") and not word.endswith("ss"):
        out.add(word[:-1])
    return frozenset(out)


def _same_word(a: str, b: str) -> bool:
    return bool(_variants(a) & _variants(b))


def _path_words(path: str) -> list[str]:
    words: list[str] = []
    for segment in path.split("/"):
        if segment and not _PARAM_SEGMENT.match(segment):
            words.extend(_split_words(segment))
    return words


def _path_params(path: str) -> tuple[str, ...]:
    """Ordered path parameters, snake_cased with the parser's tokenizer.

    The generator's import-ID guard compares these ``expected``
    components against ``provided`` ones it derives with
    :func:`~meraki2tf.openapi_parser.snake_case`; both sides must use
    the one implementation or a digit-boundary parameter (e.g.
    ``{hotspot20RuleId}``) would tokenize differently and falsely mark
    every asset of its entity unsupported.
    """
    return tuple(
        snake_case(segment[1:-1])
        for segment in path.split("/")
        if segment and _PARAM_SEGMENT.match(segment)
    )


def _name_tokens(resource: str) -> list[str]:
    return resource.removeprefix("meraki_").split("_")


def _identity_fit(
    identity: frozenset[str], params: tuple[str, ...]
) -> tuple[bool, bool]:
    """Whether ``identity`` is satisfiable by ``params``; and org injection.

    Scope parameters (all but the last) must be consumed by same-name
    identity attributes. The trailing parameter is the item and may be
    consumed by a same-name attribute, the identity's single non-scope
    attribute (``number``, ``port_id``, …), or the generic ``id``.
    Whatever remains must be nothing — or exactly ``organization_id``,
    which is injectable because the organization is always known.
    """
    if _BULK_MARKER in identity:
        return False, False
    if not params:
        return False, False
    remaining = set(identity) - {FORCE_DELETE_ATTR}
    *scope_params, last = params
    for param in scope_params:
        if param not in remaining:
            return False, False
        remaining.discard(param)
    if last in remaining:
        remaining.discard(last)
    else:
        non_scope = [attr for attr in remaining if attr not in _SCOPE_ATTRS]
        if len(non_scope) == 1:
            remaining.discard(non_scope[0])
        elif "id" in remaining:
            remaining.discard("id")
        else:
            return False, False
    if not remaining:
        return True, False
    if remaining == {"organization_id"}:
        return True, True
    return False, False


def _is_subsequence(tokens: list[str], sequence: list[str]) -> bool:
    iterator = iter(sequence)
    for token in tokens:
        for word in iterator:
            if _same_word(word, token):
                break
        else:
            return False
    return True


_Score = tuple[float, int, int, bool, int, int]


def _candidates(
    entity_path: str, catalog: ProviderCatalog
) -> list[tuple[_Score, str, bool]]:
    """Scored ``(score, resource, needs_org_prefix)`` candidates, best first.

    Score components, most significant first: fraction of the path's
    words the name covers, absolute coverage, ordered-subsequence bonus,
    no-org-injection preference, token count, name length. Coverage
    dominates so a name explaining the path's specific tail always
    beats a scope-generic name that merely fits the identity.
    """
    params = _path_params(entity_path)
    words = _path_words(entity_path)
    nouns = [_SCOPE_NOUNS[p] for p in params if p in _SCOPE_NOUNS]
    sequence_with_scope = nouns + words
    bag = set(words) | set(nouns)

    scored: list[tuple[_Score, str, bool]] = []
    for name, identity in catalog.resources.items():
        fits, needs_org = _identity_fit(identity, params)
        if not fits:
            continue
        tokens = _name_tokens(name)
        if not all(
            any(_same_word(token, word) for word in bag) for token in tokens
        ):
            continue
        ordered = (
            _is_subsequence(tokens, sequence_with_scope)
            or _is_subsequence(tokens, words)
        )
        covered = sum(
            1
            for word in set(words)
            if any(_same_word(word, token) for token in tokens)
        )
        fraction = covered / len(set(words)) if words else 1.0
        score: _Score = (
            fraction, covered, 1 if ordered else 0, not needs_org,
            len(tokens), len(name),
        )
        scored.append((score, name, needs_org))
    scored.sort(key=lambda item: item[0], reverse=True)
    return scored


def match_resources(
    parser: OpenApiParser, catalog: ProviderCatalog
) -> dict[tuple[str, ...], MatchedResource | None]:
    """Assign every mutable spec entity its provider resource (or None).

    Global greedy one-to-one assignment over all candidate pairs,
    strongest score first: once a resource is claimed, weaker entities
    cannot take it (a staged-events entity must not steal the
    ``firmware_upgrades`` blob resource just because nothing covers
    "staged events"). An entity whose top remaining candidates tie
    unresolvably is left unmatched rather than guessed — unmatched
    entities surface as unsupported coverage gaps, never as silently
    wrong imports.
    """
    mutable = mutable_entity_keys(parser)
    best_paths: dict[tuple[str, ...], str] = {}
    for mapping in parser.resource_mappings().values():
        if mapping.entity_key not in mutable:
            continue
        # Most specific endpoint wins; on equal parameter count the item
        # path beats a folded collection alias (/networks/{networkId}
        # over /organizations/{organizationId}/networks), because the
        # item path carries the entity's own addressing scheme.
        best_paths[mapping.entity_key] = max(
            mapping.paths,
            key=lambda path: (len(_path_params(path)), is_item_path(path)),
        )

    pool: list[tuple[_Score, tuple[str, ...], str, bool]] = []
    per_entity: dict[tuple[str, ...], list[tuple[_Score, str, bool]]] = {}
    for key, path in best_paths.items():
        candidates = _candidates(path, catalog)
        per_entity[key] = candidates
        pool.extend(
            (score, key, name, needs_org) for score, name, needs_org in candidates
        )
    pool.sort(key=lambda item: item[0], reverse=True)

    taken: set[str] = set()
    matches: dict[tuple[str, ...], MatchedResource | None] = {}
    for score, key, name, needs_org in pool:
        if key in matches or name in taken:
            continue
        ties = [
            candidate
            for candidate in per_entity[key]
            if candidate[0] == score
            and candidate[1] != name
            and candidate[1] not in taken
        ]
        if ties:
            logger.warning(
                "Entity %r matches multiple provider resources with equal "
                "confidence (%s vs %s); leaving it unmatched so it is "
                "reported as a coverage gap instead of guessed.",
                key, name, ties[0][1],
            )
            matches[key] = None
            continue
        matches[key] = MatchedResource(
            terraform_name=name,
            needs_org_prefix=needs_org,
            has_force_delete=FORCE_DELETE_ATTR in catalog.resources[name],
            import_id_components=_path_params(best_paths[key]),
        )
        taken.add(name)
    for key in best_paths:
        matches.setdefault(key, None)

    matched_count = sum(1 for value in matches.values() if value is not None)
    logger.info(
        "Resource matching: %d/%d mutable entities mapped onto %d provider "
        "resource type(s) (catalog source: %s).",
        matched_count, len(matches), len(catalog.resources), catalog.source,
    )
    return matches


def path_matches(
    parser: OpenApiParser, catalog: ProviderCatalog
) -> dict[str, MatchedResource | None]:
    """Per-path lookup over every path of every mutable entity.

    Folded collection aliases (``/organizations/{organizationId}/networks``
    belongs to the ``networks`` entity) resolve to their entity's match,
    so the generator can audit them against the matched endpoint's ID
    components exactly as before.
    """
    by_entity = match_resources(parser, catalog)
    lookup: dict[str, MatchedResource | None] = {}
    for mapping in parser.resource_mappings().values():
        if mapping.entity_key not in by_entity:
            continue
        match = by_entity[mapping.entity_key]
        for path in mapping.paths:
            lookup[path] = match
    return lookup
