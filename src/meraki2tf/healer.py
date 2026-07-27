"""Same-tenant partial recovery: recreate accidentally deleted objects.

``--heal`` answers the "someone deleted a bunch of stuff by mistake"
incident. It diffs a snapshot against fresh live discovery of the
**same** organization and rebuilds only what is missing, through the
restore engine's wave ordering and reference remapping — so a deleted
network comes back with all of its children rewired to the network's
new server-assigned ID, while references to objects that survived the
accident resolve to themselves (identity mappings).

Heal is **additive-only** by construction: an asset whose snapshot key
is still discoverable live is never dispatched, so existing objects are
never updated or deleted. Modified-in-place settings are the drift
pipeline's job (``--sync`` / ``--rebuild``), not heal's.

The recovery point is the snapshot's age: anything created after the
snapshot was taken is not in it and cannot be healed back.

``--only`` narrows a heal to a selection of the missing objects (one of
two deleted networks, some of several deleted SSIDs): see
:func:`filter_heal_plan`. Filtering is purely subtractive — the
selection is always a subset of the full heal plan — so every guarantee
above carries over unchanged.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from meraki2tf.models import NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.scope import glob_pattern
from meraki2tf.restorer import (
    NETWORK_BIND_PATH,
    NETWORK_CREATE_PATH,
    WAVE_NETWORKS,
    RestoreAction,
    RestorePlan,
    Unrestorable,
    _GRAMMAR_KEYS,
    _NATURAL_MATCH_KEYS,
    _OBJ_GRP_RE,
    _PATH_PARAM_RE,
    _REFERENCE_KEY_RE,
    _own_identity,
    _scope_stem,
    _scoped_path_pairs,
    plan_restore,
)

#: (stem, old, new, context) rows for ReferenceResolver.record — for
#: heal, old == new: the object survived with its identity intact.
IdentityMapping = tuple[str, str, str, tuple[str, ...]]


@dataclass(frozen=True)
class HealPlan:
    """What a heal would recreate — shown before any ``--confirm``."""

    #: Only the actions whose asset no longer exists live, in the full
    #: plan's wave order; ``unrestorable`` is filtered the same way.
    missing: RestorePlan
    #: Identity mappings for every surviving created/claimed object, so
    #: references from recreated objects to survivors resolve in place.
    identity_mappings: tuple[IdentityMapping, ...]
    surviving_count: int
    snapshot_asset_count: int
    #: Surviving objects that can contain others (a network that is
    #: still there, an SSID slot that still exists). ``--only`` matches
    #: these as *scope anchors* only: naming one selects the missing
    #: objects underneath it, never the survivor itself — heal stays
    #: additive-only. The common incident is objects deleted *inside* a
    #: network that is still standing, where the operator scopes the
    #: recovery by the site's name.
    surviving_anchors: tuple[RestoreAction, ...] = ()

    def summary(self) -> str:
        text = (
            f"{self.snapshot_asset_count} snapshot asset(s): "
            f"{self.surviving_count} still present live (untouched), "
            f"{len(self.missing.actions)} missing and planned for "
            f"recreation, {len(self.missing.unrestorable)} missing but "
            "not restorable via the API (rebuild manually)."
        )
        if self.missing.defaults:
            text += (
                f" {len(self.missing.defaults)} missing asset(s) were at "
                "Meraki defaults (nothing to write)."
            )
        return text


def live_asset_keys(live: NetworkGraph, parser: OpenApiParser) -> frozenset[str]:
    """Every asset identity discoverable in the live organization.

    Keys come from running the SAME classification (:func:`plan_restore`)
    over the live graph, so shapes match the snapshot plan's action keys
    by construction — including features the classifier rewrites onto a
    synthesized item path (adaptive-policy-style elements). A hand-built
    mirror of the key shapes once missed those rewrites, so a surviving
    object's key never matched, it classified as "missing", and heal
    would re-create — or adopt-and-align, i.e. MODIFY — a survivor,
    violating additive-only. Unrestorable live assets contribute their
    raw keys so the unrestorable filter matches the same way.
    """
    live_plan = plan_restore(live, parser)
    keys = {action.key for action in live_plan.actions}
    keys |= {
        f"{item.api_path}::{','.join(item.path_values)}"
        for item in live_plan.unrestorable
    }
    # At-defaults assets are alive too: an empty capture means the
    # object exists with nothing configured. Without these keys a
    # snapshot-configured counterpart would classify as "missing" and
    # heal would modify a survivor, violating additive-only.
    keys |= {entry.key for entry in live_plan.defaults}
    return frozenset(keys)


def _split_survivor_bindings(
    missing: tuple[RestoreAction, ...],
) -> tuple[tuple[RestoreAction, ...], tuple[Unrestorable, ...]]:
    """Keep config-template bindings out of a heal unless the network
    itself is being recreated.

    A network that is standing but no longer bound reads as a "missing"
    binding, and re-binding it would hand its whole configuration to a
    template — the largest possible modification of a survivor, under
    the one flag that promises never to modify one. Heal recreates
    deletions; a lost binding is reported for a human instead.

    A binding whose network IS missing rides along with the recreation:
    the network is being rebuilt from the snapshot, so restoring it
    unbound would be the incomplete answer.
    """
    recreated = {
        action.path_values[0]
        for action in missing
        if action.api_path == NETWORK_CREATE_PATH
    }
    kept: list[RestoreAction] = []
    deferred: list[Unrestorable] = []
    for action in missing:
        if (
            action.api_path == NETWORK_BIND_PATH
            and action.path_values[0] not in recreated
        ):
            deferred.append(
                Unrestorable(
                    api_path=action.api_path,
                    path_values=action.path_values,
                    reason=(
                        "the network is standing but is no longer bound "
                        "to its config template; heal is additive-only "
                        "and never re-binds a surviving network — "
                        "re-bind it in the dashboard"
                    ),
                )
            )
            continue
        kept.append(action)
    return tuple(kept), tuple(deferred)


def plan_heal(
    snapshot: NetworkGraph, live: NetworkGraph, parser: OpenApiParser
) -> HealPlan:
    """Classify snapshot assets into surviving vs missing.

    Pure — no I/O, no SDK. Children of a deleted parent are missing by
    construction (their keys carry the dead parent's ID, which live
    discovery no longer yields), so a deleted network drags its whole
    subtree into the heal plan without any tree walking here.
    """
    full = plan_restore(snapshot, parser)
    alive = live_asset_keys(live, parser)
    missing = tuple(a for a in full.actions if a.key not in alive)
    surviving = tuple(a for a in full.actions if a.key in alive)
    missing, unbound = _split_survivor_bindings(missing)
    mappings: list[IdentityMapping] = []
    for action in surviving:
        if action.kind not in ("create", "claim"):
            continue
        stem, old = _own_identity(action)
        # Context mirrors the executor's mapping_context for created
        # objects, so scoped lookups behave identically for survivors.
        context = (
            ()
            if action.wave == WAVE_NETWORKS
            else tuple(
                value
                for value in action.path_values[:-1]
                if value != snapshot.organization_id
            )
        )
        mappings.append((stem, old, old, context))
    unrestorable = tuple(
        item
        for item in full.unrestorable
        if f"{item.api_path}::{','.join(item.path_values)}" not in alive
    ) + unbound
    defaults = tuple(
        entry for entry in full.defaults if entry.key not in alive
    )
    return HealPlan(
        missing=RestorePlan(
            actions=missing, unrestorable=unrestorable, defaults=defaults
        ),
        identity_mappings=tuple(mappings),
        surviving_count=len(surviving),
        snapshot_asset_count=len(full.actions),
        surviving_anchors=tuple(a for a in surviving if _is_anchor(a)),
    )


class HealFilterError(ValueError):
    """A ``--only`` selector is empty or matched no missing object.

    Zero matches fail loudly instead of healing nothing: a typo'd
    selector that silently selected an empty set would let the operator
    believe the deletion was recovered when nothing was written.
    """


@dataclass(frozen=True)
class HealSelection:
    """A ``--only``-filtered heal plan, with reporting counters."""

    #: The original plan with ``missing`` shrunk to the selection —
    #: identity mappings and counters are untouched.
    plan: HealPlan
    #: Action keys pulled in beyond the selectors' own matches because
    #: a selected object depends on them (its deleted parent, a missing
    #: object its payload references) — without these the executor
    #: would fail loudly on an unmapped reference.
    auto_included: tuple[str, ...]
    #: (selector, direct-match count) per ``--only`` value, in order.
    selector_matches: tuple[tuple[str, int], ...]
    excluded_actions: int
    excluded_unrestorable: int
    excluded_defaults: int


#: ``TYPE:PATTERN`` split — only an identifier-shaped prefix counts as
#: a TYPE, and the bare form is always tried too (see ``_Selector``).
_SELECTOR_TYPE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*):(.+)$", re.DOTALL)


def _stem_plural(token: str) -> str:
    """Lowercase, singular form of a path segment or user-typed TYPE —
    ``groupPolicies``/``grouppolicy`` and ``ssids``/``SSID`` unify."""
    lowered = token.lower()
    if lowered.endswith("ies"):
        return lowered[:-3] + "y"
    if lowered.endswith("s") and not lowered.endswith("ss"):
        return lowered[:-1]
    return lowered


@dataclass(frozen=True)
class _Selector:
    raw: str
    #: The stemmed TYPE prefix, when the selector carries one.
    type_stem: str | None
    #: PATTERN of the typed form, compiled.
    pattern: re.Pattern[str]
    #: The whole raw value as one glob: an object literally named with
    #: a colon (``Guest:Floor2``) still selectable without escaping.
    bare: re.Pattern[str]


def _parse_selector(raw: str) -> _Selector:
    if not raw.strip():
        raise HealFilterError(
            "--only got an empty selector; pass [TYPE:]PATTERN, e.g. "
            "--only 'network:Branch-*'."
        )
    matched = _SELECTOR_TYPE_RE.match(raw)
    type_stem = _stem_plural(matched.group(1)) if matched else None
    pattern = glob_pattern(matched.group(2)) if matched else glob_pattern(raw)
    return _Selector(
        raw=raw, type_stem=type_stem, pattern=pattern, bare=glob_pattern(raw)
    )


def _type_stems(api_path: str) -> frozenset[str]:
    """Type stems an asset answers to, derived from its API path alone.

    An item path answers to its collection segment
    (``…/ssids/{number}`` → ``ssid``); anything else answers to every
    literal segment after the last placeholder (``…/{networkId}/snmp``
    → ``snmp``, the network-create collection → ``network``, the
    device-claim endpoint → ``device`` and ``claim``).
    """
    segments = [s for s in api_path.split("/") if s]
    if segments and segments[-1].startswith("{"):
        for segment in reversed(segments[:-1]):
            if not segment.startswith("{"):
                return frozenset({_stem_plural(segment)})
        return frozenset()
    stems: list[str] = []
    for segment in segments:
        if segment.startswith("{"):
            stems.clear()
        else:
            stems.append(_stem_plural(segment))
    return frozenset(stems)


def _pattern_hits(
    pattern: re.Pattern[str], payload: Mapping[str, Any], own_id: str
) -> bool:
    """Does the glob name this asset — by natural identity or own ID?"""
    for key in _NATURAL_MATCH_KEYS:
        value = payload.get(key)
        if isinstance(value, str) and pattern.match(value):
            return True
    return bool(own_id and pattern.match(own_id))


def _selector_hits(
    selector: _Selector,
    api_path: str,
    path_values: tuple[str, ...],
    payload: Mapping[str, Any],
) -> bool:
    own_id = path_values[-1] if path_values else ""
    if (
        selector.type_stem is not None
        and selector.type_stem in _type_stems(api_path)
        and _pattern_hits(selector.pattern, payload, own_id)
    ):
        return True
    return _pattern_hits(selector.bare, payload, own_id)


def _path_pairs(
    api_path: str, path_values: tuple[str, ...]
) -> tuple[tuple[str, str], ...]:
    """(scope stem, value) per positionally-paired path placeholder.

    Scope-less diagnostic gap records legitimately carry fewer values
    than their path declares (the unresolvable tail scope was never
    discovered), so a short row pairs its leading prefix. Everything
    else routes through the restorer's strict pairing: values may
    never silently OUTNUMBER placeholders — an identity hiding in an
    unpaired tail would shrink heal's scope containment — and the
    claim path's extra trailing serial pairs explicitly.
    """
    names = _PATH_PARAM_RE.findall(api_path)
    if len(path_values) < len(names):
        return tuple(
            (_scope_stem(name), value)
            for name, value in zip(names, path_values)
        )
    return tuple(
        (_scope_stem(name), value)
        for name, value in _scoped_path_pairs(api_path, path_values)
    )


def _in_scope(
    api_path: str,
    path_values: tuple[str, ...],
    anchors: Sequence[tuple[str, str, frozenset[str]]],
) -> bool:
    """Does the asset live under one of the anchor identities?

    True when a path placeholder carries the anchor's (stem, ID) and
    the anchor's own parent context is contained in the asset's path
    values — the same scoped-containment rule the reference resolver
    applies, so colliding per-network IDs never leak across networks.
    """
    pairs = _path_pairs(api_path, path_values)
    values = frozenset(path_values)
    return any(
        (stem, ident) in pairs and context <= values
        for stem, ident, context in anchors
    )


def _is_anchor(action: RestoreAction) -> bool:
    """Does the action carry an identity children can live under?

    Creates and claims mint identities; an item path's last value *is*
    its identity even when the action merely configures a fixed slot
    (SSID numbers). Singleton configures end at their parent's scope —
    anchoring on them would drag the whole parent subtree in.
    """
    return action.kind in ("create", "claim") or action.api_path.endswith("}")


def _anchor_of(action: RestoreAction) -> tuple[str, str, frozenset[str]]:
    stem, ident = _own_identity(action)
    return (stem, ident, frozenset(action.path_values[:-1]))


def _iter_ref_values(value: Any) -> Iterator[str]:
    items = value if isinstance(value, list) else (value,)
    for item in items:
        if isinstance(item, (str, int)) and not isinstance(item, bool):
            yield str(item)


def _payload_refs(value: Any, refs: set[tuple[str, str]]) -> None:
    """Collect (stem, ID) cross-references out of a write payload —
    reference-shaped keys plus the firewall-rule GRP()/OBJ() grammar."""
    if isinstance(value, Mapping):
        for key, inner in value.items():
            if isinstance(key, str) and _REFERENCE_KEY_RE.search(key):
                stem = _scope_stem(key)
                refs.update((stem, ref) for ref in _iter_ref_values(inner))
            _payload_refs(inner, refs)
    elif isinstance(value, list):
        for inner in value:
            _payload_refs(inner, refs)
    elif isinstance(value, str):
        for verb, ident in _OBJ_GRP_RE.findall(value):
            refs.add((_scope_stem(_GRAMMAR_KEYS[verb]), ident))


def _dependencies(action: RestoreAction) -> set[tuple[str, str]]:
    """Every (stem, ID) the action needs resolvable at execute time:
    its parent path scopes plus its payload's cross-references."""
    own = _own_identity(action)
    refs = {pair for pair in _path_pairs(action.api_path, action.path_values)
            if pair != own}
    _payload_refs(action.payload, refs)
    return refs


def _zero_match_message(
    unmatched: Sequence[str], missing: RestorePlan
) -> str:
    labels: list[str] = []
    for action in missing.actions[:15]:
        stems = "/".join(sorted(_type_stems(action.api_path))) or "asset"
        name = next(
            (
                value
                for key in _NATURAL_MATCH_KEYS
                if isinstance(value := action.payload.get(key), str)
            ),
            None,
        )
        own_id = action.path_values[-1] if action.path_values else "?"
        labels.append(f"{stems}:{name or own_id}")
    available = "; ".join(labels)
    if len(missing.actions) > 15:
        available += f"; … and {len(missing.actions) - 15} more"
    return (
        "--only selector(s) "
        + ", ".join(repr(s) for s in unmatched)
        + " matched no missing object — the object may still exist live "
        "(heal only recreates deletions) or the name/type may be "
        "misspelled. Missing objects available to select: "
        + (available or "<none>")
    )


def filter_heal_plan(
    plan: HealPlan, selectors: Sequence[str]
) -> HealSelection:
    """Shrink a heal plan to the objects named by ``--only`` selectors.

    Pure — no I/O. Three passes over ``plan.missing``:

    1. **Direct match** of every selector (``[TYPE:]PATTERN`` glob over
       natural identity and own ID); a selector matching nothing raises
       :class:`HealFilterError`.
    2. **Scope expansion**: everything living under a matched identity
       joins the selection, so ``network:Branch-07`` drags the deleted
       network's whole missing subtree along.
    3. **Dependency closure**: missing parents and referenced missing
       objects of the selection are auto-included (and reported), so a
       partial selection can never dispatch an unresolvable reference.

    The result is a subset of ``plan.missing`` by construction — the
    filter can only ever shrink what heal executes.
    """
    parsed = [_parse_selector(raw) for raw in dict.fromkeys(selectors)]
    actions = plan.missing.actions
    by_key = {action.key: action for action in actions}

    selected: set[str] = set()
    kept_unrestorable: set[tuple[str, tuple[str, ...]]] = set()
    kept_defaults: set[str] = set()
    matches: list[tuple[str, int]] = []
    unmatched: list[str] = []
    container_anchors: list[tuple[str, str, frozenset[str]]] = []
    for selector in parsed:
        hit_keys: set[str] = set()
        hit_unrestorable: set[tuple[str, tuple[str, ...]]] = set()
        hit_defaults: set[str] = set()
        for action in actions:
            if _selector_hits(
                selector, action.api_path, action.path_values, action.payload
            ):
                hit_keys.add(action.key)
        for item in plan.missing.unrestorable:
            if _selector_hits(selector, item.api_path, item.path_values, {}):
                hit_unrestorable.add((item.api_path, item.path_values))
        for entry in plan.missing.defaults:
            if _selector_hits(
                selector, entry.api_path, entry.path_values, {}
            ):
                hit_defaults.add(entry.key)
        # A SURVIVING container the selector names anchors the scope
        # too: "recover site X" must work whether X itself was deleted
        # or only objects inside it were. The survivor is never
        # selected — only the missing objects under it — so this can
        # still only ever shrink what heal executes.
        anchors_here = [
            _anchor_of(action)
            for action in plan.surviving_anchors
            if _selector_hits(
                selector, action.api_path, action.path_values, action.payload
            )
        ]
        if anchors_here:
            container_anchors.extend(anchors_here)
            hit_keys |= {
                action.key
                for action in actions
                if _in_scope(
                    action.api_path, action.path_values, anchors_here
                )
            }
            hit_unrestorable |= {
                (item.api_path, item.path_values)
                for item in plan.missing.unrestorable
                if _in_scope(item.api_path, item.path_values, anchors_here)
            }
            hit_defaults |= {
                entry.key
                for entry in plan.missing.defaults
                if _in_scope(entry.api_path, entry.path_values, anchors_here)
            }
        selected |= hit_keys
        kept_unrestorable |= hit_unrestorable
        kept_defaults |= hit_defaults
        # Deduplicated per selector, so a selector that names both a
        # missing object and its surviving parent is not counted twice.
        count = len(hit_keys) + len(hit_unrestorable) + len(hit_defaults)
        matches.append((selector.raw, count))
        if count == 0:
            # A surviving container with nothing missing under it is
            # still a zero-match: heal would write nothing, and a
            # silent no-op must never look like a recovery.
            unmatched.append(selector.raw)
    if unmatched:
        raise HealFilterError(_zero_match_message(unmatched, plan.missing))

    # Scope expansion to a fixed point: children of selected identities
    # join, and newly-joined items can be anchors themselves (a deleted
    # network's SSID anchors that SSID's own nested surfaces).
    while True:
        anchors = [
            _anchor_of(by_key[key])
            for key in selected
            if _is_anchor(by_key[key])
        ] + container_anchors
        grown = {
            action.key
            for action in actions
            if action.key not in selected
            and _in_scope(action.api_path, action.path_values, anchors)
        }
        if not grown:
            break
        selected |= grown

    # The operator's intent ends here; unrestorable/defaults reporting
    # follows it (dependency parents added below carry no reporting).
    kept_unrestorable |= {
        (item.api_path, item.path_values)
        for item in plan.missing.unrestorable
        if _in_scope(item.api_path, item.path_values, anchors)
    }
    kept_defaults |= {
        entry.key
        for entry in plan.missing.defaults
        if _in_scope(entry.api_path, entry.path_values, anchors)
    }

    # Dependency closure to a fixed point: a selected object's missing
    # parent or referenced missing object must restore too, or the
    # executor fails on an unmapped reference. References to SURVIVORS
    # need nothing — identity mappings resolve them in place.
    by_identity: dict[tuple[str, str], list[RestoreAction]] = {}
    by_value: dict[str, list[RestoreAction]] = {}
    for action in actions:
        # Only identity-minting actions are dependency targets: a
        # singleton configure's "own identity" is its PARENT's scope
        # (see the resolver's registration rule), and indexing it here
        # would auto-include unrelated siblings of a selected object.
        if not _is_anchor(action):
            continue
        stem, ident = _own_identity(action)
        by_identity.setdefault((stem, ident), []).append(action)
        by_value.setdefault(ident, []).append(action)
    auto_included: list[str] = []
    # Plan order, processed as a queue: auto_included stays deterministic
    # regardless of set-iteration (hash-seed) order.
    frontier = [action.key for action in actions if action.key in selected]
    while frontier:
        key = frontier.pop(0)
        values = frozenset(by_key[key].path_values)
        for stem, ident in sorted(_dependencies(by_key[key])):
            if stem:
                candidates = [
                    action
                    for action in by_identity.get((stem, ident), [])
                    if frozenset(action.path_values[:-1]) <= values
                ]
            else:
                # A bare id/ids key names no type: include only when
                # the ID is globally unambiguous among missing objects
                # (the resolver's flat-unique rule).
                candidates = by_value.get(ident, [])
                if len(candidates) != 1:
                    continue
            for action in candidates:
                if action.key not in selected:
                    selected.add(action.key)
                    auto_included.append(action.key)
                    frontier.append(action.key)

    shrunk = RestorePlan(
        actions=tuple(a for a in actions if a.key in selected),
        unrestorable=tuple(
            item
            for item in plan.missing.unrestorable
            if (item.api_path, item.path_values) in kept_unrestorable
        ),
        defaults=tuple(
            entry
            for entry in plan.missing.defaults
            if entry.key in kept_defaults
        ),
    )
    return HealSelection(
        plan=replace(plan, missing=shrunk),
        auto_included=tuple(auto_included),
        selector_matches=tuple(matches),
        excluded_actions=len(actions) - len(shrunk.actions),
        excluded_unrestorable=(
            len(plan.missing.unrestorable) - len(shrunk.unrestorable)
        ),
        excluded_defaults=len(plan.missing.defaults) - len(shrunk.defaults),
    )
