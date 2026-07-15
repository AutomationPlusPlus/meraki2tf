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
"""

from __future__ import annotations

from dataclasses import dataclass

from meraki2tf.models import NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.restorer import (
    WAVE_NETWORKS,
    RestorePlan,
    _own_identity,
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

    def summary(self) -> str:
        return (
            f"{self.snapshot_asset_count} snapshot asset(s): "
            f"{self.surviving_count} still present live (untouched), "
            f"{len(self.missing.actions)} missing and planned for "
            f"recreation, {len(self.missing.unrestorable)} missing but "
            "not restorable via the API (rebuild manually)."
        )


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
    return frozenset(keys)


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
    )
    return HealPlan(
        missing=RestorePlan(actions=missing, unrestorable=unrestorable),
        identity_mappings=tuple(mappings),
        surviving_count=len(surviving),
        snapshot_asset_count=len(full.actions),
    )
