"""Snapshot-vs-snapshot drift detection.

Comparing two discovery snapshots answers "what changed in Meraki"
directly — API-to-API, in seconds, offline — where the terraform-plan
comparison paid a full provider read pass and saw the API through the
provider's (buggy) model. The engine diffs every asset the snapshot
carries, including objects Terraform cannot express and secret-bearing
attributes the kit deliberately ignores: classes that were invisible to
plan-based drift.

Noise control is spec-driven, per the project contract:

* **Writable fields only** — a GET field that appears in no PUT/POST
  request schema for the entity cannot be configured, so it is not
  configuration (uplink counts, computed URLs, status echoes). Meraki
  fleet rollouts that add new read-only response fields therefore never
  page anyone.
* **Identity-keyed collections compare as sets** — arrays of objects
  carrying a true identity key (``id``/``serial``/``number``) compare
  order-insensitively; everything else — bare arrays and lists whose
  items merely carry a ``name`` (port-forwarding rules, one-to-many NAT
  rules, where order is match precedence) — stays ordered. A pure
  reordering is reported as an order change, never a full value dump.
* **Population-wide key additions are suppressed — but reported.** A
  brand-new attribute appearing across every modified asset of one
  endpoint is *probably* a fleet/API rollout, not an operator change —
  but a dashboard bulk edit setting a previously-unset field produces
  the exact same shape, so the suppression is carried on the diff
  (attribute names and asset counts, never values) and rendered into
  the alert digest for the operator to verify. Nothing goes unreported.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.plan_reconciler import deep_json_equal
from meraki2tf.replayer import _collection_items
from meraki2tf.runbook import write_operations

logger = logging.getLogger(__name__)

#: Pseudo-paths under which first-class objects join the diff.
NETWORK_PSEUDO_PATH = "/networks/{networkId}"
DEVICE_PSEUDO_PATH = "/devices/{serial}"

#: Payload keys that identify one element of an identity-keyed list.
#: Deliberately excludes ``name``: rule lists whose items merely carry a
#: name (portForwardingRules, oneToManyNatRules) are order-significant —
#: reordering changes firewall match precedence — so treating them as
#: multisets silenced exactly the drift the module exists to report.
_ELEMENT_IDENTITY_KEYS = ("id", "serial", "number")

#: A key-addition is treated as an API rollout only when it hits at
#: least this many modified assets of one endpoint, on *every* modified
#: asset of that endpoint, AND those modified assets cover (nearly) the
#: endpoint's whole population — see ``_ROLLOUT_MIN_COVERAGE``.
_ROLLOUT_MIN_ASSETS = 10

#: Fraction of ALL assets of a path that must be modified before a
#: key-addition can be suppressed as a rollout. A genuine operator bulk
#: edit setting a previously-null field on 10 of 200 objects must NOT
#: be suppressed to a name-only note; a Meraki fleet rollout touches
#: essentially every asset of the endpoint.
_ROLLOUT_MIN_COVERAGE = 0.9

#: Marker naming a pure reordering of an order-significant list; used
#: in place of a full before/after dump to keep the alert digest quiet.
ORDER_CHANGED = "<order changed>"


class SanitizedBaselineError(ValueError):
    """The drift baseline is a sanitized snapshot.

    A sanitized snapshot's org/network IDs and serials are pseudonyms
    (``net-0001``, ``dev-0042``), so every asset key would mismatch the
    real organization and the whole org would falsely register as
    added+removed — a drift-alert storm that buries real drift. Drift
    baselines must be the unsanitized snapshot.
    """


class BaselineOrgMismatchError(ValueError):
    """The drift baseline was captured from a different organization.

    Diffing two organizations against each other reports every asset as
    added+removed — an alert storm, never meaningful drift. The org-id
    override the baseline fetch applies would silently mask the
    mismatch, so the baseline's own recorded organization is checked
    first and a mismatch refuses loudly, naming both IDs.
    """


class PartialBaselineError(ValueError):
    """The drift baseline is a partial (``--only``) snapshot.

    A partial baseline covers only its scoped networks, so every asset
    outside the scope would falsely register as **added** — a phantom
    drift storm that buries real drift. Drift baselines must be
    full-organization snapshots; selective backups are for ``--heal``.
    """


@dataclass(frozen=True)
class AssetDiff:
    """One modified asset with its attribute-level changes."""

    api_path: str
    path_values: tuple[str, ...]
    #: attribute → (previous, current); ``None`` marks absence.
    changed: Mapping[str, tuple[Any, Any]] = field(hash=False)


@dataclass(frozen=True)
class SuppressedRollout:
    """Attributes withheld from ``modified`` as a probable API rollout.

    Names and counts only — never values — so the record is safe for
    alert payloads. The operator must verify the addition was a Meraki
    fleet rollout and not a dashboard bulk edit: the two are
    indistinguishable from snapshot shape alone.
    """

    api_path: str
    attributes: tuple[str, ...]
    asset_count: int


@dataclass(frozen=True)
class SnapshotDiff:
    """Everything that changed between two snapshots."""

    added: tuple[FeatureConfiguration, ...] = ()
    removed: tuple[FeatureConfiguration, ...] = ()
    modified: tuple[AssetDiff, ...] = ()
    suppressed_rollouts: tuple[SuppressedRollout, ...] = ()

    @property
    def is_empty(self) -> bool:
        # Suppressed rollouts count as content: a diff that is ONLY
        # probable rollouts must still reach the operator (a dashboard
        # bulk edit looks identical), so callers keying "anything to
        # alert about?" on this property alert on it too.
        return not (
            self.added
            or self.removed
            or self.modified
            or self.suppressed_rollouts
        )

    def summary(self) -> str:
        base = (
            f"{len(self.added)} added, {len(self.modified)} modified, "
            f"{len(self.removed)} removed"
        )
        if self.suppressed_rollouts:
            base += (
                f"; {len(self.suppressed_rollouts)} endpoint(s) with "
                "attribute additions suppressed as probable API rollouts"
            )
        return base


def diff_graphs(
    previous: NetworkGraph,
    current: NetworkGraph,
    parser: OpenApiParser | None = None,
) -> SnapshotDiff:
    """Attribute-level drift between two discovery snapshots.

    Assets are keyed by ``(api_path, path_values)``; networks and
    devices join under their pseudo-paths so their (Phase-0 widened)
    payloads are drift-checked like every feature. When a parser is
    supplied, comparison narrows to spec-writable attributes; without
    one (unit fixtures, exotic offline runs) all attributes compare.
    """
    writable = _writable_fields(parser)
    before = _assets_by_key(previous)
    after = _assets_by_key(current)

    added = tuple(
        feature for key, feature in after.items() if key not in before
    )
    removed = tuple(
        feature for key, feature in before.items() if key not in after
    )
    modified: list[AssetDiff] = []
    for key, feature in after.items():
        old = before.get(key)
        if old is None:
            continue
        if UNREADABLE_MARKER in feature.payload or UNREADABLE_MARKER in old.payload:
            # An unreadable endpoint has no comparable content; its gap
            # is already reported through the coverage manifest.
            continue
        allowed = writable.get(feature.api_path)
        if allowed is not None and feature.api_path == DEVICE_PSEUDO_PATH:
            # A device re-homed to another network is restore-relevant
            # drift (the claim wave depends on membership), but the
            # device PUT schema doesn't carry networkId — claims are a
            # separate endpoint — so the writable filter would silence
            # every clickops device move.
            allowed = allowed | {"networkId"}
        changed = _payload_changes(
            _strip_volatile_subtrees(old.api_path, old.payload),
            _strip_volatile_subtrees(feature.api_path, feature.payload),
            allowed,
        )
        if changed:
            modified.append(
                AssetDiff(
                    api_path=feature.api_path,
                    path_values=feature.path_values,
                    changed=changed,
                )
            )
    population: dict[str, int] = {}
    for api_path, _values in after:
        population[api_path] = population.get(api_path, 0) + 1
    survivors, suppressed = _suppress_rollouts(modified, population)
    return SnapshotDiff(
        added=added,
        removed=removed,
        modified=tuple(survivors),
        suppressed_rollouts=suppressed,
    )


def baseline_drift(
    graph: NetworkGraph,
    baseline_path: Any,
    parser: OpenApiParser | None,
) -> SnapshotDiff:
    """Diff a freshly discovered graph against a stored baseline snapshot.

    Refuses a sanitized baseline outright
    (:class:`SanitizedBaselineError`): diffing pseudonyms against real
    identifiers is never meaningful. A partial (``--only``) baseline is
    refused the same way (:class:`PartialBaselineError`), as is a
    baseline recorded from a different organization
    (:class:`BaselineOrgMismatchError`) — the org-id override below
    would otherwise mask the mismatch and report the whole org as
    added+removed.
    """
    from meraki2tf.providers.dump import StaticJsonDataProvider

    provider = StaticJsonDataProvider(baseline_path, parser=parser)
    if provider.snapshot_sanitized:
        raise SanitizedBaselineError(
            f"Drift baseline {baseline_path} is a sanitized snapshot (it "
            "carries the 'sanitized' marker): its identifiers are "
            "pseudonyms, so every asset would falsely register as "
            "added/removed. Point --drift-baseline at the unsanitized "
            "snapshot."
        )
    scope = provider.snapshot_scope
    if scope is not None:
        raise PartialBaselineError(
            f"Drift baseline {baseline_path} is a PARTIAL export "
            f"(--only, {len(scope.network_ids)} network(s)): every asset "
            "outside its scope would falsely register as added. Point "
            "--drift-baseline at a full-organization snapshot."
        )
    recorded = provider.recorded_organization_ids
    if recorded and graph.organization_id not in recorded:
        raise BaselineOrgMismatchError(
            f"Drift baseline {baseline_path} was captured from "
            f"organization {', '.join(recorded)}, but this run discovered "
            f"organization {graph.organization_id}: every asset would "
            "falsely register as added+removed. Point --drift-baseline "
            "at a snapshot of the same organization."
        )
    baseline = provider.fetch_network_graph(graph.organization_id)
    return diff_graphs(baseline, graph, parser)


def _assets_by_key(
    graph: NetworkGraph,
) -> dict[tuple[str, tuple[str, ...]], FeatureConfiguration]:
    assets: dict[tuple[str, tuple[str, ...]], FeatureConfiguration] = {}
    for network in graph.networks:
        assets[(NETWORK_PSEUDO_PATH, (network.network_id,))] = (
            FeatureConfiguration(
                api_path=NETWORK_PSEUDO_PATH,
                path_values=(network.network_id,),
                payload=network.payload,
            )
        )
    for device in graph.devices:
        assets[(DEVICE_PSEUDO_PATH, (device.serial,))] = FeatureConfiguration(
            api_path=DEVICE_PSEUDO_PATH,
            path_values=(device.serial,),
            payload=device.payload,
        )
    for feature in graph.features:
        key = (feature.api_path, feature.path_values)
        if key in assets:
            # Two assets sharing an identity key would silently shadow
            # each other (last wins), hiding drift on the shadowed one.
            # It shouldn't happen (ID-fallback collisions, duplicate gap
            # records), so surface it rather than swallow it.
            logger.warning(
                "Duplicate asset key %s in snapshot; drift on the shadowed "
                "instance will not be visible.", key,
            )
        assets[key] = feature
    return assets


def _writable_fields(
    parser: OpenApiParser | None,
) -> dict[str, frozenset[str]]:
    """api_path → top-level attribute names any PUT/POST accepts.

    Derived from the request-body schemas in the spec — "if you cannot
    write it, it is not configuration". Endpoints whose write ops
    declare no object properties (array bodies, undocumented schemas)
    are absent from the map, which means "compare everything" — err
    toward alerting, never toward silence.
    """
    if parser is None:
        return {}
    fields: dict[str, frozenset[str]] = {}
    for api_path, ops in write_operations(parser).items():
        names: set[str] = set()
        for op in ops:
            content = (
                op.raw.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
            )
            properties = content.get("schema", {}).get("properties", {})
            if isinstance(properties, Mapping):
                names.update(str(name) for name in properties)
        if names:
            fields[api_path] = frozenset(names)
    return fields


# Nested read-only subtrees the writable filter cannot see: it gates
# top-level keys only, and these hide under a genuinely writable parent
# (the firmwareUpgrades PUT accepts `products`, but only its nested
# `nextUpgrade`). Catalog/history data here changes whenever Cisco
# publishes a release or an upgrade completes — dashboard-managed state,
# not operator configuration, and not restorable. "*" matches any key.
_VOLATILE_SUBTREES: dict[str, tuple[tuple[str, ...], ...]] = {
    "/networks/{networkId}/firmwareUpgrades": (
        ("products", "*", "availableVersions"),
        ("products", "*", "currentVersion"),
        ("products", "*", "lastUpgrade"),
    ),
}


def _strip_volatile_subtrees(api_path: str, payload: Any) -> Any:
    """A copy of ``payload`` without the api_path's volatile subtrees."""
    routes = _VOLATILE_SUBTREES.get(api_path)
    if not routes or not isinstance(payload, Mapping):
        return payload

    def prune(node: Any, route: tuple[str, ...]) -> Any:
        if not isinstance(node, Mapping):
            return node
        head, rest = route[0], route[1:]
        keys = list(node) if head == "*" else [head]
        out = dict(node)
        for key in keys:
            if key not in out:
                continue
            if rest:
                out[key] = prune(out[key], rest)
            else:
                del out[key]
        return out

    for route in routes:
        payload = prune(payload, route)
    return payload


def _payload_changes(
    before: Any,
    after: Any,
    writable: frozenset[str] | None,
) -> dict[str, tuple[Any, Any]]:
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return (
            {}
            if _values_equal(before, after)
            else {"<payload>": _change_entry(before, after)}
        )
    before_items = _collection_items(before)
    after_items = _collection_items(after)
    if before_items is not None or after_items is not None:
        # Whole-collection assets are stored under the invented `items`
        # envelope, which never appears in a write schema (the write
        # body names its sole array property, e.g. `_json`) — filtering
        # by writable fields would silence ALL drift on this class.
        # Each side unwraps independently: when only one side carries
        # the envelope (a capture-format change, a hand-edited
        # snapshot), skipping this branch would filter every attribute
        # out and make ALL drift on the asset invisible.
        before_value = before_items if before_items is not None else before
        after_value = after_items if after_items is not None else after
        if _values_equal(before_value, after_value):
            return {}
        return {"items": _change_entry(before_value, after_value)}
    changed: dict[str, tuple[Any, Any]] = {}
    for key in sorted(set(before) | set(after)):
        if writable is not None and key not in writable:
            continue
        old_value = before.get(key)
        new_value = after.get(key)
        if not _values_equal(old_value, new_value):
            changed[key] = _change_entry(old_value, new_value)
    return changed


def _change_entry(before: Any, after: Any) -> tuple[Any, Any]:
    """The ``(previous, current)`` record for one detected change.

    An order-significant list whose elements are merely reordered (same
    multiset, different sequence — firewall match precedence changed)
    is reported as an explicit order change instead of a full
    before/after dump: the drift is real and must alert, but the values
    are identical and would only bloat the digest.
    """
    if (
        isinstance(before, list)
        and isinstance(after, list)
        and len(before) == len(after)
        and _canonical_multiset(before) == _canonical_multiset(after)
    ):
        return (
            ORDER_CHANGED,
            f"{ORDER_CHANGED}: {len(before)} item(s) reordered",
        )
    return (before, after)


def _values_equal(before: Any, after: Any) -> bool:
    """Order-aware equality with identity-keyed lists compared as sets."""
    if isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            return False
        if _identity_keyed(before) and _identity_keyed(after):
            return _canonical_multiset(before) == _canonical_multiset(after)
        return all(
            _values_equal(b_item, a_item)
            for b_item, a_item in zip(before, after)
        )
    return deep_json_equal(before, after)


def _identity_keyed(items: list[Any]) -> bool:
    return bool(items) and all(
        isinstance(item, Mapping)
        and any(item.get(key) is not None for key in _ELEMENT_IDENTITY_KEYS)
        for item in items
    )


def _canonical_multiset(items: list[Any]) -> dict[str, int]:
    import json as _json

    counts: dict[str, int] = {}
    for item in items:
        canonical = _json.dumps(item, sort_keys=True, default=str)
        counts[canonical] = counts.get(canonical, 0) + 1
    return counts


def _suppress_rollouts(
    modified: list[AssetDiff],
    population: Mapping[str, int],
) -> tuple[list[AssetDiff], tuple[SuppressedRollout, ...]]:
    """Withhold pure key-additions that hit every modified asset of a path.

    When Meraki rolls out a new (writable) response field, every asset
    of that endpoint "gains" the attribute in the same window — that is
    an API change, not operator drift. But an operator bulk edit that
    sets a previously-unset field on the whole fleet produces the same
    shape, so every suppression is returned as a
    :class:`SuppressedRollout` record (names and counts only) and must
    reach the alert digest — suppressed never means silent.

    ``population`` maps each api_path to how many assets of that path
    the current graph carries in total. A rollout must cover (nearly)
    the whole population, not merely ``_ROLLOUT_MIN_ASSETS`` modified
    assets: a bulk edit touching 10 of 200 objects is operator drift
    and must survive with full attribute detail. A path absent from the
    map counts as population-unknown and gates on the modified count
    alone.
    """
    per_path: dict[str, list[AssetDiff]] = {}
    for diff in modified:
        per_path.setdefault(diff.api_path, []).append(diff)
    survivors: list[AssetDiff] = []
    suppressed: list[SuppressedRollout] = []
    for api_path, diffs in per_path.items():
        rollout_keys = set()
        fleet_wide = (
            len(diffs) >= _ROLLOUT_MIN_ASSETS
            and len(diffs)
            >= _ROLLOUT_MIN_COVERAGE * population.get(api_path, 0)
        )
        if fleet_wide:
            candidate_keys = set().union(*(set(d.changed) for d in diffs))
            for key in candidate_keys:
                if all(
                    key in d.changed and d.changed[key][0] is None
                    for d in diffs
                ):
                    rollout_keys.add(key)
            if rollout_keys:
                logger.info(
                    "Suppressing fleet-rollout attribute(s) on %s "
                    "(added across all %d modified assets): %s",
                    api_path, len(diffs), ", ".join(sorted(rollout_keys)),
                )
                suppressed.append(
                    SuppressedRollout(
                        api_path=api_path,
                        attributes=tuple(sorted(rollout_keys)),
                        asset_count=len(diffs),
                    )
                )
        for diff in diffs:
            kept = {
                key: values
                for key, values in diff.changed.items()
                if key not in rollout_keys
            }
            if kept:
                survivors.append(
                    AssetDiff(
                        api_path=diff.api_path,
                        path_values=diff.path_values,
                        changed=kept,
                    )
                )
    survivors.sort(key=lambda d: (d.api_path, d.path_values))
    suppressed.sort(key=lambda s: s.api_path)
    return survivors, tuple(suppressed)


def render_diff(diff: SnapshotDiff, limit: int = 50) -> str:
    """Human-readable digest for alert payloads (values redacted to
    types/lengths for secret safety — the alert names what changed,
    never the values)."""
    lines: list[str] = [diff.summary()]
    for feature in diff.added[:limit]:
        lines.append(f"+ {feature.api_path} ({','.join(feature.path_values)})")
    for feature in diff.removed[:limit]:
        lines.append(f"- {feature.api_path} ({','.join(feature.path_values)})")
    for asset in diff.modified[:limit]:
        attrs = ", ".join(sorted(asset.changed))
        lines.append(
            f"~ {asset.api_path} ({','.join(asset.path_values)}): {attrs}"
        )
    hidden = (
        max(0, len(diff.added) - limit)
        + max(0, len(diff.removed) - limit)
        + max(0, len(diff.modified) - limit)
    )
    if hidden:
        lines.append(f"... and {hidden} more (see coverage artifacts)")
    if diff.suppressed_rollouts:
        lines.append(
            "suppressed as probable API rollout — verify these were NOT "
            "an operator bulk change:"
        )
        for rollout in diff.suppressed_rollouts:
            lines.append(
                f"! {rollout.api_path} ({rollout.asset_count} assets): "
                f"{', '.join(rollout.attributes)}"
            )
    return "\n".join(lines)
