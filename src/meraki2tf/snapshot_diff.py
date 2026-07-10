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
  carrying an identity key (``id``/``serial``/``number``/``name``)
  compare order-insensitively; bare arrays (firewall rules, whose order
  *is* the configuration) stay ordered.
* **Population-wide key additions are suppressed** — a brand-new
  attribute appearing across every modified asset of one endpoint is a
  fleet/API rollout, not an operator change.
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
_ELEMENT_IDENTITY_KEYS = ("id", "serial", "number", "name")

#: A key-addition seen on at least this many assets of one endpoint —
#: and on *every* modified asset of that endpoint — is an API rollout.
_ROLLOUT_MIN_ASSETS = 10


@dataclass(frozen=True)
class AssetDiff:
    """One modified asset with its attribute-level changes."""

    api_path: str
    path_values: tuple[str, ...]
    #: attribute → (previous, current); ``None`` marks absence.
    changed: Mapping[str, tuple[Any, Any]] = field(hash=False)


@dataclass(frozen=True)
class SnapshotDiff:
    """Everything that changed between two snapshots."""

    added: tuple[FeatureConfiguration, ...] = ()
    removed: tuple[FeatureConfiguration, ...] = ()
    modified: tuple[AssetDiff, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.modified)

    def summary(self) -> str:
        return (
            f"{len(self.added)} added, {len(self.modified)} modified, "
            f"{len(self.removed)} removed"
        )


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
        changed = _payload_changes(old.payload, feature.payload, allowed)
        if changed:
            modified.append(
                AssetDiff(
                    api_path=feature.api_path,
                    path_values=feature.path_values,
                    changed=changed,
                )
            )
    modified = _suppress_rollouts(modified)
    return SnapshotDiff(added=added, removed=removed, modified=tuple(modified))


def baseline_drift(
    graph: NetworkGraph,
    baseline_path: Any,
    parser: OpenApiParser | None,
) -> SnapshotDiff:
    """Diff a freshly discovered graph against a stored baseline snapshot."""
    from meraki2tf.providers.dump import StaticJsonDataProvider

    baseline = StaticJsonDataProvider(
        baseline_path, parser=parser
    ).fetch_network_graph(graph.organization_id)
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
        assets[(feature.api_path, feature.path_values)] = feature
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


def _payload_changes(
    before: Any,
    after: Any,
    writable: frozenset[str] | None,
) -> dict[str, tuple[Any, Any]]:
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return (
            {}
            if _values_equal(before, after)
            else {"<payload>": (before, after)}
        )
    before_items = _collection_items(before)
    after_items = _collection_items(after)
    if before_items is not None and after_items is not None:
        # Whole-collection assets are stored under the invented `items`
        # envelope, which never appears in a write schema (the write
        # body names its sole array property, e.g. `_json`) — filtering
        # by writable fields would silence ALL drift on this class.
        if _values_equal(before_items, after_items):
            return {}
        return {"items": (before_items, after_items)}
    changed: dict[str, tuple[Any, Any]] = {}
    for key in sorted(set(before) | set(after)):
        if writable is not None and key not in writable:
            continue
        old_value = before.get(key)
        new_value = after.get(key)
        if not _values_equal(old_value, new_value):
            changed[key] = (old_value, new_value)
    return changed


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


def _suppress_rollouts(modified: list[AssetDiff]) -> list[AssetDiff]:
    """Drop pure key-additions that hit every modified asset of a path.

    When Meraki rolls out a new (writable) response field, every asset
    of that endpoint "gains" the attribute in the same window — that is
    an API change, not operator drift.
    """
    per_path: dict[str, list[AssetDiff]] = {}
    for diff in modified:
        per_path.setdefault(diff.api_path, []).append(diff)
    survivors: list[AssetDiff] = []
    for api_path, diffs in per_path.items():
        rollout_keys = set()
        if len(diffs) >= _ROLLOUT_MIN_ASSETS:
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
    return survivors


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
    return "\n".join(lines)
