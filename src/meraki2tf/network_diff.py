"""Cross-network configuration comparison (golden-config conformance).

``--diff-networks 'PATTERN_A' 'PATTERN_B'`` answers the multi-site
question "does Branch-07 match the golden site?" without terraform and
without mutating anything: each pattern resolves to exactly one network
(the ``--only network:`` matching rules — case-insensitive glob over
name or ID; zero or several matches refuse loudly, listing candidates),
each network's discovered features are re-addressed under a neutral
network-ID placeholder, and the two per-network graphs run through the
snapshot-diff engine — spec-normalized writable-field comparison,
identity-keyed lists as sets, order-significant lists with explicit
order-change reporting.

Deliberate exclusions, each counted and rendered as a note:

* **Device-scoped features** — serials differ between sites by
  definition, so per-device config (switch ports, management
  interfaces) can never align key-for-key here.
* **Organization-scoped features** — shared by both networks, so they
  cannot differ between them.
* **Unreadable capture gaps** — an endpoint that could not be read has
  no comparable content; its gap is a coverage fact, not conformance
  drift.

Security contract: the rendered report and the optional ``--diff-out``
JSON carry attribute names and locators, **never values** — feature
payloads hold every secret Meraki returns on read, and conformance
tooling output travels (tickets, chat, CI logs).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.logging_setup import sanitize_control_chars
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.scope import describe_networks, glob_pattern
from meraki2tf.snapshot_diff import (
    ORDER_CHANGED,
    AssetDiff,
    SnapshotDiff,
    diff_graphs,
)

logger = logging.getLogger(__name__)

#: Placeholder replacing each side's network ID so identical features
#: of two different networks compare under identical asset keys.
NEUTRAL_NETWORK_ID = "<network>"

_NETWORK_PREFIX = "/networks/{networkId}"
_DEVICE_PREFIX = "/devices/{serial}"
_ORG_PREFIX = "/organizations/"


class NetworkResolutionError(ValueError):
    """A ``--diff-networks`` pattern resolved to zero or several networks."""


@dataclass(frozen=True)
class NetworkComparison:
    """Everything one cross-network comparison produced."""

    network_a: MerakiNetwork
    network_b: MerakiNetwork
    #: ``added``  = present only in network B; ``removed`` = only in A;
    #: ``modified`` = present in both with differing writable content.
    diff: SnapshotDiff
    device_scoped_excluded: int
    org_scoped_excluded: int
    unreadable_excluded: int


def resolve_network(
    networks: Sequence[MerakiNetwork], pattern: str
) -> MerakiNetwork:
    """Exactly one network for a pattern, or refuse listing candidates.

    Raises :class:`NetworkResolutionError` when the pattern matches no
    network or more than one — a diff needs a single unambiguous network
    on each side.
    """
    if pattern.lower().startswith("network:"):
        # Muscle memory from --only's selector syntax ("network:HQ*");
        # --diff-networks patterns are bare, but refusing over the
        # prefix would be operator-hostile — accept both spellings.
        pattern = pattern[len("network:"):]
    compiled = glob_pattern(pattern)
    hits = [
        network
        for network in networks
        if compiled.match(network.name) or compiled.match(network.network_id)
    ]
    if not hits:
        raise NetworkResolutionError(
            f"--diff-networks pattern {pattern!r} matched no network. "
            f"Available networks: {describe_networks(networks)}."
        )
    if len(hits) > 1:
        raise NetworkResolutionError(
            f"--diff-networks pattern {pattern!r} is ambiguous — it "
            f"matches {len(hits)} networks: {describe_networks(hits)}. "
            "Narrow the pattern until it matches exactly one."
        )
    return hits[0]


def _neutralized_features(
    graph: NetworkGraph, network_id: str
) -> tuple[tuple[FeatureConfiguration, ...], int]:
    """The network's comparable features under the neutral scope ID.

    Returns ``(features, unreadable_count)``. Only features scoped by
    this network's ID under the ``/networks/{networkId}`` family
    qualify; the leading path value is replaced by the placeholder so
    both sides key identically. Nested surfaces keep their remaining
    values (SSID numbers, VLAN IDs, …), which are comparable across
    networks by design.
    """
    features: list[FeatureConfiguration] = []
    unreadable = 0
    for feature in graph.features:
        if not feature.api_path.startswith(_NETWORK_PREFIX):
            continue
        if not feature.path_values or feature.path_values[0] != network_id:
            continue
        if UNREADABLE_MARKER in feature.payload:
            unreadable += 1
            continue
        features.append(
            FeatureConfiguration(
                api_path=feature.api_path,
                path_values=(NEUTRAL_NETWORK_ID, *feature.path_values[1:]),
                payload=feature.payload,
            )
        )
    return tuple(features), unreadable


def _device_scoped_count(graph: NetworkGraph, network_ids: frozenset[str]) -> int:
    """Device-scoped assets belonging to devices of the two networks."""
    serials = frozenset(
        device.serial
        for device in graph.devices
        if device.network_id in network_ids
    )
    return sum(
        1
        for feature in graph.features
        if feature.api_path.startswith(_DEVICE_PREFIX)
        and feature.path_values
        and feature.path_values[0] in serials
    )


def compare_networks(
    graph: NetworkGraph,
    pattern_a: str,
    pattern_b: str,
    parser: OpenApiParser | None = None,
) -> NetworkComparison:
    """Diff two networks of one discovered graph, feature by feature.

    Raises :class:`NetworkResolutionError` when either pattern fails to
    resolve to exactly one network (via :func:`resolve_network`) or when
    both patterns resolve to the same network.
    """
    network_a = resolve_network(graph.networks, pattern_a)
    network_b = resolve_network(graph.networks, pattern_b)
    if network_a.network_id == network_b.network_id:
        raise NetworkResolutionError(
            f"--diff-networks patterns {pattern_a!r} and {pattern_b!r} "
            f"both resolve to the same network "
            f"({network_a.name} ({network_a.network_id})); comparing a "
            "network to itself is always empty."
        )
    features_a, unreadable_a = _neutralized_features(
        graph, network_a.network_id
    )
    features_b, unreadable_b = _neutralized_features(
        graph, network_b.network_id
    )
    org_scoped = sum(
        1
        for feature in graph.features
        if feature.api_path.startswith(_ORG_PREFIX)
    )
    diff = diff_graphs(
        NetworkGraph(
            organization_id=graph.organization_id,
            networks=(),
            devices=(),
            features=features_a,
        ),
        NetworkGraph(
            organization_id=graph.organization_id,
            networks=(),
            devices=(),
            features=features_b,
        ),
        parser,
    )
    return NetworkComparison(
        network_a=network_a,
        network_b=network_b,
        diff=diff,
        device_scoped_excluded=_device_scoped_count(
            graph,
            frozenset((network_a.network_id, network_b.network_id)),
        ),
        org_scoped_excluded=org_scoped,
        unreadable_excluded=unreadable_a + unreadable_b,
    )


def _asset_ids(path_values: tuple[str, ...]) -> str:
    """The asset's own IDs with the neutral scope stripped."""
    return ",".join(path_values[1:]) or "<singleton>"


def _attribute_notes(asset: AssetDiff) -> list[str]:
    notes = []
    for attribute in sorted(asset.changed):
        before, _after = asset.changed[attribute]
        suffix = " (order changed)" if before == ORDER_CHANGED else ""
        notes.append(f"{attribute}{suffix}")
    return notes


def render_network_comparison(comparison: NetworkComparison) -> str:
    """Human-readable conformance report — attribute names, never values."""
    a, b = comparison.network_a, comparison.network_b
    diff = comparison.diff
    # Network names are tenant-controlled free text printed to stdout;
    # neutralize control characters so a crafted name cannot forge a
    # report line or emit an ANSI escape (the JSON --diff-out path is
    # already safe via json.dumps).
    label_a = f"{sanitize_control_chars(a.name)} ({a.network_id})"
    label_b = f"{sanitize_control_chars(b.name)} ({b.network_id})"
    lines = [
        f"Cross-network configuration diff: {label_a} vs {label_b}",
        (
            f"{len(diff.removed)} feature(s) only in {label_a}, "
            f"{len(diff.added)} only in {label_b}, "
            f"{len(diff.modified)} present in both but different."
        ),
        (
            "Values are never rendered (feature payloads can carry "
            "secrets); verify details in the dashboard."
        ),
    ]
    for feature in diff.removed:
        lines.append(
            f"- only in {label_a}: {feature.api_path} "
            f"({_asset_ids(feature.path_values)})"
        )
    for feature in diff.added:
        lines.append(
            f"+ only in {label_b}: {feature.api_path} "
            f"({_asset_ids(feature.path_values)})"
        )
    for asset in diff.modified:
        lines.append(
            f"~ differs: {asset.api_path} "
            f"({_asset_ids(asset.path_values)}): "
            + ", ".join(_attribute_notes(asset))
        )
    if diff.is_empty:
        lines.append(
            "No differences in comparable network-scoped configuration."
        )
    excluded = (
        f"Excluded from comparison: {comparison.device_scoped_excluded} "
        "device-scoped asset(s) (serials differ by definition), "
        f"{comparison.org_scoped_excluded} organization-scoped asset(s) "
        "(shared by both networks), "
        f"{comparison.unreadable_excluded} unreadable capture gap(s)."
    )
    lines.append(excluded)
    return "\n".join(lines)


def comparison_payload(comparison: NetworkComparison) -> dict[str, Any]:
    """Machine-readable report for ``--diff-out`` — names, never values."""
    diff = comparison.diff
    return {
        "networkA": {
            "id": comparison.network_a.network_id,
            "name": comparison.network_a.name,
        },
        "networkB": {
            "id": comparison.network_b.network_id,
            "name": comparison.network_b.name,
        },
        "onlyInA": [
            {
                "apiPath": feature.api_path,
                "ids": list(feature.path_values[1:]),
            }
            for feature in diff.removed
        ],
        "onlyInB": [
            {
                "apiPath": feature.api_path,
                "ids": list(feature.path_values[1:]),
            }
            for feature in diff.added
        ],
        "modified": [
            {
                "apiPath": asset.api_path,
                "ids": list(asset.path_values[1:]),
                "attributes": [
                    {
                        "name": attribute,
                        "orderChanged": (
                            asset.changed[attribute][0] == ORDER_CHANGED
                        ),
                    }
                    for attribute in sorted(asset.changed)
                ],
            }
            for asset in diff.modified
        ],
        "excluded": {
            "deviceScoped": comparison.device_scoped_excluded,
            "orgScoped": comparison.org_scoped_excluded,
            "unreadableGaps": comparison.unreadable_excluded,
        },
    }
