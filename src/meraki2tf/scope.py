"""Network-scoped ("selective") backup: scope model and filtering.

``--dump-to … --only 'network:PATTERN'`` exports a **partial** snapshot
covering only the selected networks (plus every org-level surface, so
references from the scoped networks stay recreatable). The snapshot
records that scope in its header; consumers either honor it (``--heal``
narrows its live discovery to the same networks), stamp it (coverage
manifest, runbook, alerts), or refuse it (``--restore``,
``--replay-gaps``, ``--drift-baseline``, ``--sync``) — a partial
snapshot must never masquerade as a full-organization capture.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from meraki2tf.models import MerakiNetwork


class ScopeFilterError(ValueError):
    """A network selector is malformed or matched no network.

    Zero matches fail loudly instead of exporting nothing: a typo'd
    selector that silently selected an empty set would leave the
    operator believing they hold a backup when the snapshot covers
    no networks at all.
    """


def glob_pattern(pattern: str) -> re.Pattern[str]:
    """Case-insensitive glob — one matching dialect for ``--only``
    everywhere (heal's write-set filter and export's network scope)."""
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE)


#: ``TYPE:PATTERN`` split, mirroring the heal selector grammar.
_SELECTOR_TYPE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9]*):(.+)$", re.DOTALL)

#: Accepted TYPE spellings for an export scope selector.
_NETWORK_STEMS = frozenset({"network", "networks"})

#: Cap on the networks listed in a zero-match diagnostic.
_MAX_LISTED_NETWORKS = 15


def parse_network_selectors(
    raw: Sequence[str],
) -> tuple[tuple[str, re.Pattern[str]], ...]:
    """Validate export-scope selectors into (raw, compiled glob) pairs.

    Export scoping deliberately accepts **only** the explicitly-typed
    ``network:PATTERN`` form: an untyped or other-typed selector is a
    usage error, so the restriction can be lifted compatibly if finer
    export scoping is ever wanted.

    Raises :class:`ScopeFilterError` for any selector that is not a
    well-formed ``network:PATTERN``.
    """
    parsed: list[tuple[str, re.Pattern[str]]] = []
    for value in raw:
        matched = _SELECTOR_TYPE_RE.match(value) if value.strip() else None
        if matched is None or matched.group(1).lower() not in _NETWORK_STEMS:
            raise ScopeFilterError(
                "--only with --dump-to supports only network:PATTERN "
                f"selectors (glob over network name or ID); got {value!r}. "
                "Example: --only 'network:Branch-07'."
            )
        parsed.append((value, glob_pattern(matched.group(2))))
    return tuple(parsed)


def describe_networks(networks: Sequence[MerakiNetwork]) -> str:
    """Capped ``name (id)`` listing for selector diagnostics."""
    return _available_networks(networks)


def _available_networks(networks: Sequence[MerakiNetwork]) -> str:
    listed = [
        f"{network.name} ({network.network_id})"
        for network in networks[:_MAX_LISTED_NETWORKS]
    ]
    remainder = len(networks) - len(listed)
    if remainder > 0:
        listed.append(f"... and {remainder} more")
    return "; ".join(listed) if listed else "(none)"


def filter_networks(
    networks: tuple[MerakiNetwork, ...], selectors: Sequence[str]
) -> tuple[MerakiNetwork, ...]:
    """Select networks by ``network:PATTERN`` globs (union, deduped).

    A selector hits when its glob matches the network's name or ID,
    case-insensitively. **Each** selector must match at least one
    network — see :class:`ScopeFilterError`. Original discovery order
    is preserved.
    """
    selected: set[str] = set()
    for raw, pattern in parse_network_selectors(selectors):
        hits = [
            network
            for network in networks
            if pattern.match(network.name) or pattern.match(network.network_id)
        ]
        if not hits:
            raise ScopeFilterError(
                f"--only selector {raw!r} matched no network in the "
                "organization. Available networks: "
                f"{_available_networks(networks)}."
            )
        selected.update(network.network_id for network in hits)
    return tuple(
        network for network in networks if network.network_id in selected
    )


def scoped_plan_targets(captured_addresses: Iterable[str]) -> tuple[str, ...]:
    """Deterministic ``-target`` set for a scoped (``--only``) plan.

    A scoped pipeline run's terraform comparison must cover exactly the
    resources the scoped discovery captured: an untargeted plan would
    read — and propose creates/updates/destroys for — every
    out-of-scope resource the accumulated kit and state carry, turning
    "scope one site" into "touch the whole kit". Targeting also makes
    the sync-mode saved plan in-scope by construction, so the guarded
    import-only apply can only ever import in-scope resources.

    An empty set refuses loudly: terraform silently degenerates an
    empty ``-target`` list into a FULL plan, which is exactly the
    out-of-scope exposure targeting exists to prevent.

    Raises :class:`ScopeFilterError` when the scoped discovery captured
    no Terraform-addressable resources (an empty target set).
    """
    targets = tuple(sorted(captured_addresses))
    if not targets:
        raise ScopeFilterError(
            "--only scoped discovery captured no Terraform-addressable "
            "resources, so the scoped plan has no targets; an untargeted "
            "plan would cover out-of-scope resources and is refused."
        )
    return targets


@dataclass(frozen=True)
class SnapshotScope:
    """The partial-export scope a snapshot declares in its header.

    ``network_ids`` is what the snapshot covers; ``selectors`` records
    the raw ``--only`` values that produced it (omitted from sanitized
    snapshots — raw selectors can carry real network names).
    """

    network_ids: tuple[str, ...]
    selectors: tuple[str, ...] = ()

    @classmethod
    def from_header(cls, value: Any) -> "SnapshotScope":
        """Parse the header's ``scope`` object, refusing malformation.

        A corrupted scope must fail loudly — silently reading it as
        "full organization" would let a partial snapshot through every
        full-org guard.

        Raises :class:`ValueError` when the ``scope`` object, its
        ``networks`` list, or its ``selectors`` list is malformed.
        """
        if not isinstance(value, dict):
            raise ValueError(
                f"snapshot 'scope' must be a JSON object, got "
                f"{type(value).__name__}"
            )
        networks = value.get("networks")
        if not isinstance(networks, list) or not all(
            isinstance(item, str) for item in networks
        ):
            raise ValueError(
                "snapshot 'scope.networks' must be a list of network IDs"
            )
        selectors = value.get("selectors", [])
        if not isinstance(selectors, list) or not all(
            isinstance(item, str) for item in selectors
        ):
            raise ValueError(
                "snapshot 'scope.selectors' must be a list of strings"
            )
        return cls(network_ids=tuple(networks), selectors=tuple(selectors))


@dataclass(frozen=True)
class LiveNetworkScope:
    """Discovery scope for the live provider — exactly one form set.

    ``selectors`` (the export path) raises :class:`ScopeFilterError`
    when a selector matches nothing; ``network_ids`` (the heal path)
    never raises — a scoped network that was deleted live is the
    maximal heal case, not an input error.
    """

    selectors: tuple[str, ...] = ()
    network_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if bool(self.selectors) == bool(self.network_ids):
            raise ValueError(
                "LiveNetworkScope requires exactly one of 'selectors' "
                "or 'network_ids'."
            )

    def apply(
        self, networks: tuple[MerakiNetwork, ...]
    ) -> tuple[MerakiNetwork, ...]:
        if self.selectors:
            return filter_networks(networks, self.selectors)
        return tuple(
            network
            for network in networks
            if network.network_id in self.network_ids
        )
