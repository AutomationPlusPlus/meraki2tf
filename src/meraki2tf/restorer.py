"""Full-organization restore planning: snapshot → ordered API writes.

The disaster-recovery question is "can this organization be rebuilt
from the snapshot?", and the honest answer must be computable **before**
the disaster. This module plans a restore entirely offline: every
snapshot asset is classified into exactly one bucket —

* ``create`` — the object gets a fresh server-assigned ID (its
  collection exposes a POST); the executor journals old → new IDs so
  later references can be rewritten;
* ``configure`` — the object occupies a stable slot or is a singleton
  (PUT; SSID numbers, VLAN IDs, per-scope settings);
* ``claim`` — devices, which are claimed into their network rather
  than created;
* unrestorable — with a spec-derived reason (dashboard-only, nothing
  captured, unreadable at capture, secrets redacted away).

Everything is derived from the OpenAPI document (write operations,
request-body schemas) per the project contract — no hard-coded entity
tables. The plan is the DR guarantee artifact: its buckets and reasons
feed the coverage manifest and notifications, replacing the
"will terraform import it?" question with "will the API accept it?" —
the question that actually matters when rebuilding.

Ordering is by dependency waves:

1. organization-scoped features (config templates and policy objects
   naturally precede the networks that reference them),
2. network creation (from the snapshot's full network payloads),
3. device claiming (into the recreated networks),
4. network-scoped features, shallow before nested (a nested surface's
   parent element must exist first),
5. device-scoped features.
"""

from __future__ import annotations

import inspect
import json
import hashlib
import logging
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.config import read_api_key
from meraki2tf.fsperms import restrict_to_owner
from meraki2tf.providers.ratelimit import AdaptiveTokenBucket
from meraki2tf.replayer import (
    ACTION_LOG_REASON,
    _collection_items,
    _secret_paths,
    _single_array_body_field,
    _strip_nulls,
    is_action_log,
    shape_rules,
    split_redacted as _split_redacted,
)
from meraki2tf.runbook import write_operations
from meraki2tf.sanitizer import SECRET_KEY_PATTERN
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)

#: Restore waves, in execution order.
WAVE_ORG_FEATURES = 1
WAVE_NETWORKS = 2
WAVE_DEVICE_CLAIM = 3
WAVE_NETWORK_FEATURES = 4
WAVE_DEVICE_FEATURES = 5


@dataclass(frozen=True)
class RestoreAction:
    """One planned write against the rebuilt organization."""

    kind: str  # "create" | "configure" | "claim"
    wave: int
    api_path: str
    path_values: tuple[str, ...]
    operation: OperationSpec = field(hash=False, compare=False)
    payload: Mapping[str, Any] = field(hash=False, default_factory=dict)
    #: Attribute names whose values were redacted in the snapshot and
    #: must be re-entered by an operator after the restore.
    secret_reentry: tuple[str, ...] = ()
    #: The GET on the create's collection, when the spec has one: the
    #: executor reads it back to adopt (by name) an object a crashed
    #: run created but never journaled, instead of duplicating it.
    lookup: OperationSpec | None = field(
        hash=False, compare=False, default=None
    )
    #: The item's PUT, when the spec has one: after adopting an
    #: already-existing counterpart (a Meraki-provisioned default), the
    #: executor aligns its content with the captured payload.
    aligner: OperationSpec | None = field(
        hash=False, compare=False, default=None
    )

    @property
    def key(self) -> str:
        """Stable identity for the resume journal."""
        return f"{self.api_path}::{','.join(self.path_values)}"


@dataclass(frozen=True)
class Unrestorable:
    """One asset the API cannot rebuild, with the operator-facing why."""

    api_path: str
    path_values: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class RestorePlan:
    """The offline answer to "what will and will not rebuild"."""

    actions: tuple[RestoreAction, ...] = ()
    unrestorable: tuple[Unrestorable, ...] = ()

    def summary(self) -> str:
        kinds: dict[str, int] = {}
        for action in self.actions:
            kinds[action.kind] = kinds.get(action.kind, 0) + 1
        parts = [f"{count} {kind}" for kind, count in sorted(kinds.items())]
        parts.append(f"{len(self.unrestorable)} unrestorable")
        return ", ".join(parts)


def plan_restore(graph: NetworkGraph, parser: OpenApiParser) -> RestorePlan:
    """Classify every snapshot asset into ordered restore actions.

    Pure — no I/O, no SDK. Safe to run on every weekly snapshot so the
    coverage manifest always carries the current restore verdict.
    """
    writes = write_operations(parser)
    lookups = {
        op.path: op for op in parser.endpoints() if op.method == "get"
    }
    actions: list[RestoreAction] = []
    unrestorable: list[Unrestorable] = []

    for network in graph.networks:
        actions.append(
            RestoreAction(
                kind="create",
                wave=WAVE_NETWORKS,
                api_path="/organizations/{organizationId}/networks",
                path_values=(network.network_id,),
                operation=_network_create_operation(parser),
                payload=dict(network.payload),
                lookup=lookups.get("/organizations/{organizationId}/networks"),
            )
        )
    for device in graph.devices:
        actions.append(
            RestoreAction(
                kind="claim",
                wave=WAVE_DEVICE_CLAIM,
                api_path="/networks/{networkId}/devices/claim",
                path_values=(device.network_id, device.serial),
                operation=_device_claim_operation(parser),
                payload=dict(device.payload),
            )
        )

    for feature in graph.features:
        classified = _classify_feature(feature, parser, writes, lookups)
        if isinstance(classified, Unrestorable):
            unrestorable.append(classified)
        else:
            actions.append(classified)

    actions.sort(key=lambda a: (a.wave, len(a.operation.path_params),
                                a.api_path, a.path_values))
    return RestorePlan(actions=tuple(actions), unrestorable=tuple(unrestorable))


def _classify_feature(
    feature: FeatureConfiguration,
    parser: OpenApiParser,
    writes: Mapping[str, tuple[OperationSpec, ...]],
    lookups: Mapping[str, OperationSpec],
) -> RestoreAction | Unrestorable:
    if UNREADABLE_MARKER in feature.payload:
        return Unrestorable(
            feature.api_path,
            feature.path_values,
            "Endpoint was unreadable at capture — nothing was recorded "
            "to restore; verify it manually after the rebuild.",
        )
    ops = writes.get(feature.api_path, ())
    if not ops:
        return Unrestorable(
            feature.api_path,
            feature.path_values,
            "No write operation in the API spec — dashboard-only; "
            "rebuild manually.",
        )
    if is_action_log(feature.api_path, ops):
        # POST-only action logs (sensor commands, PII requests, …)
        # record executed operations; re-POSTing a snapshot entry
        # would re-execute them against the rebuilt organization.
        return Unrestorable(
            feature.api_path,
            feature.path_values,
            ACTION_LOG_REASON,
        )
    if not feature.payload:
        return Unrestorable(
            feature.api_path,
            feature.path_values,
            "No payload captured in the snapshot for this asset.",
        )
    if _collection_items(feature.payload) == []:
        return Unrestorable(
            feature.api_path,
            feature.path_values,
            "Collection was empty at capture — nothing to restore.",
        )
    payload, redacted = _split_redacted(feature.payload)
    if redacted and not payload:
        return Unrestorable(
            feature.api_path,
            feature.path_values,
            "Every captured attribute is redacted (sanitized snapshot); "
            "restore needs the unsanitized snapshot.",
        )
    creates = tuple(op for op in ops if op.method == "post")
    updates = tuple(op for op in ops if op.method == "put")
    wave = _feature_wave(feature.api_path)
    if _is_server_id_item(feature, parser, creates):
        return RestoreAction(
            kind="create",
            wave=wave,
            api_path=feature.api_path,
            path_values=feature.path_values,
            operation=creates[0],
            payload=payload,
            secret_reentry=redacted,
            # The collection GET (same path as the collection POST),
            # for crash-recovery adoption by name.
            lookup=lookups.get(creates[0].path),
            aligner=updates[0] if updates else None,
        )
    placeholders = _PATH_PARAM_RE.findall(feature.api_path)
    fitting_updates = tuple(
        op for op in updates if len(op.path_params) <= len(placeholders)
    )
    if updates and not fitting_updates and creates:
        # The only update writer lives on the ITEM path but the asset
        # was captured at its collection (its element-ID key follows no
        # convention discovery knew at capture time — adaptive policy
        # elements carry `adaptivePolicyId`). Synthesize the item-path
        # create so identity, mapping, and adoption work normally.
        item_op = updates[0]
        element = _element_identity_from_payload(item_op, payload)
        if element is not None:
            return RestoreAction(
                kind="create",
                wave=wave,
                api_path=item_op.path,
                path_values=(*feature.path_values, element),
                operation=creates[0],
                payload=payload,
                secret_reentry=redacted,
                lookup=lookups.get(creates[0].path),
                aligner=item_op,
            )
    operation = (
        fitting_updates[0]
        if fitting_updates
        else (creates[0] if creates else updates[0])
    )
    return RestoreAction(
        kind="configure" if operation.method == "put" else "create",
        wave=wave,
        api_path=feature.api_path,
        path_values=feature.path_values,
        operation=operation,
        payload=payload,
        secret_reentry=redacted,
    )


def _is_server_id_item(
    feature: FeatureConfiguration,
    parser: OpenApiParser,
    creates: tuple[OperationSpec, ...],
) -> bool:
    """Server-assigned-ID objects must be POSTed and journaled.

    Spec-derived rule: an item-path asset whose collection exposes a
    POST gets fresh IDs from the API (group policies, static routes,
    admins). Item paths whose collection has **no** POST are fixed
    slots the API pre-provisions (SSID numbers, VLANs on some
    firmwares, switch ports) — they are configured with PUT and keep
    their identity, no remapping needed.
    """
    if not creates:
        return False
    # Item path = more path parameters than the collection POST itself.
    return len(feature.path_values) > len(creates[0].path_params)


def _feature_wave(api_path: str) -> int:
    if "{networkId}" in api_path:
        return WAVE_NETWORK_FEATURES
    if "{serial}" in api_path:
        return WAVE_DEVICE_FEATURES
    return WAVE_ORG_FEATURES


def _network_create_operation(parser: OpenApiParser) -> OperationSpec:
    for op in parser.endpoints():
        if op.method == "post" and op.path == (
            "/organizations/{organizationId}/networks"
        ):
            return op
    # Synthesized fallback keeps planning honest even against a spec
    # slice that omits the endpoint (unit fixtures): the executor
    # dispatches by operationId, which the real spec always carries.
    return OperationSpec(
        operation_id="createOrganizationNetwork",
        method="post",
        path="/organizations/{organizationId}/networks",
        path_params=("organizationId",),
        tags=("organizations",),
    )


def _device_claim_operation(parser: OpenApiParser) -> OperationSpec:
    for op in parser.endpoints():
        if op.method == "post" and op.path == (
            "/networks/{networkId}/devices/claim"
        ):
            return op
    return OperationSpec(
        operation_id="claimNetworkDevices",
        method="post",
        path="/networks/{networkId}/devices/claim",
        path_params=("networkId",),
        tags=("networks",),
    )


def restore_verdicts(
    plan: RestorePlan,
) -> dict[tuple[str, tuple[str, ...]], str]:
    """(api_path, identifiers) → restore verdict, for the coverage
    manifest's ``restore_via`` column."""
    verdicts: dict[tuple[str, tuple[str, ...]], str] = {}
    for action in plan.actions:
        verdicts[(action.api_path, action.path_values)] = action.kind
    for item in plan.unrestorable:
        verdicts[(item.api_path, item.path_values)] = (
            f"unrestorable: {item.reason}"
        )
    return verdicts


def render_restore_plan(plan: RestorePlan, limit: int = 30) -> str:
    """Operator-facing digest: identifiers and reasons, never values."""
    lines = [plan.summary()]
    for action in plan.actions[:limit]:
        marker = f" [secrets to re-enter: {', '.join(action.secret_reentry)}]" \
            if action.secret_reentry else ""
        lines.append(
            f"{action.kind:9s} wave {action.wave}  {action.api_path} "
            f"({','.join(action.path_values)}){marker}"
        )
    if len(plan.actions) > limit:
        lines.append(f"... and {len(plan.actions) - limit} more action(s)")
    for item in plan.unrestorable[:limit]:
        lines.append(
            f"UNRESTORABLE {item.api_path} "
            f"({','.join(item.path_values)}): {item.reason}"
        )
    if len(plan.unrestorable) > limit:
        lines.append(
            f"... and {len(plan.unrestorable) - limit} more unrestorable"
        )
    return "\n".join(lines)


class UnmappedReferenceError(RuntimeError):
    """A payload references a snapshot-tenant ID with no rebuilt
    counterpart — writing it would point the new org at a dead object,
    so the action fails loudly instead of guessing."""


class ForeignScopeError(RuntimeError):
    """A path parameter addresses a tenant location outside the
    snapshot — dispatching it would write into a live organization or
    onto live hardware the restore does not own, so the action is
    refused outright (never deferred, never passed through)."""


#: Policy-object grammar embedded in firewall rule strings, and the
#: reference-key stems its two verbs resolve through.
#: Sanitized snapshots carry pseudonymized IDs inside the grammar
#: (``OBJ(id-0012)``), so the ID part must admit more than digits — a
#: digits-only pattern silently skips the rewrite and dead pseudonyms
#: reach the dashboard ("Source address must be an IP address …").
_OBJ_GRP_RE = re.compile(r"\b(GRP|OBJ)\(([\w-]+)\)")
_GRAMMAR_KEYS = {"GRP": "policyObjectGroupId", "OBJ": "policyObjectId"}

#: Payload keys whose values are cross-references to other objects.
#: Bare ``id``/``ids`` count too (mirroring the sanitizer's rule): a
#: nested sub-object reference (staged stages' ``group.id``) carries
#: exactly that key, and skipping it dispatches dead snapshot IDs. An
#: object's own root-level ``id`` echo stays safe — creates exclude it
#: and configures resolve it through the already-recorded mapping.
_REFERENCE_KEY_RE = re.compile(r"^ids?$|Ids?$")

_PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


def _scope_stem(name: str) -> str:
    """Normalize a path-parameter or reference-key name to a type stem.

    ``groupPolicyId``/``groupPolicyIds`` → ``grouppolicy``; bare
    ``id``/``ids`` → ``""`` (generic — resolvable only when globally
    unambiguous).
    """
    lowered = name.lower()
    for suffix in ("ids", "id"):
        if lowered.endswith(suffix):
            lowered = lowered[: -len(suffix)]
            break
    return lowered


class ReferenceResolver:
    """Old→new identifier resolution scoped by type and parent context.

    Meraki IDs are only unique per object type and per parent —
    group-policy IDs restart at 100 in every network and VLAN 100 is
    ubiquitous — so a flat old→new map mis-remaps colliding IDs.
    Mappings are recorded under a *type stem* (the created object's own
    path-parameter name) plus its old-space parent path values, and
    lookups resolve in order:

    1. **scoped**: entries under the reference key's stem whose context
       is contained in the referring action's own path values;
    2. **flat-unique**: when the snapshot holds no object of that stem
       with this ID (e.g. ``hubIds`` values are network IDs), a single
       matching mapping of any scope wins;
    3. otherwise **loud failure** — a known-but-unmapped ID has no
       rebuilt counterpart *yet* (the executor defers and retries), and
       an ambiguous ID is never guessed.
    """

    def __init__(self, graph: NetworkGraph) -> None:
        #: (stem, old) → [(context, new), ...]
        self._entries: dict[
            tuple[str, str], list[tuple[frozenset[str], str]]
        ] = {}
        #: old → [(context, new), ...] across every stem, for fallback.
        self._by_old: dict[str, list[tuple[frozenset[str], str]]] = {}
        #: Identities the snapshot's own objects carry, per stem and flat.
        self._known_scoped: set[tuple[str, str]] = set()
        self._known_flat: set[str] = set()
        #: Identities the executor will remap (created objects get
        #: fresh server-assigned IDs). A scope lookup that cannot
        #: resolve one of these must fail loudly instead of passing the
        #: snapshot ID through — dispatching at a source-tenant ID
        #: would address the wrong (possibly production) object.
        self._pending_scoped: set[tuple[str, str]] = set()
        self._pending_flat: set[str] = set()
        self._register_known("organization", graph.organization_id)
        for network in graph.networks:
            self._register_known("network", network.network_id)
        for device in graph.devices:
            self._register_known("serial", device.serial)
        for feature in graph.features:
            placeholders = _PATH_PARAM_RE.findall(feature.api_path)
            if (
                placeholders
                and feature.path_values
                and feature.api_path.endswith("}")
            ):
                # Only an item path's own identity (its last path value)
                # is registered under a stem; a singleton's last value
                # is its *parent scope* (a template swept as networkId),
                # and parent values are known through the parent objects
                # themselves.
                self._register_known(
                    _scope_stem(placeholders[-1]), feature.path_values[-1]
                )
            self._known_flat.update(v for v in feature.path_values if v)

    def _register_known(self, stem: str, value: str) -> None:
        if not value:
            return
        self._known_flat.add(value)
        if stem:
            self._known_scoped.add((stem, value))

    def record(
        self, stem: str, old: str, new: str, context: tuple[str, ...] = ()
    ) -> None:
        entry = (frozenset(context), new)
        self._entries.setdefault((stem, old), []).append(entry)
        self._by_old.setdefault(old, []).append(entry)

    def forget(self, stem: str, old: str, new: str) -> None:
        """Drop every mapping of ``(stem, old)`` onto ``new``.

        Adoption of a freshly provisioned default records a provisional
        mapping onto the dashboard's ``-1`` sentinel alias so the
        content-alignment PUT can address the item; once the real
        identifier is known, the sentinel entry must go — two surviving
        entries make every reference to the object ambiguous, and the
        resolver (correctly) refuses to guess.
        """
        for entries in (
            self._entries.get((stem, old)), self._by_old.get(old),
        ):
            if entries is not None:
                entries[:] = [
                    entry for entry in entries if entry[1] != new
                ]

    def has_mapping(self, stem: str, old: str) -> bool:
        """Is any mapping recorded for ``(stem, old)``?"""
        return bool(self._entries.get((stem, old)))

    def sibling_mapping(self, stem: str, old: str) -> str | None:
        """The single new ID recorded for ``(stem, old)`` anywhere.

        Org-shared objects (Meraki's built-in payload templates) are
        discovered once per network under the *same* old ID; once one
        network's copy is created or adopted, every sibling copy is the
        same target object. Anything other than exactly one distinct
        new ID returns ``None`` — colliding per-network IDs (group
        policy "100") map to different new IDs and never qualify.
        """
        new_ids = {new for _, new in self._entries.get((stem, old), [])}
        return next(iter(new_ids)) if len(new_ids) == 1 else None

    def expect_remap(self, stem: str, old: str) -> None:
        """Declare an identity that only exists after its create runs.

        Registered for every planned create so :meth:`resolve_scope`
        can tell a fixed slot that keeps its identity from a created
        object whose old ID must never reach the API."""
        if not old:
            return
        self._pending_flat.add(old)
        if stem:
            self._pending_scoped.add((stem, old))

    def resolve_reference(
        self,
        key: str,
        old: str,
        context: tuple[str, ...],
        exclude: str | None = None,
    ) -> str:
        """Strict resolution for payload references (fails loudly).

        ``exclude`` is the referring object's own old identity on a
        create: a self-referential field is identity, not a dangling
        reference, so it passes through when nothing scoped matches.
        """
        referrer = frozenset(context)
        stem = _scope_stem(key)
        if stem:
            scoped = self._entries.get((stem, old), [])
            matches = {new for ctx, new in scoped if ctx <= referrer}
            if len(matches) == 1:
                return next(iter(matches))
            if len(matches) > 1:
                raise UnmappedReferenceError(
                    f"reference {key}={old!r} is ambiguous across "
                    "rebuilt objects; refusing to guess"
                )
            if old == exclude:
                return old
            if scoped or (stem, old) in self._known_scoped:
                # An object of this type with this ID exists in the
                # snapshot (or was rebuilt under another parent) — its
                # in-context counterpart just does not exist yet.
                raise UnmappedReferenceError(
                    f"reference to snapshot object {old!r} has no "
                    "rebuilt counterpart yet"
                )
        if old == exclude:
            return old
        candidates = {
            new
            for ctx, new in self._by_old.get(old, [])
            if ctx <= referrer
        }
        if len(candidates) == 1:
            return next(iter(candidates))
        if len(candidates) > 1:
            raise UnmappedReferenceError(
                f"reference {old!r} is ambiguous across rebuilt objects; "
                "refusing to guess"
            )
        if old in self._known_flat:
            raise UnmappedReferenceError(
                f"reference to snapshot object {old!r} has no rebuilt "
                "counterpart yet"
            )
        return old

    def resolve_scope(
        self, key: str, old: str, context: tuple[str, ...]
    ) -> str:
        """Lenient resolution for path parameters.

        A parameter with no mapping normally addresses a fixed-slot
        object that kept its identity (SSID numbers, per-scope
        singletons) and passes through. Two exceptions fail loudly
        instead of passing the snapshot ID through — dispatching at a
        source-tenant ID would address the wrong (possibly production)
        object:

        * a value declared via :meth:`expect_remap` (a created object —
          including a config template addressed through a
          ``{networkId}`` scope) whose rebuilt counterpart does not
          exist yet: the caller defers or fails;
        * an ``{organizationId}``/``{networkId}`` scope with no
          mapping at all. Those stems are tenant locations, never fixed
          slots — every legitimate value is either the snapshot's own
          org (mapped to the target up front) or an object this restore
          creates — so an unmapped one can only point *outside* the
          rebuilt organization (a crafted or inconsistent snapshot).
        """
        referrer = frozenset(context)
        stem = _scope_stem(key)
        if stem:
            matches = {
                new
                for ctx, new in self._entries.get((stem, old), [])
                if ctx <= referrer
            }
            if len(matches) == 1:
                return next(iter(matches))
        candidates = {
            new
            for ctx, new in self._by_old.get(old, [])
            if ctx <= referrer
        }
        if len(candidates) == 1:
            return next(iter(candidates))
        if (stem, old) in self._pending_scoped or (
            old in self._pending_flat
            # A genuine identity of the addressed type that is not
            # being remapped (a fixed slot) may collide with another
            # type's created ID — the slot keeps its value.
            and (stem, old) not in self._known_scoped
        ):
            raise UnmappedReferenceError(
                f"scope {key}={old!r} addresses a created object with "
                "no rebuilt counterpart yet"
            )
        if stem in ("organization", "network"):
            raise ForeignScopeError(
                f"scope {key}={old!r} does not correspond to any object "
                "recorded in the snapshot; refusing to dispatch a write "
                "outside the rebuilt organization"
            )
        return old


def rewrite_references(
    value: Any,
    resolver: ReferenceResolver,
    context: tuple[str, ...],
    exclude: str | None = None,
    dropped: list[str] | None = None,
) -> Any:
    """Rewrite snapshot-tenant identifiers to their rebuilt counterparts.

    Reference-shaped keys (``*Id``/``*Ids``) and the ``GRP()``/``OBJ()``
    grammar inside rule strings are remapped through the resolver. A
    reference to a *known* old identifier with no rebuilt counterpart
    raises :class:`UnmappedReferenceError`; unknown strings pass
    through untouched (they are data, not references).

    With ``dropped`` (a collector list), unresolvable *list-valued*
    reference fields are omitted instead of raising, and their key
    names are appended — the executor's deadlock breaker for mutually-
    referencing pairs (a policy object's ``groupIds`` vs the group's
    ``objectIds``: one side must yield so the other can create and
    record its mapping; the surviving side re-establishes the link).
    Scalar references (``configTemplateId``, ``groupPolicyId``) are
    structural dependencies, not memberships — dropping one restores a
    silently-miswired object, so they raise even then, as do
    rule-grammar strings (dropping a whole firewall rule, or passing
    the source tenant's ID through, are both worse than failing the
    object loudly).
    """
    if isinstance(value, Mapping):
        out: dict[Any, Any] = {}
        for key, inner in value.items():
            if isinstance(key, str) and _REFERENCE_KEY_RE.search(key):
                try:
                    out[key] = _rewrite_reference_value(
                        key, inner, resolver, context, exclude
                    )
                except UnmappedReferenceError:
                    if dropped is None or not isinstance(inner, list):
                        raise
                    dropped.append(key)
            else:
                out[key] = rewrite_references(
                    inner, resolver, context, exclude, dropped
                )
        return out
    if isinstance(value, list):
        return [
            rewrite_references(item, resolver, context, exclude, dropped)
            for item in value
        ]
    if isinstance(value, str):
        return _rewrite_grammar(value, resolver, context, exclude)
    return value


def _rewrite_reference_value(
    key: str,
    value: Any,
    resolver: ReferenceResolver,
    context: tuple[str, ...],
    exclude: str | None,
) -> Any:
    if isinstance(value, str):
        return resolver.resolve_reference(key, value, context, exclude)
    if isinstance(value, list):
        return [
            _rewrite_reference_value(key, item, resolver, context, exclude)
            for item in value
        ]
    return value


def _rewrite_grammar(
    value: str,
    resolver: ReferenceResolver,
    context: tuple[str, ...],
    exclude: str | None,
) -> str:
    def _sub(match: "re.Match[str]") -> str:
        verb, old = match.group(1), match.group(2)
        new = resolver.resolve_reference(
            _GRAMMAR_KEYS[verb], old, context, exclude
        )
        return f"{verb}({new})"

    return _OBJ_GRP_RE.sub(_sub, value)


def _references_serials(
    action: RestoreAction, serials: frozenset[str]
) -> bool:
    """Does the action's address or payload reference any of ``serials``?"""
    if not serials:
        return False
    if any(value in serials for value in action.path_values):
        return True

    def scan(value: Any) -> bool:
        if isinstance(value, Mapping):
            return any(scan(inner) for inner in value.values())
        if isinstance(value, list):
            return any(scan(item) for item in value)
        return isinstance(value, str) and value in serials

    return scan(action.payload)


def _body_property_names(op: OperationSpec) -> frozenset[str]:
    """Property names the operation's JSON request body declares."""
    node: Any = op.raw.get("requestBody") if op.raw else None
    for key in ("content", "application/json", "schema", "properties"):
        node = node.get(key) if isinstance(node, Mapping) else None
    if isinstance(node, Mapping):
        return frozenset(str(name) for name in node)
    return frozenset()


def _remap_serial_fields(
    value: Any, serial_map: Mapping[str, str]
) -> Any:
    """Rewrite ``serial``/``serials`` fields through the hardware map.

    ``--serial-map`` exists for hardware-loss recovery: payloads that
    embed dead serials (switch stacks, per-port references) must point
    at the replacement hardware, not just the device-claim calls —
    serial keys don't match the ``*Id`` reference grammar, so the ID
    rewriter never sees them.
    """
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, inner in value.items():
            if key == "serial" and isinstance(inner, str):
                out[key] = serial_map.get(inner, inner)
            elif key == "serials" and isinstance(inner, list):
                out[key] = [
                    serial_map.get(item, item)
                    if isinstance(item, str)
                    else item
                    for item in inner
                ]
            else:
                out[key] = _remap_serial_fields(inner, serial_map)
        return out
    if isinstance(value, list):
        return [_remap_serial_fields(item, serial_map) for item in value]
    return value


#: Body property names that bind a write to specific hardware.
_SERIAL_PROPERTY = re.compile(r"(?i)serial")

#: Dashboard 400 texts meaning "an object with this name/slot already
#: exists" — Meraki provisions defaults (payload templates, RF
#: profiles, staged upgrade groups, VLAN 1) into new networks, so a
#: snapshot's captured copy collides with the built-in on restore.
_NAME_CONFLICT_RE = re.compile(
    r"(?i)already (?:exists|been taken|opted in)|reserved name"
    r"|with this name (?:exists|already)"
)
#: Dashboard 400 texts meaning "the organization lacks the hardware
#: class this feature needs" — inevitable on device-free drill orgs.
_CAPABILITY_RE = re.compile(
    r"(?i)only supports organizations with .+ networks"
    r"|is not supported for this network"
    r"|consider upgrading your devices"
)

#: Dashboard 400 texts meaning "this setting is governed by the
#: network's config template" — a bound network refuses the write for
#: everyone, drill or not; the template's own copy restores separately.
_TEMPLATE_BOUND_RE = re.compile(r"(?i)on a template network")


class _EmptyConfigureSkip(Exception):
    """A configure payload stripped to nothing — nothing to write."""


#: Payload keys that identify an object as the Meraki-provisioned
#: default of its collection (staged upgrade groups carry `isDefault`,
#: adaptive-policy groups `isDefaultGroup`).
_DEFAULT_FLAG_RE = re.compile(r"(?i)^isdefault")

#: Natural identity keys tried, in order, when adopt-by-name finds no
#: counterpart. Each is unique within its collection per the dashboard
#: ("SGT has already been taken"); `shortName` is an API keyword the
#: sanitizer preserves verbatim, so both work from sanitized snapshots.
_NATURAL_MATCH_KEYS = ("name", "sgt", "shortName")


def _element_identity_from_payload(
    item_op: OperationSpec, payload: Mapping[str, Any]
) -> str | None:
    """The element's own ID read from its payload, by convention.

    Tried in order: the item path's own placeholder, the collection's
    ``<singular>Id``, the family segment's ``<parent>Id`` (adaptive
    policy elements carry ``adaptivePolicyId``), then a generic ``id``.
    """
    candidates: list[str] = []
    if item_op.path_params:
        candidates.append(item_op.path_params[-1])
    derived = _derived_collection_id_key(item_op.path)
    if derived:
        candidates.append(derived)
    segments = [s for s in item_op.path.split("/") if s]
    if len(segments) >= 3 and not segments[-3].startswith("{"):
        candidates.append(f"{segments[-3]}Id")
    candidates.append("id")
    for key in candidates:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _default_flag_key(payload: Mapping[str, Any]) -> str | None:
    """The truthy ``isDefault``-shaped key of the payload, if any."""
    for key, value in payload.items():
        if _DEFAULT_FLAG_RE.match(key) and value is True:
            return key
    return None


def _match_collection_item(
    listing: list[Any], payload: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    """The single listing item sharing a natural key with ``payload``."""
    for key in _NATURAL_MATCH_KEYS:
        wanted = payload.get(key)
        if wanted is None or isinstance(wanted, (Mapping, list)):
            continue
        matches = [
            item
            for item in listing
            if isinstance(item, Mapping) and item.get(key) == wanted
        ]
        if len(matches) == 1:
            return matches[0]
    return None


def _derived_collection_id_key(api_path: str) -> str | None:
    """Conventional ``<singular>Id`` named after the collection segment.

    Some collections key their elements this way while the item path's
    own placeholder is a generic ``{id}`` — adaptive policy
    ``groups/{id}`` elements (and create responses) carry ``groupId``.
    """
    segments = [s for s in api_path.split("/") if s]
    if len(segments) < 2 or not segments[-1].startswith("{"):
        return None
    collection = segments[-2]
    if collection.startswith("{"):
        return None
    singular = (
        collection[:-3] + "y"
        if collection.endswith("ies")
        else collection.removesuffix("s")
    )
    return f"{singular}Id"


def _item_identifier(
    action: RestoreAction, item: Mapping[str, Any]
) -> str | None:
    """One collection element's ID under the action's own convention.

    Collections key their items differently: a generic ``id``, the item
    path's own placeholder (``groupPolicyId``), or the conventional
    ``<singular>Id`` named after the collection segment — adaptive
    policy ``groups/{id}`` elements carry ``groupId``, not ``id``.
    """
    found = item.get("id")
    if found is None:
        placeholders = _PATH_PARAM_RE.findall(action.api_path)
        if placeholders:
            found = item.get(placeholders[-1])
    if found is None:
        derived = _derived_collection_id_key(action.api_path)
        if derived:
            found = item.get(derived)
    return str(found) if found is not None else None


def _effectively_empty(value: Any) -> bool:
    """Is a write body nothing but null leaves and empty containers?

    A GET echo can strip to this after null pruning (a config
    template's cellular uplink reads back ``{"bandwidthLimits":
    {"limitUp": null, "limitDown": null}}``), and the dashboard rejects
    the resulting PUT with "None of the fields were specified" — there
    is simply nothing to restore.
    """
    if isinstance(value, Mapping):
        return all(_effectively_empty(inner) for inner in value.values())
    if isinstance(value, list):
        return all(_effectively_empty(inner) for inner in value)
    return value is None


def _body_serial_properties(op: OperationSpec) -> frozenset[str]:
    """Serial-bearing property names the write schema declares.

    A configure operation whose schema takes serials (warm spare's
    ``spareSerial``, …) sets device placement: on a hardware-free drill
    org the dashboard rejects it whatever the payload says, so these
    are drill-skipped verdicts, never failures.
    """
    return frozenset(
        name
        for name in _body_property_names(op)
        if _SERIAL_PROPERTY.search(name)
    )


def _schema_type_at(
    op: OperationSpec | None, parts: Sequence[str]
) -> str | None:
    """The JSON-schema ``type`` of a dotted body path, if declared.

    A ``name[]`` segment descends through the array property's
    ``items`` schema (``radiusServers[].port`` → integer).
    """
    node: Any = op.raw.get("requestBody") if op is not None and op.raw else None
    for key in ("content", "application/json", "schema"):
        node = node.get(key) if isinstance(node, Mapping) else None
    for part in parts:
        is_list = part.endswith("[]")
        name = part[:-2] if is_list else part
        props = node.get("properties") if isinstance(node, Mapping) else None
        node = props.get(name) if isinstance(props, Mapping) else None
        if is_list and isinstance(node, Mapping):
            node = node.get("items")
    return node.get("type") if isinstance(node, Mapping) else None


def _inject_drill_secrets(
    payload: Mapping[str, Any],
    paths: tuple[str, ...],
    seed: str,
    op: OperationSpec | None = None,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Fill redacted secret slots with deterministic drill placeholders.

    A sanitized snapshot strips secret values, but some writes are
    invalid without one (a WPA SSID needs a psk, a RADIUS server needs
    a secret) — a drill would fail exactly the objects it is supposed
    to rehearse. The placeholder shape satisfies the strictest
    validators seen live (8+ chars, letters/digits/hyphens only) and is
    derived from the action key + path (+ element index inside lists),
    so resumed drills stay idempotent. Returns the filled payload and
    the paths actually filled.
    """
    filled = _json_copy(dict(payload))
    injected: list[str] = []
    for path in paths:
        parts = path.split(".")
        if _fill_secret_slots(filled, parts, seed, path, op, ""):
            injected.append(path)
    return filled, tuple(injected)


def _json_copy(value: Any) -> Any:
    """Deep copy of a plain-JSON payload tree."""
    if isinstance(value, Mapping):
        return {key: _json_copy(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [_json_copy(inner) for inner in value]
    return value


def _drill_placeholder(
    op: OperationSpec | None, parts: Sequence[str], digest: str
) -> Any:
    if _schema_type_at(op, parts) in ("integer", "number"):
        # A numeric secret slot (a PIN, a passcode) rejects string
        # placeholders outright; a deterministic 8-digit number
        # satisfies the widest live validators.
        return int(digest[:6], 16) % 90000000 + 10000000
    return f"drill-{digest}"


def _fill_secret_slots(
    node: Any,
    parts: Sequence[str],
    seed: str,
    path: str,
    op: OperationSpec | None,
    index: str,
) -> bool:
    """Fill every slot addressed by ``parts`` under ``node``.

    ``name[]`` segments fan out over list elements (a RADIUS SSID
    carries ``radiusServers[].secret`` — one redacted secret per
    server), with the element index folded into the digest so each
    element gets a distinct, deterministic placeholder.
    """
    if not isinstance(node, dict) or not parts:
        return False
    head, rest = parts[0], parts[1:]
    is_list = head.endswith("[]")
    key = head[:-2] if is_list else head
    if is_list:
        # List and container hops need the structure present; a LEAF
        # slot is assigned unconditionally — the sanitizer STRIPS
        # secret slots rather than nulling them, so the key is absent.
        elements = node.get(key)
        if not isinstance(elements, list):
            return False
        hit = False
        for i, element in enumerate(elements):
            if rest:
                if _fill_secret_slots(
                    element, rest, seed, path, op, f"{index}[{i}]"
                ):
                    hit = True
            else:
                digest = hashlib.sha256(
                    f"{seed}:{path}{index}[{i}]".encode()
                ).hexdigest()[:12]
                # Type lookup needs the FULL dotted path (this frame's
                # ``parts`` is truncated by the recursion).
                elements[i] = _drill_placeholder(
                    op, path.split("."), digest
                )
                hit = True
        return hit
    if rest:
        return _fill_secret_slots(
            node.get(key), rest, seed, path, op, index
        )
    digest = hashlib.sha256(
        f"{seed}:{path}{index}".encode()
    ).hexdigest()[:12]
    # Type lookup needs the FULL dotted path (this frame's ``parts``
    # is truncated by the recursion).
    node[key] = _drill_placeholder(op, path.split("."), digest)
    return True


def _inject_absent_list_secrets(
    payload: Mapping[str, Any],
    seed: str,
    op: OperationSpec | None,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Fill schema-declared secret slots Meraki never returned.

    Write-only secrets (a RADIUS server's ``secret``) are absent from
    GET echoes entirely — redaction never saw them, so
    ``secret_reentry`` is empty and the PUT fails ("Secret can't be
    blank"). For every list of objects PRESENT in the payload whose
    item schema declares secret-shaped properties, absent slots get
    deterministic drill placeholders. Only list elements qualify: a
    present element is in use and needs its secret, while a top-level
    absent secret (an open SSID's ``psk``) may be genuinely
    inapplicable and must stay absent.
    """
    schema: Any = op.raw.get("requestBody") if op is not None and op.raw else None
    for key in ("content", "application/json", "schema"):
        schema = schema.get(key) if isinstance(schema, Mapping) else None
    if not isinstance(schema, Mapping):
        return dict(payload), ()
    filled = _json_copy(dict(payload))
    injected: set[str] = set()
    _fill_absent_schema_secrets(filled, schema, seed, "", injected)
    return filled, tuple(sorted(injected))


def _fill_absent_schema_secrets(
    node: Any,
    schema: Mapping[str, Any],
    seed: str,
    base: str,
    injected: set[str],
) -> None:
    props = schema.get("properties")
    if not isinstance(node, dict) or not isinstance(props, Mapping):
        return
    for key, value in node.items():
        sub = props.get(key)
        if not isinstance(sub, Mapping):
            continue
        path = f"{base}.{key}" if base else key
        if isinstance(value, dict):
            _fill_absent_schema_secrets(value, sub, seed, path, injected)
            continue
        if not isinstance(value, list):
            continue
        items = sub.get("items")
        if not isinstance(items, Mapping):
            continue
        item_props = items.get("properties")
        if not isinstance(item_props, Mapping):
            continue
        secret_props = [
            (name, prop)
            for name, prop in item_props.items()
            if isinstance(prop, Mapping) and SECRET_KEY_PATTERN.search(name)
        ]
        for i, element in enumerate(value):
            if not isinstance(element, dict):
                continue
            for name, prop in secret_props:
                if name in element:
                    continue
                digest = hashlib.sha256(
                    f"{seed}:{path}[].{name}[{i}]".encode()
                ).hexdigest()[:12]
                if prop.get("type") in ("integer", "number"):
                    element[name] = (
                        int(digest[:6], 16) % 90000000 + 10000000
                    )
                else:
                    element[name] = f"drill-{digest}"
                injected.add(f"{path}[].{name}")
            _fill_absent_schema_secrets(
                element, items, seed, f"{path}[]", injected
            )


def _own_identity(action: RestoreAction) -> tuple[str, str]:
    """(type stem, old ID) of the object an action creates or claims."""
    if action.wave == WAVE_NETWORKS:
        return ("network", action.path_values[0])
    if action.kind == "claim":
        return ("serial", action.path_values[-1])
    placeholders = _PATH_PARAM_RE.findall(action.api_path)
    stem = _scope_stem(placeholders[-1]) if placeholders else ""
    return (stem, action.path_values[-1])


class RestoreJournalMismatchError(RuntimeError):
    """The journal belongs to a different restore (target or source)."""


class RestoreJournal:
    """Crash-resumable restore progress: the terraform-state stand-in.

    One JSONL line per event, appended and flushed after every
    successful write, owner-only on disk: a ``meta`` line binds the
    journal to its target/source organizations, ``done`` lines carry
    completed action keys, ``map`` lines carry old → new identifier
    pairs. Re-running a restore with the same journal skips completed
    actions and reuses the mappings, so an interrupted restore resumes
    instead of duplicating thousands of creates.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self.completed: set[str] = set()
        #: Creates whose API call was about to fire (write-ahead): an
        #: attempted-but-not-completed key on resume means the process
        #: died in the create/journal window and the object may exist.
        self.attempted: set[str] = set()
        self.id_map: dict[str, str] = {}
        #: (scope stem, old, new, context) per mapping — the resolver's
        #: raw material. Legacy records load with scope "" / context ()
        #: and resolve through the flat-unique fallback.
        self.mappings: list[tuple[str, str, str, tuple[str, ...]]] = []
        self.meta: dict[str, str] = {}
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    if index == len(lines) - 1:
                        # Torn final line: the process died mid-append.
                        # Its event replays on resume (worst case one
                        # duplicate-create failure); refusing to load
                        # would strand the whole restore. The fragment
                        # is truncated away — the next _append would
                        # otherwise concatenate onto it, turning a
                        # tolerated tear into unparseable mid-file
                        # corruption that strands the run after this.
                        logger.warning(
                            "Restore journal %s ends in a torn line; "
                            "removing it and resuming.", path,
                        )
                        # Records are ASCII JSON, one per "\n"-joined
                        # line, so the fragment's byte offset is the
                        # encoded length of the intact prefix.
                        os.truncate(
                            path,
                            len(
                                "".join(
                                    f"{kept}\n" for kept in lines[:index]
                                ).encode("utf-8")
                            ),
                        )
                        continue
                    raise
                if record.get("kind") == "done":
                    self.completed.add(str(record["key"]))
                elif record.get("kind") == "attempt":
                    self.attempted.add(str(record["key"]))
                elif record.get("kind") == "map":
                    old, new = str(record["old"]), str(record["new"])
                    self.id_map[old] = new
                    self.mappings.append(
                        (
                            str(record.get("scope", "")),
                            old,
                            new,
                            tuple(
                                str(v)
                                for v in record.get("context") or ()
                            ),
                        )
                    )
                elif record.get("kind") == "meta":
                    self.meta = {
                        str(key): str(value)
                        for key, value in record.items()
                        if key != "kind"
                    }
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(mode=0o600)
        restrict_to_owner(path)

    def bind(self, target: str, source: str) -> None:
        """Bind the journal to exactly one target org and snapshot source.

        A journal resumes the restore it started: replaying completed-
        action skips and ID mappings against a *different* target would
        skip every create and then write the configure actions into the
        previous target's networks.
        """
        claim = {"target": target, "source": source}
        if self.meta:
            if self.meta != claim:
                raise RestoreJournalMismatchError(
                    f"Restore journal {self._path} belongs to a restore "
                    f"of org {self.meta.get('source')!r} into "
                    f"{self.meta.get('target')!r}; refusing to reuse it "
                    f"for a restore of {source!r} into {target!r}. Use a "
                    "fresh --workdir (or remove the journal) to start a "
                    "new restore."
                )
            return
        if self.completed or self.attempted or self.mappings:
            # Records without a meta line: a journal from a version
            # that predates target/source binding. Adopting it would
            # replay another restore's skips and ID mappings against
            # this target — the exact mis-direction bind() exists to
            # prevent — so it is refused, never claimed.
            raise RestoreJournalMismatchError(
                f"Restore journal {self._path} carries restore records "
                "but no target/source binding, so which restore it "
                "belongs to cannot be verified. Use a fresh --workdir "
                "(or remove the journal) to start a new restore."
            )
        self.meta = dict(claim)
        self._append({"kind": "meta", **claim})

    def _append(self, record: Mapping[str, Any]) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(record)) + "\n")

    def record_attempt(self, key: str) -> None:
        if key in self.attempted:
            return
        self.attempted.add(key)
        self._append({"kind": "attempt", "key": key})

    def record_done(self, key: str) -> None:
        self.completed.add(key)
        self._append({"kind": "done", "key": key})

    def record_mapping(
        self,
        old: str,
        new: str,
        scope: str = "",
        context: tuple[str, ...] = (),
    ) -> None:
        self.id_map[old] = new
        self.mappings.append((scope, old, new, tuple(context)))
        self._append(
            {
                "kind": "map",
                "old": old,
                "new": new,
                "scope": scope,
                "context": list(context),
            }
        )


@dataclass(frozen=True)
class RestoreResult:
    """Outcome of one restore execution pass."""

    executed: tuple[str, ...] = ()
    failed: tuple[tuple[str, str], ...] = ()
    skipped: tuple[dict[str, str], ...] = ()
    #: action key → comma-joined secret paths that received drill
    #: placeholders (sanitized-snapshot drills only). Real secrets must
    #: be re-entered per the runbook if the org is ever kept.
    drill_placeholders: tuple[tuple[str, str], ...] = ()


class OrgRestorer:
    """Executes a restore plan against a *target* organization.

    Writes are paced by the shared AIMD bucket, isolated per object,
    and journaled for resume. Children of a parent whose creation
    failed are skipped with a reason instead of firing at a dead
    target. The caller (CLI) guarantees the target is never the
    snapshot's source organization.
    """

    def __init__(
        self,
        target_organization_id: str,
        journal: RestoreJournal,
        serial_map: Mapping[str, str] | None = None,
        bucket: AdaptiveTokenBucket | None = None,
        skip_claims: bool = False,
        preset_mappings: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (),
    ) -> None:
        self._target = target_organization_id
        self._journal = journal
        self._serial_map = dict(serial_map or {})
        self._bucket = bucket or AdaptiveTokenBucket()
        #: Drill mode: hardware is claimed by another (the production)
        #: organization, so device claiming and device-scoped features
        #: are structurally untestable — skipped with explicit drill
        #: verdicts, never reported as failures.
        self._skip_claims = skip_claims
        #: Pre-resolved (stem, old, new, context) rows recorded before
        #: execution — heal seeds identity mappings for objects that
        #: survived the incident so references to them resolve in place.
        self._preset_mappings = preset_mappings
        self._client: Any = None

    def _dashboard(self) -> Any:
        if self._client is None:
            import meraki

            self._client = meraki.DashboardAPI(
                api_key=read_api_key(),
                suppress_logging=True,
                print_console=False,
                output_log=False,
            )
        return self._client

    def execute(
        self, graph: NetworkGraph, plan: RestorePlan
    ) -> RestoreResult:
        dashboard = self._dashboard()
        self._journal.bind(
            target=self._target, source=graph.organization_id
        )
        #: Serials a drill cannot touch: production hardware without a
        #: replacement mapping. Payloads referencing them (switch
        #: stacks, …) are drill-skipped, not failed.
        drill_serials = frozenset(
            device.serial for device in graph.devices
        ) - frozenset(self._serial_map)
        resolver = ReferenceResolver(graph)
        for scope, old, new, mapping_context in self._preset_mappings:
            resolver.record(scope, old, new, mapping_context)
        for scope, old, new, mapping_context in self._journal.mappings:
            resolver.record(scope, old, new, mapping_context)
        resolver.record("organization", graph.organization_id, self._target)
        for old_serial, new_serial in self._serial_map.items():
            resolver.record("serial", old_serial, new_serial)
        for action in plan.actions:
            if action.kind == "create":
                resolver.expect_remap(*_own_identity(action))
        executed: list[str] = []
        failed: list[tuple[str, str]] = []
        skipped: list[dict[str, str]] = []
        drill_placeholders: list[tuple[str, str]] = []
        #: (type stem, old value) of creates/claims that failed this run.
        failed_parents: set[tuple[str, str]] = set()
        #: (type stem, old value) of drill-skipped parents: their
        #: children must be drill verdicts too, never writes fired at
        #: the old parent ID and reported as failures.
        skipped_parents: set[tuple[str, str]] = set()
        #: Old serials whose claim has not succeeded yet this run.
        #: ``/devices/{serial}/…`` endpoints address hardware wherever
        #: it is currently claimed — possibly the production org — so
        #: serial-scoped writes wait for their claim to land first.
        unclaimed = {
            action.path_values[-1]
            for action in plan.actions
            if action.kind == "claim"
            and action.key not in self._journal.completed
        }
        #: Serials the restore legitimately owns: hardware the snapshot
        #: records (claimed into the target by the claim wave) or an
        #: explicit --serial-map replacement. Any other serial in a
        #: scope addresses live hardware wherever it is currently
        #: claimed — possibly production — and is refused outright.
        known_serials = frozenset(
            device.serial for device in graph.devices
        ) | frozenset(self._serial_map)

        # Alphabetical wave order can place a referrer before its
        # referent (an appliance VLAN carrying groupPolicyId before the
        # group policy's own create), so unmapped references defer to
        # the next round instead of failing; a round that maps or
        # settles nothing means the references are genuinely dead.
        pending: list[RestoreAction] = list(plan.actions)
        #: 400-failed create/configure actions eligible for one
        #: end-of-run retry (same-wave sibling dependencies).
        salvage_round: dict[
            str, tuple[RestoreAction, RestoreAction, tuple[str, ...]]
        ] = {}
        #: Keys granted one drop-unresolvable-references retry after a
        #: deadlocked (no-progress) round — mutually-referencing pairs
        #: (policy object groupIds ↔ group objectIds) otherwise starve
        #: each other forever.
        drop_retry: set[str] = set()
        while pending:
            deferred: list[tuple[RestoreAction, str]] = []
            for action in pending:
                if self._skip_claims and action.wave in (
                    WAVE_DEVICE_CLAIM, WAVE_DEVICE_FEATURES
                ):
                    skipped.append(
                        {"target": action.key, "reason": "drill: hardware "
                         "is attached to another organization; device "
                         "claiming and device-scoped features only execute "
                         "in a real disaster recovery"}
                    )
                    continue
                if (
                    self._skip_claims
                    and action.kind == "configure"
                    and _body_serial_properties(action.operation)
                ):
                    # The write schema binds this feature to hardware
                    # (warm spare's spareSerial, …); a device-free drill
                    # org rejects it no matter what the payload says.
                    skipped.append(
                        {"target": action.key, "reason": "drill: the "
                         "write schema binds this feature to device "
                         "serials; it only restores in a real disaster "
                         "recovery"}
                    )
                    continue
                if self._skip_claims and _references_serials(
                    action, drill_serials
                ):
                    if action.kind in ("create", "claim"):
                        skipped_parents.add(_own_identity(action))
                    skipped.append(
                        {"target": action.key, "reason": "drill: the "
                         "payload references production hardware serials; "
                         "this object only restores in a real disaster "
                         "recovery (or with --serial-map)"}
                    )
                    continue
                if action.key in self._journal.completed:
                    if (
                        action.kind == "create"
                        and not resolver.has_mapping(*_own_identity(action))
                    ):
                        # A completed create with no journaled mapping:
                        # the run that created it could not extract the
                        # response ID, so every reference to it is dead
                        # on this and all future resumes. Recover the
                        # mapping by matching the existing object in
                        # the target.
                        remembered = self._reconcile_existing(
                            dashboard, action, resolver,
                            graph.organization_id,
                        )
                        if remembered is not None:
                            self._bookkeep_success(
                                action, remembered, resolver,
                                graph.organization_id,
                            )
                            logger.warning(
                                "Recovered the missing ID mapping for "
                                "%s by matching the already-restored "
                                "object in the target organization.",
                                action.key,
                            )
                    skipped.append(
                        {"target": action.key, "reason": "already restored "
                         "(journal); resume skips completed actions"}
                    )
                    continue
                foreign_serials = [
                    value
                    for name, value in zip(
                        _PATH_PARAM_RE.findall(action.api_path),
                        action.path_values,
                    )
                    if _scope_stem(name) == "serial"
                    and value not in known_serials
                ]
                if foreign_serials:
                    failed.append(
                        (action.key, f"device {foreign_serials[0]} is not "
                         "recorded in the snapshot; refusing to write to "
                         "hardware the restore does not own")
                    )
                    continue
                # Parents are matched by (type stem, value): a bare
                # value match would let e.g. a failed group policy
                # "100" poison the unrelated VLAN 100. A create's own
                # last path value is its identity-to-be-minted, not an
                # addressed parent — the same old ID failing in a
                # sibling network (URL-derived webhook-receiver IDs
                # repeat across networks) must not hold this one back.
                own = (
                    _own_identity(action)
                    if action.kind in ("create", "claim")
                    else None
                )
                dead = [
                    value
                    for name, value in zip(
                        _PATH_PARAM_RE.findall(action.api_path),
                        action.path_values,
                    )
                    if (_scope_stem(name), value) in failed_parents
                    and (_scope_stem(name), value) != own
                ]
                if dead:
                    skipped.append(
                        {"target": action.key, "reason": "parent object "
                         f"{dead[0]} failed to restore"}
                    )
                    continue
                held = [
                    value
                    for name, value in zip(
                        _PATH_PARAM_RE.findall(action.api_path),
                        action.path_values,
                    )
                    if (_scope_stem(name), value) in skipped_parents
                    and (_scope_stem(name), value) != own
                ]
                if held:
                    # Propagate the drill verdict down the tree: a
                    # skipped child that is itself a parent holds its
                    # own children back too.
                    if action.kind in ("create", "claim"):
                        skipped_parents.add(_own_identity(action))
                    skipped.append(
                        {"target": action.key, "reason": "drill: parent "
                         f"object {held[0]} was skipped for this drill; "
                         "its children only restore in a real disaster "
                         "recovery"}
                    )
                    continue
                if action.kind != "claim":
                    waiting = [
                        value
                        for name, value in zip(
                            _PATH_PARAM_RE.findall(action.api_path),
                            action.path_values,
                        )
                        if _scope_stem(name) == "serial"
                        and value in unclaimed
                    ]
                    if waiting:
                        deferred.append(
                            (action, f"device {waiting[0]} has not been "
                             "claimed into the target organization yet")
                        )
                        continue
                dispatch_action = action
                injected_paths: tuple[str, ...] = ()
                if self._skip_claims:
                    # A sanitized-snapshot drill: redacted secret slots
                    # get valid placeholders so the write exercises the
                    # same shape a real restore would ("Password is
                    # required to enable WPA encryption" otherwise) —
                    # and write-only secrets the API never echoed
                    # (RADIUS server secrets) are filled from the
                    # write schema ("Secret can't be blank").
                    filled, injected_paths = _inject_drill_secrets(
                        action.payload, action.secret_reentry, action.key,
                        op=action.operation,
                    )
                    filled, absent = _inject_absent_list_secrets(
                        filled, action.key, action.operation
                    )
                    injected_paths = tuple(
                        sorted({*injected_paths, *absent})
                    )
                    if injected_paths:
                        dispatch_action = replace(action, payload=filled)
                try:
                    new_id: str | None
                    recovered: str | None = None
                    if (
                        action.kind == "create"
                        and action.key in self._journal.attempted
                    ):
                        # A previous run recorded the attempt but never
                        # the completion: it died in the create/journal
                        # window and the object may already exist.
                        # Re-POSTing blind duplicates it (or fails on
                        # the duplicate name and skips every child).
                        recovered = self._reconcile_existing(
                            dashboard, action, resolver,
                            graph.organization_id,
                        )
                        if recovered is not None:
                            logger.warning(
                                "Adopted %s: an interrupted run created "
                                "it without journaling; matched in the "
                                "target instead of re-creating.",
                                action.key,
                            )
                    if recovered is None and action.kind == "create":
                        default_key = _default_flag_key(action.payload)
                        if default_key is not None:
                            recovered = self._adopt_default(
                                dashboard, action, resolver,
                                graph.organization_id, default_key,
                            )
                    if recovered is not None:
                        new_id = recovered
                    else:
                        new_id = self._dispatch(
                            dashboard, dispatch_action, resolver,
                            graph.organization_id,
                            drop_unresolvable=action.key in drop_retry,
                        )
                except _EmptyConfigureSkip as exc:
                    skipped.append(
                        {"target": action.key, "reason": str(exc)}
                    )
                    continue
                except UnmappedReferenceError as exc:
                    if action.key in drop_retry:
                        # Even dropping unresolvable fields could not
                        # dispatch it (rule-grammar references never
                        # drop): the references are genuinely dead.
                        failed.append((action.key, str(exc)))
                        if action.kind in ("create", "claim"):
                            failed_parents.add(_own_identity(action))
                        continue
                    deferred.append((action, str(exc)))
                    continue
                except Exception as exc:  # noqa: BLE001 - per-object isolation
                    verdict, salvage = self._salvage_failure(
                        dashboard, dispatch_action, resolver,
                        graph.organization_id, exc,
                    )
                    if verdict == "healed":
                        # The disabled state was restored; the extra
                        # attributes the dashboard rejected only matter
                        # once the feature is enabled for real.
                        new_id = None
                        injected_paths = ()
                    elif verdict == "adopted":
                        # The target already provisions this object (a
                        # Meraki default); its content was aligned and
                        # the mapping flows through the normal path.
                        new_id = salvage
                        injected_paths = ()
                    elif verdict == "skip":
                        skipped.append(
                            {"target": action.key, "reason": salvage or ""}
                        )
                        continue
                    else:
                        message = str(exc)
                        if _secret_paths(dispatch_action.payload):
                            # SDK error text can echo the rejected field
                            # back; this payload carries live secret
                            # values (or drill placeholders standing in
                            # for them), so the echo must not reach logs
                            # or alerts. Field NAMES are diagnosable and
                            # never sensitive — the runbook already
                            # publishes them.
                            message = (
                                f"{type(exc).__name__} (status "
                                f"{getattr(exc, 'status', 'n/a')}); detail "
                                "withheld — the request carried secret "
                                "values (fields sent: "
                                f"{', '.join(sorted(dispatch_action.payload))})"
                            )
                        if (
                            getattr(exc, "status", None) == 400
                            and action.kind in ("create", "configure")
                        ):
                            # Same-wave sibling dependencies (a static
                            # route whose next hop lives on a VLAN that
                            # sorts after it) produce 400s that resolve
                            # once the wave settles: eligible for one
                            # end-of-run salvage retry.
                            salvage_round[action.key] = (
                                action, dispatch_action, injected_paths,
                            )
                        failed.append((action.key, message))
                        if action.kind in ("create", "claim"):
                            # A failed claim poisons its serial too: the
                            # hardware may still be claimed by the source
                            # (production) organization, and serial-scoped
                            # endpoints would write straight into it.
                            failed_parents.add(_own_identity(action))
                        continue
                if action.kind == "claim":
                    unclaimed.discard(action.path_values[-1])
                self._bookkeep_success(
                    action, new_id, resolver, graph.organization_id
                )
                executed.append(action.key)
                if injected_paths:
                    drill_placeholders.append(
                        (action.key, ",".join(injected_paths))
                    )
            if not deferred:
                break
            if len(deferred) == len(pending):
                # Nothing settled this round, so no new mapping can
                # appear on its own. Grant every deferred action one
                # retry that omits unresolvable reference fields — a
                # mutual pair then converges (the first to settle
                # records the mapping the other needs, and the
                # surviving side of the pair re-establishes the link).
                # An action already granted that retry is out of moves;
                # the UnmappedReferenceError handler fails it.
                fresh = [
                    action
                    for action, _ in deferred
                    if action.key not in drop_retry
                ]
                if not fresh:
                    for action, reason in deferred:
                        failed.append((action.key, reason))
                    break
                drop_retry.update(action.key for action in fresh)
            pending = [action for action, _ in deferred]
        if salvage_round:
            # One bounded retry after the whole plan settles: same-wave
            # sibling dependencies (a static route rejected because its
            # next-hop VLAN sorted after it) resolve once the siblings
            # exist. Anything that fails again keeps its original
            # failure record.
            salvaged: list[str] = []
            for key, (action, dispatch_action, injected) in (
                salvage_round.items()
            ):
                try:
                    new_id = self._dispatch(
                        dashboard, dispatch_action, resolver,
                        graph.organization_id,
                    )
                except Exception as exc:  # noqa: BLE001 - original stands
                    # Same withholding rule as the main handler: the SDK
                    # error text can echo the rejected request fields,
                    # and this action's payload may carry live secrets.
                    detail = (
                        f"{type(exc).__name__} (status "
                        f"{getattr(exc, 'status', 'n/a')}); detail "
                        "withheld — the request carried secret values"
                        if _secret_paths(dispatch_action.payload)
                        else str(exc)
                    )
                    logger.debug(
                        "End-of-run salvage retry for %s failed (%s); "
                        "the original failure stands.", key, detail,
                    )
                    continue
                self._bookkeep_success(
                    action, new_id, resolver, graph.organization_id
                )
                executed.append(key)
                salvaged.append(key)
                if injected:
                    drill_placeholders.append((key, ",".join(injected)))
                if action.kind in ("create", "claim"):
                    failed_parents.discard(_own_identity(action))
            if salvaged:
                recovered_keys = set(salvaged)
                failed = [
                    entry for entry in failed
                    if entry[0] not in recovered_keys
                ]
                logger.warning(
                    "End-of-run salvage restored %d object(s) whose "
                    "first attempt failed on a same-wave sibling "
                    "dependency: %s", len(salvaged), ", ".join(salvaged),
                )
        if drill_placeholders:
            logger.warning(
                "%d object(s) received drill placeholder secrets (their "
                "real values are redacted in the sanitized snapshot): %s",
                len(drill_placeholders),
                "; ".join(
                    f"{key} ({paths})" for key, paths in drill_placeholders
                ),
            )
        return RestoreResult(
            executed=tuple(executed),
            failed=tuple(failed),
            skipped=tuple(skipped),
            drill_placeholders=tuple(drill_placeholders),
        )

    def _bookkeep_success(
        self,
        action: RestoreAction,
        new_id: str | None,
        resolver: ReferenceResolver,
        source_org: str,
    ) -> None:
        """Record a dispatched action's mapping and journal completion."""
        if new_id is None and action.kind == "create":
            # The API accepted the create but returned no
            # usable ID, so no old→new mapping can be recorded:
            # children referencing the snapshot ID will fail
            # loudly on this and every resumed run. Surface the
            # remediation instead of leaving a silent strand.
            logger.error(
                "Create %s returned no object ID; its old "
                "identifier cannot be remapped and any children "
                "referencing it will fail. Verify the object in "
                "the target organization and restore its "
                "children manually.", action.key,
            )
        if new_id is not None:
            own_stem, own_old = _own_identity(action)
            # The organization is a global singleton scope, so
            # it never disambiguates anything — and keeping it
            # would make org-scoped objects (policy objects,
            # config templates) unresolvable from network scope,
            # whose referrer path values never carry the org ID.
            mapping_context = (
                ()
                if action.wave == WAVE_NETWORKS
                else tuple(
                    value
                    for value in action.path_values[:-1]
                    if value != source_org
                )
            )
            resolver.record(own_stem, own_old, new_id, mapping_context)
            self._journal.record_mapping(
                own_old, new_id,
                scope=own_stem, context=mapping_context,
            )
        self._journal.record_done(action.key)

    def _salvage_failure(
        self,
        dashboard: Any,
        action: RestoreAction,
        resolver: ReferenceResolver,
        source_org: str,
        exc: Exception,
    ) -> tuple[str, str | None]:
        """Classify a dispatch failure into a salvageable outcome.

        Returns one of ``("healed", None)`` — the disabled state was
        restored with a minimal retry; ``("adopted", new_id)`` — the
        target already provisions the object (a Meraki default) and it
        was adopted + content-aligned; ``("skip", reason)`` — an
        expected drill/default condition, not a failure;
        ``("failed", None)`` — the original error stands.
        """
        if getattr(exc, "status", None) != 400:
            return ("failed", None)
        text = str(exc)
        if (
            action.kind == "configure"
            and action.payload.get("enabled") is False
        ):
            # GET echoes of disabled features carry attribute skeletons
            # their PUT refuses while disabled (OSPF demands areas, the
            # alternate management interface demands a VLAN). The
            # disabled bit alone restores the actual state; if even
            # that is refused — or the payload already WAS the bare
            # disabled bit — disabled is a rebuilt network's default
            # state already.
            skip_reason = (
                "disabled in the snapshot and the dashboard refuses "
                "the disabled-state write; a rebuilt network is "
                "already disabled by default"
            )
            if len(action.payload) == 1:
                return ("skip", skip_reason)
            minimal = replace(action, payload={"enabled": False})
            try:
                self._dispatch(dashboard, minimal, resolver, source_org)
            except Exception:  # noqa: BLE001 - degrade to the default
                return ("skip", skip_reason)
            logger.warning(
                "Restored %s as disabled-only: the dashboard rejected "
                "the full disabled-state payload; its attributes apply "
                "only when the feature is enabled.", action.key,
            )
            return ("healed", None)
        if action.kind == "create" and _NAME_CONFLICT_RE.search(text):
            adopted = self._adopt_existing(
                dashboard, action, resolver, source_org
            )
            if adopted is not None:
                return ("adopted", adopted)
        if self._skip_claims and _CAPABILITY_RE.search(text):
            return (
                "skip",
                "drill: the dashboard refuses this feature because the "
                "drill organization has no claimed hardware of the "
                "required class; it only restores in a real disaster "
                "recovery",
            )
        if _TEMPLATE_BOUND_RE.search(text):
            # Not drill-specific: a template-bound network refuses this
            # write for everyone; the config template's own copy of the
            # setting restores separately and governs the network.
            return (
                "skip",
                "the dashboard refuses this write on a template-bound "
                "network; the setting is governed by its config "
                "template (restored separately)",
            )
        return ("failed", None)

    def _adopt_existing(
        self,
        dashboard: Any,
        action: RestoreAction,
        resolver: ReferenceResolver,
        source_org: str,
    ) -> str | None:
        """Adopt the already-existing counterpart of a conflicted create.

        Meraki provisions defaults into new networks/organizations
        (payload templates, RF profiles, staged upgrade groups, VLAN 1,
        the default adaptive-policy group), so the snapshot's captured
        copy collides on create. Fixed slots with a client-assigned ID
        adopt by that ID; everything else adopts by name (the crash-
        recovery lookup). The adopted object's content is then aligned
        with the captured payload via the item's PUT, when one exists.
        """
        _, own_old = _own_identity(action)
        accepted = _body_property_names(action.operation)
        client_assigned = any(
            key in accepted and value == own_old
            for key, value in action.payload.items()
        )
        adopted = (
            own_old
            if client_assigned
            else self._reconcile_existing(
                dashboard, action, resolver, source_org
            )
        )
        if adopted is None:
            # An org-wide-unique object (a built-in payload template)
            # discovered once per network conflicts from the second
            # network on, but lives outside that network's collection —
            # the sibling network's mapping for the same old ID IS the
            # shared target object.
            own_stem, _ = _own_identity(action)
            adopted = resolver.sibling_mapping(own_stem, own_old)
            if adopted is not None:
                logger.warning(
                    "Adopted %s: the conflicting object is org-shared "
                    "and was already restored via a sibling network; "
                    "reusing its mapping.", action.key,
                )
                return adopted
        if adopted is None:
            return None
        logger.warning(
            "Adopted %s: the target already provisions this object (a "
            "Meraki default or an earlier restore); aligning its "
            "content with the snapshot.", action.key,
        )
        self._align_adopted(dashboard, action, resolver, source_org, adopted)
        return adopted

    def _adopt_default(
        self,
        dashboard: Any,
        action: RestoreAction,
        resolver: ReferenceResolver,
        source_org: str,
        flag_key: str,
    ) -> str | None:
        """Adopt the target's own default instead of duplicating it.

        A create of a snapshot object flagged ``isDefault``-true can
        SUCCEED and still be wrong: the dashboard provisions its own
        default alongside (staged upgrade groups), leaving a duplicate
        the follow-up stages PUT then rejects ("Missing Staged Upgrade
        Group: …", naming the unassigned auto-default). So defaults are
        adopted *before* the POST: the collection's existing
        flag-matching item is taken over and content-aligned. More than
        one flagged item disambiguates by natural key; no match falls
        through to the normal create.
        """
        listing = self._list_collection(dashboard, action, resolver,
                                        source_org)
        if listing is None:
            return None
        flagged = [
            item
            for item in listing
            if isinstance(item, Mapping) and item.get(flag_key) is True
        ]
        if not flagged:
            return None
        match = (
            flagged[0]
            if len(flagged) == 1
            else _match_collection_item(flagged, action.payload)
        )
        if match is None:
            return None
        adopted = _item_identifier(action, match)
        if adopted is None:
            return None
        logger.warning(
            "Adopted %s: the snapshot object is its collection's "
            "default and the target organization already provisions "
            "one; aligning the existing default instead of creating a "
            "duplicate.", action.key,
        )
        self._align_adopted(dashboard, action, resolver, source_org, adopted)
        if adopted == "-1":
            # A freshly provisioned default can list under the sentinel
            # ID -1 until the dashboard materializes it. Item PUTs
            # accept the sentinel as a default alias, but references
            # from sibling endpoints (the staged-stages PUT) reject it
            # ("Invalid Staged Upgrade Group: -1") — re-read the
            # collection after alignment for the real identifier.
            relisted = self._list_collection(
                dashboard, action, resolver, source_org
            )
            rematch = (
                _match_collection_item(relisted, action.payload)
                if relisted
                else None
            )
            refreshed = (
                _item_identifier(action, rematch)
                if rematch is not None
                else None
            )
            if refreshed is not None and refreshed != "-1":
                # The alignment follow-up recorded a provisional
                # mapping onto the sentinel; leaving both entries
                # standing makes every reference to this object
                # ambiguous ("refusing to guess").
                own_stem, own_old = _own_identity(action)
                resolver.forget(own_stem, own_old, "-1")
                adopted = refreshed
        return adopted

    def _align_adopted(
        self,
        dashboard: Any,
        action: RestoreAction,
        resolver: ReferenceResolver,
        source_org: str,
        adopted: str,
    ) -> None:
        """Push the captured payload onto an adopted object via its PUT.

        Adoption alone leaves the built-in's factory content in place;
        the drill/recovery intent is the snapshot's content. Alignment
        failures downgrade to a warning — the object exists and is
        mapped, which is what the rest of the restore depends on.
        """
        if action.aligner is None:
            return
        own_stem, own_old = _own_identity(action)
        context = tuple(
            value
            for value in action.path_values[:-1]
            if value != source_org
        )
        # Recorded ahead of the caller's bookkeeping so the follow-up
        # PUT can resolve its own path scope; the duplicate row the
        # caller records is harmless (same mapping).
        resolver.record(own_stem, own_old, adopted, context)
        follow_up = replace(action, kind="configure", operation=action.aligner)
        try:
            self._dispatch(dashboard, follow_up, resolver, source_org)
        except Exception as exc:  # noqa: BLE001 - adoption stands
            logger.warning(
                "Adopted %s but could not align its content with the "
                "snapshot (%s, status %s); review it in the dashboard.",
                action.key, type(exc).__name__,
                getattr(exc, "status", "n/a"),
            )

    def _dispatch(
        self,
        dashboard: Any,
        action: RestoreAction,
        resolver: ReferenceResolver,
        source_org: str,
        drop_unresolvable: bool = False,
    ) -> str | None:
        """One write; returns the server-assigned ID for creates."""
        op = action.operation
        params: dict[str, str] = {}
        scope_values = action.path_values
        if action.wave == WAVE_NETWORKS:
            # Network creation is scoped by the organization, not by the
            # (journal-keyed) old network ID the action carries.
            scope_values = (source_org,)
        elif action.kind == "claim":
            scope_values = (action.path_values[0],)
        for name, value in zip(op.path_params, scope_values):
            params[name] = resolver.resolve_scope(
                name, value, action.path_values
            )
            # Final interlock: whatever the resolver produced, an
            # organization scope other than the restore target must
            # never reach the dashboard — a restore only ever writes
            # into --target-org.
            if (
                _scope_stem(name) == "organization"
                and params[name] != self._target
            ):
                raise ForeignScopeError(
                    f"resolved organization scope {params[name]!r} is not "
                    "the restore target organization; refusing to dispatch"
                )
        # Path parameters win over any payload field of the same name —
        # the payload echoes the snapshot tenant's identifiers
        # (organizationId in network payloads, number in SSIDs, portId
        # in switch ports), and passing both would collide with the SDK
        # method's positional parameters.
        body = {
            key: value
            for key, value in action.payload.items()
            if key not in params
        }
        if action.kind == "claim":
            # The claim body is only the (possibly replaced) serial.
            # The discovered device payload is placement data restored
            # by later waves (floorPlanId, switchProfileId, …) —
            # rewriting it here would defer or fail the claim on
            # references the call never sends.
            serial = action.path_values[1]
            body = {"serials": [self._serial_map.get(serial, serial)]}
        else:
            exclude: str | None = None
            if action.kind == "create":
                # The object's own identity is server-assigned on
                # create: strip self-referential fields the write
                # schema does not declare, so the stale snapshot ID is
                # neither POSTed nor mistaken for a dangling reference.
                # Schema-declared fields keep their value even when it
                # equals the old ID — an appliance VLAN's
                # client-assigned `id` is required by its create
                # operation.
                _, own_old = _own_identity(action)
                accepted = _body_property_names(op)
                body = {
                    k: v
                    for k, v in body.items()
                    if v != own_old or k in accepted
                }
                exclude = own_old
            elif action.api_path.endswith("}"):
                # An item configure's payload echoes its own identity
                # (a recreated VLAN carries id: "10") — with bare id
                # keys treated as references, that echo must count as
                # identity, exactly like on creates. Singletons keep no
                # exclude: their last path value is a parent scope.
                _, exclude = _own_identity(action)
            dropped: list[str] | None = [] if drop_unresolvable else None
            body = rewrite_references(
                body, resolver, action.path_values, exclude, dropped
            )
            if dropped:
                logger.warning(
                    "Restored %s without its unresolvable reference "
                    "field(s) %s: their referents have no rebuilt "
                    "counterpart (mutual-reference deadlock); the "
                    "surviving side of each pair re-establishes the "
                    "link.", action.key, ", ".join(sorted(set(dropped))),
                )
            if self._serial_map:
                body = _remap_serial_fields(body, self._serial_map)
        items = _collection_items(body)
        if items is not None:
            # Collection envelopes ({"items": [...], "meta": …}) are
            # discovery artifacts; the writable body is the operation's
            # sole array property (same handling as the gap replayer).
            field = _single_array_body_field(op)
            if field is not None:
                body = {field: items}
        body = _strip_nulls(body)
        body = shape_rules(action.api_path, body)
        if action.kind == "configure" and _effectively_empty(body):
            raise _EmptyConfigureSkip(
                "the captured payload holds no writable values (null "
                "leaves only); nothing to restore"
            )
        section = getattr(dashboard, op.tags[0], None) if op.tags else None
        method = (
            getattr(section, op.operation_id, None)
            if section is not None
            else None
        )
        if method is None:
            raise RuntimeError(
                f"Meraki SDK exposes no method for {op.operation_id!r}"
            )
        if action.kind == "create":
            # Write-ahead: recorded after reference rewriting (so a
            # deferral leaves no trace) but before the API call, so a
            # crash inside the create/journal window is detectable on
            # resume (see _reconcile_existing).
            self._journal.record_attempt(action.key)
        self._bucket.acquire()
        if isinstance(body, Mapping):
            response = method(*params.values(), **body)
        else:  # pragma: no cover - array bodies route via _json kwarg
            response = method(*params.values(), _json=body)
        self._bucket.on_success()
        if action.kind in ("create", "claim") and isinstance(response, Mapping):
            # Create responses key their identity differently per
            # collection ('groupId', 'payloadTemplateId', …): a generic
            # 'id', the item path's own placeholder, or the
            # '<singular>Id' convention. Without this, the mapping is
            # never recorded and every child referencing the object
            # fails on dead snapshot IDs.
            new_id = _item_identifier(action, response)
            if new_id is not None:
                return new_id
        return None

    def _reconcile_existing(
        self,
        dashboard: Any,
        action: RestoreAction,
        resolver: ReferenceResolver,
        source_org: str,
    ) -> str | None:
        """The ID of an already-existing counterpart of this create.

        Reads the create's collection back from the target and matches
        by name first, then by a natural key (``sgt`` is org-unique for
        adaptive-policy groups, ``shortName`` for early-access opt-ins)
        when name matching fails — sanitized snapshots pseudonymize
        names, so the target's real-named defaults never match by name.
        Anything short of exactly one match (no matchable key in the
        payload, no collection GET in the spec, unreadable collection,
        zero or several matches) returns ``None`` and the normal create
        proceeds — worst case the API rejects a duplicate per object,
        exactly as before.
        """
        listing = self._list_collection(dashboard, action, resolver,
                                        source_org)
        if listing is None:
            return None
        match = _match_collection_item(listing, action.payload)
        if match is None:
            return None
        return _item_identifier(action, match)

    def _list_collection(
        self,
        dashboard: Any,
        action: RestoreAction,
        resolver: ReferenceResolver,
        source_org: str,
    ) -> list[Any] | None:
        """The create's target collection, or ``None`` if unreadable."""
        op = action.lookup
        if op is None:
            return None
        scope_values = action.path_values
        if action.wave == WAVE_NETWORKS:
            scope_values = (source_org,)
        params = {
            param: resolver.resolve_scope(param, value, action.path_values)
            for param, value in zip(op.path_params, scope_values)
        }
        section = getattr(dashboard, op.tags[0], None) if op.tags else None
        method = (
            getattr(section, op.operation_id, None)
            if section is not None
            else None
        )
        if method is None:
            return None
        self._bucket.acquire()
        try:
            listing = (
                method(*params.values(), total_pages="all")
                if "total_pages" in inspect.signature(method).parameters
                else method(*params.values())
            )
        except Exception as exc:  # noqa: BLE001 - fall back to the POST
            logger.debug(
                "Adoption lookup for %s failed (%s); proceeding "
                "with the create.", action.key, exc,
            )
            return None
        self._bucket.on_success()
        if isinstance(listing, Mapping):
            listing = listing.get("items")
        return listing if isinstance(listing, list) else None


@dataclass(frozen=True)
class WipePreview:
    """What a wipe would destroy — shown before any --confirm."""

    organization_id: str
    organization_name: str
    network_count: int
    claimed_device_count: int
    #: Admins other than the caller. A restore drill from a snapshot
    #: recreates the source org's admins (as pseudonyms in sanitized
    #: drills), and the dashboard refuses to delete an organization
    #: "with multiple users" — so the wipe must remove them first.
    other_admin_count: int = 0
    #: Config templates are backed by hidden networks the network loop
    #: never sees; the dashboard then refuses the org deletion with
    #: "Cannot delete organization: it still has networks".
    config_template_count: int = 0


@dataclass(frozen=True)
class WipeResult:
    """Outcome of one executed wipe."""

    deleted_networks: tuple[str, ...] = ()
    organization_deleted: bool = False
    failed: tuple[tuple[str, str], ...] = ()


class WipeRefusedError(RuntimeError):
    """A safety interlock refused the wipe target."""


class OrgWiper:
    """Tears down a drill organization after a restore rehearsal.

    The most dangerous verb in the tool, so the interlocks are stacked
    and non-negotiable:

    * an organization holding **any claimed device** is refused — a
      production org always has hardware, a drill org structurally
      never does, so the destructive path is physically incapable of
      targeting production;
    * the caller must present the organization's exact **name** as a
      second factor alongside its ID;
    * preview first, ``--confirm`` to execute, like every write path.

    The wipe deletes every network (which deletes their configuration)
    and then the organization itself. Dashboard-side deletion is
    immediate; backend retention of deleted-organization data is
    governed by Cisco's data-handling policy — for hard erasure
    guarantees after an unsanitized drill, file a data-deletion request
    with Meraki support (or drill from the sanitized snapshot so no
    real secrets or identifiers ever enter the org).
    """

    def __init__(self, bucket: AdaptiveTokenBucket | None = None) -> None:
        self._bucket = bucket or AdaptiveTokenBucket()
        self._client: Any = None

    def _dashboard(self) -> Any:
        if self._client is None:
            import meraki

            self._client = meraki.DashboardAPI(
                api_key=read_api_key(),
                suppress_logging=True,
                print_console=False,
                output_log=False,
            )
        return self._client

    def preview(self, organization_id: str, expected_name: str) -> WipePreview:
        """Validate every interlock and report the blast radius."""
        dashboard = self._dashboard()
        organization = dashboard.organizations.getOrganization(organization_id)
        name = str(organization.get("name", ""))
        if name != expected_name:
            raise WipeRefusedError(
                f"--wipe-org-name {expected_name!r} does not match the "
                f"organization's actual name {name!r}; refusing."
            )
        devices = dashboard.organizations.getOrganizationDevices(
            organization_id, total_pages="all"
        )
        # /organizations/{id}/devices lists only network-assigned
        # devices; hardware claimed into the inventory but not yet
        # added to a network appears only in the inventory endpoint —
        # and it is exactly as production-indicating.
        inventory_reader = getattr(
            dashboard.organizations, "getOrganizationInventoryDevices", None
        )
        if inventory_reader is None:
            raise WipeRefusedError(
                "Cannot verify the organization's claimed-device "
                "inventory (SDK lacks getOrganizationInventoryDevices); "
                "refusing to wipe without the interlock."
            )
        inventory = inventory_reader(organization_id, total_pages="all")
        claimed = {
            str(entry.get("serial", ""))
            for entry in (*devices, *inventory)
            if isinstance(entry, Mapping)
        } - {""}
        if claimed:
            raise WipeRefusedError(
                f"Organization {organization_id} has {len(claimed)} claimed "
                "device(s) (network-assigned or inventory-only); wiping is "
                "only permitted for hardware-free drill organizations. "
                "Unclaim the devices first if this really is a drill org."
            )
        networks = dashboard.organizations.getOrganizationNetworks(
            organization_id, total_pages="all"
        )
        return WipePreview(
            organization_id=organization_id,
            organization_name=name,
            network_count=len(networks),
            claimed_device_count=0,
            other_admin_count=len(self._other_admins(organization_id)),
            config_template_count=len(
                self._config_templates(organization_id)
            ),
        )

    def _config_templates(self, organization_id: str) -> list[str]:
        """IDs of the organization's config templates (may be empty)."""
        dashboard = self._dashboard()
        try:
            self._bucket.acquire()
            templates = dashboard.organizations.getOrganizationConfigTemplates(
                organization_id
            )
            self._bucket.on_success()
        except Exception as exc:  # noqa: BLE001 - degrade to none found
            logger.debug(
                "Could not enumerate config templates for %s (%s).",
                organization_id, exc,
            )
            return []
        return [
            str(template.get("id", ""))
            for template in (templates if isinstance(templates, list) else [])
            if isinstance(template, Mapping) and template.get("id")
        ]

    def _other_admins(self, organization_id: str) -> list[tuple[str, str]]:
        """``(admin_id, email)`` of every admin who is not the caller.

        Restore drills recreate the source org's admins, and the
        dashboard refuses to delete an organization "with multiple
        users" — the wipe removes them first. The caller is identified
        by the API key's own identity; if that cannot be established,
        NO admin is ever deleted (the org deletion may then fail with
        the dashboard's own clear message rather than risk removing
        the operator's account).
        """
        dashboard = self._dashboard()
        identity_reader = getattr(
            getattr(dashboard, "administered", None),
            "getAdministeredIdentitiesMe", None,
        )
        if identity_reader is None:
            return []
        try:
            self._bucket.acquire()
            me = identity_reader()
            self._bucket.on_success()
            own_email = str(me.get("email", "")) if isinstance(
                me, Mapping
            ) else ""
            self._bucket.acquire()
            admins = dashboard.organizations.getOrganizationAdmins(
                organization_id
            )
            self._bucket.on_success()
        except Exception as exc:  # noqa: BLE001 - degrade to no deletion
            logger.debug(
                "Could not enumerate admins for %s (%s); the wipe will "
                "not remove any admin.", organization_id, exc,
            )
            return []
        if not own_email:
            return []
        return [
            (str(admin.get("id", "")), str(admin.get("email", "")))
            for admin in (admins if isinstance(admins, list) else [])
            if isinstance(admin, Mapping)
            and str(admin.get("email", "")) != own_email
            and admin.get("id")
        ]

    def execute(self, organization_id: str, expected_name: str) -> WipeResult:
        """Re-verify the interlocks immediately before destroying."""
        self.preview(organization_id, expected_name)
        dashboard = self._dashboard()
        networks = dashboard.organizations.getOrganizationNetworks(
            organization_id, total_pages="all"
        )
        deleted: list[str] = []
        failed: list[tuple[str, str]] = []
        for network in networks:
            network_id = str(network.get("id", ""))
            try:
                self._bucket.acquire()
                dashboard.networks.deleteNetwork(network_id)
                self._bucket.on_success()
                deleted.append(network_id)
            except Exception as exc:  # noqa: BLE001 - per-object isolation
                failed.append((network_id, str(exc)))
        if not failed:
            # Config templates are backed by hidden networks the loop
            # above never lists; the dashboard refuses the organization
            # deletion while any remain ("it still has networks").
            for template_id in self._config_templates(organization_id):
                try:
                    self._bucket.acquire()
                    dashboard.organizations.deleteOrganizationConfigTemplate(
                        organization_id, template_id
                    )
                    self._bucket.on_success()
                    logger.warning(
                        "Wipe removed config template %s from "
                        "organization %s.", template_id, organization_id,
                    )
                except Exception as exc:  # noqa: BLE001 - isolate
                    failed.append((f"configTemplate:{template_id}", str(exc)))
        org_deleted = False
        if not failed:
            # Drill-restored admins block the organization deletion
            # ("Cannot delete organization - it still has multiple
            # users"); remove every admin except the caller. The caller
            # itself is never deleted — _other_admins guarantees that.
            for admin_id, admin_email in self._other_admins(
                organization_id
            ):
                try:
                    self._bucket.acquire()
                    dashboard.organizations.deleteOrganizationAdmin(
                        organization_id, admin_id
                    )
                    self._bucket.on_success()
                    logger.warning(
                        "Wipe removed admin %s from organization %s.",
                        admin_email, organization_id,
                    )
                except Exception as exc:  # noqa: BLE001 - isolate
                    failed.append((f"admin:{admin_id}", str(exc)))
        if not failed:
            try:
                # The network loop above can run for a long time on a
                # large drill org; re-run the claimed-device interlock
                # once more so hardware claimed mid-teardown stops the
                # organization deletion instead of vanishing with it.
                self.preview(organization_id, expected_name)
                self._bucket.acquire()
                dashboard.organizations.deleteOrganization(organization_id)
                self._bucket.on_success()
                org_deleted = True
            except Exception as exc:  # noqa: BLE001
                failed.append((organization_id, str(exc)))
        return WipeResult(
            deleted_networks=tuple(deleted),
            organization_deleted=org_deleted,
            failed=tuple(failed),
        )
