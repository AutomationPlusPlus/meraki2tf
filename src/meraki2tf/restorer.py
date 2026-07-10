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

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
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
from meraki2tf.replayer import _strip_nulls
from meraki2tf.runbook import write_operations
from meraki2tf.sanitizer import REDACTED, SECRET_KEY_PATTERN
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
        classified = _classify_feature(feature, parser, writes)
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
    if not feature.payload:
        return Unrestorable(
            feature.api_path,
            feature.path_values,
            "No payload captured in the snapshot for this asset.",
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
        )
    operation = updates[0] if updates else creates[0]
    return RestoreAction(
        kind="configure" if updates else "create",
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


def _split_redacted(
    payload: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Separate restorable attributes from sanitized-away secrets.

    ``**REDACTED**`` values cannot be written back; they become the
    operator's secret re-entry list. Secret-*named* attributes with
    real values (unsanitized snapshot) stay in the payload — restoring
    them is the whole point of the unsanitized DR snapshot.
    """
    clean: dict[str, Any] = {}
    redacted: list[str] = []
    for key, value in payload.items():
        if value == REDACTED and SECRET_KEY_PATTERN.search(key):
            redacted.append(key)
            continue
        clean[key] = value
    return clean, tuple(sorted(redacted))


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


#: Policy-object grammar embedded in firewall rule strings.
_OBJ_GRP_RE = re.compile(r"\b(GRP|OBJ)\((\d+)\)")

#: Payload keys whose values are cross-references to other objects.
_REFERENCE_KEY_RE = re.compile(r"Ids?$")


def rewrite_references(
    value: Any,
    id_map: Mapping[str, str],
    known_old_ids: frozenset[str],
) -> Any:
    """Rewrite snapshot-tenant identifiers to their rebuilt counterparts.

    Reference-shaped keys (``*Id``/``*Ids``) and the ``GRP()``/``OBJ()``
    grammar inside rule strings are remapped through ``id_map``. A
    reference to a *known* old identifier with no mapping raises
    :class:`UnmappedReferenceError`; unknown strings pass through
    untouched (they are data, not references).
    """
    if isinstance(value, Mapping):
        return {
            key: (
                _rewrite_reference_value(inner, id_map, known_old_ids)
                if isinstance(key, str) and _REFERENCE_KEY_RE.search(key)
                else rewrite_references(inner, id_map, known_old_ids)
            )
            for key, inner in value.items()
        }
    if isinstance(value, list):
        return [
            rewrite_references(item, id_map, known_old_ids) for item in value
        ]
    if isinstance(value, str):
        return _rewrite_grammar(value, id_map, known_old_ids)
    return value


def _rewrite_reference_value(
    value: Any, id_map: Mapping[str, str], known_old_ids: frozenset[str]
) -> Any:
    if isinstance(value, str):
        if value in id_map:
            return id_map[value]
        if value in known_old_ids:
            raise UnmappedReferenceError(
                f"reference to snapshot object {value!r} has no rebuilt "
                "counterpart yet"
            )
        return value
    if isinstance(value, list):
        return [
            _rewrite_reference_value(item, id_map, known_old_ids)
            for item in value
        ]
    return value


def _rewrite_grammar(
    value: str, id_map: Mapping[str, str], known_old_ids: frozenset[str]
) -> str:
    def _sub(match: "re.Match[str]") -> str:
        old = match.group(2)
        if old in id_map:
            return f"{match.group(1)}({id_map[old]})"
        if old in known_old_ids:
            raise UnmappedReferenceError(
                f"{match.group(1)}({old}) references a snapshot object "
                "with no rebuilt counterpart yet"
            )
        return match.group(0)

    return _OBJ_GRP_RE.sub(_sub, value)


def known_snapshot_ids(graph: NetworkGraph) -> frozenset[str]:
    """Every identifier the snapshot's own objects carry.

    The registry that separates "this string is a reference to one of
    our objects" from "this string is just data": path values, network
    IDs, and device serials.
    """
    ids: set[str] = {graph.organization_id}
    for network in graph.networks:
        ids.add(network.network_id)
    for device in graph.devices:
        ids.add(device.serial)
    for feature in graph.features:
        ids.update(feature.path_values)
    return frozenset(ids)


class RestoreJournal:
    """Crash-resumable restore progress: the terraform-state stand-in.

    One JSONL line per event, appended and flushed after every
    successful write, owner-only on disk: ``done`` lines carry
    completed action keys, ``map`` lines carry old → new identifier
    pairs. Re-running a restore with the same journal skips completed
    actions and reuses the mappings, so an interrupted restore resumes
    instead of duplicating thousands of creates.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self.completed: set[str] = set()
        self.id_map: dict[str, str] = {}
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("kind") == "done":
                    self.completed.add(str(record["key"]))
                elif record.get("kind") == "map":
                    self.id_map[str(record["old"])] = str(record["new"])
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch(mode=0o600)
        restrict_to_owner(path)

    def _append(self, record: Mapping[str, Any]) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(record)) + "\n")

    def record_done(self, key: str) -> None:
        self.completed.add(key)
        self._append({"kind": "done", "key": key})

    def record_mapping(self, old: str, new: str) -> None:
        self.id_map[old] = new
        self._append({"kind": "map", "old": old, "new": new})


@dataclass(frozen=True)
class RestoreResult:
    """Outcome of one restore execution pass."""

    executed: tuple[str, ...] = ()
    failed: tuple[tuple[str, str], ...] = ()
    skipped: tuple[dict[str, str], ...] = ()


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
    ) -> None:
        self._target = target_organization_id
        self._journal = journal
        self._serial_map = dict(serial_map or {})
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

    def execute(
        self, graph: NetworkGraph, plan: RestorePlan
    ) -> RestoreResult:
        dashboard = self._dashboard()
        known = known_snapshot_ids(graph)
        id_map = dict(self._journal.id_map)
        id_map.setdefault(graph.organization_id, self._target)
        id_map.update(self._serial_map)
        executed: list[str] = []
        failed: list[tuple[str, str]] = []
        skipped: list[dict[str, str]] = []
        failed_parents: set[str] = set()

        for action in plan.actions:
            if action.key in self._journal.completed:
                skipped.append(
                    {"target": action.key, "reason": "already restored "
                     "(journal); resume skips completed actions"}
                )
                continue
            dead = [v for v in action.path_values if v in failed_parents]
            if dead:
                skipped.append(
                    {"target": action.key, "reason": "parent object "
                     f"{dead[0]} failed to restore"}
                )
                continue
            try:
                new_id = self._dispatch(
                    dashboard, action, id_map, known, graph.organization_id
                )
            except UnmappedReferenceError as exc:
                failed.append((action.key, str(exc)))
                continue
            except Exception as exc:  # noqa: BLE001 - per-object isolation
                failed.append((action.key, str(exc)))
                if action.kind == "create":
                    failed_parents.add(action.path_values[0]
                                       if action.wave == WAVE_NETWORKS
                                       else action.path_values[-1])
                continue
            if new_id is not None:
                old = (
                    action.path_values[0]
                    if action.wave == WAVE_NETWORKS
                    else action.path_values[-1]
                )
                id_map[old] = new_id
                self._journal.record_mapping(old, new_id)
            self._journal.record_done(action.key)
            executed.append(action.key)
        return RestoreResult(
            executed=tuple(executed),
            failed=tuple(failed),
            skipped=tuple(skipped),
        )

    def _dispatch(
        self,
        dashboard: Any,
        action: RestoreAction,
        id_map: Mapping[str, str],
        known: frozenset[str],
        source_org: str,
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
            params[name] = id_map.get(value, value)
        body = dict(action.payload)
        if action.kind == "create":
            # The object's own identity is server-assigned on create:
            # strip self-referential fields so the stale snapshot ID is
            # neither POSTed nor mistaken for a dangling reference.
            own_old = (
                action.path_values[0]
                if action.wave == WAVE_NETWORKS
                else action.path_values[-1]
            )
            body = {k: v for k, v in body.items() if v != own_old}
            known = frozenset(known - {own_old})
        body = rewrite_references(body, id_map, known)
        if action.kind == "claim":
            serial = action.path_values[1]
            body = {"serials": [self._serial_map.get(serial, serial)]}
        body = _strip_nulls(body)
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
        self._bucket.acquire()
        if isinstance(body, Mapping):
            response = method(*params.values(), **body)
        else:  # pragma: no cover - array bodies route via _json kwarg
            response = method(*params.values(), _json=body)
        self._bucket.on_success()
        if action.kind in ("create", "claim") and isinstance(response, Mapping):
            new_id = response.get("id")
            if new_id is not None:
                return str(new_id)
        return None
