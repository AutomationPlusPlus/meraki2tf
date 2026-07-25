"""Gap replay: restore what Terraform cannot, from the offline snapshot.

The second and last human-invoked path that writes to Meraki (the
first is ``--rebuild --confirm``). After a disaster the Terraform kit
rebuilds every covered resource; this module replays the remainder —
objects the provider cannot express, plus the secret attributes the
kit deliberately does not carry (SSID PSKs, SNMP community strings) —
straight from the unsanitized ``--dump-to`` snapshot.

Safety properties:

* **Inert by default.** Nothing here runs during pipeline runs; the
  CLI action previews unless ``--confirm`` is passed, mirroring
  ``--rebuild``.
* **No new secret-bearing artifacts.** Payloads and secret values are
  read from the snapshot at execution time and held only in memory;
  results/alerts carry addresses and endpoints, never values.
* **Spec-derived.** Which write operation restores which object comes
  from the OpenAPI document (see :func:`runbook.write_operations`) —
  no hard-coded endpoint tables.
* **Identifier remapping.** A rebuilt organization issues new network
  and config-template IDs; snapshot path values are remapped to the
  live tenant by name before any call. Values *embedded inside
  payloads* are not rewritten — failures surface per object and the
  runbook remains the manual fallback.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from meraki2tf.config import read_api_key
from meraki2tf.hcl_generator import GenerationReport
from meraki2tf.models import UNREADABLE_MARKER, NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers.live import CONFIG_TEMPLATE_ITEM_PATH
from meraki2tf.runbook import payload_index, write_operations
from meraki2tf.sanitizer import REDACTED, SECRET_KEY_PATTERN
from meraki2tf.sdk_verify import (
    READ_ONLY_SESSION_VERBS,
    WRITE_SESSION_VERBS,
    method_matches_verbs,
)
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)


class ReplayDispatchError(RuntimeError):
    """A replay operation could not be resolved onto the Meraki SDK."""


#: Terminal nouns of one-shot operational "action log" collections:
#: POST-only, GET-discoverable surfaces whose entries record executed
#: actions (sensor reboot commands, PII delete requests, controller
#: migrations, network moves, packet captures). Re-POSTing a snapshot
#: entry re-executes the recorded action — a captured PII delete
#: request would re-trigger real data deletion. Meraki's own tags do
#: not discriminate (action logs are tagged "configure" like real
#: configuration), so — like resource_matcher's _SCOPE_NOUNS — this is
#: a small domain constant. Gated on the absence of any PUT so a
#: future config endpoint gaining an update is unaffected.
_ACTION_LOG_NOUNS = frozenset(
    {"commands", "requests", "migrations", "moves", "captures"}
)

ACTION_LOG_REASON = (
    "Historical action log, not configuration — replaying would "
    "re-execute the recorded action(s); review manually."
)

#: Plan-time refusal for scope-less diagnostic gap records: the
#: byNetwork aggregation explosion keeps rows it cannot resolve to any
#: scope as auditable ``path_values=()`` records (Cardinal Rule 2
#: visibility) — they are runbook material, never dispatchable writes.
GAP_RECORD_REASON = (
    "diagnostic gap record — no scope identifier; covered by the "
    "runbook's manual list"
)


def is_scope_gap_record(api_path: str, path_values: tuple[str, ...]) -> bool:
    """True when the asset's identifiers cannot address its write path.

    The write path's parameter arity is counted without
    ``organizationId`` (both executors inject the target organization);
    fewer discovered values than the remaining parameters means the
    asset is a scope-less diagnostic gap record, not a restorable
    object — dispatching it can only fail on missing path parameters.
    """
    required = [
        name for name in _placeholders(api_path) if name != "organizationId"
    ]
    return len(path_values) < len(required)


def is_action_log(api_path: str, ops: tuple[OperationSpec, ...]) -> bool:
    """POST-only entity whose collection records one-shot actions."""
    if any(op.method == "put" for op in ops):
        return False
    segments = [
        segment
        for segment in api_path.split("/")
        if segment and not segment.startswith("{")
    ]
    return bool(segments) and segments[-1] in _ACTION_LOG_NOUNS


@dataclass(frozen=True)
class ReplayAction:
    """One write the replay would perform against the live tenant."""

    #: ``object`` restores an unsupported asset; ``secrets`` re-applies
    #: secret attributes to a Terraform-rebuilt resource.
    kind: str
    api_path: str
    path_values: tuple[str, ...]
    #: Body for the write call. Full payload for objects; only the
    #: secret fields for secret restoration. Held in memory only.
    payload: Mapping[str, Any]
    operation: OperationSpec
    #: Terraform address (secret restorations) for operator-facing
    #: reporting; empty for gap objects.
    address: str = ""
    #: The GET on a POST-only create's collection, when the spec has
    #: one: the executor reads it back to skip an object a previous
    #: partially-failed replay already created (there is no journal),
    #: instead of duplicating it on every retry.
    lookup: OperationSpec | None = None

    @property
    def target(self) -> str:
        """Value-free label for logs, previews, and alerts."""
        ids = ",".join(self.path_values) or "<none>"
        label = self.address or f"{self.api_path} (ids={ids})"
        return f"{self.kind}: {label} via {self.operation.operation_id}"


@dataclass(frozen=True)
class SkippedReplay:
    """One asset the replay cannot restore, and why — runbook material."""

    api_path: str
    identifiers: tuple[str, ...]
    reason: str


def template_bound_networks(graph: NetworkGraph) -> frozenset[str]:
    """Snapshot IDs of networks bound to a config template.

    The dashboard refuses direct writes to template-governed surfaces
    on a bound network (staged upgrade stages, SSID credentials, …);
    those settings live on — and replay via — the template itself. The
    executor uses this set to report such refusals as skips with a
    pointer at the template rather than failures: a permanent, by-design
    condition must not make every scheduled replay exit nonzero.
    """
    return frozenset(
        network.network_id
        for network in graph.networks
        if isinstance(network.payload, Mapping)
        and network.payload.get("isBoundToConfigTemplate") is True
    )


def plan_replay(
    graph: NetworkGraph,
    report: GenerationReport,
    parser: OpenApiParser,
) -> tuple[tuple[ReplayAction, ...], tuple[SkippedReplay, ...]]:
    """Compute every write a replay would perform. Pure — no I/O.

    Gap objects come from the report's unsupported assets; secret
    restorations from captured assets whose snapshot payload carries
    secret-keyed values (the same key test the sanitizer applies, so an
    unsanitized snapshot restores exactly what ``--sanitize`` would
    have masked).
    """
    payloads = payload_index(graph)
    ops = write_operations(parser)
    lookups = {
        op.path: op for op in parser.endpoints() if op.method == "get"
    }
    actions: list[ReplayAction] = []
    skipped: list[SkippedReplay] = []

    for asset in sorted(report.unsupported, key=lambda a: (a.api_path, a.identifiers)):
        payload = payloads.get((asset.api_path, asset.identifiers))
        if is_scope_gap_record(asset.api_path, asset.identifiers):
            # Discovery's byNetwork explosion emits these for rows it
            # could not resolve to any scope; they exist to be reported
            # (Cardinal Rule 2), and dispatching one can only fail on
            # missing path parameters.
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    GAP_RECORD_REASON,
                )
            )
            continue
        writes = ops.get(asset.api_path, ())
        if not writes:
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    "No write operation in the API spec — dashboard-only.",
                )
            )
            continue
        if is_action_log(asset.api_path, writes):
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    ACTION_LOG_REASON,
                )
            )
            continue
        if isinstance(payload, Mapping) and not payload:
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    "Captured empty — the asset is at Meraki-provisioned "
                    "defaults; nothing to replay.",
                )
            )
            continue
        if not payload:
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    "No payload captured in the snapshot for this asset.",
                )
            )
            continue
        if UNREADABLE_MARKER in payload:
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    "Endpoint was unreadable at capture time — nothing "
                    "was recorded to restore; verify it manually.",
                )
            )
            continue
        if _collection_items(payload) == []:
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    "Collection was empty at capture — nothing to restore.",
                )
            )
            continue
        clean, redacted = split_redacted(payload)
        if redacted and not clean:
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    "Every captured attribute is redacted — the snapshot "
                    "was written with --sanitize; replay needs the "
                    "unsanitized snapshot.",
                )
            )
            continue
        if redacted:
            # Never write the redaction marker as live configuration;
            # the stripped attributes go on the manual re-entry list.
            skipped.append(
                SkippedReplay(
                    asset.api_path,
                    asset.identifiers,
                    "Redacted attribute(s) not replayed (sanitized "
                    "snapshot); re-enter manually: " + ", ".join(redacted),
                )
            )
        actions.append(
            ReplayAction(
                kind="object",
                api_path=asset.api_path,
                path_values=asset.identifiers,
                payload=clean,
                operation=writes[0],
                # POST-only creates carry the collection GET (same path
                # as the collection POST) so a retried replay can skip
                # objects an earlier run already created; item writes
                # carry their enclosing collection's GET so the executor
                # can verify a server-assigned item ID before the write.
                lookup=(
                    lookups.get(writes[0].path)
                    if writes[0].method == "post"
                    else _item_collection_lookup(writes[0], lookups)
                ),
            )
        )

    for captured in sorted(report.captured, key=lambda a: a.address):
        payload = payloads.get((captured.api_path, captured.identifiers))
        if not payload:
            continue
        # Secrets hide at any depth (radiusServers[].secret is the most
        # common Meraki secret); a top-level-only scan would neither
        # replay them nor report them as skipped.
        if not _secret_paths(payload):
            continue
        clean, _ = split_redacted(payload)
        live_paths = _secret_paths(clean)
        if not live_paths:
            skipped.append(
                SkippedReplay(
                    captured.api_path,
                    captured.identifiers,
                    "Secret values are masked — snapshot was written with "
                    "--sanitize; secrets need an unsanitized snapshot.",
                )
            )
            continue
        writes = ops.get(captured.api_path, ())
        updates = tuple(op for op in writes if op.method == "put")
        if not updates:
            skipped.append(
                SkippedReplay(
                    captured.api_path,
                    captured.identifiers,
                    "Secret attributes present but the API spec has no "
                    "update operation to restore them.",
                )
            )
            continue
        # A nested secret restores through its whole top-level field
        # (the PUT needs the complete sub-structure around it).
        top_level = sorted(
            {path.split(".", 1)[0].split("[", 1)[0] for path in live_paths}
        )
        actions.append(
            ReplayAction(
                kind="secrets",
                api_path=captured.api_path,
                path_values=captured.identifiers,
                payload={key: clean[key] for key in top_level},
                operation=updates[0],
                address=captured.address,
                lookup=_item_collection_lookup(updates[0], lookups),
            )
        )
    return tuple(actions), tuple(skipped)


def _item_collection_lookup(
    op: OperationSpec, lookups: Mapping[str, OperationSpec]
) -> OperationSpec | None:
    """The collection GET enclosing an item write path, when the spec
    has one — the executor's read-back source for verifying that a
    server-assigned item ID still names the same object live."""
    head, _, tail = op.path.rpartition("/")
    if tail.startswith("{"):
        return lookups.get(head)
    return None


class GapReplayer:
    """Executes replay actions against the live tenant via the SDK."""

    def __init__(self) -> None:
        self._client: Any = None

    def _dashboard(self) -> Any:
        if self._client is None:
            import meraki

            self._client = meraki.DashboardAPI(
                api_key=read_api_key(),
                suppress_logging=True,
                print_console=False,
                output_log=False,
                # A replay competes for the shared 10 req/s org budget —
                # in a real recovery, against every other integration
                # hammering the rebuilt tenant. The SDK's default 2
                # throttle retries give up far too early for writes
                # whose failure poisons the run's results.
                maximum_retries=8,
            )
            logger.debug("Meraki dashboard client initialized for replay.")
        return self._client

    def network_id_map(
        self, target_organization_id: str, graph: NetworkGraph
    ) -> dict[str, str]:
        """Snapshot scope ID → live ID for ``{networkId}`` scopes.

        Covers networks *and* config templates: template-held features
        are addressed with the template ID as their ``{networkId}``
        scope, so replays must resolve both. A rebuilt tenant issues
        fresh IDs; matching by name is the only stable join. An ID that
        still exists live maps to itself, and a snapshot scope with no
        live counterpart stays unmapped — its replays will fail loudly
        rather than write to a wrong target.
        """
        organizations = self._dashboard().organizations
        mapping = self._join_by_name(
            {network.network_id: network.name for network in graph.networks},
            organizations.getOrganizationNetworks(
                target_organization_id, total_pages="all"
            ),
            "network",
        )
        templates = {
            feature.path_values[-1]: str(feature.payload.get("name", ""))
            for feature in graph.features
            if feature.api_path == CONFIG_TEMPLATE_ITEM_PATH
            and feature.path_values
        }
        if templates:
            reader = getattr(
                organizations, "getOrganizationConfigTemplates", None
            )
            if reader is None:
                logger.warning(
                    "SDK exposes no getOrganizationConfigTemplates; "
                    "template-scoped replays will be refused rather "
                    "than guessed."
                )
            else:
                mapping.update(
                    self._join_by_name(
                        templates,
                        reader(target_organization_id),
                        "config template",
                    )
                )
        return mapping

    @staticmethod
    def _join_by_name(
        snapshot: Mapping[str, str], live: Any, label: str
    ) -> dict[str, str]:
        """Old→live IDs for one scope kind: identity first, then name."""
        items = live if isinstance(live, list) else []
        live_ids = {str(item.get("id", "")) for item in items}
        by_name = {
            str(item.get("name", "")): str(item.get("id", ""))
            for item in items
        }
        mapping: dict[str, str] = {}
        for old, name in snapshot.items():
            if old in live_ids:
                mapping[old] = old
            elif name in by_name:
                mapping[old] = by_name[name]
                logger.info(
                    "Remapped %s %r: snapshot id %s -> live id %s.",
                    label, name, old, by_name[name],
                )
            else:
                logger.warning(
                    "Snapshot %s %r (%s) has no live counterpart; its "
                    "replays will be skipped.",
                    label, name, old,
                )
        return mapping

    def claimed_serials(self, target_organization_id: str) -> frozenset[str]:
        """Serials currently claimed in the target organization.

        Covers network-assigned devices and inventory-only hardware:
        ``/devices/{serial}/…`` endpoints address a device wherever it
        is claimed, so a serial outside this set would replay against a
        foreign (possibly the still-alive source) organization.
        """
        organizations = self._dashboard().organizations
        devices = organizations.getOrganizationDevices(
            target_organization_id, total_pages="all"
        )
        inventory_reader = getattr(
            organizations, "getOrganizationInventoryDevices", None
        )
        inventory = (
            inventory_reader(target_organization_id, total_pages="all")
            if inventory_reader is not None
            else []
        )
        return frozenset(
            str(entry.get("serial", ""))
            for entry in (*devices, *inventory)
            if isinstance(entry, Mapping)
        ) - {""}

    def execute(
        self,
        actions: tuple[ReplayAction, ...],
        target_organization_id: str,
        snapshot_organization_id: str,
        network_ids: Mapping[str, str],
        template_bound: frozenset[str] = frozenset(),
    ) -> tuple[
        tuple[str, ...],
        tuple[tuple[str, str], ...],
        tuple[SkippedReplay, ...],
    ]:
        """Perform the writes; every failure is recorded, never raised.

        Returns ``(executed, failed, skipped)``; the skips are refusals
        classified at execution time (template-bound surfaces) that the
        pure planner cannot foresee.
        """
        executed: list[str] = []
        failed: list[tuple[str, str]] = []
        skipped: list[SkippedReplay] = []
        serials: frozenset[str] | None = None
        if any(
            "serial" in _placeholders(action.operation.path)
            for action in actions
        ):
            try:
                serials = self.claimed_serials(target_organization_id)
            except Exception as exc:  # noqa: BLE001 - verified per action
                logger.error(
                    "Cannot enumerate the target organization's claimed "
                    "devices: %s", exc,
                )
        for action in actions:
            try:
                params = self._parameters(
                    action, target_organization_id,
                    snapshot_organization_id, network_ids, serials,
                )
                self._verify_item_scope(action, params)
                if (
                    action.kind == "object"
                    and action.operation.method == "post"
                    and self._already_present(action, params)
                ):
                    # No journal exists for gap replays: a retry after
                    # a partial failure would re-create every object
                    # that already succeeded. Counted alongside the
                    # executed writes (the object is present), labeled
                    # so logs and the alert show it was not re-created.
                    logger.warning(
                        "Skipped %s: an object with the same name "
                        "already exists in the target organization "
                        "(a previous replay created it); not "
                        "re-creating.", action.target,
                    )
                    executed.append(
                        f"{action.target} [already present; skipped]"
                    )
                    continue
                self._call(action.operation, params, action.payload)
            except Exception as exc:  # per-object isolation by design
                if (
                    getattr(exc, "status", None) == 400
                    and self._network_scope(action) in template_bound
                ):
                    # The dashboard refuses direct writes to template-
                    # governed surfaces on a bound network — permanent
                    # and by design, so it must not fail the run week
                    # after week. The setting replays via the template.
                    reason = (
                        "the dashboard refuses this write on a "
                        "template-bound network; the setting is "
                        "governed by its config template — re-apply "
                        "it via the template"
                    )
                    logger.warning(
                        "Skipped %s: %s", action.target, reason
                    )
                    skipped.append(
                        SkippedReplay(
                            api_path=action.api_path,
                            identifiers=action.path_values,
                            reason=reason,
                        )
                    )
                    continue
                message = str(exc)
                if not isinstance(exc, ReplayDispatchError) and (
                    action.kind == "secrets"
                    or _secret_paths(action.payload)
                ):
                    # The request body carried live secret values —
                    # gap-object payloads keep secret-named attributes
                    # too (split_redacted only strips redacted ones) —
                    # and SDK error text can echo the rejected field
                    # back; keep it out of logs and alert payloads.
                    message = (
                        f"{type(exc).__name__} (status "
                        f"{getattr(exc, 'status', 'n/a')}); detail "
                        "withheld — the request carried secret values"
                    )
                logger.error("Replay failed for %s: %s", action.target, message)
                failed.append((action.target, message))
                continue
            logger.info("Replayed %s", action.target)
            executed.append(action.target)
        return tuple(executed), tuple(failed), tuple(skipped)

    @staticmethod
    def _network_scope(action: ReplayAction) -> str | None:
        """The action's snapshot-side ``{networkId}`` scope value."""
        for name, value in zip(
            _placeholders(action.operation.path), action.path_values
        ):
            if name == "networkId":
                return value
        return None

    def _verify_item_scope(
        self, action: ReplayAction, params: Mapping[str, str]
    ) -> None:
        """Refuse stale server-assigned item IDs the remap cannot vouch for.

        ``_parameters`` remaps and verifies only ``organizationId``,
        ``networkId``, and ``serial``; every other placeholder passes
        the snapshot's server-assigned item ID through verbatim. A
        rebuilt tenant re-issues such IDs in its own creation order, so
        the snapshot's ID may now name a *different* sibling in the
        same (verified) network — the write would silently misconfigure
        it instead of 404ing. The item's collection is read back: the
        ID must exist live, and when both sides carry a name it must
        match the snapshot object's. Anything unverifiable refuses,
        like the networkId/serial guards.
        """
        op_params = _placeholders(action.operation.path)
        scoped = {"organizationId", "networkId", "serial"}
        unverified = [name for name in op_params if name not in scoped]
        if not unverified:
            return
        lookup = action.lookup
        item_param = op_params[-1]
        lookup_needed = (
            _placeholders(lookup.path) if lookup is not None else ()
        )
        # Verifiable shape: the trailing parameter is the item's own ID
        # and every other non-scope parameter appears in the lookup
        # path itself — a wrong mid-path value then fails the read-back
        # (404) instead of silently scoping the write elsewhere.
        verifiable = (
            lookup is not None
            and unverified[-1] == item_param
            and item_param not in lookup_needed
            and all(name in params for name in lookup_needed)
            and all(
                name == item_param or name in lookup_needed
                for name in unverified
            )
        )
        if not verifiable or lookup is None:
            raise ReplayDispatchError(
                f"Cannot verify item parameter(s) "
                f"{', '.join(sorted(unverified))} against the live "
                "organization; refusing to replay onto a server-assigned "
                "ID blind."
            )
        dashboard = self._dashboard()
        section = (
            getattr(dashboard, lookup.tags[0], None) if lookup.tags else None
        )
        method = (
            getattr(section, lookup.operation_id, None)
            if section is not None
            else None
        )
        if method is None:
            raise ReplayDispatchError(
                f"SDK exposes no collection read for {action.target}; "
                "refusing to replay onto a server-assigned ID blind."
            )
        if not method_matches_verbs(method, READ_ONLY_SESSION_VERBS):
            raise ReplayDispatchError(
                f"Collection read {lookup.operation_id!r} for "
                f"{action.target} is not verifiably read-only; refusing "
                "to call it or to replay onto a server-assigned ID blind."
            )
        lookup_params = {name: params[name] for name in lookup_needed}
        try:
            listing = (
                method(**lookup_params, total_pages="all")
                if "total_pages" in inspect.signature(method).parameters
                else method(**lookup_params)
            )
        except Exception as exc:
            raise ReplayDispatchError(
                f"Collection read-back for {action.target} failed "
                f"({type(exc).__name__}); refusing to replay onto a "
                "server-assigned ID blind."
            ) from exc
        if isinstance(listing, Mapping):
            listing = listing.get("items")
        item_id = params[item_param]
        live = next(
            (
                item
                for item in (listing if isinstance(listing, list) else [])
                if isinstance(item, Mapping)
                and item_id
                in {
                    str(item.get("id", "")),
                    str(item.get(item_param, "")),
                }
            ),
            None,
        )
        if live is None:
            raise ReplayDispatchError(
                f"Item {item_id} has no live counterpart in the target "
                "organization; refusing to guess a replay target."
            )
        snapshot_name = action.payload.get("name")
        live_name = live.get("name")
        if (
            isinstance(snapshot_name, str) and snapshot_name
            and isinstance(live_name, str) and live_name
            and snapshot_name != live_name
        ):
            raise ReplayDispatchError(
                f"Item {item_id} exists live but names a different object "
                f"({live_name!r}, snapshot expects {snapshot_name!r}); the "
                "rebuilt tenant re-issued this ID — refusing to overwrite "
                "the wrong sibling."
            )

    def _already_present(
        self, action: ReplayAction, params: Mapping[str, str]
    ) -> bool:
        """Does the target already hold a same-named counterpart?

        Mirrors the restorer's crash-recovery adoption: the POST-only
        create's collection is read back and matched by name. Anything
        short of a usable answer (no lookup GET in the spec, no name in
        the payload, unreadable collection) keeps today's behavior and
        proceeds with the create — worst case the API rejects one
        duplicate per object, exactly as before.
        """
        op = action.lookup
        name = action.payload.get("name")
        if op is None or not isinstance(name, str) or not name:
            return False
        lookup_params: dict[str, str] = {}
        for param in _placeholders(op.path):
            if param not in params:
                return False
            lookup_params[param] = params[param]
        dashboard = self._dashboard()
        section = getattr(dashboard, op.tags[0], None) if op.tags else None
        method = (
            getattr(section, op.operation_id, None)
            if section is not None
            else None
        )
        if method is None:
            return False
        if not method_matches_verbs(method, READ_ONLY_SESSION_VERBS):
            # Never call a lookup that is not verifiably a read;
            # proceeding without the presence check is safe (worst case
            # the API rejects one duplicate create), calling a
            # mislabeled mutating method is not.
            logger.warning(
                "Already-present lookup %r for %s is not verifiably "
                "read-only; proceeding with the create.",
                op.operation_id, action.target,
            )
            return False
        try:
            listing = (
                method(**lookup_params, total_pages="all")
                if "total_pages" in inspect.signature(method).parameters
                else method(**lookup_params)
            )
        except Exception as exc:  # noqa: BLE001 - fall back to the POST
            logger.debug(
                "Already-present lookup for %s failed (%s); proceeding "
                "with the create.", action.target, exc,
            )
            return False
        if isinstance(listing, Mapping):
            listing = listing.get("items")
        return any(
            isinstance(item, Mapping) and item.get("name") == name
            for item in (listing if isinstance(listing, list) else [])
        )

    @staticmethod
    def _parameters(
        action: ReplayAction,
        target_organization_id: str,
        snapshot_organization_id: str,
        network_ids: Mapping[str, str],
        claimed_serials: frozenset[str] | None = None,
    ) -> dict[str, str]:
        """Path parameters for the write call, remapped to the live tenant."""
        def remap(value: str) -> str:
            if value == snapshot_organization_id:
                return target_organization_id
            return network_ids.get(value, value)

        placeholders = _placeholders(action.api_path)
        if len(placeholders) != len(action.path_values):
            raise ReplayDispatchError(
                f"Asset path {action.api_path} carries "
                f"{len(placeholders)} parameter(s) but "
                f"{len(action.path_values)} value(s) were discovered."
            )
        known = dict(zip(placeholders, (remap(v) for v in action.path_values)))
        known.setdefault("organizationId", target_organization_id)
        params: dict[str, str] = {}
        for name in _placeholders(action.operation.path):
            if name not in known:
                raise ReplayDispatchError(
                    f"Write operation {action.operation.operation_id} needs "
                    f"path parameter {name!r}, which the asset's address "
                    f"({action.api_path}) does not carry."
                )
            if name == "networkId" and known[name] not in network_ids.values():
                raise ReplayDispatchError(
                    f"Network {known[name]} has no live counterpart; refusing "
                    "to guess a replay target."
                )
            if name == "serial":
                # Same defense as networkId: device endpoints address
                # hardware wherever it is currently claimed — possibly
                # the still-alive source organization — so a serial not
                # verifiably claimed in the target org is refused.
                if claimed_serials is None:
                    raise ReplayDispatchError(
                        f"Cannot verify device {known[name]} is claimed in "
                        f"the target organization; refusing to replay a "
                        "device-scoped write blind."
                    )
                if known[name] not in claimed_serials:
                    raise ReplayDispatchError(
                        f"Device {known[name]} is not claimed in the target "
                        "organization; refusing to write to hardware "
                        "belonging to another organization."
                    )
            if name == "organizationId" and known[name] != target_organization_id:
                # Defense in depth: an org-scoped write may only ever hit
                # the named target org. A value the remap did not resolve
                # means the caller wired the wrong snapshot org — refuse
                # rather than write into a foreign (possibly production)
                # organization.
                raise ReplayDispatchError(
                    f"Organization {known[name]} is not the replay target "
                    f"({target_organization_id}); refusing to write into a "
                    "foreign organization."
                )
            params[name] = known[name]
        return params

    def _call(
        self,
        op: OperationSpec,
        params: Mapping[str, str],
        payload: Mapping[str, Any],
    ) -> Any:
        """Dispatch ``dashboard.<first tag>.<operationId>`` dynamically."""
        dashboard = self._dashboard()
        section = getattr(dashboard, op.tags[0], None) if op.tags else None
        method = (
            getattr(section, op.operation_id, None) if section is not None else None
        )
        if method is None:
            raise ReplayDispatchError(
                f"Meraki SDK exposes no method for operation "
                f"{op.operation_id!r} (tags={op.tags!r})."
            )
        if not method_matches_verbs(method, WRITE_SESSION_VERBS):
            raise ReplayDispatchError(
                f"SDK method {op.operation_id!r} resolved for this "
                f"{op.method.upper()} does not verifiably perform only "
                "put/post session calls; refusing to dispatch — the "
                "spec and the installed SDK disagree on what this "
                "operation does."
            )
        # Path parameters win over any payload field of the same name —
        # the payload echoes the snapshot tenant's identifiers.
        body = {key: value for key, value in payload.items() if key not in params}
        items = _collection_items(body)
        if items is not None:
            field = _single_array_body_field(op)
            if field is not None:
                body = {field: items}
        # GET echoes unset fields as null; the write endpoints reject
        # them ("'description' must be a string") — unset stays unset.
        body = _strip_nulls(body)
        body = shape_rules(op.path, body)
        accepted = inspect.signature(method).parameters
        if not any(
            p.kind is inspect.Parameter.VAR_KEYWORD for p in accepted.values()
        ):
            body = {key: value for key, value in body.items() if key in accepted}
        return method(**params, **body)


def split_redacted(
    payload: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Separate restorable attributes from sanitized-away secrets.

    ``**REDACTED**`` values cannot be written back — sending the marker
    string as live configuration (a nested RADIUS secret, a PEM
    certificate under a non-secret key) is worse than omitting the
    field — so they are stripped at **any** depth and returned as
    dotted re-entry paths. Secret-*named* attributes with real values
    (unsanitized snapshot) stay in the payload — restoring them is the
    whole point of the unsanitized DR snapshot.
    """
    redacted: set[str] = set()

    def clean_mapping(
        mapping: Mapping[str, Any], prefix: str
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in mapping.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if value == REDACTED:
                redacted.add(path)
                continue
            out[key] = clean_value(value, path)
        return out

    def clean_value(value: Any, prefix: str) -> Any:
        if isinstance(value, Mapping):
            return clean_mapping(value, prefix)
        if isinstance(value, list):
            kept = []
            for item in value:
                if item == REDACTED:
                    redacted.add(f"{prefix}[]")
                    continue
                kept.append(clean_value(item, f"{prefix}[]"))
            return kept
        return value

    return clean_mapping(payload, ""), tuple(sorted(redacted))


#: The sanitizer's by-value secret rule (sanitizer._clean_identity_
#: shaped): PEM private-key blocks are secrets no matter what key they
#: sit under (``certificate`` carries RADSEC/custom-cert keypairs).
_PEM_PRIVATE_KEY_MARKER = "PRIVATE KEY-----"


def _secret_value(value: Any) -> bool:
    """A scalar that can *be* a secret: a non-empty string or a number
    (numeric PINs/passcodes arrive as JSON numbers; booleans are flags
    like ``passwordEnabled``, never secrets)."""
    if isinstance(value, bool):
        return False
    return (isinstance(value, str) and bool(value)) or isinstance(
        value, (int, float)
    )


def _secret_paths(value: Any, prefix: str = "") -> tuple[str, ...]:
    """Dotted paths of non-empty secret values, any depth.

    Secret-keyed values plus the sanitizer's by-value PEM rule — what
    this reports must agree with what the sanitizer would redact. A
    secret-keyed list of scalars (``communityStrings: [...]``) counts
    as one secret path — the sanitizer redacts exactly that shape, so
    the replay/report side must see it too.
    """
    paths: list[str] = []
    if isinstance(value, Mapping):
        for key, inner in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if SECRET_KEY_PATTERN.search(str(key)) and _secret_value(inner):
                paths.append(path)
            elif (
                SECRET_KEY_PATTERN.search(str(key))
                and isinstance(inner, list)
                and any(_secret_value(item) for item in inner)
            ):
                paths.append(f"{path}[]")
            elif isinstance(inner, str) and _PEM_PRIVATE_KEY_MARKER in inner:
                paths.append(path)
            else:
                paths.extend(_secret_paths(inner, path))
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str) and _PEM_PRIVATE_KEY_MARKER in item:
                paths.append(f"{prefix}[]")
            else:
                paths.extend(_secret_paths(item, f"{prefix}[]"))
    return tuple(paths)


def _collection_items(payload: Mapping[str, Any]) -> list[Any] | None:
    """The wrapped item list when the payload is a collection envelope.

    Paginated GETs return ``{"items": [...], "meta": {...}}``; the
    envelope itself is never a writable body. Returns ``None`` for
    ordinary object payloads.
    """
    items = payload.get("items")
    if isinstance(items, list) and set(payload) <= {"items", "meta"}:
        return items
    return None


def _single_array_body_field(op: OperationSpec) -> str | None:
    """The write body's sole array field, when the schema has exactly one.

    Some write operations take a bare array body (the spec models it as
    a single array-typed property, e.g. ``_json`` for staged upgrade
    stages) — a collection envelope's items map onto it directly.
    """
    schema = (
        op.raw.get("requestBody", {})
        .get("content", {})
        .get("application/json", {})
        .get("schema", {})
    )
    properties = schema.get("properties", {})
    if len(properties) != 1:
        return None
    name, sub = next(iter(properties.items()))
    if isinstance(sub, Mapping) and sub.get("type") == "array":
        return str(name)
    return None


#: Synthetic rule rows Meraki appends to GET responses. The trailing
#: default rule exists on every firewall-style list; the wireless "LAN
#: access" row is the GET rendering of the SSID's allowLanAccess flag.
#: Neither is accepted back by the PUT (invalid destination / duplicate
#: rule), so GET-echo payloads must shed them before dispatch.
_DEFAULT_RULE_COMMENT = "Default rule"
_WIRELESS_LAN_ROW_COMMENT = "Wireless clients accessing LAN"
_SSID_L3_PATH_SUFFIX = "/wireless/ssids/{number}/firewall/l3FirewallRules"


def shape_rules(api_path: str, body: Any) -> Any:
    """Strip Meraki's synthetic rows from a rules-list payload.

    Drops a trailing "Default rule" row (the dashboard re-appends its
    own), and for wireless SSID L3 rules converts the synthetic
    "Wireless clients accessing LAN" row back into the
    ``allowLanAccess`` flag the PUT actually accepts.
    """
    if not isinstance(body, Mapping) or not isinstance(
        body.get("rules"), list
    ):
        return body
    rows = list(body["rules"])
    if (
        rows
        and isinstance(rows[-1], Mapping)
        and rows[-1].get("comment") == _DEFAULT_RULE_COMMENT
    ):
        rows = rows[:-1]
    shaped = dict(body)
    if api_path.endswith(_SSID_L3_PATH_SUFFIX):
        lan_rows = [
            row
            for row in rows
            if isinstance(row, Mapping)
            and row.get("comment") == _WIRELESS_LAN_ROW_COMMENT
        ]
        if lan_rows:
            rows = [row for row in rows if row not in lan_rows]
            shaped["allowLanAccess"] = lan_rows[0].get("policy") == "allow"
    shaped["rules"] = rows
    return shaped


def _strip_nulls(value: Any) -> Any:
    """Deep-copy ``value`` without null-valued or emptied-out entries.

    GET echoes pad unset sub-features with nulls; once those are
    stripped, the leftover empty object carries no data yet trips
    strict write validators (an SSID VPN PUT rejects a bare
    ``concentrator: {}`` with "Network not found"), so emptied mappings
    are dropped with their key. Empty *lists* stay: ``rules: []`` is a
    real instruction (clear the rules), not an artifact.
    """
    if isinstance(value, Mapping):
        cleaned = {
            key: _strip_nulls(inner)
            for key, inner in value.items()
            if inner is not None
        }
        return {
            key: inner
            for key, inner in cleaned.items()
            if not (isinstance(inner, Mapping) and not inner)
        }
    if isinstance(value, list):
        return [_strip_nulls(item) for item in value]
    return value


def _placeholders(path: str) -> tuple[str, ...]:
    """Ordered ``{parameter}`` names in a path template."""
    return tuple(
        segment[1:-1]
        for segment in path.split("/")
        if segment.startswith("{") and segment.endswith("}")
    )
