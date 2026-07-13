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
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)


class ReplayDispatchError(RuntimeError):
    """A replay operation could not be resolved onto the Meraki SDK."""


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
    actions: list[ReplayAction] = []
    skipped: list[SkippedReplay] = []

    for asset in sorted(report.unsupported, key=lambda a: (a.api_path, a.identifiers)):
        payload = payloads.get((asset.api_path, asset.identifiers))
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
            )
        )
    return tuple(actions), tuple(skipped)


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
    ) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
        """Perform the writes; every failure is recorded, never raised."""
        executed: list[str] = []
        failed: list[tuple[str, str]] = []
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
                self._call(action.operation, params, action.payload)
            except Exception as exc:  # per-object isolation by design
                message = str(exc)
                if action.kind == "secrets" and not isinstance(
                    exc, ReplayDispatchError
                ):
                    # The request body carried live secret values, and
                    # SDK error text can echo the rejected field back —
                    # keep it out of logs and alert payloads.
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
        return tuple(executed), tuple(failed)

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
    """Dotted paths of non-empty secret-keyed values, any depth.

    A secret-keyed list of scalars (``communityStrings: [...]``) counts
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
            else:
                paths.extend(_secret_paths(inner, path))
    elif isinstance(value, list):
        for item in value:
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


def _strip_nulls(value: Any) -> Any:
    """Deep-copy ``value`` without null-valued mapping entries."""
    if isinstance(value, Mapping):
        return {
            key: _strip_nulls(inner)
            for key, inner in value.items()
            if inner is not None
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
