"""DR runbook: the per-run manual-rebuild companion to coverage.json.

Every pipeline run regenerates ``runbook.md`` in the workdir, mirroring
what discovery just found — never a stale copy. It documents, for a
human operator working a disaster, exactly what Terraform cannot
rebuild and how to put it back:

* one section per unsupported object — endpoint, identifiers, the
  reason it cannot be expressed, the discovered payload (secrets
  redacted), and the spec-derived write operation ``--replay-gaps``
  would use to restore it;
* one section for secret attributes the DR kit cannot carry (SSID
  PSKs, SNMP community strings, …) — which resources need them and
  where in the unsanitized snapshot the values live. Values are never
  printed here.

Everything is computed dynamically from the run's discovery graph and
the OpenAPI document (via the same parser that drives generation);
there are no hard-coded endpoint tables, per the project contract.
The runbook itself contains no credentials, so it is written with
normal file permissions — the *snapshot* it points at is the
secret-bearing artifact.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from meraki2tf.hcl_generator import CapturedAsset, UnsupportedAsset
from meraki2tf.models import NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser, entity_key, snake_case
from meraki2tf.sanitizer import REDACTED, SECRET_KEY_PATTERN
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)

RUNBOOK_FILENAME = "runbook.md"

#: Write verbs a replay can use to restore an object, in preference
#: order: an idempotent update beats a create when both exist.
_WRITE_METHOD_PRECEDENCE = ("put", "post")


def redact_payload(value: Any) -> Any:
    """Deep-copy ``value`` with every secret-keyed field redacted.

    Key-name detection matches the sanitizer's, so the runbook and
    shared snapshots agree on what counts as a credential.
    """
    if isinstance(value, Mapping):
        return {
            key: (
                REDACTED
                if SECRET_KEY_PATTERN.search(key) and isinstance(inner, str) and inner
                else redact_payload(inner)
            )
            for key, inner in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact_payload(item) for item in value]
    return value


def secret_payload_keys(payload: Mapping[str, Any]) -> tuple[str, ...]:
    """Top-level payload keys holding non-empty secret values."""
    return tuple(
        key
        for key, value in payload.items()
        if SECRET_KEY_PATTERN.search(key) and isinstance(value, str) and value
    )


def write_operations(
    parser: OpenApiParser,
) -> dict[str, tuple[OperationSpec, ...]]:
    """api_path → the entity's PUT/POST operations, best-first.

    Grouping is by entity key so an item path (``.../themes/{id}``)
    still finds the collection's POST. Precedence: an update on the
    asset's own path, then any update, then creates — replays should
    prefer idempotent writes.
    """
    by_entity: dict[tuple[str, ...], list[OperationSpec]] = {}
    for op in parser.endpoints():
        if op.method in _WRITE_METHOD_PRECEDENCE:
            by_entity.setdefault(entity_key(op.path), []).append(op)

    def resolve(path: str) -> tuple[OperationSpec, ...]:
        ops = by_entity.get(entity_key(path), [])
        return tuple(
            sorted(
                ops,
                key=lambda op: (
                    _WRITE_METHOD_PRECEDENCE.index(op.method),
                    op.path != path,
                    op.operation_id,
                ),
            )
        )

    return {
        path: resolve(path)
        for path in {op.path for op in parser.endpoints()}
    }


def payload_index(
    graph: NetworkGraph,
) -> dict[tuple[str, tuple[str, ...]], Mapping[str, Any]]:
    """(api_path, path_values) → discovered payload, for every feature."""
    return {
        (feature.api_path, feature.path_values): feature.payload
        for feature in graph.features
    }


def _fence(payload: Any) -> str:
    return "```json\n" + json.dumps(payload, indent=2, sort_keys=True) + "\n```"


def _secret_sources(
    captured: tuple[CapturedAsset, ...],
    unmanaged_secret_attributes: Mapping[str, tuple[str, ...]],
    payloads: Mapping[tuple[str, tuple[str, ...]], Mapping[str, Any]],
) -> list[tuple[str, tuple[str, ...], str, str]]:
    """(address, tf attrs, snapshot locator, payload keys) per resource.

    Terraform reports secret attributes in snake_case (``psk``,
    ``community_string``); the snapshot stores Meraki's camelCase keys
    (``psk``, ``communityString``). The two are joined through
    ``snake_case`` so the operator is pointed at the exact field.

    Sources are the union of the plan reconciliation's findings and a
    direct payload scan of every captured asset — keyed runs and
    air-gapped runs (which never plan) must produce the same runbook.
    """
    by_address = {asset.address: asset for asset in captured}
    merged: dict[str, tuple[str, ...]] = {
        asset.address: tuple(
            snake_case(key)
            for key in secret_payload_keys(
                payloads.get((asset.api_path, asset.identifiers), {})
            )
        )
        for asset in captured
    }
    merged = {address: attrs for address, attrs in merged.items() if attrs}
    merged.update(unmanaged_secret_attributes)
    rows: list[tuple[str, tuple[str, ...], str, str]] = []
    for address in sorted(merged):
        attrs = merged[address]
        asset = by_address.get(address)
        if asset is None:
            rows.append((address, attrs, "(not discovered this run)", "-"))
            continue
        payload = payloads.get((asset.api_path, asset.identifiers), {})
        wanted = set(attrs)
        keys = tuple(
            key for key in secret_payload_keys(payload) if snake_case(key) in wanted
        ) or tuple(attrs)
        locator = f"`{asset.api_path}` ids=`{','.join(asset.identifiers)}`"
        rows.append((address, attrs, locator, ", ".join(f"`{k}`" for k in keys)))
    return rows


def build_runbook(
    organization_id: str,
    graph: NetworkGraph,
    captured: tuple[CapturedAsset, ...],
    unsupported: tuple[UnsupportedAsset, ...],
    unmanaged_secret_attributes: Mapping[str, tuple[str, ...]],
    parser: OpenApiParser,
) -> str:
    """Render the manual-rebuild runbook markdown for this run."""
    payloads = payload_index(graph)
    ops = write_operations(parser)
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = [
        f"# Disaster-Recovery Runbook — organization {organization_id}",
        "",
        f"Generated {generated_at} by meraki2tf. Regenerated on every run —",
        "always use the copy from the latest snapshot.",
        "",
        "## How to use this document",
        "",
        "1. Restore Terraform-managed resources first:",
        "   `meraki2tf --rebuild --confirm --workdir <this directory>`.",
        "2. Replay the objects below from the unsanitized snapshot:",
        "   `meraki2tf --replay-gaps --from-dump <snapshot.json> --org-id "
        "<org>` (preview), then add `--confirm` to write.",
        "3. Anything marked **dashboard-only** must be recreated by hand",
        "   in the Meraki dashboard using the recorded payload.",
        "",
        "Secrets are never stored in this file — the replay reads them",
        "from the unsanitized snapshot at execution time. Guard that",
        "snapshot (and the Terraform state) like a password file.",
        "",
        f"## Objects Terraform cannot rebuild ({len(unsupported)})",
        "",
    ]
    if not unsupported:
        lines += ["None — every discovered object is covered by Terraform.", ""]
    for asset in sorted(unsupported, key=lambda a: (a.api_path, a.identifiers)):
        ids = ",".join(asset.identifiers) or "<none>"
        lines += [f"### `{asset.api_path}` — ids `{ids}`", ""]
        lines += [f"- **Why Terraform can't carry it:** {asset.reason}"]
        writes = ops.get(asset.api_path, ())
        if writes:
            best = writes[0]
            lines += [
                f"- **Replay operation:** `{best.method.upper()} {best.path}`"
                f" (`{best.operation_id}`) — automated by `--replay-gaps`."
            ]
        else:
            lines += [
                "- **Replay operation:** none in the API spec — "
                "**dashboard-only**, recreate by hand."
            ]
        payload = payloads.get((asset.api_path, asset.identifiers))
        if payload:
            lines += [
                "- **Discovered configuration (secrets redacted):**",
                "",
                _fence(redact_payload(payload)),
            ]
        else:
            lines += [
                "- **Discovered configuration:** not captured this run — "
                "see the snapshot file."
            ]
        lines += [""]

    secret_rows = _secret_sources(
        captured, unmanaged_secret_attributes, payloads
    )
    lines += [
        f"## Secret attributes to restore ({len(secret_rows)} resource(s))",
        "",
    ]
    if not secret_rows:
        lines += ["None — no unmanaged secret attributes this run.", ""]
    else:
        lines += [
            "The DR kit intentionally carries **no** secret values. After",
            "a rebuild, restore these from the unsanitized snapshot —",
            "`--replay-gaps --confirm` does this automatically (a",
            f"sanitized snapshot has them masked as `{REDACTED}` and",
            "cannot restore anything).",
            "",
            "| Terraform address | attribute(s) | snapshot location | payload key(s) |",
            "|---|---|---|---|",
        ]
        for address, attrs, locator, keys in secret_rows:
            lines += [
                f"| `{address}` | {', '.join(f'`{a}`' for a in attrs)} "
                f"| {locator} | {keys} |"
            ]
        lines += [""]
    return "\n".join(lines) + "\n"


def write_runbook(
    workdir: Path,
    organization_id: str,
    graph: NetworkGraph,
    captured: tuple[CapturedAsset, ...],
    unsupported: tuple[UnsupportedAsset, ...],
    unmanaged_secret_attributes: Mapping[str, tuple[str, ...]],
    parser: OpenApiParser,
) -> Path:
    """Write ``runbook.md`` into the workdir and return its path."""
    path = workdir / RUNBOOK_FILENAME
    path.write_text(
        build_runbook(
            organization_id=organization_id,
            graph=graph,
            captured=captured,
            unsupported=unsupported,
            unmanaged_secret_attributes=unmanaged_secret_attributes,
            parser=parser,
        ),
        encoding="utf-8",
    )
    secret_rows = _secret_sources(
        captured, unmanaged_secret_attributes, payload_index(graph)
    )
    logger.info(
        "DR runbook written: %s (%d unsupported object(s), %d resource(s) "
        "with secret attributes to restore).",
        path, len(unsupported), len(secret_rows),
    )
    return path
