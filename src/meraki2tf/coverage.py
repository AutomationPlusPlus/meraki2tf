"""Per-run coverage manifest: what is — and is not — in Terraform.

Cardinal Rule 2 of the project contract: the operator must always be
able to answer "what is and isn't covered by Terraform?" with 100%
certainty. Every run therefore writes a machine-readable
``coverage.json`` plus a human-readable ``coverage.txt`` into the
workdir, listing every discovered Meraki object with a status:

- ``imported`` — the resource address is tracked in the state file;
- ``pending-import`` — in the generated kit, not yet aggregated into
  state (normal snapshot growth);
- ``unsupported`` — Terraform cannot rebuild it (with the reason).
  This list is the manual-rebuild runbook after a disaster.

Payloads carry only resource identifiers and structural data — never
credentials.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from meraki2tf.hcl_generator import CapturedAsset, UnsupportedAsset

logger = logging.getLogger(__name__)

COVERAGE_JSON_FILENAME = "coverage.json"
COVERAGE_SUMMARY_FILENAME = "coverage.txt"

STATUS_IMPORTED = "imported"
STATUS_PENDING_IMPORT = "pending-import"
STATUS_UNSUPPORTED = "unsupported"


def unsupported_payload(assets: tuple[UnsupportedAsset, ...]) -> list[dict[str, Any]]:
    """JSON-ready detail rows for objects Terraform cannot rebuild."""
    return [
        {
            "api_path": asset.api_path,
            "reason": asset.reason,
            "identifiers": list(asset.identifiers),
        }
        for asset in assets
    ]


def build_manifest(
    organization_id: str,
    captured: tuple[CapturedAsset, ...],
    unsupported: tuple[UnsupportedAsset, ...],
    state_addresses: frozenset[str],
    deletions_pending: tuple[str, ...] = (),
    unmanaged_secret_attributes: dict[str, tuple[str, ...]] | None = None,
    restore_via: dict[tuple[str, tuple[str, ...]], str] | None = None,
) -> dict[str, Any]:
    """Assemble the coverage manifest for one completed run.

    ``state_addresses`` must reflect the state file *after* any
    sync-mode apply, so freshly materialized imports count as
    ``imported`` rather than ``pending-import``. ``restore_via`` maps
    ``(api_path, identifiers)`` to the direct-API restore verdict
    (``create``/``configure``/``claim`` or an ``unrestorable: reason``)
    so the manifest answers both questions: will Terraform import it,
    and will the API rebuild it.
    """
    restore_lookup = restore_via or {}
    objects: list[dict[str, Any]] = []
    imported = 0
    for asset in captured:
        in_state = asset.address in state_addresses
        imported += in_state
        entry = {
            "address": asset.address,
            "api_path": asset.api_path,
            "import_id": asset.import_id,
            "status": STATUS_IMPORTED if in_state else STATUS_PENDING_IMPORT,
        }
        verdict = restore_lookup.get((asset.api_path, asset.identifiers))
        if verdict is not None:
            entry["restore_via"] = verdict
        objects.append(entry)
    for raw, entry in zip(unsupported, unsupported_payload(unsupported)):
        record = {"status": STATUS_UNSUPPORTED, **entry}
        verdict = restore_lookup.get((raw.api_path, raw.identifiers))
        if verdict is not None:
            record["restore_via"] = verdict
        objects.append(record)
    total = len(objects)
    covered = len(captured)
    return {
        "organization_id": organization_id,
        "totals": {
            "discovered": total,
            "imported": imported,
            "pending_import": covered - imported,
            "unsupported": len(unsupported),
        },
        "coverage_percent": round(100.0 * covered / total, 2) if total else 100.0,
        "objects": objects,
        #: Resources tracked in the DR kit that discovery no longer sees
        #: in Meraki — awaiting human confirmation, never auto-removed.
        "deletions_pending_confirmation": list(deletions_pending),
        #: Secret attributes the DR kit cannot carry (the provider only
        #: accepts them write-only): restore manually after a rebuild.
        "unmanaged_secret_attributes": {
            address: list(attrs)
            for address, attrs in sorted(
                (unmanaged_secret_attributes or {}).items()
            )
        },
    }


def write_manifest(manifest: dict[str, Any], workdir: Path) -> tuple[Path, Path]:
    """Write coverage.json and its human-readable twin into the workdir."""
    json_path = workdir / COVERAGE_JSON_FILENAME
    json_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    summary_path = workdir / COVERAGE_SUMMARY_FILENAME
    summary_path.write_text(_render_summary(manifest), encoding="utf-8")
    logger.info(
        "Coverage manifest written: %s and %s (%.2f%% of %d discovered "
        "object(s) covered by Terraform).",
        json_path,
        summary_path,
        manifest["coverage_percent"],
        manifest["totals"]["discovered"],
    )
    return json_path, summary_path


def _render_summary(manifest: dict[str, Any]) -> str:
    totals = manifest["totals"]
    lines = [
        f"meraki2tf coverage report — organization {manifest['organization_id']}",
        "",
        f"Discovered objects : {totals['discovered']}",
        f"  imported         : {totals['imported']} (tracked in Terraform state)",
        f"  pending-import   : {totals['pending_import']} (in the kit, not yet in state)",
        f"  unsupported      : {totals['unsupported']} (MANUAL rebuild required)",
        f"Coverage           : {manifest['coverage_percent']}%",
    ]
    unsupported = [
        entry for entry in manifest["objects"] if entry["status"] == STATUS_UNSUPPORTED
    ]
    if unsupported:
        lines += ["", "Objects Terraform cannot rebuild (manual DR runbook):"]
        lines += [
            f"  - {entry['api_path']} "
            f"(ids={','.join(entry['identifiers']) or '<none>'}): {entry['reason']}"
            for entry in unsupported
        ]
    if manifest["deletions_pending_confirmation"]:
        lines += ["", "Deletions detected in Meraki awaiting human confirmation:"]
        lines += [
            f"  - {address}" for address in manifest["deletions_pending_confirmation"]
        ]
    if manifest.get("unmanaged_secret_attributes"):
        lines += ["", "Secrets not captured (restore manually after a rebuild):"]
        lines += [
            f"  - {address}: {', '.join(attrs)}"
            for address, attrs in manifest["unmanaged_secret_attributes"].items()
        ]
    return "\n".join(lines) + "\n"
