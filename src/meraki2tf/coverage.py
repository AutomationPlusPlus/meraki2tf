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
- ``duplicate-id`` — its import ID is already carried by another
  captured object (rebuild-covered by that primary record); explicit
  so the totals account for every discovered object.

The manifest additionally carries spec-level accounting no graph object
can represent: write-only configuration endpoints (flagged as
``unsupported``), RPC-only action endpoints excluded by design
(``excluded_rpc_paths``), API surfaces that are read-only in Meraki
itself (``api_read_only_paths``), and endpoints every scope refused
this run (``suspect_endpoints``). Totals reconcile against the number
of objects discovery actually produced; any mismatch is reported as
``totals.unaccounted`` — a silent accounting hole is the worst failure
class under Cardinal Rule 2.

Payloads carry only resource identifiers and structural data — never
credentials.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from meraki2tf.fileio import atomic_write_text
from meraki2tf.hcl_generator import (
    IMPORTS_FILENAME,
    CapturedAsset,
    DuplicateAsset,
    UnsupportedAsset,
)
from meraki2tf.models import SuspectEndpoint

logger = logging.getLogger(__name__)

COVERAGE_JSON_FILENAME = "coverage.json"
COVERAGE_SUMMARY_FILENAME = "coverage.txt"

STATUS_IMPORTED = "imported"
STATUS_PENDING_IMPORT = "pending-import"
STATUS_UNSUPPORTED = "unsupported"
STATUS_DUPLICATE_ID = "duplicate-id"

#: Verdicts from :func:`verify_kit_fingerprint`. The manifest carries a
#: fingerprint of the ``imports.tf`` it was written beside; recomputing
#: and comparing it later answers whether the manifest and the kit still
#: agree. ``KIT_MATCH`` — they agree; ``KIT_MISMATCH`` — the kit was
#: edited, truncated, or vanished out from under the stamp (a corrupt DR
#: kit vouched for by a stale manifest, the Cardinal-Rule-2 gap this
#: closes); ``KIT_ABSENT`` — nothing to verify (a legacy manifest
#: predating the stamp, or an unreadable manifest that is its own
#: separate signal).
KIT_MATCH = "match"
KIT_MISMATCH = "mismatch"
KIT_ABSENT = "absent"


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
    scope_networks: tuple[str, ...] | None = None,
    duplicates: tuple[DuplicateAsset, ...] = (),
    discovered_assets: int | None = None,
    spec_gap_count: int = 0,
    relationship_gap_count: int = 0,
    excluded_rpc_paths: tuple[str, ...] = (),
    api_read_only_paths: tuple[str, ...] = (),
    suspect_endpoints: tuple[SuspectEndpoint, ...] = (),
) -> dict[str, Any]:
    """Assemble the coverage manifest for one completed run.

    ``state_addresses`` must reflect the state file *after* any
    sync-mode apply, so freshly materialized imports count as
    ``imported`` rather than ``pending-import``. ``restore_via`` maps
    ``(api_path, identifiers)`` to the direct-API restore verdict
    (``create``/``configure``/``claim`` or an ``unrestorable: reason``)
    so the manifest answers both questions: will Terraform import it,
    and will the API rebuild it. Every ``unsupported`` object carries a
    verdict either way: the ones with no graph object behind them
    (write-only endpoints and other spec-level findings) fall back to
    ``unrestorable`` with their own recorded reason, so a consumer
    reading the manual-rebuild list off ``restore_via`` never skips
    one.

    ``scope_networks`` marks a **partial** run (``--only`` selective
    backup, or a partial ``--from-dump`` input): the manifest then
    describes only the scoped networks, and both artifacts say so
    prominently — a plausible-looking full-coverage manifest that
    silently covered one network would violate Cardinal Rule 2.

    ``discovered_assets`` is the graph's own object count
    (``NetworkGraph.asset_count()``); the manifest reconciles it
    against ``captured + graph unsupported + duplicates`` (spec-level
    write-only findings, counted by ``spec_gap_count``, live in the
    unsupported list without being graph objects). A mismatch logs a
    WARNING and lands in ``totals.unaccounted`` — the manifest must
    never claim full coverage while objects fell through accounting.
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
    for raw, entry in zip(
        unsupported, unsupported_payload(unsupported), strict=True
    ):
        record = {"status": STATUS_UNSUPPORTED, **entry}
        verdict = restore_lookup.get((raw.api_path, raw.identifiers))
        if verdict is None:
            # Spec-level findings (write-only endpoints, unreadable
            # surfaces) are not graph objects, so the restore planner
            # never produced a verdict for them. Emitting the entry
            # without one would let a consumer that groups on
            # restore_via — the machine-readable form of the
            # manual-rebuild runbook — drop them silently, which is
            # exactly the blind spot Cardinal Rule 2 forbids. Nothing
            # was captured for them, so unrestorable is the honest
            # verdict, and their own recorded reason says why.
            verdict = f"unrestorable: {raw.reason}"
        record["restore_via"] = verdict
        objects.append(record)
    for duplicate in duplicates:
        objects.append(
            {
                "status": STATUS_DUPLICATE_ID,
                "api_path": duplicate.api_path,
                "import_id": duplicate.import_id,
                "identifiers": list(duplicate.identifiers),
                "primary_address": duplicate.primary_address,
            }
        )
    graph_unsupported = len(unsupported) - spec_gap_count
    accounted = len(captured) + graph_unsupported + len(duplicates)
    total = discovered_assets if discovered_assets is not None else accounted
    unaccounted = total - accounted
    # A duplicate is the same underlying object as its primary captured
    # record, so it counts as rebuild-covered — but never as silently
    # absent.
    covered = len(captured) + len(duplicates)
    totals: dict[str, Any] = {
        "discovered": total,
        "imported": imported,
        "pending_import": len(captured) - imported,
        "unsupported": graph_unsupported,
        "duplicate_id": len(duplicates),
        # spec_gap_count covers everything that is not a graph object;
        # the relationship share is named separately so a config-template
        # binding is never filed under "write-only endpoint".
        "write_only_endpoints": spec_gap_count - relationship_gap_count,
        "unmanageable_relationships": relationship_gap_count,
    }
    if unaccounted:
        logger.warning(
            "Coverage accounting mismatch: %d discovered object(s) but "
            "%d accounted for (captured + unsupported + duplicates); "
            "%d object(s) are unaccounted. The manifest carries "
            "totals.unaccounted — treat coverage claims as suspect "
            "until this is explained.",
            total, accounted, unaccounted,
        )
        totals["unaccounted"] = unaccounted
    manifest: dict[str, Any] = {
        "organization_id": organization_id,
        "totals": totals,
        "coverage_percent": round(100.0 * covered / total, 2) if total else 100.0,
        "objects": objects,
        #: Spec-derived visibility lists (Cardinal Rule 2): action
        #: endpoints excluded by design, and API surfaces that are
        #: read-only in Meraki itself — no tool can restore them.
        "excluded_rpc_paths": list(excluded_rpc_paths),
        "api_read_only_paths": list(api_read_only_paths),
        #: Endpoints that refused every scope tried this run (≥3):
        #: legitimate absence looks like this too, but a full-board
        #: refusal deserves eyes — an SDK/spec skew could otherwise
        #: hide a whole surface behind plausible 400s.
        "suspect_endpoints": [
            {
                "api_path": suspect.api_path,
                "scopes_tried": suspect.scopes_tried,
            }
            for suspect in suspect_endpoints
        ],
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
    if scope_networks is not None:
        manifest["scope"] = {
            "partial": True,
            "networks": sorted(scope_networks),
        }
    return manifest


def kit_fingerprint(workdir: Path) -> dict[str, Any] | None:
    """Fingerprint the workdir's ``imports.tf`` for the manifest stamp.

    A file-integrity stamp, deliberately independent of the manifest's
    own ``totals`` arithmetic: the point is to detect a kit that no
    longer matches the manifest vouching for it (a manual edit, a
    partial write, external tampering, or a pre-lock concurrent run),
    so it must be recomputed from the file's own bytes, never inferred
    from a count the manifest already carries.

    Returns ``None`` when ``workdir/imports.tf`` does not exist — a run
    with zero pending imports (or a default offline run) writes no kit,
    and there is nothing to fingerprint. Otherwise returns
    ``{"imports_sha256": <hex>, "import_block_count": <int>}``: the
    sha256 over the raw file bytes, and the number of ``import {}``
    blocks, counted from the stable block opener the generator emits
    (:mod:`~meraki2tf.hcl_generator` writes each block as a line equal
    to ``import {``). Reads bytes, decodes only for the line count, and
    raises nothing on well-formed input.
    """
    imports_path = workdir / IMPORTS_FILENAME
    if not imports_path.exists():
        return None
    raw = imports_path.read_bytes()
    text = raw.decode("utf-8", errors="replace")
    block_count = sum(
        1 for line in text.splitlines() if line.strip() == "import {"
    )
    return {
        "imports_sha256": hashlib.sha256(raw).hexdigest(),
        "import_block_count": block_count,
    }


def verify_kit_fingerprint(workdir: Path) -> tuple[str, str]:
    """Recompute the kit fingerprint and compare it to the manifest.

    Reads ``coverage.json`` and its recorded ``kit`` stamp, recomputes
    :func:`kit_fingerprint` from the live ``imports.tf``, and reports
    whether the two still agree. Returns ``(status, detail)`` where
    status is one of :data:`KIT_MATCH`, :data:`KIT_MISMATCH`,
    :data:`KIT_ABSENT` and detail is a human-readable explanation.

    Degrades rather than raises: a missing manifest, a legacy manifest
    written before this feature (no ``kit`` key), or an
    unreadable/corrupt manifest all return :data:`KIT_ABSENT` — a
    corrupt manifest is its own separate signal and must not crash the
    check. A recorded stamp whose ``imports.tf`` has since vanished is a
    :data:`KIT_MISMATCH` (the kit the manifest vouches for is gone), as
    is any divergence in the sha256 or the block count.
    """
    coverage_path = workdir / COVERAGE_JSON_FILENAME
    if not coverage_path.exists():
        return KIT_ABSENT, "no coverage.json in the workdir; nothing to verify"
    try:
        document = json.loads(coverage_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return KIT_ABSENT, f"coverage.json unreadable: {exc}"
    if not isinstance(document, dict) or "kit" not in document:
        return (
            KIT_ABSENT,
            "coverage.json carries no kit fingerprint "
            "(legacy manifest predating this stamp)",
        )
    recorded = document["kit"]
    current = kit_fingerprint(workdir)
    if current is None:
        return (
            KIT_MISMATCH,
            "coverage.json fingerprints a kit, but imports.tf is gone "
            "(the kit vanished out from under the manifest)",
        )
    recorded_hash = ""
    recorded_count: Any = None
    if isinstance(recorded, dict):
        recorded_hash = str(recorded.get("imports_sha256") or "")
        recorded_count = recorded.get("import_block_count")
    if (
        recorded_hash == current["imports_sha256"]
        and recorded_count == current["import_block_count"]
    ):
        return (
            KIT_MATCH,
            f"coverage.json matches imports.tf "
            f"({current['import_block_count']} import block(s))",
        )
    return (
        KIT_MISMATCH,
        f"recorded {recorded_count} block(s) / {recorded_hash or '<none>'}, "
        f"found {current['import_block_count']} block(s) / "
        f"{current['imports_sha256']}",
    )


def write_manifest(manifest: dict[str, Any], workdir: Path) -> tuple[Path, Path]:
    """Write coverage.json and its human-readable twin into the workdir.

    Before serialization the manifest is stamped with a fingerprint of
    the ``imports.tf`` the run just wrote beside it
    (:func:`kit_fingerprint`), under a ``kit`` key, so the stamp lands
    atomically inside the same ``coverage.json``. The stamp always
    matches at write time — the value is a *later* verification
    (:func:`verify_kit_fingerprint`, surfaced by ``--check``) detecting
    that the kit and manifest have since drifted apart. Runs that wrote
    no kit (zero pending imports) carry no ``kit`` key.
    """
    fingerprint = kit_fingerprint(workdir)
    if fingerprint is not None:
        manifest["kit"] = fingerprint
    json_path = workdir / COVERAGE_JSON_FILENAME
    atomic_write_text(
        json_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    summary_path = workdir / COVERAGE_SUMMARY_FILENAME
    atomic_write_text(summary_path, _render_summary(manifest))
    logger.info(
        "Coverage manifest written: %s and %s (%.2f%% of %d discovered "
        "object(s) covered by Terraform).",
        json_path,
        summary_path,
        manifest["coverage_percent"],
        manifest["totals"]["discovered"],
    )
    return json_path, summary_path


#: How many example locators a grouped unsupported line carries.
_GROUP_EXAMPLE_LIMIT = 3


def _grouped_unsupported_lines(unsupported: list[dict[str, Any]]) -> list[str]:
    """Unsupported entries grouped by (api_path, reason) for coverage.txt.

    A repeated endpoint used to print one line per object (11× the same
    staged-upgrade path), burying distinct gaps under repetition. Each
    group prints once with a count and up to three example locators;
    ``coverage.json`` stays fully itemized — this only condenses the
    human-readable twin. First-appearance order is preserved so the
    summary tracks the manifest.
    """
    groups: dict[tuple[str, str], list[str]] = {}
    for entry in unsupported:
        # Provider diagnostics can be multi-line; one entry must stay
        # one line so nothing reads as a separate report item.
        reason = " ".join(str(entry["reason"]).split())
        locator = f"ids={','.join(entry['identifiers']) or '<none>'}"
        groups.setdefault((str(entry["api_path"]), reason), []).append(locator)
    lines: list[str] = []
    for (api_path, reason), locators in groups.items():
        if len(locators) == 1:
            lines.append(f"  - {api_path} ({locators[0]}): {reason}")
            continue
        examples = "; ".join(locators[:_GROUP_EXAMPLE_LIMIT])
        overflow = len(locators) - _GROUP_EXAMPLE_LIMIT
        suffix = f" ...and {overflow} more" if overflow > 0 else ""
        lines.append(f"  - {api_path} ({len(locators)} objects): {reason}")
        lines.append(f"      e.g. {examples}{suffix}")
    return lines


def _render_summary(manifest: dict[str, Any]) -> str:
    totals = manifest["totals"]
    lines = [
        f"meraki2tf coverage report — organization {manifest['organization_id']}",
    ]
    scope = manifest.get("scope")
    if scope:
        networks = scope.get("networks", [])
        lines += [
            "",
            "*** PARTIAL RUN — this manifest covers ONLY "
            f"{len(networks)} selected network(s); it does NOT "
            "describe the organization's full coverage. ***",
            f"Scoped networks: {', '.join(networks) or '<none>'}",
        ]
    lines += [
        "",
        f"Discovered objects : {totals['discovered']}",
        f"  imported         : {totals['imported']} (tracked in Terraform state)",
        f"  pending-import   : {totals['pending_import']} (in the kit, not yet in state)",
        f"  unsupported      : {totals['unsupported']} (MANUAL rebuild required)",
        f"  duplicate-id     : {totals.get('duplicate_id', 0)} "
        "(covered by their primary record)",
        f"Coverage           : {manifest['coverage_percent']}%",
    ]
    if totals.get("unmanageable_relationships"):
        lines += [
            f"Plus unmanageable relationships : "
            f"{totals['unmanageable_relationships']} (config-template "
            "bindings no provider attribute expresses — listed below and "
            "counted separately from the objects above)",
        ]
    if totals.get("write_only_endpoints"):
        # Listed with the unsupported objects below but NOT part of the
        # `unsupported` count above, because they are endpoints rather
        # than discovered objects — so without this line the reader
        # counts more entries in that list than the total admits and
        # under-reads how much needs manual verification.
        lines += [
            f"Plus write-only endpoints : {totals['write_only_endpoints']} "
            "(never readable, so invisible to discovery — listed below "
            "and counted separately from the objects above)",
        ]
    if totals.get("unaccounted"):
        lines += [
            "",
            f"*** ACCOUNTING MISMATCH: {totals['unaccounted']} discovered "
            "object(s) are unaccounted for — coverage claims are suspect "
            "until this is explained. ***",
        ]
    unsupported = [
        entry for entry in manifest["objects"] if entry["status"] == STATUS_UNSUPPORTED
    ]
    if unsupported:
        lines += ["", "Objects Terraform cannot rebuild (manual DR runbook):"]
        lines += _grouped_unsupported_lines(unsupported)
    duplicate_entries = [
        entry
        for entry in manifest["objects"]
        if entry["status"] == STATUS_DUPLICATE_ID
    ]
    if duplicate_entries:
        lines += ["", "Duplicate import IDs (covered by their primary record):"]
        lines += [
            f"  - {entry['api_path']} "
            f"(ids={','.join(entry['identifiers']) or '<none>'}) "
            f"duplicates {entry['primary_address'] or '<unknown>'}"
            for entry in duplicate_entries
        ]
    suspects = manifest.get("suspect_endpoints") or []
    if suspects:
        lines += [
            "",
            "Suspect endpoints (refused by EVERY scope tried this run —",
            "verify these are genuinely not in use):",
        ]
        lines += [
            f"  - {entry['api_path']} ({entry['scopes_tried']} scope(s) tried)"
            for entry in suspects
        ]
    rpc_paths = manifest.get("excluded_rpc_paths") or []
    if rpc_paths:
        lines += [
            "",
            f"{len(rpc_paths)} RPC-style action endpoint(s) are excluded "
            "from discovery by design",
            "(one-shot actions, not configuration) — see coverage.json "
            "excluded_rpc_paths.",
        ]
    read_only = manifest.get("api_read_only_paths") or []
    if read_only:
        lines += [
            "",
            f"{len(read_only)} additional API surface(s) are read-only in "
            "the Meraki API",
            "(not restorable by any tool) — see coverage.json "
            "api_read_only_paths.",
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
