"""Coverage manifest: the operator's 'what is / isn't in Terraform' answer."""

import json
from pathlib import Path

import pytest

from meraki2tf.coverage import (
    COVERAGE_JSON_FILENAME,
    COVERAGE_SUMMARY_FILENAME,
    KIT_ABSENT,
    KIT_MATCH,
    KIT_MISMATCH,
    STATUS_IMPORTED,
    STATUS_PENDING_IMPORT,
    STATUS_UNSUPPORTED,
    build_manifest,
    kit_fingerprint,
    unsupported_payload,
    verify_kit_fingerprint,
    write_manifest,
)
from meraki2tf.hcl_generator import IMPORTS_FILENAME, CapturedAsset, UnsupportedAsset

#: Two well-formed import blocks, exactly as hcl_generator emits them.
_KIT_TWO_BLOCKS = (
    'import {\n  to = meraki_networks.n_1\n  id = "org-123,N_1"\n}\n'
    'import {\n  to = meraki_devices.q2ab\n  id = "Q2AB"\n}\n'
)

CAPTURED = (
    CapturedAsset(
        address="meraki_networks.n_1",
        api_path="/networks/{networkId}",
        import_id="N_1",
        already_in_state=True,
    ),
    CapturedAsset(
        address="meraki_devices.q2ab",
        api_path="/devices/{serial}",
        import_id="Q2AB",
        already_in_state=False,
    ),
)
UNSUPPORTED = (
    UnsupportedAsset(
        api_path="/networks/{networkId}/mystery",
        reason="No Terraform resource maps to this API path.",
        identifiers=("N_1",),
    ),
)


def test_build_manifest_statuses_totals_and_percentage() -> None:
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=UNSUPPORTED,
        state_addresses=frozenset({"meraki_networks.n_1"}),
        deletions_pending=("meraki_devices.gone",),
    )
    assert manifest["organization_id"] == "org-123"
    assert manifest["totals"] == {
        "discovered": 3,
        "imported": 1,
        "pending_import": 1,
        "unsupported": 1,
        "duplicate_id": 0,
        "write_only_endpoints": 0,
        "unmanageable_relationships": 0,
    }
    assert manifest["coverage_percent"] == 66.67
    by_status = {entry["status"] for entry in manifest["objects"]}
    assert by_status == {STATUS_IMPORTED, STATUS_PENDING_IMPORT, STATUS_UNSUPPORTED}
    unsupported_entry = next(
        entry
        for entry in manifest["objects"]
        if entry["status"] == STATUS_UNSUPPORTED
    )
    assert unsupported_entry["reason"] == UNSUPPORTED[0].reason
    assert unsupported_entry["identifiers"] == ["N_1"]
    assert manifest["deletions_pending_confirmation"] == ["meraki_devices.gone"]


def test_manifest_statuses_follow_the_final_state_not_generation_time() -> None:
    """A sync-applied import flips to imported even though generation saw
    it as new; state_addresses is authoritative."""
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=(),
        state_addresses=frozenset({"meraki_networks.n_1", "meraki_devices.q2ab"}),
    )
    assert manifest["totals"]["imported"] == 2
    assert manifest["totals"]["pending_import"] == 0
    assert manifest["coverage_percent"] == 100.0


def test_empty_discovery_is_full_coverage() -> None:
    manifest = build_manifest(
        organization_id="org-123",
        captured=(),
        unsupported=(),
        state_addresses=frozenset(),
    )
    assert manifest["coverage_percent"] == 100.0
    assert manifest["objects"] == []
    assert manifest["deletions_pending_confirmation"] == []


def test_unsupported_payload_is_json_ready() -> None:
    payload = unsupported_payload(UNSUPPORTED)
    assert json.loads(json.dumps(payload)) == payload
    assert payload[0]["api_path"] == "/networks/{networkId}/mystery"


def test_write_manifest_emits_machine_and_human_artifacts(tmp_path: Path) -> None:
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=UNSUPPORTED,
        state_addresses=frozenset({"meraki_networks.n_1"}),
        deletions_pending=("meraki_devices.gone",),
    )
    json_path, summary_path = write_manifest(manifest, tmp_path)

    assert json_path == tmp_path / COVERAGE_JSON_FILENAME
    assert summary_path == tmp_path / COVERAGE_SUMMARY_FILENAME
    assert json.loads(json_path.read_text(encoding="utf-8")) == manifest
    text = summary_path.read_text(encoding="utf-8")
    assert "org-123" in text
    assert "66.67%" in text
    # The unsupported list is the manual-rebuild runbook.
    assert "/networks/{networkId}/mystery" in text
    assert "No Terraform resource maps" in text
    assert "meraki_devices.gone" in text


def test_summary_omits_empty_sections(tmp_path: Path) -> None:
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=(),
        state_addresses=frozenset(),
    )
    _, summary_path = write_manifest(manifest, tmp_path)
    text = summary_path.read_text(encoding="utf-8")
    assert "cannot rebuild" not in text
    assert "Deletions" not in text


def test_manifest_carries_restore_verdicts() -> None:
    from meraki2tf.coverage import build_manifest
    from meraki2tf.hcl_generator import CapturedAsset, UnsupportedAsset

    captured = (
        CapturedAsset(
            address="meraki_appliance_vlan.n_1_10",
            api_path="/networks/{networkId}/appliance/vlans/{vlanId}",
            import_id="N_1,10",
            already_in_state=False,
            identifiers=("N_1", "10"),
        ),
    )
    unsupported = (
        UnsupportedAsset(
            api_path="/networks/{networkId}/clients",
            reason="no mapping",
            identifiers=("N_1",),
        ),
    )
    manifest = build_manifest(
        organization_id="org-123",
        captured=captured,
        unsupported=unsupported,
        state_addresses=frozenset(),
        restore_via={
            ("/networks/{networkId}/appliance/vlans/{vlanId}", ("N_1", "10")):
                "configure",
            ("/networks/{networkId}/clients", ("N_1",)):
                "unrestorable: dashboard-only",
        },
    )
    by_path = {obj["api_path"]: obj for obj in manifest["objects"]}
    assert by_path[
        "/networks/{networkId}/appliance/vlans/{vlanId}"
    ]["restore_via"] == "configure"
    assert by_path["/networks/{networkId}/clients"]["restore_via"] == (
        "unrestorable: dashboard-only"
    )


def test_spec_level_gaps_still_carry_a_restore_verdict() -> None:
    """An unsupported object with no restore verdict falls back to
    ``unrestorable`` rather than omitting the field.

    Regression (E2E r7): the 9 write-only endpoints are spec-level
    findings with no graph object, so the restore planner produced no
    verdict for them and the manifest emitted them with no
    ``restore_via`` key at all — a consumer reading the manual-rebuild
    list off that field skipped them silently.
    """
    unsupported = (
        UnsupportedAsset(
            api_path="/networks/{networkId}/sm/devices/fields",
            reason="write-only endpoint: the API offers no way to read "
                   "this configuration back",
            identifiers=(),
        ),
    )
    manifest = build_manifest(
        organization_id="org-123",
        captured=(),
        unsupported=unsupported,
        state_addresses=frozenset(),
        restore_via={},
        spec_gap_count=1,
    )
    (record,) = manifest["objects"]
    assert record["status"] == STATUS_UNSUPPORTED
    assert record["restore_via"].startswith("unrestorable: write-only")
    assert all("restore_via" in obj for obj in manifest["objects"])


def test_summary_counts_write_only_endpoints_beside_the_objects(
    tmp_path: Path,
) -> None:
    """The write-only endpoints listed under 'cannot rebuild' are also
    counted in the header.

    Regression (E2E r7): the header said 'unsupported: 26' while the
    list below it carried 35 entries, because the 9 write-only
    endpoints are counted separately in the JSON totals and had no line
    of their own in the summary.
    """
    unsupported = (
        UnsupportedAsset(
            api_path="/networks/{networkId}/mystery",
            reason="No Terraform resource maps to this API path.",
            identifiers=("N_1",),
        ),
        UnsupportedAsset(
            api_path="/networks/{networkId}/sm/devices/fields",
            reason="write-only endpoint: the API offers no way to read it",
            identifiers=(),
        ),
    )
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=unsupported,
        state_addresses=frozenset(),
        spec_gap_count=1,
    )
    write_manifest(manifest, tmp_path)
    summary = (tmp_path / COVERAGE_SUMMARY_FILENAME).read_text(encoding="utf-8")
    assert "unsupported      : 1 (MANUAL rebuild required)" in summary
    assert "Plus write-only endpoints : 1" in summary


def test_relationship_gaps_are_counted_apart_from_write_only_endpoints(
    tmp_path: Path,
) -> None:
    """A config-template binding is not a write-only endpoint.

    Both are gaps that are not discovered objects, so both live in
    spec_gap_count for reconciliation — but the manifest must name each
    for what it is rather than filing a binding under 'never readable'.
    """
    unsupported = (
        UnsupportedAsset(
            api_path="/networks/{networkId}/sm/devices/fields",
            reason="write-only endpoint: the API offers no way to read it",
            identifiers=(),
        ),
        UnsupportedAsset(
            api_path="/networks/{networkId}/bind",
            reason="the network is bound to a config template …",
            identifiers=("N_1",),
        ),
    )
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=unsupported,
        state_addresses=frozenset(),
        spec_gap_count=2,
        relationship_gap_count=1,
    )
    assert manifest["totals"]["write_only_endpoints"] == 1
    assert manifest["totals"]["unmanageable_relationships"] == 1
    write_manifest(manifest, tmp_path)
    summary = (tmp_path / COVERAGE_SUMMARY_FILENAME).read_text(encoding="utf-8")
    assert "Plus write-only endpoints : 1" in summary
    assert "Plus unmanageable relationships : 1" in summary


def test_partial_scope_stamps_manifest_and_summary(tmp_path: Path) -> None:
    """A scoped (--only) run must never leave a plausible-looking
    full-org manifest behind (Cardinal Rule 2): both artifacts carry
    the scope and a loud PARTIAL banner."""
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=(),
        state_addresses=frozenset(),
        scope_networks=("N_2", "N_1"),
    )
    assert manifest["scope"] == {"partial": True, "networks": ["N_1", "N_2"]}
    _, summary_path = write_manifest(manifest, tmp_path)
    text = summary_path.read_text(encoding="utf-8")
    assert "PARTIAL RUN" in text
    assert "2 selected network(s)" in text
    assert "N_1, N_2" in text


def test_full_runs_carry_no_scope_key() -> None:
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=(),
        state_addresses=frozenset(),
    )
    assert "scope" not in manifest


def test_duplicate_records_count_and_render(tmp_path: Path) -> None:
    """Duplicate import IDs are explicit records: in the objects list,
    in the totals, in the human summary — and counted as covered by
    their primary."""
    from meraki2tf.hcl_generator import DuplicateAsset

    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=(),
        state_addresses=frozenset(),
        duplicates=(
            DuplicateAsset(
                api_path="/networks/{networkId}",
                import_id="N_1",
                identifiers=("N_1",),
                primary_address="meraki_networks.n_1",
            ),
        ),
        discovered_assets=3,
    )
    assert manifest["totals"] == {
        "discovered": 3,
        "imported": 0,
        "pending_import": 2,
        "unsupported": 0,
        "duplicate_id": 1,
        "write_only_endpoints": 0,
        "unmanageable_relationships": 0,
    }
    assert manifest["coverage_percent"] == 100.0
    duplicate = next(
        entry
        for entry in manifest["objects"]
        if entry["status"] == "duplicate-id"
    )
    assert duplicate["primary_address"] == "meraki_networks.n_1"
    _, summary_path = write_manifest(manifest, tmp_path)
    text = summary_path.read_text(encoding="utf-8")
    assert "Duplicate import IDs" in text
    assert "duplicates meraki_networks.n_1" in text


def test_unaccounted_objects_warn_and_surface(
    tmp_path: Path, caplog: "pytest.LogCaptureFixture"
) -> None:
    """discovered != captured + unsupported + duplicates must never pass
    silently: WARNING + totals.unaccounted + a loud summary banner."""
    with caplog.at_level("WARNING", logger="meraki2tf.coverage"):
        manifest = build_manifest(
            organization_id="org-123",
            captured=CAPTURED,
            unsupported=(),
            state_addresses=frozenset(),
            discovered_assets=5,
        )
    assert any(
        "accounting mismatch" in record.message.lower()
        for record in caplog.records
    )
    assert manifest["totals"]["discovered"] == 5
    assert manifest["totals"]["unaccounted"] == 3
    _, summary_path = write_manifest(manifest, tmp_path)
    text = summary_path.read_text(encoding="utf-8")
    assert "ACCOUNTING MISMATCH: 3" in text


def test_spec_level_gaps_and_diagnostics_render(tmp_path: Path) -> None:
    """Write-only endpoints stay out of the graph totals (they are not
    discovered objects) but visible; RPC/read-only lists and suspect
    endpoints reach both artifacts."""
    from meraki2tf.models import SuspectEndpoint

    write_only = UnsupportedAsset(
        api_path="/networks/{networkId}/appliance/sdwan/internetPolicies",
        reason="write-only endpoint: the API offers no way to read this "
        "configuration back.",
        identifiers=(),
    )
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=UNSUPPORTED + (write_only,),
        state_addresses=frozenset(),
        discovered_assets=3,
        spec_gap_count=1,
        excluded_rpc_paths=("/devices/{serial}/blinkLeds",),
        api_read_only_paths=("/networks/{networkId}/sm/profiles",),
        suspect_endpoints=(
            SuspectEndpoint(
                api_path="/networks/{networkId}/wireless/billing",
                scopes_tried=4,
            ),
        ),
    )
    totals = manifest["totals"]
    assert totals["discovered"] == 3
    assert totals["unsupported"] == 1  # graph objects only
    assert totals["write_only_endpoints"] == 1
    assert "unaccounted" not in totals  # 2 captured + 1 unsupported = 3
    assert manifest["excluded_rpc_paths"] == ["/devices/{serial}/blinkLeds"]
    assert manifest["api_read_only_paths"] == [
        "/networks/{networkId}/sm/profiles"
    ]
    assert manifest["suspect_endpoints"] == [
        {
            "api_path": "/networks/{networkId}/wireless/billing",
            "scopes_tried": 4,
        }
    ]
    # The write-only endpoint is still an unsupported *record*.
    statuses = [
        entry["api_path"]
        for entry in manifest["objects"]
        if entry["status"] == STATUS_UNSUPPORTED
    ]
    assert "/networks/{networkId}/appliance/sdwan/internetPolicies" in statuses

    _, summary_path = write_manifest(manifest, tmp_path)
    text = summary_path.read_text(encoding="utf-8")
    assert "Suspect endpoints" in text
    assert "/networks/{networkId}/wireless/billing (4 scope(s) tried)" in text
    assert "1 RPC-style action endpoint(s) are excluded" in text
    assert "excluded_rpc_paths" in text
    assert "1 additional API surface(s) are read-only in" in text
    assert "api_read_only_paths" in text
    assert "internetPolicies" in text  # the manual-rebuild list carries it


def test_summary_groups_repeated_unsupported_gaps(tmp_path: Path) -> None:
    """Repeated (api_path, reason) gaps print once with a count and up
    to three example locators; coverage.json stays fully itemized."""
    staged = "/networks/{networkId}/firmwareUpgrades/staged/stages"
    repeated = tuple(
        UnsupportedAsset(
            api_path=staged,
            reason="Whole-list stage collections cannot round-trip.",
            identifiers=(f"N_{index}",),
        )
        for index in range(1, 6)
    )
    same_path_other_reason = UnsupportedAsset(
        api_path=staged,
        reason="A different reason keeps its own group.",
        identifiers=("N_9",),
    )
    manifest = build_manifest(
        organization_id="org-123",
        captured=(),
        unsupported=(*repeated, same_path_other_reason, *UNSUPPORTED),
        state_addresses=frozenset(),
    )
    _, summary_path = write_manifest(manifest, tmp_path)
    text = summary_path.read_text(encoding="utf-8")
    assert f"  - {staged} (5 objects): Whole-list stage" in text
    assert "e.g. ids=N_1; ids=N_2; ids=N_3 ...and 2 more" in text
    # The distinct-reason entry and the singleton keep per-object form.
    assert f"  - {staged} (ids=N_9): A different reason" in text
    assert "  - /networks/{networkId}/mystery (ids=N_1): No Terraform" in text
    # Exactly one grouped line for the repeated gap, not five.
    assert text.count("Whole-list stage collections") == 1
    # coverage.json remains fully itemized (one entry per object).
    itemized = [
        entry
        for entry in manifest["objects"]
        if entry["status"] == STATUS_UNSUPPORTED
        and entry["api_path"] == staged
    ]
    assert len(itemized) == 6


def test_summary_group_without_overflow_lists_all_examples(
    tmp_path: Path,
) -> None:
    duo = tuple(
        UnsupportedAsset(
            api_path="/networks/{networkId}/mystery",
            reason="same reason",
            identifiers=(f"N_{index}",),
        )
        for index in (1, 2)
    )
    manifest = build_manifest(
        organization_id="org-123",
        captured=(),
        unsupported=duo,
        state_addresses=frozenset(),
    )
    _, summary_path = write_manifest(manifest, tmp_path)
    text = summary_path.read_text(encoding="utf-8")
    assert "(2 objects): same reason" in text
    assert "e.g. ids=N_1; ids=N_2" in text
    assert "...and" not in text


# ---------------------------------------------------------------------------
# Kit fingerprint: coverage.json <-> imports.tf cross-stamp (Cardinal Rule 2)
# ---------------------------------------------------------------------------


def test_kit_fingerprint_hashes_and_counts_a_written_kit(tmp_path: Path) -> None:
    import hashlib

    raw = _KIT_TWO_BLOCKS.encode("utf-8")
    (tmp_path / IMPORTS_FILENAME).write_bytes(raw)

    fingerprint = kit_fingerprint(tmp_path)

    assert fingerprint == {
        "imports_sha256": hashlib.sha256(raw).hexdigest(),
        "import_block_count": 2,
    }


def test_kit_fingerprint_is_none_without_a_kit(tmp_path: Path) -> None:
    assert kit_fingerprint(tmp_path) is None


def test_kit_fingerprint_block_count_matches_known_kit(tmp_path: Path) -> None:
    block = 'import {\n  to = meraki_networks.n_%d\n  id = "N_%d"\n}\n'
    kit = "".join(block % (i, i) for i in range(5))
    (tmp_path / IMPORTS_FILENAME).write_text(kit, encoding="utf-8")

    fingerprint = kit_fingerprint(tmp_path)

    assert fingerprint is not None
    assert fingerprint["import_block_count"] == 5


def test_write_manifest_stamps_the_kit_fingerprint(tmp_path: Path) -> None:
    import hashlib

    raw = _KIT_TWO_BLOCKS.encode("utf-8")
    (tmp_path / IMPORTS_FILENAME).write_bytes(raw)
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=UNSUPPORTED,
        state_addresses=frozenset({"meraki_networks.n_1"}),
    )

    json_path, _ = write_manifest(manifest, tmp_path)

    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert document["kit"] == {
        "imports_sha256": hashlib.sha256(raw).hexdigest(),
        "import_block_count": 2,
    }


def test_write_manifest_omits_kit_without_a_kit(tmp_path: Path) -> None:
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=UNSUPPORTED,
        state_addresses=frozenset(),
    )

    json_path, _ = write_manifest(manifest, tmp_path)

    document = json.loads(json_path.read_text(encoding="utf-8"))
    assert "kit" not in document


def _stamped_workdir(tmp_path: Path) -> Path:
    (tmp_path / IMPORTS_FILENAME).write_text(_KIT_TWO_BLOCKS, encoding="utf-8")
    manifest = build_manifest(
        organization_id="org-123",
        captured=CAPTURED,
        unsupported=UNSUPPORTED,
        state_addresses=frozenset(),
    )
    write_manifest(manifest, tmp_path)
    return tmp_path


def test_verify_kit_fingerprint_matches_an_untouched_pair(
    tmp_path: Path,
) -> None:
    workdir = _stamped_workdir(tmp_path)

    status, detail = verify_kit_fingerprint(workdir)

    assert status == KIT_MATCH
    assert "2 import block(s)" in detail


def test_verify_kit_fingerprint_flags_an_edited_kit(tmp_path: Path) -> None:
    workdir = _stamped_workdir(tmp_path)
    # A tampering edit lands AFTER coverage.json was stamped.
    (workdir / IMPORTS_FILENAME).write_text(
        _KIT_TWO_BLOCKS
        + 'import {\n  to = meraki_networks.n_3\n  id = "N_3"\n}\n',
        encoding="utf-8",
    )

    status, detail = verify_kit_fingerprint(workdir)

    assert status == KIT_MISMATCH
    assert "recorded 2 block(s)" in detail
    assert "found 3 block(s)" in detail


def test_verify_kit_fingerprint_flags_a_vanished_kit(tmp_path: Path) -> None:
    workdir = _stamped_workdir(tmp_path)
    (workdir / IMPORTS_FILENAME).unlink()

    status, detail = verify_kit_fingerprint(workdir)

    assert status == KIT_MISMATCH
    assert "imports.tf is gone" in detail


def test_verify_kit_fingerprint_absent_on_legacy_manifest(
    tmp_path: Path,
) -> None:
    (tmp_path / IMPORTS_FILENAME).write_text(_KIT_TWO_BLOCKS, encoding="utf-8")
    (tmp_path / COVERAGE_JSON_FILENAME).write_text(
        json.dumps({"organization_id": "org-123"}), encoding="utf-8"
    )

    status, detail = verify_kit_fingerprint(tmp_path)

    assert status == KIT_ABSENT
    assert "legacy manifest" in detail


def test_verify_kit_fingerprint_absent_without_a_manifest(
    tmp_path: Path,
) -> None:
    status, detail = verify_kit_fingerprint(tmp_path)

    assert status == KIT_ABSENT
    assert "nothing to verify" in detail


def test_verify_kit_fingerprint_absent_on_corrupt_manifest(
    tmp_path: Path,
) -> None:
    (tmp_path / COVERAGE_JSON_FILENAME).write_text(
        "{not valid json", encoding="utf-8"
    )

    status, detail = verify_kit_fingerprint(tmp_path)

    assert status == KIT_ABSENT
    assert "unreadable" in detail


def test_verify_kit_fingerprint_absent_on_non_object_manifest(
    tmp_path: Path,
) -> None:
    (tmp_path / COVERAGE_JSON_FILENAME).write_text("[]", encoding="utf-8")

    status, _ = verify_kit_fingerprint(tmp_path)

    assert status == KIT_ABSENT


def test_verify_kit_fingerprint_mismatch_on_malformed_kit_stamp(
    tmp_path: Path,
) -> None:
    (tmp_path / IMPORTS_FILENAME).write_text(_KIT_TWO_BLOCKS, encoding="utf-8")
    (tmp_path / COVERAGE_JSON_FILENAME).write_text(
        json.dumps({"kit": "not-a-dict"}), encoding="utf-8"
    )

    status, detail = verify_kit_fingerprint(tmp_path)

    assert status == KIT_MISMATCH
    assert "<none>" in detail
