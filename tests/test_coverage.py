"""Coverage manifest: the operator's 'what is / isn't in Terraform' answer."""

import json
from pathlib import Path

import pytest

from meraki2tf.coverage import (
    COVERAGE_JSON_FILENAME,
    COVERAGE_SUMMARY_FILENAME,
    STATUS_IMPORTED,
    STATUS_PENDING_IMPORT,
    STATUS_UNSUPPORTED,
    build_manifest,
    unsupported_payload,
    write_manifest,
)
from meraki2tf.hcl_generator import CapturedAsset, UnsupportedAsset

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
