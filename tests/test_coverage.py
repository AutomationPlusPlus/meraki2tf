"""Coverage manifest: the operator's 'what is / isn't in Terraform' answer."""

import json
from pathlib import Path

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
