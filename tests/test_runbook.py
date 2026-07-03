"""DR runbook: redaction, replay-op derivation, and rendering."""

from pathlib import Path

from meraki2tf.hcl_generator import CapturedAsset, UnsupportedAsset
from meraki2tf.models import FeatureConfiguration, NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.runbook import (
    RUNBOOK_FILENAME,
    build_runbook,
    payload_index,
    redact_payload,
    secret_attribute_union,
    secret_payload_keys,
    write_operations,
    write_runbook,
)
from meraki2tf.sanitizer import REDACTED

VLAN_PATH = "/networks/{networkId}/appliance/vlans/{vlanId}"
SSID_PATH = "/networks/{networkId}/wireless/ssids/{number}"
CLIENTS_PATH = "/networks/{networkId}/clients"


def _graph(*features: FeatureConfiguration) -> NetworkGraph:
    return NetworkGraph(
        organization_id="org-123", networks=(), devices=(), features=features
    )


def test_redact_payload_masks_secret_keys_recursively() -> None:
    payload = {
        "name": "Corp",
        "psk": "wifi-secret",
        "radius": [{"sharedKey": "radius-secret", "host": "1.2.3.4"}],
        "dot11w": {"password": "x", "enabled": True},
        "retries": 3,
    }
    clean = redact_payload(payload)
    assert clean["psk"] == REDACTED
    assert clean["radius"][0]["sharedKey"] == REDACTED
    assert clean["radius"][0]["host"] == "1.2.3.4"
    assert clean["dot11w"]["password"] == REDACTED
    assert clean["dot11w"]["enabled"] is True
    assert clean["name"] == "Corp"
    assert clean["retries"] == 3
    # the original is untouched
    assert payload["psk"] == "wifi-secret"


def test_redact_payload_leaves_non_string_and_empty_secret_values() -> None:
    clean = redact_payload({"tokenCount": 4, "psk": ""})
    assert clean == {"tokenCount": 4, "psk": ""}


def test_secret_payload_keys_detects_only_valued_string_secrets() -> None:
    keys = secret_payload_keys(
        {"psk": "s", "communityString": "c", "password": "", "name": "x", "port": 1}
    )
    assert keys == ("psk", "communityString")


def test_write_operations_prefers_update_on_own_path(
    spec_parser: OpenApiParser,
) -> None:
    ops = write_operations(spec_parser)
    assert ops[VLAN_PATH][0].operation_id == "updateNetworkApplianceVlan"
    # the collection path resolves the same entity's writes
    collection = "/networks/{networkId}/appliance/vlans"
    assert ops[collection][0].operation_id == "updateNetworkApplianceVlan"
    # a create-only entity yields its POST
    org_networks = "/organizations/{organizationId}/networks"
    assert ops[org_networks][0].method == "post"
    # a read-only endpoint has no write operations
    assert ops[CLIENTS_PATH] == ()


def test_payload_index_keys_by_path_and_values() -> None:
    feature = FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"name": "Data"})
    index = payload_index(_graph(feature))
    assert index[(VLAN_PATH, ("N_1", "10"))] == {"name": "Data"}


def test_secret_attribute_union_scans_payloads_and_prefers_plan() -> None:
    captured = (
        CapturedAsset(
            address="meraki_wireless_ssid.n_1_0",
            api_path=SSID_PATH,
            import_id="N_1,0",
            already_in_state=True,
            identifiers=("N_1", "0"),
        ),
        CapturedAsset(
            address="meraki_networks.n_1",
            api_path=VLAN_PATH,
            import_id="N_1,10",
            already_in_state=True,
            identifiers=("N_1", "10"),
        ),
    )
    payloads = payload_index(
        _graph(
            FeatureConfiguration(
                SSID_PATH, ("N_1", "0"), {"psk": "wifi-secret", "name": "Guest"}
            ),
            FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"name": "Data"}),
        )
    )
    # scan alone: only the ssid carries a secret-valued key
    assert secret_attribute_union(captured, {}, payloads) == {
        "meraki_wireless_ssid.n_1_0": ("psk",)
    }
    # plan-derived findings win for their address and merge in extras
    union = secret_attribute_union(
        captured,
        {
            "meraki_wireless_ssid.n_1_0": ("psk", "radius_secret"),
            "meraki_networks.n_1": ("snmp_auth_pass",),
        },
        payloads,
    )
    assert union == {
        "meraki_networks.n_1": ("snmp_auth_pass",),
        "meraki_wireless_ssid.n_1_0": ("psk", "radius_secret"),
    }


def test_build_runbook_covers_gaps_secrets_and_redaction(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"id": 10, "name": "Data"}),
        FeatureConfiguration(CLIENTS_PATH, ("N_1",), {"usage": 12}),
        FeatureConfiguration(
            SSID_PATH, ("N_1", "0"), {"number": 0, "psk": "wifi-secret"}
        ),
    )
    text = build_runbook(
        organization_id="org-123",
        graph=graph,
        captured=(
            CapturedAsset(
                address="meraki_wireless_ssid.n_1_0",
                api_path=SSID_PATH,
                import_id="N_1,0",
                already_in_state=True,
                identifiers=("N_1", "0"),
            ),
        ),
        unsupported=(
            UnsupportedAsset(VLAN_PATH, "no provider match", ("N_1", "10")),
            UnsupportedAsset(CLIENTS_PATH, "no provider match", ("N_1",)),
        ),
        unmanaged_secret_attributes={"meraki_wireless_ssid.n_1_0": ("psk",)},
        parser=spec_parser,
    )
    assert "Objects Terraform cannot rebuild (2)" in text
    assert "updateNetworkApplianceVlan" in text
    assert "dashboard-only" in text  # clients has no write operation
    assert '"name": "Data"' in text  # payload documented
    assert "wifi-secret" not in text  # never a secret value
    assert "meraki_wireless_ssid.n_1_0" in text
    assert "`psk`" in text
    assert f"ids=`{'N_1,0'}`" in text


def test_build_runbook_handles_empty_and_unlocatable_cases(
    spec_parser: OpenApiParser,
) -> None:
    clean = build_runbook(
        organization_id="org-123",
        graph=_graph(),
        captured=(),
        unsupported=(),
        unmanaged_secret_attributes={},
        parser=spec_parser,
    )
    assert "None — every discovered object is covered by Terraform." in clean
    assert "None — no unmanaged secret attributes this run." in clean

    orphaned = build_runbook(
        organization_id="org-123",
        graph=_graph(),
        captured=(),
        unsupported=(UnsupportedAsset(VLAN_PATH, "why", ("N_1", "10")),),
        unmanaged_secret_attributes={"meraki_network_snmp.gone": ("community_string",)},
        parser=spec_parser,
    )
    assert "not captured this run" in orphaned  # unsupported without payload
    assert "(not discovered this run)" in orphaned  # secret without asset


def test_write_runbook_places_file_in_workdir(
    spec_parser: OpenApiParser, tmp_path: Path
) -> None:
    path = write_runbook(
        workdir=tmp_path,
        organization_id="org-123",
        graph=_graph(),
        captured=(),
        unsupported=(),
        unmanaged_secret_attributes={},
        parser=spec_parser,
    )
    assert path == tmp_path / RUNBOOK_FILENAME
    assert "Disaster-Recovery Runbook — organization org-123" in path.read_text()


def test_runbook_secrets_derive_from_payloads_in_airgapped_runs(
    spec_parser: OpenApiParser,
) -> None:
    """No plan ran (no unmanaged map), yet the secrets section is complete."""
    graph = _graph(
        FeatureConfiguration(
            SSID_PATH, ("N_1", "0"), {"number": 0, "communityString": "s3cret"}
        ),
    )
    text = build_runbook(
        organization_id="org-123",
        graph=graph,
        captured=(
            CapturedAsset(
                address="meraki_wireless_ssid.n_1_0",
                api_path=SSID_PATH,
                import_id="N_1,0",
                already_in_state=False,
                identifiers=("N_1", "0"),
            ),
        ),
        unsupported=(),
        unmanaged_secret_attributes={},
        parser=spec_parser,
    )
    assert "Secret attributes to restore (1 resource(s))" in text
    assert "`community_string`" in text
    assert "s3cret" not in text
