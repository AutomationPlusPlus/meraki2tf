"""Cross-network golden-config comparison: resolution, diff, rendering."""

import json

import pytest

from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.network_diff import (
    NetworkResolutionError,
    compare_networks,
    comparison_payload,
    render_network_comparison,
    resolve_network,
)

SECRET = "sup3r-s3cret-psk"


def _network(network_id: str, name: str) -> MerakiNetwork:
    return MerakiNetwork(
        network_id=network_id,
        organization_id="org-123",
        name=name,
        product_types=("appliance",),
    )


NETWORKS = (
    _network("N_1", "HQ"),
    _network("N_2", "Branch-07"),
    _network("N_3", "Branch-08"),
)


def _graph() -> NetworkGraph:
    features = (
        # Identical on both sides: never reported.
        FeatureConfiguration(
            api_path="/networks/{networkId}/appliance/trafficShaping",
            path_values=("N_1",),
            payload={"globalBandwidthLimits": {"limitUp": 0}},
        ),
        FeatureConfiguration(
            api_path="/networks/{networkId}/appliance/trafficShaping",
            path_values=("N_2",),
            payload={"globalBandwidthLimits": {"limitUp": 0}},
        ),
        # Present in both, different: one value change (a secret) and
        # one pure reordering of an order-significant list.
        FeatureConfiguration(
            api_path="/networks/{networkId}/syslogServers",
            path_values=("N_1",),
            payload={
                "psk": SECRET,
                "servers": [{"host": "10.0.0.1"}, {"host": "10.0.0.2"}],
            },
        ),
        FeatureConfiguration(
            api_path="/networks/{networkId}/syslogServers",
            path_values=("N_2",),
            payload={
                "psk": "other-secret",
                "servers": [{"host": "10.0.0.2"}, {"host": "10.0.0.1"}],
            },
        ),
        # Only in HQ / only in Branch-07 (nested IDs survive).
        FeatureConfiguration(
            api_path="/networks/{networkId}/appliance/vlans/{vlanId}",
            path_values=("N_1", "10"),
            payload={"id": 10, "name": "Data"},
        ),
        FeatureConfiguration(
            api_path="/networks/{networkId}/appliance/vlans/{vlanId}",
            path_values=("N_2", "20"),
            payload={"id": 20, "name": "Voice"},
        ),
        # Unreadable capture gap: excluded with a note, never diffed.
        FeatureConfiguration(
            api_path="/networks/{networkId}/sensor/relationships",
            path_values=("N_1",),
            payload={UNREADABLE_MARKER: "HTTP 500 after every retry"},
        ),
        # Device-scoped (serials differ by definition) and org-scoped
        # (shared by both networks): excluded classes.
        FeatureConfiguration(
            api_path="/devices/{serial}/switch/ports/{portId}",
            path_values=("S1", "1"),
            payload={"portId": "1"},
        ),
        FeatureConfiguration(
            api_path="/devices/{serial}/switch/ports/{portId}",
            path_values=("S2", "1"),
            payload={"portId": "1"},
        ),
        FeatureConfiguration(
            api_path="/organizations/{organizationId}/admins/{adminId}",
            path_values=("org-123", "A_1"),
            payload={"id": "A_1"},
        ),
        # A third network's feature: never leaks into an N_1-vs-N_2 diff.
        FeatureConfiguration(
            api_path="/networks/{networkId}/appliance/vlans/{vlanId}",
            path_values=("N_3", "30"),
            payload={"id": 30},
        ),
    )
    devices = (
        MerakiDevice(
            serial="S1", network_id="N_1", model="MS", name="sw-hq"
        ),
        MerakiDevice(
            serial="S2", network_id="N_2", model="MS", name="sw-branch"
        ),
        MerakiDevice(
            serial="S3", network_id="N_3", model="MS", name="sw-other"
        ),
    )
    return NetworkGraph(
        organization_id="org-123",
        networks=NETWORKS,
        devices=devices,
        features=features,
    )


def test_resolution_accepts_the_only_selector_prefix() -> None:
    # Muscle memory from --only: "network:HQ" resolves like bare "HQ".
    assert resolve_network(NETWORKS, "network:HQ").network_id == "N_1"
    assert resolve_network(NETWORKS, "NETWORK:N_1").network_id == "N_1"


def test_resolution_zero_match_lists_candidates() -> None:
    with pytest.raises(NetworkResolutionError, match="matched no network"):
        resolve_network(NETWORKS, "Datacenter-*")
    with pytest.raises(NetworkResolutionError, match="HQ \\(N_1\\)"):
        resolve_network(NETWORKS, "Nowhere")


def test_resolution_ambiguous_match_lists_the_hits() -> None:
    with pytest.raises(NetworkResolutionError) as excinfo:
        resolve_network(NETWORKS, "Branch-*")
    assert "ambiguous" in str(excinfo.value)
    assert "Branch-07 (N_2)" in str(excinfo.value)
    assert "Branch-08 (N_3)" in str(excinfo.value)


def test_resolution_matches_by_id_too() -> None:
    assert resolve_network(NETWORKS, "n_2").network_id == "N_2"


def test_same_network_on_both_sides_is_refused() -> None:
    with pytest.raises(NetworkResolutionError, match="same network"):
        compare_networks(_graph(), "HQ", "N_1")


def test_compare_networks_classifies_and_excludes() -> None:
    comparison = compare_networks(_graph(), "HQ", "Branch-07")
    diff = comparison.diff
    assert [f.path_values for f in diff.removed] == [("<network>", "10")]
    assert [f.path_values for f in diff.added] == [("<network>", "20")]
    assert len(diff.modified) == 1
    modified = diff.modified[0]
    assert modified.api_path == "/networks/{networkId}/syslogServers"
    assert sorted(modified.changed) == ["psk", "servers"]
    assert comparison.device_scoped_excluded == 2
    assert comparison.org_scoped_excluded == 1
    assert comparison.unreadable_excluded == 1


def test_render_names_attributes_but_never_values() -> None:
    comparison = compare_networks(_graph(), "HQ", "Branch-07")
    report = render_network_comparison(comparison)
    assert "Cross-network configuration diff: HQ (N_1) vs Branch-07 (N_2)" in report
    assert "1 feature(s) only in HQ (N_1)" in report
    assert "only in Branch-07 (N_2)" in report
    assert "(<singleton>): psk, servers (order changed)" in report
    assert "(10)" in report and "(20)" in report
    assert "2 device-scoped asset(s)" in report
    assert "1 organization-scoped asset(s)" in report
    assert "1 unreadable capture gap(s)" in report
    assert SECRET not in report
    assert "10.0.0.1" not in report


def test_payload_carries_names_and_order_flags_but_never_values() -> None:
    comparison = compare_networks(_graph(), "HQ", "Branch-07")
    payload = comparison_payload(comparison)
    rendered = json.dumps(payload)
    assert SECRET not in rendered
    assert payload["networkA"] == {"id": "N_1", "name": "HQ"}
    assert payload["onlyInA"] == [
        {
            "apiPath": "/networks/{networkId}/appliance/vlans/{vlanId}",
            "ids": ["10"],
        }
    ]
    assert payload["onlyInB"][0]["ids"] == ["20"]
    attributes = payload["modified"][0]["attributes"]
    assert {"name": "psk", "orderChanged": False} in attributes
    assert {"name": "servers", "orderChanged": True} in attributes
    assert payload["excluded"] == {
        "deviceScoped": 2,
        "orgScoped": 1,
        "unreadableGaps": 1,
    }


def test_identical_networks_render_the_empty_note() -> None:
    graph = NetworkGraph(
        organization_id="org-123",
        networks=NETWORKS,
        devices=(),
        features=(
            FeatureConfiguration(
                api_path="/networks/{networkId}/appliance/trafficShaping",
                path_values=("N_2",),
                payload={"limitUp": 0},
            ),
            FeatureConfiguration(
                api_path="/networks/{networkId}/appliance/trafficShaping",
                path_values=("N_3",),
                payload={"limitUp": 0},
            ),
        ),
    )
    comparison = compare_networks(graph, "Branch-07", "Branch-08")
    assert comparison.diff.is_empty
    report = render_network_comparison(comparison)
    assert "No differences in comparable network-scoped configuration." in report
