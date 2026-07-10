"""Domain model construction and payload validation."""

import pytest

from meraki2tf.models import (
    FeatureConfiguration,
    MalformedPayloadError,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
    coerce_sequence,
)


def test_network_from_payload() -> None:
    network = MerakiNetwork.from_payload(
        {
            "id": "N_1",
            "organizationId": "org-123",
            "name": "HQ",
            "productTypes": ["appliance", "switch"],
        }
    )
    assert network.network_id == "N_1"
    assert network.organization_id == "org-123"
    assert network.product_types == ("appliance", "switch")


def test_network_defaults_for_optional_fields() -> None:
    network = MerakiNetwork.from_payload({"id": "N_2"})
    assert network.name == ""
    assert network.product_types == ()


def test_network_requires_id() -> None:
    with pytest.raises(MalformedPayloadError):
        MerakiNetwork.from_payload({"name": "orphan"})


def test_device_from_payload() -> None:
    device = MerakiDevice.from_payload(
        {"serial": "Q2AB", "networkId": "N_1", "model": "MX64", "name": "edge"}
    )
    assert device.serial == "Q2AB"
    assert device.model == "MX64"


def test_device_requires_serial() -> None:
    with pytest.raises(MalformedPayloadError):
        MerakiDevice.from_payload({"model": "MX64"})


def test_graph_asset_count() -> None:
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(MerakiNetwork.from_payload({"id": "N_1"}),),
        devices=(MerakiDevice.from_payload({"serial": "Q2AB"}),),
        features=(FeatureConfiguration("/networks/{networkId}/x", ("N_1",)),),
    )
    assert graph.asset_count() == 3


def test_coerce_sequence_accepts_lists_and_none() -> None:
    assert coerce_sequence(None, "'x'") == ()
    assert coerce_sequence([1, 2], "'x'") == [1, 2]


@pytest.mark.parametrize("bad", ["string", {"a": 1}, 42])
def test_coerce_sequence_rejects_non_arrays(bad: object) -> None:
    with pytest.raises(MalformedPayloadError):
        coerce_sequence(bad, "'networks'")


def test_models_retain_complete_payloads_for_restore() -> None:
    """DR snapshots must be able to recreate networks/devices, not just
    address them — the full API object rides on the model."""
    network = MerakiNetwork.from_payload(
        {
            "id": "N_9",
            "organizationId": "org-1",
            "name": "Branch",
            "productTypes": ["appliance"],
            "timeZone": "America/New_York",
            "tags": ["dr-critical"],
            "isBoundToConfigTemplate": False,
        }
    )
    assert network.payload["timeZone"] == "America/New_York"
    assert network.payload["tags"] == ["dr-critical"]

    device = MerakiDevice.from_payload(
        {
            "serial": "Q2XX-XXXX-XXXX",
            "networkId": "N_9",
            "model": "MX68",
            "name": "edge",
            "address": "1 Main St",
            "lat": 42.1,
            "lng": -71.2,
            "floorPlanId": "fp-1",
        }
    )
    assert device.payload["address"] == "1 Main St"
    assert device.payload["floorPlanId"] == "fp-1"
