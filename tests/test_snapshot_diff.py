"""Snapshot-diff drift engine: keying, normalization, rollout suppression."""

from pathlib import Path

import pytest

from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.snapshot import write_snapshot
from meraki2tf.snapshot_diff import (
    AssetDiff,
    SanitizedBaselineError,
    _suppress_rollouts,
    baseline_drift,
    diff_graphs,
    render_diff,
)

VLAN_PATH = "/networks/{networkId}/appliance/vlans/{vlanId}"


def _graph(*features: FeatureConfiguration) -> NetworkGraph:
    return NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"], "timeZone": "UTC"}
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1",
                 "model": "MX68", "name": "edge"}
            ),
        ),
        features=features,
    )


def _vlan(vlan_id: str, **payload: object) -> FeatureConfiguration:
    return FeatureConfiguration(
        VLAN_PATH, ("N_1", vlan_id), {"id": vlan_id, **payload}
    )


def test_identical_graphs_diff_empty() -> None:
    diff = diff_graphs(_graph(_vlan("10", name="Data")),
                       _graph(_vlan("10", name="Data")))
    assert diff.is_empty
    assert diff.summary() == "0 added, 0 modified, 0 removed"


def test_added_removed_and_modified_assets_are_reported() -> None:
    previous = _graph(_vlan("10", name="Data"), _vlan("20", name="Voice"))
    current = _graph(_vlan("10", name="Data-renamed"), _vlan("30", name="IoT"))
    diff = diff_graphs(previous, current)
    assert [f.path_values for f in diff.added] == [("N_1", "30")]
    assert [f.path_values for f in diff.removed] == [("N_1", "20")]
    (mod,) = diff.modified
    assert mod.path_values == ("N_1", "10")
    assert mod.changed == {"name": ("Data", "Data-renamed")}


def test_network_and_device_payload_drift_is_detected() -> None:
    previous = _graph()
    current = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"], "timeZone": "Europe/Berlin"}
            ),
        ),
        devices=previous.devices,
        features=(),
    )
    diff = diff_graphs(previous, current)
    (mod,) = diff.modified
    assert mod.api_path == "/networks/{networkId}"
    assert mod.changed["timeZone"] == ("UTC", "Europe/Berlin")


def test_identity_keyed_lists_compare_order_insensitively() -> None:
    previous = _graph(
        _vlan("10", dhcpOptions=[{"id": "a", "v": 1}, {"id": "b", "v": 2}])
    )
    current = _graph(
        _vlan("10", dhcpOptions=[{"id": "b", "v": 2}, {"id": "a", "v": 1}])
    )
    assert diff_graphs(previous, current).is_empty


def test_bare_arrays_stay_order_sensitive() -> None:
    """Firewall-rule style lists: order IS the configuration."""
    previous = _graph(_vlan("10", rules=[{"policy": "allow"}, {"policy": "deny"}]))
    current = _graph(_vlan("10", rules=[{"policy": "deny"}, {"policy": "allow"}]))
    (mod,) = diff_graphs(previous, current).modified
    assert "rules" in mod.changed


def test_unreadable_assets_are_not_diffed() -> None:
    previous = _graph(
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {UNREADABLE_MARKER: "x"})
    )
    current = _graph(_vlan("10", name="Data"))
    assert diff_graphs(previous, current).modified == ()


def test_writable_field_filter_ignores_read_only_noise(tmp_path: Path) -> None:
    """Attributes absent from every PUT/POST schema are not
    configuration — computed counters must never page anyone."""
    import json

    from conftest import _op
    from meraki2tf.openapi_parser import OpenApiParser

    put = _op("updateNetworkApplianceVlan", "appliance")
    put["requestBody"] = {
        "content": {
            "application/json": {
                "schema": {"properties": {"name": {"type": "string"}}}
            }
        }
    }
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            VLAN_PATH: {"get": _op("getNetworkApplianceVlan", "appliance"),
                        "put": put},
        },
    }
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)

    previous = _graph(_vlan("10", name="Data", clientCount=5))
    current = _graph(_vlan("10", name="Data", clientCount=99))
    assert diff_graphs(previous, current, parser).is_empty

    renamed = _graph(_vlan("10", name="Data2", clientCount=99))
    (mod,) = diff_graphs(previous, renamed, parser).modified
    assert set(mod.changed) == {"name"}


def test_envelope_collections_diff_despite_the_writable_filter(
    tmp_path: Path,
) -> None:
    """Whole-collection assets live under the invented `items` key,
    which never appears in a write schema (the write body names its
    sole array property, e.g. `_json`); the writable filter must not
    silence drift on this entire endpoint class."""
    import json

    from conftest import _op
    from meraki2tf.openapi_parser import OpenApiParser

    stages = "/networks/{networkId}/firmwareUpgrades/staged/stages"
    put = _op("updateNetworkFirmwareUpgradesStagedStages", "networks")
    put["requestBody"] = {
        "content": {
            "application/json": {
                "schema": {"properties": {"_json": {"type": "array"}}}
            }
        }
    }
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            stages: {
                "get": _op("getNetworkFirmwareUpgradesStagedStages", "networks"),
                "put": put,
            },
        },
    }
    path = tmp_path / "stages-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)

    previous = _graph(
        FeatureConfiguration(stages, ("N_1",), {"items": [{"group": "a"}]})
    )
    current = _graph(
        FeatureConfiguration(
            stages, ("N_1",), {"items": [{"group": "a"}, {"group": "b"}]}
        )
    )
    (mod,) = diff_graphs(previous, current, parser).modified
    assert "items" in mod.changed

    assert diff_graphs(previous, previous, parser).is_empty


FIRMWARE_PATH = "/networks/{networkId}/firmwareUpgrades"


def _firmware(product: dict[str, object]) -> FeatureConfiguration:
    return FeatureConfiguration(
        FIRMWARE_PATH,
        ("N_1",),
        {
            "timezone": "US/Eastern",
            "participateInNextBetaRelease": False,
            "products": {"appliance": dict(product)},
        },
    )


def test_firmware_catalog_churn_is_not_drift() -> None:
    """A Cisco release changes availableVersions (and a completed
    upgrade changes currentVersion/lastUpgrade) on every network with
    zero operator involvement — the weekly loop must not page on it."""
    previous = _graph(
        _firmware(
            {
                "availableVersions": [{"id": "18842", "shortName": "MX 26.2.1"}],
                "currentVersion": {"id": "18800", "shortName": "MX 26.2"},
                "lastUpgrade": {"time": "2026-06-01T00:00:00Z"},
                "nextUpgrade": {"time": "", "toVersion": None},
            }
        )
    )
    current = _graph(
        _firmware(
            {
                "availableVersions": [{"id": "21104", "shortName": "MX 26.2.2"}],
                "currentVersion": {"id": "18842", "shortName": "MX 26.2.1"},
                "lastUpgrade": {"time": "2026-07-16T06:00:00Z"},
                "nextUpgrade": {"time": "", "toVersion": None},
            }
        )
    )
    assert diff_graphs(previous, current).is_empty


def test_firmware_scheduled_upgrade_is_still_drift() -> None:
    """nextUpgrade is operator-scheduled configuration; stripping the
    catalog noise must not silence it."""
    previous = _graph(_firmware({"nextUpgrade": {"time": "", "toVersion": None}}))
    current = _graph(
        _firmware(
            {
                "nextUpgrade": {
                    "time": "2026-08-01T04:00:00Z",
                    "toVersion": {"id": "21104", "shortName": "MX 26.2.2"},
                }
            }
        )
    )
    (mod,) = diff_graphs(previous, current).modified
    assert "products" in mod.changed


def test_volatile_strip_leaves_other_paths_untouched() -> None:
    from meraki2tf.snapshot_diff import _strip_volatile_subtrees

    payload = {"products": {"appliance": {"availableVersions": [1]}}}
    assert _strip_volatile_subtrees(VLAN_PATH, payload) == payload
    stripped = _strip_volatile_subtrees(FIRMWARE_PATH, payload)
    assert stripped == {"products": {"appliance": {}}}
    # the original payload is never mutated
    assert payload["products"]["appliance"]["availableVersions"] == [1]


def test_device_network_moves_are_drift(tmp_path: Path) -> None:
    """networkId is not in the device PUT schema (claims are separate
    endpoints), but a device re-homed between networks is exactly the
    drift the restore's claim wave depends on."""
    import json

    from conftest import _op
    from meraki2tf.openapi_parser import OpenApiParser

    put = _op("updateDevice", "devices")
    put["requestBody"] = {
        "content": {
            "application/json": {
                "schema": {"properties": {"name": {"type": "string"}}}
            }
        }
    }
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "t", "version": "1"},
        "paths": {
            "/devices/{serial}": {"get": _op("getDevice", "devices"),
                                  "put": put},
        },
    }
    path = tmp_path / "device-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)

    previous = _graph()
    current = NetworkGraph(
        organization_id="org-123",
        networks=previous.networks,
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_2",
                 "model": "MX68", "name": "edge"}
            ),
        ),
        features=(),
    )
    (mod,) = diff_graphs(previous, current, parser).modified
    assert mod.api_path == "/devices/{serial}"
    assert mod.changed["networkId"] == ("N_1", "N_2")


def test_population_wide_key_additions_are_suppressed_but_recorded() -> None:
    """A new attribute appearing on EVERY modified asset of one path is
    probably a Meraki rollout, not operator drift — but a dashboard bulk
    edit looks identical, so the suppression itself is returned for the
    alert digest (names and counts, never values)."""
    diffs = [
        AssetDiff(VLAN_PATH, ("N_1", str(i)), {"newField": (None, "x")})
        for i in range(12)
    ]
    diffs.append(
        AssetDiff(VLAN_PATH, ("N_1", "real"),
                  {"newField": (None, "x"), "name": ("a", "b")})
    )
    survivors, suppressed = _suppress_rollouts(diffs)
    (kept,) = survivors
    assert kept.path_values == ("N_1", "real")
    assert set(kept.changed) == {"name"}
    (rollout,) = suppressed
    assert rollout.api_path == VLAN_PATH
    assert rollout.attributes == ("newField",)
    assert rollout.asset_count == 13


def test_small_populations_are_never_treated_as_rollouts() -> None:
    diffs = [
        AssetDiff(VLAN_PATH, ("N_1", str(i)), {"newField": (None, "x")})
        for i in range(3)
    ]
    assert _suppress_rollouts(diffs) == (diffs, ())


def test_rollout_only_diffs_still_trigger_the_alert_path() -> None:
    """Cardinal Rule 2: a diff that is ONLY suppressed rollouts must not
    vanish — the caller keys the drift alert on is_empty, so it must be
    non-empty and the digest must carry a clearly labeled verification
    section with attribute names and counts, never values."""
    previous = _graph(*[_vlan(str(i), name=f"v{i}") for i in range(12)])
    current = _graph(
        *[_vlan(str(i), name=f"v{i}", newField="sekret") for i in range(12)]
    )
    diff = diff_graphs(previous, current)
    assert diff.modified == ()  # all changes were suppressed as rollout
    assert not diff.is_empty  # ... but the diff still alerts
    (rollout,) = diff.suppressed_rollouts
    assert rollout.attributes == ("newField",)
    assert rollout.asset_count == 12
    assert "suppressed as probable API rollouts" in diff.summary()

    text = render_diff(diff)
    assert "suppressed as probable API rollout" in text
    assert "verify these were NOT an operator bulk change" in text
    assert f"! {VLAN_PATH} (12 assets): newField" in text
    assert "sekret" not in text  # names and counts only, never values


def test_render_diff_omits_the_rollout_section_when_none_suppressed() -> None:
    previous = _graph(_vlan("10", name="Data"))
    current = _graph(_vlan("10", name="Data-renamed"))
    diff = diff_graphs(previous, current)
    assert diff.suppressed_rollouts == ()
    assert "rollout" not in render_diff(diff)
    assert "rollout" not in diff.summary()


def test_duplicate_asset_keys_warn_about_shadowed_drift(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Two assets sharing one identity key shadow each other (last
    wins); the loss of drift visibility must be loud, never silent."""
    duplicate = FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"name": "A"})
    shadowing = FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"name": "B"})
    graph = _graph(duplicate, shadowing)
    with caplog.at_level("WARNING", logger="meraki2tf.snapshot_diff"):
        diff_graphs(graph, graph)
    assert any("Duplicate asset key" in r.message for r in caplog.records)


def test_render_diff_is_secret_free_and_bounded() -> None:
    previous = _graph(*[_vlan(str(i), psk="hunter2") for i in range(60)])
    current = _graph(*[_vlan(str(i), psk="CHANGED") for i in range(60)])
    text = render_diff(diff_graphs(previous, current), limit=5)
    assert "hunter2" not in text and "CHANGED" not in text
    assert "psk" in text  # names what changed, never the values
    assert "more (see coverage artifacts)" in text


def test_non_mapping_payload_change_is_reported_whole() -> None:
    previous = _graph(
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"items": [1]})
    )
    current = _graph(
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"items": [2]})
    )
    (mod,) = diff_graphs(previous, current).modified
    assert "items" in mod.changed


def test_payload_changes_handles_non_mapping_payloads_directly() -> None:
    from meraki2tf.snapshot_diff import _payload_changes

    assert _payload_changes("same", "same", None) == {}
    assert _payload_changes("a", "b", None) == {"<payload>": ("a", "b")}


def test_list_length_change_is_drift() -> None:
    previous = _graph(_vlan("10", dhcpOptions=[{"id": "a"}]))
    current = _graph(_vlan("10", dhcpOptions=[{"id": "a"}, {"id": "b"}]))
    (mod,) = diff_graphs(previous, current).modified
    assert "dhcpOptions" in mod.changed


def test_render_diff_lists_added_and_removed_assets() -> None:
    previous = _graph(_vlan("10", name="Data"))
    current = _graph(_vlan("20", name="Voice"))
    text = render_diff(diff_graphs(previous, current))
    assert "+ " in text and "- " in text


def test_baseline_drift_refuses_sanitized_baselines(tmp_path: Path) -> None:
    """A sanitized snapshot's identifiers are pseudonyms; diffing them
    against the real org would report the whole org as added+removed —
    an alert storm, never meaningful drift. Refuse outright."""
    graph = _graph(_vlan("10", name="Data"))
    baseline = tmp_path / "baseline.json"
    write_snapshot(graph, baseline, sanitized=True)
    with pytest.raises(SanitizedBaselineError, match="'sanitized' marker"):
        baseline_drift(graph, baseline, parser=None)


def test_baseline_drift_diffs_against_unsanitized_baselines(
    tmp_path: Path,
) -> None:
    previous = _graph(_vlan("10", name="Data"))
    baseline = tmp_path / "baseline.json"
    write_snapshot(previous, baseline)
    diff = baseline_drift(
        _graph(_vlan("10", name="Data-renamed")), baseline, parser=None
    )
    (mod,) = diff.modified
    assert mod.changed == {"name": ("Data", "Data-renamed")}


def test_volatile_strip_leaves_non_mapping_products_untouched() -> None:
    """A product entry that is not an object (an API oddity or partial
    capture) has no volatile subtree to prune — it must survive as-is
    instead of crashing the weekly diff."""
    from meraki2tf.snapshot_diff import _strip_volatile_subtrees

    payload = {
        "timezone": "US/Eastern",
        "products": {"appliance": "unavailable"},
    }
    assert _strip_volatile_subtrees(FIRMWARE_PATH, payload) == payload
