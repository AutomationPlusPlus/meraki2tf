"""Selective-backup scope model: selector parsing, filtering, headers."""

import pytest

from meraki2tf.models import MerakiNetwork
from meraki2tf.scope import (
    LiveNetworkScope,
    ScopeFilterError,
    SnapshotScope,
    filter_networks,
    glob_pattern,
    parse_network_selectors,
)


def _network(network_id: str, name: str) -> MerakiNetwork:
    return MerakiNetwork(
        network_id=network_id,
        organization_id="org-123",
        name=name,
        product_types=("appliance",),
    )


NETWORKS = (
    _network("N_1", "Branch-07"),
    _network("N_2", "Branch-08"),
    _network("N_3", "HQ"),
)


def test_glob_pattern_is_case_insensitive_full_match() -> None:
    pattern = glob_pattern("branch-*")
    assert pattern.match("Branch-07")
    assert not pattern.match("My-Branch-07x") and not pattern.match("HQ")


def test_parse_network_selectors_accepts_both_spellings() -> None:
    parsed = parse_network_selectors(
        ["network:Branch-07", "Networks:HQ*"]
    )
    assert [raw for raw, _ in parsed] == ["network:Branch-07", "Networks:HQ*"]
    assert parsed[1][1].match("HQ")


@pytest.mark.parametrize(
    "selector",
    ["Branch-07", "ssid:Guest*", "", "   ", "network:"],
)
def test_parse_network_selectors_refuses_non_network_forms(
    selector: str,
) -> None:
    with pytest.raises(ScopeFilterError) as excinfo:
        parse_network_selectors([selector])
    assert "network:PATTERN" in str(excinfo.value)


def test_filter_networks_matches_name_and_id_union_deduped() -> None:
    selected = filter_networks(
        NETWORKS, ["network:branch-*", "network:N_1", "network:HQ"]
    )
    # Union across selectors, deduped, original discovery order kept.
    assert [n.network_id for n in selected] == ["N_1", "N_2", "N_3"]


def test_filter_networks_zero_match_lists_available_networks() -> None:
    with pytest.raises(ScopeFilterError) as excinfo:
        filter_networks(NETWORKS, ["network:Branch-*", "network:Warehouse*"])
    message = str(excinfo.value)
    assert "'network:Warehouse*'" in message
    assert "Branch-07 (N_1)" in message and "HQ (N_3)" in message


def test_filter_networks_zero_match_listing_truncates() -> None:
    many = tuple(_network(f"N_{i}", f"Site-{i:02d}") for i in range(20))
    with pytest.raises(ScopeFilterError) as excinfo:
        filter_networks(many, ["network:Nowhere"])
    message = str(excinfo.value)
    assert "Site-14 (N_14)" in message
    assert "Site-15" not in message
    assert "... and 5 more" in message


def test_filter_networks_zero_match_on_empty_org() -> None:
    with pytest.raises(ScopeFilterError) as excinfo:
        filter_networks((), ["network:HQ"])
    assert "(none)" in str(excinfo.value)


def test_snapshot_scope_from_header_round_trip() -> None:
    scope = SnapshotScope.from_header(
        {"networks": ["N_1", "N_2"], "selectors": ["network:Branch-*"]}
    )
    assert scope.network_ids == ("N_1", "N_2")
    assert scope.selectors == ("network:Branch-*",)


def test_snapshot_scope_from_header_selectors_optional() -> None:
    scope = SnapshotScope.from_header({"networks": ["N_1"]})
    assert scope.network_ids == ("N_1",)
    assert scope.selectors == ()


@pytest.mark.parametrize(
    "raw",
    [
        "not-a-dict",
        {"networks": "N_1"},
        {"networks": [42]},
        {"networks": ["N_1"], "selectors": "network:HQ"},
        {"networks": ["N_1"], "selectors": [1]},
        {},
    ],
)
def test_snapshot_scope_from_header_refuses_malformation(raw: object) -> None:
    with pytest.raises(ValueError):
        SnapshotScope.from_header(raw)


def test_live_scope_requires_exactly_one_form() -> None:
    with pytest.raises(ValueError):
        LiveNetworkScope()
    with pytest.raises(ValueError):
        LiveNetworkScope(
            selectors=("network:HQ",), network_ids=frozenset({"N_1"})
        )


def test_live_scope_selector_form_raises_on_zero_match() -> None:
    scope = LiveNetworkScope(selectors=("network:Nowhere",))
    with pytest.raises(ScopeFilterError):
        scope.apply(NETWORKS)


def test_live_scope_id_form_tolerates_deleted_networks() -> None:
    # The heal path: a scoped network deleted live is the maximal heal
    # case, never an input error.
    scope = LiveNetworkScope(network_ids=frozenset({"N_1", "N_gone"}))
    assert [n.network_id for n in scope.apply(NETWORKS)] == ["N_1"]
    assert scope.apply(()) == ()
