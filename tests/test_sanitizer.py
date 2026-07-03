"""Sanitization engine: secret redaction, identity pseudonymization,
consistent structural-ID mapping."""

from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.sanitizer import REDACTED, _GraphSanitizer, sanitize_graph


def _graph() -> NetworkGraph:
    return NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork("N_1", "org-123", "HQ", ("appliance", "wireless")),
            MerakiNetwork("N_2", "org-123", "", ()),
        ),
        devices=(MerakiDevice("QAAA-0001", "N_1", "MX64", "edge-fw"),),
        features=(
            FeatureConfiguration(
                api_path="/networks/{networkId}/wireless/ssids/{number}",
                path_values=("N_1", "0"),
                payload={
                    "name": "Corp WiFi",
                    "authMode": "psk",
                    "psk": "hunter2",
                    "passwordEnabled": True,
                    "emptySecret": "",
                    "communityString": "public",
                    "radiusServers": [{"host": "1.2.3.4", "secret": "radsecret"}],
                    "networkId": "N_1",
                    "adminSplashUrl": "https://dash.example/splash",
                    "tags": ["boston-office"],
                    "lat": 42.35,
                    "lng": -71.05,
                    "serials": ["QAAA-0001", "UNCLAIMED-9"],
                    "vlanId": 10,
                },
            ),
        ),
    )


def test_structural_ids_map_consistently_everywhere() -> None:
    sanitized = sanitize_graph(_graph())
    assert sanitized.organization_id == "org-0001"
    assert [n.network_id for n in sanitized.networks] == ["net-0001", "net-0002"]
    assert sanitized.networks[0].organization_id == "org-0001"
    assert sanitized.devices[0].serial == "dev-0001"
    assert sanitized.devices[0].network_id == "net-0001"
    feature = sanitized.features[0]
    assert feature.path_values == ("net-0001", "0")  # item IDs survive
    assert feature.payload["networkId"] == "net-0001"
    assert feature.payload["serials"][0] == "dev-0001"


def test_secrets_are_redacted_but_flags_keep_their_type() -> None:
    payload = sanitize_graph(_graph()).features[0].payload
    assert payload["psk"] == REDACTED
    assert payload["communityString"] == REDACTED
    assert payload["radiusServers"][0]["secret"] == REDACTED
    assert payload["passwordEnabled"] is True  # flag, not a credential
    assert payload["emptySecret"] == ""
    assert payload["authMode"] == "psk"  # a mode value, not a secret key


def test_identity_fields_are_pseudonymized() -> None:
    sanitized = sanitize_graph(_graph())
    assert sanitized.networks[0].name.startswith("network-")
    assert sanitized.networks[1].name == ""  # empty stays empty
    assert sanitized.devices[0].name.startswith("device-")
    payload = sanitized.features[0].payload
    assert payload["name"].startswith("name-")
    assert payload["adminSplashUrl"].startswith("adminsplashurl-")
    assert payload["tags"][0].startswith("tags-")
    # Unknown serials under a structural key get a consistent dev-NNNN
    # pseudonym (not a one-off digest), keeping references coherent.
    assert payload["serials"][1] == "dev-0002"
    assert payload["lat"] == 0.0 and payload["lng"] == 0.0
    assert payload["vlanId"] == 10  # structure preserved


def test_identity_shaped_values_are_scrubbed_regardless_of_key() -> None:
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                api_path="/networks/{networkId}/appliance/firewall/l3FirewallRules",
                path_values=("N_1",),
                payload={
                    "rules": [
                        {
                            "destCidr": "10.20.30.0/24",
                            "srcCidr": "Any",
                            "comment": "allow radius",
                        }
                    ],
                    "host": "1.2.3.4",
                    "fqdn": "intranet.corp.example",
                    "patterns": ["*.blocked.example", "https://portal.example/x"],
                    "bssid": "aa:bb:cc:dd:ee:ff",
                    "allowedList": "10.1.1.0/24, 10.2.2.0/24",
                    "fixedIpAssignments": {
                        "b4:7a:f1:3b:d2:8e": {"ip": "10.9.9.9", "name": "printer"}
                    },
                    "firmware": "wireless-29-5-1",
                    "timeZone": "Africa/Johannesburg",
                    "version": "1.72.0",
                },
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    rule = payload["rules"][0]
    assert rule["destCidr"].startswith("10.") and rule["destCidr"].endswith("/24")
    assert rule["srcCidr"] == "Any"  # semantic literal, not an address
    assert rule["comment"] == "allow radius"
    assert payload["host"].startswith("10.") and payload["host"] != "1.2.3.4"
    assert payload["fqdn"].startswith("host-")
    assert payload["patterns"][0].startswith("host-")
    assert payload["patterns"][1].startswith("url-")
    assert payload["bssid"].startswith("02:")
    # IPs embedded in free text (DHCP option strings) are rewritten.
    dhcp = sanitize_graph(
        NetworkGraph(
            "org-123", (), (),
            (
                FeatureConfiguration(
                    "/networks/{networkId}/appliance/vlans/{vlanId}",
                    ("N_1", "10"),
                    {"dhcpOptions": [{"type": "text", "code": "176",
                                      "value": "MCIPADD=10.9.9.9,MCPORT=1719"}]},
                ),
            ),
        )
    ).features[0].payload["dhcpOptions"][0]["value"]
    assert "10.9.9.9" not in dhcp
    assert "MCPORT=1719" in dhcp  # surrounding text preserved
    # Comma-separated address lists are sanitized element-wise, with the
    # authored spacing preserved so benign text round-trips unchanged.
    first, second = payload["allowedList"].split(",")
    assert first.startswith("10.") and second.startswith(" 10.")
    assert "10.1.1.0" not in payload["allowedList"]
    # Identity-shaped dict KEYS (fixed-IP assignments key on MACs) too.
    (mac_key, assignment), = payload["fixedIpAssignments"].items()
    assert mac_key.startswith("02:")
    assert assignment["ip"].startswith("10.") and assignment["ip"] != "10.9.9.9"
    # Version strings, firmware tags, and timezones keep their values.
    assert payload["firmware"] == "wireless-29-5-1"
    assert payload["timeZone"] == "Africa/Johannesburg"
    assert payload["version"] == "1.72.0"


def test_hostnames_with_paths_ports_and_trailing_dots_are_pseudonymized() -> None:
    """Scheme-less URL shapes carry real domains (and sometimes embedded
    secrets); they must not slip past the FQDN rule."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/contentFiltering",
                ("N_1",),
                {
                    "patterns": [
                        "example.com/path",
                        "example.com.",
                        "portal.example:8443/login",
                        "hooks.example.com/services/T0/B0/SECRETTOKEN",
                    ]
                },
            ),
        ),
    )
    patterns = sanitize_graph(graph).features[0].payload["patterns"]
    assert all(p.startswith("host-") for p in patterns)
    assert not any("example" in p or "SECRETTOKEN" in p for p in patterns)


def test_feature_only_structural_ids_are_pseudonymized() -> None:
    """Org/network IDs seen only in features (multi-org exports, partial
    snapshots) must not leak through --sanitize."""
    graph = NetworkGraph(
        organization_id="o1",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                api_path="/organizations/{organizationId}/admins/{adminId}",
                path_values=("654321", "A_1"),
                payload={"networkId": "N_998877", "email": "a@b.c"},
            ),
        ),
    )
    sanitized = sanitize_graph(graph).features[0]
    assert "654321" not in sanitized.path_values
    assert sanitized.path_values[0] == "org-0002"  # o1 took org-0001
    # Opaque item IDs are identifying and get a consistent pseudonym.
    assert sanitized.path_values[1].startswith("id-")
    # Structural references only seen inside payloads map too.
    assert sanitized.payload["networkId"] == "net-0001"


def test_numeric_item_path_values_are_preserved() -> None:
    """VLAN/SSID numbers are structure, not identity."""
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                api_path="/networks/{networkId}/appliance/vlans/{vlanId}",
                path_values=("N_1", "10"),
                payload={},
            ),
        ),
    )
    assert sanitize_graph(graph).features[0].path_values == ("net-0001", "10")


def test_long_numeric_item_path_values_are_identity() -> None:
    """All-numeric object IDs (adminId, optInId) must not survive."""
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                api_path="/organizations/{organizationId}/admins/{adminId}",
                path_values=("org-123", "2038677"),
                payload={"id": "2038677", "email": "a@b.c"},
            ),
        ),
    )
    sanitized = sanitize_graph(graph).features[0]
    assert sanitized.path_values[1].startswith("id-")
    # The payload's own echo of the ID maps to the same pseudonym.
    assert sanitized.payload["id"] == sanitized.path_values[1]


def test_payload_id_references_are_pseudonymized_consistently() -> None:
    """Opaque IDs seen only under *Id/*Ids payload keys must map too."""
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                api_path="/networks/{networkId}/appliance/vpn/bgp",
                path_values=("N_1",),
                payload={
                    "interfaceId": "1112223334445556679",
                    "policyIds": ["1112223334445556679", "opaque-ref"],
                    "vlanId": "10",  # short numeric stays structural
                    "ssid": "guest-net",  # not an ID-reference key
                },
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    assert payload["interfaceId"].startswith("id-")
    assert payload["policyIds"][0] == payload["interfaceId"]
    assert payload["policyIds"][1].startswith("id-")
    assert payload["vlanId"] == "10"
    assert payload["ssid"] == "guest-net"


def test_ipv6_addresses_are_pseudonymized() -> None:
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                api_path="/networks/{networkId}/appliance/firewall/l3FirewallRules",
                path_values=("N_1",),
                payload={
                    "rules": [
                        {"destCidr": "2001:db8:abcd::/48"},
                        {"destCidr": "fd00::1"},
                        {"destCidr": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
                    ],
                    "bssid": "aa:bb:cc:dd:ee:ff",  # MACs must stay MACs
                },
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    rules = payload["rules"]
    assert rules[0]["destCidr"].startswith("2001:db8:")
    assert rules[0]["destCidr"] != "2001:db8:abcd::/48"
    assert rules[0]["destCidr"].endswith("/48")  # prefix length preserved
    assert "fd00::1" != rules[1]["destCidr"]
    assert "85a3" not in rules[2]["destCidr"]
    assert payload["bssid"].startswith("02:")  # not eaten by the IPv6 rule


def test_sanitization_is_deterministic_and_non_destructive() -> None:
    graph = _graph()
    first = sanitize_graph(graph)
    second = sanitize_graph(graph)
    assert first == second
    # The input graph is left completely untouched.
    assert graph.features[0].payload["psk"] == "hunter2"
    assert graph.networks[0].name == "HQ"
    assert graph.organization_id == "org-123"


def test_structural_dict_keys_map_consistently() -> None:
    """Per-device maps key on serials; the key itself must pseudonymize."""
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(MerakiDevice("QAAA-0001", "N_1", "MX64", "edge-fw"),),
        features=(
            FeatureConfiguration(
                api_path="/networks/{networkId}/appliance/trafficShaping",
                path_values=("N_1",),
                payload={"QAAA-0001": {"limitUp": 0}},
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    assert payload == {"dev-0001": {"limitUp": 0}}


def test_empty_comma_list_parts_are_preserved() -> None:
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/trafficShaping",
                ("N_1",),
                {"allowedList": "10.1.1.0/24, , 10.2.2.0/24"},
            ),
        ),
    )
    cleaned = sanitize_graph(graph).features[0].payload["allowedList"]
    assert ", , " in cleaned  # the empty element survives untouched
    assert "10.1.1.0" not in cleaned


def test_keyless_scalars_pass_through_unchanged() -> None:
    """A payload that is not key-addressed has no rule to apply."""
    sanitizer = _GraphSanitizer(_graph())
    assert sanitizer._clean("free-floating", None) == "free-floating"
    assert sanitizer._clean("N_1", None) == "net-0001"  # IDs still map
