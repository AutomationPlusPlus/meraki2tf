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
    assert payload["serials"][1].startswith("serials-")  # unknown serial
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
    # Comma-separated address lists are sanitized element-wise.
    first, second = payload["allowedList"].split(",")
    assert first.startswith("10.") and second.startswith("10.")
    assert "10.1.1.0" not in payload["allowedList"]
    # Identity-shaped dict KEYS (fixed-IP assignments key on MACs) too.
    (mac_key, assignment), = payload["fixedIpAssignments"].items()
    assert mac_key.startswith("02:")
    assert assignment["ip"].startswith("10.") and assignment["ip"] != "10.9.9.9"
    # Version strings, firmware tags, and timezones keep their values.
    assert payload["firmware"] == "wireless-29-5-1"
    assert payload["timeZone"] == "Africa/Johannesburg"
    assert payload["version"] == "1.72.0"


def test_sanitization_is_deterministic_and_non_destructive() -> None:
    graph = _graph()
    first = sanitize_graph(graph)
    second = sanitize_graph(graph)
    assert first == second
    # The input graph is left completely untouched.
    assert graph.features[0].payload["psk"] == "hunter2"
    assert graph.networks[0].name == "HQ"
    assert graph.organization_id == "org-123"


def test_keyless_scalars_pass_through_unchanged() -> None:
    """A payload that is not key-addressed has no rule to apply."""
    sanitizer = _GraphSanitizer(_graph())
    assert sanitizer._clean("free-floating", None) == "free-floating"
    assert sanitizer._clean("N_1", None) == "net-0001"  # IDs still map
