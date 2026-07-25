"""Sanitization engine: secret redaction, identity pseudonymization,
consistent structural-ID mapping."""

from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
import ipaddress
import re
import stat
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.sanitizer import (
    REDACTED,
    _GraphSanitizer,
    load_or_create_salt,
    sanitize_graph,
)


def test_load_or_create_salt_persists_and_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "sanitizer.salt"  # parent created on demand
    first = load_or_create_salt(path)
    assert len(first) == 16
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    # A valid existing salt is reused verbatim (cross-run stability).
    assert load_or_create_salt(path) == first
    assert not path.with_name(path.name + ".tmp").exists()


def test_load_or_create_salt_cleans_up_the_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed atomic write must not leave a half-written temp salt
    behind to be mistaken for the real one later."""
    import meraki2tf.sanitizer as sanitizer_module

    path = tmp_path / "sanitizer.salt"

    def boom(src: Any, dst: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(sanitizer_module.os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        load_or_create_salt(path)
    assert not path.exists()
    assert not path.with_name(path.name + ".tmp").exists()


@pytest.mark.parametrize("content", ["", "  \n", "not-hex-content", "ab"])
def test_load_or_create_salt_regenerates_a_corrupt_or_empty_file(
    tmp_path: Path, content: str
) -> None:
    """An empty salt would silently defeat dictionary-inversion
    protection and a non-hex one must not crash every run; both are
    regenerated to a full-length salt rather than trusted."""
    path = tmp_path / "sanitizer.salt"
    path.write_text(content, encoding="utf-8")
    salt = load_or_create_salt(path)
    assert len(salt) == 16
    # The regenerated file is now valid and reused on the next call.
    assert load_or_create_salt(path) == salt


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


def test_secret_keyed_container_values_are_fully_redacted() -> None:
    """A secret-shaped key marks its whole subtree: a nested credentials
    object (whose inner keys are not secret-shaped) and a numeric
    passcode must not survive, and neither may a keyless list/string
    payload's PEM block."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/x",
                ("N_1",),
                {
                    "credentials": {"user": "jdoe", "pass": "hunter2"},
                    "sharedSecret": ["tok-abc", "tok-def"],
                    "pin": 123456789,
                },
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    raw = str(payload)
    assert "hunter2" not in raw and "tok-abc" not in raw
    assert "123456789" not in raw
    assert payload["credentials"]["pass"] == REDACTED
    assert payload["credentials"]["user"] == REDACTED  # whole subtree
    assert payload["sharedSecret"] == [REDACTED, REDACTED]
    assert payload["pin"] == REDACTED


def test_keyless_list_and_string_payloads_are_scrubbed() -> None:
    """A canonical snapshot may carry a list- or string-rooted payload;
    the value-shaped rules (PEM redaction, identity rewrites) still
    apply even though no key addresses the scalars."""
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n"
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration("/networks/{networkId}/a", ("N_1",),
                                 [pem, "jdoe@corp.example"]),
            FeatureConfiguration("/networks/{networkId}/b", ("N_1",), pem),
        ),
    )
    features = sanitize_graph(graph, salt=b"fixed").features
    assert features[0].payload[0] == REDACTED
    assert "jdoe" not in str(features[0].payload[1])
    assert features[1].payload == REDACTED


def test_extended_secret_keys_are_redacted() -> None:
    """SNMP v3 passes, PINs, passcodes, private keys, credentials, and
    license keys are credentials too and must never survive --sanitize."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/organizations/{organizationId}/snmp",
                ("org-123",),
                {
                    "v3AuthPass": "authpass1",
                    "v3PrivPass": "privpass1",
                    "simPin": "1234",
                    "passcode": "0000",
                    "privateKey": "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n",
                    "credentials": "svc:hunter2",
                    "licenseKey": "Z2AB-CDEF-GHIJ",
                    "pinEnabled": True,  # flag, not a credential
                },
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    for key in (
        "v3AuthPass", "v3PrivPass", "simPin", "passcode",
        "privateKey", "credentials", "licenseKey",
    ):
        assert payload[key] == REDACTED, key
    assert payload["pinEnabled"] is True


def test_meraki_catalog_uris_survive_sanitization() -> None:
    """An L7 rule's application id (`meraki:layer7/application/…`) is a
    global catalog URI, identical in every organization — pseudonymizing
    it breaks the dashboard's URI-format validation on restore drills."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/groupPolicies/{groupPolicyId}",
                ("N_1", "100"),
                {
                    "groupPolicyId": "100",
                    "name": "Guest-policy",
                    "firewallAndTrafficShaping": {
                        "l7FirewallRules": [
                            {
                                "policy": "deny",
                                "type": "application",
                                "value": {
                                    "id": "meraki:layer7/application/171",
                                    "name": "Video streaming",
                                },
                            }
                        ]
                    },
                },
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    rule = payload["firewallAndTrafficShaping"]["l7FirewallRules"][0]
    assert rule["value"]["id"] == "meraki:layer7/application/171"
    # the policy's own name is still pseudonymized
    assert payload["name"] != "Guest-policy"


def test_pem_private_keys_are_redacted_regardless_of_key() -> None:
    """A PEM private-key block under a non-secret-shaped key (e.g. a
    combined `certificate` blob) must still be redacted."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/wireless/radsec",
                ("N_1",),
                {"certificate": "-----BEGIN PRIVATE KEY-----\nMIIE\n"
                                "-----END PRIVATE KEY-----"},
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    assert payload["certificate"] == REDACTED


def test_phone_numbers_are_pseudonymized() -> None:
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/sm/devices",
                ("N_1",),
                {"phoneNumber": "+1 617 555 0100"},
            ),
        ),
    )
    # Fixed salt: the pseudonym is hex, and with a random salt a digest
    # containing the literal substring "617" (~0.3% of runs) would make
    # the not-in assertion flake.
    payload = sanitize_graph(graph, salt=b"fixed-test-salt!").features[0].payload
    assert payload["phoneNumber"].startswith("phonenumber-")
    assert "617" not in payload["phoneNumber"]


def test_identity_fields_are_pseudonymized() -> None:
    sanitized = sanitize_graph(_graph())
    assert sanitized.networks[0].name.startswith("network-")
    assert sanitized.networks[1].name == ""  # empty stays empty
    assert sanitized.devices[0].name.startswith("device-")
    payload = sanitized.features[0].payload
    assert payload["name"].startswith("name-")
    assert re.fullmatch(
        r"https://example\.com/url-[0-9a-f]{16}", payload["adminSplashUrl"]
    )
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
    # Hostname/URL pseudonyms keep their shape (firewall destinations
    # and webhook receivers validate them on restore).
    assert re.fullmatch(r"host-[0-9a-f]{16}\.invalid", payload["fqdn"])
    assert re.fullmatch(r"host-[0-9a-f]{16}\.invalid", payload["patterns"][0])
    assert re.fullmatch(
        r"https://example\.com/url-[0-9a-f]{16}", payload["patterns"][1]
    )
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


def test_prefixed_fake_addresses_are_valid_network_addresses() -> None:
    """Sanitized CIDRs feed restore drills: a fake subnet with host bits
    set ("10.7.9.3/24") fails strict API/parser validation, so prefixed
    values must be masked to their network address — deterministically."""
    import ipaddress

    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/firewall/l3FirewallRules",
                ("N_1",),
                {
                    "rules": [
                        {"destCidr": "192.168.10.0/24"},
                        {"destCidr": "10.20.0.0/16"},
                        {"destCidr": "2001:db8:abcd::/48"},
                        {"destCidr": "fd00:1234::/64"},
                    ],
                    "bareIp": "192.168.10.7",
                    "bareIpv6": "fd00::1",
                },
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    rules = [r["destCidr"] for r in payload["rules"]]
    for value, original in zip(
        rules,
        ["192.168.10.0/24", "10.20.0.0/16",
         "2001:db8:abcd::/48", "fd00:1234::/64"],
    ):
        assert value != original
        # Round-trips as a strictly valid network address, prefix kept.
        network = ipaddress.ip_network(value, strict=True)
        assert value.endswith(f"/{network.prefixlen}")
        assert original.endswith(f"/{network.prefixlen}")
    assert rules[0].startswith("10.")
    assert rules[2].startswith("2001:db8:")
    # Bare IPs (no prefix) stay valid single addresses.
    ipaddress.ip_address(payload["bareIp"])
    ipaddress.ip_address(payload["bareIpv6"])
    # Deterministic under one salt.
    again = sanitize_graph(graph, salt=b"fixed").features[0].payload
    assert again == payload


def test_impossible_prefix_lengths_keep_the_legacy_shape() -> None:
    """The value regex admits prefixes ipaddress rejects (/99); those
    keep the bare fake-address concatenation instead of crashing."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/x", ("N_1",),
                {"weird": "10.1.2.3/99"},
            ),
        ),
    )
    value = sanitize_graph(graph, salt=b"fixed").features[0].payload["weird"]
    assert value.startswith("10.") and value.endswith("/99")
    assert "10.1.2.3" not in value


def test_device_identity_keys_are_pseudonymized() -> None:
    """IMEI/ICCID/EID/MEID/MSISDN values are bare digit strings with no
    recognizable shape; the key rule must catch them like serials."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/organizations/{organizationId}/cellularGateway/esims/inventory",
                ("org-123",),
                {
                    "imei": "356938035643809",
                    "iccid": "8991101200003204510",
                    "eid": "89049032004008882600508297723225",
                    "meid": "35693803564380",
                    "msisdn": "14155550100",
                    "model": "MG21",  # non-identity config survives
                },
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    for key in ("imei", "iccid", "eid", "meid", "msisdn"):
        assert payload[key].startswith(f"{key}-"), key
    raw = str(payload)
    assert "356938035643809" not in raw and "8991101200003204510" not in raw
    assert payload["model"] == "MG21"


def test_numeric_id_references_are_pseudonymized_consistently() -> None:
    """ID references arriving as JSON numbers are the same identifiers
    as their string form and must map through the same pseudonym table
    (the pseudonym is a string — an acceptable JSON-type change for a
    sanitized structural replica)."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/vpn/bgp",
                ("N_1",),
                {
                    "interfaceId": "1112223334445556679",
                    "interfaceIdEcho": 1112223334445556679,
                    "adminId": 2038677111,
                    "networkId": 998877665544,  # structural key, numeric
                    "vlanId": 10,  # short numeric stays structure
                    "enabled": True,  # bools are ints — never IDs
                },
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    # The numeric echo maps to the SAME pseudonym as the string form.
    assert payload["interfaceIdEcho"] == payload["interfaceId"]
    assert payload["interfaceId"].startswith("id-")
    assert payload["adminId"].startswith("id-")
    # Numeric structural references get the same net-NNNN pseudonyms.
    assert payload["networkId"].startswith("net-")
    assert 1112223334445556679 not in payload.values()
    assert 998877665544 not in payload.values()
    assert payload["vlanId"] == 10
    assert payload["enabled"] is True
    # Determinism survives the type widening.
    again = sanitize_graph(graph, salt=b"fixed").features[0].payload
    assert again == payload


def test_string_and_numeric_references_obey_identical_rules() -> None:
    """The string and numeric arms share one rule set by construction.

    They used to be hand-mirrored branches; a rule added to one and not
    the other would leak a real identifier under whichever JSON type the
    writer happened to emit. Every reference kind is asserted through
    BOTH types so the arms can never drift apart again."""
    payload = {
        "networkId": "1234567890123",       # structural key
        "networkIdNum": 1234567890123,
        "interfaceId": "9876543210987",     # opaque …Id reference
        "interfaceIdNum": 9876543210987,
        "vlanId": "10",                     # short numeric = structure
        "vlanIdNum": 10,
        "shortName": "not-an-id",           # no reference key at all
    }
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/vpn/bgp", ("N_1",), payload
            ),
        ),
    )
    cleaned = sanitize_graph(graph, salt=b"fixed").features[0].payload
    # Same value, same pseudonym — whichever JSON type carried it.
    assert cleaned["networkIdNum"] == cleaned["networkId"]
    assert cleaned["interfaceIdNum"] == cleaned["interfaceId"]
    # Same exemptions, too: short numerics stay structural in both arms.
    assert cleaned["vlanId"] == "10"
    assert cleaned["vlanIdNum"] == 10
    # And nothing real survives either arm.
    assert "1234567890123" not in cleaned.values()
    assert 1234567890123 not in cleaned.values()


def test_pseudonyms_carry_64_bits_of_digest() -> None:
    """10 hex chars (40 bits) carries ~2% birthday-collision odds at the
    200k-object scale the v2 snapshot targets; 16 hex chars (64 bits)
    makes silent identity merges implausible."""
    sanitizer = _GraphSanitizer(_graph(), salt=b"fixed")
    pseudonym = sanitizer._pseudonym("host", "dc01.corp.example")
    prefix, digest = pseudonym.rsplit("-", 1)
    assert prefix == "host"
    assert len(digest) == 16
    int(digest, 16)  # pure hex


def test_sanitization_is_deterministic_and_non_destructive() -> None:
    graph = _graph()
    first = sanitize_graph(graph, salt=b"fixed-salt")
    second = sanitize_graph(graph, salt=b"fixed-salt")
    assert first == second
    # Pseudonyms are keyed by the salt: without it (a fresh random one
    # per call) they must not be reproducible — that irreproducibility
    # is what defeats dictionary inversion of the digests.
    assert sanitize_graph(graph) != first
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
    sanitizer = _GraphSanitizer(_graph(), salt=b"fixed-salt")
    assert sanitizer._clean("free-floating", None) == "free-floating"
    assert sanitizer._clean("N_1", None) == "net-0001"  # IDs still map
    assert sanitizer._clean(42, None) == 42  # numbers carry no identity


def test_network_and_device_payloads_are_sanitized() -> None:
    """The widened model payloads (restore-grade full API objects) must
    go through the same scrubbing as feature payloads."""
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {
                    "id": "N_1",
                    "organizationId": "org-123",
                    "name": "HQ",
                    "productTypes": ["appliance"],
                    "timeZone": "Europe/Berlin",
                    "notes": "contact jdoe",
                }
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {
                    "serial": "QAAA-0001",
                    "networkId": "N_1",
                    "model": "MX64",
                    "name": "edge-fw",
                    "communitySecret": "sn4ck",
                }
            ),
        ),
        features=(),
    )
    clean = sanitize_graph(graph)
    net_payload = dict(clean.networks[0].payload)
    dev_payload = dict(clean.devices[0].payload)
    # Structural IDs map consistently with the typed fields.
    assert net_payload["id"] == clean.networks[0].network_id
    assert dev_payload["serial"] == clean.devices[0].serial
    # Non-identifying config survives; secrets are redacted.
    assert net_payload["timeZone"] == "Europe/Berlin"
    assert dev_payload["communitySecret"] == REDACTED
    # Raw identifiers never survive in the payloads.
    assert "N_1" not in str(net_payload) and "QAAA-0001" not in str(dev_payload)


def test_known_ids_are_mapped_inside_comma_lists_and_free_text() -> None:
    """Structural IDs must not leak just because they sit inside a
    comma-separated list element or a free-text sentence — a real
    network ID anywhere in a shared snapshot identifies the tenant."""
    graph = NetworkGraph(
        "org-123", (MerakiNetwork("N_123456789012345", "org-123", "HQ", ()),), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/firewall/l3FirewallRules",
                ("N_123456789012345",),
                {
                    "objects": "N_123456789012345, other",
                    "comment": "temp rule for N_123456789012345 cutover",
                },
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    raw = str(payload)
    assert "N_123456789012345" not in raw
    assert payload["objects"].startswith("net-0001, ")
    assert "net-0001" in payload["comment"]


def test_fqdns_embedded_in_free_text_are_pseudonymized() -> None:
    """The docstring promises FQDN scrubbing wherever hostnames appear;
    rule comments are a common home for internal DC names."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/firewall/l3FirewallRules",
                ("N_1",),
                {"comment": "allow AD to dc01.corp.example from HQ"},
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    assert "dc01.corp.example" not in payload["comment"]
    assert "allow AD to host-" in payload["comment"]


def test_embedded_email_addresses_are_fully_pseudonymized() -> None:
    """An email under a generic key must lose its local part too — the
    FQDN rewrite alone would keep the username (`jsmith@host-…`)."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/snmp",
                ("N_1",),
                {
                    "contact": "jsmith@corp.example",
                    "description": "escalate to jdoe+oncall@ops.corp.example",
                },
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed-salt").features[0].payload
    raw = str(payload)
    assert "jsmith" not in raw and "jdoe" not in raw and "corp" not in raw
    # The fake must still parse as an email (Meraki validates recipients
    # on write, so the sanitized snapshot must stay restore-drillable)
    # and its own domain must survive the FQDN rewrite.
    assert re.fullmatch(r"user-[0-9a-f]{16}@drill\.invalid", payload["contact"])
    assert "escalate to user-" in payload["description"]
    assert "@drill.invalid" in payload["description"]
    # Deterministic under one salt: the same address maps to the same
    # pseudonym.
    again = sanitize_graph(graph, salt=b"fixed-salt").features[0].payload
    assert again == payload


def test_alert_recipient_lists_stay_valid_emails() -> None:
    """Pseudonymized recipients must pass Meraki's email validation."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/alerts/settings",
                ("N_1",),
                {"defaultDestinations": {"emails": ["noc@corp.example"]}},
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    (fake,) = payload["defaultDestinations"]["emails"]
    assert re.fullmatch(r"user-[0-9a-f]{16}@drill\.invalid", fake)


def test_keyword_path_selectors_survive_sanitization() -> None:
    """Pure-alpha path selectors (firewalledServices/{service}) are API
    keywords, not identity — pseudonymizing them 404s the restore."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/firewall/"
                "firewalledServices/{service}",
                ("N_1", "ICMP"),
                {"service": "ICMP", "access": "unrestricted"},
            ),
            FeatureConfiguration(
                "/networks/{networkId}/appliance/staticRoutes/{staticRouteId}",
                ("N_1", "d5f9e"),  # letters-and-digits opaque ID: still mapped
                {"id": "d5f9e"},
            ),
        ),
    )
    sanitized = sanitize_graph(graph)
    assert sanitized.features[0].path_values == ("net-0001", "ICMP")
    assert sanitized.features[0].payload["service"] == "ICMP"
    assert sanitized.features[1].path_values[1].startswith("id-")


def test_liquid_template_code_passes_through_verbatim() -> None:
    """Webhook payload templates are Liquid code; rewriting a dotted
    variable path renders the template unrestorable ('undefined
    variable host-…')."""
    body = (
        '{"text": "Alert from {{alertData.service.name}} at '
        'sensor.corp.example {% if alertLevel %}({{alertLevel}}){% endif %}"}'
    )
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/webhooks/payloadTemplates"
                "/{payloadTemplateId}",
                ("N_1", "wpt_1"),
                {"body": body},
            ),
        ),
    )
    payload = sanitize_graph(graph).features[0].payload
    assert "{{alertData.service.name}}" in payload["body"]
    assert "{% if alertLevel %}" in payload["body"]
    # Literal text between tags still gets the identity rewrites.
    assert "sensor.corp.example" not in payload["body"]


def test_fake_ips_keep_subnet_membership() -> None:
    """A VLAN subnet, its appliance IP, and a static route's next hop
    share a real /24, so their fakes must stay mutually coherent or the
    sanitized snapshot fails restore drills."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/vlans/{vlanId}",
                ("N_1", "10"),
                {"subnet": "192.168.128.0/24", "applianceIp": "192.168.128.1"},
            ),
            FeatureConfiguration(
                "/networks/{networkId}/appliance/staticRoutes/{staticRouteId}",
                ("N_1", "route1"),
                {"gatewayIp": "192.168.128.254", "subnet": "10.99.0.0/24"},
            ),
        ),
    )
    sanitized = sanitize_graph(graph)
    vlan = sanitized.features[0].payload
    route = sanitized.features[1].payload
    network = ipaddress.ip_network(vlan["subnet"])
    assert ipaddress.ip_address(vlan["applianceIp"]) in network
    assert ipaddress.ip_address(route["gatewayIp"]) in network
    assert "192.168.128" not in str(vlan) and "192.168.128" not in str(route)


def test_password_policy_keys_are_not_secrets() -> None:
    """Password *policy* settings (login security) are configuration,
    not credentials: redacting them makes the whole loginSecurity write
    unrestorable, while actual password fields must still vanish."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/organizations/{organizationId}/loginSecurity",
                ("org-123",),
                {
                    "numDifferentPasswords": 5,
                    "minimumPasswordLength": 12,
                    "passwordExpirationDays": 90,
                    "enforcePasswordExpiration": True,
                    "password": "hunter2",
                    "radiusPassword": "radpass1",
                    "psk": "wifikey99",
                    "passphrase": "opensesame",
                },
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    assert payload["numDifferentPasswords"] == 5
    assert payload["minimumPasswordLength"] == 12
    assert payload["passwordExpirationDays"] == 90
    assert payload["enforcePasswordExpiration"] is True
    for key in ("password", "radiusPassword", "psk", "passphrase"):
        assert payload[key] == REDACTED, key


def test_fake_urls_are_deterministic_and_distinct() -> None:
    """URL pseudonyms ride the digest in the path of the resolvable
    example.com apex (Meraki DNS-checks webhook hosts on write), stay
    stable per input, and never collide across inputs."""
    sanitizer = _GraphSanitizer(_graph(), salt=b"fixed")
    first = sanitizer._fake_url("https://hooks.example/services/T0/A")
    assert re.fullmatch(r"https://example\.com/url-[0-9a-f]{16}", first)
    assert sanitizer._fake_url("https://hooks.example/services/T0/A") == first
    assert sanitizer._fake_url("https://hooks.example/services/T0/B") != first


def test_included_payload_template_names_survive_verbatim() -> None:
    """Meraki's built-in webhook payload templates carry vendor names,
    not customer identity; pseudonymizing them breaks adopt-by-name on
    restore. Custom templates and unrelated included-typed objects still
    get their names pseudonymized."""
    template_path = (
        "/networks/{networkId}/webhooks/payloadTemplates/{payloadTemplateId}"
    )
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                template_path, ("N_1", "wpt_00001"),
                {"payloadTemplateId": "wpt_00001", "type": "included",
                 "name": "Slack (included)"},
            ),
            FeatureConfiguration(
                template_path, ("N_1", "wpt_9"),
                {"payloadTemplateId": "wpt_9", "type": "custom",
                 "name": "Corp Custom Template"},
            ),
            FeatureConfiguration(
                "/networks/{networkId}/somethingElse", ("N_1",),
                {"type": "included", "name": "Branch Office"},
            ),
        ),
    )
    features = sanitize_graph(graph, salt=b"fixed").features
    assert features[0].payload["name"] == "Slack (included)"
    assert features[1].payload["name"].startswith("name-")
    assert features[2].payload["name"].startswith("name-")
    # The exemption is name-only: the template's own ID still maps.
    assert features[0].payload["payloadTemplateId"].startswith("id-")


def test_included_template_reference_names_survive_verbatim() -> None:
    """A webhook receiver references its payload template by id + name
    WITHOUT the "type" marker; the dashboard rejects the pair when they
    disagree, so references to built-ins keep the vendor name verbatim
    too. References to custom templates stay pseudonymized (coherently
    with the pseudonymized template object)."""
    template_path = (
        "/networks/{networkId}/webhooks/payloadTemplates/{payloadTemplateId}"
    )
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                template_path, ("N_1", "wpt_00001"),
                {"payloadTemplateId": "wpt_00001", "type": "included",
                 "name": "Meraki (included)"},
            ),
            FeatureConfiguration(
                template_path, ("N_1", "wpt_9"),
                {"payloadTemplateId": "wpt_9", "type": "custom",
                 "name": "Corp Custom Template"},
            ),
            FeatureConfiguration(
                "/networks/{networkId}/webhooks/httpServers/{httpServerId}",
                ("N_1", "WH_1"),
                {"name": "receiver", "url": "https://hooks.corp.example/x",
                 "payloadTemplate": {"payloadTemplateId": "wpt_00001",
                                     "name": "Meraki (included)"}},
            ),
            FeatureConfiguration(
                "/networks/{networkId}/webhooks/httpServers/{httpServerId}",
                ("N_1", "WH_2"),
                {"name": "receiver2", "url": "https://hooks.corp.example/y",
                 "payloadTemplate": {"payloadTemplateId": "wpt_9",
                                     "name": "Corp Custom Template"}},
            ),
        ),
    )
    features = sanitize_graph(graph, salt=b"fixed").features
    included_ref = features[2].payload["payloadTemplate"]
    assert included_ref["name"] == "Meraki (included)"
    # The reference ID maps identically to the template object's own ID,
    # keeping the pair coherent after restore remapping.
    assert included_ref["payloadTemplateId"] == (
        features[0].payload["payloadTemplateId"]
    )
    custom_ref = features[3].payload["payloadTemplate"]
    assert custom_ref["name"].startswith("name-")
    # Coherent with the custom template object's pseudonymized name.
    assert custom_ref["name"] == features[1].payload["name"]


def test_spec_declared_credential_fields_are_redacted() -> None:
    """GET-visible credential fields whose names carry no classic
    secret-ish stem must still vanish: OSPF md5AuthenticationKey (the
    spec calls it "MD5 authentication credentials"), the coterm
    licensing endpoint's bare `key` ("The key of the license"), and SM
    software redemptionCode (redeemable VPP codes)."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/switch/routing/ospf",
                ("N_1",),
                {
                    "enabled": True,
                    "md5AuthenticationEnabled": True,
                    "md5AuthenticationKey": "ospfmd5",
                },
            ),
            FeatureConfiguration(
                "/organizations/{organizationId}/licensing/coterm/licenses",
                ("org-123",),
                {"key": "Z2XXXXXX-LICENSE-KEY", "counts": [{"count": 5}]},
            ),
            FeatureConfiguration(
                "/networks/{networkId}/sm/devices/{deviceId}/softwares",
                ("N_1", "D_1"),
                {"name": "App", "redemptionCode": "VPP-REDEEM-1234"},
            ),
        ),
    )
    cleaned = sanitize_graph(graph, salt=b"fixed").features
    assert cleaned[0].payload["md5AuthenticationKey"] == REDACTED
    assert cleaned[0].payload["enabled"] is True
    assert cleaned[1].payload["key"] == REDACTED
    assert cleaned[2].payload["redemptionCode"] == REDACTED


def test_enrollment_string_is_pseudonymized() -> None:
    """enrollmentString is a customer-chosen, globally unique SM slug —
    the public n.meraki.com/<slug> enrollment path — and identifies the
    organization as surely as its name does."""
    graph = NetworkGraph(
        "org-123",
        (
            MerakiNetwork(
                "N_1", "org-123", "HQ", (),
                payload={
                    "id": "N_1",
                    "name": "HQ",
                    "enrollmentString": "acme-corp-enroll",
                },
            ),
        ),
        (),
        (),
    )
    cleaned = sanitize_graph(graph, salt=b"fixed").networks[0]
    assert cleaned.payload["enrollmentString"] != "acme-corp-enroll"
    assert "acme" not in cleaned.payload["enrollmentString"]
    # Deterministic like every other pseudonym (cross-run stability).
    again = sanitize_graph(graph, salt=b"fixed").networks[0]
    assert again.payload["enrollmentString"] == cleaned.payload["enrollmentString"]


def test_certificate_pem_blocks_are_redacted() -> None:
    """Certificate/CSR PEM blocks are identity: their DER encodes the
    real Subject CN, Organization, and SAN hostnames. With private keys
    already redacted they are not restorable material, so they vanish
    like key blocks instead of shipping the org's PKI naming."""
    cert = (
        "-----BEGIN CERTIFICATE-----\nMIIBbase64identity\n"
        "-----END CERTIFICATE-----"
    )
    csr = (
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIBbase64identity\n"
        "-----END CERTIFICATE REQUEST-----"
    )
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/sm/devices/{deviceId}/certs",
                ("N_1", "D_1"),
                {"certPem": cert, "csrPem": csr, "certUsage": "keep-me"},
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    assert payload["certPem"] == REDACTED
    assert payload["csrPem"] == REDACTED
    assert payload["certUsage"] == "keep-me"


def test_default_fixed_slot_path_selector_survives() -> None:
    """The literal `default` fixed-slot selector (vlanProfiles/{iname}
    names its built-in profile "default") is identity-free — a
    pseudonym would make the slot unaddressable on restore. The
    placeholder is name-shaped, so only the special case saves it."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/vlanProfiles/{iname}",
                ("N_1", "default"),
                {"iname": "default", "name": "Default profile"},
            ),
        ),
    )
    cleaned = sanitize_graph(graph, salt=b"fixed").features[0]
    assert cleaned.path_values == ("net-0001", "default")
    # The profile's own iname echo stays addressable too, while the
    # display name is still pseudonymized.
    assert cleaned.payload["iname"] == "default"
    assert cleaned.payload["name"] != "Default profile"


def test_early_access_shortname_slugs_survive() -> None:
    """Early-access feature shortNames (`has_beta_api`) are API
    keywords the opt-in POST validates against a fixed list — a
    pseudonym would fail validation on restore."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/organizations/{organizationId}/earlyAccess/features"
                "/optIns/{optInId}",
                ("org-123", "opt-99887766"),
                {"shortName": "has_beta_api", "name": "Beta API access"},
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    assert payload["shortName"] == "has_beta_api"
    assert payload["name"] != "Beta API access"


def test_catalog_uris_survive_under_identity_shaped_keys() -> None:
    """Global catalog URIs (`meraki:…`) are identical in every
    organization — not identity — and a pseudonym fails the dashboard's
    URI-format validation on restore, even when the URI sits under an
    identity-shaped key."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/contentFiltering",
                ("N_1",),
                {"name": "meraki:contentFiltering/category/C7"},
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    assert payload["name"] == "meraki:contentFiltering/category/C7"


def _bare_sanitizer(salt: bytes = b"0123456789abcdef") -> _GraphSanitizer:
    return _GraphSanitizer(NetworkGraph("org-123", (), (), ()), salt)


def test_fake_networks_never_collide_across_distinct_real_subnets() -> None:
    """Two real /24s whose digest-derived first choice collides must map
    to DIFFERENT fake /24s: a silent merge breaks restore drills with
    subnet-overlap errors. The colliding head probes deterministically
    to the next free network; the first-seen head keeps the
    digest-derived choice the format has always used."""
    sanitizer = _bare_sanitizer()

    def start_index(head: str) -> int:
        first, second = sanitizer._digest_bytes(head)[:2]
        return (first % 254) * 254 + (second % 254)

    seen: dict[int, str] = {}
    collision: tuple[str, str] | None = None
    for third in range(5000):
        head = f"172.{third // 250}.{third % 250}"
        index = start_index(head)
        if index in seen:
            collision = (seen[index], head)
            break
        seen[index] = head
    assert collision is not None  # birthday odds guarantee one by ~600
    first_head, second_head = collision
    fake_first = sanitizer._fake_ip(f"{first_head}.9", "")
    fake_second = sanitizer._fake_ip(f"{second_head}.9", "")
    # First-seen head keeps the legacy digest-derived network.
    a, b = sanitizer._digest_bytes(first_head)[:2]
    assert fake_first == f"10.{a % 254 + 1}.{b % 254 + 1}.9"
    # The collider landed on a different fake /24 (no silent merge)...
    assert fake_first.rsplit(".", 1)[0] != fake_second.rsplit(".", 1)[0]
    # ... and both heads map consistently within the pass.
    assert (
        sanitizer._fake_ip(f"{first_head}.44", "").rsplit(".", 1)[0]
        == fake_first.rsplit(".", 1)[0]
    )
    assert (
        sanitizer._fake_ip(f"{second_head}.44", "").rsplit(".", 1)[0]
        == fake_second.rsplit(".", 1)[0]
    )


def test_fake_network_probe_wraps_past_the_end_of_the_space() -> None:
    """Linear probing wraps modulo the 254x254 space instead of running
    off its end when the digest-derived start sits near the top."""
    sanitizer = _bare_sanitizer()
    head = "192.0.2"
    first, second = sanitizer._digest_bytes(head)[:2]
    start = (first % 254) * 254 + (second % 254)
    space = 254 * 254
    sanitizer._used_fake_networks.update(
        (start + offset) % space for offset in range(space - 1)
    )
    free = (start + space - 1) % space
    fake = sanitizer._fake_ip("192.0.2.4", "")
    assert fake == f"10.{free // 254 + 1}.{free % 254 + 1}.4"


def test_fake_network_space_exhaustion_raises_a_clear_error() -> None:
    """Past 64,516 distinct real /24s a fresh fake network cannot exist;
    reusing one would merge two real subnets, so refuse loudly."""
    from meraki2tf.sanitizer import SanitizeError

    sanitizer = _bare_sanitizer()
    sanitizer._used_fake_networks.update(range(254 * 254))
    with pytest.raises(SanitizeError, match="exhausted"):
        sanitizer._fake_ip("10.1.2.3", "")


def test_x509_fingerprints_survive_while_real_macs_still_sanitize() -> None:
    """A 20-group colon-hex x509 SHA-1 fingerprint (SAML IdP payloads)
    is not a MAC and not an IPv6 address; rewriting windows inside it
    breaks drill validation. Exactly-six-group strings still map."""
    fingerprint = (
        "99:88:77:66:55:44:33:22:11:00:aa:bb:cc:dd:ee:ff:12:34:56:78"
    )
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/organizations/{organizationId}/saml/idps/{idpId}",
                ("654321", "IDP_1"),
                {
                    "x509certSha1Fingerprint": fingerprint,
                    "bssid": "aa:bb:cc:dd:ee:ff",
                    "comment": "gateway at aa:bb:cc:dd:ee:ff.",
                    "ip": "2001:0db8:1111:2222:3333:4444:5555:6666",
                },
            ),
        ),
    )
    payload = sanitize_graph(graph, salt=b"fixed").features[0].payload
    assert payload["x509certSha1Fingerprint"] == fingerprint
    # Standalone six-group MACs still become fake locally-administered
    # MACs, including ones embedded in free text with punctuation.
    assert payload["bssid"].startswith("02:")
    assert "aa:bb:cc:dd:ee:ff" not in payload["comment"]
    assert "02:" in payload["comment"]
    # Full 8-group IPv6 addresses still pseudonymize into 2001:db8::/32.
    assert payload["ip"].startswith("2001:db8:")
    assert "3333" not in payload["ip"]


def test_extra_path_values_are_pseudonymized_never_leaked(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A snapshot feature carrying more pathValues than its api_path has
    placeholders (hand-edited/foreign snapshots) must not pass the extra
    values through VERBATIM into a file stamped sanitized: unmatched
    values take the generic pseudonym path, and the arity mismatch is
    logged as a warning."""
    graph = NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                "/networks/{networkId}/appliance/vlans",
                ("N_1", "LEAKY-EXTRA-VALUE", "10", ""),
                {"items": []},
            ),
            # Fewer values than placeholders warns too and must not crash.
            FeatureConfiguration(
                "/networks/{networkId}/appliance/vlans/{vlanId}",
                ("N_1",),
                {"name": "Data"},
            ),
        ),
    )
    with caplog.at_level("WARNING", logger="meraki2tf.sanitizer"):
        sanitized = sanitize_graph(graph, salt=b"fixed")
    feature = sanitized.features[0]
    assert feature.path_values[0] == "net-0001"
    assert feature.path_values[1].startswith("id-")
    assert "LEAKY-EXTRA-VALUE" not in feature.path_values
    assert feature.path_values[2] == "10"  # short numerics stay structure
    assert feature.path_values[3] == ""
    warnings = [record.message for record in caplog.records]
    assert sum("path value(s) for" in message for message in warnings) == 2
