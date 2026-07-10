"""Snapshot sanitizer: strip secrets and identity from a discovered graph.

Backs the ``--sanitize`` flag so a snapshot can be shared for testing,
demos, or bug reports without leaking credentials or identifying
details. Three complementary rules, all deterministic (the same input
always sanitizes to the same output, so sanitized snapshots stay diffable
across runs):

* **Structural IDs are pseudonymized consistently.** Organization IDs,
  network IDs, and device serials become sequential placeholders
  (``org-0001``, ``net-0007``, ``dev-0042``) applied everywhere the
  value appears — model fields, feature ``pathValues``, and any string
  inside feature payloads — so referential integrity (and therefore
  import-block generation) survives sanitization.
* **Secret-bearing fields are redacted.** Any payload key that looks
  credential-shaped (``psk``, ``secret``, ``password``,
  ``communityString``, ``…token``, ``…apiKey``, ``v3AuthPass``,
  ``passcode``, ``…Pin``, ``privateKey``, ``credentials``,
  ``licenseKey``, …) has its value replaced with ``**REDACTED**``, and
  any string value carrying a PEM private-key block is redacted no
  matter what key it sits under.
* **Identity-bearing fields are pseudonymized.** Names, emails, URLs,
  addresses, notes, tags, MACs, and stray serials become stable
  ``<kind>-<digest>`` placeholders; coordinates are zeroed.
* **Identity-shaped values are pseudonymized wherever they appear.**
  Regardless of key, URLs and FQDN-like strings become placeholders,
  IPv4 addresses/CIDRs become deterministic fake ``10.x.y.z`` values
  (prefix length preserved, so firewall rules and subnets keep their
  shape), and MAC addresses become fake locally-administered MACs.

Everything else — product types, models, feature structure — is
preserved so the snapshot remains a faithful structural replica of the
environment.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)

REDACTED = "**REDACTED**"

#: Payload keys whose string values are credentials. Public because the
#: DR runbook and gap replayer must agree with the sanitizer on what
#: counts as a secret (redact in artifacts, restore from the dump).
SECRET_KEY_PATTERN = re.compile(
    r"secret|psk|passphrase|password|community|token|api_?key|auth_?key"
    r"|shared_?key|auth_?pass|priv_?pass|passcode|pin$|private_?key"
    r"|credential|license_?key",
    re.IGNORECASE,
)
_SECRET_KEY = SECRET_KEY_PATTERN
_IDENTITY_KEY = re.compile(
    r"name$|names$|email|url$|urls$|address|notes|^mac$|^tags$|serial|phone",
    re.IGNORECASE,
)
_COORDINATE_KEYS = frozenset({"lat", "lng"})

_URL_VALUE = re.compile(r"\w+://")
#: Dotted, letter-bearing hostname shapes (wildcards allowed) — catches
#: FQDNs under generic keys like `host`, `fqdn`, or filter `patterns`,
#: including trailing-dot forms, ports, and scheme-less URL paths
#: (`example.com./x`, `host:8080`, `hooks.example.com/T0/SECRET`).
_FQDN_VALUE = re.compile(r"(?=[^/]*[A-Za-z])[\w*-]+(\.[\w*-]+)+\.?(:\d+)?(/\S*)?")
_IPV4_VALUE = re.compile(r"(\d{1,3}\.){3}\d{1,3}(?P<prefix>/\d{1,2})?")
_MAC_VALUE = re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
#: Full 8-group form, or any `::`-compressed form (a MAC has neither
#: eight groups nor a `::`, so the two shapes never collide).
_IPV6_VALUE = re.compile(
    r"(?i)(?:"
    r"(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
    r"|(?:[0-9a-f]{1,4}:)+:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?"
    r"|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?"
    r")(?P<prefix>/\d{1,3})?"
)

#: Placeholder names in feature API paths → pseudonym prefixes.
_PATH_PARAM_PREFIXES = {
    "organizationid": "org",
    "networkid": "net",
    "serial": "dev",
}
#: Payload keys whose string values are structural references.
_STRUCTURAL_KEYS = {
    "organizationid": "org",
    "networkid": "net",
    "networkids": "net",
    "serial": "dev",
    "serials": "dev",
}
_PATH_PARAM = re.compile(r"\{([^}]+)\}")
#: Token shape for the known-ID scan over free text: Meraki structural
#: IDs (org/network IDs, serials, opaque item IDs) are word-and-dash
#: strings, so token-wise dict lookup replaces them without the cost of
#: an alternation regex over the whole ID map.
_ID_TOKEN = re.compile(r"[\w-]+")
#: Payload keys that reference other objects by opaque ID (``id``,
#: ``interfaceId``, ``policyIds`` — but not words merely ending in "id"
#: like ``ssid``). Their values are identifying and must map like any
#: other structural ID.
_ID_REFERENCE_KEY = re.compile(r"^ids?$|Ids?$")
#: Digit-count ceiling under which an all-numeric value is treated as
#: structure (VLAN 10, SSID number 3, port 48) rather than identity.
#: Real Meraki object IDs (admin IDs, interface IDs, opt-in IDs, …) are
#: far longer and leak the environment's identity if preserved.
_STRUCTURAL_NUMBER_MAX_DIGITS = 4


def _is_structural_number(value: str) -> bool:
    """Small numerics are structure, not identity; long ones identify."""
    return value.isdigit() and len(value) <= _STRUCTURAL_NUMBER_MAX_DIGITS


def _pseudonym(key: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    return f"{key.lower()}-{digest}"


def _digest_bytes(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _fake_ip(value: str, prefix: str) -> str:
    # Octets land in 1-254 so fake addresses never collide with
    # network/broadcast shapes or a `10.255.` grep for real leftovers.
    octets = [byte % 254 + 1 for byte in _digest_bytes(value)[:3]]
    return f"10.{octets[0]}.{octets[1]}.{octets[2]}{prefix}"


def _fake_mac(value: str) -> str:
    tail = _digest_bytes(value)[:5]
    return ":".join(["02", *(f"{byte:02x}" for byte in tail)])


def _fake_ipv6(value: str, prefix: str) -> str:
    # Deterministic addresses inside the 2001:db8::/32 documentation
    # range, prefix length preserved (mirrors the IPv4 treatment).
    a, b, c, d = _digest_bytes(value)[:4]
    return f"2001:db8:{a:02x}{b:02x}:{c:02x}{d:02x}::1{prefix}"


class _GraphSanitizer:
    """One sanitization pass; holds the consistent structural-ID map."""

    def __init__(self, graph: NetworkGraph) -> None:
        self._id_map: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._assign(graph.organization_id, "org")
        for network in graph.networks:
            self._assign(network.organization_id, "org")
            self._assign(network.network_id, "net")
        for device in graph.devices:
            self._assign(device.network_id, "net")
            self._assign(device.serial, "dev")
        # Feature path values can reference structural IDs that appear
        # nowhere in the networks/devices lists (multi-org exports,
        # partial snapshots); classify them by their path placeholder so
        # they pseudonymize instead of leaking. Opaque item-level IDs
        # (adminId, httpServerId, …) are identifying too — including
        # all-numeric ones (adminId 2038677) — while short numerics
        # (vlanId 10, SSID number 3) are structure, not identity.
        for feature in graph.features:
            placeholders = _PATH_PARAM.findall(feature.api_path)
            for name, value in zip(placeholders, feature.path_values):
                prefix = _PATH_PARAM_PREFIXES.get(name.lower())
                if prefix:
                    self._assign(value, prefix)
                elif value and not _is_structural_number(value):
                    self._assign(value, "id")

    def _assign(self, value: str, prefix: str) -> None:
        if value and value not in self._id_map:
            self._counters[prefix] = self._counters.get(prefix, 0) + 1
            self._id_map[value] = f"{prefix}-{self._counters[prefix]:04d}"

    def _mapped(self, value: str) -> str:
        return self._id_map.get(value, value)

    def sanitize(self, graph: NetworkGraph) -> NetworkGraph:
        return NetworkGraph(
            organization_id=self._mapped(graph.organization_id),
            networks=tuple(
                MerakiNetwork(
                    network_id=self._mapped(network.network_id),
                    organization_id=self._mapped(network.organization_id),
                    name=_pseudonym("network", network.name) if network.name else "",
                    product_types=network.product_types,
                    payload=self._clean(dict(network.payload), None),
                )
                for network in graph.networks
            ),
            devices=tuple(
                MerakiDevice(
                    serial=self._mapped(device.serial),
                    network_id=self._mapped(device.network_id),
                    model=device.model,
                    name=_pseudonym("device", device.name) if device.name else "",
                    payload=self._clean(dict(device.payload), None),
                )
                for device in graph.devices
            ),
            features=tuple(
                FeatureConfiguration(
                    api_path=feature.api_path,
                    path_values=tuple(
                        self._mapped(value) for value in feature.path_values
                    ),
                    payload=self._clean(feature.payload, None),
                )
                for feature in graph.features
            ),
        )

    def _clean(self, node: Any, key: str | None) -> Any:
        if isinstance(node, Mapping):
            # Keys are data too: fixed-IP assignments key on MACs,
            # per-device maps key on serials.
            return {
                self._clean_key(child): self._clean(value, child)
                for child, value in node.items()
            }
        if isinstance(node, (list, tuple)):
            return [self._clean(value, key) for value in node]
        return self._clean_scalar(node, key)

    def _clean_key(self, key: str) -> str:
        if key in self._id_map:
            return self._id_map[key]
        return self._clean_identity_shaped(key)

    def _clean_scalar(self, value: Any, key: str | None) -> Any:
        # Structural IDs map consistently wherever they appear, before
        # any key-based rule can obscure the reference.
        if isinstance(value, str) and value in self._id_map:
            return self._id_map[value]
        if isinstance(value, str) and value and key is not None:
            # Structural references seen only inside payloads (a
            # networkId pointing at a network absent from the snapshot's
            # own lists) still get a consistent pseudonym.
            prefix = _STRUCTURAL_KEYS.get(key.lower())
            if prefix:
                self._assign(value, prefix)
                return self._id_map[value]
            # Opaque ID references seen only inside payloads
            # (`interfaceId`, nested `id` echoes, `…Ids` lists) map to
            # the same consistent pseudonyms as path-level IDs.
            if _ID_REFERENCE_KEY.search(key) and not _is_structural_number(value):
                self._assign(value, "id")
                return self._id_map[value]
        if key is None:
            return value
        if _SECRET_KEY.search(key):
            # Only string values are replaced: booleans/numbers under
            # secret-adjacent names (e.g. `passwordEnabled`) are flags,
            # not credentials, and must keep their type.
            return REDACTED if isinstance(value, str) and value else value
        if key.lower() in _COORDINATE_KEYS:
            return 0.0
        if _IDENTITY_KEY.search(key) and isinstance(value, str) and value:
            return _pseudonym(key, value)
        if isinstance(value, str):
            return self._clean_identity_shaped(value)
        return value

    def _clean_identity_shaped(self, value: str) -> str:
        """Pseudonymize identity-shaped values regardless of their key."""
        if "PRIVATE KEY-----" in value:
            # PEM private-key blocks (RADSEC, custom certs) are secrets
            # even under non-secret-shaped keys like `certificate`.
            return REDACTED
        if "," in value:
            # Fields like firewall destCidr carry comma-separated lists;
            # spacing around the commas is preserved so benign free text
            # round-trips byte-identical.
            return "".join(
                part if index % 2 else self._clean_list_part(part)
                for index, part in enumerate(re.split(r"(\s*,\s*)", value))
            )
        if _URL_VALUE.search(value):
            return _pseudonym("url", value)
        if _FQDN_VALUE.fullmatch(value):
            return _pseudonym("host", value)
        # Known structural IDs, FQDNs, IPs, and MACs are rewritten even
        # when embedded in free text (rule comments name networks and
        # hosts; DHCP option strings carry `MCIPADD=10.0.0.1,MCPORT=…`).
        value = _ID_TOKEN.sub(
            lambda m: self._id_map.get(m.group(0), m.group(0)), value
        )
        value = _FQDN_VALUE.sub(
            lambda m: _pseudonym("host", m.group(0)), value
        )
        value = _IPV4_VALUE.sub(
            lambda m: _fake_ip(m.group(0), m.group("prefix") or ""), value
        )
        value = _IPV6_VALUE.sub(
            lambda m: _fake_ipv6(m.group(0), m.group("prefix") or ""), value
        )
        return _MAC_VALUE.sub(lambda m: _fake_mac(m.group(0)), value)

    def _clean_list_part(self, part: str) -> str:
        """Clean one comma-list element, keeping its surrounding whitespace."""
        stripped = part.strip()
        if not stripped:
            return part
        return part.replace(stripped, self._clean_identity_shaped(stripped), 1)


def sanitize_graph(graph: NetworkGraph) -> NetworkGraph:
    """A sanitized deep copy of ``graph``; the input is left untouched."""
    return _GraphSanitizer(graph).sanitize(graph)
