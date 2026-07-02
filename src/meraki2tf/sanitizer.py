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
  ``communityString``, ``…token``, ``…apiKey``, …) has its value
  replaced with ``**REDACTED**``.
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

_SECRET_KEY = re.compile(
    r"secret|psk|passphrase|password|community|token|api_?key|auth_?key|shared_?key",
    re.IGNORECASE,
)
_IDENTITY_KEY = re.compile(
    r"name$|names$|email|url$|urls$|address|notes|^mac$|^tags$|serial",
    re.IGNORECASE,
)
_COORDINATE_KEYS = frozenset({"lat", "lng"})

_URL_VALUE = re.compile(r"\w+://")
#: Dotted, letter-bearing hostname shapes (wildcards allowed) — catches
#: FQDNs under generic keys like `host`, `fqdn`, or filter `patterns`.
_FQDN_VALUE = re.compile(r"(?=[^/]*[A-Za-z])[\w*-]+(\.[\w*-]+)+")
_IPV4_VALUE = re.compile(r"(\d{1,3}\.){3}\d{1,3}(?P<prefix>/\d{1,2})?")
_MAC_VALUE = re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


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
                )
                for network in graph.networks
            ),
            devices=tuple(
                MerakiDevice(
                    serial=self._mapped(device.serial),
                    network_id=self._mapped(device.network_id),
                    model=device.model,
                    name=_pseudonym("device", device.name) if device.name else "",
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
        if "," in value:
            # Fields like firewall destCidr carry comma-separated lists.
            return ",".join(
                self._clean_identity_shaped(part.strip())
                for part in value.split(",")
            )
        if _URL_VALUE.search(value):
            return _pseudonym("url", value)
        if _FQDN_VALUE.fullmatch(value):
            return _pseudonym("host", value)
        # IPs and MACs are rewritten even when embedded in free text
        # (e.g. DHCP option strings like `MCIPADD=10.0.0.1,MCPORT=…`).
        value = _IPV4_VALUE.sub(
            lambda m: _fake_ip(m.group(0), m.group("prefix") or ""), value
        )
        return _MAC_VALUE.sub(lambda m: _fake_mac(m.group(0)), value)


def sanitize_graph(graph: NetworkGraph) -> NetworkGraph:
    """A sanitized deep copy of ``graph``; the input is left untouched."""
    return _GraphSanitizer(graph).sanitize(graph)
