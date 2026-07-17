"""Snapshot sanitizer: strip secrets and identity from a discovered graph.

Backs the ``--sanitize`` flag so a snapshot can be shared for testing,
demos, or bug reports without leaking credentials or identifying
details. All rewrites are keyed by a **salt** the sanitized artifact
never carries: pseudonyms are deterministic under one salt (the same
input always sanitizes to the same output, so sanitized snapshots stay
diffable across runs of the same workdir, whose salt persists), but
without the salt they cannot be inverted by hashing candidate values —
an unsalted digest of e.g. the RFC 1918 IPv4 space is a
seconds-of-compute dictionary attack. Three complementary rules:

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
  email addresses (the whole ``user@host``, never just the domain — a
  leftover local part is a username) become valid fake addresses under
  the reserved ``.invalid`` TLD, IPv4 addresses/CIDRs become
  deterministic fake ``10.x.y.z`` values (prefix length preserved and
  the fake network part keyed on the real /24, so subnets, appliance
  IPs, and next hops stay mutually coherent), and MAC addresses become
  fake locally-administered MACs.

The output must stay **restore-drillable**: API keyword path selectors
(pure-alpha values like ``firewalledServices/{service}``) survive
untouched, and Liquid template code in webhook payload templates passes
through verbatim (only the literal text between tags is rewritten).

Everything else — product types, models, feature structure — is
preserved so the snapshot remains a faithful structural replica of the
environment.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from meraki2tf.fsperms import restrict_to_owner
from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)

logger = logging.getLogger(__name__)

REDACTED = "**REDACTED**"

#: Payload keys whose string values are credentials. Public because the
#: DR runbook and gap replayer must agree with the sanitizer on what
#: counts as a secret (redact in artifacts, restore from the dump).
SECRET_KEY_PATTERN = re.compile(
    r"secret|psk|passphrase|password(?!expiration|length|s$|count)"
    r"|community|token|api_?key|auth_?key|authentication_?key"
    r"|shared_?key|auth_?pass|priv_?pass|passcode|pin$|private_?key"
    r"|credential|license_?key|encryption_?key|wep_?key|wpa_?key"
    # Spec-declared credential fields whose names carry no secret-ish
    # stem: the coterm licensing endpoint's bare `key` ("The key of the
    # license") and SM software `redemptionCode` (redeemable VPP codes).
    # Bare `key` over-matches a few non-credential fields (GRE keys);
    # for a sanitizer and the secret-reporting union, over-redaction is
    # the safe direction.
    r"|redemption_?code|^key$",
    re.IGNORECASE,
)
_SECRET_KEY = SECRET_KEY_PATTERN
#: Device-identity keys (imei, iccid, eid, meid, msisdn) carry
#: bare-digit hardware/subscriber identifiers with no recognizable
#: value shape, so they must be caught by key like names and serials.
_IDENTITY_KEY = re.compile(
    r"name$|names$|email|url$|urls$|address|notes|^mac$|^tags$|serial|phone"
    # enrollmentString is a customer-chosen, globally unique SM slug
    # (the public n.meraki.com/<slug> enrollment path) — it identifies
    # the organization as surely as its name does.
    r"|^imei$|^iccid$|^eid$|^meid$|^msisdn$|^enrollmentstring$",
    re.IGNORECASE,
)
_COORDINATE_KEYS = frozenset({"lat", "lng"})

_URL_VALUE = re.compile(r"\w+://")
#: Liquid template constructs (webhook payload templates): `{{ var }}`
#: interpolations and `{% tag %}` logic. Template code is not identity
#: — but dotted variable paths (`{{alertData.service.name}}`) look
#: exactly like FQDNs to the value rewrites, and a rewritten variable
#: makes the whole template fail to render on restore.
_LIQUID_TAG = re.compile(r"(\{\{.*?\}\}|\{%.*?%\})", re.DOTALL)
#: user@host shapes anywhere in a value. The local part is identity (a
#: username) just like the domain, so the whole address maps to one
#: pseudonym — the FQDN rewrite alone would leave ``jsmith@…`` behind.
_EMAIL_VALUE = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")
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

#: Path placeholders whose values are API keywords, not identity: pure
#: short alpha tokens (``firewalledServices/{service}`` takes ``ICMP``/
#: ``web``/``SNMP``) under a placeholder that is not name/ID/serial
#: shaped. Meraki identifiers always carry digits or separators, so a
#: letters-only selector pseudonymized into ``id-XXXX`` would 404 on
#: restore while preserving it leaks nothing structural. The spec
#: declares no enum for these params (the values live in prose), so the
#: shape rule is the only future-proof classifier available.
_KEYWORD_EXCLUDED_PLACEHOLDER = re.compile(r"(?i)name|id$|ids$|serial")
_KEYWORD_PATH_VALUE = re.compile(r"[A-Za-z]{1,16}")


def _is_structural_number(value: str) -> bool:
    """Small numerics are structure, not identity; long ones identify."""
    return value.isdigit() and len(value) <= _STRUCTURAL_NUMBER_MAX_DIGITS


def _is_path_keyword(placeholder: str, value: str) -> bool:
    """Whether a path value is a protocol/service keyword, not identity."""
    if value.lower() == "default":
        # The literal fixed-slot selector (vlanProfiles/{iname} names
        # its built-in profile "default"): identity-free, and a
        # pseudonym makes the slot unaddressable on restore.
        return True
    return bool(
        not _KEYWORD_EXCLUDED_PLACEHOLDER.search(placeholder)
        and _KEYWORD_PATH_VALUE.fullmatch(value)
    )


#: Salt length in bytes; a read-back shorter than this is treated as
#: torn/corrupt and regenerated rather than trusted.
_SALT_BYTES = 16


def load_or_create_salt(path: Path) -> bytes:
    """The workdir's persistent sanitizer salt (created 0600 on first use).

    Keeping the salt beside — never inside — the sanitized artifact
    preserves cross-run pseudonym stability for a given workdir while
    denying snapshot recipients the key needed for dictionary
    inversion.

    A valid existing salt is reused. A missing, empty, truncated, or
    non-hex file (e.g. a run interrupted mid-write) is regenerated
    rather than trusted — an empty salt would silently defeat the
    dictionary-inversion protection, and a corrupt one must not abort
    every subsequent run. The write is atomic (temp + ``os.replace``,
    0600 before content) so the file is never left half-written.
    """
    if path.exists():
        try:
            existing = bytes.fromhex(path.read_text(encoding="utf-8").strip())
        except ValueError:
            existing = b""
        if len(existing) >= _SALT_BYTES:
            return existing
        logger.warning(
            "Sanitizer salt %s is empty or corrupt; regenerating it "
            "(pseudonyms will differ from any prior run using it).", path,
        )
    salt = secrets.token_bytes(_SALT_BYTES)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.touch(mode=0o600, exist_ok=True)
    restrict_to_owner(tmp)
    try:
        tmp.write_text(salt.hex() + "\n", encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return salt


def _walk_mappings(node: Any) -> Iterator[Mapping[str, Any]]:
    """Every mapping in a payload tree, depth-first."""
    if isinstance(node, Mapping):
        yield node
        for value in node.values():
            yield from _walk_mappings(value)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _walk_mappings(item)


class _GraphSanitizer:
    """One sanitization pass; holds the consistent structural-ID map."""

    def __init__(self, graph: NetworkGraph, salt: bytes) -> None:
        self._salt = salt
        self._id_map: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        # Meraki built-in payload templates ("type": "included") carry
        # vendor names, not customer identity, and those names must
        # survive verbatim EVERYWHERE — on the template object itself
        # and inside references to it (a webhook receiver's
        # payloadTemplate carries id + name, and the dashboard rejects
        # the pair when they disagree). Collect the built-ins' IDs up
        # front so reference nodes (which lack the "type" marker) are
        # recognized too.
        self._included_template_ids: frozenset[str] = frozenset(
            str(payload.get("payloadTemplateId"))
            for feature in graph.features
            for payload in _walk_mappings(feature.payload)
            if payload.get("type") == "included"
            and payload.get("payloadTemplateId")
        )
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
                elif (
                    value
                    and not _is_structural_number(value)
                    and not _is_path_keyword(name, value)
                ):
                    self._assign(value, "id")

    def _assign(self, value: str, prefix: str) -> None:
        if value and value not in self._id_map:
            self._counters[prefix] = self._counters.get(prefix, 0) + 1
            self._id_map[value] = f"{prefix}-{self._counters[prefix]:04d}"

    def _mapped(self, value: str) -> str:
        return self._id_map.get(value, value)

    def _digest_bytes(self, value: str) -> bytes:
        # Keyed (HMAC) digests: without the salt, pseudonyms cannot be
        # confirmed or inverted by hashing candidate values.
        return hmac.new(
            self._salt, value.encode("utf-8"), hashlib.sha256
        ).digest()

    def _pseudonym(self, key: str, value: str) -> str:
        # 16 hex chars (64 bits): at the 200k-object scale the v2
        # snapshot format targets, a 40-bit digest carries ~2% birthday
        # collision odds — a collision silently merges two identities.
        return f"{key.lower()}-{self._digest_bytes(value).hex()[:16]}"

    def _fake_email(self, value: str) -> str:
        # Pseudonymized recipients must still parse as email addresses:
        # Meraki validates them on write, so a bare `email-<digest>`
        # placeholder makes the sanitized snapshot fail restore drills.
        # RFC 2606 reserves `.invalid` — the address can never route.
        return f"user-{self._digest_bytes(value).hex()[:16]}@drill.invalid"

    def _fake_host(self, value: str) -> str:
        # Hostname pseudonyms must stay hostname-shaped: firewall rule
        # destinations accept FQDNs, and a dotless `host-<digest>`
        # token fails their validation on restore ("Destination address
        # must be an IP address or a subnet in CIDR form…").
        return f"host-{self._digest_bytes(value).hex()[:16]}.invalid"

    def _fake_url(self, value: str) -> str:
        # URL pseudonyms must stay URLs, and their host must publicly
        # resolve: Meraki DNS-checks webhook receiver hostnames on
        # write, so a `.invalid` host fails restore drills. The apex
        # example.com (IANA, RFC 2606) has public A/AAAA records —
        # subdomains of it do NOT — so the digest rides in the path.
        return f"https://example.com/url-{self._digest_bytes(value).hex()[:16]}"

    @staticmethod
    def _masked(fake: str, prefix: str) -> str:
        # A prefixed value is a subnet: mask the host bits so the fake
        # is a valid network address — the sanitized snapshot feeds
        # restore drills, and "10.7.9.3/24" fails strict CIDR parsing.
        # A prefix the regex admitted but ipaddress rejects (e.g. /99)
        # keeps the legacy bare concatenation.
        try:
            return str(ipaddress.ip_network(fake + prefix, strict=False))
        except ValueError:
            return fake + prefix

    def _fake_ip(self, value: str, prefix: str) -> str:
        # The fake network part is keyed on the real /24 prefix and the
        # host octet is preserved, so addresses that share a real /24
        # share a fake one: a VLAN subnet, its appliance IP, and a
        # static route's next hop stay coherent and the sanitized
        # snapshot remains restore-drillable ("next hop not on a
        # configured subnet" otherwise). A lone host octet without its
        # real network context carries no identity. Octets land in
        # 1-254 so fake networks never collide with a `10.255.` grep
        # for real leftovers.
        address = value[: len(value) - len(prefix)] if prefix else value
        head, _, host = address.rpartition(".")
        octets = [byte % 254 + 1 for byte in self._digest_bytes(head)[:2]]
        fake = f"10.{octets[0]}.{octets[1]}.{host}"
        return self._masked(fake, prefix) if prefix else fake

    def _fake_mac(self, value: str) -> str:
        tail = self._digest_bytes(value)[:5]
        return ":".join(["02", *(f"{byte:02x}" for byte in tail)])

    def _fake_ipv6(self, value: str, prefix: str) -> str:
        # Deterministic addresses inside the 2001:db8::/32 documentation
        # range, prefix length preserved (mirrors the IPv4 treatment).
        a, b, c, d = self._digest_bytes(value)[:4]
        fake = f"2001:db8:{a:02x}{b:02x}:{c:02x}{d:02x}::1"
        return self._masked(fake, prefix) if prefix else fake

    def sanitize(self, graph: NetworkGraph) -> NetworkGraph:
        return NetworkGraph(
            organization_id=self._mapped(graph.organization_id),
            networks=tuple(
                MerakiNetwork(
                    network_id=self._mapped(network.network_id),
                    organization_id=self._mapped(network.organization_id),
                    name=self._pseudonym("network", network.name) if network.name else "",
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
                    name=self._pseudonym("device", device.name) if device.name else "",
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

    def _clean(self, node: Any, key: str | None, secret: bool = False) -> Any:
        # A secret-shaped key marks its WHOLE subtree: a credentials
        # object's inner keys ({"credentials": {"user", "pass"}}) need
        # not look secret-shaped themselves.
        secret = secret or bool(key and _SECRET_KEY.search(key))
        if isinstance(node, Mapping):
            # Meraki's built-in webhook payload templates carry vendor
            # names ("Slack (included)"), not customer identity — and a
            # pseudonymized name breaks adopt-by-name on restore, so
            # the org-shared built-in gets duplicated in every network.
            # Reference nodes (a webhook receiver's payloadTemplate)
            # carry the ID without the "type" marker, and the dashboard
            # rejects an id/name pair that disagrees — hence the
            # prescanned ID set.
            included = (
                node.get("type") == "included" and "payloadTemplateId" in node
            ) or (
                str(node.get("payloadTemplateId"))
                in self._included_template_ids
            )
            # Keys are data too: fixed-IP assignments key on MACs,
            # per-device maps key on serials.
            return {
                self._clean_key(child): (
                    value
                    if included and child == "name" and isinstance(value, str)
                    else self._clean(value, child, secret)
                )
                for child, value in node.items()
            }
        if isinstance(node, (list, tuple)):
            return [self._clean(value, key, secret) for value in node]
        return self._clean_scalar(node, key, secret)

    def _clean_key(self, key: str) -> str:
        if key in self._id_map:
            return self._id_map[key]
        return self._clean_identity_shaped(key)

    def _clean_scalar(
        self, value: Any, key: str | None, secret: bool = False
    ) -> Any:
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
            # the same consistent pseudonyms as path-level IDs. Global
            # catalog URIs are exempt (an L7 rule's application id
            # `meraki:layer7/application/…`): the same value exists in
            # every organization — not identity — and a pseudonym fails
            # the dashboard's URI-format validation on restore.
            if (
                _ID_REFERENCE_KEY.search(key)
                and not _is_structural_number(value)
                and not value.startswith("meraki:")
            ):
                self._assign(value, "id")
                return self._id_map[value]
        if isinstance(value, int) and not isinstance(value, bool):
            # ID references arrive as JSON numbers too (writers vary);
            # a numeric ID is the same identifier as its string form and
            # must map through the same pseudonym table or it leaks and
            # breaks referential consistency. The pseudonym is a string,
            # which changes the JSON type — acceptable for a sanitized
            # structural replica. Bools are ints in Python; excluded.
            text = str(value)
            if text in self._id_map:
                return self._id_map[text]
            if key is not None:
                prefix = _STRUCTURAL_KEYS.get(key.lower())
                if prefix:
                    self._assign(text, prefix)
                    return self._id_map[text]
                if _ID_REFERENCE_KEY.search(key) and not _is_structural_number(text):
                    self._assign(text, "id")
                    return self._id_map[text]
        if secret:
            # Everything under a secret-shaped key is a credential —
            # strings and numbers alike (numeric PINs/passcodes arrive
            # as JSON numbers). Booleans stay: `passwordEnabled` is a
            # flag, not a secret; empty strings carry nothing.
            if isinstance(value, str):
                return REDACTED if value else value
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                return REDACTED
            return value
        if key is None:
            # Root-level scalars (list/string payloads accepted verbatim
            # from canonical snapshots) still get the value-shaped
            # rules — the PEM redaction and identity rewrites apply "no
            # matter what key" a value sits under.
            if isinstance(value, str) and value:
                return self._clean_identity_shaped(value)
            return value
        if key.lower() in _COORDINATE_KEYS:
            return 0.0
        if _IDENTITY_KEY.search(key) and isinstance(value, str) and value:
            if key.lower() == "shortname":
                # Early-access feature slugs (`has_beta_api`): API
                # keywords the opt-in POST validates against a fixed
                # list, not identity.
                return value
            if value.lower() == "default":
                # The fixed-slot selector again, echoed in payloads
                # (a vlan profile's own `iname`).
                return value
            if value.startswith("meraki:"):
                # Global catalog URIs (an L7 rule's application id
                # `meraki:layer7/application/…`, content-filtering
                # category ids): the same value exists in every
                # organization — not identity — and a pseudonym fails
                # the dashboard's URI-format validation on restore.
                return value
            if "email" in key.lower() or _EMAIL_VALUE.fullmatch(value):
                return self._fake_email(value)
            if key.lower().rstrip("s").endswith("url"):
                # Same shape rule as the value-based URL rewrite:
                # receivers validate scheme and host on write.
                return self._fake_url(value)
            return self._pseudonym(key, value)
        if isinstance(value, str):
            return self._clean_identity_shaped(value)
        return value

    def _clean_identity_shaped(self, value: str) -> str:
        """Pseudonymize identity-shaped values regardless of their key."""
        if "PRIVATE KEY-----" in value or "-----BEGIN CERTIFICATE" in value:
            # PEM private-key blocks (RADSEC, custom certs) are secrets
            # even under non-secret-shaped keys like `certificate`.
            # Certificate/CSR blocks are identity: their DER encodes the
            # real Subject CN, Organization, and SAN hostnames — and
            # with the private key already redacted they are not
            # restorable material anyway.
            return REDACTED
        if _LIQUID_TAG.search(value):
            # Template code passes through verbatim; the literal text
            # between tags still gets every identity rewrite.
            return "".join(
                part if index % 2 else self._clean_identity_shaped(part)
                for index, part in enumerate(_LIQUID_TAG.split(value))
            )
        if "," in value:
            # Fields like firewall destCidr carry comma-separated lists;
            # spacing around the commas is preserved so benign free text
            # round-trips byte-identical.
            return "".join(
                part if index % 2 else self._clean_list_part(part)
                for index, part in enumerate(re.split(r"(\s*,\s*)", value))
            )
        if _URL_VALUE.search(value):
            return self._fake_url(value)
        if _FQDN_VALUE.fullmatch(value):
            return self._fake_host(value)
        # Known structural IDs, FQDNs, IPs, and MACs are rewritten even
        # when embedded in free text (rule comments name networks and
        # hosts; DHCP option strings carry `MCIPADD=10.0.0.1,MCPORT=…`).
        value = _ID_TOKEN.sub(
            lambda m: self._id_map.get(m.group(0), m.group(0)), value
        )
        # Emails before FQDNs: the FQDN rewrite would otherwise consume
        # only the domain and leave the username-bearing local part.
        # The fake addresses are valid emails (`user-…@drill.invalid`),
        # so they hide behind NUL sentinels until every other pass ran —
        # otherwise the FQDN rewrite would eat their own domain part.
        fake_emails: list[str] = []

        def _email_sentinel(match: re.Match[str]) -> str:
            fake_emails.append(self._fake_email(match.group(0)))
            return f"\x00{len(fake_emails) - 1}\x00"
        value = _EMAIL_VALUE.sub(_email_sentinel, value)
        value = _FQDN_VALUE.sub(
            lambda m: self._fake_host(m.group(0)), value
        )
        value = _IPV4_VALUE.sub(
            lambda m: self._fake_ip(m.group(0), m.group("prefix") or ""), value
        )
        value = _IPV6_VALUE.sub(
            lambda m: self._fake_ipv6(m.group(0), m.group("prefix") or ""), value
        )
        value = _MAC_VALUE.sub(lambda m: self._fake_mac(m.group(0)), value)
        for index, fake in enumerate(fake_emails):
            value = value.replace(f"\x00{index}\x00", fake)
        return value

    def _clean_list_part(self, part: str) -> str:
        """Clean one comma-list element, keeping its surrounding whitespace."""
        stripped = part.strip()
        if not stripped:
            return part
        return part.replace(stripped, self._clean_identity_shaped(stripped), 1)


def sanitize_graph(
    graph: NetworkGraph, salt: bytes | None = None
) -> NetworkGraph:
    """A sanitized deep copy of ``graph``; the input is left untouched.

    ``salt`` keys every pseudonym. Passing the workdir's persistent
    salt (:func:`load_or_create_salt`) keeps sanitized snapshots
    diffable across runs; omitting it uses a fresh random salt, so
    pseudonyms are consistent within the output but deliberately not
    comparable to any other run's.
    """
    return _GraphSanitizer(
        graph, secrets.token_bytes(16) if salt is None else salt
    ).sanitize(graph)
