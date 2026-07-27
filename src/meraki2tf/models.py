"""Domain object models shared by every data provider.

Both ingestion modalities (live cloud SDK and offline JSON dump) must
translate their raw payloads into these frozen structures, so the
downstream translation, generation, and orchestration layers never know
— or care — where the data came from.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any


class MalformedPayloadError(ValueError):
    """A raw payload lacks the identity fields the domain model requires."""


@dataclass(frozen=True)
class MerakiNetwork:
    """One dashboard network.

    ``payload`` carries the complete API object (timezone, tags, notes,
    template binding, …) — a disaster-recovery snapshot must be able to
    recreate the network, not merely address it. The typed fields stay
    as the identity/convenience surface.
    """

    network_id: str
    organization_id: str
    name: str
    product_types: tuple[str, ...]
    payload: Mapping[str, Any] = field(default_factory=dict, hash=False)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "MerakiNetwork":
        network_id = str(payload.get("id", ""))
        if not network_id.strip():
            raise MalformedPayloadError(f"Network payload has no 'id': {sorted(payload)}")
        # The raw ID is kept verbatim (not stripped): an ID carrying edge
        # whitespace or a control character is un-importable, and silently
        # trimming it would emit an import block that looks covered but
        # addresses nothing. Such IDs surface as an ``unsupported`` coverage
        # entry in the kit generator instead (see ``unsafe_identifier_reason``).
        # A bare-string productTypes (hand-edited dump) would decompose
        # into single characters and silently skip product surfaces.
        raw_types = payload.get("productTypes")
        if not isinstance(raw_types, (list, tuple)):
            raw_types = ()
        return cls(
            network_id=network_id,
            organization_id=str(payload.get("organizationId", "")),
            name=str(payload.get("name", "")),
            product_types=tuple(str(p) for p in raw_types),
            payload=dict(payload),
        )


@dataclass(frozen=True)
class MerakiDevice:
    """One physical or virtual device claimed into a network."""

    serial: str
    network_id: str
    model: str
    name: str
    #: Complete API object (address, lat/lng, tags, floorPlanId, …) —
    #: required to restore the device's placement after a disaster.
    payload: Mapping[str, Any] = field(default_factory=dict, hash=False)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "MerakiDevice":
        serial = str(payload.get("serial", ""))
        if not serial.strip():
            raise MalformedPayloadError(f"Device payload has no 'serial': {sorted(payload)}")
        # Kept verbatim, like the network ID above: a whitespace/control-
        # bearing serial is flagged unsupported downstream rather than
        # silently trimmed into a wrong-but-covered import.
        return cls(
            serial=serial,
            network_id=str(payload.get("networkId", "")),
            model=str(payload.get("model", "")),
            name=str(payload.get("name", "")),
            payload=dict(payload),
        )


#: Payload key marking an asset whose endpoint could not be read during
#: discovery (persistent server error after every retry). Such an asset
#: must surface as a coverage gap — never as an importable resource, a
#: replayable payload, or an expandable collection envelope. The value
#: is the human-readable reason.
UNREADABLE_MARKER = "__meraki2tf_unreadable__"


@dataclass(frozen=True)
class FeatureConfiguration:
    """One discovered feature asset, addressed by its OpenAPI path template.

    ``api_path`` keys straight into the parser-derived Terraform lookup
    table, and ``path_values`` carries the ordered parameter values that
    form the compound import ID — so a feature is importable without any
    further interpretation.
    """

    api_path: str
    path_values: tuple[str, ...]
    payload: Mapping[str, Any] = field(default_factory=dict, hash=False)


@dataclass(frozen=True)
class SuspectEndpoint:
    """One endpoint that refused every scope it was tried against.

    A feature-not-enabled 400/404 for one network is legitimate
    absence; the same refusal from *every* scope (with at least a few
    tried) is an anomaly the operator should see — an SDK/spec skew or
    an API regression could otherwise hide a whole surface behind
    plausible-looking refusals.
    """

    api_path: str
    scopes_tried: int


@dataclass(frozen=True)
class DiscoveryDiagnostics:
    """Side facts one live-discovery pass hands to the coverage manifest."""

    suspect_endpoints: tuple[SuspectEndpoint, ...] = ()
    #: Calls skipped because the endpoint's product segment is outside
    #: the scope's product types — absent-by-design, like a refusal.
    skipped_out_of_scope: int = 0


@dataclass(frozen=True)
class NetworkGraph:
    """The complete discovered configuration surface for one organization."""

    organization_id: str
    networks: tuple[MerakiNetwork, ...]
    devices: tuple[MerakiDevice, ...]
    features: tuple[FeatureConfiguration, ...]

    def asset_count(self) -> int:
        return len(self.networks) + len(self.devices) + len(self.features)


def coerce_sequence(value: Any, description: str) -> Sequence[Any]:
    """Validate a raw JSON value is a list-like collection of payloads."""
    if value is None:
        return ()
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return value
    raise MalformedPayloadError(f"{description} must be a JSON array, got {type(value).__name__}")
