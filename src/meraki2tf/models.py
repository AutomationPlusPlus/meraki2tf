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
    """One dashboard network."""

    network_id: str
    organization_id: str
    name: str
    product_types: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "MerakiNetwork":
        network_id = str(payload.get("id", "")).strip()
        if not network_id:
            raise MalformedPayloadError(f"Network payload has no 'id': {sorted(payload)}")
        return cls(
            network_id=network_id,
            organization_id=str(payload.get("organizationId", "")),
            name=str(payload.get("name", "")),
            product_types=tuple(str(p) for p in payload.get("productTypes") or ()),
        )


@dataclass(frozen=True)
class MerakiDevice:
    """One physical or virtual device claimed into a network."""

    serial: str
    network_id: str
    model: str
    name: str

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "MerakiDevice":
        serial = str(payload.get("serial", "")).strip()
        if not serial:
            raise MalformedPayloadError(f"Device payload has no 'serial': {sorted(payload)}")
        return cls(
            serial=serial,
            network_id=str(payload.get("networkId", "")),
            model=str(payload.get("model", "")),
            name=str(payload.get("name", "")),
        )


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
