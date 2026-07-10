"""Spec Ingestion Engine: dynamic discovery over the Meraki OpenAPI document.

The engine walks ``paths`` in the spec on-the-fly to enumerate every
operation, extract its templated path parameters (the components of a
Terraform compound import ID), and group operations into resource
candidates. No endpoint, tag, or resource name is hard-coded — a new
spec release is picked up without code changes.

The Terraform mapping/translation layer built on top of this registry
lands in a later iteration; this module fixes the discovery contract.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_HTTP_METHODS = frozenset({"get", "put", "post", "delete", "patch"})
_PATH_PARAM_PATTERN = re.compile(r"\{([^{}]+)\}")


class MalformedSpecError(ValueError):
    """The document does not carry the OpenAPI structure the engine needs."""


@dataclass(frozen=True)
class OperationSpec:
    """One API operation discovered in the spec."""

    operation_id: str
    method: str
    path: str
    #: Ordered templated path segments — the compound import ID components.
    path_params: tuple[str, ...]
    tags: tuple[str, ...]
    #: Raw OpenAPI operation object, kept for the parameter/schema
    #: translation layer to interrogate later.
    raw: Mapping[str, Any] = field(repr=False, hash=False, compare=False, default_factory=dict)


@dataclass(frozen=True)
class ResourceGroup:
    """Operations sharing one resource path, keyed by canonical path template.

    A group whose members include a ``get`` and a ``put`` on the same
    templated path is the primary signal for a manageable Terraform
    resource; read-only groups become data sources.
    """

    path: str
    operations: tuple[OperationSpec, ...]

    @property
    def methods(self) -> frozenset[str]:
        return frozenset(op.method for op in self.operations)


class SpecIngestionEngine:
    """Parses a Meraki OpenAPI document into a dynamic operation registry."""

    def __init__(self, spec: Mapping[str, Any]) -> None:
        paths = spec.get("paths")
        if not isinstance(paths, Mapping):
            raise MalformedSpecError("OpenAPI document has no 'paths' object.")
        self._spec = spec
        self._paths: Mapping[str, Any] = paths
        logger.debug("Ingested spec with %d path template(s)", len(paths))

    @classmethod
    def from_file(cls, path: Path) -> "SpecIngestionEngine":
        """Load a local OpenAPI JSON document (``--spec path/to/spec.json``)."""
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MalformedSpecError(f"Cannot read OpenAPI spec {path}: {exc}") from exc
        if not isinstance(document, Mapping):
            raise MalformedSpecError(f"OpenAPI spec {path} is not a JSON object.")
        return cls(document)

    @classmethod
    def from_latest_release(cls) -> "SpecIngestionEngine":
        """Pull the latest published Meraki OpenAPI spec from GitHub."""
        from meraki2tf.spec_resolver import fetch_latest_spec

        return cls(fetch_latest_spec())

    def operations(self) -> Iterator[OperationSpec]:
        """Walk every path/method pair in the document, in spec order."""
        for path, methods in self._paths.items():
            if not isinstance(methods, Mapping):
                continue
            for method, operation in methods.items():
                if method not in _HTTP_METHODS or not isinstance(operation, Mapping):
                    continue
                operation_id = operation.get("operationId")
                if not isinstance(operation_id, str):
                    logger.warning("Skipping %s %s: missing operationId", method, path)
                    continue
                # `tags` may be null or a bare string in hand-trimmed
                # specs; only a real sequence yields tags (a string
                # would decompose into single characters).
                raw_tags = operation.get("tags")
                if not isinstance(raw_tags, (list, tuple)):
                    raw_tags = ()
                yield OperationSpec(
                    operation_id=operation_id,
                    method=method,
                    path=path,
                    path_params=tuple(_PATH_PARAM_PATTERN.findall(path)),
                    tags=tuple(tag for tag in raw_tags if isinstance(tag, str)),
                    raw=operation,
                )

    def resource_groups(self) -> dict[str, ResourceGroup]:
        """Cluster operations by shared path template.

        The path template is the natural resource boundary in the Meraki
        API (e.g. all methods under
        ``/networks/{networkId}/appliance/vlans/{vlanId}`` describe one
        resource), so grouping needs no name heuristics.
        """
        buckets: dict[str, list[OperationSpec]] = {}
        for op in self.operations():
            buckets.setdefault(op.path, []).append(op)
        return {
            path: ResourceGroup(path=path, operations=tuple(ops))
            for path, ops in buckets.items()
        }

    def build_registry(self) -> Any:
        """Derive the API-to-Terraform resource registry.

        Later iteration: correlates resource groups with the Terraform
        provider schema, maps parameters, derives compound import ID
        formats from ``path_params``, and flags unsupported attributes
        for the exception auditing engine.
        """
        raise NotImplementedError(
            "Terraform registry mapping lands with the translation-engine iteration."
        )
