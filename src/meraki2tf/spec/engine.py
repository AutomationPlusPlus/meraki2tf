"""Spec Ingestion Engine: dynamic discovery over the Meraki OpenAPI document.

The engine walks ``paths`` in the spec on-the-fly to enumerate every
operation, extract its templated path parameters (the components of a
Terraform compound import ID), and group operations into resource
candidates. No endpoint, tag, or resource name is hard-coded — a new
spec release is picked up without code changes.

The Terraform mapping/translation layer built on top of this registry
lives in :mod:`~meraki2tf.openapi_parser` and
:mod:`~meraki2tf.resource_matcher`; this module fixes the discovery
contract.
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


def _json_pointer(document: Mapping[str, Any], ref: str) -> Any:
    """Resolve an internal ``#/...`` JSON pointer against ``document``.

    Returns ``None`` for external references (any that do not start
    with ``#/``) and for pointers that do not resolve, so the caller
    can surface the gap instead of crashing on a malformed document.
    """
    if not ref.startswith("#/"):
        return None
    node: Any = document
    for token in ref[2:].split("/"):
        # RFC 6901 escaping: ``~1`` → ``/`` first, then ``~0`` → ``~``.
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, Mapping) or token not in node:
            return None
        node = node[token]
    return node


def _fallback_operation_id(method: str, path: str) -> str:
    """Deterministic id for operations the spec left anonymous.

    ``operationId`` is optional per OpenAPI; skipping such operations
    would make their entity invisible to discovery and coverage — a
    silent DR hole. The slug never collides with a real Meraki SDK
    method name, so live dispatch reports the operation loudly as
    undispatchable instead of dropping it before discovery.
    """
    slug = re.sub(r"[^a-z0-9]+", "_", path.lower()).strip("_")
    return f"{method}_{slug}"


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


class SpecIngestionEngine:
    """Parses a Meraki OpenAPI document into a dynamic operation registry."""

    def __init__(self, spec: Mapping[str, Any]) -> None:
        paths = spec.get("paths")
        if not isinstance(paths, Mapping):
            raise MalformedSpecError("OpenAPI document has no 'paths' object.")
        if not paths:
            # An EMPTY paths object parses fine and then yields an empty
            # dispatch table: nothing maps to a Terraform resource, the
            # kit comes out with zero import blocks, and the run reports
            # success over a DR kit that would rebuild nothing. A
            # truncated download or a wrong file has to fail the run
            # rather than quietly empty it.
            raise MalformedSpecError(
                "OpenAPI document's 'paths' object is empty: it describes "
                "no endpoints, so it cannot map anything to Terraform."
            )
        self._spec = spec
        self._paths: Mapping[str, Any] = paths
        logger.debug("Ingested spec with %d path template(s)", len(paths))

    @classmethod
    def from_file(cls, path: Path) -> "SpecIngestionEngine":
        """Load a local OpenAPI JSON document (``--spec path/to/spec.json``)."""
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise MalformedSpecError(f"Cannot read OpenAPI spec {path}: {exc}") from exc
        if not isinstance(document, Mapping):
            raise MalformedSpecError(f"OpenAPI spec {path} is not a JSON object.")
        return cls(document)

    def operations(self) -> Iterator[OperationSpec]:
        """Walk every path/method pair in the document, in spec order."""
        for path, methods in self._paths.items():
            if isinstance(methods, Mapping) and "$ref" in methods:
                methods = self._resolve_path_item_ref(methods["$ref"], path)
            if not isinstance(methods, Mapping):
                continue
            for method, operation in methods.items():
                if method not in _HTTP_METHODS or not isinstance(operation, Mapping):
                    continue
                operation_id = operation.get("operationId")
                if not isinstance(operation_id, str):
                    operation_id = _fallback_operation_id(method, path)
                    logger.warning(
                        "Operation %s %s carries no operationId; using "
                        "synthesized id %r so its assets still reach "
                        "discovery and coverage (live SDK dispatch will "
                        "report it as undispatchable).",
                        method, path, operation_id,
                    )
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

    def _resolve_path_item_ref(self, ref: Any, path: str) -> Mapping[str, Any] | None:
        """Resolve a ``$ref`` path item (valid OpenAPI 3.x) in-document.

        External or dangling references cannot be followed with a local
        document alone; that is a discovery/coverage hole, so it is
        logged loudly by path instead of skipped silently.
        """
        resolved = (
            _json_pointer(self._spec, ref) if isinstance(ref, str) else None
        )
        if not isinstance(resolved, Mapping):
            logger.warning(
                "Path %s is a $ref (%r) that does not resolve inside the "
                "document (external or dangling); its operations cannot "
                "be discovered and will be missing from coverage.",
                path, ref,
            )
            return None
        return resolved
