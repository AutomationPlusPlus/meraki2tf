"""Offline provider backed by a local JSON snapshot (``--from-dump``).

Snapshot contract: a JSON object whose ``operations`` key maps an
OpenAPI operationId — suffixed with a ``/``-joined ordered list of path
parameter values when the operation is parameterized — to the captured
payload, e.g.::

    {
      "operations": {
        "getOrganizations": [...],
        "getOrganizationNetworks/123456": [...]
      }
    }

This mirrors exactly what the live provider would return, giving
air-gapped and regression runs full structural parity.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from meraki2tf.providers.base import ConfigurationProvider, OperationNotInSnapshotError

logger = logging.getLogger(__name__)


class MalformedDumpError(ValueError):
    """The snapshot file is not valid JSON or lacks the operations map."""


class DumpProvider(ConfigurationProvider):
    """Serves configuration data from an offline snapshot file."""

    mode = "dump"

    def __init__(self, dump_path: Path) -> None:
        self._path = dump_path
        try:
            document = json.loads(dump_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise MalformedDumpError(f"Cannot read snapshot {dump_path}: {exc}") from exc
        operations = document.get("operations") if isinstance(document, dict) else None
        if not isinstance(operations, dict):
            raise MalformedDumpError(
                f"Snapshot {dump_path} must be an object with an 'operations' map."
            )
        self._operations: dict[str, Any] = operations
        logger.debug("Loaded snapshot with %d captured operation(s)", len(operations))

    def execute(self, operation_id: str, **path_params: str) -> Any:
        key = "/".join([operation_id, *path_params.values()])
        if key not in self._operations:
            raise OperationNotInSnapshotError(
                f"Operation {key!r} was not captured in snapshot {self._path}."
            )
        return self._operations[key]

    def close(self) -> None:
        """Nothing to release for a file-backed snapshot."""
