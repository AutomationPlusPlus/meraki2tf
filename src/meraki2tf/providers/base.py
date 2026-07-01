"""Abstract data provider protocol for network graph ingestion.

The pipeline never calls the Meraki SDK or reads files directly; it asks
a provider to execute *operations* — identified by the ``operationId``
values the spec ingestion engine discovers in the OpenAPI document.
This keeps discovery fully dynamic (no hard-coded endpoints) and gives
live and offline runs identical semantics.
"""

from __future__ import annotations

import abc
from typing import Any


class OperationNotInSnapshotError(LookupError):
    """The requested operation has no captured result in the offline dump."""


class ConfigurationProvider(abc.ABC):
    """Uniform source of Meraki configuration data.

    ``operation_id`` is an OpenAPI operationId (e.g. ``getOrganizationNetworks``)
    and ``path_params`` are the templated path values that operation
    requires (e.g. ``organizationId="..."``). Implementations return the
    parsed JSON payload the Meraki API would produce.
    """

    #: Short mode identifier used in logs.
    mode: str = "abstract"

    @abc.abstractmethod
    def execute(self, operation_id: str, **path_params: str) -> Any:
        """Return the payload for one discovered API operation."""

    @abc.abstractmethod
    def close(self) -> None:
        """Release any underlying transport resources."""

    def __enter__(self) -> "ConfigurationProvider":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
