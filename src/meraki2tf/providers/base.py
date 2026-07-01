"""MerakiDataProvider: the dual-modality ingestion protocol.

The pipeline consumes exactly one method — :meth:`fetch_network_graph`
— which returns the shared :class:`~meraki2tf.models.NetworkGraph`
domain model. The live cloud SDK and the offline JSON snapshot
implementations both honor this contract, so every downstream component
(HCL generation, drift orchestration, alerting) is data-source
agnostic by construction.
"""

from __future__ import annotations

import abc

from meraki2tf.models import NetworkGraph


class MerakiDataProvider(abc.ABC):
    """Uniform source of the discovered Meraki configuration surface."""

    #: Short mode identifier used in logs.
    mode: str = "abstract"

    @abc.abstractmethod
    def fetch_network_graph(self, organization_id: str | None = None) -> NetworkGraph:
        """Return the full domain graph (networks, devices, features).

        ``organization_id`` scopes live discovery; offline providers may
        fall back to the organization recorded in the snapshot.
        """

    @abc.abstractmethod
    def close(self) -> None:
        """Release any underlying transport resources."""

    def __enter__(self) -> "MerakiDataProvider":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
