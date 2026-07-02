"""LiveApiDataProvider: streaming ingestion via the official Meraki SDK.

Security and contract notes:

* The API token is read from ``MERAKI_DASHBOARD_API_KEY`` only at
  client-construction time and passed straight into the SDK — never
  retained on this object. SDK-side logging of the key is suppressed.
* The 10 req/s endpoint budget is honored natively by the SDK's
  built-in rate-limit handler.
* Feature discovery is spec-driven: the endpoints to call come from the
  :class:`~meraki2tf.openapi_parser.OpenApiParser` via the shared
  :mod:`~meraki2tf.providers.discovery` helpers, and each operation
  is dispatched onto the SDK dynamically via its OpenAPI tag/operationId
  (``dashboard.<tag>.<operationId>``) — no hard-coded endpoint lists.
"""

from __future__ import annotations

import logging
from typing import Any

from meraki2tf.config import read_api_key
from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.providers.discovery import (
    config_collection_operations,
    expand_endpoint_payload,
)
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)


class LiveDispatchError(RuntimeError):
    """A spec operation could not be resolved onto the Meraki SDK surface."""


class LiveApiDataProvider(MerakiDataProvider):
    """Fetches the domain graph from the Meraki cloud."""

    mode = "live"

    def __init__(self, parser: OpenApiParser | None = None) -> None:
        self._parser = parser
        self._client: Any = None

    def _dashboard(self) -> Any:
        if self._client is None:
            import meraki

            self._client = meraki.DashboardAPI(
                api_key=read_api_key(),
                suppress_logging=True,
                print_console=False,
                output_log=False,
            )
            logger.debug("Meraki dashboard client initialized (logging suppressed).")
        return self._client

    def fetch_network_graph(self, organization_id: str | None = None) -> NetworkGraph:
        if not organization_id:
            raise ValueError("Live mode requires an explicit organization ID.")
        dashboard = self._dashboard()
        networks = tuple(
            MerakiNetwork.from_payload(item)
            for item in dashboard.organizations.getOrganizationNetworks(
                organization_id, total_pages="all"
            )
        )
        devices = tuple(
            MerakiDevice.from_payload(item)
            for item in dashboard.organizations.getOrganizationDevices(
                organization_id, total_pages="all"
            )
        )
        features = tuple(self._discover_features(dashboard, networks))
        graph = NetworkGraph(
            organization_id=organization_id,
            networks=networks,
            devices=devices,
            features=features,
        )
        logger.info(
            "Live graph fetched: %d network(s), %d device(s), %d feature(s)",
            len(networks), len(devices), len(features),
        )
        return graph

    def _discover_features(
        self, dashboard: Any, networks: tuple[MerakiNetwork, ...]
    ) -> list[FeatureConfiguration]:
        """Execute every configuration GET the spec exposes, per network."""
        if self._parser is None:
            logger.debug("No OpenAPI parser supplied; skipping feature discovery.")
            return []
        feature_ops = config_collection_operations(self._parser)
        features: list[FeatureConfiguration] = []
        for network in networks:
            for op in feature_ops:
                try:
                    payload = self._call(dashboard, op, networkId=network.network_id)
                except Exception as exc:
                    # Networks routinely lack product types for a given
                    # endpoint; a refusal is data, not a fault.
                    logger.debug(
                        "Feature endpoint %s unavailable for network %s: %s",
                        op.path, network.network_id, exc,
                    )
                    continue
                features.extend(
                    expand_endpoint_payload(
                        self._parser, op, network.network_id, payload
                    )
                )
        return features

    def _call(self, dashboard: Any, op: OperationSpec, **params: str) -> Any:
        """Resolve ``dashboard.<first tag>.<operationId>`` dynamically."""
        section = getattr(dashboard, op.tags[0], None) if op.tags else None
        method = getattr(section, op.operation_id, None) if section is not None else None
        if method is None:
            raise LiveDispatchError(
                f"Meraki SDK exposes no method for operation {op.operation_id!r} "
                f"(tags={op.tags!r})."
            )
        return method(**params)

    def close(self) -> None:
        self._client = None
