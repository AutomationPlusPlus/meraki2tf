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

import inspect
import logging
from typing import Any

from meraki2tf.config import read_api_key
from meraki2tf.models import (
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser, entity_key
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
        features = tuple(
            self._discover_features(dashboard, organization_id, networks, devices)
        )
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
        self,
        dashboard: Any,
        organization_id: str,
        networks: tuple[MerakiNetwork, ...],
        devices: tuple[MerakiDevice, ...],
    ) -> list[FeatureConfiguration]:
        """Execute every configuration GET the spec exposes.

        Organization-scoped endpoints run once, network-scoped endpoints
        run per network, and device-scoped endpoints (switch ports,
        management interfaces, …) run per device serial — mirroring the
        scopes the dump provider resolves so both modalities discover
        the same surfaces.
        """
        if self._parser is None:
            logger.debug("No OpenAPI parser supplied; skipping feature discovery.")
            return []
        undispatchable: set[str] = set()
        features: list[FeatureConfiguration] = []
        mappings = self._parser.resource_mappings()
        lookup = self._parser.endpoint_lookup()

        def _folds_elsewhere(op: OperationSpec) -> bool:
            # Collections that fold into another entity list first-class
            # assets captured individually elsewhere (e.g.
            # /organizations/{organizationId}/networks → meraki_networks);
            # re-emitting them here would only produce unimportable noise.
            name = lookup.get(op.path)
            return name is not None and mappings[name].entity_key != entity_key(
                op.path
            )

        for op in config_collection_operations(self._parser, "organizationId"):
            if _folds_elsewhere(op):
                continue
            payload = self._try_call(
                dashboard, op, "organizationId", organization_id, undispatchable
            )
            if payload is not None:
                features.extend(
                    expand_endpoint_payload(
                        self._parser, op, organization_id, payload
                    )
                )
        network_ops = tuple(
            op
            for op in config_collection_operations(self._parser)
            if not _folds_elsewhere(op)
        )
        for network in networks:
            for op in network_ops:
                payload = self._try_call(
                    dashboard, op, "networkId", network.network_id, undispatchable
                )
                if payload is not None:
                    features.extend(
                        expand_endpoint_payload(
                            self._parser, op, network.network_id, payload
                        )
                    )
        serial_ops = tuple(
            op
            for op in config_collection_operations(self._parser, "serial")
            if not _folds_elsewhere(op)
        )
        for device in devices:
            for op in serial_ops:
                payload = self._try_call(
                    dashboard, op, "serial", device.serial, undispatchable
                )
                if payload is not None:
                    features.extend(
                        expand_endpoint_payload(
                            self._parser, op, device.serial, payload
                        )
                    )
        return features

    def _try_call(
        self,
        dashboard: Any,
        op: OperationSpec,
        scope_param: str,
        scope_value: str,
        undispatchable: set[str],
    ) -> Any:
        """One endpoint call; refusals are data, dispatch gaps are loud.

        A product-type refusal for one network is normal and logged at
        DEBUG, but an operation the installed SDK cannot dispatch at all
        would silently drop that endpoint's assets from every scope —
        that is missing DR coverage, so it warns once and is skipped for
        the rest of the run.
        """
        if op.operation_id in undispatchable:
            return None
        try:
            return self._call(dashboard, op, **{scope_param: scope_value})
        except LiveDispatchError as exc:
            undispatchable.add(op.operation_id)
            logger.warning(
                "Endpoint %s cannot be dispatched onto the installed meraki "
                "SDK (%s); its assets will be missing from this snapshot. "
                "Upgrade the SDK or pin a matching --spec release.",
                op.path, exc,
            )
            return None
        except Exception as exc:
            logger.debug(
                "Feature endpoint %s unavailable for %s %s: %s",
                op.path, scope_param, scope_value, exc,
            )
            return None

    def _call(self, dashboard: Any, op: OperationSpec, **params: str) -> Any:
        """Resolve ``dashboard.<first tag>.<operationId>`` dynamically."""
        section = getattr(dashboard, op.tags[0], None) if op.tags else None
        method = getattr(section, op.operation_id, None) if section is not None else None
        if method is None:
            raise LiveDispatchError(
                f"Meraki SDK exposes no method for operation {op.operation_id!r} "
                f"(tags={op.tags!r})."
            )
        # Paginated SDK methods default to total_pages=1; without "all"
        # a large collection would be silently truncated to its first page.
        if "total_pages" in inspect.signature(method).parameters:
            return method(total_pages="all", **params)
        return method(**params)

    def close(self) -> None:
        self._client = None
