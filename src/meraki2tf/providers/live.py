"""LiveApiDataProvider: streaming ingestion via the official Meraki SDK.

Security and contract notes:

* The API token is read from ``MERAKI_DASHBOARD_API_KEY`` only at
  client-construction time and passed straight into the SDK — never
  retained on this object. SDK-side logging of the key is suppressed.
* The 10 req/s endpoint budget is honored natively by the SDK's
  built-in rate-limit handler.
* Feature discovery is spec-driven: the endpoints to call come from the
  :class:`~meraki2tf.openapi_parser.OpenApiParser`, and each operation
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
from meraki2tf.openapi_parser import OpenApiParser, is_item_path
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)

#: Payload keys probed, in order, to identify one element of a listed
#: collection (after the endpoint's own item parameter name).
_ITEM_ID_FALLBACK_KEYS = ("id", "serial", "number")


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
        """Execute every network-scoped GET the spec exposes, per network."""
        if self._parser is None:
            logger.debug("No OpenAPI parser supplied; skipping feature discovery.")
            return []
        feature_ops = [
            op
            for op in self._parser.endpoints()
            if op.method == "get"
            and op.path_params == ("networkId",)
            and not is_item_path(op.path)
        ]
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
                features.extend(self._expand(op, network.network_id, payload))
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

    def _expand(
        self, op: OperationSpec, network_id: str, payload: Any
    ) -> list[FeatureConfiguration]:
        """Normalize one endpoint response into importable feature assets.

        Singleton configs (dict payloads) address themselves at the
        endpoint's own path; listed collections expand to one asset per
        element at the corresponding item path, so both shapes come out
        identical to what an offline snapshot records.
        """
        if isinstance(payload, dict):
            return [
                FeatureConfiguration(
                    api_path=op.path, path_values=(network_id,), payload=payload
                )
            ]
        item_op = self._item_operation_for(op)
        if item_op is None:
            logger.debug("Collection %s has no item endpoint; keeping one record.", op.path)
            return [
                FeatureConfiguration(
                    api_path=op.path,
                    path_values=(network_id,),
                    payload={"items": payload},
                )
            ]
        expanded: list[FeatureConfiguration] = []
        for element in payload:
            item_id = self._element_id(item_op, element)
            if item_id is None:
                logger.warning(
                    "Skipping element of %s with no identifiable ID field.", op.path
                )
                continue
            expanded.append(
                FeatureConfiguration(
                    api_path=item_op.path,
                    path_values=(network_id, item_id),
                    payload=element,
                )
            )
        return expanded

    def _item_operation_for(self, op: OperationSpec) -> OperationSpec | None:
        assert self._parser is not None  # guarded by _discover_features
        for candidate in self._parser.endpoints():
            if (
                candidate.method == "get"
                and is_item_path(candidate.path)
                and candidate.path.startswith(op.path + "/{")
                and len(candidate.path_params) == 2
            ):
                return candidate
        return None

    @staticmethod
    def _element_id(item_op: OperationSpec, element: Any) -> str | None:
        if not isinstance(element, dict):
            return None
        for key in (item_op.path_params[-1], *_ITEM_ID_FALLBACK_KEYS):
            if key in element and str(element[key]).strip():
                return str(element[key])
        return None

    def close(self) -> None:
        self._client = None
