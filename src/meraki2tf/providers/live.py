"""LiveApiDataProvider: streaming ingestion via the official Meraki SDK.

Security and contract notes:

* The API token is read from ``MERAKI_DASHBOARD_API_KEY`` only at
  client-construction time and passed straight into the SDK — never
  retained on this object. SDK-side logging of the key is suppressed.
* The 10 req/s endpoint budget is honored natively by the SDK's
  built-in rate-limit handler. The per-organization budget is shared
  with every other API consumer of the tenant, so the client is
  configured to wait and retry generously on 429; a throttle that
  survives all retries aborts discovery instead of shrinking the
  snapshot (completeness over speed).
* Feature discovery is spec-driven: the endpoints to call come from the
  :class:`~meraki2tf.openapi_parser.OpenApiParser` via the shared
  :mod:`~meraki2tf.providers.discovery` helpers, and each operation
  is dispatched onto the SDK dynamically via its OpenAPI tag/operationId
  (``dashboard.<tag>.<operationId>``) — no hard-coded endpoint lists.
"""

from __future__ import annotations

import inspect
import itertools
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from meraki2tf.config import read_api_key
from meraki2tf.models import (
    UNREADABLE_MARKER,
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
    nested_collection_operations,
    parent_item_path,
)
from meraki2tf.providers.ratelimit import AdaptiveTokenBucket
from meraki2tf.spec.engine import OperationSpec

logger = logging.getLogger(__name__)


class LiveDispatchError(RuntimeError):
    """A spec operation could not be resolved onto the Meraki SDK surface."""


class LiveRetryExhaustedError(RuntimeError):
    """A throttle survived the SDK's retries and every extended backoff.

    That means minutes of sustained saturation of the shared
    per-organization budget. Continuing would silently drop the affected
    objects from the snapshot — a false sense of DR coverage — so
    discovery aborts loudly instead.
    """


class _EndpointUnreadable(Exception):
    """One endpoint persistently server-errors; its content is unknowable.

    Meraki is known to return deterministic 500s for specific endpoints
    on specific network configurations, so — unlike a throttle — this is
    not cured by waiting and must not abort the whole run. The caller
    records the endpoint as a coverage gap instead.
    """


#: SDK retry budget for rate-limited calls. The organization-wide limit is
#: shared with other API consumers, so transient 429 storms are expected on
#: busy tenants; each retry honors the Retry-After header.
_SDK_MAXIMUM_RETRIES = 10

#: Statuses meaning "the API refused this attempt", never "this feature
#: does not apply to that scope".
_THROTTLE_HTTP_STATUSES = frozenset({429})
_SERVER_ERROR_HTTP_STATUSES = frozenset({500, 502, 503, 504})
#: Auth refusals are in the "refused" class too: a key rotated mid-sweep
#: or an admin scope that 403s an endpoint every week must surface as a
#: coverage gap, never read as "this feature does not apply".
_AUTH_HTTP_STATUSES = frozenset({401, 403})


def _scope_label(params: dict[str, str]) -> str:
    """Human-readable scope for log/error messages, any parameter depth."""
    return ", ".join(f"{name} {value}" for name, value in params.items())


#: Per-call throttle budget: every attempt is paced by the shared AIMD
#: bucket (whose global pauses and rate cuts grow under sustained
#: saturation), so this many failed attempts means minutes of a
#: saturated organization budget — abort rather than ship a snapshot
#: that looks complete. Completeness over speed.
_MAX_THROTTLE_ATTEMPTS = 40

#: Worker-pool width for feature discovery; the AIMD bucket paces all
#: workers together, so width buys concurrency, never request rate.
DISCOVERY_WORKERS_ENV_VAR = "MERAKI2TF_DISCOVERY_WORKERS"
_DEFAULT_DISCOVERY_WORKERS = 8


class LiveApiDataProvider(MerakiDataProvider):
    """Fetches the domain graph from the Meraki cloud."""

    mode = "live"

    def __init__(self, parser: OpenApiParser | None = None) -> None:
        self._parser = parser
        self._client: Any = None
        #: True when _dashboard() built the client itself (vs a test
        #: injecting one) — decides whether workers may share it.
        self._constructed = False
        self._local = threading.local()
        self._workers = max(
            1,
            int(os.environ.get(DISCOVERY_WORKERS_ENV_VAR, "").strip()
                or _DEFAULT_DISCOVERY_WORKERS),
        )

    def _build_client(self, wait_on_rate_limit: bool) -> Any:
        import meraki

        return meraki.DashboardAPI(
            api_key=read_api_key(),
            suppress_logging=True,
            print_console=False,
            output_log=False,
            wait_on_rate_limit=wait_on_rate_limit,
            maximum_retries=_SDK_MAXIMUM_RETRIES,
        )

    def _dashboard(self) -> Any:
        if self._client is None:
            self._client = self._build_client(wait_on_rate_limit=True)
            self._constructed = True
            logger.debug("Meraki dashboard client initialized (logging suppressed).")
        return self._client

    def _worker_dashboard(self) -> Any:
        """One SDK client per worker thread.

        ``requests.Session`` is not documented thread-safe, so real
        clients are never shared across the pool. 429 waiting is turned
        off — the shared AIMD bucket owns all pacing decisions. An
        externally injected client (tests) is shared as-is.
        """
        if self._client is not None and not self._constructed:
            return self._client
        client = getattr(self._local, "client", None)
        if client is None:
            client = self._build_client(wait_on_rate_limit=False)
            self._local.client = client
        return client

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
        the same surfaces. Nested (multi-parameter) surfaces run in
        parameter-count levels, scoping off elements the previous level
        discovered.

        Work items inside a level are independent, so they run on a
        worker pool paced by one shared AIMD bucket: width buys back the
        idle time a sequential sweep wastes waiting on round trips, and
        the bucket guarantees the pool never outruns the shared
        per-organization budget. Results are gathered in submission
        order, so discovery output stays deterministic; any fatal
        failure (throttle exhaustion) cancels the remaining work and
        aborts the run — a snapshot is complete or it is nothing.
        """
        if self._parser is None:
            logger.debug("No OpenAPI parser supplied; skipping feature discovery.")
            return []
        parser = self._parser
        undispatchable: set[str] = set()
        undispatchable_lock = threading.Lock()
        bucket = AdaptiveTokenBucket()
        abort = threading.Event()
        features: list[FeatureConfiguration] = []
        mappings = parser.resource_mappings()
        lookup = parser.endpoint_lookup()

        def _folds_elsewhere(op: OperationSpec) -> bool:
            # Collections that fold into another entity list first-class
            # assets captured individually elsewhere (e.g.
            # /organizations/{organizationId}/networks → meraki_networks);
            # re-emitting them here would only produce unimportable noise.
            name = lookup.get(op.path)
            return name is not None and mappings[name].entity_key != entity_key(
                op.path
            )

        def _fetch(
            op: OperationSpec, scope_values: tuple[str, ...]
        ) -> list[FeatureConfiguration]:
            params = dict(zip(op.path_params, scope_values))
            try:
                payload = self._try_call(
                    op, params, undispatchable, undispatchable_lock, bucket, abort
                )
            except _EndpointUnreadable as exc:
                logger.warning(
                    "Feature endpoint %s for %s could not be read (%s); "
                    "recorded as a coverage gap — its objects are missing "
                    "from this snapshot.",
                    op.path, _scope_label(params), exc,
                )
                return [
                    FeatureConfiguration(
                        api_path=op.path,
                        path_values=scope_values,
                        payload={UNREADABLE_MARKER: str(exc)},
                    )
                ]
            if payload is None:
                return []
            return expand_endpoint_payload(parser, op, scope_values, payload)

        def _run_level(
            items: list[tuple[OperationSpec, tuple[str, ...]]]
        ) -> None:
            if not items:
                return
            with ThreadPoolExecutor(max_workers=self._workers) as pool:
                futures = [
                    pool.submit(_fetch, op, scope_values)
                    for op, scope_values in items
                ]
                try:
                    # Submission order, not completion order — discovery
                    # output stays deterministic under any pool width.
                    for future in futures:
                        features.extend(future.result())
                except BaseException:
                    # Fail fast and loud: cancel the level, let workers
                    # drain, and re-raise so the orchestrator alerts. A
                    # partially discovered snapshot must never look done.
                    abort.set()
                    for future in futures:
                        future.cancel()
                    raise

        level: list[tuple[OperationSpec, tuple[str, ...]]] = [
            (op, (organization_id,))
            for op in config_collection_operations(parser, "organizationId")
            if not _folds_elsewhere(op)
        ]
        network_ops = tuple(
            op
            for op in config_collection_operations(parser)
            if not _folds_elsewhere(op)
        )
        level.extend(
            (op, (network.network_id,))
            for network in networks
            for op in network_ops
        )
        serial_ops = tuple(
            op
            for op in config_collection_operations(parser, "serial")
            if not _folds_elsewhere(op)
        )
        level.extend(
            (op, (device.serial,)) for device in devices for op in serial_ops
        )
        _run_level(level)

        # Nested (multi-parameter) configuration surfaces: per-SSID
        # sub-configs, switch-stack routing, config-template switch
        # profiles, per-interface DHCP, ... Grouped by parameter count:
        # each level scopes off elements the previous levels discovered.
        nested_ops = [
            op
            for op in nested_collection_operations(parser)
            # Same folding guard as the single-scope pass; no nested
            # surface in today's spec folds, hence uncoverable.
            if not _folds_elsewhere(op)  # pragma: no branch
        ]
        # Collection paths this run actually queried (or captures
        # first-class via folding): a nested op whose parent collection
        # is in this set and simply yielded zero elements is genuine
        # emptiness; one whose parent collection was never queryable at
        # all is a structural blind spot that must be reported, not
        # silently skipped (Cardinal Rule 2).
        queried_paths = {op.path for op, _ in level}
        queried_paths.update(
            op.path
            for op in parser.endpoints()
            if op.method == "get" and _folds_elsewhere(op)
        )
        for _, level_ops in itertools.groupby(
            nested_ops, key=lambda op: len(op.path_params)
        ):
            nested_level: list[tuple[OperationSpec, tuple[str, ...]]] = []
            for op in level_ops:
                parent = parent_item_path(op.path)
                scopes = [
                    feature.path_values
                    for feature in features
                    if feature.api_path == parent
                    and len(feature.path_values) == len(op.path_params)
                ]
                if scopes:
                    nested_level.extend((op, values) for values in scopes)
                    continue
                parent_collection = parent.rsplit("/", 1)[0]
                if parent_collection not in queried_paths:
                    logger.warning(
                        "Nested surface %s cannot be swept: its parent "
                        "collection %s is not discoverable (read-only or "
                        "filtered out); recorded as a coverage gap — any "
                        "configuration there must be verified manually.",
                        op.path, parent_collection,
                    )
                    features.append(
                        FeatureConfiguration(
                            api_path=op.path,
                            path_values=(),
                            payload={
                                UNREADABLE_MARKER: (
                                    "parent collection "
                                    f"{parent_collection} is not "
                                    "discoverable, so this surface was "
                                    "never queried"
                                )
                            },
                        )
                    )
            queried_paths.update(op.path for op, _ in nested_level)
            _run_level(nested_level)
        return features

    def _try_call(
        self,
        op: OperationSpec,
        params: dict[str, str],
        undispatchable: set[str],
        undispatchable_lock: threading.Lock,
        bucket: AdaptiveTokenBucket,
        abort: threading.Event,
    ) -> Any:
        """One endpoint call; refusals are data, API failures never are.

        A product-type refusal for one network (400/404) is normal and
        logged at DEBUG. An operation the installed SDK cannot dispatch at
        all would silently drop that endpoint's assets from every scope —
        that is missing DR coverage, so it warns once and is skipped for
        the rest of the run. Throttles are retried under the shared AIMD
        bucket's pacing (its rate cuts and global pauses grow while the
        organization budget stays saturated); a call that exhausts the
        attempt budget aborts discovery (LiveRetryExhaustedError) rather
        than emit an incomplete snapshot that looks complete. A
        persistent server error raises _EndpointUnreadable so the caller
        records that one endpoint as a coverage gap without losing the
        rest of the run.
        """
        with undispatchable_lock:
            if op.operation_id in undispatchable:
                return None
        dashboard = self._worker_dashboard()
        throttled_attempts = 0
        while not abort.is_set():
            bucket.acquire()
            try:
                result = self._call(dashboard, op, **params)
            except LiveDispatchError as exc:
                with undispatchable_lock:
                    fresh = op.operation_id not in undispatchable
                    undispatchable.add(op.operation_id)
                if fresh:
                    logger.warning(
                        "Endpoint %s cannot be dispatched onto the installed "
                        "meraki SDK (%s); its assets will be missing from "
                        "this snapshot. Upgrade the SDK or pin a matching "
                        "--spec release.",
                        op.path, exc,
                    )
                return None
            except Exception as exc:
                status = getattr(exc, "status", None)
                if status in _THROTTLE_HTTP_STATUSES:
                    bucket.on_throttle()
                    throttled_attempts += 1
                    if throttled_attempts >= _MAX_THROTTLE_ATTEMPTS:
                        raise LiveRetryExhaustedError(
                            f"Feature endpoint {op.path} for "
                            f"{_scope_label(params)} was still throttled "
                            f"after {_MAX_THROTTLE_ATTEMPTS} paced attempts; "
                            "aborting discovery because the snapshot would "
                            "be silently incomplete. Rerun once the API is "
                            "responsive (the per-organization rate budget "
                            "is shared with other API consumers)."
                        ) from exc
                    continue
                if status in _SERVER_ERROR_HTTP_STATUSES:
                    raise _EndpointUnreadable(
                        f"HTTP {status} from the Meraki API after every retry"
                    ) from exc
                if status in _AUTH_HTTP_STATUSES:
                    # Not "feature does not apply": a rotated key or a
                    # scope-limited admin would otherwise vanish whole
                    # endpoints from the snapshot behind a success
                    # notification.
                    raise _EndpointUnreadable(
                        f"HTTP {status}: the API key was refused for this "
                        "endpoint (rotated key or missing admin scope)"
                    ) from exc
                logger.debug(
                    "Feature endpoint %s unavailable for %s: %s",
                    op.path, _scope_label(params), exc,
                )
                return None
            bucket.on_success()
            return result
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
