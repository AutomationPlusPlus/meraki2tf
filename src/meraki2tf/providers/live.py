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

import functools
import inspect
import itertools
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from meraki2tf.config import read_api_key
from meraki2tf.models import (
    UNREADABLE_MARKER,
    DiscoveryDiagnostics,
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
    SuspectEndpoint,
)
from meraki2tf.openapi_parser import (
    OpenApiParser,
    TerraformResourceMapping,
    entity_key,
)
from meraki2tf.providers.base import MerakiDataProvider
from meraki2tf.providers.discovery import (
    aggregation_collection_path,
    aggregation_mappings,
    config_collection_operations,
    expand_endpoint_payload,
    explode_aggregation_payload,
    nested_collection_operations,
    network_product_types,
    parent_item_path,
    product_segment,
)
from meraki2tf.providers.discovery_checkpoint import (
    OUTCOME_PAYLOAD,
    OUTCOME_REFUSED,
    OUTCOME_UNREADABLE,
    CallOutcome,
    DiscoveryCheckpoint,
)
from meraki2tf.providers.progress import DiscoveryProgress
from meraki2tf.providers.ratelimit import AdaptiveTokenBucket
from meraki2tf.scope import LiveNetworkScope, SnapshotScope
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
#: The only statuses that genuinely mean "this feature does not apply
#: to that scope" (product-type refusals, endpoints absent for the
#: network). Every other failure shape — including an APIError carrying
#: status 200 (the SDK raises one when a 200 body never parses as
#: JSON) and exceptions with no status at all — is an API failure and
#: must surface as a coverage gap, never as a quiet skip.
_SCOPE_REFUSAL_HTTP_STATUSES = frozenset({400, 404})


def _scope_label(params: dict[str, str]) -> str:
    """Human-readable scope for log/error messages, any parameter depth."""
    return ", ".join(f"{name} {value}" for name, value in params.items())


#: An endpoint refused by every scope becomes a suspect only after this
#: many attempts — one or two refusals are routine product mismatches.
_SUSPECT_MINIMUM_SCOPES = 3


class _EndpointStats:
    """Thread-safe per-endpoint attempt/refusal tally for one discovery run.

    Feature-not-enabled 400/404s are legitimate absence and stay
    absent-by-design; this tally only surfaces the anomaly of an
    endpoint refusing *every* scope it was tried against, as a
    per-endpoint diagnostic in the coverage manifest.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tried: dict[str, int] = {}
        self._refused: dict[str, int] = {}

    def record(self, path: str, refused: bool) -> None:
        with self._lock:
            self._tried[path] = self._tried.get(path, 0) + 1
            if refused:
                self._refused[path] = self._refused.get(path, 0) + 1

    def suspects(self) -> tuple[SuspectEndpoint, ...]:
        with self._lock:
            return tuple(
                SuspectEndpoint(api_path=path, scopes_tried=tried)
                for path, tried in sorted(self._tried.items())
                if tried >= _SUSPECT_MINIMUM_SCOPES
                and self._refused.get(path, 0) == tried
            )


#: Session verbs a generated SDK method may call and still be
#: dispatchable by discovery. Discovery filters operations by the
#: *spec-declared* method, but dispatch resolves purely by
#: operationId/tag strings from that same spec — so a stale or
#: tampered spec could label a mutating SDK method as a GET. The
#: resolved method's own source is the ground truth for what it does.
_READ_ONLY_SESSION_VERBS = frozenset({"get", "get_pages"})
_SESSION_VERB_PATTERN = re.compile(r"self\._session\.([A-Za-z_]+)\(")
#: Underlying SDK function → verified-read-only verdict (memoized; the
#: SDK surface is a few hundred functions and source parsing is not free).
_read_only_verdicts: dict[Any, bool] = {}


def _method_is_read_only(method: Any) -> bool:
    """True when the resolved SDK method verifiably only reads.

    Only real ``meraki``-package methods carry the generated
    ``self._session.<verb>(`` fingerprint; anything else (a test double,
    a wrapper) is outside the spec-poisoning threat model and passes.
    Real SDK methods whose source cannot be read or whose verbs are not
    exclusively read-only are refused — fail closed on Cardinal Rule 1.
    """
    func = getattr(method, "__func__", method)
    module = getattr(func, "__module__", "") or ""
    if module.split(".", 1)[0] != "meraki":
        return True
    cached = _read_only_verdicts.get(func)
    if cached is not None:
        return cached
    try:
        source = inspect.getsource(func)
    except (OSError, TypeError):
        verdict = False
    else:
        verbs = set(_SESSION_VERB_PATTERN.findall(source))
        verdict = bool(verbs) and verbs <= _READ_ONLY_SESSION_VERBS
    _read_only_verdicts[func] = verdict
    return verdict


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

#: Config templates hold network configuration readable through the
#: same ``/networks/{networkId}/...`` endpoints, scoped by the template
#: ID — but ``getOrganizationNetworks`` never lists templates. The
#: template list itself is spec-discovered like any collection; that a
#: template ID is a valid ``{networkId}`` scope is Meraki domain
#: semantics (documented dashboard behavior), not a resource mapping.
CONFIG_TEMPLATE_ITEM_PATH = (
    "/organizations/{organizationId}/configTemplates/{configTemplateId}"
)


class LiveApiDataProvider(MerakiDataProvider):
    """Fetches the domain graph from the Meraki cloud."""

    mode = "live"

    def __init__(
        self,
        parser: OpenApiParser | None = None,
        *,
        network_scope: LiveNetworkScope | None = None,
        checkpoint_path: Path | None = None,
        spec_sha256: str | None = None,
        progress_clock: Callable[[], float] | None = None,
    ) -> None:
        self._parser = parser
        #: When set, discovery covers only the matching networks and
        #: their devices; org-level surfaces and the config-template
        #: sweep stay in scope (references from scoped networks must
        #: remain recreatable). Unclaimed devices (no network) fall
        #: outside every network scope by definition.
        self._network_scope = network_scope
        #: When set, completed calls are journaled here (0600) so an
        #: aborted sweep resumes instead of restarting from zero; the
        #: file is deleted when discovery completes. ``spec_sha256``
        #: stamps/verifies the journal's identity header — replayed
        #: outcomes expand through the spec, so a spec swap between
        #: runs must refuse the resume rather than skew the graph.
        self._checkpoint_path = checkpoint_path
        self._spec_sha256 = spec_sha256
        #: Monotonic clock driving the ~30s progress-line cadence;
        #: injectable so tests control time instead of sleeping.
        self._progress_clock = progress_clock or time.monotonic
        #: Mirror of the dump provider's partial-scope declaration:
        #: set after a scoped fetch so the pipeline stamps every
        #: artifact of a ``--only`` run partial exactly like a partial
        #: snapshot input (Cardinal Rule 2 — a scoped kit must never
        #: read as a full-organization capture).
        self.snapshot_scope: SnapshotScope | None = None
        #: Side facts of the latest discovery pass (suspect endpoints,
        #: prefilter skip count) for the coverage manifest; ``None``
        #: until a feature-discovery pass has run.
        self.discovery_diagnostics: DiscoveryDiagnostics | None = None
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
        # Opened before any API call: an identity mismatch (wrong org,
        # wrong spec) must refuse the run without spending API budget.
        # The two org-level list calls below are deliberately NOT
        # checkpointed — they are two cheap calls, and re-listing on
        # resume picks up networks/devices created since the abort.
        checkpoint: DiscoveryCheckpoint | None = None
        if self._checkpoint_path is not None:
            checkpoint = DiscoveryCheckpoint(
                self._checkpoint_path, organization_id,
                self._spec_sha256 or "",
            )
        try:
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
            # The full pre-scope network universe: aggregation-row scope
            # healing must recognize every real network in the org, even
            # ones a --only selector excludes from this snapshot.
            network_universe = networks
            if self._network_scope is not None:
                total_networks, total_devices = len(networks), len(devices)
                networks = self._network_scope.apply(networks)
                selected_ids = frozenset(n.network_id for n in networks)
                devices = tuple(
                    d for d in devices if d.network_id in selected_ids
                )
                logger.info(
                    "Scoped discovery: %d of %d network(s) and %d of %d "
                    "device(s) selected; org-level surfaces remain in scope.",
                    len(networks), total_networks, len(devices), total_devices,
                )
            features = tuple(
                self._discover_features(
                    dashboard, organization_id, networks, devices,
                    checkpoint=checkpoint,
                    network_universe=network_universe,
                )
            )
        except BaseException:
            # Abort (throttle exhaustion, Ctrl-C, crash): the journal
            # survives so the next run resumes the completed calls.
            if checkpoint is not None:
                checkpoint.close()
                logger.warning(
                    "Discovery aborted; checkpoint %s kept — re-run with "
                    "the same --discovery-checkpoint to resume the "
                    "completed calls instead of restarting.",
                    self._checkpoint_path,
                )
            raise
        if checkpoint is not None:
            checkpoint.complete()
        graph = NetworkGraph(
            organization_id=organization_id,
            networks=networks,
            devices=devices,
            features=features,
        )
        if self._network_scope is not None:
            self.snapshot_scope = SnapshotScope(
                network_ids=tuple(
                    network.network_id for network in networks
                ),
                selectors=self._network_scope.selectors,
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
        checkpoint: DiscoveryCheckpoint | None = None,
        network_universe: tuple[MerakiNetwork, ...] | None = None,
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
        stats = _EndpointStats()
        progress = DiscoveryProgress(bucket, clock=self._progress_clock)
        features: list[FeatureConfiguration] = []
        mappings = parser.resource_mappings()
        lookup = parser.endpoint_lookup()
        #: Valid product types per the createNetwork enum; empty when
        #: the spec declares none (which disables prefiltering).
        product_types = network_product_types(parser)
        skipped_out_of_scope = 0

        def _folds_elsewhere(op: OperationSpec) -> bool:
            # Collections that fold into another entity list first-class
            # assets captured individually elsewhere (e.g.
            # /organizations/{organizationId}/networks → meraki_networks);
            # re-emitting them here would only produce unimportable noise.
            name = lookup.get(op.path)
            return name is not None and mappings[name].entity_key != entity_key(
                op.path
            )

        def _replay(
            op: OperationSpec,
            scope_values: tuple[str, ...],
            recorded: CallOutcome,
        ) -> list[FeatureConfiguration]:
            """A checkpointed outcome, re-expanded like a fresh call.

            Payloads run through the very same spec-driven expansion as
            live responses (the checkpoint's spec-sha guard makes that
            sound), refusals replay their suspect-endpoint tally, and
            unreadable gaps reproduce their gap record verbatim — so a
            resumed graph is identical to an uninterrupted run's.
            """
            if recorded.kind == OUTCOME_UNREADABLE:
                return [
                    FeatureConfiguration(
                        api_path=op.path,
                        path_values=scope_values,
                        payload={UNREADABLE_MARKER: recorded.reason},
                    )
                ]
            if recorded.kind == OUTCOME_REFUSED:
                stats.record(op.path, refused=True)
                return []
            stats.record(op.path, refused=False)
            return expand_endpoint_payload(
                parser, op, scope_values, recorded.payload
            )

        def _fetch(
            op: OperationSpec, scope_values: tuple[str, ...]
        ) -> list[FeatureConfiguration]:
            params = dict(zip(op.path_params, scope_values))
            if checkpoint is not None:
                recorded = checkpoint.get(op.path, scope_values)
                if recorded is not None:
                    return _replay(op, scope_values, recorded)
            try:
                payload = self._try_call(
                    op, params, undispatchable, undispatchable_lock, bucket,
                    abort, stats=stats,
                )
            except _EndpointUnreadable as exc:
                logger.warning(
                    "Feature endpoint %s for %s could not be read (%s); "
                    "recorded as a coverage gap — its objects are missing "
                    "from this snapshot.",
                    op.path, _scope_label(params), exc,
                )
                if checkpoint is not None:
                    checkpoint.record(
                        op.path, scope_values,
                        CallOutcome(kind=OUTCOME_UNREADABLE, reason=str(exc)),
                    )
                return [
                    FeatureConfiguration(
                        api_path=op.path,
                        path_values=scope_values,
                        payload={UNREADABLE_MARKER: str(exc)},
                    )
                ]
            if payload is None:
                # None is a genuine scope refusal — unless the run is
                # aborting, in which case _try_call bails out with None
                # for calls that never happened; journaling those as
                # refusals would silently drop them from every resume.
                if checkpoint is not None and not abort.is_set():
                    checkpoint.record(
                        op.path, scope_values,
                        CallOutcome(kind=OUTCOME_REFUSED),
                    )
                return []
            if checkpoint is not None:
                checkpoint.record(
                    op.path, scope_values,
                    CallOutcome(kind=OUTCOME_PAYLOAD, payload=payload),
                )
            return expand_endpoint_payload(parser, op, scope_values, payload)

        def _aggregation_gap(
            mapping: TerraformResourceMapping, reason: str
        ) -> list[FeatureConfiguration]:
            return [
                FeatureConfiguration(
                    api_path=aggregation_collection_path(mapping),
                    path_values=(),
                    payload={UNREADABLE_MARKER: reason},
                )
            ]

        #: Config-template id → name, filled from the single-scope
        #: level's discoveries before the aggregation level runs: a
        #: byNetwork row scoped by a template's per-product child id is
        #: named "<template name> - <product>", which only the template
        #: list can resolve.
        template_scopes: dict[str, str] = {}

        def _explode_scoped(
            mapping: TerraformResourceMapping, payload: Any
        ) -> list[FeatureConfiguration]:
            # The full network universe (pre --only scoping) plus every
            # config template lets the explosion detect phantom row
            # scopes (per-product child ids of networks AND templates)
            # and re-scope them to the parent they name; the scope
            # filter below then applies to resolved ids.
            known_scopes = {
                network.network_id: network.name
                for network in (
                    networks if network_universe is None else network_universe
                )
            }
            known_scopes.update(template_scopes)
            exploded = explode_aggregation_payload(
                mapping, payload, known_networks=known_scopes
            )
            if self._network_scope is not None:
                # Template-scoped rows always pass: the template sweep
                # reads config templates regardless of the network
                # scope, and aggregation-sourced assets must agree.
                allowed = frozenset(
                    network.network_id for network in networks
                ) | frozenset(template_scopes)
                exploded = [
                    feature
                    for feature in exploded
                    if not feature.path_values
                    or feature.path_values[0] in allowed
                ]
            return exploded

        def _fetch_aggregation(
            mapping: TerraformResourceMapping,
        ) -> list[FeatureConfiguration]:
            """One org-scoped aggregation GET, exploded per scope.

            The collection source of a GET-less entity (Air Marshal,
            RRM, uplink NAT, …): a single org-level call replaces the
            per-network GET the API never offered. Failures gap the
            entity's own collection path so heal/deletion flows exempt
            it through the ordinary unreadable-marker mechanism.
            Checkpointed under the aggregation endpoint's own path, so
            aggregation sweeps resume exactly like per-scope calls.
            """
            agg_op = mapping.aggregation_get
            assert agg_op is not None  # only adopted mappings are queued
            params = {"organizationId": organization_id}
            key_values = (organization_id,)
            if checkpoint is not None:
                recorded = checkpoint.get(agg_op.path, key_values)
                if recorded is not None:
                    if recorded.kind == OUTCOME_UNREADABLE:
                        return _aggregation_gap(mapping, recorded.reason)
                    if recorded.kind == OUTCOME_REFUSED:
                        stats.record(agg_op.path, refused=True)
                        return []
                    stats.record(agg_op.path, refused=False)
                    return _explode_scoped(mapping, recorded.payload)
            try:
                payload = self._try_call(
                    agg_op, params, undispatchable, undispatchable_lock,
                    bucket, abort, stats=stats,
                )
            except _EndpointUnreadable as exc:
                collection_path = aggregation_collection_path(mapping)
                logger.warning(
                    "Aggregation endpoint %s could not be read (%s); "
                    "entity %s is recorded as a coverage gap — its "
                    "objects are missing from this snapshot.",
                    agg_op.path, exc, collection_path,
                )
                if checkpoint is not None:
                    checkpoint.record(
                        agg_op.path, key_values,
                        CallOutcome(kind=OUTCOME_UNREADABLE, reason=str(exc)),
                    )
                return _aggregation_gap(mapping, str(exc))
            if payload is None:
                # A 400/404 at org scope: the organization does not
                # carry the product at all — absence by design (not
                # journaled while aborting, like _fetch).
                if checkpoint is not None and not abort.is_set():
                    checkpoint.record(
                        agg_op.path, key_values,
                        CallOutcome(kind=OUTCOME_REFUSED),
                    )
                return []
            if checkpoint is not None:
                checkpoint.record(
                    agg_op.path, key_values,
                    CallOutcome(kind=OUTCOME_PAYLOAD, payload=payload),
                )
            return _explode_scoped(mapping, payload)

        def _tracked(
            job: Callable[[], list[FeatureConfiguration]]
        ) -> list[FeatureConfiguration]:
            try:
                return job()
            finally:
                # Failures count as completed work too: the progress
                # line reports throughput, not success.
                progress.item_completed()

        def _run_level(
            label: str,
            items: list[Callable[[], list[FeatureConfiguration]]],
        ) -> None:
            if not items:
                return
            progress.start_level(label, len(items))
            with ThreadPoolExecutor(max_workers=self._workers) as pool:
                futures = [pool.submit(_tracked, job) for job in items]
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

        level: list[Callable[[], list[FeatureConfiguration]]] = []
        #: Paths this run actually queued for querying — feeds the
        #: nested-surface sweepability audit below.
        level_paths: set[str] = set()
        for op in config_collection_operations(parser, "organizationId"):
            if not _folds_elsewhere(op):
                level.append(functools.partial(_fetch, op, (organization_id,)))
                level_paths.add(op.path)
        network_ops = tuple(
            op
            for op in config_collection_operations(parser)
            if not _folds_elsewhere(op)
        )
        for network in networks:
            for op in network_ops:
                segment = product_segment(op)
                if (
                    segment in product_types
                    and network.product_types
                    and segment not in network.product_types
                ):
                    # The endpoint's product family is provably outside
                    # this network's product types: the call could only
                    # 400/404. Skipping it behaves exactly like that
                    # refusal — absent-by-design, no record. Segments
                    # that are not exact product types (sm, …) and
                    # networks with unknown product types never filter.
                    skipped_out_of_scope += 1
                    continue
                level.append(
                    functools.partial(_fetch, op, (network.network_id,))
                )
                level_paths.add(op.path)
        serial_ops = tuple(
            op
            for op in config_collection_operations(parser, "serial")
            if not _folds_elsewhere(op)
        )
        for device in devices:
            device_type = str(device.payload.get("productType") or "")
            for op in serial_ops:
                segment = product_segment(op)
                if (
                    device_type
                    and segment in product_types
                    and segment != device_type
                ):
                    # Same conservative rule per device: filter only on
                    # an exact spec-derived product-type segment and a
                    # known device productType.
                    skipped_out_of_scope += 1
                    continue
                level.append(functools.partial(_fetch, op, (device.serial,)))
                level_paths.add(op.path)
        # GET-less entities adopted via an org-scoped aggregation GET
        # (byNetwork pattern): one call each at org scope, exploded into
        # per-scope assets. Without these the whole surface class (Air
        # Marshal, RRM, uplink NAT, …) silently vanishes. They run as
        # their own level AFTER the single-scope sweep so the explosion
        # resolves phantom child scopes against everything that sweep
        # discovered — including config templates, whose per-product
        # children appear in byNetwork rows too.
        aggregation_level: list[
            Callable[[], list[FeatureConfiguration]]
        ] = []
        for mapping in aggregation_mappings(parser):
            aggregation_level.append(
                functools.partial(_fetch_aggregation, mapping)
            )
            level_paths.add(aggregation_collection_path(mapping))
        _run_level("single-scope", level)
        if skipped_out_of_scope:
            logger.info(
                "Product-type prefilter skipped %d endpoint call(s) whose "
                "product family is outside the scope's product types "
                "(absent-by-design, like a scope refusal).",
                skipped_out_of_scope,
            )

        # Template-held configuration (SSIDs, VLANs, firewall rules on
        # a config template) is invisible to the per-network sweep —
        # without this pass it would vanish from the snapshot and the
        # rebuilt org would re-inherit nothing (Cardinal Rule 2).
        template_scopes.update(
            {
                feature.path_values[-1]: str(
                    feature.payload.get("name") or ""
                )
                for feature in features
                if feature.api_path == CONFIG_TEMPLATE_ITEM_PATH
                and feature.path_values
                and UNREADABLE_MARKER not in feature.payload
            }
        )
        template_ids = tuple(template_scopes)
        # Aggregation calls run only now, with the template resolution
        # universe complete.
        _run_level("aggregation", aggregation_level)
        if template_ids:
            logger.info(
                "Sweeping %d config template(s) for template-held "
                "network configuration.", len(template_ids),
            )
            _run_level(
                "config-template",
                [
                    functools.partial(_fetch, op, (template_id,))
                    for template_id in template_ids
                    for op in network_ops
                ],
            )

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
        # Collection paths this run swept (or captures first-class via
        # folding): a nested op whose parent collection is in this set
        # and simply yielded zero elements is genuine emptiness; one
        # whose parent collection was never queryable at all is a
        # structural blind spot that must be reported, not silently
        # skipped (Cardinal Rule 2). Sweepable single-scope collections
        # count even when their scope list was empty — an org with zero
        # networks or devices has genuinely nothing there, and must not
        # manufacture phantom gap records for every nested surface.
        queried_paths = set(level_paths)
        queried_paths.update(op.path for op in network_ops)
        queried_paths.update(op.path for op in serial_ops)
        queried_paths.update(
            op.path
            for op in parser.endpoints()
            if op.method == "get" and _folds_elsewhere(op)
        )
        for param_count, level_ops in itertools.groupby(
            nested_ops, key=lambda op: len(op.path_params)
        ):
            nested_level: list[Callable[[], list[FeatureConfiguration]]] = []
            for op in level_ops:
                parent = parent_item_path(op.path)
                scopes = [
                    feature.path_values
                    for feature in features
                    if feature.api_path == parent
                    and len(feature.path_values) == len(op.path_params)
                ]
                if scopes:
                    nested_level.extend(
                        functools.partial(_fetch, op, values)
                        for values in scopes
                    )
                    queried_paths.add(op.path)
                    continue
                parent_collection = parent.rsplit("/", 1)[0]
                if parent_collection in queried_paths:
                    # The parent was sweepable and simply held zero
                    # elements — genuine emptiness. This surface counts
                    # as swept too, so surfaces nested deeper under it
                    # don't cascade into phantom gap records.
                    queried_paths.add(op.path)
                    continue
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
            _run_level(f"nested {param_count}-parameter", nested_level)
        suspects = stats.suspects()
        if suspects:
            logger.warning(
                "%d endpoint(s) refused every scope they were tried "
                "against; recorded as suspect endpoints in the coverage "
                "manifest: %s",
                len(suspects),
                ", ".join(suspect.api_path for suspect in suspects),
            )
        self.discovery_diagnostics = DiscoveryDiagnostics(
            suspect_endpoints=suspects,
            skipped_out_of_scope=skipped_out_of_scope,
        )
        return features

    def _try_call(
        self,
        op: OperationSpec,
        params: dict[str, str],
        undispatchable: set[str],
        undispatchable_lock: threading.Lock,
        bucket: AdaptiveTokenBucket,
        abort: threading.Event,
        *,
        stats: _EndpointStats | None = None,
    ) -> Any:
        """One endpoint call; refusals are data, API failures never are.

        A product-type refusal for one network (400/404) is normal and
        logged at DEBUG (and tallied in ``stats``, so an endpoint every
        scope refuses surfaces as a suspect-endpoint diagnostic). An
        operation the installed SDK cannot dispatch at all would
        silently drop that endpoint's assets from every scope — that is
        missing DR coverage, so it warns once and raises
        _EndpointUnreadable for every scope so each one is recorded as
        a coverage gap. Throttles are retried under the shared AIMD
        bucket's pacing (its rate cuts and global pauses grow while the
        organization budget stays saturated); a call that exhausts the
        attempt budget aborts discovery (LiveRetryExhaustedError) rather
        than emit an incomplete snapshot that looks complete. A
        persistent server error — or any failure that is not a genuine
        400/404 scope refusal, e.g. a 200 whose body never parsed or a
        statusless transport exception — raises _EndpointUnreadable so
        the caller records that one endpoint as a coverage gap without
        losing the rest of the run.
        """
        with undispatchable_lock:
            if op.operation_id in undispatchable:
                raise _EndpointUnreadable(
                    "operation cannot be dispatched onto the installed "
                    "meraki SDK"
                )
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
                        "meraki SDK (%s); its assets are recorded as "
                        "coverage gaps — they are missing from this "
                        "snapshot. Upgrade the SDK or pin a matching "
                        "--spec release.",
                        op.path, exc,
                    )
                raise _EndpointUnreadable(
                    "operation cannot be dispatched onto the installed "
                    f"meraki SDK ({exc})"
                ) from exc
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
                if status in _SCOPE_REFUSAL_HTTP_STATUSES:
                    logger.debug(
                        "Feature endpoint %s unavailable for %s: %s",
                        op.path, _scope_label(params), exc,
                    )
                    if stats is not None:
                        stats.record(op.path, refused=True)
                    return None
                # Anything else — an APIError with status 200 (a body
                # that never parsed as JSON), an unexpected 4xx, or a
                # statusless transport/SDK exception — is an API
                # failure, not a scope refusal. Refusals are data, API
                # failures never are: record the endpoint as a coverage
                # gap instead of silently shrinking the snapshot.
                label = (
                    f"HTTP {status}"
                    if status is not None
                    else type(exc).__name__
                )
                raise _EndpointUnreadable(
                    f"{label}: unclassifiable API failure while reading "
                    "this endpoint"
                ) from exc
            bucket.on_success()
            if stats is not None:
                stats.record(op.path, refused=False)
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
        if not _method_is_read_only(method):
            raise LiveDispatchError(
                f"Refusing to dispatch operation {op.operation_id!r}: the "
                "resolved SDK method is not verifiably read-only. Discovery "
                "never mutates Meraki, and a stale or tampered spec can "
                "mislabel a mutating operation as a GET."
            )
        # Paginated SDK methods default to total_pages=1; without "all"
        # a large collection would be silently truncated to its first page.
        if "total_pages" in inspect.signature(method).parameters:
            return method(total_pages="all", **params)
        return method(**params)

    def close(self) -> None:
        self._client = None
