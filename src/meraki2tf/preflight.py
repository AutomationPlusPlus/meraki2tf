"""Operator preflight: ``--check`` validation and ``--estimate`` cost preview.

Adversarial-review origin: a multi-hour discovery sweep used to start
before any cheap validation ran, so a typo'd ``--drift-baseline`` or a
missing terraform binary was discovered hours in — discarding the whole
sweep. This module hosts the cheap validations as reusable functions:

* :func:`run_check_command` — the standalone ``--check`` mode: one line
  per check, PASS/FAIL/SKIP, nonzero exit on failure, never mutates
  anything (no workdir writes, no terraform init, no Meraki writes);
* :func:`validate_drift_baseline` — header-level baseline validation
  shared by ``--check`` and the pipeline's pre-discovery validation,
  raising the same exception classes ``snapshot_diff.baseline_drift``
  raises mid-run (which stays authoritative, belt-and-suspenders);
* :func:`run_estimate_command` — the standalone ``--estimate`` mode: a
  read-only request-count and wall-clock preview computed from the
  spec-derived discovery surfaces (2-3 enumeration API calls live,
  zero with ``--from-dump``);
* :func:`resolve_rebuild_organization` — names the organization a
  workdir's kit/state resolves to, backing the ``--rebuild`` target
  assertion and the ``--expect-org`` guard.

Everything here is read-only toward Meraki (Cardinal Rule 1) and
spec-driven via the shared discovery helpers — no endpoint lists or
mapping tables are hard-coded (project contract).
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from meraki2tf.alerts import AlertDispatcher
from meraki2tf.config import (
    API_KEY_ENV_VAR,
    ExecutionMode,
    RuntimeConfig,
    api_key_present,
    read_api_key,
)
from meraki2tf.coverage import COVERAGE_JSON_FILENAME
from meraki2tf.hcl_generator import IMPORTS_FILENAME
from meraki2tf.openapi_parser import OpenApiParser, entity_key
from meraki2tf.provider_catalog import (
    CATALOG_CACHE_FILENAME,
    CatalogError,
    ProviderCatalog,
)
from meraki2tf.providers.discovery import (
    aggregation_mappings,
    config_collection_operations,
    nested_collection_operations,
    network_product_types,
    parent_item_path,
    product_segment,
)
from meraki2tf.providers.dump import StaticJsonDataProvider
from meraki2tf.providers.live import CONFIG_TEMPLATE_ITEM_PATH
from meraki2tf.snapshot_diff import (
    BaselineOrgMismatchError,
    PartialBaselineError,
    SanitizedBaselineError,
)
from meraki2tf.spec.engine import OperationSpec
from meraki2tf.spec_resolver import resolve_spec
from meraki2tf.terraform_runner import (
    MINIMUM_TERRAFORM_VERSION,
    TerraformError,
    probe_terraform_version,
    version_tuple,
)

logger = logging.getLogger(__name__)

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_SKIP = "SKIP"

#: Discovery's sustained request budget: the shared AIMD bucket paces
#: toward the per-organization cap, of which meraki2tf claims about
#: this much on a healthy tenant.
RATE_CAP_REQUESTS_PER_SECOND = 6.0
#: A busy tenant sharing its budget with other API consumers throttles
#: discovery toward roughly half the cap.
DEGRADED_REQUESTS_PER_SECOND = 3.0


@dataclass(frozen=True)
class CheckResult:
    """One preflight check's verdict for the report."""

    name: str
    status: str
    detail: str


# ---------------------------------------------------------------------------
# Shared validations (used by --check AND the pipeline's early validation)
# ---------------------------------------------------------------------------


def validate_drift_baseline(
    baseline_path: Path, expected_organization: str | None = None
) -> tuple[str, ...]:
    """Header-level validation of a ``--drift-baseline`` snapshot.

    The authoritative refusals live in
    :func:`meraki2tf.snapshot_diff.baseline_drift` and still fire
    mid-run (belt-and-suspenders); this applies exactly those checks to
    the snapshot header alone — raising the very same exception classes
    — so a typo'd path, a corrupt file, a sanitized or partial baseline,
    or a foreign-organization baseline fails in milliseconds instead of
    after a multi-hour discovery sweep. Returns the baseline's recorded
    organization IDs. The org check only runs when the run's
    organization is already known (live mode); dump-mode runs defer it
    to the mid-run check, which knows the snapshot's organization.
    """
    provider = StaticJsonDataProvider(baseline_path)
    if provider.snapshot_sanitized:
        raise SanitizedBaselineError(
            f"Drift baseline {baseline_path} is a sanitized snapshot (it "
            "carries the 'sanitized' marker): its identifiers are "
            "pseudonyms, so every asset would falsely register as "
            "added/removed. Point --drift-baseline at the unsanitized "
            "snapshot."
        )
    scope = provider.snapshot_scope
    if scope is not None:
        raise PartialBaselineError(
            f"Drift baseline {baseline_path} is a PARTIAL export "
            f"(--only, {len(scope.network_ids)} network(s)): every asset "
            "outside its scope would falsely register as added. Point "
            "--drift-baseline at a full-organization snapshot."
        )
    recorded = provider.recorded_organization_ids
    if (
        expected_organization is not None
        and recorded
        and expected_organization not in recorded
    ):
        raise BaselineOrgMismatchError(
            f"Drift baseline {baseline_path} was captured from "
            f"organization {', '.join(recorded)}, but this run targets "
            f"organization {expected_organization}: every asset would "
            "falsely register as added+removed. Point --drift-baseline "
            "at a snapshot of the same organization."
        )
    return recorded


def resolve_rebuild_organization(
    workdir: Path, state_path: Path | None
) -> tuple[str, str] | None:
    """``(organization_id, source)`` the workdir's kit/state resolves to.

    Tier order is reliability order: ``coverage.json`` (regenerated
    every run alongside the kit and naming the organization explicitly),
    then the local Terraform state (the ``organization_id`` attribute
    across managed instances — trusted only when every instance agrees),
    then ``imports.tf`` (the ``meraki_organization`` import ID). Returns
    ``None`` when nothing can name an organization — callers must print
    that loudly, never guess.
    """
    coverage_file = workdir / COVERAGE_JSON_FILENAME
    try:
        document = json.loads(coverage_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        document = None
    if isinstance(document, dict):
        organization = str(document.get("organization_id") or "").strip()
        if organization:
            return organization, COVERAGE_JSON_FILENAME
    organization_from_state = _state_organization(state_path)
    if organization_from_state is not None:
        return organization_from_state, "terraform state"
    organization_from_imports = _imports_organization(
        workdir / IMPORTS_FILENAME
    )
    if organization_from_imports is not None:
        return organization_from_imports, IMPORTS_FILENAME
    return None


def _state_organization(state_path: Path | None) -> str | None:
    """The single organization_id every managed state instance carries.

    Only the attribute values are read (never logged): the state is a
    secret-bearing artifact, but an organization ID is a locator, not a
    credential. Disagreement or absence yields ``None`` — an ambiguous
    state must not vouch for a rebuild target.
    """
    if state_path is None or not state_path.exists():
        return None
    try:
        document = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    found: set[str] = set()
    resources = (
        document.get("resources") if isinstance(document, dict) else None
    )
    for resource in resources if isinstance(resources, list) else ():
        if not isinstance(resource, dict) or resource.get("mode") != "managed":
            continue
        instances = resource.get("instances")
        for instance in instances if isinstance(instances, list) else ():
            if not isinstance(instance, dict):
                continue
            attributes = instance.get("attributes")
            if not isinstance(attributes, dict):
                continue
            value = str(attributes.get("organization_id") or "").strip()
            if value:
                found.add(value)
    return found.pop() if len(found) == 1 else None


#: A generated ``import`` block adopting the organization itself; its
#: ``id`` is the bare organization ID.
_ORG_IMPORT_RE = re.compile(
    r'to = meraki_organization\.[A-Za-z0-9_]+\s*\n\s*id = "(?P<org>[^"]+)"'
)


def _imports_organization(imports_path: Path) -> str | None:
    try:
        text = imports_path.read_text(encoding="utf-8")
    except OSError:
        return None
    organizations = {
        match.group("org") for match in _ORG_IMPORT_RE.finditer(text)
    }
    return organizations.pop() if len(organizations) == 1 else None


# ---------------------------------------------------------------------------
# --check
# ---------------------------------------------------------------------------


def _fetch_organizations() -> list[dict[str, Any]]:
    """One read-only ``getOrganizations`` call (the key-validity probe)."""
    import meraki

    client = meraki.DashboardAPI(
        api_key=read_api_key(),
        suppress_logging=True,
        print_console=False,
        output_log=False,
        wait_on_rate_limit=True,
    )
    organizations = client.organizations.getOrganizations()
    return [
        organization
        for organization in (
            organizations if isinstance(organizations, list) else ()
        )
        if isinstance(organization, dict)
    ]


def _check_api_key(
    config: RuntimeConfig,
) -> tuple[CheckResult, list[dict[str, Any]] | None]:
    if config.mode is not ExecutionMode.LIVE and not config.sync:
        return (
            CheckResult(
                "API key",
                STATUS_SKIP,
                "offline --from-dump run; the dashboard API is not contacted",
            ),
            None,
        )
    if not api_key_present():
        return (
            CheckResult(
                "API key",
                STATUS_FAIL,
                f"{API_KEY_ENV_VAR} is not set in the environment",
            ),
            None,
        )
    try:
        organizations = _fetch_organizations()
    except Exception as exc:
        return (
            CheckResult(
                "API key",
                STATUS_FAIL,
                f"the dashboard refused the key: {exc}",
            ),
            None,
        )
    return (
        CheckResult(
            "API key",
            STATUS_PASS,
            f"valid; sees {len(organizations)} organization(s)",
        ),
        organizations,
    )


def _check_org_ids(
    config: RuntimeConfig, organizations: list[dict[str, Any]] | None
) -> list[CheckResult]:
    if not config.org_ids:
        return [
            CheckResult(
                "--org-id",
                STATUS_SKIP,
                "not supplied (dump mode reads the snapshot's organization)",
            )
        ]
    if organizations is None:
        return [
            CheckResult(
                "--org-id",
                STATUS_SKIP,
                "cannot be resolved without a passing API-key check",
            )
        ]
    names = {
        str(organization.get("id", "")): str(organization.get("name", ""))
        for organization in organizations
    }
    results: list[CheckResult] = []
    for org_id in config.org_ids:
        if org_id in names:
            results.append(
                CheckResult(
                    f"--org-id {org_id}",
                    STATUS_PASS,
                    f"resolves to organization {names[org_id]!r}",
                )
            )
        else:
            results.append(
                CheckResult(
                    f"--org-id {org_id}",
                    STATUS_FAIL,
                    "not visible to this API key (run --list-orgs for the "
                    "organizations it can see)",
                )
            )
    return results


def _check_terraform(config: RuntimeConfig) -> CheckResult:
    if config.dump_to is not None:
        return CheckResult(
            "terraform binary",
            STATUS_SKIP,
            "snapshot export (--dump-to) never invokes terraform",
        )
    try:
        version = probe_terraform_version(config.terraform_bin)
    except TerraformError as exc:
        return CheckResult("terraform binary", STATUS_FAIL, str(exc))
    minimum = ".".join(str(part) for part in MINIMUM_TERRAFORM_VERSION)
    if version is None:
        return CheckResult(
            "terraform binary",
            STATUS_FAIL,
            f"{config.terraform_bin!r} ran but reported no parseable "
            f"version (meraki2tf requires terraform >= {minimum})",
        )
    if version_tuple(version) < MINIMUM_TERRAFORM_VERSION:
        return CheckResult(
            "terraform binary",
            STATUS_FAIL,
            f"terraform {version} is too old: import blocks require "
            f">= {minimum}",
        )
    return CheckResult(
        "terraform binary",
        STATUS_PASS,
        f"terraform {version} (>= {minimum} required for import blocks)",
    )


def _check_provider_catalog(config: RuntimeConfig) -> CheckResult:
    """Which catalog source a keyless resolution lands on, cache-first.

    Deliberately never runs ``terraform init`` (a live resolution
    downloads the provider — --check must not mutate anything, the
    workdir included); a keyed run refreshing from the installed
    provider is noted instead.
    """
    cache = config.workdir / CATALOG_CACHE_FILENAME
    prefix = ""
    source = ""
    catalog: ProviderCatalog | None = None
    if cache.exists():
        try:
            catalog = ProviderCatalog.from_cache_file(cache)
            source = f"workdir cache ({len(catalog.resources)} resource type(s))"
        except CatalogError as exc:
            prefix = f"workdir cache unreadable ({exc}); "
    if catalog is None:
        try:
            catalog = ProviderCatalog.bundled()
        except CatalogError as exc:
            return CheckResult(
                "provider catalog", STATUS_FAIL, f"{prefix}{exc}"
            )
        source = (
            f"{prefix}bundled fallback "
            f"({len(catalog.resources)} resource type(s))"
        )
    if api_key_present() and config.dump_to is None:
        source += "; a keyed run refreshes it from the installed provider"
    return CheckResult("provider catalog", STATUS_PASS, source)


def _check_drift_baseline(config: RuntimeConfig) -> CheckResult:
    if config.drift_baseline is None:
        return CheckResult(
            "--drift-baseline", STATUS_SKIP, "not supplied"
        )
    try:
        recorded = validate_drift_baseline(
            config.drift_baseline, config.org_id
        )
    except ValueError as exc:
        # MalformedDumpError and the three snapshot_diff refusals are
        # all ValueErrors carrying the operator-facing diagnostic.
        return CheckResult("--drift-baseline", STATUS_FAIL, str(exc))
    return CheckResult(
        "--drift-baseline",
        STATUS_PASS,
        "full-organization unsanitized snapshot (organization "
        f"{', '.join(recorded) or 'unrecorded'})",
    )


def _check_workdir(config: RuntimeConfig) -> CheckResult:
    """Writability probe without mkdir — --check never mutates."""
    resolved = config.workdir.resolve()
    if resolved.exists():
        if not resolved.is_dir():
            return CheckResult(
                "workdir",
                STATUS_FAIL,
                f"{config.workdir} exists but is not a directory",
            )
        if os.access(resolved, os.W_OK | os.X_OK):
            return CheckResult(
                "workdir", STATUS_PASS, f"{config.workdir} is writable"
            )
        return CheckResult(
            "workdir",
            STATUS_FAIL,
            f"{config.workdir} is not writable by this user",
        )
    ancestor = resolved
    while not ancestor.exists():
        parent = ancestor.parent
        if parent == ancestor:
            break
        ancestor = parent
    if ancestor.is_dir() and os.access(ancestor, os.W_OK | os.X_OK):
        return CheckResult(
            "workdir",
            STATUS_PASS,
            f"{config.workdir} does not exist yet; it can be created "
            f"under {ancestor}",
        )
    return CheckResult(
        "workdir",
        STATUS_FAIL,
        f"{config.workdir} cannot be created: the nearest existing "
        f"ancestor {ancestor} is not a writable directory",
    )


def _check_alert_channels(
    config: RuntimeConfig,
    dispatcher_factory: Callable[[RuntimeConfig], AlertDispatcher],
) -> CheckResult:
    """Reuses the run's own startup validation (the dispatcher factory
    refuses invalid webhook URLs, missing PagerDuty routing keys, and
    half-set SMTP AUTH pairs with SystemExit) — single-sourced."""
    try:
        dispatcher = dispatcher_factory(config)
    except SystemExit as exc:
        return CheckResult("alert channels", STATUS_FAIL, str(exc))
    count = dispatcher.channel_count
    if count:
        return CheckResult(
            "alert channels", STATUS_PASS, f"{count} channel(s) configured"
        )
    return CheckResult(
        "alert channels",
        STATUS_PASS,
        "none configured; alerts reach the run log only",
    )


def run_preflight_checks(
    config: RuntimeConfig,
    dispatcher_factory: Callable[[RuntimeConfig], AlertDispatcher],
) -> list[CheckResult]:
    """Every ``--check`` validation, in report order. Read-only."""
    api_key_result, organizations = _check_api_key(config)
    results = [api_key_result]
    results.extend(_check_org_ids(config, organizations))
    results.append(_check_terraform(config))
    results.append(_check_provider_catalog(config))
    results.append(_check_drift_baseline(config))
    results.append(_check_workdir(config))
    results.append(_check_alert_channels(config, dispatcher_factory))
    return results


def run_check_command(
    config: RuntimeConfig,
    dispatcher_factory: Callable[[RuntimeConfig], AlertDispatcher],
) -> int:
    """The standalone ``--check`` mode: report and exit, mutate nothing."""
    results = run_preflight_checks(config, dispatcher_factory)
    for result in results:
        print(f"[{result.status}] {result.name}: {result.detail}")
    failed = sum(1 for result in results if result.status == STATUS_FAIL)
    skipped = sum(1 for result in results if result.status == STATUS_SKIP)
    passed = len(results) - failed - skipped
    print()
    if failed:
        print(
            f"Preflight FAIL: {failed} of {len(results)} check(s) failed "
            f"({passed} passed, {skipped} skipped). Nothing was run or "
            "modified."
        )
        return 1
    print(
        f"Preflight PASS: {passed} check(s) passed, {skipped} skipped. "
        "Nothing was run or modified."
    )
    return 0


# ---------------------------------------------------------------------------
# --estimate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DiscoveryEstimate:
    """Expected request counts for one full discovery sweep."""

    organization_id: str
    networks: int
    devices: int
    templates: int
    #: Enumeration GETs the estimate itself spent (2-3 live, 0 offline);
    #: discovery re-runs the same enumeration, so they count toward the
    #: sweep too.
    enumeration_calls: int
    org_scoped_calls: int
    network_scoped_calls: int
    serial_scoped_calls: int
    aggregation_calls: int
    template_sweep_calls: int
    nested_calls: int
    #: True when nested parents were counted exactly (snapshot input);
    #: False when they ride the stated one-parent-per-scope assumption.
    nested_exact: bool
    prefilter_skipped: int
    notes: tuple[str, ...] = field(default=())

    @property
    def total_requests(self) -> int:
        return (
            self.enumeration_calls
            + self.org_scoped_calls
            + self.network_scoped_calls
            + self.serial_scoped_calls
            + self.aggregation_calls
            + self.template_sweep_calls
            + self.nested_calls
        )


def _folding_predicate(
    parser: OpenApiParser,
) -> Callable[[OperationSpec], bool]:
    """Collections captured first-class under another entity (mirrors
    live discovery's folding guard so counts match what it queries)."""
    mappings = parser.resource_mappings()
    lookup = parser.endpoint_lookup()

    def folds(op: OperationSpec) -> bool:
        name = lookup.get(op.path)
        return name is not None and mappings[name].entity_key != entity_key(
            op.path
        )

    return folds


def _estimate_counts(
    parser: OpenApiParser,
    organization_id: str,
    network_products: Sequence[tuple[str, ...]],
    device_products: Sequence[str],
    template_count: int,
    enumeration_calls: int,
    nested_parents: Callable[[OperationSpec], int] | None,
    notes: Sequence[str],
) -> DiscoveryEstimate:
    """Shared arithmetic over the spec-derived discovery surfaces.

    Mirrors the live provider's queueing exactly: the same collection
    enumerations, the same folding guard, and the same conservative
    product-type prefilter — so the estimate is the sweep's plan, not a
    re-derivation. ``nested_parents`` counts one nested surface's parent
    elements (exact, from a snapshot); ``None`` applies the stated
    one-parent-per-applicable-scope assumption.
    """
    folds = _folding_predicate(parser)
    product_types = network_product_types(parser)
    org_ops = [
        op
        for op in config_collection_operations(parser, "organizationId")
        if not folds(op)
    ]
    network_ops = [
        op for op in config_collection_operations(parser) if not folds(op)
    ]
    serial_ops = [
        op
        for op in config_collection_operations(parser, "serial")
        if not folds(op)
    ]

    def network_applies(op: OperationSpec, products: tuple[str, ...]) -> bool:
        segment = product_segment(op)
        return not (
            segment in product_types and products and segment not in products
        )

    def device_applies(op: OperationSpec, device_type: str) -> bool:
        segment = product_segment(op)
        return not (
            device_type and segment in product_types and segment != device_type
        )

    network_calls = 0
    skipped = 0
    for products in network_products:
        for op in network_ops:
            if network_applies(op, products):
                network_calls += 1
            else:
                skipped += 1
    serial_calls = 0
    for device_type in device_products:
        for op in serial_ops:
            if device_applies(op, device_type):
                serial_calls += 1
            else:
                skipped += 1
    nested_ops = [
        op for op in nested_collection_operations(parser) if not folds(op)
    ]
    nested_exact = nested_parents is not None
    nested_calls = 0
    for op in nested_ops:
        if nested_parents is not None:
            nested_calls += nested_parents(op)
            continue
        root = op.path_params[0]
        if root == "networkId":
            nested_calls += sum(
                1
                for products in network_products
                if network_applies(op, products)
            )
        elif root == "serial":
            nested_calls += sum(
                1
                for device_type in device_products
                if device_applies(op, device_type)
            )
        else:
            nested_calls += 1
    return DiscoveryEstimate(
        organization_id=organization_id,
        networks=len(network_products),
        devices=len(device_products),
        templates=template_count,
        enumeration_calls=enumeration_calls,
        org_scoped_calls=len(org_ops),
        network_scoped_calls=network_calls,
        serial_scoped_calls=serial_calls,
        aggregation_calls=len(aggregation_mappings(parser)),
        # The template sweep replays every network-scoped surface per
        # config template, unfiltered — exactly like live discovery.
        template_sweep_calls=template_count * len(network_ops),
        nested_calls=nested_calls,
        nested_exact=nested_exact,
        prefilter_skipped=skipped,
        notes=tuple(notes),
    )


def _estimate_live(
    config: RuntimeConfig, parser: OpenApiParser
) -> DiscoveryEstimate:
    """Live estimate: 2-3 read-only enumeration calls, then arithmetic."""
    import meraki

    organization_id = config.org_id
    assert organization_id is not None  # guarded by the CLI
    client = meraki.DashboardAPI(
        api_key=read_api_key(),
        suppress_logging=True,
        print_console=False,
        output_log=False,
        wait_on_rate_limit=True,
    )
    networks_raw = client.organizations.getOrganizationNetworks(
        organization_id, total_pages="all"
    )
    devices_raw = client.organizations.getOrganizationDevices(
        organization_id, total_pages="all"
    )
    enumeration = 2
    notes: list[str] = []
    try:
        templates_raw = client.organizations.getOrganizationConfigTemplates(
            organization_id
        )
        enumeration += 1
    except Exception as exc:
        templates_raw = []
        notes.append(
            f"config templates could not be enumerated ({exc}); the "
            "template sweep is estimated at 0 calls"
        )
    network_products = [
        tuple(str(product) for product in (network.get("productTypes") or ()))
        for network in (
            networks_raw if isinstance(networks_raw, list) else ()
        )
        if isinstance(network, dict)
    ]
    device_products = [
        str(device.get("productType") or "")
        for device in (devices_raw if isinstance(devices_raw, list) else ())
        if isinstance(device, dict)
    ]
    template_count = (
        len(templates_raw) if isinstance(templates_raw, list) else 0
    )
    notes.append(
        "nested surfaces assume ONE parent element per applicable scope; "
        "real per-network element counts (SSIDs, switch stacks, "
        "interfaces) can raise the nested share"
    )
    return _estimate_counts(
        parser,
        organization_id,
        network_products,
        device_products,
        template_count,
        enumeration_calls=enumeration,
        nested_parents=None,
        notes=notes,
    )


def _estimate_from_dump(
    config: RuntimeConfig, parser: OpenApiParser
) -> DiscoveryEstimate:
    """Offline estimate: every count read from the snapshot, zero API calls."""
    assert config.dump_path is not None  # guarded by the CLI
    provider = StaticJsonDataProvider(config.dump_path, parser=parser)
    graph = provider.fetch_network_graph(config.org_id)
    network_products = [
        network.product_types for network in graph.networks
    ]
    device_products = [
        str(device.payload.get("productType") or "")
        for device in graph.devices
    ]
    template_count = sum(
        1
        for feature in graph.features
        if feature.api_path == CONFIG_TEMPLATE_ITEM_PATH
    )

    def nested_parents(op: OperationSpec) -> int:
        parent = parent_item_path(op.path)
        return sum(
            1
            for feature in graph.features
            if feature.api_path == parent
            and len(feature.path_values) == len(op.path_params)
        )

    return _estimate_counts(
        parser,
        graph.organization_id,
        network_products,
        device_products,
        template_count,
        enumeration_calls=0,
        nested_parents=nested_parents,
        notes=(
            "all counts (nested parents included) were read from the "
            "snapshot; zero API calls were made",
        ),
    )


def _format_duration(seconds: float) -> str:
    total = int(round(seconds))
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def render_estimate(estimate: DiscoveryEstimate) -> str:
    """Human-readable request-count and wall-clock preview."""
    total = estimate.total_requests
    nested_label = (
        "exact, from the snapshot"
        if estimate.nested_exact
        else "assumed: one parent element per scope"
    )
    lines = [
        "meraki2tf discovery cost estimate — organization "
        f"{estimate.organization_id}",
        "",
        f"Inventory: {estimate.networks} network(s), "
        f"{estimate.devices} device(s), "
        f"{estimate.templates} config template(s)",
        "",
        "Expected GET requests:",
        f"  enumeration          : {estimate.enumeration_calls}",
        f"  organization-scoped  : {estimate.org_scoped_calls}",
        f"  network-scoped       : {estimate.network_scoped_calls}",
        f"  device-scoped        : {estimate.serial_scoped_calls}",
        f"  aggregation (org)    : {estimate.aggregation_calls}",
        f"  template sweep       : {estimate.template_sweep_calls}",
        f"  nested surfaces      : {estimate.nested_calls} ({nested_label})",
        f"  TOTAL                : ~{total}",
        "",
        f"Product-type prefilter skips {estimate.prefilter_skipped} "
        "endpoint call(s) that provably do not apply.",
        "",
        "Estimated wall clock:",
        "  at the rate cap "
        f"({RATE_CAP_REQUESTS_PER_SECOND:g} req/s)  : "
        f"~{_format_duration(total / RATE_CAP_REQUESTS_PER_SECOND)}",
        "  degraded / busy tenant "
        f"({DEGRADED_REQUESTS_PER_SECOND:g} req/s): "
        f"~{_format_duration(total / DEGRADED_REQUESTS_PER_SECOND)}",
    ]
    for note in estimate.notes:
        lines.append(f"Note: {note}")
    lines.append(
        "Read-only preview: nothing was written and no discovery ran."
    )
    return "\n".join(lines)


def run_estimate_command(config: RuntimeConfig) -> int:
    """The standalone ``--estimate`` mode: print the preview and exit."""
    try:
        spec_file = resolve_spec(config.spec_path)
        parser = OpenApiParser(spec_file)
        if config.dump_path is not None:
            estimate = _estimate_from_dump(config, parser)
        else:
            estimate = _estimate_live(config, parser)
    except Exception as exc:
        logger.critical("Could not estimate the discovery cost: %s", exc)
        return 1
    print(render_estimate(estimate))
    return 0
