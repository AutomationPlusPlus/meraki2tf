"""Command-line entry point and pipeline assembly.

Built for both ad-hoc invocation and unattended scheduled runs (e.g. a
weekly cron job): every input arrives via flags or environment
variables, no interactive prompts, and the exit code reports outcome
(0 = clean aggregation, 1 = pipeline fault, 2 = usage error,
3 = coverage gaps with --fail-on-gaps, 4 = sync-mode full-kit
auto-apply aborted for human review — mutations blocked the full apply,
though import-only chunks may still have grown state, 5 = the run
itself succeeded but at least one alert event reached no configured
channel). When several codes apply the most severe wins: 1/2 (nothing
usable happened) over 4 (state materialization is stalled on a human)
over 3 (known coverage gaps) over 5 (silent notifier outage).

Mode gating: the default invocation is the ad-hoc/open-source mode —
strictly read-only end-to-end (kit generation, speculative plan,
alerts), safe for anyone to run against any org. ``--sync`` opts into
DR automation: guarded import-only state materialization and
modified-object baseline regeneration. Meraki itself is never mutated
by either mode; only the explicit, human-invoked DR actions —
``--rebuild --confirm`` (terraform apply of the kit), ``--heal
--confirm`` (same-org additive recreation of deleted objects),
``--replay-gaps --confirm`` (snapshot replay of what Terraform cannot
carry), ``--restore --confirm`` (full-org rebuild into a separate
``--target-org``), and ``--wipe-org --confirm`` (drill-org teardown) —
ever change the organization.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.metadata
import json
import logging
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from meraki2tf.alerts import (
    drift_detected,
    heal_executed,
    org_wipe_executed,
    processing_fault,
    rebuild_executed,
    restore_executed,
    routing_key_present,
    run_success,
    validate_smtp_credentials,
    AlertDispatcher,
    EmailConfigError,
    EmailNotifier,
    PagerDutyNotifier,
    WebhookConfigError,
    WebhookNotifier,
    gap_replay_executed,
)
from meraki2tf.alerts.pagerduty import (
    ROUTING_KEY_ENV_VAR as PAGERDUTY_ROUTING_KEY_ENV_VAR,
)
from meraki2tf.alerts.models import condense_diff, redact_diff
from meraki2tf.config import (
    API_KEY_ENV_VAR,
    WEBHOOK_URL_ENV_VAR,
    BackendConfigError,
    ConfigFileError,
    ExecutionMode,
    RuntimeConfig,
    StateBackend,
    api_key_present,
    load_config_file,
)
from meraki2tf.coverage import build_manifest, unsupported_payload, write_manifest
from meraki2tf.hcl_generator import HclImportGenerator
from meraki2tf.logging_setup import (
    LOG_FORMATS,
    configure_logging,
    sanitize_control_chars,
)
from meraki2tf.models import DiscoveryDiagnostics, NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.orchestrator import (
    PipelineError,
    PipelineOrchestrator,
    PreflightRefusalError,
    RunSummary,
    cap_log_enumeration,
)
from meraki2tf import preflight
from meraki2tf.provider_catalog import (
    CATALOG_CACHE_FILENAME,
    CatalogError,
    ProviderCatalog,
    resolve_catalog,
)
from meraki2tf.replayer import (
    GapReplayer,
    SanitizedReplayTargetError,
    plan_replay,
    template_bound_networks,
)
from meraki2tf.providers import (
    LiveApiDataProvider,
    MerakiDataProvider,
    StaticJsonDataProvider,
)
from meraki2tf.providers.discovery_checkpoint import (
    CheckpointMismatchError,
    verify_binding,
)
from meraki2tf.sanitizer import load_or_create_salt, sanitize_graph
from meraki2tf.scope import (
    LiveNetworkScope,
    ScopeFilterError,
    parse_network_selectors,
)
from meraki2tf.sdk_client import dashboard_client
from meraki2tf.snapshot import write_snapshot
from meraki2tf.spec_resolver import resolve_spec, spec_fingerprint
from meraki2tf.terraform_runner import (
    PROVIDER_FILENAME,
    TerraformError,
    TerraformRunner,
    ensure_supported_terraform,
)

logger = logging.getLogger(__name__)


_HELP_EPILOG = """\
examples:
  # New here? List the organizations your API key can see:
  export MERAKI_DASHBOARD_API_KEY="<key>"
  meraki2tf --list-orgs

  # One-shot read-only export of an organization to Terraform:
  meraki2tf --org-id 123456

  # Capture an offline snapshot and diff it against last week's:
  meraki2tf --org-id 123456 --dump-to snapshots/this-week.jsonl.gz \\
    --drift-baseline snapshots/last-week.jsonl.gz

  # Scheduled DR job: also materialize state via the guarded
  # import-only apply, alerting to a webhook:
  meraki2tf --org-id 123456 --sync --webhook-url https://hooks.example.com/m2t

  # Disaster recovery, always preview-first (add --confirm to execute):
  meraki2tf --rebuild --workdir ./generated

The default invocation is strictly read-only toward Meraki. See the
README for the full guide: https://github.com/AutomationPlusPlus/meraki2tf
"""


def _distribution_version() -> str:
    """The installed distribution's version for ``--version``."""
    try:
        return importlib.metadata.version("meraki2tf")
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover
        # Running from an uninstalled source tree (no dist metadata).
        return "0+unknown"


def build_parser() -> argparse.ArgumentParser:
    """Construct the full ``meraki2tf`` argument parser.

    The single source of truth for the command-line surface: every flag,
    its help text, and its argument grouping are declared here so the
    ``--help`` output, the ``--config`` TOML destinations, and the
    runtime configuration all stay derived from one definition.
    """
    parser = argparse.ArgumentParser(
        prog="meraki2tf",
        description=(
            "Extract Cisco Meraki configurations and translate them into "
            "Terraform structures with drift detection and alerting."
        ),
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Prefix abbreviations would desynchronize the config-file
        # explicit-flag detection (it scans argv for the spelled-out
        # flag) and let two near-name DR flags shadow each other; every
        # flag must be typed in full.
        allow_abbrev=False,
    )
    core = parser.add_argument_group(
        "core options",
        "Everything a plain read-only export needs.",
    )
    core.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_distribution_version()}",
        help="Print the installed meraki2tf version and exit.",
    )
    core.add_argument(
        "--list-orgs",
        action="store_true",
        help=(
            "Discovery helper: list every organization the "
            f"{API_KEY_ENV_VAR} key can see (ID and name) and exit — the "
            "way to find your --org-id value. Standalone and read-only."
        ),
    )
    core.add_argument(
        "--check",
        action="store_true",
        help=(
            "Preflight helper: validate the given flag set without "
            "running anything — API key validity, --org-id resolution, "
            "terraform binary and version, provider catalog, "
            "--drift-baseline header, workdir writability, and alert-"
            "channel configuration. One line per check, nonzero exit on "
            "failure. Standalone, read-only, mutates nothing."
        ),
    )
    core.add_argument(
        "--estimate",
        action="store_true",
        help=(
            "Cost-preview helper: enumerate networks and devices (2-3 "
            "API calls; zero with --from-dump) and print the expected "
            "discovery request count plus wall-clock estimates at the "
            "rate cap and at a degraded rate, then exit. Standalone and "
            "read-only."
        ),
    )
    core.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        help=(
            "TOML file of recurring settings (keys mirror the long flag "
            "names). Precedence: command line > config file > built-in "
            "default. Disaster-recovery actions, confirmations, and "
            "credentials are refused in the file."
        ),
    )
    core.add_argument(
        "--org-id",
        action="append",
        default=None,
        help=(
            "Meraki organization ID to discover; repeat the flag to fan "
            "out over several organizations sequentially (each gets its "
            "own sub-workdir and state). Required in live mode; dump "
            "mode falls back to the organization recorded in the "
            "snapshot. DR actions take at most one."
        ),
    )
    core.add_argument(
        "--spec",
        metavar="PATH",
        default=None,
        help=(
            "Meraki OpenAPI JSON document driving the dynamic resource "
            "registry (default: ./spec3.json). Auto-downloaded and "
            "version-refreshed from GitHub; see README 'OpenAPI spec "
            "resolution'."
        ),
    )
    core.add_argument(
        "--workdir",
        metavar="DIR",
        default="generated",
        help="Terraform execution workspace directory (default: %(default)s).",
    )
    core.add_argument(
        "--terraform-bin",
        default="terraform",
        help="Terraform executable to invoke (default: %(default)s).",
    )
    core.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging; credentials are redacted at every level.",
    )
    core.add_argument(
        "--log-format",
        choices=LOG_FORMATS,
        default="text",
        help=(
            "Console log output (default: %(default)s). 'json' emits one "
            "JSON object per line for log aggregators; secret redaction "
            "applies in both formats."
        ),
    )
    snapshots = parser.add_argument_group(
        "snapshots & offline",
        "Produce and consume offline snapshots; no API key needed to read one.",
    )
    snapshots.add_argument(
        "--from-dump",
        metavar="PATH",
        default=None,
        help="Run offline against a local JSON snapshot instead of the live cloud API.",
    )
    snapshots.add_argument(
        "--dump-to",
        metavar="PATH",
        default=None,
        help=(
            "Write the discovered configuration to PATH as an offline "
            "snapshot (the --from-dump format) instead of running the "
            "Terraform pipeline."
        ),
    )
    snapshots.add_argument(
        "--sanitize",
        action="store_true",
        help=(
            "Redact secrets and pseudonymize identifying details in the "
            "snapshot written by --dump-to, keeping it structurally "
            "processable — for tests, demos, and bug reports."
        ),
    )
    snapshots.add_argument(
        "--drift-baseline",
        metavar="PATH",
        default=None,
        help=(
            "A previous snapshot to compare the fresh discovery against: "
            "attribute-level drift detection without a terraform read pass. "
            "Real differences dispatch a DRIFT_DETECTED alert."
        ),
    )
    snapshots.add_argument(
        "--discovery-checkpoint",
        metavar="PATH",
        default=None,
        help=(
            "Resumable discovery: journal every completed API call to "
            "PATH (JSONL, .gz supported; written 0600 — payloads carry "
            "secrets). An aborted sweep (throttle exhaustion, Ctrl-C, "
            "crash) keeps the journal, and the next run with the same "
            "flag resumes instead of restarting; a completed run deletes "
            "it. Valid on --dump-to exports and live pipeline runs."
        ),
    )
    snapshots.add_argument(
        "--diff-networks",
        nargs=2,
        metavar=("PATTERN_A", "PATTERN_B"),
        default=None,
        help=(
            "Standalone golden-config comparison: diff two networks' "
            "configuration against each other (spec-normalized, "
            "attribute names only — never values). Each pattern is a "
            "case-insensitive glob over network name or ID and must "
            "match exactly one network. Works live (--org-id) and "
            "offline (--from-dump). Read-only; no terraform involved."
        ),
    )
    snapshots.add_argument(
        "--diff-out",
        metavar="PATH",
        default=None,
        help=(
            "Write the --diff-networks report to PATH as JSON as well "
            "(attribute names and locators only — values are never "
            "written)."
        ),
    )
    pipeline = parser.add_argument_group(
        "pipeline options",
        "Tune the default read-only pipeline and the scheduled DR job.",
    )
    pipeline.add_argument(
        "--sync",
        action="store_true",
        help=(
            "Opt-in DR automation for the scheduled job: auto-apply the "
            "plan ONLY when it is 100%% imports (0 add / 0 change / "
            "0 destroy) and regenerate the HCL baseline of modified "
            "objects. Meraki itself is never touched. Requires "
            f"{API_KEY_ENV_VAR}."
        ),
    )
    pipeline.add_argument(
        "--rebaseline",
        action="store_true",
        help=(
            "Accept the currently discovered configuration as the new "
            "baseline: discard the accumulated resources.tf so this run "
            "regenerates it. Refused while the state file tracks resources."
        ),
    )
    pipeline.add_argument(
        "--confirm-deletions",
        action="store_true",
        help=(
            "Human confirmation to remove resources deleted in Meraki from "
            "the DR kit and the Terraform state; without it deletions stay "
            "alert-only so they cannot silently poison the rebuild baseline."
        ),
    )
    pipeline.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help=(
            "Exit with code 3 when the run discovers objects Terraform "
            "cannot rebuild (coverage gaps), so schedulers and CI can gate "
            "on full coverage. Valid in every read-only mode, including "
            "--dump-to snapshot exports."
        ),
    )
    actions = parser.add_argument_group(
        "disaster-recovery actions",
        "Mutually exclusive, human-invoked actions — the ONLY paths that "
        "can write to Meraki. Each is a read-only preview until --confirm "
        "is added; none may run from a scheduler. See the README's "
        "'Disaster Recovery' section.",
    )
    actions.add_argument(
        "--rebuild",
        action="store_true",
        help=(
            "Preview what 'terraform apply' would do with the artifacts "
            "already generated in --workdir; --confirm executes the apply."
        ),
    )
    actions.add_argument(
        "--heal",
        action="store_true",
        help=(
            "Partial recovery: recreate snapshot objects missing from the "
            "SAME organization the --from-dump snapshot was captured from "
            "(accidental deletions). Additive-only — surviving objects are "
            "never modified. Requires a matching --org-id and an "
            "unsanitized snapshot."
        ),
    )
    actions.add_argument(
        "--only",
        action="append",
        metavar="[TYPE:]PATTERN",
        default=None,
        help=(
            "Selective scope, repeatable (union); a selector matching "
            "nothing is an error. With --heal: restrict the heal to the "
            "missing objects matching a case-insensitive glob over "
            "their name or ID, optionally type-prefixed (e.g. --only "
            "'network:Branch-07', --only 'ssid:Guest*'); a matched "
            "container selects its whole missing subtree — whether the "
            "container itself was deleted or is still standing and only "
            "objects inside it went missing — and missing objects the "
            "selection depends on are auto-included. With "
            "--dump-to: selective backup — restrict discovery to the "
            "matching networks (network:PATTERN selectors only) and "
            "write a partial snapshot usable by --heal but refused by "
            "--restore, --replay-gaps, and --drift-baseline. On a "
            "default live pipeline run: scoped kit generation — "
            "discovery, the kit, and the plan cover only the matching "
            "networks (network:PATTERN selectors only); artifacts are "
            "stamped partial and out-of-scope state is never touched."
        ),
    )
    actions.add_argument(
        "--replay-gaps",
        action="store_true",
        help=(
            "Replay the objects Terraform cannot rebuild (and the secret "
            "attributes the kit cannot carry) from an unsanitized "
            "--from-dump snapshot back into the organization. Run after "
            "'--rebuild --confirm'."
        ),
    )
    actions.add_argument(
        "--restore",
        action="store_true",
        help=(
            "Rebuild an ENTIRE organization from a --from-dump snapshot "
            "into --target-org, directly via the API in dependency order "
            "with ID remapping. Refuses the snapshot's own source org."
        ),
    )
    actions.add_argument(
        "--wipe-org",
        metavar="ORG_ID",
        default=None,
        help=(
            "Drill teardown: delete every network and then the organization "
            "itself. Refused outright for any organization holding claimed "
            "devices; requires --wipe-org-name as a second factor."
        ),
    )
    actions.add_argument(
        "--confirm",
        action="store_true",
        help=(
            "Escalate --rebuild, --heal, --replay-gaps, --restore, or "
            "--wipe-org from a read-only preview to a real write against "
            "the Meraki organization."
        ),
    )
    actions.add_argument(
        "--expect-org",
        metavar="ORG_ID",
        default=None,
        help=(
            "Assertion for --rebuild and --replay-gaps: refuse to plan "
            "or write unless the organization the action resolves to "
            "(the workdir's kit/state for --rebuild, the snapshot's "
            "recorded organization for --replay-gaps) equals ORG_ID. "
            "Both actions print the resolved organization either way."
        ),
    )
    actions.add_argument(
        "--target-org",
        metavar="ORG_ID",
        default=None,
        help=(
            "Organization the --restore writes into (a fresh or scratch "
            "org). Required with --restore; must differ from the "
            "snapshot's source organization."
        ),
    )
    actions.add_argument(
        "--serial-map",
        metavar="PATH",
        default=None,
        help=(
            "JSON object mapping snapshot device serials to replacement "
            "hardware serials for --restore (hardware-loss DR). Unmapped "
            "serials are claimed as-is."
        ),
    )
    actions.add_argument(
        "--skip-claims",
        action="store_true",
        help=(
            "Drill mode for --restore: device claiming and device-scoped "
            "features become drill-skipped verdicts, never failures (the "
            "hardware is attached to the production organization)."
        ),
    )
    actions.add_argument(
        "--wipe-org-name",
        metavar="NAME",
        default=None,
        help=(
            "The exact name of the organization --wipe-org targets; a "
            "mismatch refuses the wipe."
        ),
    )
    state = parser.add_argument_group(
        "terraform state",
        "Where the materialized Terraform state lives.",
    )
    state.add_argument(
        "--state-file",
        metavar="PATH",
        default=None,
        help=(
            "Terraform state file to aggregate into; consecutive runs only "
            "import the delta (default: meraki2tf.tfstate inside --workdir; "
            "local backend only)."
        ),
    )
    state.add_argument(
        "--state-backend",
        choices=[member.value for member in StateBackend],
        default=StateBackend.LOCAL.value,
        help=(
            "Terraform state backend (default: %(default)s). 'local' keeps "
            "state on disk in --workdir/--state-file; 'azurerm' (Azure "
            "Blob Storage), 's3' (Amazon S3), and 'gcs' (Google Cloud "
            "Storage) keep it durable, locked, and off-box — recommended "
            "for scheduled DR."
        ),
    )
    state.add_argument(
        "--backend-config",
        action="append",
        metavar="KEY=VALUE",
        help=(
            "Remote backend setting passed to 'terraform init "
            "-backend-config'; repeat for several. Credentials are refused "
            "here — terraform reads them from the environment or a managed "
            "identity."
        ),
    )
    state.add_argument(
        "--backend-config-file",
        metavar="PATH",
        default=None,
        help=(
            "File of remote backend settings passed to "
            "'terraform init -backend-config=PATH' (composes with "
            "--backend-config)."
        ),
    )
    alerting = parser.add_argument_group(
        "alerting",
        "Webhook and email channels for drift, success, and fault events.",
    )
    alerting.add_argument(
        "--webhook-url",
        action="append",
        metavar="URL",
        help=(
            "HTTPS webhook alert endpoint; repeat the flag for multiple "
            "targets. Prefer the MERAKI2TF_WEBHOOK_URL environment "
            "variable (':::'-separated) for token-bearing URLs so the "
            "secret stays out of argv and process listings."
        ),
    )
    alerting.add_argument(
        "--webhook-format",
        choices=["json", "slack", "teams"],
        default="json",
        help=(
            "Shape of the webhook POST body (default: %(default)s). "
            "'json' is the raw machine-readable event payload; 'slack' "
            "renders Slack incoming-webhook text; 'teams' renders a "
            "Teams Workflows Adaptive Card message. Applies to every "
            "configured webhook target."
        ),
    )
    alerting.add_argument(
        "--pagerduty",
        action="store_true",
        help=(
            "Trigger a PagerDuty incident (Events API v2) for WARNING "
            "and CRITICAL events — drift, coverage gaps, pending "
            "deletions, faults. INFO events never page. The routing key "
            "comes only from the MERAKI2TF_PAGERDUTY_ROUTING_KEY "
            "environment variable."
        ),
    )
    alerting.add_argument(
        "--alert-email",
        action="append",
        metavar="ADDR",
        help=(
            "Email alert recipient; repeat the flag for multiple "
            "recipients. Authenticated relays: set "
            "MERAKI2TF_SMTP_USERNAME and MERAKI2TF_SMTP_PASSWORD in the "
            "environment (AUTH runs only inside verified STARTTLS)."
        ),
    )
    alerting.add_argument(
        "--smtp-host",
        default="localhost",
        help="SMTP relay host for email alerts (default: %(default)s).",
    )
    alerting.add_argument(
        "--smtp-port",
        type=int,
        default=25,
        help="SMTP relay port for email alerts (default: %(default)s).",
    )
    alerting.add_argument(
        "--email-from",
        default="meraki2tf@localhost",
        help="Sender address for email alerts (default: %(default)s).",
    )
    return parser


def build_dispatcher(config: RuntimeConfig) -> AlertDispatcher:
    """Assemble the alert fan-out from the configured destinations."""
    dispatcher = AlertDispatcher()
    for url in config.webhook_urls:
        try:
            dispatcher.register(
                WebhookNotifier(url, payload_format=config.webhook_format)
            )
        except WebhookConfigError as exc:
            # A misconfigured endpoint must not silently disable
            # alerting for the whole run: refuse loudly at startup.
            raise SystemExit(
                f"Invalid --webhook-url / {WEBHOOK_URL_ENV_VAR}: {exc}"
            ) from None
    if config.pagerduty:
        if not routing_key_present():
            # Same loud-refusal rule as a bad webhook URL: a paging
            # channel that silently cannot page is worse than none.
            raise SystemExit(
                "--pagerduty requires the "
                f"{PAGERDUTY_ROUTING_KEY_ENV_VAR} environment variable "
                "(an Events API v2 routing key)."
            )
        dispatcher.register(PagerDutyNotifier())
    if config.alert_emails:
        try:
            validate_smtp_credentials()
        except EmailConfigError as exc:
            # Same loud-refusal rule as PagerDuty: a half-set AUTH pair
            # would otherwise fail every send after the discovery sweep.
            raise SystemExit(str(exc)) from None
        dispatcher.register(
            EmailNotifier(
                host=config.smtp_host,
                port=config.smtp_port,
                sender=config.email_from,
                recipients=config.alert_emails,
            )
        )
    if dispatcher.channel_count == 0:
        # Legitimate for ad-hoc terminal runs, but a scheduled DR job
        # without channels would drop every drift/fault/coverage alert
        # on the floor with nobody watching the log.
        logger.warning(
            "No alert channels are configured (--webhook-url / "
            "--alert-email): drift, deletions, coverage gaps, and faults "
            "will reach the run log only."
        )
    return dispatcher


class OrganizationMismatchError(ValueError):
    """``--org-id`` contradicts the organization the snapshot records."""


def build_provider(
    config: RuntimeConfig,
    parser: OpenApiParser,
    spec_file: Path | None = None,
) -> MerakiDataProvider:
    """Build the discovery provider the run's inputs call for.

    Returns a :class:`StaticJsonDataProvider` when ``--from-dump`` names
    a snapshot (read as the organization it records), otherwise a
    :class:`LiveApiDataProvider` — optionally scope-restricted for
    ``--only`` and bound to a discovery checkpoint journal. The
    DR write actions that legitimately target a different organization
    (``--replay-gaps``, ``--heal``) build their own providers and never
    come through here.

    Raises :class:`OrganizationMismatchError` when a dump snapshot's
    recorded organization conflicts with an explicit ``--org-id`` — the
    read pipeline always reads a snapshot as the org it records.
    """
    if config.dump_path is not None:
        provider = StaticJsonDataProvider(config.dump_path, parser=parser)
        # Every path through this factory (the read-only pipeline, the
        # --dump-to export, --diff-networks) reads a snapshot as the
        # organization it records. --replay-gaps, the one action for
        # which --org-id legitimately names a *different* organization,
        # builds its own provider and never comes through here.
        conflict = provider.organization_mismatch(config.org_id)
        if conflict is not None:
            raise OrganizationMismatchError(conflict)
        return provider
    # Selective scope (--only): restrict live discovery to the selected
    # networks (org-level surfaces stay in scope) — the export path AND
    # the scoped default pipeline. Heal builds its own scoped provider
    # from the snapshot header and never comes through here.
    scope = (
        LiveNetworkScope(selectors=config.only) if config.only else None
    )
    checkpoint_sha: str | None = None
    if config.discovery_checkpoint is not None and spec_file is not None:
        # The journal is bound to the exact spec document: replayed
        # payloads re-expand through the spec, so a swap must refuse.
        checkpoint_sha = spec_fingerprint(spec_file)[1]
        # Eager header check: a stale/foreign journal refuses NOW —
        # before the terraform probe and before any API call — so the
        # clean input refusal is never shadowed by an environment
        # fault (and CI without terraform sees the same behavior as a
        # workstation that has it).
        verify_binding(
            config.discovery_checkpoint,
            config.org_id or "",
            checkpoint_sha,
        )
    return LiveApiDataProvider(
        parser=parser,
        network_scope=scope,
        checkpoint_path=config.discovery_checkpoint,
        spec_sha256=checkpoint_sha,
    )


def _offline_catalog(config: RuntimeConfig) -> ProviderCatalog:
    """Keyless catalog resolution without a TerraformRunner.

    The export path must never touch terraform, so this walks only the
    tail of :func:`resolve_catalog`'s chain: the workdir cache a keyed
    pipeline run left behind, then the bundled catalog.
    """
    cache = config.workdir / CATALOG_CACHE_FILENAME
    if cache.exists():
        try:
            return ProviderCatalog.from_cache_file(cache)
        except CatalogError as exc:
            logger.warning("%s; falling back to the bundled catalog.", exc)
    return ProviderCatalog.bundled()


def _export_coverage(
    graph: NetworkGraph,
    config: RuntimeConfig,
    parser: OpenApiParser,
    dispatcher: AlertDispatcher,
    drift_was_detected: bool,
    scope_networks: tuple[str, ...] | None = None,
    diagnostics: DiscoveryDiagnostics | None = None,
) -> dict[str, Any]:
    """Coverage manifest + RUN_SUCCESS for a snapshot-export run.

    The scheduled weekly job is a --dump-to invocation, and Cardinal
    Rule 2 does not pause for it: every run must answer "what is and
    isn't covered by Terraform?" and push the unsupported list to the
    operator. Classification reuses the pipeline's generator against a
    throwaway directory — terraform itself is never invoked, and the
    workdir's accumulated kit is not touched.
    """
    from meraki2tf.restorer import plan_restore, restore_verdicts
    from meraki2tf.runbook import (
        payload_index,
        secret_attribute_union,
        write_runbook,
    )

    generator = HclImportGenerator(
        parser,
        dispatcher,
        catalog_provider=lambda: _offline_catalog(config),
    )
    with tempfile.TemporaryDirectory(prefix="meraki2tf-export-") as tmp:
        report = generator.generate(graph, Path(tmp))
    # The plan reconciliation never runs here, so the payload scan alone
    # carries the "restore manually after a rebuild" secret set.
    unmanaged_secrets = secret_attribute_union(
        report.captured, {}, payload_index(graph)
    )
    surfaces = generator.spec_surfaces()
    manifest = build_manifest(
        organization_id=graph.organization_id,
        captured=report.captured,
        unsupported=report.unsupported,
        # Export runs never read Terraform state; every capturable
        # asset is honestly "in the kit, not known to be in state".
        state_addresses=frozenset(),
        unmanaged_secret_attributes=unmanaged_secrets,
        restore_via=restore_verdicts(plan_restore(graph, parser)),
        scope_networks=scope_networks,
        duplicates=report.duplicates,
        discovered_assets=graph.asset_count(),
        spec_gap_count=report.spec_gap_count,
        relationship_gap_count=report.relationship_gap_count,
        excluded_rpc_paths=surfaces.rpc_only_paths,
        api_read_only_paths=surfaces.api_read_only_paths,
        suspect_endpoints=(
            diagnostics.suspect_endpoints if diagnostics is not None else ()
        ),
    )
    config.workdir.mkdir(parents=True, exist_ok=True)
    write_manifest(manifest, config.workdir)
    # The DR runbook is regenerated every run in every mode: after a
    # disaster the manual-rebuild list must be as fresh as the snapshot
    # it accompanies, not as old as the last terraform rehearsal.
    write_runbook(
        workdir=config.workdir,
        organization_id=graph.organization_id,
        graph=graph,
        captured=report.captured,
        unsupported=report.unsupported,
        unmanaged_secret_attributes=unmanaged_secrets,
        parser=parser,
        scope_networks=scope_networks,
    )
    logger.info(
        "Snapshot export complete; dispatching RUN_SUCCESS notification. "
        "The Meraki organization was not modified — every run is "
        "read-only toward Meraki."
    )
    dispatcher.dispatch(
        run_success(
            imports_written=report.imports_written,
            drift_was_detected=drift_was_detected,
            workspace=str(config.workdir),
            discovered_assets=graph.asset_count(),
            imports_already_tracked=report.skipped_existing,
            unsupported=unsupported_payload(report.unsupported),
            pending_imports=None,
            comparison_performed=False,
            coverage_percent=float(manifest["coverage_percent"]),
            unmanaged_secret_attributes=unmanaged_secrets,
            partial_scope=scope_networks or (),
        )
    )
    return manifest


def _export_snapshot(
    provider: MerakiDataProvider,
    config: RuntimeConfig,
    parser: OpenApiParser,
    dispatcher: AlertDispatcher,
    spec_file: Path | None = None,
) -> int:
    """Discover the graph and write it as an offline snapshot (--dump-to)."""
    assert config.dump_to is not None  # guarded by the caller
    with provider as source:
        graph = source.fetch_network_graph(config.org_id)
    dispatcher.organization_id = graph.organization_id
    if config.only:
        logger.warning(
            "PARTIAL export: --only scoped discovery to %d network(s); "
            "the snapshot is a selective backup (usable by --heal), NOT "
            "a DR snapshot of the organization — --restore, "
            "--replay-gaps, and --drift-baseline will refuse it.",
            len(graph.networks),
        )
    drift_was_detected = False
    if config.drift_baseline is not None:
        from meraki2tf.snapshot_diff import baseline_drift, render_diff

        drift = baseline_drift(graph, config.drift_baseline, parser)
        if drift.is_empty:
            logger.info("Snapshot drift vs baseline: none.")
        else:
            drift_was_detected = True
            logger.warning(
                "Snapshot drift vs baseline (%s); dispatching "
                "DRIFT_DETECTED alert.", drift.summary(),
            )
            dispatcher.dispatch(
                drift_detected(
                    diff=render_diff(drift),
                    workspace=str(config.dump_to),
                    origin="snapshot-diff",
                )
            )
    # Classification keys on the raw graph: after sanitization the
    # identifiers are pseudonyms and the manifest would name objects
    # the operator cannot find in the dashboard.
    raw_graph = graph
    if config.sanitize:
        # The workdir-persistent salt keeps pseudonyms stable across
        # runs (sanitized snapshots stay diffable) without handing
        # snapshot recipients a dictionary-invertible unsalted digest.
        salt = load_or_create_salt(config.workdir / "sanitizer.salt")
        graph = sanitize_graph(graph, salt)
        logger.info("Snapshot sanitized: secrets redacted, identity pseudonymized.")
    else:
        logger.warning(
            "Snapshot is UNSANITIZED: it carries every credential Meraki "
            "returns on read (SSID PSKs, SNMP community strings, …). It is "
            "written owner-only (0600) — store it like a password file, and "
            "use --sanitize for any copy that leaves the DR vault."
        )
    spec_version: str | None = None
    spec_sha256: str | None = None
    if spec_file is not None:
        # Stamp the spec identity into the snapshot header so a later
        # --restore/--heal can warn when its runtime spec differs from
        # the one that shaped this capture.
        spec_version, spec_sha256 = spec_fingerprint(spec_file)
    write_snapshot(
        graph,
        config.dump_to,
        sanitized=config.sanitize,
        scope_selectors=tuple(config.only) if config.only else None,
        spec_version=spec_version,
        spec_sha256=spec_sha256,
    )
    manifest = _export_coverage(
        raw_graph,
        config,
        parser,
        dispatcher,
        drift_was_detected,
        scope_networks=(
            tuple(n.network_id for n in raw_graph.networks)
            if config.only
            else None
        ),
        diagnostics=getattr(source, "discovery_diagnostics", None),
    )
    if config.fail_on_gaps:
        return _coverage_gap_exit(int(manifest["totals"]["unsupported"]))
    return 0


def _rebuild(config: RuntimeConfig) -> int:
    """Explicit disaster-recovery action: preview or execute a rebuild apply.

    This is the single place in the tool where ``terraform apply`` can
    happen, and only when the operator passes both --rebuild and
    --confirm; --rebuild alone is a read-only plan preview.
    """
    if not api_key_present():
        logger.critical(
            "--rebuild requires %s: the Terraform provider must authenticate "
            "against the Meraki dashboard to plan and apply.",
            API_KEY_ENV_VAR,
        )
        return 1
    if not (config.workdir / PROVIDER_FILENAME).exists():
        logger.critical(
            "No rebuild artifacts found in %s (missing %s). Run the pipeline "
            "first to generate them.",
            config.workdir,
            PROVIDER_FILENAME,
        )
        return 1
    try:
        runner = TerraformRunner(
            config.workdir,
            executable=config.terraform_bin,
            state_path=config.state_file,
            backend=config.backend,
        )
    except TerraformError as exc:
        # e.g. --state-file named terraform.tfstate inside the workdir;
        # surface the same clean diagnostic the pipeline path gives
        # instead of an unhandled traceback.
        logger.critical("%s", exc)
        return 1
    # The apply targets whatever organization the workdir's artifacts
    # belong to — name it prominently in preview AND confirm output so
    # the operator can verify before terraform touches anything, and
    # let --expect-org turn that verification into a hard interlock.
    resolved = preflight.resolve_rebuild_organization(
        config.workdir,
        None if config.backend.is_remote else runner.state_path,
    )
    if resolved is None:
        logger.warning(
            "Rebuild target organization: UNKNOWN — neither "
            "coverage.json, the state, nor imports.tf in %s names an "
            "organization. Verify the workdir belongs to the org you "
            "intend to rebuild before confirming.",
            config.workdir,
        )
    else:
        logger.warning(
            "Rebuild target organization: %s (resolved from %s). The "
            "apply writes to this organization — verify it is the one "
            "you intend to rebuild.",
            resolved[0], resolved[1],
        )
    if config.expect_org is not None:
        if resolved is None:
            logger.critical(
                "--expect-org %s cannot be verified: the workdir does "
                "not name an organization. Refusing to plan or apply.",
                config.expect_org,
            )
            return 2
        if resolved[0] != config.expect_org:
            logger.critical(
                "--expect-org %s does not match the organization this "
                "workdir resolves to (%s, from %s). Refusing to plan or "
                "apply.",
                config.expect_org, resolved[0], resolved[1],
            )
            return 2
    # Built before the plan, like every other guarded DR path: a
    # misconfigured channel must refuse the action up front — before a
    # secret-bearing saved plan ever lands in the workdir — and a
    # mid-incident half-applied rebuild must reach the on-call channel,
    # not just the local terminal.
    dispatcher = build_dispatcher(config)
    try:
        if config.state_file is not None:
            # Re-anchor the backend at the explicitly requested state
            # file; otherwise init would silently use whatever path the
            # previous pipeline run baked into provider.tf.
            runner.prepare_workspace()
        runner.init()
        preview = runner.plan_preview()
    except (TerraformError, OSError) as exc:
        logger.critical("Rebuild planning failed: %s", exc)
        return 1
    # Same masking the alert payloads get: a plan echoes attribute
    # values, and the log must carry names and locators, never secrets.
    logger.info(
        "Rebuild plan for workspace %s:\n%s",
        config.workdir, redact_diff(condense_diff(preview.stdout)),
    )
    if not preview.has_changes:
        runner.discard_rebuild_plan()
        logger.info(
            "Nothing to rebuild: the organization already matches the "
            "generated artifacts."
        )
        return _alert_outage_exit(dispatcher)
    if not config.confirm:
        # The saved plan embeds refreshed sensitive values; a preview-
        # only run must not leave it on disk.
        runner.discard_rebuild_plan()
        logger.warning(
            "Preview only — nothing was applied. Re-run with "
            "'--rebuild --confirm' to execute terraform apply and rebuild "
            "the organization from the generated artifacts."
        )
        return _alert_outage_exit(dispatcher)
    try:
        runner.rebuild_apply()
    except (TerraformError, OSError) as exc:
        logger.critical("Rebuild apply failed: %s", exc)
        dispatcher.dispatch(
            rebuild_executed(
                workspace=str(config.workdir), succeeded=False, error=str(exc)
            )
        )
        return 1
    logger.info(
        "Rebuild complete: the organization now matches the generated artifacts."
    )
    dispatcher.dispatch(
        rebuild_executed(workspace=str(config.workdir), succeeded=True)
    )
    return _alert_outage_exit(dispatcher)


def _wipe_org(config: RuntimeConfig) -> int:
    """Guarded teardown of a hardware-free drill organization.

    The fourth guarded write path. Interlocks live in
    :class:`~meraki2tf.restorer.OrgWiper` (no-claimed-devices, exact
    name match) and are re-verified immediately before destruction.
    """
    assert config.wipe_org is not None  # guarded by the caller
    assert config.wipe_org_name is not None  # guarded by the caller
    from meraki2tf.restorer import OrgWiper, WipeRefusedError

    if not api_key_present():
        logger.critical(
            "--wipe-org requires %s to inspect and (with --confirm) "
            "delete the drill organization.", API_KEY_ENV_VAR,
        )
        return 1
    # Built before any write: a misconfigured channel must refuse the
    # whole action up front, never after the org is already gone with
    # the mandated executed-alert left undeliverable.
    dispatcher = build_dispatcher(config)
    wiper = OrgWiper()
    try:
        preview = wiper.preview(config.wipe_org, config.wipe_org_name)
    except WipeRefusedError as exc:
        logger.critical("Wipe refused: %s", exc)
        return 2
    except Exception as exc:
        logger.critical("Wipe target could not be inspected: %s", exc)
        return 1
    logger.warning(
        "Wipe target verified: organization %s (%r), %d network(s), "
        "%d config template(s), 0 claimed devices, %d admin(s) besides "
        "the caller%s.",
        preview.organization_id, preview.organization_name,
        preview.network_count, preview.config_template_count,
        preview.other_admin_count,
        " (templates/admins are removed before the organization is "
        "deleted)"
        if preview.other_admin_count or preview.config_template_count
        else "",
    )
    if not config.confirm:
        logger.warning(
            "Preview only — nothing was deleted. Re-run with "
            "'--wipe-org %s --wipe-org-name %r --confirm' to delete "
            "every network and the organization itself. Note: dashboard "
            "deletion is immediate; Cisco's backend retention of deleted "
            "data is their policy — for hard-erasure guarantees after an "
            "unsanitized drill, file a data-deletion request with Meraki "
            "support (or drill from the sanitized snapshot).",
            preview.organization_id, preview.organization_name,
        )
        return 0
    try:
        result = wiper.execute(config.wipe_org, config.wipe_org_name)
    except WipeRefusedError as exc:
        logger.critical("Wipe refused at execution recheck: %s", exc)
        return 2
    except Exception as exc:
        # A transient API fault mid-teardown must reach the notification
        # channels and exit cleanly, not die as an unhandled traceback
        # (the contract's "critical script processing faults" trigger).
        logger.critical("Wipe execution failed: %s", exc)
        dispatcher.dispatch(
            processing_fault(
                stage="drill-org wipe (--wipe-org --confirm)", error=str(exc)
            )
        )
        return 1
    for target, reason in result.failed:
        logger.error("Wipe FAILED for %s: %s", target, reason)
    logger.warning(
        "Wipe complete: %d network(s) deleted, organization %s.",
        len(result.deleted_networks),
        "deleted" if result.organization_deleted else "NOT deleted",
    )
    dispatcher.dispatch(
        org_wipe_executed(
            organization_id=config.wipe_org,
            deleted_networks=len(result.deleted_networks),
            organization_deleted=result.organization_deleted,
            failed=result.failed,
        )
    )
    if not result.organization_deleted:
        return 1
    # A write to Meraki happened; the mandated alert reaching nobody
    # must surface as the notifier-outage exit, exactly like the
    # pipeline paths.
    return _alert_outage_exit(dispatcher)


def _restore(config: RuntimeConfig) -> int:
    """Explicit DR action: preview or execute a full-organization restore.

    The third guarded write path (with ``_rebuild`` and
    ``_replay_gaps``): preview by default, ``--confirm`` executes — and
    only ever into ``--target-org``, never the snapshot's source
    organization.
    """
    assert config.dump_path is not None  # guarded by the caller
    assert config.target_org is not None  # guarded by the caller
    from meraki2tf.restorer import (
        OrgRestorer,
        RestoreJournal,
        plan_restore,
        render_restore_plan,
    )

    # Built before any write: a misconfigured channel must refuse the
    # whole action up front, never after the target org was already
    # written to with the mandated executed-alert left undeliverable.
    dispatcher = build_dispatcher(config)
    try:
        # DR write action: never auto-refresh the spec (deterministic
        # dispatch; the exact spec version+sha256 is logged).
        spec_file = resolve_spec(config.spec_path, refresh=False)
        spec_parser = OpenApiParser(spec_file)
        provider = StaticJsonDataProvider(config.dump_path, parser=spec_parser)
        with provider as source:
            # No org-ID override (the CLI refuses --org-id here): the
            # graph's organization ID is the snapshot's recorded source
            # org, which the target guard below depends on.
            graph = source.fetch_network_graph(None)
    except Exception as exc:
        logger.critical("Restore could not load the snapshot: %s", exc)
        return 1
    _warn_snapshot_spec_skew(provider, spec_file, "--restore")
    # A nested multi-org export records several source organizations,
    # but the executor can only remap ONE source org onto the target:
    # actions belonging to any other recorded org would carry their
    # real (live) organization IDs, so a multi-org snapshot is refused
    # outright rather than partially restored.
    recorded = frozenset(provider.recorded_organization_ids)
    if len(recorded) > 1:
        logger.critical(
            "This snapshot records %d organizations; --restore rebuilds "
            "exactly one organization per run. Export a single-org "
            "snapshot for the organization you want to rebuild.",
            len(recorded),
        )
        return 2
    restore_scope = provider.snapshot_scope
    if restore_scope is not None:
        # A partial snapshot cannot rebuild an organization: objects
        # outside its scope were never captured, so references to them
        # would carry dead source-org IDs into the target. Refused for
        # preview and confirm alike.
        logger.critical(
            "This snapshot is a PARTIAL export (--only, %d network(s)); "
            "--restore rebuilds a whole organization and requires a "
            "full snapshot. Selective backups are for same-org --heal.",
            len(restore_scope.network_ids),
        )
        return 2
    # The interlock must refuse every recorded source org, not just the
    # first (which is all graph.organization_id can carry).
    source_org_ids = recorded | {graph.organization_id}
    if config.target_org in source_org_ids:
        logger.critical(
            "--target-org matches the snapshot's source organization; "
            "a restore never writes to the org it was captured from. "
            "Create a fresh organization and target that."
        )
        return 2
    if provider.snapshot_sanitized:
        logger.warning(
            "This snapshot is SANITIZED: its organization ID is a "
            "pseudonym, so the never-restore-into-the-source-org check "
            "cannot verify the target — make certain %s is a scratch "
            "organization. Secret values were redacted at export and "
            "will be reported for manual re-entry, not restored.",
            config.target_org,
        )
    serial_map: dict[str, str] = {}
    if config.serial_map is not None:
        try:
            loaded = json.loads(config.serial_map.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.critical("Cannot read --serial-map: %s", exc)
            return 2
        if not isinstance(loaded, dict):
            logger.critical("--serial-map must be a JSON object of old→new serials.")
            return 2
        serial_map = {str(k): str(v) for k, v in loaded.items()}
    plan = plan_restore(graph, spec_parser)
    logger.info(
        "Restore plan for target organization %s from snapshot %s:\n%s",
        config.target_org, config.dump_path, render_restore_plan(plan),
    )
    for item in plan.unrestorable:
        logger.warning(
            "Cannot restore %s (ids=%s): %s",
            item.api_path, ",".join(item.path_values) or "<none>", item.reason,
        )
    if config.skip_claims:
        logger.info(
            "Drill mode: device claiming and device-scoped features "
            "will be skipped (hardware belongs to the production "
            "organization)."
        )
    if not config.confirm:
        logger.warning(
            "Preview only — nothing was written to Meraki. Re-run with "
            "'--restore --confirm' to rebuild organization %s from the "
            "snapshot.", config.target_org,
        )
        return 0
    if not api_key_present():
        logger.critical(
            "--restore --confirm requires %s: rebuilding writes to the "
            "Meraki dashboard API.", API_KEY_ENV_VAR,
        )
        return 1
    from meraki2tf.restorer import RestoreJournalMismatchError

    try:
        journal = RestoreJournal(config.workdir / "restore-journal.jsonl")
    except ValueError as exc:
        logger.critical("Restore journal is unreadable: %s", exc)
        return 2
    if provider.snapshot_sanitized and not (
        journal.completed or journal.attempted
    ):
        # A sanitized snapshot's recorded org ID is a pseudonym, so the
        # never-restore-into-the-source-org interlock above cannot
        # recognize the source org. A fresh restore only ever targets a
        # fresh (empty) organization — a populated target is either the
        # source org itself or an org someone cares about. A journaled
        # resume is exempt: its earlier waves populated the target (an
        # attempt-only journal counts — a run that died inside its very
        # first create/journal window may already have written, and
        # refusing would wedge that resume forever; a journal bound to
        # a different target still refuses at execute()'s bind).
        try:
            existing = _target_network_count(config.target_org)
        except Exception as exc:  # fail closed
            logger.critical(
                "Cannot verify that target organization %s is empty "
                "(%s); a sanitized-snapshot restore only writes into a "
                "fresh organization.", config.target_org, exc,
            )
            return 1
        if existing:
            logger.critical(
                "Target organization %s already contains %d network(s). "
                "A sanitized snapshot cannot prove it is not this "
                "restore's own source organization, so --restore only "
                "writes it into an EMPTY organization. Create a fresh "
                "scratch org and target that (or resume the original "
                "restore from its workdir journal).",
                config.target_org, existing,
            )
            return 2
    restorer = OrgRestorer(
        config.target_org, journal, serial_map=serial_map,
        skip_claims=config.skip_claims,
    )
    try:
        result = restorer.execute(graph, plan)
    except RestoreJournalMismatchError as exc:
        logger.critical("%s", exc)
        return 2
    except Exception as exc:
        # Per-object failures are isolated inside the restorer; anything
        # that still escapes (SDK construction, a journal write) must
        # alert and exit cleanly — completed work stays journaled, so a
        # re-run resumes instead of duplicating creates.
        logger.critical(
            "Restore execution failed: %s (completed writes are journaled "
            "at %s; re-run with --restore --confirm to resume).",
            exc, config.workdir / "restore-journal.jsonl",
        )
        dispatcher.dispatch(
            processing_fault(
                stage="organization restore (--restore --confirm)",
                error=str(exc),
            )
        )
        return 1
    for key, reason in result.failed:
        logger.error("Restore FAILED for %s: %s", key, reason)
    for entry in result.skipped:
        logger.warning("Restore skipped %s: %s", entry["target"], entry["reason"])
    for key, paths in result.drill_placeholders:
        logger.warning(
            "Drill placeholder secret(s) written for %s (%s); the real "
            "values are redacted in the sanitized snapshot — re-enter "
            "them per the runbook if this organization is ever kept.",
            key, paths,
        )
    logger.info(
        "Restore into %s complete: %d executed, %d failed, %d skipped "
        "(journal: %s).",
        config.target_org, len(result.executed), len(result.failed),
        len(result.skipped), config.workdir / "restore-journal.jsonl",
    )
    dispatcher.dispatch(
        restore_executed(
            target_organization_id=config.target_org,
            executed=result.executed,
            failed=result.failed,
            skipped=result.skipped,
        )
    )
    if result.failed:
        return 1
    # Writes happened; an undelivered RESTORE_EXECUTED alert must
    # surface as the notifier-outage exit, like the pipeline paths.
    return _alert_outage_exit(dispatcher)


def _warn_snapshot_spec_skew(
    provider: StaticJsonDataProvider, spec_file: Path, action: str
) -> None:
    """WARN when the runtime spec differs from the snapshot's recorded one.

    The snapshot header (stamped at export) records which OpenAPI
    document shaped the capture; a restore/heal planning against a
    different document may classify assets differently. Old snapshots
    without the stamp stay silent — there is nothing to compare.
    """
    recorded_version = provider.snapshot_spec_version
    recorded_sha = provider.snapshot_spec_sha256
    if recorded_version is None and recorded_sha is None:
        return
    runtime_version, runtime_sha = spec_fingerprint(spec_file)
    if recorded_version != runtime_version or (
        recorded_sha is not None and recorded_sha != runtime_sha
    ):
        logger.warning(
            "%s runs with OpenAPI spec version %s (sha256 %s) but the "
            "snapshot was exported with version %s (sha256 %s); the "
            "write plan may classify assets differently than the "
            "capture did. Pass --spec with the capture-time document "
            "for exact parity.",
            action, runtime_version or "unknown", runtime_sha,
            recorded_version or "unknown", recorded_sha or "unrecorded",
        )


def _target_network_count(target_org: str) -> int:
    """How many networks the restore target organization holds now."""
    dashboard = dashboard_client()
    networks = dashboard.organizations.getOrganizationNetworks(
        target_org, total_pages="all"
    )
    return len(networks) if isinstance(networks, list) else 0


def _heal(config: RuntimeConfig) -> int:
    """Same-organization partial recovery from accidental deletions.

    Diffs the snapshot against fresh live discovery of the SAME org and
    recreates only what is missing (additive-only — surviving objects
    are never dispatched). Preview by default; --confirm executes.
    """
    assert config.dump_path is not None  # guarded by the caller
    assert config.org_id  # guarded by the caller
    from meraki2tf.healer import HealFilterError, filter_heal_plan, plan_heal
    from meraki2tf.restorer import (
        HEAL_VERIFIED_ALIVE_REASON,
        OrgRestorer,
        RestoreJournal,
        RestoreJournalMismatchError,
        render_restore_plan,
    )

    if not api_key_present():
        # Even the preview needs the live API: what is "missing" is
        # decided by discovering the organization as it is right now.
        logger.critical(
            "--heal requires %s: live discovery of the organization "
            "decides which snapshot objects are missing.", API_KEY_ENV_VAR,
        )
        return 1
    dispatcher = build_dispatcher(config)
    try:
        # DR write action: never auto-refresh the spec (deterministic
        # dispatch; the exact spec version+sha256 is logged).
        spec_file = resolve_spec(config.spec_path, refresh=False)
        spec_parser = OpenApiParser(spec_file)
        provider = StaticJsonDataProvider(config.dump_path, parser=spec_parser)
        with provider as source:
            snapshot = source.fetch_network_graph(None)
    except Exception as exc:
        logger.critical("Heal could not load the snapshot: %s", exc)
        return 1
    _warn_snapshot_spec_skew(provider, spec_file, "--heal")
    if provider.snapshot_sanitized:
        logger.critical(
            "--heal requires the unsanitized snapshot: a sanitized "
            "snapshot's identifiers are pseudonyms and cannot be matched "
            "against the live organization."
        )
        return 2
    # The inverse of --restore's interlock: heal writes into exactly the
    # organization the snapshot came from, never anywhere else.
    recorded = frozenset(provider.recorded_organization_ids) | {
        snapshot.organization_id
    }
    if config.org_id not in recorded:
        logger.critical(
            "--org-id does not match the snapshot's source organization; "
            "--heal recreates deleted objects in the very organization "
            "the snapshot was captured from. To rebuild a different "
            "organization, use --restore --target-org."
        )
        return 2
    heal_scope = provider.snapshot_scope
    live_scope: LiveNetworkScope | None = None
    if heal_scope is not None:
        # A partial (selective-backup) snapshot heals only its scope, so
        # live discovery narrows to the same networks — the heal preview
        # then costs what the scoped export did, not a full-org sweep.
        # plan_heal needs no change: both universes cover the scoped
        # networks plus org-level surfaces, and missing = snapshot-not-
        # in-live stays correct. The ID form never errors on zero
        # matches (a fully-deleted scoped network is the maximal heal).
        logger.info(
            "Snapshot is a PARTIAL export scoped to %d network(s); live "
            "discovery and the heal plan cover only that scope.",
            len(heal_scope.network_ids),
        )
        live_scope = LiveNetworkScope(
            network_ids=frozenset(heal_scope.network_ids)
        )
    try:
        with LiveApiDataProvider(
            parser=spec_parser, network_scope=live_scope
        ) as live_source:
            live = live_source.fetch_network_graph(config.org_id)
    except Exception as exc:
        logger.critical(
            "Heal could not discover the live organization: %s", exc
        )
        return 1
    plan = plan_heal(snapshot, live, spec_parser)
    logger.info(
        "Heal plan for organization %s: %s", config.org_id, plan.summary()
    )
    if config.only:
        try:
            selection = filter_heal_plan(plan, config.only)
        except HealFilterError as exc:
            logger.critical("%s", exc)
            return 2
        for raw, count in selection.selector_matches:
            logger.info(
                "--only %r matched %d missing object(s).", raw, count
            )
        if selection.auto_included:
            logger.info(
                "Auto-included %d missing object(s) the selection depends "
                "on (deleted parents / referenced objects): %s",
                len(selection.auto_included),
                ", ".join(selection.auto_included),
            )
        logger.info(
            "Skipped by --only: %d recreatable object(s), %d unrestorable, "
            "%d at Meraki defaults.",
            selection.excluded_actions, selection.excluded_unrestorable,
            selection.excluded_defaults,
        )
        plan = selection.plan
    for item in plan.missing.unrestorable:
        logger.warning(
            "Cannot heal %s (ids=%s): %s",
            item.api_path, ",".join(item.path_values) or "<none>",
            item.reason,
        )
    if not plan.missing.actions:
        if config.only:
            logger.info(
                "Nothing to heal within the --only selection: every "
                "matched missing asset is unrestorable or at Meraki "
                "defaults."
            )
        else:
            logger.info(
                "Nothing to heal: every restorable snapshot asset is "
                "still present in the live organization."
            )
        return 0
    logger.info(
        "Missing objects to recreate:\n%s",
        render_restore_plan(plan.missing),
    )
    if not config.confirm:
        # The re-run hint must carry the selection: recommending a bare
        # '--heal --confirm' after a filtered preview would escalate the
        # write to every missing object.
        rerun = "--heal " + "".join(
            f"--only '{value}' " for value in config.only or ()
        ) + "--confirm"
        scope_note = (
            f" (partial snapshot: scope covers "
            f"{len(heal_scope.network_ids)} network(s))"
            if heal_scope is not None
            else ""
        )
        logger.warning(
            "Preview only — nothing was written to Meraki. Re-run with "
            "'%s' to recreate the %d missing object(s) in "
            "organization %s%s.", rerun, len(plan.missing.actions),
            config.org_id, scope_note,
        )
        return 0
    try:
        journal = RestoreJournal(config.workdir / "heal-journal.jsonl")
    except ValueError as exc:
        logger.critical("Heal journal is unreadable: %s", exc)
        return 2
    restorer = OrgRestorer(
        config.org_id, journal, preset_mappings=plan.identity_mappings,
        # Heal's contract: surviving objects are never modified. Without
        # this, a name-conflicted create would adopt the survivor and
        # push the stale snapshot payload over it via the alignment PUT.
        additive_only=True,
    )
    try:
        result = restorer.execute(snapshot, plan.missing)
    except RestoreJournalMismatchError as exc:
        logger.critical("%s", exc)
        return 2
    except Exception as exc:
        logger.critical(
            "Heal execution failed: %s (completed writes are journaled "
            "at %s; re-run with --heal --confirm to resume).",
            exc, config.workdir / "heal-journal.jsonl",
        )
        dispatcher.dispatch(
            processing_fault(
                stage="organization heal (--heal --confirm)", error=str(exc)
            )
        )
        return 1
    for key, reason in result.failed:
        logger.error("Heal FAILED for %s: %s", key, reason)
    for entry in result.skipped:
        logger.warning("Heal skipped %s: %s", entry["target"], entry["reason"])
    logger.info(
        "Heal of %s complete: %d recreated, %d failed, %d skipped, "
        "%d surviving object(s) untouched (journal: %s)%s.",
        config.org_id, len(result.executed), len(result.failed),
        len(result.skipped), plan.surviving_count,
        config.workdir / "heal-journal.jsonl",
        (
            f" (partial snapshot: scope covers "
            f"{len(heal_scope.network_ids)} network(s))"
            if heal_scope is not None
            else ""
        ),
    )
    dispatcher.dispatch(
        heal_executed(
            organization_id=config.org_id,
            surviving=plan.surviving_count,
            executed=result.executed,
            failed=result.failed,
            skipped=result.skipped,
            only=config.only,
            snapshot_scope=(
                tuple(heal_scope.network_ids)
                if heal_scope is not None
                else ()
            ),
            # Distinct reporting for pre-write verification skips: a
            # nonzero count means live discovery undercounted survivors
            # and the additive-only guard caught it at write time.
            verified_alive=sum(
                1
                for entry in result.skipped
                if entry["reason"] == HEAL_VERIFIED_ALIVE_REASON
            ),
        )
    )
    if result.failed:
        return 1
    # Writes happened; an undelivered HEAL_EXECUTED alert must surface
    # as the notifier-outage exit, like the pipeline paths.
    return _alert_outage_exit(dispatcher)


def _replay_gaps(config: RuntimeConfig) -> int:
    """Explicit DR action: preview or execute a snapshot gap replay.

    One of the five explicit DR write paths (with ``_rebuild``,
    ``_heal``, ``_restore``, and ``_wipe_org``), each demanding an
    explicit --confirm; --replay-gaps alone is a read-only preview of
    the planned writes.
    """
    assert config.dump_path is not None  # guarded by the caller
    try:
        # DR write action: never auto-refresh the spec (deterministic
        # dispatch; the exact spec version+sha256 is logged).
        spec_parser = OpenApiParser(
            resolve_spec(config.spec_path, refresh=False)
        )
        provider = StaticJsonDataProvider(config.dump_path, parser=spec_parser)
        with provider as source:
            graph = source.fetch_network_graph(config.org_id)
    except Exception as exc:
        logger.critical("Gap replay could not load the snapshot: %s", exc)
        return 1
    replay_scope = provider.snapshot_scope
    if replay_scope is not None:
        # Gap replay is the post-restore full-org step; replaying a
        # subset would report "gaps replayed" when most were never
        # captured. Refused for preview and confirm alike.
        logger.critical(
            "This snapshot is a PARTIAL export (--only, %d network(s)); "
            "--replay-gaps replays the whole organization's gap surface "
            "and requires a full snapshot.",
            len(replay_scope.network_ids),
        )
        return 2
    if provider.snapshot_sanitized:
        logger.warning(
            "This snapshot is SANITIZED: secret values are redaction "
            "markers and identifiers are pseudonyms. Gap replay against "
            "a live tenant needs the unsanitized DR snapshot; redacted "
            "attributes will be skipped and reported for manual "
            "re-entry, and --confirm will refuse outright unless the "
            "target organization holds this snapshot's networks (i.e. "
            "it is the drill organization restored from it)."
        )
    # The organization remap keys on the snapshot's RECORDED source org:
    # --org-id names the (rebuilt) target organization, and using the
    # override as the source would defeat the remap and misdirect
    # org-scoped writes back into the snapshot's own organization.
    recorded_orgs = provider.recorded_organization_ids
    if len(frozenset(recorded_orgs)) > 1:
        # Same stance as --restore: the network-name join is built from
        # every recorded org's networks, so a second org's same-named
        # network would remap its objects and secrets onto the target —
        # a cross-tenant config bleed.
        logger.critical(
            "This snapshot records %d organizations; --replay-gaps "
            "replays exactly one organization per run. Export a "
            "single-org snapshot for the organization you want to "
            "replay into.",
            len(frozenset(recorded_orgs)),
        )
        return 2
    snapshot_org = recorded_orgs[0] if recorded_orgs else graph.organization_id
    # Name the organization the replay will write into, prominently and
    # before any planning output; --expect-org turns the verification
    # into a hard interlock (same semantics as the --rebuild assertion).
    replay_target = config.org_id or graph.organization_id
    logger.warning(
        "Gap replay target organization: %s (%s).",
        replay_target,
        "from --org-id"
        if config.org_id
        else "the snapshot's recorded organization",
    )
    if config.expect_org is not None and config.expect_org != replay_target:
        logger.critical(
            "--expect-org %s does not match the organization this gap "
            "replay resolves to (%s). Refusing to plan or write.",
            config.expect_org, replay_target,
        )
        return 2
    dispatcher = build_dispatcher(config)
    try:
        runner = TerraformRunner(
            config.workdir,
            executable=config.terraform_bin,
            state_path=config.state_file,
            backend=config.backend,
        )
    except TerraformError as exc:
        # e.g. --state-file named terraform.tfstate inside the workdir;
        # surface the same clean diagnostic the pipeline path gives
        # instead of an unhandled traceback.
        logger.critical("%s", exc)
        return 1
    generator = HclImportGenerator(
        spec_parser,
        dispatcher,
        # Keyless resolution on purpose: replay only needs the coverage
        # classification, and the workdir cache / bundled catalog is
        # exactly what generated the kit being recovered.
        catalog_provider=lambda: resolve_catalog(runner, keyed=False),
    )
    with tempfile.TemporaryDirectory(prefix="meraki2tf-replay-") as tmp:
        # Throwaway target: classification is the goal, not artifacts —
        # the real workdir's kit must not be touched by a replay.
        report = generator.generate(graph, Path(tmp), audit=False)
    actions, skipped = plan_replay(graph, report, spec_parser)
    target_org = config.org_id or graph.organization_id
    for item in skipped:
        logger.warning(
            "Cannot replay %s (ids=%s): %s",
            item.api_path, ",".join(item.identifiers) or "<none>", item.reason,
        )
    if not actions:
        logger.info(
            "Nothing to replay: the snapshot holds no restorable "
            "unsupported objects or secret attributes."
        )
        return 0
    logger.info(
        "Gap replay plan for organization %s — %d write(s) from snapshot %s:",
        target_org, len(actions), config.dump_path,
    )
    for action in actions:
        logger.info("  %s", action.target)
    if not config.confirm:
        logger.warning(
            "Preview only — nothing was written to Meraki. Re-run with "
            "'--replay-gaps --confirm' to restore these objects from the "
            "snapshot."
        )
        return 0
    if not api_key_present():
        logger.critical(
            "--replay-gaps --confirm requires %s: restoring objects writes "
            "to the Meraki dashboard API.",
            API_KEY_ENV_VAR,
        )
        return 1
    replayer = GapReplayer()
    try:
        network_ids = replayer.network_id_map(target_org, graph)
    except Exception as exc:
        logger.critical("Gap replay could not enumerate live networks: %s", exc)
        return 1
    try:
        executed, failed, refused = replayer.execute(
            actions, target_org, snapshot_org, network_ids,
            template_bound=template_bound_networks(graph),
            sanitized=provider.snapshot_sanitized,
        )
    except SanitizedReplayTargetError as exc:
        logger.critical("%s", exc)
        return 2
    skipped = (*skipped, *refused)
    dispatcher.dispatch(
        gap_replay_executed(
            organization_id=target_org,
            executed=executed,
            failed=failed,
            skipped=[dataclasses.asdict(item) for item in skipped],
        )
    )
    if failed:
        logger.error(
            "Gap replay finished with %d failure(s) (%d restored); the "
            "runbook in the workdir covers the manual fallback.",
            len(failed), len(executed),
        )
        return 1
    logger.info(
        "Gap replay complete: %d object(s)/secret set(s) restored from "
        "the snapshot (%d skipped with documented reasons).",
        len(executed), len(skipped),
    )
    # Writes happened; an undelivered GAP_REPLAY_EXECUTED alert must
    # surface as the notifier-outage exit, like the pipeline paths.
    return _alert_outage_exit(dispatcher)


def _list_orgs() -> int:
    """Print every organization the API key can see — the --org-id helper.

    Read-only: a single ``getOrganizations`` call. The table goes to
    stdout so it works interactively and in shell pipelines; nothing is
    written to the workdir and no alerts are dispatched.
    """
    try:
        client = dashboard_client(wait_on_rate_limit=True)
        organizations = client.organizations.getOrganizations()
    except Exception as exc:
        logger.critical("Could not list organizations: %s", exc)
        return 1
    if not organizations:
        print(
            "The API key is valid but sees no organizations; check its "
            "access in the Meraki dashboard."
        )
        return 0
    # Organization names (and, defensively, IDs) are tenant-controlled
    # free text printed to stdout; neutralize control characters up front
    # so a crafted name cannot forge a table row or emit an ANSI escape.
    # Sanitizing before the width calculation keeps the columns aligned.
    rows = sorted(
        (
            (
                sanitize_control_chars(str(org.get("id", ""))),
                sanitize_control_chars(str(org.get("name", ""))),
            )
            for org in organizations
        ),
        key=lambda row: row[1].lower(),
    )
    width = max(len("ORG ID"), *(len(org_id) for org_id, _ in rows))
    print(f"{'ORG ID':<{width}}  ORGANIZATION NAME")
    for org_id, name in rows:
        print(f"{org_id:<{width}}  {name}")
    print()
    print("Next: meraki2tf --org-id <ORG ID>")
    return 0


def _diff_networks_run(config: RuntimeConfig) -> int:
    """Standalone cross-network comparison (--diff-networks).

    Read-only end to end: no terraform, no workdir artifacts, no
    alerts — the report goes to stdout (and, with --diff-out, to a
    JSON file carrying attribute names only, never values). Live mode
    narrows discovery to the union of both patterns, so the comparison
    costs two networks' sweeps instead of the organization's.
    """
    from meraki2tf.network_diff import (
        NetworkResolutionError,
        compare_networks,
        comparison_payload,
        render_network_comparison,
    )

    assert config.diff_networks is not None  # guarded by the caller
    pattern_a, pattern_b = config.diff_networks
    try:
        spec_parser = OpenApiParser(resolve_spec(config.spec_path))
        provider: MerakiDataProvider
        if config.dump_path is not None:
            provider = StaticJsonDataProvider(
                config.dump_path, parser=spec_parser
            )
        else:
            provider = LiveApiDataProvider(
                parser=spec_parser,
                network_scope=LiveNetworkScope(
                    selectors=(pattern_a, pattern_b)
                ),
            )
        with provider as source:
            graph = source.fetch_network_graph(config.org_id)
    except ScopeFilterError as exc:
        # A live pattern matching no network: operator input error,
        # already listing the available networks.
        logger.critical("%s", exc)
        return 2
    except Exception as exc:
        logger.critical(
            "Cross-network diff could not load the configuration: %s", exc
        )
        return 1
    try:
        comparison = compare_networks(
            graph, pattern_a, pattern_b, spec_parser
        )
    except NetworkResolutionError as exc:
        logger.critical("%s", exc)
        return 2
    print(render_network_comparison(comparison))
    if config.diff_out is not None:
        try:
            config.diff_out.parent.mkdir(parents=True, exist_ok=True)
            config.diff_out.write_text(
                json.dumps(comparison_payload(comparison), indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exc:
            # Every other unwritable-path in the CLI answers with one
            # CRITICAL line; this one raised through main() and printed
            # a traceback on top of an otherwise complete report.
            logger.critical(
                "Cross-network diff could not be written to %s: %s. The "
                "comparison above is complete — re-run with a writable "
                "--diff-out path to capture it as JSON.",
                config.diff_out, exc,
            )
            return 1
        logger.info(
            "Cross-network diff JSON written to %s (attribute names "
            "only — values are never written).",
            config.diff_out,
        )
    return 0


#: Config-file keys that steer where a confirmed DR action WRITES —
#: or WHAT executes it. A long-lived file must never pick a write
#: target, the workdir whose kit/journal a DR action consumes, or the
#: terraform binary --rebuild --confirm hands the API key to: when a DR
#: action is invoked, these must be typed on the command line.
_DR_TARGET_DESTS = frozenset({"org_id", "from_dump", "workdir", "terraform_bin"})


def _apply_config_file(
    arg_parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    argv: Sequence[str],
) -> None:
    """Fill flags the command line left at their default from --config.

    Precedence is strictly CLI > file > built-in default: a flag the
    operator actually typed (detected from ``argv``, so an explicitly
    typed default value still wins) is never overridden, and a file
    value is otherwise applied only where the parsed value still equals
    the parser's default. The loader has already refused every DR
    action, confirmation, and credential key; additionally, when this
    invocation carries a DR write action, the file may not supply the
    action's target (``org-id``/``from-dump``) — the org a confirmed
    write lands in must be human-typed, never inherited from a
    scheduled job's config file.
    """
    if args.config is None:
        return
    try:
        overrides = load_config_file(Path(args.config))
    except ConfigFileError as exc:
        arg_parser.error(str(exc))
    tokens = list(argv)
    explicit = {
        action.dest
        for action in arg_parser._actions
        for option in action.option_strings
        if any(token == option or token.startswith(f"{option}=") for token in tokens)
    }
    dr_action = any(
        getattr(args, dest, False) for dest in DR_ACTION_FLAGS
    )
    for dest, value in overrides.items():
        if dr_action and dest in _DR_TARGET_DESTS and dest not in explicit:
            arg_parser.error(
                f"--config {args.config} supplies '{dest.replace('_', '-')}' "
                "while a disaster-recovery action is invoked; the target of "
                "a DR action must be typed on the command line (pass "
                f"--{dest.replace('_', '-')} explicitly)."
            )
        if dest in explicit:
            continue
        if getattr(args, dest) == arg_parser.get_default(dest):
            setattr(args, dest, value)


#: The five human-invoked disaster-recovery actions. Each is a
#: standalone mode that ends the run; every one of them is a preview
#: until --confirm is added (Cardinal Rule 1).
DR_ACTION_FLAGS = ("rebuild", "heal", "replay_gaps", "restore", "wipe_org")

#: Flags that only shape a DR action — its blast radius, its second
#: factor, its target. Orphaned (no DR action alongside), each one is
#: refused rather than ignored: a flag that does nothing would let an
#: operator believe an effect happened when it did not.
DR_TARGETING_FLAGS = (
    "confirm", "target_org", "serial_map", "skip_claims", "wipe_org_name",
)

#: Flags that steer the terraform pipeline (state materialization,
#: deletion confirmation, the coverage gate, baseline reset).
PIPELINE_FLAGS = ("sync", "confirm_deletions", "fail_on_gaps", "rebaseline")

#: Flags that steer snapshot export and the snapshot-diff drift chain.
EXPORT_FLAGS = ("dump_to", "sanitize", "drift_baseline")


def _flags_set(config: RuntimeConfig, *groups: Sequence[str]) -> bool:
    """True when the operator passed any flag in the named groups.

    Every flag these groups name is a bool, a ``Path | None``, a
    ``str | None`` or a tuple, so "was it passed?" is exactly its
    truthiness — no flag has a meaningful falsy non-``None`` value.
    """
    return any(
        bool(getattr(config, name)) for group in groups for name in group
    )


def _validate_list_orgs(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--list-orgs answers one question and exits: nothing combines."""
    # Orphaned companions are refused, never silently ignored (the
    # house rule): the helper answers one question and exits, so any
    # mode or target flag alongside it marks a misunderstanding. This
    # is the one check that names EVERY mode and target flag.
    if _flags_set(
        config,
        DR_ACTION_FLAGS, DR_TARGETING_FLAGS, PIPELINE_FLAGS, EXPORT_FLAGS,
        ("org_ids", "dump_path", "expect_org", "check", "estimate",
         "diff_networks", "diff_out", "discovery_checkpoint"),
    ):
        arg_parser.error(
            "--list-orgs is a standalone discovery helper; do not "
            "combine it with any other mode or target flag."
        )
    if not api_key_present():
        arg_parser.error(
            f"--list-orgs asks the dashboard which organizations your "
            f"key can see; export {API_KEY_ENV_VAR} first."
        )


def _validate_diff_networks(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--diff-networks: read-only, one org, --from-dump or --org-id."""
    if config.diff_out is not None and config.diff_networks is None:
        # Orphaned mode-scoped flags are refused, never silently
        # ignored (the house rule).
        arg_parser.error(
            "--diff-out is only valid together with --diff-networks."
        )
    if config.diff_networks is None:
        return
    # --from-dump and --org-id are the comparison's own inputs, so they
    # are the two flags NOT named here (see the message).
    if _flags_set(
        config,
        DR_ACTION_FLAGS, DR_TARGETING_FLAGS, PIPELINE_FLAGS, EXPORT_FLAGS,
        ("expect_org", "only", "discovery_checkpoint"),
    ):
        arg_parser.error(
            "--diff-networks is a standalone read-only comparison; "
            "combine it only with --from-dump or --org-id (and "
            "optionally --diff-out / --spec)."
        )
    if len(config.org_ids) > 1:
        arg_parser.error(
            "--diff-networks compares two networks of ONE "
            "organization; pass at most one --org-id."
        )
    if config.dump_path is None and not config.org_ids:
        arg_parser.error(
            "--diff-networks in live mode requires --org-id (or run "
            "offline against a snapshot with --from-dump)."
        )
    if config.dump_path is None and not api_key_present():
        arg_parser.error(
            f"--diff-networks in live mode requires {API_KEY_ENV_VAR} "
            "to discover the two networks; export the key or run "
            "offline with --from-dump."
        )


def _validate_check_estimate(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--check / --estimate: read-only helpers, one at a time."""
    if config.check and config.estimate:
        arg_parser.error(
            "--check and --estimate are separate standalone helpers; "
            "run one at a time."
        )
    if not (config.check or config.estimate):
        return
    helper = "--check" if config.check else "--estimate"
    # Pipeline/export flags are deliberately NOT refused here: --check
    # exists to validate a full flag set, which includes them.
    if _flags_set(
        config, DR_ACTION_FLAGS, DR_TARGETING_FLAGS, ("expect_org",)
    ):
        arg_parser.error(
            f"{helper} is a standalone read-only helper; do not "
            "combine it with disaster-recovery actions or --confirm."
        )
    if not config.estimate:
        return
    if _flags_set(config, PIPELINE_FLAGS, EXPORT_FLAGS, ("only",)):
        arg_parser.error(
            "--estimate previews discovery cost only; do not combine "
            "it with pipeline, export, or scope flags."
        )
    if config.dump_path is None:
        if len(config.org_ids) != 1:
            arg_parser.error(
                "--estimate needs exactly one --org-id in live mode "
                "(or --from-dump for an offline estimate)."
            )
        if not api_key_present():
            arg_parser.error(
                "--estimate enumerates networks and devices via the "
                f"dashboard API; export {API_KEY_ENV_VAR} first (or "
                "estimate offline with --from-dump)."
            )


def _validate_dr_companions(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """Every DR-shaping flag must have its DR action alongside it."""
    if config.confirm and not _flags_set(config, DR_ACTION_FLAGS):
        arg_parser.error(
            "--confirm is only valid together with --rebuild, --replay-gaps, "
            "--restore, --heal, or --wipe-org."
        )
    if config.expect_org and not (config.rebuild or config.replay_gaps):
        arg_parser.error(
            "--expect-org is only valid together with --rebuild or "
            "--replay-gaps."
        )
    # Orphaned mode-scoped flags are refused, never silently ignored: a
    # flag that does nothing would let an operator believe an effect
    # (a serial remap, a name second factor) happened when it did not.
    if config.target_org and not config.restore:
        arg_parser.error("--target-org is only valid together with --restore.")
    if config.serial_map is not None and not config.restore:
        arg_parser.error("--serial-map is only valid together with --restore.")
    if config.skip_claims and not config.restore:
        arg_parser.error("--skip-claims is only valid together with --restore.")


def _validate_only(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """Validate every use of --only.

    ``--only`` wears three hats: heal selector, scoped export, and
    scoped pipeline run. --heal is therefore absent from the refusal
    below — the selector is that action's own argument.
    """
    scoped_pipeline = False
    if config.only and not (config.heal or config.dump_to is not None):
        # Scoped default pipeline run: generate the kit (and plan) for
        # a subset of networks — the single-site onboarding case.
        if _flags_set(
            config, ("rebuild", "replay_gaps", "restore", "wipe_org")
        ):
            arg_parser.error(
                "--only cannot be combined with --rebuild, "
                "--replay-gaps, --restore, or --wipe-org."
            )
        if config.dump_path is not None:
            arg_parser.error(
                "--only scopes LIVE discovery; re-slicing an existing "
                "--from-dump snapshot is not supported (a partial "
                "snapshot input already carries its scope in its "
                "header)."
            )
        scoped_pipeline = True
    if config.only and (
        scoped_pipeline or (config.dump_to is not None and not config.heal)
    ):
        # (--heal + --dump-to is itself refused in the heal branch.)
        if config.dump_path is not None:
            arg_parser.error(
                "--only with --dump-to scopes LIVE discovery; re-slicing "
                "an existing --from-dump snapshot is not supported. "
                "Export the scoped snapshot directly from the live "
                "organization."
            )
        if config.drift_baseline is not None:
            arg_parser.error(
                "--only cannot be combined with --drift-baseline: a "
                "scoped discovery diffed against a full baseline would "
                "register every out-of-scope network as removed. Keep "
                "the drift chain full-organization."
            )
        try:
            parse_network_selectors(config.only)
        except ScopeFilterError as exc:
            arg_parser.error(str(exc))
    if scoped_pipeline:
        if config.confirm_deletions:
            # A scoped run cannot tell "deleted in Meraki" from "outside
            # the scope" — discovery never looked at the rest of the
            # organization. Confirming deletions from that blindfolded
            # view could remove every out-of-scope resource from the DR
            # kit and state, so the combination is refused outright
            # (scoped runs additionally skip deletion review entirely;
            # deliberate conservatism over silent wrongness).
            arg_parser.error(
                "--confirm-deletions cannot be combined with --only: a "
                "scoped run cannot distinguish deleted objects from "
                "out-of-scope ones. Review and confirm deletions on a "
                "full-organization run."
            )
        if config.rebaseline:
            arg_parser.error(
                "--rebaseline cannot be combined with --only: resetting "
                "the accumulated baseline from a scoped discovery would "
                "discard every out-of-scope resource's configuration."
            )
        if len(config.org_ids) > 1:
            arg_parser.error(
                "--only cannot be combined with multiple --org-id "
                "values; scope one organization per invocation."
            )


def _validate_discovery_checkpoint(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--discovery-checkpoint journals ONE live sweep, nothing else."""
    if config.discovery_checkpoint is None:
        return
    if _flags_set(config, DR_ACTION_FLAGS, ("dump_path",)):
        arg_parser.error(
            "--discovery-checkpoint journals the live discovery "
            "sweep; it is only valid on --dump-to exports and "
            "live pipeline runs."
        )
    if len(config.org_ids) > 1:
        arg_parser.error(
            "--discovery-checkpoint cannot be combined with "
            "multiple --org-id values: the journal records exactly "
            "one organization's sweep."
        )


def _validate_wipe_org(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--wipe-org: standalone teardown, name as the second factor."""
    if not config.wipe_org_name:
        arg_parser.error(
            "--wipe-org requires --wipe-org-name: the organization's "
            "exact name is the second factor for the teardown."
        )
    if _flags_set(
        config,
        ("rebuild", "replay_gaps", "restore", "heal"),
        PIPELINE_FLAGS, EXPORT_FLAGS, ("dump_path",),
    ):
        arg_parser.error(
            "--wipe-org is a standalone drill-teardown action; do not "
            "combine it with any other mode."
        )
    if config.org_ids:
        # A differing --org-id would be silently ignored while the
        # operator believes it scoped the wipe (no-silent-orphans);
        # a matching one marks a production-shaped target.
        arg_parser.error(
            "--org-id cannot be combined with --wipe-org: the wipe "
            "targets exactly the organization named by --wipe-org."
        )


def _validate_heal(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--heal: one org, its own snapshot, no pipeline or export."""
    if config.dump_path is None:
        arg_parser.error(
            "--heal recreates missing objects from an offline "
            "snapshot; pass the unsanitized export via --from-dump."
        )
    if len(config.org_ids) != 1:
        arg_parser.error(
            "--heal requires exactly one --org-id: the organization "
            "to heal, which must be the snapshot's own source "
            "organization."
        )
    if config.restore or config.rebuild or config.replay_gaps:
        arg_parser.error(
            "--heal is a standalone DR action; do not combine it "
            "with --restore, --rebuild, or --replay-gaps."
        )
    if _flags_set(config, PIPELINE_FLAGS, EXPORT_FLAGS):
        arg_parser.error(
            "--heal cannot be combined with pipeline or export flags."
        )


def _validate_restore(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--restore: snapshot in, --target-org out, never the source org."""
    if config.dump_path is None:
        arg_parser.error(
            "--restore rebuilds from an offline snapshot; pass the "
            "unsanitized export via --from-dump."
        )
    if not config.target_org:
        arg_parser.error(
            "--restore requires --target-org: the (fresh or scratch) "
            "organization to rebuild into. It never writes to the "
            "snapshot's source organization."
        )
    if config.rebuild or config.replay_gaps:
        arg_parser.error(
            "--restore is a standalone DR action; do not combine it "
            "with --rebuild or --replay-gaps."
        )
    if config.org_ids:
        # The never-write-to-source interlock compares --target-org
        # against the snapshot's *recorded* source organization; an
        # --org-id override would replace that recorded value and
        # let a restore target the very org the snapshot came from.
        arg_parser.error(
            "--org-id cannot be combined with --restore: the source "
            "organization is read from the snapshot itself (the "
            "never-restore-into-the-source-org check depends on it)."
        )
    if _flags_set(config, PIPELINE_FLAGS, EXPORT_FLAGS):
        arg_parser.error(
            "--restore cannot be combined with pipeline or export flags."
        )


def _validate_replay_gaps(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--replay-gaps: replays a snapshot's gaps, no pipeline flags."""
    if config.dump_path is None:
        arg_parser.error(
            "--replay-gaps replays from an offline snapshot; pass the "
            "unsanitized export via --from-dump."
        )
    # --dump-to/--sanitize are refused just below with their own
    # message, which is why EXPORT_FLAGS is not used wholesale here.
    if config.dump_to is not None or config.sanitize:
        arg_parser.error(
            "--replay-gaps cannot be combined with --dump-to or "
            "--sanitize."
        )
    if _flags_set(config, PIPELINE_FLAGS, ("drift_baseline",)):
        arg_parser.error(
            "--replay-gaps cannot be combined with the pipeline flags "
            "--sync, --confirm-deletions, --fail-on-gaps, "
            "--rebaseline, or --drift-baseline."
        )


def _validate_rebuild(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """--rebuild: applies the workdir's existing kit, nothing else."""
    # --dump-to is refused here (with --from-dump, under the workdir
    # message), which is why EXPORT_FLAGS is not used wholesale below.
    if config.dump_path is not None or config.dump_to is not None:
        arg_parser.error(
            "--rebuild operates on an existing --workdir; it cannot be "
            "combined with --from-dump or --dump-to."
        )
    if config.org_ids:
        # Orphaned mode-scoped flags are refused, never silently
        # ignored: the rebuild applies whatever kit the workdir
        # holds — it is not scoped or verified against an
        # organization ID, and accepting one would let the operator
        # believe it was.
        arg_parser.error(
            "--rebuild does not take --org-id: the apply targets "
            "whatever organization the workdir's kit and state "
            "resolve to."
        )
    if _flags_set(config, PIPELINE_FLAGS, ("sanitize", "drift_baseline")):
        arg_parser.error(
            "--rebuild cannot be combined with the pipeline flags "
            "--sync, --confirm-deletions, --fail-on-gaps, "
            "--rebaseline, --sanitize, or --drift-baseline."
        )


def _validate_pipeline_run(
    arg_parser: argparse.ArgumentParser, config: RuntimeConfig
) -> None:
    """The default/--sync pipeline: export, key, and fan-out rules."""
    if config.dump_to is not None and (
        config.sync or config.confirm_deletions or config.rebaseline
    ):
        # --rebaseline resets the resources.tf baseline, which the
        # export path never touches; accepting it silently would let an
        # operator believe the baseline was reset when it was not.
        # (--fail-on-gaps is accepted: export runs write the coverage
        # manifest too, and the snapshot-only weekly job needs the gate.)
        arg_parser.error(
            "--dump-to only exports a snapshot; it cannot be combined with "
            "--sync, --confirm-deletions, or --rebaseline."
        )
    if config.mode is ExecutionMode.LIVE and not config.org_ids:
        arg_parser.error(
            "--org-id is required in live mode. New here? --list-orgs "
            "prints the organizations your API key can see, and --check "
            "validates a full flag set before anything runs."
        )
    if config.sanitize and config.dump_to is None:
        arg_parser.error("--sanitize requires --dump-to.")
    if config.sanitize and config.drift_baseline is not None:
        # A sanitized export cannot serve as the next run's baseline
        # (snapshot_diff refuses pseudonymized identifiers), so the
        # combination structurally breaks from the second run onward.
        arg_parser.error(
            "--sanitize cannot be combined with --drift-baseline: drift "
            "baselines must be unsanitized snapshots, and the sanitized "
            "export written by this run would be refused as the baseline "
            "of the next one. Export the unsanitized snapshot for the "
            "drift chain and sanitize a separate copy for sharing."
        )
    if len(config.org_ids) <= 1:
        return
    # Multi-organization fan-out covers the pipeline modes only
    # (default read-only and --sync). Snapshot modes are inherently
    # single-organization (one snapshot file per org), and shared
    # state targets would silently interleave organizations.
    if config.mode is ExecutionMode.DUMP:
        arg_parser.error(
            "--from-dump holds a single organization's snapshot; "
            "run one invocation per snapshot instead of repeating "
            "--org-id."
        )
    if config.dump_to is not None or config.drift_baseline is not None:
        arg_parser.error(
            "snapshot export/diff (--dump-to / --drift-baseline) is "
            "single-organization; run one invocation per "
            "organization, each with its own snapshot paths."
        )
    if config.state_file is not None:
        arg_parser.error(
            "--state-file cannot be combined with multiple --org-id "
            "values; each organization keeps its own state under "
            "<workdir>/<org-id>/."
        )
    for org in config.org_ids:
        if "/" in org or "\\" in org or ".." in org:
            arg_parser.error(
                f"--org-id {org!r} is not usable in a multi-org run: "
                "organization IDs become workdir path segments."
            )
    if config.backend.is_remote:
        if config.backend.config_file is not None:
            arg_parser.error(
                "--backend-config-file cannot be combined with "
                "multiple --org-id values; pass repeated "
                "--backend-config settings with an {org-id} "
                "placeholder in the state address instead."
            )
        if not any(
            ORG_ID_PLACEHOLDER in value
            for _, value in config.backend.settings
        ):
            arg_parser.error(
                "a remote --state-backend with multiple --org-id "
                "values requires an {org-id} placeholder in the "
                "state address (the azurerm/s3 'key' or gcs "
                "'prefix' setting), so each organization gets its "
                "own state object."
            )


def main(argv: Sequence[str] | None = None) -> int:
    """Validate the flag combination, then dispatch to one mode.

    Flag validation is the bulk of the work and it is safety-critical:
    an accepted-but-ignored flag is how an operator comes to believe a
    scope, a second factor, or a baseline reset applied when it did
    not. Each mode's rules live in its own ``_validate_*`` helper above,
    and the recurring flag sets are the named groups they share
    (``DR_ACTION_FLAGS`` and friends) rather than hand-written ``or``
    chains that can silently disagree. Order matters: the standalone
    helpers answer and exit before any mode rule runs.
    """
    arg_parser = build_parser()
    args = arg_parser.parse_args(argv)
    _apply_config_file(
        arg_parser, args, sys.argv[1:] if argv is None else list(argv)
    )
    try:
        config = RuntimeConfig.from_args(args)
    except BackendConfigError as exc:
        arg_parser.error(str(exc))
    configure_logging(verbose=config.verbose, log_format=config.log_format)

    # Standalone read-only helpers: each answers one question and exits.
    if config.list_orgs:
        _validate_list_orgs(arg_parser, config)
        return _list_orgs()
    _validate_diff_networks(arg_parser, config)
    if config.diff_networks is not None:
        return _diff_networks_run(config)

    if config.backend.is_remote and config.state_file is not None:
        arg_parser.error(
            "--state-file names a local state path and cannot be combined with "
            f"a remote --state-backend ({config.backend.backend.value}); the "
            "remote backend's state location comes from --backend-config "
            "(the azurerm/s3 'key' or gcs 'prefix' setting)."
        )

    _validate_check_estimate(arg_parser, config)
    if config.check:
        return preflight.run_check_command(config, build_dispatcher)
    if config.estimate:
        return preflight.run_estimate_command(config)

    _validate_dr_companions(arg_parser, config)
    _validate_only(arg_parser, config)
    _validate_discovery_checkpoint(arg_parser, config)
    if config.wipe_org_name and not config.wipe_org:
        # Checked here rather than beside the other orphaned-companion
        # refusals so its precedence against them is unchanged.
        arg_parser.error(
            "--wipe-org-name is only valid together with --wipe-org."
        )

    # The disaster-recovery actions, each standalone and ending the run.
    if config.wipe_org:
        _validate_wipe_org(arg_parser, config)
        logger.info(
            "meraki2tf starting in drill-wipe (disaster recovery) mode."
        )
        return _wipe_org(config)
    if config.heal:
        _validate_heal(arg_parser, config)
        logger.info("meraki2tf starting in heal (partial recovery) mode.")
        return _heal(config)
    if config.restore:
        _validate_restore(arg_parser, config)
        logger.info(
            "meraki2tf starting in restore (disaster recovery) mode."
        )
        return _restore(config)
    if config.rebuild and config.replay_gaps:
        arg_parser.error(
            "--rebuild and --replay-gaps are separate DR steps; run "
            "--rebuild --confirm first, then --replay-gaps."
        )
    if config.replay_gaps:
        _validate_replay_gaps(arg_parser, config)
        logger.info(
            "meraki2tf starting in gap replay (disaster recovery) mode."
        )
        return _replay_gaps(config)
    if config.rebuild:
        _validate_rebuild(arg_parser, config)
        logger.info("meraki2tf starting in rebuild (disaster recovery) mode.")
        return _rebuild(config)

    # The default (and --sync) pipeline: the only non-standalone mode.
    _validate_pipeline_run(arg_parser, config)
    # The dispatcher only needs config, so it exists before anything
    # that can fail: every fatal path below — spec resolution, provider
    # or runner construction included — gets at least one
    # PROCESSING_FAULT attempt before the nonzero exit.
    dispatcher = build_dispatcher(config)

    if config.sync and not api_key_present():
        # Sync exists to materialize state unattended; silently skipping
        # the apply would leave the weekly DR job believing it built
        # state when it did not. Fail loudly so the scheduler notices.
        message = (
            f"--sync requires {API_KEY_ENV_VAR}: state materialization "
            "runs terraform plan/apply, which must authenticate against "
            "the Meraki dashboard."
        )
        logger.critical("%s", message)
        dispatcher.dispatch(processing_fault(stage="startup", error=message))
        return 1

    if config.mode is ExecutionMode.LIVE and not api_key_present():
        # Fail fast with a purposeful message before any work starts:
        # every live path (discovery, snapshot export) must
        # authenticate, and a scheduled job with a lost key needs the
        # fault on its alert channels, not a late generic stack trace.
        message = (
            f"A live run requires the {API_KEY_ENV_VAR} environment "
            "variable. Export the dashboard API key first (--list-orgs "
            "then shows the organization IDs it can see), or run "
            "offline against a snapshot with --from-dump."
        )
        logger.critical("%s", message)
        dispatcher.dispatch(processing_fault(stage="startup", error=message))
        return 1

    if len(config.org_ids) > 1:
        return _run_multi_org(config, dispatcher)
    pipeline_exit = _run_org_pipeline(config, dispatcher)
    # Exit-code priority (see the module docstring): the pipeline codes
    # (1/2 over 4 over 3) outrank a silent notifier outage (5). The
    # outage helper runs unconditionally so the outage is always LOGGED
    # even when another code wins the exit.
    return pipeline_exit or _alert_outage_exit(dispatcher)


#: Substituted with the organization ID in remote-backend state
#: addresses during multi-org fan-out (azurerm/s3 ``key``, gcs
#: ``prefix``), so every organization gets its own state object.
ORG_ID_PLACEHOLDER = "{org-id}"

#: Exit codes ordered most severe first, per the module docstring:
#: nothing usable (1/2) over a stalled materialization (4) over known
#: coverage gaps (3) over a notifier outage (5).
_EXIT_SEVERITY = (1, 2, 4, 3, 5)


def _aggregate_exit(codes: Sequence[int]) -> int:
    """The most severe exit code across a multi-organization run."""
    for code in _EXIT_SEVERITY:
        if code in codes:
            return code
    return 0


def _single_org_config(config: RuntimeConfig, org_id: str) -> RuntimeConfig:
    """The per-organization view of a multi-org invocation.

    Each organization gets its own sub-workdir (and therefore its own
    local state/artifacts); remote-backend state addresses have the
    ``{org-id}`` placeholder substituted so state objects never
    collide.
    """
    backend = config.backend
    if backend.is_remote:
        backend = dataclasses.replace(
            backend,
            settings=tuple(
                (key, value.replace(ORG_ID_PLACEHOLDER, org_id))
                for key, value in backend.settings
            ),
        )
    return dataclasses.replace(
        config,
        org_ids=(org_id,),
        workdir=config.workdir / org_id,
        backend=backend,
    )


def _run_multi_org(config: RuntimeConfig, dispatcher: AlertDispatcher) -> int:
    """Sequential fan-out over every configured organization.

    A failing organization never stops the remaining ones — for a DR
    tool, capturing N-1 organizations beats capturing zero — and the
    final exit code is the most severe per-org outcome, so schedulers
    still notice the failure.
    """
    total = len(config.org_ids)
    codes: list[int] = []
    for index, org_id in enumerate(config.org_ids, start=1):
        logger.info(
            "=== organization %s (%d of %d) ===", org_id, index, total
        )
        codes.append(
            _run_org_pipeline(
                _single_org_config(config, org_id),
                dispatcher,
                print_epilogue=False,
            )
        )
    outage_exit = _alert_outage_exit(dispatcher)
    logger.info(
        "Multi-organization run complete: %s.",
        "; ".join(
            f"{org_id}: exit {code}"
            for org_id, code in zip(config.org_ids, codes, strict=True)
        ),
    )
    if not config.sync:
        print(
            f"\nPer-organization DR kits written under {config.workdir}: "
            + ", ".join(config.org_ids)
            + " (one sub-directory each)."
        )
        print(
            f"Next steps per org: cd {config.workdir}/<org-id> && "
            "terraform init && terraform plan"
        )
    return _aggregate_exit(codes) or outage_exit


def _run_org_pipeline(
    config: RuntimeConfig,
    dispatcher: AlertDispatcher,
    print_epilogue: bool = True,
) -> int:
    """One organization's pipeline: spec → provider → orchestrate → report.

    Returns the run's exit code EXCLUDING the notifier-outage code (5),
    which is dispatcher-wide and applied once by the caller.
    """
    logger.info("meraki2tf starting in %s mode.", config.mode.value)
    # Attribute even startup faults to the organization when the flag
    # names it; dump-mode runs refine this once the snapshot resolves.
    dispatcher.organization_id = config.org_id
    # Cheap validations FIRST (adversarial-review fix): a typo'd
    # --drift-baseline or a missing/old terraform binary must fail in
    # seconds, not hours into the discovery sweep. Both refusals stay
    # enforced at their point of use too (snapshot_diff.baseline_drift,
    # the terraform runner) — this only moves the failure earlier.
    if config.drift_baseline is not None:
        try:
            preflight.validate_drift_baseline(
                config.drift_baseline, config.org_id
            )
        except ValueError as exc:
            # MalformedDumpError and the sanitized/partial/org-mismatch
            # refusals; the scheduled job needs this on its alert
            # channels, exactly like the same failure mid-run.
            logger.critical("%s", exc)
            dispatcher.dispatch(
                processing_fault(
                    stage="drift-baseline validation", error=str(exc)
                )
            )
            return 1
    try:
        spec_file = resolve_spec(config.spec_path)
        spec_parser = OpenApiParser(spec_file)
        try:
            provider = build_provider(config, spec_parser, spec_file)
        except OrganizationMismatchError as exc:
            # Operator input error, like the --heal and --drift-baseline
            # organization refusals: loud, actionable, no alert.
            logger.critical("%s", exc)
            return 2
        if config.only and config.dump_to is None:
            logger.warning(
                "PARTIAL run: --only scopes discovery, the kit, and the "
                "plan to the matching network(s); artifacts are stamped "
                "partial, out-of-scope state is untouched, and deletion "
                "review is skipped (run full-organization to review "
                "deletions)."
            )
        if config.dump_to is not None:
            # The weekly DR job is exactly this invocation; a
            # mid-discovery failure must reach the notification
            # channels, not just the local log (the contract's
            # "critical script processing faults" trigger).
            try:
                return _export_snapshot(
                    provider, config, spec_parser, dispatcher,
                    spec_file=spec_file,
                )
            except (ScopeFilterError, CheckpointMismatchError) as exc:
                # Operator input error (a --only selector matched no
                # network, or a stale/foreign discovery checkpoint),
                # not a processing fault: fail loudly and actionably,
                # no alert — mirroring the HealFilterError handling in
                # _heal.
                logger.critical("%s", exc)
                return 2
            except Exception as exc:
                logger.critical("Snapshot export failed: %s", exc)
                dispatcher.dispatch(
                    processing_fault(
                        stage="snapshot export (--dump-to)", error=str(exc)
                    )
                )
                return 1
        partial_scope = (
            provider.snapshot_scope
            if isinstance(provider, StaticJsonDataProvider)
            else None
        )
        if partial_scope is not None:
            if config.sync or config.confirm_deletions:
                # A partial snapshot fed to state materialization or
                # deletion confirmation would present every
                # out-of-scope resource as deleted — poisoning the DR
                # kit and state with mass phantom removals.
                logger.critical(
                    "The --from-dump snapshot is a PARTIAL export "
                    "(--only, %d network(s)); --sync and "
                    "--confirm-deletions require a full-organization "
                    "snapshot.",
                    len(partial_scope.network_ids),
                )
                return 2
            logger.warning(
                "The --from-dump snapshot is a PARTIAL export (--only, "
                "%d network(s)): the kit and coverage manifest describe "
                "only that scope, not the organization.",
                len(partial_scope.network_ids),
            )
        if api_key_present():
            # This run will plan (and in sync mode apply) through
            # terraform; probe the binary and version now — after every
            # pure-input refusal above (partial-snapshot gating, scope
            # selectors, checkpoint binding), but still before the
            # discovery sweep. Input mistakes must never be masked by
            # an environment fault. Keyless air-gapped runs never
            # invoke terraform, so they deliberately skip the probe.
            try:
                ensure_supported_terraform(config.terraform_bin)
            except TerraformError as exc:
                logger.critical("%s", exc)
                dispatcher.dispatch(
                    processing_fault(
                        stage="terraform preflight", error=str(exc)
                    )
                )
                return 1
        runner = TerraformRunner(
            config.workdir,
            executable=config.terraform_bin,
            state_path=config.state_file,
            backend=config.backend,
        )
        orchestrator = PipelineOrchestrator(
            provider=provider,
            generator=HclImportGenerator(
                spec_parser,
                dispatcher,
                # Resolved lazily at generation time: keyed runs read
                # the installed provider's identity schemas (init +
                # schema dump, then cached in the workdir); keyless
                # runs fall back to that cache or the bundled catalog.
                catalog_provider=lambda: resolve_catalog(
                    runner, keyed=api_key_present()
                ),
            ),
            runner=runner,
            dispatcher=dispatcher,
            rebaseline=config.rebaseline,
            sync=config.sync,
            confirm_deletions=config.confirm_deletions,
            drift_baseline=config.drift_baseline,
        )
        summary = orchestrator.run(config.org_id)
    except CheckpointMismatchError as exc:
        # Operator input error (a stale or foreign discovery
        # checkpoint), surfaced by the eager header check at provider
        # build time: fail loudly and actionably, no fault alert —
        # mirroring the export path's handling.
        logger.critical("%s", exc)
        return 2
    except PreflightRefusalError as exc:
        # An expected refusal (preconditions unmet); nothing ran and no
        # fault alert belongs to it — same clean-refusal exit the other
        # guarded actions use.
        logger.critical("%s", exc)
        return 2
    except PipelineError as exc:
        # The orchestrator already dispatched PROCESSING_FAULT for this
        # failure; a second alert here would double-report it.
        logger.critical("%s", exc)
        return 1
    except Exception as exc:
        logger.critical("meraki2tf could not start: %s", exc)
        dispatcher.dispatch(processing_fault(stage="startup", error=str(exc)))
        return 1

    _report(summary)
    if print_epilogue and not config.sync:
        # Interactive next-step pointer for the ad-hoc/open-source mode;
        # scheduled --sync runs read the log summary and alerts instead.
        print(
            f"\nDR kit written to {config.workdir}: imports.tf, "
            "resources.tf, provider.tf, coverage.txt, runbook.md."
        )
        print(
            f"Next steps: cd {config.workdir} && terraform init && "
            "terraform plan"
        )
    if summary.apply_aborted:
        # A sync run whose full-kit apply was refused (the plan carried
        # mutations) must not report success — a scheduler gating on the
        # exit code would otherwise believe the whole kit materialized
        # while it is stalled on a human. The drift alert already fired;
        # this makes the stall visible to automation even if every
        # notifier channel is down.
        if summary.resources_added_to_state:
            growth = (
                f"; {len(summary.resources_added_to_state)} import-only "
                "resource(s) were still applied through targeted chunks"
            )
        else:
            growth = "; no state was materialized this run"
        logger.error(
            "--sync full-kit auto-apply was ABORTED: mutations blocked "
            "the full apply%s. A human must review the DRIFT_DETECTED "
            "alert before the remaining state can grow (exit code 4).",
            growth,
        )
        return 4
    if config.fail_on_gaps:
        gap_exit = _coverage_gap_exit(summary.unsupported_count)
        if gap_exit:
            return gap_exit
    return 0


def _coverage_gap_exit(unsupported_count: int) -> int:
    """0, or 3 when the run discovered objects Terraform cannot rebuild.

    One definition of the --fail-on-gaps gate for both the pipeline and
    the snapshot-export paths — the Azure wrapper treats exit 3 as a
    completed, fresh-artifact run, so the two paths must never diverge.
    """
    if unsupported_count > 0:
        logger.error(
            "--fail-on-gaps: %d discovered object(s) cannot be rebuilt by "
            "Terraform; exiting with code 3. See coverage.json in the "
            "workdir for the manual-rebuild list.",
            unsupported_count,
        )
        return 3
    return 0


def _alert_outage_exit(dispatcher: AlertDispatcher) -> int:
    """0, or 5 when any event suffered total delivery failure.

    The lowest-priority nonzero code: the run's work product is intact,
    but at least one mandated alert reached no configured channel —
    without a nonzero exit a scheduler would believe the operator was
    notified when nobody was.
    """
    if dispatcher.failed_event_count:
        logger.error(
            "%d alert event(s) could not be delivered on any configured "
            "channel this run; exiting 5 so schedulers notice the "
            "notifier outage.",
            dispatcher.failed_event_count,
        )
        return 5
    return 0


def _report(summary: RunSummary) -> None:
    if summary.comparison_skipped:
        drift_status = f"comparison skipped ({API_KEY_ENV_VAR} not set)"
    elif summary.drift_detected:
        drift_status = "DETECTED"
    else:
        drift_status = "not detected"
    if summary.apply_aborted:
        drift_status += " (sync auto-apply ABORTED for human review)"
    if summary.pending_imports is not None:
        pending_status = (
            f"{summary.pending_imports} import(s) pending state aggregation"
        )
    else:
        pending_status = "pending imports unknown"
    logger.info(
        "Run complete for organization %s: %d/%d asset(s) captured as "
        "Terraform (%d new import(s), %d already in state), %d unsupported "
        "asset(s) needing manual DR rebuild, %.2f%% coverage, %s, drift %s.",
        summary.organization_id,
        summary.imports_written + summary.imports_skipped_existing,
        summary.discovered_assets,
        summary.imports_written,
        summary.imports_skipped_existing,
        summary.unsupported_count,
        summary.coverage_percent,
        pending_status,
        drift_status,
    )
    if (
        summary.reconciliation_dropped
        or summary.unmanaged_secret_attributes
        or summary.normalized_addresses
    ):
        logger.info(
            "Plan reconciliation: %d resource(s) dropped as unexpressible, "
            "%d resource(s) with unmanaged secret attribute(s), "
            "%d resource(s) with values normalized for provider "
            "round-trip.",
            len(summary.reconciliation_dropped),
            len(summary.unmanaged_secret_attributes),
            len(summary.normalized_addresses),
        )
    if summary.reconciliation_drop_categories:
        logger.info(
            "Unexpressible drop categories: %s",
            "; ".join(
                f"{count} × {title}"
                for title, count in
                summary.reconciliation_drop_categories.items()
            ),
        )
    if summary.unmanaged_secret_attributes:
        logger.warning(
            "Secrets not captured in the DR kit (restore manually after a "
            "rebuild): %s",
            cap_log_enumeration(
                [
                    f"{address}: {', '.join(attrs)}"
                    for address, attrs in
                    summary.unmanaged_secret_attributes.items()
                ]
            ),
        )
    if summary.resources_added_to_state:
        logger.info(
            "State grew by %d resource(s): %s",
            len(summary.resources_added_to_state),
            ", ".join(summary.resources_added_to_state),
        )
    if summary.regenerated_addresses:
        logger.info(
            "HCL baseline regenerated to mirror Meraki for: %s",
            ", ".join(summary.regenerated_addresses),
        )
    if summary.snapshot_drift:
        logger.warning(
            "Snapshot drift vs baseline: %s (see DRIFT_DETECTED alert).",
            summary.snapshot_drift,
        )
    if summary.deferred_addresses:
        logger.warning(
            "Drift-racy pending import(s) deferred to the next run so the "
            "rest of the kit could apply: %s",
            ", ".join(summary.deferred_addresses),
        )
    if summary.deletions_removed:
        logger.info(
            "Confirmed deletion(s) removed from the DR kit: %s",
            ", ".join(summary.deletions_removed),
        )
    if summary.deletions_pending:
        logger.warning(
            "%d deletion(s) in Meraki await human confirmation "
            "(re-run with --confirm-deletions after review): %s",
            len(summary.deletions_pending),
            ", ".join(summary.deletions_pending),
        )


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    sys.exit(main())
