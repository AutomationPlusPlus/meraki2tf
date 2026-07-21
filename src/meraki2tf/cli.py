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
    read_api_key,
)
from meraki2tf.coverage import build_manifest, unsupported_payload, write_manifest
from meraki2tf.hcl_generator import HclImportGenerator
from meraki2tf.logging_setup import configure_logging
from meraki2tf.models import NetworkGraph
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.orchestrator import (
    PipelineError,
    PipelineOrchestrator,
    PreflightRefusalError,
    RunSummary,
)
from meraki2tf.provider_catalog import (
    CATALOG_CACHE_FILENAME,
    CatalogError,
    ProviderCatalog,
    resolve_catalog,
)
from meraki2tf.replayer import (
    GapReplayer,
    plan_replay,
    template_bound_networks,
)
from meraki2tf.providers import (
    LiveApiDataProvider,
    MerakiDataProvider,
    StaticJsonDataProvider,
)
from meraki2tf.sanitizer import load_or_create_salt, sanitize_graph
from meraki2tf.snapshot import write_snapshot
from meraki2tf.spec_resolver import resolve_spec
from meraki2tf.terraform_runner import (
    PROVIDER_FILENAME,
    TerraformError,
    TerraformRunner,
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
        choices=["text", "json"],
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
            raise SystemExit(f"Invalid --webhook-url / {WEBHOOK_URL_ENV_VAR}: {exc}")
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
            raise SystemExit(str(exc))
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


def build_provider(config: RuntimeConfig, parser: OpenApiParser) -> MerakiDataProvider:
    if config.dump_path is not None:
        return StaticJsonDataProvider(config.dump_path, parser=parser)
    return LiveApiDataProvider(parser=parser)


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
    manifest = build_manifest(
        organization_id=graph.organization_id,
        captured=report.captured,
        unsupported=report.unsupported,
        # Export runs never read Terraform state; every capturable
        # asset is honestly "in the kit, not known to be in state".
        state_addresses=frozenset(),
        unmanaged_secret_attributes=unmanaged_secrets,
        restore_via=restore_verdicts(plan_restore(graph, parser)),
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
        )
    )
    return manifest


def _export_snapshot(
    provider: MerakiDataProvider,
    config: RuntimeConfig,
    parser: OpenApiParser,
    dispatcher: AlertDispatcher,
) -> int:
    """Discover the graph and write it as an offline snapshot (--dump-to)."""
    assert config.dump_to is not None  # guarded by the caller
    with provider as source:
        graph = source.fetch_network_graph(config.org_id)
    dispatcher.organization_id = graph.organization_id
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
    write_snapshot(graph, config.dump_to, sanitized=config.sanitize)
    manifest = _export_coverage(
        raw_graph, config, parser, dispatcher, drift_was_detected
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
        spec_parser = OpenApiParser(resolve_spec(config.spec_path))
        provider = StaticJsonDataProvider(config.dump_path, parser=spec_parser)
        with provider as source:
            # No org-ID override (the CLI refuses --org-id here): the
            # graph's organization ID is the snapshot's recorded source
            # org, which the target guard below depends on.
            graph = source.fetch_network_graph(None)
    except Exception as exc:
        logger.critical("Restore could not load the snapshot: %s", exc)
        return 1
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
        except Exception as exc:  # noqa: BLE001 - fail closed
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


def _target_network_count(target_org: str) -> int:
    """How many networks the restore target organization holds now."""
    import meraki

    from meraki2tf.config import read_api_key

    dashboard = meraki.DashboardAPI(
        api_key=read_api_key(),
        suppress_logging=True,
        print_console=False,
        output_log=False,
    )
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
    from meraki2tf.healer import plan_heal
    from meraki2tf.restorer import (
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
        spec_parser = OpenApiParser(resolve_spec(config.spec_path))
        provider = StaticJsonDataProvider(config.dump_path, parser=spec_parser)
        with provider as source:
            snapshot = source.fetch_network_graph(None)
    except Exception as exc:
        logger.critical("Heal could not load the snapshot: %s", exc)
        return 1
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
    try:
        with LiveApiDataProvider(parser=spec_parser) as live_source:
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
    for item in plan.missing.unrestorable:
        logger.warning(
            "Cannot heal %s (ids=%s): %s",
            item.api_path, ",".join(item.path_values) or "<none>",
            item.reason,
        )
    if not plan.missing.actions:
        logger.info(
            "Nothing to heal: every restorable snapshot asset is still "
            "present in the live organization."
        )
        return 0
    logger.info(
        "Missing objects to recreate:\n%s",
        render_restore_plan(plan.missing),
    )
    if not config.confirm:
        logger.warning(
            "Preview only — nothing was written to Meraki. Re-run with "
            "'--heal --confirm' to recreate the %d missing object(s) in "
            "organization %s.", len(plan.missing.actions), config.org_id,
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
        "%d surviving object(s) untouched (journal: %s).",
        config.org_id, len(result.executed), len(result.failed),
        len(result.skipped), plan.surviving_count,
        config.workdir / "heal-journal.jsonl",
    )
    dispatcher.dispatch(
        heal_executed(
            organization_id=config.org_id,
            surviving=plan.surviving_count,
            executed=result.executed,
            failed=result.failed,
            skipped=result.skipped,
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
        spec_parser = OpenApiParser(resolve_spec(config.spec_path))
        provider = StaticJsonDataProvider(config.dump_path, parser=spec_parser)
        with provider as source:
            graph = source.fetch_network_graph(config.org_id)
    except Exception as exc:
        logger.critical("Gap replay could not load the snapshot: %s", exc)
        return 1
    if provider.snapshot_sanitized:
        logger.warning(
            "This snapshot is SANITIZED: secret values are redaction "
            "markers and identifiers are pseudonyms. Gap replay against "
            "a live tenant needs the unsanitized DR snapshot; redacted "
            "attributes will be skipped and reported for manual "
            "re-entry."
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
    executed, failed, refused = replayer.execute(
        actions, target_org, snapshot_org, network_ids,
        template_bound=template_bound_networks(graph),
    )
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
    import meraki

    try:
        client = meraki.DashboardAPI(
            api_key=read_api_key(),
            suppress_logging=True,
            print_console=False,
            output_log=False,
            wait_on_rate_limit=True,
        )
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
    rows = sorted(
        (
            (str(org.get("id", "")), str(org.get("name", "")))
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
        getattr(args, dest, False)
        for dest in ("rebuild", "replay_gaps", "restore", "heal", "wipe_org")
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


def main(argv: Sequence[str] | None = None) -> int:
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

    if config.list_orgs:
        # Orphaned companions are refused, never silently ignored (the
        # house rule): the helper answers one question and exits, so any
        # mode or target flag alongside it marks a misunderstanding.
        if (
            config.org_ids or config.dump_path or config.dump_to
            or config.drift_baseline or config.sanitize
            or config.rebuild or config.heal or config.replay_gaps
            or config.restore or config.wipe_org or config.wipe_org_name
            or config.confirm or config.target_org or config.serial_map
            or config.skip_claims or config.sync or config.rebaseline
            or config.confirm_deletions or config.fail_on_gaps
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
        return _list_orgs()

    if config.backend.is_remote and config.state_file is not None:
        arg_parser.error(
            "--state-file names a local state path and cannot be combined with "
            f"a remote --state-backend ({config.backend.backend.value}); the "
            "remote backend's state location comes from --backend-config "
            "(the azurerm/s3 'key' or gcs 'prefix' setting)."
        )

    if config.confirm and not (
        config.rebuild or config.replay_gaps or config.restore
        or config.heal or config.wipe_org
    ):
        arg_parser.error(
            "--confirm is only valid together with --rebuild, --replay-gaps, "
            "--restore, --heal, or --wipe-org."
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
    if config.wipe_org_name and not config.wipe_org:
        arg_parser.error(
            "--wipe-org-name is only valid together with --wipe-org."
        )
    if config.wipe_org:
        if not config.wipe_org_name:
            arg_parser.error(
                "--wipe-org requires --wipe-org-name: the organization's "
                "exact name is the second factor for the teardown."
            )
        if (
            config.rebuild or config.replay_gaps or config.restore
            or config.heal
            or config.sync or config.confirm_deletions or config.fail_on_gaps
            or config.rebaseline or config.dump_to is not None
            or config.sanitize or config.dump_path is not None
            or config.drift_baseline is not None
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
        logger.info(
            "meraki2tf starting in drill-wipe (disaster recovery) mode."
        )
        return _wipe_org(config)
    if config.heal:
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
        if (
            config.sync
            or config.confirm_deletions
            or config.fail_on_gaps
            or config.rebaseline
            or config.dump_to is not None
            or config.sanitize
            or config.drift_baseline is not None
        ):
            arg_parser.error(
                "--heal cannot be combined with pipeline or export flags."
            )
        logger.info("meraki2tf starting in heal (partial recovery) mode.")
        return _heal(config)
    if config.restore:
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
        if (
            config.sync
            or config.confirm_deletions
            or config.fail_on_gaps
            or config.rebaseline
            or config.dump_to is not None
            or config.sanitize
            or config.drift_baseline is not None
        ):
            arg_parser.error(
                "--restore cannot be combined with pipeline or export flags."
            )
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
        if config.dump_path is None:
            arg_parser.error(
                "--replay-gaps replays from an offline snapshot; pass the "
                "unsanitized export via --from-dump."
            )
        if config.dump_to is not None or config.sanitize:
            arg_parser.error(
                "--replay-gaps cannot be combined with --dump-to or "
                "--sanitize."
            )
        if (
            config.sync
            or config.confirm_deletions
            or config.fail_on_gaps
            or config.rebaseline
            or config.drift_baseline is not None
        ):
            arg_parser.error(
                "--replay-gaps cannot be combined with the pipeline flags "
                "--sync, --confirm-deletions, --fail-on-gaps, "
                "--rebaseline, or --drift-baseline."
            )
        logger.info(
            "meraki2tf starting in gap replay (disaster recovery) mode."
        )
        return _replay_gaps(config)
    if config.rebuild:
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
        if (
            config.sync or config.confirm_deletions or config.fail_on_gaps
            or config.rebaseline or config.sanitize
            or config.drift_baseline is not None
        ):
            arg_parser.error(
                "--rebuild cannot be combined with the pipeline flags "
                "--sync, --confirm-deletions, --fail-on-gaps, "
                "--rebaseline, --sanitize, or --drift-baseline."
            )
        logger.info("meraki2tf starting in rebuild (disaster recovery) mode.")
        return _rebuild(config)
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
        arg_parser.error("--org-id is required in live mode.")
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
    if len(config.org_ids) > 1:
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
            for org_id, code in zip(config.org_ids, codes)
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
    try:
        spec_parser = OpenApiParser(resolve_spec(config.spec_path))
        provider = build_provider(config, spec_parser)
        if config.dump_to is not None:
            # The weekly DR job is exactly this invocation; a
            # mid-discovery failure must reach the notification
            # channels, not just the local log (the contract's
            # "critical script processing faults" trigger).
            try:
                return _export_snapshot(
                    provider, config, spec_parser, dispatcher
                )
            except Exception as exc:
                logger.critical("Snapshot export failed: %s", exc)
                dispatcher.dispatch(
                    processing_fault(
                        stage="snapshot export (--dump-to)", error=str(exc)
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
            "; ".join(
                f"{address}: {', '.join(attrs)}"
                for address, attrs in summary.unmanaged_secret_attributes.items()
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
