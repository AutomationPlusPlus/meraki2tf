"""Command-line entry point and pipeline assembly.

Built for both ad-hoc invocation and unattended scheduled runs (e.g. a
weekly cron job): every input arrives via flags or environment
variables, no interactive prompts, and the exit code reports outcome
(0 = clean aggregation, 1 = pipeline fault, 2 = usage error,
3 = coverage gaps with --fail-on-gaps).

Mode gating: the default invocation is the ad-hoc/open-source mode —
strictly read-only end-to-end (kit generation, speculative plan,
alerts), safe for anyone to run against any org. ``--sync`` opts into
DR automation: guarded import-only state materialization and
modified-object baseline regeneration. Meraki itself is never mutated
by either mode; only the explicit, human-invoked DR actions —
``--rebuild --confirm`` (terraform apply of the kit) and
``--replay-gaps --confirm`` (snapshot replay of what Terraform cannot
carry) — ever change the organization.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from meraki2tf.alerts import (
    AlertDispatcher,
    EmailNotifier,
    WebhookNotifier,
    gap_replay_executed,
)
from meraki2tf.config import (
    API_KEY_ENV_VAR,
    BackendConfigError,
    ExecutionMode,
    RuntimeConfig,
    StateBackend,
    api_key_present,
)
from meraki2tf.hcl_generator import HclImportGenerator
from meraki2tf.logging_setup import configure_logging
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.orchestrator import PipelineError, PipelineOrchestrator, RunSummary
from meraki2tf.provider_catalog import resolve_catalog
from meraki2tf.replayer import GapReplayer, plan_replay
from meraki2tf.providers import (
    LiveApiDataProvider,
    MerakiDataProvider,
    StaticJsonDataProvider,
)
from meraki2tf.sanitizer import sanitize_graph
from meraki2tf.snapshot import write_snapshot
from meraki2tf.spec_resolver import resolve_spec
from meraki2tf.terraform_runner import (
    PROVIDER_FILENAME,
    TerraformError,
    TerraformRunner,
)

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="meraki2tf",
        description=(
            "Extract Cisco Meraki configurations and translate them into "
            "Terraform structures with drift detection and alerting."
        ),
    )
    parser.add_argument(
        "--org-id",
        default=None,
        help=(
            "Meraki organization ID to discover. Required in live mode; "
            "dump mode falls back to the organization recorded in the snapshot."
        ),
    )
    parser.add_argument(
        "--spec",
        metavar="PATH",
        default=None,
        help=(
            "Meraki OpenAPI JSON document driving the dynamic resource registry. "
            "If the file exists it is version-checked against the latest GitHub "
            "release and refreshed when outdated; if missing (or the flag is "
            "omitted, defaulting to ./spec3.json) the latest release is "
            "downloaded from GitHub."
        ),
    )
    parser.add_argument(
        "--from-dump",
        metavar="PATH",
        default=None,
        help="Run offline against a local JSON snapshot instead of the live cloud API.",
    )
    parser.add_argument(
        "--dump-to",
        metavar="PATH",
        default=None,
        help=(
            "Write the discovered configuration to PATH as an offline snapshot "
            "(the --from-dump format) instead of running the Terraform pipeline. "
            "Combine with --org-id for a live export, or with --from-dump to "
            "normalize an existing nested export into the canonical format."
        ),
    )
    parser.add_argument(
        "--sanitize",
        action="store_true",
        help=(
            "Redact secrets and pseudonymize identifying details (IDs, names, "
            "serials, MACs, URLs, …) in the snapshot written by --dump-to — for "
            "sharing in tests, demos, or bug reports. Structural IDs stay "
            "consistent so the sanitized snapshot remains fully processable."
        ),
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help=(
            "Disaster recovery: preview what 'terraform apply' would do with "
            "the artifacts already generated in --workdir. Add --confirm to "
            "actually execute the apply. This explicit action is the only way "
            "meraki2tf ever applies anything — normal pipeline runs are "
            "strictly read-only toward your Meraki organization."
        ),
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help=(
            "Escalate --rebuild or --replay-gaps from a read-only preview "
            "to a real write against the Meraki organization."
        ),
    )
    parser.add_argument(
        "--replay-gaps",
        action="store_true",
        help=(
            "Disaster recovery: preview replaying the objects Terraform "
            "cannot rebuild (and the secret attributes the kit cannot "
            "carry) from an unsanitized --from-dump snapshot back into the "
            "organization. Add --confirm to actually write. Runs after "
            "'--rebuild --confirm' has restored the Terraform-covered "
            "resources; network IDs are remapped to the rebuilt tenant "
            "by name."
        ),
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help=(
            "Opt-in disaster-recovery mode for the scheduled job: after the "
            "speculative plan, auto-apply it ONLY when it is 100%% imports "
            "(0 to add, 0 to change, 0 to destroy) to grow the Terraform "
            "state, and regenerate the HCL baseline of modified objects to "
            "mirror current Meraki. Any mutating plan aborts with a drift "
            "alert. Meraki itself is never touched. Requires "
            f"{API_KEY_ENV_VAR}."
        ),
    )
    parser.add_argument(
        "--confirm-deletions",
        action="store_true",
        help=(
            "Human confirmation to remove resources that were deleted in "
            "Meraki from the DR kit and the Terraform state. Without this "
            "flag deletions are alert-only and the kit keeps them, so an "
            "accidental clickops deletion cannot silently poison the "
            "rebuild baseline."
        ),
    )
    parser.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help=(
            "Exit with code 3 when the run discovers objects Terraform "
            "cannot rebuild (coverage gaps), so schedulers and CI can gate "
            "on full coverage."
        ),
    )
    parser.add_argument(
        "--rebaseline",
        action="store_true",
        help=(
            "Accept the currently discovered configuration as the new "
            "baseline: discard the accumulated resources.tf so this run "
            "regenerates it from live data. Use after reviewing a "
            "DRIFT_DETECTED alert. Refused while the state file tracks "
            "resources (their configuration cannot be regenerated)."
        ),
    )
    parser.add_argument(
        "--workdir",
        metavar="DIR",
        default="generated",
        help="Terraform execution workspace directory (default: %(default)s).",
    )
    parser.add_argument(
        "--state-file",
        metavar="PATH",
        default=None,
        help=(
            "Terraform state file to aggregate into. An existing state is "
            "reused so consecutive runs only import the delta; if the file "
            "does not exist it is created on the first apply "
            "(default: meraki2tf.tfstate inside --workdir)."
        ),
    )
    parser.add_argument(
        "--state-backend",
        choices=[member.value for member in StateBackend],
        default=StateBackend.LOCAL.value,
        help=(
            "Terraform state backend (default: %(default)s). 'local' keeps "
            "state on disk in --workdir/--state-file; 'azurerm' stores it in "
            "Azure Blob Storage for durable, locked, off-box state (recommended "
            "for scheduled DR). Remote backends take their settings from "
            "--backend-config / --backend-config-file."
        ),
    )
    parser.add_argument(
        "--backend-config",
        action="append",
        metavar="KEY=VALUE",
        help=(
            "Remote backend setting passed to 'terraform init -backend-config'; "
            "repeat for several. For azurerm: resource_group_name, "
            "storage_account_name, container_name, key. Credentials are refused "
            "here — terraform reads them from the environment (ARM_ACCESS_KEY, "
            "ARM_SAS_TOKEN, or a managed identity)."
        ),
    )
    parser.add_argument(
        "--backend-config-file",
        metavar="PATH",
        default=None,
        help=(
            "File of remote backend settings passed to "
            "'terraform init -backend-config=PATH' (composes with "
            "--backend-config)."
        ),
    )
    parser.add_argument(
        "--webhook-url",
        action="append",
        metavar="URL",
        help="Webhook alert endpoint; repeat the flag for multiple targets.",
    )
    parser.add_argument(
        "--alert-email",
        action="append",
        metavar="ADDR",
        help="Email alert recipient; repeat the flag for multiple recipients.",
    )
    parser.add_argument(
        "--smtp-host",
        default="localhost",
        help="SMTP relay host for email alerts (default: %(default)s).",
    )
    parser.add_argument(
        "--smtp-port",
        type=int,
        default=25,
        help="SMTP relay port for email alerts (default: %(default)s).",
    )
    parser.add_argument(
        "--email-from",
        default="meraki2tf@localhost",
        help="Sender address for email alerts (default: %(default)s).",
    )
    parser.add_argument(
        "--terraform-bin",
        default="terraform",
        help="Terraform executable to invoke (default: %(default)s).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging; credentials are redacted at every level.",
    )
    return parser


def build_dispatcher(config: RuntimeConfig) -> AlertDispatcher:
    """Assemble the alert fan-out from the configured destinations."""
    dispatcher = AlertDispatcher()
    for url in config.webhook_urls:
        dispatcher.register(WebhookNotifier(url))
    if config.alert_emails:
        dispatcher.register(
            EmailNotifier(
                host=config.smtp_host,
                port=config.smtp_port,
                sender=config.email_from,
                recipients=config.alert_emails,
            )
        )
    return dispatcher


def build_provider(config: RuntimeConfig, parser: OpenApiParser) -> MerakiDataProvider:
    if config.dump_path is not None:
        return StaticJsonDataProvider(config.dump_path, parser=parser)
    return LiveApiDataProvider(parser=parser)


def _export_snapshot(provider: MerakiDataProvider, config: RuntimeConfig) -> int:
    """Discover the graph and write it as an offline snapshot (--dump-to)."""
    assert config.dump_to is not None  # guarded by the caller
    with provider as source:
        graph = source.fetch_network_graph(config.org_id)
    if config.sanitize:
        graph = sanitize_graph(graph)
        logger.info("Snapshot sanitized: secrets redacted, identity pseudonymized.")
    else:
        logger.warning(
            "Snapshot is UNSANITIZED: it carries every credential Meraki "
            "returns on read (SSID PSKs, SNMP community strings, …). It is "
            "written owner-only (0600) — store it like a password file, and "
            "use --sanitize for any copy that leaves the DR vault."
        )
    write_snapshot(graph, config.dump_to)
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
    runner = TerraformRunner(
        config.workdir,
        executable=config.terraform_bin,
        state_path=config.state_file,
        backend=config.backend,
    )
    if config.state_file is not None:
        # Re-anchor the backend at the explicitly requested state file;
        # otherwise init would silently use whatever path the previous
        # pipeline run baked into provider.tf.
        runner.prepare_workspace()
    try:
        runner.init()
        preview = runner.plan_preview()
    except (TerraformError, OSError) as exc:
        logger.critical("Rebuild planning failed: %s", exc)
        return 1
    logger.info("Rebuild plan for workspace %s:\n%s", config.workdir, preview.stdout)
    if not preview.has_changes:
        logger.info(
            "Nothing to rebuild: the organization already matches the "
            "generated artifacts."
        )
        return 0
    if not config.confirm:
        logger.warning(
            "Preview only — nothing was applied. Re-run with "
            "'--rebuild --confirm' to execute terraform apply and rebuild "
            "the organization from the generated artifacts."
        )
        return 0
    try:
        runner.rebuild_apply()
    except (TerraformError, OSError) as exc:
        logger.critical("Rebuild apply failed: %s", exc)
        return 1
    logger.info(
        "Rebuild complete: the organization now matches the generated artifacts."
    )
    return 0


def _replay_gaps(config: RuntimeConfig) -> int:
    """Explicit DR action: preview or execute a snapshot gap replay.

    Together with ``_rebuild`` these are the only two places meraki2tf
    can write to Meraki, and both demand an explicit --confirm;
    --replay-gaps alone is a read-only preview of the planned writes.
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
    dispatcher = build_dispatcher(config)
    runner = TerraformRunner(
        config.workdir,
        executable=config.terraform_bin,
        state_path=config.state_file,
        backend=config.backend,
    )
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
    executed, failed = replayer.execute(
        actions, target_org, graph.organization_id, network_ids
    )
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
        "the snapshot.",
        len(executed),
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arg_parser = build_parser()
    args = arg_parser.parse_args(argv)
    try:
        config = RuntimeConfig.from_args(args)
    except BackendConfigError as exc:
        arg_parser.error(str(exc))
    configure_logging(verbose=config.verbose)

    if config.backend.is_remote and config.state_file is not None:
        arg_parser.error(
            "--state-file names a local state path and cannot be combined with "
            f"a remote --state-backend ({config.backend.backend.value}); the "
            "remote backend's state location comes from --backend-config "
            "(e.g. the azurerm 'key' setting)."
        )

    if config.confirm and not (config.rebuild or config.replay_gaps):
        arg_parser.error(
            "--confirm is only valid together with --rebuild or --replay-gaps."
        )
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
        ):
            arg_parser.error(
                "--replay-gaps cannot be combined with the pipeline flags "
                "--sync, --confirm-deletions, --fail-on-gaps, or "
                "--rebaseline."
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
        if config.sync or config.confirm_deletions or config.fail_on_gaps:
            arg_parser.error(
                "--rebuild cannot be combined with the pipeline flags "
                "--sync, --confirm-deletions, or --fail-on-gaps."
            )
        logger.info("meraki2tf starting in rebuild (disaster recovery) mode.")
        return _rebuild(config)
    if config.dump_to is not None and (
        config.sync or config.confirm_deletions or config.fail_on_gaps
    ):
        arg_parser.error(
            "--dump-to only exports a snapshot; it cannot be combined with "
            "--sync, --confirm-deletions, or --fail-on-gaps."
        )
    if config.mode is ExecutionMode.LIVE and not config.org_id:
        arg_parser.error("--org-id is required in live mode.")
    if config.sanitize and config.dump_to is None:
        arg_parser.error("--sanitize requires --dump-to.")
    if config.sync and not api_key_present():
        # Sync exists to materialize state unattended; silently skipping
        # the apply would leave the weekly DR job believing it built
        # state when it did not. Fail loudly so the scheduler notices.
        logger.critical(
            "--sync requires %s: state materialization runs terraform "
            "plan/apply, which must authenticate against the Meraki "
            "dashboard.",
            API_KEY_ENV_VAR,
        )
        return 1

    logger.info("meraki2tf starting in %s mode.", config.mode.value)
    try:
        spec_parser = OpenApiParser(resolve_spec(config.spec_path))
        provider = build_provider(config, spec_parser)
        if config.dump_to is not None:
            return _export_snapshot(provider, config)
        dispatcher = build_dispatcher(config)
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
        )
        summary = orchestrator.run(config.org_id)
    except PipelineError as exc:
        logger.critical("%s", exc)
        return 1
    except Exception as exc:
        logger.critical("meraki2tf could not start: %s", exc)
        return 1

    _report(summary)
    if config.fail_on_gaps and summary.unsupported_count > 0:
        logger.error(
            "--fail-on-gaps: %d discovered object(s) cannot be rebuilt by "
            "Terraform; exiting nonzero. See coverage.json in the workdir "
            "for the manual-rebuild list.",
            summary.unsupported_count,
        )
        return 3
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
