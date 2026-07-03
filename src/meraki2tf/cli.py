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
by either mode; only the explicit ``--rebuild --confirm`` action ever
changes the organization.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from meraki2tf.alerts import AlertDispatcher, EmailNotifier, WebhookNotifier
from meraki2tf.config import (
    API_KEY_ENV_VAR,
    ExecutionMode,
    RuntimeConfig,
    api_key_present,
)
from meraki2tf.hcl_generator import HclImportGenerator
from meraki2tf.logging_setup import configure_logging
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.orchestrator import PipelineError, PipelineOrchestrator, RunSummary
from meraki2tf.provider_catalog import resolve_catalog
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
        help="Escalate --rebuild from a read-only preview to a real terraform apply.",
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
            "(default: terraform.tfstate inside --workdir)."
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


def main(argv: Sequence[str] | None = None) -> int:
    arg_parser = build_parser()
    args = arg_parser.parse_args(argv)
    config = RuntimeConfig.from_args(args)
    configure_logging(verbose=config.verbose)

    if config.confirm and not config.rebuild:
        arg_parser.error("--confirm is only valid together with --rebuild.")
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
