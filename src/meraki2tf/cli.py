"""Command-line entry point and pipeline assembly.

Built for both ad-hoc invocation and unattended scheduled runs (e.g. a
weekly cron job): every input arrives via flags or environment
variables, no interactive prompts, and the exit code reports outcome
(0 = clean aggregation, 1 = pipeline fault, 2 = usage error).
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from meraki2tf.alerts import AlertDispatcher, EmailNotifier, WebhookNotifier
from meraki2tf.config import ExecutionMode, RuntimeConfig
from meraki2tf.hcl_generator import HclImportGenerator
from meraki2tf.logging_setup import configure_logging
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.orchestrator import PipelineError, PipelineOrchestrator, RunSummary
from meraki2tf.providers import (
    LiveApiDataProvider,
    MerakiDataProvider,
    StaticJsonDataProvider,
)
from meraki2tf.spec_resolver import resolve_spec
from meraki2tf.terraform_runner import TerraformRunner

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
        "--workdir",
        metavar="DIR",
        default="generated",
        help="Terraform execution workspace directory (default: %(default)s).",
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
        return StaticJsonDataProvider(config.dump_path)
    return LiveApiDataProvider(parser=parser)


def main(argv: Sequence[str] | None = None) -> int:
    arg_parser = build_parser()
    args = arg_parser.parse_args(argv)
    config = RuntimeConfig.from_args(args)
    configure_logging(verbose=config.verbose)

    if config.mode is ExecutionMode.LIVE and not config.org_id:
        arg_parser.error("--org-id is required in live mode.")

    logger.info("meraki2tf starting in %s mode.", config.mode.value)
    try:
        spec_parser = OpenApiParser(resolve_spec(config.spec_path))
        dispatcher = build_dispatcher(config)
        orchestrator = PipelineOrchestrator(
            provider=build_provider(config, spec_parser),
            generator=HclImportGenerator(spec_parser, dispatcher),
            runner=TerraformRunner(config.workdir, executable=config.terraform_bin),
            dispatcher=dispatcher,
        )
        summary = orchestrator.run(config.org_id)
    except PipelineError as exc:
        logger.critical("%s", exc)
        return 1
    except Exception as exc:
        logger.critical("meraki2tf could not start: %s", exc)
        return 1

    _report(summary)
    return 0


def _report(summary: RunSummary) -> None:
    logger.info(
        "Run complete for organization %s: %d import(s) written, "
        "%d unsupported asset(s), drift %s.",
        summary.organization_id,
        summary.imports_written,
        summary.unsupported_count,
        "DETECTED" if summary.drift_detected else "not detected",
    )


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    sys.exit(main())
