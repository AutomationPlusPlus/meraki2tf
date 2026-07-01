"""Command-line entry point.

Built for both ad-hoc invocation and unattended scheduled runs (e.g. a
weekly cron job): every input arrives via flags or environment
variables, no interactive prompts, and the exit code reports outcome.
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from meraki2tf.config import RuntimeConfig
from meraki2tf.logging_setup import configure_logging

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
        "--from-dump",
        metavar="PATH",
        default=None,
        help="Run offline against a local JSON snapshot instead of the live cloud API.",
    )
    parser.add_argument(
        "--spec",
        metavar="PATH",
        default=None,
        help=(
            "Local Meraki OpenAPI JSON document to build the resource registry "
            "from; omit to pull the latest published spec."
        ),
    )
    parser.add_argument(
        "--output-dir",
        metavar="DIR",
        default="generated",
        help="Directory that receives generated Terraform files (default: %(default)s).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging; credentials are redacted at every level.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(verbose=args.verbose)
    config = RuntimeConfig.from_args(args)
    logger.info("meraki2tf starting in %s mode", config.mode.value)
    # Pipeline wiring lands in subsequent iterations:
    # provider -> spec registry -> HCL construction -> drift evaluation
    # -> state aggregation -> notification dispatch.
    logger.info("Scaffold run complete; translation engine not yet wired in.")
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via the console script
    sys.exit(main())
