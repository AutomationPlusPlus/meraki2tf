"""Runtime configuration for a meraki2tf execution.

Security contract: the Meraki API token is read from the
``MERAKI_DASHBOARD_API_KEY`` environment variable at the moment a live
client is constructed. It is never accepted as a CLI parameter, never
stored on configuration objects, and never written to logs or output.
"""

from __future__ import annotations

import argparse
import enum
import os
from dataclasses import dataclass
from pathlib import Path

API_KEY_ENV_VAR = "MERAKI_DASHBOARD_API_KEY"


class ExecutionMode(enum.Enum):
    """How the run sources its Meraki configuration data."""

    LIVE = "live"
    DUMP = "dump"


class MissingApiKeyError(RuntimeError):
    """Raised when live mode is requested without an API token in the environment."""


@dataclass(frozen=True)
class RuntimeConfig:
    """Immutable snapshot of everything a single run needs.

    Deliberately excludes credentials; see the module docstring.
    """

    mode: ExecutionMode
    dump_path: Path | None
    spec_source: str | None
    output_dir: Path
    verbose: bool

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "RuntimeConfig":
        """Derive the run configuration from parsed CLI arguments."""
        dump_path = Path(args.from_dump) if args.from_dump else None
        return cls(
            mode=ExecutionMode.DUMP if dump_path else ExecutionMode.LIVE,
            dump_path=dump_path,
            spec_source=args.spec,
            output_dir=Path(args.output_dir),
            verbose=args.verbose,
        )


def read_api_key() -> str:
    """Read the Meraki dashboard token from the environment.

    Callers must pass the value directly into the SDK client and drop it;
    holding it on long-lived objects is prohibited.
    """
    key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    if not key:
        raise MissingApiKeyError(
            f"Live mode requires the {API_KEY_ENV_VAR} environment variable to be set."
        )
    return key
