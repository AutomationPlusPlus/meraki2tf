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
    org_id: str | None
    #: None means "resolve automatically" — see meraki2tf.spec_resolver.
    spec_path: Path | None
    dump_path: Path | None
    #: When set, discovery output is written here as a canonical
    #: snapshot instead of running the Terraform pipeline.
    dump_to: Path | None
    #: Redact secrets/identity from the exported snapshot (--dump-to).
    sanitize: bool
    #: Disaster-recovery action: preview (or, with confirm, execute) a
    #: terraform apply over the artifacts already in the workdir.
    rebuild: bool
    #: Escalates --rebuild or --replay-gaps from a read-only preview to
    #: a real write against Meraki.
    confirm: bool
    #: Disaster-recovery action: preview (or, with confirm, execute)
    #: replaying Terraform-unsupported objects and uncaptured secret
    #: attributes from a snapshot back into the Meraki organization.
    replay_gaps: bool
    #: Discard the accumulated resources.tf baseline so this run
    #: regenerates configuration from currently discovered data.
    rebaseline: bool
    #: Opt-in DR mode: guarded import-only auto-apply plus
    #: modified-object baseline regeneration (the weekly job's flag).
    sync: bool
    #: Human confirmation to remove Meraki-deleted resources from the
    #: DR kit and the state; without it deletions are alert-only.
    confirm_deletions: bool
    #: Exit nonzero when unsupported objects exist (CI coverage gate).
    fail_on_gaps: bool
    workdir: Path
    #: None means "terraform.tfstate inside the workdir".
    state_file: Path | None
    verbose: bool
    webhook_urls: tuple[str, ...]
    alert_emails: tuple[str, ...]
    smtp_host: str
    smtp_port: int
    email_from: str
    terraform_bin: str

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "RuntimeConfig":
        """Derive the run configuration from parsed CLI arguments."""
        dump_path = Path(args.from_dump) if args.from_dump else None
        return cls(
            mode=ExecutionMode.DUMP if dump_path else ExecutionMode.LIVE,
            org_id=args.org_id,
            spec_path=Path(args.spec) if args.spec else None,
            dump_path=dump_path,
            dump_to=Path(args.dump_to) if args.dump_to else None,
            sanitize=args.sanitize,
            rebuild=args.rebuild,
            confirm=args.confirm,
            replay_gaps=args.replay_gaps,
            rebaseline=args.rebaseline,
            sync=args.sync,
            confirm_deletions=args.confirm_deletions,
            fail_on_gaps=args.fail_on_gaps,
            workdir=Path(args.workdir),
            state_file=Path(args.state_file) if args.state_file else None,
            verbose=args.verbose,
            webhook_urls=tuple(args.webhook_url or ()),
            alert_emails=tuple(args.alert_email or ()),
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            email_from=args.email_from,
            terraform_bin=args.terraform_bin,
        )


def api_key_present() -> bool:
    """Whether the Meraki dashboard token is available in the environment.

    Terraform's plan/apply stages read live resources through the
    provider, so runs without a token (typical for offline dump mode)
    skip them instead of failing.
    """
    return bool(os.environ.get(API_KEY_ENV_VAR, "").strip())


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
