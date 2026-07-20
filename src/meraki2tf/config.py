"""Runtime configuration for a meraki2tf execution.

Security contract: the Meraki API token is read from the
``MERAKI_DASHBOARD_API_KEY`` environment variable at the moment a live
client is constructed. It is never accepted as a CLI parameter, never
stored on configuration objects, and never written to logs or output.
"""

from __future__ import annotations

import argparse
import enum
import json
import os
import re
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

API_KEY_ENV_VAR = "MERAKI_DASHBOARD_API_KEY"
#: Webhook URLs (which conventionally embed a bearer token in the path)
#: may be supplied here instead of via ``--webhook-url`` so the secret
#: never lands in argv / process listings / scheduler logs. Separate
#: multiple targets with ``:::`` (a plain ``:`` occurs inside every URL).
WEBHOOK_URL_ENV_VAR = "MERAKI2TF_WEBHOOK_URL"


class ExecutionMode(enum.Enum):
    """How the run sources its Meraki configuration data."""

    LIVE = "live"
    DUMP = "dump"


class StateBackend(enum.Enum):
    """Where Terraform keeps its state for the execution workspace."""

    #: A file on the local disk (the default; behaviour is unchanged).
    LOCAL = "local"
    #: Azure Blob Storage via Terraform's built-in ``azurerm`` backend.
    AZURERM = "azurerm"
    #: Amazon S3 via Terraform's built-in ``s3`` backend.
    S3 = "s3"
    #: Google Cloud Storage via Terraform's built-in ``gcs`` backend.
    GCS = "gcs"


#: ``--backend-config`` keys whose values are credentials, across every
#: supported remote backend (a union — refusing another backend's
#: credential key can never hurt). Terraform reads these from the
#: environment instead (``ARM_*`` for azurerm, ``AWS_*`` for s3,
#: ``GOOGLE_APPLICATION_CREDENTIALS``/ADC for gcs — or an ambient
#: managed identity), so meraki2tf refuses them on the command line:
#: argv, process listings, and debug logs must never carry a secret
#: (see CLAUDE.md).
SECRET_BACKEND_KEYS = frozenset(
    {
        # azurerm
        "access_key",
        "sas_token",
        "client_secret",
        "client_certificate_password",
        "password",
        "oidc_token",
        "oidc_request_token",
        # s3 (secret_key doubles as a generic credential name)
        "secret_key",
        "token",
        "sse_customer_key",
        "web_identity_token",
        # gcs ('credentials' may hold the service-account key JSON inline)
        "credentials",
        "access_token",
        "encryption_key",
    }
)

#: Per-backend settings that address the state object itself (the
#: analogue of ``--state-file`` for a remote backend). Enforced only
#: when they are not supplied out-of-band via ``--backend-config-file``;
#: connection settings with environment fallbacks (azurerm
#: ``resource_group_name``, s3 ``region``, …) are deliberately not
#: required here — terraform init fails loudly on those itself.
_REQUIRED_STATE_ADDRESS_KEYS: dict[StateBackend, tuple[str, ...]] = {
    StateBackend.AZURERM: ("storage_account_name", "container_name", "key"),
    StateBackend.S3: ("bucket", "key"),
    StateBackend.GCS: ("bucket",),
}


class BackendConfigError(ValueError):
    """A ``--state-backend`` / ``--backend-config`` combination is invalid."""


def _refuse_credential_keys_in_file(path: Path) -> None:
    """Refuse credential-shaped keys inside a ``--backend-config-file``.

    ``terraform init`` persists every backend setting — file-sourced
    included — in plaintext into ``.terraform/terraform.tfstate``, so a
    credential smuggled through the file would land on disk outside the
    two sanctioned secret-bearing artifacts. Same rule, same remedy as
    the argv form: credentials come from the environment or a managed
    identity.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        # Missing/unreadable file: terraform init will fail loudly on
        # the same path; nothing to scan here.
        return
    for key in _backend_config_file_keys(text):
        if key.lower() in SECRET_BACKEND_KEYS:
            raise BackendConfigError(
                f"--backend-config-file {path} sets {key!r}, which is a "
                "credential and must not be written to a config file; "
                "terraform reads it from the environment instead (ARM_* "
                "for azurerm, AWS_* for s3, GOOGLE_APPLICATION_CREDENTIALS "
                "for gcs — or use an ambient managed identity)."
            )


def _backend_config_file_keys(text: str) -> Iterator[str]:
    """Every setting key a backend-config file supplies, both formats.

    ``terraform init`` accepts the file as JSON as well as HCL; scanning
    only ``key = value`` lines would let ``{"access_key": "..."}`` walk
    straight past the credential refusal. JSON documents are walked
    recursively (s3 nests credentials under ``assume_role_with_web_identity``);
    anything that does not parse as JSON falls back to the HCL line scan.
    """
    try:
        document = json.loads(text)
    except ValueError:
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "//")):
                continue
            yield stripped.partition("=")[0].strip().strip('"')
        return
    stack = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                yield str(key)
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


@dataclass(frozen=True)
class BackendConfig:
    """Resolved Terraform backend selection for a run.

    ``local`` (the default) keeps the historical on-disk state file. Any
    other backend is *remote*: its settings ride ``terraform init
    -backend-config`` arguments (Terraform forbids interpolation inside a
    ``backend`` block, so a partial block plus ``-backend-config`` is the
    idiomatic way to parameterise one), and credentials come from the
    environment, never from meraki2tf.
    """

    backend: StateBackend = StateBackend.LOCAL
    #: Ordered ``(key, value)`` settings for ``-backend-config=key=value``.
    settings: tuple[tuple[str, str], ...] = ()
    #: Optional ``-backend-config=FILE`` path (composes with ``settings``).
    config_file: Path | None = None

    @property
    def is_remote(self) -> bool:
        return self.backend is not StateBackend.LOCAL

    def init_args(self) -> tuple[str, ...]:
        """The ``-backend-config`` arguments to pass to ``terraform init``."""
        args: list[str] = []
        if self.config_file is not None:
            args.append(f"-backend-config={self.config_file}")
        args.extend(f"-backend-config={key}={value}" for key, value in self.settings)
        return tuple(args)

    @classmethod
    def from_cli(
        cls,
        backend_name: str,
        config_items: list[str] | None,
        config_file: str | None,
    ) -> "BackendConfig":
        """Parse and validate the backend flags, or raise ``BackendConfigError``."""
        try:
            backend = StateBackend(backend_name)
        except ValueError:
            choices = ", ".join(member.value for member in StateBackend)
            raise BackendConfigError(
                f"unknown --state-backend {backend_name!r}; choose one of: {choices}."
            ) from None

        settings: list[tuple[str, str]] = []
        for item in config_items or ():
            key, sep, value = item.partition("=")
            key = key.strip()
            if not sep or not key:
                # Echo only a leading identifier fragment: a mistyped
                # credential (``access_key:hunter2``) must not have its
                # value repeated into stderr/CI logs by the usage error.
                match = re.match(r"[A-Za-z0-9_]*", item.strip())
                fragment = match.group(0) if match else ""
                raise BackendConfigError(
                    f"--backend-config {fragment!r}… must be in KEY=VALUE "
                    "form (value omitted from this message)."
                )
            if key.lower() in SECRET_BACKEND_KEYS:
                raise BackendConfigError(
                    f"--backend-config {key!r} is a credential and must not be "
                    "passed on the command line; terraform reads it from the "
                    "environment instead (ARM_* for azurerm, AWS_* for s3, "
                    "GOOGLE_APPLICATION_CREDENTIALS for gcs — or use an "
                    "ambient managed identity)."
                )
            settings.append((key, value))

        file_path = Path(config_file) if config_file else None
        if file_path is not None:
            _refuse_credential_keys_in_file(file_path)

        if backend is StateBackend.LOCAL and (settings or file_path is not None):
            raise BackendConfigError(
                "--backend-config / --backend-config-file only apply to a remote "
                "--state-backend; the default local backend uses --state-file."
            )

        resolved = cls(backend=backend, settings=tuple(settings), config_file=file_path)

        required = _REQUIRED_STATE_ADDRESS_KEYS.get(backend, ())
        if required and file_path is None:
            supplied = {key.lower() for key, _ in settings}
            missing = [key for key in required if key not in supplied]
            if missing:
                raise BackendConfigError(
                    f"--state-backend {backend.value} requires "
                    f"--backend-config settings: {', '.join(missing)} "
                    "(or supply them via --backend-config-file)."
                )
        return resolved


class ConfigFileError(ValueError):
    """A ``--config`` file is unreadable, malformed, or sets a refused key."""


#: Config-file keys that must stay human-typed on the command line.
#: Disaster-recovery actions, their targets, and every confirmation flag
#: are refused: a write to Meraki (or a baseline-destroying acceptance)
#: must never happen because a long-lived config file says so.
CONFIG_FILE_REFUSED_KEYS = frozenset(
    {
        "rebuild",
        "heal",
        "replay-gaps",
        "restore",
        "wipe-org",
        "wipe-org-name",
        "confirm",
        "confirm-deletions",
        "rebaseline",
        "target-org",
        "serial-map",
        "skip-claims",
    }
)

#: TOML key → argparse dest for string-valued settings.
_CONFIG_STR_KEYS = {
    "org-id": "org_id",
    "spec": "spec",
    "workdir": "workdir",
    "terraform-bin": "terraform_bin",
    "from-dump": "from_dump",
    "dump-to": "dump_to",
    "drift-baseline": "drift_baseline",
    "state-file": "state_file",
    "state-backend": "state_backend",
    "backend-config-file": "backend_config_file",
    "smtp-host": "smtp_host",
    "email-from": "email_from",
    "webhook-format": "webhook_format",
}
_CONFIG_BOOL_KEYS = {
    "verbose": "verbose",
    "sanitize": "sanitize",
    "sync": "sync",
    "fail-on-gaps": "fail_on_gaps",
    "pagerduty": "pagerduty",
}
_CONFIG_INT_KEYS = {"smtp-port": "smtp_port"}
#: Accept a single string or an array of strings (repeatable flags).
_CONFIG_LIST_KEYS = {"webhook-url": "webhook_url", "alert-email": "alert_email"}


def _config_file_allowed_keys() -> str:
    allowed = (
        set(_CONFIG_STR_KEYS)
        | set(_CONFIG_BOOL_KEYS)
        | set(_CONFIG_INT_KEYS)
        | set(_CONFIG_LIST_KEYS)
        | {"backend-config"}
    )
    return ", ".join(sorted(allowed))


def _backend_settings_from_table(path: Path, value: object) -> list[str]:
    """Convert a ``[backend-config]`` TOML table into KEY=VALUE items.

    Credential-shaped keys are refused here with a file-specific message;
    :meth:`BackendConfig.from_cli` re-validates the produced items, so the
    argv guard stays authoritative (belt-and-suspenders).
    """
    if not isinstance(value, dict):
        raise ConfigFileError(
            f"--config {path}: 'backend-config' must be a TOML table of "
            "KEY = \"VALUE\" settings."
        )
    items: list[str] = []
    for key, setting in value.items():
        if key.lower() in SECRET_BACKEND_KEYS:
            raise ConfigFileError(
                f"--config {path} sets backend-config.{key}, which is a "
                "credential and must not be written to a config file; "
                "terraform reads it from the environment or a managed "
                "identity instead."
            )
        if isinstance(setting, bool):
            rendered = "true" if setting else "false"
        elif isinstance(setting, (str, int)):
            rendered = str(setting)
        else:
            raise ConfigFileError(
                f"--config {path}: backend-config.{key} must be a string, "
                "integer, or boolean."
            )
        items.append(f"{key}={rendered}")
    return items


def load_config_file(path: Path) -> dict[str, object]:
    """Parse a ``--config`` TOML file into argparse destination overrides.

    Returns a mapping of argparse ``dest`` names to values, applied only
    where the command line did not supply the flag (CLI > file > default).
    Only schedule-safe settings are accepted: DR actions, their targets,
    and confirmation flags are refused (see ``CONFIG_FILE_REFUSED_KEYS``),
    and credential-shaped values are refused everywhere — the file must
    never hold a secret (the API key only ever comes from the
    ``MERAKI_DASHBOARD_API_KEY`` environment variable).
    """
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigFileError(f"--config {path}: cannot read the file ({exc}).") from exc
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigFileError(f"--config {path} is not valid TOML: {exc}") from exc

    overrides: dict[str, object] = {}
    for key, value in data.items():
        if key in CONFIG_FILE_REFUSED_KEYS:
            raise ConfigFileError(
                f"--config {path} sets {key!r}, which must be typed on the "
                "command line for every invocation: disaster-recovery "
                "actions and confirmations never run because a config "
                "file says so."
            )
        if key == "backend-config":
            overrides["backend_config"] = _backend_settings_from_table(path, value)
        elif key in _CONFIG_LIST_KEYS:
            if isinstance(value, str):
                values = [value]
            elif isinstance(value, list) and all(
                isinstance(item, str) for item in value
            ):
                values = list(value)
            else:
                raise ConfigFileError(
                    f"--config {path}: {key!r} must be a string or an "
                    "array of strings."
                )
            overrides[_CONFIG_LIST_KEYS[key]] = values
        elif key in _CONFIG_BOOL_KEYS:
            if not isinstance(value, bool):
                raise ConfigFileError(
                    f"--config {path}: {key!r} must be a boolean."
                )
            overrides[_CONFIG_BOOL_KEYS[key]] = value
        elif key in _CONFIG_INT_KEYS:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ConfigFileError(
                    f"--config {path}: {key!r} must be an integer."
                )
            overrides[_CONFIG_INT_KEYS[key]] = value
        elif key in _CONFIG_STR_KEYS:
            if not isinstance(value, str):
                raise ConfigFileError(
                    f"--config {path}: {key!r} must be a string."
                )
            if key == "state-backend":
                try:
                    StateBackend(value)
                except ValueError:
                    choices = ", ".join(member.value for member in StateBackend)
                    raise ConfigFileError(
                        f"--config {path}: unknown state-backend {value!r}; "
                        f"choose one of: {choices}."
                    ) from None
            overrides[_CONFIG_STR_KEYS[key]] = value
        else:
            raise ConfigFileError(
                f"--config {path}: unknown key {key!r}. Valid keys: "
                f"{_config_file_allowed_keys()}."
            )
    return overrides


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
    #: A previous snapshot to diff the fresh discovery against —
    #: API-to-API drift detection in seconds, no terraform read pass.
    drift_baseline: Path | None
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
    #: Full-organization restore from a snapshot into a TARGET org
    #: (never the source). Preview by default; --confirm executes.
    restore: bool
    target_org: str | None
    #: Same-organization partial recovery: recreate snapshot objects
    #: missing from live discovery (accidental deletions). Additive-only;
    #: preview by default, --confirm executes.
    heal: bool
    #: Optional old→new device serial map (hardware-loss DR).
    serial_map: Path | None
    #: Drill mode for --restore: skip device claiming + device-scoped
    #: features (hardware belongs to the production org).
    skip_claims: bool
    #: Guarded teardown of a hardware-free drill organization.
    wipe_org: str | None
    wipe_org_name: str | None
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
    #: Standalone discovery helper: print the organizations the API key
    #: can see (ID + name) and exit — how a new user finds --org-id.
    list_orgs: bool
    workdir: Path
    #: None means "terraform.tfstate inside the workdir".
    state_file: Path | None
    #: Terraform state backend selection (default: on-disk local).
    backend: BackendConfig
    verbose: bool
    webhook_urls: tuple[str, ...]
    #: Webhook POST body shape: raw event JSON (default) or a
    #: Slack/Teams-native rendering of the same event.
    webhook_format: str
    #: Page WARNING/CRITICAL events via the PagerDuty Events API v2
    #: (routing key environment-only).
    pagerduty: bool
    alert_emails: tuple[str, ...]
    smtp_host: str
    smtp_port: int
    email_from: str
    terraform_bin: str

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "RuntimeConfig":
        """Derive the run configuration from parsed CLI arguments.

        Raises :class:`BackendConfigError` for an invalid backend
        selection; the CLI turns that into a usage error.
        """
        dump_path = Path(args.from_dump) if args.from_dump else None
        backend = BackendConfig.from_cli(
            args.state_backend, args.backend_config, args.backend_config_file
        )
        return cls(
            mode=ExecutionMode.DUMP if dump_path else ExecutionMode.LIVE,
            org_id=args.org_id,
            spec_path=Path(args.spec) if args.spec else None,
            dump_path=dump_path,
            drift_baseline=(
                Path(args.drift_baseline) if args.drift_baseline else None
            ),
            dump_to=Path(args.dump_to) if args.dump_to else None,
            sanitize=args.sanitize,
            rebuild=args.rebuild,
            confirm=args.confirm,
            replay_gaps=args.replay_gaps,
            restore=args.restore,
            target_org=args.target_org,
            heal=args.heal,
            serial_map=Path(args.serial_map) if args.serial_map else None,
            skip_claims=args.skip_claims,
            wipe_org=args.wipe_org,
            wipe_org_name=args.wipe_org_name,
            rebaseline=args.rebaseline,
            sync=args.sync,
            confirm_deletions=args.confirm_deletions,
            fail_on_gaps=args.fail_on_gaps,
            list_orgs=args.list_orgs,
            workdir=Path(args.workdir),
            state_file=Path(args.state_file) if args.state_file else None,
            backend=backend,
            verbose=args.verbose,
            webhook_urls=_webhook_urls(args.webhook_url),
            webhook_format=args.webhook_format,
            pagerduty=args.pagerduty,
            alert_emails=tuple(args.alert_email or ()),
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            email_from=args.email_from,
            terraform_bin=args.terraform_bin,
        )


def _webhook_urls(cli_values: list[str] | None) -> tuple[str, ...]:
    """Webhook targets from the env var (preferred) plus any --webhook-url.

    The env var keeps the token-bearing URL out of argv; the flag stays
    supported for interactive use. Duplicates are collapsed, order
    preserved (env-sourced first).
    """
    urls: list[str] = []
    env_value = os.environ.get(WEBHOOK_URL_ENV_VAR, "").strip()
    if env_value:
        urls.extend(part.strip() for part in env_value.split(":::") if part.strip())
    urls.extend(cli_values or ())
    seen: dict[str, None] = {}
    for url in urls:
        seen.setdefault(url)
    return tuple(seen)


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
