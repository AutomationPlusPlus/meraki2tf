"""Azure Automation wrapper for the scheduled meraki2tf DR jobs.

Runs on a Hybrid Runbook Worker (or any Azure compute with a managed
identity) and glues three things together without ever putting the
Meraki API key on disk or on a command line:

1. Fetch the dashboard API key from Azure Key Vault using the host's
   managed identity and export it as ``MERAKI_DASHBOARD_API_KEY`` for
   the child processes only.
2. Execute meraki2tf. The default run is the **weekly snapshot job**
   (terraform was demoted from the weekly loop on 2026-07-17, after
   the full-org restore drill passed):

   a. **Snapshot export**: ``--org-id X --workdir W --dump-to
      W/snapshot.jsonl.gz`` discovers the org once, live, and writes
      the unsanitized v2 stream snapshot. Before the export, last
      run's snapshot is rotated to ``snapshot.previous.jsonl.gz`` and
      passed as ``--drift-baseline`` automatically, so week-over-week
      drift detection needs no external snapshot management. Rotation
      and injection are skipped when the operator supplies their own
      baseline or passes ``--sanitize``, and a rotated snapshot that
      is sanitized or records a different organization is never
      injected (the baseline chain restarts with this run's export).
   b. **Sync pipeline** (only with ``--with-terraform`` — the monthly
      terraform rehearsal schedule): ``--from-dump
      W/snapshot.jsonl.gz --workdir W --sync`` consumes the fresh
      snapshot offline (no second discovery pass) and materializes
      state under the import-only apply guard. The API key stays in
      the env — --sync requires it for terraform plan/apply.
      ``--dump-to`` and ``--sync`` are mutually exclusive at the CLI,
      so the stages are two sequential invocations sharing the
      workdir.

   If the export fails, the sync stage is NOT run and the wrapper
   returns the export's exit code.

   Pass-through ``extra_args`` are routed by a simple rule: flags the
   CLI rejects alongside ``--dump-to`` (``--confirm-deletions``,
   ``--rebaseline``) go only to the sync invocation and are refused
   (exit 2) when ``--with-terraform`` is absent — silently dropping
   them would fake a human confirmation; flags that shape the
   snapshot itself (``--drift-baseline``, ``--sanitize``) go only to
   the export invocation; ``--fail-on-gaps`` goes to whichever stage
   runs last, so the coverage gate governs the job's exit code in
   both shapes; everything else (``--webhook-url``, ``--spec``, email
   and backend flags, …) goes to both.
3. Archive the run's artifacts (snapshot, kit, coverage, runbook) to a
   locked-down Blob container so the DR kit survives the loss of the
   worker itself. The Terraform state is deliberately NOT uploaded: it
   is secret-bearing and fully re-materializable from the kit.
   **Failed runs archive under ``runs/<timestamp>-failed/``** instead
   of ``runs/<timestamp>/``: whatever is on disk after a failure is
   (partly) the previous run's output, and archiving it under a clean
   prefix would make storage look like a healthy weekly cadence when
   the job is actually dying. The ``-failed`` marker keeps the
   artifacts for forensics without faking health.

Standard library only — no Azure SDK required. Both managed-identity
token endpoints are supported:

- ``IDENTITY_ENDPOINT``/``IDENTITY_HEADER`` env vars (Container Apps
  jobs, App Service).
- IMDS at 169.254.169.254 (Azure VMs / Hybrid Runbook Workers).

Exit code: meraki2tf's own exit code (0 clean, 1 fault, 3 coverage
gaps with --fail-on-gaps) unless artifact archival fails, which forces
a nonzero exit — an unarchived DR kit is a failed DR run.

Example (as an Automation runbook parameter string or a shell command):

    python3 runbook.py --vault-name kv-netops --org-id 123456 \
        --storage-account stmerakidr --workdir /var/lib/meraki2tf \
        -- --webhook-url https://hooks.example.com/meraki2tf --fail-on-gaps
"""

from __future__ import annotations

import argparse
import fcntl
import gzip
import json
import logging
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API_KEY_ENV_VAR = "MERAKI_DASHBOARD_API_KEY"
# .jsonl.gz selects meraki2tf's v2 stream snapshot format (one gzipped
# record per line): the v1 single-JSON-object format buffers the whole
# document and costs gigabytes at scale, while v2 streams and
# compresses ~10-20x. --from-dump detects the format by content, so
# the sync stage reads it back without any extra flag.
SNAPSHOT_FILENAME = "snapshot.jsonl.gz"
# Last run's snapshot, rotated aside before each export so the fresh
# discovery can be diffed against it (--drift-baseline).
SNAPSHOT_PREVIOUS_FILENAME = "snapshot.previous.jsonl.gz"
# Kit + reporting artifacts to archive after a --with-terraform run.
# The snapshot is secret-bearing; the container must be RBAC-locked
# (see the guide).
ARTIFACT_FILENAMES = (
    SNAPSHOT_FILENAME,
    "resources.tf",
    "imports.tf",
    "provider.tf",
    "coverage.json",
    "coverage.txt",
    "runbook.md",
)
# What a snapshot-only run refreshes (the export path regenerates the
# DR runbook and coverage manifest every run). The kit files
# (resources.tf, imports.tf, provider.tf) are NOT archived on these
# runs: whatever kit is on disk is the last terraform rehearsal's
# output, and re-uploading it under this run's prefix would misdate it
# as fresh.
SNAPSHOT_RUN_ARTIFACTS = (
    SNAPSHOT_FILENAME,
    "coverage.json",
    "coverage.txt",
    "runbook.md",
)
IMDS_TOKEN_URL = "http://169.254.169.254/metadata/identity/oauth2/token"
KEY_VAULT_RESOURCE = "https://vault.azure.net"
STORAGE_RESOURCE = "https://storage.azure.com/"
BLOB_API_VERSION = "2021-08-06"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("meraki2tf.azure_runbook")


def acquire_token(resource: str) -> str:
    """Get a managed-identity access token for ``resource``.

    Prefers the App Service / Container Apps identity endpoint when its
    env vars are present, otherwise falls back to VM IMDS.
    """
    identity_endpoint = os.environ.get("IDENTITY_ENDPOINT")
    identity_header = os.environ.get("IDENTITY_HEADER")
    if identity_endpoint and identity_header:
        query = urllib.parse.urlencode(
            {"resource": resource, "api-version": "2019-08-01"}
        )
        request = urllib.request.Request(
            f"{identity_endpoint}?{query}",
            headers={"X-IDENTITY-HEADER": identity_header},
        )
    else:
        query = urllib.parse.urlencode(
            {"resource": resource, "api-version": "2018-02-01"}
        )
        request = urllib.request.Request(
            f"{IMDS_TOKEN_URL}?{query}", headers={"Metadata": "true"}
        )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    token = payload.get("access_token", "")
    if not token:
        raise RuntimeError("Managed-identity endpoint returned no access token.")
    return str(token)


def fetch_key_vault_secret(vault_name: str, secret_name: str) -> str:
    """Read the latest version of a Key Vault secret. Never log its value."""
    token = acquire_token(KEY_VAULT_RESOURCE)
    url = (
        f"https://{vault_name}.vault.azure.net/secrets/"
        f"{urllib.parse.quote(secret_name)}?api-version=7.4"
    )
    request = urllib.request.Request(
        url, headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        # Re-raise without the response body: Key Vault error payloads are
        # safe, but keeping the habit of never echoing vault responses.
        raise RuntimeError(
            f"Key Vault request for secret '{secret_name}' failed: "
            f"HTTP {exc.code}"
        ) from None
    value = payload.get("value", "")
    if not value:
        raise RuntimeError(f"Key Vault secret '{secret_name}' is empty.")
    return str(value)


#: Pass-through flags whose following value is a bearer credential.
_CREDENTIAL_FLAGS = frozenset({"--webhook-url"})


def _flag_name(token: str) -> str:
    """The flag part of an argv token, covering both spellings.

    ``--flag VALUE`` yields ``--flag`` unchanged; ``--flag=VALUE``
    yields ``--flag``. Every routing/validation scan in this module
    must classify tokens through this one helper so they cannot
    disagree on tokenization.
    """
    return token.partition("=")[0]


def _redact_command(command: list[str]) -> list[str]:
    """Copy of ``command`` with credential-flag values masked for logging.

    Both argparse spellings are covered: the two-token ``--flag VALUE``
    form and the single-token ``--flag=VALUE`` form — the latter would
    otherwise log the bearer-token URL verbatim into Azure job output.
    """
    redacted = list(command)
    for index, token in enumerate(redacted):
        flag = _flag_name(token)
        separator = "=" in token
        if flag in _CREDENTIAL_FLAGS:
            if separator:
                redacted[index] = f"{flag}=<redacted>"
            elif index + 1 < len(redacted):
                redacted[index + 1] = "<redacted>"
    return redacted


#: extra_args flags routed ONLY to the snapshot-export invocation
#: (they shape what the snapshot contains and are only valid with
#: --dump-to). Value: whether the flag consumes a following token in
#: the two-token spelling.
_EXPORT_ONLY_FLAGS = {"--drift-baseline": True, "--sanitize": False}
#: extra_args flags routed ONLY to the sync invocation — the CLI
#: rejects each of them when combined with --dump-to. All store_true.
_SYNC_ONLY_FLAGS = frozenset({"--confirm-deletions", "--rebaseline"})
#: Flags routed to whichever stage runs LAST: the coverage gate must
#: govern the job's exit code, and an exit-3 export would otherwise
#: short-circuit the sync stage of a --with-terraform run.
_FINAL_STAGE_FLAGS = frozenset({"--fail-on-gaps"})
#: Flags refused outright in scheduled runs: --only would export a
#: PARTIAL snapshot, and the rotation machinery would then feed it to
#: the next run as --drift-baseline — silently poisoning the drift
#: chain. Selective backup is an interactive-only workflow.
_REFUSED_FLAGS = frozenset({"--only"})


def split_extra_args(
    extra_args: list[str], with_terraform: bool = False
) -> tuple[list[str], list[str]]:
    """Route pass-through args to the (export, sync) invocations.

    Stage-specific flags go to exactly the stage that accepts them;
    everything else (alerting, spec, backend flags, …) goes to both.
    Both ``--flag VALUE`` and ``--flag=VALUE`` spellings are handled.
    Flags in :data:`_REFUSED_FLAGS` abort the job outright.
    """
    export_args: list[str] = []
    sync_args: list[str] = []
    final_stage_args = sync_args if with_terraform else export_args
    index = 0
    while index < len(extra_args):
        token = extra_args[index]
        flag = _flag_name(token)
        if flag in _REFUSED_FLAGS:
            raise RuntimeError(
                f"extra_args flag '{flag}' is refused in scheduled runs: "
                "the weekly snapshot must cover the full organization "
                "(a partial export would poison the auto-rotated drift "
                "baseline). Run selective backups interactively."
            )
        separator = "=" in token
        if flag in _EXPORT_ONLY_FLAGS:
            export_args.append(token)
            if _EXPORT_ONLY_FLAGS[flag] and not separator:
                index += 1
                if index < len(extra_args):
                    export_args.append(extra_args[index])
        elif flag in _SYNC_ONLY_FLAGS:
            sync_args.append(token)
        elif flag in _FINAL_STAGE_FLAGS:
            final_stage_args.append(token)
        else:
            export_args.append(token)
            sync_args.append(token)
        index += 1
    return export_args, sync_args


def build_export_command(
    binary: str, org_id: str, workdir: Path, export_args: list[str]
) -> list[str]:
    """Stage 1: live discovery, written as a v2 stream snapshot."""
    return [
        binary,
        "--org-id",
        org_id,
        "--workdir",
        str(workdir),
        "--dump-to",
        str(workdir / SNAPSHOT_FILENAME),
        *export_args,
    ]


def build_sync_command(
    binary: str, workdir: Path, sync_args: list[str]
) -> list[str]:
    """Stage 2: offline pipeline over the fresh snapshot, with --sync.

    No ``--org-id``: dump mode reads the organization recorded in the
    snapshot, which is exactly the org stage 1 exported.
    """
    return [
        binary,
        "--from-dump",
        str(workdir / SNAPSHOT_FILENAME),
        "--workdir",
        str(workdir),
        "--sync",
        *sync_args,
    ]


def validate_extra_args(
    extra_args: list[str], with_terraform: bool
) -> str | None:
    """Usage error for pass-through flags the job shape cannot honor.

    ``--confirm-deletions``/``--rebaseline`` carry a human decision
    (accept deletions, reset the baseline); dropping them silently on a
    snapshot-only run would report a clean run while the confirmed
    action never happened. ``--sanitize`` with ``--with-terraform``
    would hand the sync stage a pseudonymized snapshot, generating a
    kit and import IDs full of fake identifiers against the real org.
    """
    if not with_terraform:
        stranded = [
            token for token in extra_args
            if _flag_name(token) in _SYNC_ONLY_FLAGS
        ]
        if stranded:
            return (
                f"{' '.join(stranded)} only apply to the terraform sync "
                "stage; add --with-terraform (the monthly rehearsal "
                "shape) to use them."
            )
    elif any(_flag_name(token) == "--sanitize" for token in extra_args):
        return (
            "--sanitize cannot be combined with --with-terraform: the "
            "sync stage would consume the pseudonymized snapshot and "
            "build a kit of fake identifiers. Export a sanitized copy "
            "from a snapshot-only run instead."
        )
    return None


def snapshot_header(path: Path) -> dict:
    """Best-effort read of a v2 snapshot's header line ({} on failure).

    The header carries ``organizationId`` and the ``sanitized`` marker
    — both needed to decide whether a rotated snapshot is a valid drift
    baseline for this run.
    """
    try:
        opener = gzip.open if path.name.lower().endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as handle:
            header = json.loads(handle.readline())
        return header if isinstance(header, dict) else {}
    except (OSError, ValueError):
        return {}


def rotate_snapshot(workdir: Path) -> Path | None:
    """Move last run's snapshot aside as this run's drift baseline.

    Returns the baseline path, or ``None`` on the very first run. When
    the previous run's export failed, the last GOOD snapshot is already
    sitting at the rotated path (the failed run never overwrote it) and
    keeps serving as the baseline — drift is then reported against the
    last successful discovery, which is the honest comparison.
    """
    current = workdir / SNAPSHOT_FILENAME
    previous = workdir / SNAPSHOT_PREVIOUS_FILENAME
    if current.exists():
        os.replace(current, previous)
    return previous if previous.exists() else None


def _usable_baseline(baseline: Path, org_id: str) -> bool:
    """Whether a rotated snapshot may be injected as --drift-baseline.

    A sanitized snapshot is refused by the CLI's snapshot-diff
    (pseudonymized identifiers cannot be compared), and a snapshot from
    a different organization (a repointed schedule reusing the workdir)
    would diff two unrelated orgs into one giant false drift alert.
    Skipping injection is self-healing: this run exports a fresh
    matching snapshot and next run's rotation picks it up.
    """
    header = snapshot_header(baseline)
    if header.get("sanitized"):
        logger.warning(
            "Rotated snapshot %s is sanitized and cannot serve as a "
            "drift baseline; skipping --drift-baseline this run.",
            baseline.name,
        )
        return False
    recorded_org = header.get("organizationId")
    if recorded_org is not None and str(recorded_org) != org_id:
        logger.warning(
            "Rotated snapshot %s records a different organization than "
            "--org-id %s; skipping --drift-baseline this run (fresh "
            "baseline chain starts with this export).",
            baseline.name, org_id,
        )
        return False
    return True


#: Exit codes that mean "the run completed and its artifacts are
#: fresh": 3 is the --fail-on-gaps coverage gate, 5 a notifier outage.
#: Neither should stop a later stage from running. Kept consistent
#: with the CLI's exit-code priority (gaps outrank a notifier outage).
_COMPLETED_NONZERO_CODES = (3, 5)


def run_meraki2tf(
    binary: str,
    org_id: str,
    workdir: Path,
    api_key: str,
    extra_args: list[str],
    with_terraform: bool = False,
) -> int:
    """Run the scheduled job: snapshot export, then optionally the sync.

    The default shape is the weekly snapshot job — export only, with
    the previous snapshot rotated in as the drift baseline. With
    ``with_terraform`` (the monthly rehearsal) the offline ``--sync``
    pipeline follows; ``--dump-to`` and ``--sync`` are mutually
    exclusive at the CLI (argparse exit 2), so that job is two
    sequential invocations sharing the workdir and discovery still runs
    once, in stage 1. A hard-failed export short-circuits — its exit
    code is returned, the sync stage never runs against a stale
    snapshot, and the rotated snapshot is moved back so the canonical
    path keeps holding the last good snapshot for DR. Gate codes
    (3 = coverage gaps, 5 = notifier outage) are completed runs: later
    stages still execute and the highest-priority gate code is
    returned. The key travels via the child env only (both stages need
    it: live discovery, then terraform plan/apply under --sync).
    """
    problem = validate_extra_args(extra_args, with_terraform)
    if problem is not None:
        logger.critical("%s", problem)
        return 2
    export_args, sync_args = split_extra_args(extra_args, with_terraform)
    rotated: Path | None = None
    if not any(
        _flag_name(token) in ("--drift-baseline", "--sanitize")
        for token in export_args
    ):
        # An operator-supplied baseline means they own the drift chain
        # (rotating would move the very file their flag may point at);
        # a --sanitize run writes a snapshot that can never serve as a
        # baseline, so rotating would only wedge the next run.
        rotated = rotate_snapshot(workdir)
        if rotated is not None and _usable_baseline(rotated, org_id):
            export_args = [*export_args, "--drift-baseline", str(rotated)]
    stages = [
        ("snapshot export", build_export_command(binary, org_id, workdir, export_args)),
    ]
    if with_terraform:
        stages.append(
            ("sync pipeline", build_sync_command(binary, workdir, sync_args))
        )
    env = dict(os.environ)
    env[API_KEY_ENV_VAR] = api_key
    gate_code = 0
    for stage, command in stages:
        # Pass-through args can carry bearer-credential values (a
        # Slack/Teams --webhook-url whose path IS the token); Azure
        # job-output history is readable by a much broader RBAC set
        # than Key Vault, so redact the value of any credential-shaped
        # flag (both spellings) before logging.
        logger.info("Running %s: %s", stage, " ".join(_redact_command(command)))
        completed = subprocess.run(command, env=env, check=False)
        logger.info(
            "meraki2tf %s exited with code %d", stage, completed.returncode
        )
        if completed.returncode in _COMPLETED_NONZERO_CODES:
            # CLI priority: gaps (3) outrank a notifier outage (5).
            if gate_code == 0 or completed.returncode < gate_code:
                gate_code = completed.returncode
            continue
        if completed.returncode != 0:
            current = workdir / SNAPSHOT_FILENAME
            if rotated is not None and not current.exists():
                # The export died before writing a snapshot: move the
                # last good one back so the canonical DR path
                # (workdir/snapshot.jsonl.gz) never goes empty.
                os.replace(rotated, current)
                logger.warning(
                    "Export failed before writing a snapshot; restored "
                    "the previous snapshot to %s.", current.name,
                )
            return completed.returncode
    return gate_code


#: Size guard for the single-shot Put Blob upload. The service accepts
#: up to 5000 MiB per Put Blob at this API version; we stop well short
#: of it. Artifacts near this size (a v2 snapshot compresses ~10-20x,
#: so this is an enormous org) need the multi-part Put Block flow —
#: refusing loudly beats a mid-transfer HTTP 413.
MAX_SINGLE_PUT_BYTES = 4 * 1024**3


def upload_blob(
    storage_account: str,
    container: str,
    blob_name: str,
    path: Path,
    token: str,
) -> None:
    """PUT one file as a block blob using the managed-identity token.

    The body is the open file object, not ``read_bytes()``:
    ``http.client`` streams ``read()``-able bodies in fixed-size blocks
    when Content-Length is set, so a multi-hundred-MB snapshot never
    has to fit in the worker's memory.
    """
    url = (
        f"https://{storage_account}.blob.core.windows.net/"
        f"{container}/{urllib.parse.quote(blob_name)}"
    )
    size = path.stat().st_size
    if size > MAX_SINGLE_PUT_BYTES:
        raise OSError(
            f"{path.name} is {size} bytes, over the {MAX_SINGLE_PUT_BYTES}-"
            "byte single-shot Put Blob guard; a multi-part upload is needed."
        )
    with path.open("rb") as body:
        request = urllib.request.Request(
            url,
            data=body,
            method="PUT",
            headers={
                "Authorization": f"Bearer {token}",
                "x-ms-version": BLOB_API_VERSION,
                "x-ms-blob-type": "BlockBlob",
                "Content-Length": str(size),
            },
        )
        with urllib.request.urlopen(request, timeout=600):
            pass
    logger.info("Archived %s -> %s/%s", path.name, container, blob_name)


def archive_artifacts(
    storage_account: str, container: str, workdir: Path,
    run_failed: bool = False,
    filenames: tuple[str, ...] = ARTIFACT_FILENAMES,
) -> list[str]:
    """Upload every present artifact under a per-run prefix.

    When ``run_failed`` is set the prefix carries a ``-failed`` marker:
    after a failed run the workdir holds (partly or wholly) the
    PREVIOUS run's artifacts, and re-uploading them under a clean
    ``runs/<timestamp>/`` prefix would make storage show a healthy
    weekly cadence while the job is dying. The marked prefix preserves
    the on-disk state for forensics without faking health.

    Returns the artifacts that failed to upload (empty on full success).
    All uploads are attempted even if one fails.
    """
    token = acquire_token(STORAGE_RESOURCE)
    run_prefix = datetime.now(timezone.utc).strftime("runs/%Y-%m-%dT%H%M%SZ")
    if run_failed:
        run_prefix += "-failed"
    failures: list[str] = []
    for filename in filenames:
        path = workdir / filename
        if not path.exists():
            logger.info("Artifact %s not present this run; skipping.", filename)
            continue
        try:
            upload_blob(
                storage_account, container, f"{run_prefix}/{filename}", path, token
            )
        except (urllib.error.URLError, OSError) as exc:
            logger.error("Failed to archive %s: %s", filename, exc)
            failures.append(filename)
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scheduled meraki2tf DR job wrapper for Azure "
        "Automation: the weekly snapshot job by default, the monthly "
        "terraform rehearsal with --with-terraform.",
    )
    parser.add_argument("--vault-name", required=True, help="Key Vault name.")
    parser.add_argument(
        "--secret-name",
        default="meraki-dashboard-api-key",
        help="Key Vault secret holding the Meraki dashboard API key.",
    )
    parser.add_argument("--org-id", required=True, help="Meraki organization ID.")
    parser.add_argument(
        "--workdir",
        type=Path,
        required=True,
        help="Persistent meraki2tf workspace (state + accumulated kit).",
    )
    parser.add_argument(
        "--storage-account", required=True, help="Blob storage account name."
    )
    parser.add_argument(
        "--container",
        default="meraki2tf-dr",
        help="Blob container for run artifacts (must be RBAC-locked).",
    )
    parser.add_argument(
        "--meraki2tf-bin",
        default="meraki2tf",
        help="meraki2tf executable (e.g. /opt/meraki2tf/.venv/bin/meraki2tf).",
    )
    parser.add_argument(
        "--with-terraform",
        action="store_true",
        help="Also run the offline --sync pipeline after the snapshot "
        "export (kit regeneration + guarded import-only state "
        "materialization). This is the monthly terraform-rehearsal "
        "shape; the default is the weekly snapshot-only job.",
    )
    parser.add_argument(
        "extra_args",
        nargs="*",
        help="Extra arguments passed through to meraki2tf after '--' "
        "(e.g. -- --webhook-url https://... --fail-on-gaps).",
    )
    args = parser.parse_args(argv)

    problem = validate_extra_args(args.extra_args, args.with_terraform)
    if problem is not None:
        # A pure-argv usage error: refuse before the managed-identity
        # round-trips, the Key Vault secret fetch, and the artifact
        # archive — nothing ran, so nothing may be (re)uploaded.
        parser.error(problem)

    # One workdir, two schedules (weekly snapshot + monthly rehearsal):
    # if they ever overlap, the second run's snapshot rotation would
    # yank the file out from under the first's sync stage. flock is
    # held for the process lifetime and released by the kernel on any
    # exit, so a crashed run never leaves a stale lock.
    args.workdir.mkdir(parents=True, exist_ok=True)
    lock_handle = (args.workdir / ".meraki2tf-wrapper.lock").open("w")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        logger.critical(
            "Another wrapper run is active in %s (overlapping weekly/"
            "monthly schedules?); refusing to run concurrently against "
            "one workdir.", args.workdir,
        )
        return 1

    api_key = fetch_key_vault_secret(args.vault_name, args.secret_name)
    logger.info(
        "Fetched API key from vault '%s' (secret '%s').",
        args.vault_name,
        args.secret_name,
    )

    exit_code = run_meraki2tf(
        args.meraki2tf_bin, args.org_id, args.workdir, api_key,
        args.extra_args, with_terraform=args.with_terraform,
    )

    # Exit 3 (--fail-on-gaps) and 5 (notifier outage) are completed
    # runs with fresh artifacts — gates, not failures. Everything else
    # nonzero means the workdir may still hold the previous run's
    # artifacts, so archive under the -failed prefix. Snapshot-only
    # runs archive only what they refreshed; the kit files on disk are
    # the last terraform rehearsal's output.
    failures = archive_artifacts(
        args.storage_account, args.container, args.workdir,
        run_failed=exit_code not in (0, *_COMPLETED_NONZERO_CODES),
        filenames=(
            ARTIFACT_FILENAMES if args.with_terraform
            else SNAPSHOT_RUN_ARTIFACTS
        ),
    )
    if failures:
        logger.error(
            "DR archive incomplete — failed artifacts: %s", ", ".join(failures)
        )
        return exit_code or 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
