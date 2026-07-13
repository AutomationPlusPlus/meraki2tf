"""Azure Automation wrapper for the weekly meraki2tf DR job.

Runs on a Hybrid Runbook Worker (or any Azure compute with a managed
identity) and glues three things together without ever putting the
Meraki API key on disk or on a command line:

1. Fetch the dashboard API key from Azure Key Vault using the host's
   managed identity and export it as ``MERAKI_DASHBOARD_API_KEY`` for
   the child processes only.
2. Execute meraki2tf twice, sequentially, sharing the workdir —
   ``--dump-to`` and ``--sync`` are mutually exclusive at the CLI, so
   one invocation cannot do both:

   a. **Snapshot export**: ``--org-id X --workdir W --dump-to
      W/snapshot.jsonl.gz`` discovers the org once, live, and writes
      the unsanitized v2 stream snapshot.
   b. **Sync pipeline**: ``--from-dump W/snapshot.jsonl.gz --workdir W
      --sync`` consumes that fresh snapshot offline (no second
      discovery pass) and materializes state under the import-only
      apply guard. The API key stays in the env — --sync requires it
      for terraform plan/apply.

   If the export fails, the sync stage is NOT run and the wrapper
   returns the export's exit code.

   Pass-through ``extra_args`` are routed by a simple rule: flags the
   CLI rejects alongside ``--dump-to`` (``--fail-on-gaps``,
   ``--confirm-deletions``, ``--rebaseline``) go only to the sync
   invocation; flags that shape the snapshot itself
   (``--drift-baseline``, ``--sanitize``) go only to the export
   invocation; everything else (``--webhook-url``, ``--spec``, email
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
# Kit + reporting artifacts to archive after every run. The snapshot is
# secret-bearing; the container must be RBAC-locked (see the guide).
ARTIFACT_FILENAMES = (
    SNAPSHOT_FILENAME,
    "resources.tf",
    "imports.tf",
    "provider.tf",
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


def _redact_command(command: list[str]) -> list[str]:
    """Copy of ``command`` with credential-flag values masked for logging.

    Both argparse spellings are covered: the two-token ``--flag VALUE``
    form and the single-token ``--flag=VALUE`` form — the latter would
    otherwise log the bearer-token URL verbatim into Azure job output.
    """
    redacted = list(command)
    for index, token in enumerate(redacted):
        flag, separator, _value = token.partition("=")
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
_SYNC_ONLY_FLAGS = frozenset(
    {"--fail-on-gaps", "--confirm-deletions", "--rebaseline"}
)


def split_extra_args(extra_args: list[str]) -> tuple[list[str], list[str]]:
    """Route pass-through args to the (export, sync) invocations.

    Stage-specific flags go to exactly the stage that accepts them;
    everything else (alerting, spec, backend flags, …) goes to both.
    Both ``--flag VALUE`` and ``--flag=VALUE`` spellings are handled.
    """
    export_args: list[str] = []
    sync_args: list[str] = []
    index = 0
    while index < len(extra_args):
        token = extra_args[index]
        flag, separator, _value = token.partition("=")
        if flag in _EXPORT_ONLY_FLAGS:
            export_args.append(token)
            if _EXPORT_ONLY_FLAGS[flag] and not separator:
                index += 1
                if index < len(extra_args):
                    export_args.append(extra_args[index])
        elif flag in _SYNC_ONLY_FLAGS:
            sync_args.append(token)
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


def run_meraki2tf(
    binary: str,
    org_id: str,
    workdir: Path,
    api_key: str,
    extra_args: list[str],
) -> int:
    """Run the weekly job: snapshot export, then the offline sync.

    ``--dump-to`` and ``--sync`` are mutually exclusive at the CLI
    (argparse exit 2), so the job is two sequential invocations sharing
    the workdir; discovery runs once, in stage 1. A failed export
    short-circuits — its exit code is returned and the sync stage never
    runs against a stale snapshot. The key travels via the child env
    only (both stages need it: live discovery, then terraform
    plan/apply under --sync).
    """
    export_args, sync_args = split_extra_args(extra_args)
    stages = (
        ("snapshot export", build_export_command(binary, org_id, workdir, export_args)),
        ("sync pipeline", build_sync_command(binary, workdir, sync_args)),
    )
    env = dict(os.environ)
    env[API_KEY_ENV_VAR] = api_key
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
        if completed.returncode != 0:
            return completed.returncode
    return 0


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
    for filename in ARTIFACT_FILENAMES:
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
        description="Weekly meraki2tf DR job wrapper for Azure Automation.",
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
        "extra_args",
        nargs="*",
        help="Extra arguments passed through to meraki2tf after '--' "
        "(e.g. -- --webhook-url https://... --fail-on-gaps).",
    )
    args = parser.parse_args(argv)

    api_key = fetch_key_vault_secret(args.vault_name, args.secret_name)
    logger.info(
        "Fetched API key from vault '%s' (secret '%s').",
        args.vault_name,
        args.secret_name,
    )

    exit_code = run_meraki2tf(
        args.meraki2tf_bin, args.org_id, args.workdir, api_key, args.extra_args
    )

    # Exit 3 is --fail-on-gaps: the run completed and the artifacts are
    # fresh — it is a coverage gate, not a failure. Everything else
    # nonzero means the workdir may still hold the previous run's
    # artifacts, so archive under the -failed prefix.
    failures = archive_artifacts(
        args.storage_account, args.container, args.workdir,
        run_failed=exit_code not in (0, 3),
    )
    if failures:
        logger.error(
            "DR archive incomplete — failed artifacts: %s", ", ".join(failures)
        )
        return exit_code or 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
