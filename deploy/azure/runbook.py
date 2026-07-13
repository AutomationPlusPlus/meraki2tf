"""Azure Automation wrapper for the weekly meraki2tf DR job.

Runs on a Hybrid Runbook Worker (or any Azure compute with a managed
identity) and glues three things together without ever putting the
Meraki API key on disk or on a command line:

1. Fetch the dashboard API key from Azure Key Vault using the host's
   managed identity and export it as ``MERAKI_DASHBOARD_API_KEY`` for
   the child process only.
2. Execute ``meraki2tf --sync`` in the persistent workdir, writing the
   unsanitized snapshot alongside the kit.
3. Archive the run's artifacts (snapshot, kit, coverage, runbook) to a
   locked-down Blob container so the DR kit survives the loss of the
   worker itself. The Terraform state is deliberately NOT uploaded: it
   is secret-bearing and fully re-materializable from the kit.

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
SNAPSHOT_FILENAME = "snapshot.json"
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
    """Copy of ``command`` with credential-flag values masked for logging."""
    redacted = list(command)
    for index, token in enumerate(redacted[:-1]):
        if token in _CREDENTIAL_FLAGS:
            redacted[index + 1] = "<redacted>"
    return redacted


def run_meraki2tf(
    binary: str,
    org_id: str,
    workdir: Path,
    api_key: str,
    extra_args: list[str],
) -> int:
    """Run the weekly sync. The key travels via the child env only."""
    command = [
        binary,
        "--org-id",
        org_id,
        "--sync",
        "--workdir",
        str(workdir),
        "--dump-to",
        str(workdir / SNAPSHOT_FILENAME),
        *extra_args,
    ]
    env = dict(os.environ)
    env[API_KEY_ENV_VAR] = api_key
    # Pass-through args can carry bearer-credential values (a Slack/Teams
    # --webhook-url whose path IS the token); Azure job-output history is
    # readable by a much broader RBAC set than Key Vault, so redact the
    # value that follows any credential-shaped flag before logging.
    logger.info("Running: %s", " ".join(_redact_command(command)))
    completed = subprocess.run(command, env=env, check=False)
    logger.info("meraki2tf exited with code %d", completed.returncode)
    return completed.returncode


def upload_blob(
    storage_account: str,
    container: str,
    blob_name: str,
    path: Path,
    token: str,
) -> None:
    """PUT one file as a block blob using the managed-identity token."""
    url = (
        f"https://{storage_account}.blob.core.windows.net/"
        f"{container}/{urllib.parse.quote(blob_name)}"
    )
    data = path.read_bytes()
    request = urllib.request.Request(
        url,
        data=data,
        method="PUT",
        headers={
            "Authorization": f"Bearer {token}",
            "x-ms-version": BLOB_API_VERSION,
            "x-ms-blob-type": "BlockBlob",
            "Content-Length": str(len(data)),
        },
    )
    with urllib.request.urlopen(request, timeout=120):
        pass
    logger.info("Archived %s -> %s/%s", path.name, container, blob_name)


def archive_artifacts(
    storage_account: str, container: str, workdir: Path
) -> list[str]:
    """Upload every present artifact under a per-run prefix.

    Returns the artifacts that failed to upload (empty on full success).
    All uploads are attempted even if one fails.
    """
    token = acquire_token(STORAGE_RESOURCE)
    run_prefix = datetime.now(timezone.utc).strftime("runs/%Y-%m-%dT%H%M%SZ")
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

    failures = archive_artifacts(args.storage_account, args.container, args.workdir)
    if failures:
        logger.error(
            "DR archive incomplete — failed artifacts: %s", ", ".join(failures)
        )
        return exit_code or 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
