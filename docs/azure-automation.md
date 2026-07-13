# Running meraki2tf Weekly via Azure Automation

This guide deploys the weekly DR job (`meraki2tf --sync`) on Azure
Automation with the Meraki API key in Azure Key Vault and every run's
artifacts archived to geo-redundant Blob Storage. The primary path is a
**Hybrid Runbook Worker**; an **Azure Container Apps Job** alternative
is covered at the end.

## Why not the Azure-hosted sandbox?

Azure Automation can execute Python runbooks in its own cloud sandbox,
but four properties of this tool rule that out:

| Requirement | Cloud sandbox |
| --- | --- |
| Python ≥ 3.11 (`pyproject.toml`) | Sandbox runbooks top out below 3.11, and you cannot bring your own interpreter |
| `terraform` binary on PATH (every `--sync` run shells out to `terraform init/plan/apply`) | Only Python packages can be imported into the sandbox — no system binaries |
| Persistent workdir between runs (`resources.tf` baseline + `meraki2tf.tfstate` drive delta imports and drift detection) | Sandboxes are ephemeral; a fresh filesystem every job |
| POSIX `chmod 0600` on the snapshot and state | Sandboxes are Windows-based; the owner-only guarantee is a no-op |

A Hybrid Runbook Worker keeps everything you want from Azure Automation
— the schedule, job history, failure alerting, the managed identity —
while the code executes on a Linux VM where all four requirements hold.

## Architecture

```
Azure Automation (schedule, job history)
        │  triggers weekly
        ▼
Hybrid Runbook Worker (Linux VM, persistent disk)
  deploy/azure/runbook.py
        │ 1. managed identity ──► Key Vault ──► MERAKI_DASHBOARD_API_KEY (env only)
        │ 2. meraki2tf --sync --workdir /var/lib/meraki2tf --dump-to snapshot.json
        │ 3. artifacts ──► Blob container (RBAC-locked, GRS)
        ▼
Alerts (webhook / email) fire from meraki2tf itself on drift,
coverage gaps, deletions, faults, and clean runs.
```

The wrapper never writes the API key to disk or a command line: it is
fetched from Key Vault at run time and injected into the child process
environment only, matching the tool's own env-var contract.

## What you provision

- **Automation account** with a weekly schedule.
- **Linux VM** (any small size; B2s is plenty) registered as a Hybrid
  Runbook Worker, with a **system-assigned managed identity**.
- **Key Vault** holding one secret: the Meraki dashboard API key.
- **Storage account** (GRS recommended) with one private container for
  run artifacts. The unsanitized snapshot lands here — see
  [Snapshot security posture](#snapshot-security-posture).

## Step 1 — Prepare the worker VM

```bash
# Python 3.11+ venv with meraki2tf
sudo mkdir -p /opt/meraki2tf /var/lib/meraki2tf
python3 -m venv /opt/meraki2tf/.venv
/opt/meraki2tf/.venv/bin/pip install --upgrade pip
/opt/meraki2tf/.venv/bin/pip install /path/to/meraki2tf   # or from your registry

# Terraform on PATH (pin the version you validate with) — verify the
# download against HashiCorp's published SHA256SUMS so a compromised CDN
# or TLS-interception box cannot slip in a trojaned binary that would
# then run every --sync job with the dashboard API key in its env.
ver=1.9.8; tmp=$(mktemp -d)
curl -fsSLo "$tmp/terraform.zip" \
  "https://releases.hashicorp.com/terraform/$ver/terraform_${ver}_linux_amd64.zip"
curl -fsSLo "$tmp/SHA256SUMS" \
  "https://releases.hashicorp.com/terraform/$ver/terraform_${ver}_SHA256SUMS"
(cd "$tmp" && grep "terraform_${ver}_linux_amd64.zip" SHA256SUMS \
  | sed "s#terraform_${ver}_linux_amd64.zip#$tmp/terraform.zip#" | sha256sum -c -)
sudo unzip "$tmp/terraform.zip" -d /usr/local/bin && rm -rf "$tmp"
```

`/var/lib/meraki2tf` is the persistent workspace. It accumulates the
`resources.tf` baseline across weeks — do not put it on ephemeral/temp
storage, and keep it out of any cleanup jobs. Losing it does not lose
data (the kit is re-derivable) but the next run would regenerate it from
scratch. **State durability is better handled by a remote backend** (see
[Step 3b](#step-3b--terraform-state-backend-recommended)): with
`--state-backend azurerm` the Terraform state lives in Blob Storage —
durable, locked, and independent of the VM — so even a total worker loss
does not force a full re-import.

Register the VM as a Hybrid Runbook Worker (extension-based):

```bash
az automation hrwg create --automation-account-name aa-netops \
  --resource-group rg-netops --name meraki2tf-workers
az automation hrwg hrw create --automation-account-name aa-netops \
  --resource-group rg-netops --hybrid-runbook-worker-group-name meraki2tf-workers \
  --name worker-1 --vm-resource-id "$(az vm show -g rg-netops -n vm-meraki2tf --query id -o tsv)"
```

## Step 2 — Key Vault

```bash
# Read the key from a file (or stdin) rather than --value, so the
# org-admin token never lands in shell history or the process list on a
# shared jump host. Create the file 0600 and delete it afterwards.
az keyvault secret set --vault-name kv-netops \
  --name meraki-dashboard-api-key --file ./dashboard-api-key.txt
# (or interactively:  az keyvault secret set ... --file /dev/stdin  )

# Grant ONLY secret-read to the VM's managed identity (RBAC mode):
az role assignment create \
  --assignee "$(az vm show -g rg-netops -n vm-meraki2tf --query identity.principalId -o tsv)" \
  --role "Key Vault Secrets User" \
  --scope "$(az keyvault show --name kv-netops --query id -o tsv)"
```

Rotating the Meraki key is now a Key Vault update; no VM or runbook
changes needed.

## Step 3 — Storage for run artifacts

```bash
az storage account create -g rg-netops -n stmerakidr \
  --sku Standard_GRS --min-tls-version TLS1_2 \
  --allow-shared-key-access false --allow-blob-public-access false
az storage container create --account-name stmerakidr \
  --name meraki2tf-dr --auth-mode login

az role assignment create \
  --assignee "$(az vm show -g rg-netops -n vm-meraki2tf --query identity.principalId -o tsv)" \
  --role "Storage Blob Data Contributor" \
  --scope "$(az storage account show -g rg-netops -n stmerakidr --query id -o tsv)/blobServices/default/containers/meraki2tf-dr"
```

After every run the wrapper uploads, under a `runs/<timestamp>/`
prefix: `snapshot.json`, `resources.tf`, `imports.tf`, `provider.tf`,
`coverage.json`, `coverage.txt`, and `runbook.md`. The Terraform state
is deliberately **not** placed in this artifact prefix — it is
secret-bearing. With the local backend it stays `0600` on the worker and
is re-materializable from the kit; with the azurerm backend (Step 3b) it
lives in its own container, encrypted and RBAC-locked, and Terraform
manages it directly.

## Step 3b — Terraform state backend (recommended)

Give Terraform a dedicated, private container for state and let the
`azurerm` backend manage it. This is durable (GRS), locked (blob-lease
state locking prevents two runs colliding), and off-box:

```bash
az storage container create --account-name stmerakidr \
  --name tfstate --auth-mode login
# The job identity already has Storage Blob Data Contributor on the
# account from Step 3; that covers the tfstate container too.
```

Then pass the backend through the wrapper's pass-through flags (after
`--`). The managed identity authenticates via AAD — no storage key on
disk or in a flag:

```bash
# In the runbook/job environment (the wrapper already sets these style
# vars for the MSI; ARM_USE_MSI lets terraform reuse the VM identity):
export ARM_USE_MSI=true
export ARM_SUBSCRIPTION_ID=<sub> ARM_TENANT_ID=<tenant>

python3 runbook.py ... -- \
  --sync --webhook-url https://hooks.example.com/meraki2tf --fail-on-gaps \
  --state-backend azurerm \
  --backend-config use_azuread_auth=true \
  --backend-config resource_group_name=rg-netops \
  --backend-config storage_account_name=stmerakidr \
  --backend-config container_name=tfstate \
  --backend-config key=org-123456.tfstate
```

meraki2tf refuses credential-shaped `--backend-config` keys, so the
storage credential can only come from the environment/identity — keeping
the tool's no-secret-on-the-command-line contract intact. Use one
distinct `key=` per organization if you protect several.

### Snapshot security posture

The unsanitized snapshot is the crown jewels of the DR story: it holds
the secrets Terraform cannot carry (RADIUS shared secrets, SNMP v3
passphrases, PSKs, …) and is what `--replay-gaps --confirm` reads
during a real recovery. It must live off the worker — a snapshot that
only exists on the VM does not survive the disaster it exists for.

Protection here is **access control + Azure server-side encryption**:
shared-key access disabled, public access disabled, RBAC grants limited
to the job identity and break-glass operators, GRS for regional loss.
On the VM itself meraki2tf keeps the snapshot (and, with the local
backend, the state) `0600`; with the azurerm backend the state is held
in Blob under the same account controls instead. If your
threat model requires the blob copy to be ciphertext even against a
storage-plane compromise, add client-side encryption in the wrapper
(e.g. an `openssl`/`age` step with a Key Vault–held key) before upload
— the tool does not need to change for that. Consider also a retention
policy: each weekly prefix is a full secret-bearing snapshot, so prune
old runs deliberately rather than never.

## Step 4 — The runbook

Import [`deploy/azure/runbook.py`](../deploy/azure/runbook.py) as a
Python runbook in the Automation account and target the hybrid worker
group. It is stdlib-only (no Azure SDK needed on the worker). The
runbook parameters map to:

```bash
# Prefer MERAKI2TF_WEBHOOK_URL (set in the job's environment) over a
# --webhook-url pass-through arg: the URL path may itself be a bearer
# token, and the wrapper logs the child argv to Azure job history (which
# a broader RBAC set can read than Key Vault). The wrapper redacts
# --webhook-url values it does log, but keeping the URL out of argv
# entirely is stronger.
python3 runbook.py \
  --vault-name kv-netops \
  --org-id 123456 \
  --workdir /var/lib/meraki2tf \
  --storage-account stmerakidr \
  --meraki2tf-bin /opt/meraki2tf/.venv/bin/meraki2tf \
  -- --fail-on-gaps
```

Everything after `--` is passed straight through to meraki2tf, so the
full flag surface (`--alert-email`, `--confirm-deletions` runs,
`--spec`, …) stays available. The wrapper exits with meraki2tf's own
exit code (0 clean, 1 fault, 3 coverage gaps) and forces nonzero if
artifact archival fails — wire your Automation job alerts to nonzero
completions.

Attach a weekly schedule:

```bash
az automation schedule create --automation-account-name aa-netops \
  -g rg-netops --name weekly-monday-0600 --frequency Week --interval 1 \
  --start-time 2026-07-06T06:00:00+00:00
```

then link the runbook to the schedule and the `meraki2tf-workers`
group in the portal (or via `az automation job-schedule create`).

## Alternative: Azure Container Apps Job

If you would rather not manage a VM, the same wrapper runs as a
scheduled Container Apps Job using
[`deploy/azure/Dockerfile`](../deploy/azure/Dockerfile):

- **Schedule:** the job's cron trigger (e.g. `0 6 * * 1`) replaces the
  Automation schedule.
- **Persistent workspace:** mount an Azure Files share at
  `/var/lib/meraki2tf`. This is mandatory — the container filesystem is
  ephemeral and the workspace must survive between runs.
- **Identity:** assign the job a managed identity with the same two
  role assignments as above. The wrapper auto-detects the Container
  Apps identity endpoint (`IDENTITY_ENDPOINT`) and falls back to VM
  IMDS, so the same script serves both paths.
- **Caveat — file permissions:** Azure Files (SMB) does not honor
  `chmod 0600`, so the owner-only guarantee on the snapshot and state
  is degraded to the share's own access control; meraki2tf logs a
  warning when it detects this. If that guarantee matters to you, the
  Hybrid Worker path with a local disk is the stronger choice.
- **Trade-off:** no VM to patch, but you own a container image (and
  its Terraform version) and rebuild it for every meraki2tf upgrade.

## During an actual disaster

The worker VM may be gone; the Blob container is the recovery source.

1. Pull the latest `runs/<timestamp>/` prefix from
   `stmerakidr/meraki2tf-dr` onto a machine with terraform and
   meraki2tf installed.
2. Follow the recovered `runbook.md` — it is regenerated every run and
   carries the exact rebuild order, the coverage gaps that need manual
   work, and the secret re-entry pointers.
3. `--rebuild --confirm` re-creates what Terraform can;
   `--replay-gaps --confirm` (fed by the recovered snapshot) restores
   what it cannot. Both are preview-first: run each without
   `--confirm` and read the output before executing.

See the [Disaster Recovery](../README.md#disaster-recovery) section of
the README for the full restore flows.
