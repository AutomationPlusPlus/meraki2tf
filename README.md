# meraki2tf

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/terraform-CiscoDevNet%2Fmeraki-844FBA?logo=terraform&logoColor=white)](https://registry.terraform.io/providers/CiscoDevNet/meraki)
[![Tests](https://img.shields.io/badge/tests-passing-success?logo=pytest&logoColor=white)](#contributor-architecture)
[![Coverage](https://img.shields.io/badge/coverage-100%25-success)](#contributor-architecture)
[![Typing: mypy strict](https://img.shields.io/badge/typing-mypy%20strict-blue)](#contributor-architecture)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue)](LICENSE)

Extract Cisco Meraki configurations, translate them into Terraform
structures for the [`CiscoDevNet/meraki`](https://registry.terraform.io/providers/CiscoDevNet/meraki)
provider, detect state drift, aggregate imports into state, and alert on
every outcome — from one schedulable CLI.

## Project Overview

meraki2tf discovers your Meraki organization (networks, devices, and
per-network feature configurations), writes modern declarative Terraform
`import {}` blocks for every discovered asset, runs a speculative
`terraform plan -generate-config-out=...` comparison against your local
state, and applies the missing delta. Drift, success, and unsupported
features each fire structured alerts to your configured webhook/email
channels.

**Why dynamic OpenAPI spec parsing?** The Meraki API surface changes
with every dashboard release. Instead of maintaining a brittle
hand-written table from API endpoints to Terraform resources, meraki2tf
ingests the official Meraki OpenAPI JSON document at runtime and derives
everything from its structure: which paths are resource entities, what
each one's `CiscoDevNet/meraki` resource name is, and which ordered path
parameters (`{organizationId}`, `{networkId}`, `{vlanId}`, …) compose
the comma-separated compound import IDs Terraform needs. Point the tool
at a newer spec release and new endpoints are picked up with zero code
changes; anything the provider cannot express is flagged through the
exception auditor instead of silently dropped.

## Prerequisites & Installation

- Python 3.11+
- The `terraform` CLI on your `PATH` (any version supporting `import` blocks, ≥ 1.5)
- A Meraki dashboard API key (live mode only)
- The Meraki OpenAPI spec — fetched from GitHub automatically; only
  air-gapped runs need a local copy pre-staged (see
  [OpenAPI spec resolution](#openapi-spec-resolution))

This project deliberately uses plain `venv` + `pip` — poetry and uv are
not used and not supported.

```bash
git clone git@github.com:AutomationPlusPlus/meraki2tf.git
cd meraki2tf

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

## Usage Guide

### Live Mode (cloud streaming)

The API token is read exclusively from the `MERAKI_DASHBOARD_API_KEY`
environment variable — it is never accepted as a flag, never stored,
and never logged. The SDK's native handler keeps requests inside the
10 req/s endpoint budget.

```bash
export MERAKI_DASHBOARD_API_KEY="<your-dashboard-api-key>"

meraki2tf \
  --org-id 123456 \
  --spec ./openapi.json \
  --workdir ./generated \
  --webhook-url https://hooks.example.com/meraki2tf
```

### Dump Mode (offline / air-gapped)

Run against a local JSON snapshot instead of the cloud — ideal for
air-gapped runtimes, scheduled offline parsing, and regression testing.
No API key is required.

```bash
meraki2tf \
  --spec ./openapi.json \
  --from-dump ./snapshots/org-123456.json \
  --workdir ./generated
```

Snapshot format:

```json
{
  "organizationId": "123456",
  "networks":  [ { "id": "N_1", "name": "HQ", "productTypes": ["appliance"] } ],
  "devices":   [ { "serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1", "model": "MX64" } ],
  "features": [
    {
      "apiPath": "/networks/{networkId}/appliance/vlans/{vlanId}",
      "pathValues": ["N_1", "10"],
      "payload": { "id": 10, "name": "Data" }
    }
  ]
}
```

`networks`/`devices` use the exact payload shapes the Meraki API
returns; each feature addresses itself by OpenAPI path template plus the
ordered parameter values that form its compound import ID.

Nested export layouts produced by common Meraki backup scripts are also
accepted, detected by a top-level `organizations` array:

```json
{
  "organizations": [
    {
      "info": { "id": "123456", "name": "Org" },
      "admins": [ ... ],
      "networks": [
        {
          "info": { "id": "N_1", "name": "HQ", "productTypes": ["appliance"] },
          "devices": [ ... ],
          "vlans": [ ... ],
          "firewall_l3": { "rules": [ ... ] }
        }
      ]
    }
  ]
}
```

Section names (`vlans`, `firewall_l3`, `ssids`, …) carry no API path, so
each one is resolved onto its OpenAPI endpoint dynamically — matched by
name tokens against the spec's configuration endpoints, with lexical
ties broken by comparing payload fields to the declared response
schemas. Sections that resolve to no configuration endpoint (operational
telemetry such as `clients` or `uplink_statuses`, or names the spec
cannot disambiguate) are reported in the log and skipped.

### Producing a snapshot (`--dump-to`)

The easiest way to create a `--from-dump` file is to let meraki2tf make
one for you. `--dump-to PATH` runs discovery and writes the canonical
snapshot instead of executing the Terraform pipeline:

```bash
# Export a live organization to a snapshot for later offline runs.
export MERAKI_DASHBOARD_API_KEY="<your-dashboard-api-key>"
meraki2tf --org-id 123456 --dump-to ./snapshots/org-123456.json

# Replay it later — fully offline, no API key needed for discovery.
meraki2tf --from-dump ./snapshots/org-123456.json
```

`--dump-to` also accepts `--from-dump` as its *input*, which normalizes
an existing nested export into the canonical contract:

```bash
meraki2tf --from-dump ./backup-tool-export.json --dump-to ./canonical.json
```

Add `--sanitize` to strip sensitive information for tests, demos, or
bug reports:

```bash
meraki2tf --org-id 123456 --dump-to ./demo-snapshot.json --sanitize
```

Sanitization is deterministic and preserves referential integrity:

| Data | Treatment |
| --- | --- |
| Organization/network IDs, device serials | Pseudonymized consistently everywhere (`org-0001`, `net-0007`, `dev-0042`) — cross-references and import-block generation keep working |
| Credential-shaped fields (`psk`, `secret`, `password`, `communityString`, `…token`, `…apiKey`, …) | Replaced with `**REDACTED**` |
| Names, emails, URLs, addresses, notes, tags, MACs | Stable `<kind>-<digest>` placeholders |
| URL/FQDN-shaped values under any key (RADIUS hosts, filter patterns, …) | Stable placeholders |
| IPv4 addresses and CIDRs under any key (subnets, firewall rules, …) | Deterministic fake `10.x.y.z` addresses, prefix length preserved |
| Coordinates (`lat`/`lng`) | Zeroed |
| Product types, models, feature structure | Preserved — the snapshot stays a faithful structural replica |

> **Note:** Terraform's `plan`/`apply` stages always read the real
> resources through the Meraki provider, so a sanitized snapshot
> exercises everything up to and including `imports.tf` generation;
> importing into state additionally needs real IDs and an API key.

## Configuration Options

Quick reference (each flag is described in detail below):

| Flag | Default | Purpose |
| --- | --- | --- |
| `--org-id` | — | Organization to discover (required in live mode) |
| `--spec PATH` | `./spec3.json` | Meraki OpenAPI JSON document; auto-downloaded/refreshed from GitHub |
| `--from-dump PATH` | — | Offline snapshot; switches to dump mode |
| `--dump-to PATH` | — | Export discovery output as a snapshot instead of running Terraform |
| `--sanitize` | off | Redact secrets/identity in the `--dump-to` snapshot |
| `--workdir DIR` | `generated` | Terraform execution workspace |
| `--state-file PATH` | `<workdir>/terraform.tfstate` | Terraform state to aggregate into across runs |
| `--webhook-url URL` | — | Webhook alert endpoint (repeatable) |
| `--alert-email ADDR` | — | Email alert recipient (repeatable) |
| `--smtp-host` / `--smtp-port` | `localhost` / `25` | SMTP relay for email alerts |
| `--email-from` | `meraki2tf@localhost` | Sender address for email alerts |
| `--terraform-bin` | `terraform` | Terraform executable to invoke |
| `-v`, `--verbose` | off | Debug logging (secrets always redacted) |

### Parameters in detail

**`--org-id ID`** — the Meraki organization to discover. Required in
live mode. In dump mode it may be omitted (the organization recorded in
the snapshot's `organizationId` is used) or supplied to override it.

```bash
meraki2tf --org-id 123456                          # live discovery
meraki2tf --from-dump snap.json                    # org taken from the snapshot
meraki2tf --from-dump snap.json --org-id 999999    # override the snapshot org
```

**`--spec PATH`** — the OpenAPI document driving the dynamic resource
registry. Optional; see [OpenAPI spec resolution](#openapi-spec-resolution)
for the freshness/download rules.

**`--from-dump PATH`** — run entirely offline against a JSON snapshot
(format above). No API key needed; ideal for air-gapped runs and
regression tests.

**`--dump-to PATH`** — write the discovered configuration to PATH as a
canonical snapshot and exit; the Terraform pipeline does not run. Works
from live discovery (`--org-id`) or from an existing dump
(`--from-dump`, e.g. to normalize a nested export). See
[Producing a snapshot](#producing-a-snapshot---dump-to).

**`--sanitize`** — redact secrets and pseudonymize identifying details
in the snapshot written by `--dump-to`. Deterministic; structural IDs
stay internally consistent so the sanitized snapshot remains fully
processable.

**`--workdir DIR`** — the Terraform execution workspace. meraki2tf
writes `provider.tf` and `imports.tf` here, and Terraform adds
`generated_resources.tf` plus its `.terraform/` directory. Safe to
delete between runs — everything in it is regenerated. Use one workdir
per organization if you manage several.

**`--state-file PATH`** — where Terraform state lives; see
[Terraform state management](#terraform-state-management).

**`--webhook-url URL`** *(repeatable)* — HTTP endpoint(s) receiving
each alert as a JSON POST (`Content-Type: application/json`). Repeat
the flag to fan out to several receivers:

```bash
meraki2tf --org-id 123456 \
  --webhook-url https://hooks.example.com/netops \
  --webhook-url https://hooks.example.com/audit
```

**`--alert-email ADDR`** *(repeatable)* — email recipient(s) for
alerts. Delivery goes through the relay configured with
**`--smtp-host`** / **`--smtp-port`**, with the sender set by
**`--email-from`**:

```bash
meraki2tf --org-id 123456 \
  --alert-email netops@example.com --alert-email sec@example.com \
  --smtp-host smtp.example.com --smtp-port 587 \
  --email-from meraki2tf@example.com
```

**`--terraform-bin PATH`** — alternative Terraform executable (e.g. a
pinned binary or `tofu`):

```bash
meraki2tf --org-id 123456 --terraform-bin /opt/terraform-1.9/terraform
```

**`-v` / `--verbose`** — DEBUG logging with logger origins and full
terraform output, including the complete drift diff. Credentials are
redacted at every level, so verbose is safe for shared logs.

### Terraform state management

State is stored via Terraform's **local backend** at the path anchored
in the generated `provider.tf`:

- **Default**: `terraform.tfstate` inside `--workdir` (e.g.
  `generated/terraform.tfstate`).
- **Custom location**: pass `--state-file /path/to/existing.tfstate` to
  aggregate into a state file you already have — parent directories are
  created as needed, and if the file doesn't exist Terraform creates it
  on the first apply.

Consecutive runs are incremental: before generating `imports.tf`,
meraki2tf reads the state file and **skips every resource address it
already tracks**, so a weekly run only imports newly discovered assets
instead of regenerating state from zero. Newly appeared drift on
already-tracked resources still surfaces through the speculative plan
and fires `DRIFT_DETECTED`.

```bash
# Monday: first run creates /var/lib/meraki2tf/org-123456.tfstate
meraki2tf --org-id 123456 --state-file /var/lib/meraki2tf/org-123456.tfstate

# Following Mondays: same command; only the delta is imported,
# existing state is updated in place.
```

Treat the state file like any Terraform state: back it up, and never
commit it (the repository `.gitignore` already excludes `*.tfstate`).

### OpenAPI spec resolution

You normally never manage the spec by hand:

- **Spec file exists** (at `--spec PATH`, or `./spec3.json` when the
  flag is omitted): its `info.version` is compared against the latest
  release in the [`meraki/openapi`](https://github.com/meraki/openapi)
  GitHub repository; when outdated the file is refreshed in place.
- **Spec file missing**: the latest release is downloaded from GitHub
  to that path automatically.
- **GitHub unreachable** (air-gapped/offline runs): an existing local
  spec is used as-is with a warning; if there is no local copy either,
  the run fails with a clear error — pre-stage `spec3.json` for
  fully offline environments.

### Logging & secret isolation

Normal runs log clean INFO lines; `--verbose` switches to DEBUG with
logger origins and full terraform output. A mandatory redaction filter
scrubs `Authorization` / `X-Cisco-Meraki-API-Key` header values and the
raw token from **every** log record, so verbose mode never compromises
credentials. The generated `provider.tf` is credential-free: the
Terraform provider reads `MERAKI_DASHBOARD_API_KEY` from the process
environment itself.

### Alerting events

| Event | Trigger |
| --- | --- |
| `DRIFT_DETECTED` | The speculative plan found differences between discovery and state (payload carries the diff) |
| `RUN_SUCCESS` | State aggregation completed flawlessly |
| `UNSUPPORTED_FEATURE_FLAGGED` | A discovered asset cannot be mapped to a Terraform resource |
| `PROCESSING_FAULT` | A critical pipeline failure (payload carries the failing stage) |

### Scheduled (cron) execution

The CLI is non-interactive end to end and reports outcome via exit code
(0 clean, 1 fault), so a weekly headless run is one crontab line:

```cron
# Every Monday 06:00 — stream live, alert to the NetOps webhook.
0 6 * * 1 cd /opt/meraki2tf && . .venv/bin/activate && \
  MERAKI_DASHBOARD_API_KEY=$(cat /etc/meraki2tf/token) \
  meraki2tf --org-id 123456 --spec ./openapi.json \
  --webhook-url https://hooks.example.com/meraki2tf >> /var/log/meraki2tf.log 2>&1
```

## Contributor Architecture

Package layout and pipeline design live in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the binding project
contract is [`CLAUDE.md`](CLAUDE.md).

```bash
# One-time setup (inside the venv)
pip install -r requirements.txt
pre-commit install          # hygiene + flake8 + mypy on every commit

# The full gate — lint, strict typing, tests with coverage
tox

# Individual checks
flake8 src/ tests/
mypy src/
pytest --cov=src --cov-report=term-missing
pre-commit run --all-files
```

House rules: near-100% test coverage on parsing/translation/alerting
engines (fixtures only, no network sockets), signed atomic commits on
scoped feature branches, and no poetry/ruff/uv anywhere in the
toolchain.
