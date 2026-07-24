# Usage & Configuration

The complete flag-by-flag guide: run modes, snapshots, the
config file, Terraform state backends, alert channel settings,
and spec resolution. Part of the [meraki2tf](../README.md) docs.

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

When `MERAKI_DASHBOARD_API_KEY` is not set, the run stops after
generating `imports.tf` — the `terraform plan` comparison is skipped
(the Terraform provider needs a token to read live resources) and the
run still exits 0. Set the variable if you also want drift comparison
and the generated `resources.tf` baseline from a dump-mode run.

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
          "devices": [
            { "serial": "Q2AB-CDEF-GHIJ", "model": "MS220" },
            {
              "info": { "serial": "Q2XY-1234-5678", "model": "MS220" },
              "switch_ports": [ { "portId": "1", "name": "Uplink" } ]
            }
          ],
          "vlans": [ ... ],
          "firewall_l3": { "rules": [ ... ] }
        }
      ]
    }
  ]
}
```

Device entries come in two shapes: a flat raw device payload, or a
structured `{ "info": …, "<section>": … }` object whose extra sections
(`switch_ports`, `management_interface`, …) resolve onto serial-scoped
endpoints — capturing per-device configuration alongside the device
itself.

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

Snapshot paths ending in `.jsonl` or `.jsonl.gz` select the **v2 stream
format** — one object per line, gzip-compressed when the name says so
(~10–20× smaller; the right choice for large organizations and for
weekly snapshot rotation). Reading auto-detects the format by content,
so both formats work everywhere `--from-dump` does:

```bash
meraki2tf --org-id 123456 --dump-to ./snapshots/2026-07-10.jsonl.gz
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
| Credential-shaped fields (`psk`, `secret`, `password`, `passphrase`, `communityString`, `…token`, `…apiKey`, `authKey`, `sharedKey`, `v3AuthPass`/`v3PrivPass`, `passcode`, `…Pin`, `privateKey`, …) plus any value carrying a PEM private-key block | Replaced with `**REDACTED**` |
| Names, emails, URLs, addresses, notes, tags, MACs, phone numbers, serials | Stable `<kind>-<digest>` placeholders |
| URL/FQDN-shaped values under any key (RADIUS hosts, filter patterns, …) | Stable placeholders |
| IPv4 addresses and CIDRs under any key (subnets, firewall rules, …) | Deterministic fake `10.x.y.z` addresses, prefix length preserved |
| Coordinates (`lat`/`lng`) | Zeroed |
| Product types, models, feature structure | Preserved — the snapshot stays a faithful structural replica |

> **Note:** Terraform's `plan` stage always reads the real resources
> through the Meraki provider, so a sanitized snapshot exercises
> everything up to and including `imports.tf` generation; the plan
> comparison additionally needs real IDs and an API key.

### Snapshot-diff drift detection (`--drift-baseline`)

Comparing two snapshots answers "what changed in Meraki?" directly —
API-to-API, attribute-level, in seconds, with **no terraform read
pass**. It also sees drift classes the plan comparison never could:
objects the provider cannot express and secret-valued attributes the
kit deliberately leaves unmanaged.

```bash
# The scheduled weekly shape: export this week's snapshot and diff it
# against last week's. Real differences fire DRIFT_DETECTED
# (details.origin = "snapshot-diff"); the digest names the changed
# attributes, never their values.
meraki2tf --org-id 123456 \
  --dump-to snapshots/this-week.jsonl.gz \
  --drift-baseline snapshots/last-week.jsonl.gz \
  --webhook-url https://alerts.example/dr

# Also works inside the full pipeline (any mode):
meraki2tf --from-dump snapshots/this-week.jsonl.gz \
  --drift-baseline snapshots/last-week.jsonl.gz
```

Noise control is spec-driven: only attributes that appear in a PUT/POST
request schema are compared ("if you can't write it, it isn't
configuration"), identity-keyed lists compare order-insensitively while
bare arrays (firewall rules) stay ordered, and an attribute that
appears fleet-wide across every modified asset of one endpoint is
suppressed as a Meraki API rollout rather than operator drift.

## Configuration Options

Quick reference (each flag is described in detail below):

| Flag | Default | Purpose |
| --- | --- | --- |
| `--version` | — | Print the installed meraki2tf version and exit |
| `--list-orgs` | — | List every organization the API key can see (ID + name) and exit — the way to find `--org-id` |
| `--config PATH` | — | TOML file of recurring settings (CLI > file > default); DR actions, confirmations, and credentials refused |
| `--org-id` | — | Organization to discover (required in live mode); repeat for sequential multi-org fan-out |
| `--spec PATH` | `./spec3.json` | Meraki OpenAPI JSON document; auto-downloaded/refreshed from GitHub |
| `--from-dump PATH` | — | Offline snapshot; switches to dump mode |
| `--dump-to PATH` | — | Export discovery output as a snapshot instead of running Terraform |
| `--sanitize` | off | Redact secrets/identity in the `--dump-to` snapshot |
| `--drift-baseline PATH` | — | Prior snapshot to diff the fresh discovery against — attribute-level drift in seconds, no terraform read pass |
| `--rebuild` | off | Disaster recovery: preview a rebuild apply of the workdir artifacts |
| `--heal` | off | Disaster recovery: preview recreating snapshot objects missing from the same live org (additive-only) |
| `--only [TYPE:]PATTERN` | — | Selective scope, repeatable. With `--heal`: restrict the heal to missing objects matching a name/ID glob (e.g. `network:Branch-07`, `ssid:Guest*`); dependencies auto-included. With `--dump-to`: selective backup — scope discovery to the matching networks (`network:PATTERN` only) and write a partial snapshot (usable by `--heal`; refused by `--restore`/`--replay-gaps`/`--drift-baseline`) |
| `--replay-gaps` | off | Disaster recovery: preview restoring objects/secrets Terraform can't rebuild, from an unsanitized snapshot |
| `--restore` | off | Disaster recovery: preview a full-organization rebuild from a snapshot into `--target-org` |
| `--target-org ORG_ID` | — | The (fresh/scratch) organization `--restore` writes into; never the snapshot's source org |
| `--serial-map PATH` | — | JSON old→new device-serial map for hardware-loss restores |
| `--skip-claims` | off | Drill mode for `--restore`: device claiming + device-scoped features become drill-skipped verdicts |
| `--wipe-org ORG_ID` | — | Drill teardown: delete every network then the org; refused for any org with claimed devices |
| `--wipe-org-name NAME` | — | Second factor for `--wipe-org`: must match the organization's exact name |
| `--confirm` | off | Escalate `--rebuild`, `--heal`, `--replay-gaps`, `--restore`, or `--wipe-org` from preview to a real write against Meraki |
| `--rebaseline` | off | Accept current reality: discard `resources.tf` so this run regenerates the baseline |
| `--sync` | off | DR automation: guarded import-only auto-apply + modified-object baseline regeneration |
| `--confirm-deletions` | off | Human confirmation to remove Meraki-deleted resources from the kit and state |
| `--fail-on-gaps` | off | Exit 3 when unsupported (uncoverable) objects exist — CI coverage gate |
| `--workdir DIR` | `generated` | Terraform execution workspace |
| `--state-file PATH` | `<workdir>/meraki2tf.tfstate` | Terraform state to aggregate into across runs (local backend only) |
| `--state-backend {local,azurerm,s3,gcs}` | `local` | Where Terraform keeps state; the remote backends store it in Azure Blob Storage / Amazon S3 / Google Cloud Storage |
| `--backend-config KEY=VALUE` | — | Remote-backend setting (repeatable); e.g. azurerm `storage_account_name`, `container_name`, `key` |
| `--backend-config-file PATH` | — | File of remote-backend settings (composes with `--backend-config`) |
| `--webhook-url URL` | — | Webhook alert endpoint (repeatable) |
| `--webhook-format {json,slack,teams}` | `json` | Webhook body shape: raw event JSON, Slack incoming-webhook text, or a Teams Workflows Adaptive Card |
| `--pagerduty` | off | Page WARNING/CRITICAL events via PagerDuty Events API v2 (routing key from `MERAKI2TF_PAGERDUTY_ROUTING_KEY`) |
| `--alert-email ADDR` | — | Email alert recipient (repeatable); authenticated relays via `MERAKI2TF_SMTP_USERNAME`/`MERAKI2TF_SMTP_PASSWORD` |
| `--smtp-host` / `--smtp-port` | `localhost` / `25` | SMTP relay for email alerts |
| `--email-from` | `meraki2tf@localhost` | Sender address for email alerts |
| `--terraform-bin` | `terraform` | Terraform executable to invoke |
| `-v`, `--verbose` | off | Debug logging (secrets always redacted) |
| `--log-format {text,json}` | `text` | Console log output; `json` emits one JSON object per line for log aggregators |

### Config file (`--config`)

Recurring settings — everything a scheduled job would otherwise pass as
flags — can live in a TOML file, so the weekly DR invocation shrinks to
one flag:

```toml
# /etc/meraki2tf/meraki2tf.toml
org-id = "123456"
workdir = "/var/lib/meraki2tf/dr-kit"
sync = true
fail-on-gaps = true
state-backend = "azurerm"

[backend-config]
storage_account_name = "storacct"
container_name = "tfstate"
key = "org.tfstate"
```

```bash
meraki2tf --config /etc/meraki2tf/meraki2tf.toml
```

Keys mirror the long flag names (`org-id`, `state-backend`,
`webhook-url` — repeatable flags take a string or an array of strings;
`backend-config` is a table). Precedence is strictly **command line >
config file > built-in default**: a file value applies only where the
flag was not typed. A ready-to-copy annotated sample lives in
[`examples/config.toml`](../examples/config.toml), alongside
`--backend-config-file` samples for each remote state backend.

Two classes of keys are refused in the file, by design:

- **Disaster-recovery actions and confirmations** (`--rebuild`,
  `--heal`, `--replay-gaps`, `--restore`, `--wipe-org`, `--confirm`,
  `--confirm-deletions`, `--rebaseline`, and their scoped companions).
  A write to Meraki — or a baseline-destroying acceptance — must be
  typed by a human for that specific invocation, never inherited from a
  long-lived file.
- **Credentials**, exactly as on the command line: credential-shaped
  `backend-config` keys are rejected, and the API key is only ever read
  from `MERAKI_DASHBOARD_API_KEY`. The config file never holds a
  secret, so it needs no special file permissions.

### Parameters in detail

**`--list-orgs`** — standalone discovery helper: print the ID and name
of every organization the `MERAKI_DASHBOARD_API_KEY` key can see, then
exit. Read-only (one `getOrganizations` call), touches nothing on disk,
and refuses to be combined with any other mode or target flag. This is
the fastest way to find the `--org-id` value.

**`--config PATH`** — TOML file of recurring settings; see
[Config file](#config-file---config) above.

**`--org-id ID`** *(repeatable)* — the Meraki organization to discover
(find it with `--list-orgs`). Required in live mode. In dump mode it
may be omitted (the organization recorded in the snapshot's
`organizationId` is used) or supplied to override it.

Repeat the flag to fan out over several organizations in one
invocation (config-file key: `org-ids = ["111222", "333444"]`). The
organizations run **sequentially**; each gets its own sub-workdir
(`<workdir>/<org-id>/`) and therefore its own kit, coverage manifest,
and local state, and a failing organization never stops the remaining
ones. The final exit code is the most severe per-org outcome
(1 > 4 > 3 > 5 > 0). Constraints:

- Pipeline modes only (default read-only and `--sync`). Snapshot
  modes (`--from-dump`, `--dump-to`, `--drift-baseline`) and DR
  actions stay single-organization — run one invocation per org.
- `--state-file` cannot be combined with multiple organizations.
- A remote `--state-backend` requires an `{org-id}` placeholder in
  the state address so state objects never collide:

```bash
meraki2tf --org-id 111222 --org-id 333444 \
  --state-backend s3 \
  --backend-config bucket=example-terraform-state \
  --backend-config 'key=meraki2tf/{org-id}.tfstate'
```

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

**`--rebuild`** — disaster-recovery action: run `terraform init` +
`terraform plan` over the artifacts already in `--workdir` and show
what an apply would do. Read-only on its own; requires
`MERAKI_DASHBOARD_API_KEY` and a workdir populated by a previous run.
Cannot be combined with `--from-dump`/`--dump-to`. See
[Disaster Recovery](DR-GUIDE.md#disaster-recovery).

**`--heal`** — disaster-recovery action: recreate snapshot objects that
are missing from the live organization (accidental deletions) — the
**same** organization the `--from-dump` snapshot was captured from
(`--org-id` must match its source org). Additive-only: surviving
objects are never modified; a deleted parent's children are rewired to
its new ID. Requires an unsanitized snapshot and
`MERAKI_DASHBOARD_API_KEY` (even the preview performs a live discovery
to decide what is missing). Read-only preview on its own; `--confirm`
executes with a crash-resumable journal. See
[Healing accidental deletions](DR-GUIDE.md#healing-accidental-deletions---heal).

**`--replay-gaps`** — disaster-recovery action: restore the pieces
Terraform cannot rebuild — objects the provider can't express, plus the
secret attributes the kit deliberately never carries (SSID PSKs, SNMP
community strings, …) — by replaying them from an unsanitized
`--from-dump` snapshot straight to the Meraki API (via the SDK, not
`terraform`). Read-only preview on its own; requires
`MERAKI_DASHBOARD_API_KEY` only when you add `--confirm`. Run it *after*
`--rebuild --confirm` has restored the Terraform-covered resources;
network IDs are remapped to the rebuilt tenant by name. Secrets are read
from the snapshot at execution time and held only in memory. See
[Restoring what Terraform can't rebuild](DR-GUIDE.md#restoring-what-terraform-cant-rebuild---replay-gaps).

**`--confirm`** — escalates a disaster-recovery action — `--rebuild`
(a `terraform apply` of the kit), `--heal` (recreates deleted objects
in the same org), `--replay-gaps` (SDK writes from the snapshot),
`--restore` (full-organization rebuild into `--target-org`), or
`--wipe-org` (drill-org teardown) — from a read-only preview to a real
write. These five disaster-recovery actions are the *only* ways
meraki2tf ever changes Meraki; every other invocation — including every
scheduled run — is read-only toward your organization.

**`--rebaseline`** — discard the accumulated `resources.tf`
configuration baseline so this run regenerates it from currently
discovered data. Use after reviewing a `DRIFT_DETECTED` alert whose
changes are legitimate. Refused while the state file tracks resources —
their configuration cannot be regenerated (they are skipped from
`imports.tf`, and Terraform only generates config for import targets),
so discarding it would make the plan propose destroying them.

**`--sync`** — opt-in DR automation for the scheduled job. After the
speculative plan, auto-apply it **only** when it is verified as 100%
imports (0 to add, 0 to change, 0 to destroy) — imports only write
state, so Meraki is never touched. Mutating plans abort with a
`DRIFT_DETECTED` alert (`apply_aborted: true`); purely *modified*
objects get their HCL baseline regenerated to mirror current Meraki
before the guarded apply. Requires `MERAKI_DASHBOARD_API_KEY` and
refuses to start without it. See
[Scheduled DR automation](DR-GUIDE.md#scheduled-dr-automation---sync).

**`--confirm-deletions`** — the human side of the deletion contract.
Deletions detected in Meraki are alert-only until you review them and
re-run with this flag, which removes the confirmed resources from
`resources.tf` and the Terraform state (local surgery — Meraki is
untouched).

**`--fail-on-gaps`** — exit with code 3 when the run discovers objects
Terraform cannot rebuild, so CI and schedulers can gate on full
coverage. The gap list is in `coverage.json`/`coverage.txt` and in
every success/drift notification.

**`--workdir DIR`** — the Terraform execution workspace. meraki2tf
writes `provider.tf`, `imports.tf`, and the accumulated `resources.tf`
here, and Terraform adds its `.terraform/` directory. This is your
disaster-recovery kit — back it up. Use one workdir per organization if
you manage several.

**`--state-file PATH`** — where Terraform state lives with the default
local backend; see [Terraform state management](#terraform-state-management).
Ignored/refused with a remote `--state-backend` (the remote backend
addresses its own state, e.g. the azurerm `key` setting).

**`--state-backend {local,azurerm,s3,gcs}`** — the Terraform state
backend. `local` (default) keeps state on disk in
`--workdir`/`--state-file`, exactly as before. `azurerm` (Azure Blob
Storage), `s3` (Amazon S3), and `gcs` (Google Cloud Storage) store
state durably, locked, and off-box, which is what a scheduled DR job
wants (a local state file lives on the very machine the DR job
protects). Remote backends take their settings from `--backend-config`
/ `--backend-config-file`; see
[Remote state backends](#remote-state-backends).

**`--backend-config KEY=VALUE`** *(repeatable)* — a setting passed to
`terraform init -backend-config` for a remote `--state-backend`. For
azurerm: `resource_group_name`, `storage_account_name`, `container_name`,
`key`; for s3: `bucket`, `key`, `region`; for gcs: `bucket`, `prefix`.
**Credential-shaped keys are refused** (`access_key`, `sas_token`,
`secret_key`, `token`, `credentials`, …): terraform reads those from the
environment (`ARM_*`, `AWS_*`, `GOOGLE_APPLICATION_CREDENTIALS`) or an
ambient identity, so a secret never lands in a flag, a process listing,
or a log.

**`--backend-config-file PATH`** — a file of remote-backend settings
passed to `terraform init -backend-config=PATH` (composes with repeated
`--backend-config`). Useful for keeping a `*.tfbackend` file per org.

**`--webhook-url URL`** *(repeatable)* — HTTPS endpoint(s) receiving
each alert as a JSON POST (`Content-Type: application/json`). Repeat
the flag to fan out to several receivers:

```bash
meraki2tf --org-id 123456 \
  --webhook-url https://hooks.example.com/netops \
  --webhook-url https://hooks.example.com/audit
```

**`--webhook-format {json,slack,teams}`** — the shape of the webhook
POST body (applies to every webhook target). `json` (default) is the
raw machine-readable event payload for generic receivers. `slack`
renders each event as Slack incoming-webhook text (`{"text": …}` with
the event type, summary, and a budgeted details block). `teams`
renders a Teams **Workflows** Adaptive Card `message` — the format the
Power Automate "when a Teams webhook request is received" trigger
expects (the retired Office 365 connectors are not targeted). Chat
formats truncate oversized detail blocks; the run log, workdir
artifacts, and `json` format always keep the full payload.

```bash
meraki2tf --org-id 123456 \
  --webhook-url https://hooks.slack.com/services/T000/B000/XXXX \
  --webhook-format slack
```

**`--pagerduty`** — trigger a PagerDuty incident (Events API v2) for
every **WARNING/CRITICAL** event: drift, unsupported coverage gaps,
deletions awaiting confirmation, processing faults, and failed DR
actions. INFO events (clean runs, successful DR confirmations) never
page — pair PagerDuty with a webhook/email channel if you also want
routine notifications. The routing key is a credential and comes only
from the `MERAKI2TF_PAGERDUTY_ROUTING_KEY` environment variable.

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

Authenticated relays: set `MERAKI2TF_SMTP_USERNAME` and
`MERAKI2TF_SMTP_PASSWORD` in the environment (never flags or config
keys). AUTH runs only inside the verified STARTTLS session — if the
relay never advertises STARTTLS, the send fails rather than letting
the credential cross the network in cleartext.

**`--terraform-bin PATH`** — alternative Terraform executable (e.g. a
pinned binary or `tofu`):

```bash
meraki2tf --org-id 123456 --terraform-bin /opt/terraform-1.9/terraform
```

**`-v` / `--verbose`** — DEBUG logging with logger origins and full
terraform output, including the complete drift diff. Credentials are
redacted at every level, so verbose is safe for shared logs.

**`--log-format {text,json}`** — console log output. `json` emits one
JSON object per line (`timestamp`, `level`, `logger`, `message`, plus
`exception` when present) for Splunk/ELK/Cloud-Logging pipelines. The
secret-redaction filter applies identically in both formats.

### Terraform state management

By default state is stored via Terraform's **local backend** at the path
anchored in the generated `provider.tf` (for a durable off-box option,
see [Remote state backends](#remote-state-backends)):

- **Default**: `meraki2tf.tfstate` inside `--workdir` (e.g.
  `generated/meraki2tf.tfstate`). The name is deliberately not
  `terraform.tfstate`: `terraform init` treats a file of that exact name
  next to the configuration as pre-backend legacy state and empties it
  during backend initialization, which would destroy the accumulated
  imports. A legacy `terraform.tfstate` from older meraki2tf versions is
  adopted (renamed) automatically, and `--state-file` refuses that
  filename inside the workdir.
- **Custom location**: pass `--state-file /path/to/existing.tfstate` to
  point at a state file you already have — parent directories are
  created as needed.

Because the pipeline never applies, **it never writes state itself**:
state only gains resources when *you* apply (via
`--rebuild --confirm` or a manual `terraform apply` in the workdir).
Runs with an empty or absent state simply regenerate the complete
import/config snapshot every time — exactly what a DR kit should be.

If you do maintain a populated state, runs are incremental: before
generating `imports.tf`, meraki2tf reads the state file and **skips
every resource address it already tracks**, so a weekly run only writes
import blocks for newly discovered assets. Drift on already-tracked
resources surfaces through the speculative plan and fires
`DRIFT_DETECTED` — pending imports alone are *not* treated as drift.

```bash
# Weekly snapshot against a state you maintain:
meraki2tf --org-id 123456 --state-file /var/lib/meraki2tf/org-123456.tfstate
```

Treat the state file like any Terraform state: back it up, and never
commit it (the repository `.gitignore` already excludes `*.tfstate`).

#### Remote state backends

The default local backend keeps state on the same host that runs the
job — fine for ad-hoc use, but the weakest link for a DR tool: the state
sits on the very machine you are protecting against losing. Point
`--state-backend` at a remote backend to store state durably off-box
instead — `azurerm` (Azure Blob Storage), `s3` (Amazon S3), or `gcs`
(Google Cloud Storage). Each gives you redundancy, access control,
encryption at rest, and state locking:

```bash
export MERAKI_DASHBOARD_API_KEY="<your-dashboard-api-key>"
# terraform reads the storage credential from the environment (or an
# ambient identity) — never from a flag:
export ARM_ACCESS_KEY="<storage-account-key>"   # or use MSI / az login

meraki2tf --org-id 123456 --sync \
  --state-backend azurerm \
  --backend-config resource_group_name=rg-meraki-dr \
  --backend-config storage_account_name=merakidrstate \
  --backend-config container_name=tfstate \
  --backend-config key=org-123456.tfstate
```

```bash
# Amazon S3 — credentials from AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY,
# a shared credentials profile, or an instance/task role:
meraki2tf --org-id 123456 --sync \
  --state-backend s3 \
  --backend-config bucket=meraki-dr-state \
  --backend-config key=org-123456.tfstate \
  --backend-config region=us-east-1

# Google Cloud Storage — credentials from
# GOOGLE_APPLICATION_CREDENTIALS or Application Default Credentials:
meraki2tf --org-id 123456 --sync \
  --state-backend gcs \
  --backend-config bucket=meraki-dr-state \
  --backend-config prefix=org-123456
```

Notes:

- **Credentials stay in the environment.** meraki2tf refuses
  credential-shaped `--backend-config` keys (`access_key`, `sas_token`,
  `client_secret`, `secret_key`, `token`, `credentials`,
  `access_token`, …); terraform reads them from the environment
  (`ARM_*`, `AWS_*`, `GOOGLE_APPLICATION_CREDENTIALS`) or an ambient
  identity (managed identity, instance role, ADC). Nothing secret
  touches a flag, a process listing, or a log.
- **At-rest protection moves to the backend.** The owner-only (0600)
  guarantee applies to the *local* state file; with a remote backend,
  encryption and access control are the storage service's
  responsibility (RBAC/IAM + service-side encryption). The unsanitized
  snapshot remains 0600 either way.
- `--state-file` is a local-backend concept and is refused alongside a
  remote `--state-backend`; the remote backend addresses its state via
  its own settings (the azurerm/s3 `key`, the gcs `prefix`).
- The state-address settings are validated eagerly (azurerm:
  `storage_account_name`, `container_name`, `key`; s3: `bucket`, `key`;
  gcs: `bucket`) so a misconfigured scheduled job fails at argument
  parsing, not hours into a run. Connection settings with environment
  fallbacks (s3 `region`, azurerm `resource_group_name`, …) are left to
  `terraform init` to enforce.
- Prefer keeping the backend settings in a file? Pass
  `--backend-config-file org-123456.tfbackend` instead of (or alongside)
  the individual `--backend-config` flags.

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
