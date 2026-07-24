# Operations

Running meraki2tf on a schedule: API-key permissions, alert events,
cron/exit-code wiring, performance at scale, and troubleshooting.
Part of the [meraki2tf](../README.md) docs.

## API-key permission model

A **read-only organization admin** key is all every scheduled and
ad-hoc read path needs — the default pipeline, `--sync` (its applies
only write local/backend Terraform *state*; Meraki is never mutated),
`--dump-to`, `--drift-baseline`, `--list-orgs`, `--check`,
`--estimate`, `--diff-networks`, and every DR-action *preview*.
Discovery is GET-only by construction, and defensively so: before
dispatching any dynamically resolved SDK method, its source is
verified to only ever perform reads — a method that cannot be proven
read-only is refused (fail-closed), so even a tampered OpenAPI spec
cannot trick a scheduled run into a write. Run your weekly/monthly
jobs on a read-only key.

**Full-access is needed only for the five human-invoked `--confirm`
executions** (`--rebuild`, `--heal`, `--replay-gaps`, `--restore`,
`--wipe-org` — and for `terraform apply` run by hand in the workdir).
Keeping a separate full-access key offline until an incident is a
reasonable posture; the previews of all five actions work on the
read-only key.

Scope expectations: endpoints the key cannot read (401/403 — e.g. a
key scoped below org-wide, or camera/SM feature scopes withheld) are
**never** silently treated as "feature not in use". Each one surfaces
as a coverage gap in `coverage.json`, and an endpoint refused by every
scope it was tried against is additionally listed under
`suspect_endpoints` in the manifest — so a permissions hole shows up
as missing DR coverage, not as a quietly smaller snapshot.

## Alerting events

| Event | Trigger |
| --- | --- |
| `DRIFT_DETECTED` | Real configuration drift. Two origins, distinguished by `details.origin`: `terraform-plan` (the speculative plan found add/change/destroy on tracked resources — pending imports alone don't count) and `snapshot-diff` (`--drift-baseline` comparison found added/modified/removed assets, including provider-inexpressible and secret-bearing ones). Payload carries the diff/digest, the unsupported list, `apply_aborted` (true when a `--sync` auto-apply was refused), `regenerated_addresses` (modified objects re-baselined in sync mode), and `deferred_addresses` (drift-racy pending imports pushed to the next run) |
| `RUN_SUCCESS` | Snapshot generation (and comparison, when an API key was available) completed flawlessly. Payload carries the coverage picture: `discovered_assets`, `imports_written`, `imports_already_tracked`, `unsupported_count` plus the full `unsupported` list, `pending_imports` (imports the plan reports as not yet in state; `null` when unknown), `comparison_performed`, `resources_added_to_state` (sync mode), `coverage_percent`, `deletions_pending_confirmation`, `unmanaged_secret_attributes` (secrets the kit cannot carry — restore manually after a rebuild), `deferred_addresses`, `reconciliation_drop_categories` (reconciliation drops aggregated by diagnostic, so a provider regression names the resource class it broke), and `partial_scope` (the covered network IDs of a `--only` run — never mistake a one-network export for a full capture) |
| `UNSUPPORTED_FEATURE_FLAGGED` | A discovered asset cannot be mapped to a Terraform resource |
| `DELETION_PENDING_CONFIRMATION` | Resources tracked in the DR kit were not found in Meraki (deleted?); they stay in the kit until a human confirms with `--confirm-deletions` |
| `RESTORE_EXECUTED` | A human-invoked `--restore --confirm` rebuilt a target organization from a snapshot. Payload carries executed/failed/skipped action labels (identifiers and endpoints only — never values) |
| `HEAL_EXECUTED` | A human-invoked `--heal --confirm` recreated snapshot objects missing from the same live organization. Payload carries the executed/failed/skipped actions plus the surviving (untouched) count — identifiers and endpoints only, never values. Selective heals add `only_filters`; heals from a partial (selective-backup) snapshot add `snapshot_scope`; `verified_alive_skips` counts planned actions the pre-write liveness probe found alive and skipped (additive-only held) |
| `ORG_WIPE_EXECUTED` | A human-invoked `--wipe-org --confirm` tore down a hardware-free drill organization (networks deleted + org deleted, with any failures) |
| `REBUILD_EXECUTED` | A human-invoked `--rebuild --confirm` ran `terraform apply` of the DR kit. INFO on success, CRITICAL on failure (the organization may be partially rebuilt) — the largest write path must reach the on-call channel either way |
| `GAP_REPLAY_EXECUTED` | A human-invoked `--replay-gaps --confirm` wrote unsupported objects and/or secret attributes back to Meraki from a snapshot. Payload carries the executed, skipped, and failed operations (identifiers/endpoints only — never secret values) |
| `PROCESSING_FAULT` | A critical pipeline failure (payload carries the failing stage) |

Every event's details additionally carry an `organization_id` (stamped
by the dispatcher as soon as the organization is known), so multi-org
fan-out consumers can attribute interleaved events. Diff/detail
payloads are value-redacted before they leave the process — attribute
names and locators only.

## Scheduled (cron) execution

The CLI is non-interactive end to end and reports outcome via exit code
(0 clean, 1 fault, 2 usage error, 3 coverage gaps with `--fail-on-gaps`,
4 sync auto-apply aborted for human review, 5 run succeeded but at
least one alert reached no configured channel), so each scheduled job
is one crontab line. The recommended cadence is a weekly snapshot job
plus a monthly terraform rehearsal:

```cron
# Every Monday 06:00 — export this week's snapshot, diff it against last
# week's, alert on drift and coverage gaps. Snapshot-only: no terraform.
# --drift-baseline is passed only when a previous snapshot exists, so
# the very first run (no baseline yet) succeeds unedited; the
# --discovery-checkpoint journal lets an aborted multi-hour sweep
# resume on the next run instead of restarting.
0 6 * * 1 cd /opt/meraki2tf && . .venv/bin/activate && \
  { [ ! -f snapshots/latest.jsonl.gz ] || mv -f snapshots/latest.jsonl.gz snapshots/previous.jsonl.gz; } && \
  MERAKI_DASHBOARD_API_KEY=$(cat /etc/meraki2tf/token) \
  MERAKI2TF_WEBHOOK_URL=$(cat /etc/meraki2tf/webhook-url) \
  meraki2tf --org-id 123456 --spec ./openapi.json --fail-on-gaps \
  --dump-to snapshots/latest.jsonl.gz \
  --discovery-checkpoint snapshots/checkpoint.jsonl.gz \
  $([ -f snapshots/previous.jsonl.gz ] && echo "--drift-baseline snapshots/previous.jsonl.gz") \
  >> /var/log/meraki2tf.log 2>&1

# The 1st of every month 03:00 — terraform rehearsal: regenerate the kit
# and materialize state under the guarded import-only apply.
0 3 1 * * cd /opt/meraki2tf && . .venv/bin/activate && \
  MERAKI_DASHBOARD_API_KEY=$(cat /etc/meraki2tf/token) \
  MERAKI2TF_WEBHOOK_URL=$(cat /etc/meraki2tf/webhook-url) \
  meraki2tf --org-id 123456 --spec ./openapi.json --sync \
  >> /var/log/meraki2tf.log 2>&1

# Optional retention (see "Snapshot retention & archival" below): keep
# dated copies beyond the latest/previous pair and prune old ones.
15 6 * * 1 cd /opt/meraki2tf && umask 077 && mkdir -p snapshots/archive && \
  { [ ! -f snapshots/latest.jsonl.gz ] || cp -p snapshots/latest.jsonl.gz "snapshots/archive/$(date +\%Y-\%m-\%d).jsonl.gz"; } && \
  find snapshots/archive -name '*.jsonl.gz' -mtime +400 -delete
```

The `$([ -f … ] && echo …)` guard is the same first-run-safe shape the
systemd unit uses: a missing baseline file is an error, not a silent
skip, so the flag must only appear once a previous snapshot exists. On
Azure, the deployment wrapper does this snapshot rotation for you (see
below).

Create the token (and webhook-URL) files owner-only so no other local
account can read the org-admin key or the bearer-token-bearing webhook
URL — e.g. `install -m 0600 /dev/null /etc/meraki2tf/token` then paste
the value in. Passing the key via the environment (as above) keeps it
out of the process list; the `MERAKI2TF_WEBHOOK_URL` variable does the
same for the webhook URL, whose path may itself be a secret (use it
instead of `--webhook-url` in scheduled jobs). Separate multiple webhook
targets with `:::`.

`--fail-on-gaps` turns unsupported objects into a nonzero exit your
scheduler can page on; it is valid on every read-only shape, snapshot
exports included. Drop `--sync` from the monthly line if you want that
job to stay plan-only (state building then remains a manual step).

Running on Azure? A full deployment guide — Azure Automation with a
Hybrid Runbook Worker (or a Container Apps Job), the API key in Key
Vault, and every run's artifacts archived to Blob Storage — lives in
[`docs/azure-automation.md`](azure-automation.md), with a
ready-made wrapper runbook in
[`deploy/azure/runbook.py`](../deploy/azure/runbook.py).

## Scheduled execution with systemd

Ready-made hardened units live in
[`deploy/systemd/`](../deploy/systemd/): a weekly snapshot
service+timer pair (with automatic `--drift-baseline` rotation, a
first-run-safe baseline check, and a `--discovery-checkpoint` journal
so an aborted sweep resumes on the next timer run) and a monthly
`--sync` terraform rehearsal pair. Both run as a dedicated system
user, read the API key and webhook URL from a root-owned 0600
`EnvironmentFile`, confine writes to `/var/lib/meraki2tf`
(`ProtectSystem=strict`), and set `TimeoutStartSec=infinity`
explicitly so no manager default can SIGTERM a multi-hour sweep. Each
unit header marks the **mandatory edits** (the placeholder `--org-id`
and the install paths) and carries a commented optional retention step
(see below). The setup steps (user, directories, secret file,
`systemctl enable --now`) are in the header of
[`meraki2tf-snapshot.service`](../deploy/systemd/meraki2tf-snapshot.service).

Timer-driven jobs report through the same exit codes as cron; the
units treat exit 3 (coverage gaps) as success so a permanently-gapped
org doesn't flap the unit — the gap list still arrives via alerts.
Remove `SuccessExitStatus=3` to page on gaps instead.

## Snapshot retention & archival

The recipes above (cron, systemd, and the Azure wrapper's rotation)
keep exactly two generations on disk: `latest` and `previous`. That is
enough for the drift chain, but it is a thin DR margin — two bad runs
in a row, or a corruption that goes unnoticed for a week, leave
nothing to restore from. Add a retention step:

- **Dated local copies + pruning** — after each successful export,
  copy the snapshot to a dated name and prune old copies (both recipe
  sets carry this as a commented optional step):

  ```bash
  umask 077 && mkdir -p snapshots/archive
  cp -p snapshots/latest.jsonl.gz "snapshots/archive/$(date +%Y-%m-%d).jsonl.gz"
  find snapshots/archive -name '*.jsonl.gz' -mtime +400 -delete
  ```

  Keep copies owner-only (`umask 077` / `cp -p`): unsanitized
  snapshots carry secret values.
- **Off-box copies** — a snapshot on the machine that runs the job
  dies with that machine. Ship the dated copies somewhere that
  survives the disaster you are protecting against: `rclone copy
  snapshots/archive remote:meraki2tf/`, `scp` to a backup host, or
  object storage with a lifecycle rule (the Azure wrapper already
  archives every run's snapshot to Blob Storage under a dated
  prefix). Apply the same at-rest access control you would give a
  password vault.
- **How much to keep** — at minimum, enough history to reach back
  past your detection lag: 13 monthly + 5 weekly copies is a sane
  default (`-mtime +400` above approximates it). The Terraform state
  deserves the same treatment when you use the local backend; remote
  backends (`--state-backend azurerm/s3/gcs`) get durability and
  versioning from the storage service.

## AWS: scheduled Fargate task

Build and push the repo-root [`Dockerfile`](../Dockerfile) image to
ECR, then run it as an EventBridge-scheduled ECS/Fargate task:

1. **Secrets:** store the API key (and webhook URL) in AWS Secrets
   Manager, and inject them via the task definition's `secrets` block
   so they reach the container as `MERAKI_DASHBOARD_API_KEY` /
   `MERAKI2TF_WEBHOOK_URL` without touching the task definition in
   plaintext:

   ```json
   {
     "containerDefinitions": [{
       "name": "meraki2tf",
       "image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/meraki2tf:v0.1.0",
       "command": ["--org-id", "123456",
                   "--dump-to", "/data/latest.jsonl.gz",
                   "--workdir", "/data", "--fail-on-gaps"],
       "secrets": [
         {"name": "MERAKI_DASHBOARD_API_KEY",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:111111111111:secret:meraki2tf/api-key"},
         {"name": "MERAKI2TF_WEBHOOK_URL",
          "valueFrom": "arn:aws:secretsmanager:us-east-1:111111111111:secret:meraki2tf/webhook-url"}
       ],
       "mountPoints": [{"sourceVolume": "workdir", "containerPath": "/data"}]
     }]
   }
   ```

2. **Persistence:** mount an EFS volume at `/data` so snapshots (and
   the drift baseline rotated by your command wrapper) survive between
   runs — or skip local persistence and keep Terraform state in S3
   (`--state-backend s3`, credentials from the task role) with
   snapshots copied to S3 by a small post-step.
3. **Schedule:** an EventBridge Scheduler rule per job — weekly for
   the snapshot shape, monthly adding `--sync` — targeting the task
   with `RunTask`. Give the task a generous timeout: discovery on a
   large org is hours, by design.
4. **Outcome:** alerts carry the run report; the container exit code
   surfaces in the stopped-task event (map exit 3/5 per the table
   above before paging on it).

## GCP: Cloud Run Job

Push the same image to Artifact Registry and wrap it in a Cloud Run
Job triggered by Cloud Scheduler:

```bash
gcloud run jobs create meraki2tf-snapshot \
  --image us-docker.pkg.dev/example-project/meraki2tf/meraki2tf:v0.1.0 \
  --args="--org-id,123456,--dump-to,/data/latest.jsonl.gz,--workdir,/data,--fail-on-gaps" \
  --set-secrets=MERAKI_DASHBOARD_API_KEY=meraki2tf-api-key:latest,MERAKI2TF_WEBHOOK_URL=meraki2tf-webhook:latest \
  --task-timeout=6h --max-retries=0

gcloud scheduler jobs create http meraki2tf-weekly \
  --schedule="0 6 * * 1" --uri="https://run.googleapis.com/v2/projects/example-project/locations/us-central1/jobs/meraki2tf-snapshot:run" \
  --oauth-service-account-email=scheduler@example-project.iam.gserviceaccount.com
```

Secrets come from Secret Manager via `--set-secrets` (never flags);
Terraform state belongs in GCS (`--state-backend gcs`, Application
Default Credentials from the job's service account). Cloud Run Jobs
have no built-in persistent disk — mount a Cloud Storage volume
(`--add-volume`/`gcsfuse`) for the snapshot + drift-baseline chain, or
export snapshots to GCS in a wrapper step. `--max-retries=0` matters:
a retried half-run would re-discover from scratch and double the API
load for no benefit.

## Performance & Scale

Discovery reads every configuration surface of the organization —
including nested, multi-parameter surfaces (per-SSID identity PSKs and
firewall rules, switch-stack routing, config-template switch
profiles, …) that scope off elements discovered at their parent paths.
Completeness costs reads: budget roughly one GET per (object ×
surface).

Feature discovery runs on a worker pool (`MERAKI2TF_DISCOVERY_WORKERS`,
default 8) paced by a single adaptive AIMD rate bucket: the pool speeds
up while the API accepts calls, backs off multiplicatively and pauses
globally the moment anything is throttled, and never exceeds 6 req/s —
the per-organization budget is 10 req/s and it is **shared with every
other API consumer of your tenant**. Width buys back idle round-trip
time; it cannot mint budget.

Empirically (a ~22k-object organization with a busy co-tenant
integration): a full sequential read pass costs ~2.5–3 h; the pool
reclaims most idle time, and the snapshot-diff drift path removes the
second (terraform) read pass entirely, so a weekly
`--dump-to … --drift-baseline …` job is dominated by a single
discovery sweep. Prefer `.jsonl.gz` snapshots at this scale, and give
schedulers a generous timeout — completeness matters more than speed
for a DR safety net.

Operating a long sweep:

- **Preview the cost first** — `meraki2tf --org-id 123456 --estimate`
  prints the expected request count and wall-clock estimates (at the
  rate cap and at a degraded rate) from 2-3 enumeration calls.
- **Liveness is visible** — discovery emits one INFO progress line at
  most every ~30 s (items done/total for the running level, overall
  count, the current effective request rate, and a rough ETA), so a
  working sweep and a hung one look different in the log; the line is
  an ordinary record and renders in `--log-format json` too.
- **Aborts are resumable** — pass `--discovery-checkpoint PATH` so an
  aborted sweep (throttle exhaustion, reboot) resumes from its journal
  instead of restarting from zero; a completed run deletes the
  journal. The journal carries raw payloads (secrets) and is written
  0600.

## Troubleshooting & FAQ

**The run finished but no plan/drift comparison happened.**
`MERAKI_DASHBOARD_API_KEY` was not set. Without it the pipeline still
generates the full kit (imports, HCL, coverage manifest) but skips the
speculative `terraform plan` comparison and exits 0 — by design, so
air-gapped and dump-mode runs stay useful. Export the key to get the
drift comparison.

**`terraform executable 'terraform' was not found`.**
Install Terraform (≥ 1.5) and make sure it is on `PATH`, or point at a
specific binary with `--terraform-bin /path/to/terraform` (OpenTofu
works too).

**`Pipeline fault during configuration discovery: …` early in a live
run.**
Usually a bad `--org-id` or an API key without access to that
organization: the very first discovery calls
(`getOrganizationNetworks`) fail with the SDK's 404 error text, the
run logs `Pipeline fault during configuration discovery: …` followed
by `Pipeline failed during configuration discovery: …`, exits 1, and
dispatches a `PROCESSING_FAULT` alert (stage `configuration
discovery`). Remediation: `meraki2tf --list-orgs` prints exactly which
organization IDs your key can reach, and `meraki2tf --org-id <id>
--check` validates the key/org pair (and the rest of your flag set) in
seconds before you schedule anything.

**Resource names look right but import IDs seem off / resources are
missing.**
meraki2tf reads resource identity schemas from the *installed*
`CiscoDevNet/meraki` provider and needs **≥ v1.12.0**. With an older
provider (or no `terraform init` yet) it falls back to a bundled
v1.12.2 catalog, which can drift from what your workdir actually runs.
Upgrade the provider and re-run.

**Discovery is slow on a big organization.**
That's the design trade-off: completeness over speed. Every object ×
surface costs a GET, paced under Meraki's 10 req/s org budget (which is
shared with your other integrations — the pool caps itself at 6 req/s).
Tune the worker pool with `MERAKI2TF_DISCOVERY_WORKERS` (default 8) and
see [Performance & Scale](#performance--scale). A DR kit missing
objects is worse than a slow one.

**Will this ever change my Meraki org?**
Not unless you explicitly ask it to. Every pipeline invocation —
scheduled or ad-hoc, live or dump — is read-only toward Meraki. Only
the five human-invoked DR actions gated behind `--confirm` can write;
each is a read-only preview without it. See the
[read-only guarantee](../README.md#project-overview).

**Does it work behind a corporate proxy?**
Mostly, via the standard environment variables. The Meraki SDK
(`requests`) and the webhook/PagerDuty notifiers (`urllib`) honor
`HTTPS_PROXY`/`NO_PROXY`, and Terraform does the same for provider
traffic. The one exception is SMTP: Python's `smtplib` does not speak
HTTP proxies at all, so email alerts need a directly reachable relay
(or use webhooks/PagerDuty instead). Spec auto-download also goes over
HTTPS and follows the same proxy variables; pre-stage `spec3.json` for
fully air-gapped hosts.

**Is it on PyPI?**
Not yet — install from a clone (`pip install -e .` puts the
`meraki2tf` command on your PATH, as shown in the quickstart).

**What does the AGPL v3 license mean for me?**
Running meraki2tf internally against your own organizations carries no
obligations. The copyleft terms apply when you distribute modified
versions or offer the tool itself as a network service.
