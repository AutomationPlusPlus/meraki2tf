# Operations

Running meraki2tf on a schedule: alert events, cron/exit-code
wiring, performance at scale, and troubleshooting. Part of the
[meraki2tf](../README.md) docs.

## Alerting events

| Event | Trigger |
| --- | --- |
| `DRIFT_DETECTED` | Real configuration drift. Two origins, distinguished by `details.origin`: `terraform-plan` (the speculative plan found add/change/destroy on tracked resources — pending imports alone don't count) and `snapshot-diff` (`--drift-baseline` comparison found added/modified/removed assets, including provider-inexpressible and secret-bearing ones). Payload carries the diff/digest, the unsupported list, `apply_aborted` (true when a `--sync` auto-apply was refused), `regenerated_addresses` (modified objects re-baselined in sync mode), and `deferred_addresses` (drift-racy pending imports pushed to the next run) |
| `RUN_SUCCESS` | Snapshot generation (and comparison, when an API key was available) completed flawlessly. Payload carries the coverage picture: `discovered_assets`, `imports_written`, `imports_already_tracked`, `unsupported_count` plus the full `unsupported` list, `pending_imports` (imports the plan reports as not yet in state; `null` when unknown), `comparison_performed`, `resources_added_to_state` (sync mode), `coverage_percent`, `deletions_pending_confirmation`, and `unmanaged_secret_attributes` (secrets the kit cannot carry — restore manually after a rebuild) |
| `UNSUPPORTED_FEATURE_FLAGGED` | A discovered asset cannot be mapped to a Terraform resource |
| `DELETION_PENDING_CONFIRMATION` | Resources tracked in the DR kit were not found in Meraki (deleted?); they stay in the kit until a human confirms with `--confirm-deletions` |
| `RESTORE_EXECUTED` | A human-invoked `--restore --confirm` rebuilt a target organization from a snapshot. Payload carries executed/failed/skipped action labels (identifiers and endpoints only — never values) |
| `HEAL_EXECUTED` | A human-invoked `--heal --confirm` recreated snapshot objects missing from the same live organization. Payload carries the executed/failed/skipped actions plus the surviving (untouched) count — identifiers and endpoints only, never values |
| `ORG_WIPE_EXECUTED` | A human-invoked `--wipe-org --confirm` tore down a hardware-free drill organization (networks deleted + org deleted, with any failures) |
| `GAP_REPLAY_EXECUTED` | A human-invoked `--replay-gaps --confirm` wrote unsupported objects and/or secret attributes back to Meraki from a snapshot. Payload carries the executed, skipped, and failed operations (identifiers/endpoints only — never secret values) |
| `PROCESSING_FAULT` | A critical pipeline failure (payload carries the failing stage) |

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
0 6 * * 1 cd /opt/meraki2tf && . .venv/bin/activate && \
  { [ ! -f snapshots/latest.jsonl.gz ] || mv -f snapshots/latest.jsonl.gz snapshots/previous.jsonl.gz; } && \
  MERAKI_DASHBOARD_API_KEY=$(cat /etc/meraki2tf/token) \
  MERAKI2TF_WEBHOOK_URL=$(cat /etc/meraki2tf/webhook-url) \
  meraki2tf --org-id 123456 --spec ./openapi.json --fail-on-gaps \
  --dump-to snapshots/latest.jsonl.gz --drift-baseline snapshots/previous.jsonl.gz \
  >> /var/log/meraki2tf.log 2>&1

# The 1st of every month 03:00 — terraform rehearsal: regenerate the kit
# and materialize state under the guarded import-only apply.
0 3 1 * * cd /opt/meraki2tf && . .venv/bin/activate && \
  MERAKI_DASHBOARD_API_KEY=$(cat /etc/meraki2tf/token) \
  MERAKI2TF_WEBHOOK_URL=$(cat /etc/meraki2tf/webhook-url) \
  meraki2tf --org-id 123456 --spec ./openapi.json --sync \
  >> /var/log/meraki2tf.log 2>&1
```

On the very first weekly run there is no previous snapshot yet — omit
`--drift-baseline` for that run (a missing baseline file is an error,
not a silent skip). On Azure, the deployment wrapper does this snapshot
rotation for you (see below).

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
service+timer pair (with automatic `--drift-baseline` rotation and a
first-run-safe baseline check) and a monthly `--sync` terraform
rehearsal pair. Both run as a dedicated system user, read the API key
and webhook URL from a root-owned 0600 `EnvironmentFile`, and confine
writes to `/var/lib/meraki2tf` (`ProtectSystem=strict`). The setup
steps (user, directories, secret file, `systemctl enable --now`) are
in the header of
[`meraki2tf-snapshot.service`](../deploy/systemd/meraki2tf-snapshot.service).

Timer-driven jobs report through the same exit codes as cron; the
units treat exit 3 (coverage gaps) as success so a permanently-gapped
org doesn't flap the unit — the gap list still arrives via alerts.
Remove `SuccessExitStatus=3` to page on gaps instead.

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

**`meraki2tf could not start: …` right after launch.**
Usually a bad `--org-id` or an API key without access to that
organization. Run `meraki2tf --list-orgs` to see exactly which
organization IDs your key can reach; the failed run exits 1 and
dispatches a `PROCESSING_FAULT` alert.

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
