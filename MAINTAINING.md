# Maintaining meraki2tf

A practical guide for keeping this tool healthy without needing to hold the
whole codebase in your head. The contract (what the tool must and must never
do) lives in `CLAUDE.md`; this file covers *how to operate, triage, and evolve
it*. Most maintenance is reading one log line and following a checklist here.

The single most important habit: **run a drill on a schedule.** Nearly every
bug ever found in this tool was found by a drill reading its own failure lines
— not by studying code. If the drill passes, the tool works.

---

## 1. Architecture map (which file owns what)

All source lives in `src/meraki2tf/`. One line each:

| Module | Owns |
|---|---|
| `cli.py` | Argument parsing, mode gating, refusals/interlocks, exit codes, the per-command flows (`--restore`, `--heal`, `--wipe-org`, `--replay-gaps`, `--rebuild`) |
| `config.py` | `RuntimeConfig`, `--config` TOML loading (and its refused-keys list), backend-config validation (`SECRET_BACKEND_KEYS`), API-key reading |
| `orchestrator.py` | The default/sync pipeline: discovery → kit → speculative plan → guarded apply → coverage → runbook → alerts |
| `openapi_parser.py`, `spec/engine.py`, `spec_resolver.py` | Meraki OpenAPI spec ingestion; `OperationSpec` objects everything else consumes. **No hard-coded endpoint tables anywhere — ever** |
| `providers/live.py` / `dump.py` | Live-API and offline-snapshot data providers (identical downstream shape) |
| `providers/discovery.py` | The spec-driven sweep: which endpoints to read, element-ID conventions (`element_id`), unreadable-endpoint records |
| `providers/ratelimit.py` | Adaptive token bucket for the 10 req/s limit |
| `resource_matcher.py` | API path → Terraform provider resource matching |
| `hcl_generator.py` | `imports.tf` / `resources.tf` generation |
| `plan_reconciler.py` | Reads the plan back: unexpressible resources, unmanaged secret attributes, value normalization |
| `terraform_runner.py` | Runs terraform; **the import-only apply guard lives here** (belt-and-suspenders, per contract); backends (local/azurerm/s3/gcs); chunked `-target` windows |
| `snapshot.py` / `snapshot_diff.py` | v2 snapshot format; `--drift-baseline` diffing |
| `sanitizer.py` | Salted pseudonymization; `SECRET_KEY_PATTERN` (shared with runbook + replayer — change it in one place only) |
| `restorer.py` | The big one: restore planner (waves, classification), `ReferenceResolver` (old→new ID mapping), executor (journal, adoption of Meraki defaults, salvage retries, drill secret injection), and `OrgWiper` |
| `healer.py` | Same-org additive-only recovery (drives the restorer's executor) |
| `replayer.py` | `--replay-gaps`: writes unsupported objects + captured secrets back via the SDK |
| `runbook.py` | Per-run `runbook.md`; `write_operations` (entity → write ops, shared with the restore planner) |
| `coverage.py` | `coverage.json` / `coverage.txt` manifest |
| `alerts/` | Notifier plugins (webhook, email) and event payload builders |

Rule of thumb for locating a bug: the failure line names an API path and an
operation — discovery problems say "could not be read", restore problems say
"Restore FAILED for `<path>`", terraform problems quote terraform. That names
the module.

## 2. Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | Clean run | Nothing |
| 1 | Pipeline/critical fault (API down, terraform failed, restore had failures) | Read the last `CRITICAL`/`ERROR` line; it names the stage |
| 2 | Refusal — an interlock or invalid invocation (wrong org, sanitized snapshot where forbidden, bad flags) | The message says exactly which interlock; this is the tool protecting you |
| 3 | `--fail-on-gaps`: unsupported objects exist | Normal on an org with known coverage gaps; the list is in `coverage.json` |
| 4 | `--sync` full-kit auto-apply ABORTED — the plan carried mutations | Review the `DRIFT_DETECTED` alert (`apply_aborted: true`); import-only chunks may still have grown state |
| 5 | Run succeeded but **no alert channel could deliver** | Work product is fine; fix the webhook/SMTP/PagerDuty endpoint |

(Deletions pending confirmation are an *alert* (`DELETION_PENDING_CONFIRMATION`), not an exit code — the run still exits by the table above; rerun with `--confirm-deletions` after review.)

## 3. Routine operations

Weekly scheduled run (DR mode): `meraki2tf --org-id <org> --sync --workdir <wd> --webhook-url <url>`. Expect: RUN_SUCCESS with 0-or-few imports added, coverage ~98.7%, no drift, exit 0. Anything else → §4.

Read-only ad-hoc run: same without `--sync`. Snapshot only: `--dump-to snap.json` (add `--sanitize` for a shareable/drill-safe copy). Air-gapped kit: `--from-dump snap.json --workdir <wd>` with no API key set.

**Quarterly (recommended): run a restore drill** — §6. It is the only end-to-end
proof that the DR path still works against current Meraki behavior.

## 4. Triage playbook (by symptom)

**DRIFT_DETECTED alert, run exit 0** — normal life: someone clickopsed. The
diff is in the alert. Sync mode already regenerated HCL to mirror Meraki
(Meraki is truth) and re-imported. Nothing to do unless the change was wrong
in Meraki itself.

**DRIFT_DETECTED with `apply_aborted: true`** — the plan contained a real
add/change/destroy, so the guarded apply refused. Read the diff in the alert.
Usually a provider round-trip quirk on a new resource type. Ask an assistant
to add normalization in `plan_reconciler.py`, or accept the abort (state just
doesn't grow this week; nothing is harmed).

**DELETION_PENDING_CONFIRMATION alert** — something was deleted in Meraki.
If intended: rerun with `--confirm-deletions`. If not intended: the DR kit
still holds the object — rebuild it via `--rebuild --confirm` (subset) or
`--heal --confirm` (recreates whatever a snapshot has that live lacks).

**Coverage percentage dropped** — Meraki shipped endpoints the provider
doesn't support yet. Not a malfunction: the new objects are listed as
`unsupported` in `coverage.json` with reasons, and the runbook carries the
manual-rebuild instructions. Re-check after the next provider release.

**Restore/heal drill failures** — each line is
`Restore FAILED for <api_path>::<ids>: <the API's own error>`. Rerun first:
the journal resumes, and transient/ordering failures self-heal. Deterministic
failures cluster into classes (same error text) — hand the failure lines, the
journal (`restore-journal.jsonl`), and this repo to an assistant; every class
so far took under a day to fix. The drill org is disposable either way.

**`--wipe-org` refuses or fails** — the interlocks are: exact `--wipe-org-name`
required (even for preview), refuses any org with claimed devices, and the
teardown removes networks → config templates → non-caller admins → org. If the
org deletion still 400s, the error names what's left; delete it in the
dashboard or file the error text as a new teardown class.

**`terraform init failed` with a remote backend** — credentials come ONLY from
the environment/managed identity (`ARM_*`, `AWS_*`,
`GOOGLE_APPLICATION_CREDENTIALS`). Credential-shaped `--backend-config` keys
are refused by design.

**Discovery 403 on an endpoint** — recorded as a coverage gap, not fatal
(insight monitoredMediaServers is a permanent known one on the dev org: API
key scope).

## 5. Upgrade checklist (where surprise breakage comes from)

Bump ONE thing at a time; after each: `tox`, then a read-only live run, then —
for anything touching restore — a drill.

1. **Meraki OpenAPI spec** — self-updates each run (`spec3.json`, pulls latest
   release). New endpoints appear automatically; a spec change is the usual
   cause of new unsupported/coverage lines.
2. **Terraform provider (CiscoDevNet/meraki)** — changes what is expressible.
   After a bump, expect coverage to move and possibly plan-normalization
   churn. Policy: official registry provider ONLY, no forks.
3. **meraki Python SDK** — restore/replay call through it. Watch for renamed
   operation methods (the spec's operationIds are the contract).
4. **Terraform binary** — plan-output parsing is column-anchored
   (`terraform_runner.py`); a major bump warrants a kit run + `--rebuild`
   preview.
5. **Python** — tox runs 3.11–3.14; add the new version to `tox.ini` and CI
   your way in.

Dependency policy (contract): stdlib + the pre-approved list only. No poetry,
no ruff, no uv. New pip modules need explicit human approval.

## 6. Drill runbook (condensed)

Full worked example with logs: `~/meraki2tf-e2e-r2/` (2026-07-14 round).

```bash
# 0. optional: keep the org's test variety topped up (idempotent)
python seeder.py <org-id>                        # lives in the e2e workdir

# 1. snapshot + sanitize (secrets/identity never enter the drill org)
meraki2tf --org-id <org> --dump-to raw.json
meraki2tf --org-id <org> --from-dump raw.json --dump-to san.json --sanitize

# 2. fresh scratch org (dashboard or SDK), then preview + drill
meraki2tf --restore --from-dump san.json --target-org <SCRATCH> --skip-claims --workdir wd-drill
meraki2tf --restore --confirm --from-dump san.json --target-org <SCRATCH> --skip-claims --workdir wd-drill

# 3. PASS = "N executed, 0 failed"; skips must all be drill verdicts
#    (hardware-class, disabled-state, null-only echoes, template-bound).
#    Rerun the same command once: journal-resume must re-fail nothing.

# 4. teardown (interlocked; removes networks, templates, drill admins, org)
meraki2tf --wipe-org <SCRATCH> --wipe-org-name "<exact name>" --confirm
```

Heal drill (same-org recovery): unsanitized `--dump-to baseline.json`, delete
something in the scratch org, `--heal --from-dump baseline.json --org-id
<SCRATCH>` preview then `--confirm`; expect 0 failed and survivors untouched.

## 7. Working on the code (yourself or with an AI assistant)

Context to hand an assistant, in order of value: the failing run log, the
drill journal, `CLAUDE.md` (the contract), this file. That combination has
been enough to fix every issue to date in a fresh session.

House rules (enforced by contract + pre-commit):
- Never mutate Meraki outside the five `--confirm` DR actions; the apply guard
  stays in `terraform_runner`; each flag alone is a preview.
- Feature branches + PRs only, signed commits, `tox` green before merge
  (flake8, strict mypy, py311–py314), coverage stays ~99% on the engines.
- Secrets: only the unsanitized snapshot and the state file may hold values
  (0600); logs/alerts/artifacts carry names, never values.
- Any change touching `restorer.py`, `sanitizer.py`, or `discovery.py` gets a
  drill before it's trusted, no matter how green the tests are.

## 8. Invariants that must never regress

1. Meraki is never mutated outside explicit human-invoked `--confirm` actions.
2. Every discovered object is accounted for: imported, pending-import, or
   unsupported-with-reason. Silence is the only forbidden state.
3. Sync applies only 100%-import plans, verified from the saved plan document
   immediately before applying.
4. Deletions never silently leave the DR kit.
5. Restore never targets its own source org; heal never targets anything else.
6. Sanitized snapshots must stay drill-valid (resolvable URLs, coherent CIDRs,
   preserved product constants) — the sanitizer is part of the DR path, not
   just a privacy filter.

## 9. Releasing a version

Releases are tags on `main` plus a matching `CHANGELOG.md` entry (Keep a
Changelog). Checklist:

1. Land everything for the release on `main`; CI green (lint, strict mypy,
   pip-audit, py311–py314, coverage gate).
2. Update `CHANGELOG.md`: move `[Unreleased]` content under a new
   `[X.Y.Z] - YYYY-MM-DD` heading and refresh the link references at the
   bottom.
3. Bump `version` in `pyproject.toml` to match.
4. Regenerate `requirements-lock.txt` if the `meraki` pin or its closure
   moved (instructions in that file's header). `tox -e lock` is the check —
   it runs in CI on every PR, and re-resolving is required whenever the SDK
   changes its *own* dependencies, not just when its version moves. A
   Dependabot bump rewrites the pinned line only; it does not re-resolve
   what sits underneath it, and a closure that no longer matches breaks the
   hash-pinned worker and container installs while every other check stays
   green.
5. Merge that PR, then tag the merge commit (signed) and publish:

   ```bash
   git checkout main && git pull
   git tag -s vX.Y.Z -m "meraki2tf vX.Y.Z"
   git push origin vX.Y.Z
   gh release create vX.Y.Z --title "meraki2tf vX.Y.Z" \
     --notes "See CHANGELOG.md for the full list."
   ```

6. If the release touched `restorer.py`, `sanitizer.py`, or discovery, run a
   scratch-org drill before announcing it (§7 rule — no exceptions).
