# meraki2tf (Project Contract)

## Core Mission & Architecture
A robust, secure, and schedulable CLI tool written in Python to extract Cisco Meraki configurations, map them to Terraform structures using the Meraki OpenAPI specification, evaluate state drift, generate import blocks for new resources, and flag unsupported parameters.

**Primary Disaster-Recovery Mission:** The owning team manages Meraki via clickops; meraki2tf is the safety net. Run on a schedule (typically weekly), it dumps **everything** out of the Meraki tenant, converts it into runnable Terraform artifacts, and materializes a Terraform state from them — so the environment can be rebuilt after a major incident. Meraki (the dashboard) is the source of truth in this mode; Terraform trails it, never leads it.

**Secondary Ad-hoc Mission:** As an open-source tool, meraki2tf must remain equally useful for one-shot users who want to generate Terraform for an org once and then own/maintain it themselves. The default invocation therefore stays conservative (see Mode Gating below); DR automation is opt-in.

### The Two Cardinal Rules
1. **Meraki is never mutated.** No run — scheduled, ad-hoc, live, or dump — may ever change anything in the Meraki organization. The sole exceptions are the explicit, human-invoked disaster-recovery actions `--rebuild --confirm` (terraform apply of the kit) and `--replay-gaps --confirm` (snapshot replay of unsupported objects and uncaptured secrets); each flag alone is a read-only preview.
2. **Nothing Terraform can't rebuild goes unreported.** The operator must always be able to answer "what is and isn't covered by Terraform?" with 100% certainty. Every discovered Meraki object that cannot be represented/imported (unsupported by the provider, skipped, or errored) must surface in the coverage manifest and in notifications — that list is the manual-rebuild runbook after a disaster.

### Core Pipeline Steps
1. **Dynamic Spec Ingestion:** Parse the Meraki OpenAPI JSON schema dynamically (either via a local file or pulling the latest release) to programmatically build the API-to-Terraform resource registry. **Hard-coded mapping tables are strictly prohibited**; the engine must dynamically derive resources and compound ID paths from the spec metadata to stay future-proof.
2. **Configuration Discovery:** Ingest the *entire* organization via dual input modalities (Live Cloud API or Offline JSON Dump). Completeness matters more than speed — a DR kit missing objects is a false sense of security.
3. **HCL Construction:** Write clean, declarative configuration structures natively utilizing modern Terraform `import` blocks.
4. **State Orchestration & Drift Alerting:** Compare discovered configurations against the existing state file via a read-only speculative `terraform plan` (skipped gracefully when no API key is available, e.g. air-gapped dump runs). Pending imports are normal snapshot growth, not drift. In sync/DR mode, import-only plans are auto-applied to grow the state (see State Materialization). Real add/change/destroy differences produce a diff payload and **trigger a drift alert** via configured notification channels.
5. **Artifact Completion & Success Notification:** Leave a complete rebuild kit (`imports.tf`, `provider.tf`, the accumulated `resources.tf` baseline, the coverage manifest, and the per-run `runbook.md` DR runbook) in the workspace. Upon absolute execution success, **dispatch a success notification** confirming a clean run and summarizing what changed since the last run (resources added to state, drift observed, coverage gaps).
6. **Exception Auditing & Coverage Manifest:** Flag parameters or features unsupported by the Terraform provider, emit structured payloads to alerting endpoints, and write the per-run coverage manifest (see Coverage Guarantee).

---

## State Materialization (Guarded Import-Only Apply)

The weekly DR job must build real Terraform state unattended, which requires applying import blocks. This is permitted under a strict guard, because `import` blocks only write state — they never touch Meraki:

- In sync/DR mode, after the speculative plan, the pipeline may run `terraform apply` **only when the plan is 100% imports (0 to add, 0 to change, 0 to destroy)**.
- If the plan contains *any* mutation, the apply is **aborted** and a drift alert fires with the diff. A human decides what happens next.
- Every auto-applied run must report exactly which resources were added to state (in the log and in the success notification), so weekly reruns tell the operator what grew.
- Default (non-sync) runs keep today's behavior: generate the kit, plan speculatively, never apply. State building is then a human/CI step outside the tool.

### Drift Handling Defaults (DR mode)
- **New objects in Meraki:** auto-generated, auto-imported into state, reported in the run summary/notification.
- **Modified objects:** the HCL baseline is regenerated to mirror current Meraki (Meraki is truth) and the diff is dispatched via alerts.
- **Deleted objects:** **alert-only.** Deletions are never silently synced out of the DR kit — an accidental clickops deletion must not quietly poison the rebuild baseline. A human reviews the alert and confirms removal (e.g. via `--rebaseline` or an explicit confirmation flag).

### Mode Gating
- **Default invocation** = ad-hoc/open-source mode: strictly read-only end-to-end (kit generation + speculative plan + alerts). Safe for anyone to run against any org.
- **`--sync` (opt-in DR mode):** enables the guarded import-only auto-apply and modified-object HCL regeneration described above. This is the flag the scheduled weekly job passes.

---

## Coverage Guarantee ("what is / isn't in Terraform")

- **Per-run coverage manifest:** every run writes a machine-readable `coverage.json` (and human-readable summary) into the workdir listing **every** discovered Meraki object with a status: `imported` (in state), `pending-import` (in kit, not yet in state), or `unsupported` (cannot be rebuilt by Terraform — include the reason). Include totals and a coverage percentage.
- **Unsupported objects are pushed, not just stored:** success and drift notifications always carry the count and list of objects Terraform cannot rebuild, so the manual-rebuild list reaches the operator every week without them checking disk.
- Optional CI gate: a flag (e.g. `--fail-on-gaps`) makes the run exit nonzero when unsupported objects exist, so schedulers can gate on full coverage.

### Implementation Status Note
The full contract above is implemented as of 2026-07-02: `--sync` guarded auto-apply (guard in `terraform_runner.apply_import_plan`), the deletion flow (`DELETION_PENDING_CONFIRMATION` alert + `--confirm-deletions`), the coverage manifest (`coverage.json`/`coverage.txt`), and `--fail-on-gaps` (exit 3). As of 2026-07-03 the DR gap surface is implemented too: the per-run `runbook.md` (redacted payloads + replay operations + secret re-entry pointers, regenerated every run in `runbook.py`) and the guarded `--replay-gaps` action (`replayer.py`; preview by default, `--confirm` writes unsupported objects and dump-sourced secrets back via the SDK with name-based network-ID remapping, `GAP_REPLAY_EXECUTED` alert). Secrets at rest: unsanitized snapshots and the Terraform state are written/kept owner-only (0600); artifacts and alerts never carry secret values. None of it — nor the earlier surface (read-only pipeline, `--rebuild --confirm`, `--rebaseline`, dump/live providers, webhook/email alerts) — may regress.

---

## Workspace Modes of Operation

### 1. Live Mode (Cloud Streaming)
Queries target environments directly via the official Meraki cloud ecosystem.
- Authentication: Must read token dynamically via `MERAKI_DASHBOARD_API_KEY`.
- Rate Limiting: Handle the 10 requests/sec endpoint limit safely (handled natively via the Meraki Python SDK).

### 2. Dump Mode (Offline Execution)
Accepts a filepath parameter to an offline local JSON snapshot file (`--from-dump path/to/file.json`).
- Architecture: Employs a Provider interface abstraction to guarantee structural processing parity between live JSON payloads and static file configurations.
- Perfect for air-gapped runtimes, scheduled offline parsing, or running regression test validations.

---

## Environment & Tooling Commands

### Environment Initialization (No Poetry, No UV)
- **Setup Environment:** `python3 -m venv .venv && source .venv/bin/activate && pip install --upgrade pip`
- **Install Core Packages:** `pip install pre-commit flake8 mypy tox meraki pytest pytest-cov`

### Code Quality & Validation Pipeline
- **Run Complete Check Suite:** `tox`
- **Run Python Linter:** `flake8 src/ tests/`
- **Run Static Type Checker:** `mypy src/`
- **Run Test Suite:** `pytest`
- **Verify Code Coverage:** `pytest --cov=src --cov-report=term-missing`

---

## Strict Guardrails & Constraints

### 🚫 Banned Tools & Ecosystems
Do NOT install, generate configurations for, or utilize:
- `poetry`
- `ruff`
- `uv`

### ⚠️ Dependency Escalation Policy
- Pre-approved: `meraki` (SDK), `pre-commit`, `flake8`, `mypy`, `tox`, `pytest`, `pytest-cov`, and Python standard library utilities.
- **CRITICAL:** The agent must explicitly halt and request human operational authorization before introducing *any* other external pip module.

### 🔒 Meraki Read-Only Guarantee (Apply Guard)
- No run may **ever** mutate the Meraki organization. The only paths that touch Meraki are the explicit disaster-recovery actions `--rebuild --confirm` and `--replay-gaps --confirm`; each flag alone must remain a read-only preview, and neither may ever run as part of a scheduled/pipeline invocation.
- `terraform apply` against *state* is permitted only via the sync-mode guard: the plan must be verified as import-only (0 add / 0 change / 0 destroy) immediately before applying, and any violation aborts with an alert. Default (non-sync) runs never apply anything.
- Belt-and-suspenders: the guard check must live in `terraform_runner`, not just the orchestrator, so no future call path can bypass it.

### 🛡️ Security First Principle
- **Secret Handling:** Zero tolerance for plaintext token parameters, hardcoded API variables, or hardcoded organization credentials in the repository, state logs, or output fields.
- **Verbose Logging Isolation:** Ensure that verbose/debug console and log systems exclude raw `Authorization` HTTP headers or private configuration values.
- **Secret-Bearing Artifacts:** Exactly two artifacts may hold secret values — the unsanitized snapshot and the Terraform state — and both must be written/kept owner-only (0600). Everything else (HCL kit, coverage manifest, runbook, alerts, logs, replay results) carries attribute names and locators, never values; the gap replayer reads secrets from the snapshot at execution time and holds them only in memory.

### 🧪 Code Coverage Target
- Maintain as close to **100% test coverage** as possible for all parsing, structural translation, and alerting engines to eliminate regression bugs.
- Mocking: Utilize local JSON mock dictionaries to test configuration mappings exhaustively without relying on network sockets.

### 🐙 GitHub & Git Collaboration Workflow
- **Cryptographic Signatures:** Every single commit must be cryptographically signed by Git. Confirm signing parameters are functioning before execution.
- **Commit Cycle:** Commit modifications regularly in small, logically structured atomic units.
- **Branching & PR Strategy:** Never commit directly to `main`. Create scoped feature branches (e.g., `feature/openapi-parser`) and structure code layout iterations to support clean GitHub Pull Request reviews.

### 📢 Notification & Alerting Infrastructure
- Build decoupled modular notifier plugins (Webhook targets, Email placeholders).
- **Trigger alert/notification dispatching on:**
  - Detection of configuration drift/differences during the comparison phase (including aborted auto-applies).
  - Successful finalization of a run — including the list of resources newly added to state and the current unsupported/coverage summary.
  - Identification of unsupported Meraki features or critical script processing faults.
  - Deletions detected in Meraki that await human confirmation.
