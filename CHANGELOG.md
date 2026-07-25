# Changelog

All notable changes to meraki2tf are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Operator preflight (#102): `--check` validates an entire flag set in
  seconds — API key, `--org-id` resolution, terraform binary and
  version, provider catalog, `--drift-baseline` header, workdir
  writability, alert-channel configuration — one PASS/FAIL/SKIP line
  per check, nonzero exit on failure, mutating nothing; `--estimate`
  prints the expected discovery request count and wall-clock estimates
  (2-3 API calls live, zero offline); `--expect-org` pins `--rebuild`
  and `--replay-gaps` to a named organization (both actions print the
  resolved org either way); and the pipeline runs the cheap
  validations (baseline header, terraform version probe) *before* the
  discovery sweep instead of failing hours into it.
- Discovery progress and resume (#103): the multi-hour sweep emits one
  INFO progress line at most every ~30 s (items done/total, overall
  count, effective request rate, rough ETA — renders in JSON logs
  too), and `--discovery-checkpoint PATH` journals every completed
  call (0600 JSONL, `.gz` supported; org-ID + spec-sha guarded,
  torn-tail tolerant) so an aborted sweep resumes instead of
  restarting; a completed run deletes its journal.
- Scoped pipeline runs (#103): `--only 'network:PATTERN'` on a default
  live pipeline run generates the kit and plan for just the matching
  networks — artifacts stamped PARTIAL with the covered networks,
  plan/apply targeted at the captured addresses so out-of-scope state
  is never touched, deletion review skipped (and
  `--confirm-deletions`/`--rebaseline`/`--drift-baseline` refused
  alongside it).
- Cross-network conformance diff (#103): `--diff-networks A B`
  (optionally `--diff-out report.json`) compares two networks'
  configuration through the snapshot-diff engine, live or offline —
  attribute names and locators only, never values.
- Coverage integrity (#100): GET-less mutable surfaces (Air Marshal,
  RRM, uplink NAT, …) are adopted via their org-scoped byNetwork
  aggregation GETs and exploded into per-network assets; network
  endpoints are prefiltered by product type derived from the
  createNetwork enum (an absent enum disables filtering); the
  manifest gains a `duplicate-id` status, spec-level fields
  (`excluded_rpc_paths`, `api_read_only_paths`, `suspect_endpoints`)
  and reconciled totals with `totals.unaccounted` (loud ACCOUNTING
  MISMATCH banner); write-only spec endpoints are flagged
  unsupported; `coverage.txt` groups repeated unsupported gaps by
  endpoint + reason.
- Bash flag completion at `deploy/completion/meraki2tf.bash`,
  CI-pinned against the real argument parser, with README/OPERATIONS
  pointers (this PR).
- A development requirements file (`requirements-dev.txt`) with the
  flake8/mypy/tox/pytest/pre-commit/pip-audit toolchain (this PR).

### Changed
- The bundled fallback provider catalog is refreshed to
  `CiscoDevNet/meraki` **v1.13.0** (206 resource identity schemas, up
  from v1.12.2's 205). The only delta is the added
  `meraki_network_firmware_upgrades_rollback` type — no identity
  attribute changed and nothing was removed, so no import ID moves.
  That type is a POST-only action sharing its identity (`network_id`)
  with `meraki_network_firmware_upgrades`; the matcher correctly maps
  it to nothing, and a regression test now pins that so it can never
  shadow the real resource. This affects only first-ever offline runs
  (no API key *and* no workdir cache) — keyed runs already read the
  installed provider's schemas, so they picked v1.13.0 up on their next
  `terraform init` without this change. The floor stays `>= 1.12.0`
  (identity schemas ship from there), but **v1.13.0+ is now
  recommended**: it fixes the "Missing Resource Identity After Read"
  provider error on resources deleted out-of-band, which is exactly the
  clickops-deletion case the DR loop is built to survive.
- `--expect-org` is now refused alongside `--diff-networks` (#112)
  instead of being silently ignored. It pins a `--rebuild` /
  `--replay-gaps` target (as `docs/USAGE.md` already documented) and
  had no effect on a standalone comparison; every sibling helper
  (`--list-orgs`, `--check`, `--estimate`) already refused it. **This
  is the one behavior change in the release**: an invocation that
  previously ran the comparison while ignoring the flag now exits 2.
- The CLI's flag-compatibility rules are declarative (#112): the
  recurring flag sets are named groups (`DR_ACTION_FLAGS`,
  `DR_TARGETING_FLAGS`, `PIPELINE_FLAGS`, `EXPORT_FLAGS`) shared by
  per-mode `_validate_*` helpers, replacing eight hand-written `or`
  chains whose memberships could silently disagree. Every refusal
  message is unchanged.
- Shared helpers replace four sets of copy-pasted internals (#111), so
  a rule can no longer be fixed in one copy and left stale in another:
  one HCL literal escaper for every Terraform writer (`hcl.py`), one
  definition of the drift-baseline header refusals
  (`snapshot_diff.validate_baseline_header`), one rule set mapping
  string *and* numeric ID references in the sanitizer, and one
  `meraki.DashboardAPI` construction site (`sdk_client.py`) that pins
  the SDK log-suppression arguments for all eight callers. Behavior
  and every operator-facing message are unchanged.

### Fixed
- Lone UTF-16 surrogates no longer crash the `resources.tf` baseline
  write (#111): the kit generator scrubbed them before escaping but
  the plan reconciler's copy of the escaper did not, so a surrogate
  arriving from a snapshot raised `UnicodeEncodeError` at write time.
  Both now share the scrubbing escaper.
- Pure-input refusals always win over the terraform environment probe
  (#106): a partial-snapshot/`--sync` mistake or a foreign discovery
  checkpoint now produces the same exit-2 refusal whether or not the
  host has terraform installed (previously CI-only failures — the
  probe's fault shadowed the refusal on terraform-less runners).
- `--diff-networks` accepts the `--only` selector spelling
  (`network:PATTERN`) in addition to bare patterns (#107).
- byNetwork aggregation explosion (#108): nested-element rows
  (per-SSID openRoaming lists) explode at the entity's own write path
  instead of colliding with the ssids entity, and rows keyed by
  Meraki's per-product child network ids ("N_…", named
  "parent - wireless") resolve to their parent network by name;
  unresolvable rows stay auditable gap records instead of becoming
  phantom-addressed objects.
- Drill edge cases from the live scratch-org restore (#109):
  scope-less diagnostic gap records are plan-time skips in both the
  restorer and the gap replayer (never dispatched, never counted
  failed); empty-default payloads (e.g. VPN exclusions `[]`) skip with
  "nothing to restore" instead of PUTting no-ops that 400 on
  prerequisite-less networks; config templates join the aggregation
  scope-resolution universe; `--wipe-org` retries Meraki's transient
  "currently processing data" refusal of organization deletion
  (5 × 30s, conservative match).
- Provider import refusals degrade instead of killing the run (#104):
  terraform's "Cannot import non-existent remote object" diagnostic
  (no `with <address>,` line — the address is quoted inline) now rides
  the drop-and-report-unsupported rail, observed live with
  byNetwork-adopted settings surfaces the provider refuses to import
  until they are configured on the network.
- Sanitizer and drift-diff correctness (#99): collision-free fake /24
  subnets, fingerprint-safe MAC/IPv6 anchors, and arity-safe
  `pathValues` in the sanitizer; order-significant rule lists
  (firewall, port forwarding) report explicit `<order changed>`
  entries instead of value dumps; rollout suppression is
  population-gated; response envelopes are normalized before
  comparison; a drift baseline captured from a different organization
  is refused; workspace surgery is heredoc-aware with exhaustive
  multi-file edits and an aged plan-copy sweep; `pending_imports`
  converges to 0 once chunk windows are fully imported.
- DR write hardening (#101): every dynamically resolved SDK method's
  verbs are source-verified before a DR write dispatches (put/post
  only, delete never — fail-closed); restore/heal probe object
  liveness at execution time, so a second incident after a successful
  heal re-executes journaled actions whose object is missing again,
  while heal skips anything verified alive (additive-only held even
  when the sweep undercounted survivors; reported as
  `verified_alive_skips`); throttled writes never enter the
  reference-deadlock breaker; DR write actions never auto-refresh the
  OpenAPI spec (deterministic mid-incident reruns), snapshot headers
  record the spec version + sha256, and restores warn on spec skew;
  the pending-deletions record is written atomically.
- Terraform is version-probed up front and the generated kit pins
  `required_version = ">= 1.5.0"`; the runbook's rebuild step is
  preview-first (#102).
- Documentation now matches actual behavior (this PR): the generated
  kit authenticates via the provider's `MERAKI_API_KEY` (bridged from
  `MERAKI_DASHBOARD_API_KEY` only for tool-spawned terraform — manual
  runs must export it); the cron recipe passes `--drift-baseline`
  conditionally so the first run succeeds unedited; the bad-org-id
  troubleshooting entry quotes the real failure shape and points at
  `--list-orgs`/`--check`; the coverage badge matches the 100% CI
  gate; the `--wipe-org` "cannot target production" claim is scoped
  honestly (a device-less org is protected only by the exact-name
  second factor); the architecture module map covers every module and
  the alert table lists all 10 events (REBUILD_EXECUTED was missing).
- Restore/heal no longer fails a whole configure write when the
  dashboard refuses a single product-type-dependent setting ("Remote
  status page is not supported by this network", found live in the
  2026-07-22 selective-heal drill): the named field(s) are stripped —
  mapped from the error phrase to payload keys by camelCase tokens, no
  field table — and the remaining captured state is retried. Field
  names (never values) are logged; a payload that was nothing but
  unsupported settings becomes a skip verdict instead of a failure.

### Added
- Selective backup: `--dump-to … --only 'network:PATTERN'` scopes live
  discovery to the matching networks (name/ID glob, repeatable, union)
  and writes a **partial** snapshot in minutes instead of hours — the
  pre-change safety net for risky edits to one network. The snapshot
  records its scope in the header; org-level objects and config
  templates stay captured so references remain recreatable. `--heal`
  honors the scope (its live discovery narrows to the recorded
  networks, and the `HEAL_EXECUTED` alert names the partial scope),
  while `--restore`, `--replay-gaps`, `--drift-baseline`, pipeline
  `--sync`/`--confirm-deletions`, and the scheduled Azure wrapper all
  refuse partial snapshots — a selective backup can never masquerade
  as a full-organization capture. Coverage manifest, runbook, and
  RUN_SUCCESS notifications of scoped runs carry a PARTIAL banner
  naming the covered networks (Cardinal Rule 2).
- Selective heal: repeatable `--only '[TYPE:]PATTERN'` selectors
  restrict `--heal` to a subset of the missing objects (e.g. restore
  one of two deleted networks, or some of several deleted SSIDs).
  Selectors are case-insensitive globs over each missing object's name
  or ID with an optional spec-derived type prefix; a matched container
  selects its whole missing subtree, missing dependencies (deleted
  parents, referenced missing objects) are auto-included and reported,
  and a selector matching nothing is refused. Filtering only ever
  shrinks the run — additive-only, preview-first, and journaling are
  unchanged, and the `HEAL_EXECUTED` alert names the active filters.
- Multi-organization fan-out: `--org-id` is repeatable (config file:
  `org-ids` array). Organizations run sequentially with per-org
  sub-workdirs and state; remote backends take an `{org-id}`
  placeholder in the state address; the exit code is the most severe
  per-org outcome. Snapshot modes and DR actions remain
  single-organization.
- Scheduling recipes beyond Azure: hardened systemd service+timer
  pairs under `deploy/systemd/`, plus AWS (EventBridge → Fargate) and
  GCP (Cloud Scheduler → Cloud Run Job) recipes in
  `docs/OPERATIONS.md`.

### Changed
- `requirements.txt` is runtime-only (the meraki SDK pin); the dev
  toolchain moved to `requirements-dev.txt` — install docs updated,
  CI/tox/Docker were never wired through it (this PR).
- systemd units: explicit `TimeoutStartSec=infinity` (no manager
  default can SIGTERM a multi-hour sweep), mandatory-edit markers on
  the placeholder `--org-id`/paths, `--discovery-checkpoint` on the
  snapshot unit, and commented optional retention steps; new
  OPERATIONS sections cover snapshot retention/archival and the
  API-key permission model (read-only admin suffices for every read
  path), and the DR guide opens with an incident-to-action decision
  matrix (this PR).
- The monolithic README is split into `docs/USAGE.md`,
  `docs/DR-GUIDE.md`, and `docs/OPERATIONS.md`; the README is now a
  landing page with a documentation index.
- Every alert now carries an `organization_id` in its details (stamped
  by the dispatcher as soon as the organization is known), so
  multi-org fan-out consumers can attribute interleaved events to the
  right organization. Events that already name their organization
  (the DR actions) keep their own value.
- Half-set SMTP AUTH credentials (`MERAKI2TF_SMTP_USERNAME` /
  `MERAKI2TF_SMTP_PASSWORD`) now refuse at startup — matching the
  `--pagerduty` routing-key check — instead of surfacing after the
  discovery sweep as a delivery failure on every alert.
- The snapshot-diff drift alert summary now says the comparison was
  against the drift baseline; it previously claimed a
  Terraform-state comparison regardless of origin.
- Confirmed-deletion state removal logs requested-vs-removed counts
  ("Removed 1 of 2 requested resource(s) … (1 already absent)"), so
  an address already dropped by an earlier refresh no longer makes
  the log under-report the confirmed removals.

## [0.1.0] - 2026-07-20

First tagged release. Everything below is the state of the tool at
tagging time, proven by a full-organization restore drill into a
scratch organization (sanitized snapshot, 0 failures) and a same-org
heal drill.

### Core pipeline (read-only by default)
- Spec-driven discovery of the entire Meraki organization (dynamic
  OpenAPI ingestion — no hard-coded endpoint tables), live-API and
  offline-snapshot providers with identical downstream shape.
- Terraform kit generation: modern `import {}` blocks, accumulated
  `resources.tf` baseline, credential-free `provider.tf`, speculative
  plan comparison, per-run `coverage.json`/`coverage.txt` manifest and
  `runbook.md` DR runbook.
- Drift detection via speculative plan or snapshot diffing
  (`--drift-baseline`), with alerting on drift, success, unsupported
  features, pending deletions, and processing faults.
- `--sync` DR automation: guarded import-only auto-apply (0 add /
  0 change / 0 destroy verified in `terraform_runner` immediately
  before applying), chunked `-target` windows for busy organizations,
  deletion confirmation flow (`--confirm-deletions`), `--rebaseline`.
- State backends: local (default), azurerm, s3, gcs — credentials
  env/managed-identity only; credential-shaped settings refused.

### Disaster recovery (each preview-first; `--confirm` executes)
- `--rebuild` (terraform apply of the kit), `--replay-gaps` (snapshot
  replay of Terraform-unsupported objects and uncaptured secrets),
  `--restore` (full-org rebuild into a separate `--target-org`,
  wave-ordered, journaled/resumable, reference-rewriting),
  `--heal` (same-org additive-only recovery), `--wipe-org`
  (drill teardown, refused for any org holding claimed devices).
- Snapshot sanitizer (`--sanitize`) producing shareable, drill-safe
  exports.

### Interfaces
- `--config` TOML files (DR actions and credentials refused), grouped
  `--help`, `--version`, `--list-orgs`, `python -m meraki2tf`,
  documented exit codes 0–5.
- Alerting: webhooks (raw JSON, Slack, or Teams Workflows Adaptive
  Card via `--webhook-format`), email with STARTTLS verification and
  optional SMTP AUTH (env-only credentials), PagerDuty Events API v2
  (`--pagerduty`, WARNING/CRITICAL events only).
- Azure deployment path: hardened container image and two-phase
  runbook wrapper (Key Vault via managed identity, Blob archival,
  snapshot rotation) — `docs/azure-automation.md`.

### Security posture
- Meraki is never mutated outside the five confirmed DR actions; the
  import-only apply guard lives in `terraform_runner` (belt and
  suspenders).
- Secrets only ever in the unsanitized snapshot and the Terraform
  state, both 0600; all other artifacts and alerts carry names and
  locators, never values. Credential env-vars only — never flags or
  config keys; log redaction at every verbosity.

[Unreleased]: https://github.com/AutomationPlusPlus/meraki2tf/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AutomationPlusPlus/meraki2tf/releases/tag/v0.1.0
