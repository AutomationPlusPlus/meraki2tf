# Changelog

All notable changes to meraki2tf are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
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
