# Changelog

All notable changes to meraki2tf are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
