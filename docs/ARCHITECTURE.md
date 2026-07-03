# meraki2tf Architecture

Structural map of the production pipeline. See `CLAUDE.md` for the
binding project contract and `README.md` for usage.

## Package Layout

```
src/meraki2tf/
├── cli.py                # Entry point + pipeline assembly (console script: meraki2tf)
├── config.py             # RuntimeConfig, execution modes, env-only secret sourcing
├── logging_setup.py      # Clean vs. verbose profiles + mandatory secret redaction
├── models.py             # Shared domain objects: NetworkGraph, networks, devices, features
├── spec_resolver.py     # Spec freshness check + GitHub download (local → version-check → fetch)
├── spec/
│   └── engine.py         # Dynamic OpenAPI walker → operations, resource groups
├── openapi_parser.py     # OpenApiParser → Terraform names, compound IDs, lookup table
├── providers/            # Dual-modality ingestion (MerakiDataProvider protocol)
│   ├── base.py           #   fetch_network_graph() contract shared by both modes
│   ├── discovery.py      #   Shared spec-driven feature discovery, expansion, section matching
│   ├── live.py           #   LiveApiDataProvider — Meraki SDK, spec-driven dispatch
│   └── dump.py           #   StaticJsonDataProvider — offline snapshot (--from-dump)
├── snapshot.py           # Graph → canonical offline snapshot writer (--dump-to)
├── sanitizer.py          # Deterministic secret/identity scrubbing (--sanitize)
├── hcl_generator.py      # HclImportGenerator → imports.tf + exception auditing
├── terraform_runner.py   # subprocess runner: provider.tf, init, plan -generate-config-out
│                         #   (apply exists only as rebuild_apply for --rebuild --confirm)
├── orchestrator.py       # PipelineOrchestrator — full lifecycle + alert triggers
└── alerts/               # Decoupled alerting subsystem
    ├── models.py         #   Event contracts: DRIFT_DETECTED / RUN_SUCCESS /
    │                     #   UNSUPPORTED_FEATURE_FLAGGED / PROCESSING_FAULT
    ├── base.py           #   Notifier ABC (channel plugin contract)
    ├── webhook.py        #   urllib.request JSON POST channel
    ├── email.py          #   smtplib channel with injectable transport
    └── dispatcher.py     #   Fan-out with per-channel failure isolation
```

## Dynamic OpenAPI Processing

The contract prohibits hard-coded mapping tables, so everything is
derived from the OpenAPI document at runtime:

1. **Ingest** — `SpecIngestionEngine` loads the spec and walks
   `paths` × HTTP methods into `OperationSpec` records (operationId,
   path template, ordered `{templated}` parameters, tags).
2. **Derive** — `OpenApiParser` computes entity keys from non-parameter
   path segments, folds parent-scoped collection paths into their
   canonical entity (`/organizations/{organizationId}/networks` →
   the `networks` entity), and orders path parameters into compound
   import-ID components (`network_id,vlan_id`).
2b. **Match** — `resource_matcher` assigns each mutable entity its
   authoritative `CiscoDevNet/meraki` resource type by matching against
   the provider's resource identity schemas (`provider_catalog`:
   installed-provider schema dump → workdir cache → bundled fallback).
   Identity attributes must be satisfiable by the entity's path
   parameters, name tokens must be compatible with the path's words,
   scoring is coverage-first, and a global one-to-one assignment
   guarantees no resource is claimed twice; unmatched entities surface
   as unsupported coverage gaps.
3. **Consume** — `providers/discovery.py` selects the spec's
   configuration surfaces (GET endpoints whose entity also exposes a
   mutating verb — read-only telemetry is excluded) and normalizes each
   payload into importable assets. The live provider dispatches those
   endpoints dynamically (`dashboard.<tag>.<operationId>`); the dump
   provider resolves raw snapshot section names onto the same endpoints
   by name-token matching with response-schema tie-breaking. Both feed
   the HCL generator through the derived lookup table.

## Execution Flow

```
OpenAPI spec ──► OpenApiParser ──► entities ──► resource_matcher ──► endpoint → resource lookup
                                                     ▲                        │
                       provider identity schemas ────┘                        │
                (installed provider / cache / bundled)                        │
Live SDK ──┐                                  ▼
           ├─► MerakiDataProvider ──► NetworkGraph ──► HclImportGenerator
JSON dump ─┘   (identical domain models)     │        │            │
                                             │   imports.tf   UNSUPPORTED_FEATURE_FLAGGED
                                             ▼                     alerts
                     TerraformRunner: provider.tf → init
                       → plan -detailed-exitcode -generate-config-out
                          (skipped when no API key is available)
                             │                        │
                    real changes found       in sync / imports only
                             │                        │
                      DRIFT_DETECTED alert            │
                             └──────────┬─────────────┘
                                        │
                                 RUN_SUCCESS alert
                          (no apply — pipeline is read-only)
```

`PipelineOrchestrator` owns this cycle; any stage failure dispatches a
`PROCESSING_FAULT` alert and surfaces as `PipelineError` → exit code 1,
making the CLI safe for headless cron scheduling.

The pipeline never executes `terraform apply`: meraki2tf is a
disaster-recovery snapshotting tool and stays read-only toward the
Meraki organization. The single apply path is the explicit CLI action
`--rebuild --confirm` (`TerraformRunner.rebuild_apply`), which bypasses
the orchestrator entirely; `--rebuild` alone is a plan preview.

## Plan Reconciliation

`terraform plan -generate-config-out` builds configuration from what
the provider reads out of Meraki, but provider round-trip quirks leave
the very first plan proposing changes that correspond to nothing real
in Meraki. Unhandled, those phantom changes would fire a drift alert on
every scheduled run and permanently block the sync-mode guard (which
only auto-applies 100% import plans). `plan_reconciler.py` classifies
every diffed attribute of every planned update and converges the
workspace in a plan → classify → edit → re-plan loop. Every iteration
must make progress — drop a rejected resource or remediate an
(address, attribute) pair it has not touched before — or the loop ends
and whatever remains is reported as drift (a hard attempt cap guards
against pathological plans):

- **Unexpressible values** — the provider's validators reject values
  its own Read returns. Example from live testing: firmware upgrade
  windows, where the API returns `"Mon"` but the provider only accepts
  lowercase `"mon"` — writing the state value fails validation, writing
  the lowercase value diffs against state forever. Such resources are
  dropped from the kit and reported as `unsupported` (they are part of
  the manual-rebuild runbook, per the coverage guarantee).
- **Secret attributes** — generated config cannot carry sensitive
  values (`psk`, `community_string`, …), so the plan wants to null
  them. A `lifecycle { ignore_changes = […] }` edit suppresses the
  phantom diff, and the attributes are reported as *unmanaged secrets*
  in `coverage.json`, `coverage.txt`, and the success notification —
  restore them manually after any rebuild.
- **Value normalization** — state values that are JSON-equivalent to
  what the generated expression evaluates to but textually different:
  `jsonencode()` emits alphabetized keys and no whitespace, while
  Meraki stores its own key order and formatting. The whole attribute
  is re-synthesized in HCL directly from the state value (string
  leaves byte-exact, never via `jsonencode()`), which covers both
  whitespace and key-order diffs at any nesting depth. Empty strings
  the generator omitted (`"" → null`) are injected the same way. Real
  future drift on those attributes stays visible. Attributes with any
  sensitive leaf are never synthesized — that would write secret
  material into the workspace — and surface as drift instead.

A resource is only remediated when *every* diffed attribute is provably
phantom; a single unexplained diff leaves the whole resource alone so
genuine drift is never masked. All remediation is local file surgery —
Meraki is never touched.

## Security Posture

- The API token lives only in `MERAKI_DASHBOARD_API_KEY`; it is read at
  client-construction time, passed into the SDK, and never retained.
- `SecretRedactionFilter` scrubs `Authorization` /
  `X-Cisco-Meraki-API-Key` values from every log record at every level.
- The generated `provider.tf` is credential-free — the Terraform
  provider reads the same environment variable itself.
- Alert payloads carry resource identifiers and structural data only.
