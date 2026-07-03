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

## Security Posture

- The API token lives only in `MERAKI_DASHBOARD_API_KEY`; it is read at
  client-construction time, passed into the SDK, and never retained.
- `SecretRedactionFilter` scrubs `Authorization` /
  `X-Cisco-Meraki-API-Key` values from every log record at every level.
- The generated `provider.tf` is credential-free — the Terraform
  provider reads the same environment variable itself.
- Alert payloads carry resource identifiers and structural data only.
