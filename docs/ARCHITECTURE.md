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
├── spec/
│   └── engine.py         # Dynamic OpenAPI walker → operations, resource groups
├── openapi_parser.py     # OpenApiParser → Terraform names, compound IDs, lookup table
├── providers/            # Dual-modality ingestion (MerakiDataProvider protocol)
│   ├── base.py           #   fetch_network_graph() contract shared by both modes
│   ├── live.py           #   LiveApiDataProvider — Meraki SDK, spec-driven dispatch
│   └── dump.py           #   StaticJsonDataProvider — offline snapshot (--from-dump)
├── hcl_generator.py      # HclImportGenerator → imports.tf + exception auditing
├── terraform_runner.py   # subprocess runner: provider.tf, init, plan -generate-config-out, apply
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
   `meraki_networks`), joins snake_cased segments into
   `cisco-open/meraki` resource names, and orders path parameters into
   compound import-ID components (`network_id,vlan_id`).
3. **Consume** — the live provider executes spec-discovered GET
   endpoints dynamically (`dashboard.<tag>.<operationId>`); the HCL
   generator resolves every asset through the derived lookup table.

## Execution Flow

```
OpenAPI spec ──► OpenApiParser ──► endpoint → resource lookup table
                                              │
Live SDK ──┐                                  ▼
           ├─► MerakiDataProvider ──► NetworkGraph ──► HclImportGenerator
JSON dump ─┘   (identical domain models)     │        │            │
                                             │   imports.tf   UNSUPPORTED_FEATURE_FLAGGED
                                             ▼                     alerts
                     TerraformRunner: provider.tf → init
                       → plan -detailed-exitcode -generate-config-out
                             │                        │
                       delta found              state in sync
                             │                        │
                      DRIFT_DETECTED alert            │
                             └──────────► apply ◄─────┘
                                            │
                                      RUN_SUCCESS alert
```

`PipelineOrchestrator` owns this cycle; any stage failure dispatches a
`PROCESSING_FAULT` alert and surfaces as `PipelineError` → exit code 1,
making the CLI safe for headless cron scheduling.

## Security Posture

- The API token lives only in `MERAKI_DASHBOARD_API_KEY`; it is read at
  client-construction time, passed into the SDK, and never retained.
- `SecretRedactionFilter` scrubs `Authorization` /
  `X-Cisco-Meraki-API-Key` values from every log record at every level.
- The generated `provider.tf` is credential-free — the Terraform
  provider reads the same environment variable itself.
- Alert payloads carry resource identifiers and structural data only.
