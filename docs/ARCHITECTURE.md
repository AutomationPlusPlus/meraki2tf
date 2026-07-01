# meraki2tf Architecture

Baseline structural layout for the extraction/translation pipeline. See
`CLAUDE.md` for the binding project contract.

## Package Layout

```
src/meraki2tf/
├── cli.py               # Ad-hoc / cron-schedulable entry point (console script: meraki2tf)
├── config.py            # RuntimeConfig, execution modes, env-only secret sourcing
├── logging_setup.py     # Clean vs. verbose profiles + mandatory secret redaction
├── providers/           # Ingestion Engine interface (Step 2 of the pipeline)
│   ├── base.py          #   ConfigurationProvider ABC — operationId-keyed execution
│   ├── live.py          #   Meraki cloud SDK provider (lazy client, suppressed key logging)
│   └── dump.py          #   Offline JSON snapshot provider (--from-dump)
├── spec/                # Spec Ingestion Engine (Step 1 of the pipeline)
│   └── engine.py        #   Dynamic OpenAPI walker → operations, resource groups, registry
└── notifications/       # Alerting infrastructure (Steps 4–6 triggers)
    ├── models.py        #   Event schema: drift / run-success / unsupported-feature payloads
    ├── base.py          #   Notifier ABC (channel plugin contract)
    ├── webhook.py       #   Webhook channel plugin (transport TBD)
    ├── email.py         #   Email channel plugin (transport TBD)
    └── dispatcher.py    #   Fan-out with per-channel failure isolation
```

## Dynamic OpenAPI Processing Strategy

The contract prohibits hard-coded mapping tables. The Spec Ingestion
Engine therefore derives everything from the OpenAPI document at
runtime, in four stages:

1. **Ingest** — load the spec from a local file (`--spec`) or, in a
   later iteration, pull the latest published release. Validation stops
   at "has a `paths` object"; the walker is tolerant of vendor
   extensions and unknown keys so future spec releases parse unchanged.
2. **Enumerate** — walk `paths` × HTTP methods to yield one
   `OperationSpec` per `operationId`, capturing the path template, its
   ordered `{templated}` parameters, tags, and the raw operation object
   for later schema interrogation.
3. **Group** — cluster operations by shared path template into
   `ResourceGroup`s. The path template is the natural resource boundary
   in the Meraki API; a group with both `get` and `put` signals a
   manageable Terraform resource, read-only groups become data sources.
4. **Map (future)** — `build_registry()` will correlate resource groups
   against the Terraform provider schema to produce the API-to-Terraform
   registry: attribute mappings, compound import ID formats derived from
   `path_params` (e.g. `networkId,vlanId`), and a list of attributes the
   provider cannot express, which feeds the exception-auditing alerts.

Because discovery keys everything by `operationId`, the
`ConfigurationProvider` abstraction executes those same IDs against
either the live SDK or an offline snapshot — the registry never knows
which mode produced the data.

## Execution Flow (target state)

```
OpenAPI spec ──► SpecIngestionEngine ──► resource registry
                                              │
Live SDK ──┐                                  ▼
           ├─► ConfigurationProvider ──► discovered config ──► HCL + import blocks
JSON dump ─┘                                  │
                                              ▼
                            drift comparison vs. .tfstate
                             │            │           │
                       drift alert   state merge   unsupported-
                       (webhook/     + success     feature audit
                        email)       notification  alerts
```

## Scheduling & Security Posture

- The CLI is non-interactive end to end, so a weekly cron entry is just
  `meraki2tf --spec spec.json` (or `--from-dump` for air-gapped runs).
- The API token exists only in `MERAKI_DASHBOARD_API_KEY`; it is read at
  client-construction time, never stored, and `SecretRedactionFilter`
  scrubs `Authorization`/`X-Cisco-Meraki-API-Key` values from every log
  record regardless of verbosity.
