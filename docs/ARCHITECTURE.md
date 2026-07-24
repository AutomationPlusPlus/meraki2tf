# meraki2tf Architecture

Structural map of the production pipeline. See `CLAUDE.md` for the
binding project contract and `README.md` for usage.

## Package Layout

```
src/meraki2tf/
├── cli.py                # Entry point + pipeline assembly + DR-action wiring (console script: meraki2tf)
├── config.py             # RuntimeConfig, execution modes, --config TOML loading, env-only secret sourcing
├── logging_setup.py      # Clean vs. verbose profiles, --log-format json, mandatory secret redaction
├── models.py             # Shared domain objects: NetworkGraph, networks, devices, features, SuspectEndpoint
├── spec_resolver.py      # Spec freshness check + GitHub download; refresh=False deterministic
│                         #   mode for DR write actions (never auto-refresh mid-incident) +
│                         #   spec fingerprinting (version + sha256) for snapshot headers
├── spec/
│   └── engine.py         # Dynamic OpenAPI walker → operations, resource groups
├── openapi_parser.py     # OpenApiParser → entities, compound IDs, byNetwork aggregation adoption
├── resource_matcher.py   # Entity → provider resource-type assignment against identity schemas
├── provider_catalog.py   # Provider identity-schema source: installed provider → workdir cache → bundled fallback
├── providers/            # Dual-modality ingestion (MerakiDataProvider protocol)
│   ├── base.py           #   fetch_network_graph() contract shared by both modes
│   ├── discovery.py      #   Shared spec-driven surface selection, aggregation explosion,
│   │                     #     spec-surface report (write-only/RPC/read-only), product-type derivation
│   ├── live.py           #   LiveApiDataProvider — SDK dispatch, worker pool, read-only source
│   │                     #     verification, suspect-endpoint tally, product prefiltering
│   ├── dump.py           #   StaticJsonDataProvider — offline snapshot (--from-dump), section matching
│   ├── ratelimit.py      #   Shared adaptive AIMD token bucket (≤6 req/s, global backoff)
│   ├── progress.py       #   ~30s INFO progress lines: items done/total, rate, rough ETA
│   └── discovery_checkpoint.py  # --discovery-checkpoint: 0600 JSONL journal; aborted sweeps resume
├── snapshot.py           # Graph → canonical snapshot writer (--dump-to; v1 JSON + v2 JSONL stream,
│                         #   header carries org, scope, and the spec fingerprint)
├── snapshot_diff.py      # --drift-baseline engine: spec-normalized attribute diff, order-change
│                         #   reporting, rollout suppression, cross-org/sanitized baseline refusal
├── sanitizer.py          # Deterministic secret/identity scrubbing (--sanitize)
├── scope.py              # --only selector grammar + partial-snapshot scope model (honor/stamp/refuse)
├── network_diff.py       # --diff-networks: two networks through the snapshot-diff engine (names only)
├── preflight.py          # --check / --estimate engines + shared cheap pre-sweep validations
│                         #   + --rebuild organization resolution (--expect-org interlock)
├── fileio.py             # Atomic writes (tmp + rename) for every artifact
├── fsperms.py            # Owner-only (0600) enforcement + degraded-filesystem warning
├── hcl_generator.py      # HclImportGenerator → imports.tf, duplicate-id records, exception auditing
├── coverage.py           # coverage.json / coverage.txt manifest: per-object status, spec-level
│                         #   accounting (rpc/read-only/suspect), reconciled totals (totals.unaccounted)
├── runbook.py            # Per-run runbook.md: manual-rebuild steps for every uncoverable object
├── terraform_runner.py   # subprocess runner: provider.tf, init, version probe, plan
│                         #   -generate-config-out, import-only apply guard, MERAKI_API_KEY bridge
├── plan_reconciler.py    # Phantom-diff classification: unexpressible values, secret attributes,
│                         #   value normalization — plan → classify → edit → re-plan convergence
├── orchestrator.py       # PipelineOrchestrator — full lifecycle, scoped (--only) runs, deletion
│                         #   review, chunked sync applies, alert triggers
├── sdk_verify.py         # Source-level verb verification of dynamically resolved SDK methods
│                         #   (read paths: get-only; DR writes: put/post only, delete never)
├── restorer.py           # THE WRITE ENGINE (--restore): wave-ordered dependency planning, ID
│                         #   journal (crash-resumable), reference rewriting, restore_via verdicts,
│                         #   execution-time liveness probes, adopt-don't-duplicate matching
├── healer.py             # --heal: snapshot vs. live diff → additive-only recreation plan through
│                         #   the restorer's waves; --only selection (filter_heal_plan)
├── replayer.py           # --replay-gaps: SDK replay of unsupported objects + snapshot-held secrets
└── alerts/               # Decoupled alerting subsystem
    ├── models.py         #   Event contracts (10 event types, see table in docs/OPERATIONS.md)
    │                     #     + diff condensing/redaction before payloads leave the process
    ├── base.py           #   Notifier ABC (channel plugin contract)
    ├── webhook.py        #   urllib.request POST channel (raw JSON / Slack / Teams via formats.py)
    ├── formats.py        #   Webhook body renderers for --webhook-format
    ├── email.py          #   smtplib channel, verified STARTTLS + optional AUTH
    ├── pagerduty.py      #   PagerDuty Events API v2 (WARNING/CRITICAL only)
    └── dispatcher.py     #   Fan-out with per-channel failure isolation + org stamping
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

## Integrity Mechanisms

Defenses added by the coverage-integrity and DR-write-hardening
sweeps; each closes a class of silent wrongness:

- **byNetwork aggregation adoption** — mutable entities with no
  per-scope GET (Air Marshal rules, RRM, uplink NAT, …) used to be
  invisible to discovery. The parser now adopts their org-scoped
  aggregation GET (`…/byNetwork`-pattern endpoints); live discovery
  calls it once per org and explodes the response into per-network
  assets addressed at their canonical per-scope path.
- **Product-type prefiltering** — the valid network product types are
  derived from the createNetwork enum (never hard-coded), and a
  network-scoped endpoint whose path segment names a product the
  network does not carry is skipped without an API call. Conservative:
  an absent enum disables filtering entirely.
- **Reconciled manifest totals** — `coverage.json` totals must add up
  to exactly what discovery produced (`imported` + `pending-import` +
  `unsupported` + `duplicate-id`); any shortfall is reported as
  `totals.unaccounted` with a loud banner in `coverage.txt` instead of
  silently inflating the coverage percentage.
- **Write-verb verification** (`sdk_verify.py`) — the OpenAPI spec is
  effectively a dispatch table, so every dynamically resolved SDK
  method is verified against its own source before dispatch: discovery
  methods may only call `get`/`get_pages`; DR write actions may only
  call `put`/`post` (never `delete`). Fail-closed — an unverifiable
  method is refused (Cardinal Rule 1).
- **Execution-time liveness probes** (`restorer.py`) — restore/heal
  re-check each planned object immediately before writing: heal skips
  anything verified alive (additive-only held even when the discovery
  sweep undercounted survivors; reported as `verified_alive_skips`),
  and a journaled action whose object is missing *again* re-executes —
  so a second incident after a successful heal is recoverable with the
  same journal.
- **Deterministic spec for DR writes** — `--restore`, `--heal`, and
  `--replay-gaps` never auto-refresh the OpenAPI spec: mid-incident
  reruns must be reproducible. Snapshot headers record the spec's
  version + sha256, and a restore warns about skew between the
  snapshot's spec and the runtime one.
- **Resumable discovery** (`providers/discovery_checkpoint.py`) — an
  optional 0600 JSONL journal of every completed discovery call;
  aborted multi-hour sweeps resume instead of restarting, guarded by
  an org-ID + spec-sha header so a foreign checkpoint refuses loudly.

## Security Posture

- The API token lives only in `MERAKI_DASHBOARD_API_KEY`; it is read at
  client-construction time, passed into the SDK, and never retained.
- `SecretRedactionFilter` scrubs `Authorization` /
  `X-Cisco-Meraki-API-Key` values from every log record at every level.
- The generated `provider.tf` is credential-free — the
  `CiscoDevNet/meraki` provider reads its own `MERAKI_API_KEY`
  variable, which `terraform_runner` bridges from
  `MERAKI_DASHBOARD_API_KEY` for every terraform subprocess it spawns
  (an explicitly set `MERAKI_API_KEY` always wins). Manual terraform
  runs in the workdir must export `MERAKI_API_KEY` themselves.
- Alert payloads carry resource identifiers and structural data only.
