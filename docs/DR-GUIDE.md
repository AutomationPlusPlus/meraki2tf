# Disaster Recovery Guide

How the DR kit is produced, what coverage means, and every
recovery action (`--rebuild`, `--heal`, `--replay-gaps`,
`--restore`, `--wipe-org`) — each preview-first, `--confirm` to
execute. Part of the [meraki2tf](../README.md) docs.

## Disaster Recovery

meraki2tf is designed as a DR tool: schedule it to run continuously so
your organization's configuration is always captured as runnable
Terraform, and when a major incident hits, rebuild from the latest
artifacts. Normal runs are **strictly read-only** toward Meraki — no
`terraform apply` ever happens during the pipeline.

### Which recovery action do I need?

Every action below is **preview-first**: the flag alone shows exactly
what would happen and writes nothing; only adding `--confirm` executes.

| Symptom | Command | Prerequisites | What it will NOT do |
| --- | --- | --- | --- |
| Single objects accidentally deleted; the org is still alive | `--heal --from-dump <snapshot> --org-id <id>` (narrow with `--only`) | Unsanitized snapshot; `--org-id` must equal the snapshot's source org; API key (even the preview discovers live) | Never modifies surviving objects (additive-only); cannot un-modify settings or restore objects created after the snapshot |
| Settings were modified/mangled; you want Terraform to reapply the kit to the same org | `--rebuild --workdir <kit>` (pin the target with `--expect-org`) | A workdir populated by a previous run; API key | Cannot recreate *deleted* objects (their `import {}` blocks fail — that is `--heal`'s job); does not restore unsupported objects or secrets |
| After a rebuild, the pieces Terraform can't carry are still missing (unsupported objects, secret values) | `--replay-gaps --from-dump <snapshot>` | Unsanitized full snapshot; API key with `--confirm`; run *after* `--rebuild --confirm` | Does not touch anything Terraform already rebuilt; skips (and reports) entries a sanitized snapshot masked |
| The organization is lost entirely | `--restore --from-dump <snapshot> --target-org <new-org>` | Unsanitized full snapshot; a fresh/scratch `--target-org` (the source org is refused); `--serial-map` if hardware was replaced | Never writes into the snapshot's source org; cannot claim hardware still claimed elsewhere (use `--skip-claims` for drills) |
| A finished drill org needs tearing down | `--wipe-org <id> --wipe-org-name "<exact name>"` | Org must hold **zero** claimed devices; exact name as second factor | Refuses any org with claimed devices; never usable from a scheduler |

### What a run produces

Each run leaves a complete rebuild kit in `--workdir`:

| Artifact | Written by | Purpose |
| --- | --- | --- |
| `imports.tf` | meraki2tf | One `import {}` block per discovered asset (compound IDs included) |
| `provider.tf` | meraki2tf | Credential-free provider + backend anchor (local by default; a partial remote block for `--state-backend`) |
| `resources.tf` | meraki2tf (accumulated from `terraform plan -generate-config-out`) | Full HCL configuration for every captured asset — the actual rebuild material and the drift-comparison baseline |
| `generated_resources.tf` | terraform (transient) | Freshly generated config for new imports; folded into `resources.tf` after every plan |
| `coverage.json` / `coverage.txt` | meraki2tf | Per-run coverage manifest: every discovered object with status `imported`, `pending-import`, or `unsupported` (with reason), plus totals and a coverage percentage. `coverage.json` also carries a `kit` object fingerprinting the `imports.tf` it was written beside (`imports_sha256` + `import_block_count`) so `--check` can verify the manifest and the kit still agree |
| `runbook.md` | meraki2tf | Per-run DR runbook: for each object Terraform can't rebuild — the endpoint, identifiers, reason, redacted payload, and the `--replay-gaps` write op — plus which secret attributes to restore and where in the snapshot they live |
| `meraki2tf.tfstate` | terraform (`--sync` runs, `--rebuild --confirm`, or a manual apply) | State tracking, once the resources are adopted (local backend; a remote `--state-backend` keeps state in its own store instead) |

Back up the workdir (and ideally a `--dump-to` snapshot) somewhere that
survives the disaster you are protecting against — dated copies,
pruning, and off-box shipping are covered in
[Snapshot retention & archival](OPERATIONS.md#snapshot-retention--archival);
the scheduling recipes carry it as a ready-made optional step.

### Knowing what is (and isn't) covered

Every run audits Terraform coverage so you can trust the kit *before*
you need it. The workdir always contains a machine-readable
`coverage.json` and a human-readable `coverage.txt` listing **every**
discovered object with a status — `imported` (in state),
`pending-import` (in the kit, not yet in state), `unsupported`
(cannot be rebuilt by Terraform, with the reason), or `duplicate-id`
(its import ID is already carried by another captured object, so it is
rebuild-covered by that primary record) — plus totals and a coverage
percentage. The totals must reconcile against exactly what discovery
produced; any shortfall appears as `totals.unaccounted` with a loud
`ACCOUNTING MISMATCH` banner in `coverage.txt` — treat coverage claims
as suspect until it is explained. The manifest also carries spec-level
visibility no per-object row can:

- `suspect_endpoints` — endpoints that refused *every* scope they were
  tried against this run (≥ 3): usually a permissions hole or an API
  change, so verify those features are genuinely not in use;
- `excluded_rpc_paths` — RPC-style action endpoints excluded from
  discovery by design (one-shot actions, not configuration);
- `api_read_only_paths` — surfaces that are read-only in the Meraki
  API itself (much of Systems Manager, inventories, telemetry-shaped
  reads with no write verb): not restorable by *any* tool, Terraform
  or otherwise — know this before an incident, not during one.

`coverage.txt` groups repeated unsupported gaps by (endpoint, reason)
with example locators, so a provider regression across 500 objects
reads as one line, not 500. The log and the `RUN_SUCCESS` payload carry the
same picture, and each asset the provider **cannot express** is flagged
with an `UNSUPPORTED_FEATURE_FLAGGED` alert; the full unsupported list
also rides along on every success and drift notification — those are
the pieces you would have to rebuild manually in a DR event, so review
them ahead of time. Pass `--fail-on-gaps` to exit with code 3 whenever
unsupported objects exist, so CI or your scheduler can gate on full
coverage. Alongside the manifest, every run regenerates `runbook.md` —
the human DR runbook that, for each uncoverable object, records the
endpoint, identifiers, reason, a redacted payload, and the exact
`--replay-gaps` write operation that would restore it (plus which secret
attributes to re-enter and where in the snapshot they live). When the
plan comparison runs (API key available), the plan's own summary is also
reported: pending imports (discovered but not yet aggregated into state)
versus real add/change/destroy pressure, which fires `DRIFT_DETECTED`.
By default the plan stays speculative — nothing is applied unless you
opt into `--sync`.

The comparison also **reconciles provider round-trip artifacts** before
judging drift (see `docs/ARCHITECTURE.md`, *Plan Reconciliation*):
configurations the provider itself refuses to accept are dropped and
reported `unsupported`; secret attributes the generated config cannot
carry (Wi-Fi PSKs, SNMP community strings, …) are excluded from
management and listed as `unmanaged_secret_attributes` in the manifest
and the success notification — **restore those manually after any
rebuild**; formatting-only differences are normalized away. Only real
changes ever fire `DRIFT_DETECTED`.

### Scheduled DR automation (`--sync`)

The default invocation is the ad-hoc/open-source mode: strictly
read-only end to end, safe for anyone to run against any org. The
scheduled terraform rehearsal (monthly in the recommended cadence)
passes `--sync` to also **materialize Terraform state** unattended:

- After the speculative plan, the run auto-applies **only when the plan
  is 100% imports (0 to add, 0 to change, 0 to destroy)**. Import
  blocks only write state — Meraki is never touched. The guard lives in
  the Terraform runner itself and re-verifies the saved plan
  immediately before applying it, so no code path can sneak a mutation
  through.
- Any mutating plan **aborts the apply** and fires a `DRIFT_DETECTED`
  alert with the diff (`apply_aborted: true`). A human decides next.
- Modified objects (Meraki is truth): their HCL baseline is regenerated
  to mirror the current dashboard via local state surgery
  (`terraform state rm` + baseline prune + re-import) and the diff is
  alerted with `regenerated_addresses`.
- Deleted objects: **alert-only** in every mode. Resources tracked in
  the kit that discovery no longer finds fire a
  `DELETION_PENDING_CONFIRMATION` alert and stay in the kit until a
  human re-runs with `--confirm-deletions`, which removes them from
  `resources.tf` and the state.
- Every applied run reports exactly which resources were added to state
  (log + `RUN_SUCCESS.resources_added_to_state`), so scheduled reruns
  tell you what grew.

`--sync` requires `MERAKI_DASHBOARD_API_KEY` and fails loudly without
it — silently skipping the apply would let the scheduled job believe it
built state when it did not.

Drift is measured against the captured baseline in `resources.tf`, so a
`DRIFT_DETECTED` alert keeps firing until you act on it: either fix the
organization back to the baseline (that's the DR posture), or accept
the new reality with `--rebaseline`, which discards `resources.tf` so
the next plan regenerates it from live data:

```bash
# After reviewing the drift diff and deciding the change is legitimate:
meraki2tf --org-id 123456 --rebaseline
```

### Restoring an existing organization (primary DR path)

When the org still exists but its configuration was damaged (mass
misconfiguration, botched change, malicious edits), the artifacts
restore it to the last captured snapshot:

```bash
export MERAKI_DASHBOARD_API_KEY="<your-dashboard-api-key>"

# 1. Preview — read-only, shows exactly what would change:
meraki2tf --rebuild --workdir ./generated

# 2. Execute — the ONLY way meraki2tf ever runs terraform apply:
meraki2tf --rebuild --confirm --workdir ./generated
```

`--rebuild` alone is always a dry run (`terraform plan`); nothing is
touched until you add `--confirm`.

> **Re-run the pipeline first if anything changed the organization out of
> band.** `--rebuild` applies whatever the workdir last captured, so a kit
> that has fallen behind reality will push the stale version back. Two
> ways to get there, both seen in end-to-end testing:
>
> - **You changed something in the dashboard.** The kit still holds the
>   previous value and the apply reverts your change — which is exactly
>   what the action is *for*, but only if you meant it.
> - **A `--heal` ran.** Heal recreates a deleted object with a **new**
>   server-assigned ID, so the kit and state still name the dead one. The
>   plan then reads `1 to add` and a `--confirm` creates a **duplicate**
>   of an object that already exists.
>
> Both cases are visible before you commit to them: the preview names
> every resource it would create, and a pipeline run reports
> `N resource(s) tracked in the DR kit were not discovered in Meraki
> (deleted?)`. Reconcile with `--sync --confirm-deletions` (or
> `--rebaseline` on a workdir whose state tracks nothing), confirm the
> preview is `0 to add, 0 to change, 0 to destroy`, and only then add
> `--confirm`.

Prefer doing it by hand? The workdir
is a plain Terraform root module — but note that the
`CiscoDevNet/meraki` provider reads its credential from
`MERAKI_API_KEY`, not `MERAKI_DASHBOARD_API_KEY` (meraki2tf bridges
the two only for the terraform subprocesses it spawns itself):

```bash
cd ./generated
export MERAKI_API_KEY="$MERAKI_DASHBOARD_API_KEY"   # the provider's own variable
terraform init
terraform plan     # inspect
terraform apply    # rebuild
```

On the first apply the `import {}` blocks adopt every still-existing
resource into state, then Terraform reverts any settings that diverged
from the snapshot.

### Rebuilding from scratch (org or resources destroyed)

If resources no longer exist, their `import {}` blocks will fail —
Terraform cannot import something that is gone. Adjust the kit first:

1. Copy the workdir to a fresh directory (keep the original as backup).
2. Delete `imports.tf` (or just the blocks for destroyed resources) so
   Terraform **creates** instead of imports.
3. Start from an empty state (delete/relocate `meraki2tf.tfstate` if
   the old one references destroyed resources).
4. `export MERAKI_API_KEY=…` (the provider's own credential variable —
   see the note above), then
   `terraform init && terraform plan && terraform apply`.

> **Greenfield caveat:** `resources.tf` captures IDs as
> literal strings (organization ID, `network_id = "N_…"`, serials).
> Rebuilding into a **brand-new organization** assigns new IDs, so
> cross-resource references must be re-pointed (e.g. replace literal
> network IDs with `meraki_networks.<name>.id` references) and device
> serials must match hardware you actually own. Restoring into the
> *same* organization avoids all of this, which is why it is the
> primary DR path.

### Healing accidental deletions (`--heal`)

`--rebuild` reverts *modified* settings, but when objects were
**deleted** from a still-healthy organization (the classic clickops
accident), their `import {}` blocks fail — Terraform cannot import
something that is gone. `--heal` covers exactly this case: it diffs
your snapshot against a fresh live discovery of the **same**
organization and recreates only what is missing, directly through the
API:

```bash
export MERAKI_DASHBOARD_API_KEY="<your-dashboard-api-key>"

# 1. Preview — shows every missing object and what would be recreated:
meraki2tf --heal --from-dump vault/latest.jsonl.gz --org-id 123456

# 2. Execute — recreates the missing objects; survivors are untouched:
meraki2tf --heal --confirm --from-dump vault/latest.jsonl.gz --org-id 123456

# 3. Selective heal — recreate only part of what is missing:
meraki2tf --heal --only 'network:Branch-07' --only 'ssid:Guest*' \
    --from-dump vault/latest.jsonl.gz --org-id 123456
```

Notes:

- **Additive-only.** Objects still present in the organization are
  never modified or dispatched — heal only creates what is missing. A
  deleted parent's children are rewired to the parent's new ID.
- **Same-org interlock** (the inverse of `--restore`): `--org-id` must
  match the snapshot's source organization, or the run is refused. To
  rebuild a *different* organization, use `--restore --target-org`.
- **Unsanitized snapshot required.** A sanitized snapshot's
  identifiers are pseudonyms and cannot be matched against the live
  organization.
- **API key required even for preview** — deciding what is "missing"
  takes a live discovery of the organization as it is right now.
- **Crash-resumable.** Executed writes are journaled
  (`<workdir>/heal-journal.jsonl`); re-running `--heal --confirm`
  resumes instead of duplicating creates.
- **Additive-only is re-verified at write time.** Immediately before
  each create, heal probes whether the object is alive *right now*;
  anything found alive is skipped even if the discovery sweep missed
  it (a transient 400, SDK/spec skew). The `HEAL_EXECUTED` alert
  reports these as `verified_alive_skips` — a nonzero count means the
  sweep undercounted survivors.
- **Second incidents re-execute.** A journaled action whose object has
  gone missing *again* (deleted a second time after a successful heal)
  is re-executed rather than skipped as "already done" — the journal
  never masks a fresh deletion.
- **Selective heal (`--only`).** When only part of a deletion should
  come back (two networks deleted, restore one; several SSIDs deleted,
  restore some), repeatable `--only '[TYPE:]PATTERN'` selectors narrow
  the run — a case-insensitive glob over each missing object's name or
  ID, optionally prefixed with its type (`network:`, `ssid:`,
  `vlan:`, …, singular or plural). A matched container brings its whole
  missing subtree, and the container may be one that **survived**:
  naming a network that is still standing recovers the objects deleted
  inside it (the survivor itself is never written — heal stays
  additive-only), which is the usual "recover site X" case. Missing
  objects the selection depends on (a deleted parent, a referenced
  missing object) are auto-included and reported.
  A selector matching nothing is refused loudly — a typo must never
  masquerade as a successful no-op heal. Filtering only ever *shrinks*
  the run: everything above (additive-only, preview-first, journaling)
  applies unchanged, and the preview's re-run hint carries the same
  `--only` selection.
- Execution dispatches a `HEAL_EXECUTED` alert with the recreated,
  failed, skipped, and surviving counts; objects the API cannot
  recreate are reported with reasons, never silently dropped.

### Selective backup before risky changes (`--dump-to --only`)

About to make major changes to **one** network of a large organization?
A full-org snapshot can take hours; a scoped one takes minutes and
gives you a same-day undo path through `--heal`:

```bash
export MERAKI_DASHBOARD_API_KEY="<your-dashboard-api-key>"

# 1. Fast partial backup of just the network you are about to touch:
meraki2tf --org-id 123456 --dump-to pre-change.jsonl.gz \
    --only 'network:Branch-07'

# 2. ...make your changes in the dashboard...

# 3. If something you needed got deleted — preview, then heal it back:
meraki2tf --heal --from-dump pre-change.jsonl.gz --org-id 123456
meraki2tf --heal --confirm --from-dump pre-change.jsonl.gz --org-id 123456
```

How it works and what to expect:

- **Scope selectors are `network:PATTERN` only** (case-insensitive
  glob over network name or ID, repeatable, union). A selector
  matching no network is refused with the available networks listed.
- **What the snapshot contains:** the selected networks with their
  features, their claimed devices with device-level features, **all
  org-level objects** (cheap, and required so references from the
  scoped networks stay recreatable), and every config template.
  Unclaimed devices fall outside any network scope and are not
  captured.
- **Heal is scope-aware:** against a partial snapshot, `--heal`
  narrows its live discovery to the recorded networks, so the preview
  is as fast as the backup was. `--only` composes at heal time to
  narrow further. The `HEAL_EXECUTED` alert and run log name the
  partial scope.
- **A partial snapshot is a selective backup, not a DR snapshot.**
  It is refused by `--restore`, `--replay-gaps`, `--drift-baseline`,
  and pipeline `--sync`/`--confirm-deletions`; the scheduled Azure
  wrapper refuses `--only` outright so the weekly drift chain stays
  full-organization. The coverage manifest, runbook, and RUN_SUCCESS
  notification of a scoped run carry a loud **PARTIAL** banner naming
  the covered networks.
- **Caveats:** objects created *after* the backup are not in it (heal
  cannot un-create anything — it is additive-only, so your new work is
  safe); a device moved to another network between backup and heal is
  reported, never silently re-claimed.

### Restoring what Terraform can't rebuild (`--replay-gaps`)

`--rebuild` restores everything the Terraform provider can express. Two
things it *cannot* carry always remain:

- **Unsupported objects** — Meraki configuration the `CiscoDevNet/meraki`
  provider has no resource for (listed as `unsupported` in
  `coverage.json`).
- **Secret values** — the provider refuses to read secrets back (PSKs,
  SNMP community strings), so a Terraform rebuild leaves them blank.

`runbook.md` documents every one of these for manual restoration. When
you'd rather automate it, `--replay-gaps` replays them from your
unsanitized `--dump-to` snapshot straight to the Meraki API:

```bash
export MERAKI_DASHBOARD_API_KEY="<your-dashboard-api-key>"

# 1. Preview — read-only, prints exactly what would be written:
meraki2tf --replay-gaps --from-dump ./snapshots/org-123456.json

# 2. Execute — writes the gap objects and secrets back via the SDK:
meraki2tf --replay-gaps --confirm --from-dump ./snapshots/org-123456.json
```

Run it **after** `--rebuild --confirm` has restored the Terraform-covered
resources. Notes:

- **Inert by default.** `--replay-gaps` alone is a preview; nothing is
  written without `--confirm`.
- **Snapshot must be unsanitized.** Replay reads the real secret values
  from the snapshot; a `--sanitize`d snapshot has them masked and those
  entries are skipped (and reported). A sanitized snapshot additionally
  cannot be replayed into an organization that does not already hold
  its (pseudonymized) networks: `--confirm` refuses with exit 2, because
  org-scoped writes would otherwise overwrite a live tenant's settings
  with pseudonyms. Drills — replaying into the organization the same
  sanitized snapshot was just restored into — are unaffected.
- **New-org remapping.** A rebuilt organization issues new network IDs;
  snapshot path values are remapped to the live tenant by network
  name before each call. Values embedded *inside* payloads are not
  rewritten — per-object failures are reported, and `runbook.md` remains
  the manual fallback.
- Success dispatches a `GAP_REPLAY_EXECUTED` notification summarizing
  what was restored, skipped, and (if any) failed.

### Rebuilding an entire organization (`--restore`)

`--rebuild` applies the Terraform kit and is the right tool when the
organization still exists (the statistically likely disaster: a subset
of objects was deleted or mangled). For **total organization loss** the
kit is not enough — its generated configuration carries the old org's
literal IDs. `--restore` rebuilds directly through the API from an
unsanitized snapshot:

```bash
# Preview (default): the full restore plan — what will be created,
# configured, claimed, and what cannot be restored (with reasons).
meraki2tf --restore --from-dump vault/latest.jsonl.gz --target-org 999999

# Execute. Only ever into --target-org; the snapshot's own source
# organization is refused outright.
meraki2tf --restore --from-dump vault/latest.jsonl.gz --target-org 999999 \
  --confirm --workdir ./restore-run

# Hardware was lost too? Map old device serials to replacement units.
meraki2tf --restore --from-dump vault/latest.jsonl.gz --target-org 999999 \
  --serial-map replacements.json --confirm
```

The restore runs in dependency waves — organization-level objects,
config templates, network creation, device claiming, then features
(shallow before nested) — capturing every server-assigned ID into a
crash-resumable journal (`<workdir>/restore-journal.jsonl`) and
rewriting payload-embedded references (`*Id`/`*Ids` fields, firewall
`GRP()`/`OBJ()` grammar) to the rebuilt IDs. A reference that cannot be
rewritten fails that one object loudly; children of failed parents are
skipped with reasons. Re-running with the same journal resumes instead
of duplicating creates. The run ends with a `RESTORE_EXECUTED` alert
listing executed/failed/skipped (identifiers only, never values).

Determinism under incident pressure: the DR write actions (`--restore`,
`--heal`, `--replay-gaps`) **never auto-refresh the OpenAPI spec** —
the local file is used as-is (version + sha256 logged) so preview,
`--confirm`, and any rerun all dispatch from the same document.
Snapshots record the spec fingerprint they were captured with, and a
restore warns when the runtime spec skews from it.

Every weekly coverage manifest also carries each asset's `restore_via`
verdict (`create` / `configure` / `claim` / `unrestorable: <reason>`),
so "will the API rebuild it?" is answered **before** any disaster.

#### Restore drills (and cleaning up after them)

Rehearse into a scratch organization — Meraki organizations are free to
create. Two drill realities the tool handles for you:

**Hardware is mono-org.** Your devices are claimed by production, so a
drill cannot claim them. `--skip-claims` marks device claiming and
device-scoped features as drill-skipped verdicts (never failures); the
drill still exercises everything risky — network creation, ID
remapping, the journal, and every network-scoped feature:

```bash
meraki2tf --restore --from-dump vault/sanitized.jsonl.gz \
  --target-org <scratch-org> --skip-claims --confirm
```

**No sensitive residue.** Prefer drilling from the **sanitized**
snapshot: it is structurally faithful (same object graph, same
ordering and remapping exercise) but contains pseudonymized names,
fake IPs, and no secret values — so the drill org never holds real
environment data. Run one full-fidelity unsanitized drill before final
sign-off, then tear the org down:

```bash
# Preview: verifies the interlocks and shows the blast radius.
meraki2tf --wipe-org <scratch-org> --wipe-org-name "DR Drill"

# Execute: deletes every network, then the organization itself.
meraki2tf --wipe-org <scratch-org> --wipe-org-name "DR Drill" --confirm
```

The wipe is refused outright for **any organization holding claimed
devices** — a typical production org always has hardware, a drill org
never does, so the destructive path cannot target it. Scope that claim
honestly: a **device-less** production organization (licensing-only,
Systems-Manager-only, or a hub org whose devices live elsewhere) is
protected *only* by the exact-name second factor — give drill orgs
unmistakable names (e.g. "DR Drill 2026-07") and never reuse a
production org's name for one. The exact organization name is a
required second factor, and the interlocks are re-verified immediately
before deletion. Note that dashboard deletion
is immediate, but backend retention of deleted-organization data is
governed by Cisco's data-handling policy — for hard-erasure guarantees
after an unsanitized drill, file a data-deletion request with Meraki
support.

### Recommended operating cadence

| Cadence | Job | Cost |
| --- | --- | --- |
| Weekly | `--dump-to <new> --drift-baseline <previous>` + rotate snapshots | one discovery sweep |
| Monthly | Terraform kit export + `--rebuild` preview (`--sync` run or plain pipeline) | one kit/plan cycle |
| Quarterly | Restore drill: `--restore --confirm` into a scratch org, verify by discovering the rebuilt org and diffing vs the source snapshot | one restore + one sweep |

> The terraform kit remains in the rotation deliberately: it is the
> proven tool for *same-org subset* restores, and the monthly plan
> preview catches provider regressions before a disaster does. The kit
> ran weekly until the full-org restore drill passed; since then the
> weekly job is snapshot-only and terraform runs on the monthly
> rehearsal. (`--fail-on-gaps` works on `--dump-to` exports too, so
> the weekly coverage gate survives the change.) One cadence caveat:
> the weekly snapshot-diff reports a deletion **once** — the next
> week's baseline already lacks the object — while the kit-based
> `DELETION_PENDING_CONFIRMATION` reminder re-fires on every monthly
> terraform run until a human confirms. Treat weekly deletion drift
> alerts as act-now signals.

### Transitioning to Infrastructure-as-Code

The full Terraform pipeline is a permanent, first-class capability —
not a legacy path. When (or if) your team decides to stop clickops and
manage Meraki as code, the transition is one `--sync` run away: the
kit (`imports.tf`, `resources.tf`, `provider.tf`) plus the materialized
state file are a complete, importable Terraform root module reflecting
the live organization. From there you own the HCL — commit it, review
changes as pull requests, and `terraform plan/apply` becomes your
change-management process, with meraki2tf's weekly snapshot+diff
continuing to serve as the independent DR safety net underneath.
