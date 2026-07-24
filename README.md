# meraki2tf

[![Python 3.11–3.14](https://img.shields.io/badge/python-3.11%20%E2%80%93%203.14-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Terraform](https://img.shields.io/badge/terraform-CiscoDevNet%2Fmeraki-844FBA?logo=terraform&logoColor=white)](https://registry.terraform.io/providers/CiscoDevNet/meraki)
[![CI](https://github.com/AutomationPlusPlus/meraki2tf/actions/workflows/ci.yml/badge.svg)](https://github.com/AutomationPlusPlus/meraki2tf/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A598%25%20(CI--gated)-success)](#contributor-architecture)
[![Typing: mypy strict](https://img.shields.io/badge/typing-mypy%20strict-blue)](#contributor-architecture)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue)](LICENSE)

Extract Cisco Meraki configurations, translate them into Terraform
structures for the [`CiscoDevNet/meraki`](https://registry.terraform.io/providers/CiscoDevNet/meraki)
provider, detect state drift, and alert on every outcome — from one
schedulable CLI built as a **disaster-recovery snapshotting tool**.

## 60-second quickstart

Turn your Meraki organization into runnable Terraform with one flag.
The run is **strictly read-only** — nothing in your organization is
ever touched, and nothing is applied:

```bash
# Install (needs Python ≥ 3.11 and terraform ≥ 1.5 on PATH; not on PyPI yet)
git clone https://github.com/AutomationPlusPlus/meraki2tf.git && cd meraki2tf
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt && pip install -e .

# The API key only ever comes from the environment, never a flag
export MERAKI_DASHBOARD_API_KEY="<your-dashboard-api-key>"

# Don't know your organization ID? List every org the key can see:
meraki2tf --list-orgs

# Run
meraki2tf --org-id 123456
```

Everything lands in `./generated/` — a plain Terraform root module with
one `import {}` block per discovered asset plus the generated HCL:

```terraform
# generated/imports.tf
import {
  to = meraki_networks.n_111222333444555666
  id = "123456,N_111222333444555666"
}

import {
  to = meraki_appliance_vlan.vlan_10
  id = "N_111222333444555666,10"
}
```

…and a coverage report that answers "what is and isn't in Terraform?"
for every object it found:

```text
# generated/coverage.txt
meraki2tf coverage report — organization 123456

Discovered objects : 412
  imported         : 0   (tracked in Terraform state)
  pending-import   : 406 (in the kit, not yet in state)
  unsupported      : 6   (MANUAL rebuild required)
Coverage           : 98.5%
```

From there, `cd generated && terraform init && terraform plan` (running
terraform by hand needs `export MERAKI_API_KEY=…` — the provider reads
its own variable, not `MERAKI_DASHBOARD_API_KEY`) — or let
the tool keep running on a schedule as a DR safety net. Full install
notes: [Prerequisites & Installation](#prerequisites--installation).

## Which mode do I want?

| Your goal | Invocation | Where it's documented |
| --- | --- | --- |
| One-shot export of my org to Terraform | `meraki2tf --org-id <id>` | [Live Mode](docs/USAGE.md#live-mode-cloud-streaming) |
| Scheduled DR job that also materializes Terraform state | add `--sync` | [Scheduled DR automation](docs/DR-GUIDE.md#scheduled-dr-automation---sync) |
| Capture a snapshot for offline / air-gapped use | `--dump-to <path>` (add `--sanitize` to share it) | [Producing a snapshot](docs/USAGE.md#producing-a-snapshot---dump-to) |
| Run entirely offline from a snapshot | `--from-dump <path>` | [Dump Mode](docs/USAGE.md#dump-mode-offline--air-gapped) |
| Fast drift check between two snapshots (no terraform) | `--drift-baseline <prev>` | [Snapshot-diff drift detection](docs/USAGE.md#snapshot-diff-drift-detection---drift-baseline) |
| Rebuild after an incident | `--rebuild` / `--heal` / `--replay-gaps` / `--restore` (each previews; add `--confirm`; scope `--heal` with `--only`) | [Disaster Recovery](docs/DR-GUIDE.md#disaster-recovery) |
| Backup one network before risky changes | `--dump-to snap.jsonl.gz --only 'network:NAME'` (fast partial snapshot; undo deletions later via `--heal`) | [Selective backup](docs/DR-GUIDE.md#selective-backup-before-risky-changes---dump-to---only) |
| Stop clickops and manage Meraki as code | one `--sync` run, then own the HCL | [Transitioning to IaC](docs/DR-GUIDE.md#transitioning-to-infrastructure-as-code) |

## Project Overview

meraki2tf discovers your Meraki organization (networks, devices, and
organization-, network-, and device-scoped feature configuration —
admins, VLANs, switch ports, …), writes modern declarative Terraform
`import {}` blocks for every discovered asset, and runs a speculative
`terraform plan -generate-config-out=...` comparison against your local
state. Drift, success, and unsupported features each fire structured
alerts to your configured webhook/email channels.

**Read-only guarantee:** the pipeline never runs `terraform apply` and
never mutates your Meraki organization. Its job is to continuously
convert your org into runnable Terraform artifacts; in the event of a
major incident you use those artifacts to rebuild — see
[Disaster Recovery](docs/DR-GUIDE.md#disaster-recovery). Only five explicit,
human-invoked disaster-recovery actions ever write anything, and each is
a read-only preview until you add `--confirm`:
[`--rebuild --confirm`](docs/DR-GUIDE.md#restoring-an-existing-organization-primary-dr-path)
(a `terraform apply` of the kit),
[`--heal --confirm`](docs/DR-GUIDE.md#healing-accidental-deletions---heal)
(recreates snapshot objects missing from the same organization —
additive-only, survivors untouched),
[`--replay-gaps --confirm`](docs/DR-GUIDE.md#restoring-what-terraform-cant-rebuild---replay-gaps)
(restores objects and secrets Terraform cannot carry, via the SDK),
[`--restore --confirm`](docs/DR-GUIDE.md#rebuilding-an-entire-organization---restore)
(rebuilds an entire organization from a snapshot — only ever into a
separate `--target-org`, never the source), and
[`--wipe-org --confirm`](docs/DR-GUIDE.md#restore-drills-and-cleaning-up-after-them)
(drill-org teardown — refused outright for any organization holding
claimed devices, so it physically cannot target production).
Every scheduled/automated run stays strictly read-only toward Meraki.

**Why dynamic OpenAPI spec parsing?** The Meraki API surface changes
with every dashboard release. Instead of maintaining a brittle
hand-written table from API endpoints to Terraform resources, meraki2tf
ingests the official Meraki OpenAPI JSON document at runtime and derives
the resource entities and their ordered path parameters
(`{organizationId}`, `{networkId}`, `{vlanId}`, …) from its structure.
Each entity is then **matched against the installed
`CiscoDevNet/meraki` provider's own resource identity schemas**
(`terraform providers schema -json`, cached per workdir with a bundled
fallback for air-gapped runs), which yields the authoritative resource
type names (`meraki_appliance_vlan`) and the comma-separated compound
import IDs Terraform needs — including the provider's conventions of
prefixing the organization ID where the identity demands it and
supplying a literal `false` for `force_delete` identities. Point the
tool at a newer spec release or provider version and new endpoints are
picked up with zero code changes; anything the provider cannot express
is flagged through the exception auditor instead of silently dropped.

## Prerequisites & Installation

- Python 3.11–3.14 (every CPython version still receiving security patches;
  3.14 recommended — the floor is 3.11 because the `meraki` SDK requires it)
- The `terraform` CLI on your `PATH` (any version supporting `import` blocks, ≥ 1.5)
- The [`CiscoDevNet/meraki`](https://registry.terraform.io/providers/CiscoDevNet/meraki)
  Terraform provider **≥ v1.12.0** — `terraform init` in the generated
  workdir fetches it; with an older (or not-yet-initialized) provider the
  tool falls back to a bundled v1.12.2 identity catalog, which can drift
  from what your workdir actually runs
- A Meraki dashboard API key (live mode only)
- The Meraki OpenAPI spec — fetched from GitHub automatically; only
  air-gapped runs need a local copy pre-staged (see
  [OpenAPI spec resolution](docs/USAGE.md#openapi-spec-resolution))

This project deliberately uses plain `venv` + `pip` — poetry and uv are
not used and not supported.

```bash
git clone https://github.com/AutomationPlusPlus/meraki2tf.git   # or SSH: git@github.com:AutomationPlusPlus/meraki2tf.git
cd meraki2tf

python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

**Reproducible worker installs** — unattended schedulers should pin
the runtime closure by hash so a mid-incident rebuild cannot silently
pull an untested or tampered SDK:

```bash
pip install --require-hashes -r requirements-lock.txt
pip install --no-deps .
```

**Container** — a general-purpose image (bare `meraki2tf` entrypoint,
pinned + checksum-verified Terraform, non-root, hash-locked runtime
deps) builds from the repo-root [`Dockerfile`](Dockerfile):

```bash
docker build -t meraki2tf .
docker run --rm -e MERAKI_DASHBOARD_API_KEY \
  -v "$PWD/generated:/data" meraki2tf --org-id 123456 --workdir /data
```

(The Azure-specific image with the runbook wrapper entrypoint lives at
`deploy/azure/Dockerfile`.) Releases are tagged (`vX.Y.Z`) and listed
in [`CHANGELOG.md`](CHANGELOG.md) — pin a tag for production use.

## Documentation

| Guide | Contents |
| --- | --- |
| [Usage & Configuration](docs/USAGE.md) | Run modes (live/dump/snapshot), every flag in detail, `--config` files, Terraform state backends, alerting settings, spec resolution |
| [Disaster Recovery Guide](docs/DR-GUIDE.md) | The DR kit, coverage guarantees, `--sync` automation, and the five recovery actions (`--rebuild`, `--heal`, `--replay-gaps`, `--restore`, `--wipe-org`) |
| [Operations](docs/OPERATIONS.md) | Alert events, scheduling (cron, systemd timers, AWS Fargate, GCP Cloud Run Jobs), exit codes, performance & scale, troubleshooting & FAQ |
| [Azure deployment](docs/azure-automation.md) | Azure Automation / Container Apps Job wrapper: Key Vault, Blob archival, snapshot rotation |
| [Architecture](docs/ARCHITECTURE.md) | Package layout and pipeline design (contributors) |
| [CHANGELOG](CHANGELOG.md) | Release history (tags `vX.Y.Z`) |

## Contributor Architecture

Package layout and pipeline design live in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the binding project
contract is [`CLAUDE.md`](CLAUDE.md).

```bash
# One-time setup (inside the venv)
pip install -r requirements.txt
pre-commit install          # hygiene + flake8 + mypy on every commit

# The full gate — lint, strict typing, tests with coverage
tox

# Individual checks
flake8 src/ tests/
mypy src/
pytest --cov=src --cov-report=term-missing
pre-commit run --all-files
```

House rules: near-100% test coverage on parsing/translation/alerting
engines (fixtures only, no network sockets), signed atomic commits on
scoped feature branches, and no poetry/ruff/uv anywhere in the
toolchain.

## Contributing

Contributions are welcome — start with [CONTRIBUTING.md](CONTRIBUTING.md)
(setup, workflow, and the two non-negotiable safety rules), and see
[SECURITY.md](SECURITY.md) for reporting vulnerabilities privately.
Operational practice for maintainers lives in
[MAINTAINING.md](MAINTAINING.md). This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md).
