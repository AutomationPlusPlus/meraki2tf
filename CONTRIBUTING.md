# Contributing to meraki2tf

Thanks for your interest. This project is a disaster-recovery safety net for
live networks, so it holds a few lines harder than most codebases. Read this
once and the rest is ordinary Python.

## The two rules that are never negotiable

1. **Meraki is never mutated.** No code path may write to a Meraki
   organization except the explicit, human-invoked DR actions
   (`--rebuild`/`--replay-gaps`/`--restore`/`--heal`/`--wipe-org`, each
   requiring `--confirm`; each flag alone must remain a read-only preview).
   A PR that weakens this — however convenient — will not merge.
2. **Nothing unrepresentable goes unreported.** Every discovered object that
   Terraform cannot rebuild must surface in the coverage manifest and alerts.
   If your change can drop an object silently, it is wrong.

The full contract lives in [`CLAUDE.md`](CLAUDE.md); operational practice in
[`MAINTAINING.md`](MAINTAINING.md); architecture in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Getting set up

```bash
git clone https://github.com/AutomationPlusPlus/meraki2tf.git && cd meraki2tf   # or SSH: git@github.com:AutomationPlusPlus/meraki2tf.git
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip && pip install -r requirements.txt && pip install -e .
pre-commit install
```

Supported Pythons: 3.11–3.14 (3.14 primary). Terraform ≥ 1.5 on PATH is
needed only for live plan/apply paths — the test suite mocks it.

## Development workflow

- Branch from `main` (`feature/<topic>`); never commit to `main` directly.
- Run the full check suite before pushing: `tox` (flake8, strict mypy, pytest
  with coverage across supported Pythons).
- Sign your commits (`git config commit.gpgsign true`).
- Keep commits small and atomic; PRs should read as one reviewable story.

### Tooling constraints

`flake8` + `mypy` + `tox` + `pytest` are the approved toolchain. Do **not**
introduce `poetry`, `ruff`, or `uv` — configuration for them will be
rejected. New runtime dependencies need explicit maintainer sign-off before
they appear in a PR (the only pre-approved runtime dependency is the
`meraki` SDK).

## Testing expectations

- Mock the Meraki API with local JSON fixtures — tests must never open
  network sockets.
- Parsing, structural translation, and alerting engines target ~100%
  coverage; `pytest --cov=src --cov-report=term-missing` shows gaps.
- Changes to restore/heal/wipe behavior additionally require a scratch-org
  drill before merging (see MAINTAINING.md) — say so in the PR.

## Data hygiene in contributions

Never include real organization data anywhere: no org/network IDs, device
serials, hostnames, internal URLs, or API keys in code, fixtures, tests,
commit messages, issues, or PRs. Use clearly fictional placeholders
(`123456`, `N_1`, `Q2XX-XXXX-XXXX`, `corp.example`). When quoting logs,
redact first.

## Reporting security issues

Privately, please — see [SECURITY.md](SECURITY.md). Never open a public
issue for a vulnerability.
