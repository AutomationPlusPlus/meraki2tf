# Summary

<!-- What does this change do, and why? -->

## Checklist

- [ ] `tox` passes locally (flake8, mypy strict, pytest on at least one supported Python)
- [ ] New behavior is covered by tests (the project targets ~100% on parsing, translation, and alerting engines)
- [ ] Commits are signed
- [ ] No organization-identifying data anywhere in the diff, commit messages, or this PR (org/network IDs, serials, hostnames, tokens — use fictional placeholders)
- [ ] The Meraki read-only guarantee is intact: no code path writes to Meraki outside the explicit `--confirm` DR actions
- [ ] If this touches restore/heal/wipe behavior: a scratch-org drill has been re-run, or the PR explains why one is not needed
