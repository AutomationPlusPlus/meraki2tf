# Security Policy

meraki2tf handles Meraki Dashboard API keys and produces snapshots of entire
network configurations. Treat every security report accordingly.

## Reporting a vulnerability

Please report vulnerabilities **privately** via
[GitHub Security Advisories](https://github.com/AutomationPlusPlus/meraki2tf/security/advisories/new).
Do not open a public issue. You can expect an acknowledgement within a week.

Include redacted reproduction detail — never real org IDs, serials,
hostnames, or tokens.

## Supported versions

The `main` branch is the supported version. There are no maintained release
branches yet.

## Security model (what to hold the tool to)

- **API keys** are read from the environment (`MERAKI_DASHBOARD_API_KEY`) or
  owner-only files — never from flags, and never logged. Credential-shaped
  backend-config keys are refused so no secret reaches argv.
- **Exactly two artifacts may contain secret values**: the unsanitized
  snapshot and the Terraform state. Both are written owner-only (0600).
  Everything else — HCL kit, coverage manifest, runbook, alerts, logs —
  carries attribute names and locators, never values.
- **The Meraki organization is never mutated** outside the explicit
  `--confirm` DR actions; every scheduled/pipeline invocation is read-only
  toward Meraki by contract.
- **Alert payloads and webhooks**: webhook URLs must be HTTPS (tokens may be
  embedded in them); payloads never carry secret values.
- The sanitizer (`--sanitize`) pseudonymizes identifying data for
  shareable/drill snapshots; a sanitized snapshot is refused where using it
  would be unsafe (e.g. `--heal`).

Anything that violates one of these bullets is a security bug — please
report it, even if it looks minor.
