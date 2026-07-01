# meraki2tf (Project Contract)

## Core Mission & Architecture
A robust, secure, and schedulable CLI tool written in Python to extract Cisco Meraki configurations, map them to Terraform structures using the Meraki OpenAPI specification, evaluate state drift, auto-import new resources, and flag unsupported parameters.

### Core Pipeline Steps
1. **Spec Ingestion:** Parse the Meraki OpenAPI JSON schema to build a dynamic API-to-Terraform resource registry.
2. **Configuration Discovery:** Ingest network infrastructure schemas via dual input modalities (Live Cloud API or Offline JSON Dump).
3. **HCL Construction:** Write clean, declarative configuration structures natively utilizing modern Terraform `import` blocks.
4. **State Orchestration:** Compare configurations against existing state (or initialize a baseline). Output structural differences and changes since the last state.
5. **State Aggregation:** Apply missing delta pieces into the current state file.
6. **Exception Auditing:** Flag parameters or features completely unsupported by the Terraform provider, and emit structured payloads to alerting endpoints.

---

## Workspace Modes of Operation

### 1. Live Mode (Cloud Streaming)
Queries target environments directly via the official Meraki cloud ecosystem.
- Authentication: Must read token dynamically via `MERAKI_DASHBOARD_API_KEY`.
- Rate Limiting: Handle the 10 requests/sec endpoint limit safely (handled natively via the Meraki Python SDK).

### 2. Dump Mode (Offline Execution)
Accepts a filepath parameter to an offline local JSON snapshot file (`--from-dump path/to/file.json`).
- Architecture: Employs a Provider interface abstraction to guarantee structural processing parity between live JSON payloads and static file configurations.
- Perfect for air-gapped runtimes, scheduled offline parsing, or running regression test validations.

---

## Environment & Tooling Commands

### Environment Initialization (No Poetry, No UV)
- **Setup Environment:** `python3 -m venv .venv && source .venv/bin/activate && pip install --upgrade pip`
- **Install Core Packages:** `pip install pre-commit flake8 mypy tox meraki pytest pytest-cov`

### Code Quality & Validation Pipeline
- **Run Complete Check Suite:** `tox`
- **Run Python Linter:** `flake8 src/ tests/`
- **Run Static Type Checker:** `mypy src/`
- **Run Test Suite:** `pytest`
- **Verify Code Coverage:** `pytest --cov=src --cov-report=term-missing`

---

## Strict Guardrails & Constraints

### 🚫 Banned Tools & Ecosystems
Do NOT install, generate configurations for, or utilize:
- `poetry`
- `ruff`
- `uv`

### ⚠️ Dependency Escalation Policy
- Pre-approved: `meraki` (SDK), `pre-commit`, `flake8`, `mypy`, `tox`, `pytest`, `pytest-cov`, and Python standard library utilities.
- **CRITICAL:** The agent must explicitly halt and request human operational authorization before introducing *any* other external pip module.

### 🛡️ Security First Principle
- **Secret Handling:** Zero tolerance for plaintext token parameters, hardcoded API variables, or hardcoded organization credentials in the repository, state logs, or output fields.
- **Verbose Logging Isolation:** Ensure that verbose/debug console and log systems exclude raw `Authorization` HTTP headers or private configuration values.

### 🧪 Code Coverage Target
- Maintain as close to **100% test coverage** as possible for all parsing, structural translation, and alerting engines to eliminate regression bugs.
- Mocking: Utilize local JSON mock dictionaries to test configuration mappings exhaustively without relying on network sockets.

### 🐙 GitHub & Git Collaboration Workflow
- **Cryptographic Signatures:** Every single commit must be cryptographically signed by Git. Confirm signing parameters are functioning before execution.
- **Commit Cycle:** Commit modifications regularly in small, logically structured atomic units.
- **Branching & PR Strategy:** Never commit directly to `main`. Create scoped feature branches (e.g., `feature/openapi-parser`) and structure code layout iterations to support clean GitHub Pull Request reviews.

### 📢 Notification & Alerting Infrastructure
- Build decoupled modular notifier plugins (Webhook targets, Email placeholders).
- Trigger alert dispatching whenever an explicit configuration drift occurs, a script run experiences a processing fault, or an unsupported Meraki feature is flagged during code construction.
