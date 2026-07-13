# Container image for running the weekly meraki2tf DR job as an Azure
# Container Apps Job (the alternative to a Hybrid Runbook Worker — see
# docs/azure-automation.md). Build from the repository root:
#
#   docker build -f deploy/azure/Dockerfile -t meraki2tf-dr .
#
# The job needs a managed identity (Key Vault + Blob access) and an
# Azure Files volume mounted at /var/lib/meraki2tf for the persistent
# workspace. Note: Azure Files (SMB) does not honor chmod 0600, so the
# snapshot/state owner-only guarantee is degraded there — meraki2tf
# logs a warning when that happens. The RBAC on the share and the
# storage account is the effective access control.

# Project primary interpreter is CPython 3.14 (supports 3.11-3.14).
#
# Multi-stage: the wheel is built in a throwaway builder stage so the
# repository contents never become a layer of the shipped image — a
# single-stage `COPY . /src` persists in the layer history even after
# an `rm -rf /src`, shipping the full source tree, git metadata, and
# anything else in the build context to everyone who can pull the
# image.
FROM python:3.14-slim AS builder

COPY . /src
RUN pip wheel --no-deps --wheel-dir /wheels /src

FROM python:3.14-slim

ARG TERRAFORM_VERSION=1.9.8

# Terraform is downloaded and its checksum verified against HashiCorp's
# published SHA256SUMS. Both files come from the same origin, so this
# defends against a corrupted or truncated transfer — NOT against a
# compromised releases.hashicorp.com, which could serve matching sums
# for a trojaned binary.
RUN set -eux \
    && apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && cd /tmp \
    && curl -fsSLO \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
    && curl -fsSLO \
        "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_SHA256SUMS" \
    && grep "terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
        "terraform_${TERRAFORM_VERSION}_SHA256SUMS" | sha256sum -c - \
    && unzip "terraform_${TERRAFORM_VERSION}_linux_amd64.zip" -d /usr/local/bin \
    && rm -f "terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
        "terraform_${TERRAFORM_VERSION}_SHA256SUMS" \
    && apt-get purge -y curl unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Only the built wheel and the runbook wrapper cross into this stage;
# dependencies resolve from PyPI during install.
COPY --from=builder /wheels /wheels
COPY deploy/azure/runbook.py /usr/local/bin/meraki2tf-runbook.py
RUN pip install --no-cache-dir /wheels/*.whl \
    && rm -rf /wheels

# Run as an unprivileged user: any compromise of the SDK/terraform in
# the job then does not execute as container root while holding the API
# key. The persistent workspace mount must be writable by this uid.
RUN useradd --create-home --uid 10001 meraki2tf
USER meraki2tf

# Configure via the job's command/args, e.g.:
#   python /usr/local/bin/meraki2tf-runbook.py --vault-name kv-netops \
#     --org-id 123456 --storage-account stmerakidr \
#     --workdir /var/lib/meraki2tf -- --webhook-url https://... --fail-on-gaps
ENTRYPOINT ["python", "/usr/local/bin/meraki2tf-runbook.py"]
