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
FROM python:3.14-slim

ARG TERRAFORM_VERSION=1.9.8

# Terraform is downloaded and its integrity verified against HashiCorp's
# published SHA256SUMS before use: without this a compromised CDN or a
# TLS-interception box could substitute a trojaned binary that then runs
# every --sync job with the dashboard API key in its environment.
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

COPY . /src
RUN pip install --no-cache-dir /src \
    && cp /src/deploy/azure/runbook.py /usr/local/bin/meraki2tf-runbook.py \
    && rm -rf /src

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
