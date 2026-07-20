# General-purpose meraki2tf container image — the bare CLI as
# entrypoint, for any container scheduler (AWS ECS/Fargate scheduled
# tasks, GCP Cloud Run Jobs, plain docker/cron, CI). Build from the
# repository root:
#
#   docker build -t meraki2tf .
#
# Run (read-only export; workdir on a mounted volume):
#
#   docker run --rm -e MERAKI_DASHBOARD_API_KEY \
#     -v "$PWD/generated:/data" meraki2tf --org-id 123456 --workdir /data
#
# The Azure-specific image (Key Vault fetch, Blob archival, runbook
# wrapper entrypoint) lives at deploy/azure/Dockerfile; this one adds
# no cloud glue — credentials and alert settings come from the
# environment exactly as in a host install.

# Project primary interpreter is CPython 3.14 (supports 3.11-3.14).
#
# Multi-stage: the wheel is built in a throwaway builder stage so the
# repository contents never become a layer of the shipped image.
FROM python:3.14-slim AS builder

COPY . /src
RUN pip wheel --no-deps --wheel-dir /wheels /src

FROM python:3.14-slim

ARG TERRAFORM_VERSION=1.9.8

# Terraform is downloaded and its checksum verified against HashiCorp's
# published SHA256SUMS. Both files come from the same origin, so this
# defends against a corrupted or truncated transfer — NOT against a
# compromised releases.hashicorp.com.
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

# Only the built wheel crosses into this stage; runtime dependencies
# resolve from PyPI against the hash-pinned lock so an image rebuild
# cannot silently pull an untested or tampered SDK.
COPY --from=builder /wheels /wheels
COPY requirements-lock.txt /tmp/requirements-lock.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements-lock.txt \
    && pip install --no-cache-dir --no-deps /wheels/*.whl \
    && rm -rf /wheels /tmp/requirements-lock.txt

# Run as an unprivileged user: a compromise of the SDK/terraform then
# does not execute as container root while holding the API key. Any
# mounted workdir volume must be writable by this uid.
RUN useradd --create-home --uid 10001 meraki2tf \
    && mkdir /data && chown meraki2tf:meraki2tf /data
USER meraki2tf
WORKDIR /home/meraki2tf
VOLUME ["/data"]

ENTRYPOINT ["meraki2tf"]
CMD ["--help"]
