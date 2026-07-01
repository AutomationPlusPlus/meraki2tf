"""Meraki OpenAPI spec resolution: local file, freshness check, GitHub fetch.

Resolution rules for ``--spec``:

* The spec file exists → compare its ``info.version`` against the
  latest release published in the ``meraki/openapi`` GitHub repository;
  when the versions differ (or either is unknown) the local file is
  refreshed with the latest release. If GitHub is unreachable the local
  copy is used as-is with a warning, keeping air-gapped and offline
  runs functional.
* The file does not exist (or ``--spec`` was omitted, defaulting to
  ``spec3.json`` in the current directory) → the latest release is
  downloaded from GitHub directly.

Only standard-library networking (``urllib.request``) is used.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: Latest published OpenAPI v3 document of the Meraki dashboard API.
SPEC_REMOTE_URL = (
    "https://raw.githubusercontent.com/meraki/openapi/master/openapi/spec3.json"
)

#: Local filename assumed when ``--spec`` is omitted.
DEFAULT_SPEC_FILENAME = "spec3.json"

_DOWNLOAD_TIMEOUT_SECONDS = 60.0


class SpecResolutionError(RuntimeError):
    """The OpenAPI spec could not be obtained from any source."""


def _download(url: str) -> str:
    try:
        with urllib.request.urlopen(url, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as response:
            return str(response.read().decode("utf-8"))
    except Exception as exc:
        raise SpecResolutionError(
            f"Could not download the Meraki OpenAPI spec from {url}: {exc}"
        ) from exc


def _parse_spec(text: str, source: str) -> dict[str, Any]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SpecResolutionError(f"Spec from {source} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SpecResolutionError(f"Spec from {source} is not a JSON object.")
    return document


def _version_of(document: dict[str, Any]) -> str | None:
    info = document.get("info")
    version = info.get("version") if isinstance(info, dict) else None
    return str(version) if version else None


def _local_version(path: Path) -> str | None:
    try:
        return _version_of(_parse_spec(path.read_text(encoding="utf-8"), str(path)))
    except (OSError, SpecResolutionError):
        logger.warning("Local spec %s is unreadable; treating it as outdated.", path)
        return None


def fetch_latest_spec(url: str = SPEC_REMOTE_URL) -> dict[str, Any]:
    """Download and parse the latest published spec release."""
    return _parse_spec(_download(url), url)


def resolve_spec(spec_path: Path | None, remote_url: str = SPEC_REMOTE_URL) -> Path:
    """Materialize the OpenAPI spec to run against and return its path."""
    path = spec_path if spec_path is not None else Path(DEFAULT_SPEC_FILENAME)

    if path.exists():
        local_version = _local_version(path)
        try:
            remote_text = _download(remote_url)
            remote_version = _version_of(_parse_spec(remote_text, remote_url))
        except SpecResolutionError as exc:
            logger.warning(
                "Could not check GitHub for a newer spec (%s); using local %s.",
                exc, path,
            )
            return path
        if local_version is not None and local_version == remote_version:
            logger.info("Spec %s is already the latest release (%s).", path, local_version)
            return path
        path.write_text(remote_text, encoding="utf-8")
        logger.info(
            "Refreshed spec %s from GitHub: %s -> %s.",
            path, local_version or "unknown", remote_version or "unknown",
        )
        return path

    logger.info("Spec %s not found; downloading the latest release from GitHub.", path)
    remote_text = _download(remote_url)
    _parse_spec(remote_text, remote_url)  # never write an unparseable document
    path.write_text(remote_text, encoding="utf-8")
    logger.info("Downloaded latest spec release to %s.", path)
    return path
