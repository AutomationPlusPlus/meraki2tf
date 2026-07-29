"""Meraki OpenAPI spec resolution: local file, freshness check, GitHub fetch.

Resolution rules for ``--spec``:

* The spec file exists → compare its ``info.version`` against the
  latest release published in the ``meraki/openapi`` GitHub repository.
  For the tool-managed default (``--spec`` omitted), a version
  difference (or an unknown version on either side) refreshes the file
  with the latest release; an explicitly user-supplied ``--spec`` file
  is never overwritten — the difference is only warned about. If
  GitHub is unreachable the local copy is used as-is with a warning,
  keeping air-gapped and offline runs functional.
* The file does not exist (or ``--spec`` was omitted, defaulting to
  ``spec3.json`` in the current directory) → the latest release is
  downloaded from GitHub directly.

Only standard-library networking (``urllib.request``) is used.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.request
from pathlib import Path
from typing import Any

from meraki2tf.fileio import atomic_write_text

logger = logging.getLogger(__name__)

#: Latest published OpenAPI v3 document of the Meraki dashboard API.
SPEC_REMOTE_URL = (
    "https://raw.githubusercontent.com/meraki/openapi/master/openapi/spec3.json"
)

#: Local filename assumed when ``--spec`` is omitted.
DEFAULT_SPEC_FILENAME = "spec3.json"

_DOWNLOAD_TIMEOUT_SECONDS = 60.0
#: Wall-clock ceiling on the whole transfer. The socket timeout above
#: is per read operation, so a server dripping one byte per minute
#: would otherwise keep the unattended DR job "alive" forever.
_DOWNLOAD_DEADLINE_SECONDS = 600.0
#: The published Meraki spec is a few MB; cap the download so a
#: poisoned or wrong endpoint cannot OOM the unattended DR job with an
#: unbounded response body.
_MAX_SPEC_BYTES = 128 * 1024 * 1024
_DOWNLOAD_CHUNK_BYTES = 1024 * 1024


class SpecResolutionError(RuntimeError):
    """The OpenAPI spec could not be obtained from any source."""


def _download(url: str) -> str:
    deadline = time.monotonic() + _DOWNLOAD_DEADLINE_SECONDS
    try:
        with urllib.request.urlopen(url, timeout=_DOWNLOAD_TIMEOUT_SECONDS) as response:
            # Read one byte past the ceiling so an oversized body is
            # detected rather than silently truncated. Chunked with a
            # wall-clock deadline: the socket timeout only bounds each
            # read, so a byte-dripping server would otherwise stall the
            # unattended run indefinitely.
            chunks: list[bytes] = []
            received = 0
            while received <= _MAX_SPEC_BYTES:
                if time.monotonic() > deadline:
                    raise SpecResolutionError(
                        f"Spec download from {url} did not complete within "
                        f"{_DOWNLOAD_DEADLINE_SECONDS:.0f}s; giving up."
                    )
                chunk = response.read(
                    min(_DOWNLOAD_CHUNK_BYTES, _MAX_SPEC_BYTES + 1 - received)
                )
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
            raw = b"".join(chunks)
    except SpecResolutionError:
        raise
    except Exception as exc:
        raise SpecResolutionError(
            f"Could not download the Meraki OpenAPI spec from {url}: {exc}"
        ) from exc
    if len(raw) > _MAX_SPEC_BYTES:
        raise SpecResolutionError(
            f"Spec download from {url} exceeds the {_MAX_SPEC_BYTES}-byte "
            "ceiling; refusing to load a suspiciously large document."
        )
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A garbled body must translate like every other download
        # failure so callers with a local copy can fall back to it
        # instead of crashing the run.
        raise SpecResolutionError(
            f"Spec download from {url} is not valid UTF-8: {exc}"
        ) from exc


def _parse_spec(text: str, source: str) -> dict[str, Any]:
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, RecursionError) as exc:
        # RecursionError: pathologically nested JSON must degrade like
        # any other malformed document so the local-copy fallback runs.
        raise SpecResolutionError(f"Spec from {source} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise SpecResolutionError(f"Spec from {source} is not a JSON object.")
    return document


def _version_of(document: dict[str, Any]) -> str | None:
    info = document.get("info")
    version = info.get("version") if isinstance(info, dict) else None
    return str(version) if version else None


def _has_paths(document: dict[str, Any]) -> bool:
    """Structural sanity: a JSON object without a usable ``paths`` object
    (an API error body, a wrong file, a truncated download) parses fine
    but kills ingestion.

    An EMPTY ``paths`` is just as unusable as a missing one — it yields
    an empty dispatch table, so nothing would map to Terraform and the
    kit would come out empty — and must never be written over a
    known-good spec or adopted as one.
    """
    paths = document.get("paths")
    return isinstance(paths, dict) and bool(paths)


def _local_version(path: Path) -> str | None:
    try:
        return _version_of(_parse_spec(path.read_text(encoding="utf-8"), str(path)))
    except (OSError, UnicodeDecodeError, SpecResolutionError):
        logger.warning("Local spec %s is unreadable; treating it as outdated.", path)
        return None


def fetch_latest_spec(url: str = SPEC_REMOTE_URL) -> dict[str, Any]:
    """Download and parse the latest published spec release."""
    return _parse_spec(_download(url), url)


def spec_fingerprint(path: Path) -> tuple[str | None, str]:
    """``(info.version, sha256 hex digest)`` of a spec file on disk.

    The pair identifies exactly which document a run executed against:
    DR write actions log it, and snapshot exports stamp it into the
    snapshot header so a later restore can warn about spec skew.
    """
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        version = _version_of(_parse_spec(raw.decode("utf-8"), str(path)))
    except (UnicodeDecodeError, SpecResolutionError):
        version = None
    return version, digest


def resolve_spec(
    spec_path: Path | None,
    remote_url: str = SPEC_REMOTE_URL,
    *,
    refresh: bool = True,
) -> Path:
    """Materialize the OpenAPI spec to run against and return its path.

    ``spec_path`` is ``None`` when ``--spec`` was omitted: the tool then
    owns the default ``./spec3.json`` and refreshes it whenever GitHub
    publishes a different release. An explicitly supplied file belongs
    to the user — a hand-curated or deliberately pinned spec (including
    a downgrade) is never overwritten; a version difference against the
    latest release only logs a warning and the run continues on the
    user's file. A missing file is downloaded fresh in either mode.

    ``refresh=False`` is the DR write-action mode (``--restore``,
    ``--heal``, ``--replay-gaps``): an existing local spec is used
    exactly as it is — no network check, no chance of the mutable
    remote tip swapping the dispatch table under a live write run — and
    the file's version + sha256 are logged so the run's exact spec is
    on record. Only a completely missing file still downloads (there is
    nothing local to be deterministic about).

    Raises :class:`SpecResolutionError` when a download fails or yields a
    spec that is not valid JSON, is not an object, or carries no
    ``paths`` — an unparseable or structurally empty spec is never
    written or run against.
    """
    user_supplied = spec_path is not None
    path = spec_path if spec_path is not None else Path(DEFAULT_SPEC_FILENAME)

    if not refresh and path.exists():
        version, digest = spec_fingerprint(path)
        logger.info(
            "DR write action: using the %s spec %s as-is (version %s, "
            "sha256 %s); write actions never auto-refresh the spec.",
            "user-supplied" if user_supplied else "local",
            path, version or "unknown", digest,
        )
        return path
    if not refresh:
        logger.warning(
            "Spec %s does not exist; downloading the latest release once "
            "(DR write actions otherwise never fetch the spec — keep the "
            "downloaded file, or pass --spec, for deterministic reruns).",
            path,
        )

    if path.exists():
        local_version = _local_version(path)
        try:
            remote_text = _download(remote_url)
            remote_document = _parse_spec(remote_text, remote_url)
            remote_version = _version_of(remote_document)
        except SpecResolutionError as exc:
            logger.warning(
                "Could not check GitHub for a newer spec (%s); using local %s.",
                exc, path,
            )
            return path
        if local_version is not None and local_version == remote_version:
            logger.info("Spec %s is already the latest release (%s).", path, local_version)
            return path
        if user_supplied:
            # An explicit --spec file is the user's, not the tool's
            # cache: never clobber it (versions differing includes
            # deliberate downgrades and hand-curated documents).
            logger.warning(
                "Spec %s (version %s) differs from the latest published "
                "release (%s); keeping the user-supplied file as-is.",
                path, local_version or "unknown", remote_version or "unknown",
            )
            return path
        if not _has_paths(remote_document):
            # Never clobber a known-good local spec with a document
            # that would fail ingestion — the good copy would be gone
            # and every scheduled run after would re-download the same
            # broken one.
            logger.warning(
                "Remote spec from %s parses but carries no 'paths' "
                "object; keeping the local %s.", remote_url, path,
            )
            return path
        # Atomic replace: a crash or full disk mid-write must never
        # leave a truncated dispatch table where the good spec was.
        atomic_write_text(path, remote_text)
        logger.info(
            "Refreshed spec %s from GitHub: %s -> %s.",
            path, local_version or "unknown", remote_version or "unknown",
        )
        return path

    logger.info("Spec %s not found; downloading the latest release from GitHub.", path)
    remote_text = _download(remote_url)
    # Never write an unparseable or structurally empty document.
    if not _has_paths(_parse_spec(remote_text, remote_url)):
        raise SpecResolutionError(
            f"Spec from {remote_url} carries no 'paths' object; refusing "
            "to write it."
        )
    atomic_write_text(path, remote_text)
    logger.info("Downloaded latest spec release to %s.", path)
    return path
