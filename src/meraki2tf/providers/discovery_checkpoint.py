"""Resumable discovery: an append-only checkpoint journal for the sweep.

Discovery of a large organization is a multi-hour API read pass, and it
used to be all-or-nothing: one sustained throttle at hour N discarded
every completed call (restore and heal are journaled; discovery was
not). The checkpoint journal fixes that asymmetry: every completed
call's outcome — payload, scope-refusal absence, or unreadable-gap —
is appended as one JSONL record the moment it finishes, so an aborted
run (``LiveRetryExhaustedError``, Ctrl-C, crash) leaves the file behind
and the next run with the same ``--discovery-checkpoint`` skips the
completed calls and replays their outcomes into the graph. A run that
finishes deletes its checkpoint.

Safety properties:

* **Secret-bearing** — recorded payloads are raw API responses (SSID
  PSKs, SNMP strings, …), so the file is created 0600 before any secret
  byte lands in it, exactly like the unsanitized snapshot.
* **Identity-guarded** — the header records the organization ID and the
  OpenAPI spec's sha256; a mismatched checkpoint refuses loudly instead
  of silently splicing another org's (or another spec's) outcomes into
  this run's graph.
* **Torn-tail tolerant** — an abort can tear the last record (or, for
  ``.gz`` journals, the last compressed member). Loading stops at the
  first unreadable record with a warning; the lost calls simply re-run.
* **Outcome-exact** — refusals and unreadable gaps round-trip as
  themselves, so a resumed graph is byte-identical to an uninterrupted
  run's (payload expansion runs through the very same spec-driven code
  path on replay, guarded by the spec-sha check).
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import os
import threading
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO

from meraki2tf.fsperms import restrict_to_owner

logger = logging.getLogger(__name__)

#: First-line marker identifying a discovery checkpoint journal.
CHECKPOINT_MARKER = "meraki2tfDiscoveryCheckpoint"
CHECKPOINT_VERSION = 1

#: Outcome discriminators (the ``result`` field of a call record).
OUTCOME_PAYLOAD = "payload"
OUTCOME_REFUSED = "refused"
OUTCOME_UNREADABLE = "unreadable"


class CheckpointMismatchError(ValueError):
    """The checkpoint belongs to a different organization or spec.

    Replaying another organization's payloads — or outcomes shaped by a
    different OpenAPI document — into this run's graph would produce a
    silently wrong snapshot, so a mismatch refuses loudly; the operator
    picks a fresh checkpoint path (or deletes the stale file).
    """


def _wants_gzip(path: Path) -> bool:
    return path.name.lower().endswith(".gz")


def _read_intact_lines(path: Path) -> list[str]:
    """Every intact line of the journal; a torn tail is dropped.

    A crash mid-append can leave a partial final line — or, for gzip
    journals, a member without its trailer (``EOFError``) or one whose
    last deflate block was only half written (``zlib.error``, which
    descends from ``Exception`` rather than ``OSError`` and so has to be
    named explicitly). Everything up to the tear is valid; the torn
    record's call simply re-runs.

    Letting any of these escape would be the worst outcome available:
    the journal exists so an aborted multi-hour sweep resumes, and an
    unhandled decompression error instead makes every subsequent run
    fail at startup until a human deletes the file — a scheduled job
    wedged permanently by the very artifact meant to rescue it.
    """
    lines: list[str] = []
    try:
        if _wants_gzip(path):
            with gzip.open(path, "rt", encoding="utf-8") as handle:
                for line in handle:
                    lines.append(line)
        else:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    lines.append(line)
    except (EOFError, OSError, UnicodeDecodeError, zlib.error) as exc:
        logger.warning(
            "Checkpoint %s has a torn tail (%s); records after the "
            "tear are discarded and their calls will re-run.",
            path, exc,
        )
    return lines


def _validate_header(
    path: Path, header_line: str, organization_id: str, spec_sha256: str
) -> None:
    """Refuse a journal whose identity header does not bind this run."""
    try:
        header = json.loads(header_line)
    except json.JSONDecodeError:
        header = None
    if (
        not isinstance(header, dict)
        or header.get(CHECKPOINT_MARKER) != CHECKPOINT_VERSION
    ):
        raise CheckpointMismatchError(
            f"{path} is not a meraki2tf discovery checkpoint "
            "(or was written by an incompatible version); refusing to "
            "resume from it. Point --discovery-checkpoint at a fresh "
            "path."
        )
    recorded_org = str(header.get("organizationId", ""))
    recorded_sha = str(header.get("specSha256", ""))
    if recorded_org != organization_id:
        raise CheckpointMismatchError(
            f"Checkpoint {path} was recorded for organization "
            f"{recorded_org}, but this run discovers organization "
            f"{organization_id}; replaying it would splice "
            "another organization's data into this snapshot. Use a "
            "fresh checkpoint path per organization."
        )
    if recorded_sha != spec_sha256:
        raise CheckpointMismatchError(
            f"Checkpoint {path} was recorded against a "
            "different OpenAPI spec (sha256 "
            f"{recorded_sha or 'unrecorded'} vs "
            f"{spec_sha256}); replayed outcomes would expand "
            "differently than fresh calls. Re-run with the "
            "capture-time --spec, or start a fresh checkpoint."
        )


def verify_binding(
    path: Path, organization_id: str, spec_sha256: str
) -> None:
    """Eagerly refuse a stale/foreign checkpoint before anything runs.

    Read-only header check for the CLI's fail-fast validation pass: a
    mismatched journal must refuse before environment probes and hours
    of discovery, not when the provider first opens it. A missing or
    headerless file is fine — this run will write a fresh header.
    """
    if not path.exists():
        return
    lines = _read_intact_lines(path)
    if not lines:
        return
    _validate_header(path, lines[0], organization_id, spec_sha256)


@dataclass(frozen=True)
class CallOutcome:
    """One completed discovery call's recorded result.

    ``kind`` is one of the ``OUTCOME_*`` discriminators; ``payload``
    carries the raw API response for :data:`OUTCOME_PAYLOAD`, and
    ``reason`` the human-readable gap reason for
    :data:`OUTCOME_UNREADABLE`.
    """

    kind: str
    payload: Any = None
    reason: str = ""


#: A completed call's identity: (api_path, path_values).
CallKey = tuple[str, tuple[str, ...]]


class DiscoveryCheckpoint:
    """Append-only journal of completed discovery calls (0600, JSONL[.gz]).

    Thread-safe: discovery workers append concurrently; each record is
    written and flushed under a lock so a crash can tear at most the
    final record.
    """

    def __init__(
        self, path: Path, organization_id: str, spec_sha256: str
    ) -> None:
        self._path = path
        self._organization_id = organization_id
        self._spec_sha256 = spec_sha256
        self._lock = threading.Lock()
        self._completed: dict[CallKey, CallOutcome] = {}
        self._closed = False
        if path.exists():
            has_header = self._load_existing()
            self._handle = self._open_for_append(header=not has_header)
        else:
            self._handle = self._open_for_append(header=True)

    @property
    def resumed_count(self) -> int:
        """Completed calls loaded from a previous run's journal."""
        return len(self._completed)

    def get(self, api_path: str, path_values: tuple[str, ...]) -> CallOutcome | None:
        """The recorded outcome for one call, or None when it must run."""
        return self._completed.get((api_path, path_values))

    def record(
        self, api_path: str, path_values: tuple[str, ...], outcome: CallOutcome
    ) -> None:
        """Append one completed call's outcome and flush it to disk."""
        entry: dict[str, Any] = {
            "apiPath": api_path,
            "pathValues": list(path_values),
            "result": outcome.kind,
        }
        if outcome.kind == OUTCOME_PAYLOAD:
            entry["payload"] = outcome.payload
        elif outcome.kind == OUTCOME_UNREADABLE:
            entry["reason"] = outcome.reason
        line = json.dumps(entry) + "\n"
        with self._lock:
            self._completed[(api_path, path_values)] = outcome
            self._handle.write(line)
            # Sync-flushed per record (gzip uses Z_SYNC_FLUSH): an abort
            # one second later must not lose an hour of completed calls
            # sitting in a buffer.
            self._handle.flush()

    def close(self) -> None:
        """Close the journal, KEEPING the file (the abort path)."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._handle.close()

    def complete(self) -> None:
        """Close and delete the journal (the success path).

        A finished discovery needs no resume point, and leaving a
        secret-bearing file behind after the snapshot exists would be a
        third copy of every credential for no benefit.
        """
        self.close()
        self._path.unlink(missing_ok=True)
        logger.info(
            "Discovery completed; checkpoint %s deleted.", self._path
        )

    # -- storage ------------------------------------------------------

    def _wants_gzip(self) -> bool:
        return _wants_gzip(self._path)

    def _open_for_append(self, header: bool) -> TextIO:
        """Open the journal 0600 for appending; write the header if new."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # O_CREAT with mode 0600: no wider-mode window ever exists, even
        # before restrict_to_owner verifies (and warns on filesystems
        # that ignore POSIX modes).
        fd = os.open(
            self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
        )
        restrict_to_owner(self._path)
        raw = os.fdopen(fd, "ab")
        handle: TextIO
        if self._wants_gzip():
            # Appending opens a NEW gzip member; readers of multi-member
            # files see one concatenated stream, so resume-appended
            # records read exactly like first-run ones.
            handle = io.TextIOWrapper(
                gzip.GzipFile(fileobj=raw, mode="ab"), encoding="utf-8"
            )
        else:
            handle = io.TextIOWrapper(raw, encoding="utf-8")
        if header:
            handle.write(
                json.dumps(
                    {
                        CHECKPOINT_MARKER: CHECKPOINT_VERSION,
                        "organizationId": self._organization_id,
                        "specSha256": self._spec_sha256,
                    }
                )
                + "\n"
            )
            handle.flush()
        return handle

    def _read_lines(self) -> list[str]:
        """Every intact line of the journal; a torn tail is dropped.

        A crash mid-append can leave a partial final line — or, for
        gzip journals, a member without its trailer (``EOFError``).
        Everything up to the tear is valid; the torn record's call
        simply re-runs.
        """
        return _read_intact_lines(self._path)

    def _load_existing(self) -> bool:
        """Load a previous run's journal, verifying its identity header.

        Returns True when a valid header was found (appends need no new
        one); an empty file — created, then crashed before the header
        flushed — reports False so this run writes a fresh header.
        """
        lines = self._read_lines()
        if not lines:
            # Zero intact lines: nothing to resume, nothing to verify.
            return False
        _validate_header(
            self._path, lines[0], self._organization_id, self._spec_sha256
        )
        loaded = 0
        for number, line in enumerate(lines[1:], start=2):
            entry = self._parse_entry(line)
            if entry is None:
                logger.warning(
                    "Checkpoint %s line %d is unreadable; it and every "
                    "later record are discarded (their calls re-run).",
                    self._path, number,
                )
                break
            key, outcome = entry
            self._completed[key] = outcome
            loaded += 1
        if loaded:
            logger.info(
                "Resuming discovery from checkpoint %s: %d completed "
                "call(s) will be replayed instead of re-queried.",
                self._path, loaded,
            )
        return True

    @staticmethod
    def _parse_entry(line: str) -> tuple[CallKey, CallOutcome] | None:
        """One journal line → (key, outcome), or None when unreadable."""
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return None
        if not isinstance(record, dict):
            return None
        api_path = record.get("apiPath")
        values = record.get("pathValues")
        result = record.get("result")
        if (
            not isinstance(api_path, str)
            or not isinstance(values, list)
            or not all(isinstance(value, str) for value in values)
            or result not in (
                OUTCOME_PAYLOAD, OUTCOME_REFUSED, OUTCOME_UNREADABLE
            )
        ):
            return None
        key: CallKey = (api_path, tuple(values))
        if result == OUTCOME_PAYLOAD:
            return key, CallOutcome(
                kind=OUTCOME_PAYLOAD, payload=record.get("payload")
            )
        if result == OUTCOME_UNREADABLE:
            return key, CallOutcome(
                kind=OUTCOME_UNREADABLE, reason=str(record.get("reason", ""))
            )
        return key, CallOutcome(kind=OUTCOME_REFUSED)
