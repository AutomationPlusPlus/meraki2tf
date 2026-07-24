"""Periodic progress reporting for the multi-hour discovery sweep.

A large organization takes hours to discover, and a silent console is
indistinguishable from a hung one. The reporter emits one ordinary
INFO log record at most every ~30 seconds — completed/total work items
for the running level, the overall completed count, the current
effective request rate from the shared AIMD bucket, and a rough ETA —
so an operator (or a log aggregator; the line is a normal record and
renders fine in ``--log-format json``) can tell "working" from "hung"
at a glance without drowning the log.

Time is read from an injectable monotonic clock so the 30-second
cadence is deterministic under test; production uses
:func:`time.monotonic`.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable

from meraki2tf.providers.ratelimit import AdaptiveTokenBucket

logger = logging.getLogger(__name__)

#: Minimum seconds between two progress lines. Chatty enough to prove
#: liveness, quiet enough that a multi-hour sweep stays readable.
PROGRESS_INTERVAL_SECONDS = 30.0


def _format_eta(seconds: float) -> str:
    """A rough human ETA (``~2h 05m`` / ``~3m 12s`` / ``~45s``)."""
    whole = int(seconds)
    if whole >= 3600:
        return f"~{whole // 3600}h {(whole % 3600) // 60:02d}m"
    if whole >= 60:
        return f"~{whole // 60}m {whole % 60:02d}s"
    return f"~{whole}s"


class DiscoveryProgress:
    """Thread-safe, time-throttled progress line for discovery levels.

    Workers call :meth:`item_completed` after every finished work item;
    a line is emitted only when at least ``interval`` seconds of the
    injected monotonic clock passed since the previous one, so pool
    width and item rate never change the log volume. The ETA is a rough
    estimate — remaining items of the current level at the bucket's
    current effective rate (one request per item; retries and nested
    follow-ups make it an underestimate, which is fine for a liveness
    signal).
    """

    def __init__(
        self,
        bucket: AdaptiveTokenBucket,
        clock: Callable[[], float] = time.monotonic,
        interval: float = PROGRESS_INTERVAL_SECONDS,
    ) -> None:
        self._bucket = bucket
        self._clock = clock
        self._interval = interval
        self._lock = threading.Lock()
        self._level_label = "discovery"
        self._level_total = 0
        self._level_done = 0
        self._overall_done = 0
        #: No line before the first interval elapses: the sweep's own
        #: startup logging already proves liveness at second zero.
        self._last_emit = clock()

    def start_level(self, label: str, total: int) -> None:
        """Begin a new work level (single-scope, template, nested…)."""
        with self._lock:
            self._level_label = label
            self._level_total = total
            self._level_done = 0

    def item_completed(self) -> None:
        """Count one finished work item; emit a line when one is due."""
        with self._lock:
            self._level_done += 1
            self._overall_done += 1
            now = self._clock()
            if now - self._last_emit < self._interval:
                return
            self._last_emit = now
            label = self._level_label
            done = self._level_done
            total = self._level_total
            overall = self._overall_done
        rate = self._bucket.rate
        remaining = max(0, total - done)
        eta = _format_eta(remaining / rate) if rate > 0 else "unknown"
        # Emitted outside the lock: a slow log handler must never stall
        # the worker pool behind the progress counter.
        logger.info(
            "Discovery progress: %d/%d %s call(s) done, %d completed "
            "overall, %.1f req/s effective, %s remaining in this level.",
            done, total, label, overall, rate, eta,
        )
