"""Adaptive request pacing shared by every discovery worker.

The Meraki per-organization budget (10 req/s) is shared with every
other API consumer of the tenant, so a worker pool must not simply
multiply the request rate: the bucket paces all workers together,
backs off multiplicatively the moment the API throttles anyone
(global pause — one 429 means the *organization* is saturated, not one
worker), and recovers additively while calls succeed. Classic AIMD,
deliberately capped below the documented budget so the co-tenant
integrations keep working during our sweeps.
"""

from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)

#: Never pace above this even after long success streaks — the org
#: budget is 10 req/s and it is shared.
_MAX_RATE = 6.0
#: Floor under repeated throttling; keeps progress crawling instead of
#: stalling entirely.
_MIN_RATE = 0.5
#: Additive increase per successful call (req/s).
_INCREASE = 0.05
#: Multiplicative decrease factor on a throttle.
_DECREASE = 0.5
#: Global pause after a throttle before anyone dispatches again.
_THROTTLE_PAUSE_SECONDS = 2.0


class AdaptiveTokenBucket:
    """Thread-safe AIMD pacer for a pool of API workers."""

    def __init__(self, rate: float = 4.0) -> None:
        self._rate = min(max(rate, _MIN_RATE), _MAX_RATE)
        self._lock = threading.Lock()
        self._next_slot = time.monotonic()
        #: Nobody dispatches before this instant (throttle pause).
        self._paused_until = time.monotonic()

    @property
    def rate(self) -> float:
        with self._lock:
            return self._rate

    def acquire(self) -> None:
        """Block until this worker may dispatch one request."""
        while True:
            with self._lock:
                now = time.monotonic()
                earliest = max(self._next_slot, self._paused_until)
                if earliest <= now:
                    self._next_slot = now + 1.0 / self._rate
                    return
                wait = earliest - now
            time.sleep(wait)

    def on_success(self) -> None:
        """Additive recovery while the API keeps accepting calls."""
        with self._lock:
            self._rate = min(self._rate + _INCREASE, _MAX_RATE)

    def on_throttle(self) -> None:
        """Multiplicative backoff plus a global pause: one 429 means the
        shared organization budget is saturated for every worker."""
        with self._lock:
            self._rate = max(self._rate * _DECREASE, _MIN_RATE)
            self._paused_until = max(
                self._paused_until,
                time.monotonic() + _THROTTLE_PAUSE_SECONDS,
            )
            logger.debug(
                "Throttled: pacing reduced to %.2f req/s with a %.0fs "
                "global pause.", self._rate, _THROTTLE_PAUSE_SECONDS,
            )
