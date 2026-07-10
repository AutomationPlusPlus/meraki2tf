"""AIMD pacing bucket: additive recovery, multiplicative backoff, pause."""

import pytest

from meraki2tf.providers import ratelimit
from meraki2tf.providers.ratelimit import AdaptiveTokenBucket


def test_rate_recovers_additively_and_caps() -> None:
    bucket = AdaptiveTokenBucket(rate=5.9)
    for _ in range(10):
        bucket.on_success()
    assert bucket.rate == pytest.approx(6.0)  # capped at the ceiling


def test_throttle_halves_rate_and_floors() -> None:
    bucket = AdaptiveTokenBucket(rate=4.0)
    bucket.on_throttle()
    assert bucket.rate == pytest.approx(2.0)
    for _ in range(10):
        bucket.on_throttle()
    assert bucket.rate == pytest.approx(0.5)  # floored, never zero


def test_constructor_clamps_into_bounds() -> None:
    assert AdaptiveTokenBucket(rate=99.0).rate == pytest.approx(6.0)
    assert AdaptiveTokenBucket(rate=0.0).rate == pytest.approx(0.5)


def test_acquire_paces_and_throttle_pauses_globally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 0.0}
    sleeps: list[float] = []

    def fake_monotonic() -> float:
        return clock["now"]

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock["now"] += seconds

    monkeypatch.setattr(ratelimit.time, "monotonic", fake_monotonic)
    monkeypatch.setattr(ratelimit.time, "sleep", fake_sleep)

    bucket = AdaptiveTokenBucket(rate=2.0)
    bucket.acquire()          # first slot is free
    bucket.acquire()          # second waits 1/rate
    assert sleeps == [pytest.approx(0.5)]

    bucket.on_throttle()      # global pause: nobody dispatches for a while
    bucket.acquire()
    assert sleeps[-1] == pytest.approx(ratelimit._THROTTLE_PAUSE_SECONDS)
