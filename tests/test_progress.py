"""Discovery progress reporting: cadence, content, and live wiring."""

import json
import logging
import sys
import types
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.config import API_KEY_ENV_VAR
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers import LiveApiDataProvider
from meraki2tf.providers.progress import DiscoveryProgress, _format_eta


class _Bucket:
    """Rate-only stand-in for the AIMD bucket."""

    def __init__(self, rate: float = 2.0) -> None:
        self.rate = rate


class _Clock:
    """Deterministic monotonic clock the tests advance by hand."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _messages(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == "meraki2tf.providers.progress"
    ]


def test_no_line_before_the_interval_elapses(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _Clock()
    progress = DiscoveryProgress(_Bucket(), clock=clock, interval=30.0)
    progress.start_level("single-scope", 10)
    with caplog.at_level(logging.INFO):
        for _ in range(9):
            clock.now += 1.0
            progress.item_completed()
    assert _messages(caplog) == []


def test_one_line_per_interval_with_counts_rate_and_eta(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _Clock()
    progress = DiscoveryProgress(_Bucket(rate=2.0), clock=clock, interval=30.0)
    progress.start_level("single-scope", 10)
    with caplog.at_level(logging.INFO):
        for _ in range(3):
            progress.item_completed()  # same instant: throttled
        clock.now = 31.0
        progress.item_completed()  # due: 4 done
        progress.item_completed()  # same instant again: throttled
    lines = _messages(caplog)
    assert len(lines) == 1
    # 4/10 done, 4 overall, 2.0 req/s, 6 remaining / 2.0 = ~3s.
    assert (
        "Discovery progress: 4/10 single-scope call(s) done, "
        "4 completed overall, 2.0 req/s effective, ~3s remaining "
        "in this level." == lines[0]
    )


def test_levels_reset_but_overall_count_accumulates(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _Clock()
    progress = DiscoveryProgress(_Bucket(rate=1.0), clock=clock, interval=30.0)
    progress.start_level("single-scope", 2)
    with caplog.at_level(logging.INFO):
        progress.item_completed()
        progress.item_completed()
        progress.start_level("config-template", 5)
        clock.now = 60.0
        progress.item_completed()
    lines = _messages(caplog)
    assert len(lines) == 1
    assert "1/5 config-template call(s) done, 3 completed overall" in lines[0]


def test_zero_rate_reports_unknown_eta(
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = _Clock()
    progress = DiscoveryProgress(_Bucket(rate=0.0), clock=clock, interval=1.0)
    progress.start_level("single-scope", 3)
    with caplog.at_level(logging.INFO):
        clock.now = 5.0
        progress.item_completed()
    assert "unknown remaining in this level" in _messages(caplog)[0]


@pytest.mark.parametrize(
    ("seconds", "rendered"),
    [
        (45.0, "~45s"),
        (200.0, "~3m 20s"),
        (7500.0, "~2h 05m"),
        (0.0, "~0s"),
    ],
)
def test_eta_formatting(seconds: float, rendered: str) -> None:
    assert _format_eta(seconds) == rendered


class _RateBucket:
    """Instant, non-sleeping bucket carrying a rate for progress lines."""

    def __init__(self, rate: float = 4.0) -> None:
        self.rate = rate

    def acquire(self) -> None:
        return None

    def on_success(self) -> None:
        return None

    def on_throttle(self) -> None:  # pragma: no cover - not throttled here
        return None


class _AdvancingClock:
    """Monotonic clock that jumps a full interval on every read."""

    def __init__(self, step: float = 31.0) -> None:
        self.now = 0.0
        self._step = step

    def __call__(self) -> float:
        self.now += self._step
        return self.now


class _Organizations:
    def getOrganizationNetworks(
        self, org_id: str, total_pages: str
    ) -> list[dict[str, Any]]:
        return []

    def getOrganizationDevices(
        self, org_id: str, total_pages: str
    ) -> list[dict[str, Any]]:
        return []

    def getOrganizationAdmins(self, organizationId: str) -> list[dict[str, Any]]:
        return [{"id": "A_1", "email": "ops@example.com"}]


class _Wireless:
    def getOrganizationWirelessAirMarshalSettingsByNetwork(
        self, organizationId: str
    ) -> dict[str, Any]:
        return {"items": [], "meta": {}}


class _Dashboard:
    def __init__(self) -> None:
        self.organizations = _Organizations()
        self.wireless = _Wireless()


def test_live_discovery_emits_progress_lines_at_info(
    monkeypatch: pytest.MonkeyPatch,
    spec_file: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The sweep emits periodic INFO progress under the injected clock,
    and the line renders as a normal record in JSON log mode too."""
    monkeypatch.setattr(
        "meraki2tf.providers.live.AdaptiveTokenBucket", _RateBucket
    )
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: _Dashboard()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    provider = LiveApiDataProvider(
        parser=OpenApiParser(spec_file),
        progress_clock=_AdvancingClock(step=31.0),
    )
    with caplog.at_level(logging.INFO):
        provider.fetch_network_graph("org-123")
    lines = _messages(caplog)
    assert lines, "expected at least one progress line"
    assert "single-scope call(s) done" in lines[0]
    # A normal log record: message renders standalone (JSON mode uses
    # record.getMessage() exactly like the text formatter).
    assert json.dumps({"message": lines[0]})
