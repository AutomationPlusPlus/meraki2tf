"""Resumable discovery: checkpoint journal round-trip, guards, wiring.

The core property under test: a sweep that aborts halfway and resumes
from its checkpoint must produce a graph byte-identical to an
uninterrupted run's — including scope-refusal absences and
unreadable-gap records — while never re-querying completed calls.
"""

import copy
import json
import logging
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.config import API_KEY_ENV_VAR
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.providers import LiveApiDataProvider, LiveRetryExhaustedError
from meraki2tf.providers.discovery_checkpoint import (
    OUTCOME_PAYLOAD,
    OUTCOME_REFUSED,
    OUTCOME_UNREADABLE,
    CallOutcome,
    CheckpointMismatchError,
    DiscoveryCheckpoint,
)
from meraki2tf.providers.live import DISCOVERY_WORKERS_ENV_VAR

SUFFIXES = ["ckpt.jsonl", "ckpt.jsonl.gz"]


# ---------------------------------------------------------------- unit


@pytest.mark.parametrize("name", SUFFIXES)
def test_round_trip_of_all_outcome_kinds(tmp_path: Path, name: str) -> None:
    path = tmp_path / "nested" / name
    journal = DiscoveryCheckpoint(path, "org-123", "sha-1")
    assert journal.resumed_count == 0
    assert journal.get("/a", ("N_1",)) is None
    journal.record(
        "/a", ("N_1",),
        CallOutcome(kind=OUTCOME_PAYLOAD, payload=[{"id": 1, "psk": "s3cr3t"}]),
    )
    journal.record("/b", ("N_1",), CallOutcome(kind=OUTCOME_REFUSED))
    journal.record(
        "/c", ("N_1", "2"),
        CallOutcome(kind=OUTCOME_UNREADABLE, reason="HTTP 500 after retries"),
    )
    journal.close()

    resumed = DiscoveryCheckpoint(path, "org-123", "sha-1")
    assert resumed.resumed_count == 3
    assert resumed.get("/a", ("N_1",)) == CallOutcome(
        kind=OUTCOME_PAYLOAD, payload=[{"id": 1, "psk": "s3cr3t"}]
    )
    assert resumed.get("/b", ("N_1",)) == CallOutcome(kind=OUTCOME_REFUSED)
    assert resumed.get("/c", ("N_1", "2")) == CallOutcome(
        kind=OUTCOME_UNREADABLE, reason="HTTP 500 after retries"
    )
    # Appends after a resume land as readable records too (gz: a new
    # member of the multi-member stream).
    resumed.record("/d", (), CallOutcome(kind=OUTCOME_REFUSED))
    resumed.close()
    third = DiscoveryCheckpoint(path, "org-123", "sha-1")
    assert third.resumed_count == 4
    third.complete()
    assert not path.exists()


def test_checkpoint_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "discovery.ckpt.jsonl"
    journal = DiscoveryCheckpoint(path, "org-123", "sha-1")
    journal.record(
        "/a", (), CallOutcome(kind=OUTCOME_PAYLOAD, payload={"psk": "x"})
    )
    journal.close()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_close_is_idempotent_and_keeps_the_file(tmp_path: Path) -> None:
    path = tmp_path / "discovery.ckpt.jsonl"
    journal = DiscoveryCheckpoint(path, "org-123", "sha-1")
    journal.close()
    journal.close()
    assert path.exists()


def test_org_mismatch_refuses_loudly(tmp_path: Path) -> None:
    path = tmp_path / "discovery.ckpt.jsonl"
    DiscoveryCheckpoint(path, "org-999", "sha-1").close()
    with pytest.raises(CheckpointMismatchError, match="organization org-999"):
        DiscoveryCheckpoint(path, "org-123", "sha-1")


def test_spec_sha_mismatch_refuses_loudly(tmp_path: Path) -> None:
    path = tmp_path / "discovery.ckpt.jsonl"
    DiscoveryCheckpoint(path, "org-123", "sha-OLD").close()
    with pytest.raises(CheckpointMismatchError, match="different OpenAPI spec"):
        DiscoveryCheckpoint(path, "org-123", "sha-NEW")


@pytest.mark.parametrize("first_line", ["not-json\n", "[1, 2]\n", "{}\n"])
def test_non_checkpoint_file_refuses_loudly(
    tmp_path: Path, first_line: str
) -> None:
    path = tmp_path / "discovery.ckpt.jsonl"
    path.write_text(first_line, encoding="utf-8")
    with pytest.raises(CheckpointMismatchError, match="not a meraki2tf"):
        DiscoveryCheckpoint(path, "org-123", "sha-1")


def test_empty_existing_file_gets_a_fresh_header(tmp_path: Path) -> None:
    path = tmp_path / "discovery.ckpt.jsonl"
    path.touch()
    journal = DiscoveryCheckpoint(path, "org-123", "sha-1")
    journal.record("/a", (), CallOutcome(kind=OUTCOME_REFUSED))
    journal.close()
    resumed = DiscoveryCheckpoint(path, "org-123", "sha-1")
    assert resumed.resumed_count == 1
    resumed.close()


def test_torn_plain_tail_is_discarded_with_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "discovery.ckpt.jsonl"
    journal = DiscoveryCheckpoint(path, "org-123", "sha-1")
    journal.record("/a", (), CallOutcome(kind=OUTCOME_REFUSED))
    journal.record("/b", (), CallOutcome(kind=OUTCOME_REFUSED))
    journal.close()
    with path.open("ab") as handle:
        handle.write(b'{"apiPath": "/torn", "pathVal')
    with caplog.at_level(logging.WARNING):
        resumed = DiscoveryCheckpoint(path, "org-123", "sha-1")
    assert resumed.resumed_count == 2
    assert "unreadable" in caplog.text
    resumed.close()


def test_torn_gzip_tail_is_discarded_with_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "discovery.ckpt.jsonl.gz"
    journal = DiscoveryCheckpoint(path, "org-123", "sha-1")
    journal.record("/a", (), CallOutcome(kind=OUTCOME_REFUSED))
    journal.record("/b", (), CallOutcome(kind=OUTCOME_REFUSED))
    journal.close()
    raw = path.read_bytes()
    path.write_bytes(raw[:-8])  # chop the gzip trailer (a crash's shape)
    with caplog.at_level(logging.WARNING):
        resumed = DiscoveryCheckpoint(path, "org-123", "sha-1")
    assert resumed.resumed_count == 2
    assert "torn tail" in caplog.text
    resumed.close()


def test_malformed_record_stops_loading_with_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "discovery.ckpt.jsonl"
    header = {
        "meraki2tfDiscoveryCheckpoint": 1,
        "organizationId": "org-123",
        "specSha256": "sha-1",
    }
    good = {"apiPath": "/a", "pathValues": [], "result": "refused"}
    later = {"apiPath": "/b", "pathValues": [], "result": "refused"}
    path.write_text(
        json.dumps(header) + "\n" + json.dumps(good) + "\n"
        + "garbage\n" + json.dumps(later) + "\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        journal = DiscoveryCheckpoint(path, "org-123", "sha-1")
    assert journal.resumed_count == 1
    assert journal.get("/b", ()) is None
    assert "line 3 is unreadable" in caplog.text
    journal.close()


@pytest.mark.parametrize(
    "line",
    [
        "garbage",
        json.dumps(["not", "a", "dict"]),
        json.dumps({"pathValues": [], "result": "refused"}),
        json.dumps({"apiPath": "/a", "pathValues": "N_1", "result": "refused"}),
        json.dumps({"apiPath": "/a", "pathValues": [1], "result": "refused"}),
        json.dumps({"apiPath": "/a", "pathValues": [], "result": "exploded"}),
    ],
)
def test_parse_entry_rejects_malformed_shapes(line: str) -> None:
    assert DiscoveryCheckpoint._parse_entry(line) is None


# --------------------------------------------- provider integration


NETWORK = {
    "id": "N_1",
    "organizationId": "org-123",
    "name": "HQ",
    "productTypes": ["appliance"],
}
DEVICE = {
    "serial": "Q2AB-CDEF-GHIJ",
    "networkId": "N_1",
    "model": "MX64",
    "name": "edge",
}


class _FakeApiError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status


class _NullBucket:
    def __init__(self) -> None:
        self.rate = 4.0

    def acquire(self) -> None:
        return None

    def on_success(self) -> None:
        return None

    def on_throttle(self) -> None:
        return None


_SECTIONS = {
    "organizations": (
        "getOrganizationNetworks",
        "getOrganizationDevices",
        "getOrganizationAdmins",
    ),
    "appliance": (
        "getNetworkApplianceVlans",
        "getNetworkApplianceTrafficShaping",
        "getNetworkApplianceSsids",
    ),
    "wireless": (
        "getNetworkWirelessSsids",
        "getOrganizationWirelessAirMarshalSettingsByNetwork",
    ),
    "networks": ("getNetworkSyslogServers",),
    "sensor": ("getNetworkSensorRelationships",),
    "switch": ("getDeviceSwitchPorts",),
}


def _dashboard(responses: dict[str, Any], calls: dict[str, int]) -> Any:
    def handler(name: str) -> Any:
        def call(*args: Any, **kwargs: Any) -> Any:
            calls[name] = calls.get(name, 0) + 1
            value = responses[name]
            if isinstance(value, BaseException):
                raise value
            return copy.deepcopy(value)

        return call

    class Section:
        pass

    class Dashboard:
        pass

    dashboard = Dashboard()
    for section_name, methods in _SECTIONS.items():
        section = Section()
        for method in methods:
            setattr(section, method, handler(method))
        setattr(dashboard, section_name, section)
    return dashboard


#: An uninterrupted run's responses: one refusal (sensor), one
#: unreadable endpoint (syslog), everything else data.
REFERENCE_RESPONSES: dict[str, Any] = {
    "getOrganizationNetworks": [NETWORK],
    "getOrganizationDevices": [DEVICE],
    "getOrganizationAdmins": [{"id": "A_1", "email": "ops@example.com"}],
    "getNetworkApplianceVlans": [{"id": 10, "name": "Data"}],
    "getNetworkApplianceTrafficShaping": {
        "globalBandwidthLimits": {"limitUp": 0, "limitDown": 0}
    },
    "getNetworkApplianceSsids": [{"number": 1, "authMode": "psk"}],
    "getNetworkWirelessSsids": [{"number": 1, "name": "Corp"}],
    "getNetworkSyslogServers": _FakeApiError(500),
    "getNetworkSensorRelationships": _FakeApiError(400),
    "getDeviceSwitchPorts": [{"portId": "1", "name": "Uplink"}],
    "getOrganizationWirelessAirMarshalSettingsByNetwork": {
        "items": [{"networkId": "N_1", "defaultPolicy": "allowed"}],
        "meta": {"counts": {"items": {"total": 1}}},
    },
}

#: Ops the aborted first run completes (everything queued before the
#: failing aggregation call under a single worker).
_COMPLETED_OPS = (
    "getOrganizationAdmins",
    "getNetworkApplianceVlans",
    "getNetworkApplianceTrafficShaping",
    "getNetworkApplianceSsids",
    "getNetworkWirelessSsids",
    "getNetworkSyslogServers",
    "getNetworkSensorRelationships",
    "getDeviceSwitchPorts",
)


def _provider(
    monkeypatch: pytest.MonkeyPatch,
    spec_parser: OpenApiParser,
    dashboard: Any,
    checkpoint: Path | None = None,
) -> LiveApiDataProvider:
    monkeypatch.setattr(
        "meraki2tf.providers.live.AdaptiveTokenBucket", _NullBucket
    )
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    monkeypatch.setenv(DISCOVERY_WORKERS_ENV_VAR, "1")
    provider = LiveApiDataProvider(
        parser=spec_parser, checkpoint_path=checkpoint, spec_sha256="sha-1"
    )
    provider._client = dashboard  # injected client (test seam)
    return provider


@pytest.mark.parametrize("name", SUFFIXES)
def test_aborted_sweep_resumes_to_a_byte_identical_graph(
    monkeypatch: pytest.MonkeyPatch,
    spec_parser: OpenApiParser,
    tmp_path: Path,
    name: str,
) -> None:
    """The headline property: abort halfway, resume, compare graphs.

    Run 2's dashboard returns TAMPERED data for every call run 1
    completed — including the scope-refusal and the unreadable
    endpoint, which now 'work' — so equality with the uninterrupted
    reference proves every recorded outcome (payload, absence, gap)
    was replayed rather than re-queried.
    """
    reference = _provider(
        monkeypatch, spec_parser, _dashboard(dict(REFERENCE_RESPONSES), {})
    ).fetch_network_graph("org-123")
    # Sanity: the reference carries the gap record and the absence.
    assert any(
        "syslogServers" in feature.api_path for feature in reference.features
    )
    assert not any(
        "sensor" in feature.api_path for feature in reference.features
    )

    checkpoint = tmp_path / name
    run1 = dict(REFERENCE_RESPONSES)
    run1["getOrganizationWirelessAirMarshalSettingsByNetwork"] = (
        _FakeApiError(429)
    )
    provider1 = _provider(
        monkeypatch, spec_parser, _dashboard(run1, {}), checkpoint
    )
    with pytest.raises(LiveRetryExhaustedError):
        provider1.fetch_network_graph("org-123")
    assert checkpoint.exists()
    assert stat.S_IMODE(os.stat(checkpoint).st_mode) == 0o600

    run2 = dict(REFERENCE_RESPONSES)
    run2["getOrganizationAdmins"] = [{"id": "TAMPERED"}]
    run2["getNetworkApplianceVlans"] = [{"id": 99, "name": "TAMPERED"}]
    run2["getNetworkApplianceTrafficShaping"] = {"tampered": True}
    run2["getNetworkApplianceSsids"] = [{"number": 9}]
    run2["getNetworkWirelessSsids"] = [{"number": 9, "name": "TAMPERED"}]
    run2["getNetworkSyslogServers"] = [{"host": "10.0.0.9"}]
    run2["getNetworkSensorRelationships"] = [{"id": "R1"}]
    run2["getDeviceSwitchPorts"] = [{"portId": "9", "name": "TAMPERED"}]
    calls2: dict[str, int] = {}
    provider2 = _provider(
        monkeypatch, spec_parser, _dashboard(run2, calls2), checkpoint
    )
    resumed = provider2.fetch_network_graph("org-123")

    assert resumed == reference
    assert not checkpoint.exists()  # deleted on success
    for op_name in _COMPLETED_OPS:
        assert calls2.get(op_name, 0) == 0, op_name  # replayed, not re-run
    assert calls2["getOrganizationWirelessAirMarshalSettingsByNetwork"] == 1


def test_completed_run_deletes_its_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    spec_parser: OpenApiParser,
    tmp_path: Path,
) -> None:
    checkpoint = tmp_path / "discovery.ckpt.jsonl"
    provider = _provider(
        monkeypatch, spec_parser,
        _dashboard(dict(REFERENCE_RESPONSES), {}), checkpoint,
    )
    graph = provider.fetch_network_graph("org-123")
    assert graph.networks
    assert not checkpoint.exists()


def test_keyboard_interrupt_keeps_the_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    spec_parser: OpenApiParser,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    checkpoint = tmp_path / "discovery.ckpt.jsonl"
    responses = dict(REFERENCE_RESPONSES)
    responses["getNetworkApplianceVlans"] = KeyboardInterrupt()
    provider = _provider(
        monkeypatch, spec_parser, _dashboard(responses, {}), checkpoint
    )
    with caplog.at_level(logging.WARNING):
        with pytest.raises(KeyboardInterrupt):
            provider.fetch_network_graph("org-123")
    assert checkpoint.exists()
    assert "kept" in caplog.text


_AGG_PATH = (
    "/organizations/{organizationId}/wireless/airMarshal/settings/byNetwork"
)
_AGG_OP = "getOrganizationWirelessAirMarshalSettingsByNetwork"
_AGG_COLLECTION = "/networks/{networkId}/wireless/airMarshal/settings"


@pytest.mark.parametrize("status", [500, 400])
def test_aggregation_outcomes_are_journaled(
    monkeypatch: pytest.MonkeyPatch,
    spec_parser: OpenApiParser,
    tmp_path: Path,
    status: int,
) -> None:
    """Aggregation failures/refusals journal like per-scope calls (the
    run completes, so the journal is deleted — recording still ran)."""
    checkpoint = tmp_path / "discovery.ckpt.jsonl"
    responses = dict(REFERENCE_RESPONSES)
    responses[_AGG_OP] = _FakeApiError(status)
    provider = _provider(
        monkeypatch, spec_parser, _dashboard(responses, {}), checkpoint
    )
    graph = provider.fetch_network_graph("org-123")
    if status == 500:
        assert any(
            feature.api_path == _AGG_COLLECTION for feature in graph.features
        )
    else:
        assert not any(
            "airMarshal" in feature.api_path for feature in graph.features
        )
    assert not checkpoint.exists()


@pytest.mark.parametrize("kind", ["payload", "refused", "unreadable"])
def test_aggregation_outcomes_replay_from_the_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    spec_parser: OpenApiParser,
    tmp_path: Path,
    kind: str,
) -> None:
    checkpoint = tmp_path / "discovery.ckpt.jsonl"
    journal = DiscoveryCheckpoint(checkpoint, "org-123", "sha-1")
    if kind == "payload":
        outcome = CallOutcome(
            kind=OUTCOME_PAYLOAD,
            payload=REFERENCE_RESPONSES[_AGG_OP],
        )
    elif kind == "refused":
        outcome = CallOutcome(kind=OUTCOME_REFUSED)
    else:
        outcome = CallOutcome(
            kind=OUTCOME_UNREADABLE, reason="HTTP 503 after every retry"
        )
    journal.record(_AGG_PATH, ("org-123",), outcome)
    journal.close()

    calls: dict[str, int] = {}
    responses = dict(REFERENCE_RESPONSES)
    responses[_AGG_OP] = {"items": [{"networkId": "N_1", "tampered": True}]}
    provider = _provider(
        monkeypatch, spec_parser, _dashboard(responses, calls), checkpoint
    )
    graph = provider.fetch_network_graph("org-123")

    assert calls.get(_AGG_OP, 0) == 0  # replayed, never re-queried
    airmarshal = [
        feature
        for feature in graph.features
        if "airMarshal" in feature.api_path
    ]
    if kind == "payload":
        assert [feature.payload for feature in airmarshal] == [
            {"defaultPolicy": "allowed"}
        ]
    elif kind == "refused":
        assert airmarshal == []
    else:
        assert [feature.api_path for feature in airmarshal] == [
            _AGG_COLLECTION
        ]
        assert "HTTP 503" in str(airmarshal[0].payload)


def test_template_sweep_calls_replay_from_the_checkpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Config-template sweeps journal and resume like every other call:
    a journaled template-scoped outcome is replayed, not re-queried."""
    import types

    from conftest import _op

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "templates", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/configTemplates": {
                "get": _op("getOrganizationConfigTemplates", "organizations"),
                "post": _op(
                    "createOrganizationConfigTemplate", "organizations"
                ),
            },
            "/organizations/{organizationId}/configTemplates"
            "/{configTemplateId}": {
                "get": _op("getOrganizationConfigTemplate", "organizations"),
                "put": _op(
                    "updateOrganizationConfigTemplate", "organizations"
                ),
            },
            "/networks/{networkId}/appliance/vlans": {
                "get": _op("getNetworkApplianceVlans", "appliance"),
            },
            "/networks/{networkId}/appliance/vlans/{vlanId}": {
                "get": _op("getNetworkApplianceVlan", "appliance"),
                "put": _op("updateNetworkApplianceVlan", "appliance"),
            },
        },
    }
    spec_path = tmp_path / "template-spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")

    checkpoint = tmp_path / "discovery.ckpt.jsonl"
    journal = DiscoveryCheckpoint(checkpoint, "org-123", "sha-1")
    journal.record(
        "/networks/{networkId}/appliance/vlans", ("T_1",),
        CallOutcome(
            kind=OUTCOME_PAYLOAD,
            payload=[{"id": 77, "name": "Template-Data"}],
        ),
    )
    journal.close()

    vlan_scopes: list[str] = []

    class Organizations:
        def getOrganizationNetworks(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return [NETWORK]

        def getOrganizationDevices(
            self, org_id: str, total_pages: str
        ) -> list[dict[str, Any]]:
            return []

        def getOrganizationConfigTemplates(
            self, organizationId: str
        ) -> list[dict[str, Any]]:
            return [{"id": "T_1", "name": "Branch Template"}]

    class Appliance:
        def getNetworkApplianceVlans(
            self, networkId: str
        ) -> list[dict[str, Any]]:
            vlan_scopes.append(networkId)
            return [{"id": 10, "name": "TAMPERED"}]

    provider = _provider(
        monkeypatch,
        OpenApiParser(spec_path),
        types.SimpleNamespace(
            organizations=Organizations(), appliance=Appliance()
        ),
        checkpoint,
    )
    graph = provider.fetch_network_graph("org-123")

    assert vlan_scopes == ["N_1"]  # the template scope was replayed
    template_vlans = [
        feature
        for feature in graph.features
        if feature.path_values and feature.path_values[0] == "T_1"
        and feature.api_path
        == "/networks/{networkId}/appliance/vlans/{vlanId}"
    ]
    assert [f.payload for f in template_vlans] == [
        {"id": 77, "name": "Template-Data"}
    ]
    assert not checkpoint.exists()


def test_provider_refuses_a_foreign_checkpoint_before_any_call(
    monkeypatch: pytest.MonkeyPatch,
    spec_parser: OpenApiParser,
    tmp_path: Path,
) -> None:
    checkpoint = tmp_path / "discovery.ckpt.jsonl"
    DiscoveryCheckpoint(checkpoint, "org-999", "sha-1").close()
    calls: dict[str, int] = {}
    provider = _provider(
        monkeypatch, spec_parser,
        _dashboard(dict(REFERENCE_RESPONSES), calls), checkpoint,
    )
    with pytest.raises(CheckpointMismatchError):
        provider.fetch_network_graph("org-123")
    assert calls == {}  # refused before spending any API budget
    assert checkpoint.exists()  # a mismatch never destroys the journal
