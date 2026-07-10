"""Restore planner: waves, create-vs-configure classification, audit."""

import json
from pathlib import Path

from conftest import _op

from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    MerakiDevice,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.restorer import (
    WAVE_DEVICE_CLAIM,
    WAVE_DEVICE_FEATURES,
    WAVE_NETWORK_FEATURES,
    WAVE_NETWORKS,
    WAVE_ORG_FEATURES,
    plan_restore,
    render_restore_plan,
)
from meraki2tf.sanitizer import REDACTED

GP_COLLECTION = "/networks/{networkId}/groupPolicies"
GP_ITEM = "/networks/{networkId}/groupPolicies/{groupPolicyId}"
SSID_ITEM = "/networks/{networkId}/wireless/ssids/{number}"
SNMP_PATH = "/networks/{networkId}/snmp"
ADMINS_ITEM = "/organizations/{organizationId}/admins/{adminId}"
CLIENTS_PATH = "/networks/{networkId}/clients"
PORT_ITEM = "/devices/{serial}/switch/ports/{portId}"


def _restore_spec(tmp_path: Path) -> OpenApiParser:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "restore", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            "/organizations/{organizationId}/admins": {
                "get": _op("getOrganizationAdmins", "organizations"),
                "post": _op("createOrganizationAdmin", "organizations"),
            },
            ADMINS_ITEM: {
                "get": _op("getOrganizationAdmin", "organizations"),
                "put": _op("updateOrganizationAdmin", "organizations"),
            },
            GP_COLLECTION: {
                "get": _op("getNetworkGroupPolicies", "networks"),
                "post": _op("createNetworkGroupPolicy", "networks"),
            },
            GP_ITEM: {
                "get": _op("getNetworkGroupPolicy", "networks"),
                "put": _op("updateNetworkGroupPolicy", "networks"),
            },
            "/networks/{networkId}/wireless/ssids": {
                "get": _op("getNetworkWirelessSsids", "wireless"),
            },
            SSID_ITEM: {
                "get": _op("getNetworkWirelessSsid", "wireless"),
                "put": _op("updateNetworkWirelessSsid", "wireless"),
            },
            SNMP_PATH: {
                "get": _op("getNetworkSnmp", "networks"),
                "put": _op("updateNetworkSnmp", "networks"),
            },
            CLIENTS_PATH: {
                "get": _op("getNetworkClients", "networks"),
            },
            PORT_ITEM: {
                "get": _op("getDeviceSwitchPort", "switch"),
                "put": _op("updateDeviceSwitchPort", "switch"),
            },
        },
    }
    path = tmp_path / "restore-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def _graph(*features: FeatureConfiguration) -> NetworkGraph:
    return NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"], "timeZone": "UTC"}
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1",
                 "model": "MX68", "name": "edge"}
            ),
        ),
        features=features,
    )


def test_plan_orders_waves_and_classifies_kinds(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(PORT_ITEM, ("Q2AB-CDEF-GHIJ", "1"),
                                 {"portId": "1", "name": "uplink"}),
            FeatureConfiguration(GP_ITEM, ("N_1", "100"),
                                 {"groupPolicyId": "100", "name": "kiosk"}),
            FeatureConfiguration(SSID_ITEM, ("N_1", "0"),
                                 {"number": 0, "name": "Corp"}),
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
            FeatureConfiguration(ADMINS_ITEM, ("org-123", "A_1"),
                                 {"id": "A_1", "name": "Jordan Sample"}),
        ),
        parser,
    )
    assert plan.unrestorable == ()
    waves = [action.wave for action in plan.actions]
    assert waves == sorted(waves)  # strictly wave-ordered output

    by_path = {action.api_path: action for action in plan.actions}
    # Networks are created; devices claimed.
    assert by_path["/organizations/{organizationId}/networks"].kind == "create"
    assert by_path["/organizations/{organizationId}/networks"].wave == WAVE_NETWORKS
    assert by_path["/networks/{networkId}/devices/claim"].kind == "claim"
    assert by_path["/networks/{networkId}/devices/claim"].wave == WAVE_DEVICE_CLAIM
    # Server-assigned-ID items (collection POST exists) are creates.
    assert by_path[GP_ITEM].kind == "create"
    assert by_path[GP_ITEM].operation.operation_id == "createNetworkGroupPolicy"
    assert by_path[GP_ITEM].wave == WAVE_NETWORK_FEATURES
    # Fixed-slot items (no collection POST) are configured in place.
    assert by_path[SSID_ITEM].kind == "configure"
    assert by_path[SSID_ITEM].operation.operation_id == "updateNetworkWirelessSsid"
    # Singletons are configured.
    assert by_path[SNMP_PATH].kind == "configure"
    # Org features run in the first wave.
    assert by_path[ADMINS_ITEM].wave == WAVE_ORG_FEATURES
    # Device features run last.
    assert by_path[PORT_ITEM].wave == WAVE_DEVICE_FEATURES


def test_unrestorable_reasons_are_spec_derived(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(CLIENTS_PATH, ("N_1",), {"usage": 1}),
            FeatureConfiguration(SNMP_PATH, ("N_1",), {}),
            FeatureConfiguration(
                GP_ITEM, ("N_1", "9"), {UNREADABLE_MARKER: "HTTP 500"}
            ),
        ),
        parser,
    )
    reasons = {u.api_path: u.reason for u in plan.unrestorable}
    assert "dashboard-only" in reasons[CLIENTS_PATH]
    assert "No payload captured" in reasons[SNMP_PATH]
    assert "unreadable at capture" in reasons[GP_ITEM]


def test_redacted_secrets_become_reentry_pointers(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"),
                {"number": 0, "name": "Corp", "psk": REDACTED},
            ),
        ),
        parser,
    )
    ssid = next(a for a in plan.actions if a.api_path == SSID_ITEM)
    assert ssid.secret_reentry == ("psk",)
    assert "psk" not in ssid.payload  # never write the redaction marker
    assert ssid.payload["name"] == "Corp"


def test_fully_redacted_asset_is_unrestorable(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(FeatureConfiguration(SSID_ITEM, ("N_1", "0"), {"psk": REDACTED})),
        parser,
    )
    (item,) = plan.unrestorable
    assert "sanitized snapshot" in item.reason


def test_unsanitized_secrets_stay_in_the_payload(tmp_path: Path) -> None:
    """Restoring real secret values from the unsanitized snapshot is the
    point of the DR vault copy."""
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"),
                {"number": 0, "name": "Corp", "psk": "hunter2"},
            ),
        ),
        parser,
    )
    ssid = next(a for a in plan.actions if a.api_path == SSID_ITEM)
    assert ssid.payload["psk"] == "hunter2"
    assert ssid.secret_reentry == ()


def test_render_restore_plan_is_bounded_and_value_free(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    features = tuple(
        FeatureConfiguration(
            GP_ITEM, ("N_1", str(i)),
            {"groupPolicyId": str(i), "secretSauce": "s3cr3t"},
        )
        for i in range(40)
    )
    plan = plan_restore(_graph(*features), parser)
    text = render_restore_plan(plan, limit=5)
    assert "s3cr3t" not in text
    assert "more action(s)" in text
    assert plan.summary() in text


def test_action_key_and_operation_fallbacks(tmp_path: Path) -> None:
    """A spec slice without the network/claim endpoints still plans —
    the synthesized operations carry the real operationIds."""
    import json as _json

    spec = {
        "openapi": "3.0.0",
        "info": {"title": "tiny", "version": "1"},
        "paths": {
            SNMP_PATH: {
                "get": _op("getNetworkSnmp", "networks"),
                "put": _op("updateNetworkSnmp", "networks"),
            },
        },
    }
    path = tmp_path / "tiny-spec.json"
    path.write_text(_json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    plan = plan_restore(_graph(), parser)
    create = next(a for a in plan.actions if a.kind == "create")
    claim = next(a for a in plan.actions if a.kind == "claim")
    assert create.operation.operation_id == "createOrganizationNetwork"
    assert claim.operation.operation_id == "claimNetworkDevices"
    assert create.key == "/organizations/{organizationId}/networks::N_1"


def test_render_restore_plan_lists_and_bounds_unrestorable(
    tmp_path: Path,
) -> None:
    parser = _restore_spec(tmp_path)
    features = tuple(
        FeatureConfiguration(CLIENTS_PATH, (f"N_{i}",), {"usage": 1})
        for i in range(10)
    )
    plan = plan_restore(_graph(*features), parser)
    text = render_restore_plan(plan, limit=3)
    assert "UNRESTORABLE" in text
    assert "more unrestorable" in text


# ---------------------------------------------------------------- executor


def test_rewrite_references_maps_ids_and_grammar() -> None:
    from meraki2tf.restorer import rewrite_references

    id_map = {"N_old": "N_new", "100": "200"}
    known = frozenset({"N_old", "100", "GP_dangling"})
    payload = {
        "groupPolicyId": "100",
        "hubIds": ["N_old"],
        "rule": "allow GRP(100) to any",
        "comment": "mentions N_old only as data",
        "nested": {"rfProfileId": "unrelated-string"},
    }
    rewritten = rewrite_references(payload, id_map, known)
    assert rewritten["groupPolicyId"] == "200"
    assert rewritten["hubIds"] == ["N_new"]
    assert rewritten["rule"] == "allow GRP(200) to any"
    # Non-reference keys pass through even when they contain known IDs.
    assert rewritten["comment"] == "mentions N_old only as data"
    assert rewritten["nested"]["rfProfileId"] == "unrelated-string"


def test_rewrite_references_fails_loudly_on_dangling_ids() -> None:
    import pytest as _pytest

    from meraki2tf.restorer import UnmappedReferenceError, rewrite_references

    known = frozenset({"GP_dangling", "42"})
    with _pytest.raises(UnmappedReferenceError):
        rewrite_references({"groupPolicyId": "GP_dangling"}, {}, known)
    with _pytest.raises(UnmappedReferenceError):
        rewrite_references({"rule": "deny OBJ(42)"}, {}, known)


def test_restore_journal_round_trips_and_resumes(tmp_path: Path) -> None:
    from meraki2tf.restorer import RestoreJournal

    path = tmp_path / "restore-journal.jsonl"
    journal = RestoreJournal(path)
    journal.record_done("a::1")
    journal.record_mapping("old-1", "new-1")
    assert oct(path.stat().st_mode & 0o777) == "0o600"

    resumed = RestoreJournal(path)
    assert resumed.completed == {"a::1"}
    assert resumed.id_map == {"old-1": "new-1"}


class _RecordingSection:
    """SDK-section stand-in recording every dispatched write."""

    def __init__(self, calls: list, fail_ops: set[str] | None = None) -> None:
        self._calls = calls
        self._fail = fail_ops or set()

    def __getattr__(self, operation_id: str):  # noqa: ANN204
        def _dispatch(*args: object, **kwargs: object) -> dict:
            self._calls.append((operation_id, args, kwargs))
            if operation_id in self._fail:
                raise RuntimeError("simulated API failure")
            if operation_id == "createOrganizationNetwork":
                return {"id": "L_NEW"}
            if operation_id == "createNetworkGroupPolicy":
                return {"id": "900"}
            return {}

        return _dispatch


def _executor(tmp_path: Path, fail_ops: set[str] | None = None):
    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    calls: list = []
    restorer = OrgRestorer(
        "org-TARGET",
        RestoreJournal(tmp_path / "journal.jsonl"),
        serial_map={"Q2AB-CDEF-GHIJ": "Q9ZZ-NEWW-HWSN"},
    )
    section = _RecordingSection(calls, fail_ops)
    restorer._client = __import__("types").SimpleNamespace(
        organizations=section, networks=section, wireless=section,
        switch=section,
    )
    return restorer, calls


def test_executor_creates_claims_and_remaps_in_order(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            GP_ITEM, ("N_1", "100"), {"groupPolicyId": "100", "name": "kiosk"}
        ),
        FeatureConfiguration(
            SSID_ITEM, ("N_1", "0"),
            {"number": 0, "name": "Corp", "groupPolicyId": "100"},
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    ops = [c[0] for c in calls]
    # Network created before claim, before its features.
    assert ops.index("createOrganizationNetwork") < ops.index("claimNetworkDevices")
    assert ops.index("claimNetworkDevices") < ops.index("createNetworkGroupPolicy")
    # Network create targets the TARGET org.
    create = next(c for c in calls if c[0] == "createOrganizationNetwork")
    assert create[1] == ("org-TARGET",)
    # Claim uses the mapped network ID and the replacement serial.
    claim = next(c for c in calls if c[0] == "claimNetworkDevices")
    assert claim[1] == ("L_NEW",)
    assert claim[2] == {"serials": ["Q9ZZ-NEWW-HWSN"]}
    # The SSID references the group policy's NEW server-assigned ID.
    ssid = next(c for c in calls if c[0] == "updateNetworkWirelessSsid")
    assert ssid[1] == ("L_NEW", "0")
    assert ssid[2]["groupPolicyId"] == "900"


def test_executor_skips_children_of_failed_parents(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(
        tmp_path, fail_ops={"createOrganizationNetwork"}
    )
    result = restorer.execute(graph, plan)

    assert [key for key, _ in result.failed] == [
        "/organizations/{organizationId}/networks::N_1"
    ]
    skipped_reasons = " ".join(e["reason"] for e in result.skipped)
    assert "parent object N_1 failed" in skipped_reasons
    assert all(c[0] != "updateNetworkSnmp" for c in calls)


def test_executor_resumes_from_the_journal(tmp_path: Path) -> None:
    from meraki2tf.restorer import RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph()
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    first = restorer.execute(graph, plan)
    assert len(first.executed) == 2  # network + device claim

    # Fresh executor, same journal: everything already restored.
    from meraki2tf.restorer import OrgRestorer

    calls2: list = []
    section = _RecordingSection(calls2)
    again = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "journal.jsonl")
    )
    again._client = __import__("types").SimpleNamespace(
        organizations=section, networks=section
    )
    second = again.execute(graph, plan)
    assert second.executed == ()
    assert calls2 == []
    assert all("already restored" in e["reason"] for e in second.skipped)


def test_executor_reports_unmapped_references_per_object(
    tmp_path: Path,
) -> None:
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SSID_ITEM, ("N_1", "0"),
            # references a group policy that exists in the snapshot but
            # is never restored (no feature for it) → dangling.
            {"number": 0, "groupPolicyId": "GP_ghost"},
        ),
        FeatureConfiguration(
            GP_ITEM, ("N_1", "GP_ghost"), {UNREADABLE_MARKER: "HTTP 500"}
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, _calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)
    assert any("no rebuilt counterpart" in reason for _, reason in result.failed)


def test_rewrite_reference_edges() -> None:
    from meraki2tf.restorer import rewrite_references

    # Non-string reference values (fixed-slot numbers) pass through.
    assert rewrite_references({"vlanId": 5}, {}, frozenset()) == {"vlanId": 5}
    # Unknown GRP ids are data, not references.
    assert rewrite_references(
        {"rule": "allow GRP(999)"}, {}, frozenset({"1"})
    ) == {"rule": "allow GRP(999)"}


def test_journal_ignores_blank_lines(tmp_path: Path) -> None:
    from meraki2tf.restorer import RestoreJournal

    path = tmp_path / "j.jsonl"
    path.write_text('{"kind": "done", "key": "a"}\n\n', encoding="utf-8")
    assert RestoreJournal(path).completed == {"a"}


def test_executor_records_missing_sdk_method_as_failure(
    tmp_path: Path,
) -> None:
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph()
    plan = plan_restore(graph, parser)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j2.jsonl")
    )
    restorer._client = SimpleNamespace()  # no sections at all
    result = restorer.execute(graph, plan)
    assert result.executed == ()
    assert all("no method" in reason for _, reason in result.failed)


def test_drill_mode_skips_claims_and_device_features(tmp_path: Path) -> None:
    """A drill cannot claim production hardware; those waves are
    drill-skipped verdicts, never failures."""
    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(PORT_ITEM, ("Q2AB-CDEF-GHIJ", "1"),
                             {"portId": "1", "name": "uplink"}),
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    restorer = OrgRestorer(
        "org-TARGET",
        RestoreJournal(tmp_path / "drill-journal.jsonl"),
        skip_claims=True,
    )
    section = _RecordingSection(calls)
    restorer._client = __import__("types").SimpleNamespace(
        organizations=section, networks=section, switch=section
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    ops = [c[0] for c in calls]
    assert "claimNetworkDevices" not in ops
    assert "updateDeviceSwitchPort" not in ops
    assert "updateNetworkSnmp" in ops  # network config still restored
    drill_skips = [e for e in result.skipped if "drill" in e["reason"]]
    assert len(drill_skips) == 2  # the claim + the switch port
