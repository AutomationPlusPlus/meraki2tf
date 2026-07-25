"""Restore planner: waves, create-vs-configure classification, audit."""

import json
import logging
import re
from pathlib import Path

import pytest

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
    OrgRestorer,
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
    assert "unreadable at capture" in reasons[GP_ITEM]
    # An empty object is a faithful capture (Meraki defaults), not a
    # missing payload: it must land in the defaults bucket, not as an
    # unrestorable gap.
    assert SNMP_PATH not in reasons
    assert [(d.api_path, d.path_values) for d in plan.defaults] == [
        (SNMP_PATH, ("N_1",))
    ]


def test_scope_less_gap_records_plan_as_unrestorable(tmp_path: Path) -> None:
    """A byNetwork aggregation row discovery could not resolve to any
    scope carries ``path_values=()``: it exists for Cardinal Rule 2
    visibility and must classify as unrestorable, never dispatch to
    die on a missing path parameter and count as a restore FAILURE."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH,
            (),
            {"networkName": "ghost - wireless", "access": "none"},
        )
    )
    plan = plan_restore(graph, parser)
    assert all(action.api_path != SNMP_PATH for action in plan.actions)
    (gap,) = plan.unrestorable
    assert gap.path_values == ()
    assert gap.reason == (
        "diagnostic gap record — no scope identifier; covered by the "
        "runbook's manual list"
    )
    # End-to-end: the executor never sees the record, so nothing fails.
    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert not [c for c in calls if c[0] == "updateNetworkSnmp"]


def test_restore_verdicts_key_containers_under_capture_paths(
    tmp_path: Path,
) -> None:
    """The coverage manifest joins on capture-time pseudo-paths, so
    container verdicts must be keyed both ways (regression: every
    network and device row lacked ``restore_via``)."""
    from meraki2tf.coverage import build_manifest
    from meraki2tf.hcl_generator import (
        DEVICE_API_PATH,
        NETWORK_API_PATH,
        CapturedAsset,
    )
    from meraki2tf.restorer import (
        DEVICE_CLAIM_PATH,
        NETWORK_CREATE_PATH,
        restore_verdicts,
    )

    verdicts = restore_verdicts(plan_restore(_graph(), _restore_spec(tmp_path)))
    # Write-endpoint keys (the restore plan's own spelling) survive.
    assert verdicts[(NETWORK_CREATE_PATH, ("N_1",))] == "create"
    assert verdicts[(DEVICE_CLAIM_PATH, ("N_1", "Q2AB-CDEF-GHIJ"))] == "claim"
    # Capture-time keys land the manifest join.
    assert verdicts[(NETWORK_API_PATH, ("N_1",))] == "create"
    assert verdicts[(DEVICE_API_PATH, ("Q2AB-CDEF-GHIJ",))] == "claim"

    manifest = build_manifest(
        organization_id="org-123",
        captured=(
            CapturedAsset(
                address="meraki_networks.n_1",
                api_path=NETWORK_API_PATH,
                import_id="N_1",
                already_in_state=False,
                identifiers=("N_1",),
            ),
            CapturedAsset(
                address="meraki_devices.q2ab_cdef_ghij",
                api_path=DEVICE_API_PATH,
                import_id="Q2AB-CDEF-GHIJ",
                already_in_state=False,
                identifiers=("Q2AB-CDEF-GHIJ",),
            ),
        ),
        unsupported=(),
        state_addresses=frozenset(),
        restore_via=verdicts,
    )
    by_path = {obj["api_path"]: obj for obj in manifest["objects"]}
    assert by_path[NETWORK_API_PATH]["restore_via"] == "create"
    assert by_path[DEVICE_API_PATH]["restore_via"] == "claim"


def test_empty_capture_gets_default_state_verdict(tmp_path: Path) -> None:
    from meraki2tf.restorer import DEFAULT_STATE_VERDICT, restore_verdicts

    plan = plan_restore(
        _graph(FeatureConfiguration(SNMP_PATH, ("N_1",), {})),
        _restore_spec(tmp_path),
    )
    verdicts = restore_verdicts(plan)
    assert verdicts[(SNMP_PATH, ("N_1",))] == DEFAULT_STATE_VERDICT
    assert "1 at Meraki defaults" in plan.summary()
    assert "at Meraki defaults" in render_restore_plan(plan)


SENSOR_COMMANDS = "/devices/{serial}/sensor/commands"
PII_REQUESTS = "/networks/{networkId}/pii/requests"
PII_REQUEST_ITEM = PII_REQUESTS + "/{requestId}"
SPLASH_THEMES = "/organizations/{organizationId}/splash/themes"
CONTROLLER_MOVES = "/networks/{networkId}/controller/moves"


def _action_log_spec(tmp_path: Path) -> OpenApiParser:
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "logs", "version": "1"},
        "paths": {
            SENSOR_COMMANDS: {
                "get": _op("getDeviceSensorCommands", "sensor"),
                "post": _op("createDeviceSensorCommand", "sensor"),
            },
            PII_REQUESTS: {
                "get": _op("getNetworkPiiRequests", "networks"),
                "post": _op("createNetworkPiiRequest", "networks"),
            },
            PII_REQUEST_ITEM: {
                "get": _op("getNetworkPiiRequest", "networks"),
            },
            SPLASH_THEMES: {
                "get": _op("getOrganizationSplashThemes", "organizations"),
                "post": _op("createOrganizationSplashTheme", "organizations"),
            },
            CONTROLLER_MOVES: {
                "get": _op("getNetworkControllerMoves", "networks"),
                "put": _op("updateNetworkControllerMoves", "networks"),
            },
        },
    }
    path = tmp_path / "action-log-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def test_action_logs_are_unrestorable_never_planned(tmp_path: Path) -> None:
    """POST-only action logs (sensor reboot commands, PII delete
    requests, migrations/moves/captures) record executed operations —
    a restore that re-POSTs them re-executes history against the new
    org. They surface as unrestorable with a reason, never as creates;
    legitimate POST-only entities (splash themes, networks) and
    PUT-bearing entities ending in a log noun are unaffected."""
    parser = _action_log_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(
                SENSOR_COMMANDS, ("Q2AB-CDEF-GHIJ",),
                {"items": [{"operation": "cycleDownstreamPower"}], "meta": {}},
            ),
            FeatureConfiguration(
                PII_REQUEST_ITEM, ("N_1", "123"),
                {"id": "123", "type": "delete"},
            ),
            FeatureConfiguration(
                SPLASH_THEMES, ("org-123",), {"name": "Corp Theme"}
            ),
            FeatureConfiguration(
                CONTROLLER_MOVES, ("N_1",), {"status": "complete"}
            ),
        ),
        parser,
    )
    reasons = {u.api_path: u.reason for u in plan.unrestorable}
    assert "re-execute" in reasons[SENSOR_COMMANDS]
    assert "re-execute" in reasons[PII_REQUEST_ITEM]  # item paths too
    by_path = {a.api_path: a for a in plan.actions}
    assert SENSOR_COMMANDS not in by_path
    assert PII_REQUEST_ITEM not in by_path
    assert by_path[SPLASH_THEMES].kind == "create"
    assert by_path[CONTROLLER_MOVES].kind == "configure"


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
    from meraki2tf.restorer import ReferenceResolver, rewrite_references

    graph = _graph(
        FeatureConfiguration(GP_ITEM, ("N_1", "100"), {"name": "kiosk"}),
    )
    resolver = ReferenceResolver(graph)
    resolver.record("network", "N_1", "N_new")
    resolver.record("grouppolicy", "100", "200", ("N_1",))
    payload = {
        "groupPolicyId": "100",
        "hubIds": ["N_1"],
        "rule": "allow GRP(100) to any",
        "comment": "mentions N_1 only as data",
        "nested": {"rfProfileId": "unrelated-string"},
    }
    rewritten = rewrite_references(payload, resolver, ("N_1", "0"))
    assert rewritten["groupPolicyId"] == "200"
    assert rewritten["hubIds"] == ["N_new"]  # network ref via flat-unique
    assert rewritten["rule"] == "allow GRP(200) to any"
    # Non-reference keys pass through even when they contain known IDs.
    assert rewritten["comment"] == "mentions N_1 only as data"
    assert rewritten["nested"]["rfProfileId"] == "unrelated-string"


def test_rewrite_references_fails_loudly_on_dangling_ids() -> None:
    import pytest as _pytest

    from meraki2tf.restorer import (
        ReferenceResolver,
        UnmappedReferenceError,
        rewrite_references,
    )

    graph = _graph(
        FeatureConfiguration(GP_ITEM, ("N_1", "GP_dangling"), {"name": "x"}),
        FeatureConfiguration(
            "/organizations/{organizationId}/policyObjects/{policyObjectId}",
            ("org-123", "42"),
            {"name": "obj"},
        ),
    )
    resolver = ReferenceResolver(graph)  # no rebuilt counterparts yet
    with _pytest.raises(UnmappedReferenceError):
        rewrite_references(
            {"groupPolicyId": "GP_dangling"}, resolver, ("N_1", "0")
        )
    with _pytest.raises(UnmappedReferenceError):
        rewrite_references({"rule": "deny OBJ(42)"}, resolver, ("N_1",))


def test_resolver_scopes_colliding_ids_by_type() -> None:
    """Group-policy IDs start at 100 and VLAN 100 is ubiquitous; the
    old flat map remapped whichever was journaled last. Type stems keep
    them apart, and an unscopable collision refuses to guess."""
    import pytest as _pytest

    from meraki2tf.restorer import (
        ReferenceResolver,
        UnmappedReferenceError,
        rewrite_references,
    )

    graph = _graph(
        FeatureConfiguration(GP_ITEM, ("N_1", "100"), {"name": "kiosk"}),
        FeatureConfiguration(VLAN_ITEM, ("N_1", "100"), {"id": "100"}),
    )
    resolver = ReferenceResolver(graph)
    resolver.record("grouppolicy", "100", "900", ("N_1",))
    resolver.record("vlan", "100", "100", ("N_1",))

    rewritten = rewrite_references(
        {"groupPolicyId": "100", "vlanId": "100"}, resolver, ("N_1", "0")
    )
    assert rewritten == {"groupPolicyId": "900", "vlanId": "100"}
    # A reference key naming no snapshot type cannot pick between the
    # two colliding mappings — never guess.
    with _pytest.raises(UnmappedReferenceError, match="ambiguous"):
        rewrite_references({"policyIds": ["100"]}, resolver, ("N_1", "0"))


def test_resolver_scopes_same_type_ids_by_parent_context() -> None:
    """Two networks both hold group policy 100; a referrer resolves the
    one under its own network, and a cross-parent reference refuses."""
    import pytest as _pytest

    from meraki2tf.restorer import (
        ReferenceResolver,
        UnmappedReferenceError,
        rewrite_references,
    )

    graph = _graph(
        FeatureConfiguration(GP_ITEM, ("N_1", "100"), {"name": "a"}),
        FeatureConfiguration(GP_ITEM, ("N_2", "100"), {"name": "b"}),
    )
    resolver = ReferenceResolver(graph)
    resolver.record("grouppolicy", "100", "900", ("N_1",))
    resolver.record("grouppolicy", "100", "901", ("N_2",))

    assert rewrite_references(
        {"groupPolicyId": "100"}, resolver, ("N_1", "0")
    ) == {"groupPolicyId": "900"}
    assert rewrite_references(
        {"groupPolicyId": "100"}, resolver, ("N_2", "0")
    ) == {"groupPolicyId": "901"}
    with _pytest.raises(UnmappedReferenceError):
        rewrite_references({"groupPolicyId": "100"}, resolver, ("N_3",))


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

    def __init__(
        self,
        calls: list,
        fail_ops: set[str] | None = None,
        responses: dict[str, dict] | None = None,
    ) -> None:
        self._calls = calls
        self._fail = fail_ops or set()
        self._responses = responses or {}

    def __getattr__(self, operation_id: str):  # noqa: ANN204
        def _dispatch(*args: object, **kwargs: object) -> dict:
            self._calls.append((operation_id, args, kwargs))
            if operation_id in self._fail:
                raise RuntimeError("simulated API failure")
            if operation_id in self._responses:
                return self._responses[operation_id]
            if operation_id == "createOrganizationNetwork":
                return {"id": "L_NEW"}
            if operation_id == "createNetworkGroupPolicy":
                return {"id": "900"}
            return {}

        return _dispatch


def _executor(
    tmp_path: Path,
    fail_ops: set[str] | None = None,
    responses: dict[str, dict] | None = None,
):
    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    calls: list = []
    restorer = OrgRestorer(
        "org-TARGET",
        RestoreJournal(tmp_path / "journal.jsonl"),
        serial_map={"Q2AB-CDEF-GHIJ": "Q9ZZ-NEWW-HWSN"},
    )
    section = _RecordingSection(calls, fail_ops, responses)
    restorer._client = __import__("types").SimpleNamespace(
        organizations=section, networks=section, wireless=section,
        switch=section, appliance=section,
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

    # Fresh executor, same journal: everything still present in the
    # target (the liveness probe finds the restored network), so the
    # resume skips every completed action without writing anything.
    from meraki2tf.restorer import OrgRestorer

    calls2: list = []
    section = _RecordingSection(
        calls2,
        responses={
            "getOrganizationNetworks": [{"id": "L_NEW", "name": "HQ"}],
        },
    )
    again = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "journal.jsonl")
    )
    again._client = __import__("types").SimpleNamespace(
        organizations=section, networks=section
    )
    second = again.execute(graph, plan)
    assert second.executed == ()
    # Probe reads only — no write (create/claim/update) was dispatched.
    assert {c[0] for c in calls2} <= {"getOrganizationNetworks"}
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


def test_resolver_edge_cases() -> None:
    import pytest as _pytest

    from meraki2tf.models import (
        MerakiDevice as _Device,
        MerakiNetwork as _Network,
        NetworkGraph as _NetworkGraph,
    )
    from meraki2tf.restorer import (
        ReferenceResolver,
        UnmappedReferenceError,
    )

    graph = _NetworkGraph(
        "org-123",
        (_Network("N_1", "org-123", "HQ", ()),),
        # Empty identifiers are ignored, not registered.
        (_Device("", "N_1", "MX68", "ghost"),),
        (FeatureConfiguration(VLAN_ITEM, ("N_1", "100"), {"id": "100"}),),
    )
    resolver = ReferenceResolver(graph)

    # Same stem, same old, two in-context targets: never guess.
    resolver.record("grouppolicy", "9", "900", ("N_1",))
    resolver.record("grouppolicy", "9", "901", ("N_1",))
    with _pytest.raises(UnmappedReferenceError, match="ambiguous"):
        resolver.resolve_reference("groupPolicyId", "9", ("N_1", "0"))

    # A create's own identity is never a dangling reference — scoped
    # (schema-kept VLAN id) and generic keys alike.
    assert resolver.resolve_reference(
        "vlanId", "100", ("N_1", "100"), exclude="100"
    ) == "100"
    assert resolver.resolve_reference(
        "id", "N_1", ("N_1",), exclude="N_1"
    ) == "N_1"

    # Known-but-unmapped IDs raise even under type-less reference keys.
    with _pytest.raises(UnmappedReferenceError, match="no rebuilt"):
        resolver.resolve_reference("someIds", "N_1", ())

    # Lenient path-parameter resolution: flat-unique wins (a config
    # template ID used as a {networkId} scope). An organization or
    # network scope with no mapping at all is refused outright — it can
    # only address a tenant location outside the snapshot.
    from meraki2tf.restorer import ForeignScopeError

    resolver.record("configtemplate", "T_1", "T_NEW", ())
    assert resolver.resolve_scope("networkId", "T_1", ("T_1",)) == "T_NEW"
    with _pytest.raises(ForeignScopeError, match="outside the rebuilt"):
        resolver.resolve_scope("networkId", "N_x", ("N_x",))
    with _pytest.raises(ForeignScopeError, match="outside the rebuilt"):
        resolver.resolve_scope("organizationId", "org-999", ())
    # Non-tenant scopes (fixed slots) still pass through.
    assert resolver.resolve_scope("wirelessProfileId", "7", ("N_1",)) == "7"

    # A declared-but-unmapped create identity must never pass through a
    # scope lookup — the snapshot ID would address the source tenant's
    # (possibly production) object. Both the typed and the flat lookup
    # fail loudly; blank identities are ignored.
    resolver.expect_remap("floorplan", "g_9")
    resolver.expect_remap("", "")
    with _pytest.raises(UnmappedReferenceError, match="no rebuilt"):
        resolver.resolve_scope("floorPlanId", "g_9", ("N_1", "g_9"))
    with _pytest.raises(UnmappedReferenceError, match="no rebuilt"):
        resolver.resolve_scope("networkId", "g_9", ("g_9",))
    # A fixed slot of the addressed type keeps its identity even when
    # a created object of another type collides on the bare value.
    resolver.expect_remap("grouppolicy", "100")
    assert resolver.resolve_scope("vlanId", "100", ("N_2", "100")) == "100"


def test_own_identity_covers_all_action_kinds(tmp_path: Path) -> None:
    from meraki2tf.restorer import _own_identity

    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(FeatureConfiguration(GP_ITEM, ("N_1", "100"), {"name": "x"})),
        parser,
    )
    by_kind = {action.kind: action for action in plan.actions}
    assert _own_identity(by_kind["create"]) == (
        ("network", "N_1")
        if by_kind["create"].wave == WAVE_NETWORKS
        else ("grouppolicy", "100")
    )
    assert _own_identity(by_kind["claim"]) == ("serial", "Q2AB-CDEF-GHIJ")
    gp = next(a for a in plan.actions if a.api_path == GP_ITEM)
    assert _own_identity(gp) == ("grouppolicy", "100")


def test_rewrite_reference_edges() -> None:
    from meraki2tf.models import NetworkGraph as _NetworkGraph
    from meraki2tf.restorer import ReferenceResolver, rewrite_references

    resolver = ReferenceResolver(
        _NetworkGraph("org-123", (), (), ())
    )
    # Non-string reference values (fixed-slot numbers) pass through.
    assert rewrite_references({"vlanId": 5}, resolver, ()) == {"vlanId": 5}
    # Non-string, non-reference scalars pass through untouched.
    assert rewrite_references({"count": 5}, resolver, ()) == {"count": 5}
    # Unknown GRP ids are data, not references.
    assert rewrite_references(
        {"rule": "allow GRP(999)"}, resolver, ()
    ) == {"rule": "allow GRP(999)"}


def test_journal_ignores_blank_lines(tmp_path: Path) -> None:
    from meraki2tf.restorer import RestoreJournal

    path = tmp_path / "j.jsonl"
    path.write_text('{"kind": "done", "key": "a"}\n\n', encoding="utf-8")
    assert RestoreJournal(path).completed == {"a"}


def test_executor_withholds_error_detail_for_pem_bearing_payloads(
    tmp_path: Path,
) -> None:
    """The sanitizer treats PEM private-key blocks as secrets by value
    (under non-secret keys like ``certificate``); a failed write whose
    payload carries one must withhold SDK error text — the echo could
    leak the key material into logs and alerts."""
    parser = _restore_spec(tmp_path)
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
    graph = _graph(
        FeatureConfiguration(
            SSID_ITEM, ("N_1", "0"),
            {"number": 0, "name": "Corp", "certificate": pem},
        ),
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
    )
    plan = plan_restore(graph, parser)
    restorer, _calls = _executor(
        tmp_path, fail_ops={"updateNetworkWirelessSsid", "updateNetworkSnmp"}
    )
    result = restorer.execute(graph, plan)

    reasons = dict(result.failed)
    ssid_reason = reasons[f"{SSID_ITEM}::N_1,0"]
    assert "detail withheld" in ssid_reason
    assert "simulated API failure" not in ssid_reason
    assert "PRIVATE KEY" not in ssid_reason
    # Secret-free payloads keep the actionable SDK error text.
    assert "simulated API failure" in reasons[f"{SNMP_PATH}::N_1"]


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


# ----------------------------------------------------- dispatch hardening


VLAN_COLLECTION = "/networks/{networkId}/appliance/vlans"
VLAN_ITEM = "/networks/{networkId}/appliance/vlans/{vlanId}"
STAGES_PATH = "/networks/{networkId}/firmwareUpgrades/staged/stages"


def _vlan_spec(tmp_path: Path) -> OpenApiParser:
    """Spec slice where a referrer sorts before its referent in-wave and
    the create schema declares the client-assigned ``id``."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "vlan", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            VLAN_COLLECTION: {
                "get": _op("getNetworkApplianceVlans", "appliance"),
                "post": {
                    **_op("createNetworkApplianceVlan", "appliance"),
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {
                                        "id": {"type": "string"},
                                        "name": {"type": "string"},
                                        "groupPolicyId": {"type": "string"},
                                    }
                                }
                            }
                        }
                    },
                },
            },
            VLAN_ITEM: {
                "get": _op("getNetworkApplianceVlan", "appliance"),
                "put": _op("updateNetworkApplianceVlan", "appliance"),
            },
            GP_COLLECTION: {
                "get": _op("getNetworkGroupPolicies", "networks"),
                "post": _op("createNetworkGroupPolicy", "networks"),
            },
            GP_ITEM: {
                "get": _op("getNetworkGroupPolicy", "networks"),
                "put": _op("updateNetworkGroupPolicy", "networks"),
            },
        },
    }
    path = tmp_path / "vlan-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def test_executor_defers_references_created_later_in_the_wave(
    tmp_path: Path,
) -> None:
    """Alphabetical wave order puts appliance VLANs before group
    policies; a VLAN carrying groupPolicyId must retry after the policy
    exists, not fail as an unmapped reference — and its client-assigned
    ``id`` (declared by the create schema) must survive the stale-ID
    strip."""
    parser = _vlan_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            VLAN_ITEM, ("N_1", "100"),
            {"id": "100", "name": "Data", "groupPolicyId": "101"},
        ),
        FeatureConfiguration(
            GP_ITEM, ("N_1", "101"),
            {"groupPolicyId": "101", "name": "kiosk"},
        ),
    )
    plan = plan_restore(graph, parser)
    ordered = [a.api_path for a in plan.actions if a.wave == WAVE_NETWORK_FEATURES]
    assert ordered.index(VLAN_ITEM) < ordered.index(GP_ITEM)  # the trap

    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    ops = [c[0] for c in calls]
    assert ops.index("createNetworkGroupPolicy") < ops.index(
        "createNetworkApplianceVlan"
    )
    vlan = next(c for c in calls if c[0] == "createNetworkApplianceVlan")
    assert vlan[2]["id"] == "100"  # schema-declared, required, kept
    assert vlan[2]["groupPolicyId"] == "900"  # remapped to the new GP


def test_dispatch_never_passes_path_params_as_body_kwargs(
    tmp_path: Path,
) -> None:
    """Payloads echo the snapshot tenant's identifiers (organizationId
    in networks, number in SSIDs); the real SDK methods take those as
    explicit positional parameters, so forwarding them as body kwargs
    raises 'got multiple values for argument'."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SSID_ITEM, ("N_1", "0"), {"number": 0, "name": "Corp"}
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class StrictSections:
        """SDK-faithful signatures: path params are named positionals."""

        def createOrganizationNetwork(
            self, organizationId: str, **kwargs: object
        ) -> dict:
            calls.append(("createOrganizationNetwork", organizationId, kwargs))
            return {"id": "L_NEW"}

        def claimNetworkDevices(
            self, networkId: str, **kwargs: object
        ) -> dict:
            calls.append(("claimNetworkDevices", networkId, kwargs))
            return {}

        def updateNetworkWirelessSsid(
            self, networkId: str, number: str, **kwargs: object
        ) -> dict:
            calls.append(("updateNetworkWirelessSsid", networkId, number, kwargs))
            return {}

    section = StrictSections()
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "strict.jsonl")
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    network = next(c for c in calls if c[0] == "createOrganizationNetwork")
    assert network[1] == "org-TARGET"
    assert "organizationId" not in network[2] and "id" not in network[2]
    ssid = next(c for c in calls if c[0] == "updateNetworkWirelessSsid")
    assert ssid[1:3] == ("L_NEW", "0")
    assert "number" not in ssid[3]


def test_dispatch_unwraps_collection_envelopes(tmp_path: Path) -> None:
    """Whole-collection {"items": [...]} payloads are discovery
    artifacts; the write body is the operation's sole array property,
    exactly like the gap replayer."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "stages", "version": "1"},
        "paths": {
            STAGES_PATH: {
                "get": _op("getNetworkFirmwareUpgradesStagedStages", "networks"),
                "put": {
                    **_op(
                        "updateNetworkFirmwareUpgradesStagedStages", "networks"
                    ),
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "properties": {"_json": {"type": "array"}}
                                }
                            }
                        }
                    },
                },
            },
        },
    }
    path = tmp_path / "stages-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            STAGES_PATH, ("N_1",),
            {"items": [{"group": {"id": "1"}}], "meta": {"counts": {}}},
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    stages = next(
        c for c in calls
        if c[0] == "updateNetworkFirmwareUpgradesStagedStages"
    )
    assert stages[2] == {"_json": [{"group": {"id": "1"}}]}


FIRMWARE_PATH = "/networks/{networkId}/firmwareUpgrades"


def _firmware_spec(tmp_path: Path) -> OpenApiParser:
    put = dict(_op("updateNetworkFirmwareUpgrades", "networks"))
    put["requestBody"] = {
        "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {
                "products": {}, "timezone": {},
                "participateInNextBetaRelease": {},
            },
        }}}
    }
    spec = {
        "openapi": "3.0.0", "info": {"title": "fw", "version": "1"},
        "paths": {
            FIRMWARE_PATH: {
                "get": _op("getNetworkFirmwareUpgrades", "networks"),
                "put": put,
            },
        },
    }
    path = tmp_path / "fw-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def _firmware_feature(to_version: dict) -> FeatureConfiguration:
    return FeatureConfiguration(
        FIRMWARE_PATH, ("N_1",),
        {
            "timezone": "US/Eastern",
            "participateInNextBetaRelease": False,
            "products": {"switch": {
                "availableVersions": [{"id": "6016", "shortName": "MS 17"}],
                "currentVersion": {"id": "6016", "shortName": "MS 17"},
                "lastUpgrade": {"time": "2026-06-01T00:00:00Z"},
                "nextUpgrade": {
                    "time": "2026-08-01T04:00:00Z", "toVersion": to_version,
                },
            }},
        },
    )


def test_firmware_next_upgrade_remaps_by_shortname(tmp_path: Path) -> None:
    """Firmware version IDs are org-local catalog rows: the snapshot's
    ID (or sanitized pseudonym) reaches the dashboard as version 0 and
    the whole PUT 400s. The pending upgrade must be re-keyed by
    shortName against the target network's own catalog."""
    parser = _firmware_spec(tmp_path)
    graph = _graph(
        _firmware_feature({"id": "id-0092", "shortName": "MS 17.2.1"})
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(
        tmp_path,
        responses={"getNetworkFirmwareUpgrades": {"products": {"switch": {
            "availableVersions": [
                {"id": 4242, "shortName": "MS 17.1"},
                {"id": 9999, "shortName": "MS 17.2.1"},
            ]
        }}}},
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    update = next(c for c in calls if c[0] == "updateNetworkFirmwareUpgrades")
    switch = update[2]["products"]["switch"]
    assert switch["nextUpgrade"]["toVersion"] == {"id": 9999}
    # read-only catalog/history subtrees never reach the PUT
    for noise in ("availableVersions", "currentVersion", "lastUpgrade"):
        assert noise not in switch
    assert update[2]["timezone"] == "US/Eastern"


def test_firmware_unmatchable_upgrade_drops_with_manual_pointer(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A device-less drill network offers no catalog at all: the pending
    upgrade is dropped (logged as a manual follow-up) so the remaining
    settings still restore instead of failing the whole surface."""
    parser = _firmware_spec(tmp_path)
    graph = _graph(
        _firmware_feature({"id": "id-0092", "shortName": "MS 17.2.1"})
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(
        tmp_path,
        responses={"getNetworkFirmwareUpgrades": {"products": {}}},
    )
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        result = restorer.execute(graph, plan)
    assert result.failed == ()
    update = next(c for c in calls if c[0] == "updateNetworkFirmwareUpgrades")
    assert "nextUpgrade" not in update[2]["products"]["switch"]
    assert update[2]["timezone"] == "US/Eastern"
    assert any(
        "re-schedule it manually" in r.getMessage() for r in caplog.records
    )


def test_empty_collections_plan_as_nothing_to_restore(tmp_path: Path) -> None:
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(FeatureConfiguration(GP_COLLECTION, ("N_1",), {"items": []})),
        parser,
    )
    (item,) = plan.unrestorable
    assert "empty at capture" in item.reason


def test_nested_redacted_secrets_become_reentry_pointers(
    tmp_path: Path,
) -> None:
    """Sanitized snapshots redact recursively (and PEM blocks under any
    key); the restore must strip those markers at any depth — writing
    the literal string as a live RADIUS secret would make a drill
    'pass' with garbage credentials."""
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"),
                {
                    "number": 0,
                    "name": "Corp",
                    "certificate": REDACTED,
                    "radiusServers": [{"host": "10.0.0.1", "secret": REDACTED}],
                },
            ),
        ),
        parser,
    )
    ssid = next(a for a in plan.actions if a.api_path == SSID_ITEM)
    assert ssid.secret_reentry == ("certificate", "radiusServers[].secret")
    assert "certificate" not in ssid.payload
    assert ssid.payload["radiusServers"] == [{"host": "10.0.0.1"}]


def test_serial_map_rewrites_embedded_serial_references(
    tmp_path: Path,
) -> None:
    """--serial-map must reach serials embedded in payloads (switch
    stacks and friends), not just the device-claim calls — serial keys
    never match the *Id reference grammar."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"access": "none", "serials": ["Q2AB-CDEF-GHIJ"],
             "users": [{"serial": "Q2AB-CDEF-GHIJ"}]},
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)  # maps Q2AB… → Q9ZZ-NEWW-HWSN
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    snmp = next(c for c in calls if c[0] == "updateNetworkSnmp")
    assert snmp[2]["serials"] == ["Q9ZZ-NEWW-HWSN"]
    assert snmp[2]["users"] == [{"serial": "Q9ZZ-NEWW-HWSN"}]


def test_drill_mode_skips_objects_referencing_production_serials(
    tmp_path: Path,
) -> None:
    """In a --skip-claims drill the hardware belongs to production; a
    network-wave object whose payload references those serials is a
    drill-skipped verdict, not a failure."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"access": "none", "serials": ["Q2AB-CDEF-GHIJ"]},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(calls)
    restorer = OrgRestorer(
        "org-TARGET",
        RestoreJournal(tmp_path / "drill2.jsonl"),
        skip_claims=True,
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    assert all(c[0] != "updateNetworkSnmp" for c in calls)
    assert any(
        "production hardware serial" in e["reason"] for e in result.skipped
    )


# ------------------------------------ cross-scope and claim regressions


PO_COLLECTION = "/organizations/{organizationId}/policyObjects"
PO_ITEM = "/organizations/{organizationId}/policyObjects/{policyObjectId}"
L3_RULES = "/networks/{networkId}/appliance/firewall/l3FirewallRules"
CT_COLLECTION = "/organizations/{organizationId}/configTemplates"
CT_ITEM = (
    "/organizations/{organizationId}/configTemplates/{configTemplateId}"
)
FP_COLLECTION = "/networks/{networkId}/floorPlans"
FP_ITEM = "/networks/{networkId}/floorPlans/{floorPlanId}"
STACK_COLLECTION = "/networks/{networkId}/switch/stacks"
STACK_ITEM = "/networks/{networkId}/switch/stacks/{switchStackId}"
STACK_IF_COLLECTION = (
    "/networks/{networkId}/switch/stacks/{switchStackId}/routing/interfaces"
)
STACK_IF_ITEM = STACK_IF_COLLECTION + "/{interfaceId}"


def _cross_scope_spec(tmp_path: Path) -> OpenApiParser:
    """Spec slice where org-scoped creates are referenced from network
    scope and hardware-adjacent objects hang off networks/devices."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "cross", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            PO_COLLECTION: {
                "get": _op("getOrganizationPolicyObjects", "organizations"),
                "post": _op(
                    "createOrganizationPolicyObject", "organizations"
                ),
            },
            PO_ITEM: {
                "get": _op("getOrganizationPolicyObject", "organizations"),
                "put": _op("updateOrganizationPolicyObject", "organizations"),
            },
            CT_COLLECTION: {
                "get": _op("getOrganizationConfigTemplates", "organizations"),
                "post": _op(
                    "createOrganizationConfigTemplate", "organizations"
                ),
            },
            CT_ITEM: {
                "get": _op("getOrganizationConfigTemplate", "organizations"),
                "put": _op(
                    "updateOrganizationConfigTemplate", "organizations"
                ),
            },
            L3_RULES: {
                "get": _op("getNetworkApplianceFirewallL3Rules", "appliance"),
                "put": _op(
                    "updateNetworkApplianceFirewallL3Rules", "appliance"
                ),
            },
            SNMP_PATH: {
                "get": _op("getNetworkSnmp", "networks"),
                "put": _op("updateNetworkSnmp", "networks"),
            },
            FP_COLLECTION: {
                "get": _op("getNetworkFloorPlans", "networks"),
                "post": _op("createNetworkFloorPlan", "networks"),
            },
            FP_ITEM: {
                "get": _op("getNetworkFloorPlan", "networks"),
                "put": _op("updateNetworkFloorPlan", "networks"),
            },
            PORT_ITEM: {
                "get": _op("getDeviceSwitchPort", "switch"),
                "put": _op("updateDeviceSwitchPort", "switch"),
            },
            STACK_COLLECTION: {
                "get": _op("getNetworkSwitchStacks", "switch"),
                "post": _op("createNetworkSwitchStack", "switch"),
            },
            STACK_ITEM: {
                "get": _op("getNetworkSwitchStack", "switch"),
            },
            STACK_IF_COLLECTION: {
                "get": _op("getStackRoutingInterfaces", "switch"),
                "post": _op("createStackRoutingInterface", "switch"),
            },
            STACK_IF_ITEM: {
                "get": _op("getStackRoutingInterface", "switch"),
                "put": _op("updateStackRoutingInterface", "switch"),
            },
        },
    }
    path = tmp_path / "cross-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def _template_graph() -> NetworkGraph:
    """A template-bound network plus a template-held feature (swept
    with the template ID as its ``{networkId}`` scope value)."""
    return NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"], "timeZone": "UTC",
                 "configTemplateId": "T_1"}
            ),
        ),
        devices=(),
        features=(
            FeatureConfiguration(
                CT_ITEM, ("org-123", "T_1"),
                {"id": "T_1", "name": "Branch Template",
                 "productTypes": ["appliance"]},
            ),
            FeatureConfiguration(
                SNMP_PATH, ("T_1",), {"access": "community"}
            ),
        ),
    )


def test_org_scoped_creates_resolve_from_network_scope(
    tmp_path: Path,
) -> None:
    """Policy objects are org-scoped; the GRP()/OBJ() grammar inside a
    network's firewall rules must resolve to the NEW id once the object
    is created (regression: the mapping context carried the source org
    ID, which no network-scoped referrer's path values ever contain)."""
    parser = _cross_scope_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            PO_ITEM, ("org-123", "42"),
            {"id": "42", "name": "web", "cidr": "203.0.113.0/24"},
        ),
        FeatureConfiguration(
            L3_RULES, ("N_1",),
            {"rules": [{"policy": "deny", "srcCidr": "OBJ(42)"}]},
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(
        tmp_path,
        responses={"createOrganizationPolicyObject": {"id": "9042"}},
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    rules = next(
        c for c in calls
        if c[0] == "updateNetworkApplianceFirewallL3Rules"
    )
    assert rules[1] == ("L_NEW",)
    assert rules[2]["rules"][0]["srcCidr"] == "OBJ(9042)"


def test_template_references_and_features_use_the_rebuilt_template(
    tmp_path: Path,
) -> None:
    """A bound network's ``configTemplateId`` and template-held features
    (addressed with the template ID as their ``{networkId}`` scope)
    must both follow the template's NEW server-assigned id."""
    parser = _cross_scope_spec(tmp_path)
    graph = _template_graph()
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(
        tmp_path,
        responses={"createOrganizationConfigTemplate": {"id": "T_NEW"}},
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    network = next(c for c in calls if c[0] == "createOrganizationNetwork")
    assert network[2]["configTemplateId"] == "T_NEW"
    snmp = next(c for c in calls if c[0] == "updateNetworkSnmp")
    assert snmp[1] == ("T_NEW",)  # never the snapshot's template ID


def test_template_features_fail_loudly_when_the_template_is_dead(
    tmp_path: Path,
) -> None:
    """When the template create fails, nothing may dispatch at the OLD
    template ID — against a still-live source org that ID addresses the
    production template. Loud failures, never silent passthrough."""
    parser = _cross_scope_spec(tmp_path)
    graph = _template_graph()
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(
        tmp_path, fail_ops={"createOrganizationConfigTemplate"}
    )
    result = restorer.execute(graph, plan)

    assert all(c[0] != "updateNetworkSnmp" for c in calls)
    assert all("T_1" not in c[1] for c in calls)
    reasons = dict(result.failed)
    assert "no rebuilt counterpart" in reasons[f"{SNMP_PATH}::T_1"]
    assert "no rebuilt counterpart" in reasons[
        "/organizations/{organizationId}/networks::N_1"
    ]


def test_claims_ignore_placement_references_in_the_device_payload(
    tmp_path: Path,
) -> None:
    """The claim body is only the serial; a ``floorPlanId`` in the
    device payload — whose floor plan even failed to restore — must not
    defer or fail the claim (regression: the payload was rewritten and
    then discarded)."""
    parser = _cross_scope_spec(tmp_path)
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["switch"], "timeZone": "UTC"}
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1",
                 "model": "MS120", "name": "sw1", "floorPlanId": "g_555"}
            ),
        ),
        features=(
            FeatureConfiguration(
                FP_ITEM, ("N_1", "g_555"),
                {"floorPlanId": "g_555", "name": "Floor 1"},
            ),
            FeatureConfiguration(
                PORT_ITEM, ("Q2AB-CDEF-GHIJ", "1"),
                {"portId": "1", "name": "uplink"},
            ),
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(
        tmp_path, fail_ops={"createNetworkFloorPlan"}
    )
    result = restorer.execute(graph, plan)

    claim = next(c for c in calls if c[0] == "claimNetworkDevices")
    assert claim[1] == ("L_NEW",)
    assert claim[2] == {"serials": ["Q9ZZ-NEWW-HWSN"]}
    # Only the floor plan failed; the claim and the port both landed.
    assert [key for key, _ in result.failed] == [f"{FP_ITEM}::N_1,g_555"]
    assert any(c[0] == "updateDeviceSwitchPort" for c in calls)


def test_device_features_gate_on_a_failed_claim(tmp_path: Path) -> None:
    """A failed claim leaves the hardware wherever it is currently
    claimed (possibly the production org): serial-addressed writes must
    be skipped and reported, never dispatched."""
    parser = _cross_scope_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            PORT_ITEM, ("Q2AB-CDEF-GHIJ", "1"),
            {"portId": "1", "name": "uplink"},
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path, fail_ops={"claimNetworkDevices"})
    result = restorer.execute(graph, plan)

    assert all(c[0] != "updateDeviceSwitchPort" for c in calls)
    assert [key for key, _ in result.failed] == [
        "/networks/{networkId}/devices/claim::N_1,Q2AB-CDEF-GHIJ"
    ]
    assert any(
        "parent object Q2AB-CDEF-GHIJ failed" in e["reason"]
        for e in result.skipped
    )


def test_device_features_wait_for_a_deferred_claim(tmp_path: Path) -> None:
    """A claim that cannot dispatch yet (its network defers a round)
    holds the device's serial-addressed features back with it, instead
    of letting them fire at unclaimed (or production-claimed)
    hardware."""
    parser = _cross_scope_spec(tmp_path)
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["switch"], "timeZone": "UTC",
                 # N_1 sorts before its referent, so it defers a round.
                 "copyFromNetworkId": "N_2"}
            ),
            MerakiNetwork.from_payload(
                {"id": "N_2", "organizationId": "org-123", "name": "Lab",
                 "productTypes": ["switch"], "timeZone": "UTC"}
            ),
        ),
        devices=(
            MerakiDevice.from_payload(
                {"serial": "Q2AB-CDEF-GHIJ", "networkId": "N_1",
                 "model": "MS120", "name": "sw1"}
            ),
        ),
        features=(
            FeatureConfiguration(
                PORT_ITEM, ("Q2AB-CDEF-GHIJ", "1"),
                {"portId": "1", "name": "uplink"},
            ),
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    ops = [c[0] for c in calls]
    assert ops.count("createOrganizationNetwork") == 2
    # Without the wait, the port fires in round 1 — before the claim.
    assert ops.index("claimNetworkDevices") < ops.index(
        "updateDeviceSwitchPort"
    )


def test_drill_children_of_skipped_parents_are_drill_verdicts(
    tmp_path: Path,
) -> None:
    """A drill-skipped switch stack takes its nested children with it:
    drill verdicts, never failures fired at the old stack ID."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _cross_scope_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            STACK_ITEM, ("N_1", "stack_1"),
            {"id": "stack_1", "name": "core",
             "serials": ["Q2AB-CDEF-GHIJ"]},
        ),
        FeatureConfiguration(
            STACK_IF_ITEM, ("N_1", "stack_1", "if_9"),
            {"interfaceId": "if_9", "name": "vlan10", "vlanId": 10},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(calls)
    restorer = OrgRestorer(
        "org-TARGET",
        RestoreJournal(tmp_path / "drill3.jsonl"),
        skip_claims=True,
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, switch=section
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    ops = [c[0] for c in calls]
    assert "createNetworkSwitchStack" not in ops
    assert "createStackRoutingInterface" not in ops
    assert any(
        "parent object stack_1 was skipped" in e["reason"]
        for e in result.skipped
    )


def test_references_serials_checks_path_values_and_empty_sets() -> None:
    from meraki2tf.restorer import RestoreAction, _references_serials
    from meraki2tf.spec.engine import OperationSpec

    op = OperationSpec(
        operation_id="updateNetworkSnmp",
        method="put",
        path=SNMP_PATH,
        path_params=("networkId",),
        tags=("networks",),
    )
    action = RestoreAction(
        kind="configure", wave=4, api_path=SNMP_PATH,
        path_values=("Q2AB-CDEF-GHIJ",), operation=op,
    )
    assert _references_serials(action, frozenset()) is False
    assert _references_serials(action, frozenset({"Q2AB-CDEF-GHIJ"})) is True


def test_attempted_creates_reconcile_by_name_instead_of_duplicating(
    tmp_path: Path,
) -> None:
    """A crash between the API create and the journal append leaves an
    attempted-but-not-done key; the resume must adopt the existing
    object by name, not re-POST it (a duplicate network name 400 would
    skip every child of the network)."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}))
    plan = plan_restore(graph, parser)
    network_key = "/organizations/{organizationId}/networks::N_1"

    journal = RestoreJournal(tmp_path / "crashed.jsonl")
    journal.bind(target="org-TARGET", source="org-123")
    journal.record_attempt(network_key)  # the crashed run got this far

    calls: list = []

    class AdoptingSection(_RecordingSection):
        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list[dict]:
            self._calls.append(("getOrganizationNetworks", (organizationId,), {}))
            return [
                {"id": "L_EXIST", "name": "HQ"},
                {"id": "L_OTHER", "name": "Branch"},
            ]

    section = AdoptingSection(calls)
    restorer = OrgRestorer("org-TARGET", RestoreJournal(tmp_path / "crashed.jsonl"))
    restorer._client = SimpleNamespace(organizations=section, networks=section)
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    ops = [c[0] for c in calls]
    assert "createOrganizationNetwork" not in ops  # adopted, not re-created
    assert "getOrganizationNetworks" in ops
    # Children run against the adopted network's real ID.
    claim = next(c for c in calls if c[0] == "claimNetworkDevices")
    assert claim[1] == ("L_EXIST",)
    snmp = next(c for c in calls if c[0] == "updateNetworkSnmp")
    assert snmp[1] == ("L_EXIST",)
    assert network_key in result.executed


def test_unattempted_creates_never_pay_the_recovery_lookup(
    tmp_path: Path,
) -> None:
    """A clean run must not read collections back before every create —
    the write-ahead attempt record is what marks the crash window."""
    parser = _restore_spec(tmp_path)
    graph = _graph()
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    restorer.execute(graph, plan)

    ops = [c[0] for c in calls]
    assert "getOrganizationNetworks" not in ops
    assert "createOrganizationNetwork" in ops
    # The journal write-ahead is on disk: attempt precedes done.
    lines = [
        json.loads(line)
        for line in (tmp_path / "journal.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]
    kinds = [record["kind"] for record in lines]
    assert kinds.index("attempt") < kinds.index("done")


def test_recovery_lookup_edge_branches(tmp_path: Path) -> None:
    from types import SimpleNamespace

    from meraki2tf.models import NetworkGraph as _NetworkGraph
    from meraki2tf.restorer import (
        OrgRestorer,
        ReferenceResolver,
        RestoreAction,
        RestoreJournal,
    )
    from meraki2tf.spec.engine import OperationSpec

    resolver = ReferenceResolver(_NetworkGraph("org-123", (), (), ()))
    # Tenant scopes never pass through unmapped; the lookup's network
    # scope must resolve to a rebuilt counterpart.
    resolver.record("network", "N_1", "N_LIVE", ())
    restorer = OrgRestorer("org-TARGET", RestoreJournal(tmp_path / "e.jsonl"))
    lookup = OperationSpec(
        operation_id="getNetworkGroupPolicies",
        method="get",
        path=GP_COLLECTION,
        path_params=("networkId",),
        tags=("networks",),
    )

    def action(**overrides: object) -> RestoreAction:
        values = dict(
            kind="create", wave=4, api_path=GP_ITEM,
            path_values=("N_1", "100"), operation=lookup,
            payload={"name": "kiosk"}, lookup=lookup,
        )
        values.update(overrides)
        return RestoreAction(**values)  # type: ignore[arg-type]

    dashboard = SimpleNamespace()

    # No lookup op / no usable name → straight to the POST.
    assert restorer._reconcile_existing(
        dashboard, action(lookup=None), resolver, "org-123"
    ) is None
    assert restorer._reconcile_existing(
        dashboard, action(payload={}), resolver, "org-123"
    ) is None
    # SDK without the lookup method → straight to the POST.
    assert restorer._reconcile_existing(
        dashboard, action(), resolver, "org-123"
    ) is None

    class Sections:
        def getNetworkGroupPolicies(self, networkId: str) -> object:
            raise RuntimeError("boom")

    # Unreadable collection → straight to the POST.
    assert restorer._reconcile_existing(
        SimpleNamespace(networks=Sections()), action(), resolver, "org-123"
    ) is None

    class EnvelopeSections:
        def getNetworkGroupPolicies(self, networkId: str) -> dict:
            return {"items": [{"name": "kiosk", "groupPolicyId": "900",
                               "id": "900"}]}

    # Envelope listings unwrap; a unique name match adopts.
    assert restorer._reconcile_existing(
        SimpleNamespace(networks=EnvelopeSections()), action(),
        resolver, "org-123",
    ) == "900"


def test_recovery_lookup_falls_back_to_the_create(tmp_path: Path) -> None:
    """No unique name match (or an unreadable collection) proceeds with
    the POST — worst case the API rejects one duplicate, as before."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph()
    plan = plan_restore(graph, parser)
    network_key = "/organizations/{organizationId}/networks::N_1"

    journal = RestoreJournal(tmp_path / "nomatch.jsonl")
    journal.bind(target="org-TARGET", source="org-123")
    journal.record_attempt(network_key)

    calls: list = []

    class NoMatchSection(_RecordingSection):
        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list[dict]:
            return []  # the crashed create never landed

    section = NoMatchSection(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "nomatch.jsonl")
    )
    restorer._client = SimpleNamespace(organizations=section, networks=section)
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    assert "createOrganizationNetwork" in [c[0] for c in calls]


# ------------------------------------------------------------- journal


def test_journal_binds_to_one_target_and_source(tmp_path: Path) -> None:
    """Resuming a journal against a different target would skip every
    create and write the configure actions into the previous target."""
    import pytest as _pytest

    from meraki2tf.restorer import (
        RestoreJournal,
        RestoreJournalMismatchError,
    )

    path = tmp_path / "bound.jsonl"
    RestoreJournal(path).bind(target="org-A", source="org-123")
    RestoreJournal(path).bind(target="org-A", source="org-123")  # resume: ok
    with _pytest.raises(RestoreJournalMismatchError, match="refusing"):
        RestoreJournal(path).bind(target="org-B", source="org-123")
    with _pytest.raises(RestoreJournalMismatchError, match="refusing"):
        RestoreJournal(path).bind(target="org-A", source="org-456")


def test_journal_with_records_but_no_meta_is_refused(tmp_path: Path) -> None:
    """A journal from a version predating target/source binding carries
    done/map lines but no meta; adopting it would replay another
    restore's skips and mappings against this target."""
    import pytest as _pytest

    from meraki2tf.restorer import RestoreJournal, RestoreJournalMismatchError

    legacy = tmp_path / "legacy.jsonl"
    legacy.write_text(
        '{"kind": "done", "key": "/organizations/{organizationId}/networks::N_1"}\n'
        '{"kind": "map", "old": "N_1", "new": "L_OLD"}\n',
        encoding="utf-8",
    )
    with _pytest.raises(RestoreJournalMismatchError, match="no target/source"):
        RestoreJournal(legacy).bind(target="org-A", source="org-123")


def test_journal_tolerates_a_torn_final_line_only(tmp_path: Path) -> None:
    import pytest as _pytest

    torn = tmp_path / "torn.jsonl"
    torn.write_text(
        '{"kind": "done", "key": "a"}\n{"kind": "ma', encoding="utf-8"
    )
    from meraki2tf.restorer import RestoreJournal

    journal = RestoreJournal(torn)
    assert journal.completed == {"a"}  # the torn tail is dropped

    corrupt = tmp_path / "corrupt.jsonl"
    corrupt.write_text(
        '{"kind": "ma\n{"kind": "done", "key": "a"}\n', encoding="utf-8"
    )
    with _pytest.raises(json.JSONDecodeError):
        RestoreJournal(corrupt)  # mid-file corruption still refuses


def test_journal_truncates_the_torn_tail_so_appends_stay_parseable(
    tmp_path: Path,
) -> None:
    """A tolerated torn line must also be removed: the resumed run's
    first append would otherwise concatenate onto the fragment,
    producing a mid-file unparseable line that strands the third run."""
    from meraki2tf.restorer import RestoreJournal

    path = tmp_path / "torn-append.jsonl"
    journal = RestoreJournal(path)
    journal.record_done("a::1")
    intact = path.read_text(encoding="utf-8")
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"kind": "ma')  # the process died mid-append

    resumed = RestoreJournal(path)  # tolerated — and truncated away
    assert resumed.completed == {"a::1"}
    assert path.read_text(encoding="utf-8") == intact
    assert oct(path.stat().st_mode & 0o777) == "0o600"

    resumed.record_done("b::2")
    third = RestoreJournal(path)  # every line parses again
    assert third.completed == {"a::1", "b::2"}


def test_journal_truncates_a_torn_only_line_to_empty(tmp_path: Path) -> None:
    from meraki2tf.restorer import RestoreJournal

    path = tmp_path / "torn-only.jsonl"
    path.write_text('{"kind": "ma', encoding="utf-8")
    journal = RestoreJournal(path)
    assert journal.completed == set()
    assert path.read_text(encoding="utf-8") == ""
    journal.record_done("a::1")
    assert RestoreJournal(path).completed == {"a::1"}


# ------------------------------------------------------------------- wipe


def _wipe_dashboard(
    devices: int = 0,
    networks: int = 2,
    name: str = "Drill Org",
    inventory: int = 0,
):
    from types import SimpleNamespace

    deleted: dict[str, list] = {"networks": [], "orgs": []}

    class Organizations:
        def getOrganization(self, organizationId: str) -> dict:
            return {"id": organizationId, "name": name}

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return [{"serial": f"Q{i}"} for i in range(devices)]

        def getOrganizationInventoryDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return [{"serial": f"QI{i}"} for i in range(inventory)]

        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return [{"id": f"L_{i}"} for i in range(networks)]

        def deleteOrganization(self, organizationId: str) -> dict:
            deleted["orgs"].append(organizationId)
            return {}

    class Networks:
        def deleteNetwork(self, networkId: str) -> dict:
            deleted["networks"].append(networkId)
            return {}

    return (
        SimpleNamespace(organizations=Organizations(), networks=Networks()),
        deleted,
    )


def test_wipe_refuses_orgs_with_claimed_devices() -> None:
    import pytest as _pytest

    from meraki2tf.restorer import OrgWiper, WipeRefusedError

    wiper = OrgWiper()
    wiper._client, _ = _wipe_dashboard(devices=3)
    with _pytest.raises(WipeRefusedError, match="claimed device"):
        wiper.preview("org-drill", "Drill Org")


def test_wipe_refuses_orgs_with_inventory_only_claims() -> None:
    """Hardware claimed into the inventory but not yet assigned to a
    network is invisible to /organizations/{id}/devices — the interlock
    must consult the inventory too, or a production org whose devices
    are staged-but-unassigned would pass the hardware check."""
    import pytest as _pytest

    from meraki2tf.restorer import OrgWiper, WipeRefusedError

    wiper = OrgWiper()
    wiper._client, _ = _wipe_dashboard(devices=0, inventory=2)
    with _pytest.raises(WipeRefusedError, match="claimed device"):
        wiper.preview("org-drill", "Drill Org")


def test_wipe_fails_closed_without_the_inventory_endpoint() -> None:
    """An SDK that cannot answer the inventory question refuses the
    wipe instead of proceeding on partial evidence."""
    import pytest as _pytest

    from meraki2tf.restorer import OrgWiper, WipeRefusedError

    wiper = OrgWiper()
    dashboard, _ = _wipe_dashboard()
    del dashboard.organizations.__class__.getOrganizationInventoryDevices
    wiper._client = dashboard
    with _pytest.raises(WipeRefusedError, match="inventory"):
        wiper.preview("org-drill", "Drill Org")


def test_wipe_refuses_name_mismatch() -> None:
    import pytest as _pytest

    from meraki2tf.restorer import OrgWiper, WipeRefusedError

    wiper = OrgWiper()
    wiper._client, _ = _wipe_dashboard()
    with _pytest.raises(WipeRefusedError, match="does not match"):
        wiper.preview("org-drill", "Production Org")


def test_wipe_executes_networks_then_organization() -> None:
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, deleted = _wipe_dashboard(networks=3)
    result = wiper.execute("org-drill", "Drill Org")
    assert result.deleted_networks == ("L_0", "L_1", "L_2")
    assert result.organization_deleted is True
    assert deleted["orgs"] == ["org-drill"]
    assert result.failed == ()


def test_wipe_keeps_the_org_when_a_network_fails() -> None:
    """A partial wipe never deletes the organization out from under
    whatever refused to delete — the operator investigates first."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    dashboard, deleted = _wipe_dashboard(networks=2)

    def explode(networkId: str) -> dict:
        raise RuntimeError("network is bound to a template")

    dashboard.networks = SimpleNamespace(deleteNetwork=explode)
    wiper._client = dashboard
    result = wiper.execute("org-drill", "Drill Org")
    assert result.organization_deleted is False
    assert len(result.failed) == 2
    assert deleted["orgs"] == []


def test_wipe_reports_organization_delete_failure() -> None:
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    dashboard, deleted = _wipe_dashboard(networks=0)

    def explode(organizationId: str) -> dict:
        raise RuntimeError("org has pending licenses")

    dashboard.organizations.deleteOrganization = explode
    wiper._client = dashboard
    result = wiper.execute("org-drill", "Drill Org")
    assert result.organization_deleted is False
    assert result.failed == (("org-drill", "org has pending licenses"),)


def test_empty_default_configures_skip_instead_of_dispatching(
    tmp_path: Path,
) -> None:
    """The vpnExclusions shape observed live: nothing but empty
    containers plus the aggregation row's scope-name echo. The PUT
    restores configuration that does not exist and 400s on orgs
    lacking the endpoint's prerequisites — skip, distinctly."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH,
            ("N_1",),
            {
                "networkName": "HQ - appliance",
                "custom": [],
                "majorApplications": [],
                "detail": None,
            },
        )
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert not [c for c in calls if c[0] == "updateNetworkSnmp"]
    (skip,) = [
        entry
        for entry in result.skipped
        if entry["target"].startswith(SNMP_PATH)
    ]
    assert skip["reason"] == (
        "empty default configuration — nothing to restore"
    )


def test_false_zero_and_empty_string_configures_still_dispatch(
    tmp_path: Path,
) -> None:
    """Conservative emptiness: false/0/"" are real configuration (a
    deliberately disabled feature is not an empty default), so the
    write must go out."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH,
            ("N_1",),
            {
                "networkName": "HQ - appliance",
                "custom": [],
                "enabled": False,
                "port": 0,
                "comment": "",
            },
        )
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    (snmp,) = [c for c in calls if c[0] == "updateNetworkSnmp"]
    assert snmp[2]["enabled"] is False
    assert snmp[2]["port"] == 0
    assert snmp[2]["comment"] == ""
    assert not [
        entry
        for entry in result.skipped
        if entry["target"].startswith(SNMP_PATH)
    ]


def test_drill_secret_placeholders_fill_redacted_slots(tmp_path: Path) -> None:
    """A sanitized-snapshot drill substitutes valid placeholder secrets
    so secret-requiring writes rehearse instead of failing ('Password
    is required to enable WPA encryption')."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"access": "community", "communityString": REDACTED},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section,
        switch=section, appliance=section,
    )
    result = restorer.execute(graph, plan)

    snmp = next(c for c in calls if c[0] == "updateNetworkSnmp")
    placeholder = snmp[2]["communityString"]
    assert placeholder.startswith("drill-") and len(placeholder) >= 8
    assert result.drill_placeholders == (
        (f"{SNMP_PATH}::N_1", "communityString"),
    )
    # Resumed drills stay idempotent: the placeholder is deterministic.
    from meraki2tf.restorer import _inject_drill_secrets

    again, _ = _inject_drill_secrets(
        {"access": "community"}, ("communityString",), f"{SNMP_PATH}::N_1"
    )
    assert again["communityString"] == placeholder


def test_real_restores_never_inject_placeholders(tmp_path: Path) -> None:
    """Unsanitized payload secrets pass through untouched, and without
    --skip-claims nothing is substituted at all."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"access": "community", "communityString": "real-value"},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(calls)
    restorer = OrgRestorer("org-TARGET", RestoreJournal(tmp_path / "j.jsonl"))
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section,
        switch=section, appliance=section,
    )
    result = restorer.execute(graph, plan)
    snmp = next(c for c in calls if c[0] == "updateNetworkSnmp")
    assert snmp[2]["communityString"] == "real-value"
    assert result.drill_placeholders == ()


def test_inject_drill_secrets_handles_nesting_and_list_slots() -> None:
    from meraki2tf.restorer import _inject_drill_secrets

    payload = {
        "radius": {"host": "10.0.0.1"},
        "servers": [{"a": 1}, {"a": 2}],
    }
    filled, injected = _inject_drill_secrets(
        payload,
        ("radius.secret", "servers[].secret", "missing.parent.secret"),
        "seed",
    )
    assert injected == ("radius.secret", "servers[].secret")
    assert filled["radius"]["secret"].startswith("drill-")
    assert payload["radius"] == {"host": "10.0.0.1"}  # input untouched
    assert payload["servers"] == [{"a": 1}, {"a": 2}]  # input untouched
    # List slots fan out: every element gets a DISTINCT deterministic
    # placeholder (a RADIUS SSID carries one secret per server).
    first, second = (server["secret"] for server in filled["servers"])
    assert first.startswith("drill-") and second.startswith("drill-")
    assert first != second
    refill, _ = _inject_drill_secrets(
        payload,
        ("radius.secret", "servers[].secret", "missing.parent.secret"),
        "seed",
    )
    assert refill == filled  # deterministic across resumed drills


def test_serial_schema_configures_are_drill_skipped(tmp_path: Path) -> None:
    """A write schema that binds to device serials (warm spare's
    spareSerial) cannot apply on a hardware-free drill org: drill-skip
    verdict, never a failure."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    warm_path = "/networks/{networkId}/appliance/warmSpare"
    op = dict(_op("updateNetworkApplianceWarmSpare", "appliance"))
    op["requestBody"] = {
        "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {"enabled": {}, "spareSerial": {}},
        }}}
    }
    spec = {
        "openapi": "3.0.0", "info": {"title": "w", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            warm_path: {
                "get": _op("getNetworkApplianceWarmSpare", "appliance"),
                "put": op,
            },
        },
    }
    path = tmp_path / "warm-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(warm_path, ("N_1",), {"enabled": False})
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, appliance=section,
    )
    result = restorer.execute(graph, plan)
    assert "updateNetworkApplianceWarmSpare" not in [c[0] for c in calls]
    assert result.failed == ()
    assert any(
        "write schema binds this feature to device serials" in e["reason"]
        for e in result.skipped
    )


def test_disabled_features_retry_with_minimal_payload(tmp_path: Path) -> None:
    """GET echoes of disabled features carry skeletons their PUT
    rejects (OSPF: 'There must be at least one area defined'); the
    disabled bit alone restores the actual state."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    class Rejecting400(Exception):
        status = 400

    calls: list = []

    class OspfSection(_RecordingSection):
        def updateNetworkSwitchRoutingOspf(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSwitchRoutingOspf", args, kwargs))
            if set(kwargs) != {"enabled"}:
                raise Rejecting400("There must be at least one area defined.")
            return {}

    ospf_path = "/networks/{networkId}/switch/routing/ospf"
    spec = {
        "openapi": "3.0.0", "info": {"title": "o", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            ospf_path: {
                "get": _op("getNetworkSwitchRoutingOspf", "switch"),
                "put": _op("updateNetworkSwitchRoutingOspf", "switch"),
            },
        },
    }
    path = tmp_path / "ospf-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            ospf_path, ("N_1",),
            {"enabled": False, "areas": [], "helloTimerInSeconds": 10},
        )
    )
    plan = plan_restore(graph, parser)
    section = OspfSection(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, switch=section,
    )
    result = restorer.execute(graph, plan)
    ospf_calls = [c for c in calls if c[0] == "updateNetworkSwitchRoutingOspf"]
    assert len(ospf_calls) == 2  # full payload, then the minimal retry
    assert ospf_calls[1][2] == {"enabled": False}
    assert result.failed == ()
    assert f"{ospf_path}::N_1" in result.executed


def _conflict_error(message: str) -> Exception:
    class Conflict400(Exception):
        status = 400

    return Conflict400(message)


def test_conflicted_create_adopts_client_assigned_slot(tmp_path: Path) -> None:
    """VLAN 1 exists in every new appliance network; the captured
    VLAN's create collides ('Vlan has already been taken') and must
    adopt the slot by its client-assigned ID, then align content."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    vlan_collection = "/networks/{networkId}/appliance/vlans"
    vlan_item = "/networks/{networkId}/appliance/vlans/{vlanId}"
    create_op = dict(_op("createNetworkApplianceVlan", "appliance"))
    create_op["requestBody"] = {
        "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {"id": {}, "name": {}, "subnet": {}},
        }}}
    }
    spec = {
        "openapi": "3.0.0", "info": {"title": "v", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            vlan_collection: {
                "get": _op("getNetworkApplianceVlans", "appliance"),
                "post": create_op,
            },
            vlan_item: {
                "get": _op("getNetworkApplianceVlan", "appliance"),
                "put": _op("updateNetworkApplianceVlan", "appliance"),
            },
        },
    }
    path = tmp_path / "vlan-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            vlan_item, ("N_1", "1"),
            {"id": "1", "name": "Default", "subnet": "10.0.0.0/24"},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def createNetworkApplianceVlan(self, *args, **kwargs) -> dict:
            self._calls.append(("createNetworkApplianceVlan", args, kwargs))
            raise _conflict_error("Vlan has already been taken")

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, appliance=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert f"{vlan_item}::N_1,1" in result.executed
    # The adopted slot's content was aligned via the item PUT.
    aligned = next(c for c in calls if c[0] == "updateNetworkApplianceVlan")
    assert aligned[2]["subnet"] == "10.0.0.0/24"


def test_conflicted_create_adopts_reserved_default_by_name(
    tmp_path: Path,
) -> None:
    """Meraki-provisioned defaults (payload templates, RF profiles)
    reject the captured copy's create by name; adopt by name and align."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            GP_ITEM, ("N_1", "100"), {"groupPolicyId": "100", "name": "gp"}
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def createNetworkGroupPolicy(self, *args, **kwargs) -> dict:
            self._calls.append(("createNetworkGroupPolicy", args, kwargs))
            raise _conflict_error("'gp' is a reserved name and cannot be used")

        def getNetworkGroupPolicies(self, networkId: str) -> list[dict]:
            self._calls.append(("getNetworkGroupPolicies", (networkId,), {}))
            return [{"groupPolicyId": "901", "name": "gp"}]

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    aligned = next(c for c in calls if c[0] == "updateNetworkGroupPolicy")
    assert aligned[1][1] == "901"  # PUT targets the adopted counterpart


def test_mutual_reference_deadlock_converges_by_dropping_one_side(
    tmp_path: Path,
) -> None:
    """A policy object referencing its group while the group references
    the object deadlocks the wave loop; the drop-retry round must
    settle both, re-establishing the link from the surviving side."""
    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    po_collection = "/organizations/{organizationId}/policyObjects"
    po_item = "/organizations/{organizationId}/policyObjects/{policyObjectId}"
    grp_collection = "/organizations/{organizationId}/policyObjects/groups"
    grp_item = (
        "/organizations/{organizationId}/policyObjects/groups"
        "/{policyObjectGroupId}"
    )
    spec = {
        "openapi": "3.0.0", "info": {"title": "p", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            po_collection: {
                "get": _op("getOrganizationPolicyObjects", "organizations"),
                "post": _op("createOrganizationPolicyObject", "organizations"),
            },
            po_item: {
                "get": _op("getOrganizationPolicyObject", "organizations"),
                "put": _op("updateOrganizationPolicyObject", "organizations"),
            },
            grp_collection: {
                "get": _op(
                    "getOrganizationPolicyObjectsGroups", "organizations"
                ),
                "post": _op(
                    "createOrganizationPolicyObjectsGroup", "organizations"
                ),
            },
            grp_item: {
                "get": _op(
                    "getOrganizationPolicyObjectsGroup", "organizations"
                ),
                "put": _op(
                    "updateOrganizationPolicyObjectsGroup", "organizations"
                ),
            },
        },
    }
    path = tmp_path / "po-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(),
        devices=(),
        features=(
            FeatureConfiguration(
                po_item, ("org-123", "5001"),
                {"id": "5001", "name": "po-a", "groupIds": ["6001"]},
            ),
            FeatureConfiguration(
                grp_item, ("org-123", "6001"),
                {"id": "6001", "name": "grp-a", "objectIds": ["5001"]},
            ),
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(
        calls,
        responses={
            "createOrganizationPolicyObject": {"id": "9001"},
            "createOrganizationPolicyObjectsGroup": {"id": "9002"},
        },
    )
    from types import SimpleNamespace as NS

    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    restorer._client = NS(organizations=section, networks=section)
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert len(result.executed) == 2
    po = next(c for c in calls if c[0] == "createOrganizationPolicyObject")
    grp = next(
        c for c in calls if c[0] == "createOrganizationPolicyObjectsGroup"
    )
    # One side dropped its membership list to break the deadlock; the
    # other carries the remapped reference, restoring the link.
    po_refs = po[2].get("groupIds")
    grp_refs = grp[2].get("objectIds")
    assert (po_refs is None and grp_refs == ["9001"]) or (
        grp_refs is None and po_refs == ["9002"]
    )


def test_refused_disabled_state_downgrades_to_skip(tmp_path: Path) -> None:
    """When even {enabled: false} is refused (alternate management
    interface), the feature's disabled state is a fresh network's
    default — a skip verdict, not a failure."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    ami_path = "/networks/{networkId}/switch/alternateManagementInterface"
    spec = {
        "openapi": "3.0.0", "info": {"title": "a", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            ami_path: {
                "get": _op(
                    "getNetworkSwitchAlternateManagementInterface", "switch"
                ),
                "put": _op(
                    "updateNetworkSwitchAlternateManagementInterface",
                    "switch",
                ),
            },
        },
    }
    path = tmp_path / "ami-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            ami_path, ("N_1",),
            {"enabled": False, "protocols": [], "switches": []},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSwitchAlternateManagementInterface(
            self, *args, **kwargs
        ) -> dict:
            self._calls.append(("ami", args, kwargs))
            raise _conflict_error("Vlan can't be blank")

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, switch=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert any(
        "already disabled by default" in entry["reason"]
        for entry in result.skipped
    )
    assert len([c for c in calls if c[0] == "ami"]) == 2  # full + minimal


def test_capability_400_is_drill_skipped_under_skip_claims(
    tmp_path: Path,
) -> None:
    """'This endpoint only supports organizations with MX networks' is
    inevitable on a device-free drill org: drill-skip, not failure."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"})
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            raise _conflict_error(
                "This endpoint only supports organizations with MX networks"
            )

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert any("drill:" in entry["reason"] for entry in result.skipped)


def test_create_ids_extracted_via_the_item_placeholder(tmp_path: Path) -> None:
    """Create responses key their identity per collection ('groupId',
    'payloadTemplateId', …); the mapping must still be recorded or every
    child referencing the object fails on dead snapshot IDs."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            GP_ITEM, ("N_1", "100"), {"groupPolicyId": "100", "name": "gp"}
        ),
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"access": "none", "groupPolicyId": "100"},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(
        calls,
        responses={"createNetworkGroupPolicy": {"groupPolicyId": "955"}},
    )
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    snmp = next(c for c in calls if c[0] == "updateNetworkSnmp")
    assert snmp[2]["groupPolicyId"] == "955"  # remapped via 'groupPolicyId' key


def test_bare_disabled_payload_refusal_skips(tmp_path: Path) -> None:
    """A payload that already IS the bare disabled bit has nothing to
    trim; if the dashboard refuses it, disabled is the rebuilt default."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    ami_path = "/networks/{networkId}/switch/alternateManagementInterface"
    spec = {
        "openapi": "3.0.0", "info": {"title": "a2", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            ami_path: {
                "get": _op(
                    "getNetworkSwitchAlternateManagementInterface", "switch"
                ),
                "put": _op(
                    "updateNetworkSwitchAlternateManagementInterface",
                    "switch",
                ),
            },
        },
    }
    path = tmp_path / "ami2-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(FeatureConfiguration(ami_path, ("N_1",), {"enabled": False}))
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSwitchAlternateManagementInterface(
            self, *args, **kwargs
        ) -> dict:
            self._calls.append(("ami", args, kwargs))
            raise _conflict_error("Vlan can't be blank")

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, switch=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert any(
        "already disabled by default" in entry["reason"]
        for entry in result.skipped
    )
    assert len([c for c in calls if c[0] == "ami"]) == 1  # no pointless retry


def test_nested_bare_id_references_are_remapped(tmp_path: Path) -> None:
    """Staged-upgrade stages reference their groups as {'group': {'id':
    ...}} — a bare nested 'id' key that must remap or the write fires
    at dead snapshot IDs ('Invalid Staged Upgrade Group')."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    groups_collection = "/networks/{networkId}/firmwareUpgrades/staged/groups"
    group_item = groups_collection + "/{groupId}"
    stages_path = "/networks/{networkId}/firmwareUpgrades/staged/stages"
    spec = {
        "openapi": "3.0.0", "info": {"title": "s", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            groups_collection: {
                "get": _op(
                    "getNetworkFirmwareUpgradesStagedGroups", "networks"
                ),
                "post": _op(
                    "createNetworkFirmwareUpgradesStagedGroup", "networks"
                ),
            },
            group_item: {
                "get": _op(
                    "getNetworkFirmwareUpgradesStagedGroup", "networks"
                ),
            },
            stages_path: {
                "get": _op("getNetworkFirmwareUpgradesStagedStages", "networks"),
                "put": _op(
                    "updateNetworkFirmwareUpgradesStagedStages", "networks"
                ),
            },
        },
    }
    path = tmp_path / "staged-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            group_item, ("N_1", "3510"),
            {"groupId": "3510", "name": "ring-a", "isDefault": False},
        ),
        FeatureConfiguration(
            stages_path, ("N_1",),
            {"items": [{"group": {"id": "3510", "name": "ring-a"}}]},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(
        calls,
        responses={
            "createNetworkFirmwareUpgradesStagedGroup": {"groupId": "3530"}
        },
    )
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    stages = next(
        c for c in calls if c[0] == "updateNetworkFirmwareUpgradesStagedStages"
    )
    sent = json.dumps(stages[2])
    assert "3530" in sent and "3510" not in sent


# --------------------------------------- drill-fix helpers and adoption


def test_name_conflict_pattern_matches_early_access_opt_ins() -> None:
    """Re-opting a network into an already-enabled early-access feature
    400s with 'has already opted in' — a name-conflict-shaped condition
    the adopter must recognize, not a failure."""
    from meraki2tf.restorer import _NAME_CONFLICT_RE

    assert _NAME_CONFLICT_RE.search(
        "Organization has already opted in to early access feature "
        "has_vlan_db"
    )
    # The pre-existing conflict shapes still match.
    assert _NAME_CONFLICT_RE.search("Name has already been taken")
    assert _NAME_CONFLICT_RE.search("A vlan with this name exists")
    assert _NAME_CONFLICT_RE.search("'gp' is a reserved name")
    assert not _NAME_CONFLICT_RE.search("Something else went wrong")


def test_sibling_mapping_returns_the_single_distinct_new_id() -> None:
    from meraki2tf.models import NetworkGraph as _NetworkGraph
    from meraki2tf.restorer import ReferenceResolver

    resolver = ReferenceResolver(_NetworkGraph("org-123", (), (), ()))
    # Nothing recorded for the identity yet: no sibling to adopt.
    assert resolver.sibling_mapping("payloadtemplate", "wpt_1") is None
    # The same old ID recorded across two network contexts with ONE
    # distinct new ID is the org-shared object.
    resolver.record("payloadtemplate", "wpt_1", "wpt_A", ("N_1",))
    resolver.record("payloadtemplate", "wpt_1", "wpt_A", ("N_2",))
    assert resolver.sibling_mapping("payloadtemplate", "wpt_1") == "wpt_A"
    # Colliding per-network IDs map to DIFFERENT new IDs: never adopt.
    resolver.record("grouppolicy", "100", "900", ("N_1",))
    resolver.record("grouppolicy", "100", "901", ("N_2",))
    assert resolver.sibling_mapping("grouppolicy", "100") is None


def test_default_flag_key_detects_truthy_isdefault_variants() -> None:
    from meraki2tf.restorer import _default_flag_key

    assert _default_flag_key({"isDefault": True}) == "isDefault"
    assert _default_flag_key(
        {"name": "x", "isDefaultGroup": True}
    ) == "isDefaultGroup"
    assert _default_flag_key({"isDefault": False}) is None
    assert _default_flag_key({}) is None
    assert _default_flag_key({"isDefault": "true"}) is None  # literal True only


def test_match_collection_item_falls_back_through_natural_keys() -> None:
    from meraki2tf.restorer import _match_collection_item

    listing = [
        {"name": "Employee Group", "sgt": 5, "groupId": "1"},
        {"name": "Guest Group", "sgt": 10, "groupId": "2"},
    ]
    # A unique name match wins outright.
    match = _match_collection_item(listing, {"name": "Guest Group"})
    assert match is not None and match["groupId"] == "2"
    # Sanitized snapshots pseudonymize names; the org-unique sgt breaks
    # the tie when no name matches.
    match = _match_collection_item(
        listing, {"name": "name-0a1b2c3d4e5f6071", "sgt": 5}
    )
    assert match is not None and match["groupId"] == "1"
    # shortName (an API keyword the sanitizer preserves) is the last key.
    opt_ins = [{"shortName": "has_vlan_db", "id": "9"}]
    match = _match_collection_item(
        opt_ins, {"name": "name-ffff", "shortName": "has_vlan_db"}
    )
    assert match is not None and match["id"] == "9"
    # Two items sharing the key are ambiguous: never guess.
    dup = [{"name": "dup"}, {"name": "dup"}]
    assert _match_collection_item(dup, {"name": "dup"}) is None
    # No key matches anything: fall through to the create.
    assert _match_collection_item(listing, {"name": "nothing"}) is None
    # Dict/list-valued payload keys are structure, not identity values.
    match = _match_collection_item(
        listing, {"name": {"nested": True}, "shortName": ["x"], "sgt": 10}
    )
    assert match is not None and match["groupId"] == "2"


def test_item_identifier_covers_per_collection_id_conventions() -> None:
    from meraki2tf.restorer import RestoreAction, _item_identifier
    from meraki2tf.spec.engine import OperationSpec

    def action(api_path: str) -> RestoreAction:
        op = OperationSpec(
            operation_id="op", method="post", path=api_path,
            path_params=("networkId",), tags=("networks",),
        )
        return RestoreAction(
            kind="create", wave=4, api_path=api_path,
            path_values=("N_1", "x"), operation=op,
        )

    gp = action(GP_ITEM)
    # A generic id wins first (and stringifies).
    assert _item_identifier(gp, {"id": 7}) == "7"
    # The item path's own placeholder names the field.
    assert _item_identifier(gp, {"groupPolicyId": "7"}) == "7"
    # A bare {id} placeholder falls back to the collection-derived
    # <singular>Id convention (adaptive policy groups carry groupId).
    apg = action("/organizations/{organizationId}/adaptivePolicy/groups/{id}")
    assert _item_identifier(apg, {"groupId": "7"}) == "7"
    # -ies plurals singularize (policies -> policyId).
    pol = action("/organizations/{organizationId}/policies/{id}")
    assert _item_identifier(pol, {"policyId": "9"}) == "9"
    # Nothing matches: None, never a guess.
    assert _item_identifier(apg, {"unrelated": "7"}) is None
    # Singleton paths (no trailing placeholder) have no item convention.
    assert _item_identifier(action(SNMP_PATH), {"snmpId": "3"}) is None
    # A placeholder-only collection segment derives no convention.
    two = action("/networks/{networkId}/{id}")
    assert _item_identifier(two, {"networkId": "N_9"}) is None


def test_drill_secrets_respect_declared_numeric_schema_types() -> None:
    """A numeric secret slot (a PIN) rejects string placeholders; the
    schema-declared type routes the injection."""
    from meraki2tf.restorer import _inject_drill_secrets, _schema_type_at
    from meraki2tf.spec.engine import OperationSpec

    op = OperationSpec(
        operation_id="updateThing", method="put",
        path="/networks/{networkId}/thing", path_params=("networkId",),
        tags=("networks",),
        raw={"requestBody": {"content": {"application/json": {"schema": {
            "type": "object",
            "properties": {
                "pin": {"type": "integer"},
                "cost": {"type": "number"},
                "communityString": {"type": "string"},
                "radius": {
                    "type": "object",
                    "properties": {"secret": {"type": "string"}},
                },
            },
        }}}}},
    )
    assert _schema_type_at(op, ["pin"]) == "integer"
    assert _schema_type_at(op, ["radius", "secret"]) == "string"
    assert _schema_type_at(op, ["undeclared"]) is None
    assert _schema_type_at(None, ["pin"]) is None
    bare = OperationSpec(
        operation_id="bare", method="put",
        path="/networks/{networkId}/thing", path_params=("networkId",),
        tags=("networks",),
    )
    assert _schema_type_at(bare, ["pin"]) is None

    filled, injected = _inject_drill_secrets(
        {"radius": {"host": "10.0.0.1"}},
        ("pin", "cost", "communityString", "radius.secret", "undeclared"),
        "seed", op=op,
    )
    assert injected == (
        "pin", "cost", "communityString", "radius.secret", "undeclared"
    )
    assert isinstance(filled["pin"], int)
    assert 10000000 <= filled["pin"] <= 99999999  # 8 digits, always
    assert isinstance(filled["cost"], int)
    assert re.fullmatch(r"drill-[0-9a-f]{12}", filled["communityString"])
    assert re.fullmatch(r"drill-[0-9a-f]{12}", filled["radius"]["secret"])
    # Paths the schema does not declare stay string placeholders.
    assert re.fullmatch(r"drill-[0-9a-f]{12}", filled["undeclared"])
    # Deterministic per (seed, path): resumed drills stay idempotent.
    again, _ = _inject_drill_secrets(
        {"radius": {"host": "10.0.0.1"}}, ("pin",), "seed", op=op
    )
    assert again["pin"] == filled["pin"]


STAGED_GROUPS = "/networks/{networkId}/firmwareUpgrades/staged/groups"
STAGED_GROUP_ITEM = STAGED_GROUPS + "/{groupId}"
STAGED_STAGES = "/networks/{networkId}/firmwareUpgrades/staged/stages"


def _staged_spec(tmp_path: Path) -> OpenApiParser:
    spec = {
        "openapi": "3.0.0", "info": {"title": "staged", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            STAGED_GROUPS: {
                "get": _op(
                    "getNetworkFirmwareUpgradesStagedGroups", "networks"
                ),
                "post": _op(
                    "createNetworkFirmwareUpgradesStagedGroup", "networks"
                ),
            },
            STAGED_GROUP_ITEM: {
                "get": _op(
                    "getNetworkFirmwareUpgradesStagedGroup", "networks"
                ),
                # The item PUT makes adoption run its content-alignment
                # follow-up, which records a PROVISIONAL mapping for the
                # adopted ID — the live-observed ambiguity bug needs it.
                "put": _op(
                    "updateNetworkFirmwareUpgradesStagedGroup", "networks"
                ),
            },
            STAGED_STAGES: {
                "get": _op(
                    "getNetworkFirmwareUpgradesStagedStages", "networks"
                ),
                "put": _op(
                    "updateNetworkFirmwareUpgradesStagedStages", "networks"
                ),
            },
        },
    }
    path = tmp_path / "staged-adopt-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def test_default_flagged_creates_adopt_the_provisioned_default(
    tmp_path: Path,
) -> None:
    """A create of an isDefault-true object can SUCCEED and still be
    wrong (the dashboard provisions its own default alongside); the
    target's flagged default is adopted BEFORE any POST, and children
    resolve to the adopted ID."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _staged_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            STAGED_GROUP_ITEM, ("N_1", "3510"),
            {"groupId": "3510", "name": "Default group", "isDefault": True},
        ),
        FeatureConfiguration(
            STAGED_STAGES, ("N_1",),
            {"items": [{"group": {"id": "3510"}}]},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def getNetworkFirmwareUpgradesStagedGroups(
            self, networkId: str
        ) -> list[dict]:
            self._calls.append(
                ("getNetworkFirmwareUpgradesStagedGroups", (networkId,), {})
            )
            return [
                {"groupId": "901", "name": "Auto default", "isDefault": True}
            ]

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    ops = [c[0] for c in calls]
    assert "createNetworkFirmwareUpgradesStagedGroup" not in ops  # adopted
    assert "getNetworkFirmwareUpgradesStagedGroups" in ops
    assert f"{STAGED_GROUP_ITEM}::N_1,3510" in result.executed
    # The follow-up stages PUT references the ADOPTED default's ID.
    stages = next(
        c for c in calls
        if c[0] == "updateNetworkFirmwareUpgradesStagedStages"
    )
    sent = json.dumps(stages[2])
    assert "901" in sent and "3510" not in sent


def test_adopted_default_sentinel_id_is_refreshed_after_align(
    tmp_path: Path,
) -> None:
    """A freshly provisioned default can list under the sentinel ID -1
    until the dashboard materializes it; item PUTs accept the alias but
    sibling references (the stages PUT) reject it ("Invalid Staged
    Upgrade Group: -1"), so adoption re-reads the collection after
    alignment and records the real identifier."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _staged_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            STAGED_GROUP_ITEM, ("N_1", "3510"),
            {"groupId": "3510", "name": "Default group", "isDefault": True},
        ),
        FeatureConfiguration(
            STAGED_STAGES, ("N_1",),
            {"items": [{"group": {"id": "3510"}}]},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def __init__(self, record: list) -> None:
            super().__init__(record)
            self._listed = 0

        def getNetworkFirmwareUpgradesStagedGroups(
            self, networkId: str
        ) -> list[dict]:
            self._calls.append(
                ("getNetworkFirmwareUpgradesStagedGroups", (networkId,), {})
            )
            self._listed += 1
            if self._listed == 1:
                return [
                    {"groupId": "-1", "name": "Auto default",
                     "isDefault": True}
                ]
            return [
                {"groupId": "901", "name": "Default group",
                 "isDefault": True}
            ]

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    # The collection was re-read after alignment…
    assert section._listed == 2
    # …and the stages PUT references the materialized ID, never -1.
    stages = next(
        c for c in calls
        if c[0] == "updateNetworkFirmwareUpgradesStagedStages"
    )
    sent = json.dumps(stages[2])
    assert "901" in sent and "-1" not in sent


PT_COLLECTION = "/networks/{networkId}/webhooks/payloadTemplates"
PT_ITEM = PT_COLLECTION + "/{payloadTemplateId}"


def _template_pair_spec(tmp_path: Path) -> OpenApiParser:
    spec = {
        "openapi": "3.0.0", "info": {"title": "pt", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            PT_COLLECTION: {
                "get": _op("getNetworkWebhooksPayloadTemplates", "networks"),
                "post": _op(
                    "createNetworkWebhooksPayloadTemplate", "networks"
                ),
            },
            PT_ITEM: {
                "get": _op("getNetworkWebhooksPayloadTemplate", "networks"),
            },
        },
    }
    path = tmp_path / "pt-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def _two_network_template_graph() -> NetworkGraph:
    """The same org-shared built-in template discovered in two networks
    under the SAME old ID (URL-derived IDs repeat across networks)."""
    payload = {
        "payloadTemplateId": "wpt_shared",
        "name": "Slack (included)",
        "type": "included",
    }
    return NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"], "timeZone": "UTC"}
            ),
            MerakiNetwork.from_payload(
                {"id": "N_2", "organizationId": "org-123", "name": "Lab",
                 "productTypes": ["appliance"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(
            FeatureConfiguration(PT_ITEM, ("N_1", "wpt_shared"), dict(payload)),
            FeatureConfiguration(PT_ITEM, ("N_2", "wpt_shared"), dict(payload)),
        ),
    )


class _TemplateSection(_RecordingSection):
    """Sequential network IDs plus a scriptable template create."""

    def __init__(self, calls: list, template_results: list) -> None:
        super().__init__(calls)
        self._network_count = 0
        #: One entry per create call: a dict response or an Exception.
        self._template_results = template_results

    def createOrganizationNetwork(self, *args: object, **kwargs: object) -> dict:
        self._calls.append(("createOrganizationNetwork", args, kwargs))
        self._network_count += 1
        return {"id": f"L_{self._network_count}"}

    def createNetworkWebhooksPayloadTemplate(
        self, *args: object, **kwargs: object
    ) -> dict:
        self._calls.append(
            ("createNetworkWebhooksPayloadTemplate", args, kwargs)
        )
        outcome = self._template_results.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def getNetworkWebhooksPayloadTemplates(self, networkId: str) -> list:
        self._calls.append(
            ("getNetworkWebhooksPayloadTemplates", (networkId,), {})
        )
        return []  # the built-in lives outside this network's collection


def test_org_shared_conflicts_adopt_the_sibling_networks_mapping(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The second network's copy of an org-shared template conflicts on
    create and is absent from its own collection; the sibling network's
    mapping for the same old ID IS the shared target object."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _template_pair_spec(tmp_path)
    graph = _two_network_template_graph()
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _TemplateSection(
        calls,
        [
            {"payloadTemplateId": "wpt_NEW"},
            _conflict_error("Name has already been taken"),
        ],
    )
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    with caplog.at_level("WARNING", logger="meraki2tf.restorer"):
        result = restorer.execute(graph, plan)

    assert result.failed == ()
    assert f"{PT_ITEM}::N_1,wpt_shared" in result.executed
    assert f"{PT_ITEM}::N_2,wpt_shared" in result.executed
    creates = [
        c for c in calls if c[0] == "createNetworkWebhooksPayloadTemplate"
    ]
    assert len(creates) == 2  # the second was attempted, then adopted
    # Both copies map to the one shared target object.
    assert restorer._journal.id_map["wpt_shared"] == "wpt_NEW"
    assert "org-shared" in caplog.text


def test_failed_same_old_id_in_a_sibling_network_is_still_attempted(
    tmp_path: Path,
) -> None:
    """A create's own last path value is its identity-to-be-minted, not
    an addressed parent: the same old ID failing in network A must not
    dead-parent the sibling copy in network B."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _template_pair_spec(tmp_path)
    graph = _two_network_template_graph()
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _TemplateSection(
        calls,
        [
            RuntimeError("boom"),  # N_1's copy fails for real (non-400)
            {"payloadTemplateId": "wpt_B"},
        ],
    )
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    result = restorer.execute(graph, plan)

    assert [key for key, _ in result.failed] == [
        f"{PT_ITEM}::N_1,wpt_shared"
    ]
    assert f"{PT_ITEM}::N_2,wpt_shared" in result.executed
    creates = [
        c for c in calls if c[0] == "createNetworkWebhooksPayloadTemplate"
    ]
    assert len(creates) == 2  # B was attempted, not skipped as dead
    assert not any(
        "parent object wpt_shared failed" in entry["reason"]
        for entry in result.skipped
    )


SR_COLLECTION = "/networks/{networkId}/appliance/staticRoutes"
SR_ITEM = SR_COLLECTION + "/{staticRouteId}"


def test_end_of_run_salvage_retries_same_wave_dependency_400s(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A 400 caused by a same-wave sibling (a static route whose next
    hop lives on a VLAN that sorts after it) succeeds once the plan
    settles: one end-of-run retry salvages it; a genuine 400 keeps its
    original failure record."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    spec = {
        "openapi": "3.0.0", "info": {"title": "sr", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            SR_COLLECTION: {
                "get": _op("getNetworkApplianceStaticRoutes", "appliance"),
                "post": _op("createNetworkApplianceStaticRoute", "appliance"),
            },
            SR_ITEM: {
                "get": _op("getNetworkApplianceStaticRoute", "appliance"),
                "put": _op("updateNetworkApplianceStaticRoute", "appliance"),
            },
        },
    }
    path = tmp_path / "sr-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            SR_ITEM, ("N_1", "r1"),
            {"id": "r1", "name": "salvageable", "subnet": "10.1.0.0/24"},
        ),
        FeatureConfiguration(
            SR_ITEM, ("N_1", "r2"),
            {"id": "r2", "name": "hopeless", "subnet": "10.2.0.0/24"},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    attempts: dict[str, int] = {"salvageable": 0, "hopeless": 0}

    class Section(_RecordingSection):
        def createNetworkApplianceStaticRoute(
            self, *args: object, **kwargs: object
        ) -> dict:
            self._calls.append(
                ("createNetworkApplianceStaticRoute", args, kwargs)
            )
            name = str(kwargs.get("name"))
            attempts[name] += 1
            if name == "hopeless":
                raise _conflict_error("hopeless is genuinely invalid")
            if attempts[name] == 1:
                raise _conflict_error(
                    "The next hop must be on a configured subnet"
                )
            return {"id": "sr_900"}

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, appliance=section
    )
    with caplog.at_level("WARNING", logger="meraki2tf.restorer"):
        result = restorer.execute(graph, plan)

    assert f"{SR_ITEM}::N_1,r1" in result.executed
    assert attempts == {"salvageable": 2, "hopeless": 2}  # one retry each
    # The salvaged route left the failure list; the hopeless one kept
    # its ORIGINAL message.
    assert [key for key, _ in result.failed] == [f"{SR_ITEM}::N_1,r2"]
    assert "hopeless is genuinely invalid" in dict(result.failed)[
        f"{SR_ITEM}::N_1,r2"
    ]
    assert "End-of-run salvage restored 1 object(s)" in caplog.text
    assert f"{SR_ITEM}::N_1,r1" in caplog.text


def test_withheld_detail_names_the_fields_sent(tmp_path: Path) -> None:
    """Secret-bearing failures withhold the SDK echo but list the
    top-level field NAMES sent — diagnosable, never sensitive."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"access": "community", "communityString": "real-secret-value"},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args: object, **kwargs: object) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            raise _conflict_error(
                "communityString rejected: real-secret-value"
            )

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    result = restorer.execute(graph, plan)

    reason = dict(result.failed)[f"{SNMP_PATH}::N_1"]
    assert "detail withheld" in reason
    assert "fields sent: access, communityString" in reason
    assert "real-secret-value" not in reason


# ------------------------------------------------------ wipe: drill admins


def _admin_wipe_dashboard(
    networks: int = 1,
    name: str = "Drill Org",
    me: object = None,
    admins: object = None,
    with_identity: bool = True,
    admins_error: bool = False,
    admin_delete_error: bool = False,
    templates: object = None,
    template_delete_error: bool = False,
):
    from types import SimpleNamespace

    deleted: dict[str, list] = {
        "networks": [], "orgs": [], "admins": [], "templates": [],
    }

    class Organizations:
        def getOrganization(self, organizationId: str) -> dict:
            return {"id": organizationId, "name": name}

        def getOrganizationDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return []

        def getOrganizationInventoryDevices(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return []

        def getOrganizationNetworks(
            self, organizationId: str, total_pages: str = "all"
        ) -> list:
            return [{"id": f"L_{i}"} for i in range(networks)]

        def getOrganizationAdmins(self, organizationId: str) -> object:
            if admins_error:
                raise RuntimeError("admins endpoint down")
            return admins if admins is not None else []

        def deleteOrganizationAdmin(
            self, organizationId: str, adminId: str
        ) -> dict:
            if admin_delete_error:
                raise RuntimeError("admin is protected")
            deleted["admins"].append(adminId)
            return {}

        def deleteOrganization(self, organizationId: str) -> dict:
            deleted["orgs"].append(organizationId)
            return {}

        def getOrganizationConfigTemplates(
            self, organizationId: str
        ) -> object:
            return templates if templates is not None else []

        def deleteOrganizationConfigTemplate(
            self, organizationId: str, configTemplateId: str
        ) -> dict:
            if template_delete_error:
                raise RuntimeError("template is protected")
            deleted["templates"].append(configTemplateId)
            return {}

    class Networks:
        def deleteNetwork(self, networkId: str) -> dict:
            deleted["networks"].append(networkId)
            return {}

    class Administered:
        def getAdministeredIdentitiesMe(self) -> object:
            return me if me is not None else {"email": "caller@drill.invalid"}

    sections: dict[str, object] = {
        "organizations": Organizations(), "networks": Networks(),
    }
    if with_identity:
        sections["administered"] = Administered()
    return SimpleNamespace(**sections), deleted


_DRILL_ADMINS = [
    {"id": "1", "email": "caller@drill.invalid"},
    {"id": "2", "email": "user-4f6a@drill.invalid"},
    {"email": "no-id@drill.invalid"},  # id-less rows never qualify
]


def test_wipe_preview_counts_admins_other_than_the_caller() -> None:
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, _ = _admin_wipe_dashboard(admins=list(_DRILL_ADMINS))
    preview = wiper.preview("org-drill", "Drill Org")
    assert preview.other_admin_count == 1


def test_wipe_removes_drill_admins_before_the_org() -> None:
    """The dashboard refuses to delete an org 'with multiple users';
    drill-restored admins (never the caller) are removed first."""
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, deleted = _admin_wipe_dashboard(admins=list(_DRILL_ADMINS))
    result = wiper.execute("org-drill", "Drill Org")
    assert deleted["admins"] == ["2"]  # only the non-caller admin
    assert result.organization_deleted is True
    assert deleted["orgs"] == ["org-drill"]
    assert result.failed == ()


def test_wipe_without_identity_endpoint_never_deletes_admins() -> None:
    """If the caller's own identity cannot be established, NO admin is
    ever deleted — the org deletion may then fail on its own."""
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, deleted = _admin_wipe_dashboard(
        admins=list(_DRILL_ADMINS), with_identity=False
    )
    preview = wiper.preview("org-drill", "Drill Org")
    assert preview.other_admin_count == 0
    result = wiper.execute("org-drill", "Drill Org")
    assert deleted["admins"] == []
    assert result.organization_deleted is True  # the fake org allows it


def test_wipe_admin_deletion_failure_blocks_the_org_deletion() -> None:
    """A failed admin removal is recorded and stops the organization
    deletion — the operator investigates first."""
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, deleted = _admin_wipe_dashboard(
        admins=list(_DRILL_ADMINS), admin_delete_error=True
    )
    result = wiper.execute("org-drill", "Drill Org")
    assert result.organization_deleted is False
    assert deleted["orgs"] == []
    assert [target for target, _ in result.failed] == ["admin:2"]
    assert "admin is protected" in result.failed[0][1]


def test_wipe_admin_enumeration_failures_degrade_to_no_deletion() -> None:
    """An unreadable admin list — or an identity without an email —
    means no admin is deleted, never a crash or a guess."""
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, deleted = _admin_wipe_dashboard(
        admins=list(_DRILL_ADMINS), admins_error=True
    )
    assert wiper.preview("org-drill", "Drill Org").other_admin_count == 0

    wiper = OrgWiper()
    wiper._client, deleted = _admin_wipe_dashboard(
        admins=list(_DRILL_ADMINS), me={}
    )
    result = wiper.execute("org-drill", "Drill Org")
    assert deleted["admins"] == []
    assert result.organization_deleted is True


def test_salvaged_actions_keep_their_drill_placeholder_record(
    tmp_path: Path,
) -> None:
    """An end-of-run salvage of a drill write that received placeholder
    secrets must still report those placeholders — the operator's
    re-entry list may not lose entries to the retry."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"access": "community", "communityString": REDACTED},
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    attempts = {"count": 0}

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args: object, **kwargs: object) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise _conflict_error("Community string is not usable yet")
            return {}

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    assert f"{SNMP_PATH}::N_1" in result.executed
    assert result.drill_placeholders == (
        (f"{SNMP_PATH}::N_1", "communityString"),
    )
    assert attempts["count"] == 2  # original 400, then the salvage retry


def test_unadoptable_name_conflicts_stay_failed(tmp_path: Path) -> None:
    """A name-conflict 400 with no reconcilable counterpart, no
    client-assigned slot, and no sibling mapping keeps its failure."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _template_pair_spec(tmp_path)
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"], "timeZone": "UTC"}
            ),
        ),
        devices=(),
        features=(
            FeatureConfiguration(
                PT_ITEM, ("N_1", "wpt_lone"),
                {"payloadTemplateId": "wpt_lone", "name": "Custom",
                 "type": "custom"},
            ),
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _TemplateSection(
        calls, [_conflict_error("Name has already been taken")]
    )
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    result = restorer.execute(graph, plan)

    reasons = dict(result.failed)
    assert "already been taken" in reasons[f"{PT_ITEM}::N_1,wpt_lone"]


def test_adopt_default_falls_through_on_every_non_match(
    tmp_path: Path,
) -> None:
    """Anything short of one identifiable flagged default falls through
    to the normal create — never a guess."""
    from types import SimpleNamespace

    from meraki2tf.models import NetworkGraph as _NetworkGraph
    from meraki2tf.restorer import (
        OrgRestorer,
        ReferenceResolver,
        RestoreAction,
        RestoreJournal,
    )
    from meraki2tf.spec.engine import OperationSpec

    resolver = ReferenceResolver(_NetworkGraph("org-123", (), (), ()))
    resolver.record("network", "N_1", "N_LIVE", ())
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "adopt.jsonl")
    )
    lookup = OperationSpec(
        operation_id="getNetworkFirmwareUpgradesStagedGroups",
        method="get", path=STAGED_GROUPS, path_params=("networkId",),
        tags=("networks",),
    )

    def action(**overrides: object) -> RestoreAction:
        values = dict(
            kind="create", wave=4, api_path=STAGED_GROUP_ITEM,
            path_values=("N_1", "3510"), operation=lookup,
            payload={"name": "Default", "isDefault": True}, lookup=lookup,
        )
        values.update(overrides)
        return RestoreAction(**values)  # type: ignore[arg-type]

    class Sections:
        def __init__(self, listing: list) -> None:
            self._listing = listing

        def getNetworkFirmwareUpgradesStagedGroups(
            self, networkId: str
        ) -> list:
            return self._listing

    def dashboard(listing: list) -> object:
        return SimpleNamespace(networks=Sections(listing))

    # No collection GET in the spec: nothing to adopt from.
    assert restorer._adopt_default(
        dashboard([]), action(lookup=None), resolver, "org-123", "isDefault"
    ) is None
    # The target provisions no flagged default.
    assert restorer._adopt_default(
        dashboard([{"groupId": "9", "isDefault": False}]),
        action(), resolver, "org-123", "isDefault",
    ) is None
    # Several flagged items and no natural key breaks the tie.
    assert restorer._adopt_default(
        dashboard([
            {"groupId": "8", "isDefault": True, "name": "a"},
            {"groupId": "9", "isDefault": True, "name": "b"},
        ]),
        action(), resolver, "org-123", "isDefault",
    ) is None
    # The flagged item carries no recognizable identifier.
    assert restorer._adopt_default(
        dashboard([{"isDefault": True, "name": "Only"}]),
        action(), resolver, "org-123", "isDefault",
    ) is None
    # Several flagged items DO disambiguate on a natural key.
    assert restorer._adopt_default(
        dashboard([
            {"groupId": "8", "isDefault": True, "name": "other"},
            {"groupId": "9", "isDefault": True, "name": "Default"},
        ]),
        action(), resolver, "org-123", "isDefault",
    ) == "9"


# ------------------------------------ enriched-drill regression fixes


def test_grammar_rewrites_pseudonymized_policy_object_ids() -> None:
    """Sanitized snapshots pseudonymize policy-object IDs inside the
    GRP()/OBJ() firewall grammar (``OBJ(id-0012)``); the digits-only
    pattern silently skipped the rewrite and dead pseudonyms reached
    the dashboard ('Source address must be an IP address ...').
    Numeric IDs must keep rewriting."""
    from meraki2tf.restorer import ReferenceResolver, rewrite_references

    graph = _graph(
        FeatureConfiguration(PO_ITEM, ("org-123", "id-0012"), {"name": "web"}),
    )
    resolver = ReferenceResolver(graph)
    resolver.record("policyobject", "id-0012", "9012")
    resolver.record("policyobjectgroup", "id-0015", "9015")
    resolver.record("policyobject", "42", "9042")
    payload = {
        "rules": [
            {"policy": "deny", "srcCidr": "OBJ(id-0012)",
             "destCidr": "GRP(id-0015)"},
            {"policy": "allow", "srcCidr": "OBJ(42)"},
        ]
    }
    rewritten = rewrite_references(payload, resolver, ("N_1",))
    assert rewritten["rules"][0]["srcCidr"] == "OBJ(9012)"
    assert rewritten["rules"][0]["destCidr"] == "GRP(9015)"
    assert rewritten["rules"][1]["srcCidr"] == "OBJ(9042)"


def test_derived_collection_id_key_singularizes_the_collection() -> None:
    from meraki2tf.restorer import _derived_collection_id_key

    assert _derived_collection_id_key(
        "/organizations/{organizationId}/adaptivePolicy/groups/{id}"
    ) == "groupId"
    # -ies plurals singularize (policies -> policyId).
    assert _derived_collection_id_key(
        "/organizations/{organizationId}/policies/{id}"
    ) == "policyId"
    # Non-item paths (no trailing placeholder) carry no convention.
    assert _derived_collection_id_key(SNMP_PATH) is None
    # A placeholder-only collection segment derives no convention.
    assert _derived_collection_id_key("/networks/{networkId}/{id}") is None
    # A bare item placeholder has no collection segment at all.
    assert _derived_collection_id_key("/{id}") is None


def test_create_response_id_extracted_via_the_collection_convention(
    tmp_path: Path,
) -> None:
    """An adaptive-policy-group create answers with ONLY ``groupId``
    (no ``id``, and the item path's own placeholder is a generic
    ``{id}``): the mapping must still be recorded or every child
    referencing the group fails on dead snapshot IDs (the live 'Create
    returned no object ID' -> 'no rebuilt counterpart' failure)."""
    apg_collection = "/organizations/{organizationId}/adaptivePolicy/groups"
    apg_item = apg_collection + "/{id}"
    spec = {
        "openapi": "3.0.0", "info": {"title": "apg", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            apg_collection: {
                "get": _op(
                    "getOrganizationAdaptivePolicyGroups", "organizations"
                ),
                "post": _op(
                    "createOrganizationAdaptivePolicyGroup", "organizations"
                ),
            },
            apg_item: {
                "get": _op(
                    "getOrganizationAdaptivePolicyGroup", "organizations"
                ),
            },
            SNMP_PATH: {
                "get": _op("getNetworkSnmp", "networks"),
                "put": _op("updateNetworkSnmp", "networks"),
            },
        },
    }
    path = tmp_path / "apg-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            apg_item, ("org-123", "APG_9"),
            {"name": "Employee Group", "sgt": 5},
        ),
        FeatureConfiguration(
            SNMP_PATH, ("N_1",), {"access": "none", "groupId": "APG_9"},
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(
        tmp_path,
        responses={
            "createOrganizationAdaptivePolicyGroup": {"groupId": "955"}
        },
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    assert f"{apg_item}::org-123,APG_9" in result.executed
    # The dependent child resolves to the NEW server-assigned ID.
    snmp = next(c for c in calls if c[0] == "updateNetworkSnmp")
    assert snmp[2]["groupId"] == "955"


def test_effectively_empty_detects_null_only_bodies() -> None:
    from meraki2tf.restorer import _effectively_empty

    assert _effectively_empty({"a": {"b": None}}) is True
    assert _effectively_empty({}) is True
    assert _effectively_empty({"a": []}) is True
    assert _effectively_empty({"a": [None]}) is True
    assert _effectively_empty({"a": 0}) is False
    assert _effectively_empty({"a": ["x"]}) is False


def test_null_only_configure_payload_is_skipped_not_dispatched(
    tmp_path: Path,
) -> None:
    """A GET echo can strip to nothing but null leaves (a config
    template's cellular uplink reads back ``{"bandwidthLimits":
    {"limitUp": null, "limitDown": null}}``); the dashboard 400s the
    resulting PUT with 'None of the fields were specified' — there is
    nothing to restore, so the action skips without any API call."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"bandwidthLimits": {"limitUp": None, "limitDown": None}},
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    assert all(c[0] != "updateNetworkSnmp" for c in calls)  # never sent
    (entry,) = [
        e for e in result.skipped if e["target"] == f"{SNMP_PATH}::N_1"
    ]
    assert "no writable values" in entry["reason"]
    assert f"{SNMP_PATH}::N_1" not in result.executed


def test_device_class_capability_400_is_drill_skipped(
    tmp_path: Path,
) -> None:
    """"'wan2' is not supported for this network. Consider upgrading
    your devices" is the device-class refusal a hardware-free drill org
    produces: drill-skip under --skip-claims, not failure."""
    from types import SimpleNamespace

    from meraki2tf.restorer import _CAPABILITY_RE, OrgRestorer, RestoreJournal

    # Both new alternatives match independently.
    assert _CAPABILITY_RE.search("'wan2' is not supported for this network")
    assert _CAPABILITY_RE.search("Consider upgrading your devices")

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"})
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            raise _conflict_error(
                "'wan2' is not supported for this network. Consider "
                "upgrading your devices"
            )

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert any("drill:" in entry["reason"] for entry in result.skipped)


def test_template_bound_400_skips_even_outside_drills(
    tmp_path: Path,
) -> None:
    """'Cannot configure sensor alerts on a template network' is NOT
    drill-gated: a template-bound network refuses the write for
    everyone; the config template's own copy restores separately."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"})
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            raise _conflict_error(
                "Cannot configure sensor alerts on a template network"
            )

    section = Section(calls)
    restorer = OrgRestorer(  # a REAL restore: skip_claims stays False
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    (entry,) = [
        e for e in result.skipped if e["target"] == f"{SNMP_PATH}::N_1"
    ]
    assert "governed by its config template" in entry["reason"]
    assert not entry["reason"].startswith("drill:")
    # No pointless retry: the refusal is classified on the first 400.
    assert len([c for c in calls if c[0] == "updateNetworkSnmp"]) == 1


def test_schema_type_at_descends_array_hops(tmp_path: Path) -> None:
    """A ``name[]`` path segment descends through the array property's
    ``items`` schema, so per-element numeric slots keep their declared
    type (``radiusServers[].port`` -> integer placeholder)."""
    from meraki2tf.restorer import _inject_drill_secrets, _schema_type_at
    from meraki2tf.spec.engine import OperationSpec

    op = OperationSpec(
        operation_id="updateNetworkWirelessSsid", method="put",
        path=SSID_ITEM, path_params=("networkId", "number"),
        tags=("wireless",),
        raw={"requestBody": {"content": {"application/json": {"schema": {
            "type": "object",
            "properties": {
                "radiusServers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "port": {"type": "integer"},
                            "secret": {"type": "string"},
                        },
                    },
                },
            },
        }}}}},
    )
    assert _schema_type_at(op, ["radiusServers[]", "port"]) == "integer"
    assert _schema_type_at(op, ["radiusServers[]", "secret"]) == "string"

    payload = {"radiusServers": [{"host": "10.0.0.1"}, {"host": "10.0.0.2"}]}
    filled, injected = _inject_drill_secrets(
        payload,
        ("radiusServers[].port", "radiusServers[].secret"),
        "seed", op=op,
    )
    assert injected == ("radiusServers[].port", "radiusServers[].secret")
    ports = [server["port"] for server in filled["radiusServers"]]
    assert all(
        isinstance(port, int) and 10000000 <= port <= 99999999
        for port in ports
    )
    secrets = [server["secret"] for server in filled["radiusServers"]]
    assert all(re.fullmatch(r"drill-[0-9a-f]{12}", s) for s in secrets)
    assert secrets[0] != secrets[1]  # per-element digests, never shared
    assert payload["radiusServers"] == [
        {"host": "10.0.0.1"}, {"host": "10.0.0.2"}
    ]  # input untouched


def test_list_leaf_secret_slots_fan_out_with_distinct_placeholders() -> None:
    """A list-leaf slot (``secrets[]`` over scalar elements) replaces
    every element; a path whose container is not a list stays omitted."""
    from meraki2tf.restorer import _inject_drill_secrets

    filled, injected = _inject_drill_secrets(
        {"secrets": ["gone", "gone"], "psks": {"not": "a list"}},
        ("secrets[]", "psks[]"),
        "seed",
    )
    assert injected == ("secrets[]",)  # psks is no list: no slot to fill
    first, second = filled["secrets"]
    assert first.startswith("drill-") and second.startswith("drill-")
    assert first != second
    assert filled["psks"] == {"not": "a list"}


def test_absent_schema_secrets_injected_into_list_elements() -> None:
    """Write-only secrets (a RADIUS server's ``secret``) never appear
    in GET echoes, so redaction recorded nothing — the drill must fill
    them from the WRITE SCHEMA for every present list element. Absent
    top-level secrets (an open SSID's psk) stay absent."""
    from meraki2tf.restorer import _inject_absent_list_secrets
    from meraki2tf.spec.engine import OperationSpec

    op = OperationSpec(
        operation_id="updateNetworkWirelessSsid", method="put",
        path=SSID_ITEM, path_params=("networkId", "number"),
        tags=("wireless",),
        raw={"requestBody": {"content": {"application/json": {"schema": {
            "type": "object",
            "properties": {
                "psk": {"type": "string"},
                "radiusServers": {
                    "type": "array",
                    "items": {"properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer"},
                        "secret": {"type": "string"},
                    }},
                },
            },
        }}}}},
    )
    payload = {
        "radiusServers": [
            {"host": "10.0.0.1", "port": 1812},
            {"host": "10.0.0.2", "port": 1812},
            {"host": "10.0.0.3", "port": 1812, "secret": "kept"},
        ],
    }
    filled, injected = _inject_absent_list_secrets(payload, "seed", op)
    assert injected == ("radiusServers[].secret",)
    first, second, third = filled["radiusServers"]
    assert first["secret"].startswith("drill-")
    assert second["secret"].startswith("drill-")
    assert first["secret"] != second["secret"]  # per-element digests
    assert third["secret"] == "kept"  # present slots untouched
    assert "psk" not in filled  # top-level absent secrets stay absent
    assert "secret" not in payload["radiusServers"][0]  # input untouched
    refill, _ = _inject_absent_list_secrets(payload, "seed", op)
    assert refill == filled  # deterministic across resumed drills


def test_resume_recovers_mapping_for_done_but_unmapped_create(
    tmp_path: Path,
) -> None:
    """A journal-done create whose run never extracted a response ID
    leaves every reference permanently dead on resume; the resume now
    recovers the mapping by matching the existing target object."""
    from meraki2tf.restorer import RestoreJournal

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

    # First pass: run everything, then rewrite the journal WITHOUT the
    # group policy's mapping rows — simulating a run that created the
    # object but could not extract its response ID.
    restorer, calls = _executor(tmp_path)
    assert restorer.execute(graph, plan).failed == ()
    journal_path = tmp_path / "journal.jsonl"
    lines = [
        line
        for line in journal_path.read_text().splitlines()
        if not (
            '"kind": "map"' in line and '"old": "100"' in line
        )
    ]
    journal_path.write_text("\n".join(lines) + "\n")

    restorer2, calls2 = _executor(
        tmp_path,
        responses={
            "getOrganizationNetworks": [{"id": "L_NEW", "name": "HQ"}],
            "getNetworkGroupPolicies": [{"id": "900", "name": "kiosk"}],
            "getNetworkWirelessSsid": {"number": 0, "name": "Corp"},
        },
    )
    restorer2._journal = RestoreJournal(journal_path)
    result = restorer2.execute(graph, plan)

    assert result.failed == ()
    # The resume looked the existing policy up by name…
    assert any(c[0] == "getNetworkGroupPolicies" for c in calls2)
    # …recovered its mapping into the journal…
    assert RestoreJournal(journal_path).id_map.get("100") == "900"
    # …and no object was re-created or re-configured.
    assert not any(c[0] == "createNetworkGroupPolicy" for c in calls2)


def test_element_identity_from_payload_tries_family_convention() -> None:
    """Adaptive-policy elements key on ``adaptivePolicyId`` — the
    FAMILY segment's convention, after the placeholder and the
    collection's ``<singular>Id``."""
    from meraki2tf.restorer import _element_identity_from_payload
    from meraki2tf.spec.engine import OperationSpec

    op = OperationSpec(
        operation_id="updateOrganizationAdaptivePolicyPolicy",
        method="put",
        path="/organizations/{organizationId}/adaptivePolicy/policies/{id}",
        path_params=("organizationId", "id"), tags=("organizations",),
        raw={},
    )
    assert _element_identity_from_payload(op, {"id": "7"}) == "7"
    assert _element_identity_from_payload(op, {"policyId": "8"}) == "8"
    assert _element_identity_from_payload(
        op, {"adaptivePolicyId": "id-0052"}
    ) == "id-0052"
    assert _element_identity_from_payload(op, {"name": "x"}) is None


def test_collection_captured_item_synthesizes_an_item_create(
    tmp_path: Path,
) -> None:
    """An asset captured at its COLLECTION path whose only update
    writer lives on the item path (extra {id} the feature cannot bind)
    is planned as an item-path CREATE via the collection POST — the
    live 'missing 1 required positional argument' failure."""
    ap_collection = "/organizations/{organizationId}/adaptivePolicy/policies"
    ap_item = ap_collection + "/{id}"
    spec = {
        "openapi": "3.0.0", "info": {"title": "app", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            ap_collection: {
                "get": _op(
                    "getOrganizationAdaptivePolicyPolicies", "organizations"
                ),
                "post": _op(
                    "createOrganizationAdaptivePolicyPolicy", "organizations"
                ),
            },
            ap_item: {
                "get": _op(
                    "getOrganizationAdaptivePolicyPolicy", "organizations"
                ),
                "put": _op(
                    "updateOrganizationAdaptivePolicyPolicy", "organizations"
                ),
            },
        },
    }
    path = tmp_path / "app-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            ap_collection, ("org-123",),
            {"adaptivePolicyId": "AP_1", "lastEntryRule": "deny"},
        ),
    )
    plan = plan_restore(graph, parser)
    action = next(
        a for a in plan.actions if "adaptivePolicy" in a.api_path
    )
    assert action.kind == "create"
    assert action.api_path == ap_item
    assert action.path_values == ("org-123", "AP_1")
    assert action.operation.operation_id == (
        "createOrganizationAdaptivePolicyPolicy"
    )
    assert action.aligner is not None
    assert action.aligner.operation_id == (
        "updateOrganizationAdaptivePolicyPolicy"
    )


def test_discovery_element_id_knows_the_family_convention() -> None:
    from meraki2tf.providers.discovery import element_id
    from meraki2tf.spec.engine import OperationSpec

    op = OperationSpec(
        operation_id="getOrganizationAdaptivePolicyPolicy", method="get",
        path="/organizations/{organizationId}/adaptivePolicy/policies/{id}",
        path_params=("organizationId", "id"), tags=("organizations",),
        raw={},
    )
    assert element_id(op, {"adaptivePolicyId": "AP_9"}) == "AP_9"


def test_wipe_removes_config_templates_before_the_org() -> None:
    """Config templates are backed by hidden networks the network loop
    never lists; the dashboard then refuses the org deletion with
    'Cannot delete organization: it still has networks'."""
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, deleted = _admin_wipe_dashboard(
        templates=[{"id": "L_T1", "name": "tmpl"}]
    )
    preview = wiper.preview("org-drill", "Drill Org")
    assert preview.config_template_count == 1
    result = wiper.execute("org-drill", "Drill Org")
    assert deleted["templates"] == ["L_T1"]
    assert result.organization_deleted is True
    assert result.failed == ()


def test_wipe_template_failure_blocks_the_org_deletion() -> None:
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, deleted = _admin_wipe_dashboard(
        templates=[{"id": "L_T1"}], template_delete_error=True,
    )
    result = wiper.execute("org-drill", "Drill Org")
    assert result.organization_deleted is False
    assert deleted["orgs"] == []
    assert any(key == "configTemplate:L_T1" for key, _ in result.failed)


def test_additive_only_adoption_never_aligns_surviving_content(
    tmp_path: Path,
) -> None:
    """Heal's contract: surviving objects are never modified. A
    name-conflicted create adopts the survivor mapping-only — the
    content-alignment PUT that would push the stale snapshot payload
    over an operator's manual recreation must never fire."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    vlan_collection = "/networks/{networkId}/appliance/vlans"
    vlan_item = "/networks/{networkId}/appliance/vlans/{vlanId}"
    create_op = dict(_op("createNetworkApplianceVlan", "appliance"))
    create_op["requestBody"] = {
        "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {"id": {}, "name": {}, "subnet": {}},
        }}}
    }
    spec = {
        "openapi": "3.0.0", "info": {"title": "v", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            vlan_collection: {
                "get": _op("getNetworkApplianceVlans", "appliance"),
                "post": create_op,
            },
            vlan_item: {
                "get": _op("getNetworkApplianceVlan", "appliance"),
                "put": _op("updateNetworkApplianceVlan", "appliance"),
            },
        },
    }
    path = tmp_path / "vlan-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            vlan_item, ("N_1", "1"),
            {"id": "1", "name": "Default", "subnet": "10.0.0.0/24"},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def createNetworkApplianceVlan(self, *args, **kwargs) -> dict:
            self._calls.append(("createNetworkApplianceVlan", args, kwargs))
            raise _conflict_error("Vlan has already been taken")

    section = Section(calls, responses={"getOrganizationNetworks": []})
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"),
        skip_claims=True, additive_only=True,
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, appliance=section
    )
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert f"{vlan_item}::N_1,1" in result.executed
    # Adoption stands (children can rewire) but the survivor's content
    # was left exactly as the operator had it.
    assert not [c for c in calls if c[0] == "updateNetworkApplianceVlan"]


def test_additive_only_adoption_log_never_claims_alignment(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The adoption message must describe what actually happens: in
    additive-only mode the alignment PUT is skipped, so logging
    "aligning its content with the snapshot" right before "NOT pushed"
    reads as a contradiction to the operator reviewing a heal run."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    vlan_collection = "/networks/{networkId}/appliance/vlans"
    vlan_item = "/networks/{networkId}/appliance/vlans/{vlanId}"
    create_op = dict(_op("createNetworkApplianceVlan", "appliance"))
    create_op["requestBody"] = {
        "content": {"application/json": {"schema": {
            "type": "object",
            "properties": {"id": {}, "name": {}, "subnet": {}},
        }}}
    }
    spec = {
        "openapi": "3.0.0", "info": {"title": "v", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            vlan_collection: {
                "get": _op("getNetworkApplianceVlans", "appliance"),
                "post": create_op,
            },
            vlan_item: {
                "get": _op("getNetworkApplianceVlan", "appliance"),
                "put": _op("updateNetworkApplianceVlan", "appliance"),
            },
        },
    }
    path = tmp_path / "vlan-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(
            vlan_item, ("N_1", "1"),
            {"id": "1", "name": "Default", "subnet": "10.0.0.0/24"},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def createNetworkApplianceVlan(self, *args, **kwargs) -> dict:
            self._calls.append(("createNetworkApplianceVlan", args, kwargs))
            raise _conflict_error("Vlan has already been taken")

    section = Section(calls, responses={"getOrganizationNetworks": []})
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"),
        skip_claims=True, additive_only=True,
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, appliance=section
    )
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        restorer.execute(graph, plan)
    adoption = [
        r.getMessage() for r in caplog.records if "Adopted" in r.getMessage()
    ]
    assert adoption, "expected an adoption log line"
    assert not any("aligning" in message for message in adoption)
    assert any("additive-only" in message for message in adoption)


def test_throttled_writes_defer_instead_of_poisoning_the_subtree(
    tmp_path: Path,
) -> None:
    """A 429 that survives the SDK's own retries is transient pressure,
    not a verdict on the object: the action defers (with bucket
    backoff) and is retried before the run gives up on it."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph()
    plan = plan_restore(graph, parser)
    calls: list = []
    throttles: list[bool] = []
    bucket = SimpleNamespace(
        acquire=lambda: None,
        on_success=lambda: None,
        on_throttle=lambda: throttles.append(True),
    )

    class Throttled(Exception):
        status = 429

    class Section(_RecordingSection):
        def createOrganizationNetwork(self, *args, **kwargs) -> dict:
            self._calls.append(("createOrganizationNetwork", args, kwargs))
            raise Throttled("429 Too Many Requests")

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"),
        skip_claims=True, bucket=bucket,  # type: ignore[arg-type]
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    result = restorer.execute(graph, plan)
    creates = [c for c in calls if c[0] == "createOrganizationNetwork"]
    assert len(creates) >= 2  # deferred and retried, not failed outright
    assert throttles  # the shared pacer was backed off
    ((key, reason),) = [
        (key, reason)
        for key, reason in result.failed
        if "throttled" in reason
    ]
    assert "429" in reason


def test_throttle_storm_never_trips_the_reference_deadlock_breaker(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Consecutive all-throttled rounds are transient saturation, not a
    reference deadlock: the throttled create retries under backoff and
    the referring action then resolves the REAL mapping — its reference
    fields are never silently dropped and nothing is failed."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

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
    calls: list = []
    bucket = SimpleNamespace(
        acquire=lambda: None, on_success=lambda: None,
        on_throttle=lambda: None,
    )

    class Throttled(Exception):
        status = 429

    class Section(_RecordingSection):
        throttles_left = 2

        def createNetworkGroupPolicy(self, *args, **kwargs) -> dict:
            self._calls.append(("createNetworkGroupPolicy", args, kwargs))
            if Section.throttles_left:
                Section.throttles_left -= 1
                raise Throttled("429 Too Many Requests")
            return {"id": "900"}

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"),
        serial_map={"Q2AB-CDEF-GHIJ": "Q9ZZ-NEWW-HWSN"},
        bucket=bucket,  # type: ignore[arg-type]
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        result = restorer.execute(graph, plan)
    assert result.failed == ()
    # The SSID waited for the group policy's real mapping — no dropped
    # reference fields, no deadlock-breaker involvement.
    ssid = next(c for c in calls if c[0] == "updateNetworkWirelessSsid")
    assert ssid[2]["groupPolicyId"] == "900"
    assert "unresolvable reference" not in caplog.text
    assert "deferred by API throttling" in caplog.text


def test_throttle_budget_exhaustion_fails_and_poisons_children(
    tmp_path: Path,
) -> None:
    """Only exhausting the generous per-action attempt budget fails a
    throttled write; the failure then holds its subtree back exactly
    like any other failed parent."""
    from types import SimpleNamespace

    from meraki2tf.restorer import (
        _MAX_THROTTLE_ATTEMPTS,
        OrgRestorer,
        RestoreJournal,
    )

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    bucket = SimpleNamespace(
        acquire=lambda: None, on_success=lambda: None,
        on_throttle=lambda: None,
    )

    class Throttled(Exception):
        status = 429

    class Section(_RecordingSection):
        def createOrganizationNetwork(self, *args, **kwargs) -> dict:
            self._calls.append(("createOrganizationNetwork", args, kwargs))
            raise Throttled("429 Too Many Requests")

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"),
        skip_claims=True, bucket=bucket,  # type: ignore[arg-type]
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    result = restorer.execute(graph, plan)
    creates = [c for c in calls if c[0] == "createOrganizationNetwork"]
    assert len(creates) == _MAX_THROTTLE_ATTEMPTS
    ((_, reason),) = [f for f in result.failed if "throttled" in f[1]]
    assert "retry budget" in reason
    assert any(
        "parent object N_1 failed" in entry["reason"]
        for entry in result.skipped
    )


def test_journal_refuses_non_object_lines(tmp_path: Path) -> None:
    """Line-valid JSON that is not an object must surface as the CLI's
    'journal is unreadable' ValueError, not an AttributeError."""
    from meraki2tf.restorer import RestoreJournal

    path = tmp_path / "journal.jsonl"
    path.write_text('"just-a-string"\n', encoding="utf-8")
    with pytest.raises(ValueError, match="not a JSON object"):
        RestoreJournal(path)


def test_journal_refuses_records_missing_required_fields(
    tmp_path: Path,
) -> None:
    from meraki2tf.restorer import RestoreJournal

    path = tmp_path / "journal.jsonl"
    path.write_text('{"kind": "done"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="missing required field"):
        RestoreJournal(path)


def test_wipe_caller_email_match_is_case_insensitive() -> None:
    """The identity and admin endpoints may case the same address
    differently; mistaking the caller for 'other' would delete the API
    key's own admin record mid-teardown."""
    from meraki2tf.restorer import OrgWiper

    wiper = OrgWiper()
    wiper._client, deleted = _admin_wipe_dashboard(
        admins=[
            {"id": "1", "email": "Caller@Drill.INVALID "},
            {"id": "2", "email": "user-4f6a@drill.invalid"},
        ],
        me={"email": "caller@drill.invalid"},
    )
    result = wiper.execute("org-drill", "Drill Org")
    assert deleted["admins"] == ["2"]  # never the caller, however cased
    assert result.organization_deleted is True


def test_falsy_non_mapping_payload_is_unrestorable(tmp_path: Path) -> None:
    """A capture that recorded no payload object at all (empty array,
    no body) has nothing to write back and must land as an explicit
    unrestorable gap — never crash or silently vanish."""
    parser = _restore_spec(tmp_path)
    plan = plan_restore(
        _graph(FeatureConfiguration(SNMP_PATH, ("N_1",), [])),
        parser,
    )
    (item,) = plan.unrestorable
    assert item.api_path == SNMP_PATH
    assert "No payload captured" in item.reason


def test_verdicts_cover_defaults_and_unrestorable_keys(
    tmp_path: Path,
) -> None:
    """DefaultState carries the same journal-style key as actions, and
    unrestorable assets join the coverage manifest with their reason."""
    from meraki2tf.restorer import DefaultState, restore_verdicts

    assert DefaultState(SNMP_PATH, ("N_1",)).key == f"{SNMP_PATH}::N_1"
    plan = plan_restore(
        _graph(FeatureConfiguration(CLIENTS_PATH, ("N_1",), {"usage": 1})),
        _restore_spec(tmp_path),
    )
    verdict = restore_verdicts(plan)[(CLIENTS_PATH, ("N_1",))]
    assert verdict.startswith("unrestorable: ")
    assert "dashboard-only" in verdict


def test_absent_secret_injection_skips_unschematized_shapes() -> None:
    """The write-schema walk only fills slots it can vouch for: absent
    properties declarations, non-mapping property schemas, itemless or
    scalar-item arrays, and non-object list elements all pass through
    untouched, while declared numeric secrets get numeric placeholders."""
    from meraki2tf.restorer import _inject_absent_list_secrets
    from meraki2tf.spec.engine import OperationSpec

    def op_for(schema: dict) -> OperationSpec:
        return OperationSpec(
            operation_id="updateNetworkWirelessSsid", method="put",
            path=SSID_ITEM, path_params=("networkId", "number"),
            tags=("wireless",),
            raw={"requestBody": {"content": {"application/json": {
                "schema": schema,
            }}}},
        )

    # A schema without a properties mapping offers no verifiable slots.
    filled, injected = _inject_absent_list_secrets(
        {"radiusServers": [{"host": "10.0.0.1"}]}, "seed",
        op_for({"type": "object"}),
    )
    assert injected == ()
    assert filled == {"radiusServers": [{"host": "10.0.0.1"}]}

    schema = {
        "type": "object",
        "properties": {
            "radius": {"type": "object", "properties": {
                "servers": {"type": "array", "items": {"properties": {
                    "host": {"type": "string"},
                    "secret": {"type": "string"},
                    "passcode": {"type": "integer"},
                }}},
            }},
            "typo": True,  # non-mapping property schema
            "bareList": {"type": "array"},  # no items schema
            "scalarList": {"type": "array", "items": {"type": "string"}},
        },
    }
    payload = {
        "radius": {"servers": [{"host": "10.0.0.1"}, "not-an-object"]},
        "typo": ["x"],
        "unknown": ["y"],  # key the schema does not declare
        "bareList": ["z"],
        "scalarList": ["w"],
    }
    filled, injected = _inject_absent_list_secrets(
        payload, "seed", op_for(schema)
    )
    assert injected == (
        "radius.servers[].passcode", "radius.servers[].secret",
    )
    element = filled["radius"]["servers"][0]
    assert element["secret"].startswith("drill-")
    assert isinstance(element["passcode"], int)
    assert 10000000 <= element["passcode"] <= 99999999
    assert filled["radius"]["servers"][1] == "not-an-object"
    # Unschematized shapes pass through untouched.
    assert filled["typo"] == ["x"] and filled["unknown"] == ["y"]
    assert filled["bareList"] == ["z"]
    assert filled["scalarList"] == ["w"]


def test_resume_recovery_bookkeeps_the_matched_mapping(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """When the resume's reconcile lookup DOES find the already-restored
    object, the recovered mapping must be recorded (resolver + journal)
    so references stop dying on every future resume."""
    from meraki2tf.restorer import RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            GP_ITEM, ("N_1", "100"), {"groupPolicyId": "100", "name": "kiosk"}
        ),
    )
    plan = plan_restore(graph, parser)

    restorer, _calls = _executor(tmp_path)
    assert restorer.execute(graph, plan).failed == ()
    journal_path = tmp_path / "journal.jsonl"
    lines = [
        line
        for line in journal_path.read_text().splitlines()
        if not ('"kind": "map"' in line and '"old": "100"' in line)
    ]
    journal_path.write_text("\n".join(lines) + "\n")

    restorer2, calls2 = _executor(
        tmp_path,
        responses={"getNetworkGroupPolicies": {"items": [
            {"groupPolicyId": "900", "name": "kiosk"},
        ]}},
    )
    restorer2._journal = RestoreJournal(journal_path)
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        result = restorer2.execute(graph, plan)

    assert result.failed == ()
    assert any(
        "Recovered the missing ID mapping" in r.getMessage()
        for r in caplog.records
    )
    # The recovered mapping is journaled for every future resume.
    assert any(
        '"kind": "map"' in line and '"old": "100"' in line
        and '"new": "900"' in line
        for line in journal_path.read_text().splitlines()
    )
    # Nothing was re-created: the object was matched, not duplicated.
    assert not any(c[0] == "createNetworkGroupPolicy" for c in calls2)


def test_serial_scoped_writes_refuse_foreign_hardware(
    tmp_path: Path,
) -> None:
    """A feature addressed at a serial the snapshot never recorded
    would write to hardware the restore does not own (possibly still
    claimed by production) — refused outright, never dispatched."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            PORT_ITEM, ("Q2ZZ-AAAA-ZZZZ", "1"),
            {"portId": "1", "name": "rogue"},
        ),
    )
    plan = plan_restore(graph, parser)
    restorer, calls = _executor(tmp_path)
    result = restorer.execute(graph, plan)

    reasons = dict(result.failed)
    key = f"{PORT_ITEM}::Q2ZZ-AAAA-ZZZZ,1"
    assert "not recorded in the snapshot" in reasons[key]
    assert "refusing to write to hardware" in reasons[key]
    assert all(c[0] != "updateDeviceSwitchPort" for c in calls)


def test_preset_mappings_resolve_surviving_parents(tmp_path: Path) -> None:
    """Heal-style preset mappings seed the resolver before execution,
    so children of a surviving (never-recreated) parent dispatch at the
    survivor's live ID."""
    from types import SimpleNamespace

    from meraki2tf.models import NetworkGraph as _NetworkGraph
    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _NetworkGraph(
        "org-123", (), (),
        (
            FeatureConfiguration(
                GP_ITEM, ("N_1", "100"),
                {"groupPolicyId": "100", "name": "kiosk"},
            ),
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"),
        preset_mappings=(("network", "N_1", "L_SURV", ()),),
    )
    restorer._client = SimpleNamespace(networks=section)
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    create = next(c for c in calls if c[0] == "createNetworkGroupPolicy")
    assert create[1] == ("L_SURV",)


def test_adoption_survives_a_failed_content_alignment(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Alignment of an adopted counterpart is best-effort: the adopted
    object exists and is mapped, so a failing follow-up PUT downgrades
    to a warning instead of failing the object."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            GP_ITEM, ("N_1", "100"), {"groupPolicyId": "100", "name": "gp"}
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def createNetworkGroupPolicy(self, *args, **kwargs) -> dict:
            self._calls.append(("createNetworkGroupPolicy", args, kwargs))
            raise _conflict_error("'gp' is a reserved name and cannot be used")

        def getNetworkGroupPolicies(self, networkId: str) -> list[dict]:
            self._calls.append(("getNetworkGroupPolicies", (networkId,), {}))
            return [{"groupPolicyId": "901", "name": "gp"}]

        def updateNetworkGroupPolicy(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkGroupPolicy", args, kwargs))
            raise _conflict_error("alignment rejected")

    section = Section(calls)
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl"), skip_claims=True
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section
    )
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        result = restorer.execute(graph, plan)

    assert result.failed == ()  # the adoption stands
    assert f"{GP_ITEM}::N_1,100" in result.executed
    assert any(
        "could not align its content" in r.getMessage()
        for r in caplog.records
    )


def test_dispatch_interlocks_on_a_foreign_resolved_org_scope(
    tmp_path: Path,
) -> None:
    """Whatever the resolver produced, an organization scope other than
    the restore target must never reach the dashboard."""
    from types import SimpleNamespace

    from meraki2tf.models import NetworkGraph as _NetworkGraph
    from meraki2tf.restorer import (
        ForeignScopeError,
        OrgRestorer,
        ReferenceResolver,
        RestoreAction,
        RestoreJournal,
        WAVE_ORG_FEATURES,
    )
    from meraki2tf.spec.engine import OperationSpec

    resolver = ReferenceResolver(_NetworkGraph("org-123", (), (), ()))
    resolver.record("organization", "org-123", "org-OTHER")
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    op = OperationSpec(
        operation_id="updateOrganizationAdmin", method="put",
        path=ADMINS_ITEM, path_params=("organizationId", "adminId"),
        tags=("organizations",),
    )
    action = RestoreAction(
        kind="configure", wave=WAVE_ORG_FEATURES, api_path=ADMINS_ITEM,
        path_values=("org-123", "A_1"), operation=op,
        payload={"name": "Jordan Sample"},
    )
    with pytest.raises(
        ForeignScopeError, match="not the restore target organization"
    ):
        restorer._dispatch(SimpleNamespace(), action, resolver, "org-123")


def test_adoption_lookup_degrades_when_its_scope_cannot_resolve(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A lookup whose scope cannot resolve (journaled-complete parent
    with an unrecovered mapping) degrades to 'collection unreadable'
    instead of aborting the run outside per-action isolation."""
    from types import SimpleNamespace

    from meraki2tf.models import NetworkGraph as _NetworkGraph
    from meraki2tf.restorer import (
        OrgRestorer,
        ReferenceResolver,
        RestoreAction,
        RestoreJournal,
    )
    from meraki2tf.spec.engine import OperationSpec

    resolver = ReferenceResolver(_NetworkGraph("org-123", (), (), ()))
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    lookup = OperationSpec(
        operation_id="getNetworkGroupPolicies", method="get",
        path=GP_COLLECTION, path_params=("networkId",), tags=("networks",),
    )
    action = RestoreAction(
        kind="create", wave=4, api_path=GP_ITEM,
        path_values=("N_1", "100"), operation=lookup,
        payload={"name": "kiosk"}, lookup=lookup,
    )
    with caplog.at_level(logging.DEBUG, logger="meraki2tf.restorer"):
        listing = restorer._list_collection(
            SimpleNamespace(), action, resolver, "org-123"
        )
    assert listing is None
    assert any(
        "could not resolve its scope" in r.getMessage()
        for r in caplog.records
    )


def _firmware_shaping_action() -> object:
    from meraki2tf.restorer import RestoreAction
    from meraki2tf.spec.engine import OperationSpec

    op = OperationSpec(
        operation_id="updateNetworkFirmwareUpgrades", method="put",
        path=FIRMWARE_PATH, path_params=("networkId",), tags=("networks",),
    )
    return RestoreAction(
        kind="configure", wave=4, api_path=FIRMWARE_PATH,
        path_values=("N_1",), operation=op, payload={},
    )


def test_firmware_shaping_passes_through_unshaped_bodies(
    tmp_path: Path,
) -> None:
    """Bodies without the products mapping shape (or with non-mapping
    product configs) pass through untouched — nothing to remap."""
    from types import SimpleNamespace

    restorer, _calls = _executor(tmp_path)
    action = _firmware_shaping_action()
    dashboard = SimpleNamespace()

    body: object = ["not-a-mapping"]
    assert restorer._shape_firmware_upgrades(
        dashboard, action, "N_9", body
    ) == ["not-a-mapping"]
    assert restorer._shape_firmware_upgrades(
        dashboard, action, "N_9", {"products": "n/a"}
    ) == {"products": "n/a"}
    shaped = restorer._shape_firmware_upgrades(
        dashboard, action, "N_9", {"products": {"switch": "n/a"}}
    )
    assert shaped == {"products": {"switch": "n/a"}}


def test_target_firmware_catalog_degrades_on_unreadable_shapes(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Every unreadable catalog shape (no network, no SDK reader, a
    failing read, a non-mapping response) degrades to an empty catalog
    so pending upgrades drop as unmatchable instead of crashing."""
    from types import SimpleNamespace

    restorer, _calls = _executor(tmp_path)

    # A drill without a rebuilt network has no catalog to read.
    assert restorer._target_firmware_catalog(SimpleNamespace(), None) == {}
    # SDK without the reader method.
    assert restorer._target_firmware_catalog(SimpleNamespace(), "N_9") == {}

    class Boom:
        @staticmethod
        def getNetworkFirmwareUpgrades(network_id: str) -> None:
            raise RuntimeError("boom")

    with caplog.at_level(logging.DEBUG, logger="meraki2tf.restorer"):
        assert restorer._target_firmware_catalog(
            SimpleNamespace(networks=Boom()), "N_9"
        ) == {}
    assert any(
        "unreadable" in r.getMessage() for r in caplog.records
    )

    class Listy:
        @staticmethod
        def getNetworkFirmwareUpgrades(network_id: str) -> list:
            return ["not-a-mapping"]

    assert restorer._target_firmware_catalog(
        SimpleNamespace(networks=Listy()), "N_9"
    ) == {}

    class Mixed:
        @staticmethod
        def getNetworkFirmwareUpgrades(network_id: str) -> dict:
            return {"products": {
                "switch": "n/a",  # non-mapping product config: ignored
                "wireless": {"availableVersions": [
                    {"id": 7, "shortName": "MR 31"},
                    "junk",
                    {"shortName": "MR 32"},  # no id: filtered out
                ]},
            }}

    catalog = restorer._target_firmware_catalog(
        SimpleNamespace(networks=Mixed()), "N_9"
    )
    assert catalog == {"wireless": {"MR 31": 7}}


def test_lazy_dashboard_clients_construct_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Restorer and wiper build their SDK client lazily, exactly once,
    with logging suppressed and the key read from the environment."""
    import sys
    import types
    from types import SimpleNamespace

    from meraki2tf.config import API_KEY_ENV_VAR
    from meraki2tf.restorer import OrgRestorer, OrgWiper, RestoreJournal

    dashboard = SimpleNamespace()
    captured: list[dict] = []

    def factory(**kwargs: object) -> SimpleNamespace:
        captured.append(dict(kwargs))
        return dashboard

    stub = types.ModuleType("meraki")
    stub.DashboardAPI = factory  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")

    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    assert restorer._dashboard() is dashboard
    assert restorer._dashboard() is dashboard  # cached, not rebuilt
    wiper = OrgWiper()
    assert wiper._dashboard() is dashboard
    assert len(captured) == 2
    assert all(kw["suppress_logging"] is True for kw in captured)


# ---------------------------------------------------------------------------
# Unsupported-setting 400s: strip the named field(s) and retry.
# ---------------------------------------------------------------------------


def _settings_restorer(tmp_path: Path, section) -> OrgRestorer:
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    return restorer


def test_unsupported_setting_400_strips_named_field_and_retries(
    tmp_path: Path,
) -> None:
    """'Remote status page is not supported by this network' (live
    heal-drill finding, 2026-07-22): GET echoes carry product-type-
    dependent fields the PUT refuses. The named field is dropped and
    the remaining captured state restores."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"remoteStatusPageEnabled": True, "access": "none"},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            if "remoteStatusPageEnabled" in kwargs:
                raise _conflict_error(
                    "Remote status page is not supported by this network"
                )
            return {}

    restorer = _settings_restorer(tmp_path, Section(calls))
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    assert f"{SNMP_PATH}::N_1" in result.executed
    attempts = [c for c in calls if c[0] == "updateNetworkSnmp"]
    assert len(attempts) == 2
    assert attempts[1][2] == {"access": "none"}  # field stripped, rest kept


def test_unsupported_setting_retry_iterates_per_named_field(
    tmp_path: Path,
) -> None:
    """Each retry may surface the NEXT refused field; the loop strips
    one per round until the remainder applies."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"remoteStatusPageEnabled": True,
             "namedVlans": {"enabled": True}, "access": "none"},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            if "remoteStatusPageEnabled" in kwargs:
                raise _conflict_error(
                    "Remote status page is not supported by this network"
                )
            if "namedVlans" in kwargs:
                raise _conflict_error(
                    "Named VLANs are not supported for this network"
                )
            return {}

    restorer = _settings_restorer(tmp_path, Section(calls))
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    attempts = [c for c in calls if c[0] == "updateNetworkSnmp"]
    assert len(attempts) == 3
    assert attempts[2][2] == {"access": "none"}


def test_unsupported_setting_covering_whole_payload_skips(
    tmp_path: Path,
) -> None:
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",), {"remoteStatusPageEnabled": True},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            raise _conflict_error(
                "Remote status page is not supported by this network"
            )

    restorer = _settings_restorer(tmp_path, Section(calls))
    result = restorer.execute(graph, plan)

    assert result.failed == ()
    (entry,) = [
        e for e in result.skipped if e["target"] == f"{SNMP_PATH}::N_1"
    ]
    assert "product types do not support" in entry["reason"]
    assert "remoteStatusPageEnabled" in entry["reason"]
    # Nothing left to write: no retry dispatch happened.
    assert len([c for c in calls if c[0] == "updateNetworkSnmp"]) == 1


def test_unsupported_setting_naming_no_payload_key_still_fails(
    tmp_path: Path,
) -> None:
    """A refused phrase that maps to no payload key cannot be stripped;
    the original failure stands (no blind retry)."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"})
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            raise _conflict_error(
                "Remote status page is not supported by this network"
            )

    restorer = _settings_restorer(tmp_path, Section(calls))
    result = restorer.execute(graph, plan)

    ((key, reason),) = [f for f in result.failed if SNMP_PATH in f[0]]
    assert "Remote status page" in reason
    # Initial attempt + the standing end-of-run salvage retry — but no
    # stripped-payload retry in between (nothing was strippable).
    assert len([c for c in calls if c[0] == "updateNetworkSnmp"]) == 2


def test_unsupported_setting_retry_non_400_keeps_original_error(
    tmp_path: Path,
) -> None:
    """A retry that dies on a different (non-400) error stands down:
    the original 400 is recorded, nothing loops."""
    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            SNMP_PATH, ("N_1",),
            {"remoteStatusPageEnabled": True, "access": "none"},
        )
    )
    plan = plan_restore(graph, parser)
    calls: list = []

    class Section(_RecordingSection):
        def updateNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("updateNetworkSnmp", args, kwargs))
            if "remoteStatusPageEnabled" in kwargs:
                raise _conflict_error(
                    "Remote status page is not supported by this network"
                )
            raise RuntimeError("connection reset mid-retry")

    restorer = _settings_restorer(tmp_path, Section(calls))
    result = restorer.execute(graph, plan)

    ((key, reason),) = [f for f in result.failed if SNMP_PATH in f[0]]
    assert "Remote status page" in reason
    # Initial 400 + one stripped retry (dies non-400, no loop) + the
    # standing end-of-run salvage retry of the original payload.
    assert len([c for c in calls if c[0] == "updateNetworkSnmp"]) == 3


def test_unsupported_setting_key_matcher_edges(tmp_path: Path) -> None:
    from meraki2tf.restorer import (
        OrgRestorer,
        RestoreJournal,
        _unsupported_setting_keys,
    )

    payload = {
        "remoteStatusPageEnabled": True,
        "remoteStatusPage": {"authentication": None},
        "securePort": {"enabled": False},
        "access": "none",
    }
    named = _unsupported_setting_keys(
        "networks, updateNetworkSettings - 400 Bad Request, {'errors': "
        "['Remote status page is not supported by this network']}",
        payload,
    )
    # Both spellings of the family match; unrelated keys never do.
    assert named == ("remoteStatusPageEnabled", "remoteStatusPage")
    assert _unsupported_setting_keys("no refusal here", payload) == ()
    assert _unsupported_setting_keys(
        "Named VLANs are not supported for this network", payload
    ) == ()

    # Defensive loop bound: an empty payload names nothing and the
    # retry helper stands down immediately.
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "j.jsonl")
    )
    action = plan_restore(
        _graph(FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "x"})),
        _restore_spec(tmp_path),
    ).actions[-1]
    from dataclasses import replace as _replace

    empty = _replace(action, payload={})
    assert restorer._retry_without_unsupported(
        None, empty, None, "org-123",
        "Remote status page is not supported by this network",
    ) is None


# ------------------------------------------------- spec verb verification


def _mislabeled_delete(*args: object, **kwargs: object) -> dict:
    """A spec-mislabeled destroyer: self._session.delete(url)."""
    raise AssertionError("a mislabeled SDK method must never be called")


def _as_meraki_method(func):  # noqa: ANN001, ANN201
    clone = __import__("types").FunctionType(
        func.__code__, func.__globals__, func.__name__,
        func.__defaults__, func.__closure__,
    )
    clone.__module__ = "meraki.api.networks"
    return clone


def test_dispatch_refuses_spec_mislabeled_write_methods(
    tmp_path: Path,
) -> None:
    """A poisoned/skewed spec could route a PUT-labeled entry to a
    deleting SDK method; the resolved method's source is verified and
    the action fails closed instead of dispatching."""
    import types as _types

    from meraki2tf.models import NetworkGraph as _NetworkGraph

    parser = _restore_spec(tmp_path)
    graph = _NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["appliance"]}
            ),
        ),
        devices=(),
        features=(
            FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
        ),
    )
    plan = plan_restore(graph, parser)
    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    calls: list = []
    restorer = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "journal.jsonl")
    )
    restorer._client = _types.SimpleNamespace(
        organizations=_RecordingSection(calls),
        networks=_types.SimpleNamespace(
            updateNetworkSnmp=_as_meraki_method(_mislabeled_delete),
        ),
    )
    result = restorer.execute(graph, plan)
    ((key, reason),) = [f for f in result.failed if SNMP_PATH in f[0]]
    assert "put/post" in reason and "refusing to dispatch" in reason
    # The mislabeled method never fired (its body would AssertionError),
    # and the legitimate network create still went through.
    assert any(c[0] == "createOrganizationNetwork" for c in calls)


def test_adoption_lookup_refuses_non_read_only_methods(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A lookup GET that is not verifiably a read is never called; the
    executor proceeds without adoption (worst case one duplicate-create
    failure) instead of invoking a mislabeled mutating method."""
    import types as _types

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(GP_ITEM, ("N_1", "100"), {"name": "kiosk"}),
    )
    plan = plan_restore(graph, parser)
    gp_create = next(a for a in plan.actions if a.api_path == GP_ITEM)
    restorer, calls = _executor(tmp_path)
    restorer._client.networks = _types.SimpleNamespace(
        getNetworkGroupPolicies=_as_meraki_method(_mislabeled_delete),
    )
    from meraki2tf.restorer import ReferenceResolver

    resolver = ReferenceResolver(graph)
    resolver.record("network", "N_1", "L_NEW")
    with caplog.at_level(logging.WARNING):
        listing = restorer._list_collection(
            restorer._client, gp_create, resolver, "org-123"
        )
    assert listing is None
    assert "not verifiably read-only" in caplog.text


# ------------------------------------ liveness probes & second incidents


def _identity_preset() -> tuple:
    """Heal-style identity mapping for the surviving network N_1."""
    return (("network", "N_1", "N_1", ()),)


def _heal_executor(  # noqa: ANN201
    tmp_path: Path,
    section,  # noqa: ANN001
    journal_name: str = "heal.jsonl",
    preset: tuple | None = None,
):
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    restorer = OrgRestorer(
        "org-123", RestoreJournal(tmp_path / journal_name),
        preset_mappings=(
            _identity_preset() if preset is None else preset
        ),
        additive_only=True,
    )
    restorer._client = SimpleNamespace(
        organizations=section, networks=section, wireless=section
    )
    return restorer


def _snmp_plan(tmp_path: Path):  # noqa: ANN201
    from meraki2tf.restorer import RestorePlan

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"})
    )
    full = plan_restore(graph, parser)
    snmp = next(a for a in full.actions if a.api_path == SNMP_PATH)
    return graph, snmp, RestorePlan(actions=(snmp,))


def test_heal_pre_write_verification_skips_alive_settings(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Fix for the additive-only break: a silent discovery gap makes a
    live singleton classify as 'missing'; the pre-write read finds it
    alive and heal must skip instead of PUTting the stale snapshot."""
    from meraki2tf.restorer import HEAL_VERIFIED_ALIVE_REASON

    graph, snmp, plan = _snmp_plan(tmp_path)
    calls: list = []
    section = _RecordingSection(
        calls, responses={"getNetworkSnmp": {"access": "full"}}
    )
    restorer = _heal_executor(tmp_path, section)
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        result = restorer.execute(graph, plan)
    assert result.executed == () and result.failed == ()
    assert result.skipped == (
        {"target": snmp.key, "reason": HEAL_VERIFIED_ALIVE_REASON},
    )
    assert not any(c[0] == "updateNetworkSnmp" for c in calls)
    assert "verified ALIVE" in caplog.text


def test_heal_pre_write_verification_uncertain_is_not_a_license(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from meraki2tf.restorer import HEAL_VERIFY_UNCERTAIN_PREFIX

    graph, snmp, plan = _snmp_plan(tmp_path)
    calls: list = []

    class Section(_RecordingSection):
        def getNetworkSnmp(self, *args, **kwargs) -> dict:
            raise RuntimeError("read failed mid-probe")

    restorer = _heal_executor(tmp_path, Section(calls))
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        result = restorer.execute(graph, plan)
    assert result.executed == () and result.failed == ()
    ((entry,),) = (result.skipped,)
    assert entry["reason"].startswith(HEAL_VERIFY_UNCERTAIN_PREFIX)
    assert not any(c[0] == "updateNetworkSnmp" for c in calls)
    assert "not a license to write" in caplog.text


def test_heal_refuses_unverifiable_surfaces(tmp_path: Path) -> None:
    """No usable GET → additive-only cannot be proven → the action is
    refused and reported, never written blind."""
    from meraki2tf.restorer import RestorePlan

    spec = {
        "openapi": "3.0.0", "info": {"title": "t", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
            SNMP_PATH: {
                "put": _op("updateNetworkSnmp", "networks"),
            },
        },
    }
    path = tmp_path / "no-get-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"})
    )
    snmp = next(
        a
        for a in plan_restore(graph, parser).actions
        if a.api_path == SNMP_PATH
    )
    calls: list = []
    restorer = _heal_executor(tmp_path, _RecordingSection(calls))
    result = restorer.execute(graph, RestorePlan(actions=(snmp,)))
    assert result.executed == ()
    ((key, reason),) = result.failed
    assert key == snmp.key
    assert "additive-only heal refuses" in reason
    assert not any(c[0] == "updateNetworkSnmp" for c in calls)


def test_heal_refuses_non_read_only_probe_methods(tmp_path: Path) -> None:
    """The liveness probe never calls a method that is not verifiably a
    read — the surface is refused as unverifiable instead."""
    from types import SimpleNamespace

    graph, snmp, plan = _snmp_plan(tmp_path)
    calls: list = []
    section = _RecordingSection(calls)
    restorer = _heal_executor(tmp_path, section)
    restorer._client = SimpleNamespace(
        organizations=section,
        networks=SimpleNamespace(
            getNetworkSnmp=_as_meraki_method(_mislabeled_delete),
        ),
    )
    result = restorer.execute(graph, plan)
    ((key, reason),) = result.failed
    assert "additive-only heal refuses" in reason


def test_heal_unverifiable_claim_poisons_its_children(
    tmp_path: Path,
) -> None:
    """An unverifiable create/claim fails AND holds its subtree back,
    exactly like any other failed parent."""
    parser = _restore_spec(tmp_path)  # no devices GET: claims unverifiable
    graph = _graph(
        FeatureConfiguration(
            PORT_ITEM, ("Q2AB-CDEF-GHIJ", "1"), {"portId": "1", "name": "up"}
        )
    )
    full = plan_restore(graph, parser)
    from meraki2tf.restorer import RestorePlan

    actions = tuple(a for a in full.actions if a.wave != WAVE_NETWORKS)
    calls: list = []
    restorer = _heal_executor(tmp_path, _RecordingSection(calls))
    result = restorer.execute(graph, RestorePlan(actions=actions))
    ((key, reason),) = result.failed
    assert "devices/claim" in key and "additive-only heal refuses" in reason
    assert any(
        "parent object Q2AB-CDEF-GHIJ failed" in entry["reason"]
        for entry in result.skipped
    )
    assert not any(c[0] == "updateDeviceSwitchPort" for c in calls)


def test_heal_alive_network_create_adopts_its_identity_mapping(
    tmp_path: Path,
) -> None:
    """A 'missing' network the probe finds alive: skipped, identity
    mapping adopted, and its children heal into the survivor."""
    from meraki2tf.restorer import HEAL_VERIFIED_ALIVE_REASON, RestoreJournal

    class Missing404(Exception):
        status = 404

    calls: list = []

    class Section(_RecordingSection):
        def getNetworkWirelessSsid(self, *args, **kwargs) -> dict:
            raise Missing404("404 not found")

    parser = _restore_spec(tmp_path)
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"]}
            ),
        ),
        devices=(),
        features=(
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"), {"number": 0, "name": "Corp"}
            ),
        ),
    )
    plan = plan_restore(graph, parser)
    section = Section(
        calls,
        responses={
            "getOrganizationNetworks": [{"id": "N_1", "name": "HQ"}],
        },
    )
    restorer = _heal_executor(tmp_path, section, preset=())
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert any(
        e["reason"] == HEAL_VERIFIED_ALIVE_REASON for e in result.skipped
    )
    assert not any(c[0] == "createOrganizationNetwork" for c in calls)
    ssid = next(c for c in calls if c[0] == "updateNetworkWirelessSsid")
    assert ssid[1] == ("N_1", "0")
    assert RestoreJournal(tmp_path / "heal.jsonl").id_map.get("N_1") == "N_1"


def test_heal_second_incident_reexecutes_despite_completed_journal(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Healed Monday, deleted again Friday: Friday's heal must re-write
    the object instead of reporting 'already restored (journal)'."""
    from meraki2tf.restorer import RestoreJournal

    graph, snmp, plan = _snmp_plan(tmp_path)
    journal = RestoreJournal(tmp_path / "heal.jsonl")
    journal.bind(target="org-123", source="org-123")
    journal.record_done(snmp.key)  # Monday's heal

    class Missing404(Exception):
        status = 404

    calls: list = []

    class Section(_RecordingSection):
        def getNetworkSnmp(self, *args, **kwargs) -> dict:
            self._calls.append(("getNetworkSnmp", args, kwargs))
            raise Missing404("404 not found")

    restorer = _heal_executor(tmp_path, Section(calls))
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        result = restorer.execute(graph, plan)
    assert result.executed == (snmp.key,)
    assert any(c[0] == "updateNetworkSnmp" for c in calls)
    assert "re-executing (new incident)" in caplog.text
    # The 404 answer was cached: the journal probe and the pre-write
    # verification shared one paced read.
    assert len([c for c in calls if c[0] == "getNetworkSnmp"]) == 1


def test_heal_journaled_object_still_present_keeps_the_resume_skip(
    tmp_path: Path,
) -> None:
    from meraki2tf.restorer import RestoreJournal

    graph, snmp, plan = _snmp_plan(tmp_path)
    journal = RestoreJournal(tmp_path / "heal.jsonl")
    journal.bind(target="org-123", source="org-123")
    journal.record_done(snmp.key)
    calls: list = []
    section = _RecordingSection(
        calls, responses={"getNetworkSnmp": {"access": "none"}}
    )
    restorer = _heal_executor(tmp_path, section)
    result = restorer.execute(graph, plan)
    assert result.executed == ()
    assert all("already restored" in e["reason"] for e in result.skipped)
    assert not any(c[0] == "updateNetworkSnmp" for c in calls)


def test_heal_alive_create_adopts_the_survivor_mapping(
    tmp_path: Path,
) -> None:
    """A create the probe finds alive is skipped, but its mapping is
    recorded so children rewire to the survivor."""
    from meraki2tf.restorer import (
        HEAL_VERIFIED_ALIVE_REASON,
        RestoreJournal,
        RestorePlan,
    )

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
    full = plan_restore(graph, parser)
    actions = tuple(
        a for a in full.actions if a.api_path in (GP_ITEM, SSID_ITEM)
    )

    class Missing404(Exception):
        status = 404

    calls: list = []

    class Section(_RecordingSection):
        def getNetworkWirelessSsid(self, *args, **kwargs) -> dict:
            raise Missing404("404 not found")

    section = Section(
        calls,
        responses={
            # The 'missing' policy is in fact alive with its identity.
            "getNetworkGroupPolicies": [{"id": "100", "name": "kiosk"}],
        },
    )
    restorer = _heal_executor(tmp_path, section)
    result = restorer.execute(graph, RestorePlan(actions=actions))
    gp_key = next(a.key for a in actions if a.api_path == GP_ITEM)
    assert any(
        e["target"] == gp_key
        and e["reason"] == HEAL_VERIFIED_ALIVE_REASON
        for e in result.skipped
    )
    # The SSID healed and its reference resolved through the adopted
    # identity mapping — never dropped, never re-created.
    ssid = next(c for c in calls if c[0] == "updateNetworkWirelessSsid")
    assert ssid[2]["groupPolicyId"] == "100"
    assert not any(c[0] == "createNetworkGroupPolicy" for c in calls)
    assert RestoreJournal(tmp_path / "heal.jsonl").id_map.get("100") == "100"


def test_heal_children_of_a_recreated_parent_skip_the_probe(
    tmp_path: Path,
) -> None:
    """A child scoped under a parent THIS run minted cannot predate it:
    its liveness probe short-circuits (a freshly recreated network's
    default settings must never read as 'survivors')."""
    parser = _restore_spec(tmp_path)
    graph = NetworkGraph(
        organization_id="org-123",
        networks=(
            MerakiNetwork.from_payload(
                {"id": "N_1", "organizationId": "org-123", "name": "HQ",
                 "productTypes": ["wireless"]}
            ),
        ),
        devices=(),
        features=(
            FeatureConfiguration(
                SSID_ITEM, ("N_1", "0"), {"number": 0, "name": "Corp"}
            ),
        ),
    )
    plan = plan_restore(graph, parser)
    calls: list = []
    section = _RecordingSection(
        calls, responses={"getOrganizationNetworks": []}
    )
    # The network was deleted, so heal presets no identity for it —
    # its create is part of the plan.
    restorer = _heal_executor(tmp_path, section, preset=())
    result = restorer.execute(graph, plan)
    assert result.failed == ()
    assert any(c[0] == "createOrganizationNetwork" for c in calls)
    assert any(c[0] == "updateNetworkWirelessSsid" for c in calls)
    # The SSID's own GET was never consulted: the parent was minted.
    assert not any(c[0] == "getNetworkWirelessSsid" for c in calls)


def test_restore_resume_second_incident_recreates_the_subtree(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A network journaled as restored but deleted from the target
    since: the resume re-creates it (and re-claims its device) instead
    of skipping forever on Monday's journal."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph()
    plan = plan_restore(graph, parser)
    restorer, _calls = _executor(tmp_path)
    assert len(restorer.execute(graph, plan).executed) == 2

    calls2: list = []
    section = _RecordingSection(
        calls2, responses={"getOrganizationNetworks": []}
    )
    again = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "journal.jsonl"),
        serial_map={"Q2AB-CDEF-GHIJ": "Q9ZZ-NEWW-HWSN"},
    )
    again._client = SimpleNamespace(
        organizations=section, networks=section
    )
    with caplog.at_level(logging.WARNING, logger="meraki2tf.restorer"):
        second = again.execute(graph, plan)
    assert len(second.executed) == 2
    assert any(c[0] == "createOrganizationNetwork" for c in calls2)
    claim = next(c for c in calls2 if c[0] == "claimNetworkDevices")
    assert claim[1] == ("L_NEW",)
    assert claim[2] == {"serials": ["Q9ZZ-NEWW-HWSN"]}
    assert "re-executing (new incident)" in caplog.text
    # The stale mapping was retired durably: a reload sees exactly one
    # live mapping for the old network ID.
    reloaded = RestoreJournal(tmp_path / "journal.jsonl")
    rows = [row for row in reloaded.mappings if row[1] == "N_1"]
    assert rows == [("network", "N_1", "L_NEW", ())]


def test_restore_resume_with_unreadable_probe_keeps_the_skip(
    tmp_path: Path,
) -> None:
    """An unreadable liveness probe is not proof of absence: the resume
    keeps the conservative journal skip (the pre-hardening behavior)
    instead of re-creating potential duplicates."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph()
    plan = plan_restore(graph, parser)
    restorer, _calls = _executor(tmp_path)
    assert len(restorer.execute(graph, plan).executed) == 2

    calls2: list = []
    section = _RecordingSection(calls2)  # collection GETs answer {}
    again = OrgRestorer(
        "org-TARGET", RestoreJournal(tmp_path / "journal.jsonl")
    )
    again._client = SimpleNamespace(
        organizations=section, networks=section
    )
    second = again.execute(graph, plan)
    assert second.executed == ()
    assert all("already restored" in e["reason"] for e in second.skipped)
    assert not any(c[0] == "createOrganizationNetwork" for c in calls2)


def test_second_incident_reclaims_missing_devices(tmp_path: Path) -> None:
    """A journaled claim whose device is no longer in the target's
    network re-claims; one still present keeps the resume skip."""
    from types import SimpleNamespace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    spec = {
        "openapi": "3.0.0", "info": {"title": "d", "version": "1"},
        "paths": {
            "/organizations/{organizationId}/networks": {
                "get": _op("getOrganizationNetworks", "organizations"),
                "post": _op("createOrganizationNetwork", "organizations"),
            },
            "/networks/{networkId}/devices": {
                "get": _op("getNetworkDevices", "networks"),
            },
            "/networks/{networkId}/devices/claim": {
                "post": _op("claimNetworkDevices", "networks"),
            },
        },
    }
    path = tmp_path / "devices-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenApiParser(path)
    graph = _graph()
    plan = plan_restore(graph, parser)
    restorer, _calls = _executor(tmp_path)
    assert restorer.execute(graph, plan).failed == ()

    def resume(listings: list) -> tuple:  # noqa: ANN001
        calls: list = []
        section = _RecordingSection(
            calls,
            responses={
                "getOrganizationNetworks": [{"id": "L_NEW", "name": "HQ"}],
                "getNetworkDevices": listings,
            },
        )
        again = OrgRestorer(
            "org-TARGET", RestoreJournal(tmp_path / "journal.jsonl"),
            serial_map={"Q2AB-CDEF-GHIJ": "Q9ZZ-NEWW-HWSN"},
        )
        again._client = SimpleNamespace(
            organizations=section, networks=section
        )
        return again.execute(graph, plan), calls

    removed, calls_removed = resume([])
    claim_key = next(a.key for a in plan.actions if a.kind == "claim")
    assert claim_key in removed.executed
    assert any(c[0] == "claimNetworkDevices" for c in calls_removed)

    present, calls_present = resume([{"serial": "Q9ZZ-NEWW-HWSN"}])
    assert present.executed == ()
    assert not any(c[0] == "claimNetworkDevices" for c in calls_present)


def test_classify_probe_shapes(tmp_path: Path) -> None:
    from dataclasses import replace as _replace

    from meraki2tf.restorer import OrgRestorer, RestoreJournal

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(GP_ITEM, ("N_1", "100"), {"name": "kiosk"}),
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"}),
    )
    plan = plan_restore(graph, parser)
    gp = next(a for a in plan.actions if a.api_path == GP_ITEM)
    snmp = next(a for a in plan.actions if a.api_path == SNMP_PATH)
    claim = next(a for a in plan.actions if a.kind == "claim")
    heal = OrgRestorer(
        "org-123", RestoreJournal(tmp_path / "a.jsonl"), additive_only=True
    )
    rest = OrgRestorer(
        "org-T", RestoreJournal(tmp_path / "b.jsonl"),
        serial_map={"Q2AB-CDEF-GHIJ": "Q9ZZ-NEWW-HWSN"},
    )

    # Claims match by (mapped) serial; a non-list answer is uncertain.
    assert rest._classify_probe(claim, {"nope": 1}) == ("uncertain", None)
    assert rest._classify_probe(
        claim, [{"serial": "Q9ZZ-NEWW-HWSN"}]
    ) == ("alive", None)
    assert rest._classify_probe(claim, []) == ("absent", None)

    # Creates: heal trusts retained identity; items envelopes unwrap.
    assert heal._classify_probe(
        gp, {"items": [{"id": "100", "name": "x"}]}
    ) == ("alive", "100")
    # Restore matches by natural key; ambiguity is never guessed.
    assert rest._classify_probe(
        gp, [{"id": "900", "name": "kiosk"}]
    ) == ("alive", "900")
    assert rest._classify_probe(
        gp, [{"id": "a", "name": "kiosk"}, {"id": "b", "name": "kiosk"}]
    ) == ("uncertain", None)
    assert rest._classify_probe(
        gp, [{"id": "1", "name": "other"}]
    ) == ("absent", None)
    # Keyless payloads: heal can still prove absence (same-org IDs);
    # restore only trusts a client-assigned ID hit.
    bare = _replace(gp, payload={"content": "x"})
    assert heal._classify_probe(bare, [{"id": "999"}]) == ("absent", None)
    assert rest._classify_probe(bare, [{"id": "999"}]) == ("uncertain", None)
    assert rest._classify_probe(bare, [{"id": "100"}]) == ("alive", "100")

    # Configures: empty/none answers are absence, content is life.
    assert rest._classify_probe(snmp, None) == ("absent", None)
    assert rest._classify_probe(snmp, {}) == ("absent", None)
    assert rest._classify_probe(snmp, {"access": "full"}) == ("alive", None)
    assert rest._classify_probe(snmp, []) == ("absent", None)
    assert rest._classify_probe(snmp, "weird") == ("uncertain", None)


def test_probe_liveness_edges(tmp_path: Path) -> None:
    from dataclasses import replace as _replace
    from types import SimpleNamespace

    from meraki2tf.restorer import ReferenceResolver

    parser = _restore_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(SNMP_PATH, ("N_1",), {"access": "none"})
    )
    plan = plan_restore(graph, parser)
    snmp = next(a for a in plan.actions if a.api_path == SNMP_PATH)
    gp_lookup = next(
        a for a in plan.actions if a.wave == WAVE_NETWORKS
    )
    restorer, calls = _executor(tmp_path)
    resolver = ReferenceResolver(graph)
    resolver.record("network", "N_1", "L_NEW")
    dash = restorer._client

    # Minted-parent bypass.
    restorer._minted.add(("network", "N_1"))
    assert restorer._probe_liveness(dash, snmp, resolver, "org-123") == (
        "absent", None,
    )
    restorer._minted.clear()

    # No GET in the spec / no SDK method for it.
    bare = _replace(snmp, lookup=None)
    assert restorer._probe_liveness(dash, bare, resolver, "org-123") == (
        "unverifiable", None,
    )
    hollow = SimpleNamespace(networks=SimpleNamespace())
    assert restorer._probe_liveness(hollow, snmp, resolver, "org-123") == (
        "unverifiable", None,
    )

    # Unresolvable scope: the dispatch path owns deferral.
    fresh = ReferenceResolver(graph)
    assert restorer._probe_liveness(dash, snmp, fresh, "org-123") == (
        "proceed", None,
    )

    # Non-404 read failures are uncertain and never cached.
    class Boom:
        @staticmethod
        def getNetworkSnmp(*args: object, **kwargs: object) -> dict:
            raise RuntimeError("boom")

    boom_dash = SimpleNamespace(networks=Boom())
    assert restorer._probe_liveness(
        boom_dash, snmp, resolver, "org-123"
    ) == ("uncertain", None)

    # Successful reads are cached per resolved scope, and paginated
    # readers are asked for every page.
    class Pager:
        reads = 0

        @staticmethod
        def getNetworkSnmp(
            network_id: str, total_pages: str = "1"
        ) -> dict:
            Pager.reads += 1
            assert total_pages == "all"
            return {"access": "full"}

    pager_dash = SimpleNamespace(networks=Pager())
    assert restorer._probe_liveness(
        pager_dash, snmp, resolver, "org-123"
    ) == ("alive", None)
    assert restorer._probe_liveness(
        pager_dash, snmp, resolver, "org-123"
    ) == ("alive", None)
    assert Pager.reads == 1
    assert gp_lookup.lookup is not None  # network create carries its GET


def test_restore_journal_unmap_round_trips(tmp_path: Path) -> None:
    from meraki2tf.restorer import RestoreJournal

    path = tmp_path / "journal.jsonl"
    journal = RestoreJournal(path)
    journal.record_mapping("old-1", "new-1", scope="network", context=("P",))
    journal.record_mapping("old-1", "new-2", scope="network")
    journal.record_unmap("old-1", "new-1", scope="network")
    assert journal.id_map == {"old-1": "new-2"}
    assert journal.mappings == [("network", "old-1", "new-2", ())]

    reloaded = RestoreJournal(path)
    assert reloaded.id_map == {"old-1": "new-2"}
    assert reloaded.mappings == [("network", "old-1", "new-2", ())]

    journal.record_unmap("old-1", "new-2", scope="network")
    assert journal.id_map == {}
    assert journal.mappings == []
    assert RestoreJournal(path).mappings == []


def test_resolver_recorded_targets() -> None:
    from meraki2tf.models import NetworkGraph as _NetworkGraph
    from meraki2tf.restorer import ReferenceResolver

    resolver = ReferenceResolver(_NetworkGraph("org-123", (), (), ()))
    resolver.record("network", "N_1", "A")
    resolver.record("network", "N_1", "A", ("ctx",))
    resolver.record("network", "N_1", "B")
    assert resolver.recorded_targets("network", "N_1") == ("A", "B")
    assert resolver.recorded_targets("vlan", "9") == ()
