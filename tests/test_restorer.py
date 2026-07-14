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

    payload = {"radius": {"host": "10.0.0.1"}, "servers": [{"a": 1}]}
    filled, injected = _inject_drill_secrets(
        payload,
        ("radius.secret", "servers[].secret", "missing.parent.secret"),
        "seed",
    )
    assert injected == ("radius.secret",)
    assert filled["radius"]["secret"].startswith("drill-")
    assert payload["radius"] == {"host": "10.0.0.1"}  # input untouched
    assert filled["servers"] == [{"a": 1}]  # list slots stay omitted


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
