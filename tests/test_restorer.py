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
