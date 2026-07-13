"""Gap replayer: planning branches, ID remapping, and SDK dispatch."""

import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest
from conftest import _op

from meraki2tf.config import API_KEY_ENV_VAR
from meraki2tf.hcl_generator import (
    CapturedAsset,
    GenerationReport,
    UnsupportedAsset,
)
from meraki2tf.models import (
    UNREADABLE_MARKER,
    FeatureConfiguration,
    MerakiNetwork,
    NetworkGraph,
)
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.replayer import (
    GapReplayer,
    ReplayAction,
    ReplayDispatchError,
    _collection_items,
    _single_array_body_field,
    is_action_log,
    plan_replay,
)
from meraki2tf.sanitizer import REDACTED
from meraki2tf.spec.engine import OperationSpec

VLAN_PATH = "/networks/{networkId}/appliance/vlans/{vlanId}"
SSID_PATH = "/networks/{networkId}/wireless/ssids/{number}"
CLIENTS_PATH = "/networks/{networkId}/clients"


def _graph(*features: FeatureConfiguration, networks=()) -> NetworkGraph:
    return NetworkGraph(
        organization_id="org-123",
        networks=networks,
        devices=(),
        features=features,
    )


def _report(
    captured: tuple[CapturedAsset, ...] = (),
    unsupported: tuple[UnsupportedAsset, ...] = (),
) -> GenerationReport:
    return GenerationReport(
        imports_file=Path("imports.tf"),
        imports_written=0,
        unsupported=unsupported,
        captured=captured,
    )


def _captured(api_path: str, ids: tuple[str, ...], address: str) -> CapturedAsset:
    return CapturedAsset(
        address=address,
        api_path=api_path,
        import_id=",".join(ids),
        already_in_state=False,
        identifiers=ids,
    )


class _FakeSection:
    """SDK section stub recording calls; methods accept **kwargs."""

    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._fail = fail or set()

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)

        def method(**kwargs: Any) -> dict[str, Any]:
            if name in self._fail:
                raise RuntimeError(f"{name} rejected by API")
            self.calls.append((name, kwargs))
            return kwargs

        return method


class _FakeDashboard:
    def __init__(self, networks: list[dict[str, str]], fail: set[str] | None = None):
        self._networks = networks
        self.appliance = _FakeSection(fail)
        self.wireless = _FakeSection(fail)
        self.organizations = types.SimpleNamespace(
            getOrganizationNetworks=lambda org, total_pages: list(self._networks)
        )


def _install_fake_meraki(
    monkeypatch: pytest.MonkeyPatch, dashboard: _FakeDashboard
) -> None:
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")


# ---------------------------------------------------------------- planning


def test_plan_replay_object_with_write_operation(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"id": 10, "name": "Data"})
    )
    report = _report(
        unsupported=(UnsupportedAsset(VLAN_PATH, "no match", ("N_1", "10")),)
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert skipped == ()
    (action,) = actions
    assert action.kind == "object"
    assert action.operation.operation_id == "updateNetworkApplianceVlan"
    assert action.payload == {"id": 10, "name": "Data"}
    assert "meraki_" not in action.target and "updateNetworkApplianceVlan" in action.target


def test_plan_replay_skips_dashboard_only_and_payloadless(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(FeatureConfiguration(CLIENTS_PATH, ("N_1",), {"usage": 1}))
    report = _report(
        unsupported=(
            UnsupportedAsset(CLIENTS_PATH, "no match", ("N_1",)),
            UnsupportedAsset(VLAN_PATH, "no match", ("N_1", "99")),
        )
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    reasons = {item.api_path: item.reason for item in skipped}
    assert "dashboard-only" in reasons[CLIENTS_PATH]
    assert "No payload" in reasons[VLAN_PATH]


def test_plan_replay_skips_unreadable_gap_records(
    spec_parser: OpenApiParser,
) -> None:
    """An endpoint that server-errored at capture recorded no payload —
    there is nothing to write back, only a manual-verification pointer."""
    graph = _graph(
        FeatureConfiguration(
            VLAN_PATH,
            ("N_1", "10"),
            {UNREADABLE_MARKER: "HTTP 500 from the Meraki API after every retry"},
        )
    )
    report = _report(
        unsupported=(UnsupportedAsset(VLAN_PATH, "unreadable", ("N_1", "10")),)
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    (skip,) = skipped
    assert "unreadable at capture" in skip.reason


def test_plan_replay_skips_empty_collection_envelopes(
    spec_parser: OpenApiParser,
) -> None:
    """A paginated GET that returned no items leaves nothing to write."""
    path = "/organizations/{organizationId}/networks"
    graph = _graph(
        FeatureConfiguration(
            path,
            ("org-123",),
            {"items": [], "meta": {"counts": {"items": {"total": 0}}}},
        )
    )
    report = _report(unsupported=(UnsupportedAsset(path, "no match", ("org-123",)),))
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    (skip,) = skipped
    assert "empty at capture" in skip.reason


def test_plan_replay_restores_secrets_from_captured_assets(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(
        FeatureConfiguration(
            SSID_PATH, ("N_1", "0"), {"number": 0, "name": "Corp", "psk": "wifi-secret"}
        ),
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"id": 10, "name": "Data"}),
    )
    report = _report(
        captured=(
            _captured(SSID_PATH, ("N_1", "0"), "meraki_wireless_ssid.n_1_0"),
            _captured(VLAN_PATH, ("N_1", "10"), "meraki_appliance_vlan.n_1_10"),
        )
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert skipped == ()
    (action,) = actions  # the secretless VLAN produces nothing
    assert action.kind == "secrets"
    assert action.address == "meraki_wireless_ssid.n_1_0"
    assert action.payload == {"psk": "wifi-secret"}  # only the secret fields
    assert action.operation.operation_id == "updateNetworkWirelessSsid"
    assert "meraki_wireless_ssid.n_1_0" in action.target


def test_plan_replay_skips_sanitized_and_updateless_secrets(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(
        FeatureConfiguration(SSID_PATH, ("N_1", "0"), {"number": 0, "psk": REDACTED}),
        FeatureConfiguration(CLIENTS_PATH, ("N_1",), {"password": "x"}),
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"id": 10}),
    )
    report = _report(
        captured=(
            _captured(SSID_PATH, ("N_1", "0"), "meraki_wireless_ssid.n_1_0"),
            _captured(CLIENTS_PATH, ("N_1",), "meraki_clients.n_1"),
            # captured without a snapshot payload is silently fine
            _captured(VLAN_PATH, ("N_1", "77"), "meraki_appliance_vlan.n_1_77"),
        )
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    reasons = {item.api_path: item.reason for item in skipped}
    assert "--sanitize" in reasons[SSID_PATH]
    assert "no update operation" in reasons[CLIENTS_PATH]


def test_plan_replay_restores_nested_secrets(
    spec_parser: OpenApiParser,
) -> None:
    """radiusServers[].secret is the most common Meraki secret; a
    top-level-only scan would neither replay it nor report it."""
    graph = _graph(
        FeatureConfiguration(
            SSID_PATH, ("N_1", "0"),
            {"number": 0, "name": "Corp",
             "radiusServers": [{"host": "10.0.0.1", "secret": "radius-secret"}]},
        )
    )
    report = _report(
        captured=(_captured(SSID_PATH, ("N_1", "0"), "meraki_wireless_ssid.n_1_0"),)
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert skipped == ()
    (action,) = actions
    assert action.kind == "secrets"
    # The whole top-level field rides along: the PUT needs the complete
    # sub-structure around the nested secret.
    assert action.payload == {
        "radiusServers": [{"host": "10.0.0.1", "secret": "radius-secret"}]
    }


def test_plan_replay_reports_masked_nested_secrets(
    spec_parser: OpenApiParser,
) -> None:
    """A sanitized snapshot's nested secrets must surface as a skip —
    silence here loses them from the manual re-entry list."""
    graph = _graph(
        FeatureConfiguration(
            SSID_PATH, ("N_1", "0"),
            {"number": 0,
             "radiusServers": [{"host": "10.0.0.1", "secret": REDACTED}]},
        )
    )
    report = _report(
        captured=(_captured(SSID_PATH, ("N_1", "0"), "meraki_wireless_ssid.n_1_0"),)
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    (item,) = skipped
    assert "--sanitize" in item.reason


def test_plan_replay_skips_fully_redacted_objects(
    spec_parser: OpenApiParser,
) -> None:
    graph = _graph(
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"psk": REDACTED})
    )
    report = _report(
        unsupported=(UnsupportedAsset(VLAN_PATH, "no match", ("N_1", "10")),)
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    assert actions == ()
    (item,) = skipped
    assert "unsanitized snapshot" in item.reason


def test_split_redacted_strips_redacted_list_items() -> None:
    from meraki2tf.replayer import split_redacted

    clean, redacted = split_redacted({"chain": [REDACTED, "cert-a"]})
    assert clean == {"chain": ["cert-a"]}
    assert redacted == ("chain[]",)


def test_plan_replay_object_strips_redacted_values(
    spec_parser: OpenApiParser,
) -> None:
    """Gap-object replay from a sanitized snapshot must never write the
    literal redaction marker into the live tenant."""
    graph = _graph(
        FeatureConfiguration(
            VLAN_PATH, ("N_1", "10"),
            {"id": 10, "name": "Data", "certificate": REDACTED},
        )
    )
    report = _report(
        unsupported=(UnsupportedAsset(VLAN_PATH, "no match", ("N_1", "10")),)
    )
    actions, skipped = plan_replay(graph, report, spec_parser)
    (action,) = actions
    assert action.payload == {"id": 10, "name": "Data"}
    (item,) = skipped
    assert "re-enter manually" in item.reason and "certificate" in item.reason


PII_REQUESTS_PATH = "/networks/{networkId}/pii/requests"
SENSOR_COMMANDS_PATH = "/devices/{serial}/sensor/commands"
SPLASH_THEMES_PATH = "/organizations/{organizationId}/splash/themes"
CONTROLLER_MOVES_PATH = "/networks/{networkId}/controller/moves"


def _action_log_spec(tmp_path: Path) -> OpenApiParser:
    """Spec slice with POST-only action logs, a legitimate POST-only
    entity, and a PUT-bearing entity ending in an action-log noun."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "logs", "version": "1"},
        "paths": {
            PII_REQUESTS_PATH: {
                "get": _op("getNetworkPiiRequests", "networks"),
                "post": _op("createNetworkPiiRequest", "networks"),
            },
            SENSOR_COMMANDS_PATH: {
                "get": _op("getDeviceSensorCommands", "sensor"),
                "post": _op("createDeviceSensorCommand", "sensor"),
            },
            SPLASH_THEMES_PATH: {
                "get": _op("getOrganizationSplashThemes", "organizations"),
                "post": _op("createOrganizationSplashTheme", "organizations"),
            },
            CONTROLLER_MOVES_PATH: {
                "get": _op("getNetworkControllerMoves", "networks"),
                "put": _op("updateNetworkControllerMoves", "networks"),
            },
        },
    }
    path = tmp_path / "action-log-spec.json"
    path.write_text(json.dumps(spec), encoding="utf-8")
    return OpenApiParser(path)


def test_plan_replay_never_replays_action_logs(tmp_path: Path) -> None:
    """POST-only action logs record executed operations; re-POSTing a
    snapshot entry re-executes it (a captured PII delete request would
    re-trigger real data deletion, sensor commands reboot hardware).
    They surface as skipped-with-reason, never as planned writes."""
    parser = _action_log_spec(tmp_path)
    graph = _graph(
        FeatureConfiguration(
            PII_REQUESTS_PATH, ("N_1",),
            {"items": [{"id": "1", "type": "delete"}], "meta": {}},
        ),
        FeatureConfiguration(
            SENSOR_COMMANDS_PATH, ("Q2XX-AAAA-BBBB",),
            {"items": [{"operation": "cycleDownstreamPower"}], "meta": {}},
        ),
        FeatureConfiguration(
            SPLASH_THEMES_PATH, ("org-123",), {"name": "Corp Theme"}
        ),
        FeatureConfiguration(
            CONTROLLER_MOVES_PATH, ("N_1",), {"status": "complete"}
        ),
    )
    report = _report(
        unsupported=(
            UnsupportedAsset(PII_REQUESTS_PATH, "no match", ("N_1",)),
            UnsupportedAsset(
                SENSOR_COMMANDS_PATH, "no match", ("Q2XX-AAAA-BBBB",)
            ),
            UnsupportedAsset(SPLASH_THEMES_PATH, "no match", ("org-123",)),
            UnsupportedAsset(CONTROLLER_MOVES_PATH, "no match", ("N_1",)),
        )
    )
    actions, skipped = plan_replay(graph, report, parser)
    reasons = {item.api_path: item.reason for item in skipped}
    assert "re-execute" in reasons[PII_REQUESTS_PATH]
    assert "re-execute" in reasons[SENSOR_COMMANDS_PATH]
    planned = {action.api_path for action in actions}
    assert PII_REQUESTS_PATH not in planned
    assert SENSOR_COMMANDS_PATH not in planned
    # Legitimate POST-only entities (splash themes, networks, camera
    # artifacts) still replay; a PUT-bearing entity ending in an
    # action-log noun is unaffected by the guard.
    assert planned == {SPLASH_THEMES_PATH, CONTROLLER_MOVES_PATH}


def test_is_action_log_is_gated_on_the_absence_of_a_put() -> None:
    post = OperationSpec(
        operation_id="createNetworkPiiRequest", method="post",
        path=PII_REQUESTS_PATH, path_params=("networkId",),
        tags=("networks",),
    )
    put = OperationSpec(
        operation_id="updateNetworkControllerMoves", method="put",
        path=CONTROLLER_MOVES_PATH, path_params=("networkId",),
        tags=("networks",),
    )
    assert is_action_log(PII_REQUESTS_PATH, (post,)) is True
    # Item paths resolve through their collection's writes.
    assert is_action_log(PII_REQUESTS_PATH + "/{requestId}", (post,)) is True
    # A PUT anywhere on the entity means configuration, not a log.
    assert is_action_log(CONTROLLER_MOVES_PATH, (put, post)) is False
    # Non-log terminal nouns never match.
    assert is_action_log(
        "/organizations/{organizationId}/networks", (post,)
    ) is False


def test_plan_replay_threads_the_collection_lookup_for_post_only_creates(
    spec_parser: OpenApiParser,
) -> None:
    """POST-only creates carry the collection GET so a retried replay
    can skip objects an earlier partially-failed run already created;
    PUT-backed objects need no lookup (updates are idempotent)."""
    networks_path = "/organizations/{organizationId}/networks"
    graph = _graph(
        FeatureConfiguration(networks_path, ("org-123",), {"name": "HQ"}),
        FeatureConfiguration(VLAN_PATH, ("N_1", "10"), {"id": 10, "name": "Data"}),
    )
    report = _report(
        unsupported=(
            UnsupportedAsset(networks_path, "no match", ("org-123",)),
            UnsupportedAsset(VLAN_PATH, "no match", ("N_1", "10")),
        )
    )
    actions, _ = plan_replay(graph, report, spec_parser)
    by_path = {action.api_path: action for action in actions}
    create = by_path[networks_path]
    assert create.operation.method == "post"
    assert create.lookup is not None
    assert create.lookup.operation_id == "getOrganizationNetworks"
    assert by_path[VLAN_PATH].lookup is None


# ------------------------------------------------------------- id mapping


def test_network_id_map_prefers_identity_then_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dashboard = _FakeDashboard(
        networks=[{"id": "N_1", "name": "HQ"}, {"id": "N_9", "name": "Branch"}]
    )
    _install_fake_meraki(monkeypatch, dashboard)
    graph = _graph(
        networks=(
            MerakiNetwork("N_1", "org-123", "HQ", ()),
            MerakiNetwork("N_2", "org-123", "Branch", ()),
            MerakiNetwork("N_3", "org-123", "Ghost", ()),
        )
    )
    mapping = GapReplayer().network_id_map("org-123", graph)
    assert mapping == {"N_1": "N_1", "N_2": "N_9"}  # N_3 stays unmapped


def test_network_id_map_covers_config_templates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Template-held features address the template ID as a
    ``{networkId}`` scope, so the map must cover config templates too —
    identity first, then name, unmapped otherwise (refuse-to-guess)."""
    from meraki2tf.providers.live import CONFIG_TEMPLATE_ITEM_PATH

    dashboard = _FakeDashboard(networks=[{"id": "N_1", "name": "HQ"}])
    dashboard.organizations.getOrganizationConfigTemplates = lambda org: [
        {"id": "T_1", "name": "Kept"},
        {"id": "T_NEW", "name": "Branch Template"},
    ]
    _install_fake_meraki(monkeypatch, dashboard)
    graph = _graph(
        FeatureConfiguration(
            CONFIG_TEMPLATE_ITEM_PATH, ("org-123", "T_1"),
            {"id": "T_1", "name": "Kept"},
        ),
        FeatureConfiguration(
            CONFIG_TEMPLATE_ITEM_PATH, ("org-123", "T_2"),
            {"id": "T_2", "name": "Branch Template"},
        ),
        FeatureConfiguration(
            CONFIG_TEMPLATE_ITEM_PATH, ("org-123", "T_3"),
            {"id": "T_3", "name": "Ghost"},
        ),
        networks=(MerakiNetwork("N_1", "org-123", "HQ", ()),),
    )
    mapping = GapReplayer().network_id_map("org-123", graph)
    assert mapping == {"N_1": "N_1", "T_1": "T_1", "T_2": "T_NEW"}


def test_network_id_map_warns_without_a_template_reader(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An SDK without the template listing leaves template scopes
    unmapped — their replays are refused loudly, never guessed."""
    from meraki2tf.providers.live import CONFIG_TEMPLATE_ITEM_PATH

    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    graph = _graph(
        FeatureConfiguration(
            CONFIG_TEMPLATE_ITEM_PATH, ("org-123", "T_1"), {"name": "X"}
        )
    )
    mapping = GapReplayer().network_id_map("org-123", graph)
    assert mapping == {}
    assert "template-scoped replays will be refused" in caplog.text


def test_execute_reaches_template_scoped_targets(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    """A template-scoped write dispatches at the LIVE template ID once
    the map covers it (regression: it was always refused)."""
    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    executed, failed = GapReplayer().execute(
        (_vlan_action(spec_parser, network="T_1"),),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={"T_1": "T_NEW"},
    )
    assert failed == ()
    assert len(executed) == 1
    assert dashboard.appliance.calls[0][1]["networkId"] == "T_NEW"


# -------------------------------------------------------------- execution


def _vlan_action(spec_parser: OpenApiParser, network: str = "N_2") -> ReplayAction:
    op = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "updateNetworkApplianceVlan"
    )
    return ReplayAction(
        kind="object",
        api_path=VLAN_PATH,
        path_values=(network, "10"),
        payload={"id": 10, "name": "Data", "networkId": "N_2"},
        operation=op,
    )


def test_execute_remaps_ids_and_prefers_path_params(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    executed, failed = GapReplayer().execute(
        (_vlan_action(spec_parser),),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={"N_2": "N_9"},
    )
    assert failed == ()
    assert len(executed) == 1
    (name, kwargs) = dashboard.appliance.calls[0]
    assert name == "updateNetworkApplianceVlan"
    assert kwargs["networkId"] == "N_9"  # remapped path parameter wins
    assert kwargs["vlanId"] == "10"
    assert kwargs["name"] == "Data"
    assert kwargs["id"] == 10  # payload field that is not a path param


def test_execute_isolates_failures_per_action(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    dashboard = _FakeDashboard(networks=[], fail={"updateNetworkApplianceVlan"})
    _install_fake_meraki(monkeypatch, dashboard)
    ssid_op = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "updateNetworkWirelessSsid"
    )
    ssid = ReplayAction(
        kind="secrets",
        api_path=SSID_PATH,
        path_values=("N_2", "0"),
        payload={"psk": "wifi-secret"},
        operation=ssid_op,
        address="meraki_wireless_ssid.n_2_0",
    )
    executed, failed = GapReplayer().execute(
        (_vlan_action(spec_parser), ssid),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={"N_2": "N_9"},
    )
    assert len(failed) == 1 and "rejected by API" in failed[0][1]
    assert len(executed) == 1  # the SSID still went through
    assert dashboard.wireless.calls[0][1]["psk"] == "wifi-secret"
    assert "wifi-secret" not in failed[0][0]  # targets carry no values


def test_execute_withholds_error_detail_for_secret_bearing_objects(
    monkeypatch: pytest.MonkeyPatch,
    spec_parser: OpenApiParser,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """kind == "object" payloads carry live secret values too
    (split_redacted keeps secret-named attributes); a failed write's
    SDK error can echo them back and must be withheld exactly like a
    secrets-kind failure."""

    class EchoingSection:
        @staticmethod
        def updateNetworkWirelessSsid(**kwargs: Any) -> None:
            raise RuntimeError(f"psk {kwargs.get('psk')!r} was rejected")

    dashboard = types.SimpleNamespace(wireless=EchoingSection())
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")

    ssid_op = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "updateNetworkWirelessSsid"
    )
    action = ReplayAction(
        kind="object",  # a gap object, not a secrets restoration
        api_path=SSID_PATH,
        path_values=("N_2", "0"),
        payload={"number": 0, "name": "Corp", "psk": "hunter2"},
        operation=ssid_op,
    )
    executed, failed = GapReplayer().execute(
        (action,),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={"N_2": "N_9"},
    )
    assert executed == ()
    ((_, message),) = failed
    assert "hunter2" not in message
    assert "detail withheld" in message
    assert "hunter2" not in caplog.text


def test_execute_keeps_dispatch_error_text_for_secret_payloads(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    """ReplayDispatchError text is ours (value-free by construction);
    withholding it would hide the actionable refusal reason."""
    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    ssid_op = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "updateNetworkWirelessSsid"
    )
    action = ReplayAction(
        kind="object",
        api_path=SSID_PATH,
        path_values=("N_GONE", "0"),
        payload={"psk": "hunter2"},
        operation=ssid_op,
    )
    executed, failed = GapReplayer().execute(
        (action,),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={},
    )
    assert executed == ()
    ((_, message),) = failed
    assert "no live counterpart" in message
    assert "hunter2" not in message


# --------------------------------------------------- replay idempotency


def _networks_create_action(
    spec_parser: OpenApiParser, name: str
) -> ReplayAction:
    create = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "createOrganizationNetwork"
    )
    lookup = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "getOrganizationNetworks"
    )
    return ReplayAction(
        kind="object",
        api_path="/organizations/{organizationId}/networks",
        path_values=("org-123",),
        payload={"name": name},
        operation=create,
        lookup=lookup,
    )


class _IdempotencySection:
    """Org section with a listable collection and a recording create."""

    def __init__(self, existing: list[dict[str, str]] | Exception) -> None:
        self.calls: list[tuple[str, Any]] = []
        self._existing = existing

    def getOrganizationNetworks(
        self, organizationId: str, total_pages: str = "all"
    ) -> list[dict[str, str]]:
        self.calls.append(("getOrganizationNetworks", organizationId))
        if isinstance(self._existing, Exception):
            raise self._existing
        return list(self._existing)

    def createOrganizationNetwork(
        self, organizationId: str, **kwargs: Any
    ) -> dict[str, Any]:
        self.calls.append(("createOrganizationNetwork", kwargs))
        return {"id": "L_NEW", **kwargs}


def _run_idempotency(
    monkeypatch: pytest.MonkeyPatch,
    section: _IdempotencySection,
    actions: tuple[ReplayAction, ...],
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    dashboard = types.SimpleNamespace(organizations=section)
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")
    return GapReplayer().execute(
        actions,
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={},
    )


def test_execute_skips_post_only_creates_that_already_exist(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    """A --replay-gaps --confirm retry after a partial failure must not
    duplicate every object that already succeeded: same-named items in
    the collection are skipped with a reason, never re-POSTed."""
    section = _IdempotencySection(existing=[{"id": "L_1", "name": "HQ"}])
    executed, failed = _run_idempotency(
        monkeypatch,
        section,
        (
            _networks_create_action(spec_parser, "HQ"),
            _networks_create_action(spec_parser, "Branch"),
        ),
    )
    assert failed == ()
    creates = [c for c in section.calls if c[0] == "createOrganizationNetwork"]
    assert creates == [("createOrganizationNetwork", {"name": "Branch"})]
    # Both actions stay accounted for — one write, one labeled skip.
    assert len(executed) == 2
    assert sum(
        entry.endswith("[already present; skipped]") for entry in executed
    ) == 1


def test_already_present_lookup_failures_fall_back_to_the_create(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    """An unreadable collection keeps today's behavior — the POST fires
    and, worst case, the API rejects one duplicate per object."""
    section = _IdempotencySection(existing=RuntimeError("listing exploded"))
    executed, failed = _run_idempotency(
        monkeypatch, section, (_networks_create_action(spec_parser, "HQ"),)
    )
    assert failed == ()
    assert len(executed) == 1
    assert any(c[0] == "createOrganizationNetwork" for c in section.calls)


def test_already_present_needs_a_lookup_and_a_name(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    """No collection GET or no name-like attribute → current behavior."""
    import dataclasses

    section = _IdempotencySection(existing=[{"id": "L_1", "name": "HQ"}])
    no_lookup = dataclasses.replace(
        _networks_create_action(spec_parser, "HQ"), lookup=None
    )
    nameless = dataclasses.replace(
        _networks_create_action(spec_parser, "HQ"), payload={"timeZone": "UTC"}
    )
    executed, failed = _run_idempotency(
        monkeypatch, section, (no_lookup, nameless)
    )
    assert failed == ()
    creates = [c for c in section.calls if c[0] == "createOrganizationNetwork"]
    assert len(creates) == 2  # both POSTed, no lookup consulted for them
    assert all("already present" not in entry for entry in executed)


def test_already_present_edge_branches(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    """A lookup the write's parameters cannot satisfy, or an SDK
    without the lookup method, proceeds with the create."""
    import dataclasses

    section = _IdempotencySection(existing=[{"id": "L_1", "name": "HQ"}])
    dashboard = types.SimpleNamespace(organizations=section)
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")

    replayer = GapReplayer()
    action = _networks_create_action(spec_parser, "HQ")
    params = {"organizationId": "org-999"}
    assert replayer._already_present(action, params) is True

    vlans_lookup = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "getNetworkApplianceVlans"
    )
    mismatched = dataclasses.replace(action, lookup=vlans_lookup)
    assert replayer._already_present(mismatched, params) is False

    assert action.lookup is not None
    sectionless = dataclasses.replace(
        action, lookup=dataclasses.replace(action.lookup, tags=("nowhere",))
    )
    assert replayer._already_present(sectionless, params) is False


def test_already_present_unwraps_envelope_listings(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    section = _IdempotencySection(existing=[])

    def envelope(organizationId: str, total_pages: str = "all") -> dict:
        section.calls.append(("getOrganizationNetworks", organizationId))
        return {"items": [{"id": "L_1", "name": "HQ"}], "meta": {}}

    section.getOrganizationNetworks = envelope  # type: ignore[method-assign]
    executed, failed = _run_idempotency(
        monkeypatch, section, (_networks_create_action(spec_parser, "HQ"),)
    )
    assert failed == ()
    assert all(c[0] != "createOrganizationNetwork" for c in section.calls)
    assert any("already present; skipped" in entry for entry in executed)


def test_execute_refuses_unmapped_network(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    executed, failed = GapReplayer().execute(
        (_vlan_action(spec_parser, network="N_GONE"),),
        target_organization_id="org-999",
        snapshot_organization_id="org-123",
        network_ids={"N_2": "N_9"},
    )
    assert executed == ()
    assert "no live counterpart" in failed[0][1]
    assert dashboard.appliance.calls == []


def test_parameters_rejects_arity_and_unknown_placeholders(
    spec_parser: OpenApiParser,
) -> None:
    action = _vlan_action(spec_parser)
    broken = ReplayAction(
        kind="object",
        api_path=VLAN_PATH,
        path_values=("N_2",),  # one value for two placeholders
        payload={},
        operation=action.operation,
    )
    with pytest.raises(ReplayDispatchError, match="parameter"):
        GapReplayer._parameters(broken, "org", "org-123", {})

    device_op = next(
        op for op in spec_parser.endpoints() if op.operation_id == "updateDevice"
    )
    foreign = ReplayAction(
        kind="object",
        api_path=VLAN_PATH,
        path_values=("N_2", "10"),
        payload={},
        operation=device_op,  # needs {serial}, which a VLAN cannot supply
    )
    with pytest.raises(ReplayDispatchError, match="serial"):
        GapReplayer._parameters(foreign, "org", "org-123", {"N_2": "N_9"})


def test_parameters_refuse_serial_not_claimed_in_target(
    spec_parser: OpenApiParser,
) -> None:
    """A device-scoped write must never fire at a serial that is not
    verifiably claimed in the target org — the device would be addressed
    wherever it is currently claimed (possibly production)."""
    device_op = next(
        op for op in spec_parser.endpoints() if op.operation_id == "updateDevice"
    )
    action = ReplayAction(
        kind="object",
        api_path="/devices/{serial}",
        path_values=("Q2XX-AAAA-BBBB",),
        payload={"name": "edge"},
        operation=device_op,
    )
    # No claimed-serial set available → refuse rather than write blind.
    with pytest.raises(ReplayDispatchError, match="Cannot verify device"):
        GapReplayer._parameters(action, "org-1", "org-123", {}, None)
    # Serial absent from the target's claimed set → refuse.
    with pytest.raises(ReplayDispatchError, match="not claimed"):
        GapReplayer._parameters(
            action, "org-1", "org-123", {}, frozenset({"Q2XX-OTHER"})
        )
    # Serial present → allowed through.
    params = GapReplayer._parameters(
        action, "org-1", "org-123", {}, frozenset({"Q2XX-AAAA-BBBB"})
    )
    assert params == {"serial": "Q2XX-AAAA-BBBB"}


def test_secret_paths_detects_secret_keyed_string_lists_and_numbers() -> None:
    from meraki2tf.replayer import _secret_paths

    paths = _secret_paths(
        {
            "communityStrings": ["c1", "c2"],
            "passcode": 4321,
            "radiusServers": [{"host": "h", "secret": "r1"}],
            "passwordEnabled": True,  # a flag, never a secret
            "emptyPsk": "",
        }
    )
    assert "communityStrings[]" in paths
    assert "passcode" in paths
    assert "radiusServers[].secret" in paths
    assert not any("passwordEnabled" in p for p in paths)
    assert not any("emptyPsk" in p for p in paths)


def test_secret_paths_flags_pem_private_keys_by_value() -> None:
    """The sanitizer redacts PEM private-key blocks under any key
    (certificate payloads carry RADSEC/custom-cert keypairs); the
    error-suppression side must agree on what counts as a secret."""
    from meraki2tf.replayer import _secret_paths

    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
    paths = _secret_paths(
        {
            "certificate": pem,
            "chain": ["cert-only-material", pem],
            "nested": {"contents": pem},
            "publicCertificate": "-----BEGIN CERTIFICATE-----\nMIIB...",
        }
    )
    assert "certificate" in paths
    assert "chain[]" in paths
    assert "nested.contents" in paths
    # Public certificate material is not a secret.
    assert not any("publicCertificate" in p for p in paths)


def test_parameters_injects_organization_for_org_scoped_writes(
    spec_parser: OpenApiParser,
) -> None:
    create = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "createOrganizationNetwork"
    )
    action = ReplayAction(
        kind="object",
        api_path="/organizations/{organizationId}/networks",
        path_values=("org-123",),
        payload={"name": "HQ"},
        operation=create,
    )
    params = GapReplayer._parameters(action, "org-999", "org-123", {})
    assert params == {"organizationId": "org-999"}  # snapshot org remapped


def test_parameters_refuse_writes_into_a_foreign_organization(
    spec_parser: OpenApiParser,
) -> None:
    """Defense in depth: when the recorded org value does not remap to
    the target (mis-wired snapshot org), the write is refused rather
    than dispatched into a foreign — possibly production — org."""
    create = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "createOrganizationNetwork"
    )
    action = ReplayAction(
        kind="object",
        api_path="/organizations/{organizationId}/networks",
        path_values=("org-123",),
        payload={"name": "HQ"},
        operation=create,
    )
    with pytest.raises(ReplayDispatchError, match="foreign organization"):
        GapReplayer._parameters(action, "org-999", "org-777", {})


def test_call_filters_body_to_explicit_signatures(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    calls: list[dict[str, Any]] = []

    class StrictSection:
        @staticmethod
        def updateNetworkApplianceVlan(
            networkId: str, vlanId: str, name: str = ""
        ) -> None:
            calls.append({"networkId": networkId, "vlanId": vlanId, "name": name})

    dashboard = types.SimpleNamespace(appliance=StrictSection())
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")

    action = _vlan_action(spec_parser)
    replayer = GapReplayer()
    replayer._call(
        action.operation,
        {"networkId": "N_9", "vlanId": "10"},
        {"id": 10, "name": "Data"},  # "id" is not in the strict signature
    )
    assert calls == [{"networkId": "N_9", "vlanId": "10", "name": "Data"}]


def _staged_stages_op() -> OperationSpec:
    """A write op whose body is a single array field, like the real
    updateNetworkFirmwareUpgradesStagedStages."""
    return OperationSpec(
        operation_id="updateNetworkFirmwareUpgradesStagedStages",
        method="put",
        path="/networks/{networkId}/firmwareUpgrades/staged/stages",
        path_params=("networkId",),
        tags=("networks",),
        raw={
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "_json": {"type": "array", "items": {}}
                            },
                        }
                    }
                }
            }
        },
    )


def test_call_maps_collection_envelope_to_array_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    section = _FakeSection()
    dashboard = types.SimpleNamespace(networks=section)
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")

    GapReplayer()._call(
        _staged_stages_op(),
        {"networkId": "N_9"},
        {"items": [{"group": {"id": "-1", "description": None}}]},
    )
    (name, kwargs) = section.calls[0]
    assert name == "updateNetworkFirmwareUpgradesStagedStages"
    # envelope unwrapped onto the spec's array field, nulls stripped
    assert kwargs["_json"] == [{"group": {"id": "-1"}}]
    assert "items" not in kwargs


def test_call_strips_null_payload_fields(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    """GET echoes unset fields as null; write endpoints reject them."""
    dashboard = _FakeDashboard(networks=[])
    _install_fake_meraki(monkeypatch, dashboard)
    op = next(
        o
        for o in spec_parser.endpoints()
        if o.operation_id == "updateNetworkApplianceVlan"
    )
    GapReplayer()._call(
        op,
        {"networkId": "N_9", "vlanId": "10"},
        {"name": "Data", "description": None, "nested": [{"x": None, "y": 1}]},
    )
    (_, kwargs) = dashboard.appliance.calls[0]
    assert kwargs["name"] == "Data"
    assert "description" not in kwargs
    assert kwargs["nested"] == [{"y": 1}]


def test_collection_and_array_body_helpers_reject_non_matches() -> None:
    # a real object payload that merely has an "items" key is no envelope
    assert _collection_items({"items": [], "name": "x"}) is None
    assert _collection_items({"name": "x"}) is None
    assert _collection_items({"items": ["a"], "meta": {}}) == ["a"]
    # multi-property or non-array bodies never get the envelope mapping
    multi = OperationSpec(
        operation_id="op", method="put", path="/p", path_params=(),
        tags=("t",),
        raw={
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {
                            "properties": {
                                "a": {"type": "array"},
                                "b": {"type": "string"},
                            }
                        }
                    }
                }
            }
        },
    )
    assert _single_array_body_field(multi) is None
    scalar = OperationSpec(
        operation_id="op", method="put", path="/p", path_params=(),
        tags=("t",),
        raw={
            "requestBody": {
                "content": {
                    "application/json": {
                        "schema": {"properties": {"name": {"type": "string"}}}
                    }
                }
            }
        },
    )
    assert _single_array_body_field(scalar) is None
    assert _single_array_body_field(_staged_stages_op()) == "_json"


def test_call_raises_on_missing_sdk_method(
    monkeypatch: pytest.MonkeyPatch, spec_parser: OpenApiParser
) -> None:
    dashboard = types.SimpleNamespace()  # no sections at all
    stub = types.ModuleType("meraki")
    stub.DashboardAPI = lambda **kwargs: dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-key")
    op = next(
        op
        for op in spec_parser.endpoints()
        if op.operation_id == "updateNetworkApplianceVlan"
    )
    with pytest.raises(ReplayDispatchError, match="no method"):
        GapReplayer()._call(op, {}, {})
