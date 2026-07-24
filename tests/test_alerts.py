"""Alert payload contracts, webhook/email transports, dispatcher fan-out."""

import json
import urllib.request
from email.message import EmailMessage
from typing import Any

import pytest

from meraki2tf.alerts import (
    AlertDispatcher,
    AlertEvent,
    EmailConfigError,
    EmailNotifier,
    EventSeverity,
    EventType,
    Notifier,
    PagerDutyConfigError,
    PagerDutyDeliveryError,
    PagerDutyNotifier,
    WebhookConfigError,
    WebhookDeliveryError,
    WebhookNotifier,
    deletion_pending_confirmation,
    drift_detected,
    processing_fault,
    run_success,
    unsupported_feature_flagged,
)
from meraki2tf.alerts import pagerduty as pagerduty_module
from meraki2tf.alerts import webhook as webhook_module
from meraki2tf.alerts.email import (
    SMTP_PASSWORD_ENV_VAR,
    SMTP_USERNAME_ENV_VAR,
    _default_smtp_factory,
)
from meraki2tf.alerts.formats import render_payload
from meraki2tf.alerts.pagerduty import ROUTING_KEY_ENV_VAR


class RecordingNotifier(Notifier):
    channel = "recording"

    def __init__(self) -> None:
        self.events: list[AlertEvent] = []

    def send(self, event: AlertEvent) -> None:
        self.events.append(event)


class ExplodingNotifier(Notifier):
    channel = "exploding"

    def send(self, event: AlertEvent) -> None:
        raise ConnectionError("endpoint unreachable")


def test_drift_detected_payload_contract() -> None:
    payload = drift_detected(diff="~ plan delta", workspace="generated").to_payload()
    assert payload["event_type"] == "DRIFT_DETECTED"
    assert payload["severity"] == EventSeverity.WARNING.value
    assert payload["details"] == {
        "diff": "~ plan delta",
        "workspace": "generated",
        "origin": "terraform-plan",
        "apply_aborted": False,
        "regenerated_addresses": [],
        "deferred_addresses": [],
        "unsupported_count": 0,
        "unsupported": [],
    }


def test_drift_alert_carries_unsupported_list_and_abort_marker() -> None:
    """Contract: drift notifications always carry the manual-rebuild list,
    and an aborted sync auto-apply is flagged for human review."""
    unsupported = [
        {"api_path": "/x", "reason": "no mapping", "identifiers": ["N_1"]}
    ]
    event = drift_detected(
        diff="~ delta",
        workspace="generated",
        unsupported=unsupported,
        apply_aborted=True,
        regenerated_addresses=["meraki_networks.n_1"],
    )
    assert "aborted" in event.summary
    details = event.to_payload()["details"]
    assert details["apply_aborted"] is True
    assert details["unsupported_count"] == 1
    assert details["unsupported"] == unsupported
    assert details["regenerated_addresses"] == ["meraki_networks.n_1"]


def test_run_success_payload_contract() -> None:
    payload = run_success(
        imports_written=4,
        drift_was_detected=True,
        workspace="generated",
        discovered_assets=10,
        imports_already_tracked=5,
        unsupported=[{"api_path": "/x", "reason": "r", "identifiers": []}],
        pending_imports=4,
        comparison_performed=True,
        resources_added_to_state=["meraki_networks.n_1"],
        coverage_percent=90.0,
        deletions_pending=["meraki_devices.q2ab"],
        unmanaged_secret_attributes={"meraki_wireless_ssid.s_0": ("psk",)},
        reconciliation_drop_categories={"Invalid Attribute Value Match": 2},
    ).to_payload()
    assert payload["event_type"] == "RUN_SUCCESS"
    assert payload["severity"] == EventSeverity.INFO.value
    assert payload["details"] == {
        "imports_written": 4,
        "drift_was_detected": True,
        "workspace": "generated",
        "discovered_assets": 10,
        "imports_already_tracked": 5,
        "unsupported_count": 1,
        "unsupported": [{"api_path": "/x", "reason": "r", "identifiers": []}],
        "pending_imports": 4,
        "comparison_performed": True,
        "resources_added_to_state": ["meraki_networks.n_1"],
        "coverage_percent": 90.0,
        "deletions_pending_confirmation": ["meraki_devices.q2ab"],
        "unmanaged_secret_attribute_count": 1,
        "unmanaged_secret_attributes": {"meraki_wireless_ssid.s_0": ["psk"]},
        "deferred_addresses": [],
        "reconciliation_drop_categories": {
            "Invalid Attribute Value Match": 2
        },
        "partial_scope": [],
    }
    assert "1 resource(s) added to state" in run_success(
        imports_written=4,
        drift_was_detected=False,
        workspace="w",
        discovered_assets=1,
        imports_already_tracked=0,
        unsupported=[],
        pending_imports=None,
        comparison_performed=True,
        resources_added_to_state=["meraki_networks.n_1"],
    ).summary


def test_deletion_pending_confirmation_payload_contract() -> None:
    event = deletion_pending_confirmation(
        addresses=["meraki_networks.n_1"], workspace="generated"
    )
    assert event.event_type is EventType.DELETION_PENDING_CONFIRMATION
    assert event.severity is EventSeverity.WARNING
    details = event.to_payload()["details"]
    assert details["addresses"] == ["meraki_networks.n_1"]
    assert details["workspace"] == "generated"
    assert "--confirm-deletions" in details["remediation"]


def test_unsupported_feature_payload_contract() -> None:
    event = unsupported_feature_flagged(
        api_path="/networks/{networkId}/mystery",
        reason="No Terraform resource maps to this API path.",
        identifiers=("N_1",),
    )
    assert event.event_type is EventType.UNSUPPORTED_FEATURE_FLAGGED
    payload = event.to_payload()
    assert payload["details"]["identifiers"] == ["N_1"]
    assert json.loads(json.dumps(payload)) == payload


def test_processing_fault_payload_contract() -> None:
    event = processing_fault(stage="terraform init", error="binary not found")
    assert event.severity is EventSeverity.CRITICAL
    assert event.to_payload()["details"] == {
        "stage": "terraform init",
        "error": "binary not found",
    }


class FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def test_webhook_posts_structured_json(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(200)

    monkeypatch.setattr(webhook_module, "_open", fake_urlopen)
    event = run_success(
        imports_written=1,
        drift_was_detected=False,
        workspace="w",
        discovered_assets=1,
        imports_already_tracked=0,
        unsupported=[],
        pending_imports=1,
        comparison_performed=True,
    )
    WebhookNotifier("https://hooks.example/abc", timeout=5.0).send(event)

    request = captured["request"]
    assert request.full_url == "https://hooks.example/abc"
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert json.loads(request.data.decode("utf-8")) == event.to_payload()
    assert captured["timeout"] == 5.0


def test_webhook_raises_on_non_success_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        webhook_module, "_open", lambda request, timeout: FakeResponse(302)
    )
    with pytest.raises(WebhookDeliveryError):
        WebhookNotifier("https://hooks.example/abc").send(
            processing_fault(stage="x", error="y")
        )


def test_webhook_wraps_transport_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        raise OSError("connection refused")

    monkeypatch.setattr(webhook_module, "_open", fake_urlopen)
    with pytest.raises(WebhookDeliveryError):
        WebhookNotifier("https://hooks.example/abc").send(
            processing_fault(stage="x", error="y")
        )


def test_webhook_rejects_insecure_scheme_without_echoing_the_token() -> None:
    """A scheme-less/plain-http URL (whose path may be the secret) is
    refused at construction; the refusal names the scheme, not the token."""
    url = "hooks.example.com/services/T000/B000/SECRETTOKEN"
    with pytest.raises(WebhookConfigError) as excinfo:
        WebhookNotifier(url)
    assert "SECRETTOKEN" not in str(excinfo.value)
    assert "https" in str(excinfo.value)
    with pytest.raises(WebhookConfigError):
        WebhookNotifier("http://hooks.example/plain")


def test_webhook_https_failure_never_leaks_the_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An https transport failure whose message embeds the URL (and its
    path secret) must be scrubbed before it leaves the notifier."""
    url = "https://hooks.example.com/services/T000/B000/SECRETTOKEN"

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        raise OSError(f"connection to {url} refused")

    monkeypatch.setattr(webhook_module, "_open", fake_urlopen)
    with pytest.raises(WebhookDeliveryError) as excinfo:
        WebhookNotifier(url).send(processing_fault(stage="x", error="y"))
    assert "SECRETTOKEN" not in str(excinfo.value)
    assert "<webhook-url>" in str(excinfo.value)
    # No chained exception for the dispatcher's traceback log to echo.
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__


class FakeSmtp:
    sent: list[EmailMessage] = []
    last_timeout: float | None = None

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.host = host
        self.port = port
        self.ehlo_count = 0
        FakeSmtp.last_timeout = timeout

    def __enter__(self) -> "FakeSmtp":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def has_extn(self, name: str) -> bool:
        # Mirror smtplib: extensions are unknown until ehlo() runs. This
        # relay advertises no STARTTLS even after EHLO.
        assert self.ehlo_count > 0, "has_extn called before ehlo()"
        return False

    def starttls(  # pragma: no cover - not reached here
        self, *, context: Any = None
    ) -> None:
        raise AssertionError("starttls attempted on a non-TLS relay")

    def ehlo(self) -> None:
        self.ehlo_count += 1

    def send_message(self, message: EmailMessage) -> None:
        FakeSmtp.sent.append(message)


def test_email_notifier_builds_and_sends_json_report() -> None:
    FakeSmtp.sent.clear()
    notifier = EmailNotifier(
        host="smtp.example",
        port=2525,
        sender="meraki2tf@example.com",
        recipients=["netops@example.com", "sec@example.com"],
        smtp_factory=FakeSmtp,
    )
    event = drift_detected(diff="delta", workspace="generated")
    notifier.send(event)

    assert len(FakeSmtp.sent) == 1
    assert FakeSmtp.last_timeout == 30.0  # a hung relay cannot wedge a run
    message = FakeSmtp.sent[0]
    assert "DRIFT_DETECTED" in message["Subject"]
    assert message["From"] == "meraki2tf@example.com"
    assert message["To"] == "netops@example.com, sec@example.com"
    assert json.loads(message.get_content()) == event.to_payload()


def test_email_subject_collapses_newlines_from_untrusted_summaries() -> None:
    """A CR/LF in an (externally sourced) summary must not reach the
    Subject header: EmailMessage would raise and drop the alert, and a
    laxer library would allow header injection."""
    from meraki2tf.alerts.models import AlertEvent, EventSeverity, EventType

    FakeSmtp.sent.clear()
    event = AlertEvent(
        event_type=EventType.UNSUPPORTED_FEATURE_FLAGGED,
        severity=EventSeverity.WARNING,
        summary="bad\r\nBcc: attacker@evil.example\r\n path /x",
    )
    EmailNotifier(
        host="smtp.example", port=25, sender="a@example.com",
        recipients=["b@example.com"], smtp_factory=FakeSmtp,
    ).send(event)
    subject = FakeSmtp.sent[0]["Subject"]
    assert "\n" not in subject and "\r" not in subject


def test_email_negotiates_starttls_when_the_relay_offers_it() -> None:
    """Opportunistic encryption: the alert body carries the full
    inventory, so STARTTLS is used whenever the relay advertises it."""

    class TlsSmtp(FakeSmtp):
        started = False

        def has_extn(self, name: str) -> bool:
            # smtplib contract: STARTTLS is only discoverable after EHLO.
            assert self.ehlo_count > 0, "has_extn called before ehlo()"
            return name == "starttls"

        def starttls(self, *, context: Any = None) -> None:
            # The notifier must hand over a verified context — an
            # unverified handshake protects against passive sniffing
            # only (see test_email_tls.py for the full contract).
            assert context is not None, "starttls called without a context"
            TlsSmtp.started = True

    FakeSmtp.sent.clear()
    EmailNotifier(
        host="smtp.example", port=587, sender="a@example.com",
        recipients=["b@example.com"], smtp_factory=TlsSmtp,
    ).send(drift_detected(diff="d", workspace="w"))
    assert TlsSmtp.started is True
    assert len(FakeSmtp.sent) == 1


def test_redact_diff_masks_values_on_secret_named_lines() -> None:
    from meraki2tf.alerts.models import redact_diff

    diff = (
        "  ~ name             = \"Corp WiFi\"\n"
        "  ~ psk              = \"hunter2\" -> \"letmein\"\n"
        "  ~ radiusSecret     = \"abc\"\n"
        "  + community_string : public"
    )
    out = redact_diff(diff)
    assert "hunter2" not in out and "letmein" not in out
    assert "abc" not in out and "public" not in out
    assert "Corp WiFi" in out  # non-secret attribute values survive
    assert out.count("(value redacted)") == 3


def test_drift_alert_payload_redacts_secret_values() -> None:
    event = drift_detected(
        diff='  ~ psk = "hunter2" -> "letmein"', workspace="w"
    )
    assert "hunter2" not in event.details["diff"]
    assert "(value redacted)" in event.details["diff"]


def test_condense_diff_strips_plan_progress_noise() -> None:
    from meraki2tf.alerts.models import condense_diff

    diff = (
        "meraki_wireless_ssid.l_1_0: Refreshing state... [id=1,0]\n"
        "meraki_network_snmp.l_1: Still refreshing... [10s elapsed]\n"
        "data.meraki_networks.all: Reading...\n"
        "data.meraki_networks.all: Still reading... [10s elapsed]\n"
        "data.meraki_networks.all: Read complete after 11s\n"
        "meraki_wireless_ssid.l_1_0: Preparing import... [id=1,0]\n"
        "\n"
        "Terraform will perform the following actions:\n"
        "\n"
        "  # meraki_wireless_ssid.l_1_0 will be updated in-place\n"
        "  ~ resource \"meraki_wireless_ssid\" \"l_1_0\" {\n"
        "      ~ name = \"a\" -> \"b\"\n"
        "    }\n"
        "\n"
        "Plan: 0 to add, 1 to change, 0 to destroy.\n"
    )
    out = condense_diff(diff)
    assert "Refreshing state" not in out
    assert "Still refreshing" not in out
    assert "Reading..." not in out
    assert "Read complete" not in out
    assert "Preparing import" not in out
    assert "will be updated in-place" in out
    assert '~ name = "a" -> "b"' in out
    assert "Plan: 0 to add, 1 to change, 0 to destroy." in out
    assert not out.startswith("\n")
    assert "\n\n\n" not in out  # removals leave no blank runs


def test_condense_diff_keeps_indented_hunks_that_mention_progress() -> None:
    from meraki2tf.alerts.models import condense_diff

    # Indented diff content is never progress chatter, even when an
    # attribute value happens to contain the same words.
    diff = '      ~ note = "Refreshing state: manual"'
    assert condense_diff(diff) == diff


def test_drift_alert_payload_drops_refresh_noise() -> None:
    event = drift_detected(
        diff=(
            "meraki_networks.n_1: Refreshing state... [id=1]\n"
            '  ~ name = "a" -> "b"'
        ),
        workspace="w",
    )
    assert "Refreshing state" not in event.details["diff"]
    assert '~ name = "a" -> "b"' in event.details["diff"]


def test_default_smtp_factory_applies_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            captured.update(host=host, port=port, timeout=timeout)

    monkeypatch.setattr("meraki2tf.alerts.email.smtplib.SMTP", FakeSMTP)
    _default_smtp_factory("smtp.example", 25, 30.0)
    assert captured == {"host": "smtp.example", "port": 25, "timeout": 30.0}


def test_dispatcher_fans_out_and_isolates_failures() -> None:
    recorder = RecordingNotifier()
    dispatcher = AlertDispatcher([ExplodingNotifier()])
    dispatcher.register(recorder)
    delivered = dispatcher.dispatch(
        run_success(
            imports_written=1,
            drift_was_detected=False,
            workspace="w",
            discovered_assets=1,
            imports_already_tracked=0,
            unsupported=[],
            pending_imports=None,
            comparison_performed=False,
        )
    )
    assert delivered == 1
    assert recorder.events[0].event_type is EventType.RUN_SUCCESS


def test_gap_replay_executed_shapes_and_severity() -> None:
    from meraki2tf.alerts import gap_replay_executed

    clean = gap_replay_executed(
        organization_id="org-1",
        executed=("secrets: meraki_wireless_ssid.a via updateNetworkWirelessSsid",),
        failed=(),
        skipped=({"api_path": "/x", "identifiers": ("1",), "reason": "why"},),
    )
    assert clean.event_type is EventType.GAP_REPLAY_EXECUTED
    assert clean.severity is EventSeverity.INFO
    assert "1 restored, 0 failed, 1 skipped" in clean.summary
    assert clean.details["organization_id"] == "org-1"
    assert clean.details["skipped"][0]["reason"] == "why"

    dirty = gap_replay_executed(
        organization_id="org-1",
        executed=(),
        failed=(("object: /x (ids=1) via createX", "boom"),),
        skipped=(),
    )
    assert dirty.severity is EventSeverity.WARNING
    assert dirty.details["failed"] == [["object: /x (ids=1) via createX", "boom"]]


def test_dispatcher_logs_error_when_every_channel_fails(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Per-channel isolation must not let a total delivery failure look
    like success: a drift alert that reached nobody is unmissable in
    the run log."""
    dispatcher = AlertDispatcher([ExplodingNotifier(), ExplodingNotifier()])
    with caplog.at_level("ERROR", logger="meraki2tf.alerts.dispatcher"):
        delivered = dispatcher.dispatch(
            drift_detected(diff="delta", workspace="generated")
        )
    assert delivered == 0
    (record,) = [r for r in caplog.records if "ALL" in r.message]
    assert "2 configured channel(s)" in record.message
    assert "DRIFT_DETECTED" in record.message


def test_dispatcher_without_notifiers_stays_quiet(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Zero configured channels is a deliberate setup (ad-hoc runs), not
    a delivery failure."""
    with caplog.at_level("ERROR", logger="meraki2tf.alerts.dispatcher"):
        delivered = AlertDispatcher().dispatch(
            drift_detected(diff="delta", workspace="generated")
        )
    assert delivered == 0
    assert not [r for r in caplog.records if "ALL" in r.message]


def test_partial_success_does_not_log_total_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    dispatcher = AlertDispatcher([ExplodingNotifier(), RecordingNotifier()])
    with caplog.at_level("ERROR", logger="meraki2tf.alerts.dispatcher"):
        delivered = dispatcher.dispatch(
            drift_detected(diff="delta", workspace="generated")
        )
    assert delivered == 1
    assert not [r for r in caplog.records if "ALL" in r.message]


def test_dispatcher_counts_total_delivery_failures() -> None:
    """The counter feeds the CLI's exit-5 contract: an event no channel
    accepted must be visible to the caller after the run."""
    dispatcher = AlertDispatcher([ExplodingNotifier()])
    assert dispatcher.failed_event_count == 0
    dispatcher.dispatch(drift_detected(diff="delta", workspace="generated"))
    dispatcher.dispatch(drift_detected(diff="delta", workspace="generated"))
    assert dispatcher.failed_event_count == 2


def test_partial_delivery_does_not_count_as_failure() -> None:
    dispatcher = AlertDispatcher([ExplodingNotifier(), RecordingNotifier()])
    dispatcher.dispatch(drift_detected(diff="delta", workspace="generated"))
    assert dispatcher.failed_event_count == 0


def test_zero_channels_never_count_as_failure() -> None:
    """No channels is a deliberate ad-hoc setup, not an outage."""
    dispatcher = AlertDispatcher()
    assert dispatcher.channel_count == 0
    dispatcher.dispatch(drift_detected(diff="delta", workspace="generated"))
    assert dispatcher.failed_event_count == 0


def test_dispatcher_reports_registered_channel_count() -> None:
    dispatcher = AlertDispatcher([RecordingNotifier()])
    dispatcher.register(RecordingNotifier())
    assert dispatcher.channel_count == 2


def test_drift_summary_names_the_snapshot_diff_origin() -> None:
    """A snapshot-diff drift alert compares snapshot vs baseline; its
    summary must not claim a Terraform-state comparison."""
    event = drift_detected(diff="d", workspace="w", origin="snapshot-diff")
    assert "drift baseline" in event.summary
    assert "Terraform state" not in event.summary
    assert event.details["origin"] == "snapshot-diff"


def test_dispatcher_stamps_organization_context() -> None:
    """Multi-org fan-out interleaves several organizations' alerts on
    one channel; every dispatched event must be attributable."""
    recorder = RecordingNotifier()
    dispatcher = AlertDispatcher([recorder])
    dispatcher.organization_id = "123456"
    dispatcher.dispatch(drift_detected(diff="d", workspace="w"))
    assert recorder.events[0].details["organization_id"] == "123456"


def test_dispatcher_stamp_never_clobbers_an_explicit_org() -> None:
    recorder = RecordingNotifier()
    dispatcher = AlertDispatcher([recorder])
    dispatcher.organization_id = "123456"
    event = drift_detected(diff="d", workspace="w")
    event.details["organization_id"] = "999999"
    dispatcher.dispatch(event)
    assert recorder.events[0].details["organization_id"] == "999999"


def test_dispatcher_leaves_events_unstamped_without_context() -> None:
    recorder = RecordingNotifier()
    AlertDispatcher([recorder]).dispatch(drift_detected(diff="d", workspace="w"))
    assert "organization_id" not in recorder.events[0].details


def test_email_notifier_logs_partial_recipient_refusals(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """smtplib raises only when EVERY recipient is refused; a partial
    refusal comes back as a dict and still counts as delivered, but the
    dropped recipients must be visible at ERROR."""

    class PartialRefusalSmtp(FakeSmtp):
        def send_message(  # type: ignore[override]
            self, message: EmailMessage
        ) -> dict[str, tuple[int, bytes]]:
            FakeSmtp.sent.append(message)
            return {"sec@example.com": (550, b"user unknown")}

    notifier = EmailNotifier(
        host="smtp.example",
        port=2525,
        sender="meraki2tf@example.com",
        recipients=["netops@example.com", "sec@example.com"],
        smtp_factory=PartialRefusalSmtp,
    )
    with caplog.at_level("ERROR", logger="meraki2tf.alerts.email"):
        notifier.send(drift_detected(diff="delta", workspace="generated"))
    (record,) = [r for r in caplog.records if "refused" in r.message]
    assert "sec@example.com" in record.message
    assert "1 of 2 recipient(s)" in record.message


# ---------------------------------------------------------------------------
# Channel-native webhook formats (Slack / Teams).
# ---------------------------------------------------------------------------


def _drift_event() -> AlertEvent:
    return drift_detected(diff="~ update", workspace="generated")


def test_render_payload_json_is_the_raw_event() -> None:
    event = _drift_event()
    assert render_payload(event, "json") == event.to_payload()


def test_render_payload_slack_shape() -> None:
    body = render_payload(_drift_event(), "slack")
    assert set(body) == {"text"}
    assert "[meraki2tf] DRIFT_DETECTED (warning)" in body["text"]
    assert "Configuration drift detected" in body["text"]
    assert "```" in body["text"]  # details ride in a code block


def test_render_payload_teams_is_an_adaptive_card_message() -> None:
    body = render_payload(_drift_event(), "teams")
    assert body["type"] == "message"
    attachment = body["attachments"][0]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = attachment["content"]
    assert card["type"] == "AdaptiveCard"
    texts = [block["text"] for block in card["body"]]
    assert any("DRIFT_DETECTED" in text for text in texts)
    assert any("Configuration drift detected" in text for text in texts)


def test_render_payload_truncates_oversized_details_for_chat() -> None:
    event = drift_detected(diff="x" * 50_000, workspace="generated")
    slack_text = render_payload(event, "slack")["text"]
    assert len(slack_text) < 10_000
    assert "truncated for chat delivery" in slack_text
    # The raw json format stays lossless.
    raw = render_payload(event, "json")
    assert raw["details"]["diff"] == "x" * 50_000


def test_render_payload_rejects_unknown_formats() -> None:
    with pytest.raises(ValueError):
        render_payload(_drift_event(), "discord")


def test_webhook_posts_slack_format_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse(200)

    monkeypatch.setattr(webhook_module, "_open", fake_urlopen)
    WebhookNotifier(
        "https://hooks.example/abc", payload_format="slack"
    ).send(_drift_event())
    assert set(captured["body"]) == {"text"}


def test_webhook_rejects_unknown_payload_format() -> None:
    with pytest.raises(WebhookConfigError):
        WebhookNotifier("https://hooks.example/abc", payload_format="discord")


# ---------------------------------------------------------------------------
# PagerDuty Events API v2 notifier.
# ---------------------------------------------------------------------------


def test_pagerduty_handles_only_problem_severities() -> None:
    notifier = PagerDutyNotifier()
    assert notifier.handles(_drift_event())  # WARNING
    assert notifier.handles(processing_fault(stage="x", error="y"))  # CRITICAL
    clean = run_success(
        imports_written=0,
        drift_was_detected=False,
        workspace="w",
        discovered_assets=0,
        imports_already_tracked=0,
        unsupported=[],
        pending_imports=0,
        comparison_performed=True,
    )
    assert not notifier.handles(clean)  # INFO never pages


def test_pagerduty_triggers_an_incident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ROUTING_KEY_ENV_VAR, "rk-test-0001")
    captured: dict[str, Any] = {}

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse(202)

    monkeypatch.setattr(pagerduty_module, "_open", fake_urlopen)
    PagerDutyNotifier().send(processing_fault(stage="startup", error="boom"))

    assert captured["url"] == "https://events.pagerduty.com/v2/enqueue"
    body = captured["body"]
    assert body["routing_key"] == "rk-test-0001"
    assert body["event_action"] == "trigger"
    assert body["payload"]["severity"] == "critical"
    assert body["payload"]["source"] == "meraki2tf"
    assert body["payload"]["summary"].startswith("[meraki2tf] PROCESSING_FAULT")
    assert body["payload"]["custom_details"]["stage"] == "startup"


def test_pagerduty_requires_the_routing_key_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ROUTING_KEY_ENV_VAR, raising=False)
    with pytest.raises(PagerDutyConfigError):
        PagerDutyNotifier().send(processing_fault(stage="x", error="y"))


def test_pagerduty_raises_on_api_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ROUTING_KEY_ENV_VAR, "rk-test-0001")
    monkeypatch.setattr(
        pagerduty_module, "_open", lambda request, timeout: FakeResponse(400)
    )
    with pytest.raises(PagerDutyDeliveryError):
        PagerDutyNotifier().send(processing_fault(stage="x", error="y"))


def test_pagerduty_transport_failure_never_leaks_the_routing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(ROUTING_KEY_ENV_VAR, "rk-secret-9999")

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        raise OSError("request with rk-secret-9999 refused")

    monkeypatch.setattr(pagerduty_module, "_open", fake_urlopen)
    with pytest.raises(PagerDutyDeliveryError) as excinfo:
        PagerDutyNotifier().send(processing_fault(stage="x", error="y"))
    assert "rk-secret-9999" not in str(excinfo.value)
    assert "<routing-key>" in str(excinfo.value)
    assert excinfo.value.__cause__ is None


# ---------------------------------------------------------------------------
# Dispatcher routing with declining (paging) channels.
# ---------------------------------------------------------------------------


class DecliningNotifier(Notifier):
    channel = "declining"

    def handles(self, event: AlertEvent) -> bool:
        return False

    def send(self, event: AlertEvent) -> None:  # pragma: no cover - never routed
        raise AssertionError("dispatcher routed a declined event")


def test_dispatcher_skips_channels_that_decline_the_event() -> None:
    recording = RecordingNotifier()
    dispatcher = AlertDispatcher([DecliningNotifier(), recording])
    delivered = dispatcher.dispatch(_drift_event())
    assert delivered == 1
    assert len(recording.events) == 1
    assert dispatcher.failed_event_count == 0


def test_event_declined_by_every_channel_is_not_an_outage(
    caplog: pytest.LogCaptureFixture,
) -> None:
    dispatcher = AlertDispatcher([DecliningNotifier()])
    with caplog.at_level("INFO", logger="meraki2tf.alerts.dispatcher"):
        delivered = dispatcher.dispatch(_drift_event())
    assert delivered == 0
    assert dispatcher.failed_event_count == 0
    assert "No configured alert channel handles" in caplog.text


def test_failure_counter_ignores_declining_channels() -> None:
    """All *handling* channels failing is an outage even when a
    declining channel sits alongside them."""
    dispatcher = AlertDispatcher([DecliningNotifier(), ExplodingNotifier()])
    dispatcher.dispatch(_drift_event())
    assert dispatcher.failed_event_count == 1


# ---------------------------------------------------------------------------
# SMTP AUTH (environment-only credentials, TLS required).
# ---------------------------------------------------------------------------


class AuthRecordingSmtp:
    """SMTP stand-in advertising STARTTLS and recording login()."""

    last_instance: "AuthRecordingSmtp | None" = None

    def __init__(self, host: str, port: int, timeout: float) -> None:
        self.logins: list[tuple[str, str]] = []
        self.sent: list[EmailMessage] = []
        self.tls_active = False
        AuthRecordingSmtp.last_instance = self

    def __enter__(self) -> "AuthRecordingSmtp":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def ehlo(self) -> None:
        return None

    def has_extn(self, name: str) -> bool:
        return name == "starttls"

    def starttls(self, *, context: Any = None) -> None:
        self.tls_active = True

    def login(self, username: str, password: str) -> None:
        assert self.tls_active, "login attempted before STARTTLS"
        self.logins.append((username, password))

    def send_message(self, message: EmailMessage) -> dict[str, Any]:
        self.sent.append(message)
        return {}


def _auth_notifier(factory: Any) -> EmailNotifier:
    return EmailNotifier(
        host="smtp.corp.example",
        port=587,
        sender="meraki2tf@corp.example",
        recipients=["netops@corp.example"],
        smtp_factory=factory,
    )


def test_email_authenticates_inside_tls_when_credentials_are_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(SMTP_USERNAME_ENV_VAR, "alert-bot")
    monkeypatch.setenv(SMTP_PASSWORD_ENV_VAR, "relay-pass")
    _auth_notifier(AuthRecordingSmtp).send(processing_fault(stage="x", error="y"))
    smtp = AuthRecordingSmtp.last_instance
    assert smtp is not None
    assert smtp.logins == [("alert-bot", "relay-pass")]
    assert len(smtp.sent) == 1


def test_email_refuses_auth_over_cleartext(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A relay that never advertises STARTTLS must not receive the
    credential — and the alert must visibly fail, not silently skip AUTH."""
    monkeypatch.setenv(SMTP_USERNAME_ENV_VAR, "alert-bot")
    monkeypatch.setenv(SMTP_PASSWORD_ENV_VAR, "relay-pass")
    FakeSmtp.sent.clear()
    with pytest.raises(EmailConfigError):
        _auth_notifier(FakeSmtp).send(processing_fault(stage="x", error="y"))
    assert FakeSmtp.sent == []


def test_email_half_credential_pair_fails_loudly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(SMTP_USERNAME_ENV_VAR, "alert-bot")
    monkeypatch.delenv(SMTP_PASSWORD_ENV_VAR, raising=False)
    with pytest.raises(EmailConfigError):
        _auth_notifier(AuthRecordingSmtp).send(
            processing_fault(stage="x", error="y")
        )


def test_email_without_credentials_never_logs_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(SMTP_USERNAME_ENV_VAR, raising=False)
    monkeypatch.delenv(SMTP_PASSWORD_ENV_VAR, raising=False)
    _auth_notifier(AuthRecordingSmtp).send(processing_fault(stage="x", error="y"))
    smtp = AuthRecordingSmtp.last_instance
    assert smtp is not None
    assert smtp.logins == []
    assert len(smtp.sent) == 1


def test_condense_diff_collapses_blank_runs_left_by_removals() -> None:
    from meraki2tf.alerts.models import condense_diff

    # Progress lines sandwiched between blank lines leave consecutive
    # blanks behind; the condensed diff collapses them to one.
    diff = (
        "Terraform will perform the following actions:\n"
        "\n"
        "meraki_network_snmp.l_1: Refreshing state... [id=L_1]\n"
        "\n"
        "  # meraki_network_snmp.l_1 will be updated in-place\n"
    )
    assert condense_diff(diff) == (
        "Terraform will perform the following actions:\n"
        "\n"
        "  # meraki_network_snmp.l_1 will be updated in-place"
    )


def test_heal_executed_severity_tracks_failures() -> None:
    from meraki2tf.alerts import heal_executed

    clean = heal_executed(
        organization_id="123456",
        surviving=7,
        executed=["create /networks/{networkId}/groupPolicies"],
        failed=[],
        skipped=[{"operation": "op-1", "reason": "sanitized"}],
    )
    assert clean.severity is EventSeverity.INFO
    assert clean.event_type is EventType.HEAL_EXECUTED
    assert "1 missing object(s) recreated" in clean.summary
    assert clean.details["surviving_untouched"] == 7

    failing = heal_executed(
        organization_id="123456",
        surviving=7,
        executed=[],
        failed=[["create /networks/{networkId}/groupPolicies", "HTTP 400"]],
        skipped=[],
    )
    assert failing.severity is EventSeverity.WARNING
    assert failing.details["failed"] == [
        ["create /networks/{networkId}/groupPolicies", "HTTP 400"]
    ]
    # A full heal carries no filter marker at all.
    assert "only_filters" not in clean.details
    assert "Selective heal" not in clean.summary


def test_heal_executed_selective_run_names_its_filters() -> None:
    """The alert must say a heal deliberately covered a subset — an
    operator reading '1 recreated' after a 3-object deletion would
    otherwise investigate a phantom failure."""
    from meraki2tf.alerts import heal_executed

    event = heal_executed(
        organization_id="123456",
        surviving=7,
        executed=["update /networks/{networkId}/wireless/ssids/{number}"],
        failed=[],
        skipped=[],
        only=["ssid:Guest*", "network:Branch-07"],
    )
    assert event.details["only_filters"] == [
        "ssid:Guest*", "network:Branch-07",
    ]
    assert "Selective heal (--only 'ssid:Guest*', 'network:Branch-07')" in (
        event.summary
    )


def test_pagerduty_open_delegates_to_urlopen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The _open seam (patched everywhere else) itself just hands the
    request to urllib against the fixed https Events API endpoint."""
    captured: dict[str, Any] = {}
    sentinel = FakeResponse(202)

    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        captured["request"] = request
        captured["timeout"] = timeout
        return sentinel

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    request = urllib.request.Request(
        "https://events.pagerduty.com/v2/enqueue", data=b"{}"
    )
    assert pagerduty_module._open(request, timeout=5.0) is sentinel
    assert captured["request"] is request
    assert captured["timeout"] == 5.0


def test_run_success_partial_scope_marks_summary_and_details() -> None:
    event = run_success(
        imports_written=1,
        drift_was_detected=False,
        workspace="w",
        discovered_assets=3,
        imports_already_tracked=0,
        unsupported=[],
        pending_imports=None,
        comparison_performed=False,
        partial_scope=("N_1", "N_2"),
    )
    assert "PARTIAL run scoped to 2 network(s)" in event.summary
    assert event.to_payload()["details"]["partial_scope"] == ["N_1", "N_2"]


def test_heal_executed_names_partial_snapshot_scope() -> None:
    from meraki2tf.alerts import heal_executed

    event = heal_executed(
        organization_id="org-123",
        surviving=5,
        executed=["networks|create|N_1"],
        failed=[],
        skipped=[],
        snapshot_scope=("N_1",),
    )
    assert "PARTIAL snapshot scoped to 1 network(s)" in event.summary
    assert event.to_payload()["details"]["snapshot_scope"] == ["N_1"]

    unscoped = heal_executed(
        organization_id="org-123",
        surviving=5,
        executed=[],
        failed=[],
        skipped=[],
    )
    assert "PARTIAL" not in unscoped.summary
    assert "snapshot_scope" not in unscoped.to_payload()["details"]
