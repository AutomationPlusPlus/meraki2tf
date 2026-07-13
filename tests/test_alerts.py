"""Alert payload contracts, webhook/email transports, dispatcher fan-out."""

import json
import urllib.request
from email.message import EmailMessage
from typing import Any

import pytest

from meraki2tf.alerts import (
    AlertDispatcher,
    AlertEvent,
    EmailNotifier,
    EventSeverity,
    EventType,
    Notifier,
    WebhookConfigError,
    WebhookDeliveryError,
    WebhookNotifier,
    deletion_pending_confirmation,
    drift_detected,
    processing_fault,
    run_success,
    unsupported_feature_flagged,
)
from meraki2tf.alerts.email import _default_smtp_factory


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

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
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
        urllib.request, "urlopen", lambda request, timeout: FakeResponse(302)
    )
    with pytest.raises(WebhookDeliveryError):
        WebhookNotifier("https://hooks.example/abc").send(
            processing_fault(stage="x", error="y")
        )


def test_webhook_wraps_transport_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request: urllib.request.Request, timeout: float) -> FakeResponse:
        raise OSError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
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

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
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

    def starttls(self) -> None:  # pragma: no cover - not reached here
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

        def starttls(self) -> None:
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
