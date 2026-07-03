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
        "apply_aborted": False,
        "regenerated_addresses": [],
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


def test_webhook_failure_never_leaks_the_url() -> None:
    """A scheme-less URL fails inside urllib with the full URL (and its
    embedded secret) in the message; the wrapped error must scrub it."""
    url = "hooks.example.com/services/T000/B000/SECRETTOKEN"
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
        FakeSmtp.last_timeout = timeout

    def __enter__(self) -> "FakeSmtp":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

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
