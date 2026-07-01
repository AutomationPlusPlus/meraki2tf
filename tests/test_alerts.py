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
    drift_detected,
    processing_fault,
    run_success,
    unsupported_feature_flagged,
)


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
    assert payload["details"] == {"diff": "~ plan delta", "workspace": "generated"}


def test_run_success_payload_contract() -> None:
    payload = run_success(
        imports_written=4, drift_was_detected=True, workspace="generated"
    ).to_payload()
    assert payload["event_type"] == "RUN_SUCCESS"
    assert payload["severity"] == EventSeverity.INFO.value
    assert payload["details"] == {
        "imports_written": 4,
        "drift_was_detected": True,
        "workspace": "generated",
    }


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
    event = run_success(imports_written=1, drift_was_detected=False, workspace="w")
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


class FakeSmtp:
    sent: list[EmailMessage] = []

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

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
    message = FakeSmtp.sent[0]
    assert "DRIFT_DETECTED" in message["Subject"]
    assert message["From"] == "meraki2tf@example.com"
    assert message["To"] == "netops@example.com, sec@example.com"
    assert json.loads(message.get_content()) == event.to_payload()


def test_dispatcher_fans_out_and_isolates_failures() -> None:
    recorder = RecordingNotifier()
    dispatcher = AlertDispatcher([ExplodingNotifier()])
    dispatcher.register(recorder)
    delivered = dispatcher.dispatch(
        run_success(imports_written=1, drift_was_detected=False, workspace="w")
    )
    assert delivered == 1
    assert recorder.events[0].event_type is EventType.RUN_SUCCESS
