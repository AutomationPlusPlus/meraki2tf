"""Notification schema payloads and dispatcher fan-out semantics."""

from meraki2tf.notifications import (
    EventSeverity,
    EventType,
    NotificationDispatcher,
    NotificationEvent,
    Notifier,
)
from meraki2tf.notifications.email import EmailNotifier
from meraki2tf.notifications.models import (
    ResourceDiff,
    drift_alert,
    run_success,
    unsupported_feature,
)
from meraki2tf.notifications.webhook import WebhookNotifier


class RecordingNotifier(Notifier):
    channel = "recording"

    def __init__(self) -> None:
        self.events: list[NotificationEvent] = []

    def send(self, event: NotificationEvent) -> None:
        self.events.append(event)


class ExplodingNotifier(Notifier):
    channel = "exploding"

    def send(self, event: NotificationEvent) -> None:
        raise ConnectionError("endpoint unreachable")


def test_drift_alert_payload_carries_diffs() -> None:
    event = drift_alert([
        ResourceDiff("meraki_network", "N_1", "name", expected="lab", actual="lab-2"),
    ])
    payload = event.to_payload()
    assert payload["event_type"] == EventType.DRIFT_DETECTED.value
    assert payload["severity"] == EventSeverity.WARNING.value
    assert payload["details"]["diffs"][0]["attribute"] == "name"


def test_run_success_payload() -> None:
    payload = run_success(resources_synced=7).to_payload()
    assert payload["event_type"] == EventType.RUN_SUCCESS.value
    assert payload["details"]["resources_synced"] == 7


def test_unsupported_feature_payload() -> None:
    event = unsupported_feature("switch.stormControl", {"network": "N_1"})
    assert event.event_type is EventType.UNSUPPORTED_FEATURE
    assert event.details == {"network": "N_1"}


def test_dispatcher_fans_out_and_isolates_failures() -> None:
    recorder = RecordingNotifier()
    dispatcher = NotificationDispatcher([ExplodingNotifier()])
    dispatcher.register(recorder)
    delivered = dispatcher.dispatch(run_success(1))
    assert delivered == 1
    assert len(recorder.events) == 1


def test_channel_placeholders_prepare_but_do_not_deliver() -> None:
    import pytest

    event = run_success(0)
    with pytest.raises(NotImplementedError):
        WebhookNotifier("https://hooks.example/abc").send(event)
    with pytest.raises(NotImplementedError):
        EmailNotifier(["netops@example.com"]).send(event)
