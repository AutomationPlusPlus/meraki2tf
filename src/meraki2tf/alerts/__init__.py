"""Decoupled alerting subsystem: event contracts, channels, dispatch.

Alerting fires on the three contract events — drift detected during
state comparison, flawless run/state aggregation, and unsupported
features flagged during schema parsing — plus critical processing
faults.
"""

from meraki2tf.alerts.base import Notifier
from meraki2tf.alerts.dispatcher import AlertDispatcher
from meraki2tf.alerts.email import EmailNotifier
from meraki2tf.alerts.models import (
    AlertEvent,
    EventSeverity,
    EventType,
    deletion_pending_confirmation,
    drift_detected,
    gap_replay_executed,
    restore_executed,
    processing_fault,
    run_success,
    unsupported_feature_flagged,
)
from meraki2tf.alerts.webhook import WebhookDeliveryError, WebhookNotifier

__all__ = [
    "AlertDispatcher",
    "AlertEvent",
    "EmailNotifier",
    "EventSeverity",
    "EventType",
    "Notifier",
    "WebhookDeliveryError",
    "WebhookNotifier",
    "deletion_pending_confirmation",
    "drift_detected",
    "gap_replay_executed",
    "restore_executed",
    "processing_fault",
    "run_success",
    "unsupported_feature_flagged",
]
