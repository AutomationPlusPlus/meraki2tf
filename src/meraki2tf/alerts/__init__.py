"""Decoupled alerting subsystem: event contracts, channels, dispatch.

Alerting fires on the three contract events — drift detected during
state comparison, flawless run/state aggregation, and unsupported
features flagged during schema parsing — plus critical processing
faults.
"""

from meraki2tf.alerts.base import Notifier
from meraki2tf.alerts.dispatcher import AlertDispatcher
from meraki2tf.alerts.email import (
    EmailConfigError,
    EmailNotifier,
    validate_smtp_credentials,
)
from meraki2tf.alerts.formats import WEBHOOK_FORMATS
from meraki2tf.alerts.pagerduty import (
    PagerDutyConfigError,
    PagerDutyDeliveryError,
    PagerDutyNotifier,
    routing_key_present,
)
from meraki2tf.alerts.models import (
    AlertEvent,
    EventSeverity,
    EventType,
    deletion_pending_confirmation,
    drift_detected,
    gap_replay_executed,
    heal_executed,
    org_wipe_executed,
    rebuild_executed,
    restore_executed,
    processing_fault,
    run_success,
    unsupported_feature_flagged,
)
from meraki2tf.alerts.webhook import (
    WebhookConfigError,
    WebhookDeliveryError,
    WebhookNotifier,
)

__all__ = [
    "AlertDispatcher",
    "AlertEvent",
    "EmailConfigError",
    "EmailNotifier",
    "EventSeverity",
    "EventType",
    "Notifier",
    "PagerDutyConfigError",
    "PagerDutyDeliveryError",
    "PagerDutyNotifier",
    "WEBHOOK_FORMATS",
    "WebhookConfigError",
    "WebhookDeliveryError",
    "WebhookNotifier",
    "routing_key_present",
    "deletion_pending_confirmation",
    "drift_detected",
    "gap_replay_executed",
    "heal_executed",
    "org_wipe_executed",
    "rebuild_executed",
    "restore_executed",
    "processing_fault",
    "run_success",
    "unsupported_feature_flagged",
    "validate_smtp_credentials",
]
