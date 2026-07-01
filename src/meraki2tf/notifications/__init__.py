"""Modular notification plugins and event schema.

Alerting fires on three conditions defined by the project contract:
configuration drift detected during comparison, successful state
aggregation at the end of a clean run, and unsupported-feature or
critical processing faults.
"""

from meraki2tf.notifications.base import Notifier
from meraki2tf.notifications.dispatcher import NotificationDispatcher
from meraki2tf.notifications.models import (
    DriftAlert,
    EventSeverity,
    EventType,
    NotificationEvent,
    RunSuccessReport,
    UnsupportedFeatureReport,
)

__all__ = [
    "DriftAlert",
    "EventSeverity",
    "EventType",
    "NotificationDispatcher",
    "NotificationEvent",
    "Notifier",
    "RunSuccessReport",
    "UnsupportedFeatureReport",
]
