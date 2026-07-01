"""Abstract notifier contract implemented by every channel plugin."""

from __future__ import annotations

import abc

from meraki2tf.alerts.models import AlertEvent


class Notifier(abc.ABC):
    """A single delivery channel (webhook, email, ...).

    Implementations must be stateless with respect to credentials and
    raise on delivery failure; the dispatcher handles isolation so one
    failing channel never suppresses the others.
    """

    #: Short channel identifier used in logs and configuration.
    channel: str = "abstract"

    @abc.abstractmethod
    def send(self, event: AlertEvent) -> None:
        """Deliver one event to this channel."""
