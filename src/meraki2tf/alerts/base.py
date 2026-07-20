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

    def handles(self, event: AlertEvent) -> bool:
        """Whether this channel wants ``event`` at all.

        Fan-out channels take everything (the default). Paging channels
        override this to decline routine events — a clean-run
        notification must not open an incident — without the dispatcher
        counting the declination as a delivery failure.
        """
        return True

    @abc.abstractmethod
    def send(self, event: AlertEvent) -> None:
        """Deliver one event to this channel."""
