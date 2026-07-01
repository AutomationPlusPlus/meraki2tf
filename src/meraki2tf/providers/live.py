"""Live provider streaming from the Meraki cloud via the official SDK.

The SDK client is constructed lazily on first use so that offline runs
never require the ``MERAKI_DASHBOARD_API_KEY`` environment variable, and
the token itself is passed straight into the SDK without being retained
on this object. SDK-side logging of the key is suppressed; the 10 req/s
endpoint budget is honored natively by the SDK's built-in rate handler.
"""

from __future__ import annotations

import logging
from typing import Any

from meraki2tf.config import read_api_key
from meraki2tf.providers.base import ConfigurationProvider

logger = logging.getLogger(__name__)


class LiveProvider(ConfigurationProvider):
    """Executes discovered operations against the Meraki dashboard API."""

    mode = "live"

    def __init__(self) -> None:
        self._client: Any = None

    def _dashboard(self) -> Any:
        if self._client is None:
            import meraki

            self._client = meraki.DashboardAPI(
                api_key=read_api_key(),
                suppress_logging=True,
                print_console=False,
                output_log=False,
            )
            logger.debug("Meraki dashboard client initialized (logging suppressed).")
        return self._client

    def execute(self, operation_id: str, **path_params: str) -> Any:
        # Dynamic dispatch: the spec registry resolves operation_id to the
        # SDK section/method pair. Wired in with the translation engine
        # iteration; the interface is fixed now so callers never change.
        self._dashboard()
        raise NotImplementedError(
            "Live operation dispatch lands with the spec-registry iteration."
        )

    def close(self) -> None:
        self._client = None
