"""Construction of the Meraki SDK client, with log hygiene pinned.

Every path that talks to the dashboard — discovery, the ``--check``
probes, ``--list-orgs``, and the DR write engines — builds its own
``meraki.DashboardAPI``. All of them must suppress the SDK's own
logging: left at its defaults the SDK prints request/response detail to
the console and writes a ``meraki_api_*.log`` file next to the workdir,
which is exactly the "verbose logging isolation" the security contract
forbids (those records carry ``Authorization`` headers and payload
values). That guarantee is a property of *how the client is built*, so
it lives in one factory rather than in eight copies of four keyword
arguments.

The API key is read from the environment at construction time and never
passed around as a parameter (no plaintext token arguments, per the
same contract).
"""

from __future__ import annotations

from typing import Any

from meraki2tf.config import read_api_key

#: Throttle retries for the DR write engines (``--restore``, ``--heal``,
#: ``--replay-gaps``, ``--wipe-org``). They compete for the shared
#: 10 req/s organization budget — post-disaster, against every surviving
#: integration hammering the rebuilt tenant — and the SDK's default of 2
#: gives up far too early for writes whose failure poisons a whole
#: subtree (or aborts a teardown mid-way).
WRITE_ENGINE_MAXIMUM_RETRIES = 8


def dashboard_client(**overrides: Any) -> Any:
    """A dashboard client with SDK console/file logging suppressed.

    ``overrides`` are passed straight through to ``DashboardAPI`` for
    call-site concerns like ``wait_on_rate_limit`` and
    ``maximum_retries``; the log-hygiene arguments are not overridable.
    """
    import meraki

    return meraki.DashboardAPI(
        api_key=read_api_key(),
        suppress_logging=True,
        print_console=False,
        output_log=False,
        **overrides,
    )
