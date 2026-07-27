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

The same reasoning covers the SDK's *other* self-written artifact. SDK
4.x adds a "smart flow" client-side rate limiter which, left at its
defaults, persists a per-organization mapping cache to
``~/.meraki/.cache/rate_limit_cache.json`` — network IDs, device
serials, and organization IDs, written outside the workdir at the
process umask and kept for a week. The contract enumerates exactly
which artifacts a run may leave and how each is permissioned; an
undeclared file of tenant identifiers in the operator's home directory
is not one of them. The limiter itself is welcome (it paces the shared
10 req/s organization budget), so the factory keeps it and disables
only its cache.

The API key is read from the environment at construction time and never
passed around as a parameter (no plaintext token arguments, per the
same contract).
"""

from __future__ import annotations

import inspect
from typing import Any

from meraki2tf.config import read_api_key

#: Throttle retries for the DR write engines (``--restore``, ``--heal``,
#: ``--replay-gaps``, ``--wipe-org``). They compete for the shared
#: 10 req/s organization budget — post-disaster, against every surviving
#: integration hammering the rebuilt tenant — and the SDK's default of 2
#: gives up far too early for writes whose failure poisons a whole
#: subtree (or aborts a teardown mid-way).
WRITE_ENGINE_MAXIMUM_RETRIES = 8

#: Prefix of every SDK 4.x smart-flow constructor parameter.
SMART_FLOW_PREFIX = "smart_flow"

#: The smart-flow parameter naming the on-disk mapping cache. The SDK
#: reads it as ``cache_path or None``, so an empty string switches the
#: cache off while leaving the rate limiter running.
SMART_FLOW_CACHE_PARAMETER = "smart_flow_cache_path"

#: Smart flow's own log channel. Redundant today — the SDK hands its
#: limiter ``logger if smart_flow_logging else None`` and
#: ``suppress_logging=True`` already leaves that logger unset — but the
#: hygiene guarantee should not rest on an internal coupling between
#: two unrelated constructor arguments.
SMART_FLOW_LOGGING_PARAMETER = "smart_flow_logging"


def _smart_flow_overrides(dashboard_api: Any) -> dict[str, Any]:
    """Arguments that switch off the SDK's self-written cache and log.

    Empty for an SDK with no smart flow at all (3.x, and the test
    doubles that stand in for the real client), because there is then
    no cache to disable and the argument would be a ``TypeError``. The
    declared dependency range spans both majors, so the factory reads
    the constructor rather than assuming one.

    Fail closed on the third case: an SDK that *has* smart flow but not
    the parameter this function knows how to switch off is a renamed or
    restructured cache we would otherwise silently start writing.
    """
    try:
        parameters = inspect.signature(dashboard_api).parameters
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return {}
    smart_flow = [n for n in parameters if n.startswith(SMART_FLOW_PREFIX)]
    if not smart_flow:
        return {}
    if SMART_FLOW_CACHE_PARAMETER not in parameters:
        raise RuntimeError(
            "the installed Meraki SDK exposes smart-flow settings "
            f"({', '.join(sorted(smart_flow))}) but no "
            f"{SMART_FLOW_CACHE_PARAMETER}; refusing to build a client "
            "that may persist organization identifiers outside the "
            "workdir. Pin a supported SDK release."
        )
    overrides: dict[str, Any] = {SMART_FLOW_CACHE_PARAMETER: ""}
    if SMART_FLOW_LOGGING_PARAMETER in parameters:
        overrides[SMART_FLOW_LOGGING_PARAMETER] = False
    return overrides


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
        **_smart_flow_overrides(meraki.DashboardAPI),
        **overrides,
    )
