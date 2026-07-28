"""meraki2tf: extract Cisco Meraki configurations into Terraform structures.

The pipeline is spec-driven end to end: the Meraki OpenAPI document is
ingested dynamically to derive the resource registry, so no endpoint or
mapping table is ever hard-coded.
"""

import importlib.metadata

try:
    #: Read from the installed distribution metadata so the version has a
    #: single source of truth — ``pyproject.toml``. A hardcoded copy here
    #: silently goes stale the moment the version is bumped (it is exactly
    #: the attribute a bump for a release changes), while ``--version``
    #: (which already reads the metadata) stays correct.
    __version__ = importlib.metadata.version("meraki2tf")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover
    # An uninstalled source tree (no distribution metadata on the path).
    __version__ = "0+unknown"
