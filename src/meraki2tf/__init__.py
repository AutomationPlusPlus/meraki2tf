"""meraki2tf: extract Cisco Meraki configurations into Terraform structures.

The pipeline is spec-driven end to end: the Meraki OpenAPI document is
ingested dynamically to derive the resource registry, so no endpoint or
mapping table is ever hard-coded.
"""

__version__ = "0.2.0"
