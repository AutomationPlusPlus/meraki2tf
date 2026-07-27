"""Dynamic Meraki OpenAPI spec ingestion.

Everything the translation engine knows about the Meraki API — paths,
operations, resource groupings, parameters, compound ID components — is
derived at runtime from the OpenAPI document. Hard-coded endpoint or
mapping tables are prohibited by the project contract.
"""

from meraki2tf.spec.engine import OperationSpec, SpecIngestionEngine

__all__ = ["OperationSpec", "SpecIngestionEngine"]
