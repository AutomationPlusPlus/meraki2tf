"""Provider catalog: what the installed Terraform provider can manage.

Live-org testing exposed that the ``CiscoDevNet/meraki`` provider's
resource type names cannot be derived from Meraki API paths alone (the
provider hand-curates scope disambiguation, segment dedupe, and
singularization). The ground truth is the provider itself: since
v1.12.0 every resource publishes a **resource identity schema** through
``terraform providers schema -json``, giving both the authoritative
resource names and the identity attributes each import needs.

This module models that catalog and its provenance chain:

1. **Live** — a keyed run initializes the workspace and dumps the
   installed provider's schema, so the catalog always matches the
   provider version terraform actually selected. The result is cached
   in the workdir.
2. **Workdir cache** — keyless/air-gapped runs (offline dump mode)
   reuse the cache left by a previous keyed run against that workdir.
3. **Bundled fallback** — a copy of the v1.12.2 identity schemas ships
   inside the package for first-ever offline runs.

The catalog is *provider metadata ingested at runtime*, exactly like the
OpenAPI document — no API-path-to-resource mapping table is hard-coded
anywhere (see the project contract).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources as importlib_resources
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, types only
    from meraki2tf.terraform_runner import TerraformRunner

logger = logging.getLogger(__name__)

#: Workdir cache filename; written on keyed runs, read by keyless ones.
CATALOG_CACHE_FILENAME = "provider_catalog.json"

_BUNDLED_RESOURCE = "provider_catalog.json"


class CatalogError(RuntimeError):
    """A catalog document was malformed or missing identity schemas."""


@dataclass(frozen=True)
class ProviderCatalog:
    """Resource identity schemas of one installed Meraki provider.

    ``resources`` maps each Terraform resource type name to the frozen
    set of its identity attribute names (``{"network_id", "number"}``
    for ``meraki_wireless_ssid``). ``source`` records provenance for
    logging (``"terraform providers schema"``, a cache path, or
    ``"bundled"``).
    """

    resources: Mapping[str, frozenset[str]]
    source: str

    @classmethod
    def from_schema_document(
        cls, document: Mapping[str, Any], source: str = "terraform providers schema"
    ) -> "ProviderCatalog":
        """Parse full ``terraform providers schema -json`` output.

        Tolerant of the provider registry key (any key containing
        ``meraki`` matches, so mirrors and registry proxies work), but
        strict about identity schemas: a provider without them predates
        v1.12.0 and cannot drive import-ID composition.
        """
        schemas = document.get("provider_schemas")
        if not isinstance(schemas, Mapping):
            raise CatalogError(
                "Schema document has no 'provider_schemas' object."
            )
        provider = next(
            (
                value
                for key, value in schemas.items()
                if "meraki" in key.lower() and isinstance(value, Mapping)
            ),
            None,
        )
        if provider is None:
            raise CatalogError(
                "No Meraki provider found in the schema document."
            )
        identity = provider.get("resource_identity_schemas")
        if not isinstance(identity, Mapping) or not identity:
            raise CatalogError(
                "Provider publishes no resource identity schemas; "
                "meraki2tf requires CiscoDevNet/meraki >= 1.12.0."
            )
        resources = {
            str(name): frozenset(schema.get("attributes", {}))
            for name, schema in identity.items()
            if isinstance(schema, Mapping)
        }
        return cls(resources=resources, source=source)

    @classmethod
    def from_cache_file(cls, path: Path) -> "ProviderCatalog":
        """Load a catalog previously cached by :func:`resolve_catalog`."""
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CatalogError(f"Catalog cache {path} is unreadable: {exc}") from exc
        return cls._from_cache_payload(document, source=str(path))

    @classmethod
    def bundled(cls) -> "ProviderCatalog":
        """The packaged fallback catalog (CiscoDevNet/meraki v1.12.2)."""
        text = (
            importlib_resources.files("meraki2tf.data")
            .joinpath(_BUNDLED_RESOURCE)
            .read_text(encoding="utf-8")
        )
        return cls._from_cache_payload(json.loads(text), source="bundled")

    @classmethod
    def _from_cache_payload(
        cls, document: Any, source: str
    ) -> "ProviderCatalog":
        if not isinstance(document, Mapping):
            raise CatalogError(f"Catalog payload from {source} is not an object.")
        raw = document.get("resources")
        if not isinstance(raw, Mapping) or not raw:
            raise CatalogError(f"Catalog payload from {source} has no resources.")
        resources = {
            str(name): frozenset(str(attr) for attr in attrs)
            for name, attrs in raw.items()
        }
        return cls(resources=resources, source=source)

    def to_cache_payload(self) -> dict[str, Any]:
        """JSON-serializable form for the workdir cache."""
        return {
            "provider": "registry.terraform.io/ciscodevnet/meraki",
            "resources": {
                name: sorted(attrs) for name, attrs in sorted(self.resources.items())
            },
        }


def resolve_catalog(runner: "TerraformRunner", keyed: bool) -> ProviderCatalog:
    """Resolve the catalog through the live → cache → bundled chain.

    Keyed runs ask the installed provider itself (init + schema dump)
    and refresh the workdir cache; any failure degrades with a warning
    instead of crashing the DR run — a stale catalog still produces a
    kit, whereas a crash produces nothing.
    """
    # Imported here (not at module top) to avoid a hard import cycle:
    # terraform_runner imports this module for its return type.
    from meraki2tf.terraform_runner import TerraformError

    cache = runner.workdir / CATALOG_CACHE_FILENAME
    if keyed:
        try:
            runner.init()
            catalog = runner.provider_schema_catalog()
            cache.write_text(
                json.dumps(catalog.to_cache_payload(), indent=1) + "\n",
                encoding="utf-8",
            )
            logger.info(
                "Provider catalog: %d resource identity schema(s) from the "
                "installed provider (cached at %s).",
                len(catalog.resources), cache,
            )
            return catalog
        except (TerraformError, CatalogError, OSError) as exc:
            logger.warning(
                "Could not read the installed provider's schema (%s); "
                "falling back to a cached/bundled catalog.",
                exc,
            )
    if cache.exists():
        try:
            catalog = ProviderCatalog.from_cache_file(cache)
            logger.info(
                "Provider catalog: %d resource(s) from workdir cache %s.",
                len(catalog.resources), cache,
            )
            return catalog
        except CatalogError as exc:
            logger.warning("%s; falling back to the bundled catalog.", exc)
    catalog = ProviderCatalog.bundled()
    logger.info(
        "Provider catalog: %d resource(s) from the bundled fallback "
        "(CiscoDevNet/meraki v1.12.2 identity schemas). Run once with an "
        "API key to refresh it from the installed provider.",
        len(catalog.resources),
    )
    return catalog
