"""Provider catalog: schema parsing, provenance chain, cache round-trip."""

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from conftest import fixture_schema_document

from meraki2tf import provider_catalog as pc_module
from meraki2tf.provider_catalog import (
    CATALOG_CACHE_FILENAME,
    CatalogError,
    ProviderCatalog,
    resolve_catalog,
)
from meraki2tf.terraform_runner import TerraformError


def test_from_schema_document_extracts_identity_attributes() -> None:
    catalog = ProviderCatalog.from_schema_document(fixture_schema_document())
    assert catalog.resources["meraki_network"] == frozenset(
        {"id", "organization_id"}
    )
    assert catalog.resources["meraki_wireless_ssid"] == frozenset(
        {"network_id", "number"}
    )
    assert catalog.source == "terraform providers schema"


def test_from_schema_document_tolerates_any_meraki_registry_key() -> None:
    document = fixture_schema_document()
    document["provider_schemas"] = {
        "example.mirror/CiscoDevNet/meraki": document["provider_schemas"][
            "registry.terraform.io/ciscodevnet/meraki"
        ]
    }
    catalog = ProviderCatalog.from_schema_document(document)
    assert "meraki_device" in catalog.resources


@pytest.mark.parametrize(
    "document, message",
    [
        ({}, "provider_schemas"),
        ({"provider_schemas": {"registry.terraform.io/other/aws": {}}}, "Meraki"),
        (
            {
                "provider_schemas": {
                    "registry.terraform.io/ciscodevnet/meraki": {
                        "resource_schemas": {}
                    }
                }
            },
            "identity",
        ),
    ],
)
def test_from_schema_document_rejects_malformed_input(
    document: dict[str, Any], message: str
) -> None:
    with pytest.raises(CatalogError, match=message):
        ProviderCatalog.from_schema_document(document)


def test_cache_payload_round_trips(tmp_path: Path) -> None:
    original = ProviderCatalog.from_schema_document(fixture_schema_document())
    cache = tmp_path / CATALOG_CACHE_FILENAME
    cache.write_text(json.dumps(original.to_cache_payload()), encoding="utf-8")
    loaded = ProviderCatalog.from_cache_file(cache)
    assert loaded.resources == dict(original.resources)
    assert loaded.source == str(cache)


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        "[]",
        '{"resources": {}}',
        # Malformed attribute values must be CatalogError (degrades to
        # the bundled fallback), never TypeError (crashes the DR run) —
        # and a string here would silently explode into characters.
        '{"resources": {"meraki_network": null}}',
        '{"resources": {"meraki_network": "id,organization_id"}}',
    ],
)
def test_cache_file_rejects_malformed_payloads(
    tmp_path: Path, content: str
) -> None:
    cache = tmp_path / "cache.json"
    cache.write_text(content, encoding="utf-8")
    with pytest.raises(CatalogError):
        ProviderCatalog.from_cache_file(cache)


def test_from_schema_document_tolerates_null_attributes() -> None:
    """A provider schema quirk (attributes: null) degrades to an
    attributeless identity instead of crashing catalog resolution."""
    document = {
        "provider_schemas": {
            "registry.terraform.io/ciscodevnet/meraki": {
                "resource_identity_schemas": {
                    "meraki_network": {"attributes": None},
                }
            }
        }
    }
    catalog = ProviderCatalog.from_schema_document(document)
    assert catalog.resources["meraki_network"] == frozenset()


def test_cache_file_missing_is_a_catalog_error(tmp_path: Path) -> None:
    with pytest.raises(CatalogError, match="unreadable"):
        ProviderCatalog.from_cache_file(tmp_path / "absent.json")


def test_bundled_catalog_ships_the_full_provider_surface() -> None:
    catalog = ProviderCatalog.bundled()
    assert catalog.source == "bundled"
    assert len(catalog.resources) == 205
    assert catalog.resources["meraki_appliance_vlan"] == frozenset(
        {"id", "network_id"}
    )
    assert "force_delete" in catalog.resources["meraki_network_group_policy"]


class FakeRunner:
    """Duck-typed TerraformRunner for the resolution chain."""

    def __init__(
        self,
        workdir: Path,
        catalog: ProviderCatalog | None = None,
        init_error: Exception | None = None,
    ) -> None:
        self.workdir = workdir
        self._catalog = catalog
        self._init_error = init_error
        self.initialized = False

    def init(self) -> SimpleNamespace:
        if self._init_error is not None:
            raise self._init_error
        self.initialized = True
        return SimpleNamespace(returncode=0)

    def provider_schema_catalog(self) -> ProviderCatalog:
        if self._catalog is None:
            raise TerraformError("no schema available")
        return self._catalog


def test_keyed_resolution_reads_provider_and_writes_cache(tmp_path: Path) -> None:
    live = ProviderCatalog.from_schema_document(fixture_schema_document())
    runner = FakeRunner(tmp_path, catalog=live)
    resolved = resolve_catalog(runner, keyed=True)  # type: ignore[arg-type]
    assert runner.initialized
    assert resolved.resources == dict(live.resources)
    cached = json.loads(
        (tmp_path / CATALOG_CACHE_FILENAME).read_text(encoding="utf-8")
    )
    assert "meraki_network" in cached["resources"]


def test_keyed_failure_falls_back_to_cache(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    live = ProviderCatalog.from_schema_document(fixture_schema_document())
    cache = tmp_path / CATALOG_CACHE_FILENAME
    cache.write_text(json.dumps(live.to_cache_payload()), encoding="utf-8")
    runner = FakeRunner(tmp_path, init_error=TerraformError("init exploded"))
    with caplog.at_level(logging.WARNING):
        resolved = resolve_catalog(runner, keyed=True)  # type: ignore[arg-type]
    assert resolved.source == str(cache)
    assert any("falling back" in record.message for record in caplog.records)


def test_keyless_resolution_prefers_cache_over_bundled(tmp_path: Path) -> None:
    live = ProviderCatalog.from_schema_document(fixture_schema_document())
    cache = tmp_path / CATALOG_CACHE_FILENAME
    cache.write_text(json.dumps(live.to_cache_payload()), encoding="utf-8")
    runner = FakeRunner(tmp_path)
    resolved = resolve_catalog(runner, keyed=False)  # type: ignore[arg-type]
    assert resolved.source == str(cache)
    assert not runner.initialized  # keyless runs never touch terraform


def test_corrupt_cache_falls_back_to_bundled(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / CATALOG_CACHE_FILENAME).write_text("{corrupt", encoding="utf-8")
    runner = FakeRunner(tmp_path)
    with caplog.at_level(logging.WARNING):
        resolved = resolve_catalog(runner, keyed=False)  # type: ignore[arg-type]
    assert resolved.source == "bundled"
    assert len(resolved.resources) == 205


def test_keyless_resolution_without_cache_uses_bundled(tmp_path: Path) -> None:
    resolved = resolve_catalog(FakeRunner(tmp_path), keyed=False)  # type: ignore[arg-type]
    assert resolved.source == "bundled"


def test_module_logger_is_namespaced() -> None:
    assert pc_module.logger.name == "meraki2tf.provider_catalog"
