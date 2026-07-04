"""Runtime configuration and secret-sourcing behavior."""

from pathlib import Path

import pytest

from meraki2tf.cli import build_parser
from meraki2tf.config import (
    API_KEY_ENV_VAR,
    BackendConfig,
    BackendConfigError,
    ExecutionMode,
    MissingApiKeyError,
    RuntimeConfig,
    StateBackend,
    read_api_key,
)

_AZURERM_MIN = [
    "--state-backend", "azurerm",
    "--backend-config", "storage_account_name=sa",
    "--backend-config", "container_name=tfstate",
    "--backend-config", "key=org.tfstate",
]


def _config(argv: list[str]) -> RuntimeConfig:
    return RuntimeConfig.from_args(build_parser().parse_args(argv))


def test_defaults_to_live_mode() -> None:
    config = _config(["--spec", "openapi.json"])
    assert config.mode is ExecutionMode.LIVE
    assert config.dump_path is None
    assert config.spec_path == Path("openapi.json")


def test_spec_path_defaults_to_auto_resolution() -> None:
    assert _config([]).spec_path is None


def test_state_file_defaults_to_workdir_and_accepts_override() -> None:
    assert _config([]).state_file is None
    config = _config(["--state-file", "/var/lib/meraki2tf/org.tfstate"])
    assert config.state_file == Path("/var/lib/meraki2tf/org.tfstate")


def test_dump_flag_selects_dump_mode() -> None:
    config = _config(
        ["--spec", "openapi.json", "--from-dump", "snapshots/site.json", "-v"]
    )
    assert config.mode is ExecutionMode.DUMP
    assert config.dump_path == Path("snapshots/site.json")
    assert config.verbose


def test_config_never_carries_credentials() -> None:
    config = _config(["--spec", "openapi.json"])
    assert "api_key" not in {f for f in config.__dataclass_fields__}
    assert "token" not in repr(config).lower()


def test_read_api_key_returns_env_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "unit-test-token")
    assert read_api_key() == "unit-test-token"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_read_api_key_rejects_missing_or_blank(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    if value is None:
        monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(API_KEY_ENV_VAR, value)
    with pytest.raises(MissingApiKeyError):
        read_api_key()


def test_backend_defaults_to_local() -> None:
    backend = _config([]).backend
    assert backend.backend is StateBackend.LOCAL
    assert not backend.is_remote
    assert backend.init_args() == ()


def test_azurerm_backend_parses_settings_into_init_args() -> None:
    backend = _config([*_AZURERM_MIN, "--backend-config", "resource_group_name=rg"]).backend
    assert backend.backend is StateBackend.AZURERM
    assert backend.is_remote
    assert backend.init_args() == (
        "-backend-config=storage_account_name=sa",
        "-backend-config=container_name=tfstate",
        "-backend-config=key=org.tfstate",
        "-backend-config=resource_group_name=rg",
    )


def test_backend_config_file_leads_init_args_and_skips_required_check() -> None:
    # A config file may supply the required settings out of band, so the
    # required-key check is skipped and the file arg comes first.
    backend = _config(
        ["--state-backend", "azurerm", "--backend-config-file", "azure.tfbackend"]
    ).backend
    assert backend.is_remote
    assert backend.init_args()[0] == "-backend-config=azure.tfbackend"


@pytest.mark.parametrize("secret_key", ["access_key", "sas_token", "client_secret"])
def test_backend_config_rejects_credential_keys(secret_key: str) -> None:
    with pytest.raises(BackendConfigError, match="credential"):
        _config([*_AZURERM_MIN, "--backend-config", f"{secret_key}=super-secret"])


def test_backend_config_requires_key_value_form() -> None:
    with pytest.raises(BackendConfigError, match="KEY=VALUE"):
        _config([*_AZURERM_MIN, "--backend-config", "not-a-pair"])


def test_backend_config_rejected_for_local_backend() -> None:
    with pytest.raises(BackendConfigError, match="remote"):
        _config(["--backend-config", "container_name=tfstate"])


def test_azurerm_backend_requires_core_settings() -> None:
    with pytest.raises(BackendConfigError, match="container_name"):
        _config(["--state-backend", "azurerm", "--backend-config", "key=org.tfstate"])


def test_from_cli_rejects_unknown_backend() -> None:
    # argparse's choices normally guards this; from_cli is defensive too.
    with pytest.raises(BackendConfigError, match="unknown"):
        BackendConfig.from_cli("consul", None, None)
