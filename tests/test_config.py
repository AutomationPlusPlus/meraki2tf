"""Runtime configuration and secret-sourcing behavior."""

from pathlib import Path

import pytest

from meraki2tf.cli import build_parser
from meraki2tf.config import (
    API_KEY_ENV_VAR,
    ExecutionMode,
    MissingApiKeyError,
    RuntimeConfig,
    read_api_key,
)


def _config(argv: list[str]) -> RuntimeConfig:
    return RuntimeConfig.from_args(build_parser().parse_args(argv))


def test_defaults_to_live_mode() -> None:
    config = _config(["--spec", "openapi.json"])
    assert config.mode is ExecutionMode.LIVE
    assert config.dump_path is None
    assert config.spec_path == Path("openapi.json")


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
