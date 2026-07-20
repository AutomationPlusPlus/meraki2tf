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
    WEBHOOK_URL_ENV_VAR,
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


@pytest.mark.parametrize(
    "secret_key",
    ["access_key", "sas_token", "client_secret", "oidc_token",
     "oidc_request_token"],
)
def test_backend_config_rejects_credential_keys(secret_key: str) -> None:
    with pytest.raises(BackendConfigError, match="credential"):
        _config([*_AZURERM_MIN, "--backend-config", f"{secret_key}=super-secret"])


def test_backend_config_requires_key_value_form() -> None:
    with pytest.raises(BackendConfigError, match="KEY=VALUE"):
        _config([*_AZURERM_MIN, "--backend-config", "not-a-pair"])


def test_backend_config_key_value_error_does_not_echo_the_value() -> None:
    """A mistyped credential (colon instead of =) must not have its
    value repeated into the usage error / CI logs."""
    with pytest.raises(BackendConfigError) as excinfo:
        _config([*_AZURERM_MIN, "--backend-config", "access_key:SUPERSECRET"])
    assert "SUPERSECRET" not in str(excinfo.value)


def test_backend_config_file_credential_key_is_refused(tmp_path: Path) -> None:
    """terraform init persists file-sourced backend settings in plaintext
    into .terraform state, so a credential in the file is refused just
    like the argv form."""
    backend_file = tmp_path / "azure.tfbackend"
    backend_file.write_text(
        'storage_account_name = "sa"\n'
        'container_name        = "tfstate"\n'
        'key                   = "org.tfstate"\n'
        'access_key            = "SUPERSECRET"\n',
        encoding="utf-8",
    )
    with pytest.raises(BackendConfigError, match="credential") as excinfo:
        _config(
            ["--state-backend", "azurerm",
             "--backend-config-file", str(backend_file)]
        )
    assert "SUPERSECRET" not in str(excinfo.value)


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


def test_s3_backend_parses_settings_into_init_args() -> None:
    backend = _config(
        ["--state-backend", "s3",
         "--backend-config", "bucket=meraki-dr-state",
         "--backend-config", "key=org.tfstate",
         "--backend-config", "region=us-east-1"]
    ).backend
    assert backend.backend is StateBackend.S3
    assert backend.is_remote
    assert backend.init_args() == (
        "-backend-config=bucket=meraki-dr-state",
        "-backend-config=key=org.tfstate",
        "-backend-config=region=us-east-1",
    )


def test_gcs_backend_parses_settings_into_init_args() -> None:
    backend = _config(
        ["--state-backend", "gcs",
         "--backend-config", "bucket=meraki-dr-state",
         "--backend-config", "prefix=org"]
    ).backend
    assert backend.backend is StateBackend.GCS
    assert backend.is_remote
    assert backend.init_args() == (
        "-backend-config=bucket=meraki-dr-state",
        "-backend-config=prefix=org",
    )


def test_s3_backend_requires_state_address_settings() -> None:
    with pytest.raises(BackendConfigError, match="bucket, key"):
        _config(["--state-backend", "s3"])
    with pytest.raises(BackendConfigError, match="key"):
        _config(
            ["--state-backend", "s3", "--backend-config", "bucket=meraki-dr"]
        )


def test_gcs_backend_requires_bucket() -> None:
    with pytest.raises(BackendConfigError, match="bucket"):
        _config(["--state-backend", "gcs"])


@pytest.mark.parametrize(
    "argv_backend, secret_key",
    [
        ("s3", "access_key"),
        ("s3", "secret_key"),
        ("s3", "token"),
        ("s3", "sse_customer_key"),
        ("gcs", "credentials"),
        ("gcs", "access_token"),
        ("gcs", "encryption_key"),
    ],
)
def test_s3_and_gcs_credential_keys_are_refused(
    argv_backend: str, secret_key: str
) -> None:
    with pytest.raises(BackendConfigError, match="credential") as excinfo:
        _config(
            ["--state-backend", argv_backend,
             "--backend-config", "bucket=meraki-dr-state",
             "--backend-config", "key=org.tfstate",
             "--backend-config", f"{secret_key}=SUPERSECRET"]
        )
    assert "SUPERSECRET" not in str(excinfo.value)


def test_s3_backend_config_file_skips_required_check() -> None:
    backend = _config(
        ["--state-backend", "s3", "--backend-config-file", "aws.tfbackend"]
    ).backend
    assert backend.is_remote
    assert backend.init_args()[0] == "-backend-config=aws.tfbackend"


def test_gcs_credential_key_in_backend_file_is_refused(
    tmp_path: Path,
) -> None:
    backend_file = tmp_path / "gcs.tfbackend"
    backend_file.write_text(
        'bucket      = "meraki-dr-state"\n'
        'credentials = "{\\"type\\": \\"service_account\\"}"\n',
        encoding="utf-8",
    )
    with pytest.raises(BackendConfigError, match="credential") as excinfo:
        _config(
            ["--state-backend", "gcs",
             "--backend-config-file", str(backend_file)]
        )
    assert "service_account" not in str(excinfo.value)


def test_backend_config_file_credential_key_in_json_is_refused(
    tmp_path: Path,
) -> None:
    """terraform init accepts JSON backend-config files too; a
    line-based HCL scan alone would wave {"access_key": ...} straight
    through the credential refusal."""
    backend_file = tmp_path / "bc.json"
    backend_file.write_text(
        '{"storage_account_name": "sa", "container_name": "tfstate",\n'
        ' "key": "org.tfstate", "access_key": "SUPERSECRET"}\n',
        encoding="utf-8",
    )
    with pytest.raises(BackendConfigError, match="credential") as excinfo:
        _config(
            ["--state-backend", "azurerm",
             "--backend-config-file", str(backend_file)]
        )
    assert "SUPERSECRET" not in str(excinfo.value)


def test_backend_config_file_nested_json_credential_is_refused(
    tmp_path: Path,
) -> None:
    """s3 nests web-identity credentials under
    assume_role_with_web_identity; the JSON walk must reach them."""
    backend_file = tmp_path / "bc.json"
    backend_file.write_text(
        '{"bucket": "b", "key": "state", "region": "us-east-1",\n'
        ' "assume_role_with_web_identity":\n'
        '   {"web_identity_token": "SECRETJWT"}}\n',
        encoding="utf-8",
    )
    with pytest.raises(BackendConfigError, match="credential") as excinfo:
        _config(
            ["--state-backend", "s3",
             "--backend-config-file", str(backend_file)]
        )
    assert "SECRETJWT" not in str(excinfo.value)


def test_web_identity_token_is_refused_on_argv() -> None:
    with pytest.raises(BackendConfigError, match="credential") as excinfo:
        _config(
            ["--state-backend", "s3",
             "--backend-config", "bucket=b",
             "--backend-config", "key=state",
             "--backend-config", "web_identity_token=SECRETJWT"]
        )
    assert "SECRETJWT" not in str(excinfo.value)


def test_backend_config_file_hcl_scan_skips_comments_and_blanks(
    tmp_path: Path,
) -> None:
    """A benign HCL file with comment and blank lines scans clean end to
    end — nothing there is credential-shaped."""
    backend_file = tmp_path / "azure.tfbackend"
    backend_file.write_text(
        "# state address for the DR runbook\n"
        "\n"
        "// terraform init reads this via -backend-config\n"
        'storage_account_name = "sa"\n'
        'container_name        = "tfstate"\n'
        'key                   = "org.tfstate"\n',
        encoding="utf-8",
    )
    backend = _config(
        ["--state-backend", "azurerm",
         "--backend-config-file", str(backend_file)]
    ).backend
    assert backend.is_remote
    assert backend.init_args()[0] == f"-backend-config={backend_file}"


def test_backend_config_file_json_credential_inside_list_is_refused(
    tmp_path: Path,
) -> None:
    """The JSON walk descends into list values too — a credential
    wrapped in an array must not slip past the refusal."""
    backend_file = tmp_path / "bc.json"
    backend_file.write_text(
        '{"bucket": "meraki-dr-state", "key": "org.tfstate",\n'
        ' "extras": [{"region": "us-east-1"},\n'
        '            {"secret_key": "SUPERSECRET"}]}\n',
        encoding="utf-8",
    )
    with pytest.raises(BackendConfigError, match="credential") as excinfo:
        _config(
            ["--state-backend", "s3",
             "--backend-config-file", str(backend_file)]
        )
    assert "SUPERSECRET" not in str(excinfo.value)


def test_webhook_urls_come_from_env_var_and_dedupe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The env var keeps token-bearing URLs out of argv: ':::'-separated
    targets are split, blanks dropped, and env-sourced entries lead with
    duplicates collapsed."""
    monkeypatch.setenv(
        WEBHOOK_URL_ENV_VAR,
        " https://hooks.example/a ::: https://hooks.example/b :::",
    )
    config = _config(
        ["--spec", "openapi.json",
         "--webhook-url", "https://hooks.example/a",
         "--webhook-url", "https://hooks.example/c"]
    )
    assert config.webhook_urls == (
        "https://hooks.example/a",
        "https://hooks.example/b",
        "https://hooks.example/c",
    )
