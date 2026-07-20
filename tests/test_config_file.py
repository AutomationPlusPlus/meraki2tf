"""--config TOML file: loading, precedence, and refusal guards."""

from pathlib import Path

import pytest

from meraki2tf import spec_resolver
from meraki2tf.cli import build_parser, main
from meraki2tf.config import (
    API_KEY_ENV_VAR,
    CONFIG_FILE_REFUSED_KEYS,
    ConfigFileError,
    RuntimeConfig,
    StateBackend,
    load_config_file,
)
from meraki2tf.spec_resolver import SpecResolutionError


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "meraki2tf.toml"
    path.write_text(text, encoding="utf-8")
    return path


def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def offline(url: str) -> str:
        raise SpecResolutionError(f"offline test environment ({url})")

    monkeypatch.setattr(spec_resolver, "_download", offline)


# ---------------------------------------------------------------------------
# Loader: accepted keys and value shapes
# ---------------------------------------------------------------------------


def test_loads_scalars_bools_ints_and_lists(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        org-id = "123456"
        workdir = "dr-kit"
        sync = true
        fail-on-gaps = true
        smtp-port = 587
        webhook-url = ["https://hooks.example.com/a", "https://hooks.example.com/b"]
        alert-email = "netops@example.com"
        """,
    )
    overrides = load_config_file(path)
    assert overrides == {
        "org_id": "123456",
        "workdir": "dr-kit",
        "sync": True,
        "fail_on_gaps": True,
        "smtp_port": 587,
        "webhook_url": [
            "https://hooks.example.com/a",
            "https://hooks.example.com/b",
        ],
        "alert_email": ["netops@example.com"],
    }


def test_backend_config_table_becomes_key_value_items(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        state-backend = "azurerm"

        [backend-config]
        storage_account_name = "storacct"
        container_name = "tfstate"
        key = "org.tfstate"
        use_azuread_auth = true
        """,
    )
    overrides = load_config_file(path)
    assert overrides["state_backend"] == "azurerm"
    assert overrides["backend_config"] == [
        "storage_account_name=storacct",
        "container_name=tfstate",
        "key=org.tfstate",
        "use_azuread_auth=true",
    ]


# ---------------------------------------------------------------------------
# Loader: refusals and malformed input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(CONFIG_FILE_REFUSED_KEYS))
def test_dr_actions_and_confirmations_are_refused(
    tmp_path: Path, key: str
) -> None:
    path = _write(tmp_path, f'{key} = "x"\n')
    with pytest.raises(ConfigFileError, match="typed on the command line"):
        load_config_file(path)


def test_backend_config_credential_key_is_refused(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        [backend-config]
        access_key = "hunter2"
        """,
    )
    with pytest.raises(ConfigFileError, match="credential") as excinfo:
        load_config_file(path)
    assert "hunter2" not in str(excinfo.value)


def test_unknown_key_names_the_valid_ones(tmp_path: Path) -> None:
    path = _write(tmp_path, 'api-key = "sneaky"\n')
    with pytest.raises(ConfigFileError, match="unknown key 'api-key'") as excinfo:
        load_config_file(path)
    assert "org-id" in str(excinfo.value)
    assert "sneaky" not in str(excinfo.value)


def test_invalid_toml_is_reported(tmp_path: Path) -> None:
    path = _write(tmp_path, "org-id = [unterminated\n")
    with pytest.raises(ConfigFileError, match="not valid TOML"):
        load_config_file(path)


def test_missing_file_is_reported(tmp_path: Path) -> None:
    with pytest.raises(ConfigFileError, match="cannot read"):
        load_config_file(tmp_path / "absent.toml")


def test_unknown_state_backend_value_is_refused(tmp_path: Path) -> None:
    path = _write(tmp_path, 'state-backend = "s3-compatible"\n')
    with pytest.raises(ConfigFileError, match="unknown state-backend"):
        load_config_file(path)


@pytest.mark.parametrize("backend", ["local", "azurerm", "s3", "gcs"])
def test_every_supported_state_backend_is_accepted(
    tmp_path: Path, backend: str
) -> None:
    path = _write(tmp_path, f'state-backend = "{backend}"\n')
    assert load_config_file(path) == {"state_backend": backend}


@pytest.mark.parametrize(
    "line, match",
    [
        ('sync = "yes"', "must be a boolean"),
        ("smtp-port = true", "must be an integer"),
        ("org-id = 123456", "must be a string"),
        ("webhook-url = [1, 2]", "array of strings"),
        ('backend-config = "key=value"', "TOML table"),
        ("[backend-config]\nkey = 1.5", "string, integer, or boolean"),
    ],
)
def test_wrongly_typed_values_are_refused(
    tmp_path: Path, line: str, match: str
) -> None:
    path = _write(tmp_path, line + "\n")
    with pytest.raises(ConfigFileError, match=match):
        load_config_file(path)


# ---------------------------------------------------------------------------
# Precedence: CLI > file > built-in default
# ---------------------------------------------------------------------------


def _parse_with_config(tmp_path: Path, text: str, argv: list[str]) -> RuntimeConfig:
    from meraki2tf.cli import _apply_config_file

    path = _write(tmp_path, text)
    parser = build_parser()
    full_argv = ["--config", str(path), *argv]
    args = parser.parse_args(full_argv)
    _apply_config_file(parser, args, full_argv)
    return RuntimeConfig.from_args(args)


def test_file_fills_flags_the_cli_left_at_default(tmp_path: Path) -> None:
    config = _parse_with_config(
        tmp_path,
        """
        org-id = "123456"
        workdir = "dr-kit"
        sync = true
        smtp-port = 587
        """,
        [],
    )
    assert config.org_id == "123456"
    assert config.workdir == Path("dr-kit")
    assert config.sync is True
    assert config.smtp_port == 587


def test_cli_flags_override_file_values(tmp_path: Path) -> None:
    config = _parse_with_config(
        tmp_path,
        """
        org-id = "123456"
        workdir = "dr-kit"
        webhook-url = ["https://hooks.example.com/from-file"]
        """,
        [
            "--org-id", "999999",
            "--webhook-url", "https://hooks.example.com/from-cli",
        ],
    )
    assert config.org_id == "999999"
    assert config.workdir == Path("dr-kit")  # file still fills the rest
    assert config.webhook_urls == ("https://hooks.example.com/from-cli",)


def test_file_backend_settings_flow_into_backend_config(tmp_path: Path) -> None:
    config = _parse_with_config(
        tmp_path,
        """
        state-backend = "azurerm"

        [backend-config]
        storage_account_name = "storacct"
        container_name = "tfstate"
        key = "org.tfstate"
        """,
        [],
    )
    assert config.backend.backend is StateBackend.AZURERM
    assert config.backend.settings == (
        ("storage_account_name", "storacct"),
        ("container_name", "tfstate"),
        ("key", "org.tfstate"),
    )


def test_refused_key_is_a_usage_error_via_main(tmp_path: Path) -> None:
    path = _write(tmp_path, "confirm = true\n")
    with pytest.raises(SystemExit) as excinfo:
        main(["--config", str(path)])
    assert excinfo.value.code == 2


def test_no_config_flag_leaves_args_untouched(tmp_path: Path) -> None:
    parser = build_parser()
    args = parser.parse_args([])
    from meraki2tf.cli import _apply_config_file

    _apply_config_file(parser, args, [])
    assert args.org_id is None
    assert args.workdir == "generated"


# ---------------------------------------------------------------------------
# End-to-end: a config file drives an offline pipeline run
# ---------------------------------------------------------------------------


def test_offline_pipeline_run_from_config_file(
    spec_file: Path,
    dump_file: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A config file supplying spec/from-dump/workdir behaves like flags."""
    _no_network(monkeypatch)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    workdir = tmp_path / "workspace"
    path = _write(
        tmp_path,
        f"""
        spec = {str(spec_file)!r}
        from-dump = {str(dump_file)!r}
        workdir = {str(workdir)!r}
        """,
    )
    exit_code = main(["--config", str(path)])
    assert exit_code == 0
    assert (workdir / "imports.tf").exists()


def test_notification_keys_are_accepted(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        '\n'.join(
            (
                'webhook-format = "teams"',
                'pagerduty = true',
            )
        ),
    )
    overrides = load_config_file(path)
    assert overrides["webhook_format"] == "teams"
    assert overrides["pagerduty"] is True


def test_log_format_key_is_accepted(tmp_path: Path) -> None:
    path = _write(tmp_path, 'log-format = "json"')
    assert load_config_file(path)["log_format"] == "json"
