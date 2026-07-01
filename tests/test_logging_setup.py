"""Verbose/clean logging controls and mandatory secret redaction."""

import logging

import pytest

from meraki2tf.config import API_KEY_ENV_VAR
from meraki2tf.logging_setup import SecretRedactionFilter, configure_logging


def _filtered_message(message: str) -> str:
    record = logging.LogRecord(
        name="test", level=logging.DEBUG, pathname=__file__, lineno=1,
        msg=message, args=None, exc_info=None,
    )
    assert SecretRedactionFilter().filter(record)
    return record.getMessage()


def test_authorization_header_is_redacted() -> None:
    out = _filtered_message("request headers: {'Authorization': 'Bearer abc123secret'}")
    assert "abc123secret" not in out
    assert "[REDACTED]" in out


def test_meraki_api_key_header_is_redacted() -> None:
    out = _filtered_message("X-Cisco-Meraki-API-Key: deadbeef42")
    assert "deadbeef42" not in out
    assert "[REDACTED]" in out


def test_raw_token_value_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "supersecrettoken")
    out = _filtered_message("debug dump includes supersecrettoken inline")
    assert "supersecrettoken" not in out
    assert "[REDACTED]" in out


def test_benign_messages_pass_through(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    assert _filtered_message("synced 12 resources") == "synced 12 resources"


@pytest.mark.parametrize("verbose,expected", [(False, logging.INFO), (True, logging.DEBUG)])
def test_configure_logging_sets_level_and_redaction(verbose: bool, expected: int) -> None:
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers, root.level
    try:
        configure_logging(verbose=verbose)
        assert root.level == expected
        assert len(root.handlers) == 1
        assert any(
            isinstance(f, SecretRedactionFilter) for f in root.handlers[0].filters
        )
    finally:
        root.handlers, root.level = saved_handlers, saved_level
