"""Verbose/clean logging controls and mandatory secret redaction."""

import logging
import sys

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


def test_unquoted_bearer_value_is_fully_redacted() -> None:
    """`Authorization: Bearer <token>` without quotes must not leak the token."""
    out = _filtered_message("Authorization: Bearer 0123abcdrotatedkey")
    assert "0123abcdrotatedkey" not in out
    assert "[REDACTED]" in out


def test_preformatted_exc_text_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    """A record whose traceback was already rendered gets scrubbed too."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "supersecrettoken")
    record = logging.LogRecord(
        name="test", level=logging.ERROR, pathname=__file__, lineno=1,
        msg="boom", args=None, exc_info=None,
    )
    record.exc_text = "Traceback ... Authorization: Bearer supersecrettoken"
    assert SecretRedactionFilter().filter(record)
    assert "supersecrettoken" not in record.exc_text
    assert "[REDACTED]" in record.exc_text


def test_exception_tracebacks_are_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    """logger.exception output is rendered separately and must be scrubbed too."""
    monkeypatch.setenv(API_KEY_ENV_VAR, "supersecrettoken")
    try:
        raise ValueError(
            "unknown url type: 'hooks.example/supersecrettoken'"
        )
    except ValueError:
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname=__file__, lineno=1,
            msg="delivery failed", args=None, exc_info=sys.exc_info(),
        )
    assert SecretRedactionFilter().filter(record)
    rendered = logging.Formatter().format(record)
    assert "supersecrettoken" not in rendered
    assert "[REDACTED]" in rendered
    assert "ValueError" in rendered  # the traceback itself is preserved


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


def test_json_format_emits_parseable_lines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json as _json

    configure_logging(log_format="json")
    handler = logging.getLogger().handlers[0]
    record = logging.LogRecord(
        name="meraki2tf.test",
        level=logging.WARNING,
        pathname=__file__,
        lineno=1,
        msg="drift detected on %s",
        args=("meraki_networks.n_1",),
        exc_info=None,
    )
    for filt in handler.filters:
        filt.filter(record)
    entry = _json.loads(handler.format(record))
    assert entry["level"] == "WARNING"
    assert entry["logger"] == "meraki2tf.test"
    assert entry["message"] == "drift detected on meraki_networks.n_1"
    assert "timestamp" in entry
    assert "exception" not in entry


def test_json_format_redacts_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    import json as _json

    monkeypatch.setenv(API_KEY_ENV_VAR, "super-secret-token")
    configure_logging(log_format="json")
    handler = logging.getLogger().handlers[0]
    record = logging.LogRecord(
        name="meraki2tf.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="key is super-secret-token",
        args=None,
        exc_info=None,
    )
    for filt in handler.filters:
        filt.filter(record)
    entry = _json.loads(handler.format(record))
    assert "super-secret-token" not in entry["message"]
    assert "[REDACTED]" in entry["message"]


def test_json_format_carries_scrubbed_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json as _json

    configure_logging(log_format="json")
    handler = logging.getLogger().handlers[0]
    try:
        raise ValueError("boom")
    except ValueError:
        record = logging.LogRecord(
            name="meraki2tf.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="failed",
            args=None,
            exc_info=sys.exc_info(),
        )
    for filt in handler.filters:
        filt.filter(record)
    entry = _json.loads(handler.format(record))
    assert entry["message"] == "failed"
    assert "ValueError: boom" in entry["exception"]


def test_text_format_stays_the_default() -> None:
    configure_logging()
    handler = logging.getLogger().handlers[0]
    assert not isinstance(
        handler.formatter, type(None)
    )
    record = logging.LogRecord(
        name="meraki2tf.test", level=logging.INFO, pathname=__file__,
        lineno=1, msg="hello", args=None, exc_info=None,
    )
    rendered = handler.format(record)
    assert "hello" in rendered
    assert not rendered.startswith("{")
