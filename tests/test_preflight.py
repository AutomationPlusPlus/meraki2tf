"""Preflight engines: --check validation, --estimate arithmetic, and the
shared pre-sweep validations (baseline header, rebuild-org resolution)."""

import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from conftest import _op

from meraki2tf import preflight
from meraki2tf.cli import build_dispatcher, build_parser
from meraki2tf.config import API_KEY_ENV_VAR, RuntimeConfig
from meraki2tf.openapi_parser import OpenApiParser
from meraki2tf.provider_catalog import CatalogError
from meraki2tf.providers.dump import MalformedDumpError
from meraki2tf.snapshot_diff import (
    BaselineOrgMismatchError,
    PartialBaselineError,
    SanitizedBaselineError,
    UnrecognizedBaselineError,
)
from meraki2tf import terraform_runner
from meraki2tf.terraform_runner import (
    TerraformError,
    TerraformNotFoundError,
    ensure_supported_terraform,
    parse_terraform_version,
    probe_terraform_version,
    version_tuple,
)


def _config(argv: list[str]) -> RuntimeConfig:
    return RuntimeConfig.from_args(build_parser().parse_args(argv))


def _stub_meraki_orgs(
    monkeypatch: pytest.MonkeyPatch, organizations: Any
) -> None:
    """Fake meraki module whose getOrganizations returns (or raises)."""

    def get_orgs() -> Any:
        if isinstance(organizations, Exception):
            raise organizations
        return organizations

    def dashboard(**kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            organizations=SimpleNamespace(getOrganizations=get_orgs)
        )

    stub = types.ModuleType("meraki")
    stub.DashboardAPI = dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)


def _fake_terraform(
    monkeypatch: pytest.MonkeyPatch, stdout: str = "Terraform v1.7.5\n"
) -> None:
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda command, **kwargs: SimpleNamespace(
            returncode=0, stdout=stdout, stderr=""
        ),
    )


def _results_by_name(results: list[preflight.CheckResult]) -> dict[str, Any]:
    return {result.name: result for result in results}


# ---------------------------------------------------------------------------
# terraform version probing (terraform_runner helpers)
# ---------------------------------------------------------------------------


def test_parse_terraform_version_plain() -> None:
    output = "Terraform v1.7.5\non linux_amd64\n"
    assert parse_terraform_version(output) == "1.7.5"


def test_parse_terraform_version_json() -> None:
    output = json.dumps(
        {"terraform_version": "1.9.8", "platform": "linux_amd64"}
    )
    assert parse_terraform_version(output) == "1.9.8"


def test_parse_terraform_version_braced_garbage_falls_to_regex() -> None:
    assert parse_terraform_version('{"broken Terraform v1.6.2') == "1.6.2"


def test_parse_terraform_version_json_without_version_field() -> None:
    assert parse_terraform_version('{"platform": "linux_amd64"}') is None


def test_parse_terraform_version_unrecognizable() -> None:
    assert parse_terraform_version("some wrapper banner\n") is None


def test_version_tuple_ignores_prerelease_suffix() -> None:
    assert version_tuple("1.5.0-beta1") == (1, 5, 0)
    assert version_tuple("1.7") == (1, 7)


def test_probe_terraform_version_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_terraform(monkeypatch, "Terraform v1.8.0\n")
    assert probe_terraform_version("terraform") == "1.8.0"


def test_probe_terraform_version_missing_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_missing(command: Any, **kwargs: Any) -> None:
        raise FileNotFoundError(2, "No such file", "terraform")

    monkeypatch.setattr(terraform_runner.subprocess, "run", raise_missing)
    with pytest.raises(TerraformNotFoundError) as excinfo:
        probe_terraform_version("terraform")
    assert "--terraform-bin" in str(excinfo.value)


def test_probe_terraform_version_unlaunchable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_permission(command: Any, **kwargs: Any) -> None:
        raise PermissionError(13, "Permission denied", "terraform")

    monkeypatch.setattr(terraform_runner.subprocess, "run", raise_permission)
    with pytest.raises(TerraformNotFoundError) as excinfo:
        probe_terraform_version("/opt/tf")
    assert "could not be launched" in str(excinfo.value)


def test_ensure_supported_terraform_accepts_current(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_terraform(monkeypatch, "Terraform v1.5.0\n")
    assert ensure_supported_terraform("terraform") == "1.5.0"


def test_ensure_supported_terraform_refuses_old(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fake_terraform(monkeypatch, "Terraform v1.4.7\n")
    with pytest.raises(TerraformError) as excinfo:
        ensure_supported_terraform("terraform")
    assert "too old" in str(excinfo.value)
    assert "1.5.0" in str(excinfo.value)


def test_ensure_supported_terraform_tolerates_unparseable(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A wrapper with nonstandard output warns but never blocks the run
    (the generated required_version constraint still gates the kit)."""
    _fake_terraform(monkeypatch, "wrapped tf runner\n")
    with caplog.at_level("WARNING"):
        assert ensure_supported_terraform("terraform") is None
    assert "Could not parse a version" in caplog.text


def test_provider_template_pins_required_version(tmp_path: Path) -> None:
    runner = terraform_runner.TerraformRunner(tmp_path / "ws")
    provider_file = runner.prepare_workspace()
    content = provider_file.read_text(encoding="utf-8")
    assert 'required_version = ">= 1.5.0"' in content


# ---------------------------------------------------------------------------
# validate_drift_baseline (shared by --check and the pipeline)
# ---------------------------------------------------------------------------


def _write_snapshot(path: Path, document: dict[str, Any]) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_validate_baseline_accepts_full_snapshot(tmp_path: Path) -> None:
    baseline = _write_snapshot(
        tmp_path / "base.json",
        {"organizationId": "123456", "networks": [], "features": []},
    )
    assert preflight.validate_drift_baseline(baseline, "123456") == ("123456",)


def test_validate_baseline_missing_file(tmp_path: Path) -> None:
    with pytest.raises(MalformedDumpError) as excinfo:
        preflight.validate_drift_baseline(tmp_path / "absent.json")
    assert "Cannot read snapshot" in str(excinfo.value)


def test_validate_baseline_refuses_sanitized(tmp_path: Path) -> None:
    baseline = _write_snapshot(
        tmp_path / "base.json", {"organizationId": "123456", "sanitized": True}
    )
    with pytest.raises(SanitizedBaselineError) as excinfo:
        preflight.validate_drift_baseline(baseline)
    assert "sanitized" in str(excinfo.value)


def test_validate_baseline_refuses_partial(tmp_path: Path) -> None:
    baseline = _write_snapshot(
        tmp_path / "base.json",
        {"organizationId": "123456", "scope": {"networks": ["N_1"]}},
    )
    with pytest.raises(PartialBaselineError) as excinfo:
        preflight.validate_drift_baseline(baseline)
    assert "PARTIAL" in str(excinfo.value)


def test_validate_baseline_refuses_foreign_org(tmp_path: Path) -> None:
    baseline = _write_snapshot(
        tmp_path / "base.json", {"organizationId": "999999"}
    )
    with pytest.raises(BaselineOrgMismatchError) as excinfo:
        preflight.validate_drift_baseline(baseline, "123456")
    assert "999999" in str(excinfo.value)
    assert "123456" in str(excinfo.value)


def test_validate_baseline_defers_org_check_when_unknown(
    tmp_path: Path,
) -> None:
    """Dump-mode runs know their org only mid-run, so no expected org
    means no early mismatch verdict."""
    baseline = _write_snapshot(
        tmp_path / "base.json", {"organizationId": "999999"}
    )
    assert preflight.validate_drift_baseline(baseline, None) == ("999999",)


def test_validate_baseline_refuses_file_that_is_not_a_snapshot(
    tmp_path: Path,
) -> None:
    """A readable JSON document recording no organization is some other
    file, and loads as an empty graph: without this refusal the whole
    organization falsely registers as added."""
    orgless = _write_snapshot(tmp_path / "orgless.json", {"networks": []})
    with pytest.raises(UnrecognizedBaselineError) as excinfo:
        preflight.validate_drift_baseline(orgless, "123456")
    assert "not a meraki2tf snapshot" in str(excinfo.value)
    # Refused before the org is known, too — the weekly job's dump-mode
    # preflight must not defer this one to a mid-run alert.
    with pytest.raises(UnrecognizedBaselineError):
        preflight.validate_drift_baseline(orgless, None)


def test_validate_baseline_refuses_foreign_artifact(tmp_path: Path) -> None:
    """The workdir's own coverage.json is the plausible operator slip:
    it sits beside the snapshot and parses cleanly as JSON."""
    coverage = _write_snapshot(
        tmp_path / "coverage.json",
        {"organization_id": "123456", "coverage_percent": 96.83,
         "objects": [], "totals": {"discovered": 820}},
    )
    with pytest.raises(UnrecognizedBaselineError):
        preflight.validate_drift_baseline(coverage, "123456")


# ---------------------------------------------------------------------------
# resolve_rebuild_organization
# ---------------------------------------------------------------------------


def test_resolve_rebuild_org_prefers_coverage_json(tmp_path: Path) -> None:
    (tmp_path / "coverage.json").write_text(
        json.dumps({"organization_id": "123456"}), encoding="utf-8"
    )
    assert preflight.resolve_rebuild_organization(tmp_path, None) == (
        "123456",
        "coverage.json",
    )


def test_resolve_rebuild_org_from_state(tmp_path: Path) -> None:
    (tmp_path / "coverage.json").write_text("{corrupt", encoding="utf-8")
    state = tmp_path / "meraki2tf.tfstate"
    state.write_text(
        json.dumps(
            {
                "resources": [
                    "not-a-dict",
                    {"mode": "data", "type": "x", "name": "y"},
                    {
                        "mode": "managed",
                        "type": "meraki_network",
                        "name": "n_1",
                        "instances": [
                            "not-a-dict",
                            {"attributes": "not-a-dict"},
                            {"attributes": {"organization_id": ""}},
                            {"attributes": {"organization_id": "123456"}},
                        ],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    assert preflight.resolve_rebuild_organization(tmp_path, state) == (
        "123456",
        "terraform state",
    )


def test_resolve_rebuild_org_ambiguous_state_falls_to_imports(
    tmp_path: Path,
) -> None:
    state = tmp_path / "meraki2tf.tfstate"
    state.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "mode": "managed",
                        "type": "meraki_network",
                        "name": "a",
                        "instances": [
                            {"attributes": {"organization_id": "111111"}},
                            {"attributes": {"organization_id": "222222"}},
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "imports.tf").write_text(
        'import {\n  to = meraki_organization.org_123456\n'
        '  id = "123456"\n}\n',
        encoding="utf-8",
    )
    assert preflight.resolve_rebuild_organization(tmp_path, state) == (
        "123456",
        "imports.tf",
    )


def test_resolve_rebuild_org_unreadable_state(tmp_path: Path) -> None:
    state = tmp_path / "meraki2tf.tfstate"
    state.write_text("{corrupt", encoding="utf-8")
    assert preflight.resolve_rebuild_organization(tmp_path, state) is None


def test_resolve_rebuild_org_ambiguous_imports_is_unknown(
    tmp_path: Path,
) -> None:
    (tmp_path / "imports.tf").write_text(
        'import {\n  to = meraki_organization.a\n  id = "111111"\n}\n'
        'import {\n  to = meraki_organization.b\n  id = "222222"\n}\n',
        encoding="utf-8",
    )
    assert preflight.resolve_rebuild_organization(tmp_path, None) is None


def test_public_state_organization_wrapper(tmp_path: Path) -> None:
    """The round-9 foreign-state guard consumes this thin public wrapper
    over the private extraction; a matching state names its org and an
    absent one names none."""
    assert preflight.state_organization(None) is None
    state = tmp_path / "meraki2tf.tfstate"
    state.write_text(
        json.dumps(
            {
                "resources": [
                    {
                        "mode": "managed",
                        "type": "meraki_network",
                        "name": "n_1",
                        "instances": [
                            {"attributes": {"organization_id": "654321"}}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert preflight.state_organization(state) == "654321"


def test_resolve_rebuild_org_nothing_available(tmp_path: Path) -> None:
    assert preflight.resolve_rebuild_organization(tmp_path, None) is None


# ---------------------------------------------------------------------------
# --check matrix
# ---------------------------------------------------------------------------


def test_check_all_pass_live(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_meraki_orgs(monkeypatch, [{"id": "123456", "name": "Acme Corp"}])
    _fake_terraform(monkeypatch)
    config = _config(
        ["--check", "--org-id", "123456", "--workdir", str(tmp_path)]
    )
    exit_code = preflight.run_check_command(config, build_dispatcher)
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "[PASS] API key: valid; sees 1 organization(s)" in out
    assert "[PASS] --org-id 123456: resolves to organization 'Acme Corp'" in out
    assert "[PASS] terraform binary: terraform 1.7.5" in out
    assert "bundled fallback" in out
    assert "refreshes it from the installed provider" in out
    assert "[SKIP] --drift-baseline: not supplied" in out
    assert "[PASS] workdir" in out
    assert "[PASS] alert channels: none configured" in out
    assert "Preflight PASS" in out
    assert "Nothing was run or modified." in out


def test_check_fails_without_api_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)
    config = _config(
        ["--check", "--org-id", "123456", "--workdir", str(tmp_path)]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 1
    out = capsys.readouterr().out
    assert f"[FAIL] API key: {API_KEY_ENV_VAR} is not set" in out
    assert "[SKIP] --org-id: cannot be resolved" in out
    assert "Preflight FAIL" in out


def test_check_reports_refused_key_and_unknown_org(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_meraki_orgs(monkeypatch, RuntimeError("401 unauthorized"))
    _fake_terraform(monkeypatch)
    config = _config(
        ["--check", "--org-id", "123456", "--workdir", str(tmp_path)]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 1
    assert "the dashboard refused the key: 401" in capsys.readouterr().out


def test_check_org_not_visible(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_meraki_orgs(monkeypatch, [{"id": "999999", "name": "Other"}])
    _fake_terraform(monkeypatch)
    config = _config(
        ["--check", "--org-id", "123456", "--workdir", str(tmp_path)]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 1
    out = capsys.readouterr().out
    assert "[FAIL] --org-id 123456: not visible to this API key" in out


def test_check_offline_dump_skips_key_and_terraform_notes_keyless(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)
    config = _config(
        [
            "--check",
            "--from-dump", str(tmp_path / "snap.json"),
            "--workdir", str(tmp_path),
        ]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 0
    out = capsys.readouterr().out
    assert "[SKIP] API key: offline --from-dump run" in out
    assert "[SKIP] --org-id: not supplied" in out
    # Keyless: the bundled-catalog line carries no keyed-refresh note.
    assert "refreshes it from the installed provider" not in out


def test_check_export_skips_terraform(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_meraki_orgs(monkeypatch, [{"id": "123456", "name": "Acme"}])

    def forbidden_run(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("terraform must not run for an export check")

    monkeypatch.setattr(terraform_runner.subprocess, "run", forbidden_run)
    config = _config(
        [
            "--check",
            "--org-id", "123456",
            "--dump-to", str(tmp_path / "snap.jsonl.gz"),
            "--workdir", str(tmp_path),
        ]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 0
    out = capsys.readouterr().out
    assert "[SKIP] terraform binary: snapshot export" in out


def test_check_terraform_failures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    argv = ["--check", "--from-dump", str(tmp_path / "s.json"),
            "--workdir", str(tmp_path)]
    # Missing binary → the actionable not-found message.
    monkeypatch.setattr(
        terraform_runner.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError(2, "x")),
    )
    assert preflight.run_check_command(_config(argv), build_dispatcher) == 1
    assert "--terraform-bin" in capsys.readouterr().out
    # Unparseable version → FAIL (a check is strict where the run warns).
    _fake_terraform(monkeypatch, "wrapper banner\n")
    assert preflight.run_check_command(_config(argv), build_dispatcher) == 1
    assert "no parseable version" in capsys.readouterr().out
    # Version below the import-block floor → FAIL.
    _fake_terraform(monkeypatch, "Terraform v1.4.6\n")
    assert preflight.run_check_command(_config(argv), build_dispatcher) == 1
    assert "too old" in capsys.readouterr().out


def test_check_catalog_from_workdir_cache(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)
    (tmp_path / "provider_catalog.json").write_text(
        json.dumps({"resources": {"meraki_network": ["id"]}}),
        encoding="utf-8",
    )
    config = _config(
        ["--check", "--from-dump", str(tmp_path / "s.json"),
         "--workdir", str(tmp_path)]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 0
    assert "workdir cache (1 resource type(s))" in capsys.readouterr().out


def test_check_catalog_corrupt_cache_falls_to_bundled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)
    (tmp_path / "provider_catalog.json").write_text("{corrupt", "utf-8")
    config = _config(
        ["--check", "--from-dump", str(tmp_path / "s.json"),
         "--workdir", str(tmp_path)]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 0
    out = capsys.readouterr().out
    assert "workdir cache unreadable" in out
    assert "bundled fallback" in out


def test_check_catalog_total_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)

    def broken_bundled() -> None:
        raise CatalogError("bundled catalog unreadable")

    monkeypatch.setattr(
        preflight.ProviderCatalog, "bundled", staticmethod(broken_bundled)
    )
    config = _config(
        ["--check", "--from-dump", str(tmp_path / "s.json"),
         "--workdir", str(tmp_path)]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 1
    assert "[FAIL] provider catalog" in capsys.readouterr().out


def test_check_drift_baseline_pass_and_fail(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_meraki_orgs(monkeypatch, [{"id": "123456", "name": "Acme"}])
    _fake_terraform(monkeypatch)
    good = _write_snapshot(
        tmp_path / "good.json", {"organizationId": "123456"}
    )
    config = _config(
        ["--check", "--org-id", "123456",
         "--drift-baseline", str(good), "--workdir", str(tmp_path)]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 0
    assert "[PASS] --drift-baseline: full-organization" in (
        capsys.readouterr().out
    )
    bad = _write_snapshot(
        tmp_path / "bad.json", {"organizationId": "123456", "sanitized": True}
    )
    config = _config(
        ["--check", "--org-id", "123456",
         "--drift-baseline", str(bad), "--workdir", str(tmp_path)]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 1
    assert "[FAIL] --drift-baseline" in capsys.readouterr().out


def test_check_workdir_states(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    # Existing writable directory.
    result = preflight._check_workdir(
        _config(["--check", "--workdir", str(tmp_path)])
    )
    assert result.status == preflight.STATUS_PASS
    # Existing path that is a file.
    file_path = tmp_path / "afile"
    file_path.write_text("x", encoding="utf-8")
    result = preflight._check_workdir(
        _config(["--check", "--workdir", str(file_path)])
    )
    assert result.status == preflight.STATUS_FAIL
    assert "not a directory" in result.detail
    # Not existing yet, creatable under a writable ancestor.
    result = preflight._check_workdir(
        _config(["--check", "--workdir", str(tmp_path / "new" / "deep")])
    )
    assert result.status == preflight.STATUS_PASS
    assert "can be created" in result.detail
    # Existing but unwritable directory.
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    try:
        result = preflight._check_workdir(
            _config(["--check", "--workdir", str(locked)])
        )
        assert result.status == preflight.STATUS_FAIL
        assert "not writable" in result.detail
        # Not existing, under an unwritable ancestor.
        result = preflight._check_workdir(
            _config(["--check", "--workdir", str(locked / "sub")])
        )
        assert result.status == preflight.STATUS_FAIL
        assert "cannot be created" in result.detail
    finally:
        locked.chmod(0o700)


def test_check_kit_integrity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The kit-integrity check is a pure local-file verdict: no API key,
    no live org — it must PASS/FAIL/SKIP offline on a --from-dump run."""
    from meraki2tf.coverage import build_manifest, write_manifest
    from meraki2tf.hcl_generator import IMPORTS_FILENAME

    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    kit = 'import {\n  to = meraki_networks.n_1\n  id = "org,N_1"\n}\n'

    def stamped(workdir: Path) -> None:
        (workdir / IMPORTS_FILENAME).write_text(kit, encoding="utf-8")
        manifest = build_manifest(
            organization_id="org",
            captured=(),
            unsupported=(),
            state_addresses=frozenset(),
        )
        write_manifest(manifest, workdir)

    # A matching pair PASSes — and needs no API key to say so.
    good = tmp_path / "good"
    good.mkdir()
    stamped(good)
    result = preflight._check_kit_integrity(
        _config(["--check", "--workdir", str(good)])
    )
    assert result.status == preflight.STATUS_PASS
    assert "1 import block(s)" in result.detail

    # A kit tampered with after stamping FAILs, naming the mismatch.
    bad = tmp_path / "bad"
    bad.mkdir()
    stamped(bad)
    (bad / IMPORTS_FILENAME).write_text(
        kit + 'import {\n  to = meraki_networks.n_2\n  id = "org,N_2"\n}\n',
        encoding="utf-8",
    )
    result = preflight._check_kit_integrity(
        _config(["--check", "--workdir", str(bad)])
    )
    assert result.status == preflight.STATUS_FAIL
    assert "does not match imports.tf" in result.detail
    assert "found 2 block(s)" in result.detail

    # A legacy/kitless workdir SKIPs — nothing stamped to verify.
    empty = tmp_path / "empty"
    empty.mkdir()
    result = preflight._check_kit_integrity(
        _config(["--check", "--workdir", str(empty)])
    )
    assert result.status == preflight.STATUS_SKIP


def test_check_alert_channels(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)
    base = ["--check", "--from-dump", str(tmp_path / "s.json"),
            "--workdir", str(tmp_path)]
    # A configured valid channel counts.
    config = _config([*base, "--webhook-url", "https://hooks.example/alerts"])
    assert preflight.run_check_command(config, build_dispatcher) == 0
    assert "1 channel(s) configured" in capsys.readouterr().out
    # An invalid channel fails with the startup validation's message.
    config = _config([*base, "--webhook-url", "http://insecure.example/x"])
    assert preflight.run_check_command(config, build_dispatcher) == 1
    assert "[FAIL] alert channels" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# --estimate arithmetic
# ---------------------------------------------------------------------------


#: Hand-countable spec: 1 org-scoped surface (admins), 3 network-scoped
#: surfaces (wireless/ssids, appliance/vlans, settings), 1 device-scoped
#: (switch/ports), 1 nested (per-SSID splash settings), 1 org-scoped
#: aggregation (Air Marshal byNetwork), and a createNetwork productTypes
#: enum enabling the conservative prefilter.
ESTIMATE_SPEC: dict[str, Any] = {
    "openapi": "3.0.1",
    "paths": {
        "/organizations/{organizationId}/networks": {
            "post": {
                "operationId": "createOrganizationNetwork",
                "tags": ["organizations"],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {
                                "properties": {
                                    "productTypes": {
                                        "type": "array",
                                        "items": {
                                            "enum": [
                                                "appliance",
                                                "wireless",
                                                "switch",
                                            ]
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
            },
        },
        "/organizations/{organizationId}/admins": {
            "get": _op("getOrganizationAdmins", "organizations"),
        },
        "/organizations/{organizationId}/admins/{adminId}": {
            "put": _op("updateOrganizationAdmin", "organizations"),
        },
        "/networks/{networkId}/wireless/ssids": {
            "get": _op("getNetworkWirelessSsids", "wireless"),
        },
        "/networks/{networkId}/wireless/ssids/{number}": {
            "get": _op("getNetworkWirelessSsid", "wireless"),
            "put": _op("updateNetworkWirelessSsid", "wireless"),
        },
        "/networks/{networkId}/appliance/vlans": {
            "get": _op("getNetworkApplianceVlans", "appliance"),
        },
        "/networks/{networkId}/appliance/vlans/{vlanId}": {
            "get": _op("getNetworkApplianceVlan", "appliance"),
            "put": _op("updateNetworkApplianceVlan", "appliance"),
        },
        "/networks/{networkId}/settings": {
            "get": _op("getNetworkSettings", "networks"),
            "put": _op("updateNetworkSettings", "networks"),
        },
        "/networks/{networkId}/wireless/ssids/{number}/splash/settings": {
            "get": _op("getNetworkWirelessSsidSplashSettings", "wireless"),
            "put": _op("updateNetworkWirelessSsidSplashSettings", "wireless"),
        },
        "/devices/{serial}/switch/ports": {
            "get": _op("getDeviceSwitchPorts", "switch"),
        },
        "/devices/{serial}/switch/ports/{portId}": {
            "get": _op("getDeviceSwitchPort", "switch"),
            "put": _op("updateDeviceSwitchPort", "switch"),
        },
        # Serial-rooted nested surface (per-port QoS).
        "/devices/{serial}/switch/ports/{portId}/qos": {
            "get": _op("getDeviceSwitchPortQos", "switch"),
            "put": _op("updateDeviceSwitchPortQos", "switch"),
        },
        # Organization-rooted nested surface (per-role permissions).
        "/organizations/{organizationId}/camera/roles/{roleId}/permissions": {
            "get": _op("getOrganizationCameraRolePermissions", "camera"),
            "put": _op("updateOrganizationCameraRolePermissions", "camera"),
        },
        "/networks/{networkId}/wireless/airMarshal/settings": {
            "put": _op("updateNetworkWirelessAirMarshalSettings", "wireless"),
        },
        "/organizations/{organizationId}/wireless/airMarshal/settings/byNetwork": {
            "get": {
                "operationId": (
                    "getOrganizationWirelessAirMarshalSettingsByNetwork"
                ),
                "tags": ["wireless"],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "items": {
                                            "type": "array",
                                            "items": {"type": "object"},
                                        },
                                        "meta": {"type": "object"},
                                    },
                                }
                            }
                        }
                    }
                },
            },
        },
    },
}

ESTIMATE_NETWORKS = [
    {"id": "N_1", "name": "hq", "productTypes": ["wireless"]},
    {"id": "N_2", "name": "branch", "productTypes": ["appliance"]},
]
ESTIMATE_DEVICES = [
    {"serial": "Q2AA-0001-0001", "networkId": "N_1", "productType": "switch"},
    {"serial": "Q2AA-0001-0002", "networkId": "N_1", "productType": "wireless"},
]
ESTIMATE_TEMPLATES = [{"id": "T_1", "productTypes": ["wireless"]}]


@pytest.fixture()
def estimate_spec_file(tmp_path: Path) -> Path:
    path = tmp_path / "estimate-spec.json"
    path.write_text(json.dumps(ESTIMATE_SPEC), encoding="utf-8")
    return path


def _stub_estimate_meraki(
    monkeypatch: pytest.MonkeyPatch, templates: Any
) -> None:
    def get_networks(org: str, total_pages: str) -> list[dict[str, Any]]:
        return ESTIMATE_NETWORKS

    def get_devices(org: str, total_pages: str) -> list[dict[str, Any]]:
        return ESTIMATE_DEVICES

    def get_templates(org: str) -> Any:
        if isinstance(templates, Exception):
            raise templates
        return templates

    def dashboard(**kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(
            organizations=SimpleNamespace(
                getOrganizationNetworks=get_networks,
                getOrganizationDevices=get_devices,
                getOrganizationConfigTemplates=get_templates,
            )
        )

    stub = types.ModuleType("meraki")
    stub.DashboardAPI = dashboard  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "meraki", stub)


def test_estimate_live_prefilter_aware_counts(
    monkeypatch: pytest.MonkeyPatch, estimate_spec_file: Path
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_estimate_meraki(monkeypatch, ESTIMATE_TEMPLATES)
    parser = OpenApiParser(estimate_spec_file)
    config = _config(["--estimate", "--org-id", "123456"])
    estimate = preflight._estimate_live(config, parser)
    assert estimate.organization_id == "123456"
    assert estimate.networks == 2
    assert estimate.devices == 2
    assert estimate.templates == 1
    # networks + devices + config templates
    assert estimate.enumeration_calls == 3
    # admins only (the networks path has no org-scoped GET)
    assert estimate.org_scoped_calls == 1
    # N_1 (wireless): ssids + settings; N_2 (appliance): vlans + settings
    assert estimate.network_scoped_calls == 4
    # switch/ports applies to the switch device, not the wireless one
    assert estimate.serial_scoped_calls == 1
    # Air Marshal byNetwork: one org-scoped aggregation call
    assert estimate.aggregation_calls == 1
    # 1 template × all 3 network-scoped surfaces (unfiltered, as live)
    assert estimate.template_sweep_calls == 3
    # Nested, assumed one parent per applicable scope: splash settings
    # on N_1 (wireless), per-port QoS on the switch device, and the
    # org-rooted camera-role permissions once.
    assert estimate.nested_calls == 3
    assert estimate.nested_exact is False
    # vlans skipped on N_1, ssids skipped on N_2, ports on the AP device
    assert estimate.prefilter_skipped == 3
    assert estimate.total_requests == 16


def test_estimate_live_template_enumeration_failure_noted(
    monkeypatch: pytest.MonkeyPatch, estimate_spec_file: Path
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_estimate_meraki(monkeypatch, RuntimeError("404 not found"))
    parser = OpenApiParser(estimate_spec_file)
    config = _config(["--estimate", "--org-id", "123456"])
    estimate = preflight._estimate_live(config, parser)
    assert estimate.enumeration_calls == 2
    assert estimate.templates == 0
    assert estimate.template_sweep_calls == 0
    assert any("could not be enumerated" in note for note in estimate.notes)


ESTIMATE_SNAPSHOT: dict[str, Any] = {
    "organizationId": "123456",
    "networks": ESTIMATE_NETWORKS,
    "devices": ESTIMATE_DEVICES,
    "features": [
        {
            "apiPath": "/networks/{networkId}/wireless/ssids/{number}",
            "pathValues": ["N_1", "0"],
            "payload": {"number": 0, "name": "corp"},
        },
        {
            "apiPath": "/networks/{networkId}/wireless/ssids/{number}",
            "pathValues": ["N_1", "1"],
            "payload": {"number": 1, "name": "guest"},
        },
        {
            "apiPath": (
                "/organizations/{organizationId}/configTemplates/"
                "{configTemplateId}"
            ),
            "pathValues": ["123456", "T_1"],
            "payload": {"id": "T_1", "name": "template"},
        },
    ],
}


def test_estimate_from_dump_zero_api_calls_exact_nested(
    monkeypatch: pytest.MonkeyPatch,
    estimate_spec_file: Path,
    tmp_path: Path,
) -> None:
    # No meraki module stub: any API attempt would blow up loudly.
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    snapshot = _write_snapshot(tmp_path / "snap.json", ESTIMATE_SNAPSHOT)
    parser = OpenApiParser(estimate_spec_file)
    config = _config(["--estimate", "--from-dump", str(snapshot)])
    estimate = preflight._estimate_from_dump(config, parser)
    assert estimate.enumeration_calls == 0
    assert estimate.org_scoped_calls == 1
    assert estimate.network_scoped_calls == 4
    assert estimate.serial_scoped_calls == 1
    assert estimate.aggregation_calls == 1
    assert estimate.templates == 1
    assert estimate.template_sweep_calls == 3
    # Two SSID parent elements recorded in the snapshot → exact count.
    assert estimate.nested_calls == 2
    assert estimate.nested_exact is True
    assert estimate.total_requests == 12
    assert any("zero API calls" in note for note in estimate.notes)


def test_render_estimate_wall_clock_and_notes(
    monkeypatch: pytest.MonkeyPatch,
    estimate_spec_file: Path,
    tmp_path: Path,
) -> None:
    snapshot = _write_snapshot(tmp_path / "snap.json", ESTIMATE_SNAPSHOT)
    parser = OpenApiParser(estimate_spec_file)
    config = _config(["--estimate", "--from-dump", str(snapshot)])
    estimate = preflight._estimate_from_dump(config, parser)
    text = preflight.render_estimate(estimate)
    assert "organization 123456" in text
    assert "TOTAL                : ~12" in text
    assert "6 req/s" in text and "3 req/s" in text
    assert "exact, from the snapshot" in text
    assert "Read-only preview" in text
    # The live form states its nested assumption instead.
    _stub_estimate_meraki(monkeypatch, ESTIMATE_TEMPLATES)
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    live = preflight._estimate_live(
        _config(["--estimate", "--org-id", "123456"]), parser
    )
    live_text = preflight.render_estimate(live)
    assert "assumed: one parent element per scope" in live_text
    assert "ONE parent element per applicable scope" in live_text


def test_format_duration_units() -> None:
    assert preflight._format_duration(5) == "5s"
    assert preflight._format_duration(90) == "1m 30s"
    assert preflight._format_duration(3700) == "1h 01m"


def test_run_estimate_command_success_and_failure(
    monkeypatch: pytest.MonkeyPatch,
    estimate_spec_file: Path,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        preflight, "resolve_spec", lambda path: estimate_spec_file
    )
    snapshot = _write_snapshot(tmp_path / "snap.json", ESTIMATE_SNAPSHOT)
    config = _config(["--estimate", "--from-dump", str(snapshot)])
    assert preflight.run_estimate_command(config) == 0
    assert "discovery cost estimate" in capsys.readouterr().out
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not json", encoding="utf-8")
    config = _config(["--estimate", "--from-dump", str(corrupt)])
    assert preflight.run_estimate_command(config) == 1


def test_run_estimate_command_live_path(
    monkeypatch: pytest.MonkeyPatch,
    estimate_spec_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv(API_KEY_ENV_VAR, "test-token")
    _stub_estimate_meraki(monkeypatch, ESTIMATE_TEMPLATES)
    monkeypatch.setattr(
        preflight, "resolve_spec", lambda path: estimate_spec_file
    )
    config = _config(["--estimate", "--org-id", "123456"])
    assert preflight.run_estimate_command(config) == 0
    assert "TOTAL                : ~16" in capsys.readouterr().out


def test_check_flags_snapshot_org_disagreeing_with_org_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    dump_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The consequence is silent — the run succeeds and only the
    artifacts carry the wrong organization — so --check has to surface
    it in the second it takes, before the scheduled job runs."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)
    config = _config(
        [
            "--check",
            "--from-dump", str(dump_file),
            "--org-id", "org-999",
            "--workdir", str(tmp_path),
        ]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 1
    out = capsys.readouterr().out
    assert "[FAIL] --from-dump:" in out
    assert "org-123" in out and "org-999" in out


def test_check_passes_when_snapshot_org_matches_org_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    dump_file: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)
    config = _config(
        [
            "--check",
            "--from-dump", str(dump_file),
            "--org-id", "org-123",
            "--workdir", str(tmp_path),
        ]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 0
    assert "[PASS] --from-dump: snapshot organization matches" in (
        capsys.readouterr().out
    )


def test_check_reports_an_unreadable_snapshot_as_a_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A corrupt or truncated snapshot must fail the check, not crash
    the preflight that exists to keep failures out of the run."""
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    _fake_terraform(monkeypatch)
    broken = tmp_path / "broken.json"
    broken.write_text("not a snapshot", encoding="utf-8")
    config = _config(
        [
            "--check",
            "--from-dump", str(broken),
            "--org-id", "org-123",
            "--workdir", str(tmp_path),
        ]
    )
    assert preflight.run_check_command(config, build_dispatcher) == 1
    assert "[FAIL] --from-dump:" in capsys.readouterr().out
