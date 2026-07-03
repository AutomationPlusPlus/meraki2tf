"""Plan reconciliation: classification, diagnostics parsing, file surgery."""

from pathlib import Path
from typing import Any

from meraki2tf.plan_reconciler import (
    ReconciliationPlan,
    ResourceRemediation,
    apply_remediations,
    classify_plan,
    drop_import_blocks,
    drop_resource_blocks,
    hcl_quote,
    inject_attribute,
    insert_ignore_changes,
    rewrite_jsonencode_spans,
    validation_failures,
)

VALIDATION_STDERR = """\
Error: Invalid Attribute Value Match

  with meraki_network_firmware_upgrades.l_1,
  on generated_resources.tf line 30:
  (source code not available)

Attribute upgrade_window_day_of_week value must be one of: ["fri" "mon"], got: "Mon"

Error: Invalid Attribute Value Match

  with meraki_network_firmware_upgrades.l_2,
  on generated_resources.tf line 61:
  (source code not available)

Attribute upgrade_window_day_of_week value must be one of: ["fri" "mon"], got: "Sun"
"""


def _update(
    address: str,
    before: dict[str, Any],
    after: dict[str, Any],
    before_sensitive: Any = None,
    after_sensitive: Any = None,
) -> dict[str, Any]:
    rtype, _, name = address.partition(".")
    return {
        "address": address,
        "type": rtype,
        "name": name,
        "change": {
            "actions": ["update"],
            "before": before,
            "after": after,
            "before_sensitive": before_sensitive or {},
            "after_sensitive": after_sensitive or {},
        },
    }


def test_validation_failures_parses_every_error_block() -> None:
    failures = validation_failures(VALIDATION_STDERR)
    assert set(failures) == {
        "meraki_network_firmware_upgrades.l_1",
        "meraki_network_firmware_upgrades.l_2",
    }
    reason = failures["meraki_network_firmware_upgrades.l_1"]
    assert reason.startswith("Invalid Attribute Value Match")
    assert 'got: "Mon"' in reason
    assert "source code not available" not in reason


def test_validation_failures_without_resource_blocks_is_empty() -> None:
    assert validation_failures("Error: Unable to find API key\n\nboom\n") == {}
    assert validation_failures("") == {}


def test_classify_secret_null_diffs_become_ignores() -> None:
    document = {
        "resource_changes": [
            _update(
                "meraki_network_snmp.l_1",
                {"community_string": "s3cret", "access": "community"},
                {"community_string": None, "access": "community"},
                before_sensitive={"community_string": True},
            )
        ]
    }
    plan = classify_plan(document)
    assert plan.real_changes == ()
    (remediation,) = plan.remediations
    assert remediation.secret_attrs == ("community_string",)
    assert remediation.json_rewrites == {}
    assert remediation.inject_attrs == {}


def test_classify_whitespace_json_diffs_collect_exact_state_strings() -> None:
    pretty = '{\n  "a": 1\n}'
    compact = '{"a":1}'
    document = {
        "resource_changes": [
            _update(
                "meraki_network_webhook_payload_template.t_1",
                {"body": pretty, "name": "wpt"},
                {"body": compact, "name": "wpt"},
            )
        ]
    }
    (remediation,) = classify_plan(document).remediations
    assert remediation.json_rewrites == {"body": (pretty,)}
    assert remediation.normalized_attrs == ("body",)


def test_classify_nested_whitespace_diffs_keep_span_order() -> None:
    """Only the list elements the plan proved whitespace-diffed get a
    rewrite decision; matching elements map to None (span kept)."""
    pretty = '{\n  "x": 2\n}'
    same = '{"y":3}'
    document = {
        "resource_changes": [
            _update(
                "meraki_network_alerts_settings.l_1",
                {"alerts": [{"filters_selector": same},
                            {"filters_selector": pretty}]},
                {"alerts": [{"filters_selector": same},
                            {"filters_selector": '{"x":2}'}]},
            )
        ]
    }
    (remediation,) = classify_plan(document).remediations
    assert remediation.json_rewrites == {"filters_selector": (None, pretty)}


def test_classify_empty_null_scalars_become_injections() -> None:
    document = {
        "resource_changes": [
            _update(
                "meraki_organization_saml.r_1",
                {"enabled": False, "sp_initiated_idp_id": "",
                 "sp_initiated_subdomain": ""},
                {"enabled": False, "sp_initiated_idp_id": None,
                 "sp_initiated_subdomain": None},
            )
        ]
    }
    (remediation,) = classify_plan(document).remediations
    assert remediation.inject_attrs == {
        "sp_initiated_idp_id": "",
        "sp_initiated_subdomain": "",
    }
    assert remediation.normalized_attrs == (
        "sp_initiated_idp_id", "sp_initiated_subdomain",
    )


def test_classify_real_changes_disable_remediation_for_the_resource() -> None:
    """One unexplained diff makes the whole resource real drift — a
    genuine change must never be partially masked."""
    document = {
        "resource_changes": [
            _update(
                "meraki_wireless_ssid.l_1_0",
                {"name": "Corp", "psk": "old",
                 "body": '{\n"a": 1\n}'},
                {"name": "Guest", "psk": None,
                 "body": '{"a":1}'},
                before_sensitive={"psk": True},
            )
        ]
    }
    plan = classify_plan(document)
    assert plan.remediations == ()
    assert plan.real_changes == ("meraki_wireless_ssid.l_1_0",)


def test_classify_tolerates_malformed_documents() -> None:
    assert classify_plan([]) == ReconciliationPlan()
    assert classify_plan({}) == ReconciliationPlan()
    assert classify_plan({"resource_changes": ["junk", {"change": None}]}) == (
        ReconciliationPlan()
    )
    creates = {
        "resource_changes": [
            {"address": "a.b", "change": {"actions": ["create"]}}
        ]
    }
    assert classify_plan(creates) == ReconciliationPlan()


def test_classify_non_object_before_after_is_real_drift() -> None:
    document = {
        "resource_changes": [
            {
                "address": "meraki_networks.n_1",
                "change": {"actions": ["update"], "before": None,
                           "after": {"a": 1}},
            }
        ]
    }
    plan = classify_plan(document)
    assert plan.real_changes == ("meraki_networks.n_1",)


BLOCK = """\
resource "meraki_network_snmp" "l_1" {
  access     = "community"
  network_id = "L_1"
}
"""


def test_insert_ignore_changes_adds_lifecycle_block() -> None:
    edited = insert_ignore_changes(BLOCK, ("community_string",))
    assert "lifecycle {" in edited
    assert "ignore_changes = [community_string]" in edited
    # inserted immediately after the opening line
    assert edited.splitlines()[1].strip() == "lifecycle {"


def test_insert_ignore_changes_merges_existing_attributes() -> None:
    once = insert_ignore_changes(BLOCK, ("community_string",))
    twice = insert_ignore_changes(once, ("users",))
    assert twice.count("lifecycle {") == 1
    assert "ignore_changes = [community_string, users]" in twice


def test_inject_attribute_literals_and_escaping() -> None:
    assert '  flag = true\n' in inject_attribute(BLOCK, "flag", True)
    assert '  count_x = 5\n' in inject_attribute(BLOCK, "count_x", 5)
    injected = inject_attribute(BLOCK, "template", 'say "${hi}"')
    assert '  template = "say \\"$${hi}\\""\n' in injected


def test_inject_attribute_replaces_existing_assignment() -> None:
    """Generated config may already carry the attribute (as null);
    terraform rejects duplicate arguments, so injection must replace."""
    block = (
        'resource "meraki_organization_saml" "r_1" {\n'
        "  enabled                = true\n"
        "  sp_initiated_idp_id    = null\n"
        "}\n"
    )
    injected = inject_attribute(block, "sp_initiated_idp_id", "")
    assert injected.count("sp_initiated_idp_id") == 1
    assert '  sp_initiated_idp_id    = ""\n' in injected
    # untouched attributes keep their lines
    assert "  enabled                = true\n" in injected


def test_rewrite_jsonencode_spans_by_occurrence() -> None:
    block = (
        'resource "meraki_network_alerts_settings" "l_1" {\n'
        "  alerts = [\n"
        "    {\n"
        '      filters_selector = jsonencode({"y" = 3})\n'
        "    },\n"
        "    {\n"
        '      filters_selector = jsonencode({"x" = (2)})\n'
        "    },\n"
        "  ]\n"
        "}\n"
    )
    pretty = '{\n  "x": 2\n}'
    edited = rewrite_jsonencode_spans(
        block, "filters_selector", (None, pretty)
    )
    assert 'jsonencode({"y" = 3})' in edited  # None keeps the span
    assert 'jsonencode({"x" = (2)})' not in edited  # balanced parens honored
    assert f'filters_selector = "{hcl_quote(pretty)}"' in edited


def test_drop_resource_blocks_and_import_blocks(tmp_path: Path) -> None:
    config = tmp_path / "resources.tf"
    config.write_text(
        BLOCK + "\n"
        'resource "meraki_network_snmp" "l_2" {\n  network_id = "L_2"\n}\n',
        encoding="utf-8",
    )
    imports = tmp_path / "imports.tf"
    imports.write_text(
        "import {\n  to = meraki_network_snmp.l_1\n  id = \"L_1\"\n}\n\n"
        "import {\n  to = meraki_network_snmp.l_2\n  id = \"L_2\"\n}\n",
        encoding="utf-8",
    )
    removed = drop_resource_blocks((config,), {"meraki_network_snmp.l_1"})
    assert removed == 1
    text = config.read_text(encoding="utf-8")
    assert '"l_1"' not in text and '"l_2"' in text
    assert drop_import_blocks(imports, {"meraki_network_snmp.l_1"}) == 1
    itext = imports.read_text(encoding="utf-8")
    assert "meraki_network_snmp.l_1" not in itext
    assert "meraki_network_snmp.l_2" in itext


def test_drop_helpers_tolerate_missing_files_and_addresses(tmp_path: Path) -> None:
    assert drop_resource_blocks((tmp_path / "absent.tf",), {"a.b"}) == 0
    assert drop_import_blocks(tmp_path / "absent.tf", {"a.b"}) == 0
    config = tmp_path / "resources.tf"
    config.write_text(BLOCK, encoding="utf-8")
    assert drop_resource_blocks((config,), {"meraki_x.gone"}) == 0


def test_apply_remediations_edits_blocks_and_reports(tmp_path: Path) -> None:
    config = tmp_path / "resources.tf"
    config.write_text(
        BLOCK + "\n"
        'resource "meraki_organization_saml" "r_1" {\n'
        "  enabled = false\n"
        "}\n",
        encoding="utf-8",
    )
    plan = ReconciliationPlan(
        remediations=(
            ResourceRemediation(
                address="meraki_network_snmp.l_1",
                secret_attrs=("community_string",),
            ),
            ResourceRemediation(
                address="meraki_organization_saml.r_1",
                inject_attrs={"sp_initiated_idp_id": ""},
            ),
            ResourceRemediation(  # block not present anywhere
                address="meraki_wireless_ssid.gone",
                secret_attrs=("psk",),
            ),
        )
    )
    ignored, normalized = apply_remediations(
        tmp_path, plan, ("generated_resources.tf", "resources.tf")
    )
    assert ignored == {"meraki_network_snmp.l_1": ("community_string",)}
    assert normalized == {
        "meraki_organization_saml.r_1": ("sp_initiated_idp_id",)
    }
    text = config.read_text(encoding="utf-8")
    assert "ignore_changes = [community_string]" in text
    assert 'sp_initiated_idp_id = ""' in text


def test_classification_matches_real_plan_shapes() -> None:
    """A trimmed replica of the live org's plan document (one resource
    per observed class) classifies exactly as observed."""
    document = {
        "resource_changes": [
            _update(
                "meraki_network_snmp.l_a",
                {"community_string": "x"},
                {"community_string": None},
                before_sensitive={"community_string": True},
            ),
            _update(
                "meraki_wireless_ssid.l_a_0",
                {"psk": "wpa-secret"},
                {"psk": None},
                before_sensitive={"psk": True},
            ),
            _update(
                "meraki_network_webhook_payload_template.l_a_wpt",
                {"body": '{\n  "markdown": "**{{alertType}}**"\n}'},
                {"body": '{"markdown":"**{{alertType}}**"}'},
            ),
            _update(
                "meraki_organization_saml.r_1",
                {"sp_initiated_idp_id": ""},
                {"sp_initiated_idp_id": None},
            ),
        ]
    }
    plan = classify_plan(document)
    assert len(plan.remediations) == 4
    assert plan.real_changes == ()
    by_address = {r.address: r for r in plan.remediations}
    assert by_address["meraki_network_snmp.l_a"].secret_attrs == (
        "community_string",
    )
    assert by_address["meraki_wireless_ssid.l_a_0"].secret_attrs == ("psk",)
    assert "body" in by_address[
        "meraki_network_webhook_payload_template.l_a_wpt"
    ].json_rewrites
    assert by_address["meraki_organization_saml.r_1"].inject_attrs == {
        "sp_initiated_idp_id": ""
    }


def test_hcl_quote_round_trip_specials() -> None:
    assert hcl_quote('a"b\\c\nd${x}%{y}') == 'a\\"b\\\\c\\nd$${x}%%{y}'


def test_json_helpers_ignore_non_json_strings() -> None:
    document = {
        "resource_changes": [
            _update("meraki_x.n", {"name": "alpha"}, {"name": "beta"})
        ]
    }
    plan = classify_plan(document)
    assert plan.real_changes == ("meraki_x.n",)


def test_sensitivity_mask_shapes() -> None:
    """Nested masks: True mid-path, list-indexed masks, out-of-range."""
    document = {
        "resource_changes": [
            _update(
                "meraki_x.whole_subtree",
                {"nested": {"secret": "v"}},
                {"nested": {"secret": None}},
                before_sensitive=True,  # everything sensitive
            ),
            _update(
                "meraki_x.list_mask",
                {"items": [{"secret": "v", "note": '{\n"a":1\n}'}]},
                {"items": [{"secret": "v", "note": '{"a":1}'}]},
                before_sensitive={"items": [{"secret": True}]},
            ),
        ]
    }
    plan = classify_plan(document)
    # whole-subtree sensitive diff is nested (len(path)>1) → real drift
    assert "meraki_x.whole_subtree" in plan.real_changes
    # the list-masked resource's only diff is whitespace → remediated
    (remediation,) = plan.remediations
    assert remediation.address == "meraki_x.list_mask"
    assert "note" in remediation.json_rewrites


def test_block_span_at_end_of_file_without_trailing_newline(
    tmp_path: Path,
) -> None:
    config = tmp_path / "resources.tf"
    config.write_text(
        'resource "meraki_network_snmp" "l_1" {\n  a = 1\n}',
        encoding="utf-8",
    )
    assert drop_resource_blocks((config,), {"meraki_network_snmp.l_1"}) == 1
    assert config.read_text(encoding="utf-8") == ""
    # unterminated block: not matched, left alone
    config.write_text(
        'resource "meraki_network_snmp" "l_1" {\n  a = 1\n', encoding="utf-8"
    )
    assert drop_resource_blocks((config,), {"meraki_network_snmp.l_1"}) == 0


def test_apply_remediations_combines_all_edit_kinds(tmp_path: Path) -> None:
    config = tmp_path / "resources.tf"
    config.write_text(
        'resource "meraki_organization_saml" "r_1" {\n'
        "  enabled = false\n"
        '  body    = jsonencode({"a" = 1})\n'
        "}\n",
        encoding="utf-8",
    )
    pretty = '{\n  "a": 1\n}'
    plan = ReconciliationPlan(
        remediations=(
            ResourceRemediation(
                address="meraki_organization_saml.r_1",
                secret_attrs=("certificate",),
                json_rewrites={"body": (pretty,)},
                inject_attrs={"sp_initiated_idp_id": ""},
            ),
        )
    )
    ignored, normalized = apply_remediations(
        tmp_path, plan, ("resources.tf",)
    )
    text = config.read_text(encoding="utf-8")
    assert "ignore_changes = [certificate]" in text
    assert 'sp_initiated_idp_id = ""' in text
    assert "jsonencode" not in text
    assert normalized == {
        "meraki_organization_saml.r_1": ("body", "sp_initiated_idp_id")
    }
    assert ignored == {"meraki_organization_saml.r_1": ("certificate",)}
