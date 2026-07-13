"""Plan reconciliation: classification, diagnostics parsing, file surgery."""

from pathlib import Path
from typing import Any

from meraki2tf.plan_reconciler import (
    ReconciliationPlan,
    ResourceRemediation,
    apply_enum_case_repairs,
    apply_remediations,
    classify_plan,
    deep_json_equal,
    drop_import_blocks,
    drop_resource_blocks,
    duplicate_set_values,
    enum_case_repairs,
    payload_carries_duplicate,
    hcl_quote,
    inject_attribute,
    insert_ignore_changes,
    locate_duplicate_value_resources,
    plan_throttled,
    replace_attribute_value,
    synthesize_hcl,
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


THROTTLED_STDERR = """\
Error: Client Error

Failed to retrieve object (GET), got error: HTTP Request failed: StatusCode
429, {"errors":["API rate limit exceeded for organization"]}
"""

DUPLICATE_SET_STDERR = """\
Error: Duplicate Set Element

This attribute contains duplicate values of:
tftypes.String<"content-autofill.example.com">

Error: Duplicate Set Element

This attribute contains duplicate values of:
tftypes.String<"content-autofill.example.com">
"""


def test_plan_throttled_detects_the_wrapped_429_signature() -> None:
    assert plan_throttled(THROTTLED_STDERR) is True
    assert plan_throttled(VALIDATION_STDERR) is False


def test_duplicate_set_values_extracts_and_dedupes_literals() -> None:
    assert duplicate_set_values(DUPLICATE_SET_STDERR) == (
        "content-autofill.example.com",
    )
    assert duplicate_set_values(THROTTLED_STDERR) == ()


def test_payload_carries_duplicate_walks_nested_structures() -> None:
    payload = {
        "contentFiltering": {
            "allowedUrlPatterns": {
                "patterns": ["a.example", "b.example", "a.example"]
            }
        },
        "rules": [{"values": ["x"]}],
    }
    assert payload_carries_duplicate(payload, "a.example") is True
    assert payload_carries_duplicate(payload, "b.example") is False
    assert payload_carries_duplicate(payload, "x") is False
    assert payload_carries_duplicate([["y"], ["y", "y"]], "y") is True
    assert payload_carries_duplicate("scalar", "scalar") is False


def test_locate_duplicate_value_resources_finds_the_owning_block(
    tmp_path: Path,
) -> None:
    """Terraform names no resource for set-uniqueness violations; the
    owner is whichever generated block carries the literal twice."""
    config = tmp_path / "resources.tf"
    config.write_text(
        'resource "meraki_appliance_content_filtering" "l_1" {\n'
        "  allowed_url_patterns = [\n"
        '    "content-autofill.example.com",\n'
        '    "content-autofill.example.com",\n'
        "  ]\n"
        "}\n"
        'resource "meraki_appliance_content_filtering" "l_2" {\n'
        "  allowed_url_patterns = [\n"
        '    "content-autofill.example.com",\n'
        "  ]\n"
        "}\n",
        encoding="utf-8",
    )
    truncated = tmp_path / "generated_resources.tf"
    truncated.write_text(
        # An opener whose block never closes — spanless, skipped.
        'resource "meraki_appliance_content_filtering" "l_3" {\n'
        '  allowed_url_patterns = ["content-autofill.example.com",',
        encoding="utf-8",
    )
    failures = locate_duplicate_value_resources(
        (config, truncated, tmp_path / "missing.tf"),
        ("content-autofill.example.com",),
    )
    assert set(failures) == {"meraki_appliance_content_filtering.l_1"}
    reason = failures["meraki_appliance_content_filtering.l_1"]
    assert "Duplicate Set Element" in reason
    assert "content-autofill.example.com" in reason
    assert validation_failures("") == {}


def test_enum_case_repairs_extracts_case_insensitive_matches() -> None:
    """``"Mon"`` has the lowercase ``"mon"`` in the allowed list and is
    repairable; ``"Sun"`` matches nothing and stays unexpressible."""
    repairs = enum_case_repairs(validation_failures(VALIDATION_STDERR))
    assert repairs == {
        "meraki_network_firmware_upgrades.l_1": {
            "upgrade_window_day_of_week": "mon"
        }
    }


def test_enum_case_repairs_prefers_plain_lowercase_spelling() -> None:
    failures = {
        "meraki_x.a": (
            "Invalid Attribute Value Match: Attribute day value must be "
            'one of: ["sunday" "sun"], got: "Sun"'
        ),
        "meraki_x.b": (
            "Invalid Attribute Value Match: Attribute day value must be "
            'one of: ["SUNDAY"], got: "Sunday"'
        ),
    }
    repairs = enum_case_repairs(failures)
    assert repairs["meraki_x.a"] == {"day": "sun"}
    # no plain-lowercase spelling offered → first case-insensitive match
    assert repairs["meraki_x.b"] == {"day": "SUNDAY"}


def test_enum_case_repairs_ignores_non_enum_and_exact_values() -> None:
    failures = {
        "meraki_x.a": "Invalid Attribute Value: some other diagnostic",
        # value already allowed — nothing to repair (defensive; the
        # validator would not have failed)
        "meraki_x.b": (
            'Attribute day value must be one of: ["mon"], got: "mon"'
        ),
    }
    assert enum_case_repairs(failures) == {}


FIRMWARE_CASE_BLOCK = """\
resource "meraki_network_firmware_upgrades" "l_1" {
  network_id                 = "L_1"
  upgrade_window_day_of_week = "Mon"
}
"""


def test_apply_enum_case_repairs_recases_and_pins(tmp_path: Path) -> None:
    config = tmp_path / "resources.tf"
    config.write_text(FIRMWARE_CASE_BLOCK, encoding="utf-8")
    repaired = apply_enum_case_repairs(
        tmp_path,
        {
            "meraki_network_firmware_upgrades.l_1": {
                "upgrade_window_day_of_week": "mon"
            }
        },
        ("absent.tf", "resources.tf"),
    )
    assert repaired == {
        "meraki_network_firmware_upgrades.l_1": (
            "upgrade_window_day_of_week",
        )
    }
    text = config.read_text(encoding="utf-8")
    assert 'upgrade_window_day_of_week = "mon"' in text
    assert "ignore_changes = [upgrade_window_day_of_week]" in text
    assert '"Mon"' not in text


def test_apply_enum_case_repairs_skips_unlocatable_targets(
    tmp_path: Path,
) -> None:
    config = tmp_path / "resources.tf"
    config.write_text(FIRMWARE_CASE_BLOCK, encoding="utf-8")
    repaired = apply_enum_case_repairs(
        tmp_path,
        {
            # block exists but the attribute does not
            "meraki_network_firmware_upgrades.l_1": {"absent_attr": "x"},
            # block does not exist at all
            "meraki_network_firmware_upgrades.l_9": {"day": "mon"},
        },
        ("resources.tf",),
    )
    assert repaired == {}
    text = config.read_text(encoding="utf-8")
    assert "ignore_changes" not in text


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
    assert remediation.normalize_attrs == {}
    assert remediation.inject_attrs == {}


def test_classify_whitespace_json_diffs_collect_exact_state_values() -> None:
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
    assert remediation.normalize_attrs == {"body": pretty}
    assert remediation.normalized_attrs == ("body",)


def test_classify_key_order_diffs_record_the_whole_attribute() -> None:
    """The live alerts case: jsonencode alphabetizes keys, Meraki does
    not — the whole attribute is recorded for synthesis, including the
    elements that matched (their exact strings must survive)."""
    state_order = (
        '{"smartSensitivity":"medium","smartEnabled":false,'
        '"eventReminderPeriodSecs":10800}'
    )
    alphabetized = (
        '{"eventReminderPeriodSecs":10800,"smartEnabled":false,'
        '"smartSensitivity":"medium"}'
    )
    before_alerts = [
        {"filters_selector": None, "type": "a"},
        {"filters_selector": "any port", "type": "b"},
        {"filters_selector": state_order, "type": "c"},
    ]
    after_alerts = [
        {"filters_selector": None, "type": "a"},
        {"filters_selector": "any port", "type": "b"},
        {"filters_selector": alphabetized, "type": "c"},
    ]
    document = {
        "resource_changes": [
            _update(
                "meraki_network_alerts_settings.l_1",
                {"alerts": before_alerts},
                {"alerts": after_alerts},
            )
        ]
    }
    (remediation,) = classify_plan(document).remediations
    assert remediation.normalize_attrs == {"alerts": before_alerts}
    assert remediation.normalized_attrs == ("alerts",)


def test_deep_json_equal_edges() -> None:
    # scalar-parsing strings never count as equal
    assert deep_json_equal("Mon", "mon") is False
    assert deep_json_equal("123", "123.0") is False
    assert deep_json_equal("true", "true ") is False
    # object/array documents differing in whitespace or key order do
    assert deep_json_equal('{"b":2,"a":1}', '{\n"a": 1, "b": 2}') is True
    assert deep_json_equal("[1, 2]", "[1,2]") is True
    # nested containers recurse; unequal content stays unequal
    assert deep_json_equal(
        [{"note": '{"x":1}'}], [{"note": '{ "x" : 1 }'}]
    ) is True
    assert deep_json_equal('{"x":1}', '{"x":2}') is False
    assert deep_json_equal({"a": 1}, {"a": 1, "b": 2}) is False
    assert deep_json_equal([1], [1, 2]) is False
    assert deep_json_equal("not json", "not json either") is False


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


def test_classify_nonempty_scalar_to_null_is_real_drift() -> None:
    """A NON-empty before with a null after means the value changed in
    Meraki after the config was generated (the generator only omits
    null/empty reads) — genuine clickops drift that must alert, never
    be silently injected into the config as if nothing happened."""
    document = {
        "resource_changes": [
            _update(
                "meraki_networks.n_1",
                {"notes": "set by clickops after generation"},
                {"notes": None},
            )
        ]
    }
    plan = classify_plan(document)
    assert plan.remediations == ()
    assert plan.real_changes == ("meraki_networks.n_1",)


def test_classify_unknown_after_values_are_real_drift() -> None:
    """'(known after apply)' attributes are omitted from `after` and
    would otherwise masquerade as generator omissions; an unknown value
    is never a provable phantom."""
    document = {
        "resource_changes": [
            _update(
                "meraki_networks.n_1",
                {"sp_initiated_idp_id": ""},
                {"sp_initiated_idp_id": None},
            )
        ]
    }
    document["resource_changes"][0]["change"]["after_unknown"] = {
        "sp_initiated_idp_id": True
    }
    plan = classify_plan(document)
    assert plan.remediations == ()
    assert plan.real_changes == ("meraki_networks.n_1",)


def test_validation_failures_do_not_cross_error_block_boundaries() -> None:
    """An address-less error block must not steal the next block's
    address — the garbled reason would land in the coverage manifest as
    that resource's drop cause."""
    diagnostics = (
        "Error: Unable to find API key\n"
        "\n"
        "boom\n"
        "\n"
        "Error: Invalid Attribute Value Match\n"
        "\n"
        "  with meraki_network_firmware_upgrades.l_1,\n"
        "  on resources.tf line 5:\n"
        "Attribute upgrade_window_day_of_week value must be one of...\n"
    )
    failures = validation_failures(diagnostics)
    assert set(failures) == {"meraki_network_firmware_upgrades.l_1"}
    assert failures["meraki_network_firmware_upgrades.l_1"].startswith(
        "Invalid Attribute Value Match"
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
    harmless = {
        "resource_changes": [
            {"address": "a.b", "change": {"actions": ["no-op"]}},
            {"address": "a.c", "change": {"actions": ["read"]}},
            {"address": "a.d", "change": {"actions": []}},
        ]
    }
    assert classify_plan(harmless) == ReconciliationPlan()


def test_classify_counts_non_update_mutations_as_real() -> None:
    """create/delete/replace actions have no phantom classes — they are
    genuine drift and must be counted in real_changes, or the
    reconciliation report ("N real change(s) left as drift")
    undercounts the mutations left in the plan."""
    document = {
        "resource_changes": [
            {"address": "meraki_networks.new", "change": {"actions": ["create"]}},
            {"address": "meraki_devices.gone", "change": {"actions": ["delete"]}},
            {
                "address": "meraki_wireless_ssid.reborn",
                "change": {"actions": ["delete", "create"]},  # replace
            },
            _update(  # phantom update: still remediated, never real
                "meraki_organization_saml.r_1",
                {"sp_initiated_idp_id": ""},
                {"sp_initiated_idp_id": None},
            ),
        ]
    }
    plan = classify_plan(document)
    (remediation,) = plan.remediations
    assert remediation.address == "meraki_organization_saml.r_1"
    assert plan.real_changes == (
        "meraki_devices.gone",
        "meraki_networks.new",
        "meraki_wireless_ssid.reborn",
    )


def test_classify_without_sensitivity_masks() -> None:
    """Plan documents may omit the sensitivity masks entirely."""
    document = {
        "resource_changes": [
            {
                "address": "meraki_organization_saml.r_1",
                "change": {
                    "actions": ["update"],
                    "before": {"sp_initiated_idp_id": ""},
                    "after": {"sp_initiated_idp_id": None},
                },
            }
        ]
    }
    (remediation,) = classify_plan(document).remediations
    assert remediation.inject_attrs == {"sp_initiated_idp_id": ""}


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


def test_synthesize_hcl_covers_all_json_shapes() -> None:
    assert synthesize_hcl(None) == "null"
    assert synthesize_hcl(True) == "true"
    assert synthesize_hcl(False) == "false"
    assert synthesize_hcl(10800) == "10800"
    assert synthesize_hcl(1.5) == "1.5"
    assert synthesize_hcl("plain") == '"plain"'
    assert synthesize_hcl({}) == "{}"
    assert synthesize_hcl([]) == "[]"
    obj = synthesize_hcl({"enabled": True, "weird key": "v"}, indent=4)
    assert obj == '{\n    enabled = true\n    "weird key" = "v"\n  }'
    lst = synthesize_hcl(["a", {"b": 1}], indent=4)
    assert lst.startswith("[\n    \"a\",\n    {\n")
    assert lst.endswith("\n  ]")


def test_synthesize_hcl_falls_back_to_quoted_repr() -> None:
    """Non-JSON leaf types cannot occur in a plan document, but the
    fallback must still emit valid HCL rather than crash."""
    assert synthesize_hcl(complex(1, 2)) == '"(1+2j)"'


def test_replace_attribute_value_at_end_of_text() -> None:
    block = 'resource "meraki_x" "r" {\n  body = null'
    edited = replace_attribute_value(block, "body", '"v"')
    assert edited == 'resource "meraki_x" "r" {\n  body = "v"'


def test_synthesize_hcl_keeps_string_leaves_byte_exact() -> None:
    """State strings pass through hcl_quote untouched — key order and
    whitespace inside JSON-document strings survive synthesis."""
    state_order = '{"z": 1,\n "a": 2}'
    out = synthesize_hcl([{"filters_selector": state_order}], indent=4)
    assert hcl_quote(state_order) in out


def test_replace_attribute_value_handles_every_value_shape() -> None:
    block = (
        'resource "meraki_x" "r" {\n'
        "  a_null   = null\n"
        "  a_number = 5\n"
        '  a_string = "keep (parens) and {braces} and \\"${escaped}\\""\n'
        "  a_list = [\n"
        "    1,\n"
        "    2,\n"
        "  ]\n"
        '  a_json = jsonencode({\n    x = 1\n  })\n'
        "  trailing = true\n"
        "}\n"
    )
    for attr in ("a_null", "a_number", "a_string", "a_list", "a_json"):
        edited = replace_attribute_value(block, attr, '"NEW"')
        assert edited is not None
        assert f'{attr} = "NEW"' in edited.replace("   ", " ").replace("  ", " ")
        # neighbours survive the surgery intact
        assert "  trailing = true\n" in edited
        assert edited.count("resource ") == 1
    assert replace_attribute_value(block, "absent", '"x"') is None


def test_replace_attribute_value_is_quote_aware() -> None:
    """Brackets and quotes inside string literals must not derail the
    value-span scan (the old balanced-paren scan corrupted these)."""
    tricky = hcl_quote('body ( with { unbalanced ] and " tricks')
    block = (
        'resource "meraki_x" "r" {\n'
        f'  body     = "{tricky}"\n'
        "  after_it = 1\n"
        "}\n"
    )
    edited = replace_attribute_value(block, "body", '"replaced"')
    assert edited is not None
    assert '  body     = "replaced"\n' in edited
    assert "  after_it = 1\n" in edited


def test_replace_attribute_value_only_touches_top_level() -> None:
    """A same-named attribute nested in a list element (indented deeper)
    is out of reach; only the two-space top-level assignment matches."""
    block = (
        'resource "meraki_network_alerts_settings" "l_1" {\n'
        "  alerts = [\n"
        "    {\n"
        '      filters_selector = "nested"\n'
        "    },\n"
        "  ]\n"
        "}\n"
    )
    assert replace_attribute_value(block, "filters_selector", '"x"') is None
    edited = replace_attribute_value(block, "alerts", "[]")
    assert edited is not None
    assert "  alerts = []\n" in edited
    assert "nested" not in edited


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
    ].normalize_attrs
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
    """Nested masks: True mid-path, list-indexed masks. An attribute
    containing ANY sensitive leaf is never synthesized to disk — even
    when its diff is provably formatting-only — because synthesis
    writes state values (secret material included) into the config."""
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
    assert plan.remediations == ()
    # whole-subtree sensitive diff (value not null-ed) → real drift
    assert "meraki_x.whole_subtree" in plan.real_changes
    # formatting-only diff, but the attribute carries a secret leaf →
    # conservative real drift, never written to the workspace
    assert "meraki_x.list_mask" in plan.real_changes


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


def test_one_line_block_span_never_swallows_the_next_block(
    tmp_path: Path,
) -> None:
    """A one-line ``resource "t" "n" {}`` block spans exactly its own
    line — searching for a multi-line closer used to absorb (and then
    delete or mis-edit) the innocent block that follows it."""
    config = tmp_path / "resources.tf"
    config.write_text(
        'resource "meraki_networks" "oneliner" {}\n' + BLOCK,
        encoding="utf-8",
    )
    assert drop_resource_blocks((config,), {"meraki_networks.oneliner"}) == 1
    text = config.read_text(encoding="utf-8")
    assert '"oneliner"' not in text
    assert text == BLOCK  # the neighbor survives intact


def test_one_line_block_as_last_block_is_dropped(tmp_path: Path) -> None:
    config = tmp_path / "resources.tf"
    config.write_text(
        BLOCK + '\nresource "meraki_networks" "oneliner" {}\n',
        encoding="utf-8",
    )
    assert drop_resource_blocks((config,), {"meraki_networks.oneliner"}) == 1
    assert '"oneliner"' not in config.read_text(encoding="utf-8")
    # and without a trailing newline at EOF (previously a silent no-op)
    config.write_text(
        'resource "meraki_networks" "oneliner" {}', encoding="utf-8"
    )
    assert drop_resource_blocks((config,), {"meraki_networks.oneliner"}) == 1
    assert config.read_text(encoding="utf-8") == ""


def test_editors_reopen_one_line_blocks(tmp_path: Path) -> None:
    """Insertions into a one-line block must land inside the braces —
    they used to be appended after the same-line closing brace, emitting
    invalid top-level HCL."""
    one_liner = 'resource "meraki_networks" "oneliner" {}\n'
    edited = insert_ignore_changes(one_liner, ("psk",))
    assert edited == (
        'resource "meraki_networks" "oneliner" {\n'
        "  lifecycle {\n"
        "    ignore_changes = [psk]\n"
        "  }\n"
        "}\n"
    )
    injected = inject_attribute(one_liner, "name", "lab")
    assert injected == (
        'resource "meraki_networks" "oneliner" {\n'
        '  name = "lab"\n'
        "}\n"
    )
    # remediation end-to-end through the file editor
    config = tmp_path / "resources.tf"
    config.write_text(one_liner + BLOCK, encoding="utf-8")
    plan = ReconciliationPlan(
        remediations=(
            ResourceRemediation(
                address="meraki_networks.oneliner",
                secret_attrs=("psk",),
            ),
        )
    )
    ignored, _ = apply_remediations(tmp_path, plan, ("resources.tf",))
    assert ignored == {"meraki_networks.oneliner": ("psk",)}
    text = config.read_text(encoding="utf-8")
    assert text.endswith(BLOCK)  # the neighbor is untouched
    assert "ignore_changes = [psk]" in text.split("meraki_network_snmp")[0]


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
                normalize_attrs={"body": pretty},
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
    assert f'body    = "{hcl_quote(pretty)}"' in text
    assert normalized == {
        "meraki_organization_saml.r_1": ("body", "sp_initiated_idp_id")
    }
    assert ignored == {"meraki_organization_saml.r_1": ("certificate",)}
