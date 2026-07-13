"""Plan reconciliation: converge generated configuration to import-only.

``terraform plan -generate-config-out`` builds resource configuration
from what the provider reads out of Meraki, but three provider quirks
leave the very first plan proposing *changes* that do not correspond to
any real difference in Meraki. Left alone they would (a) raise phantom
DRIFT_DETECTED alerts on every scheduled run and (b) permanently block
the sync-mode guard, which only auto-applies plans with 0 to add,
0 to change, 0 to destroy. Observed classes, all remediated here by
editing the workspace files and re-planning:

* **Unexpressible values** — the provider's own validators reject the
  values its own Read returns (e.g. ``upgrade_window_day_of_week``
  must be lowercase ``"mon"`` while Meraki returns ``"Mon"``). When
  the rejection is a pure enum *case* mismatch (a case-insensitive
  match exists in the validator's allowed list) the value is repaired
  to the provider's casing and the attribute is pinned with
  ``ignore_changes`` — the state keeps the API casing, so the
  case-only diff that would otherwise follow is provably phantom.
  Anything else cannot round-trip at all, so the resource is dropped
  from the kit (import block + config block) and reported as
  *unsupported* — the coverage manifest is the manual-rebuild runbook.
* **Secret attributes** — generated configuration never carries
  sensitive values (the provider exposes write-only ``…_wo`` siblings
  instead), so the plan wants to null them out (``psk``,
  ``community_string``). A ``lifecycle {{ ignore_changes = […] }}``
  block suppresses the phantom change; the attributes are reported as
  *unmanaged secrets* so the operator knows to restore them manually
  after a rebuild.
* **Value normalization** — the state holds JSON-document strings that
  differ from what the generated expression evaluates to only in
  formatting: whitespace *or key order* (``jsonencode()`` alphabetizes
  keys; Meraki stores its own ordering), or holds empty strings the
  generator omitted entirely (plan: ``"" -> null``). The whole
  attribute is re-synthesized in HCL from the exact state value —
  byte-for-byte for every string leaf — so the diff disappears while
  real future drift on the same attribute stays visible. Attributes
  containing *any* sensitive leaf are never synthesized (that would
  write secret material into the workspace files); they surface as
  drift instead.

Anything the classifier cannot prove to be one of these classes is left
untouched and surfaces as ordinary drift. All edits are local file
surgery on the workspace — Meraki is never touched.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def hcl_quote(value: str) -> str:
    """Escape a raw value for interpolation into a quoted HCL literal."""
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("${", "$${")
        .replace("%{", "%%{")
    )


#: ``terraform plan -no-color`` diagnostic blocks:
#: ``Error: <title>`` followed by ``  with <address>,``. The gap
#: between title and address must not run past the next ``Error:``
#: line, or an address-less block (Duplicate Set Element, auth
#: failures) steals the following block's address and garbles the
#: operator-facing reason.
_VALIDATION_ERROR_RE = re.compile(
    r"^Error: (?P<title>.+?)\n"
    r"\n"
    r"(?:(?!Error: ).*\n)*?"
    r"\s+with (?P<address>[A-Za-z0-9_.\[\]\"-]+),\n"
    r"(?P<rest>(?:.*\n?)*?)(?=^Error: |\Z)",
    re.MULTILINE,
)

#: Top-level resource block opener exactly as terraform emits it.
_RESOURCE_BLOCK_RE = re.compile(
    r'^resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{'
)

_LIFECYCLE_IGNORE_RE = re.compile(
    r"^\s*lifecycle\s*\{\s*\n\s*ignore_changes\s*=\s*\[(?P<attrs>[^\]]*)\]\s*\n\s*\}\s*\n",
    re.MULTILINE,
)


@dataclass(frozen=True)
class ResourceRemediation:
    """Per-resource remediation extracted from one plan document."""

    address: str
    #: Top-level sensitive attributes whose only diff is state → null.
    secret_attrs: tuple[str, ...] = ()
    #: Top-level attributes whose config value is JSON-equivalent to
    #: state but textually different (whitespace/key order): attr →
    #: the full state value to re-synthesize the attribute from.
    normalize_attrs: dict[str, Any] = field(default_factory=dict)
    #: Top-level scalar attributes the generator omitted (plan shows
    #: state-value → null): attr → exact state value to inject.
    inject_attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def normalized_attrs(self) -> tuple[str, ...]:
        """Attribute names whose values get rewritten or injected."""
        return tuple(sorted({*self.normalize_attrs, *self.inject_attrs}))


@dataclass(frozen=True)
class ReconciliationPlan:
    """Everything one classification pass decided about a plan."""

    remediations: tuple[ResourceRemediation, ...] = ()
    #: Addresses whose diffs include anything the classifier cannot
    #: prove phantom — genuine drift, left for the normal alert path.
    real_changes: tuple[str, ...] = ()

    @property
    def has_remediations(self) -> bool:
        return bool(self.remediations)


def validation_failures(diagnostics: str) -> dict[str, str]:
    """Parse resource addresses out of terraform validation errors.

    Returns ``{address: reason}`` for every ``Error:`` block that names
    a resource. The reason carries the error title plus the last
    substantive diagnostic line (e.g. the attribute constraint), which
    becomes the operator-facing unsupported reason.
    """
    failures: dict[str, str] = {}
    for match in _VALIDATION_ERROR_RE.finditer(diagnostics):
        address = match["address"]
        detail_lines = [
            line.strip()
            for line in match["rest"].splitlines()
            if line.strip()
            and not line.strip().startswith("on ")
            and "source code not available" not in line
        ]
        detail = " ".join(detail_lines)
        reason = match["title"].strip()
        if detail:
            reason = f"{reason}: {detail}"
        # first error per address wins; later duplicates add nothing
        failures.setdefault(address, reason)
    return failures


#: The provider's REST client failure once its 429 retries are spent.
#: Terraform wraps diagnostic lines, so the status code may sit on the
#: line after "StatusCode".
_THROTTLE_429_RE = re.compile(r"StatusCode\s+429\b")


def plan_throttled(diagnostics: str) -> bool:
    """True when the plan failed because the API rate-limited the
    provider (its REST client exhausted every 429 retry). Transient by
    definition — the plan is retryable once the shared per-organization
    budget frees up."""
    return bool(_THROTTLE_429_RE.search(diagnostics))


#: Terraform's set-uniqueness violation. The framework emits it while
#: decoding provider data, so — unlike validation errors — it names no
#: resource, only the duplicated value.
_DUPLICATE_SET_RE = re.compile(
    r"^Error: Duplicate Set Element\n"
    r"(?P<body>(?:.*\n?)*?)(?=^Error: |\Z)",
    re.MULTILINE,
)
_TFTYPES_STRING_RE = re.compile(r'tftypes\.String<"(?P<value>[^"]*)">')


def duplicate_set_values(diagnostics: str) -> tuple[str, ...]:
    """Duplicated literals named by Duplicate Set Element diagnostics.

    The API can return the same string twice in a list the provider
    models as a Set (observed live: a duplicated content-filtering URL
    pattern); terraform reports only the value, never the resource.
    """
    values: list[str] = []
    for match in _DUPLICATE_SET_RE.finditer(diagnostics):
        for literal in _TFTYPES_STRING_RE.finditer(match["body"]):
            if literal["value"] not in values:
                values.append(literal["value"])
    return tuple(values)


def payload_carries_duplicate(node: Any, value: str) -> bool:
    """True when any list anywhere in the payload holds ``value`` twice.

    This is the discovery-side mirror of the provider's Set decoding:
    a duplicated element that breaks the provider's own Read exists in
    the raw API payload, and — because the Read fails before terraform
    generates any configuration — the payload is the only place the
    duplicate can be attributed from.
    """
    if isinstance(node, list):
        if sum(1 for item in node if item == value) >= 2:
            return True
        return any(payload_carries_duplicate(item, value) for item in node)
    if isinstance(node, Mapping):
        return any(
            payload_carries_duplicate(child, value) for child in node.values()
        )
    return False


def duplicate_set_reason(value: str) -> str:
    """Operator-facing unsupported reason for a duplicate set element."""
    return (
        "Duplicate Set Element: the API returns "
        f"{value!r} more than once in a set-typed "
        "attribute, which the provider cannot represent."
    )


def locate_duplicate_value_resources(
    config_files: tuple[Path, ...], values: tuple[str, ...]
) -> dict[str, str]:
    """Resolve address-less Duplicate Set Element errors to resources.

    The owner is whichever generated resource block carries the
    duplicated literal more than once. Returns ``{address: reason}`` in
    ``validation_failures`` shape so the owners ride the normal
    drop-and-report-unsupported rail.
    """
    failures: dict[str, str] = {}
    for path in config_files:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for opener in re.finditer(_RESOURCE_BLOCK_RE.pattern, text, re.MULTILINE):
            address = f"{opener['type']}.{opener['name']}"
            span = _block_span(text, address)
            if span is None:
                continue
            block = text[span[0]:span[1]]
            for value in values:
                if block.count(f'"{hcl_quote(value)}"') >= 2:
                    failures.setdefault(address, duplicate_set_reason(value))
                    break
    return failures


#: Terraform's enum-validator diagnostic, as flattened into a
#: ``validation_failures`` reason string: ``Attribute <attr> value must
#: be one of: ["a" "b" …], got: "X"``.
_ENUM_MISMATCH_RE = re.compile(
    r'Attribute (?P<attr>[A-Za-z_][A-Za-z0-9_]*) value must be one of:'
    r'\s*\[(?P<allowed>[^\]]*)\],\s*got:\s*"(?P<got>[^"]*)"'
)


def enum_case_repairs(
    failures: dict[str, str],
) -> dict[str, dict[str, str]]:
    """Repairable enum-case mismatches among validation failures.

    Returns ``{address: {attribute: replacement}}`` for every failure
    whose diagnostic is an enum-validator rejection where the offending
    value matches an allowed value case-insensitively (preferring the
    plain lowercase form when the list offers several spellings).
    Failures without such a match are absent — they stay unexpressible.
    """
    repairs: dict[str, dict[str, str]] = {}
    for address, reason in failures.items():
        match = _ENUM_MISMATCH_RE.search(reason)
        if match is None:
            continue
        got = match["got"]
        allowed = re.findall(r'"([^"]*)"', match["allowed"])
        candidates = [
            value for value in allowed if value.lower() == got.lower()
        ]
        if got in allowed or not candidates:
            continue
        replacement = (
            got.lower() if got.lower() in candidates else candidates[0]
        )
        repairs[address] = {match["attr"]: replacement}
    return repairs


def apply_enum_case_repairs(
    workdir: Path,
    repairs: dict[str, dict[str, str]],
    config_filenames: tuple[str, ...],
) -> dict[str, tuple[str, ...]]:
    """Rewrite enum values to the provider's casing in the workspace.

    Each repaired attribute is additionally pinned with
    ``ignore_changes``: the provider keeps the API's casing in state
    while rejecting it in configuration, so once the value is repaired
    the plan would forever propose the case-only flip back. Returns
    ``{address: (attributes…,)}`` for the blocks actually edited;
    addresses whose block (or attribute) cannot be located are absent
    and remain ordinary unexpressible failures.
    """
    config_files = tuple(workdir / name for name in config_filenames)
    repaired: dict[str, tuple[str, ...]] = {}
    for address, attrs in sorted(repairs.items()):
        edited_attrs: list[str] = []

        def edit(block: str, attrs: dict[str, str] = attrs) -> str:
            for attr, replacement in sorted(attrs.items()):
                replaced = replace_attribute_value(
                    block, attr, f'"{hcl_quote(replacement)}"'
                )
                if replaced is None:
                    continue
                block = replaced
                edited_attrs.append(attr)
            if edited_attrs:
                block = insert_ignore_changes(block, tuple(edited_attrs))
            return block

        if (
            any(
                _edit_resource_block(path, address, edit)
                for path in config_files
            )
            and edited_attrs
        ):
            repaired[address] = tuple(sorted(set(edited_attrs)))
    return repaired


def _attr_sensitive(mask: Any, attr: str) -> bool:
    """Whether the sensitivity mask marks the whole top-level attribute."""
    if mask is True:
        return True
    if isinstance(mask, dict):
        return mask.get(attr) is True
    return False


def _mask_marks_within(mask: Any) -> bool:
    """Whether a sensitivity (sub)mask marks anything at or below it."""
    if mask is True:
        return True
    if isinstance(mask, dict):
        return any(_mask_marks_within(value) for value in mask.values())
    if isinstance(mask, list):
        return any(_mask_marks_within(item) for item in mask)
    return False


def _mask_subtree(mask: Any, attr: str) -> Any:
    return mask.get(attr) if isinstance(mask, dict) else mask


def deep_json_equal(before: Any, after: Any) -> bool:
    """Recursive equality where two unequal string leaves still count
    as equal iff both parse to a JSON *object or array* (never a
    scalar — ``"Mon"`` vs ``"mon"`` must stay unequal) with deep-equal
    content. This is exactly the class of diff ``jsonencode()``
    round-tripping produces: same document, different whitespace or
    key order."""
    if before == after:
        return True
    if isinstance(before, dict) and isinstance(after, dict):
        return set(before) == set(after) and all(
            deep_json_equal(value, after[key]) for key, value in before.items()
        )
    if isinstance(before, list) and isinstance(after, list):
        return len(before) == len(after) and all(
            deep_json_equal(b_item, a_item)
            for b_item, a_item in zip(before, after)
        )
    if isinstance(before, str) and isinstance(after, str):
        try:
            b_doc, a_doc = json.loads(before), json.loads(after)
        except ValueError:
            return False
        if not isinstance(b_doc, (dict, list)) or not isinstance(a_doc, (dict, list)):
            return False
        return deep_json_equal(b_doc, a_doc)
    return False


def classify_plan(document: Any) -> ReconciliationPlan:
    """Split a plan's update actions into phantom classes vs real drift.

    Classification is per top-level attribute; a resource is only
    remediated when *every* diffed attribute falls into a provable
    phantom class — one unexplained attribute makes the whole resource
    real drift (conservative: never mask a genuine change). Only update
    actions have phantom classes at all: any other mutating verb
    (create/delete/replace) is genuine drift by definition and is
    counted in ``real_changes`` so the reconciliation report never
    understates the mutations left in the plan.
    """
    remediations: list[ResourceRemediation] = []
    real: list[str] = []
    changes = document.get("resource_changes") if isinstance(document, dict) else None
    for change in changes if isinstance(changes, list) else []:
        if not isinstance(change, dict):
            continue
        body = change.get("change")
        if not isinstance(body, dict):
            continue
        actions = tuple(body.get("actions") or ())
        if "update" not in actions:
            if any(action not in ("no-op", "read") for action in actions):
                # create/delete/replace: never remediable, always real.
                real.append(str(change.get("address", "")))
            continue
        address = str(change.get("address", ""))
        before, after = body.get("before"), body.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            real.append(address)
            continue
        before_mask = body.get("before_sensitive")
        after_mask = body.get("after_sensitive")
        after_unknown = body.get("after_unknown")
        secret_attrs: list[str] = []
        normalize_attrs: dict[str, Any] = {}
        inject_attrs: dict[str, Any] = {}
        explainable = True
        for attr in sorted(set(before) | set(after)):
            b_value, a_value = before.get(attr), after.get(attr)
            if b_value == a_value:
                continue
            if _mask_marks_within(_mask_subtree(after_unknown, attr)):
                # "(known after apply)" — the plan omits the value from
                # `after`, which would otherwise read as a generator
                # omission; an unknown value is never a provable
                # phantom, so the resource is real drift.
                explainable = False
                break
            sensitive = _attr_sensitive(before_mask, attr) or _attr_sensitive(
                after_mask, attr
            )
            #: normalization writes the state value into the config
            #: files verbatim — never do that when anything under the
            #: attribute is marked sensitive.
            sensitive_within = _mask_marks_within(
                _mask_subtree(before_mask, attr)
            ) or _mask_marks_within(_mask_subtree(after_mask, attr))
            if a_value is None and b_value is not None and sensitive:
                secret_attrs.append(attr)
            elif not sensitive_within and deep_json_equal(b_value, a_value):
                normalize_attrs[attr] = b_value
            elif a_value is None and b_value == "" and not sensitive:
                # Exactly the empty-string class: terraform's generator
                # omits ""-valued attributes, so the provider reads ""
                # while the config says null — a phantom. A NON-empty
                # before with a null after means the value changed in
                # Meraki after generation: genuine clickops drift that
                # must alert, never be silently written into the config.
                inject_attrs[attr] = b_value
            else:
                explainable = False
                break
        if not explainable:
            real.append(address)
            continue
        if secret_attrs or normalize_attrs or inject_attrs:
            remediations.append(
                ResourceRemediation(
                    address=address,
                    secret_attrs=tuple(sorted(set(secret_attrs))),
                    normalize_attrs=normalize_attrs,
                    inject_attrs=inject_attrs,
                )
            )
    return ReconciliationPlan(
        remediations=tuple(remediations), real_changes=tuple(sorted(real))
    )


# ---------------------------------------------------------------------------
# Workspace file surgery
# ---------------------------------------------------------------------------


def _block_span(text: str, address: str) -> tuple[int, int] | None:
    """(start, end) offsets of ``resource "type" "name" { … }`` for the
    address, using terraform's emitted shape (closing brace at column 0,
    or the one-line ``resource "t" "n" {}`` form)."""
    rtype, _, name = address.partition(".")
    opener = re.compile(
        r'^resource\s+"%s"\s+"%s"\s*\{' % (re.escape(rtype), re.escape(name)),
        re.MULTILINE,
    )
    match = opener.search(text)
    if match is None:
        return None
    line_end = text.find("\n", match.start())
    opener_line = text[match.start(): line_end if line_end >= 0 else len(text)]
    if not opener_line.rstrip().endswith("{"):
        # One-line block: the span is exactly its own line — searching
        # for a ``\n}\n`` closer would swallow the *next* block.
        return match.start(), (len(text) if line_end < 0 else line_end + 1)
    close = text.find("\n}\n", match.start())
    if close < 0:
        if text.endswith("\n}"):
            return match.start(), len(text)
        return None
    return match.start(), close + len("\n}\n")


def _edit_resource_block(
    path: Path, address: str, editor: Any
) -> bool:
    """Apply ``editor(block_text) -> str`` to the address's block in
    ``path``; returns True when the file contained (and now holds) it."""
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8")
    span = _block_span(text, address)
    if span is None:
        return False
    start, end = span
    replacement = editor(text[start:end])
    path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
    return True


def drop_resource_blocks(config_files: tuple[Path, ...], addresses: set[str]) -> int:
    """Remove the addresses' resource blocks from whichever config file
    holds them; returns how many blocks were removed."""
    removed = 0
    for path in config_files:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        changed = False
        for address in sorted(addresses):
            span = _block_span(text, address)
            if span is None:
                continue
            start, end = span
            while end < len(text) and text[end] == "\n":
                end += 1
            text = text[:start] + text[end:]
            changed = True
            removed += 1
        if changed:
            path.write_text(text, encoding="utf-8")
    return removed


def drop_import_blocks(imports_file: Path, addresses: set[str]) -> int:
    """Remove ``import { to = <address> … }`` blocks; returns the count."""
    if not imports_file.exists():
        return 0
    text = imports_file.read_text(encoding="utf-8")
    removed = 0
    for address in sorted(addresses):
        pattern = re.compile(
            r"import\s*\{\s*\n\s*to\s*=\s*%s\s*\n(?:.*\n)*?\}\s*\n?"
            % re.escape(address)
        )
        text, count = pattern.subn("", text)
        removed += count
    if removed:
        imports_file.write_text(text, encoding="utf-8")
    return removed


def _reopen_one_line_block(block: str) -> str:
    """Rewrite terraform's one-line ``resource "t" "n" {}`` shape into an
    open multi-line block, so head-insertion editors place content inside
    the braces instead of after the (same-line) closing brace."""
    head, newline, tail = block.partition("\n")
    stripped = head.rstrip()
    if stripped.endswith("{") or tail:
        return block
    reopened, count = re.subn(r"\{\s*\}\s*$", "{", stripped)
    if not count:
        return block
    return reopened + "\n}" + newline


def insert_ignore_changes(block: str, attrs: tuple[str, ...]) -> str:
    """Add (or merge into) a ``lifecycle { ignore_changes = […] }``
    block so plans stop proposing to null out unmanaged secrets."""
    block = _reopen_one_line_block(block)
    existing = _LIFECYCLE_IGNORE_RE.search(block)
    merged = set(attrs)
    if existing:
        merged |= {
            item.strip()
            for item in existing["attrs"].split(",")
            if item.strip()
        }
        block = block[: existing.start()] + block[existing.end():]
    lifecycle = (
        "  lifecycle {\n"
        f"    ignore_changes = [{', '.join(sorted(merged))}]\n"
        "  }\n"
    )
    head, newline, tail = block.partition("\n")
    return head + newline + lifecycle + tail


_BARE_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def synthesize_hcl(value: Any, indent: int = 2) -> str:
    """HCL expression for a state value, string leaves byte-exact.

    Strings are emitted as quoted literals (``hcl_quote`` escaping),
    never ``jsonencode()`` — that is the whole point: ``jsonencode``
    re-serializes with alphabetical keys and no whitespace, which is
    what caused the round-trip diff being remediated.
    """
    pad = " " * indent
    closing = " " * max(indent - 2, 0)
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f'"{hcl_quote(value)}"'
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = []
        for key, item in value.items():
            key_text = (
                key
                if isinstance(key, str) and _BARE_KEY_RE.match(key)
                else f'"{hcl_quote(str(key))}"'
            )
            lines.append(f"{pad}{key_text} = {synthesize_hcl(item, indent + 2)}")
        return "{\n" + "\n".join(lines) + f"\n{closing}}}"
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        lines = [f"{pad}{synthesize_hcl(item, indent + 2)}," for item in value]
        return "[\n" + "\n".join(lines) + f"\n{closing}]"
    # JSON documents have no other leaf types; repr the stragglers as
    # strings so the edit never emits invalid HCL.
    return f'"{hcl_quote(str(value))}"'


def _value_span_end(block: str, start: int) -> int:
    """End offset of the attribute value beginning at ``start``.

    Quote-aware scan: double-quoted strings (backslash escapes honored)
    never contribute to nesting, ``()[]{}`` outside strings do, and the
    value ends at the first newline once nesting is balanced. Generated
    values are literals — interpolations are escaped ``$${`` — so no
    template grammar is needed.
    """
    depth = 0
    in_string = False
    index = start
    while index < len(block):
        char = block[index]
        if in_string:
            if char == "\\":
                index += 2
                continue
            if char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "\n" and depth <= 0:
            return index
        index += 1
    return index


def replace_attribute_value(block: str, attr: str, value_hcl: str) -> str | None:
    """Replace the top-level ``attr = <value>`` assignment's value.

    Top-level attributes in terraform-emitted blocks are indented by
    exactly two spaces, which keeps same-named nested attributes (list
    elements carry their own ``filters_selector``) out of reach.
    Returns None when the block has no top-level assignment.
    """
    opener = re.compile(r"^ {2}%s\s*=\s*" % re.escape(attr), re.MULTILINE)
    match = opener.search(block)
    if match is None:
        return None
    end = _value_span_end(block, match.end())
    return block[: match.end()] + value_hcl + block[end:]


def inject_attribute(block: str, attr: str, value: Any) -> str:
    """Set ``attr = <synthesized literal>`` so config matches state.

    Replaces the attribute's existing top-level assignment when the
    generated config already carries one (e.g. an explicit ``null``);
    otherwise inserts it at the top of the block. Terraform rejects
    duplicate arguments, so replace-or-insert is mandatory.
    """
    literal = synthesize_hcl(value, indent=4)
    replaced = replace_attribute_value(block, attr, literal)
    if replaced is not None:
        return replaced
    block = _reopen_one_line_block(block)
    head, newline, tail = block.partition("\n")
    return f"{head}{newline}  {attr} = {literal}\n{tail}"


def apply_remediations(
    workdir: Path,
    plan: ReconciliationPlan,
    config_filenames: tuple[str, ...],
) -> tuple[dict[str, tuple[str, ...]], dict[str, tuple[str, ...]]]:
    """Apply every remediation to the workspace configuration files.

    Returns ``(ignored_secrets, normalized)`` keyed by address, for
    reporting. Remediations whose resource block cannot be located are
    skipped (the next plan simply reports the change again as drift).
    """
    config_files = tuple(workdir / name for name in config_filenames)
    ignored: dict[str, tuple[str, ...]] = {}
    normalized: dict[str, tuple[str, ...]] = {}
    for remediation in plan.remediations:
        def edit(block: str, remediation: ResourceRemediation = remediation) -> str:
            for attr, value in sorted(remediation.normalize_attrs.items()):
                block = inject_attribute(block, attr, value)
            for attr, value in sorted(remediation.inject_attrs.items()):
                block = inject_attribute(block, attr, value)
            if remediation.secret_attrs:
                block = insert_ignore_changes(block, remediation.secret_attrs)
            return block

        edited = any(
            _edit_resource_block(path, remediation.address, edit)
            for path in config_files
        )
        if not edited:
            logger.warning(
                "Reconciliation could not locate the configuration block "
                "for %s; its plan changes will surface as drift.",
                remediation.address,
            )
            continue
        if remediation.secret_attrs:
            ignored[remediation.address] = remediation.secret_attrs
        if remediation.normalized_attrs:
            normalized[remediation.address] = remediation.normalized_attrs
    return ignored, normalized
