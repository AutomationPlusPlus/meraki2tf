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
  must be lowercase ``"mon"`` while Meraki returns ``"Mon"``). The
  configuration cannot round-trip at all, so the resource is dropped
  from the kit (import block + config block) and reported as
  *unsupported* — the coverage manifest is the manual-rebuild runbook.
* **Secret attributes** — generated configuration never carries
  sensitive values (the provider exposes write-only ``…_wo`` siblings
  instead), so the plan wants to null them out (``psk``,
  ``community_string``). A ``lifecycle {{ ignore_changes = […] }}``
  block suppresses the phantom change; the attributes are reported as
  *unmanaged secrets* so the operator knows to restore them manually
  after a rebuild.
* **Value normalization** — the state holds strings that differ from
  the generated expression only in formatting (``jsonencode()``
  whitespace), or holds empty strings the generator omitted entirely
  (plan: ``"" -> null``). The configuration is rewritten to the exact
  state value, so the diff disappears while real future drift on the
  same attribute stays visible.

Anything the classifier cannot prove to be one of these classes is left
untouched and surfaces as ordinary drift. All edits are local file
surgery on the workspace — Meraki is never touched.
"""

from __future__ import annotations

import json
import logging
import re
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
#: ``Error: <title>`` followed by ``  with <address>,``.
_VALIDATION_ERROR_RE = re.compile(
    r"^Error: (?P<title>.+?)\n"
    r"\n"
    r"(?:.*?\n)*?"
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

_SCALAR_TYPES = (str, int, float, bool)


@dataclass(frozen=True)
class ResourceRemediation:
    """Per-resource remediation extracted from one plan document."""

    address: str
    #: Top-level sensitive attributes whose only diff is state → null.
    secret_attrs: tuple[str, ...] = ()
    #: attr → ordered per-occurrence decisions for its ``jsonencode()``
    #: spans: the exact state string to substitute, or None to keep.
    json_rewrites: dict[str, tuple[str | None, ...]] = field(default_factory=dict)
    #: Top-level scalar attributes the generator omitted (plan shows
    #: state-value → null): attr → exact state value to inject.
    inject_attrs: dict[str, Any] = field(default_factory=dict)

    @property
    def normalized_attrs(self) -> tuple[str, ...]:
        """Attribute names whose values get rewritten or injected."""
        rewritten = tuple(
            attr
            for attr, decisions in sorted(self.json_rewrites.items())
            if any(d is not None for d in decisions)
        )
        return rewritten + tuple(sorted(self.inject_attrs))


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


def _diff_leaves(
    before: Any, after: Any, path: tuple[Any, ...] = ()
) -> list[tuple[tuple[Any, ...], Any, Any]]:
    """Differing leaves of two parallel JSON trees, in generated-config
    order (list index order; dict keys alphabetical, matching how
    terraform emits generated attributes)."""
    if isinstance(before, dict) and isinstance(after, dict):
        leaves: list[tuple[tuple[Any, ...], Any, Any]] = []
        for key in sorted(set(before) | set(after)):
            leaves.extend(_diff_leaves(before.get(key), after.get(key), path + (key,)))
        return leaves
    if (
        isinstance(before, list)
        and isinstance(after, list)
        and len(before) == len(after)
    ):
        leaves = []
        for index, (b_item, a_item) in enumerate(zip(before, after)):
            leaves.extend(_diff_leaves(b_item, a_item, path + (index,)))
        return leaves
    if before != after:
        return [(path, before, after)]
    return []


def _string_leaves(node: Any, attr: str, path: tuple[Any, ...] = ()) -> list[
    tuple[tuple[Any, ...], str]
]:
    """String-valued leaves named ``attr``, in generated-config order."""
    if isinstance(node, dict):
        leaves: list[tuple[tuple[Any, ...], str]] = []
        for key in sorted(node):
            value = node[key]
            if key == attr and isinstance(value, str):
                leaves.append((path + (key,), value))
            else:
                leaves.extend(_string_leaves(value, attr, path + (key,)))
        return leaves
    if isinstance(node, list):
        leaves = []
        for index, item in enumerate(node):
            leaves.extend(_string_leaves(item, attr, path + (index,)))
        return leaves
    return []


def _is_sensitive(mask: Any, path: tuple[Any, ...]) -> bool:
    """Whether the sensitivity mask marks ``path`` (or a parent) sensitive."""
    node = mask
    for step in path:
        if node is True:
            return True
        if isinstance(node, dict):
            node = node.get(step)
        elif isinstance(node, list) and isinstance(step, int) and step < len(node):
            node = node[step]
        else:
            return False
    return node is True


def _json_equal_strings(before: Any, after: Any) -> bool:
    """True when both values are JSON documents differing only in text."""
    if not isinstance(before, str) or not isinstance(after, str):
        return False
    try:
        return bool(json.loads(before) == json.loads(after))
    except ValueError:
        return False


def classify_plan(document: Any) -> ReconciliationPlan:
    """Split a plan's update actions into phantom classes vs real drift.

    A resource is only remediated when *every* diffed leaf falls into a
    provable phantom class; one unexplained leaf makes the whole
    resource real drift (conservative — never mask a genuine change).
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
        if "update" not in tuple(body.get("actions") or ()):
            continue
        address = str(change.get("address", ""))
        before, after = body.get("before"), body.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            real.append(address)
            continue
        secret_attrs: list[str] = []
        whitespace_attrs: dict[str, set[tuple[Any, ...]]] = {}
        inject_attrs: dict[str, Any] = {}
        explainable = True
        for path, b_leaf, a_leaf in _diff_leaves(before, after):
            attr = path[-1] if path else ""
            sensitive = _is_sensitive(
                body.get("before_sensitive"), path
            ) or _is_sensitive(body.get("after_sensitive"), path)
            if a_leaf is None and b_leaf is not None and sensitive and len(path) == 1:
                secret_attrs.append(str(attr))
            elif _json_equal_strings(b_leaf, a_leaf):
                whitespace_attrs.setdefault(str(attr), set()).add(path)
            elif (
                a_leaf is None
                and isinstance(b_leaf, _SCALAR_TYPES)
                and not sensitive
                and len(path) == 1
            ):
                inject_attrs[str(attr)] = b_leaf
            else:
                explainable = False
                break
        if not explainable:
            real.append(address)
            continue
        json_rewrites: dict[str, tuple[str | None, ...]] = {}
        for attr, diff_paths in whitespace_attrs.items():
            # every jsonencode() span of this attribute in the generated
            # block, in text order == tree order; rewrite only the
            # occurrences the plan proved to be whitespace-only diffs
            decisions = tuple(
                before_value if leaf_path in diff_paths else None
                for leaf_path, before_value in _string_leaves(before, attr)
            )
            json_rewrites[attr] = decisions
        if secret_attrs or json_rewrites or inject_attrs:
            remediations.append(
                ResourceRemediation(
                    address=address,
                    secret_attrs=tuple(sorted(set(secret_attrs))),
                    json_rewrites=json_rewrites,
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
    address, using terraform's emitted shape (closing brace at column 0)."""
    rtype, _, name = address.partition(".")
    opener = re.compile(
        r'^resource\s+"%s"\s+"%s"\s*\{' % (re.escape(rtype), re.escape(name)),
        re.MULTILINE,
    )
    match = opener.search(text)
    if match is None:
        return None
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


def insert_ignore_changes(block: str, attrs: tuple[str, ...]) -> str:
    """Add (or merge into) a ``lifecycle { ignore_changes = […] }``
    block so plans stop proposing to null out unmanaged secrets."""
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


def inject_attribute(block: str, attr: str, value: Any) -> str:
    """Set ``attr = <literal>`` so the config matches state exactly.

    Replaces the attribute's existing top-level assignment when the
    generated config already carries one (e.g. an explicit ``null``);
    otherwise inserts it at the top of the block. Terraform rejects
    duplicate arguments, so replace-or-insert is mandatory.
    """
    if isinstance(value, bool):
        literal = "true" if value else "false"
    elif isinstance(value, str):
        literal = f'"{hcl_quote(value)}"'
    else:
        literal = json.dumps(value)
    existing = re.compile(
        r"^(\s+%s\s*=\s*).*$" % re.escape(attr), re.MULTILINE
    )
    match = existing.search(block)
    if match is not None:
        return (
            block[: match.start()]
            + f"{match.group(1)}{literal}"
            + block[match.end():]
        )
    head, newline, tail = block.partition("\n")
    return f"{head}{newline}  {attr} = {literal}\n{tail}"


def rewrite_jsonencode_spans(
    block: str, attr: str, decisions: tuple[str | None, ...]
) -> str:
    """Replace the k-th ``attr = jsonencode( … )`` span with the exact
    state string from ``decisions[k]`` (None keeps the span).

    Occurrence order in the generated text matches the plan tree's
    walk order — list elements in order, attributes alphabetical —
    which is how ``classify_plan`` built the decision tuple.
    """
    opener = re.compile(r"%s\s*=\s*jsonencode\(" % re.escape(attr))
    result: list[str] = []
    cursor = 0
    occurrence = 0
    while True:
        match = opener.search(block, cursor)
        if match is None:
            break
        # balanced-paren scan from the opening parenthesis
        depth = 1
        index = match.end()
        while index < len(block) and depth:
            depth += {"(": 1, ")": -1}.get(block[index], 0)
            index += 1
        decision = (
            decisions[occurrence] if occurrence < len(decisions) else None
        )
        result.append(block[cursor:match.start()])
        if decision is None:
            result.append(block[match.start():index])
        else:
            result.append(f'{attr} = "{hcl_quote(decision)}"')
        cursor = index
        occurrence += 1
    result.append(block[cursor:])
    return "".join(result)


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
            for attr, decisions in sorted(remediation.json_rewrites.items()):
                block = rewrite_jsonencode_spans(block, attr, decisions)
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
