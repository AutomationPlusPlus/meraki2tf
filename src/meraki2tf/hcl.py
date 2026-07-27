"""HCL literal escaping, shared by every module that writes Terraform.

Three writers emit quoted HCL string literals — the kit generator's
``imports.tf`` IDs, the reconciler's ``resources.tf`` baseline values,
and the runner's ``provider.tf``/backend templating. They all escape
raw, externally-sourced text: dump-mode snapshots and Terraform state
carry arbitrary JSON strings straight from the Meraki dashboard.

The escaping therefore has exactly one definition. An unescaped ``"``,
``\\``, or raw newline breaks the whole file's parse; an unescaped
``${``/``%{`` injects a Terraform interpolation expression. JSON also
admits lone UTF-16 surrogates (``"\\ud800"``) that the UTF-8 artifact
write cannot encode, so they are replaced up front — a corrupted
snapshot must not be able to crash the run at write time.

Any remaining raw C0 control byte (a NUL, a form feed, …) or DEL is
escaped to a ``\\uXXXX`` sequence too, so every artifact stays clean,
diff-able, greppable text rather than a binary blob that editors, CI
log collectors, and ``terraform`` scanner tolerance would each treat
differently.
"""

from __future__ import annotations


def hcl_quote(value: str) -> str:
    """Escape a raw value for interpolation into a quoted HCL literal.

    Lone UTF-16 surrogates are replaced before escaping so the result is
    always encodable by the UTF-8 artifact writes. Any remaining C0
    control character (except the ``\\t``/``\\n``/``\\r`` handled above)
    and U+007F are escaped to ``\\uXXXX`` so the emitted file is clean
    text; a ``terraform console`` round-trip still decodes the intended
    (control) byte.
    """
    value = value.encode("utf-8", errors="replace").decode("utf-8")
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("${", "$${")
        .replace("%{", "%%{")
    )
    if not any(_is_bare_control(ch) for ch in escaped):
        return escaped
    return "".join(
        f"\\u{ord(ch):04x}" if _is_bare_control(ch) else ch for ch in escaped
    )


def _is_bare_control(char: str) -> bool:
    """True for a C0 control or DEL still standing after the short escapes.

    ``\\t``/``\\n``/``\\r`` are already turned into two-character escapes
    before this sweep runs, so only the remaining controls reach here.
    """
    codepoint = ord(char)
    return codepoint < 0x20 or codepoint == 0x7F


def unsafe_identifier_reason(value: str) -> str | None:
    """Why *value* can't be an import-ID component verbatim, or ``None``.

    An import ID must round-trip into ``imports.tf`` and address the live
    object byte-for-byte. Three classes of character cannot, and each is
    silently rewritten somewhere upstream unless caught here — turning an
    un-importable asset into one the coverage manifest calls covered:

    * a lone UTF-16 surrogate (or anything the UTF-8 artifact write can't
      encode) — ``hcl_quote`` replaces it with ``?``;
    * leading or trailing whitespace — the model layer strips it;
    * any other C0 control character or DEL — ``hcl_quote`` escapes it, so
      the emitted ``\\uXXXX`` no longer matches the object's real ID.

    Genuinely valid IDs (network/org IDs, serials, path components) carry
    none of these, so they return ``None`` and import unchanged.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return (
            "contains an un-encodable character (a lone UTF-16 surrogate) "
            "and cannot be safely imported"
        )
    if value != value.strip():
        return (
            "has leading or trailing whitespace and cannot be safely "
            "imported"
        )
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        return "contains a control character and cannot be safely imported"
    return None
