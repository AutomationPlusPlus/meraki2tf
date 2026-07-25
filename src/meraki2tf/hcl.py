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
"""

from __future__ import annotations


def hcl_quote(value: str) -> str:
    """Escape a raw value for interpolation into a quoted HCL literal.

    Lone UTF-16 surrogates are replaced before escaping so the result is
    always encodable by the UTF-8 artifact writes.
    """
    value = value.encode("utf-8", errors="replace").decode("utf-8")
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("${", "$${")
        .replace("%{", "%%{")
    )
