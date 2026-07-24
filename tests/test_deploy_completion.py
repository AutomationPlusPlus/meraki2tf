"""The bash completion script must track the real CLI flag set.

deploy/completion/meraki2tf.bash is hand-maintained (static flag-name
completion, no runtime introspection); this test pins it to
``build_parser()`` so a new or removed flag cannot silently drift the
completion out of truth.
"""

from __future__ import annotations

import re
from pathlib import Path

from meraki2tf.cli import build_parser

COMPLETION_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy" / "completion" / "meraki2tf.bash"
)


def _completion_flags() -> set[str]:
    text = COMPLETION_PATH.read_text(encoding="utf-8")
    match = re.search(r'flags="\n(.*?)\n\s*"', text, re.DOTALL)
    assert match is not None, "flags list not found in the completion script"
    return {line.strip() for line in match.group(1).splitlines() if line.strip()}


def _parser_long_flags() -> set[str]:
    parser = build_parser()
    return {
        option
        for action in parser._actions
        for option in action.option_strings
        if option.startswith("--")
    }


def test_completion_covers_exactly_the_parsers_long_flags() -> None:
    assert _completion_flags() == _parser_long_flags()


def test_completion_registers_the_console_script_name() -> None:
    text = COMPLETION_PATH.read_text(encoding="utf-8")
    assert re.search(r"complete .*-F _meraki2tf_complete meraki2tf\s*$", text, re.M)
