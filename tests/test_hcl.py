"""The single HCL literal escaper and its import-ID safety predicate."""

from meraki2tf.hcl import hcl_quote, unsafe_identifier_reason


def test_hcl_quote_preserves_the_existing_escapes() -> None:
    """The pre-existing escape set (and its ordering) is unchanged — a
    backslash is doubled before the other sequences can re-introduce one."""
    assert hcl_quote('a\\b"c\nd\re\tf${g}%{h}') == 'a\\\\b\\"c\\nd\\re\\tf$${g}%%{h}'


def test_hcl_quote_escapes_a_nul_to_a_clean_text_sequence() -> None:
    """F2: a raw NUL (or any other C0 control) used to land literally in
    imports.tf, making the DR kit a binary blob editors/CI collectors
    mangle. It must be escaped so the file stays clean, greppable text."""
    quoted = hcl_quote("L_\x00123")
    assert quoted == "L_\\u0000123"
    # The emitted bytes are printable text — no bare control byte survives.
    assert "\x00" not in quoted
    assert all(ord(ch) >= 0x20 for ch in quoted)


def test_hcl_quote_escapes_the_c0_range_and_del_but_not_tab_newline_cr() -> None:
    """Every C0 control and U+007F is escaped, except the three that
    already have a dedicated short escape (which must not double-escape)."""
    # 0x07 (BEL) and 0x1f (US) and 0x7f (DEL) become \uXXXX.
    assert hcl_quote("\x07\x1f\x7f") == "\\u0007\\u001f\\u007f"
    # tab/newline/cr keep their short escapes, not 	 etc.
    assert hcl_quote("\t\n\r") == "\\t\\n\\r"


def test_hcl_quote_leaves_clean_text_untouched() -> None:
    """The escape sweep only runs when a bare control is present, so an
    ordinary identifier is returned byte-for-byte."""
    assert hcl_quote("org-123,L_647392837465") == "org-123,L_647392837465"


def test_hcl_quote_output_round_trips_the_intended_value() -> None:
    """A ``terraform console`` decode of the escaped literal yields the
    original bytes back — F2 changes the FILE's cleanliness, not meaning.

    ``codecs.decode(..., "unicode_escape")`` mirrors HCL's decoding of the
    ``\\uXXXX``/``\\n`` sequences for the ASCII-range values here.
    """
    import codecs

    for original in ("L_\x00123", "a\tb", "x\x1fy", "z\x7f"):
        decoded = codecs.decode(hcl_quote(original), "unicode_escape")
        assert decoded == original


def test_unsafe_identifier_reason_passes_genuine_ids() -> None:
    """Real Meraki identifiers carry none of the un-encodable/edge/control
    characters, so they are importable verbatim."""
    for good in ("L_647392837465", "Q2XX-1234-ABCD", "org-123", "10", "N.1", "N-1"):
        assert unsafe_identifier_reason(good) is None


def test_unsafe_identifier_reason_rejects_a_lone_surrogate() -> None:
    """A lone UTF-16 surrogate cannot be UTF-8 encoded; hcl_quote would
    silently replace it with ``?`` — reject instead."""
    reason = unsafe_identifier_reason("L_\ud800123")
    assert reason is not None and "un-encodable" in reason


def test_unsafe_identifier_reason_rejects_edge_whitespace() -> None:
    """Edge whitespace is exactly what the model layer used to strip."""
    for padded in ("L_123 ", " L_123", "L_123\n", "\tL_123"):
        reason = unsafe_identifier_reason(padded)
        assert reason is not None and "whitespace" in reason


def test_unsafe_identifier_reason_rejects_a_control_character() -> None:
    """An interior control byte round-trips through hcl_quote but no real
    ID carries one; treat it as un-importable rather than covered."""
    reason = unsafe_identifier_reason("L_\x001")
    assert reason is not None and "control character" in reason
