"""Shared SDK verb verification: the spec-poisoned-dispatch defense."""

import types
from typing import Any

from meraki2tf.sdk_verify import (
    READ_ONLY_SESSION_VERBS,
    WRITE_SESSION_VERBS,
    method_matches_verbs,
)


def _put_method(*args: object, **kwargs: object) -> dict[str, object]:
    """Stand-in for a generated SDK PUT: self._session.put(url)."""
    return {}


def _get_method(*args: object, **kwargs: object) -> dict[str, object]:
    """Stand-in for a generated SDK GET: self._session.get(url)."""
    return {}


def _delete_method(*args: object, **kwargs: object) -> dict[str, object]:
    """Stand-in for a mislabeled destroyer: self._session.delete(url)."""
    return {}


def _verbless_method(*args: object, **kwargs: object) -> dict[str, object]:
    """A 'meraki' function with no session-verb fingerprint at all."""
    return {}


def _as_meraki(func: Any) -> Any:
    """A distinct clone of ``func`` claiming to live in the meraki SDK."""
    clone = types.FunctionType(
        func.__code__, func.__globals__, func.__name__,
        func.__defaults__, func.__closure__,
    )
    clone.__doc__ = func.__doc__
    clone.__module__ = "meraki.api.networks"
    return clone


def test_non_meraki_methods_pass() -> None:
    """Test doubles and wrappers are outside the threat model."""
    assert method_matches_verbs(_delete_method, WRITE_SESSION_VERBS)
    assert method_matches_verbs(lambda: None, READ_ONLY_SESSION_VERBS)


def test_meraki_methods_verified_by_source_verbs() -> None:
    assert method_matches_verbs(_as_meraki(_put_method), WRITE_SESSION_VERBS)
    assert method_matches_verbs(
        _as_meraki(_get_method), READ_ONLY_SESSION_VERBS
    )
    # A GET-verb method is not a write, and vice versa.
    assert not method_matches_verbs(
        _as_meraki(_get_method), WRITE_SESSION_VERBS
    )
    assert not method_matches_verbs(
        _as_meraki(_put_method), READ_ONLY_SESSION_VERBS
    )
    # The attack this exists for: a delete routed under a PUT label.
    assert not method_matches_verbs(
        _as_meraki(_delete_method), WRITE_SESSION_VERBS
    )


def test_meraki_method_without_verbs_fails_closed() -> None:
    assert not method_matches_verbs(
        _as_meraki(_verbless_method), WRITE_SESSION_VERBS
    )


def test_meraki_method_without_readable_source_fails_closed() -> None:
    namespace: dict[str, Any] = {}
    exec("def sourceless(*a, **k):\n    return {}", namespace)
    sourceless = namespace["sourceless"]
    sourceless.__module__ = "meraki.api.networks"
    assert not method_matches_verbs(sourceless, WRITE_SESSION_VERBS)


def test_verdicts_are_memoized_per_function_and_verb_set() -> None:
    clone = _as_meraki(_put_method)
    first = method_matches_verbs(clone, WRITE_SESSION_VERBS)
    second = method_matches_verbs(clone, WRITE_SESSION_VERBS)
    assert first is second is True
    # Same function under a different allowed set is a separate verdict.
    assert not method_matches_verbs(clone, READ_ONLY_SESSION_VERBS)
    assert not method_matches_verbs(clone, READ_ONLY_SESSION_VERBS)


def test_bound_methods_are_verified_via_their_function() -> None:
    class Section:
        put_like = _as_meraki(_put_method)
        delete_like = _as_meraki(_delete_method)

    section = Section()
    assert method_matches_verbs(section.put_like, WRITE_SESSION_VERBS)
    assert not method_matches_verbs(section.delete_like, WRITE_SESSION_VERBS)
