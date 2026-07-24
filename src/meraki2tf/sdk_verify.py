"""Source-level verification of dynamically resolved Meraki SDK methods.

The DR engines resolve SDK methods purely by operationId/tag strings
taken from the OpenAPI document (``getattr(section, op.operation_id)``)
and then call whatever came back. The spec is therefore a dispatch
table: a stale, skewed, or tampered document could label a *deleting*
SDK method as this asset's PUT, and the engine would faithfully call
it. The resolved method's own source is the ground truth for what it
does — every generated ``meraki``-package method funnels its request
through exactly one ``self._session.<verb>(`` call — so the engines
verify that fingerprint before dispatching.

The discovery read path pioneered this defense
(:func:`meraki2tf.providers.live._method_is_read_only`); this module is
the generalized, shared form for the write paths (``--restore``,
``--heal``, ``--replay-gaps``) and for read-back lookups performed by
those engines. Fail-closed per Cardinal Rule 1: a real SDK method whose
source cannot be read, or whose session verbs stray outside the allowed
set, is refused.
"""

from __future__ import annotations

import inspect
import re
from typing import Any

#: Session verbs that only ever read.
READ_ONLY_SESSION_VERBS = frozenset({"get", "get_pages"})

#: Session verbs a non-destructive write (create/configure/claim) may
#: use. ``delete`` is deliberately absent: no restore/heal/replay
#: action ever legitimately deletes.
WRITE_SESSION_VERBS = frozenset({"put", "post"})

_SESSION_VERB_PATTERN = re.compile(r"self\._session\.([A-Za-z_]+)\(")

#: (underlying function, allowed verb set) → verdict. Memoized: the SDK
#: surface is a few hundred generated functions and source parsing is
#: not free, while a restore dispatches thousands of actions.
_verdicts: dict[tuple[Any, frozenset[str]], bool] = {}


def method_matches_verbs(method: Any, allowed: frozenset[str]) -> bool:
    """True when the resolved SDK method verifiably stays within ``allowed``.

    Only real ``meraki``-package methods carry the generated
    ``self._session.<verb>(`` fingerprint; anything else (a test double,
    a wrapper) is outside the spec-poisoning threat model and passes.
    Real SDK methods whose source cannot be read, or whose session
    verbs are not a subset of ``allowed``, are refused — fail closed.
    """
    func = getattr(method, "__func__", method)
    module = getattr(func, "__module__", "") or ""
    if module.split(".", 1)[0] != "meraki":
        return True
    key = (func, allowed)
    cached = _verdicts.get(key)
    if cached is not None:
        return cached
    try:
        source = inspect.getsource(func)
    except (OSError, TypeError):
        verdict = False
    else:
        verbs = set(_SESSION_VERB_PATTERN.findall(source))
        verdict = bool(verbs) and verbs <= allowed
    _verdicts[key] = verdict
    return verdict
