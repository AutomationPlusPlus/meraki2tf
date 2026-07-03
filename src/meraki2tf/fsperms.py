"""Owner-only (0600) enforcement for secret-bearing files.

Snapshots and terraform state carry plaintext credentials; POSIX file
modes are the lock. On non-POSIX platforms — and on mounts that ignore
chmod, such as SMB/Azure Files — that lock silently does not hold.
This helper verifies the mode after chmod and warns instead of
pretending, so a scheduled run on a degraded filesystem is visible in
the log rather than a false sense of security.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

_OWNER_ONLY = 0o600


def restrict_to_owner(path: Path) -> bool:
    """chmod ``path`` to 0600 and verify it stuck; WARN when it cannot.

    Returns True when owner-only permissions are verified in effect.
    """
    path.chmod(_OWNER_ONLY)
    if os.name != "posix":
        logger.warning(
            "Owner-only (0600) permissions cannot be guaranteed for %s: "
            "this platform (os.name=%r) does not enforce POSIX file modes. "
            "The file may contain secrets; restrict access via filesystem ACLs.",
            path,
            os.name,
        )
        return False
    actual = os.stat(path).st_mode & 0o777
    if actual != _OWNER_ONLY:
        logger.warning(
            "chmod(0600) did not take effect for %s: effective mode is %04o "
            "(the filesystem likely ignores POSIX permissions, e.g. an "
            "SMB/Azure Files mount). The file may contain secrets; restrict "
            "access via share or directory ACLs.",
            path,
            actual,
        )
        return False
    return True
