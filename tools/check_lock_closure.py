#!/usr/bin/env python3
"""Verify ``requirements-lock.txt`` is a usable, complete runtime closure.

The lock file is the unattended worker's and the container image's only
source of runtime dependencies, and nothing else in the suite installs
from it: the tests run against the developer's environment and CI's tox
envs resolve ``pyproject.toml``'s range instead. A lock file that no
longer matches the SDK's dependency set therefore breaks the DR install
path silently, and stays broken until someone rebuilds an image
mid-incident.

That is not hypothetical. The SDK's 4.x line replaced ``aiohttp`` and
``requests`` with ``httpx``; a version bump rewrites the pinned line but
does not re-resolve the closure around it, leaving the file both missing
``httpx`` (pip refuses the whole install in hash-checking mode) and
still pinning an aiohttp stack nothing imports.

Two checks, run against the real resolver:

1. **Shape** — the set of distribution *names* pip resolves from
   ``requirements.txt`` must equal the set pinned in the lock. Missing a
   name is the breakage above; carrying an extra one is stale weight
   shipped into every image. Versions are deliberately not compared:
   the lock trails the range by design between dependency bumps, and
   gating on that would turn CI red on any upstream release.

2. **Install** — the documented command must actually succeed and yield
   a working CLI, in hash-checking, wheels-only mode.

Network access is required (both checks resolve against PyPI), which is
why this lives here rather than in the hermetic pytest suite.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "requirements-lock.txt"
REQUIREMENTS = ROOT / "requirements.txt"

#: ``pkg==version`` at the start of a line — the pinned distributions.
PIN_PATTERN = re.compile(r"^([A-Za-z0-9_.-]+)==", re.M)


def normalize(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def make_venv(path: Path) -> Path:
    """Create a virtualenv at ``path`` and return its interpreter."""
    venv.EnvBuilder(with_pip=True).create(path)
    return path / "bin" / "python"


def run(*command: str | Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(part) for part in command], capture_output=True, text=True
    )


def pinned_names() -> set[str]:
    return {normalize(n) for n in PIN_PATTERN.findall(LOCK.read_text())}


def resolved_names(python: Path) -> set[str]:
    install = run(python, "-m", "pip", "install", "-q", "-r", REQUIREMENTS)
    if install.returncode:
        sys.exit(f"resolving {REQUIREMENTS.name} failed:\n{install.stderr}")
    frozen = run(python, "-m", "pip", "freeze")
    return {
        normalize(line.split("==")[0])
        for line in frozen.stdout.splitlines()
        if "==" in line
    }


def check_shape(python: Path) -> list[str]:
    pinned, resolved = pinned_names(), resolved_names(python)
    problems = []
    for missing in sorted(resolved - pinned):
        problems.append(
            f"{missing} is a runtime dependency but is not pinned in "
            f"{LOCK.name} — the hash-checked install will refuse to run"
        )
    for extra in sorted(pinned - resolved):
        problems.append(
            f"{extra} is pinned in {LOCK.name} but is no longer a runtime "
            "dependency — stale weight in every image built from it"
        )
    return problems


def check_install(python: Path) -> list[str]:
    install = run(
        python,
        "-m",
        "pip",
        "install",
        "-q",
        "--require-hashes",
        "--only-binary=:all:",
        "-r",
        LOCK,
    )
    if install.returncode:
        return [f"the hash-pinned install failed:\n{install.stderr.strip()}"]
    package = run(python, "-m", "pip", "install", "-q", "--no-deps", ROOT)
    if package.returncode:
        return [f"installing the package failed:\n{package.stderr.strip()}"]
    smoke = run(python, "-m", "meraki2tf.cli", "--version")
    if smoke.returncode:
        return [f"the installed CLI does not run:\n{smoke.stderr.strip()}"]
    return []


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        problems = check_shape(make_venv(root / "range"))
        problems += check_install(make_venv(root / "lock"))

    for problem in problems:
        print(f"error: {problem}", file=sys.stderr)
    if problems:
        print(
            f"\n{LOCK.name} is out of date — re-resolve it "
            "(instructions in that file's header).",
            file=sys.stderr,
        )
        return 1
    print(f"{LOCK.name}: closure complete, hash-pinned install verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
