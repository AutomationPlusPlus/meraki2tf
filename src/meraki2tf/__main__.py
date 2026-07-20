"""``python -m meraki2tf`` — same entry point as the console script."""

import sys

from meraki2tf.cli import main

if __name__ == "__main__":  # pragma: no cover - exercised via python -m
    sys.exit(main())
