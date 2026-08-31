"""Entry point for ``python -m warpep``."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
