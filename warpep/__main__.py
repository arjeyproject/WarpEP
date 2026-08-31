"""Allow ``python -m warpep`` everywhere, including Termux and plain Windows."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
