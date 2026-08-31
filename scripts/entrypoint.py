"""PyInstaller entry point: builds a standalone `warpep` executable."""

import sys

from warpep.cli import main

if __name__ == "__main__":
    sys.exit(main())
