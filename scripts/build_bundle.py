#!/usr/bin/env python3
"""Build ``warpep.pyz``: the whole scanner in one runnable file.

Because WarpEP has zero third-party dependencies, a zipapp is a genuinely
portable build artefact: copy it anywhere Python 3.8+ exists and run
``python3 warpep.pyz scan``. No pip, no compiler, no root.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "warpep.pyz"

LAUNCHER = '''"""WarpEP by ArJey - single-file bundle."""
import sys

from warpep.cli import main

if __name__ == "__main__":
    sys.exit(main())
'''


def build(output: Path = OUTPUT) -> Path:
    with tempfile.TemporaryDirectory() as tmp:
        staging = Path(tmp) / "app"
        staging.mkdir()
        shutil.copytree(
            ROOT / "warpep",
            staging / "warpep",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (staging / "__main__.py").write_text(LAUNCHER, encoding="utf-8")
        zipapp.create_archive(staging, output, interpreter="/usr/bin/env python3", compressed=True)
    output.chmod(0o755)
    return output


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else OUTPUT
    built = build(target)
    print(f"built {built} ({built.stat().st_size // 1024} KiB)")
