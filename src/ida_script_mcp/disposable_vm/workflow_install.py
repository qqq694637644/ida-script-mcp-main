"""Install the repository package for GitHub Actions workflows.

Keep workflow logic in Python files instead of inline shell/PowerShell blocks so
changes are reviewable, syntax-checkable, and locally testable.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    command = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-e", "."]
    print("Installing project package:", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=str(_repo_root()), check=False)
    return int(completed.returncode)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
