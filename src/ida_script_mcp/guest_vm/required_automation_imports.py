"""Required imports for guest-side IDA GUI/integration automation snapshots.

Run this module inside the guest VM before taking an automation snapshot:

    py -3.11 -m ida_script_mcp.guest_vm.required_automation_imports

The base guest agent only needs ``required_imports.py``. This module covers the
next layer used for opening IDA, waiting for analysis, and testing plugin APIs.
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class RequiredAutomationImport:
    """A guest-side automation import and the package spec that provides it."""

    import_name: str
    package_spec: str
    reason: str


GUEST_AUTOMATION_REQUIRED_IMPORTS = (
    RequiredAutomationImport(
        import_name="requests",
        package_spec="requests>=2.32.0",
        reason="HTTP client used by guest agent and plugin API checks",
    ),
    RequiredAutomationImport(
        import_name="pywinauto",
        package_spec="pywinauto>=0.6.8",
        reason="Windows GUI/process automation for IDA smoke tests",
    ),
    RequiredAutomationImport(
        import_name="psutil",
        package_spec="psutil>=5.9.0",
        reason="robust process discovery and cleanup during IDA automation",
    ),
)

# Import paths that exercise pywinauto's Windows backend dependencies as well as
# the top-level package import.
AUTOMATION_IMPORT_PROBES = (
    "requests",
    "pywinauto",
    "pywinauto.application",
    "pywinauto.keyboard",
    "psutil",
)


def missing_guest_automation_imports() -> list[RequiredAutomationImport]:
    """Return automation imports that are not available in the current interpreter."""

    return [
        item
        for item in GUEST_AUTOMATION_REQUIRED_IMPORTS
        if importlib.util.find_spec(item.import_name) is None
    ]


def verify_guest_automation_imports() -> None:
    """Import every automation probe and raise ImportError if anything is missing."""

    for import_name in AUTOMATION_IMPORT_PROBES:
        importlib.import_module(import_name)


def install_command() -> str:
    """Return the pip command to prepare the guest VM automation snapshot."""

    specs = " ".join(item.package_spec for item in GUEST_AUTOMATION_REQUIRED_IMPORTS)
    return f"{sys.executable} -m pip install --disable-pip-version-check {specs}"


def main() -> None:
    missing = missing_guest_automation_imports()
    if missing:
        print("Missing guest VM automation snapshot imports:", file=sys.stderr)
        for item in missing:
            print(
                f"  {item.import_name}: install {item.package_spec} ({item.reason})",
                file=sys.stderr,
            )
        print("Install command:", file=sys.stderr)
        print(f"  {install_command()}", file=sys.stderr)
        raise SystemExit(1)

    verify_guest_automation_imports()
    print("Guest VM automation imports are available:")
    for item in GUEST_AUTOMATION_REQUIRED_IMPORTS:
        print(f"  {item.import_name} ({item.package_spec})")


if __name__ == "__main__":  # pragma: no cover
    main()
