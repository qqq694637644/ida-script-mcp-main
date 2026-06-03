from __future__ import annotations

import sys

from ida_script_mcp.guest_vm import required_imports


def test_guest_required_imports_lists_requests() -> None:
    assert [item.import_name for item in required_imports.GUEST_REQUIRED_IMPORTS] == ["requests"]
    assert required_imports.GUEST_REQUIRED_IMPORTS[0].package_spec == "requests>=2.32.0"


def test_missing_guest_imports_reports_unavailable_imports(monkeypatch) -> None:
    monkeypatch.setattr(required_imports.importlib.util, "find_spec", lambda name: None)

    missing = required_imports.missing_guest_imports()

    assert [item.import_name for item in missing] == ["requests"]


def test_missing_guest_imports_accepts_available_imports(monkeypatch) -> None:
    monkeypatch.setattr(required_imports.importlib.util, "find_spec", lambda name: object())

    assert required_imports.missing_guest_imports() == []


def test_install_command_uses_current_python() -> None:
    command = required_imports.install_command()

    assert command.startswith(sys.executable)
    assert "requests>=2.32.0" in command
