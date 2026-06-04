from __future__ import annotations

import sys

from ida_script_mcp.guest_vm import required_automation_imports


def test_guest_automation_required_imports_lists_expected_packages() -> None:
    assert [
        item.import_name for item in required_automation_imports.GUEST_AUTOMATION_REQUIRED_IMPORTS
    ] == ["requests", "pywinauto", "psutil"]
    assert required_automation_imports.GUEST_AUTOMATION_REQUIRED_IMPORTS[1].package_spec == (
        "pywinauto>=0.6.8"
    )


def test_missing_guest_automation_imports_reports_unavailable_imports(monkeypatch) -> None:
    monkeypatch.setattr(required_automation_imports.importlib.util, "find_spec", lambda name: None)

    missing = required_automation_imports.missing_guest_automation_imports()

    assert [item.import_name for item in missing] == ["requests", "pywinauto", "psutil"]


def test_missing_guest_automation_imports_accepts_available_imports(monkeypatch) -> None:
    monkeypatch.setattr(
        required_automation_imports.importlib.util,
        "find_spec",
        lambda name: object(),
    )

    assert required_automation_imports.missing_guest_automation_imports() == []


def test_install_command_uses_current_python_and_automation_specs() -> None:
    command = required_automation_imports.install_command()

    assert command.startswith(sys.executable)
    assert "requests>=2.32.0" in command
    assert "pywinauto>=0.6.8" in command
    assert "psutil>=5.9.0" in command
