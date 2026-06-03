from __future__ import annotations

import json
import os
import subprocess
import sys

from ida_script_mcp.payload.ida_plugin_install import (
    DEFAULT_GUEST_IDA_DIR,
    LEGACY_ROOT_SUPPORT_FILES,
    PLUGIN_INSTALL_FILES,
    build_guest_ida_plugin_install_script,
)


def test_build_guest_ida_plugin_install_script_contains_ida_dir() -> None:
    script = build_guest_ida_plugin_install_script(ida_dir=DEFAULT_GUEST_IDA_DIR)

    assert "IDAPro8.3" in script
    assert "IDA_PLUGIN_INSTALL_VERIFY_RESULT=" in script
    for destination in PLUGIN_INSTALL_FILES.values():
        assert destination in script


def test_guest_ida_plugin_install_script_installs_and_verifies(tmp_path) -> None:
    ida_dir = tmp_path / "IDAPro8.3"
    ida_dir.mkdir()
    (ida_dir / "ida64.exe").write_bytes(b"fake ida executable")
    appdata = tmp_path / "AppData" / "Roaming"
    plugins_dir = appdata / "Hex-Rays" / "IDA Pro" / "plugins"
    plugins_dir.mkdir(parents=True)
    for legacy_name in LEGACY_ROOT_SUPPORT_FILES:
        (plugins_dir / legacy_name).write_text("# stale root support file\n", encoding="utf-8")

    script_path = tmp_path / "install_payload.py"
    script_path.write_text(
        build_guest_ida_plugin_install_script(ida_dir=str(ida_dir)),
        encoding="utf-8",
    )

    env = os.environ.copy()
    env["APPDATA"] = str(appdata)
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    for destination in PLUGIN_INSTALL_FILES.values():
        assert (plugins_dir / destination).is_file()
    assert (plugins_dir / "ida_script_mcp_support" / "__init__.py").is_file()
    for legacy_name in LEGACY_ROOT_SUPPORT_FILES:
        assert not (plugins_dir / legacy_name).exists()

    manifest_path = plugins_dir / "ida_script_mcp_install_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "installed"
    assert manifest["ida_dir"] == str(ida_dir)
    assert manifest["plugin_name"] == "IDA-Script-MCP"
    assert manifest["plugin_has_ida_runtime"] is False
    assert "ida_script_mcp_support.protocol" in manifest["imported_support"]
    assert "ida_script_mcp_support.change_recorder" in manifest["imported_support"]
    assert len(manifest["removed_legacy_support_files"]) == len(LEGACY_ROOT_SUPPORT_FILES)
    assert manifest["remaining_legacy_support_files"] == []
    assert str(ida_dir / "ida64.exe") in manifest["ida_executables"]
    assert "IDA_PLUGIN_INSTALL_VERIFY_RESULT=" in result.stdout
