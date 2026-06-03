from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ida_script_mcp.payload.ida_api_test import (
    DEFAULT_GUEST_DLL_PATH,
    DEFAULT_GUEST_IDA_DIR,
    DEFAULT_IDA_API_TEST_MODE,
    DEFAULT_IDA_TIMEOUT_SECONDS,
    build_guest_ida_api_test_script,
)


def test_build_guest_ida_api_test_script_contains_inputs_and_endpoints() -> None:
    script = build_guest_ida_api_test_script(
        ida_dir=DEFAULT_GUEST_IDA_DIR,
        dll_path=DEFAULT_GUEST_DLL_PATH,
    )

    assert "IDAPro8.3" in script
    assert "test1.dll" in script
    assert f"IDA_TIMEOUT_SECONDS = {DEFAULT_IDA_TIMEOUT_SECONDS}" in script
    assert f'IDA_API_TEST_MODE = "{DEFAULT_IDA_API_TEST_MODE}"' in script
    assert "IDA_PLUGIN_API_TEST_RESULT=" in script
    assert "IDA_API_STAGE=" in script
    assert "ida_ready.json" in script
    assert "ida_ready_wait_start" in script
    assert "_run_external_api_tests" in script
    assert "functions_offset_beyond_total_start" in script
    assert "xrefs_invalid_kind_start" in script
    assert "threading.Thread" not in script
    assert "_run_http_tests" not in script
    assert "__DLL_PATH_JSON__" not in script
    outer_script = script.split("BOOTSTRAP_TEMPLATE", maxsplit=1)[0]
    assert "DLL_PATH = __BOOTSTRAP_DLL_PATH_JSON__" not in outer_script
    assert "__IDA_DIR_JSON__" not in script
    assert "__IDA_TIMEOUT_SECONDS_JSON__" not in script
    assert "__IDA_API_TEST_MODE_JSON__" not in script
    assert '"/metadata"' in script
    assert '"/functions"' in script
    assert '"/decompile"' in script
    assert '"/xrefs"' in script
    assert '"/execute"' in script
    compile(script, "<generated_ida_api_test_payload>", "exec")


def test_build_guest_ida_api_test_script_accepts_custom_paths(tmp_path) -> None:
    ida_dir = tmp_path / "IDA Pro Custom"
    dll_path = tmp_path / "sample.dll"

    script = build_guest_ida_api_test_script(
        ida_dir=str(ida_dir),
        dll_path=str(dll_path),
        ida_timeout_seconds=123,
        test_mode="full",
    )

    assert "IDA Pro Custom" in script
    assert "sample.dll" in script
    assert "IDA_TIMEOUT_SECONDS = 123" in script
    assert 'IDA_API_TEST_MODE = "full"' in script
    compile(script, "<generated_ida_api_test_payload>", "exec")


def test_generated_ida_api_payload_file_can_be_written(tmp_path) -> None:
    output = tmp_path / "ida_api_payload.py"
    output.write_text(build_guest_ida_api_test_script(), encoding="utf-8")

    assert output.is_file()
    assert output.read_text(encoding="utf-8").startswith("from __future__ import annotations")
    assert isinstance(output, Path)


def test_generated_ida_api_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "ida_api_payload.py"
    script_path.write_text(
        build_guest_ida_api_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "IDA_PLUGIN_API_TEST_RESULT=" in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "HEARTBEAT_PATH" not in result.stdout
    assert "validate_inputs_start" in result.stdout
