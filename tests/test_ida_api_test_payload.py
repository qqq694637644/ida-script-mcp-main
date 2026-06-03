from __future__ import annotations

from pathlib import Path

from ida_script_mcp.payload.ida_api_test import (
    DEFAULT_GUEST_DLL_PATH,
    DEFAULT_GUEST_IDA_DIR,
    build_guest_ida_api_test_script,
)


def test_build_guest_ida_api_test_script_contains_inputs_and_endpoints() -> None:
    script = build_guest_ida_api_test_script(
        ida_dir=DEFAULT_GUEST_IDA_DIR,
        dll_path=DEFAULT_GUEST_DLL_PATH,
    )

    assert "IDAPro8.3" in script
    assert "test1.dll" in script
    assert "IDA_PLUGIN_API_TEST_RESULT=" in script
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
    )

    assert "IDA Pro Custom" in script
    assert "sample.dll" in script
    assert "IDA_TIMEOUT_SECONDS = 123" in script
    compile(script, "<generated_ida_api_test_payload>", "exec")


def test_generated_ida_api_payload_file_can_be_written(tmp_path) -> None:
    output = tmp_path / "ida_api_payload.py"
    output.write_text(build_guest_ida_api_test_script(), encoding="utf-8")

    assert output.is_file()
    assert output.read_text(encoding="utf-8").startswith("from __future__ import annotations")
    assert isinstance(output, Path)
