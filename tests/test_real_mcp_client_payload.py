"""Tests for the strict real MCP client disposable-VM payload builder."""

from __future__ import annotations

import os
import py_compile
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_script_mcp.payload.ida_u004_real_mcp_client_test import (  # noqa: E402
    build_guest_u004_real_mcp_client_test_script,
)


def test_real_mcp_payload_generation_uses_current_strict_tool_surface(tmp_path):
    script = build_guest_u004_real_mcp_client_test_script(
        ida_dir=r"C:\IDA",
        dll_path=r"C:\sample\test1.dll",
        ida_timeout_seconds=30,
    )
    output = tmp_path / "real_mcp_client_payload.py"
    output.write_text(script, encoding="utf-8")

    py_compile.compile(str(output), doraise=True)

    assert "list_ida_instances" in script
    assert "get_ida_database_info" in script
    assert "list_functions" in script
    assert "decompile_function" in script
    assert "get_xrefs" in script
    assert "execute_idapython" in script
    assert 'call_tool("apply_worker_changes"' not in script
    assert "collect_changes" not in script
    assert "mcp_changes" not in script
    assert "isolated" not in script
    assert "execute_idapython_script_path" in script
    assert "ScriptExecutionTimeout" in script
