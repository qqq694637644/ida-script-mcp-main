from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path


def test_ida_plugin_protocols_import_without_pydantic():
    repo_root = Path(__file__).resolve().parents[1]
    src_path = repo_root / "src"
    script = textwrap.dedent(
        f"""
        from __future__ import annotations

        import importlib.abc
        import sys

        class BlockPydantic(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "pydantic" or fullname.startswith("pydantic."):
                    raise ImportError("blocked pydantic for IDA fallback test")
                return None

        sys.meta_path.insert(0, BlockPydantic())
        sys.modules.pop("pydantic", None)
        sys.path.insert(0, {str(src_path)!r})

        from ida_script_mcp.protocol import ExecuteRequest, ExecuteResult
        from ida_script_mcp.change_protocol import (
            ApplyChangesRequest,
            DatabaseFingerprint,
            RenameChange,
        )
        from ida_script_mcp.isolated_protocol import IsolatedExecuteRequest
        from ida_script_mcp import ida_plugin

        execute_request = ExecuteRequest(code="result = 1")
        assert execute_request.model_dump(mode="json")["timeout_seconds"] == 30

        result = ExecuteResult(status="ok", result=1)
        assert result.model_validate_json(result.model_dump_json()).status == "ok"

        change_request = ApplyChangesRequest(
            job_id="job-1",
            database_fingerprint=DatabaseFingerprint(database_sha256="abc"),
            operations=[
                RenameChange(op_id="op-1", ea=0x1000, new_name="main", source="explicit_api")
            ],
        )
        assert change_request.model_dump(mode="json")["operations"][0]["op"] == "rename"

        isolated = IsolatedExecuteRequest(
            execute=execute_request,
            job_id="job-1",
            database_path="source.i64",
            database_copy_path="copy.i64",
            output_dir="out",
        )
        assert isolated.execute.code == "result = 1"
        assert ida_plugin.PLUGIN_NAME == "IDA-Script-MCP"
        print("ok")
        """
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
