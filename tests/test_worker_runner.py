from __future__ import annotations

from ida_script_mcp.isolated_protocol import IsolatedExecuteRequest
from ida_script_mcp.protocol import ExecuteRequest, ExecuteResult
from ida_script_mcp.worker_runner import run


def test_worker_runner_maps_missing_mcp_changes_module_to_recorder_error(tmp_path):
    request = IsolatedExecuteRequest(
        execute=ExecuteRequest(code="mcp_changes.rename(0x1000, 'entry')"),
        job_id="job-1",
        database_path="source.i64",
        database_copy_path="copy.i64",
        output_dir=str(tmp_path),
    )
    request_path = tmp_path / "request.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")

    exit_code = run(request_path)
    result = ExecuteResult.model_validate_json((tmp_path / "result.json").read_text())

    assert exit_code == 1
    assert result.status == "recorder_error"
    assert result.error is not None
    assert result.error.type == "RecorderError"
    assert result.changes == []
