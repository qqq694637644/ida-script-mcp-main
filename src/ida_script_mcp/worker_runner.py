"""Headless IDA worker runner for isolated execution jobs."""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

try:
    from .change_protocol import ChangeSet, fingerprint_from_metadata
    from .change_recorder import ChangeRecorder, McpChangesApi, RecorderError
    from .execution import ScriptExecutor
    from .isolated_protocol import IsolatedExecuteRequest
    from .protocol import ExecuteResult, ExecutionError
except ImportError:  # pragma: no cover - copied runner inside IDA job dir
    current_dir = Path(__file__).parent
    package_parent = current_dir.parent
    for candidate in (str(package_parent), str(current_dir)):
        if candidate not in sys.path:
            sys.path.insert(0, candidate)
    from ida_script_mcp.change_protocol import ChangeSet, fingerprint_from_metadata  # type: ignore[no-redef]
    from ida_script_mcp.change_recorder import ChangeRecorder, McpChangesApi, RecorderError  # type: ignore[no-redef]
    from ida_script_mcp.execution import ScriptExecutor  # type: ignore[no-redef]
    from ida_script_mcp.isolated_protocol import IsolatedExecuteRequest  # type: ignore[no-redef]
    from ida_script_mcp.protocol import ExecuteResult, ExecutionError  # type: ignore[no-redef]


def _json_dump_atomic(path: Path, payload: dict[str, Any]) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp_path, path)


def _lazy_import(name: str):
    try:
        return __import__(name)
    except Exception:
        return None


def _build_worker_globals(recorder: ChangeRecorder) -> dict[str, Any]:
    modules = {
        "idaapi": _lazy_import("idaapi"),
        "idc": _lazy_import("idc"),
        "idautils": _lazy_import("idautils"),
        "ida_name": _lazy_import("ida_name"),
        "ida_bytes": _lazy_import("ida_bytes"),
        "ida_funcs": _lazy_import("ida_funcs"),
        "ida_typeinf": _lazy_import("ida_typeinf"),
    }
    recorder.install(modules, patch_explicit_api_modules=False)
    namespace = {"__builtins__": __builtins__, **modules}
    namespace["mcp_changes"] = McpChangesApi(recorder, modules)
    return namespace


def _worker_metadata(request: IsolatedExecuteRequest) -> dict[str, Any]:
    # Changes must be replayable against the GUI database that produced this
    # worker job, not against the transient copied database path. Preserve the
    # original GUI fingerprint from request.context.
    return dict(request.context)


def run(request_path: Path) -> int:
    request = IsolatedExecuteRequest.model_validate_json(request_path.read_text(encoding="utf-8"))
    output_dir = Path(request.output_dir)
    result_path = output_dir / "result.json"
    changes_path = output_dir / "changes.json"
    recorder = ChangeRecorder()

    try:
        namespace = _build_worker_globals(recorder)
    except Exception as exc:
        result = ExecuteResult(
            status="worker_start_error",
            result=None,
            error=ExecutionError(type=type(exc).__name__, message=str(exc), traceback=traceback.format_exc()),
            timeout_seconds=request.execute.timeout_seconds,
            isolated=True,
            job_id=request.job_id,
        )
        _json_dump_atomic(result_path, result.model_dump(mode="json"))
        return 2

    try:
        result = ScriptExecutor(lambda: namespace).execute(request.execute)
    except RecorderError as exc:
        result = ExecuteResult(
            status="recorder_error",
            result=None,
            error=ExecutionError(type=type(exc).__name__, message=str(exc), traceback=traceback.format_exc()),
            timeout_seconds=request.execute.timeout_seconds,
            isolated=True,
            job_id=request.job_id,
        )
    finally:
        try:
            recorder.uninstall()
        except Exception:
            pass

    try:
        change_set = ChangeSet(
            job_id=request.job_id,
            database_fingerprint=fingerprint_from_metadata(_worker_metadata(request)),
            operations=recorder.operations if request.collect_changes else [],
        )
        result = result.model_copy(update={"isolated": True, "job_id": request.job_id, "changes": change_set.operations})
        _json_dump_atomic(changes_path, change_set.model_dump(mode="json"))
        _json_dump_atomic(result_path, result.model_dump(mode="json"))
    except Exception as exc:
        error_result = ExecuteResult(
            status="recorder_error",
            result=None,
            error=ExecutionError(type=type(exc).__name__, message=str(exc), traceback=traceback.format_exc()),
            timeout_seconds=request.execute.timeout_seconds,
            isolated=True,
            job_id=request.job_id,
        )
        _json_dump_atomic(result_path, error_result.model_dump(mode="json"))
        return 3

    return 0 if result.status in {"ok", "script_error", "source_error", "timeout"} else 1


def main() -> None:
    request_json = os.environ.get("IDA_SCRIPT_MCP_REQUEST_JSON")
    if not request_json:
        raise SystemExit("IDA_SCRIPT_MCP_REQUEST_JSON is required")
    raise SystemExit(run(Path(request_json)))


if __name__ == "__main__":
    main()
