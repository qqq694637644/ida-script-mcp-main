"""Headless IDA worker runner for isolated execution jobs."""

from __future__ import annotations

import json
import os
import sys
import traceback
from collections.abc import Callable
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
    from ida_script_mcp.change_protocol import (  # type: ignore[no-redef]
        ChangeSet,
        fingerprint_from_metadata,
    )
    from ida_script_mcp.change_recorder import (  # type: ignore[no-redef]
        ChangeRecorder,
        McpChangesApi,
        RecorderError,
    )
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


def _required_import(name: str):
    module = _lazy_import(name)
    if module is None:
        raise RuntimeError(f"Required IDAPython module is unavailable: {name}")
    return module


def _required_callable(module: Any, module_name: str, function_name: str) -> Callable[..., Any]:
    function = getattr(module, function_name, None)
    if not callable(function):
        raise RuntimeError(f"Required IDAPython API is unavailable: {module_name}.{function_name}")
    return function


def _is_ida_runtime() -> bool:
    return _lazy_import("idaapi") is not None or _lazy_import("idc") is not None


def _same_path(left: str, right: str) -> bool:
    left_path = Path(left).expanduser().resolve(strict=False)
    right_path = Path(right).expanduser().resolve(strict=False)
    return os.path.normcase(str(left_path)) == os.path.normcase(str(right_path))


def _current_database_path() -> str:
    ida_loader = _required_import("ida_loader")
    get_path = _required_callable(ida_loader, "ida_loader", "get_path")
    path_type = getattr(ida_loader, "PATH_TYPE_IDB", None)
    if path_type is None:
        raise RuntimeError("Required IDAPython constant is unavailable: ida_loader.PATH_TYPE_IDB")
    value = get_path(path_type)
    if not value:
        raise RuntimeError("IDA did not report the currently opened IDB/I64 path")
    return str(value)


def _prepare_worker_runtime(request: IsolatedExecuteRequest) -> dict[str, Any]:
    """Force deterministic IDA worker lifecycle before user code runs."""
    if not _is_ida_runtime():
        return {"ida_runtime": False}

    idc = _required_import("idc")
    batch = _required_callable(idc, "idc", "batch")
    batch(1)

    ida_auto = _required_import("ida_auto")
    auto_wait = _required_callable(ida_auto, "ida_auto", "auto_wait")
    auto_wait_result = auto_wait()
    if auto_wait_result is False:
        raise RuntimeError("ida_auto.auto_wait returned False")

    opened_database_path = _current_database_path()
    if not _same_path(opened_database_path, request.database_copy_path):
        raise RuntimeError(
            "Worker opened database path mismatch: "
            f"expected copied database {request.database_copy_path!r}, "
            f"got {opened_database_path!r}"
        )

    qexit = getattr(idc, "qexit", None)
    if not callable(qexit):
        raise RuntimeError("Required IDAPython API is unavailable: idc.qexit")

    return {
        "ida_runtime": True,
        "batch_enabled": True,
        "auto_wait_result": auto_wait_result,
        "opened_database_path": opened_database_path,
    }


def _request_ida_exit(exit_code: int) -> None:
    if not _is_ida_runtime():
        return
    idc = _required_import("idc")
    qexit = _required_callable(idc, "idc", "qexit")
    qexit(int(exit_code))


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
    recorder.install(modules)
    namespace = {"__builtins__": __builtins__, **modules}
    namespace["mcp_changes"] = McpChangesApi(recorder, modules)
    return namespace


def _worker_metadata(request: IsolatedExecuteRequest) -> dict[str, Any]:
    # Changes must be replayable against the GUI database that produced this
    # worker job, not against the transient copied database path. Preserve the
    # original GUI fingerprint from request.context.
    return dict(request.context)


def _worker_start_error_result(
    request: IsolatedExecuteRequest,
    exc: BaseException,
) -> ExecuteResult:
    return ExecuteResult(
        status="worker_start_error",
        result=None,
        error=ExecutionError(
            type=type(exc).__name__, message=str(exc), traceback=traceback.format_exc()
        ),
        timeout_seconds=request.execute.timeout_seconds,
        isolated=True,
        job_id=request.job_id,
    )


def run(request_path: Path) -> int:
    request = IsolatedExecuteRequest.model_validate_json(request_path.read_text(encoding="utf-8"))
    output_dir = Path(request.output_dir)
    result_path = output_dir / "result.json"
    changes_path = output_dir / "changes.json"
    worker_runtime_path = output_dir / "worker_runtime.json"
    recorder = ChangeRecorder()

    try:
        worker_runtime = _prepare_worker_runtime(request)
        _json_dump_atomic(worker_runtime_path, worker_runtime)
        namespace = _build_worker_globals(recorder)
    except Exception as exc:
        result = _worker_start_error_result(request, exc)
        _json_dump_atomic(result_path, result.model_dump(mode="json"))
        return 2

    try:
        result = ScriptExecutor(lambda: namespace).execute(request.execute)
        if (
            result.status == "script_error"
            and result.error
            and result.error.type == "RecorderError"
        ):
            result = result.model_copy(update={"status": "recorder_error"})
    except RecorderError as exc:
        result = ExecuteResult(
            status="recorder_error",
            result=None,
            error=ExecutionError(
                type=type(exc).__name__, message=str(exc), traceback=traceback.format_exc()
            ),
            timeout_seconds=request.execute.timeout_seconds,
            isolated=True,
            job_id=request.job_id,
        )
    finally:
        try:
            recorder.uninstall()
        except Exception as exc:
            result = ExecuteResult(
                status="recorder_error",
                result=None,
                error=ExecutionError(
                    type=type(exc).__name__,
                    message=str(exc),
                    traceback=traceback.format_exc(),
                ),
                timeout_seconds=request.execute.timeout_seconds,
                isolated=True,
                job_id=request.job_id,
            )

    try:
        change_set = ChangeSet(
            job_id=request.job_id,
            database_fingerprint=fingerprint_from_metadata(_worker_metadata(request)),
            operations=recorder.operations if request.collect_changes else [],
        )
        result = result.model_copy(
            update={"isolated": True, "job_id": request.job_id, "changes": change_set.operations}
        )
        _json_dump_atomic(changes_path, change_set.model_dump(mode="json"))
        _json_dump_atomic(result_path, result.model_dump(mode="json"))
    except Exception as exc:
        error_result = ExecuteResult(
            status="recorder_error",
            result=None,
            error=ExecutionError(
                type=type(exc).__name__, message=str(exc), traceback=traceback.format_exc()
            ),
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
    exit_code = 2
    try:
        exit_code = run(Path(request_json))
    finally:
        _request_ida_exit(exit_code)
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
