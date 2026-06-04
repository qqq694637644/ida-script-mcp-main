"""Server-side isolated IDA worker process manager."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

from .change_protocol import ChangeSet
from .isolated_protocol import IsolatedExecuteRequest
from .process_utils import kill_process_tree
from .protocol import ExecuteRequest, ExecuteResult, ExecutionError

HARD_TIMEOUT_MARGIN_SECONDS = 5


def _sha256_file(path: Path) -> str | None:
    try:
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception:
        return None


def _json_dump_atomic(path: Path, payload: dict[str, Any]) -> None:
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp_path, path)


def _default_work_dir() -> Path:
    configured = os.environ.get("IDA_SCRIPT_MCP_WORK_DIR")
    return Path(configured) if configured else Path(tempfile.gettempdir()) / "ida-script-mcp-jobs"


def _keep_jobs_enabled() -> bool:
    raw = os.environ.get("IDA_SCRIPT_MCP_KEEP_JOBS", "0").strip()
    if raw in {"", "0"}:
        return False
    if raw == "1":
        return True
    raise ValueError("IDA_SCRIPT_MCP_KEEP_JOBS must be exactly 0 or 1")


def _discover_ida_path() -> Path | None:
    explicit = os.environ.get("IDA_SCRIPT_MCP_IDA_PATH")
    if explicit:
        path = Path(explicit)
        return path if path.exists() else None
    mode = os.environ.get("IDA_SCRIPT_MCP_WORKER_MODE", "auto").lower()
    if mode not in {"auto", "ida", "idat"}:
        return None
    names = (
        ["idat64", "idat", "ida64", "ida"]
        if mode == "auto"
        else (["ida64", "ida"] if mode == "ida" else ["idat64", "idat"])
    )
    if sys.platform == "win32":
        names = [f"{name}.exe" for name in names]
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


class IsolatedExecutionManager:
    """Create isolated worker jobs and classify worker process outcomes."""

    def __init__(
        self,
        *,
        work_dir: Path | None = None,
        ida_path: Path | None = None,
        hard_timeout_margin_seconds: int = HARD_TIMEOUT_MARGIN_SECONDS,
        popen=subprocess.Popen,
        kill_tree=kill_process_tree,
    ):
        self.work_dir = work_dir or _default_work_dir()
        self.ida_path = ida_path
        self.hard_timeout_margin_seconds = hard_timeout_margin_seconds
        self._popen = popen
        self._kill_tree = kill_tree

    def execute(
        self,
        request: ExecuteRequest,
        *,
        gui_context: dict[str, Any],
        instance_id: str | None,
        port: int | None,
        collect_changes: bool = True,
    ) -> ExecuteResult:
        started = time.monotonic()
        job_id = f"job-{uuid.uuid4().hex}"
        try:
            keep_jobs = _keep_jobs_enabled()
        except ValueError as exc:
            return self._failure(
                "worker_start_error",
                request,
                started,
                type(exc).__name__,
                str(exc),
                instance_id=instance_id,
                port=port,
                job_id=job_id,
            )
        if gui_context.get("dirty_state_known") is False or gui_context.get("dirty") is None:
            return self._failure(
                "rejected",
                request,
                started,
                "GuiDatabaseDirtyStateUnknown",
                "GUI database dirty state is unknown; refusing isolated execution.",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
            )
        dirty = bool(gui_context.get("dirty") or gui_context.get("unsaved"))
        if dirty:
            return self._failure(
                "rejected",
                request,
                started,
                "GuiDatabaseDirty",
                "GUI database has unsaved changes; save the database before isolated execution.",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
            )

        database_path_value = gui_context.get("database_path")
        if not database_path_value:
            return self._failure(
                "source_error",
                request,
                started,
                "MissingDatabasePath",
                "GUI plugin did not report a saved database_path.",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
            )
        database_path = Path(str(database_path_value))
        if not database_path.exists() or not database_path.is_file():
            return self._failure(
                "source_error",
                request,
                started,
                "DatabaseSourceUnavailable",
                f"Saved database path is not readable: {database_path}",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
            )
        if gui_context.get("database_identity_known") is False:
            return self._failure(
                "source_error",
                request,
                started,
                "DatabaseIdentityUnavailable",
                "Saved database SHA-256 is unavailable; refusing isolated execution.",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
            )
        if not gui_context.get("database_sha256"):
            gui_context = dict(gui_context)
            gui_context["database_sha256"] = _sha256_file(database_path)
            gui_context["database_size"] = database_path.stat().st_size
        if not gui_context.get("database_sha256"):
            return self._failure(
                "source_error",
                request,
                started,
                "DatabaseIdentityUnavailable",
                "Failed to compute saved database SHA-256; refusing isolated execution.",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
            )

        ida_path = self.ida_path or _discover_ida_path()
        if ida_path is None or not ida_path.exists():
            return self._failure(
                "worker_start_error",
                request,
                started,
                "IdaExecutableNotConfigured",
                (
                    "Set IDA_SCRIPT_MCP_IDA_PATH to idat/idat64/ida64; "
                    "no GUI /execute fallback is allowed."
                ),
                instance_id=instance_id,
                port=port,
                job_id=job_id,
            )

        job_dir = self.work_dir / job_id
        artifacts = {
            "job_dir": str(job_dir),
            "request": str(job_dir / "request.json"),
            "runner": str(job_dir / "runner.py"),
            "stdout": str(job_dir / "stdout.txt"),
            "stderr": str(job_dir / "stderr.txt"),
            "result": str(job_dir / "result.json"),
            "changes": str(job_dir / "changes.json"),
            "metadata": str(job_dir / "metadata.json"),
            "worker_runtime": str(job_dir / "worker_runtime.json"),
        }
        try:
            job_dir.mkdir(parents=True, exist_ok=False)
            database_copy_path = job_dir / f"database{database_path.suffix or '.i64'}"
            shutil.copy2(database_path, database_copy_path)
        except FileNotFoundError as exc:
            result = self._failure(
                "source_error",
                request,
                started,
                type(exc).__name__,
                str(exc),
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )
            return self._finalize_job_result(
                result,
                request,
                started,
                job_dir=job_dir,
                keep_jobs=keep_jobs,
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )
        except Exception as exc:
            result = self._failure(
                "worker_start_error",
                request,
                started,
                type(exc).__name__,
                str(exc),
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )
            return self._finalize_job_result(
                result,
                request,
                started,
                job_dir=job_dir,
                keep_jobs=keep_jobs,
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )

        try:
            execute_request = self._materialize_source(request, job_dir)
            isolated_request = IsolatedExecuteRequest(
                execute=execute_request,
                job_id=job_id,
                database_path=str(database_path),
                database_copy_path=str(database_copy_path),
                input_file_path=gui_context.get("input_file_path"),
                context=gui_context,
                collect_changes=collect_changes,
                output_dir=str(job_dir),
            )
            _json_dump_atomic(job_dir / "request.json", isolated_request.model_dump(mode="json"))
            self._write_runner(job_dir / "runner.py")
            _json_dump_atomic(
                job_dir / "metadata.json", {"job_id": job_id, "gui_context": gui_context}
            )
        except Exception as exc:
            result = self._failure(
                "worker_start_error",
                request,
                started,
                type(exc).__name__,
                str(exc),
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )
            return self._finalize_job_result(
                result,
                request,
                started,
                job_dir=job_dir,
                keep_jobs=keep_jobs,
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )

        stdout_path = job_dir / "stdout.txt"
        stderr_path = job_dir / "stderr.txt"
        args = [str(ida_path), "-A", f"-S{job_dir / 'runner.py'}", str(database_copy_path)]
        env = os.environ.copy()
        env["IDA_SCRIPT_MCP_REQUEST_JSON"] = str(job_dir / "request.json")
        env.setdefault("PYTHONIOENCODING", "utf-8")
        try:
            with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
                popen_kwargs: dict[str, Any] = {
                    "stdout": stdout_handle,
                    "stderr": stderr_handle,
                    "env": env,
                    "cwd": str(job_dir),
                }
                if sys.platform != "win32":
                    popen_kwargs["start_new_session"] = True
                process = self._popen(args, **popen_kwargs)
        except Exception as exc:
            result = self._failure(
                "worker_start_error",
                request,
                started,
                type(exc).__name__,
                str(exc),
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )
            return self._finalize_job_result(
                result,
                request,
                started,
                job_dir=job_dir,
                keep_jobs=keep_jobs,
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )

        wait_seconds = request.timeout_seconds + self.hard_timeout_margin_seconds
        try:
            exit_code = process.wait(timeout=wait_seconds)
        except subprocess.TimeoutExpired:
            killed = self._kill_tree(process)
            result = ExecuteResult(
                status="timeout",
                result=None,
                stdout=self._safe_read(stdout_path),
                stderr=self._safe_read(stderr_path),
                error=ExecutionError(
                    type="WorkerHardTimeout",
                    message=f"Worker exceeded hard timeout of {wait_seconds} seconds",
                    traceback=None,
                ),
                duration_seconds=max(0.0, time.monotonic() - started),
                timeout_seconds=request.timeout_seconds,
                instance_id=instance_id,
                port=port,
                isolated=True,
                job_id=job_id,
                worker_pid=getattr(process, "pid", None),
                worker_exit_code=process.poll(),
                killed=killed,
                hard_timeout=True,
                artifacts=artifacts,
            )
            return self._finalize_job_result(
                result,
                request,
                started,
                job_dir=job_dir,
                keep_jobs=keep_jobs,
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=artifacts,
            )

        result = self._read_worker_result(
            request,
            started,
            job_id=job_id,
            exit_code=exit_code,
            worker_pid=getattr(process, "pid", None),
            instance_id=instance_id,
            port=port,
            job_dir=job_dir,
            artifacts=artifacts,
        )
        return self._finalize_job_result(
            result,
            request,
            started,
            job_dir=job_dir,
            keep_jobs=keep_jobs,
            instance_id=instance_id,
            port=port,
            job_id=job_id,
            artifacts=artifacts,
        )

    def _materialize_source(self, request: ExecuteRequest, job_dir: Path) -> ExecuteRequest:
        if request.code is not None:
            user_code = job_dir / "user_code.py"
            user_code.write_text(request.code, encoding="utf-8")
            return request.model_copy(update={"script_path": str(user_code), "code": None})
        return request

    def _write_runner(self, path: Path) -> None:
        source_dir = Path(__file__).parent
        source = source_dir.joinpath("worker_runner.py").read_text(encoding="utf-8")
        path.write_text(source, encoding="utf-8")

        package_dir = path.parent / "ida_script_mcp"
        package_dir.mkdir(exist_ok=True)
        package_dir.joinpath("__init__.py").write_text("", encoding="utf-8")
        for module_name in (
            "change_protocol.py",
            "change_recorder.py",
            "execution.py",
            "isolated_protocol.py",
            "protocol.py",
        ):
            shutil.copy2(source_dir / module_name, package_dir / module_name)

    def _read_worker_result(
        self,
        request: ExecuteRequest,
        started: float,
        *,
        job_id: str,
        exit_code: int,
        worker_pid: int | None,
        instance_id: str | None,
        port: int | None,
        job_dir: Path,
        artifacts: dict[str, str],
    ) -> ExecuteResult:
        result_path = job_dir / "result.json"
        changes_path = job_dir / "changes.json"
        stdout_path = job_dir / "stdout.txt"
        stderr_path = job_dir / "stderr.txt"
        if not result_path.exists():
            status = "worker_crashed" if exit_code != 0 else "worker_result_missing"
            return self._failure(
                status,
                request,
                started,
                "WorkerResultMissing",
                "Worker exited without result.json",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                worker_pid=worker_pid,
                worker_exit_code=exit_code,
                stdout=self._safe_read(stdout_path),
                stderr=self._safe_read(stderr_path),
                artifacts=artifacts,
            )
        try:
            result = ExecuteResult.model_validate_json(result_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return self._failure(
                "worker_result_missing",
                request,
                started,
                type(exc).__name__,
                str(exc),
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                worker_pid=worker_pid,
                worker_exit_code=exit_code,
                artifacts=artifacts,
            )
        changes = result.changes
        if changes_path.exists():
            try:
                changes = ChangeSet.model_validate_json(
                    changes_path.read_text(encoding="utf-8")
                ).operations
            except Exception as exc:
                return self._failure(
                    "recorder_error",
                    request,
                    started,
                    type(exc).__name__,
                    str(exc),
                    instance_id=instance_id,
                    port=port,
                    job_id=job_id,
                    worker_pid=worker_pid,
                    worker_exit_code=exit_code,
                    artifacts=artifacts,
                )
        if exit_code != 0 and result.status == "ok":
            return self._failure(
                "worker_crashed",
                request,
                started,
                "WorkerCrashed",
                f"Worker exited with code {exit_code}",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                worker_pid=worker_pid,
                worker_exit_code=exit_code,
                artifacts=artifacts,
            )
        return result.model_copy(
            update={
                "instance_id": instance_id,
                "port": port,
                "isolated": True,
                "job_id": job_id,
                "worker_pid": worker_pid,
                "worker_exit_code": exit_code,
                "changes": changes,
                "artifacts": artifacts,
            }
        )

    @staticmethod
    def _safe_read(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""

    def _finalize_job_result(
        self,
        result: ExecuteResult,
        request: ExecuteRequest,
        started: float,
        *,
        job_dir: Path,
        keep_jobs: bool,
        instance_id: str | None,
        port: int | None,
        job_id: str,
        artifacts: dict[str, str],
    ) -> ExecuteResult:
        if keep_jobs:
            return result.model_copy(update={"artifacts_retained": True})
        try:
            shutil.rmtree(job_dir)
        except FileNotFoundError:
            return result.model_copy(update={"artifacts": {}, "artifacts_retained": False})
        except Exception as exc:
            cleanup_artifacts = dict(artifacts)
            cleanup_artifacts["cleanup_error"] = str(exc)
            return self._failure(
                "worker_start_error",
                request,
                started,
                "JobCleanupFailed",
                f"Failed to clean isolated job directory {job_dir}: {exc}",
                instance_id=instance_id,
                port=port,
                job_id=job_id,
                artifacts=cleanup_artifacts,
            )
        return result.model_copy(update={"artifacts": {}, "artifacts_retained": False})

    def _failure(
        self,
        status: str,
        request: ExecuteRequest,
        started: float,
        error_type: str,
        message: str,
        *,
        instance_id: str | None = None,
        port: int | None = None,
        job_id: str | None = None,
        worker_pid: int | None = None,
        worker_exit_code: int | None = None,
        stdout: str = "",
        stderr: str = "",
        artifacts: dict[str, str] | None = None,
    ) -> ExecuteResult:
        return ExecuteResult(
            status=status,
            result=None,
            stdout=stdout,
            stderr=stderr,
            error=ExecutionError(type=error_type, message=message, traceback=None),
            duration_seconds=max(0.0, time.monotonic() - started),
            timeout_seconds=request.timeout_seconds,
            instance_id=instance_id,
            port=port,
            isolated=True,
            job_id=job_id,
            worker_pid=worker_pid,
            worker_exit_code=worker_exit_code,
            artifacts=artifacts or {},
        )
