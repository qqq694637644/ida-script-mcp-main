"""Strict Python execution subsystem for the IDA plugin."""

from __future__ import annotations

import ast
import io
import sys
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import Any

try:  # Package import used by the MCP server and normal test runs.
    from .protocol import EXECUTE_FILENAME, ExecuteRequest, ExecuteResult, ExecutionError
except ImportError:  # pragma: no cover - IDA plugin support-file import fallback.
    try:
        from ida_script_mcp_protocol import (  # type: ignore[no-redef]
            EXECUTE_FILENAME,
            ExecuteRequest,
            ExecuteResult,
            ExecutionError,
        )
    except ImportError:
        from protocol import (  # type: ignore[no-redef]
            EXECUTE_FILENAME,
            ExecuteRequest,
            ExecuteResult,
            ExecutionError,
        )


class ScriptExecutionTimeout(TimeoutError):  # noqa: N818
    """Raised when Python bytecode execution exceeds its deadline."""

    def __init__(self, timeout_seconds: int):
        self.timeout_seconds = timeout_seconds
        super().__init__(f"Execution timed out after {timeout_seconds} seconds")


class DeadlineTracer:
    """A line-level trace hook that softly interrupts Python bytecode execution."""

    def __init__(
        self,
        timeout_seconds: int,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.timeout_seconds = timeout_seconds
        self.deadline = clock() + timeout_seconds
        self._clock = clock
        self.previous_trace: Callable[..., Any] | None = None

    def __enter__(self) -> DeadlineTracer:
        self.previous_trace = sys.gettrace()
        sys.settrace(self._trace)
        return self

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        sys.settrace(self.previous_trace)

    def _trace(self, frame: FrameType, _event: str, _arg: Any):
        frame.f_trace_lines = True
        if self._clock() >= self.deadline:
            raise ScriptExecutionTimeout(self.timeout_seconds)
        return self._trace


def _make_jsonable(value: Any, depth: int = 0) -> Any:
    """Convert arbitrary Python values into JSON-serializable structures."""
    if depth > 6:
        return str(value)

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): _make_jsonable(inner_value, depth + 1) for key, inner_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_make_jsonable(item, depth + 1) for item in value]

    try:
        return _make_jsonable(vars(value), depth + 1)
    except Exception:
        return str(value)


class ScriptExecutor:
    """Compile and execute one strict ``/execute`` request."""

    def __init__(
        self,
        namespace_factory: Callable[[], dict[str, Any]],
        *,
        filename: str = EXECUTE_FILENAME,
    ):
        self.namespace_factory = namespace_factory
        self.filename = filename

    def execute(self, request: ExecuteRequest) -> ExecuteResult:
        """Execute ``request`` and return a structured result."""
        start_time = time.monotonic()

        try:
            source, filename = self._load_source(request)
            tree = ast.parse(source, filename=filename, mode="exec")
        except Exception as exc:
            return self._error_result(
                "source_error",
                request,
                start_time,
                exc,
                traceback.format_exc(),
            )

        stdout_capture = io.StringIO() if request.capture_output else None
        stderr_capture = io.StringIO() if request.capture_output else None
        old_stdout = sys.stdout if request.capture_output else None
        old_stderr = sys.stderr if request.capture_output else None

        try:
            if request.capture_output:
                sys.stdout = stdout_capture
                sys.stderr = stderr_capture

            namespace = self.namespace_factory()
            namespace.setdefault("__builtins__", __builtins__)
            result_value = self._execute_tree(source, tree, namespace, request, filename)

            return ExecuteResult(
                status="ok",
                result=_make_jsonable(result_value),
                stdout=stdout_capture.getvalue() if stdout_capture else "",
                stderr=stderr_capture.getvalue() if stderr_capture else "",
                error=None,
                duration_seconds=self._duration_since(start_time),
                timeout_seconds=request.timeout_seconds,
            )
        except ScriptExecutionTimeout as exc:
            return self._error_result(
                "timeout",
                request,
                start_time,
                exc,
                traceback.format_exc(),
                stdout_capture=stdout_capture,
                stderr_capture=stderr_capture,
            )
        except Exception as exc:
            return self._error_result(
                "script_error",
                request,
                start_time,
                exc,
                traceback.format_exc(),
                stdout_capture=stdout_capture,
                stderr_capture=stderr_capture,
            )
        finally:
            if request.capture_output:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

    def _load_source(self, request: ExecuteRequest) -> tuple[str, str]:
        if request.script_path is None:
            return request.code or "", self.filename

        script_path = Path(request.script_path)
        return script_path.read_text(encoding="utf-8"), str(script_path)

    def _execute_tree(
        self,
        source: str,
        tree: ast.Module,
        namespace: dict[str, Any],
        request: ExecuteRequest,
        filename: str,
    ) -> Any:
        if len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
            expression = ast.Expression(body=tree.body[0].value)
            ast.fix_missing_locations(expression)
            compiled = compile(expression, filename, "eval")
            with DeadlineTracer(request.timeout_seconds):
                return eval(compiled, namespace, namespace)

        compiled = compile(source, filename, "exec")
        with DeadlineTracer(request.timeout_seconds):
            exec(compiled, namespace, namespace)
        return namespace["result"] if "result" in namespace else None

    @staticmethod
    def _duration_since(start_time: float) -> float:
        return max(0.0, time.monotonic() - start_time)

    def _error_result(
        self,
        status: str,
        request: ExecuteRequest,
        start_time: float,
        exc: BaseException,
        traceback_text: str | None,
        *,
        stdout_capture: io.StringIO | None = None,
        stderr_capture: io.StringIO | None = None,
    ) -> ExecuteResult:
        return ExecuteResult(
            status=status,  # type: ignore[arg-type]
            result=None,
            stdout=stdout_capture.getvalue() if stdout_capture else "",
            stderr=stderr_capture.getvalue() if stderr_capture else "",
            error=ExecutionError(
                type=type(exc).__name__,
                message=str(exc),
                traceback=traceback_text,
            ),
            duration_seconds=self._duration_since(start_time),
            timeout_seconds=request.timeout_seconds,
        )
