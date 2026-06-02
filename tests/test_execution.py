"""Tests for the strict script execution subsystem."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_script_mcp.execution import ScriptExecutor
from ida_script_mcp.protocol import ExecuteRequest


def _namespace() -> dict[str, object]:
    return {"__builtins__": __builtins__}


def _execute(code: str, *, timeout_seconds: int = 30):
    executor = ScriptExecutor(_namespace)
    return executor.execute(ExecuteRequest(code=code, timeout_seconds=timeout_seconds))


class TestScriptExecutor:
    """Validate status-machine behavior for pure Python execution."""

    def test_single_expression_returns_value(self):
        result = _execute("1 + 2")
        assert result.status == "ok"
        assert result.result == 3
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.error is None

    def test_multi_statement_returns_result_variable(self):
        result = _execute("x = 1\ny = 2\nresult = x + y")
        assert result.status == "ok"
        assert result.result == 3

    def test_multi_statement_does_not_auto_return_last_expression(self):
        result = _execute("x = 1\nx + 2")
        assert result.status == "ok"
        assert result.result is None

    def test_stdout_and_stderr_are_user_output_only(self):
        result = _execute("import sys\nprint('out')\nprint('err', file=sys.stderr)\nresult = 7")
        assert result.status == "ok"
        assert result.result == 7
        assert result.stdout == "out\n"
        assert result.stderr == "err\n"
        assert result.error is None

    def test_runtime_exception_is_script_error(self):
        result = _execute("print('before')\nraise ValueError('boom')")
        assert result.status == "script_error"
        assert result.result is None
        assert result.stdout == "before\n"
        assert result.stderr == ""
        assert result.error is not None
        assert result.error.type == "ValueError"
        assert result.error.message == "boom"
        assert result.error.traceback is not None

    def test_syntax_error_is_source_error(self):
        result = _execute("def broken(:\n    pass")
        assert result.status == "source_error"
        assert result.result is None
        assert result.error is not None
        assert result.error.type == "SyntaxError"

    def test_script_path_source(self, tmp_path):
        script = tmp_path / "script.py"
        script.write_text("result = 'from file'\n", encoding="utf-8")

        executor = ScriptExecutor(_namespace)
        result = executor.execute(ExecuteRequest(script_path=str(script)))

        assert result.status == "ok"
        assert result.result == "from file"

    def test_missing_script_path_is_source_error(self, tmp_path):
        executor = ScriptExecutor(_namespace)
        result = executor.execute(ExecuteRequest(script_path=str(tmp_path / "missing.py")))

        assert result.status == "source_error"
        assert result.error is not None
        assert result.error.type == "FileNotFoundError"

    def test_python_bytecode_timeout(self):
        result = _execute("while True:\n    pass", timeout_seconds=1)
        assert result.status == "timeout"
        assert result.error is not None
        assert result.error.type == "ScriptExecutionTimeout"
        assert result.timeout_seconds == 1
