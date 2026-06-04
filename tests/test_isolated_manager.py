from __future__ import annotations

import json
import subprocess
from pathlib import Path

from ida_script_mcp.isolated_manager import IsolatedExecutionManager
from ida_script_mcp.protocol import ExecuteRequest, ExecuteResult


class FakeProcess:
    pid = 1234

    def __init__(self, exit_code: int = 0, timeout: bool = False):
        self.exit_code = exit_code
        self.timeout = timeout
        self.wait_calls = []
        self.killed = False

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        if self.timeout:
            raise subprocess.TimeoutExpired(cmd="ida", timeout=timeout)
        return self.exit_code

    def poll(self):
        return None if self.timeout and not self.killed else self.exit_code

    def kill(self):
        self.killed = True


def _gui_context(db_path: Path, **extra):
    return {
        "database_path": str(db_path),
        "dirty": False,
        "unsaved": False,
        "dirty_state_known": True,
        **extra,
    }


def test_dirty_gui_database_is_rejected_without_launch(tmp_path):
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    launched = False

    def popen(*_args, **_kwargs):
        nonlocal launched
        launched = True
        return FakeProcess()

    manager = IsolatedExecutionManager(
        work_dir=tmp_path / "jobs", ida_path=tmp_path / "missing", popen=popen
    )
    result = manager.execute(
        ExecuteRequest(code="1"),
        gui_context=_gui_context(db, dirty=True),
        instance_id="sample",
        port=1,
    )

    assert result.status == "rejected"
    assert launched is False


def test_unknown_dirty_state_is_rejected_without_launch(tmp_path):
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    launched = False

    def popen(*_args, **_kwargs):
        nonlocal launched
        launched = True
        return FakeProcess()

    manager = IsolatedExecutionManager(
        work_dir=tmp_path / "jobs", ida_path=tmp_path / "missing", popen=popen
    )
    result = manager.execute(
        ExecuteRequest(code="1"),
        gui_context=_gui_context(db, dirty=None, unsaved=None, dirty_state_known=False),
        instance_id="sample",
        port=1,
    )

    assert result.status == "rejected"
    assert result.error.type == "GuiDatabaseDirtyStateUnknown"
    assert launched is False


def test_missing_database_identity_is_source_error_without_launch(tmp_path):
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    launched = False

    def popen(*_args, **_kwargs):
        nonlocal launched
        launched = True
        return FakeProcess()

    manager = IsolatedExecutionManager(
        work_dir=tmp_path / "jobs", ida_path=tmp_path / "missing", popen=popen
    )
    result = manager.execute(
        ExecuteRequest(code="1"),
        gui_context=_gui_context(db, database_identity_known=False),
        instance_id="sample",
        port=1,
    )

    assert result.status == "source_error"
    assert result.error.type == "DatabaseIdentityUnavailable"
    assert launched is False


def test_missing_ida_path_returns_worker_start_error(tmp_path):
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", ida_path=tmp_path / "missing")

    result = manager.execute(
        ExecuteRequest(code="1"),
        gui_context=_gui_context(db),
        instance_id="sample",
        port=1,
    )

    assert result.status == "worker_start_error"
    assert "IDA_SCRIPT_MCP_IDA_PATH" in result.error.message


def test_successful_worker_result_uses_arg_list_and_reads_changes(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_SCRIPT_MCP_KEEP_JOBS", "1")
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    ida = tmp_path / "idat64"
    ida.write_text("fake", encoding="utf-8")
    captured = {}

    def popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        job_dir = Path(kwargs["cwd"])
        (job_dir / "result.json").write_text(
            ExecuteResult(status="ok", result=7).model_dump_json(), encoding="utf-8"
        )
        request_payload = json.loads((job_dir / "request.json").read_text(encoding="utf-8"))
        assert request_payload["context"]["database_sha256"]
        (job_dir / "changes.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "job_id": job_dir.name,
                    "database_fingerprint": {
                        "database_sha256": request_payload["context"]["database_sha256"]
                    },
                    "operations": [
                        {
                            "op_id": "op-1",
                            "op": "rename",
                            "ea": 4096,
                            "source": "explicit_api",
                            "new_name": "main",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return FakeProcess(exit_code=0)

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", ida_path=ida, popen=popen)
    result = manager.execute(
        ExecuteRequest(code="result = 7"),
        gui_context=_gui_context(db),
        instance_id="sample",
        port=13338,
    )

    assert isinstance(captured["args"], list)
    assert captured["args"][0] == str(ida)
    assert captured["args"][1] == "-A"
    assert result.status == "ok"
    assert result.result == 7
    assert result.worker_exit_code == 0
    assert result.changes[0].op == "rename"
    assert result.artifacts["request"].endswith("request.json")
    assert result.artifacts_retained is True


def test_worker_discovery_prefers_gui_executable_directory(tmp_path, monkeypatch):
    monkeypatch.delenv("IDA_SCRIPT_MCP_IDA_PATH", raising=False)
    monkeypatch.delenv("IDA_SCRIPT_MCP_WORKER_MODE", raising=False)
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    ida_dir = tmp_path / "ida"
    ida_dir.mkdir()
    gui_ida = ida_dir / "ida64.exe"
    gui_ida.write_text("gui", encoding="utf-8")
    worker_ida = ida_dir / "idat64.exe"
    worker_ida.write_text("worker", encoding="utf-8")
    captured = {}

    def popen(args, **kwargs):
        captured["args"] = args
        job_dir = Path(kwargs["cwd"])
        (job_dir / "result.json").write_text(
            ExecuteResult(status="ok", result=1).model_dump_json(), encoding="utf-8"
        )
        return FakeProcess(exit_code=0)

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", popen=popen)
    result = manager.execute(
        ExecuteRequest(code="result = 1"),
        gui_context=_gui_context(db, gui_executable_path=str(gui_ida)),
        instance_id="sample",
        port=13338,
    )

    assert captured["args"][0] == str(worker_ida)
    assert result.status == "ok"


def test_worker_discovery_falls_back_to_env_when_gui_directory_has_no_worker(
    tmp_path, monkeypatch
):
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    gui_dir = tmp_path / "gui-only"
    gui_dir.mkdir()
    gui_ida = gui_dir / "ida64.exe"
    gui_ida.write_text("gui", encoding="utf-8")
    env_ida = tmp_path / "idat64-env.exe"
    env_ida.write_text("worker", encoding="utf-8")
    monkeypatch.setenv("IDA_SCRIPT_MCP_IDA_PATH", str(env_ida))
    monkeypatch.setenv("IDA_SCRIPT_MCP_WORKER_MODE", "idat")
    captured = {}

    def popen(args, **kwargs):
        captured["args"] = args
        job_dir = Path(kwargs["cwd"])
        (job_dir / "result.json").write_text(
            ExecuteResult(status="ok", result=1).model_dump_json(), encoding="utf-8"
        )
        return FakeProcess(exit_code=0)

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", popen=popen)
    result = manager.execute(
        ExecuteRequest(code="result = 1"),
        gui_context=_gui_context(db, gui_executable_path=str(gui_ida)),
        instance_id="sample",
        port=13338,
    )

    assert captured["args"][0] == str(env_ida)
    assert result.status == "ok"


def test_missing_result_classified_by_exit_code(tmp_path):
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    ida = tmp_path / "idat64"
    ida.write_text("fake", encoding="utf-8")
    manager = IsolatedExecutionManager(
        work_dir=tmp_path / "jobs", ida_path=ida, popen=lambda *_a, **_k: FakeProcess(exit_code=2)
    )

    result = manager.execute(
        ExecuteRequest(code="1"), gui_context=_gui_context(db), instance_id="sample", port=1
    )

    assert result.status == "worker_crashed"


def test_timeout_kills_process_tree(tmp_path):
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    ida = tmp_path / "idat64"
    ida.write_text("fake", encoding="utf-8")
    killed = []
    fake = FakeProcess(timeout=True)

    def kill_tree(process):
        killed.append(process.pid)
        process.killed = True
        return True

    manager = IsolatedExecutionManager(
        work_dir=tmp_path / "jobs", ida_path=ida, popen=lambda *_a, **_k: fake, kill_tree=kill_tree
    )
    result = manager.execute(
        ExecuteRequest(code="while True:\n    pass", timeout_seconds=1),
        gui_context=_gui_context(db),
        instance_id="sample",
        port=1,
    )

    assert killed == [1234]
    assert result.status == "timeout"
    assert result.killed is True
    assert result.hard_timeout is True


def test_job_directory_is_deleted_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("IDA_SCRIPT_MCP_KEEP_JOBS", raising=False)
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    ida = tmp_path / "idat64"
    ida.write_text("fake", encoding="utf-8")
    captured = {}

    def popen(_args, **kwargs):
        job_dir = Path(kwargs["cwd"])
        captured["job_dir"] = job_dir
        (job_dir / "result.json").write_text(
            ExecuteResult(status="ok", result=1).model_dump_json(), encoding="utf-8"
        )
        return FakeProcess(exit_code=0)

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", ida_path=ida, popen=popen)

    result = manager.execute(
        ExecuteRequest(code="result = 1"),
        gui_context=_gui_context(db),
        instance_id="sample",
        port=1,
    )

    assert result.status == "ok"
    assert result.artifacts == {}
    assert result.artifacts_retained is False
    assert not captured["job_dir"].exists()


def test_keep_jobs_env_preserves_job_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_SCRIPT_MCP_KEEP_JOBS", "1")
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    ida = tmp_path / "idat64"
    ida.write_text("fake", encoding="utf-8")
    captured = {}

    def popen(_args, **kwargs):
        job_dir = Path(kwargs["cwd"])
        captured["job_dir"] = job_dir
        (job_dir / "result.json").write_text(
            ExecuteResult(status="ok", result=1).model_dump_json(), encoding="utf-8"
        )
        return FakeProcess(exit_code=0)

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", ida_path=ida, popen=popen)

    result = manager.execute(
        ExecuteRequest(code="result = 1"),
        gui_context=_gui_context(db),
        instance_id="sample",
        port=1,
    )

    assert result.status == "ok"
    assert result.artifacts["request"].endswith("request.json")
    assert result.artifacts_retained is True
    assert captured["job_dir"].exists()


def test_invalid_keep_jobs_env_is_worker_start_error_without_launch(tmp_path, monkeypatch):
    monkeypatch.setenv("IDA_SCRIPT_MCP_KEEP_JOBS", "true")
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    ida = tmp_path / "idat64"
    ida.write_text("fake", encoding="utf-8")
    launched = False

    def popen(*_args, **_kwargs):
        nonlocal launched
        launched = True
        return FakeProcess(exit_code=0)

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", ida_path=ida, popen=popen)

    result = manager.execute(
        ExecuteRequest(code="result = 1"),
        gui_context=_gui_context(db),
        instance_id="sample",
        port=1,
    )

    assert result.status == "worker_start_error"
    assert result.error.type == "ValueError"
    assert "IDA_SCRIPT_MCP_KEEP_JOBS" in result.error.message
    assert launched is False


def test_materialize_source_failure_is_structured_and_cleans_job_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("IDA_SCRIPT_MCP_KEEP_JOBS", raising=False)
    db = tmp_path / "sample.i64"
    db.write_bytes(b"db")
    ida = tmp_path / "idat64"
    ida.write_text("fake", encoding="utf-8")
    launched = False

    def popen(*_args, **_kwargs):
        nonlocal launched
        launched = True
        return FakeProcess(exit_code=0)

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", ida_path=ida, popen=popen)

    def fail_materialize(_request, _job_dir):
        raise PermissionError("cannot write user code")

    manager._materialize_source = fail_materialize  # type: ignore[method-assign]

    result = manager.execute(
        ExecuteRequest(code="result = 1"),
        gui_context=_gui_context(db),
        instance_id="sample",
        port=1,
    )

    assert result.status == "worker_start_error"
    assert result.error.type == "PermissionError"
    assert result.artifacts == {}
    assert result.artifacts_retained is False
    assert launched is False
    assert list((tmp_path / "jobs").iterdir()) == []
