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

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", ida_path=tmp_path / "missing", popen=popen)
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

    manager = IsolatedExecutionManager(work_dir=tmp_path / "jobs", ida_path=tmp_path / "missing", popen=popen)
    result = manager.execute(
        ExecuteRequest(code="1"),
        gui_context=_gui_context(db, dirty=None, unsaved=None, dirty_state_known=False),
        instance_id="sample",
        port=1,
    )

    assert result.status == "rejected"
    assert result.error.type == "GuiDatabaseDirtyStateUnknown"
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


def test_successful_worker_result_uses_arg_list_and_reads_changes(tmp_path):
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
