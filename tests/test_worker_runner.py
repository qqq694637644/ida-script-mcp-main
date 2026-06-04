from __future__ import annotations

import json
import sys
import types
from pathlib import Path

from ida_script_mcp.isolated_protocol import IsolatedExecuteRequest
from ida_script_mcp.protocol import ExecuteRequest, ExecuteResult
from ida_script_mcp.worker_runner import run

IDA_MODULES = (
    "idaapi",
    "idc",
    "idautils",
    "ida_name",
    "ida_bytes",
    "ida_funcs",
    "ida_typeinf",
    "ida_auto",
    "ida_loader",
)


def _write_request(tmp_path: Path, request: IsolatedExecuteRequest) -> Path:
    request_path = tmp_path / "request.json"
    request_path.write_text(request.model_dump_json(), encoding="utf-8")
    return request_path


def _clear_ida_modules(monkeypatch) -> None:
    for module_name in IDA_MODULES:
        monkeypatch.delitem(sys.modules, module_name, raising=False)


def _install_fake_ida_runtime(monkeypatch, opened_database_path: Path) -> dict[str, list]:
    state: dict[str, list] = {"batch_calls": [], "auto_wait_calls": [], "qexit_calls": []}
    memory = bytearray(range(64))

    def offset(ea):
        return int(ea) - 0x1000

    def get_name(_ea):
        return "old_name"

    def set_name(_ea, _name, _flags=0):
        return True

    def set_cmt(_ea, _text, _repeatable=0):
        return True

    def set_func_cmt(_ea, _text, _repeatable=0):
        return True

    def get_bytes(ea, size):
        start = offset(ea)
        return bytes(memory[start : start + int(size)])

    def patch_int(width):
        def patch(ea, value):
            start = offset(ea)
            memory[start : start + width] = int(value).to_bytes(width, "little")
            return True

        return patch

    def patch_bytes(ea, data):
        new_bytes = bytes(data)
        start = offset(ea)
        memory[start : start + len(new_bytes)] = new_bytes
        return True

    def set_type(_ea, _decl):
        return True

    idc = types.SimpleNamespace(
        batch=lambda enabled: state["batch_calls"].append(enabled),
        qexit=lambda code: state["qexit_calls"].append(code),
        set_name=set_name,
        get_name=get_name,
        set_cmt=set_cmt,
        set_func_cmt=set_func_cmt,
        patch_byte=patch_int(1),
        patch_word=patch_int(2),
        patch_dword=patch_int(4),
        patch_qword=patch_int(8),
        get_bytes=get_bytes,
        SetType=set_type,
        set_type=set_type,
    )
    ida_bytes = types.SimpleNamespace(
        set_cmt=set_cmt,
        patch_byte=patch_int(1),
        patch_word=patch_int(2),
        patch_dword=patch_int(4),
        patch_qword=patch_int(8),
        patch_bytes=patch_bytes,
    )
    ida_auto = types.SimpleNamespace(
        auto_wait=lambda: state["auto_wait_calls"].append(True) or True
    )
    ida_loader = types.SimpleNamespace(
        PATH_TYPE_IDB=1,
        get_path=lambda path_type: str(opened_database_path) if path_type == 1 else None,
    )

    modules = {
        "idaapi": types.SimpleNamespace(),
        "idc": idc,
        "idautils": types.SimpleNamespace(),
        "ida_name": types.SimpleNamespace(set_name=set_name),
        "ida_bytes": ida_bytes,
        "ida_funcs": types.SimpleNamespace(set_func_cmt=set_func_cmt),
        "ida_typeinf": types.SimpleNamespace(apply_tinfo=lambda *_args: True),
        "ida_auto": ida_auto,
        "ida_loader": ida_loader,
    }
    for module_name, module in modules.items():
        monkeypatch.setitem(sys.modules, module_name, module)
    return state


def test_worker_runner_strict_install_missing_ida_modules_is_start_error(tmp_path, monkeypatch):
    _clear_ida_modules(monkeypatch)
    request = IsolatedExecuteRequest(
        execute=ExecuteRequest(code="result = 1"),
        job_id="job-1",
        database_path="source.i64",
        database_copy_path="copy.i64",
        output_dir=str(tmp_path),
    )

    exit_code = run(_write_request(tmp_path, request))
    result = ExecuteResult.model_validate_json((tmp_path / "result.json").read_text())

    assert exit_code == 2
    assert result.status == "worker_start_error"
    assert result.error is not None
    assert result.error.type == "RecorderError"
    assert "idc" in result.error.message


def test_worker_runner_sets_batch_waits_and_executes_against_copied_database(
    tmp_path,
    monkeypatch,
):
    copied_db = tmp_path / "copy.i64"
    copied_db.write_bytes(b"db")
    state = _install_fake_ida_runtime(monkeypatch, copied_db)
    request = IsolatedExecuteRequest(
        execute=ExecuteRequest(code="result = 42"),
        job_id="job-1",
        database_path="source.i64",
        database_copy_path=str(copied_db),
        context={"database_sha256": "abc"},
        output_dir=str(tmp_path),
    )

    exit_code = run(_write_request(tmp_path, request))
    result = ExecuteResult.model_validate_json((tmp_path / "result.json").read_text())

    assert exit_code == 0
    assert result.status == "ok"
    assert result.result == 42
    assert state["batch_calls"] == [1]
    assert state["auto_wait_calls"] == [True]
    worker_runtime = json.loads((tmp_path / "worker_runtime.json").read_text(encoding="utf-8"))
    assert worker_runtime["opened_database_path"] == str(copied_db)


def test_worker_runner_rejects_database_path_mismatch(tmp_path, monkeypatch):
    copied_db = tmp_path / "copy.i64"
    opened_db = tmp_path / "other.i64"
    copied_db.write_bytes(b"db")
    opened_db.write_bytes(b"other")
    _install_fake_ida_runtime(monkeypatch, opened_db)
    request = IsolatedExecuteRequest(
        execute=ExecuteRequest(code="result = 42"),
        job_id="job-1",
        database_path="source.i64",
        database_copy_path=str(copied_db),
        output_dir=str(tmp_path),
    )

    exit_code = run(_write_request(tmp_path, request))
    result = ExecuteResult.model_validate_json((tmp_path / "result.json").read_text())

    assert exit_code == 2
    assert result.status == "worker_start_error"
    assert result.error is not None
    assert "mismatch" in result.error.message
