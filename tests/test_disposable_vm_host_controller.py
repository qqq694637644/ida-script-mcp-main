from __future__ import annotations

import argparse

import pytest

from ida_script_mcp.disposable_vm import host_controller
from ida_script_mcp.disposable_vm.host_controller import ControllerState, build_payload
from ida_script_mcp.payload.disposable_vm import GuestHello, GuestResult, TaskAction, TaskPayload


def _args(**overrides):
    values = {
        "task_action": "noop",
        "timeout_seconds": 10,
        "command_json": None,
        "script_path": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_build_payload_defaults_command_to_python_version() -> None:
    payload = build_payload(_args(task_action="command"), "job-1")

    assert payload.action is TaskAction.COMMAND
    assert payload.command == ["python", "--version"]


def test_build_payload_uses_command_json() -> None:
    payload = build_payload(
        _args(task_action="command", command_json='["py", "-3", "--version"]'),
        "job-1",
    )

    assert payload.command == ["py", "-3", "--version"]


def test_build_payload_uses_python_script_file(tmp_path) -> None:
    script_path = tmp_path / "payload.py"
    script_path.write_text("print('phase3 ok')\n", encoding="utf-8")

    payload = build_payload(
        _args(task_action="python_script", script_path=str(script_path)),
        "job-1",
    )

    assert payload.action is TaskAction.PYTHON_SCRIPT
    assert payload.script_text == "print('phase3 ok')\n"


def test_controller_state_persists_hello_and_result(tmp_path) -> None:
    payload = TaskPayload(job_id="job-1", action=TaskAction.NOOP, timeout_seconds=10)
    state = ControllerState(
        job_id="job-1",
        advertise_url="http://127.0.0.1:8766",
        payload=payload,
        result_dir=tmp_path,
    )

    state.record_hello(
        GuestHello(
            guest_id="ida-test-vm",
            hostname="WIN10-GUEST",
            agent_version="0.1",
            boot_id="boot-1",
            python_version="3.11.7",
        )
    )
    state.record_payload_download()
    state.record_result(GuestResult(job_id="job-1", status="completed", exit_code=0))

    snapshot = state.snapshot()
    assert snapshot["status"] == "success"
    assert snapshot["payload_url"] == "http://127.0.0.1:8766/payload/job-1"
    assert state.hello_event.is_set()
    assert state.result_event.is_set()
    assert (tmp_path / "hello.json").is_file()
    assert (tmp_path / "payload.json").is_file()
    assert (tmp_path / "result.json").is_file()
    assert (tmp_path / "controller_state.json").is_file()


def test_missing_host_runtime_modules_uses_import_names(monkeypatch) -> None:
    monkeypatch.setattr(
        host_controller,
        "_module_available",
        lambda name: name == "fastapi",
    )

    assert host_controller.missing_host_runtime_modules(["fastapi", "uvicorn"]) == ["uvicorn"]


def test_ensure_host_runtime_modules_installs_missing(monkeypatch) -> None:
    installed = {"fastapi": False}
    calls: list[list[str]] = []

    def fake_module_available(name: str) -> bool:
        return installed.get(name, True)

    def fake_install(names: list[str]) -> None:
        calls.append(list(names))
        for name in names:
            installed[name] = True

    monkeypatch.setattr(host_controller, "_module_available", fake_module_available)
    monkeypatch.setattr(host_controller, "_install_host_runtime_modules", fake_install)

    host_controller.ensure_host_runtime_modules(["fastapi"])

    assert calls == [["fastapi"]]


def test_ensure_host_runtime_modules_respects_disabled_auto_install(monkeypatch) -> None:
    monkeypatch.setenv("IDA_SCRIPT_MCP_VM_HOST_AUTO_INSTALL", "0")
    monkeypatch.setattr(host_controller, "_module_available", lambda name: False)

    with pytest.raises(RuntimeError, match="auto-install disabled"):
        host_controller.ensure_host_runtime_modules(["fastapi"])
