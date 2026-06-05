"""Tests for Python-based disposable VM workflow glue."""

from __future__ import annotations

import os
import json
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_script_mcp.disposable_vm.workflow_runner import (  # noqa: E402
    DEFAULT_COMMAND_JSON,
    WorkflowInputs,
    _controller_args,
    inputs_from_env,
)


def _inputs(tmp_path: Path, task_action: str = "noop") -> WorkflowInputs:
    return WorkflowInputs(
        controller_url="http://192.168.1.249:8766",
        port=8766,
        restore_script=r"C:\Users\alion\Scripts\vmware_restore_test1.py",
        restore_gui=True,
        run_vmware_restore=True,
        restore_extra_args=(),
        task_action=task_action,
        ida_dir=r"C:\Users\alion\Desktop\IDAPro8.3",
        dll_path=r"C:\Users\alion\Desktop\test1.dll",
        ida_timeout_seconds=180,
        ida_api_test_mode="basic",
        command_json=DEFAULT_COMMAND_JSON,
        connect_timeout_seconds=600,
        run_timeout_seconds=1800,
        result_dir=tmp_path,
    )


def test_python_script_action_writes_reviewable_payload_file(tmp_path):
    args = _controller_args(_inputs(tmp_path, "python_script"))

    assert args[args.index("--task-action") + 1] == "python_script"
    script_path = Path(args[args.index("--script-path") + 1])
    assert script_path.is_file()
    assert script_path.name == "phase3_payload.py"
    assert "phase3 script ok" in script_path.read_text(encoding="utf-8")


def test_u004_real_mcp_action_generates_one_python_payload_file(tmp_path):
    args = _controller_args(_inputs(tmp_path, "ida_plugin_u004_real_mcp_client_test"))

    assert args[args.index("--task-action") + 1] == "python_script"
    script_path = Path(args[args.index("--script-path") + 1])
    assert script_path.is_file()
    assert script_path.name == "U004_real_MCP_client_end-to-end.py"
    script = script_path.read_text(encoding="utf-8")
    assert "execute_idapython" in script
    assert 'call_tool("apply_worker_changes"' not in script


def test_workflow_yaml_uses_python_files_not_powershell():
    workflow = Path(".github/workflows/disposable-vm-guest-agent-smoke.yml").read_text(encoding="utf-8")

    assert "shell: pwsh" not in workflow
    assert "shell: cmd" not in workflow
    assert "IDA_MCP_" not in workflow
    assert "$ErrorActionPreference" not in workflow
    assert "shell: python" in workflow
    assert "runpy.run_path" in workflow
    assert "workflow_runner.py" in workflow
    assert "workflow_install.py" in workflow


def test_workflow_runner_reads_github_event_inputs(tmp_path, monkeypatch):
    event_path = tmp_path / "event.json"
    event_path.write_text(
        json.dumps(
            {
                "inputs": {
                    "controller_url": "http://example.invalid:9000",
                    "port": "9000",
                    "restore_script": r"C:\restore.py",
                    "restore_gui": "false",
                    "run_vmware_restore": "false",
                    "restore_extra_args_json": '["--snapshot", "test"]',
                    "task_action": "command",
                    "ida_dir": r"C:\IDA",
                    "dll_path": r"C:\sample.dll",
                    "ida_timeout_seconds": "11",
                    "ida_api_test_mode": "basic",
                    "command_json": '["python", "-V"]',
                    "connect_timeout_seconds": "12",
                    "run_timeout_seconds": "13",
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))

    parsed = inputs_from_env()

    assert parsed.controller_url == "http://example.invalid:9000"
    assert parsed.port == 9000
    assert parsed.restore_gui is False
    assert parsed.run_vmware_restore is False
    assert parsed.restore_extra_args == ("--snapshot", "test")
    assert parsed.task_action == "command"
    assert parsed.ida_timeout_seconds == 11
    assert parsed.connect_timeout_seconds == 12
    assert parsed.run_timeout_seconds == 13
    assert parsed.result_dir == tmp_path / "ida-script-mcp-disposable-vm"
