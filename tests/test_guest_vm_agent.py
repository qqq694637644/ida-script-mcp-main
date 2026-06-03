from __future__ import annotations

import sys

import pytest

from ida_script_mcp.guest_vm.agent import execute_payload, normalize_command, tail_text


def test_tail_text_truncates_by_utf8_bytes() -> None:
    value = "prefix-" + "é" * 20

    result = tail_text(value, 12)

    assert len(result.encode("utf-8")) <= 14  # May include a replacement char at the boundary.
    assert result.endswith("é" * 5)


def test_normalize_command_rejects_shell_string() -> None:
    with pytest.raises(ValueError, match="non-empty list"):
        normalize_command("python --version")


def test_execute_noop_payload_reports_python_runtime(tmp_path) -> None:
    result = execute_payload(
        {"job_id": "job-1", "action": "noop", "timeout_seconds": 10},
        tmp_path,
        default_timeout_seconds=10,
        tail_bytes=4096,
    )

    assert result["status"] == "completed"
    assert result["exit_code"] == 0
    assert "python_version=" in result["stdout_tail"]
    assert result["metadata"]["python_executable"] == sys.executable


def test_execute_python_script_payload(tmp_path) -> None:
    result = execute_payload(
        {
            "job_id": "job-1",
            "action": "python_script",
            "timeout_seconds": 10,
            "script_text": "print('guest script ok')\n",
        },
        tmp_path,
        default_timeout_seconds=10,
        tail_bytes=4096,
    )

    assert result["status"] == "completed"
    assert result["exit_code"] == 0
    assert "guest script ok" in result["stdout_tail"]
    assert (tmp_path / "payload.py").is_file()
