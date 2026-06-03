from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from ida_script_mcp.guest_vm.agent import (
    config_from_args,
    execute_payload,
    normalize_command,
    normalize_controller_url,
    tail_text,
)


def test_tail_text_truncates_by_utf8_bytes() -> None:
    value = "prefix-" + "é" * 20

    result = tail_text(value, 12)

    assert len(result.encode("utf-8")) <= 14  # May include a replacement char at the boundary.
    assert result.endswith("é" * 5)


def test_normalize_command_rejects_shell_string() -> None:
    with pytest.raises(ValueError, match="non-empty list"):
        normalize_command("python --version")


def test_normalize_controller_url_adds_http_scheme() -> None:
    assert normalize_controller_url("192.168.1.249:8766") == "http://192.168.1.249:8766"


def test_normalize_controller_url_preserves_http_url_and_strips_slash() -> None:
    assert normalize_controller_url("http://192.168.1.249:8766/") == "http://192.168.1.249:8766"


def test_normalize_controller_url_rejects_non_http_url() -> None:
    with pytest.raises(ValueError, match="HTTP URL"):
        normalize_controller_url("ftp://192.168.1.249:8766")


def test_config_from_args_normalizes_controller_url(tmp_path) -> None:
    config = config_from_args(
        SimpleNamespace(
            controller_url="192.168.1.249:8766",
            guest_id="ida-test-vm",
            agent_version="0.1.0",
            boot_id="boot-1",
            work_root=str(tmp_path),
            connect_retries=1,
            connect_retry_delay=0.1,
            request_timeout=1.0,
            result_tail_bytes=4096,
        )
    )

    assert config.controller_url == "http://192.168.1.249:8766"


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
