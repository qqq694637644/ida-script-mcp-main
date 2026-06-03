from __future__ import annotations

import pytest
from pydantic import ValidationError

from ida_script_mcp.payload.disposable_vm import GuestHello, GuestResult, TaskAction, TaskPayload


def test_guest_hello_strips_required_strings() -> None:
    hello = GuestHello(
        guest_id=" ida-test-vm ",
        hostname=" WIN10-GUEST ",
        agent_version=" 0.1 ",
        boot_id=" boot-1 ",
    )

    assert hello.guest_id == "ida-test-vm"
    assert hello.hostname == "WIN10-GUEST"
    assert hello.agent_version == "0.1"
    assert hello.boot_id == "boot-1"


def test_noop_payload_rejects_command() -> None:
    with pytest.raises(ValidationError, match="noop action must not include command"):
        TaskPayload(
            job_id="job-1",
            action=TaskAction.NOOP,
            timeout_seconds=10,
            command=["python", "--version"],
        )


def test_command_payload_requires_command() -> None:
    with pytest.raises(ValidationError, match="command action requires command"):
        TaskPayload(job_id="job-1", action=TaskAction.COMMAND, timeout_seconds=10)


def test_python_script_payload_requires_script_text() -> None:
    with pytest.raises(ValidationError, match="python_script action requires script_text"):
        TaskPayload(job_id="job-1", action=TaskAction.PYTHON_SCRIPT, timeout_seconds=10)


def test_guest_result_accepts_artifact_metadata() -> None:
    result = GuestResult(
        job_id="job-1",
        status="completed",
        exit_code=0,
        artifacts=[{"name": "stdout.txt", "size_bytes": 12}],
    )

    assert result.artifacts[0].name == "stdout.txt"
    assert result.model_dump(mode="json")["status"] == "completed"
