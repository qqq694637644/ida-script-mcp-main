"""Shared protocol models for IDA script execution."""

from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

try:
    from .change_protocol import ChangeOperation
except ImportError:  # pragma: no cover - IDA plugin support-file import fallback.
    try:
        from ida_script_mcp_change_protocol import ChangeOperation  # type: ignore[no-redef]
    except ImportError:
        from change_protocol import ChangeOperation  # type: ignore[no-redef]

DEFAULT_EXECUTE_TIMEOUT_SECONDS = 30
MAX_EXECUTE_TIMEOUT_SECONDS = 600
EXECUTE_FILENAME = "<ida-script-mcp-execute>"

ExecuteStatus = Literal[
    "ok",
    "timeout",
    "script_error",
    "source_error",
    "worker_crashed",
    "worker_start_error",
    "worker_result_missing",
    "recorder_error",
    "rejected",
]


class ExecuteRequest(BaseModel):
    """Strict request body for IDAPython execution."""

    model_config = ConfigDict(extra="forbid", strict=True)

    code: Optional[str] = None
    script_path: Optional[str] = None
    capture_output: StrictBool = True
    timeout_seconds: int = Field(
        default=DEFAULT_EXECUTE_TIMEOUT_SECONDS,
        ge=1,
        le=MAX_EXECUTE_TIMEOUT_SECONDS,
    )

    @model_validator(mode="after")
    def validate_source(self) -> "ExecuteRequest":
        has_code = self.code is not None and bool(self.code.strip())
        has_script_path = self.script_path is not None and bool(self.script_path.strip())
        if has_code == has_script_path:
            raise ValueError("Provide exactly one of code or script_path")
        return self


class ExecutionError(BaseModel):
    """Structured execution-system error details."""

    model_config = ConfigDict(extra="forbid")

    type: str
    message: str
    traceback: Optional[str] = None


class ExecuteResult(BaseModel):
    """Structured result returned by isolated script execution."""

    model_config = ConfigDict(extra="forbid")

    status: ExecuteStatus
    result: Any = None
    stdout: str = ""
    stderr: str = ""
    error: Optional[ExecutionError] = None
    duration_seconds: float = Field(default=0.0, ge=0.0)
    timeout_seconds: int = Field(default=DEFAULT_EXECUTE_TIMEOUT_SECONDS, ge=1)
    instance_id: Optional[str] = None
    port: Optional[int] = None
    isolated: bool = True
    job_id: Optional[str] = None
    worker_pid: Optional[int] = None
    worker_exit_code: Optional[int] = None
    killed: bool = False
    hard_timeout: bool = False
    changes: list[ChangeOperation] = Field(default_factory=list)
    artifacts: dict[str, str] = Field(default_factory=dict)
