"""Shared protocol models for IDA script execution."""

from __future__ import annotations

import json
from typing import Any, Literal

try:
    from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

    HAS_PYDANTIC = True
except Exception:  # pragma: no cover - exercised in IDA Python without pydantic.
    BaseModel = object  # type: ignore[assignment,misc]
    ConfigDict = dict  # type: ignore[assignment,misc]
    Field = None  # type: ignore[assignment]
    StrictBool = bool  # type: ignore[assignment]
    model_validator = None  # type: ignore[assignment]
    HAS_PYDANTIC = False

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
EXECUTE_STATUSES = {
    "ok",
    "timeout",
    "script_error",
    "source_error",
    "worker_crashed",
    "worker_start_error",
    "worker_result_missing",
    "recorder_error",
    "rejected",
}


if HAS_PYDANTIC:

    class ExecuteRequest(BaseModel):
        """Strict request body for IDAPython execution."""

        model_config = ConfigDict(extra="forbid", strict=True)

        code: str | None = None
        script_path: str | None = None
        capture_output: StrictBool = True
        timeout_seconds: int = Field(
            default=DEFAULT_EXECUTE_TIMEOUT_SECONDS,
            ge=1,
            le=MAX_EXECUTE_TIMEOUT_SECONDS,
        )

        @model_validator(mode="after")
        def validate_source(self) -> ExecuteRequest:
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
        traceback: str | None = None

    class ExecuteResult(BaseModel):
        """Structured result returned by isolated script execution."""

        model_config = ConfigDict(extra="forbid")

        status: ExecuteStatus
        result: Any = None
        stdout: str = ""
        stderr: str = ""
        error: ExecutionError | None = None
        duration_seconds: float = Field(default=0.0, ge=0.0)
        timeout_seconds: int = Field(default=DEFAULT_EXECUTE_TIMEOUT_SECONDS, ge=1)
        instance_id: str | None = None
        port: int | None = None
        isolated: bool = True
        job_id: str | None = None
        worker_pid: int | None = None
        worker_exit_code: int | None = None
        killed: bool = False
        hard_timeout: bool = False
        changes: list[ChangeOperation] = Field(default_factory=list)
        artifacts: dict[str, str] = Field(default_factory=dict)
        artifacts_retained: bool = True

else:

    class _ValidationError(ValueError):
        """Fallback validation error used only when pydantic is unavailable."""

    def _reject_extra(data: dict[str, Any], allowed: set[str], model_name: str) -> None:
        extra = set(data) - allowed
        if extra:
            raise _ValidationError(f"{model_name} forbids extra fields: {sorted(extra)!r}")

    def _strict_bool(value: Any, field_name: str) -> bool:
        if type(value) is not bool:
            raise _ValidationError(f"{field_name} must be a strict bool")
        return value

    def _optional_str(value: Any, field_name: str) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise _ValidationError(f"{field_name} must be a string")
        return value

    def _required_str(value: Any, field_name: str) -> str:
        if not isinstance(value, str):
            raise _ValidationError(f"{field_name} must be a string")
        return value

    def _optional_int(value: Any, field_name: str) -> int | None:
        if value is None:
            return None
        if type(value) is bool:
            raise _ValidationError(f"{field_name} must be an int")
        return int(value)

    def _required_int(value: Any, field_name: str) -> int:
        if value is None or type(value) is bool:
            raise _ValidationError(f"{field_name} must be an int")
        return int(value)

    def _duration(value: Any) -> float:
        result = float(value)
        if result < 0:
            raise _ValidationError("duration_seconds must be >= 0")
        return result

    def _timeout(value: Any) -> int:
        timeout = _required_int(value, "timeout_seconds")
        if timeout < 1 or timeout > MAX_EXECUTE_TIMEOUT_SECONDS:
            raise _ValidationError("timeout_seconds out of range")
        return timeout

    def _dump_value(value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if isinstance(value, list):
            return [_dump_value(item) for item in value]
        if isinstance(value, dict):
            return {str(key): _dump_value(inner) for key, inner in value.items()}
        return value

    def _change_operation(value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return value
        if isinstance(value, dict):
            try:
                from .change_protocol import _change_operation as coerce_change_operation
            except ImportError:  # pragma: no cover - IDA plugin support-file import fallback.
                try:
                    from ida_script_mcp_change_protocol import (  # type: ignore[no-redef]
                        _change_operation as coerce_change_operation,
                    )
                except ImportError:
                    from change_protocol import (  # type: ignore[no-redef]
                        _change_operation as coerce_change_operation,
                    )
            return coerce_change_operation(value)
        raise _ValidationError("change operation must be a dict")

    class _SimpleModel:
        _fields: tuple[str, ...] = ()

        @classmethod
        def model_validate(cls, data: Any):
            if isinstance(data, cls):
                return data
            if not isinstance(data, dict):
                raise _ValidationError(f"{cls.__name__} requires a dict")
            return cls(**data)

        @classmethod
        def model_validate_json(cls, text: str):
            return cls.model_validate(json.loads(text))

        def model_dump(
            self,
            mode: str = "json",
            exclude: set[str] | None = None,
        ) -> dict[str, Any]:
            exclude = exclude or set()
            return {
                field: _dump_value(getattr(self, field))
                for field in self._fields
                if field not in exclude
            }

        def model_dump_json(self) -> str:
            return json.dumps(self.model_dump(mode="json"), ensure_ascii=False)

        def model_copy(self, *, update: dict[str, Any] | None = None):
            data = self.model_dump(mode="json")
            if update:
                data.update(update)
            return self.__class__.model_validate(data)

    class ExecuteRequest(_SimpleModel):
        """Strict request body for IDAPython execution."""

        _fields = ("code", "script_path", "capture_output", "timeout_seconds")

        def __init__(
            self,
            *,
            code: str | None = None,
            script_path: str | None = None,
            capture_output: bool = True,
            timeout_seconds: int = DEFAULT_EXECUTE_TIMEOUT_SECONDS,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(f"ExecuteRequest forbids extra fields: {sorted(extra)!r}")
            self.code = _optional_str(code, "code")
            self.script_path = _optional_str(script_path, "script_path")
            self.capture_output = _strict_bool(capture_output, "capture_output")
            self.timeout_seconds = _timeout(timeout_seconds)
            has_code = self.code is not None and bool(self.code.strip())
            has_script_path = self.script_path is not None and bool(self.script_path.strip())
            if has_code == has_script_path:
                raise _ValidationError("Provide exactly one of code or script_path")

    class ExecutionError(_SimpleModel):
        """Structured execution-system error details."""

        _fields = ("type", "message", "traceback")

        def __init__(
            self,
            *,
            type: str,
            message: str,
            traceback: str | None = None,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(f"ExecutionError forbids extra fields: {sorted(extra)!r}")
            self.type = _required_str(type, "type")
            self.message = _required_str(message, "message")
            self.traceback = _optional_str(traceback, "traceback")

    class ExecuteResult(_SimpleModel):
        """Structured result returned by isolated script execution."""

        _fields = (
            "status",
            "result",
            "stdout",
            "stderr",
            "error",
            "duration_seconds",
            "timeout_seconds",
            "instance_id",
            "port",
            "isolated",
            "job_id",
            "worker_pid",
            "worker_exit_code",
            "killed",
            "hard_timeout",
            "changes",
            "artifacts",
            "artifacts_retained",
        )

        def __init__(
            self,
            *,
            status: str,
            result: Any = None,
            stdout: str = "",
            stderr: str = "",
            error: ExecutionError | dict[str, Any] | None = None,
            duration_seconds: float = 0.0,
            timeout_seconds: int = DEFAULT_EXECUTE_TIMEOUT_SECONDS,
            instance_id: str | None = None,
            port: int | None = None,
            isolated: bool = True,
            job_id: str | None = None,
            worker_pid: int | None = None,
            worker_exit_code: int | None = None,
            killed: bool = False,
            hard_timeout: bool = False,
            changes: list[Any] | None = None,
            artifacts: dict[str, Any] | None = None,
            artifacts_retained: bool = True,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(f"ExecuteResult forbids extra fields: {sorted(extra)!r}")
            if status not in EXECUTE_STATUSES:
                raise _ValidationError(f"unsupported execute status: {status!r}")
            self.status = status
            self.result = result
            self.stdout = _required_str(stdout, "stdout")
            self.stderr = _required_str(stderr, "stderr")
            self.error = ExecutionError.model_validate(error) if error is not None else None
            self.duration_seconds = _duration(duration_seconds)
            self.timeout_seconds = _timeout(timeout_seconds)
            self.instance_id = _optional_str(instance_id, "instance_id")
            self.port = _optional_int(port, "port")
            self.isolated = _strict_bool(isolated, "isolated")
            self.job_id = _optional_str(job_id, "job_id")
            self.worker_pid = _optional_int(worker_pid, "worker_pid")
            self.worker_exit_code = _optional_int(worker_exit_code, "worker_exit_code")
            self.killed = _strict_bool(killed, "killed")
            self.hard_timeout = _strict_bool(hard_timeout, "hard_timeout")
            self.changes = [_change_operation(change) for change in (changes or [])]
            self.artifacts = {str(key): str(value) for key, value in (artifacts or {}).items()}
            self.artifacts_retained = _strict_bool(artifacts_retained, "artifacts_retained")
