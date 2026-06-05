"""Shared protocol models for IDA script execution.

The MCP server normally has :mod:`pydantic` installed and uses the strict models
below. The IDA plugin can also run in IDA's bundled Python environment where
third-party packages may be unavailable, so this module includes a small fallback
implementation for the subset of model behavior used by the plugin.
"""

from __future__ import annotations

from typing import Any, Literal, Optional

try:
    from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

    _HAS_PYDANTIC = True
except ImportError:  # pragma: no cover - exercised by IDA runtime and fallback tests.
    _HAS_PYDANTIC = False


DEFAULT_EXECUTE_TIMEOUT_SECONDS = 30
MAX_EXECUTE_TIMEOUT_SECONDS = 600
PLUGIN_RESPONSE_TIMEOUT_MARGIN_SECONDS = 5
EXECUTE_FILENAME = "<ida-script-mcp-execute>"

ExecuteStatus = Literal[
    "ok",
    "timeout",
    "script_error",
    "source_error",
    "busy",
    "plugin_response_timeout",
]

_ALLOWED_STATUSES = {
    "ok",
    "timeout",
    "script_error",
    "source_error",
    "busy",
    "plugin_response_timeout",
}


if _HAS_PYDANTIC:

    class ExecuteRequest(BaseModel):
        """Strict request body for the IDA plugin ``/execute`` endpoint."""

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
        """Structured result returned by script execution."""

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

else:

    class ProtocolValidationError(ValueError):
        """Raised by the lightweight fallback models when validation fails."""


    def _reject_extra(data: dict[str, Any], allowed: set[str]) -> None:
        extra = sorted(set(data) - allowed)
        if extra:
            raise ProtocolValidationError("Extra fields are not permitted: " + ", ".join(extra))


    def _dump_value(value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if isinstance(value, dict):
            return {str(key): _dump_value(inner) for key, inner in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_dump_value(item) for item in value]
        return value


    class _FallbackModel:
        """Small pydantic-compatible surface used by the IDA plugin."""

        @classmethod
        def model_validate(cls, data: Any):
            if not isinstance(data, dict):
                raise ProtocolValidationError(f"Expected object for {cls.__name__}")
            return cls(**data)

        def model_dump(self, mode: str = "python") -> dict[str, Any]:
            del mode
            return {key: _dump_value(value) for key, value in self.__dict__.items()}

        def model_copy(self, *, update: Optional[dict[str, Any]] = None):
            data = self.model_dump(mode="json")
            if update:
                data.update(update)
            return type(self)(**data)


    class ExecuteRequest(_FallbackModel):
        """Strict request body for the IDA plugin ``/execute`` endpoint."""

        _fields = {"code", "script_path", "capture_output", "timeout_seconds"}

        def __init__(
            self,
            *,
            code: Optional[str] = None,
            script_path: Optional[str] = None,
            capture_output: bool = True,
            timeout_seconds: int = DEFAULT_EXECUTE_TIMEOUT_SECONDS,
            **extra: Any,
        ):
            _reject_extra(extra, set())
            if code is not None and not isinstance(code, str):
                raise ProtocolValidationError("code must be a string or null")
            if script_path is not None and not isinstance(script_path, str):
                raise ProtocolValidationError("script_path must be a string or null")
            if not isinstance(capture_output, bool):
                raise ProtocolValidationError("capture_output must be a boolean")
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
                raise ProtocolValidationError("timeout_seconds must be an integer")
            if not (1 <= timeout_seconds <= MAX_EXECUTE_TIMEOUT_SECONDS):
                raise ProtocolValidationError(
                    f"timeout_seconds must be between 1 and {MAX_EXECUTE_TIMEOUT_SECONDS}"
                )

            has_code = code is not None and bool(code.strip())
            has_script_path = script_path is not None and bool(script_path.strip())
            if has_code == has_script_path:
                raise ProtocolValidationError("Provide exactly one of code or script_path")

            self.code = code
            self.script_path = script_path
            self.capture_output = capture_output
            self.timeout_seconds = timeout_seconds

        @classmethod
        def model_validate(cls, data: Any) -> "ExecuteRequest":
            if not isinstance(data, dict):
                raise ProtocolValidationError("Expected object for ExecuteRequest")
            _reject_extra(data, cls._fields)
            return cls(**data)


    class ExecutionError(_FallbackModel):
        """Structured execution-system error details."""

        _fields = {"type", "message", "traceback"}

        def __init__(
            self,
            *,
            type: str,
            message: str,
            traceback: Optional[str] = None,
            **extra: Any,
        ):
            _reject_extra(extra, set())
            if not isinstance(type, str) or not type:
                raise ProtocolValidationError("type must be a non-empty string")
            if not isinstance(message, str):
                raise ProtocolValidationError("message must be a string")
            if traceback is not None and not isinstance(traceback, str):
                raise ProtocolValidationError("traceback must be a string or null")
            self.type = type
            self.message = message
            self.traceback = traceback

        @classmethod
        def model_validate(cls, data: Any) -> "ExecutionError":
            if not isinstance(data, dict):
                raise ProtocolValidationError("Expected object for ExecutionError")
            _reject_extra(data, cls._fields)
            return cls(**data)


    class ExecuteResult(_FallbackModel):
        """Structured result returned by script execution."""

        _fields = {
            "status",
            "result",
            "stdout",
            "stderr",
            "error",
            "duration_seconds",
            "timeout_seconds",
            "instance_id",
            "port",
        }

        def __init__(
            self,
            *,
            status: str,
            result: Any = None,
            stdout: str = "",
            stderr: str = "",
            error: Optional[ExecutionError | dict[str, Any]] = None,
            duration_seconds: float = 0.0,
            timeout_seconds: int = DEFAULT_EXECUTE_TIMEOUT_SECONDS,
            instance_id: Optional[str] = None,
            port: Optional[int] = None,
            **extra: Any,
        ):
            _reject_extra(extra, set())
            if status not in _ALLOWED_STATUSES:
                raise ProtocolValidationError(f"Unsupported execution status: {status!r}")
            if not isinstance(stdout, str):
                raise ProtocolValidationError("stdout must be a string")
            if not isinstance(stderr, str):
                raise ProtocolValidationError("stderr must be a string")
            if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, (int, float)):
                raise ProtocolValidationError("duration_seconds must be numeric")
            if float(duration_seconds) < 0:
                raise ProtocolValidationError("duration_seconds must be non-negative")
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
                raise ProtocolValidationError("timeout_seconds must be an integer")
            if timeout_seconds < 1:
                raise ProtocolValidationError("timeout_seconds must be at least 1")
            if instance_id is not None and not isinstance(instance_id, str):
                raise ProtocolValidationError("instance_id must be a string or null")
            if port is not None and (isinstance(port, bool) or not isinstance(port, int)):
                raise ProtocolValidationError("port must be an integer or null")
            if isinstance(error, dict):
                error = ExecutionError.model_validate(error)
            if error is not None and not isinstance(error, ExecutionError):
                raise ProtocolValidationError("error must be an ExecutionError, object, or null")

            self.status = status
            self.result = result
            self.stdout = stdout
            self.stderr = stderr
            self.error = error
            self.duration_seconds = float(duration_seconds)
            self.timeout_seconds = timeout_seconds
            self.instance_id = instance_id
            self.port = port

        @classmethod
        def model_validate(cls, data: Any) -> "ExecuteResult":
            if not isinstance(data, dict):
                raise ProtocolValidationError("Expected object for ExecuteResult")
            _reject_extra(data, cls._fields)
            return cls(**data)
