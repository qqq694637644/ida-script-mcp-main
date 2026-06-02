"""Protocol models for isolated IDA worker execution."""

from __future__ import annotations

import json
from typing import Any, Optional

try:
    from pydantic import BaseModel, ConfigDict, Field

    HAS_PYDANTIC = True
except Exception:  # pragma: no cover - exercised in IDA Python without pydantic.
    BaseModel = object  # type: ignore[assignment,misc]
    ConfigDict = dict  # type: ignore[assignment,misc]
    Field = None  # type: ignore[assignment]
    HAS_PYDANTIC = False

try:
    from .protocol import ExecuteRequest
except ImportError:  # pragma: no cover - copied runner inside IDA job dir.
    try:
        from ida_script_mcp_protocol import ExecuteRequest  # type: ignore[no-redef]
    except ImportError:
        from protocol import ExecuteRequest  # type: ignore[no-redef]


if HAS_PYDANTIC:

    class IsolatedExecuteRequest(BaseModel):
        """Request serialized into an isolated worker job directory."""

        model_config = ConfigDict(extra="forbid")

        execute: ExecuteRequest
        job_id: str
        database_path: str
        database_copy_path: str
        input_file_path: Optional[str] = None
        context: dict[str, Any] = Field(default_factory=dict)
        collect_changes: bool = True
        output_dir: str

else:

    class _ValidationError(ValueError):
        """Fallback validation error used only when pydantic is unavailable."""


    def _required_str(value: Any, field_name: str) -> str:
        if not isinstance(value, str):
            raise _ValidationError(f"{field_name} must be a string")
        return value


    def _optional_str(value: Any, field_name: str) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise _ValidationError(f"{field_name} must be a string")
        return value


    def _strict_bool(value: Any, field_name: str) -> bool:
        if type(value) is not bool:
            raise _ValidationError(f"{field_name} must be a strict bool")
        return value


    def _dump_value(value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if isinstance(value, dict):
            return {str(key): _dump_value(inner) for key, inner in value.items()}
        if isinstance(value, list):
            return [_dump_value(item) for item in value]
        return value


    class IsolatedExecuteRequest:
        """Request serialized into an isolated worker job directory."""

        _fields = (
            "execute",
            "job_id",
            "database_path",
            "database_copy_path",
            "input_file_path",
            "context",
            "collect_changes",
            "output_dir",
        )

        def __init__(
            self,
            *,
            execute: ExecuteRequest | dict[str, Any],
            job_id: str,
            database_path: str,
            database_copy_path: str,
            input_file_path: Optional[str] = None,
            context: Optional[dict[str, Any]] = None,
            collect_changes: bool = True,
            output_dir: str,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(
                    f"IsolatedExecuteRequest forbids extra fields: {sorted(extra)!r}"
                )
            self.execute = ExecuteRequest.model_validate(execute)
            self.job_id = _required_str(job_id, "job_id")
            self.database_path = _required_str(database_path, "database_path")
            self.database_copy_path = _required_str(database_copy_path, "database_copy_path")
            self.input_file_path = _optional_str(input_file_path, "input_file_path")
            if context is None:
                self.context = {}
            elif isinstance(context, dict):
                self.context = dict(context)
            else:
                raise _ValidationError("context must be a dict")
            self.collect_changes = _strict_bool(collect_changes, "collect_changes")
            self.output_dir = _required_str(output_dir, "output_dir")

        @classmethod
        def model_validate(cls, data: Any):
            if isinstance(data, cls):
                return data
            if not isinstance(data, dict):
                raise _ValidationError("IsolatedExecuteRequest requires a dict")
            return cls(**data)

        @classmethod
        def model_validate_json(cls, text: str):
            return cls.model_validate(json.loads(text))

        def model_dump(
            self,
            mode: str = "json",
            exclude: Optional[set[str]] = None,
        ) -> dict[str, Any]:
            exclude = exclude or set()
            return {
                field: _dump_value(getattr(self, field))
                for field in self._fields
                if field not in exclude
            }

        def model_dump_json(self) -> str:
            return json.dumps(self.model_dump(mode="json"), ensure_ascii=False)

        def model_copy(self, *, update: Optional[dict[str, Any]] = None):
            data = self.model_dump(mode="json")
            if update:
                data.update(update)
            return self.__class__.model_validate(data)
