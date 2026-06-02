"""Protocol models for isolated IDA worker execution."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from .protocol import ExecuteRequest


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
