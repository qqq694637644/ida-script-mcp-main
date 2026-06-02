"""Structured worker-to-GUI database change protocol."""

from __future__ import annotations

from typing import Annotated, Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, StrictBool


class DatabaseFingerprint(BaseModel):
    """Strong database identity used before replaying worker changes."""

    model_config = ConfigDict(extra="forbid")

    input_file_path: Optional[str] = None
    database_path: Optional[str] = None
    root_filename: Optional[str] = None
    imagebase: Optional[int] = None
    input_md5: Optional[str] = None
    input_sha256: Optional[str] = None
    processor: Optional[str] = None
    bitness: Optional[int] = None
    copied_database_lineage: Optional[str] = None
    database_sha256: Optional[str] = None
    database_size: Optional[int] = None


class ChangeBase(BaseModel):
    """Base metadata carried by every replayable change."""

    model_config = ConfigDict(extra="forbid")

    op_id: str
    op: str
    ea: Optional[int] = None
    source: Literal["explicit_api", "monkeypatch"]
    confidence: Literal["high", "medium", "low"] = "high"
    reason: Optional[str] = None


class RenameChange(ChangeBase):
    op: Literal["rename"] = "rename"
    ea: int
    old_name: Optional[str] = None
    new_name: str
    flags: int = 0


class CommentChange(ChangeBase):
    op: Literal["comment"] = "comment"
    ea: int
    text: str
    repeatable: bool = False


class FunctionCommentChange(ChangeBase):
    op: Literal["function_comment"] = "function_comment"
    ea: int
    text: str
    repeatable: bool = False


class PatchBytesChange(ChangeBase):
    op: Literal["patch_bytes"] = "patch_bytes"
    ea: int
    old_bytes_hex: Optional[str] = None
    new_bytes_hex: str


class TypeChange(ChangeBase):
    op: Literal["set_type"] = "set_type"
    ea: int
    decl: str
    flags: int = 0


ChangeOperation = Annotated[
    RenameChange | CommentChange | FunctionCommentChange | PatchBytesChange | TypeChange,
    Field(discriminator="op"),
]


class ChangeSet(BaseModel):
    """A set of worker changes that can be previewed or replayed into the GUI database."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    job_id: str
    database_fingerprint: DatabaseFingerprint
    operations: list[ChangeOperation] = Field(default_factory=list)


class ApplyChangesRequest(ChangeSet):
    """GUI ``/apply_changes`` request body."""

    dry_run: StrictBool = True


class OperationApplyResult(BaseModel):
    """Per-operation preview/apply result."""

    model_config = ConfigDict(extra="forbid")

    op_id: str
    op: str
    status: Literal["applied", "skipped", "error"]
    message: str = ""


class ApplyChangesResult(BaseModel):
    """Structured response from GUI change replay."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "partial", "rejected", "error"]
    job_id: str
    dry_run: bool = True
    applied: list[OperationApplyResult] = Field(default_factory=list)
    skipped: list[OperationApplyResult] = Field(default_factory=list)
    errors: list[OperationApplyResult] = Field(default_factory=list)
    message: str = ""


def fingerprint_matches(expected: DatabaseFingerprint, actual: DatabaseFingerprint) -> bool:
    """Return whether two fingerprints are strong enough for safe replay.

    Saved IDB/I64 database hashes are the only authoritative replay identity in
    V2.3. Missing, mismatched, or input-only identities must fail closed.
    """
    return (
        expected.database_sha256 is not None
        and actual.database_sha256 is not None
        and expected.database_sha256 == actual.database_sha256
    )


def fingerprint_from_metadata(metadata: dict[str, Any]) -> DatabaseFingerprint:
    """Build a fingerprint from GUI or worker metadata dictionaries."""
    return DatabaseFingerprint(
        input_file_path=metadata.get("input_file_path"),
        database_path=metadata.get("database_path"),
        root_filename=metadata.get("root_filename") or metadata.get("database"),
        imagebase=metadata.get("imagebase"),
        input_md5=metadata.get("input_md5"),
        input_sha256=metadata.get("input_sha256"),
        processor=metadata.get("processor"),
        bitness=metadata.get("bitness"),
        copied_database_lineage=metadata.get("copied_database_lineage"),
        database_sha256=metadata.get("database_sha256"),
        database_size=metadata.get("database_size"),
    )
