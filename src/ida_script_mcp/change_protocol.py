"""Structured worker-to-GUI database change protocol."""

from __future__ import annotations

import json
from typing import Annotated, Any, Literal

try:
    from pydantic import BaseModel, ConfigDict, Field, StrictBool

    HAS_PYDANTIC = True
except Exception:  # pragma: no cover - exercised in IDA Python without pydantic.
    BaseModel = object  # type: ignore[assignment,misc]
    ConfigDict = dict  # type: ignore[assignment,misc]
    Field = None  # type: ignore[assignment]
    StrictBool = bool  # type: ignore[assignment]
    HAS_PYDANTIC = False


if HAS_PYDANTIC:

    class DatabaseFingerprint(BaseModel):
        """Strong database identity used before replaying worker changes."""

        model_config = ConfigDict(extra="forbid")

        input_file_path: str | None = None
        database_path: str | None = None
        root_filename: str | None = None
        imagebase: int | None = None
        input_md5: str | None = None
        input_sha256: str | None = None
        processor: str | None = None
        bitness: int | None = None
        copied_database_lineage: str | None = None
        database_sha256: str | None = None
        database_size: int | None = None

    class ChangeBase(BaseModel):
        """Base metadata carried by every replayable change."""

        model_config = ConfigDict(extra="forbid")

        op_id: str
        op: str
        ea: int | None = None
        source: Literal["explicit_api", "monkeypatch"]
        confidence: Literal["high", "medium", "low"] = "high"
        reason: str | None = None

    class RenameChange(ChangeBase):
        op: Literal["rename"] = "rename"
        ea: int
        old_name: str | None = None
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
        old_bytes_hex: str | None = None
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

    def _source(value: Any) -> str:
        value = _required_str(value, "source")
        if value not in {"explicit_api", "monkeypatch"}:
            raise _ValidationError("source must be explicit_api or monkeypatch")
        return value

    def _confidence(value: Any) -> str:
        value = _required_str(value, "confidence")
        if value not in {"high", "medium", "low"}:
            raise _ValidationError("confidence must be high, medium, or low")
        return value

    def _dump_value(value: Any) -> Any:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if isinstance(value, list):
            return [_dump_value(item) for item in value]
        if isinstance(value, dict):
            return {str(key): _dump_value(inner) for key, inner in value.items()}
        return value

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

    class DatabaseFingerprint(_SimpleModel):
        """Strong database identity used before replaying worker changes."""

        _fields = (
            "input_file_path",
            "database_path",
            "root_filename",
            "imagebase",
            "input_md5",
            "input_sha256",
            "processor",
            "bitness",
            "copied_database_lineage",
            "database_sha256",
            "database_size",
        )

        def __init__(
            self,
            *,
            input_file_path: str | None = None,
            database_path: str | None = None,
            root_filename: str | None = None,
            imagebase: int | None = None,
            input_md5: str | None = None,
            input_sha256: str | None = None,
            processor: str | None = None,
            bitness: int | None = None,
            copied_database_lineage: str | None = None,
            database_sha256: str | None = None,
            database_size: int | None = None,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(
                    f"DatabaseFingerprint forbids extra fields: {sorted(extra)!r}"
                )
            self.input_file_path = _optional_str(input_file_path, "input_file_path")
            self.database_path = _optional_str(database_path, "database_path")
            self.root_filename = _optional_str(root_filename, "root_filename")
            self.imagebase = _optional_int(imagebase, "imagebase")
            self.input_md5 = _optional_str(input_md5, "input_md5")
            self.input_sha256 = _optional_str(input_sha256, "input_sha256")
            self.processor = _optional_str(processor, "processor")
            self.bitness = _optional_int(bitness, "bitness")
            self.copied_database_lineage = _optional_str(
                copied_database_lineage, "copied_database_lineage"
            )
            self.database_sha256 = _optional_str(database_sha256, "database_sha256")
            self.database_size = _optional_int(database_size, "database_size")

    class ChangeBase(_SimpleModel):
        """Base metadata carried by every replayable change."""

        _base_fields = ("op_id", "op", "ea", "source", "confidence", "reason")

        def _init_base(
            self,
            *,
            op_id: str,
            op: str,
            ea: int | None,
            source: str,
            confidence: str = "high",
            reason: str | None = None,
        ) -> None:
            self.op_id = _required_str(op_id, "op_id")
            self.op = _required_str(op, "op")
            self.ea = _optional_int(ea, "ea")
            self.source = _source(source)
            self.confidence = _confidence(confidence)
            self.reason = _optional_str(reason, "reason")

    class RenameChange(ChangeBase):
        _fields = ChangeBase._base_fields + ("old_name", "new_name", "flags")

        def __init__(
            self,
            *,
            op_id: str,
            ea: int,
            new_name: str,
            source: str,
            op: str = "rename",
            old_name: str | None = None,
            flags: int = 0,
            confidence: str = "high",
            reason: str | None = None,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(f"RenameChange forbids extra fields: {sorted(extra)!r}")
            if op != "rename":
                raise _ValidationError("RenameChange op must be rename")
            self._init_base(
                op_id=op_id,
                op=op,
                ea=_required_int(ea, "ea"),
                source=source,
                confidence=confidence,
                reason=reason,
            )
            self.old_name = _optional_str(old_name, "old_name")
            self.new_name = _required_str(new_name, "new_name")
            self.flags = _required_int(flags, "flags")

    class CommentChange(ChangeBase):
        _fields = ChangeBase._base_fields + ("text", "repeatable")

        def __init__(
            self,
            *,
            op_id: str,
            ea: int,
            text: str,
            source: str,
            op: str = "comment",
            repeatable: bool = False,
            confidence: str = "high",
            reason: str | None = None,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(f"CommentChange forbids extra fields: {sorted(extra)!r}")
            if op != "comment":
                raise _ValidationError("CommentChange op must be comment")
            self._init_base(
                op_id=op_id,
                op=op,
                ea=_required_int(ea, "ea"),
                source=source,
                confidence=confidence,
                reason=reason,
            )
            self.text = _required_str(text, "text")
            self.repeatable = _strict_bool(repeatable, "repeatable")

    class FunctionCommentChange(CommentChange):
        def __init__(self, *, op: str = "function_comment", **kwargs: Any):
            if op != "function_comment":
                raise _ValidationError("FunctionCommentChange op must be function_comment")
            super().__init__(op="comment", **kwargs)
            self.op = "function_comment"

    class PatchBytesChange(ChangeBase):
        _fields = ChangeBase._base_fields + ("old_bytes_hex", "new_bytes_hex")

        def __init__(
            self,
            *,
            op_id: str,
            ea: int,
            new_bytes_hex: str,
            source: str,
            op: str = "patch_bytes",
            old_bytes_hex: str | None = None,
            confidence: str = "high",
            reason: str | None = None,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(f"PatchBytesChange forbids extra fields: {sorted(extra)!r}")
            if op != "patch_bytes":
                raise _ValidationError("PatchBytesChange op must be patch_bytes")
            self._init_base(
                op_id=op_id,
                op=op,
                ea=_required_int(ea, "ea"),
                source=source,
                confidence=confidence,
                reason=reason,
            )
            self.old_bytes_hex = _optional_str(old_bytes_hex, "old_bytes_hex")
            self.new_bytes_hex = _required_str(new_bytes_hex, "new_bytes_hex")

    class TypeChange(ChangeBase):
        _fields = ChangeBase._base_fields + ("decl", "flags")

        def __init__(
            self,
            *,
            op_id: str,
            ea: int,
            decl: str,
            source: str,
            op: str = "set_type",
            flags: int = 0,
            confidence: str = "high",
            reason: str | None = None,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(f"TypeChange forbids extra fields: {sorted(extra)!r}")
            if op != "set_type":
                raise _ValidationError("TypeChange op must be set_type")
            self._init_base(
                op_id=op_id,
                op=op,
                ea=_required_int(ea, "ea"),
                source=source,
                confidence=confidence,
                reason=reason,
            )
            self.decl = _required_str(decl, "decl")
            self.flags = _required_int(flags, "flags")

    ChangeOperation = (
        RenameChange | CommentChange | FunctionCommentChange | PatchBytesChange | TypeChange
    )

    def _change_operation(data: Any) -> ChangeOperation:
        if isinstance(
            data,
            (RenameChange, CommentChange, FunctionCommentChange, PatchBytesChange, TypeChange),
        ):
            return data
        if not isinstance(data, dict):
            raise _ValidationError("change operation must be a dict")
        op = data.get("op")
        if op == "rename":
            return RenameChange.model_validate(data)
        if op == "comment":
            return CommentChange.model_validate(data)
        if op == "function_comment":
            return FunctionCommentChange.model_validate(data)
        if op == "patch_bytes":
            return PatchBytesChange.model_validate(data)
        if op == "set_type":
            return TypeChange.model_validate(data)
        raise _ValidationError(f"unsupported change operation: {op!r}")

    class ChangeSet(_SimpleModel):
        """A set of worker changes that can be previewed or replayed into the GUI database."""

        _fields = ("schema_version", "job_id", "database_fingerprint", "operations")

        def __init__(
            self,
            *,
            job_id: str,
            database_fingerprint: DatabaseFingerprint | dict[str, Any],
            operations: list[Any] | None = None,
            schema_version: int = 1,
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(f"ChangeSet forbids extra fields: {sorted(extra)!r}")
            if schema_version != 1:
                raise _ValidationError("schema_version must be 1")
            self.schema_version = 1
            self.job_id = _required_str(job_id, "job_id")
            self.database_fingerprint = DatabaseFingerprint.model_validate(database_fingerprint)
            self.operations = [_change_operation(operation) for operation in (operations or [])]

    class ApplyChangesRequest(ChangeSet):
        """GUI ``/apply_changes`` request body."""

        _fields = ChangeSet._fields + ("dry_run",)

        def __init__(self, *, dry_run: bool = True, **kwargs: Any):
            super().__init__(**kwargs)
            self.dry_run = _strict_bool(dry_run, "dry_run")

    class OperationApplyResult(_SimpleModel):
        """Per-operation preview/apply result."""

        _fields = ("op_id", "op", "status", "message")

        def __init__(self, *, op_id: str, op: str, status: str, message: str = "", **extra: Any):
            if extra:
                raise _ValidationError(
                    f"OperationApplyResult forbids extra fields: {sorted(extra)!r}"
                )
            if status not in {"applied", "skipped", "error"}:
                raise _ValidationError("operation status must be applied, skipped, or error")
            self.op_id = _required_str(op_id, "op_id")
            self.op = _required_str(op, "op")
            self.status = status
            self.message = _required_str(message, "message")

    class ApplyChangesResult(_SimpleModel):
        """Structured response from GUI change replay."""

        _fields = ("status", "job_id", "dry_run", "applied", "skipped", "errors", "message")

        def __init__(
            self,
            *,
            status: str,
            job_id: str,
            dry_run: bool = True,
            applied: list[Any] | None = None,
            skipped: list[Any] | None = None,
            errors: list[Any] | None = None,
            message: str = "",
            **extra: Any,
        ):
            if extra:
                raise _ValidationError(
                    f"ApplyChangesResult forbids extra fields: {sorted(extra)!r}"
                )
            if status not in {"ok", "partial", "rejected", "error"}:
                raise _ValidationError("apply status must be ok, partial, rejected, or error")
            self.status = status
            self.job_id = _required_str(job_id, "job_id")
            self.dry_run = _strict_bool(dry_run, "dry_run")
            self.applied = [OperationApplyResult.model_validate(item) for item in (applied or [])]
            self.skipped = [OperationApplyResult.model_validate(item) for item in (skipped or [])]
            self.errors = [OperationApplyResult.model_validate(item) for item in (errors or [])]
            self.message = _required_str(message, "message")


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
