"""Strict change recording support for isolated worker scripts."""

from __future__ import annotations

import itertools
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Optional

from .change_protocol import (
    ChangeOperation,
    CommentChange,
    FunctionCommentChange,
    PatchBytesChange,
    RenameChange,
    TypeChange,
)


class RecorderError(RuntimeError):
    """Raised when a successful write cannot be recorded."""


class ChangeRecorder:
    """Record explicit and monkeypatched IDAPython database writes."""

    def __init__(self):
        self.operations: list[ChangeOperation] = []
        self._counter = itertools.count(1)
        self._patches: list[tuple[Any, str, Any]] = []
        self._suppress_depth = 0

    @contextmanager
    def suppress_recording(self) -> Iterator[None]:
        """Temporarily suppress monkeypatch recording while preserving API effects."""
        self._suppress_depth += 1
        try:
            yield
        finally:
            self._suppress_depth -= 1

    @property
    def recording_suppressed(self) -> bool:
        return self._suppress_depth > 0

    def _op_id(self) -> str:
        return f"op-{next(self._counter):06d}"

    def rename(self, ea: int, new_name: str, *, old_name: Optional[str] = None, flags: int = 0, source: str = "explicit_api") -> RenameChange:
        op = RenameChange(op_id=self._op_id(), ea=int(ea), old_name=old_name, new_name=new_name, flags=int(flags), source=source)  # type: ignore[arg-type]
        self.operations.append(op)
        return op

    def comment(self, ea: int, text: str, *, repeatable: bool = False, source: str = "explicit_api") -> CommentChange:
        op = CommentChange(op_id=self._op_id(), ea=int(ea), text=text, repeatable=bool(repeatable), source=source)  # type: ignore[arg-type]
        self.operations.append(op)
        return op

    def function_comment(self, ea: int, text: str, *, repeatable: bool = False, source: str = "explicit_api") -> FunctionCommentChange:
        op = FunctionCommentChange(op_id=self._op_id(), ea=int(ea), text=text, repeatable=bool(repeatable), source=source)  # type: ignore[arg-type]
        self.operations.append(op)
        return op

    def patch_bytes(self, ea: int, data: bytes | bytearray | str, *, old_bytes_hex: Optional[str] = None, source: str = "explicit_api") -> PatchBytesChange:
        if isinstance(data, str):
            new_bytes_hex = data
        else:
            new_bytes_hex = bytes(data).hex()
        op = PatchBytesChange(op_id=self._op_id(), ea=int(ea), old_bytes_hex=old_bytes_hex, new_bytes_hex=new_bytes_hex, source=source)  # type: ignore[arg-type]
        self.operations.append(op)
        return op

    def set_type(self, ea: int, decl: str, *, flags: int = 0, source: str = "explicit_api") -> TypeChange:
        op = TypeChange(op_id=self._op_id(), ea=int(ea), decl=decl, flags=int(flags), source=source)  # type: ignore[arg-type]
        self.operations.append(op)
        return op

    def install(self, modules: dict[str, Any]) -> None:
        """Patch common write APIs in provided IDAPython modules."""
        self._patch_two_arg_name(modules.get("idc"), "set_name")
        self._patch_two_arg_name(modules.get("ida_name"), "set_name")
        self._patch_comment(modules.get("idc"), "set_cmt")
        self._patch_comment(modules.get("ida_bytes"), "set_cmt")
        self._patch_func_comment(modules.get("idc"), "set_func_cmt")
        self._patch_func_comment(modules.get("ida_funcs"), "set_func_cmt")
        for module_name in ("idc", "ida_bytes"):
            module = modules.get(module_name)
            self._patch_patch_int(module, "patch_byte", 1)
            self._patch_patch_int(module, "patch_word", 2)
            self._patch_patch_int(module, "patch_dword", 4)
            self._patch_patch_int(module, "patch_qword", 8)
        self._patch_patch_bytes(modules.get("ida_bytes"), "patch_bytes")
        self._patch_type(modules.get("idc"), "SetType")
        self._patch_type(modules.get("idc"), "set_type")

    def uninstall(self) -> None:
        while self._patches:
            module, name, original = self._patches.pop()
            setattr(module, name, original)

    def _replace(self, module: Any, name: str, wrapper_factory: Callable[[Callable[..., Any]], Callable[..., Any]]) -> None:
        if module is None or not hasattr(module, name):
            return
        original = getattr(module, name)
        setattr(module, name, wrapper_factory(original))
        self._patches.append((module, name, original))

    @staticmethod
    def _success(result: Any) -> bool:
        return bool(result)

    def _patch_two_arg_name(self, module: Any, name: str) -> None:
        def factory(original):
            def wrapper(ea, new_name, flags=0, *args, **kwargs):
                result = original(ea, new_name, flags, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.rename(ea, str(new_name), flags=int(flags), source="monkeypatch")
                return result
            return wrapper
        self._replace(module, name, factory)

    def _patch_comment(self, module: Any, name: str) -> None:
        def factory(original):
            def wrapper(ea, text, repeatable=0, *args, **kwargs):
                result = original(ea, text, repeatable, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.comment(ea, str(text), repeatable=bool(repeatable), source="monkeypatch")
                return result
            return wrapper
        self._replace(module, name, factory)

    def _patch_func_comment(self, module: Any, name: str) -> None:
        def factory(original):
            def wrapper(ea, text, repeatable=0, *args, **kwargs):
                result = original(ea, text, repeatable, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.function_comment(ea, str(text), repeatable=bool(repeatable), source="monkeypatch")
                return result
            return wrapper
        self._replace(module, name, factory)

    def _patch_patch_int(self, module: Any, name: str, width: int) -> None:
        def factory(original):
            def wrapper(ea, value, *args, **kwargs):
                result = original(ea, value, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.patch_bytes(ea, int(value).to_bytes(width, "little", signed=False), source="monkeypatch")
                return result
            return wrapper
        self._replace(module, name, factory)

    def _patch_patch_bytes(self, module: Any, name: str) -> None:
        def factory(original):
            def wrapper(ea, data, *args, **kwargs):
                result = original(ea, data, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.patch_bytes(ea, data, source="monkeypatch")
                return result
            return wrapper
        self._replace(module, name, factory)

    def _patch_type(self, module: Any, name: str) -> None:
        def factory(original):
            def wrapper(ea, decl, flags=0, *args, **kwargs):
                result = original(ea, decl, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.set_type(ea, str(decl), flags=int(flags or 0), source="monkeypatch")
                return result
            return wrapper
        self._replace(module, name, factory)


class McpChangesApi:
    """Explicit safe API exposed to worker scripts as ``mcp_changes``."""

    def __init__(self, recorder: ChangeRecorder, modules: dict[str, Any]):
        self.recorder = recorder
        self.modules = modules

    def rename(self, ea: int, name: str, flags: int = 0):
        module = self.modules.get("ida_name") or self.modules.get("idc")
        with self.recorder.suppress_recording():
            ok = True if module is None or not hasattr(module, "set_name") else module.set_name(ea, name, flags)
        if not ok:
            return ok
        self.recorder.rename(ea, name, flags=flags)
        return ok

    def comment(self, ea: int, text: str, repeatable: bool = False):
        module = self.modules.get("ida_bytes") or self.modules.get("idc")
        with self.recorder.suppress_recording():
            ok = True if module is None or not hasattr(module, "set_cmt") else module.set_cmt(ea, text, int(repeatable))
        if not ok:
            return ok
        self.recorder.comment(ea, text, repeatable=repeatable)
        return ok

    def function_comment(self, ea: int, text: str, repeatable: bool = False):
        module = self.modules.get("ida_funcs") or self.modules.get("idc")
        with self.recorder.suppress_recording():
            ok = True if module is None or not hasattr(module, "set_func_cmt") else module.set_func_cmt(ea, text, int(repeatable))
        if not ok:
            return ok
        self.recorder.function_comment(ea, text, repeatable=repeatable)
        return ok

    def patch_bytes(self, ea: int, data: bytes | bytearray | str):
        module = self.modules.get("ida_bytes")
        with self.recorder.suppress_recording():
            ok = True if module is None or not hasattr(module, "patch_bytes") else module.patch_bytes(ea, data)
        if not ok:
            return ok
        self.recorder.patch_bytes(ea, data)
        return ok

    def set_type(self, ea: int, decl: str, flags: int = 0):
        module = self.modules.get("idc")
        func = getattr(module, "set_type", None) or getattr(module, "SetType", None) if module is not None else None
        with self.recorder.suppress_recording():
            ok = True if func is None else func(ea, decl)
        if not ok:
            return ok
        self.recorder.set_type(ea, decl, flags=flags)
        return ok
