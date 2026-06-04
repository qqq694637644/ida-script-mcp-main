"""Strict change recording support for isolated worker scripts."""

from __future__ import annotations

import itertools
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

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


def _required_module(modules: dict[str, Any], module_name: str) -> Any:
    module = modules.get(module_name)
    if module is None:
        raise RecorderError(f"Required IDAPython module is unavailable: {module_name}")
    return module


def _required_callable(
    modules: dict[str, Any], module_name: str, function_name: str
) -> Callable[..., Any]:
    module = _required_module(modules, module_name)
    function = getattr(module, function_name, None)
    if not callable(function):
        raise RecorderError(f"Required IDAPython API is unavailable: {module_name}.{function_name}")
    return function


class ChangeRecorder:
    """Record explicit and monkeypatched IDAPython database writes.

    V2.3 is intentionally fail-closed: the worker must install every expected
    recorder wrapper up front. Missing IDA modules/APIs become worker start
    failures instead of warnings so unsupported runtime versions are visible.
    """

    def __init__(self):
        self.operations: list[ChangeOperation] = []
        self._counter = itertools.count(1)
        self._patches: list[tuple[Any, str, Any]] = []
        self._suppress_depth = 0
        self._modules: dict[str, Any] = {}

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

    def rename(
        self,
        ea: int,
        new_name: str,
        *,
        old_name: str | None = None,
        flags: int = 0,
        source: str = "explicit_api",
    ) -> RenameChange:
        op = RenameChange(
            op_id=self._op_id(),
            ea=int(ea),
            old_name=old_name,
            new_name=new_name,
            flags=int(flags),
            source=source,  # type: ignore[arg-type]
        )
        self.operations.append(op)
        return op

    def comment(
        self,
        ea: int,
        text: str,
        *,
        repeatable: bool = False,
        source: str = "explicit_api",
    ) -> CommentChange:
        op = CommentChange(
            op_id=self._op_id(),
            ea=int(ea),
            text=text,
            repeatable=bool(repeatable),
            source=source,  # type: ignore[arg-type]
        )
        self.operations.append(op)
        return op

    def function_comment(
        self,
        ea: int,
        text: str,
        *,
        repeatable: bool = False,
        source: str = "explicit_api",
    ) -> FunctionCommentChange:
        op = FunctionCommentChange(
            op_id=self._op_id(),
            ea=int(ea),
            text=text,
            repeatable=bool(repeatable),
            source=source,  # type: ignore[arg-type]
        )
        self.operations.append(op)
        return op

    def patch_bytes(
        self,
        ea: int,
        data: bytes | bytearray | str,
        *,
        old_bytes_hex: str | None = None,
        source: str = "explicit_api",
    ) -> PatchBytesChange:
        new_bytes_hex = self._coerce_patch_bytes(data).hex()
        op = PatchBytesChange(
            op_id=self._op_id(),
            ea=int(ea),
            old_bytes_hex=old_bytes_hex,
            new_bytes_hex=new_bytes_hex,
            source=source,  # type: ignore[arg-type]
        )
        self.operations.append(op)
        return op

    def set_type(
        self,
        ea: int,
        decl: str,
        *,
        flags: int = 0,
        source: str = "explicit_api",
    ) -> TypeChange:
        op = TypeChange(
            op_id=self._op_id(),
            ea=int(ea),
            decl=decl,
            flags=int(flags),
            source=source,  # type: ignore[arg-type]
        )
        self.operations.append(op)
        return op

    def install(self, modules: dict[str, Any]) -> None:
        """Patch common write APIs in provided IDAPython modules.

        This method is strict by design. If any required monkeypatch cannot be
        installed, already-installed wrappers are removed and ``RecorderError``
        is raised before user code runs.
        """
        self.uninstall()
        self._modules = dict(modules)
        try:
            self._patch_two_arg_name("idc", "set_name")
            self._patch_two_arg_name("ida_name", "set_name")
            self._patch_comment("idc", "set_cmt")
            self._patch_comment("ida_bytes", "set_cmt")
            self._patch_func_comment("idc", "set_func_cmt")
            self._patch_func_comment("ida_funcs", "set_func_cmt")
            for module_name in ("idc", "ida_bytes"):
                self._patch_patch_int(module_name, "patch_byte", 1)
                self._patch_patch_int(module_name, "patch_word", 2)
                self._patch_patch_int(module_name, "patch_dword", 4)
                self._patch_patch_int(module_name, "patch_qword", 8)
            self._patch_patch_bytes("ida_bytes", "patch_bytes")
            self._patch_type("idc", "SetType")
            self._patch_type("idc", "set_type")
            self._patch_apply_tinfo("ida_typeinf", "apply_tinfo")
        except Exception:
            self.uninstall()
            self._modules = {}
            raise

    def uninstall(self) -> None:
        while self._patches:
            module, name, original = self._patches.pop()
            setattr(module, name, original)
        self._modules = {}

    def _replace(
        self,
        module_name: str,
        name: str,
        wrapper_factory: Callable[[Callable[..., Any]], Callable[..., Any]],
    ) -> None:
        module = _required_module(self._modules, module_name)
        original = _required_callable(self._modules, module_name, name)
        setattr(module, name, wrapper_factory(original))
        self._patches.append((module, name, original))

    @staticmethod
    def _success(result: Any) -> bool:
        return bool(result)

    @staticmethod
    def _coerce_patch_bytes(data: bytes | bytearray | str) -> bytes:
        if isinstance(data, bytes):
            return data
        if isinstance(data, bytearray):
            return bytes(data)
        if isinstance(data, str):
            try:
                return bytes.fromhex(data.strip())
            except ValueError as exc:
                raise RecorderError("patch_bytes string data must be hex encoded") from exc
        raise RecorderError(
            f"patch_bytes data must be bytes, bytearray, or hex string: {type(data)!r}"
        )

    @staticmethod
    def _int_to_bytes(value: Any, width: int) -> bytes:
        integer = int(value)
        if integer < 0:
            raise RecorderError("patch integer value must be non-negative")
        max_value = 1 << (8 * width)
        if integer >= max_value:
            raise RecorderError(f"patch integer value does not fit in {width} bytes")
        return integer.to_bytes(width, "little", signed=False)

    def _old_name(self, modules: dict[str, Any], ea: int) -> str | None:
        get_name = _required_callable(modules, "idc", "get_name")
        try:
            value = get_name(int(ea))
        except Exception as exc:
            raise RecorderError(f"Failed to read old name at 0x{int(ea):x}: {exc}") from exc
        return str(value) if value else None

    def _old_bytes_hex(self, modules: dict[str, Any], ea: int, width: int) -> str:
        get_bytes = _required_callable(modules, "idc", "get_bytes")
        try:
            value = get_bytes(int(ea), int(width))
        except Exception as exc:
            raise RecorderError(f"Failed to read old bytes at 0x{int(ea):x}: {exc}") from exc
        if value is None:
            raise RecorderError(f"Failed to read {width} old bytes at 0x{int(ea):x}")
        return bytes(value).hex()

    def _tinfo_to_decl(self, tinfo: Any) -> str:
        for method_name in ("dstr", "_print"):
            method = getattr(tinfo, method_name, None)
            if callable(method):
                try:
                    value = method()
                except TypeError:
                    continue
                if value:
                    return str(value)
        text = str(tinfo)
        if text and not (text.startswith("<") and text.endswith(">")):
            return text
        raise RecorderError("ida_typeinf.apply_tinfo tinfo argument is not printable")

    def _patch_two_arg_name(self, module_name: str, name: str) -> None:
        def factory(original):
            def wrapper(ea, new_name, flags=0, *args, **kwargs):
                if self.recording_suppressed:
                    return original(ea, new_name, flags, *args, **kwargs)
                old_name = self._old_name(self._modules, ea)
                result = original(ea, new_name, flags, *args, **kwargs)
                if self._success(result):
                    self.rename(
                        ea,
                        str(new_name),
                        old_name=old_name,
                        flags=int(flags),
                        source="monkeypatch",
                    )
                return result

            return wrapper

        self._replace(module_name, name, factory)

    def _patch_comment(self, module_name: str, name: str) -> None:
        def factory(original):
            def wrapper(ea, text, repeatable=0, *args, **kwargs):
                result = original(ea, text, repeatable, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.comment(ea, str(text), repeatable=bool(repeatable), source="monkeypatch")
                return result

            return wrapper

        self._replace(module_name, name, factory)

    def _patch_func_comment(self, module_name: str, name: str) -> None:
        def factory(original):
            def wrapper(ea, text, repeatable=0, *args, **kwargs):
                result = original(ea, text, repeatable, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.function_comment(
                        ea,
                        str(text),
                        repeatable=bool(repeatable),
                        source="monkeypatch",
                    )
                return result

            return wrapper

        self._replace(module_name, name, factory)

    def _patch_patch_int(self, module_name: str, name: str, width: int) -> None:
        def factory(original):
            def wrapper(ea, value, *args, **kwargs):
                if self.recording_suppressed:
                    return original(ea, value, *args, **kwargs)
                new_bytes = self._int_to_bytes(value, width)
                old_bytes_hex = self._old_bytes_hex(self._modules, ea, width)
                result = original(ea, value, *args, **kwargs)
                if self._success(result):
                    self.patch_bytes(
                        ea,
                        new_bytes,
                        old_bytes_hex=old_bytes_hex,
                        source="monkeypatch",
                    )
                return result

            return wrapper

        self._replace(module_name, name, factory)

    def _patch_patch_bytes(self, module_name: str, name: str) -> None:
        def factory(original):
            def wrapper(ea, data, *args, **kwargs):
                if self.recording_suppressed:
                    return original(ea, data, *args, **kwargs)
                new_bytes = self._coerce_patch_bytes(data)
                old_bytes_hex = self._old_bytes_hex(self._modules, ea, len(new_bytes))
                result = original(ea, data, *args, **kwargs)
                if self._success(result):
                    self.patch_bytes(
                        ea,
                        new_bytes,
                        old_bytes_hex=old_bytes_hex,
                        source="monkeypatch",
                    )
                return result

            return wrapper

        self._replace(module_name, name, factory)

    def _patch_type(self, module_name: str, name: str) -> None:
        def factory(original):
            def wrapper(ea, decl, flags=0, *args, **kwargs):
                result = original(ea, decl, *args, **kwargs)
                if self._success(result) and not self.recording_suppressed:
                    self.set_type(ea, str(decl), flags=int(flags or 0), source="monkeypatch")
                return result

            return wrapper

        self._replace(module_name, name, factory)

    def _patch_apply_tinfo(self, module_name: str, name: str) -> None:
        def factory(original):
            def wrapper(ea, tinfo, flags=0, *args, **kwargs):
                if self.recording_suppressed:
                    return original(ea, tinfo, flags, *args, **kwargs)
                decl = self._tinfo_to_decl(tinfo)
                result = original(ea, tinfo, flags, *args, **kwargs)
                if self._success(result):
                    self.set_type(ea, decl, flags=int(flags or 0), source="monkeypatch")
                return result

            return wrapper

        self._replace(module_name, name, factory)


class McpChangesApi:
    """Explicit safe API exposed to worker scripts as ``mcp_changes``."""

    def __init__(self, recorder: ChangeRecorder, modules: dict[str, Any]):
        self.recorder = recorder
        self.modules = modules

    def _required_api(self, module_name: str, function_name: str) -> Callable[..., Any]:
        return _required_callable(self.modules, module_name, function_name)

    def rename(self, ea: int, name: str, flags: int = 0):
        old_name = self.recorder._old_name(self.modules, ea)
        set_name = self._required_api("ida_name", "set_name")
        with self.recorder.suppress_recording():
            ok = set_name(ea, name, flags)
        if not ok:
            return ok
        self.recorder.rename(ea, name, old_name=old_name, flags=flags)
        return ok

    def comment(self, ea: int, text: str, repeatable: bool = False):
        set_cmt = self._required_api("ida_bytes", "set_cmt")
        with self.recorder.suppress_recording():
            ok = set_cmt(ea, text, int(repeatable))
        if not ok:
            return ok
        self.recorder.comment(ea, text, repeatable=repeatable)
        return ok

    def function_comment(self, ea: int, text: str, repeatable: bool = False):
        set_func_cmt = self._required_api("ida_funcs", "set_func_cmt")
        with self.recorder.suppress_recording():
            ok = set_func_cmt(ea, text, int(repeatable))
        if not ok:
            return ok
        self.recorder.function_comment(ea, text, repeatable=repeatable)
        return ok

    def patch_bytes(self, ea: int, data: bytes | bytearray | str):
        new_bytes = self.recorder._coerce_patch_bytes(data)
        old_bytes_hex = self.recorder._old_bytes_hex(self.modules, ea, len(new_bytes))
        patch_bytes = self._required_api("ida_bytes", "patch_bytes")
        with self.recorder.suppress_recording():
            ok = patch_bytes(ea, new_bytes)
        if not ok:
            return ok
        self.recorder.patch_bytes(ea, new_bytes, old_bytes_hex=old_bytes_hex)
        return ok

    def set_type(self, ea: int, decl: str, flags: int = 0):
        set_type = self._required_api("idc", "set_type")
        with self.recorder.suppress_recording():
            ok = set_type(ea, decl)
        if not ok:
            return ok
        self.recorder.set_type(ea, decl, flags=flags)
        return ok
