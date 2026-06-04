"""Build guest-side IDA open-DLL/plugin-API verification payloads."""
# ruff: noqa: E501

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from textwrap import dedent

from .ida_plugin_install import (
    DEFAULT_GUEST_IDA_DIR,
    IDA_EXECUTABLE_CANDIDATES,
    LEGACY_ROOT_SUPPORT_FILES,
    _read_install_files,
)

DEFAULT_GUEST_DLL_PATH = r"C:\Users\alion\Desktop\test1.dll"
DEFAULT_IDA_TIMEOUT_SECONDS = 180
DEFAULT_IDA_API_TEST_MODE = "basic"


def build_guest_ida_api_test_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    dll_path: str = DEFAULT_GUEST_DLL_PATH,
    ida_timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
    test_mode: str = DEFAULT_IDA_API_TEST_MODE,
    source_root: Path | None = None,
) -> str:
    """Build a standalone guest-side script that opens a DLL in IDA and tests APIs."""

    install_files = _read_install_files(source_root)
    files_b64 = {
        destination: base64.b64encode(content).decode("ascii")
        for destination, content in sorted(install_files.items())
    }
    expected_sha256 = {
        destination: hashlib.sha256(content).hexdigest()
        for destination, content in sorted(install_files.items())
    }

    script = _GUEST_IDA_API_TEST_TEMPLATE
    replacements = {
        "__IDA_DIR_JSON__": json.dumps(ida_dir),
        "__DLL_PATH_JSON__": json.dumps(dll_path),
        "__IDA_TIMEOUT_SECONDS_JSON__": json.dumps(ida_timeout_seconds),
        "__IDA_API_TEST_MODE_JSON__": json.dumps(test_mode),
        "__IDA_EXECUTABLE_CANDIDATES_JSON__": json.dumps(list(IDA_EXECUTABLE_CANDIDATES)),
        "__LEGACY_ROOT_SUPPORT_FILES_JSON__": json.dumps(list(LEGACY_ROOT_SUPPORT_FILES)),
        "__FILES_B64_JSON__": json.dumps(files_b64, ensure_ascii=False),
        "__EXPECTED_SHA256_JSON__": json.dumps(expected_sha256, ensure_ascii=False),
    }
    for placeholder, value in replacements.items():
        script = script.replace(placeholder, value)
    return script


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", default=DEFAULT_GUEST_IDA_DIR)
    parser.add_argument("--dll-path", default=DEFAULT_GUEST_DLL_PATH)
    parser.add_argument("--ida-timeout-seconds", type=int, default=DEFAULT_IDA_TIMEOUT_SECONDS)
    parser.add_argument(
        "--test-mode",
        default=DEFAULT_IDA_API_TEST_MODE,
        choices=["basic", "full", "apply_changes", "inspect_address"],
    )
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        build_guest_ida_api_test_script(
            ida_dir=args.ida_dir,
            dll_path=args.dll_path,
            ida_timeout_seconds=args.ida_timeout_seconds,
            test_mode=args.test_mode,
        ),
        encoding="utf-8",
    )
    print(f"Wrote guest IDA API test payload: {output_path}")


_GUEST_IDA_API_TEST_TEMPLATE = dedent(
    r"""
    from __future__ import annotations

    import base64
    import hashlib
    import json
    import os
    import py_compile
    import subprocess
    import sys
    import tempfile
    import time
    import traceback
    import urllib.error
    import urllib.request
    from pathlib import Path

    IDA_DIR = __IDA_DIR_JSON__
    DLL_PATH = __DLL_PATH_JSON__
    IDA_TIMEOUT_SECONDS = __IDA_TIMEOUT_SECONDS_JSON__
    IDA_API_TEST_MODE = __IDA_API_TEST_MODE_JSON__
    IDA_READY_TIMEOUT_SECONDS = min(60, max(15, IDA_TIMEOUT_SECONDS // 3))
    IDA_EXECUTABLE_CANDIDATES = __IDA_EXECUTABLE_CANDIDATES_JSON__
    LEGACY_ROOT_SUPPORT_FILES = __LEGACY_ROOT_SUPPORT_FILES_JSON__
    FILES_B64 = __FILES_B64_JSON__
    EXPECTED_SHA256 = __EXPECTED_SHA256_JSON__
    WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-api-test-"))
    READY_PATH = WORK_DIR / "ida_ready.json"
    HEARTBEAT_PATH = WORK_DIR / "heartbeat.ndjson"
    RESULT_PATH = WORK_DIR / "ida_api_test_result.json"
    IDA_LOG_PATH = WORK_DIR / "ida.log"

    BOOTSTRAP_TEMPLATE = r'''
    from __future__ import annotations

    import json
    import sys
    import time
    import traceback
    from pathlib import Path

    READY_PATH = __READY_PATH_JSON__
    HEARTBEAT_PATH = __HEARTBEAT_PATH_JSON__
    PLUGIN_DIR = __PLUGIN_DIR_JSON__
    DLL_PATH = __BOOTSTRAP_DLL_PATH_JSON__
    IDA_API_TEST_MODE = __BOOTSTRAP_IDA_API_TEST_MODE_JSON__


    def _write_json(path, payload):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


    def _stage(name, detail=None):
        payload = {"timestamp": time.time(), "stage": name}
        if detail is not None:
            payload["detail"] = detail
        path = Path(HEARTBEAT_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            output.write("\n")


    def _ida_database_path(idaapi_module, ida_loader_module):
        for module in (ida_loader_module, idaapi_module):
            path_type = getattr(module, "PATH_TYPE_IDB", None)
            getter = getattr(module, "get_path", None)
            if path_type is None or getter is None:
                continue
            try:
                path = getter(path_type)
            except Exception:
                continue
            if path:
                return str(path)
        return ""


    def _save_database_for_apply_changes(idaapi_module, ida_loader_module):
        database_path = _ida_database_path(idaapi_module, ida_loader_module)
        if not database_path:
            raise RuntimeError("Cannot resolve saved IDB/I64 path before apply_changes test")

        _stage("database_save_start", {"database_path": database_path})
        saver = getattr(ida_loader_module, "save_database", None)
        if saver is None:
            saver = getattr(idaapi_module, "save_database", None)
        if saver is None:
            raise RuntimeError("IDA save_database API is unavailable")

        try:
            saved = saver(database_path, 0)
        except TypeError:
            saved = saver(database_path)
        if saved is False:
            raise RuntimeError(f"IDA save_database returned failure for {database_path}")

        flusher = getattr(ida_loader_module, "flush_buffers", None)
        if flusher is None:
            flusher = getattr(idaapi_module, "flush_buffers", None)
        if flusher is not None:
            try:
                flusher()
            except Exception:
                pass

        path = Path(database_path)
        if not path.is_file():
            raise RuntimeError(f"Saved IDB/I64 path does not exist after save: {database_path}")
        size = path.stat().st_size
        if size <= 0:
            raise RuntimeError(f"Saved IDB/I64 path is empty after save: {database_path}")
        _stage("database_save_done", {"database_path": database_path, "database_size": size})
        return database_path


    def _u009_get_name(idc_module, ea):
        for getter_name, args in (
            ("get_name", (ea,)),
            ("get_name", (ea, 0)),
            ("get_func_name", (ea,)),
        ):
            getter = getattr(idc_module, getter_name, None)
            if getter is None:
                continue
            try:
                value = getter(*args)
            except TypeError:
                continue
            except Exception:
                continue
            if value:
                return str(value)
        return ""


    def _u009_select_function(ida_funcs_module):
        try:
            import idautils

            for ea in idautils.Functions():
                func = ida_funcs_module.get_func(ea)
                if func is None:
                    continue
                start_ea = int(getattr(func, "start_ea", 0) or 0)
                end_ea = int(getattr(func, "end_ea", start_ea) or start_ea)
                if end_ea > start_ea:
                    return func
        except Exception:
            pass

        badaddr = int(getattr(__import__("idaapi"), "BADADDR", 0xFFFFFFFFFFFFFFFF))
        next_func = getattr(ida_funcs_module, "get_next_func", None)
        if next_func is None:
            return None
        ea = 0
        for _ in range(2048):
            func = next_func(ea)
            if func is None:
                return None
            start_ea = int(getattr(func, "start_ea", 0) or 0)
            end_ea = int(getattr(func, "end_ea", start_ea) or start_ea)
            if end_ea > start_ea:
                return func
            ea = end_ea if end_ea > start_ea else start_ea + 1
            if ea == badaddr:
                return None
        return None


    def _u009_select_instruction_middle(ida_bytes_module, func):
        start_ea = int(getattr(func, "start_ea", 0) or 0)
        end_ea = int(getattr(func, "end_ea", start_ea) or start_ea)
        try:
            import idautils

            for ea in idautils.FuncItems(start_ea):
                ea = int(ea)
                try:
                    item_end = int(ida_bytes_module.get_item_end(ea))
                except Exception:
                    continue
                if item_end > ea + 1 and item_end <= end_ea:
                    return ea + 1, ea, item_end
        except Exception:
            pass
        if end_ea > start_ea + 1:
            return start_ea + 1, start_ea, end_ea
        return start_ea, start_ea, end_ea


    def _u009_select_data_address(ida_bytes_module, ida_segment_module):
        badaddr = int(getattr(__import__("idaapi"), "BADADDR", 0xFFFFFFFFFFFFFFFF))
        first_seg = getattr(ida_segment_module, "get_first_seg", None)
        next_seg = getattr(ida_segment_module, "get_next_seg", None)
        get_class = getattr(ida_segment_module, "get_segm_class", None)
        if first_seg is None or next_seg is None:
            return None

        best_code_segment_non_code = None
        seg = first_seg()
        visited = set()
        while seg is not None:
            start_ea = int(getattr(seg, "start_ea", 0) or 0)
            end_ea = int(getattr(seg, "end_ea", start_ea) or start_ea)
            if start_ea in visited:
                break
            visited.add(start_ea)
            seg_class = ""
            if get_class is not None:
                try:
                    seg_class = str(get_class(seg) or "")
                except Exception:
                    seg_class = ""
            upper_class = seg_class.upper()
            ea = start_ea
            limit = min(end_ea, start_ea + 0x20000)
            while ea < limit:
                try:
                    flags = ida_bytes_module.get_flags(ea)
                except Exception:
                    flags = 0
                try:
                    is_code = bool(ida_bytes_module.is_code(flags))
                except Exception:
                    is_code = False
                try:
                    is_loaded = bool(ida_bytes_module.is_loaded(ea))
                except Exception:
                    is_loaded = True
                if (not is_code) and is_loaded:
                    if upper_class != "CODE":
                        return ea
                    if best_code_segment_non_code is None:
                        best_code_segment_non_code = ea

                next_addr = getattr(ida_bytes_module, "next_addr", None)
                if next_addr is None:
                    ea += 1
                    continue
                try:
                    candidate = int(next_addr(ea))
                except Exception:
                    ea += 1
                    continue
                if candidate == badaddr or candidate <= ea:
                    ea += 1
                else:
                    ea = candidate
            seg = next_seg(start_ea)
        return best_code_segment_non_code


    def _u009_select_unmapped_address(ida_bytes_module, ida_segment_module):
        first_seg = getattr(ida_segment_module, "get_first_seg", None)
        next_seg = getattr(ida_segment_module, "get_next_seg", None)
        getseg = getattr(ida_segment_module, "getseg", None)
        is_mapped = getattr(ida_bytes_module, "is_mapped", None)
        max_end = 0
        if first_seg is not None and next_seg is not None:
            seg = first_seg()
            visited = set()
            while seg is not None:
                start_ea = int(getattr(seg, "start_ea", 0) or 0)
                end_ea = int(getattr(seg, "end_ea", start_ea) or start_ea)
                if start_ea in visited:
                    break
                visited.add(start_ea)
                max_end = max(max_end, end_ea)
                seg = next_seg(start_ea)

        candidates = []
        if max_end:
            candidates.extend(max_end + delta for delta in (0x100000, 0x1000000, 0x10000000, 0x100000000))
        candidates.extend((0x700000000000, 0x7FFF00000000, 0x1000000000000, 0x4000000000000000))

        badaddr = int(getattr(__import__("idaapi"), "BADADDR", 0xFFFFFFFFFFFFFFFF))
        fallback = candidates[0]
        for candidate in candidates:
            if candidate <= 0 or candidate >= badaddr:
                continue
            fallback = candidate
            if getseg is not None:
                try:
                    if getseg(candidate) is not None:
                        continue
                except Exception:
                    pass
            if is_mapped is not None:
                try:
                    if is_mapped(candidate):
                        continue
                except Exception:
                    pass
            try:
                data = ida_bytes_module.get_bytes(candidate, 1)
            except Exception:
                return candidate
            if data is None or data == b"" or data == "":
                return candidate
        return fallback


    def _u009_set_type(idc_module, ea, decl):
        setter = getattr(idc_module, "set_type", None)
        if setter is None:
            setter = getattr(idc_module, "SetType", None)
        if setter is None:
            return False, "idc.set_type/idc.SetType unavailable"
        try:
            return bool(setter(ea, decl)), None
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"


    def _prepare_u009_inspect_address_seed(idaapi_module, ida_loader_module):
        import ida_bytes
        import ida_funcs
        import ida_name
        import ida_segment
        import idc

        _stage("u009_seed_start")
        func = _u009_select_function(ida_funcs)
        if func is None:
            raise RuntimeError("U009 could not find a function to inspect")
        target_ea = int(getattr(func, "start_ea", 0) or 0)
        function_end_ea = int(getattr(func, "end_ea", target_ea) or target_ea)
        middle_ea, middle_head_ea, middle_item_end_ea = _u009_select_instruction_middle(ida_bytes, func)
        data_ea = _u009_select_data_address(ida_bytes, ida_segment)
        unmapped_ea = _u009_select_unmapped_address(ida_bytes, ida_segment)

        run_id = str(int(time.time()))
        requested_unicode_name = f"u009_名前_测试_{run_id}"
        fallback_name = f"u009_inspect_address_{run_id}"
        set_name = getattr(ida_name, "set_name", None)
        if set_name is None:
            set_name = getattr(idc, "set_name", None)
        if set_name is None:
            raise RuntimeError("U009 cannot seed target name because set_name is unavailable")

        unicode_name_set_ok = False
        unicode_name_error = None
        try:
            unicode_name_set_ok = bool(set_name(target_ea, requested_unicode_name, getattr(ida_name, "SN_FORCE", 0)))
        except Exception as exc:
            unicode_name_error = f"{type(exc).__name__}: {exc}"
        actual_name = _u009_get_name(idc, target_ea)
        if not actual_name or (not unicode_name_set_ok):
            fallback_flags = getattr(ida_name, "SN_FORCE", 0) | getattr(ida_name, "SN_NOCHECK", 0)
            fallback_ok = bool(set_name(target_ea, fallback_name, fallback_flags))
            if not fallback_ok:
                raise RuntimeError(f"U009 fallback set_name failed for {hex(target_ea)}")
            actual_name = _u009_get_name(idc, target_ea)

        regular_comment = f"U009 regular 注释 🚀 {run_id}"
        repeatable_comment = f"U009 repeatable 注释 Ω {run_id}"
        function_comment = f"U009 function 注释 Ф {run_id}"
        repeatable_function_comment = f"U009 repeatable function 注释 λ {run_id}"
        ida_bytes.set_cmt(target_ea, regular_comment, 0)
        ida_bytes.set_cmt(target_ea, repeatable_comment, 1)
        ida_funcs.set_func_cmt(func, function_comment, 0)
        ida_funcs.set_func_cmt(func, repeatable_function_comment, 1)

        type_decl = f"int __cdecl {actual_name}(void);"
        type_set_ok, type_error = _u009_set_type(idc, target_ea, type_decl)
        type_text_after_seed = None
        for getter_name, args in (("get_type", (target_ea,)), ("print_type", (target_ea, 0))):
            getter = getattr(idc, getter_name, None)
            if getter is None:
                continue
            try:
                value = getter(*args)
            except Exception:
                continue
            if value:
                type_text_after_seed = str(value)
                break

        database_path = _save_database_for_apply_changes(idaapi_module, ida_loader_module)
        seed = {
            "target_ea": target_ea,
            "target_hex": hex(target_ea),
            "function_end_ea": function_end_ea,
            "instruction_middle_ea": int(middle_ea),
            "instruction_middle_hex": hex(int(middle_ea)),
            "instruction_middle_head_ea": int(middle_head_ea),
            "instruction_middle_item_end_ea": int(middle_item_end_ea),
            "instruction_middle_is_tail": int(middle_ea) != int(middle_head_ea),
            "data_ea": int(data_ea) if data_ea is not None else None,
            "data_hex": hex(int(data_ea)) if data_ea is not None else None,
            "unmapped_ea": int(unmapped_ea),
            "unmapped_hex": hex(int(unmapped_ea)),
            "requested_unicode_name": requested_unicode_name,
            "fallback_name": fallback_name,
            "actual_name": actual_name,
            "unicode_name_set_ok": bool(unicode_name_set_ok and actual_name == requested_unicode_name),
            "unicode_name_error": unicode_name_error,
            "regular_comment": regular_comment,
            "repeatable_comment": repeatable_comment,
            "function_comment": function_comment,
            "repeatable_function_comment": repeatable_function_comment,
            "type_decl": type_decl,
            "type_set_ok": bool(type_set_ok),
            "type_error": type_error,
            "type_text_after_seed": type_text_after_seed,
            "database_path": database_path,
        }
        _stage("u009_seed_done", seed)
        return seed


    def main():
        try:
            _stage("ida_bootstrap_start")
            import ida_auto
            import idaapi
            import ida_loader

            _stage("auto_wait_start")
            ida_auto.auto_wait()
            _stage("auto_wait_done")

            u009_seed = None
            if IDA_API_TEST_MODE == "apply_changes":
                _save_database_for_apply_changes(idaapi, ida_loader)
            if IDA_API_TEST_MODE == "inspect_address":
                u009_seed = _prepare_u009_inspect_address_seed(idaapi, ida_loader)

            if PLUGIN_DIR not in sys.path:
                sys.path.insert(0, PLUGIN_DIR)

            import importlib.util

            plugin_path = str(Path(PLUGIN_DIR) / "ida_script_mcp.py")
            spec = importlib.util.spec_from_file_location("ida_script_mcp_loaded_plugin", plugin_path)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"Cannot load plugin from {plugin_path}")

            _stage("plugin_load_start", {"plugin_path": plugin_path})
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            plugin_instance = plugin_module.PLUGIN_ENTRY()
            globals()["IDA_SCRIPT_MCP_TEST_PLUGIN_INSTANCE"] = plugin_instance
            init_result = plugin_instance.init()
            plugin_instance.run(0)
            _stage("plugin_run_done", {"init_result": int(init_result) if init_result is not None else None})

            port = int(getattr(plugin_module.instance_registry, "port", 0) or 0)
            if port <= 0:
                port = int(getattr(plugin_instance, "port", 13338) or 13338)
            base_url = f"http://127.0.0.1:{port}"

            try:
                input_file_path = idaapi.get_input_file_path()
            except Exception:
                input_file_path = ""
            try:
                database_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
            except Exception:
                database_path = ""

            ready = {
                "status": "ready",
                "base_url": base_url,
                "port": port,
                "dll_path": DLL_PATH,
                "plugin_dir": PLUGIN_DIR,
                "plugin_name": getattr(plugin_module, "PLUGIN_NAME", None),
                "input_file_path": input_file_path,
                "database_path": database_path,
                "instance_id": getattr(plugin_module.instance_registry, "instance_id", None),
                "u009_seed": u009_seed,
            }
            _write_json(READY_PATH, ready)
            _stage("ready_written", ready)
        except Exception as exc:
            error_payload = {
                "status": "failed",
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
            }
            _write_json(READY_PATH, error_payload)
            _stage("bootstrap_failed", error_payload)


    if __name__ == "__main__":
        main()
    '''


    def _stage(name: str, detail: object | None = None) -> None:
        payload = {"timestamp": time.time(), "stage": name}
        if detail is not None:
            payload["detail"] = detail
        with HEARTBEAT_PATH.open("a", encoding="utf-8") as output:
            output.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            output.write("\n")
        print("IDA_API_STAGE=" + json.dumps(payload, ensure_ascii=True, sort_keys=True), flush=True)


    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


    def _ida_user_dir() -> Path:
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise RuntimeError("APPDATA is not set; cannot locate per-user IDA directory")
        return Path(appdata) / "Hex-Rays" / "IDA Pro"


    def _write_bytes_atomic(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_bytes(content)
        os.replace(temp_path, path)


    def _write_json(path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


    def _tail(path: Path, max_chars: int = 12000) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        return text[-max_chars:]


    def _read_process_pipes(process: subprocess.Popen) -> tuple[str, str]:
        try:
            stdout, stderr = process.communicate(timeout=10)
        except Exception:
            stdout, stderr = "", ""
        return stdout or "", stderr or ""


    def _install_plugin_files() -> Path:
        plugin_dir = _ida_user_dir() / "plugins"
        plugin_dir.mkdir(parents=True, exist_ok=True)
        removed_legacy_support_files = []
        for legacy_name in LEGACY_ROOT_SUPPORT_FILES:
            legacy_path = plugin_dir / legacy_name
            if legacy_path.exists() or legacy_path.is_symlink():
                legacy_path.unlink()
                removed_legacy_support_files.append(str(legacy_path))
        remaining_legacy_support_files = [
            str(plugin_dir / legacy_name)
            for legacy_name in LEGACY_ROOT_SUPPORT_FILES
            if (plugin_dir / legacy_name).exists() or (plugin_dir / legacy_name).is_symlink()
        ]
        _stage(
            "legacy_support_cleanup_done",
            {
                "removed": removed_legacy_support_files,
                "remaining": remaining_legacy_support_files,
            },
        )
        if remaining_legacy_support_files:
            raise RuntimeError(
                "Legacy root support files remain in IDA plugins directory: "
                + ", ".join(remaining_legacy_support_files)
            )
        for destination, encoded in FILES_B64.items():
            path = plugin_dir / destination
            content = base64.b64decode(encoded.encode("ascii"))
            _write_bytes_atomic(path, content)
            digest = _sha256(path)
            if digest != EXPECTED_SHA256[destination]:
                raise RuntimeError(f"SHA-256 mismatch for {path}")
            py_compile.compile(str(path), doraise=True)
        return plugin_dir


    def _select_ida_executable(ida_dir: Path) -> Path:
        for candidate in ("ida64.exe", "ida.exe", "idat64.exe", "idat.exe"):
            path = ida_dir / candidate
            if path.is_file():
                return path
        raise RuntimeError(
            "No IDA executable found under "
            + str(ida_dir)
            + "; checked "
            + ", ".join(IDA_EXECUTABLE_CANDIDATES)
        )


    def _write_bootstrap(work_dir: Path, plugin_dir: Path, ready_path: Path, heartbeat_path: Path) -> Path:
        bootstrap_path = work_dir / "ida_api_bootstrap.py"
        bootstrap_text = BOOTSTRAP_TEMPLATE
        replacements = {
            "__READY_PATH_JSON__": json.dumps(str(ready_path)),
            "__HEARTBEAT_PATH_JSON__": json.dumps(str(heartbeat_path)),
            "__PLUGIN_DIR_JSON__": json.dumps(str(plugin_dir)),
            "__BOOTSTRAP_DLL_PATH_JSON__": json.dumps(str(Path(DLL_PATH))),
            "__BOOTSTRAP_IDA_API_TEST_MODE_JSON__": json.dumps(IDA_API_TEST_MODE),
        }
        for placeholder, value in replacements.items():
            bootstrap_text = bootstrap_text.replace(placeholder, value)
        bootstrap_path.write_text(bootstrap_text, encoding="utf-8")
        return bootstrap_path


    def _terminate_process(process: subprocess.Popen | None) -> None:
        if process is None or process.poll() is not None:
            return
        _stage("ida_terminate_start", {"pid": process.pid})
        try:
            process.terminate()
            process.wait(timeout=10)
        except Exception:
            pass
        if process.poll() is None:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        _stage("ida_terminate_done", {"returncode": process.poll()})


    def _json_request(method, base_url, path, payload=None, expected_status=200, timeout=5):
        data = None
        headers = {"Content-Type": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
                status = int(response.status)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            status = int(exc.code)
        body = json.loads(raw) if raw.strip() else {}
        if status != expected_status:
            raise AssertionError(
                f"{method} {path} returned HTTP {status}, expected {expected_status}: {body!r}"
            )
        return {"status": status, "body": body}


    def _check(result, name, ok, detail=None):
        result["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            raise AssertionError(f"check failed: {name}: {detail!r}")


    def _wait_for_ready(process: subprocess.Popen, ready_path: Path, ida_log_path: Path) -> dict:
        deadline = time.monotonic() + IDA_READY_TIMEOUT_SECONDS
        _stage("ida_ready_wait_start", {"timeout_seconds": IDA_READY_TIMEOUT_SECONDS})
        last_status = None
        while time.monotonic() < deadline:
            if ready_path.is_file():
                ready = json.loads(ready_path.read_text(encoding="utf-8"))
                _stage("ida_ready_file_seen", ready)
                if ready.get("status") != "ready":
                    raise RuntimeError("IDA bootstrap failed: " + json.dumps(ready, ensure_ascii=False))
                return ready
            if process.poll() is not None:
                raise RuntimeError(
                    "IDA exited before ready file was created: "
                    + json.dumps(
                        {
                            "returncode": process.returncode,
                            "ida_log_tail": _tail(ida_log_path),
                            "last_status": last_status,
                        },
                        ensure_ascii=False,
                    )
                )
            time.sleep(0.5)
        raise RuntimeError(
            "Timed out waiting for IDA ready file: "
            + json.dumps(
                {
                    "ready_path": str(ready_path),
                    "ida_log_tail": _tail(ida_log_path),
                    "process_alive": process.poll() is None,
                },
                ensure_ascii=False,
            )
        )


    def _health_with_retry(base_url: str) -> dict:
        last_error = None
        _stage("health_wait_start", {"base_url": base_url})
        for _ in range(30):
            try:
                return _json_request("GET", base_url, "/health", expected_status=200, timeout=2)
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.5)
        raise RuntimeError(f"/health did not become reachable: {last_error}")


    def _run_apply_changes_tests(base_url: str, metadata: dict, functions_page: dict, result: dict) -> None:
        functions = functions_page.get("functions") or []
        _check(result, "apply_changes has selected function", bool(functions), functions_page)
        _check(result, "metadata clean before destructive apply", metadata.get("dirty_state_known") is True and metadata.get("dirty") is False, metadata)
        database_sha256 = metadata.get("database_sha256")
        _check(result, "metadata includes database_sha256", bool(database_sha256), metadata)

        target_ea = int(functions[0]["start_ea"])
        target_hex = hex(target_ea)
        patch_target_ea = 0x180002308
        patch_target_hex = hex(patch_target_ea)
        _stage("apply_changes_inspect_before_start", {"address": target_hex})
        inspect_before = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": target_hex, "byte_count": 8},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["inspect_before"] = inspect_before["body"]
        before_body = inspect_before["body"]
        _check(result, "inspect_address resolves selected function", before_body.get("found") is True, before_body)
        before_bytes = before_body.get("bytes_hex") or ""
        _check(result, "inspect_address reads at least one byte", len(before_bytes) >= 2, before_body)
        _stage("apply_changes_inspect_before_done")

        _stage("apply_changes_patch_inspect_before_start", {"address": patch_target_hex})
        patch_inspect_before = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": patch_target_hex, "byte_count": 8},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["patch_inspect_before"] = patch_inspect_before["body"]
        patch_before_body = patch_inspect_before["body"]
        _check(result, "patch target address resolves", patch_before_body.get("found") is True, patch_before_body)
        patch_before_bytes = patch_before_body.get("bytes_hex") or ""
        _check(result, "patch target reads at least one byte", len(patch_before_bytes) >= 2, patch_before_body)
        _stage("apply_changes_patch_inspect_before_done")

        run_id = str(int(time.time()))
        new_name = f"mcp_apply_e2e_{run_id}"
        comment_text = f"mcp regular comment {run_id}"
        func_comment_text = f"mcp function comment {run_id}"
        old_first_byte = before_bytes[:2]
        patch_old_first_byte = patch_before_bytes[:2]
        patch_new_first_byte = "90" if patch_old_first_byte.lower() != "90" else "cc"
        decl = f"int __cdecl {new_name}(void);"
        patch_operation = {
            "op_id": "op-patch-byte",
            "op": "patch_bytes",
            "ea": patch_target_ea,
            "source": "explicit_api",
            "old_bytes_hex": patch_old_first_byte,
            "new_bytes_hex": patch_new_first_byte,
        }
        destructive_operations = [
            {
                "op_id": "op-rename",
                "op": "rename",
                "ea": target_ea,
                "source": "explicit_api",
                "new_name": new_name,
                "flags": 0,
            },
            {
                "op_id": "op-comment",
                "op": "comment",
                "ea": target_ea,
                "source": "explicit_api",
                "text": comment_text,
                "repeatable": False,
            },
            {
                "op_id": "op-function-comment",
                "op": "function_comment",
                "ea": target_ea,
                "source": "explicit_api",
                "text": func_comment_text,
                "repeatable": False,
            },
            patch_operation,
            {
                "op_id": "op-set-type",
                "op": "set_type",
                "ea": target_ea,
                "source": "explicit_api",
                "decl": decl,
                "flags": 0,
            },
        ]
        dry_run_operations = destructive_operations
        change_set = {
            "schema_version": 1,
            "job_id": f"apply-e2e-{run_id}",
            "database_fingerprint": {"database_sha256": database_sha256},
            "operations": dry_run_operations,
        }

        bad_fingerprint = json.loads(json.dumps(change_set))
        bad_fingerprint["database_fingerprint"]["database_sha256"] = "0" * 64
        bad_fingerprint["dry_run"] = False
        _stage("apply_changes_bad_fingerprint_start")
        apply_bad_fingerprint = _json_request(
            "POST",
            base_url,
            "/apply_changes",
            bad_fingerprint,
            expected_status=200,
            timeout=10,
        )
        result["responses"]["apply_bad_fingerprint"] = apply_bad_fingerprint["body"]
        _check(result, "bad fingerprint apply is rejected", apply_bad_fingerprint["body"].get("status") == "rejected", apply_bad_fingerprint["body"])
        _stage("apply_changes_bad_fingerprint_done")

        _stage("apply_changes_dry_run_default_start")
        apply_dry_run_default = _json_request(
            "POST",
            base_url,
            "/apply_changes",
            change_set,
            expected_status=200,
            timeout=10,
        )
        result["responses"]["apply_dry_run_default"] = apply_dry_run_default["body"]
        dry_body = apply_dry_run_default["body"]
        _check(result, "default apply_changes is dry-run", dry_body.get("dry_run") is True, dry_body)
        _check(result, "default dry-run status is ok", dry_body.get("status") == "ok", dry_body)
        _check(result, "default dry-run applies nothing", dry_body.get("applied") == [], dry_body)
        _check(result, "default dry-run skips all operations", len(dry_body.get("skipped") or []) == len(dry_run_operations), dry_body)
        _stage("apply_changes_dry_run_default_done")

        inspect_after_dry_run = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": target_hex, "byte_count": 8},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["inspect_after_dry_run"] = inspect_after_dry_run["body"]
        dry_inspect = inspect_after_dry_run["body"]
        _check(result, "dry-run leaves name unchanged", dry_inspect.get("name") == before_body.get("name"), dry_inspect)
        _check(result, "dry-run leaves first byte unchanged", (dry_inspect.get("bytes_hex") or "")[:2].lower() == old_first_byte.lower(), dry_inspect)
        _check(result, "dry-run leaves comment unchanged", dry_inspect.get("comment") == before_body.get("comment"), dry_inspect)
        _check(result, "dry-run leaves function comment unchanged", dry_inspect.get("function_comment") == before_body.get("function_comment"), dry_inspect)

        patch_inspect_after_dry_run = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": patch_target_hex, "byte_count": 8},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["patch_inspect_after_dry_run"] = patch_inspect_after_dry_run["body"]
        patch_dry_body = patch_inspect_after_dry_run["body"]
        _check(
            result,
            "dry-run leaves patch target byte unchanged",
            (patch_dry_body.get("bytes_hex") or "")[:2].lower() == patch_old_first_byte.lower(),
            patch_dry_body,
        )

        metadata_after_dry_run = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
        result["responses"]["metadata_after_dry_run"] = metadata_after_dry_run["body"]
        _check(result, "metadata stays clean after dry-run", metadata_after_dry_run["body"].get("dirty") is False, metadata_after_dry_run["body"])

        destructive_change_set = json.loads(json.dumps(change_set))
        destructive_change_set["operations"] = destructive_operations
        destructive_change_set["dry_run"] = False
        _stage("apply_changes_destructive_start")
        apply_destructive = _json_request(
            "POST",
            base_url,
            "/apply_changes",
            destructive_change_set,
            expected_status=200,
            timeout=10,
        )
        result["responses"]["apply_destructive"] = apply_destructive["body"]
        apply_body = apply_destructive["body"]
        _check(result, "destructive apply status is ok", apply_body.get("status") == "ok", apply_body)
        _check(result, "destructive apply applies all operations", len(apply_body.get("applied") or []) == len(destructive_operations), apply_body)
        _check(result, "destructive apply has no errors", apply_body.get("errors") == [], apply_body)
        _stage("apply_changes_destructive_done")

        inspect_after_apply = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": target_hex, "byte_count": 8},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["inspect_after_apply"] = inspect_after_apply["body"]
        after_body = inspect_after_apply["body"]
        _check(result, "applied rename is visible", after_body.get("name") == new_name, after_body)
        _check(result, "applied comment is visible", after_body.get("comment") == comment_text, after_body)
        _check(result, "applied function comment is visible", after_body.get("function_comment") == func_comment_text, after_body)

        patch_inspect_after_apply = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": patch_target_hex, "byte_count": 8},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["patch_inspect_after_apply"] = patch_inspect_after_apply["body"]
        patch_after_body = patch_inspect_after_apply["body"]
        _check(
            result,
            "applied patch byte is visible",
            (patch_after_body.get("bytes_hex") or "")[:2].lower() == patch_new_first_byte.lower(),
            patch_after_body,
        )
        type_text = after_body.get("type") or ""
        if new_name not in type_text and "int" not in type_text:
            result.setdefault("warnings", []).append(
                {
                    "name": "applied type text did not contain expected signature fragments",
                    "expected_name": new_name,
                    "decl": decl,
                    "observed_type": type_text,
                }
            )

        metadata_after_apply = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
        result["responses"]["metadata_after_apply"] = metadata_after_apply["body"]
        _check(result, "metadata dirty after destructive apply", metadata_after_apply["body"].get("dirty") is True, metadata_after_apply["body"])

        _stage("apply_changes_rejected_when_dirty_start")
        apply_rejected_when_dirty = _json_request(
            "POST",
            base_url,
            "/apply_changes",
            destructive_change_set,
            expected_status=200,
            timeout=10,
        )
        result["responses"]["apply_rejected_when_dirty"] = apply_rejected_when_dirty["body"]
        dirty_body = apply_rejected_when_dirty["body"]
        dirty_message = str(dirty_body.get("message") or "").lower()
        _check(result, "second destructive apply is rejected when dirty", dirty_body.get("status") == "rejected", dirty_body)
        _check(result, "dirty rejection message mentions unsaved or dirty", "unsaved" in dirty_message or "dirty" in dirty_message, dirty_body)
        _stage("apply_changes_rejected_when_dirty_done")


    def _has_non_ascii(text) -> bool:
        if text is None:
            return False
        return any(ord(ch) > 127 for ch in str(text))


    def _run_inspect_address_tests(base_url: str, seed: dict, metadata: dict, result: dict) -> None:
        result["u009_seed"] = seed
        _check(
            result,
            "U009 seed is present",
            isinstance(seed, dict) and bool(seed.get("target_hex")),
            seed,
        )
        target_hex = str(seed["target_hex"])
        target_ea = int(seed["target_ea"])

        def inspect(key: str, payload: dict) -> dict:
            _stage(f"u009_{key}_start", payload)
            response = _json_request(
                "POST",
                base_url,
                "/inspect_address",
                payload,
                expected_status=200,
                timeout=10,
            )
            body = response["body"]
            result["responses"][key] = body
            _stage(f"u009_{key}_done")
            return body

        invalid_address = inspect("inspect_invalid_address", {"address": "not-an-address"})
        _check(
            result,
            "U009 invalid address is structured not-found",
            invalid_address.get("found") is False,
            invalid_address,
        )
        _check(
            result,
            "U009 invalid address reports parse error",
            "parse" in str(invalid_address.get("error") or "").lower(),
            invalid_address,
        )

        missing_target = inspect("inspect_missing_target", {})
        _check(
            result,
            "U009 missing address/name is structured not-found",
            missing_target.get("found") is False,
            missing_target,
        )
        _check(
            result,
            "U009 missing address/name asks for target",
            "address" in str(missing_target.get("error") or "").lower(),
            missing_target,
        )

        byte_count_zero = inspect("inspect_byte_count_zero", {"address": target_hex, "byte_count": 0})
        _check(
            result,
            "U009 byte_count=0 clamps to one",
            byte_count_zero.get("query", {}).get("byte_count") == 1,
            byte_count_zero,
        )
        _check(
            result,
            "U009 byte_count=0 still reads one byte",
            isinstance(byte_count_zero.get("bytes_hex"), str)
            and len(byte_count_zero.get("bytes_hex") or "") == 2,
            byte_count_zero,
        )

        byte_count_negative = inspect(
            "inspect_byte_count_negative", {"address": target_hex, "byte_count": -10}
        )
        _check(
            result,
            "U009 negative byte_count clamps to one",
            byte_count_negative.get("query", {}).get("byte_count") == 1,
            byte_count_negative,
        )
        _check(
            result,
            "U009 negative byte_count still reads one byte",
            isinstance(byte_count_negative.get("bytes_hex"), str)
            and len(byte_count_negative.get("bytes_hex") or "") == 2,
            byte_count_negative,
        )

        byte_count_huge = inspect(
            "inspect_byte_count_huge", {"address": target_hex, "byte_count": 999999}
        )
        huge_bytes = byte_count_huge.get("bytes_hex") or ""
        _check(
            result,
            "U009 huge byte_count clamps to 64",
            byte_count_huge.get("query", {}).get("byte_count") == 64,
            byte_count_huge,
        )
        _check(
            result,
            "U009 huge byte_count returns bounded bytes",
            isinstance(huge_bytes, str) and 2 <= len(huge_bytes) <= 128,
            byte_count_huge,
        )

        if seed.get("data_hex"):
            data_address = inspect("inspect_data_address", {"address": seed["data_hex"], "byte_count": 8})
            _check(result, "U009 data address resolves", data_address.get("found") is True, data_address)
            _check(
                result,
                "U009 data address returns requested ea",
                int(data_address.get("ea")) == int(seed["data_ea"]),
                data_address,
            )
            _check(
                result,
                "U009 data address reads bytes",
                isinstance(data_address.get("bytes_hex"), str)
                and len(data_address.get("bytes_hex") or "") >= 2,
                data_address,
            )
        else:
            result.setdefault("warnings", []).append(
                {"name": "U009 data address selection skipped", "seed": seed}
            )

        middle_address = inspect(
            "inspect_instruction_middle",
            {"address": seed["instruction_middle_hex"], "byte_count": 8},
        )
        _check(
            result,
            "U009 instruction-middle address resolves",
            middle_address.get("found") is True,
            middle_address,
        )
        _check(
            result,
            "U009 instruction-middle returns requested ea",
            int(middle_address.get("ea")) == int(seed["instruction_middle_ea"]),
            middle_address,
        )
        _check(
            result,
            "U009 selected an actual instruction tail byte",
            seed.get("instruction_middle_is_tail") is True,
            seed,
        )
        _check(
            result,
            "U009 instruction-middle reads bytes",
            isinstance(middle_address.get("bytes_hex"), str)
            and len(middle_address.get("bytes_hex") or "") >= 2,
            middle_address,
        )

        unmapped_address = inspect(
            "inspect_unmapped_address", {"address": seed["unmapped_hex"], "byte_count": 8}
        )
        _check(
            result,
            "U009 unmapped address remains structured",
            unmapped_address.get("found") is True,
            unmapped_address,
        )
        _check(
            result,
            "U009 unmapped address returns requested ea",
            int(unmapped_address.get("ea")) == int(seed["unmapped_ea"]),
            unmapped_address,
        )
        _check(
            result,
            "U009 unmapped address has no bytes",
            unmapped_address.get("bytes_hex") is None,
            unmapped_address,
        )

        seeded_address = inspect("inspect_seeded_unicode_address", {"address": target_hex, "byte_count": 8})
        _check(result, "U009 seeded address resolves", seeded_address.get("found") is True, seeded_address)
        _check(
            result,
            "U009 seeded address returns target ea",
            int(seeded_address.get("ea")) == target_ea,
            seeded_address,
        )
        _check(
            result,
            "U009 seeded name is returned",
            seeded_address.get("name") == seed.get("actual_name"),
            seeded_address,
        )
        _check(
            result,
            "U009 Unicode regular comment is preserved",
            seeded_address.get("comment") == seed.get("regular_comment")
            and _has_non_ascii(seeded_address.get("comment")),
            seeded_address,
        )
        _check(
            result,
            "U009 Unicode repeatable comment is preserved",
            seeded_address.get("repeatable_comment") == seed.get("repeatable_comment")
            and _has_non_ascii(seeded_address.get("repeatable_comment")),
            seeded_address,
        )
        _check(
            result,
            "U009 Unicode function comment is preserved",
            seeded_address.get("function_comment") == seed.get("function_comment")
            and _has_non_ascii(seeded_address.get("function_comment")),
            seeded_address,
        )
        _check(
            result,
            "U009 Unicode repeatable function comment is preserved",
            seeded_address.get("repeatable_function_comment")
            == seed.get("repeatable_function_comment")
            and _has_non_ascii(seeded_address.get("repeatable_function_comment")),
            seeded_address,
        )
        if seed.get("type_set_ok"):
            _check(
                result,
                "U009 type text is returned",
                isinstance(seeded_address.get("type"), str) and bool(seeded_address.get("type")),
                seeded_address,
            )
        else:
            result.setdefault("warnings", []).append(
                {"name": "U009 type seeding was not accepted by IDA", "seed": seed}
            )
        if seed.get("unicode_name_set_ok"):
            _check(
                result,
                "U009 Unicode name is preserved",
                seeded_address.get("name") == seed.get("requested_unicode_name")
                and _has_non_ascii(seeded_address.get("name")),
                seeded_address,
            )
        else:
            result.setdefault("warnings", []).append(
                {
                    "name": "U009 requested Unicode name was not accepted by IDA; tested fallback name lookup instead",
                    "requested_unicode_name": seed.get("requested_unicode_name"),
                    "actual_name": seed.get("actual_name"),
                    "unicode_name_error": seed.get("unicode_name_error"),
                }
            )

        by_name = inspect("inspect_by_seeded_name", {"name": seed.get("actual_name"), "byte_count": 8})
        _check(result, "U009 name lookup resolves seeded name", by_name.get("found") is True, by_name)
        _check(
            result,
            "U009 name lookup returns target ea",
            int(by_name.get("ea")) == target_ea,
            by_name,
        )
        _check(
            result,
            "U009 name lookup bytes match address lookup",
            by_name.get("bytes_hex") == seeded_address.get("bytes_hex"),
            by_name,
        )

        missing_name = inspect("inspect_missing_unicode_name", {"name": "U009_不存在的符号"})
        _check(
            result,
            "U009 missing Unicode name is structured not-found",
            missing_name.get("found") is False,
            missing_name,
        )
        _check(
            result,
            "U009 missing Unicode name reports resolve error",
            "resolve" in str(missing_name.get("error") or "").lower(),
            missing_name,
        )

        metadata_after = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
        result["responses"]["u009_metadata_after"] = metadata_after["body"]
        _check(
            result,
            "U009 inspect_address does not mark apply_changes mutation",
            metadata_after["body"].get("apply_changes_mutated") is False,
            metadata_after["body"],
        )
        if metadata_after["body"].get("dirty_state_known") is True:
            _check(
                result,
                "U009 seeded database remains clean after read-only inspect calls",
                metadata_after["body"].get("dirty") is False,
                metadata_after["body"],
            )


    def _run_external_api_tests(ready: dict) -> dict:
        base_url = str(ready["base_url"])
        result = {
            "status": "running",
            "mode": IDA_API_TEST_MODE,
            "dll_path": DLL_PATH,
            "ready": ready,
            "checks": [],
            "responses": {},
            "warnings": [],
            "selected_function": None,
        }

        _stage("health_start", {"base_url": base_url})
        health = _health_with_retry(base_url)
        result["responses"]["health"] = health["body"]
        _check(result, "health reports plugin name", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])
        _stage("health_done")

        _stage("metadata_start")
        metadata = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
        result["responses"]["metadata"] = metadata["body"]
        _check(result, "metadata includes input path", bool(metadata["body"].get("input_file_path")), metadata["body"])
        _check(result, "metadata includes database path", "database_path" in metadata["body"], metadata["body"])
        _check(result, "metadata includes dirty state", "dirty_state_known" in metadata["body"], metadata["body"])
        _stage("metadata_done")

        _stage("functions_start")
        functions_page = _json_request(
            "POST",
            base_url,
            "/functions",
            {"offset": 0, "limit": 20, "include_thunks": True, "include_library_functions": True},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["functions_page"] = functions_page["body"]
        functions = functions_page["body"].get("functions") or []
        _check(result, "functions endpoint returns a list", isinstance(functions, list), functions_page["body"])
        _check(result, "functions endpoint returns at least one function", len(functions) > 0, functions_page["body"])
        _check(result, "functions pagination respects limit", functions_page["body"].get("returned", 0) <= 20, functions_page["body"])

        functions_limit_one = _json_request(
            "POST",
            base_url,
            "/functions",
            {"offset": 0, "limit": 1, "include_thunks": True, "include_library_functions": True},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["functions_limit_one"] = functions_limit_one["body"]
        _check(result, "functions limit=1 returns at most one", functions_limit_one["body"].get("returned", 0) <= 1, functions_limit_one["body"])

        total_functions = int(functions_page["body"].get("total", 0) or 0)
        _stage("functions_offset_beyond_total_start", {"total": total_functions})
        functions_offset_beyond = _json_request(
            "POST",
            base_url,
            "/functions",
            {
                "offset": total_functions + 1000,
                "limit": 5,
                "include_thunks": True,
                "include_library_functions": True,
            },
            expected_status=200,
            timeout=10,
        )
        result["responses"]["functions_offset_beyond_total"] = functions_offset_beyond["body"]
        _check(
            result,
            "functions offset beyond total returns empty page",
            functions_offset_beyond["body"].get("returned", -1) == 0
            and functions_offset_beyond["body"].get("functions") == [],
            functions_offset_beyond["body"],
        )
        _stage("functions_offset_beyond_total_done")
        _stage("functions_done")

        first_function = functions[0]
        result["selected_function"] = first_function
        start_ea = int(first_function["start_ea"])
        start_ea_hex = hex(start_ea)
        first_name = first_function.get("name") or ""

        if first_name:
            _stage("functions_filter_start", {"name": first_name})
            name_filter = first_name[: max(1, min(4, len(first_name)))]
            functions_filter = _json_request(
                "POST",
                base_url,
                "/functions",
                {
                    "offset": 0,
                    "limit": 5,
                    "name_contains": name_filter,
                    "include_thunks": True,
                    "include_library_functions": True,
                },
                expected_status=200,
                timeout=10,
            )
            result["responses"]["functions_filter"] = functions_filter["body"]
            _check(result, "functions name filter is accepted", "functions" in functions_filter["body"], functions_filter["body"])
            _stage("functions_filter_done")

        if IDA_API_TEST_MODE == "basic":
            result["status"] = "passed"
            return result

        if IDA_API_TEST_MODE == "inspect_address":
            _stage("u009_inspect_address_tests_start", {"address": start_ea_hex})
            _run_inspect_address_tests(base_url, ready.get("u009_seed") or {}, metadata["body"], result)
            _stage("u009_inspect_address_tests_done")
            result["status"] = "passed"
            return result

        if IDA_API_TEST_MODE == "apply_changes":
            _stage("apply_changes_tests_start", {"address": start_ea_hex})
            _run_apply_changes_tests(base_url, metadata["body"], functions_page["body"], result)
            _stage("apply_changes_tests_done")
            result["status"] = "passed"
            return result

        _stage("decompile_start", {"address": start_ea_hex})
        decompile = _json_request(
            "POST",
            base_url,
            "/decompile",
            {"address": start_ea_hex, "include_disassembly": True},
            expected_status=200,
            timeout=30,
        )
        result["responses"]["decompile"] = decompile["body"]
        _check(result, "decompile resolves selected function", decompile["body"].get("found") is True, decompile["body"])
        _check(result, "decompile includes disassembly", isinstance(decompile["body"].get("disassembly"), list), decompile["body"])
        _stage("decompile_done")

        _stage("decompile_bad_address_start")
        decompile_bad = _json_request(
            "POST",
            base_url,
            "/decompile",
            {"address": "not-an-address", "include_disassembly": True},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["decompile_bad_address"] = decompile_bad["body"]
        _check(result, "decompile bad address returns structured not found", decompile_bad["body"].get("found") is False, decompile_bad["body"])
        _stage("decompile_bad_address_done")

        for direction in ("to", "from"):
            _stage(f"xrefs_{direction}_start", {"address": start_ea_hex})
            xrefs = _json_request(
                "POST",
                base_url,
                "/xrefs",
                {"address": start_ea_hex, "direction": direction, "xref_kind": "all", "limit": 20},
                expected_status=200,
                timeout=10,
            )
            result["responses"][f"xrefs_{direction}"] = xrefs["body"]
            _check(result, f"xrefs-{direction} resolves selected target", xrefs["body"].get("found") is True, xrefs["body"])
            _check(result, f"xrefs-{direction} returns a list", isinstance(xrefs["body"].get("xrefs"), list), xrefs["body"])
            _stage(f"xrefs_{direction}_done")

        _stage("xrefs_invalid_direction_start")
        xrefs_invalid = _json_request(
            "POST",
            base_url,
            "/xrefs",
            {"address": start_ea_hex, "direction": "sideways", "xref_kind": "all", "limit": 20},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["xrefs_invalid_direction"] = xrefs_invalid["body"]
        _check(result, "xrefs invalid direction is structured", bool(xrefs_invalid["body"].get("error")), xrefs_invalid["body"])
        _stage("xrefs_invalid_direction_done")

        _stage("xrefs_invalid_kind_start")
        xrefs_invalid_kind = _json_request(
            "POST",
            base_url,
            "/xrefs",
            {"address": start_ea_hex, "direction": "from", "xref_kind": "nonsense", "limit": 20},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["xrefs_invalid_kind"] = xrefs_invalid_kind["body"]
        _check(result, "xrefs invalid kind is structured", bool(xrefs_invalid_kind["body"].get("error")), xrefs_invalid_kind["body"])
        _stage("xrefs_invalid_kind_done")

        _stage("execute_disabled_start")
        execute_disabled = _json_request(
            "POST",
            base_url,
            "/execute",
            {"code": "print('must not run in GUI')"},
            expected_status=410,
            timeout=10,
        )
        result["responses"]["execute_disabled"] = execute_disabled["body"]
        _check(result, "GUI /execute is disabled", execute_disabled["body"].get("status") == "rejected", execute_disabled["body"])
        _stage("execute_disabled_done")

        _stage("not_found_start")
        not_found = _json_request("GET", base_url, "/does-not-exist", expected_status=404, timeout=5)
        result["responses"]["not_found"] = not_found["body"]
        _check(result, "unknown GET route returns 404", bool(not_found["body"].get("error")), not_found["body"])
        _stage("not_found_done")

        result["status"] = "passed"
        return result


    def main() -> int:
        ida_dir = Path(IDA_DIR)
        dll_path = Path(DLL_PATH)
        work_dir = WORK_DIR
        ready_path = READY_PATH
        heartbeat_path = HEARTBEAT_PATH
        result_path = RESULT_PATH
        ida_log_path = IDA_LOG_PATH
        stdout = ""
        stderr = ""
        process = None
        result: dict = {
            "status": "failed",
            "mode": IDA_API_TEST_MODE,
            "dll_path": DLL_PATH,
            "work_dir": str(work_dir),
            "checks": [],
        }

        try:
            _stage("validate_inputs_start", {"ida_dir": str(ida_dir), "dll_path": str(dll_path)})
            if not ida_dir.is_dir():
                raise RuntimeError(f"IDA directory does not exist: {ida_dir}")
            if not dll_path.is_file():
                raise RuntimeError(f"DLL path does not exist: {dll_path}")
            if IDA_API_TEST_MODE not in {"basic", "full", "apply_changes", "inspect_address"}:
                raise RuntimeError(f"Unsupported IDA API test mode: {IDA_API_TEST_MODE!r}")

            plugin_dir = _install_plugin_files()
            ida_executable = _select_ida_executable(ida_dir)
            database_path = work_dir / (dll_path.stem + ".i64")
            bootstrap_path = _write_bootstrap(work_dir, plugin_dir, ready_path, heartbeat_path)
            _stage("validate_inputs_done", {"ida_executable": str(ida_executable), "plugin_dir": str(plugin_dir)})

            command = [
                str(ida_executable),
                "-A",
                f"-L{ida_log_path}",
                f"-S{bootstrap_path}",
                f"-o{database_path}",
                str(dll_path),
            ]
            _stage("ida_start", {"command": command, "work_dir": str(work_dir)})
            process = subprocess.Popen(
                command,
                cwd=str(work_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            ready = _wait_for_ready(process, ready_path, ida_log_path)
            result = _run_external_api_tests(ready)
            result.update(
                {
                    "ida_executable": str(ida_executable),
                    "ida_log_path": str(ida_log_path),
                    "work_dir": str(work_dir),
                    "database_path": str(database_path),
                }
            )
            _stage("api_tests_done", {"status": result.get("status")})
        except Exception as exc:
            result["status"] = "failed"
            result["failed_stage"] = _tail(heartbeat_path, max_chars=2000)
            result["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            }
        finally:
            _terminate_process(process)
            if process is not None:
                stdout, stderr = _read_process_pipes(process)
                result["ida_returncode"] = process.returncode
            result.update(
                {
                    "ida_log_tail": _tail(ida_log_path),
                    "heartbeat_tail": _tail(heartbeat_path),
                    "stdout_tail": stdout[-4000:],
                    "stderr_tail": stderr[-4000:],
                }
            )
            _write_json(result_path, result)
            print("IDA_PLUGIN_API_TEST_RESULT=" + json.dumps(result, ensure_ascii=True, sort_keys=True), flush=True)

        return 0 if result.get("status") == "passed" else 1


    if __name__ == "__main__":
        try:
            raise SystemExit(main())
        except Exception as exc:
            print(
                "IDA_PLUGIN_API_TEST_ERROR="
                + json.dumps(
                    {
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "traceback": traceback.format_exc(),
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            raise SystemExit(1)
    """
).lstrip()


if __name__ == "__main__":  # pragma: no cover
    main()
