"""IDA Pro plugin for IDA Script MCP.

The plugin runs inside IDA Pro and exposes a small local HTTP API that the MCP
server can call. High-frequency read operations such as listing functions,
decompiling a function, and reading xrefs are exposed as dedicated endpoints so
LLMs do not need to synthesize IDAPython for every common workflow.
"""

from __future__ import annotations

import ast
import io
import json
import os
import queue
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import idaapi
    import ida_kernwin
    import idc

    HAS_IDA = True
except ImportError:
    HAS_IDA = False

PLUGIN_NAME = "IDA-Script-MCP"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13338
MAX_PORT_RANGE = 100
MAX_DISASSEMBLY_LINES = 1000

INSTANCE_INFO_FILE = Path.home() / ".ida_script_mcp_instances.json"
INSTANCE_LOCK = threading.Lock()


def get_instance_id() -> str:
    """Get a stable instance id for the current IDA process."""
    if HAS_IDA:
        try:
            db_path = idaapi.get_input_file_path()
            if db_path:
                db_name = os.path.basename(db_path)
                return f"{os.getpid()}_{db_name}"
        except Exception:
            pass
    return str(os.getpid())


class InstanceRegistry:
    """Registry for tracking multiple IDA instances."""

    def __init__(self):
        self.instance_id = get_instance_id()
        self.port: Optional[int] = None
        self.host = DEFAULT_HOST
        self.database: Optional[str] = None

    def _load_instances(self) -> dict[str, Any]:
        try:
            if INSTANCE_INFO_FILE.exists():
                with open(INSTANCE_INFO_FILE, "r", encoding="utf-8") as handle:
                    return json.load(handle)
        except Exception:
            pass
        return {}

    def _save_instances(self, instances: dict[str, Any]) -> None:
        try:
            with open(INSTANCE_INFO_FILE, "w", encoding="utf-8") as handle:
                json.dump(instances, handle, indent=2, ensure_ascii=False)
        except Exception as exc:
            print(f"[{PLUGIN_NAME}] Warning: Failed to save instance info: {exc}")

    def register(self, port: int) -> None:
        self.port = port
        db_info = _collect_database_info()
        self.database = db_info.get("database")

        with INSTANCE_LOCK:
            instances = self._load_instances()
            instances[self.instance_id] = {
                "pid": os.getpid(),
                "port": port,
                "host": self.host,
                **db_info,
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self._save_instances(instances)
            print(f"[{PLUGIN_NAME}] Registered instance: {self.instance_id}")

    def unregister(self) -> None:
        with INSTANCE_LOCK:
            instances = self._load_instances()
            if self.instance_id in instances:
                del instances[self.instance_id]
                self._save_instances(instances)
                print(f"[{PLUGIN_NAME}] Unregistered instance: {self.instance_id}")

    @staticmethod
    def list_instances() -> dict[str, Any]:
        with INSTANCE_LOCK:
            try:
                if INSTANCE_INFO_FILE.exists():
                    with open(INSTANCE_INFO_FILE, "r", encoding="utf-8") as handle:
                        instances = json.load(handle)
                else:
                    return {}
            except Exception:
                return {}

            alive_instances = {}
            for instance_id, info in instances.items():
                pid = info.get("pid")
                if pid:
                    try:
                        os.kill(pid, 0)
                        alive_instances[instance_id] = info
                    except (OSError, ProcessLookupError):
                        pass

            if len(alive_instances) != len(instances):
                try:
                    with open(INSTANCE_INFO_FILE, "w", encoding="utf-8") as handle:
                        json.dump(alive_instances, handle, indent=2, ensure_ascii=False)
                except Exception:
                    pass

            return alive_instances


instance_registry = InstanceRegistry()


def execute_on_main_thread(func, *args, write: bool = False, **kwargs):
    """Execute a function on IDA's main thread and return the result."""
    if not HAS_IDA or not hasattr(idaapi, "execute_sync"):
        return func(*args, **kwargs)

    result_queue: queue.Queue[Any] = queue.Queue()

    def wrapper() -> int:
        try:
            result = func(*args, **kwargs)
            result_queue.put(("success", result))
        except Exception as exc:
            result_queue.put(("error", str(exc), traceback.format_exc()))
        return 1

    flag_name = "MFF_WRITE" if write else "MFF_READ"
    flags = getattr(idaapi, flag_name, getattr(idaapi, "MFF_WRITE", 0))
    idaapi.execute_sync(wrapper, flags)
    result = result_queue.get()

    if result[0] == "error":
        raise RuntimeError(f"{result[1]}\n{result[2]}")
    return result[1]


def _make_jsonable(value: Any, depth: int = 0) -> Any:
    """Convert arbitrary Python values into JSON-serializable structures."""
    if depth > 6:
        return str(value)

    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {
            str(key): _make_jsonable(inner_value, depth + 1)
            for key, inner_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [_make_jsonable(item, depth + 1) for item in value]

    try:
        return _make_jsonable(vars(value), depth + 1)
    except Exception:
        return str(value)


def execute_python_script(
    code: Optional[str] = None,
    script_path: Optional[str] = None,
    capture_output: bool = True,
) -> dict[str, Any]:
    """Execute Python code or a script file in the IDA context."""
    if code is None and script_path is None:
        return {
            "result": None,
            "stdout": "",
            "stderr": "Error: Either 'code' or 'script_path' must be provided",
        }

    if script_path is not None:
        try:
            with open(script_path, "r", encoding="utf-8") as handle:
                code = handle.read()
        except Exception as exc:
            return {
                "result": None,
                "stdout": "",
                "stderr": f"Error reading script file: {exc}",
            }

    stdout_capture = io.StringIO() if capture_output else None
    stderr_capture = io.StringIO() if capture_output else None
    old_stdout = sys.stdout if capture_output else None
    old_stderr = sys.stderr if capture_output else None

    try:
        if capture_output:
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture

        exec_globals = _build_ida_globals()
        exec_locals: dict[str, Any] = {}
        result_value: Any = None

        try:
            tree = ast.parse(code or "")
        except SyntaxError:
            exec(code or "", exec_globals, exec_locals)
            exec_globals.update(exec_locals)
            if "result" in exec_locals:
                result_value = exec_locals["result"]
            elif exec_locals:
                last_key = list(exec_locals.keys())[-1]
                result_value = exec_locals[last_key]
        else:
            if not tree.body:
                result_value = None
            elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                result_value = eval(code or "", exec_globals)
            elif isinstance(tree.body[-1], ast.Expr):
                if len(tree.body) > 1:
                    exec_tree = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(compile(exec_tree, "<string>", "exec"), exec_globals, exec_locals)
                    exec_globals.update(exec_locals)
                eval_tree = ast.Expression(body=tree.body[-1].value)
                result_value = eval(compile(eval_tree, "<string>", "eval"), exec_globals)
            else:
                exec(code or "", exec_globals, exec_locals)
                exec_globals.update(exec_locals)
                if "result" in exec_locals:
                    result_value = exec_locals["result"]
                elif exec_locals:
                    last_key = list(exec_locals.keys())[-1]
                    result_value = exec_locals[last_key]

        stdout_text = stdout_capture.getvalue() if stdout_capture else ""
        stderr_text = stderr_capture.getvalue() if stderr_capture else ""

        return {
            "instance_id": instance_registry.instance_id,
            "port": instance_registry.port,
            "result": _make_jsonable(result_value),
            "stdout": stdout_text,
            "stderr": stderr_text,
        }
    except Exception:
        return {
            "instance_id": instance_registry.instance_id,
            "port": instance_registry.port,
            "result": None,
            "stdout": stdout_capture.getvalue() if stdout_capture else "",
            "stderr": traceback.format_exc(),
        }
    finally:
        if capture_output:
            sys.stdout = old_stdout
            sys.stderr = old_stderr


def _build_ida_globals() -> dict[str, Any]:
    """Build the global namespace for script execution with IDA modules."""

    def lazy_import(module_name: str):
        try:
            return __import__(module_name)
        except Exception:
            return None

    if not HAS_IDA:
        return {"__builtins__": __builtins__}

    return {
        "__builtins__": __builtins__,
        "idaapi": idaapi,
        "idc": idc,
        "idautils": lazy_import("idautils"),
        "ida_allins": lazy_import("ida_allins"),
        "ida_auto": lazy_import("ida_auto"),
        "ida_bitrange": lazy_import("ida_bitrange"),
        "ida_bytes": lazy_import("ida_bytes"),
        "ida_dbg": lazy_import("ida_dbg"),
        "ida_dirtree": lazy_import("ida_dirtree"),
        "ida_diskio": lazy_import("ida_diskio"),
        "ida_entry": lazy_import("ida_entry"),
        "ida_expr": lazy_import("ida_expr"),
        "ida_fixup": lazy_import("ida_fixup"),
        "ida_fpro": lazy_import("ida_fpro"),
        "ida_frame": lazy_import("ida_frame"),
        "ida_funcs": lazy_import("ida_funcs"),
        "ida_gdl": lazy_import("ida_gdl"),
        "ida_graph": lazy_import("ida_graph"),
        "ida_hexrays": lazy_import("ida_hexrays"),
        "ida_ida": lazy_import("ida_ida"),
        "ida_idd": lazy_import("ida_idd"),
        "ida_idp": lazy_import("ida_idp"),
        "ida_ieee": lazy_import("ida_ieee"),
        "ida_kernwin": ida_kernwin,
        "ida_libfuncs": lazy_import("ida_libfuncs"),
        "ida_lines": lazy_import("ida_lines"),
        "ida_loader": lazy_import("ida_loader"),
        "ida_merge": lazy_import("ida_merge"),
        "ida_mergemod": lazy_import("ida_mergemod"),
        "ida_moves": lazy_import("ida_moves"),
        "ida_nalt": lazy_import("ida_nalt"),
        "ida_name": lazy_import("ida_name"),
        "ida_netnode": lazy_import("ida_netnode"),
        "ida_offset": lazy_import("ida_offset"),
        "ida_pro": lazy_import("ida_pro"),
        "ida_problems": lazy_import("ida_problems"),
        "ida_range": lazy_import("ida_range"),
        "ida_regfinder": lazy_import("ida_regfinder"),
        "ida_registry": lazy_import("ida_registry"),
        "ida_search": lazy_import("ida_search"),
        "ida_segment": lazy_import("ida_segment"),
        "ida_segregs": lazy_import("ida_segregs"),
        "ida_srclang": lazy_import("ida_srclang"),
        "ida_strlist": lazy_import("ida_strlist"),
        "ida_struct": lazy_import("ida_struct"),
        "ida_tryblks": lazy_import("ida_tryblks"),
        "ida_typeinf": lazy_import("ida_typeinf"),
        "ida_ua": lazy_import("ida_ua"),
        "ida_undo": lazy_import("ida_undo"),
        "ida_xref": lazy_import("ida_xref"),
        "ida_enum": lazy_import("ida_enum"),
    }


def _badaddr() -> int:
    return int(getattr(idaapi, "BADADDR", 0xFFFFFFFFFFFFFFFF)) if HAS_IDA else -1


def _parse_address(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value

    text = str(value).strip()
    if not text:
        return None

    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.lower().endswith("h") and all(ch in "0123456789abcdefABCDEF" for ch in text[:-1]):
            return int(text[:-1], 16)
        if all(ch in "0123456789abcdefABCDEF" for ch in text) and any(
            ch in "abcdefABCDEF" for ch in text
        ):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _symbol_name(ea: int) -> str:
    try:
        func_name = idc.get_func_name(ea)
        if func_name:
            return func_name
    except Exception:
        pass
    try:
        symbol_name = idc.get_name(ea, 0)
        if symbol_name:
            return symbol_name
    except Exception:
        pass
    return ""


def _segment_name(ea: int) -> Optional[str]:
    try:
        segname = idc.get_segm_name(ea)
        return segname or None
    except Exception:
        return None


def _resolve_target_ea(address: Optional[str] = None, name: Optional[str] = None) -> tuple[Optional[int], Optional[str]]:
    if address:
        ea = _parse_address(address)
        if ea is None:
            return None, f"Could not parse address: {address!r}"
        return ea, None

    if not name:
        return None, "Provide either 'address' or 'name'."

    try:
        ea = idc.get_name_ea_simple(name)
        if ea is not None and int(ea) != _badaddr():
            return int(ea), None
    except Exception:
        pass

    try:
        ea = idaapi.get_name_ea(_badaddr(), name)
        if ea is not None and int(ea) != _badaddr():
            return int(ea), None
    except Exception:
        pass

    return None, f"Could not resolve name: {name!r}"


def _resolve_function(address: Optional[str] = None, name: Optional[str] = None):
    try:
        import ida_funcs
    except Exception as exc:
        return None, None, f"IDA function APIs are unavailable: {exc}"

    ea, error = _resolve_target_ea(address=address, name=name)
    if error:
        return None, None, error

    func = ida_funcs.get_func(ea)
    if func is None:
        return None, ea, f"No function found for address {hex(int(ea))}."
    return func, ea, None


def _collect_database_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "instance_id": instance_registry.instance_id,
        "port": instance_registry.port,
        "database": None,
        "database_path": None,
        "platform": sys.platform,
    }

    if not HAS_IDA:
        return info

    try:
        info["database"] = idaapi.get_root_filename()
    except Exception:
        pass
    try:
        info["database_path"] = idaapi.get_input_file_path()
    except Exception:
        pass
    try:
        info["imagebase"] = int(idaapi.get_imagebase())
    except Exception:
        pass

    try:
        inf = idaapi.get_inf_structure()
    except Exception:
        inf = None

    if inf is not None:
        try:
            if inf.is_64bit():
                info["bitness"] = 64
            elif inf.is_32bit():
                info["bitness"] = 32
            elif inf.is_16bit():
                info["bitness"] = 16
        except Exception:
            pass

        try:
            procname = getattr(inf, "procname", None)
            if isinstance(procname, bytes):
                procname = procname.decode(errors="ignore").rstrip("\x00")
            if procname:
                info["processor"] = str(procname)
        except Exception:
            pass

        for attr_name in ("min_ea", "max_ea"):
            try:
                attr_value = getattr(inf, attr_name)
                if attr_value is not None:
                    info[attr_name] = int(attr_value)
            except Exception:
                pass

    try:
        import idautils

        info["function_count"] = sum(1 for _ in idautils.Functions())
    except Exception:
        pass

    try:
        import idautils

        info["segment_count"] = sum(1 for _ in idautils.Segments())
    except Exception:
        pass

    return info


def _function_summary(func) -> dict[str, Any]:
    start_ea = int(func.start_ea)
    end_ea = int(func.end_ea)
    flags = 0
    try:
        flags = idc.get_func_flags(start_ea)
    except Exception:
        pass

    thunk_mask = int(getattr(idc, "FUNC_THUNK", 0))
    library_mask = int(getattr(idc, "FUNC_LIB", 0))

    return {
        "start_ea": start_ea,
        "end_ea": end_ea,
        "size": max(0, end_ea - start_ea),
        "name": _symbol_name(start_ea),
        "segment": _segment_name(start_ea),
        "is_thunk": bool(flags & thunk_mask),
        "is_library": bool(flags & library_mask),
    }


def list_functions_data(
    offset: int = 0,
    limit: int = 200,
    name_contains: Optional[str] = None,
    segment: Optional[str] = None,
    include_thunks: bool = False,
    include_library_functions: bool = False,
) -> dict[str, Any]:
    """List functions in the current IDA database."""
    result = _collect_database_info()
    result.update(
        {
            "offset": offset,
            "limit": limit,
            "name_contains": name_contains,
            "segment_filter": segment,
            "include_thunks": include_thunks,
            "include_library_functions": include_library_functions,
        }
    )

    if not HAS_IDA:
        result.update({"total": 0, "returned": 0, "truncated": False, "functions": []})
        return result

    try:
        import idautils
        import ida_funcs
    except Exception as exc:
        result.update({"error": f"IDA function APIs are unavailable: {exc}", "functions": []})
        return result

    name_filter = name_contains.lower() if name_contains else None
    selected_functions: list[dict[str, Any]] = []

    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        if func is None:
            continue

        summary = _function_summary(func)
        if summary["is_thunk"] and not include_thunks:
            continue
        if summary["is_library"] and not include_library_functions:
            continue
        if name_filter and name_filter not in (summary["name"] or "").lower():
            continue
        if segment and summary["segment"] != segment:
            continue

        selected_functions.append(summary)

    total = len(selected_functions)
    page = selected_functions[offset : offset + limit]
    result.update(
        {
            "total": total,
            "returned": len(page),
            "next_offset": offset + len(page) if offset + len(page) < total else None,
            "truncated": offset + len(page) < total,
            "functions": page,
        }
    )
    return result


def _render_pseudocode(cfunc) -> str:
    try:
        import ida_lines
    except Exception:
        ida_lines = None

    lines = []
    pseudocode = cfunc.get_pseudocode()
    for line in pseudocode:
        text = getattr(line, "line", str(line))
        if ida_lines is not None and hasattr(ida_lines, "tag_remove"):
            try:
                text = ida_lines.tag_remove(text)
            except Exception:
                pass
        lines.append(str(text).rstrip())
    return "\n".join(lines)


def _collect_disassembly(func_start_ea: int, max_lines: int = MAX_DISASSEMBLY_LINES) -> tuple[list[dict[str, Any]], bool]:
    try:
        import idautils
    except Exception:
        return [], False

    lines: list[dict[str, Any]] = []
    truncated = False

    for index, ea in enumerate(idautils.FuncItems(func_start_ea)):
        if index >= max_lines:
            truncated = True
            break
        try:
            text = idc.generate_disasm_line(ea, 0) or ""
        except Exception:
            text = ""
        lines.append({"ea": int(ea), "text": text})

    return lines, truncated


def decompile_function_data(
    address: Optional[str] = None,
    name: Optional[str] = None,
    include_disassembly: bool = False,
) -> dict[str, Any]:
    """Decompile a function or return a structured error."""
    result = _collect_database_info()
    result["query"] = {
        "address": address,
        "name": name,
        "include_disassembly": include_disassembly,
    }

    func, resolved_ea, error = _resolve_function(address=address, name=name)
    if error:
        result.update({"found": False, "error": error})
        return result

    summary = _function_summary(func)
    result.update(summary)
    result["found"] = True
    result["resolved_ea"] = int(resolved_ea)
    result["hexrays_available"] = False
    result["pseudocode"] = None
    result["warning"] = None

    try:
        import ida_hexrays

        init_ok = True
        if hasattr(ida_hexrays, "init_hexrays_plugin"):
            init_ok = bool(ida_hexrays.init_hexrays_plugin())
        if not init_ok:
            raise RuntimeError(
                "Hex-Rays decompiler is not available for this database, architecture, or license."
            )

        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc is None:
            raise RuntimeError("Hex-Rays returned no pseudocode output.")

        result["hexrays_available"] = True
        result["pseudocode"] = _render_pseudocode(cfunc)
    except Exception as exc:
        result["warning"] = f"Could not produce pseudocode: {exc}"

    if include_disassembly:
        lines, truncated = _collect_disassembly(int(func.start_ea))
        result["disassembly"] = lines
        result["disassembly_truncated"] = truncated

    return result


def _xref_type_name(xref_type: int) -> Optional[str]:
    try:
        import ida_xref
    except Exception:
        return None

    mapping = {
        getattr(ida_xref, "fl_CF", None): "call_far",
        getattr(ida_xref, "fl_CN", None): "call_near",
        getattr(ida_xref, "fl_JF", None): "jump_far",
        getattr(ida_xref, "fl_JN", None): "jump_near",
        getattr(ida_xref, "fl_F", None): "ordinary_flow",
        getattr(ida_xref, "dr_R", None): "data_read",
        getattr(ida_xref, "dr_W", None): "data_write",
        getattr(ida_xref, "dr_O", None): "offset",
        getattr(ida_xref, "dr_T", None): "text",
        getattr(ida_xref, "dr_I", None): "informational",
        getattr(ida_xref, "dr_S", None): "struct",
    }
    return mapping.get(xref_type)


def get_xrefs_data(
    address: Optional[str] = None,
    name: Optional[str] = None,
    direction: str = "to",
    xref_kind: str = "all",
    limit: int = 200,
) -> dict[str, Any]:
    """Get cross references to or from an address or symbol."""
    result = _collect_database_info()
    result["query"] = {
        "address": address,
        "name": name,
        "direction": direction,
        "xref_kind": xref_kind,
        "limit": limit,
    }

    target_ea, error = _resolve_target_ea(address=address, name=name)
    if error:
        result.update({"found": False, "error": error, "xrefs": []})
        return result

    result["found"] = True
    result["target_ea"] = int(target_ea)
    result["target_name"] = _symbol_name(int(target_ea))
    result["direction"] = direction
    result["xref_kind"] = xref_kind

    try:
        import idautils
    except Exception as exc:
        result.update({"error": f"IDA xref APIs are unavailable: {exc}", "xrefs": []})
        return result

    if direction not in {"to", "from"}:
        result.update({"error": f"Unsupported direction: {direction!r}", "xrefs": []})
        return result
    if xref_kind not in {"all", "code", "data"}:
        result.update({"error": f"Unsupported xref_kind: {xref_kind!r}", "xrefs": []})
        return result

    iterable = idautils.XrefsTo(target_ea, 0) if direction == "to" else idautils.XrefsFrom(target_ea, 0)

    xrefs: list[dict[str, Any]] = []
    truncated = False
    for xref in iterable:
        is_code = bool(getattr(xref, "iscode", 0))
        if xref_kind == "code" and not is_code:
            continue
        if xref_kind == "data" and is_code:
            continue

        from_ea = int(getattr(xref, "frm", 0))
        to_ea = int(getattr(xref, "to", 0))
        try:
            source_disasm = idc.generate_disasm_line(from_ea, 0) or ""
        except Exception:
            source_disasm = ""

        if len(xrefs) >= limit:
            truncated = True
            break

        xrefs.append(
            {
                "from_ea": from_ea,
                "to_ea": to_ea,
                "from_name": _symbol_name(from_ea),
                "to_name": _symbol_name(to_ea),
                "type": int(getattr(xref, "type", 0)),
                "type_name": _xref_type_name(int(getattr(xref, "type", 0))),
                "is_code": is_code,
                "user": bool(getattr(xref, "user", False)),
                "source_disassembly": source_disasm,
            }
        )

    result.update(
        {
            "returned": len(xrefs),
            "truncated": truncated,
            "xrefs": xrefs,
        }
    )
    return result


class IdaScriptHttpHandler(BaseHTTPRequestHandler):
    """HTTP request handler for IDA Script MCP."""

    server: "IdaScriptHttpServer"

    def log_message(self, _format, *_args):
        """Reduce logging noise."""
        return

    def _send_json_response(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Optional[dict[str, Any]]:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                return {}
            body = self.rfile.read(content_length).decode("utf-8")
            if not body.strip():
                return {}
            return json.loads(body)
        except json.JSONDecodeError as exc:
            self._send_json_response(400, {"error": f"Invalid JSON: {exc}"})
            return None

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send_json_response(
                200,
                {
                    "status": "ok",
                    "plugin": PLUGIN_NAME,
                    "instance_id": instance_registry.instance_id,
                    "port": instance_registry.port,
                },
            )
            return

        if parsed.path == "/metadata":
            try:
                if HAS_IDA:
                    data = execute_on_main_thread(_collect_database_info, write=False)
                else:
                    data = _collect_database_info()
                self._send_json_response(200, data)
            except Exception as exc:
                self._send_json_response(500, {"error": str(exc)})
            return

        self._send_json_response(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        request_data = self._read_json_body()
        if request_data is None:
            return

        try:
            if parsed.path == "/execute":
                if HAS_IDA:
                    result = execute_on_main_thread(
                        execute_python_script,
                        code=request_data.get("code"),
                        script_path=request_data.get("script_path"),
                        capture_output=request_data.get("capture_output", True),
                        write=True,
                    )
                else:
                    result = execute_python_script(
                        code=request_data.get("code"),
                        script_path=request_data.get("script_path"),
                        capture_output=request_data.get("capture_output", True),
                    )
                self._send_json_response(200, result)
                return

            if parsed.path == "/functions":
                result = execute_on_main_thread(
                    list_functions_data,
                    offset=int(request_data.get("offset", 0) or 0),
                    limit=int(request_data.get("limit", 200) or 200),
                    name_contains=request_data.get("name_contains"),
                    segment=request_data.get("segment"),
                    include_thunks=bool(request_data.get("include_thunks", False)),
                    include_library_functions=bool(
                        request_data.get("include_library_functions", False)
                    ),
                    write=False,
                )
                self._send_json_response(200, result)
                return

            if parsed.path == "/decompile":
                result = execute_on_main_thread(
                    decompile_function_data,
                    address=request_data.get("address"),
                    name=request_data.get("name"),
                    include_disassembly=bool(request_data.get("include_disassembly", False)),
                    write=False,
                )
                self._send_json_response(200, result)
                return

            if parsed.path == "/xrefs":
                result = execute_on_main_thread(
                    get_xrefs_data,
                    address=request_data.get("address"),
                    name=request_data.get("name"),
                    direction=str(request_data.get("direction", "to")),
                    xref_kind=str(request_data.get("xref_kind", "all")),
                    limit=int(request_data.get("limit", 200) or 200),
                    write=False,
                )
                self._send_json_response(200, result)
                return

            self._send_json_response(404, {"error": "Not found"})
        except Exception as exc:
            self._send_json_response(
                500,
                {
                    "instance_id": instance_registry.instance_id,
                    "port": instance_registry.port,
                    "error": str(exc),
                },
            )


class IdaScriptHttpServer(HTTPServer):
    """HTTP server for IDA Script MCP."""

    allow_reuse_address = False

    def __init__(self, host: str, port: int):
        super().__init__((host, port), IdaScriptHttpHandler)
        self.host = host
        self.port = port


if HAS_IDA:
    class IDAScriptMCPPlugin(idaapi.plugin_t):
        """IDA Pro plugin entry point."""

        flags = idaapi.PLUGIN_KEEP
        comment = "IDA Script MCP Plugin"
        help = "IDA Script MCP - Execute Python scripts via MCP"
        wanted_name = PLUGIN_NAME
        wanted_hotkey = "Ctrl-Alt-S"

        def init(self):
            print(f"[{PLUGIN_NAME}] Plugin loaded (supports multiple instances)")
            self.server: Optional[IdaScriptHttpServer] = None
            self.host = DEFAULT_HOST
            self.port = DEFAULT_PORT
            self.server_thread: Optional[threading.Thread] = None
            return idaapi.PLUGIN_KEEP

        def run(self, _arg):
            if self.server:
                self._stop_server()
                return
            self._start_server()

        def _start_server(self):
            port = self.port
            max_port = port + MAX_PORT_RANGE

            while port < max_port:
                try:
                    self.server = IdaScriptHttpServer(self.host, port)
                    self.port = port

                    instance_registry.register(port)

                    self.server_thread = threading.Thread(
                        target=self.server.serve_forever,
                        daemon=True,
                    )
                    self.server_thread.start()

                    print(f"[{PLUGIN_NAME}] Server started at http://{self.host}:{port}")
                    print(f"[{PLUGIN_NAME}] Instance ID: {instance_registry.instance_id}")
                    print(f"[{PLUGIN_NAME}] Database: {instance_registry.database}")
                    print(f"[{PLUGIN_NAME}] Metadata endpoint: GET http://{self.host}:{port}/metadata")
                    print(f"[{PLUGIN_NAME}] Functions endpoint: POST http://{self.host}:{port}/functions")
                    print(f"[{PLUGIN_NAME}] Decompile endpoint: POST http://{self.host}:{port}/decompile")
                    print(f"[{PLUGIN_NAME}] Xrefs endpoint: POST http://{self.host}:{port}/xrefs")
                    print(f"[{PLUGIN_NAME}] Execute endpoint: POST http://{self.host}:{port}/execute")
                    return
                except OSError as exc:
                    if exc.errno in (48, 98, 10048):
                        port += 1
                    else:
                        raise

            print(
                f"[{PLUGIN_NAME}] Error: No available port in range {self.port}-{max_port - 1}"
            )

        def _stop_server(self):
            if self.server:
                instance_registry.unregister()
                self.server.shutdown()
                self.server.server_close()
                self.server = None
                self.server_thread = None
                print(f"[{PLUGIN_NAME}] Server stopped")

        def term(self):
            self._stop_server()


    def PLUGIN_ENTRY():
        """Plugin entry point for IDA Pro."""
        return IDAScriptMCPPlugin()
