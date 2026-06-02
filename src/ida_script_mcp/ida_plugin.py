"""IDA Pro plugin for IDA Script MCP.

The plugin runs inside IDA Pro and exposes a small local HTTP API that the MCP
server can call. High-frequency read operations such as listing functions,
decompiling a function, and reading xrefs are exposed as dedicated endpoints so
LLMs do not need to synthesize IDAPython for every common workflow.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

try:  # Package import used when this module is imported from ida_script_mcp.
    from .change_protocol import ApplyChangesRequest, ApplyChangesResult, OperationApplyResult, fingerprint_from_metadata, fingerprint_matches
    from .execution import ScriptExecutor
    from .protocol import ExecuteRequest, ExecuteResult, ExecutionError
except ImportError:  # pragma: no cover - standalone IDA plugin support-file import.
    plugin_dir = Path(__file__).parent
    if str(plugin_dir) not in sys.path:
        sys.path.insert(0, str(plugin_dir))

    try:
        from ida_script_mcp_change_protocol import (  # type: ignore[no-redef]
            ApplyChangesRequest,
            ApplyChangesResult,
            OperationApplyResult,
            fingerprint_from_metadata,
            fingerprint_matches,
        )
        from ida_script_mcp_execution import ScriptExecutor  # type: ignore[no-redef]
        from ida_script_mcp_protocol import (  # type: ignore[no-redef]
            ExecuteRequest,
            ExecuteResult,
            ExecutionError,
        )
    except ImportError:
        from change_protocol import (  # type: ignore[no-redef]
            ApplyChangesRequest,
            ApplyChangesResult,
            OperationApplyResult,
            fingerprint_from_metadata,
            fingerprint_matches,
        )
        from execution import ScriptExecutor  # type: ignore[no-redef]
        from protocol import ExecuteRequest, ExecuteResult, ExecutionError  # type: ignore[no-redef]

PLUGIN_NAME = "IDA-Script-MCP"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13338
MAX_PORT_RANGE = 100
MAX_DISASSEMBLY_LINES = 1000
UNSAFE_GUI_EXECUTE_ENV = "IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE"

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


def _execute_result_payload(result: ExecuteResult) -> dict[str, Any]:
    """Attach plugin identity and convert an execution result to JSON data."""
    result = result.model_copy(
        update={
            "instance_id": instance_registry.instance_id,
            "port": instance_registry.port,
        }
    )
    return result.model_dump(mode="json")


def _source_error_payload(exc: BaseException) -> dict[str, Any]:
    result = ExecuteResult(
        status="source_error",
        result=None,
        stdout="",
        stderr="",
        error=ExecutionError(
            type=type(exc).__name__,
            message=str(exc),
            traceback=traceback.format_exc(),
        ),
    )
    return _execute_result_payload(result)


def execute_python_script(
    code: Optional[str] = None,
    script_path: Optional[str] = None,
    capture_output: bool = True,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Execute Python code or a script file in the IDA context."""
    try:
        request = ExecuteRequest.model_validate(
            {
                "code": code,
                "script_path": script_path,
                "capture_output": capture_output,
                "timeout_seconds": timeout_seconds,
            }
        )
    except Exception as exc:
        return _source_error_payload(exc)

    return _execute_result_payload(_execute_request(request))


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


def _execute_request(request: ExecuteRequest) -> ExecuteResult:
    """Execute a validated request in the current Python thread."""
    return ScriptExecutor(_build_ida_globals).execute(request)


def _execute_request_on_ida_main_thread(request: ExecuteRequest) -> ExecuteResult:
    """Execute a validated request on IDA's main thread when IDA is available."""
    if HAS_IDA:
        return execute_on_main_thread(_execute_request, request, write=True)
    return _execute_request(request)


class ExecutionBusyError(RuntimeError):
    """Raised when another script is already running."""


class ExecutionRecord:
    """Observable state for the currently running script."""

    def __init__(self, request: ExecuteRequest):
        self.started_monotonic = time.monotonic()
        self.started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.timeout_seconds = request.timeout_seconds
        self.source = "script_path" if request.script_path is not None else "code"

    @property
    def elapsed_seconds(self) -> float:
        return max(0.0, time.monotonic() - self.started_monotonic)

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": "running",
            "started_at": self.started_at,
            "source": self.source,
            "elapsed_seconds": self.elapsed_seconds,
            "timeout_seconds": self.timeout_seconds,
            "deadline_exceeded": self.elapsed_seconds >= self.timeout_seconds,
        }


class ExecutionManager:
    """Serialize IDA script execution and expose current execution state."""

    def __init__(self):
        self._lock = threading.Lock()
        self.current: Optional[ExecutionRecord] = None

    def run(self, request: ExecuteRequest) -> ExecuteResult:
        if not self._lock.acquire(blocking=False):
            raise ExecutionBusyError("Another script is already running")

        self.current = ExecutionRecord(request)
        try:
            return _execute_request_on_ida_main_thread(request)
        finally:
            self.current = None
            self._lock.release()

    def status(self) -> dict[str, Any]:
        current = self.current
        if current is None:
            return {"state": "idle"}
        return current.as_dict()


execution_manager = ExecutionManager()


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




def _path_from_ida_path_type(path_type_name: str) -> Optional[str]:
    if not HAS_IDA:
        return None
    modules = [idaapi]
    try:
        modules.append(__import__("ida_loader"))
    except Exception:
        pass

    for module in modules:
        getter = getattr(module, "get_path", None)
        path_type = getattr(module, path_type_name, None)
        if getter is None or path_type is None:
            continue
        try:
            value = getter(path_type)
        except Exception:
            continue
        if value:
            return str(value)
    return None


def _saved_database_path() -> Optional[str]:
    """Return the saved IDB/I64 path, never the original input sample path."""
    if not HAS_IDA:
        return None
    for path_type_name in ("PATH_TYPE_IDB", "PATH_TYPE_ID0"):
        value = _path_from_ida_path_type(path_type_name)
        if value:
            return value
    return None


def _input_file_path() -> Optional[str]:
    if not HAS_IDA:
        return None
    try:
        value = idaapi.get_input_file_path()
    except Exception:
        return None
    return str(value) if value else None


def _sha256_file(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    try:
        hasher = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                hasher.update(block)
        return hasher.hexdigest()
    except Exception:
        return None


def _file_size(path: Optional[str]) -> Optional[int]:
    if not path:
        return None
    try:
        return int(os.path.getsize(path))
    except Exception:
        return None


def _ida_bytes_to_hex(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    text = str(value).strip()
    return text or None


def _input_hash(name: str) -> Optional[str]:
    if not HAS_IDA:
        return None
    for module_name in ("ida_nalt", "ida_loader"):
        try:
            module = __import__(module_name)
        except Exception:
            continue
        getter = getattr(module, name, None)
        if getter is None:
            continue
        try:
            return _ida_bytes_to_hex(getter())
        except Exception:
            continue
    return None


def _database_dirty_state() -> tuple[Optional[bool], Optional[str]]:
    if not HAS_IDA:
        return None, "IDA APIs unavailable"
    checker = getattr(idaapi, "is_database_modified", None)
    if checker is None:
        return None, "idaapi.is_database_modified is unavailable"
    try:
        return bool(checker()), None
    except Exception as exc:
        return None, str(exc)

def _collect_database_info() -> dict[str, Any]:
    saved_db_path = _saved_database_path()
    input_path = _input_file_path()
    dirty_state, dirty_error = _database_dirty_state()
    info: dict[str, Any] = {
        "instance_id": instance_registry.instance_id,
        "port": instance_registry.port,
        "database": None,
        "database_path": saved_db_path,
        "input_file_path": input_path,
        "platform": sys.platform,
        "dirty": dirty_state,
        "unsaved": dirty_state,
        "dirty_state_known": dirty_state is not None,
    }
    if dirty_error:
        info["dirty_error"] = dirty_error

    if saved_db_path:
        info["database_sha256"] = _sha256_file(saved_db_path)
        info["database_size"] = _file_size(saved_db_path)

    if not HAS_IDA:
        return info

    try:
        info["database"] = idaapi.get_root_filename()
    except Exception:
        pass
    try:
        info["root_filename"] = idaapi.get_root_filename()
    except Exception:
        pass
    info["input_md5"] = _input_hash("retrieve_input_file_md5")
    info["input_sha256"] = _input_hash("retrieve_input_file_sha256")
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

    return info


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


def _execute_change_operation(operation, *, dry_run: bool) -> OperationApplyResult:
    op = operation.op
    try:
        if dry_run:
            return OperationApplyResult(op_id=operation.op_id, op=op, status="skipped", message="dry run")
        if op == "rename":
            module = __import__("ida_name") if HAS_IDA else None
            ok = module.set_name(operation.ea, operation.new_name, operation.flags) if module else True
        elif op == "comment":
            module = __import__("ida_bytes") if HAS_IDA else None
            ok = module.set_cmt(operation.ea, operation.text, int(operation.repeatable)) if module else True
        elif op == "function_comment":
            module = __import__("ida_funcs") if HAS_IDA else None
            ok = module.set_func_cmt(operation.ea, operation.text, int(operation.repeatable)) if module else True
        elif op == "patch_bytes":
            module = __import__("ida_bytes") if HAS_IDA else None
            ok = module.patch_bytes(operation.ea, bytes.fromhex(operation.new_bytes_hex)) if module else True
        elif op == "set_type":
            module = __import__("idc") if HAS_IDA else None
            setter = getattr(module, "set_type", None) or getattr(module, "SetType", None) if module else None
            ok = setter(operation.ea, operation.decl) if setter else True
        else:
            return OperationApplyResult(op_id=operation.op_id, op=op, status="error", message="unsupported operation")
        if not ok:
            return OperationApplyResult(op_id=operation.op_id, op=op, status="error", message="IDA API returned failure")
        return OperationApplyResult(op_id=operation.op_id, op=op, status="applied", message="applied")
    except Exception as exc:
        return OperationApplyResult(op_id=operation.op_id, op=op, status="error", message=str(exc))


def apply_changes_request(payload: dict[str, Any]) -> dict[str, Any]:
    request = ApplyChangesRequest.model_validate(payload)
    current_metadata = _collect_database_info()
    if current_metadata.get("dirty_state_known") is False or current_metadata.get("dirty") is None:
        return ApplyChangesResult(
            status="rejected",
            job_id=request.job_id,
            dry_run=request.dry_run,
            message="database dirty state is unknown; refusing change replay",
        ).model_dump(mode="json")
    if current_metadata.get("dirty") or current_metadata.get("unsaved"):
        return ApplyChangesResult(
            status="rejected",
            job_id=request.job_id,
            dry_run=request.dry_run,
            message="database has unsaved changes; save before replaying worker changes",
        ).model_dump(mode="json")

    current_fingerprint = fingerprint_from_metadata(current_metadata)
    if not fingerprint_matches(request.database_fingerprint, current_fingerprint):
        return ApplyChangesResult(
            status="rejected",
            job_id=request.job_id,
            dry_run=request.dry_run,
            message="database fingerprint mismatch",
        ).model_dump(mode="json")

    applied = []
    skipped = []
    errors = []
    for operation in request.operations:
        result = _execute_change_operation(operation, dry_run=request.dry_run)
        if result.status == "applied":
            applied.append(result)
        elif result.status == "skipped":
            skipped.append(result)
        else:
            errors.append(result)
            if not request.dry_run:
                break
    status = "ok" if not errors else ("partial" if applied or skipped else "error")
    return ApplyChangesResult(
        status=status,
        job_id=request.job_id,
        dry_run=request.dry_run,
        applied=applied,
        skipped=skipped,
        errors=errors,
    ).model_dump(mode="json")


def _unsafe_gui_execute_enabled() -> bool:
    return os.environ.get(UNSAFE_GUI_EXECUTE_ENV) == "1"


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
                    "execution": execution_manager.status(),
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
                if not _unsafe_gui_execute_enabled():
                    self._send_json_response(410, {
                        "status": "rejected",
                        "error": "GUI /execute is disabled by default; use isolated worker execution.",
                    })
                    return
                try:
                    execute_request = ExecuteRequest.model_validate(request_data)
                except Exception as exc:
                    self._send_json_response(400, _source_error_payload(exc))
                    return
                try:
                    result = execution_manager.run(execute_request)
                except ExecutionBusyError as exc:
                    self._send_json_response(409, {"status": "rejected", "error": str(exc)})
                    return
                self._send_json_response(200, _execute_result_payload(result))
                return

            if parsed.path == "/apply_changes":
                try:
                    result = execute_on_main_thread(apply_changes_request, request_data, write=True)
                    self._send_json_response(200, result)
                except Exception as exc:
                    self._send_json_response(400, {"status": "error", "error": str(exc)})
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


class IdaScriptHttpServer(ThreadingHTTPServer):
    """HTTP server for IDA Script MCP."""

    allow_reuse_address = False
    daemon_threads = True

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
                    print(f"[{PLUGIN_NAME}] Execute endpoint disabled by default; use isolated worker execution")
                    print(f"[{PLUGIN_NAME}] Apply changes endpoint: POST http://{self.host}:{port}/apply_changes")
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
