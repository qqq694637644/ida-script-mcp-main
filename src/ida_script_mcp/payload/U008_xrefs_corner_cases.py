# ruff: noqa: E501, N999, B904
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

IDA_DIR = "__IDA_DIR_JSON__"
DLL_PATH = "__DLL_PATH_JSON__"
IDA_TIMEOUT_SECONDS = int("__IDA_TIMEOUT_SECONDS_JSON__")
IDA_READY_TIMEOUT_SECONDS = min(60, max(15, IDA_TIMEOUT_SECONDS // 3))
IDA_EXECUTABLE_CANDIDATES = "__IDA_EXECUTABLE_CANDIDATES_JSON__"
LEGACY_ROOT_SUPPORT_FILES = "__LEGACY_ROOT_SUPPORT_FILES_JSON__"
PLUGIN_FILES_B64 = "__PLUGIN_FILES_B64_JSON__"
PLUGIN_EXPECTED_SHA256 = "__PLUGIN_EXPECTED_SHA256_JSON__"
WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-u008-xrefs-"))
READY_PATH = WORK_DIR / "ida_ready.json"
HEARTBEAT_PATH = WORK_DIR / "heartbeat.ndjson"
RESULT_PATH = WORK_DIR / "U008_xrefs_corner_cases_result.json"
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


def _symbol_name(ea):
    try:
        import idc
        name = idc.get_func_name(ea) or idc.get_name(ea, 0)
        return str(name or "")
    except Exception:
        return ""


def _xref_type_name(xref_type):
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


def _record_xref(xref):
    try:
        import ida_xref
    except Exception:
        ida_xref = None
    xref_type = int(getattr(xref, "type", 0))
    is_flow = bool(ida_xref is not None and xref_type == getattr(ida_xref, "fl_F", None))
    return {
        "from_ea": int(getattr(xref, "frm", 0)),
        "to_ea": int(getattr(xref, "to", 0)),
        "type": xref_type,
        "type_name": _xref_type_name(xref_type),
        "is_code": bool(getattr(xref, "iscode", 0)),
        "is_flow": is_flow,
        "from_name": _symbol_name(int(getattr(xref, "frm", 0))),
        "to_name": _symbol_name(int(getattr(xref, "to", 0))),
    }


def _func_bounds(ea):
    try:
        import ida_funcs
        func = ida_funcs.get_func(ea)
        if func is None:
            return None
        return int(func.start_ea), int(func.end_ea)
    except Exception:
        return None


def _same_function(a, b):
    return _func_bounds(a) is not None and _func_bounds(a) == _func_bounds(b)


def _discover_string_data_target(idautils):
    try:
        strings = idautils.Strings()
        try:
            strings.setup(strtypes=None, ignore_instructions=True, display_only_existing_strings=True)
        except Exception:
            pass
        best = None
        for string_info in strings:
            ea = int(getattr(string_info, "ea", 0) or 0)
            if ea <= 0:
                continue
            refs = [_record_xref(xref) for xref in idautils.XrefsTo(ea, 0)]
            data_refs = [xref for xref in refs if not xref.get("is_code")]
            if data_refs:
                candidate = {
                    "address": ea,
                    "address_hex": hex(ea),
                    "direction": "to",
                    "xref_kind": "data",
                    "expected_min_refs": len(data_refs),
                    "sample_xref": data_refs[0],
                    "string_preview": str(string_info)[:120],
                }
                if best is None or candidate["expected_min_refs"] > best["expected_min_refs"]:
                    best = candidate
        return best
    except Exception as exc:
        return {"error": f"string discovery failed: {type(exc).__name__}: {exc}"}


def _discover_xref_targets():
    targets = {}
    diagnostics = {"function_count": 0, "name_count": 0}
    try:
        import ida_funcs
        import ida_xref
        import idautils
    except Exception as exc:
        return {"error": f"IDA xref discovery APIs unavailable: {type(exc).__name__}: {exc}"}

    functions = list(idautils.Functions())
    diagnostics["function_count"] = len(functions)
    multi_candidates = []
    name_candidates = []

    for function_ea in functions:
        function_ea = int(function_ea)
        function_name = _symbol_name(function_ea)
        to_refs = [_record_xref(xref) for xref in idautils.XrefsTo(function_ea, 0)]
        if function_name and to_refs:
            name_candidates.append(
                {
                    "address": function_ea,
                    "address_hex": hex(function_ea),
                    "name": function_name,
                    "direction": "to",
                    "xref_kind": "all",
                    "expected_min_refs": len(to_refs),
                    "sample_xref": to_refs[0],
                }
            )
        if len(to_refs) > 1:
            multi_candidates.append(
                {
                    "address": function_ea,
                    "address_hex": hex(function_ea),
                    "name": function_name,
                    "direction": "to",
                    "xref_kind": "all",
                    "expected_min_refs": len(to_refs),
                    "sample_xref": to_refs[0],
                }
            )

        try:
            items = list(idautils.FuncItems(function_ea))
        except Exception:
            items = []
        for item_ea in items:
            item_ea = int(item_ea)
            for xref in idautils.XrefsFrom(item_ea, 0):
                record = _record_xref(xref)
                if record["is_code"] and "code_from" not in targets:
                    targets["code_from"] = {
                        "address": record["from_ea"],
                        "address_hex": hex(record["from_ea"]),
                        "direction": "from",
                        "xref_kind": "code",
                        "expected_to_ea": record["to_ea"],
                        "sample_xref": record,
                    }
                if record["is_flow"] and "flow_from" not in targets:
                    targets["flow_from"] = {
                        "address": record["from_ea"],
                        "address_hex": hex(record["from_ea"]),
                        "direction": "from",
                        "xref_kind": "flow",
                        "expected_to_ea": record["to_ea"],
                        "sample_xref": record,
                    }
                if (
                    record["is_code"]
                    and _same_function(record["from_ea"], record["to_ea"])
                    and record["to_ea"] <= record["from_ea"]
                    and "cycle_or_backedge" not in targets
                ):
                    targets["cycle_or_backedge"] = {
                        "address": record["from_ea"],
                        "address_hex": hex(record["from_ea"]),
                        "direction": "from",
                        "xref_kind": "code",
                        "expected_to_ea": record["to_ea"],
                        "sample_xref": record,
                    }
                if not record["is_code"] and "data_from_code" not in targets:
                    targets["data_from_code"] = {
                        "address": record["from_ea"],
                        "address_hex": hex(record["from_ea"]),
                        "direction": "from",
                        "xref_kind": "data",
                        "expected_to_ea": record["to_ea"],
                        "sample_xref": record,
                    }

    for function_ea in functions:
        try:
            func = ida_funcs.get_func(function_ea)
            flags = int(getattr(func, "flags", 0) or 0) if func is not None else 0
        except Exception:
            flags = 0
        if flags & int(getattr(ida_funcs, "FUNC_THUNK", 0)):
            targets["import_thunk"] = {
                "address": int(function_ea),
                "address_hex": hex(int(function_ea)),
                "name": _symbol_name(int(function_ea)),
                "direction": "from",
                "xref_kind": "all",
                "flags": flags,
            }
            break

    string_target = _discover_string_data_target(idautils)
    if string_target and not string_target.get("error"):
        targets["string_data"] = string_target
        if string_target.get("expected_min_refs", 0) > 1:
            multi_candidates.append({**string_target, "xref_kind": "all"})

    if multi_candidates:
        targets["multi_xrefs"] = max(multi_candidates, key=lambda target: int(target.get("expected_min_refs", 0)))
    if name_candidates:
        targets["name_query"] = max(name_candidates, key=lambda target: int(target.get("expected_min_refs", 0)))

    # Keep the payload resilient on small samples while still recording whether a real back-edge was found.
    if "cycle_or_backedge" not in targets and "flow_from" in targets:
        targets["cycle_or_backedge"] = {**targets["flow_from"], "fallback_reason": "no backward/same-function code xref discovered"}

    diagnostics["discovered_keys"] = sorted(targets)
    return {"targets": targets, "diagnostics": diagnostics}


def main():
    try:
        _stage("ida_bootstrap_start")
        import ida_auto
        import idaapi

        _stage("auto_wait_start")
        ida_auto.auto_wait()
        _stage("auto_wait_done")

        xref_discovery = _discover_xref_targets()
        _stage("xrefs_target_discovery_done", xref_discovery.get("diagnostics", xref_discovery))

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
        globals()["IDA_SCRIPT_MCP_U008_XREFS_PLUGIN_INSTANCE"] = plugin_instance
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
            "xrefs_discovery": xref_discovery,
        }
        _write_json(READY_PATH, ready)
        _stage("ready_written", {"base_url": base_url, "target_keys": sorted((xref_discovery.get("targets") or {}).keys())})
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
    HEARTBEAT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HEARTBEAT_PATH.open("a", encoding="utf-8") as output:
        output.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        output.write("\n")
    print("U008_XREFS_STAGE=" + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_bytes_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    temp_path.write_bytes(content)
    os.replace(temp_path, path)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tail(path: Path, max_chars: int = 12000) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    return text[-max_chars:]


def _ida_user_dir() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise RuntimeError("APPDATA is not set; cannot locate per-user IDA directory")
    return Path(appdata) / "Hex-Rays" / "IDA Pro"


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
    _stage("legacy_support_cleanup_done", {"removed": removed_legacy_support_files, "remaining": remaining_legacy_support_files})
    if remaining_legacy_support_files:
        raise RuntimeError("Legacy root support files remain: " + ", ".join(remaining_legacy_support_files))

    for destination, encoded in PLUGIN_FILES_B64.items():
        path = plugin_dir / destination
        content = base64.b64decode(encoded.encode("ascii"))
        _write_bytes_atomic(path, content)
        digest = _sha256(path)
        if digest != PLUGIN_EXPECTED_SHA256[destination]:
            raise RuntimeError(f"SHA-256 mismatch for {path}")
        py_compile.compile(str(path), doraise=True)
    return plugin_dir


def _select_ida_executable(ida_dir: Path) -> Path:
    for candidate in ("ida64.exe", "ida.exe", "idat64.exe", "idat.exe"):
        path = ida_dir / candidate
        if path.is_file():
            return path
    raise RuntimeError("No IDA executable found under " + str(ida_dir) + "; checked " + ", ".join(IDA_EXECUTABLE_CANDIDATES))


def _write_bootstrap(work_dir: Path, plugin_dir: Path, ready_path: Path, heartbeat_path: Path) -> Path:
    bootstrap_path = work_dir / "U008_xrefs_corner_cases_bootstrap.py"
    bootstrap_text = BOOTSTRAP_TEMPLATE
    replacements = {
        "__READY_PATH_JSON__": json.dumps(str(ready_path)),
        "__HEARTBEAT_PATH_JSON__": json.dumps(str(heartbeat_path)),
        "__PLUGIN_DIR_JSON__": json.dumps(str(plugin_dir)),
        "__BOOTSTRAP_DLL_PATH_JSON__": json.dumps(str(Path(DLL_PATH))),
    }
    for placeholder, value in replacements.items():
        bootstrap_text = bootstrap_text.replace(placeholder, value)
    bootstrap_path.write_text(bootstrap_text, encoding="utf-8")
    py_compile.compile(str(bootstrap_path), doraise=True)
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
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, text=True, timeout=10, check=False)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass
    _stage("ida_terminate_done", {"returncode": process.poll()})


def _read_process_pipes(process: subprocess.Popen) -> tuple[str, str]:
    try:
        stdout, stderr = process.communicate(timeout=10)
    except Exception:
        stdout, stderr = "", ""
    return stdout or "", stderr or ""


def _wait_for_ready(process: subprocess.Popen, ready_path: Path, ida_log_path: Path) -> dict:
    deadline = time.monotonic() + IDA_READY_TIMEOUT_SECONDS
    _stage("ida_ready_wait_start", {"timeout_seconds": IDA_READY_TIMEOUT_SECONDS})
    while time.monotonic() < deadline:
        if ready_path.is_file():
            ready = json.loads(ready_path.read_text(encoding="utf-8"))
            _stage("ida_ready_file_seen", {"status": ready.get("status"), "target_keys": sorted(((ready.get("xrefs_discovery") or {}).get("targets") or {}).keys())})
            if ready.get("status") != "ready":
                raise RuntimeError("IDA bootstrap failed: " + json.dumps(ready, ensure_ascii=False))
            return ready
        if process.poll() is not None:
            raise RuntimeError("IDA exited before ready file was created: " + json.dumps({"returncode": process.returncode, "ida_log_tail": _tail(ida_log_path)}, ensure_ascii=False))
        time.sleep(0.5)
    raise RuntimeError("Timed out waiting for IDA ready file: " + json.dumps({"ready_path": str(ready_path), "ida_log_tail": _tail(ida_log_path), "process_alive": process.poll() is None}, ensure_ascii=False))


def _json_request(method: str, base_url: str, path: str, payload=None, expected_status: int = 200, timeout: int = 5) -> dict:
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status = int(exc.code)
    body = json.loads(raw) if raw.strip() else {}
    if status != expected_status:
        raise AssertionError(f"{method} {path} returned HTTP {status}, expected {expected_status}: {body!r}")
    return {"status": status, "body": body}


def _check(result: dict, name: str, ok: bool, detail=None) -> None:
    result["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
    if not ok:
        raise AssertionError(f"check failed: {name}: {detail!r}")


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


def _target(targets: dict, key: str) -> dict:
    value = targets.get(key)
    if not isinstance(value, dict):
        raise AssertionError(f"required discovered target missing: {key}; discovered={sorted(targets)}")
    return value


def _call_xrefs(base_url: str, target: dict, *, limit: object | None = None, xref_kind: str | None = None, direction: str | None = None, use_name: bool = False) -> dict:
    payload = {
        "direction": direction or target.get("direction", "to"),
        "xref_kind": xref_kind or target.get("xref_kind", "all"),
        "limit": target.get("limit", 20) if limit is None else limit,
    }
    if use_name:
        payload["name"] = target["name"]
    else:
        payload["address"] = target.get("address_hex") or hex(int(target["address"]))
    return _json_request("POST", base_url, "/xrefs", payload, expected_status=200, timeout=15)["body"]


def _assert_xref_list(result: dict, check_prefix: str, body: dict, *, min_returned: int = 1) -> None:
    _check(result, f"{check_prefix} found target", body.get("found") is True, body)
    _check(result, f"{check_prefix} returns xrefs list", isinstance(body.get("xrefs"), list), body)
    _check(result, f"{check_prefix} returned enough xrefs", int(body.get("returned", 0)) >= min_returned, body)


def _assert_all(result: dict, check_prefix: str, body: dict, predicate_name: str, predicate) -> None:
    xrefs = body.get("xrefs") or []
    _check(result, f"{check_prefix} has xrefs to inspect", bool(xrefs), body)
    _check(result, f"{check_prefix} all {predicate_name}", all(predicate(xref) for xref in xrefs), xrefs)


def _run_xrefs_corner_cases(ready: dict, result: dict) -> None:
    base_url = str(ready["base_url"])
    discovery = ready.get("xrefs_discovery") or {}
    targets = discovery.get("targets") or {}
    result["discovered_targets"] = targets
    result["discovery_diagnostics"] = discovery.get("diagnostics") or {}

    required = ["code_from", "flow_from", "data_from_code", "string_data", "import_thunk", "multi_xrefs", "name_query", "cycle_or_backedge"]
    for key in required:
        _target(targets, key)

    health = _health_with_retry(base_url)
    result["responses"]["health"] = health["body"]
    _check(result, "IDA plugin health ok before U008 xrefs", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])

    metadata_before = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_before_u008_xrefs"] = metadata_before["body"]
    _check(result, "metadata clean before U008 xrefs", metadata_before["body"].get("dirty") is False, metadata_before["body"])

    code_target = _target(targets, "code_from")
    _stage("xrefs_code_filter_start", code_target)
    code_body = _call_xrefs(base_url, code_target, xref_kind="code", limit=20)
    result["responses"]["xrefs_code_filter"] = code_body
    _assert_xref_list(result, "code xref_kind", code_body)
    _assert_all(result, "code xref_kind", code_body, "is_code", lambda xref: xref.get("is_code") is True)
    _stage("xrefs_code_filter_done")

    flow_target = _target(targets, "flow_from")
    _stage("xrefs_flow_filter_start", flow_target)
    flow_body = _call_xrefs(base_url, flow_target, xref_kind="flow", limit=20)
    result["responses"]["xrefs_flow_filter"] = flow_body
    _assert_xref_list(result, "flow xref_kind", flow_body)
    _assert_all(result, "flow xref_kind", flow_body, "is_flow", lambda xref: xref.get("is_flow") is True or xref.get("type_name") == "ordinary_flow")
    _stage("xrefs_flow_filter_done")

    data_target = _target(targets, "data_from_code")
    _stage("xrefs_data_filter_from_code_start", data_target)
    data_body = _call_xrefs(base_url, data_target, xref_kind="data", limit=20)
    result["responses"]["xrefs_data_filter_from_code"] = data_body
    _assert_xref_list(result, "data xref_kind from code", data_body)
    _assert_all(result, "data xref_kind from code", data_body, "not is_code", lambda xref: xref.get("is_code") is False)
    _stage("xrefs_data_filter_from_code_done")

    string_target = _target(targets, "string_data")
    _stage("xrefs_string_data_address_start", string_target)
    string_body = _call_xrefs(base_url, string_target, xref_kind="data", direction="to", limit=20)
    result["responses"]["xrefs_string_data_address"] = string_body
    _assert_xref_list(result, "string/data address", string_body)
    _assert_all(result, "string/data address", string_body, "not is_code", lambda xref: xref.get("is_code") is False)
    _check(result, "string/data address resolves target", int(string_body.get("target_ea")) == int(string_target["address"]), string_body)
    _stage("xrefs_string_data_address_done")

    multi_target = _target(targets, "multi_xrefs")
    _stage("xrefs_limit_one_truncation_start", multi_target)
    limit_one_body = _call_xrefs(base_url, multi_target, xref_kind="all", direction=multi_target.get("direction", "to"), limit=1)
    result["responses"]["xrefs_limit_one_truncation"] = limit_one_body
    _assert_xref_list(result, "limit=1 truncation", limit_one_body, min_returned=1)
    _check(result, "limit=1 returns exactly one", limit_one_body.get("returned") == 1, limit_one_body)
    _check(result, "limit=1 marks truncated", limit_one_body.get("truncated") is True, limit_one_body)
    _stage("xrefs_limit_one_truncation_done")

    _stage("xrefs_limit_zero_start")
    limit_zero_body = _call_xrefs(base_url, multi_target, xref_kind="all", direction=multi_target.get("direction", "to"), limit=0)
    result["responses"]["xrefs_limit_zero"] = limit_zero_body
    _check(result, "limit=0 keeps target found", limit_zero_body.get("found") is True, limit_zero_body)
    _check(result, "limit=0 returns zero xrefs", limit_zero_body.get("returned") == 0 and limit_zero_body.get("xrefs") == [], limit_zero_body)
    _check(result, "limit=0 effective limit is zero", limit_zero_body.get("limit") == 0, limit_zero_body)
    _stage("xrefs_limit_zero_done")

    _stage("xrefs_limit_negative_start")
    negative_body = _call_xrefs(base_url, multi_target, xref_kind="all", direction=multi_target.get("direction", "to"), limit=-1)
    result["responses"]["xrefs_limit_negative"] = negative_body
    _check(result, "negative limit is structured error", bool(negative_body.get("error")), negative_body)
    _check(result, "negative limit does not return xrefs", negative_body.get("returned") == 0 and negative_body.get("xrefs") == [], negative_body)
    _stage("xrefs_limit_negative_done")

    _stage("xrefs_limit_non_integer_start")
    non_integer_body = _call_xrefs(base_url, multi_target, xref_kind="all", direction=multi_target.get("direction", "to"), limit="not-an-int")
    result["responses"]["xrefs_limit_non_integer"] = non_integer_body
    _check(result, "non-integer limit is structured error", bool(non_integer_body.get("error")), non_integer_body)
    _check(result, "non-integer limit does not return xrefs", non_integer_body.get("returned") == 0 and non_integer_body.get("xrefs") == [], non_integer_body)
    _stage("xrefs_limit_non_integer_done")

    _stage("xrefs_limit_huge_start")
    huge_body = _call_xrefs(base_url, multi_target, xref_kind="all", direction=multi_target.get("direction", "to"), limit=100000)
    result["responses"]["xrefs_limit_huge"] = huge_body
    _assert_xref_list(result, "huge limit", huge_body, min_returned=1)
    _check(result, "huge limit is clamped", huge_body.get("limit") == 5000 and huge_body.get("limit_clamped") is True, huge_body)
    _stage("xrefs_limit_huge_done")

    name_target = _target(targets, "name_query")
    _stage("xrefs_name_query_start", name_target)
    name_body = _call_xrefs(base_url, name_target, xref_kind="all", direction=name_target.get("direction", "to"), limit=20, use_name=True)
    result["responses"]["xrefs_name_query"] = name_body
    _assert_xref_list(result, "name query", name_body)
    _check(result, "name query resolves requested name", name_body.get("target_name") == name_target.get("name"), name_body)
    _stage("xrefs_name_query_done")

    missing_name = "__ida_script_mcp_missing_xrefs_U008_" + str(int(time.time()))
    _stage("xrefs_missing_name_start", {"name": missing_name})
    missing_name_body = _json_request("POST", base_url, "/xrefs", {"name": missing_name, "direction": "to", "xref_kind": "all", "limit": 20}, expected_status=200, timeout=10)["body"]
    result["responses"]["xrefs_missing_name"] = missing_name_body
    _check(result, "missing name returns found=false", missing_name_body.get("found") is False, missing_name_body)
    _check(result, "missing name returns structured error", bool(missing_name_body.get("error")), missing_name_body)
    _stage("xrefs_missing_name_done")

    thunk_target = _target(targets, "import_thunk")
    _stage("xrefs_import_thunk_start", thunk_target)
    thunk_body = _call_xrefs(base_url, thunk_target, xref_kind="all", direction=thunk_target.get("direction", "from"), limit=20)
    result["responses"]["xrefs_import_thunk"] = thunk_body
    _check(result, "import thunk address is found", thunk_body.get("found") is True, thunk_body)
    _check(result, "import thunk response is structured", isinstance(thunk_body.get("xrefs"), list), thunk_body)
    _stage("xrefs_import_thunk_done")

    cycle_target = _target(targets, "cycle_or_backedge")
    _stage("xrefs_cycle_or_backedge_start", cycle_target)
    cycle_body = _call_xrefs(base_url, cycle_target, xref_kind="code", direction=cycle_target.get("direction", "from"), limit=20)
    result["responses"]["xrefs_cycle_or_backedge"] = cycle_body
    _assert_xref_list(result, "cycle/backedge candidate", cycle_body)
    expected_to = cycle_target.get("expected_to_ea")
    if expected_to is not None:
        _check(result, "cycle/backedge expected edge returned", any(int(xref.get("to_ea")) == int(expected_to) for xref in cycle_body.get("xrefs") or []), {"expected_to_ea": expected_to, "body": cycle_body})
    result["cycle_or_backedge_is_fallback"] = bool(cycle_target.get("fallback_reason"))
    _stage("xrefs_cycle_or_backedge_done")

    invalid_kind_body = _call_xrefs(base_url, code_target, xref_kind="nonsense", limit=20)
    result["responses"]["xrefs_invalid_kind"] = invalid_kind_body
    _check(result, "invalid xref_kind stays structured", bool(invalid_kind_body.get("error")), invalid_kind_body)

    metadata_after = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_after_u008_xrefs"] = metadata_after["body"]
    _check(result, "U008 xrefs leaves GUI database clean", metadata_after["body"].get("dirty") is False, metadata_after["body"])

    result["summary"] = {
        "covered": [
            "code xref_kind real filtering",
            "data xref_kind real filtering",
            "flow xref_kind real filtering",
            "limit=1 truncation",
            "limit=0",
            "negative limit structured error",
            "non-integer limit structured error",
            "huge limit clamp",
            "name query",
            "missing name",
            "import thunk address",
            "string/data address",
            "cycle/backedge candidate",
            "read-only dirty-state check",
        ],
        "check_count": len(result.get("checks", [])),
        "target_keys": sorted(targets),
        "cycle_or_backedge_is_fallback": result.get("cycle_or_backedge_is_fallback"),
    }


def main() -> int:
    ida_dir = Path(IDA_DIR)
    dll_path = Path(DLL_PATH)
    stdout = ""
    stderr = ""
    process = None
    result: dict = {
        "status": "failed",
        "mode": "u008_xrefs_corner_cases",
        "dll_path": DLL_PATH,
        "work_dir": str(WORK_DIR),
        "checks": [],
        "responses": {},
    }

    try:
        _stage("validate_inputs_start", {"ida_dir": str(ida_dir), "dll_path": str(dll_path)})
        if not ida_dir.is_dir():
            raise RuntimeError(f"IDA directory does not exist: {ida_dir}")
        if not dll_path.is_file():
            raise RuntimeError(f"DLL path does not exist: {dll_path}")

        plugin_dir = _install_plugin_files()
        ida_executable = _select_ida_executable(ida_dir)
        database_path = WORK_DIR / (dll_path.stem + ".i64")
        bootstrap_path = _write_bootstrap(WORK_DIR, plugin_dir, READY_PATH, HEARTBEAT_PATH)
        _stage("validate_inputs_done", {"ida_executable": str(ida_executable), "plugin_dir": str(plugin_dir)})

        command = [str(ida_executable), "-A", f"-L{IDA_LOG_PATH}", f"-S{bootstrap_path}", f"-o{database_path}", str(dll_path)]
        _stage("ida_start", {"command": command, "work_dir": str(WORK_DIR)})
        process = subprocess.Popen(command, cwd=str(WORK_DIR), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")

        ready = _wait_for_ready(process, READY_PATH, IDA_LOG_PATH)
        result["ready"] = ready
        _run_xrefs_corner_cases(ready, result)
        result.update({"status": "passed", "ida_executable": str(ida_executable), "ida_log_path": str(IDA_LOG_PATH), "work_dir": str(WORK_DIR), "database_path": str(database_path)})
        _stage("u008_xrefs_tests_done", {"status": result.get("status")})
    except Exception as exc:
        result["status"] = "failed"
        result["failed_stage"] = _tail(HEARTBEAT_PATH, max_chars=2000)
        result["error"] = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    finally:
        _terminate_process(process)
        if process is not None:
            stdout, stderr = _read_process_pipes(process)
            result["ida_returncode"] = process.returncode
        result.update({"ida_log_tail": _tail(IDA_LOG_PATH), "heartbeat_tail": _tail(HEARTBEAT_PATH), "stdout_tail": stdout[-4000:], "stderr_tail": stderr[-4000:]})
        _write_json(RESULT_PATH, result)
        print("U008_XREFS_CORNER_CASES_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "U008_XREFS_CORNER_CASES_ERROR="
            + json.dumps({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(1)
