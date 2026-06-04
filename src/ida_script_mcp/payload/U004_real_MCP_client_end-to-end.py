from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import json
import os
import py_compile
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

IDA_DIR = "__IDA_DIR_JSON__"
DLL_PATH = "__DLL_PATH_JSON__"
IDA_TIMEOUT_SECONDS = int("__IDA_TIMEOUT_SECONDS_JSON__")
IDA_READY_TIMEOUT_SECONDS = min(60, max(15, IDA_TIMEOUT_SECONDS // 3))
IDA_EXECUTABLE_CANDIDATES = "__IDA_EXECUTABLE_CANDIDATES_JSON__"
LEGACY_ROOT_SUPPORT_FILES = "__LEGACY_ROOT_SUPPORT_FILES_JSON__"
PLUGIN_FILES_B64 = "__PLUGIN_FILES_B64_JSON__"
PLUGIN_EXPECTED_SHA256 = "__PLUGIN_EXPECTED_SHA256_JSON__"
RUNTIME_FILES_B64 = "__RUNTIME_FILES_B64_JSON__"
RUNTIME_EXPECTED_SHA256 = "__RUNTIME_EXPECTED_SHA256_JSON__"
WORKER_SCRIPT_B64 = "__WORKER_SCRIPT_B64_JSON__"
WORKER_SCRIPT_SHA256 = "__WORKER_SCRIPT_SHA256_JSON__"
WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-u004-real-client-"))
READY_PATH = WORK_DIR / "ida_ready.json"
HEARTBEAT_PATH = WORK_DIR / "heartbeat.ndjson"
RESULT_PATH = WORK_DIR / "U004_real_MCP_client_end-to-end_result.json"
IDA_LOG_PATH = WORK_DIR / "ida.log"
PIP_PROXY = "http://192.168.1.249:10810"
MCP_HTTP_PORT = 8765
THIRD_PARTY_REQUIREMENTS = ("mcp>=1.25.0", "pydantic>=2.0.0")

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


def _save_database(idaapi_module, ida_loader_module):
    database_path = _ida_database_path(idaapi_module, ida_loader_module)
    if not database_path:
        raise RuntimeError("Cannot resolve saved IDB/I64 path before U004 test")
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
    if not path.is_file() or path.stat().st_size <= 0:
        raise RuntimeError(f"Saved IDB/I64 path is unavailable after save: {database_path}")
    _stage("database_save_done", {"database_path": database_path, "database_size": path.stat().st_size})
    return database_path


def main():
    try:
        _stage("ida_bootstrap_start")
        import ida_auto
        import idaapi
        import ida_loader

        _stage("auto_wait_start")
        ida_auto.auto_wait()
        _stage("auto_wait_done")
        _save_database(idaapi, ida_loader)

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
    HEARTBEAT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with HEARTBEAT_PATH.open("a", encoding="utf-8") as output:
        output.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        output.write("\n")
    print("U004_STAGE=" + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


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


def _install_runtime_package_files() -> Path:
    runtime_root = WORK_DIR / "runtime_src"
    for destination, encoded in RUNTIME_FILES_B64.items():
        path = runtime_root / destination
        content = base64.b64decode(encoded.encode("ascii"))
        _write_bytes_atomic(path, content)
        digest = _sha256(path)
        if digest != RUNTIME_EXPECTED_SHA256[destination]:
            raise RuntimeError(f"SHA-256 mismatch for runtime file {path}")
        py_compile.compile(str(path), doraise=True)
    if str(runtime_root) not in sys.path:
        sys.path.insert(0, str(runtime_root))
    _stage("runtime_package_install_done", {"runtime_root": str(runtime_root), "file_count": len(RUNTIME_FILES_B64)})
    return runtime_root


def _write_worker_script() -> Path:
    worker_script = WORK_DIR / "U004_real_MCP_client_worker_script.py"
    content = base64.b64decode(WORKER_SCRIPT_B64.encode("ascii"))
    _write_bytes_atomic(worker_script, content)
    digest = _sha256(worker_script)
    if digest != WORKER_SCRIPT_SHA256:
        raise RuntimeError("SHA-256 mismatch for U004 worker script")
    py_compile.compile(str(worker_script), doraise=True)
    return worker_script


def _select_ida_executable(ida_dir: Path) -> Path:
    for candidate in ("ida64.exe", "ida.exe", "idat64.exe", "idat.exe"):
        path = ida_dir / candidate
        if path.is_file():
            return path
    raise RuntimeError("No IDA executable found under " + str(ida_dir))


def _select_worker_ida_executable(ida_dir: Path) -> Path:
    for candidate in ("idat64.exe", "idat.exe", "ida64.exe", "ida.exe"):
        path = ida_dir / candidate
        if path.is_file():
            return path
    raise RuntimeError("No worker-capable IDA executable found under " + str(ida_dir))


def _write_bootstrap(work_dir: Path, plugin_dir: Path, ready_path: Path, heartbeat_path: Path) -> Path:
    bootstrap_path = work_dir / "U004_real_MCP_client_bootstrap.py"
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
    _stage("process_terminate_start", {"pid": process.pid})
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
    _stage("process_terminate_done", {"pid": process.pid, "returncode": process.poll()})


def _json_request(method, base_url, path, payload=None, expected_status=200, timeout=5):
    import urllib.error
    import urllib.request

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


def _wait_for_ready(process: subprocess.Popen, ready_path: Path, ida_log_path: Path) -> dict:
    deadline = time.monotonic() + IDA_READY_TIMEOUT_SECONDS
    _stage("ida_ready_wait_start", {"timeout_seconds": IDA_READY_TIMEOUT_SECONDS})
    while time.monotonic() < deadline:
        if ready_path.is_file():
            ready = json.loads(ready_path.read_text(encoding="utf-8"))
            _stage("ida_ready_file_seen", ready)
            if ready.get("status") != "ready":
                raise RuntimeError("IDA bootstrap failed: " + json.dumps(ready, ensure_ascii=False))
            return ready
        if process.poll() is not None:
            raise RuntimeError("IDA exited before ready file was created: " + json.dumps({"returncode": process.returncode, "ida_log_tail": _tail(ida_log_path)}, ensure_ascii=False))
        time.sleep(0.5)
    raise RuntimeError("Timed out waiting for IDA ready file: " + json.dumps({"ready_path": str(ready_path), "ida_log_tail": _tail(ida_log_path), "process_alive": process.poll() is None}, ensure_ascii=False))


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


def _ensure_mcp_dependencies(result: dict) -> None:
    try:
        importlib.import_module("mcp.client.stdio")
        importlib.import_module("mcp.client.session")
        importlib.import_module("mcp.client.sse")
        importlib.import_module("pydantic")
        _stage("mcp_dependencies_already_available")
        result["dependency_install"] = {"needed": False}
        return
    except Exception as exc:
        _stage("mcp_dependency_install_needed", {"reason": f"{type(exc).__name__}: {exc}"})

    requirements_path = WORK_DIR / "requirements.txt"
    requirements_path.write_text("\n".join(THIRD_PARTY_REQUIREMENTS) + "\n", encoding="utf-8")
    command = ["py", "-3.11", "-m", "pip", "install", "-r", "requirements.txt", "--proxy", PIP_PROXY]
    _stage("mcp_dependency_install_start", {"command": command, "cwd": str(WORK_DIR)})
    completed = subprocess.run(command, cwd=str(WORK_DIR), capture_output=True, text=True, timeout=180, check=False)
    result["dependency_install"] = {
        "needed": True,
        "command": command,
        "returncode": completed.returncode,
        "stdout_tail": (completed.stdout or "")[-4000:],
        "stderr_tail": (completed.stderr or "")[-4000:],
        "requirements": list(THIRD_PARTY_REQUIREMENTS),
        "proxy": PIP_PROXY,
    }
    if completed.returncode != 0:
        raise RuntimeError("Failed to install MCP dependencies with required proxy command")
    importlib.invalidate_caches()
    importlib.import_module("mcp.client.stdio")
    importlib.import_module("mcp.client.session")
    importlib.import_module("mcp.client.sse")
    importlib.import_module("pydantic")
    _stage("mcp_dependency_install_done")


def _model_dump(obj):
    if hasattr(obj, "model_dump"):
        try:
            return obj.model_dump(mode="json")
        except TypeError:
            return obj.model_dump()
    if isinstance(obj, dict):
        return obj
    return {"repr": repr(obj)}


def _tool_payload(call_result) -> dict:
    raw = _model_dump(call_result)
    structured = raw.get("structuredContent") or raw.get("structured_content")
    if isinstance(structured, dict):
        return structured
    for item in raw.get("content") or []:
        text = item.get("text") if isinstance(item, dict) else getattr(item, "text", None)
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except Exception:
            return {"text": text, "_raw": raw}
        if isinstance(parsed, dict):
            return parsed
        return {"value": parsed, "_raw": raw}
    return {"_raw": raw}


def _tool_is_error(call_result) -> bool:
    raw = _model_dump(call_result)
    return bool(raw.get("isError") or raw.get("is_error"))


def _server_env(runtime_root: Path, worker_ida: Path, ready: dict) -> dict[str, str]:
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(runtime_root) if not existing_pythonpath else str(runtime_root) + os.pathsep + existing_pythonpath
    env["IDA_SCRIPT_MCP_IDA_PATH"] = str(worker_ida)
    env["IDA_SCRIPT_MCP_WORK_DIR"] = str(WORK_DIR / "U004_worker_jobs")
    env["IDA_SCRIPT_MCP_KEEP_JOBS"] = "1"
    env["IDA_SCRIPT_MCP_PORT"] = str(int(ready["port"]))
    env["IDA_SCRIPT_MCP_U004_COMMENT"] = "u004 real MCP client dry-run comment"
    return env


def _assert_tool_payload(result: dict, key: str, payload: dict) -> None:
    _check(result, f"MCP tool {key} returned dict", isinstance(payload, dict), payload)
    _check(result, f"MCP tool {key} did not return tool error", payload.get("error") is not True, payload)


def _schema_contains_property(schema: object, property_name: str) -> bool:
    if isinstance(schema, dict):
        properties = schema.get("properties")
        if isinstance(properties, dict) and property_name in properties:
            return True
        return any(_schema_contains_property(value, property_name) for value in schema.values())
    if isinstance(schema, list):
        return any(_schema_contains_property(value, property_name) for value in schema)
    return False


async def _run_stdio_mcp_client(ready: dict, runtime_root: Path, worker_ida: Path, worker_script: Path, result: dict) -> None:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    preselected_functions = _json_request(
        "POST",
        str(ready["base_url"]),
        "/functions",
        {"offset": 0, "limit": 5, "include_thunks": True, "include_library_functions": True},
        expected_status=200,
        timeout=10,
    )
    preselected_function_list = preselected_functions["body"].get("functions") or []
    _check(result, "U004 preselects target function before MCP server start", bool(preselected_function_list), preselected_functions["body"])
    target_ea = int(preselected_function_list[0]["start_ea"])
    target_hex = hex(target_ea)

    env = _server_env(runtime_root, worker_ida, ready)
    env["IDA_SCRIPT_MCP_U004_TARGET_EA"] = target_hex
    server_parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ida_script_mcp.server", "--ida-port", str(int(ready["port"])), "--transport", "stdio"],
        env=env,
        cwd=str(WORK_DIR),
        encoding="utf-8",
        encoding_error_handler="replace",
    )
    _stage("mcp_stdio_client_start", {"command": server_parameters.command, "args": server_parameters.args})
    observed: dict = {"transport": "stdio", "tool_results": {}, "preselected_target": target_hex}
    result["mcp_stdio"] = observed

    async with stdio_client(server_parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialize_result = await session.initialize()
            observed["initialize"] = _model_dump(initialize_result)
            tools_result = await session.list_tools()
            tools_dump = _model_dump(tools_result)
            observed["list_tools"] = tools_dump
            tool_names = [tool.get("name") for tool in tools_dump.get("tools", []) if isinstance(tool, dict)]
            observed["tool_names"] = tool_names
            required_tools = {
                "list_ida_instances",
                "get_ida_database_info",
                "list_functions",
                "decompile_function",
                "get_xrefs",
                "execute_idapython",
                "apply_worker_changes",
            }
            _check(result, "stdio list_tools includes required tools", required_tools.issubset(set(tool_names)), tool_names)

            def _schema_for(name: str) -> dict:
                for tool in tools_dump.get("tools", []):
                    if isinstance(tool, dict) and tool.get("name") == name:
                        return tool.get("inputSchema") or tool.get("input_schema") or {}
                return {}

            execute_schema = _schema_for("execute_idapython")
            _check(result, "stdio execute_idapython schema has properties", bool(execute_schema.get("properties")), execute_schema)
            _check(result, "stdio execute_idapython schema wraps params", "params" in execute_schema.get("properties", {}), execute_schema)
            _check(result, "stdio execute_idapython schema includes timeout_seconds", _schema_contains_property(execute_schema, "timeout_seconds"), execute_schema)

            instances_call = await session.call_tool("list_ida_instances", {})
            _check(result, "stdio list_ida_instances not error", not _tool_is_error(instances_call), _model_dump(instances_call))
            instances = _tool_payload(instances_call)
            observed["tool_results"]["list_ida_instances"] = instances
            _assert_tool_payload(result, "list_ida_instances", instances)
            _check(result, "stdio list_ida_instances sees IDA", int(instances.get("count", 0)) >= 1, instances)

            db_call = await session.call_tool("get_ida_database_info", {"params": {"port": int(ready["port"])}})
            _check(result, "stdio get_ida_database_info not error", not _tool_is_error(db_call), _model_dump(db_call))
            db_info = _tool_payload(db_call)
            observed["tool_results"]["get_ida_database_info"] = db_info
            _assert_tool_payload(result, "get_ida_database_info", db_info)
            _check(result, "stdio db info clean before execute", db_info.get("dirty") is False, db_info)
            _check(result, "stdio db info has database_sha256", bool(db_info.get("database_sha256")), db_info)

            functions_call = await session.call_tool(
                "list_functions",
                {"params": {"port": int(ready["port"]), "offset": 0, "limit": 5, "include_thunks": True, "include_library_functions": True}},
            )
            _check(result, "stdio list_functions not error", not _tool_is_error(functions_call), _model_dump(functions_call))
            functions = _tool_payload(functions_call)
            observed["tool_results"]["list_functions"] = functions
            _assert_tool_payload(result, "list_functions", functions)
            function_list = functions.get("functions") or []
            _check(result, "stdio list_functions returned functions", bool(function_list), functions)

            decompile_call = await session.call_tool(
                "decompile_function",
                {"params": {"port": int(ready["port"]), "address": target_hex, "include_disassembly": True}},
            )
            _check(result, "stdio decompile_function not error", not _tool_is_error(decompile_call), _model_dump(decompile_call))
            decompile = _tool_payload(decompile_call)
            observed["tool_results"]["decompile_function"] = decompile
            _assert_tool_payload(result, "decompile_function", decompile)
            _check(result, "stdio decompile_function found target", decompile.get("found") is True, decompile)

            xrefs_call = await session.call_tool(
                "get_xrefs",
                {"params": {"port": int(ready["port"]), "address": target_hex, "direction": "to", "xref_kind": "all", "limit": 20}},
            )
            _check(result, "stdio get_xrefs not error", not _tool_is_error(xrefs_call), _model_dump(xrefs_call))
            xrefs = _tool_payload(xrefs_call)
            observed["tool_results"]["get_xrefs"] = xrefs
            _assert_tool_payload(result, "get_xrefs", xrefs)
            _check(result, "stdio get_xrefs returned xrefs list", isinstance(xrefs.get("xrefs"), list), xrefs)

            execute_call = await session.call_tool(
                "execute_idapython",
                {
                    "params": {
                        "port": int(ready["port"]),
                        "script_path": str(WORK_DIR / "U004_missing_source_for_real_MCP_client.py"),
                        "capture_output": True,
                        "timeout_seconds": 5,
                        "collect_changes": True,
                    }
                },
            )
            _check(result, "stdio execute_idapython not MCP error", not _tool_is_error(execute_call), _model_dump(execute_call))
            execute = _tool_payload(execute_call)
            observed["tool_results"]["execute_idapython"] = execute
            _assert_tool_payload(result, "execute_idapython", execute)
            _check(result, "stdio execute_idapython returns structured result", execute.get("status") in {"source_error", "timeout"}, execute)
            _check(result, "stdio execute_idapython isolated true", execute.get("isolated") is True, execute)
            _check(
                result,
                "stdio execute_idapython structured error type",
                (execute.get("error") or {}).get("type") in {"FileNotFoundError", "WorkerHardTimeout"},
                execute,
            )
            if execute.get("status") == "timeout":
                _check(result, "stdio execute_idapython timeout is hard timeout", execute.get("hard_timeout") is True, execute)
                _check(result, "stdio execute_idapython timeout killed worker", execute.get("killed") is True, execute)
            change_set = {
                "schema_version": 1,
                "job_id": "u004-dry-run-comment",
                "database_fingerprint": {
                    "input_file_path": db_info.get("input_file_path"),
                    "database_path": db_info.get("database_path"),
                    "root_filename": db_info.get("root_filename") or db_info.get("database"),
                    "imagebase": db_info.get("imagebase"),
                    "input_md5": db_info.get("input_md5"),
                    "input_sha256": db_info.get("input_sha256"),
                    "processor": db_info.get("processor"),
                    "bitness": db_info.get("bitness"),
                    "database_sha256": db_info.get("database_sha256"),
                    "database_size": db_info.get("database_size"),
                },
                "operations": [
                    {
                        "op_id": "op-u004-comment",
                        "op": "comment",
                        "ea": target_ea,
                        "source": "explicit_api",
                        "confidence": "high",
                        "text": "u004 real MCP client dry-run comment",
                        "repeatable": False,
                    }
                ],
            }
            observed["change_set_summary"] = {
                "job_id": change_set.get("job_id"),
                "operation_count": len(change_set.get("operations") or []),
                "operation_types": [operation.get("op") for operation in change_set.get("operations") or []],
            }

            dry_payload = json.loads(json.dumps(change_set))
            dry_payload["dry_run"] = True
            dry_payload["port"] = int(ready["port"])
            apply_call = await session.call_tool("apply_worker_changes", {"params": dry_payload})
            _check(result, "stdio apply_worker_changes not MCP error", not _tool_is_error(apply_call), _model_dump(apply_call))
            apply_dry = _tool_payload(apply_call)
            observed["tool_results"]["apply_worker_changes"] = apply_dry
            _assert_tool_payload(result, "apply_worker_changes", apply_dry)
            _check(result, "stdio apply_worker_changes dry-run status ok", apply_dry.get("status") == "ok", apply_dry)
            _check(result, "stdio apply_worker_changes dry-run applies nothing", apply_dry.get("applied") == [], apply_dry)
            _check(result, "stdio apply_worker_changes skips dry-run operation", len(apply_dry.get("skipped") or []) == 1, apply_dry)
            _check(result, "stdio apply_worker_changes dry-run errors empty", apply_dry.get("errors") == [], apply_dry)

    _stage("mcp_stdio_client_done", {"tools": observed.get("tool_names")})


async def _run_sse_mcp_client(ready: dict, runtime_root: Path, worker_ida: Path, result: dict) -> None:
    from mcp.client.session import ClientSession
    from mcp.client.sse import sse_client

    env = _server_env(runtime_root, worker_ida, ready)
    command = [sys.executable, "-m", "ida_script_mcp.server", "--ida-port", str(int(ready["port"])), "--transport", "http", "--port", str(MCP_HTTP_PORT)]
    _stage("mcp_http_server_start", {"command": command})
    process = subprocess.Popen(
        command,
        cwd=str(WORK_DIR),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    result["mcp_http"] = {"transport": "http_sse", "port": MCP_HTTP_PORT, "pid": process.pid}
    try:
        url = f"http://127.0.0.1:{MCP_HTTP_PORT}/sse"
        last_error = None
        for attempt in range(20):
            if process.poll() is not None:
                break
            try:
                async with sse_client(url, timeout=2, sse_read_timeout=30) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        initialize_result = await session.initialize()
                        tools_result = await session.list_tools()
                        instances_call = await session.call_tool("list_ida_instances", {})
                        instances = _tool_payload(instances_call)
                        result["mcp_http"].update(
                            {
                                "initialize": _model_dump(initialize_result),
                                "list_tools": _model_dump(tools_result),
                                "list_ida_instances": instances,
                            }
                        )
                        _check(result, "http/sse list_ida_instances not error", not _tool_is_error(instances_call), _model_dump(instances_call))
                        _check(result, "http/sse list_ida_instances sees IDA", int(instances.get("count", 0)) >= 1, instances)
                        _stage("mcp_http_client_done", {"url": url})
                        return
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(0.5)
        stdout_tail, stderr_tail = _read_process_pipes_nonblocking(process)
        raise RuntimeError(
            "HTTP/SSE MCP client failed: "
            + json.dumps(
                {"url": url, "last_error": last_error, "returncode": process.poll(), "stdout_tail": stdout_tail, "stderr_tail": stderr_tail},
                ensure_ascii=False,
            )
        )
    finally:
        _terminate_process(process)
        stdout_tail, stderr_tail = _read_process_pipes_nonblocking(process)
        result["mcp_http"].update({"returncode": process.poll(), "stdout_tail": stdout_tail[-4000:], "stderr_tail": stderr_tail[-4000:]})


def _read_process_pipes_nonblocking(process: subprocess.Popen | None) -> tuple[str, str]:
    if process is None:
        return "", ""
    try:
        stdout, stderr = process.communicate(timeout=5)
    except Exception:
        return "", ""
    return stdout or "", stderr or ""


def _read_process_pipes(process: subprocess.Popen) -> tuple[str, str]:
    try:
        stdout, stderr = process.communicate(timeout=10)
    except Exception:
        stdout, stderr = "", ""
    return stdout or "", stderr or ""


def _run_u004(ready: dict, ida_dir: Path, worker_script: Path, result: dict) -> None:
    health = _health_with_retry(str(ready["base_url"]))
    result["responses"]["health"] = health["body"]
    _check(result, "IDA plugin health ok before MCP client", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])
    runtime_root = _install_runtime_package_files()
    worker_ida = _select_worker_ida_executable(ida_dir)
    _ensure_mcp_dependencies(result)
    asyncio.run(_run_stdio_mcp_client(ready, runtime_root, worker_ida, worker_script, result))
    asyncio.run(_run_sse_mcp_client(ready, runtime_root, worker_ida, result))
    metadata_after = _json_request("GET", str(ready["base_url"]), "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_after_u004"] = metadata_after["body"]
    _check(result, "U004 leaves GUI database clean", metadata_after["body"].get("dirty") is False, metadata_after["body"])


def main() -> int:
    ida_dir = Path(IDA_DIR)
    dll_path = Path(DLL_PATH)
    stdout = ""
    stderr = ""
    process = None
    result: dict = {"status": "failed", "mode": "u004_real_mcp_client", "dll_path": DLL_PATH, "work_dir": str(WORK_DIR), "checks": [], "responses": {}}

    try:
        _stage("validate_inputs_start", {"ida_dir": str(ida_dir), "dll_path": str(dll_path)})
        if not ida_dir.is_dir():
            raise RuntimeError(f"IDA directory does not exist: {ida_dir}")
        if not dll_path.is_file():
            raise RuntimeError(f"DLL path does not exist: {dll_path}")

        plugin_dir = _install_plugin_files()
        worker_script = _write_worker_script()
        ida_executable = _select_ida_executable(ida_dir)
        database_path = WORK_DIR / (dll_path.stem + ".i64")
        bootstrap_path = _write_bootstrap(WORK_DIR, plugin_dir, READY_PATH, HEARTBEAT_PATH)
        _stage("validate_inputs_done", {"ida_executable": str(ida_executable), "plugin_dir": str(plugin_dir), "worker_script": str(worker_script)})

        command = [str(ida_executable), "-A", f"-L{IDA_LOG_PATH}", f"-S{bootstrap_path}", f"-o{database_path}", str(dll_path)]
        _stage("ida_start", {"command": command, "work_dir": str(WORK_DIR)})
        process = subprocess.Popen(command, cwd=str(WORK_DIR), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")

        ready = _wait_for_ready(process, READY_PATH, IDA_LOG_PATH)
        result["ready"] = ready
        _run_u004(ready, ida_dir, worker_script, result)
        result.update({"status": "passed", "ida_executable": str(ida_executable), "ida_log_path": str(IDA_LOG_PATH), "work_dir": str(WORK_DIR), "database_path": str(database_path)})
        _stage("u004_tests_done", {"status": result.get("status")})
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
        print("U004_REAL_MCP_CLIENT_TEST_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "U004_REAL_MCP_CLIENT_TEST_ERROR="
            + json.dumps({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(1)
