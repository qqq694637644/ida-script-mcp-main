from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import json
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

IDA_DIR = "__IDA_DIR_JSON__"
DLL_PATH = "__DLL_PATH_JSON__"
IDA_TIMEOUT_SECONDS = int("__IDA_TIMEOUT_SECONDS_JSON__")
IDA_READY_TIMEOUT_SECONDS = min(90, max(30, IDA_TIMEOUT_SECONDS // 2))
IDA_EXECUTABLE_CANDIDATES = "__IDA_EXECUTABLE_CANDIDATES_JSON__"
LEGACY_ROOT_SUPPORT_FILES = "__LEGACY_ROOT_SUPPORT_FILES_JSON__"
PLUGIN_FILES_B64 = "__PLUGIN_FILES_B64_JSON__"
PLUGIN_EXPECTED_SHA256 = "__PLUGIN_EXPECTED_SHA256_JSON__"
RUNTIME_FILES_B64 = "__RUNTIME_FILES_B64_JSON__"
RUNTIME_EXPECTED_SHA256 = "__RUNTIME_EXPECTED_SHA256_JSON__"
WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-u005-multi-instance-"))
HEARTBEAT_PATH = WORK_DIR / "heartbeat.ndjson"
RESULT_PATH = WORK_DIR / "U005_multi_IDA_instance_selection_result.json"
INSTANCE_INFO_PATH = Path.home() / ".ida_script_mcp_instances.json"
COPY_SUFFIX = "_u005_copy"

BOOTSTRAP_TEMPLATE = r'''
from __future__ import annotations

import json
import sys
import time
import traceback
from pathlib import Path

LABEL = __LABEL_JSON__
READY_PATH = __READY_PATH_JSON__
HEARTBEAT_PATH = __HEARTBEAT_PATH_JSON__
PLUGIN_DIR = __PLUGIN_DIR_JSON__
DLL_PATH = __BOOTSTRAP_DLL_PATH_JSON__


def _write_json(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _stage(name, detail=None):
    payload = {"timestamp": time.time(), "label": LABEL, "stage": name}
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
        raise RuntimeError("Cannot resolve saved IDB/I64 path before U005 test")
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
        saved_database_path = _save_database(idaapi, ida_loader)

        if PLUGIN_DIR not in sys.path:
            sys.path.insert(0, PLUGIN_DIR)

        import importlib.util

        plugin_path = str(Path(PLUGIN_DIR) / "ida_script_mcp.py")
        module_name = "ida_script_mcp_loaded_plugin_" + LABEL.replace("-", "_")
        spec = importlib.util.spec_from_file_location(module_name, plugin_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot load plugin from {plugin_path}")

        _stage("plugin_load_start", {"plugin_path": plugin_path})
        plugin_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin_module)
        plugin_instance = plugin_module.PLUGIN_ENTRY()
        globals()["IDA_SCRIPT_MCP_TEST_PLUGIN_INSTANCE_" + LABEL] = plugin_instance
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
            root_filename = idaapi.get_root_filename()
        except Exception:
            root_filename = Path(input_file_path).name if input_file_path else ""
        try:
            database_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
        except Exception:
            database_path = saved_database_path

        ready = {
            "status": "ready",
            "label": LABEL,
            "base_url": base_url,
            "port": port,
            "dll_path": DLL_PATH,
            "plugin_dir": PLUGIN_DIR,
            "plugin_name": getattr(plugin_module, "PLUGIN_NAME", None),
            "input_file_path": input_file_path,
            "root_filename": root_filename,
            "database_path": database_path,
            "instance_id": getattr(plugin_module.instance_registry, "instance_id", None),
        }
        _write_json(READY_PATH, ready)
        _stage("ready_written", ready)
    except Exception as exc:
        error_payload = {
            "status": "failed",
            "label": LABEL,
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
    print("U005_STAGE=" + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


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


def _select_ida_executable(ida_dir: Path) -> Path:
    preferred = ["ida64.exe", "ida.exe", "idat64.exe", "idat.exe"]
    for candidate in preferred + [name for name in IDA_EXECUTABLE_CANDIDATES if name not in preferred]:
        path = ida_dir / candidate
        if path.is_file():
            return path
    raise RuntimeError("No IDA executable found under " + str(ida_dir))


def _copy_sibling_dll(dll_path: Path) -> Path:
    copy_path = dll_path.with_name(dll_path.stem + COPY_SUFFIX + dll_path.suffix)
    if copy_path.resolve() == dll_path.resolve():
        raise RuntimeError("U005 copy path unexpectedly equals source DLL path")
    if copy_path.exists() or copy_path.is_symlink():
        copy_path.unlink()
    shutil.copy2(dll_path, copy_path)
    if not copy_path.is_file() or copy_path.stat().st_size != dll_path.stat().st_size:
        raise RuntimeError(f"Failed to create same-directory DLL copy: {copy_path}")
    _stage("sibling_dll_copy_done", {"source": str(dll_path), "copy": str(copy_path), "same_dir": copy_path.parent == dll_path.parent})
    return copy_path


def _clear_instance_registry() -> None:
    if INSTANCE_INFO_PATH.exists() or INSTANCE_INFO_PATH.is_symlink():
        INSTANCE_INFO_PATH.unlink()
        _stage("instance_registry_cleared", {"path": str(INSTANCE_INFO_PATH)})
    else:
        _stage("instance_registry_absent", {"path": str(INSTANCE_INFO_PATH)})


def _write_bootstrap(label: str, dll_path: Path, plugin_dir: Path, ready_path: Path, heartbeat_path: Path) -> Path:
    bootstrap_path = WORK_DIR / f"U005_multi_IDA_instance_selection_{label}_bootstrap.py"
    bootstrap_text = BOOTSTRAP_TEMPLATE
    replacements = {
        "__LABEL_JSON__": json.dumps(label),
        "__READY_PATH_JSON__": json.dumps(str(ready_path)),
        "__HEARTBEAT_PATH_JSON__": json.dumps(str(heartbeat_path)),
        "__PLUGIN_DIR_JSON__": json.dumps(str(plugin_dir)),
        "__BOOTSTRAP_DLL_PATH_JSON__": json.dumps(str(dll_path)),
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


def _wait_for_ready(label: str, process: subprocess.Popen, ready_path: Path, ida_log_path: Path) -> dict:
    deadline = time.monotonic() + IDA_READY_TIMEOUT_SECONDS
    _stage("ida_ready_wait_start", {"label": label, "timeout_seconds": IDA_READY_TIMEOUT_SECONDS})
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
                + json.dumps({"label": label, "returncode": process.returncode, "ida_log_tail": _tail(ida_log_path)}, ensure_ascii=False)
            )
        time.sleep(0.5)
    raise RuntimeError(
        "Timed out waiting for IDA ready file: "
        + json.dumps({"label": label, "ready_path": str(ready_path), "ida_log_tail": _tail(ida_log_path), "process_alive": process.poll() is None}, ensure_ascii=False)
    )


def _start_ida_instance(label: str, ida_executable: Path, dll_path: Path, database_path: Path, plugin_dir: Path) -> dict:
    ready_path = WORK_DIR / f"{label}_ida_ready.json"
    heartbeat_path = WORK_DIR / f"{label}_heartbeat.ndjson"
    ida_log_path = WORK_DIR / f"{label}_ida.log"
    bootstrap_path = _write_bootstrap(label, dll_path, plugin_dir, ready_path, heartbeat_path)
    command = [str(ida_executable), "-A", f"-L{ida_log_path}", f"-S{bootstrap_path}", f"-o{database_path}", str(dll_path)]
    _stage("ida_start", {"label": label, "command": command})
    process = subprocess.Popen(command, cwd=str(WORK_DIR), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
    ready = _wait_for_ready(label, process, ready_path, ida_log_path)
    health = _json_request("GET", str(ready["base_url"]), "/health", expected_status=200, timeout=5)["body"]
    _stage("ida_health_seen", {"label": label, "health": health})
    return {
        "label": label,
        "process": process,
        "ready": ready,
        "health": health,
        "ida_log_path": ida_log_path,
        "heartbeat_path": heartbeat_path,
        "database_path": database_path,
        "dll_path": dll_path,
    }


def _read_process_pipes(process: subprocess.Popen) -> tuple[str, str]:
    try:
        stdout, stderr = process.communicate(timeout=10)
    except Exception:
        stdout, stderr = "", ""
    return stdout or "", stderr or ""


def _record_instance_summary(instance: dict) -> dict:
    ready = instance["ready"]
    return {
        "label": instance["label"],
        "pid": instance["process"].pid,
        "returncode": instance["process"].poll(),
        "port": ready.get("port"),
        "instance_id": ready.get("instance_id"),
        "root_filename": ready.get("root_filename"),
        "input_file_path": ready.get("input_file_path"),
        "database_path": ready.get("database_path"),
        "base_url": ready.get("base_url"),
        "ida_log_tail": _tail(instance["ida_log_path"], 4000),
        "heartbeat_tail": _tail(instance["heartbeat_path"], 4000),
    }


def _find_record(records: list[dict], instance_id: str) -> dict:
    for record in records:
        if record.get("instance_id") == instance_id:
            return record
    raise AssertionError(f"Instance {instance_id!r} not found in records: {records!r}")


async def _run_selection_tests(result: dict, primary: dict, copy_instance: dict, copy_path: Path) -> None:
    runtime_root = _install_runtime_package_files()
    os.environ.pop("IDA_SCRIPT_MCP_PORT", None)
    os.environ.pop("IDA_SCRIPT_MCP_INSTANCE_ID", None)
    importlib.invalidate_caches()
    server = importlib.import_module("ida_script_mcp.server")

    primary_ready = primary["ready"]
    copy_ready = copy_instance["ready"]
    primary_id = str(primary_ready["instance_id"])
    copy_id = str(copy_ready["instance_id"])
    primary_port = int(primary_ready["port"])
    copy_port = int(copy_ready["port"])
    primary_name = Path(str(primary_ready["input_file_path"])).name
    copy_name = copy_path.name

    result["runtime_root"] = str(runtime_root)
    result["selection"] = {
        "primary_id": primary_id,
        "copy_id": copy_id,
        "primary_port": primary_port,
        "copy_port": copy_port,
        "primary_name": primary_name,
        "copy_name": copy_name,
    }

    _check(result, "U005 starts two different instance ids", primary_id != copy_id, result["selection"])
    _check(result, "U005 starts two different ports", primary_port != copy_port, result["selection"])
    _check(result, "U005 copy is same directory as original", copy_path.parent == Path(DLL_PATH).parent, str(copy_path))
    _check(result, "U005 copy filename includes suffix", COPY_SUFFIX in copy_name, copy_name)

    instances = await server.list_ida_instances()
    result["responses"]["list_ida_instances"] = instances
    records = instances.get("instances") or []
    _check(result, "list_ida_instances returns at least two instances", int(instances.get("count", 0)) >= 2, instances)
    primary_record = _find_record(records, primary_id)
    copy_record = _find_record(records, copy_id)
    _check(result, "primary record has expected port", int(primary_record.get("port")) == primary_port, primary_record)
    _check(result, "copy record has expected port", int(copy_record.get("port")) == copy_port, copy_record)
    _check(result, "primary record database matches original", str(primary_record.get("database", "")).lower() == primary_name.lower(), primary_record)
    _check(result, "copy record database matches copied DLL", str(copy_record.get("database", "")).lower() == copy_name.lower(), copy_record)

    no_selector = await server.get_ida_database_info(server.DatabaseInfoInput())
    result["responses"]["get_info_no_selector"] = no_selector
    _check(result, "no selector rejects multiple instances", "Multiple IDA instances found" in str(no_selector.get("error", "")), no_selector)

    primary_by_full_id = await server.get_ida_database_info(server.DatabaseInfoInput(instance_id=primary_id))
    result["responses"]["primary_by_full_id"] = primary_by_full_id
    _check(result, "full primary instance_id selects primary", primary_by_full_id.get("instance_id") == primary_id, primary_by_full_id)
    _check(result, "full primary selection returns primary port", int(primary_by_full_id.get("port")) == primary_port, primary_by_full_id)
    _check(result, "full primary selection returns clean database", primary_by_full_id.get("dirty") is False, primary_by_full_id)

    copy_by_full_id = await server.get_ida_database_info(server.DatabaseInfoInput(instance_id=copy_id))
    result["responses"]["copy_by_full_id"] = copy_by_full_id
    _check(result, "full copy instance_id selects copy", copy_by_full_id.get("instance_id") == copy_id, copy_by_full_id)
    _check(result, "full copy selection returns copy port", int(copy_by_full_id.get("port")) == copy_port, copy_by_full_id)
    _check(result, "full copy selection returns clean database", copy_by_full_id.get("dirty") is False, copy_by_full_id)

    primary_by_filename = await server.get_ida_database_info(server.DatabaseInfoInput(instance_id=primary_name))
    result["responses"]["primary_by_filename"] = primary_by_filename
    _check(result, "unique primary filename substring selects primary", primary_by_filename.get("instance_id") == primary_id, primary_by_filename)

    copy_by_substring = await server.get_ida_database_info(server.DatabaseInfoInput(instance_id=COPY_SUFFIX.lstrip("_")))
    result["responses"]["copy_by_substring"] = copy_by_substring
    _check(result, "unique copy substring selects copy", copy_by_substring.get("instance_id") == copy_id, copy_by_substring)

    copy_by_port = await server.get_ida_database_info(server.DatabaseInfoInput(port=copy_port))
    result["responses"]["copy_by_port"] = copy_by_port
    _check(result, "port selector selects copy", copy_by_port.get("instance_id") == copy_id, copy_by_port)

    port_precedence = await server.get_ida_database_info(server.DatabaseInfoInput(instance_id=primary_id, port=copy_port))
    result["responses"]["port_precedence"] = port_precedence
    _check(result, "port takes precedence over conflicting instance_id", port_precedence.get("instance_id") == copy_id, port_precedence)

    ambiguous = await server.get_ida_database_info(server.DatabaseInfoInput(instance_id="test1"))
    result["responses"]["ambiguous_test1"] = ambiguous
    _check(result, "ambiguous substring is rejected", "matched multiple instance ids" in str(ambiguous.get("error", "")), ambiguous)

    missing = await server.get_ida_database_info(server.DatabaseInfoInput(instance_id="definitely_missing_u005_instance"))
    result["responses"]["missing_instance"] = missing
    _check(result, "missing instance is rejected", "not found" in str(missing.get("error", "")), missing)

    primary_functions = await server.list_functions(
        server.ListFunctionsInput(instance_id=primary_id, offset=0, limit=3, include_thunks=True, include_library_functions=True)
    )
    result["responses"]["primary_functions_by_id"] = primary_functions
    _check(result, "list_functions by primary id returns primary", primary_functions.get("instance_id") == primary_id, primary_functions)
    _check(result, "list_functions by primary id returns functions", int(primary_functions.get("returned", 0)) > 0, primary_functions)

    copy_functions = await server.list_functions(
        server.ListFunctionsInput(instance_id=COPY_SUFFIX.lstrip("_"), offset=0, limit=3, include_thunks=True, include_library_functions=True)
    )
    result["responses"]["copy_functions_by_substring"] = copy_functions
    _check(result, "list_functions by copy substring returns copy", copy_functions.get("instance_id") == copy_id, copy_functions)
    _check(result, "list_functions by copy substring returns functions", int(copy_functions.get("returned", 0)) > 0, copy_functions)

    _stage("u005_selection_tests_done", result["selection"])


def main() -> int:
    ida_dir = Path(IDA_DIR)
    dll_path = Path(DLL_PATH)
    copy_path: Path | None = None
    instances: list[dict] = []
    result: dict = {"status": "failed", "mode": "u005_multi_ida_instance_selection", "dll_path": DLL_PATH, "work_dir": str(WORK_DIR), "checks": [], "responses": {}}

    try:
        _stage("validate_inputs_start", {"ida_dir": str(ida_dir), "dll_path": str(dll_path)})
        if not ida_dir.is_dir():
            raise RuntimeError(f"IDA directory does not exist: {ida_dir}")
        if not dll_path.is_file():
            raise RuntimeError(f"DLL path does not exist: {dll_path}")

        plugin_dir = _install_plugin_files()
        ida_executable = _select_ida_executable(ida_dir)
        _clear_instance_registry()
        copy_path = _copy_sibling_dll(dll_path)
        result["copied_dll"] = {"source": str(dll_path), "copy": str(copy_path), "same_dir": copy_path.parent == dll_path.parent}

        primary = _start_ida_instance("primary", ida_executable, dll_path, WORK_DIR / "primary.i64", plugin_dir)
        instances.append(primary)
        copy_instance = _start_ida_instance("copy", ida_executable, copy_path, WORK_DIR / "copy.i64", plugin_dir)
        instances.append(copy_instance)
        result["instances"] = [_record_instance_summary(instance) for instance in instances]

        asyncio.run(_run_selection_tests(result, primary, copy_instance, copy_path))
        result["instances_after_tests"] = [_record_instance_summary(instance) for instance in instances]
        result.update({"status": "passed", "ida_executable": str(ida_executable), "work_dir": str(WORK_DIR)})
        _stage("u005_tests_done", {"status": result.get("status")})
    except Exception as exc:
        result["status"] = "failed"
        result["failed_stage"] = _tail(HEARTBEAT_PATH, max_chars=3000)
        result["error"] = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    finally:
        for instance in reversed(instances):
            _terminate_process(instance.get("process"))
        terminated_summaries = []
        for instance in instances:
            process = instance.get("process")
            stdout, stderr = _read_process_pipes(process) if process is not None else ("", "")
            summary = _record_instance_summary(instance)
            summary.update({"stdout_tail": stdout[-4000:], "stderr_tail": stderr[-4000:]})
            terminated_summaries.append(summary)
        if terminated_summaries:
            result["instances_after_cleanup"] = terminated_summaries
        if copy_path is not None:
            try:
                copy_path.unlink(missing_ok=True)
                result["copied_dll_cleanup"] = {"path": str(copy_path), "exists_after_cleanup": copy_path.exists()}
            except Exception as exc:
                result["copied_dll_cleanup"] = {"path": str(copy_path), "error": f"{type(exc).__name__}: {exc}"}
        result.update({"heartbeat_tail": _tail(HEARTBEAT_PATH)})
        _write_json(RESULT_PATH, result)
        print("U005_MULTI_IDA_INSTANCE_TEST_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "U005_MULTI_IDA_INSTANCE_TEST_ERROR="
            + json.dumps({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(1)
