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
TEST_MODE = "__TEST_MODE_JSON__"
USER_SCRIPT_FILENAME = "__USER_SCRIPT_FILENAME_JSON__"
IDA_TIMEOUT_SECONDS = int("__IDA_TIMEOUT_SECONDS_JSON__")
IDA_READY_TIMEOUT_SECONDS = min(60, max(15, IDA_TIMEOUT_SECONDS // 3))
IDA_EXECUTABLE_CANDIDATES = "__IDA_EXECUTABLE_CANDIDATES_JSON__"
LEGACY_ROOT_SUPPORT_FILES = "__LEGACY_ROOT_SUPPORT_FILES_JSON__"
PLUGIN_FILES_B64 = "__PLUGIN_FILES_B64_JSON__"
PLUGIN_EXPECTED_SHA256 = "__PLUGIN_EXPECTED_SHA256_JSON__"
RUNTIME_FILES_B64 = "__RUNTIME_FILES_B64_JSON__"
RUNTIME_EXPECTED_SHA256 = "__RUNTIME_EXPECTED_SHA256_JSON__"
USER_SCRIPTS_B64 = "__USER_SCRIPT_B64_JSON__"
USER_SCRIPT_SHA256 = "__USER_SCRIPT_SHA256_JSON__"
WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-worker-chain-"))
READY_PATH = WORK_DIR / "ida_ready.json"
HEARTBEAT_PATH = WORK_DIR / "heartbeat.ndjson"
RESULT_PATH = WORK_DIR / "worker_chain_test_result.json"
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
        raise RuntimeError("Cannot resolve saved IDB/I64 path before worker-chain test")
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
    print("WORKER_CHAIN_STAGE=" + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


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
    _stage(
        "legacy_support_cleanup_done",
        {"removed": removed_legacy_support_files, "remaining": remaining_legacy_support_files},
    )
    if remaining_legacy_support_files:
        raise RuntimeError(
            "Legacy root support files remain in IDA plugins directory: "
            + ", ".join(remaining_legacy_support_files)
        )
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


def _write_worker_user_scripts() -> dict[str, Path]:
    scripts: dict[str, Path] = {}
    for filename, encoded in USER_SCRIPTS_B64.items():
        user_script = WORK_DIR / filename
        content = base64.b64decode(encoded.encode("ascii"))
        _write_bytes_atomic(user_script, content)
        digest = _sha256(user_script)
        expected_digest = USER_SCRIPT_SHA256[filename]
        if digest != expected_digest:
            raise RuntimeError(f"SHA-256 mismatch for worker user script {filename}")
        py_compile.compile(str(user_script), doraise=True)
        scripts[filename] = user_script
    if USER_SCRIPT_FILENAME not in scripts:
        raise RuntimeError(f"Primary worker user script is missing: {USER_SCRIPT_FILENAME}")
    return scripts


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


def _select_worker_ida_executable(ida_dir: Path) -> Path:
    for candidate in ("idat64.exe", "idat.exe", "ida64.exe", "ida.exe"):
        path = ida_dir / candidate
        if path.is_file():
            return path
    raise RuntimeError(
        "No worker-capable IDA executable found under "
        + str(ida_dir)
        + "; checked idat64.exe, idat.exe, ida64.exe, ida.exe"
    )


def _write_bootstrap(work_dir: Path, plugin_dir: Path, ready_path: Path, heartbeat_path: Path) -> Path:
    bootstrap_path = work_dir / "ida_worker_chain_bootstrap.py"
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
                    {"returncode": process.returncode, "ida_log_tail": _tail(ida_log_path)},
                    ensure_ascii=False,
                )
            )
        time.sleep(0.5)
    raise RuntimeError(
        "Timed out waiting for IDA ready file: "
        + json.dumps(
            {"ready_path": str(ready_path), "ida_log_tail": _tail(ida_log_path), "process_alive": process.poll() is None},
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


def _run_worker_chain(
    ready: dict,
    base_url: str,
    ida_dir: Path,
    user_script: Path,
    result: dict,
) -> None:
    health = _health_with_retry(base_url)
    result["responses"]["health"] = health["body"]
    _check(result, "health reports plugin name", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])

    metadata = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_before"] = metadata["body"]
    _check(result, "metadata clean before execution", metadata["body"].get("dirty_state_known") is True and metadata["body"].get("dirty") is False, metadata["body"])
    database_sha256 = metadata["body"].get("database_sha256")
    _check(result, "metadata includes database_sha256", bool(database_sha256), metadata["body"])

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
    _check(result, "functions endpoint returns at least one function", len(functions) > 0, functions_page["body"])

    target_ea = int(functions[0]["start_ea"])
    target_hex = hex(target_ea)
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
    _check(result, "inspect before resolves target", before_body.get("found") is True, before_body)

    run_id = str(int(time.time()))
    new_name = f"mcp_worker_chain_{run_id}"
    comment_text = f"mcp worker chain comment {run_id}"

    runtime_root = _install_runtime_package_files()
    worker_ida = _select_worker_ida_executable(ida_dir)
    worker_jobs = WORK_DIR / "worker_jobs"
    env_keys = [
        "IDA_SCRIPT_MCP_IDA_PATH",
        "IDA_SCRIPT_MCP_WORK_DIR",
        "IDA_SCRIPT_MCP_KEEP_JOBS",
        "IDA_SCRIPT_MCP_WORKER_TIMEOUT_SENTINEL",
        "IDA_SCRIPT_MCP_WORKER_CHAIN_TARGET_EA",
        "IDA_SCRIPT_MCP_WORKER_CHAIN_NEW_NAME",
        "IDA_SCRIPT_MCP_WORKER_CHAIN_COMMENT",
    ]
    previous_env = {key: os.environ.get(key) for key in env_keys}
    os.environ["IDA_SCRIPT_MCP_IDA_PATH"] = str(worker_ida)
    os.environ["IDA_SCRIPT_MCP_WORK_DIR"] = str(worker_jobs)
    os.environ["IDA_SCRIPT_MCP_KEEP_JOBS"] = "1"
    os.environ["IDA_SCRIPT_MCP_WORKER_CHAIN_TARGET_EA"] = target_hex
    os.environ["IDA_SCRIPT_MCP_WORKER_CHAIN_NEW_NAME"] = new_name
    os.environ["IDA_SCRIPT_MCP_WORKER_CHAIN_COMMENT"] = comment_text
    _stage(
        "worker_chain_runtime_prepare_done",
        {"runtime_root": str(runtime_root), "worker_ida": str(worker_ida), "user_script": str(user_script)},
    )

    try:
        import asyncio
        from ida_script_mcp import server as mcp_server

        class ExecuteParams:
            instance_id = None
            port = int(ready["port"])
            code = None
            script_path = str(user_script)
            capture_output = True
            timeout_seconds = 90
            collect_changes = True

            def to_execute_request(self):
                return mcp_server.ExecuteRequest.model_validate(
                    {
                        "code": self.code,
                        "script_path": self.script_path,
                        "capture_output": self.capture_output,
                        "timeout_seconds": self.timeout_seconds,
                    }
                )

        class ApplyParams:
            instance_id = None

            def __init__(self, payload: dict):
                self._payload = dict(payload)
                self.port = int(self._payload.get("port") or ready["port"])

            def model_dump(self, mode="json", exclude=None):
                exclude = exclude or set()
                return {key: value for key, value in self._payload.items() if key not in exclude}

        execute_params = ExecuteParams()
        _stage("worker_chain_execute_start", {"port": int(ready["port"])})
        execute_result = asyncio.run(mcp_server.execute_idapython(execute_params))
        result["responses"]["execute_idapython"] = execute_result
        _check(result, "execute status ok", execute_result.get("status") == "ok", execute_result)
        _check(result, "execute isolated true", execute_result.get("isolated") is True, execute_result)
        _check(result, "execute job_id present", bool(execute_result.get("job_id")), execute_result)
        changes = execute_result.get("changes") or []
        _check(result, "execute produced changes", len(changes) >= 2, execute_result)
        _stage(
            "worker_chain_execute_done",
            {"status": execute_result.get("status"), "job_id": execute_result.get("job_id"), "change_count": len(changes)},
        )

        artifacts = execute_result.get("artifacts") or {}
        changes_path = artifacts.get("changes")
        _check(result, "changes artifact path present", bool(changes_path), artifacts)
        change_set = json.loads(Path(changes_path).read_text(encoding="utf-8"))
        result["worker_chain_change_set_summary"] = {
            "schema_version": change_set.get("schema_version"),
            "job_id": change_set.get("job_id"),
            "operation_count": len(change_set.get("operations") or []),
            "operation_types": [operation.get("op") for operation in change_set.get("operations") or []],
            "database_sha256": (change_set.get("database_fingerprint") or {}).get("database_sha256"),
        }
        _check(result, "changes artifact matches execute job", change_set.get("job_id") == execute_result.get("job_id"), change_set)
        _check(result, "change fingerprint matches metadata", (change_set.get("database_fingerprint") or {}).get("database_sha256") == database_sha256, change_set)

        dry_payload = json.loads(json.dumps(change_set))
        dry_payload["dry_run"] = True
        dry_payload["port"] = int(ready["port"])
        dry_result = asyncio.run(mcp_server.apply_worker_changes(ApplyParams(dry_payload)))
        result["responses"]["apply_worker_changes_dry_run"] = dry_result
        _check(result, "dry-run status ok", dry_result.get("status") == "ok", dry_result)
        _check(result, "dry-run applies nothing", dry_result.get("applied") == [], dry_result)
        _check(result, "dry-run skips all operations", len(dry_result.get("skipped") or []) == len(change_set.get("operations") or []), dry_result)

        inspect_after_dry = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": target_hex, "byte_count": 8},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["inspect_after_dry_run"] = inspect_after_dry["body"]
        _check(result, "dry-run leaves name unchanged", inspect_after_dry["body"].get("name") == before_body.get("name"), inspect_after_dry["body"])
        _check(result, "dry-run leaves comment unchanged", inspect_after_dry["body"].get("comment") == before_body.get("comment"), inspect_after_dry["body"])

        apply_payload = json.loads(json.dumps(change_set))
        apply_payload["dry_run"] = False
        apply_payload["port"] = int(ready["port"])
        apply_result = asyncio.run(mcp_server.apply_worker_changes(ApplyParams(apply_payload)))
        result["responses"]["apply_worker_changes_destructive"] = apply_result
        _check(result, "destructive apply status ok", apply_result.get("status") == "ok", apply_result)
        _check(result, "destructive apply applied all operations", len(apply_result.get("applied") or []) == len(change_set.get("operations") or []), apply_result)
        _check(result, "destructive apply has no errors", apply_result.get("errors") == [], apply_result)

        inspect_after_apply = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": target_hex, "byte_count": 8},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["inspect_after_apply"] = inspect_after_apply["body"]
        _check(result, "applied rename visible", inspect_after_apply["body"].get("name") == new_name, inspect_after_apply["body"])
        _check(result, "applied comment visible", inspect_after_apply["body"].get("comment") == comment_text, inspect_after_apply["body"])

        metadata_after_apply = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
        result["responses"]["metadata_after_apply"] = metadata_after_apply["body"]
        _check(result, "metadata dirty after destructive apply", metadata_after_apply["body"].get("dirty") is True, metadata_after_apply["body"])
    finally:
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _pid_exists(pid: int | None) -> bool:
    if pid is None:
        return False
    try:
        completed = subprocess.run(
            ["tasklist", "/FI", f"PID eq {int(pid)}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except Exception:
        return False
    return str(int(pid)) in (completed.stdout or "")


def _run_worker_timeout(
    ready: dict,
    base_url: str,
    ida_dir: Path,
    user_script: Path,
    result: dict,
) -> None:
    health = _health_with_retry(base_url)
    result["responses"]["health"] = health["body"]
    _check(result, "health reports plugin name", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])

    metadata_before = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_before"] = metadata_before["body"]
    _check(
        result,
        "metadata clean before timeout execution",
        metadata_before["body"].get("dirty_state_known") is True and metadata_before["body"].get("dirty") is False,
        metadata_before["body"],
    )

    runtime_root = _install_runtime_package_files()
    worker_ida = _select_worker_ida_executable(ida_dir)
    worker_jobs = WORK_DIR / "worker_jobs"
    sentinel_path = WORK_DIR / "worker_timeout_started.txt"
    env_keys = [
        "IDA_SCRIPT_MCP_IDA_PATH",
        "IDA_SCRIPT_MCP_WORK_DIR",
        "IDA_SCRIPT_MCP_KEEP_JOBS",
        "IDA_SCRIPT_MCP_WORKER_TIMEOUT_SENTINEL",
    ]
    previous_env = {key: os.environ.get(key) for key in env_keys}
    os.environ["IDA_SCRIPT_MCP_IDA_PATH"] = str(worker_ida)
    os.environ["IDA_SCRIPT_MCP_WORK_DIR"] = str(worker_jobs)
    os.environ["IDA_SCRIPT_MCP_KEEP_JOBS"] = "1"
    os.environ["IDA_SCRIPT_MCP_WORKER_TIMEOUT_SENTINEL"] = str(sentinel_path)
    _stage(
        "worker_timeout_runtime_prepare_done",
        {"runtime_root": str(runtime_root), "worker_ida": str(worker_ida), "user_script": str(user_script)},
    )

    try:
        import asyncio
        from ida_script_mcp import server as mcp_server

        class ExecuteParams:
            instance_id = None
            port = int(ready["port"])
            code = None
            script_path = str(user_script)
            capture_output = True
            timeout_seconds = 2
            collect_changes = True

            def to_execute_request(self):
                return mcp_server.ExecuteRequest.model_validate(
                    {
                        "code": self.code,
                        "script_path": self.script_path,
                        "capture_output": self.capture_output,
                        "timeout_seconds": self.timeout_seconds,
                    }
                )

        _stage("worker_timeout_execute_start", {"port": int(ready["port"]), "timeout_seconds": 2})
        execute_result = asyncio.run(mcp_server.execute_idapython(ExecuteParams()))
        result["responses"]["execute_idapython_timeout"] = execute_result
        _check(result, "timeout execute status", execute_result.get("status") == "timeout", execute_result)
        _check(result, "timeout execute isolated true", execute_result.get("isolated") is True, execute_result)
        _check(result, "timeout hard_timeout true", execute_result.get("hard_timeout") is True, execute_result)
        _check(result, "timeout killed true", execute_result.get("killed") is True, execute_result)
        _check(result, "timeout worker_pid recorded", execute_result.get("worker_pid") is not None, execute_result)
        _check(result, "timeout worker_exit_code recorded", execute_result.get("worker_exit_code") is not None, execute_result)
        _check(result, "timeout worker process gone", not _pid_exists(execute_result.get("worker_pid")), execute_result)
        _check(result, "timeout user script reached blocking section", sentinel_path.is_file(), {"sentinel": str(sentinel_path)})
        _check(result, "timeout produced no changes", execute_result.get("changes") == [], execute_result)
        _stage(
            "worker_timeout_execute_done",
            {
                "status": execute_result.get("status"),
                "worker_pid": execute_result.get("worker_pid"),
                "worker_exit_code": execute_result.get("worker_exit_code"),
                "killed": execute_result.get("killed"),
            },
        )

        metadata_after = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
        result["responses"]["metadata_after_timeout"] = metadata_after["body"]
        _check(result, "metadata stays clean after timeout", metadata_after["body"].get("dirty") is False, metadata_after["body"])
        _check(
            result,
            "apply_changes mutation flag stays false after timeout",
            metadata_after["body"].get("apply_changes_mutated") is False,
            metadata_after["body"],
        )
        result["worker_timeout_summary"] = {
            "status": execute_result.get("status"),
            "hard_timeout": execute_result.get("hard_timeout"),
            "killed": execute_result.get("killed"),
            "worker_pid": execute_result.get("worker_pid"),
            "worker_exit_code": execute_result.get("worker_exit_code"),
            "worker_process_alive_after_kill": _pid_exists(execute_result.get("worker_pid")),
            "sentinel_path": str(sentinel_path),
            "sentinel_seen": sentinel_path.is_file(),
            "metadata_dirty_after_timeout": metadata_after["body"].get("dirty"),
        }
    finally:
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _run_worker_failure_matrix(
    ready: dict,
    base_url: str,
    ida_dir: Path,
    user_scripts: dict[str, Path],
    result: dict,
) -> None:
    health = _health_with_retry(base_url)
    result["responses"]["health"] = health["body"]
    _check(result, "health reports plugin name", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])

    metadata_before = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_before"] = metadata_before["body"]
    _check(
        result,
        "metadata clean before failure matrix",
        metadata_before["body"].get("dirty_state_known") is True and metadata_before["body"].get("dirty") is False,
        metadata_before["body"],
    )

    functions_page = _json_request(
        "POST",
        base_url,
        "/functions",
        {"offset": 0, "limit": 5, "include_thunks": True, "include_library_functions": True},
        expected_status=200,
        timeout=10,
    )
    functions = functions_page["body"].get("functions") or []
    _check(result, "failure matrix has target function", bool(functions), functions_page["body"])
    target_ea = int(functions[0]["start_ea"])
    target_hex = hex(target_ea)

    runtime_root = _install_runtime_package_files()
    worker_ida = _select_worker_ida_executable(ida_dir)
    worker_jobs = WORK_DIR / "worker_failure_matrix_jobs"
    matrix: dict[str, dict] = {}
    result["worker_failure_matrix"] = matrix

    def _execute_case(
        case_id: str,
        script_path: Path,
        *,
        expected_status: str,
        timeout_seconds: int = 30,
        ida_path: Path | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> dict:
        env_keys = [
            "IDA_SCRIPT_MCP_IDA_PATH",
            "IDA_SCRIPT_MCP_WORK_DIR",
            "IDA_SCRIPT_MCP_KEEP_JOBS",
            "IDA_SCRIPT_MCP_WORKER_FAILURE_TARGET_EA",
        ]
        extra_env = extra_env or {}
        env_keys.extend(extra_env)
        previous_env = {key: os.environ.get(key) for key in env_keys}
        os.environ["IDA_SCRIPT_MCP_IDA_PATH"] = str(ida_path or worker_ida)
        os.environ["IDA_SCRIPT_MCP_WORK_DIR"] = str(worker_jobs)
        os.environ["IDA_SCRIPT_MCP_KEEP_JOBS"] = "1"
        os.environ["IDA_SCRIPT_MCP_WORKER_FAILURE_TARGET_EA"] = target_hex
        for key, value in extra_env.items():
            os.environ[key] = value
        try:
            import asyncio
            from ida_script_mcp import server as mcp_server

            case_port = int(ready["port"])
            case_script_path = str(script_path)
            case_timeout_seconds = int(timeout_seconds)

            class ExecuteParams:
                instance_id = None
                port = case_port
                code = None
                script_path = case_script_path
                capture_output = True
                timeout_seconds = case_timeout_seconds
                collect_changes = True

                def to_execute_request(self):
                    return mcp_server.ExecuteRequest.model_validate(
                        {
                            "code": self.code,
                            "script_path": self.script_path,
                            "capture_output": self.capture_output,
                            "timeout_seconds": self.timeout_seconds,
                        }
                    )

            _stage(
                "worker_failure_case_start",
                {"case": case_id, "expected_status": expected_status, "script_path": str(script_path)},
            )
            execute_result = asyncio.run(mcp_server.execute_idapython(ExecuteParams()))
            matrix[case_id] = {
                "passed": execute_result.get("status") == expected_status,
                "expected_status": expected_status,
                "actual_status": execute_result.get("status"),
                "error_type": (execute_result.get("error") or {}).get("type") if isinstance(execute_result.get("error"), dict) else None,
                "worker_pid": execute_result.get("worker_pid"),
                "worker_exit_code": execute_result.get("worker_exit_code"),
                "job_id": execute_result.get("job_id"),
            }
            result["responses"][f"failure_matrix_{case_id}"] = execute_result
            _check(
                result,
                f"failure matrix {case_id} status",
                execute_result.get("status") == expected_status,
                execute_result,
            )
            _stage(
                "worker_failure_case_done",
                {"case": case_id, "status": execute_result.get("status"), "worker_exit_code": execute_result.get("worker_exit_code")},
            )
            return execute_result
        finally:
            for key, value in previous_env.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value

    bad_worker_ida = WORK_DIR / "missing-idat64.exe"
    start_error = _execute_case(
        "worker_start_error",
        user_scripts["worker_crash_user_script.py"],
        expected_status="worker_start_error",
        ida_path=bad_worker_ida,
    )
    _check(result, "worker_start_error did not launch worker", start_error.get("worker_pid") is None, start_error)

    source_error = _execute_case(
        "source_error",
        WORK_DIR / "missing_source_for_u003.py",
        expected_status="source_error",
    )
    _check(result, "source_error has worker pid", source_error.get("worker_pid") is not None, source_error)

    crashed = _execute_case(
        "worker_crashed",
        user_scripts["worker_crash_user_script.py"],
        expected_status="worker_crashed",
    )
    _check(result, "worker_crashed has nonzero exit", crashed.get("worker_exit_code") not in (None, 0), crashed)

    missing = _execute_case(
        "worker_result_missing",
        user_scripts["worker_result_missing_user_script.py"],
        expected_status="worker_result_missing",
    )
    _check(result, "worker_result_missing has zero exit", missing.get("worker_exit_code") == 0, missing)

    recorder = _execute_case(
        "recorder_error",
        user_scripts["worker_recorder_error_user_script.py"],
        expected_status="recorder_error",
    )
    _check(result, "recorder_error has RecorderError", (recorder.get("error") or {}).get("type") == "RecorderError", recorder)

    dirty_payload = {
        "schema_version": 1,
        "job_id": "u003-dirty-rejected",
        "database_fingerprint": {
            "input_file_path": metadata_before["body"].get("input_file_path"),
            "database_path": metadata_before["body"].get("database_path"),
            "root_filename": metadata_before["body"].get("root_filename") or metadata_before["body"].get("database"),
            "imagebase": metadata_before["body"].get("imagebase"),
            "input_md5": metadata_before["body"].get("input_md5"),
            "input_sha256": metadata_before["body"].get("input_sha256"),
            "processor": metadata_before["body"].get("processor"),
            "bitness": metadata_before["body"].get("bitness"),
            "database_sha256": metadata_before["body"].get("database_sha256"),
            "database_size": metadata_before["body"].get("database_size"),
        },
        "operations": [
            {
                "op_id": "op-000001",
                "op": "comment",
                "ea": target_ea,
                "source": "explicit_api",
                "confidence": "high",
                "text": "u003 dirty marker before rejected execute",
                "repeatable": False,
            }
        ],
        "dry_run": False,
    }
    dirty_apply = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        dirty_payload,
        expected_status=200,
        timeout=10,
    )
    result["responses"]["failure_matrix_dirty_apply"] = dirty_apply["body"]
    _check(result, "dirty apply succeeded before rejected case", dirty_apply["body"].get("status") == "ok", dirty_apply["body"])
    metadata_dirty = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["failure_matrix_metadata_dirty"] = metadata_dirty["body"]
    _check(result, "metadata dirty before rejected case", metadata_dirty["body"].get("dirty") is True, metadata_dirty["body"])

    rejected = _execute_case(
        "rejected",
        user_scripts["worker_crash_user_script.py"],
        expected_status="rejected",
    )
    _check(result, "rejected did not launch worker", rejected.get("worker_pid") is None, rejected)

    expected_cases = {
        "worker_start_error",
        "source_error",
        "worker_crashed",
        "worker_result_missing",
        "recorder_error",
        "rejected",
    }
    _check(result, "failure matrix contains all cases", set(matrix) == expected_cases, matrix)
    _check(result, "failure matrix all passed", all(item.get("passed") for item in matrix.values()), matrix)
    _stage("worker_failure_matrix_done", matrix)


def _read_process_pipes(process: subprocess.Popen) -> tuple[str, str]:
    try:
        stdout, stderr = process.communicate(timeout=10)
    except Exception:
        stdout, stderr = "", ""
    return stdout or "", stderr or ""


def main() -> int:
    ida_dir = Path(IDA_DIR)
    dll_path = Path(DLL_PATH)
    stdout = ""
    stderr = ""
    process = None
    result: dict = {"status": "failed", "mode": TEST_MODE, "dll_path": DLL_PATH, "work_dir": str(WORK_DIR), "checks": [], "responses": {}}

    try:
        _stage("validate_inputs_start", {"ida_dir": str(ida_dir), "dll_path": str(dll_path)})
        if not ida_dir.is_dir():
            raise RuntimeError(f"IDA directory does not exist: {ida_dir}")
        if not dll_path.is_file():
            raise RuntimeError(f"DLL path does not exist: {dll_path}")

        plugin_dir = _install_plugin_files()
        user_scripts = _write_worker_user_scripts()
        user_script = user_scripts[USER_SCRIPT_FILENAME]
        ida_executable = _select_ida_executable(ida_dir)
        database_path = WORK_DIR / (dll_path.stem + ".i64")
        bootstrap_path = _write_bootstrap(WORK_DIR, plugin_dir, READY_PATH, HEARTBEAT_PATH)
        _stage("validate_inputs_done", {"ida_executable": str(ida_executable), "plugin_dir": str(plugin_dir), "user_script": str(user_script)})

        command = [
            str(ida_executable),
            "-A",
            f"-L{IDA_LOG_PATH}",
            f"-S{bootstrap_path}",
            f"-o{database_path}",
            str(dll_path),
        ]
        _stage("ida_start", {"command": command, "work_dir": str(WORK_DIR)})
        process = subprocess.Popen(
            command,
            cwd=str(WORK_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        ready = _wait_for_ready(process, READY_PATH, IDA_LOG_PATH)
        result["ready"] = ready
        if TEST_MODE == "worker_timeout":
            _run_worker_timeout(ready, str(ready["base_url"]), ida_dir, user_script, result)
        elif TEST_MODE == "worker_failure_matrix":
            _run_worker_failure_matrix(ready, str(ready["base_url"]), ida_dir, user_scripts, result)
        elif TEST_MODE == "worker_chain":
            _run_worker_chain(ready, str(ready["base_url"]), ida_dir, user_script, result)
        else:
            raise RuntimeError(f"Unsupported worker payload TEST_MODE: {TEST_MODE!r}")
        result.update(
            {
                "status": "passed",
                "ida_executable": str(ida_executable),
                "ida_log_path": str(IDA_LOG_PATH),
                "work_dir": str(WORK_DIR),
                "database_path": str(database_path),
            }
        )
        _stage("worker_chain_tests_done", {"status": result.get("status")})
    except Exception as exc:
        result["status"] = "failed"
        result["failed_stage"] = _tail(HEARTBEAT_PATH, max_chars=2000)
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
                "ida_log_tail": _tail(IDA_LOG_PATH),
                "heartbeat_tail": _tail(HEARTBEAT_PATH),
                "stdout_tail": stdout[-4000:],
                "stderr_tail": stderr[-4000:],
            }
        )
        _write_json(RESULT_PATH, result)
        print("IDA_WORKER_CHAIN_TEST_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "IDA_WORKER_CHAIN_TEST_ERROR="
            + json.dumps(
                {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)
