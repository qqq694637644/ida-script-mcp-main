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
WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-u008-decompile-"))
READY_PATH = WORK_DIR / "ida_ready.json"
HEARTBEAT_PATH = WORK_DIR / "heartbeat.ndjson"
RESULT_PATH = WORK_DIR / "U008_decompile_corner_cases_result.json"
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


def main():
    try:
        _stage("ida_bootstrap_start")
        import ida_auto
        import idaapi

        _stage("auto_wait_start")
        ida_auto.auto_wait()
        _stage("auto_wait_done")

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
        globals()["IDA_SCRIPT_MCP_U008_PLUGIN_INSTANCE"] = plugin_instance
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
    print("U008_STAGE=" + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


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
    raise RuntimeError(
        "No IDA executable found under "
        + str(ida_dir)
        + "; checked "
        + ", ".join(IDA_EXECUTABLE_CANDIDATES)
    )


def _write_bootstrap(work_dir: Path, plugin_dir: Path, ready_path: Path, heartbeat_path: Path) -> Path:
    bootstrap_path = work_dir / "U008_decompile_corner_cases_bootstrap.py"
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
            {
                "ready_path": str(ready_path),
                "ida_log_tail": _tail(ida_log_path),
                "process_alive": process.poll() is None,
            },
            ensure_ascii=False,
        )
    )


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


def _skip(result: dict, name: str, detail=None) -> None:
    result.setdefault("skips", []).append({"name": name, "detail": detail})
    _stage("u008_skip", {"name": name, "detail": detail})


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


def _require_decompile_success_shape(result: dict, check_prefix: str, body: dict, require_disassembly: bool) -> None:
    _check(result, f"{check_prefix} found function", body.get("found") is True, body)
    _check(result, f"{check_prefix} reports hexrays availability", body.get("hexrays_available") in {True, False}, body)
    if body.get("hexrays_available") is True:
        _check(result, f"{check_prefix} includes pseudocode", isinstance(body.get("pseudocode"), str), body)
    else:
        _check(result, f"{check_prefix} returns structured decompile warning", bool(body.get("warning")), body)
    if require_disassembly:
        _check(result, f"{check_prefix} includes disassembly fallback", isinstance(body.get("disassembly"), list), body)


def _find_selected_function(functions: list[dict]) -> dict:
    with_body = [fn for fn in functions if int(fn.get("size") or 0) > 1]
    normal = [fn for fn in with_body if not fn.get("is_thunk") and not fn.get("is_library")]
    if normal:
        return normal[0]
    if with_body:
        return with_body[0]
    return functions[0]


def _run_decompile_corner_cases(ready: dict, result: dict) -> None:
    base_url = str(ready["base_url"])

    health = _health_with_retry(base_url)
    result["responses"]["health"] = health["body"]
    _check(result, "IDA plugin health ok before U008", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])

    metadata_before = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_before_u008"] = metadata_before["body"]
    _check(result, "metadata is clean before U008", metadata_before["body"].get("dirty") is False, metadata_before["body"])

    functions_page = _json_request(
        "POST",
        base_url,
        "/functions",
        {"offset": 0, "limit": 80, "include_thunks": True, "include_library_functions": True},
        expected_status=200,
        timeout=10,
    )
    result["responses"]["functions_for_u008"] = functions_page["body"]
    functions = functions_page["body"].get("functions") or []
    _check(result, "U008 has at least one function", bool(functions), functions_page["body"])

    selected = _find_selected_function(functions)
    result["selected_function"] = selected
    start_ea = int(selected["start_ea"])
    end_ea = int(selected.get("end_ea") or start_ea)
    size = max(0, int(selected.get("size") or 0))
    name = selected.get("name") or ""
    start_hex = hex(start_ea)

    _stage("decompile_start_address_start", {"address": start_hex})
    start_body = _json_request(
        "POST",
        base_url,
        "/decompile",
        {"address": start_hex, "include_disassembly": True},
        expected_status=200,
        timeout=45,
    )["body"]
    result["responses"]["decompile_start_address"] = start_body
    _require_decompile_success_shape(result, "decompile start address", start_body, require_disassembly=True)
    _check(result, "decompile start address preserves function start", int(start_body.get("start_ea")) == start_ea, start_body)
    _stage("decompile_start_address_done")

    _stage("decompile_decimal_address_start", {"address": str(start_ea)})
    decimal_body = _json_request(
        "POST",
        base_url,
        "/decompile",
        {"address": str(start_ea), "include_disassembly": False},
        expected_status=200,
        timeout=45,
    )["body"]
    result["responses"]["decompile_decimal_address"] = decimal_body
    _require_decompile_success_shape(result, "decompile decimal address", decimal_body, require_disassembly=False)
    _stage("decompile_decimal_address_done")

    if size > 1 and end_ea > start_ea + 1:
        middle_ea = start_ea + min(max(1, size // 2), size - 1)
        _stage("decompile_middle_address_start", {"address": hex(middle_ea), "start_ea": start_hex})
        middle_body = _json_request(
            "POST",
            base_url,
            "/decompile",
            {"address": hex(middle_ea), "include_disassembly": True},
            expected_status=200,
            timeout=45,
        )["body"]
        result["responses"]["decompile_middle_address"] = middle_body
        _require_decompile_success_shape(result, "decompile middle address", middle_body, require_disassembly=True)
        _check(result, "middle address resolves original function", int(middle_body.get("start_ea")) == start_ea, middle_body)
        _check(result, "middle address records resolved_ea", int(middle_body.get("resolved_ea")) == middle_ea, middle_body)
        _stage("decompile_middle_address_done")
    else:
        _skip(result, "decompile middle address", {"reason": "selected function is too small", "selected": selected})

    if name:
        _stage("decompile_name_query_start", {"name": name})
        name_body = _json_request(
            "POST",
            base_url,
            "/decompile",
            {"name": name, "include_disassembly": True},
            expected_status=200,
            timeout=45,
        )["body"]
        result["responses"]["decompile_name_query"] = name_body
        _require_decompile_success_shape(result, "decompile name query", name_body, require_disassembly=True)
        _check(result, "name query resolves selected function", int(name_body.get("start_ea")) == start_ea, name_body)
        _stage("decompile_name_query_done")
    else:
        _skip(result, "decompile name query", {"reason": "selected function has no name", "selected": selected})

    missing_name = "__ida_script_mcp_missing_U008_" + str(int(time.time()))
    _stage("decompile_missing_name_start", {"name": missing_name})
    missing_name_body = _json_request(
        "POST",
        base_url,
        "/decompile",
        {"name": missing_name, "include_disassembly": True},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["decompile_missing_name"] = missing_name_body
    _check(result, "missing name returns found=false", missing_name_body.get("found") is False, missing_name_body)
    _check(result, "missing name returns structured error", bool(missing_name_body.get("error")), missing_name_body)
    _stage("decompile_missing_name_done")

    _stage("decompile_no_target_start")
    no_target_body = _json_request(
        "POST",
        base_url,
        "/decompile",
        {},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["decompile_no_target"] = no_target_body
    _check(result, "missing address/name returns found=false", no_target_body.get("found") is False, no_target_body)
    _check(result, "missing address/name returns structured error", bool(no_target_body.get("error")), no_target_body)
    _stage("decompile_no_target_done")

    _stage("decompile_bad_address_start")
    bad_address_body = _json_request(
        "POST",
        base_url,
        "/decompile",
        {"address": "not-an-address", "include_disassembly": True},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["decompile_bad_address"] = bad_address_body
    _check(result, "bad address returns found=false", bad_address_body.get("found") is False, bad_address_body)
    _check(result, "bad address returns structured error", bool(bad_address_body.get("error")), bad_address_body)
    _stage("decompile_bad_address_done")

    max_end_ea = max(int(fn.get("end_ea") or fn.get("start_ea") or 0) for fn in functions)
    outside_hex = hex(max_end_ea + 0x100000)
    _stage("decompile_outside_function_start", {"address": outside_hex})
    outside_body = _json_request(
        "POST",
        base_url,
        "/decompile",
        {"address": outside_hex, "include_disassembly": True},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["decompile_outside_function"] = outside_body
    _check(result, "outside function address returns found=false", outside_body.get("found") is False, outside_body)
    _check(result, "outside function address returns structured error", bool(outside_body.get("error")), outside_body)
    _stage("decompile_outside_function_done")

    thunk_or_library = next((fn for fn in functions if fn.get("is_thunk") or fn.get("is_library")), None)
    if thunk_or_library is not None:
        thunk_hex = hex(int(thunk_or_library["start_ea"]))
        _stage("decompile_thunk_or_library_start", {"address": thunk_hex, "function": thunk_or_library})
        thunk_body = _json_request(
            "POST",
            base_url,
            "/decompile",
            {"address": thunk_hex, "include_disassembly": True},
            expected_status=200,
            timeout=45,
        )["body"]
        result["responses"]["decompile_thunk_or_library"] = thunk_body
        _require_decompile_success_shape(result, "decompile thunk/library", thunk_body, require_disassembly=True)
        result["thunk_or_library_function"] = thunk_or_library
        _stage("decompile_thunk_or_library_done")
    else:
        _skip(result, "decompile thunk/library", {"reason": "no thunk or library function in first page", "returned": len(functions)})

    largest = max(functions, key=lambda fn: int(fn.get("size") or 0))
    largest_hex = hex(int(largest["start_ea"]))
    _stage("decompile_largest_function_start", {"address": largest_hex, "size": largest.get("size")})
    started = time.monotonic()
    largest_body = _json_request(
        "POST",
        base_url,
        "/decompile",
        {"address": largest_hex, "include_disassembly": False},
        expected_status=200,
        timeout=60,
    )["body"]
    elapsed = time.monotonic() - started
    result["responses"]["decompile_largest_function"] = largest_body
    result["largest_function"] = {"function": largest, "elapsed_seconds": elapsed}
    _require_decompile_success_shape(result, "decompile largest function", largest_body, require_disassembly=False)
    _check(result, "largest function decompile completed before timeout", elapsed < 60, result["largest_function"])
    _stage("decompile_largest_function_done", {"elapsed_seconds": elapsed})

    metadata_after = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_after_u008"] = metadata_after["body"]
    _check(result, "U008 leaves GUI database clean", metadata_after["body"].get("dirty") is False, metadata_after["body"])

    result["summary"] = {
        "covered": [
            "start address",
            "decimal address string",
            "middle-of-function address",
            "name query",
            "missing name",
            "missing target",
            "unparseable address",
            "address outside any function",
            "thunk/library if present",
            "largest discovered function",
            "read-only dirty-state check",
        ],
        "selected_function": selected,
        "skip_count": len(result.get("skips", [])),
        "check_count": len(result.get("checks", [])),
    }


def main() -> int:
    ida_dir = Path(IDA_DIR)
    dll_path = Path(DLL_PATH)
    stdout = ""
    stderr = ""
    process = None
    result: dict = {
        "status": "failed",
        "mode": "u008_decompile_corner_cases",
        "dll_path": DLL_PATH,
        "work_dir": str(WORK_DIR),
        "checks": [],
        "skips": [],
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
        _run_decompile_corner_cases(ready, result)
        result.update(
            {
                "status": "passed",
                "ida_executable": str(ida_executable),
                "ida_log_path": str(IDA_LOG_PATH),
                "work_dir": str(WORK_DIR),
                "database_path": str(database_path),
            }
        )
        _stage("u008_tests_done", {"status": result.get("status")})
    except Exception as exc:
        result["status"] = "failed"
        result["failed_stage"] = _tail(HEARTBEAT_PATH, max_chars=2000)
        result["error"] = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
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
        print("U008_DECOMPILE_CORNER_CASES_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "U008_DECOMPILE_CORNER_CASES_ERROR="
            + json.dumps({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(1)
