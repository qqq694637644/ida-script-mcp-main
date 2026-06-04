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
WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-u010-rename-"))
RESULT_PATH = WORK_DIR / "U010_rename_complex_cases_result.json"
HEARTBEAT_PATH = WORK_DIR / "U010_rename_complex_cases_heartbeat.ndjson"

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
        raise RuntimeError("Cannot resolve saved IDB/I64 path before U010 test")

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


def _rename_flags():
    try:
        import ida_name
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    names = (
        "SN_CHECK",
        "SN_NOCHECK",
        "SN_PUBLIC",
        "SN_NON_PUBLIC",
        "SN_WEAK",
        "SN_NON_WEAK",
        "SN_AUTO",
        "SN_NON_AUTO",
        "SN_NOLIST",
        "SN_NOWARN",
        "SN_LOCAL",
        "SN_IDBENC",
        "SN_FORCE",
    )
    flags = {}
    for name in names:
        if hasattr(ida_name, name):
            try:
                flags[name] = int(getattr(ida_name, name))
            except Exception:
                pass
    return flags


def main():
    try:
        _stage("ida_bootstrap_start")
        import ida_auto
        import idaapi
        import ida_loader

        _stage("auto_wait_start")
        ida_auto.auto_wait()
        _stage("auto_wait_done")
        database_path = _save_database(idaapi, ida_loader)

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
            "rename_flags": _rename_flags(),
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
    print("U010_STAGE=" + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


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


def _write_bootstrap(
    session_dir: Path, plugin_dir: Path, ready_path: Path, heartbeat_path: Path
) -> Path:
    bootstrap_path = session_dir / "U010_rename_complex_bootstrap.py"
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


def _json_request(method, base_url, path, payload=None, expected_status=200, timeout=5):
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
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


def _check(result: dict, name: str, ok: bool, detail=None) -> None:
    result.setdefault("checks", []).append({"name": name, "ok": bool(ok), "detail": detail})
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
                    {
                        "returncode": process.returncode,
                        "ida_log_tail": _tail(ida_log_path),
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


def _metadata(base_url: str, result: dict, *, clean_required: bool = True) -> dict:
    response = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    body = response["body"]
    result.setdefault("metadata_samples", []).append(body)
    _check(result, "metadata includes dirty state", "dirty_state_known" in body, body)
    _check(result, "metadata includes database_sha256", bool(body.get("database_sha256")), body)
    if clean_required:
        _check(
            result,
            "metadata is clean before apply_changes",
            body.get("dirty_state_known") is True and body.get("dirty") is False,
            body,
        )
    return body


def _functions(base_url: str, result: dict) -> dict:
    response = _json_request(
        "POST",
        base_url,
        "/functions",
        {"offset": 0, "limit": 300, "include_thunks": True, "include_library_functions": True},
        expected_status=200,
        timeout=10,
    )
    body = response["body"]
    result["functions_page"] = body
    functions = body.get("functions") or []
    _check(result, "functions endpoint returns functions", isinstance(functions, list) and functions, body)
    return body


def _inspect(base_url: str, address: int, result: dict, key: str) -> dict:
    response = _json_request(
        "POST",
        base_url,
        "/inspect_address",
        {"address": hex(int(address)), "byte_count": 8},
        expected_status=200,
        timeout=10,
    )
    body = response["body"]
    result.setdefault("inspect_samples", {})[key] = body
    _check(result, f"inspect {key} returns structured body", isinstance(body, dict), body)
    return body


def _named_functions(functions_body: dict) -> list[dict]:
    functions = functions_body.get("functions") or []
    return [item for item in functions if item.get("name")]


def _normal_named_functions(functions_body: dict) -> list[dict]:
    named = _named_functions(functions_body)
    normal = [
        item
        for item in named
        if not bool(item.get("is_thunk")) and not bool(item.get("is_library"))
    ]
    return normal or named


def _flags(ready: dict, *names: str) -> int:
    available = ready.get("rename_flags") or {}
    value = 0
    for name in names:
        raw = available.get(name)
        if isinstance(raw, int):
            value |= int(raw)
    return value


def _short_operation(operation: dict) -> dict:
    compact = dict(operation)
    new_name = compact.get("new_name")
    if isinstance(new_name, str) and len(new_name) > 120:
        compact["new_name_preview"] = new_name[:60] + "..." + new_name[-20:]
        compact["new_name_length"] = len(new_name)
        del compact["new_name"]
    return compact


def _apply_operations(
    base_url: str,
    result: dict,
    *,
    case_name: str,
    job_id: str,
    operations: list[dict],
) -> dict:
    metadata = _metadata(base_url, result, clean_required=True)
    request = {
        "schema_version": 1,
        "job_id": job_id,
        "database_fingerprint": {"database_sha256": metadata["database_sha256"]},
        "operations": operations,
        "dry_run": False,
    }
    _stage("u010_apply_start", {"case": case_name, "operation_count": len(operations)})
    response = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        request,
        expected_status=200,
        timeout=20,
    )
    body = response["body"]
    result.setdefault("cases", []).append(
        {
            "case": case_name,
            "operations": [_short_operation(operation) for operation in operations],
            "response": body,
        }
    )
    _stage("u010_apply_done", {"case": case_name, "status": body.get("status")})
    return body


def _op_result(body: dict, op_id: str) -> tuple[str | None, dict | None]:
    for bucket in ("applied", "skipped", "errors"):
        for item in body.get(bucket) or []:
            if item.get("op_id") == op_id:
                return bucket, item
    return None, None


def _assert_single_error(result: dict, body: dict, op_id: str, case_name: str) -> None:
    bucket, item = _op_result(body, op_id)
    _check(result, f"{case_name} returns operation error", bucket == "errors", body)
    _check(result, f"{case_name} has no applied operations", body.get("applied") == [], body)
    _check(result, f"{case_name} top-level status is error", body.get("status") == "error", body)
    _check(result, f"{case_name} error has message", bool((item or {}).get("message")), item)


def _clean_after_failed_rename(base_url: str, result: dict, target_ea: int, before_name: str, key: str) -> None:
    after = _inspect(base_url, target_ea, result, key)
    _check(result, f"{key} leaves target name unchanged", after.get("name") == before_name, after)
    _metadata(base_url, result, clean_required=True)


def _run_reject_matrix(ready: dict, result: dict) -> None:
    base_url = str(ready["base_url"])
    health = _health_with_retry(base_url)
    result["health"] = health["body"]
    _check(result, "health reports IDA Script MCP", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])

    functions_body = _functions(base_url, result)
    named = _named_functions(functions_body)
    normal = _normal_named_functions(functions_body)
    _check(result, "reject matrix has at least two named functions", len(named) >= 2, functions_body)
    target = normal[0]
    duplicate_source = next(item for item in named if item.get("name") != target.get("name"))
    target_ea = int(target["start_ea"])
    before = _inspect(base_url, target_ea, result, "reject_target_before")
    before_name = str(before.get("name") or "")
    run_id = str(int(time.time()))

    cases = [
        (
            "duplicate_existing_function_name",
            {
                "op_id": "u010-duplicate-existing-function-name",
                "op": "rename",
                "ea": target_ea,
                "source": "explicit_api",
                "new_name": str(duplicate_source["name"]),
                "flags": 0,
            },
        ),
        (
            "invalid_name_with_spaces",
            {
                "op_id": "u010-invalid-name-with-spaces",
                "op": "rename",
                "ea": target_ea,
                "source": "explicit_api",
                "new_name": f"bad name with spaces {run_id}",
                "flags": 0,
            },
        ),
        (
            "overlong_name",
            {
                "op_id": "u010-overlong-name",
                "op": "rename",
                "ea": target_ea,
                "source": "explicit_api",
                "new_name": "mcp_u010_" + ("a" * 4096),
                "flags": 0,
            },
        ),
    ]

    for case_name, operation in cases:
        body = _apply_operations(
            base_url,
            result,
            case_name=case_name,
            job_id=f"u010-{case_name}-{run_id}",
            operations=[operation],
        )
        _assert_single_error(result, body, str(operation["op_id"]), case_name)
        _clean_after_failed_rename(base_url, result, target_ea, before_name, case_name)


def _run_success_matrix(ready: dict, result: dict) -> None:
    base_url = str(ready["base_url"])
    functions_body = _functions(base_url, result)
    targets = _normal_named_functions(functions_body)
    _check(result, "success matrix has at least two normal/named functions", len(targets) >= 2, functions_body)
    run_id = str(int(time.time()))
    nowarn = _flags(ready, "SN_NOWARN")
    nocheck_nowarn = _flags(ready, "SN_NOCHECK", "SN_NOWARN")
    nonauto_nowarn = _flags(ready, "SN_NON_AUTO", "SN_NOWARN")
    default_target = targets[0]
    unicode_target = targets[1]
    operations = [
        {
            "op_id": "u010-valid-default-flags",
            "op": "rename",
            "ea": int(default_target["start_ea"]),
            "source": "explicit_api",
            "new_name": f"mcp_u010_default_{run_id}",
            "flags": 0,
        },
        {
            "op_id": "u010-unicode-nocheck-nowarn",
            "op": "rename",
            "ea": int(unicode_target["start_ea"]),
            "source": "explicit_api",
            "new_name": f"mcp_u010_测试_{run_id}",
            "flags": nocheck_nowarn,
        },
    ]
    expected_names = {
        int(default_target["start_ea"]): operations[0]["new_name"],
        int(unicode_target["start_ea"]): operations[1]["new_name"],
    }
    if len(targets) >= 3:
        nonauto_target = targets[2]
        operation = {
            "op_id": "u010-valid-nonauto-nowarn-flags",
            "op": "rename",
            "ea": int(nonauto_target["start_ea"]),
            "source": "explicit_api",
            "new_name": f"mcp_u010_nonauto_{run_id}",
            "flags": nonauto_nowarn or nowarn,
        }
        operations.append(operation)
        expected_names[int(nonauto_target["start_ea"])] = operation["new_name"]

    body = _apply_operations(
        base_url,
        result,
        case_name="success_default_unicode_flag_combinations",
        job_id=f"u010-success-matrix-{run_id}",
        operations=operations,
    )
    _check(result, "success matrix top-level status is ok", body.get("status") == "ok", body)
    _check(result, "success matrix has no errors", body.get("errors") == [], body)
    _check(result, "success matrix applied all operations", len(body.get("applied") or []) == len(operations), body)
    for operation in operations:
        bucket, _ = _op_result(body, str(operation["op_id"]))
        _check(result, f"{operation['op_id']} was applied", bucket == "applied", body)
    for address, expected_name in expected_names.items():
        after = _inspect(base_url, address, result, f"success_after_{address:x}")
        _check(result, f"applied rename visible at {address:x}", after.get("name") == expected_name, after)
    metadata_after = _metadata(base_url, result, clean_required=False)
    _check(result, "success matrix leaves database dirty", metadata_after.get("dirty") is True, metadata_after)


def _run_empty_name(ready: dict, result: dict) -> None:
    base_url = str(ready["base_url"])
    functions_body = _functions(base_url, result)
    target = _normal_named_functions(functions_body)[0]
    target_ea = int(target["start_ea"])
    before = _inspect(base_url, target_ea, result, "empty_name_before")
    before_name = str(before.get("name") or "")
    run_id = str(int(time.time()))
    operation = {
        "op_id": "u010-empty-name",
        "op": "rename",
        "ea": target_ea,
        "source": "explicit_api",
        "new_name": "",
        "flags": 0,
    }
    body = _apply_operations(
        base_url,
        result,
        case_name="empty_name",
        job_id=f"u010-empty-name-{run_id}",
        operations=[operation],
    )
    bucket, _ = _op_result(body, "u010-empty-name")
    _check(result, "empty name returns structured operation result", bucket in {"applied", "errors"}, body)
    if bucket == "applied":
        result["observed_empty_name_behavior"] = "applied"
        after = _inspect(base_url, target_ea, result, "empty_name_after_applied")
        result["empty_name_after"] = after
        metadata_after = _metadata(base_url, result, clean_required=False)
        _check(result, "empty name apply leaves database dirty", metadata_after.get("dirty") is True, metadata_after)
    else:
        result["observed_empty_name_behavior"] = "error"
        _clean_after_failed_rename(base_url, result, target_ea, before_name, "empty_name_after_error")


def _non_function_candidate(functions_body: dict) -> tuple[int, dict]:
    starts = {int(item["start_ea"]) for item in functions_body.get("functions") or []}
    for item in functions_body.get("functions") or []:
        start = int(item["start_ea"])
        end = int(item.get("end_ea") or start)
        if end > start + 1 and start + 1 not in starts:
            return start + 1, item
    first = (functions_body.get("functions") or [])[0]
    return int(first["start_ea"]) + 1, first


def _run_non_function_address(ready: dict, result: dict) -> None:
    base_url = str(ready["base_url"])
    functions_body = _functions(base_url, result)
    target_ea, parent_function = _non_function_candidate(functions_body)
    before = _inspect(base_url, target_ea, result, "non_function_before")
    before_name = str(before.get("name") or "")
    run_id = str(int(time.time()))
    new_name = f"mcp_u010_nonfunc_{run_id}"
    operation = {
        "op_id": "u010-non-function-address",
        "op": "rename",
        "ea": target_ea,
        "source": "explicit_api",
        "new_name": new_name,
        "flags": _flags(ready, "SN_NOCHECK", "SN_NOWARN"),
    }
    result["non_function_candidate"] = {
        "ea": target_ea,
        "parent_function": parent_function,
        "before_name": before_name,
    }
    body = _apply_operations(
        base_url,
        result,
        case_name="non_function_address",
        job_id=f"u010-non-function-address-{run_id}",
        operations=[operation],
    )
    bucket, _ = _op_result(body, "u010-non-function-address")
    _check(result, "non-function rename returns structured operation result", bucket in {"applied", "errors"}, body)
    if bucket == "applied":
        result["observed_non_function_behavior"] = "applied"
        after = _inspect(base_url, target_ea, result, "non_function_after_applied")
        _check(result, "non-function applied name is visible", after.get("name") == new_name, after)
        metadata_after = _metadata(base_url, result, clean_required=False)
        _check(result, "non-function apply leaves database dirty", metadata_after.get("dirty") is True, metadata_after)
    else:
        result["observed_non_function_behavior"] = "error"
        _clean_after_failed_rename(base_url, result, target_ea, before_name, "non_function_after_error")


def _run_import_library_thunk(ready: dict, result: dict) -> None:
    base_url = str(ready["base_url"])
    functions_body = _functions(base_url, result)
    candidates = [
        item
        for item in functions_body.get("functions") or []
        if bool(item.get("is_thunk")) or bool(item.get("is_library"))
    ]
    if not candidates:
        result["status"] = "skipped"
        result["skip_reason"] = "No thunk/library function was returned by /functions for this sample."
        return
    target = candidates[0]
    target_ea = int(target["start_ea"])
    before = _inspect(base_url, target_ea, result, "import_library_thunk_before")
    before_name = str(before.get("name") or "")
    run_id = str(int(time.time()))
    new_name = f"mcp_u010_import_thunk_{run_id}"
    operation = {
        "op_id": "u010-import-library-thunk",
        "op": "rename",
        "ea": target_ea,
        "source": "explicit_api",
        "new_name": new_name,
        "flags": _flags(ready, "SN_NOCHECK", "SN_NOWARN"),
    }
    result["import_library_thunk_target"] = target
    body = _apply_operations(
        base_url,
        result,
        case_name="import_library_thunk",
        job_id=f"u010-import-library-thunk-{run_id}",
        operations=[operation],
    )
    bucket, _ = _op_result(body, "u010-import-library-thunk")
    _check(result, "import/library/thunk rename returns structured operation result", bucket in {"applied", "errors"}, body)
    if bucket == "applied":
        result["observed_import_library_thunk_behavior"] = "applied"
        after = _inspect(base_url, target_ea, result, "import_library_thunk_after_applied")
        _check(result, "import/library/thunk applied name is visible", after.get("name") == new_name, after)
        metadata_after = _metadata(base_url, result, clean_required=False)
        _check(result, "import/library/thunk apply leaves database dirty", metadata_after.get("dirty") is True, metadata_after)
    else:
        result["observed_import_library_thunk_behavior"] = "error"
        _clean_after_failed_rename(base_url, result, target_ea, before_name, "import_library_thunk_after_error")


def _run_force_duplicate(ready: dict, result: dict) -> None:
    base_url = str(ready["base_url"])
    functions_body = _functions(base_url, result)
    named = _named_functions(functions_body)
    _check(result, "force duplicate has at least two named functions", len(named) >= 2, functions_body)
    target = named[0]
    duplicate_source = next(item for item in named if item.get("name") != target.get("name"))
    target_ea = int(target["start_ea"])
    before = _inspect(base_url, target_ea, result, "force_duplicate_before")
    before_name = str(before.get("name") or "")
    run_id = str(int(time.time()))
    operation = {
        "op_id": "u010-force-duplicate-existing-function-name",
        "op": "rename",
        "ea": target_ea,
        "source": "explicit_api",
        "new_name": str(duplicate_source["name"]),
        "flags": _flags(ready, "SN_FORCE", "SN_NOWARN"),
    }
    result["force_duplicate_target"] = {
        "target": target,
        "duplicate_source": duplicate_source,
        "before_name": before_name,
    }
    body = _apply_operations(
        base_url,
        result,
        case_name="force_duplicate_existing_function_name",
        job_id=f"u010-force-duplicate-{run_id}",
        operations=[operation],
    )
    bucket, _ = _op_result(body, "u010-force-duplicate-existing-function-name")
    _check(result, "SN_FORCE duplicate returns structured operation result", bucket in {"applied", "errors"}, body)
    if bucket == "applied":
        result["observed_force_duplicate_behavior"] = "applied"
        after = _inspect(base_url, target_ea, result, "force_duplicate_after_applied")
        result["force_duplicate_after"] = after
        metadata_after = _metadata(base_url, result, clean_required=False)
        _check(result, "SN_FORCE duplicate apply leaves database dirty", metadata_after.get("dirty") is True, metadata_after)
    else:
        result["observed_force_duplicate_behavior"] = "error"
        _clean_after_failed_rename(base_url, result, target_ea, before_name, "force_duplicate_after_error")


SCENARIOS = {
    "reject_matrix": _run_reject_matrix,
    "success_matrix": _run_success_matrix,
    "empty_name": _run_empty_name,
    "non_function_address": _run_non_function_address,
    "import_library_thunk": _run_import_library_thunk,
    "force_duplicate": _run_force_duplicate,
}


def _run_session(
    *,
    session_name: str,
    ida_executable: Path,
    plugin_dir: Path,
    dll_path: Path,
    scenario_runner,
) -> dict:
    session_dir = WORK_DIR / session_name
    session_dir.mkdir(parents=True, exist_ok=True)
    ready_path = session_dir / "ida_ready.json"
    heartbeat_path = session_dir / "heartbeat.ndjson"
    ida_log_path = session_dir / "ida.log"
    database_path = session_dir / (dll_path.stem + ".i64")
    bootstrap_path = _write_bootstrap(session_dir, plugin_dir, ready_path, heartbeat_path)
    command = [
        str(ida_executable),
        "-A",
        f"-L{ida_log_path}",
        f"-S{bootstrap_path}",
        f"-o{database_path}",
        str(dll_path),
    ]
    session_result: dict = {
        "status": "running",
        "session": session_name,
        "database_path": str(database_path),
        "ida_log_path": str(ida_log_path),
        "checks": [],
    }
    process = None
    stdout = ""
    stderr = ""
    try:
        _stage("session_start", {"session": session_name, "command": command})
        process = subprocess.Popen(
            command,
            cwd=str(session_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        ready = _wait_for_ready(process, ready_path, ida_log_path)
        session_result["ready"] = ready
        scenario_runner(ready, session_result)
        if session_result.get("status") != "skipped":
            session_result["status"] = "passed"
        _stage("session_done", {"session": session_name, "status": session_result["status"]})
    except Exception as exc:
        session_result["status"] = "failed"
        session_result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
        }
        _stage("session_failed", {"session": session_name, "error": session_result["error"]})
    finally:
        _terminate_process(process)
        if process is not None:
            stdout, stderr = _read_process_pipes(process)
            session_result["ida_returncode"] = process.returncode
        session_result.update(
            {
                "ida_log_tail": _tail(ida_log_path),
                "session_heartbeat_tail": _tail(heartbeat_path),
                "stdout_tail": stdout[-4000:],
                "stderr_tail": stderr[-4000:],
            }
        )
        time.sleep(1.0)
    return session_result


def main() -> int:
    ida_dir = Path(IDA_DIR)
    dll_path = Path(DLL_PATH)
    result: dict = {
        "status": "failed",
        "test_id": "U010",
        "test_name": "rename complex cases",
        "dll_path": DLL_PATH,
        "work_dir": str(WORK_DIR),
        "sessions": {},
        "warnings": [],
        "checks": [],
    }

    try:
        _stage("validate_inputs_start", {"ida_dir": str(ida_dir), "dll_path": str(dll_path)})
        if not ida_dir.is_dir():
            raise RuntimeError(f"IDA directory does not exist: {ida_dir}")
        if not dll_path.is_file():
            raise RuntimeError(f"DLL path does not exist: {dll_path}")
        plugin_dir = _install_plugin_files()
        ida_executable = _select_ida_executable(ida_dir)
        result["ida_executable"] = str(ida_executable)
        result["plugin_dir"] = str(plugin_dir)
        _stage("validate_inputs_done", {"ida_executable": str(ida_executable), "plugin_dir": str(plugin_dir)})

        failed_sessions = []
        skipped_sessions = []
        for session_name, runner in SCENARIOS.items():
            session_result = _run_session(
                session_name=session_name,
                ida_executable=ida_executable,
                plugin_dir=plugin_dir,
                dll_path=dll_path,
                scenario_runner=runner,
            )
            result["sessions"][session_name] = session_result
            if session_result.get("status") == "failed":
                failed_sessions.append(session_name)
            elif session_result.get("status") == "skipped":
                skipped_sessions.append(session_name)

        result["session_statuses"] = {
            name: session.get("status") for name, session in result["sessions"].items()
        }
        if skipped_sessions:
            result["warnings"].append(
                {
                    "name": "skipped sessions",
                    "sessions": skipped_sessions,
                    "message": "Skipped sessions are reported as residual coverage gaps, not infrastructure failures.",
                }
            )
        if failed_sessions:
            result["status"] = "failed"
            result["failed_sessions"] = failed_sessions
        else:
            result["status"] = "passed"
        _stage("u010_tests_done", {"status": result["status"], "session_statuses": result["session_statuses"]})
    except Exception as exc:
        result["status"] = "failed"
        result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
        }
        _stage("u010_tests_failed", result["error"])
    finally:
        result["heartbeat_tail"] = _tail(HEARTBEAT_PATH)
        _write_json(RESULT_PATH, result)
        print("U010_RENAME_COMPLEX_TEST_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)

    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "U010_RENAME_COMPLEX_TEST_ERROR="
            + json.dumps(
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc(),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)
