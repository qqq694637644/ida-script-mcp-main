# ruff: noqa
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
IDA_READY_TIMEOUT_SECONDS = min(90, max(30, IDA_TIMEOUT_SECONDS // 2))
IDA_EXECUTABLE_CANDIDATES = "__IDA_EXECUTABLE_CANDIDATES_JSON__"
LEGACY_ROOT_SUPPORT_FILES = "__LEGACY_ROOT_SUPPORT_FILES_JSON__"
PLUGIN_FILES_B64 = "__PLUGIN_FILES_B64_JSON__"
PLUGIN_EXPECTED_SHA256 = "__PLUGIN_EXPECTED_SHA256_JSON__"
WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-u011-comments-"))
READY_PATH = WORK_DIR / "ida_ready.json"
HEARTBEAT_PATH = WORK_DIR / "heartbeat.ndjson"
RESULT_PATH = WORK_DIR / "U011_comment_function_comment_complex_result.json"
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
        raise RuntimeError("Cannot resolve saved IDB/I64 path before U011 test")

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
        spec = importlib.util.spec_from_file_location("ida_script_mcp_loaded_plugin_u011", plugin_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot load plugin from {plugin_path}")

        _stage("plugin_load_start", {"plugin_path": plugin_path})
        plugin_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin_module)
        plugin_instance = plugin_module.PLUGIN_ENTRY()
        globals()["IDA_SCRIPT_MCP_TEST_PLUGIN_INSTANCE_U011"] = plugin_instance
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
    print("U011_STAGE=" + json.dumps(payload, ensure_ascii=True, sort_keys=True), flush=True)


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
    preferred = ["ida64.exe", "ida.exe", "idat64.exe", "idat.exe"]
    for candidate in preferred + [name for name in IDA_EXECUTABLE_CANDIDATES if name not in preferred]:
        path = ida_dir / candidate
        if path.is_file():
            return path
    raise RuntimeError("No IDA executable found under " + str(ida_dir))


def _write_bootstrap(work_dir: Path, plugin_dir: Path, ready_path: Path, heartbeat_path: Path) -> Path:
    bootstrap_path = work_dir / "U011_comment_function_comment_bootstrap.py"
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
    _stage("ida_terminate_done", {"pid": process.pid, "returncode": process.poll()})


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
            raise RuntimeError(
                "IDA exited before ready file was created: "
                + json.dumps({"returncode": process.returncode, "ida_log_tail": _tail(ida_log_path)}, ensure_ascii=False)
            )
        time.sleep(0.5)
    raise RuntimeError(
        "Timed out waiting for IDA ready file: "
        + json.dumps({"ready_path": str(ready_path), "ida_log_tail": _tail(ida_log_path), "process_alive": process.poll() is None}, ensure_ascii=False)
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


def _comment_op(op_id: str, ea: int, text: str, *, repeatable: bool = False) -> dict:
    return {
        "op_id": op_id,
        "op": "comment",
        "ea": int(ea),
        "source": "explicit_api",
        "confidence": "high",
        "text": text,
        "repeatable": bool(repeatable),
    }


def _function_comment_op(op_id: str, ea: int, text: str, *, repeatable: bool = False) -> dict:
    return {
        "op_id": op_id,
        "op": "function_comment",
        "ea": int(ea),
        "source": "explicit_api",
        "confidence": "high",
        "text": text,
        "repeatable": bool(repeatable),
    }


def _apply_payload(metadata: dict, operations: list[dict], *, job_id: str, dry_run: bool) -> dict:
    return {
        "schema_version": 1,
        "job_id": job_id,
        "database_fingerprint": {"database_sha256": metadata.get("database_sha256")},
        "operations": operations,
        "dry_run": dry_run,
    }


def _function_summary(function: dict) -> dict:
    return {
        "name": function.get("name"),
        "start_ea": int(function.get("start_ea")),
        "end_ea": int(function.get("end_ea") or function.get("start_ea")),
        "is_thunk": bool(function.get("is_thunk")),
        "is_library": bool(function.get("is_library")),
        "segment": function.get("segment"),
    }


def _unique_functions(functions: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for function in functions:
        try:
            start_ea = int(function.get("start_ea"))
        except Exception:
            continue
        if start_ea in seen:
            continue
        seen.add(start_ea)
        unique.append(function)
    return unique


def _inspect(base_url: str, result: dict, key: str, ea: int) -> dict:
    response = _json_request(
        "POST",
        base_url,
        "/inspect_address",
        {"address": hex(int(ea)), "byte_count": 8},
        expected_status=200,
        timeout=10,
    )
    result["responses"][key] = response["body"]
    return response["body"]


def _run_u011_tests(base_url: str, result: dict) -> None:
    health = _health_with_retry(base_url)
    result["responses"]["health"] = health["body"]
    _check(result, "health reports plugin name", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])

    metadata = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_before"] = metadata["body"]
    metadata_body = metadata["body"]
    _check(result, "metadata clean before U011", metadata_body.get("dirty_state_known") is True and metadata_body.get("dirty") is False, metadata_body)
    _check(result, "metadata includes database_sha256", bool(metadata_body.get("database_sha256")), metadata_body)

    functions_page = _json_request(
        "POST",
        base_url,
        "/functions",
        {"offset": 0, "limit": 500, "include_thunks": True, "include_library_functions": True},
        expected_status=200,
        timeout=10,
    )
    result["responses"]["functions_page"] = functions_page["body"]
    functions = _unique_functions(functions_page["body"].get("functions") or [])
    _check(result, "U011 functions endpoint returns enough functions", len(functions) >= 8, functions_page["body"])

    thunk_or_library = next((function for function in functions if function.get("is_thunk") or function.get("is_library")), None)
    _check(result, "U011 has thunk or library function target", thunk_or_library is not None, functions_page["body"])
    thunk_ea = int(thunk_or_library["start_ea"])
    non_thunk_targets = [function for function in functions if int(function["start_ea"]) != thunk_ea]
    _check(result, "U011 has distinct non-thunk targets", len(non_thunk_targets) >= 7, [_function_summary(function) for function in functions[:20]])

    targets = {
        "repeatable_comment": int(non_thunk_targets[0]["start_ea"]),
        "clear_comment": int(non_thunk_targets[1]["start_ea"]),
        "long_comment": int(non_thunk_targets[2]["start_ea"]),
        "unicode_comment": int(non_thunk_targets[3]["start_ea"]),
        "function_comment": int(non_thunk_targets[4]["start_ea"]),
        "repeatable_function_comment": int(non_thunk_targets[5]["start_ea"]),
        "overwrite_comment": int(non_thunk_targets[6]["start_ea"]),
        "thunk_or_library_comment": thunk_ea,
        "non_function_function_comment": 0x7FFFFFFFFFFF,
    }
    result["targets"] = {
        key: hex(value)
        for key, value in targets.items()
    }
    result["target_functions"] = {
        "non_thunk_targets": [_function_summary(function) for function in non_thunk_targets[:7]],
        "thunk_or_library": _function_summary(thunk_or_library),
    }

    for key, ea in targets.items():
        if key == "non_function_function_comment":
            continue
        before = _inspect(base_url, result, f"inspect_before_{key}", ea)
        _check(result, f"inspect before {key} resolves", before.get("found") is True, before)

    run_id = str(int(time.time()))
    repeatable_comment_text = f"u011 repeatable comment {run_id}"
    clear_seed_text = f"u011 comment to clear {run_id}"
    long_comment_text = "u011 long comment " + run_id + " " + ("L" * 1536) + " end"
    unicode_comment_text = f"u011 Unicode comment {run_id}: 注释/コメント/комментарий/تعليق/λ/emoji-🧪"
    function_comment_text = f"u011 function comment {run_id}"
    repeatable_function_comment_text = f"u011 repeatable function comment {run_id}"
    thunk_comment_text = f"u011 thunk/library regular comment {run_id}"
    overwrite_first_text = f"u011 overwrite first {run_id}"
    overwrite_second_text = f"u011 overwrite second {run_id}"
    non_function_text = f"u011 function comment should fail on non-function {run_id}"

    operations = [
        _comment_op("op-repeatable-comment", targets["repeatable_comment"], repeatable_comment_text, repeatable=True),
        _comment_op("op-clear-comment-seed", targets["clear_comment"], clear_seed_text),
        _comment_op("op-clear-comment", targets["clear_comment"], ""),
        _comment_op("op-long-comment", targets["long_comment"], long_comment_text),
        _comment_op("op-unicode-comment", targets["unicode_comment"], unicode_comment_text),
        _function_comment_op("op-function-comment", targets["function_comment"], function_comment_text),
        _function_comment_op("op-repeatable-function-comment", targets["repeatable_function_comment"], repeatable_function_comment_text, repeatable=True),
        _comment_op("op-thunk-library-comment", targets["thunk_or_library_comment"], thunk_comment_text),
        _comment_op("op-overwrite-first", targets["overwrite_comment"], overwrite_first_text),
        _comment_op("op-overwrite-second", targets["overwrite_comment"], overwrite_second_text),
        _function_comment_op("op-function-comment-non-function", targets["non_function_function_comment"], non_function_text),
    ]
    expected_applied_ids = [operation["op_id"] for operation in operations[:-1]]
    result["u011_expected"] = {
        "operation_count": len(operations),
        "expected_applied_ids": expected_applied_ids,
        "expected_error_id": operations[-1]["op_id"],
        "long_comment_length": len(long_comment_text),
        "unicode_comment_text": unicode_comment_text,
    }

    _stage("u011_dry_run_start", {"operation_count": len(operations)})
    dry_run = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        _apply_payload(metadata_body, operations, job_id=f"u011-comments-{run_id}", dry_run=True),
        expected_status=200,
        timeout=10,
    )
    result["responses"]["apply_dry_run"] = dry_run["body"]
    dry_body = dry_run["body"]
    _check(result, "U011 dry-run status ok", dry_body.get("status") == "ok", dry_body)
    _check(result, "U011 dry-run applies nothing", dry_body.get("applied") == [], dry_body)
    _check(result, "U011 dry-run skips all operations", len(dry_body.get("skipped") or []) == len(operations), dry_body)

    metadata_after_dry = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_after_dry_run"] = metadata_after_dry["body"]
    _check(result, "U011 dry-run keeps metadata clean", metadata_after_dry["body"].get("dirty") is False, metadata_after_dry["body"])
    _stage("u011_dry_run_done")

    _stage("u011_destructive_apply_start", {"operation_count": len(operations)})
    destructive = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        _apply_payload(metadata_body, operations, job_id=f"u011-comments-{run_id}", dry_run=False),
        expected_status=200,
        timeout=10,
    )
    result["responses"]["apply_destructive"] = destructive["body"]
    apply_body = destructive["body"]
    applied_ids = [item.get("op_id") for item in apply_body.get("applied") or []]
    errors = apply_body.get("errors") or []
    _check(result, "U011 destructive apply is partial due non-function function_comment", apply_body.get("status") == "partial", apply_body)
    _check(result, "U011 destructive apply applies expected operations before error", applied_ids == expected_applied_ids, apply_body)
    _check(result, "U011 destructive apply records one expected error", len(errors) == 1 and errors[0].get("op_id") == "op-function-comment-non-function", apply_body)
    _check(result, "U011 non-function error mentions no function", "No function found" in str(errors[0].get("message") or ""), errors[0])
    _stage("u011_destructive_apply_done", {"status": apply_body.get("status"), "applied_ids": applied_ids, "errors": errors})

    after_repeatable = _inspect(base_url, result, "inspect_after_repeatable_comment", targets["repeatable_comment"])
    _check(result, "U011 repeatable comment visible", after_repeatable.get("repeatable_comment") == repeatable_comment_text, after_repeatable)

    after_clear = _inspect(base_url, result, "inspect_after_clear_comment", targets["clear_comment"])
    _check(result, "U011 cleared regular comment is empty", after_clear.get("comment") is None, after_clear)

    after_long = _inspect(base_url, result, "inspect_after_long_comment", targets["long_comment"])
    _check(result, "U011 long comment length preserved", after_long.get("comment") == long_comment_text, {"expected_length": len(long_comment_text), "actual_length": len(after_long.get("comment") or ""), "actual_tail": str(after_long.get("comment") or "")[-40:]})

    after_unicode = _inspect(base_url, result, "inspect_after_unicode_comment", targets["unicode_comment"])
    _check(result, "U011 Unicode comment visible", after_unicode.get("comment") == unicode_comment_text, after_unicode)

    after_function_comment = _inspect(base_url, result, "inspect_after_function_comment", targets["function_comment"])
    _check(result, "U011 function comment visible", after_function_comment.get("function_comment") == function_comment_text, after_function_comment)

    after_repeatable_function_comment = _inspect(base_url, result, "inspect_after_repeatable_function_comment", targets["repeatable_function_comment"])
    _check(result, "U011 repeatable function comment visible", after_repeatable_function_comment.get("repeatable_function_comment") == repeatable_function_comment_text, after_repeatable_function_comment)

    after_thunk = _inspect(base_url, result, "inspect_after_thunk_or_library_comment", targets["thunk_or_library_comment"])
    _check(result, "U011 thunk/library regular comment visible", after_thunk.get("comment") == thunk_comment_text, after_thunk)

    after_overwrite = _inspect(base_url, result, "inspect_after_overwrite_comment", targets["overwrite_comment"])
    _check(result, "U011 repeated overwrite keeps second comment", after_overwrite.get("comment") == overwrite_second_text, after_overwrite)

    metadata_after_apply = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
    result["responses"]["metadata_after_apply"] = metadata_after_apply["body"]
    _check(result, "U011 metadata dirty after destructive partial apply", metadata_after_apply["body"].get("dirty") is True, metadata_after_apply["body"])
    _check(result, "U011 apply_changes mutation flag true", metadata_after_apply["body"].get("apply_changes_mutated") is True, metadata_after_apply["body"])

    result["u011_summary"] = {
        "status": apply_body.get("status"),
        "applied_ids": applied_ids,
        "error_ids": [item.get("op_id") for item in errors],
        "repeatable_comment_ok": after_repeatable.get("repeatable_comment") == repeatable_comment_text,
        "cleared_comment": after_clear.get("comment"),
        "long_comment_length": len(after_long.get("comment") or ""),
        "unicode_comment": after_unicode.get("comment"),
        "function_comment_ok": after_function_comment.get("function_comment") == function_comment_text,
        "repeatable_function_comment_ok": after_repeatable_function_comment.get("repeatable_function_comment") == repeatable_function_comment_text,
        "thunk_or_library_comment_ok": after_thunk.get("comment") == thunk_comment_text,
        "overwrite_comment": after_overwrite.get("comment"),
        "metadata_dirty": metadata_after_apply["body"].get("dirty"),
    }


def main() -> int:
    ida_dir = Path(IDA_DIR)
    dll_path = Path(DLL_PATH)
    stdout = ""
    stderr = ""
    process = None
    result: dict = {
        "status": "failed",
        "mode": "u011_comment_function_comment_complex",
        "dll_path": DLL_PATH,
        "work_dir": str(WORK_DIR),
        "checks": [],
        "responses": {},
        "warnings": [],
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
        _stage("validate_inputs_done", {"ida_executable": str(ida_executable), "plugin_dir": str(plugin_dir), "database_path": str(database_path)})

        command = [
            str(ida_executable),
            "-A",
            f"-L{IDA_LOG_PATH}",
            f"-S{bootstrap_path}",
            f"-o{database_path}",
            str(dll_path),
        ]
        _stage("ida_start", {"command": command, "work_dir": str(WORK_DIR)})
        process = subprocess.Popen(command, cwd=str(WORK_DIR), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")

        ready = _wait_for_ready(process, READY_PATH, IDA_LOG_PATH)
        result["ready"] = ready
        _stage("u011_tests_start", {"base_url": ready["base_url"]})
        _run_u011_tests(str(ready["base_url"]), result)
        result.update({"status": "passed", "ida_executable": str(ida_executable), "ida_log_path": str(IDA_LOG_PATH), "database_path": str(database_path)})
        _stage("u011_tests_done", {"status": result.get("status")})
    except Exception as exc:
        result["status"] = "failed"
        result["failed_stage"] = _tail(HEARTBEAT_PATH, max_chars=3000)
        result["error"] = {"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}
    finally:
        _terminate_process(process)
        if process is not None:
            stdout, stderr = _read_process_pipes(process)
            result["ida_returncode"] = process.returncode
        result.update({"ida_log_tail": _tail(IDA_LOG_PATH), "heartbeat_tail": _tail(HEARTBEAT_PATH), "stdout_tail": stdout[-4000:], "stderr_tail": stderr[-4000:]})
        _write_json(RESULT_PATH, result)
        print(
            "U011_COMMENT_FUNCTION_COMMENT_TEST_RESULT="
            + json.dumps(result, ensure_ascii=True, sort_keys=True),
            flush=True,
        )
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "U011_COMMENT_FUNCTION_COMMENT_TEST_ERROR="
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
