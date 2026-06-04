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
from pathlib import Path

IDA_DIR = "__IDA_DIR_JSON__"
DLL_PATH = "__DLL_PATH_JSON__"
IDA_TIMEOUT_SECONDS = int("__IDA_TIMEOUT_SECONDS_JSON__")
IDA_READY_TIMEOUT_SECONDS = min(60, max(15, IDA_TIMEOUT_SECONDS // 3))
IDA_EXECUTABLE_CANDIDATES = "__IDA_EXECUTABLE_CANDIDATES_JSON__"
LEGACY_ROOT_SUPPORT_FILES = "__LEGACY_ROOT_SUPPORT_FILES_JSON__"
PLUGIN_FILES_B64 = "__PLUGIN_FILES_B64_JSON__"
PLUGIN_EXPECTED_SHA256 = "__PLUGIN_EXPECTED_SHA256_JSON__"
WORK_DIR = Path(tempfile.mkdtemp(prefix="ida-script-mcp-u013-patch-bytes-"))
READY_PATH = WORK_DIR / "ida_ready.json"
HEARTBEAT_PATH = WORK_DIR / "heartbeat.ndjson"
RESULT_PATH = WORK_DIR / "U013_patch_bytes_complex_cases_result.json"
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
        raise RuntimeError("Cannot resolve saved IDB/I64 path before U013 test")
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
        spec = importlib.util.spec_from_file_location("ida_script_mcp_loaded_plugin_u013", plugin_path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"Cannot load plugin from {plugin_path}")

        _stage("plugin_load_start", {"plugin_path": plugin_path})
        plugin_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin_module)
        plugin_instance = plugin_module.PLUGIN_ENTRY()
        globals()["IDA_SCRIPT_MCP_TEST_PLUGIN_INSTANCE_U013"] = plugin_instance
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
            database_path = saved_database_path

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
    print("U013_STAGE=" + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


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
    bootstrap_path = work_dir / "U013_patch_bytes_complex_cases_bootstrap.py"
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


def _read_process_pipes(process: subprocess.Popen) -> tuple[str, str]:
    try:
        stdout, stderr = process.communicate(timeout=10)
    except Exception:
        stdout, stderr = "", ""
    return stdout or "", stderr or ""


def _flip_byte_hex(byte_hex: str) -> str:
    value = int(byte_hex, 16)
    flipped = value ^ 0xFF
    if flipped == value:
        flipped ^= 0x55
    return f"{flipped & 0xFF:02x}"


def _flip_bytes_hex(bytes_hex: str) -> str:
    return "".join(_flip_byte_hex(bytes_hex[i : i + 2]) for i in range(0, len(bytes_hex), 2))


def _find_data_patch_target(base_url: str, imagebase: int, function_ea: int) -> dict:
    candidates = [0x4000, 0x5000, 0x6000, 0x7000, 0x41A8]
    for offset in candidates:
        address = imagebase + offset
        if abs(address - function_ea) < 0x100:
            continue
        response = _json_request(
            "POST",
            base_url,
            "/inspect_address",
            {"address": hex(address), "byte_count": 4},
            expected_status=200,
            timeout=10,
        )["body"]
        bytes_hex = response.get("bytes_hex") or ""
        if response.get("found") is True and len(bytes_hex) >= 2:
            return {"ea": address, "address": hex(address), "before": response, "old_byte": bytes_hex[:2]}
    raise RuntimeError("Could not find a data/readonly patch target candidate")


def _apply_payload(database_sha256: str, operations: list[dict], *, dry_run: bool | None = None, job_id: str = "u013") -> dict:
    payload = {
        "schema_version": 1,
        "job_id": job_id,
        "database_fingerprint": {"database_sha256": database_sha256},
        "operations": operations,
    }
    if dry_run is not None:
        payload["dry_run"] = dry_run
    return payload


def _run_u013(base_url: str, result: dict) -> None:
    health = _health_with_retry(base_url)
    result["responses"]["health"] = health["body"]
    metadata = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=10)["body"]
    result["responses"]["metadata_before"] = metadata
    _check(result, "metadata clean before U013", metadata.get("dirty_state_known") is True and metadata.get("dirty") is False, metadata)
    database_sha256 = metadata.get("database_sha256")
    _check(result, "metadata includes database_sha256", bool(database_sha256), metadata)
    imagebase = int(metadata.get("imagebase") or 0)
    _check(result, "metadata includes imagebase", imagebase > 0, metadata)

    functions = _json_request(
        "POST",
        base_url,
        "/functions",
        {"offset": 0, "limit": 8, "include_thunks": True, "include_library_functions": True},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["functions"] = functions
    function_list = functions.get("functions") or []
    _check(result, "functions returned for U013", bool(function_list), functions)
    target_ea = int(function_list[0]["start_ea"])
    target_hex = hex(target_ea)
    before = _json_request(
        "POST",
        base_url,
        "/inspect_address",
        {"address": target_hex, "byte_count": 16},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["inspect_code_before"] = before
    before_bytes = before.get("bytes_hex") or ""
    _check(result, "U013 code target has at least 16 bytes", len(before_bytes) >= 32, before)
    _check(result, "U013 code target has disassembly before patch", isinstance(before.get("disassembly"), str), before)

    data_target = _find_data_patch_target(base_url, imagebase, target_ea)
    result["data_patch_target"] = data_target

    multi_old = before_bytes[0:8]
    multi_new = _flip_bytes_hex(multi_old)
    middle_ea = target_ea + 5
    middle_old = before_bytes[10:12]
    middle_new = _flip_byte_hex(middle_old)
    same_ea = target_ea + 12
    same_old = before_bytes[24:26]
    repeat_ea = target_ea + 10
    repeat_old = before_bytes[20:22]
    repeat_mid = _flip_byte_hex(repeat_old)
    repeat_final = _flip_byte_hex(repeat_mid)
    data_old = data_target["old_byte"]
    data_new = _flip_byte_hex(data_old)
    unmapped_ea = 0x7FFFFFFFF000

    mismatch_old = "00" if middle_old.lower() != "00" else "ff"
    mismatch_op = {
        "op_id": "op-old-bytes-mismatch",
        "op": "patch_bytes",
        "ea": middle_ea,
        "source": "explicit_api",
        "old_bytes_hex": mismatch_old,
        "new_bytes_hex": middle_new,
    }
    mismatch_result = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        _apply_payload(database_sha256, [mismatch_op], dry_run=False, job_id="u013-mismatch"),
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["old_bytes_mismatch"] = mismatch_result
    _check(result, "old_bytes mismatch returns error", mismatch_result.get("status") == "error", mismatch_result)
    _check(result, "old_bytes mismatch is reported", "old_bytes mismatch" in str((mismatch_result.get("errors") or [{}])[0].get("message", "")), mismatch_result)
    metadata_after_mismatch = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)["body"]
    result["responses"]["metadata_after_mismatch"] = metadata_after_mismatch
    _check(result, "metadata remains clean after mismatch-only failure", metadata_after_mismatch.get("dirty") is False, metadata_after_mismatch)

    unmapped_only_op = {
        "op_id": "op-unmapped-only",
        "op": "patch_bytes",
        "ea": unmapped_ea,
        "source": "explicit_api",
        "old_bytes_hex": "00",
        "new_bytes_hex": "90",
    }
    unmapped_result = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        _apply_payload(database_sha256, [unmapped_only_op], dry_run=False, job_id="u013-unmapped-only"),
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["unmapped_only"] = unmapped_result
    _check(result, "unmapped patch returns error", unmapped_result.get("status") == "error", unmapped_result)
    metadata_after_unmapped = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)["body"]
    result["responses"]["metadata_after_unmapped"] = metadata_after_unmapped
    _check(result, "metadata remains clean after unmapped-only failure", metadata_after_unmapped.get("dirty") is False, metadata_after_unmapped)

    operations = [
        {
            "op_id": "op-multi-byte-code",
            "op": "patch_bytes",
            "ea": target_ea,
            "source": "explicit_api",
            "old_bytes_hex": multi_old,
            "new_bytes_hex": multi_new,
        },
        {
            "op_id": "op-middle-byte-code",
            "op": "patch_bytes",
            "ea": middle_ea,
            "source": "explicit_api",
            "old_bytes_hex": middle_old,
            "new_bytes_hex": middle_new,
        },
        {
            "op_id": "op-same-byte-code",
            "op": "patch_bytes",
            "ea": same_ea,
            "source": "explicit_api",
            "old_bytes_hex": same_old,
            "new_bytes_hex": same_old,
        },
        {
            "op_id": "op-repeat-byte-1",
            "op": "patch_bytes",
            "ea": repeat_ea,
            "source": "explicit_api",
            "old_bytes_hex": repeat_old,
            "new_bytes_hex": repeat_mid,
        },
        {
            "op_id": "op-repeat-byte-2",
            "op": "patch_bytes",
            "ea": repeat_ea,
            "source": "explicit_api",
            "old_bytes_hex": repeat_mid,
            "new_bytes_hex": repeat_final,
        },
        {
            "op_id": "op-data-byte",
            "op": "patch_bytes",
            "ea": int(data_target["ea"]),
            "source": "explicit_api",
            "old_bytes_hex": data_old,
            "new_bytes_hex": data_new,
        },
        {
            "op_id": "op-unmapped-partial-stop",
            "op": "patch_bytes",
            "ea": unmapped_ea,
            "source": "explicit_api",
            "old_bytes_hex": "00",
            "new_bytes_hex": "90",
        },
    ]
    result["u013_operation_summary"] = {
        "target_ea": target_ea,
        "data_ea": int(data_target["ea"]),
        "unmapped_ea": unmapped_ea,
        "operation_ids": [op["op_id"] for op in operations],
        "multi_old": multi_old,
        "multi_new": multi_new,
        "middle_old": middle_old,
        "middle_new": middle_new,
        "same_old": same_old,
        "repeat_old": repeat_old,
        "repeat_mid": repeat_mid,
        "repeat_final": repeat_final,
        "data_old": data_old,
        "data_new": data_new,
    }

    dry_run = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        _apply_payload(database_sha256, operations, dry_run=True, job_id="u013-dry-run"),
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["dry_run_complex"] = dry_run
    _check(result, "U013 dry-run status ok", dry_run.get("status") == "ok", dry_run)
    _check(result, "U013 dry-run applies nothing", dry_run.get("applied") == [], dry_run)
    _check(result, "U013 dry-run skips all operations", len(dry_run.get("skipped") or []) == len(operations), dry_run)
    inspect_after_dry = _json_request(
        "POST",
        base_url,
        "/inspect_address",
        {"address": target_hex, "byte_count": 16},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["inspect_after_dry"] = inspect_after_dry
    _check(result, "U013 dry-run leaves code bytes unchanged", (inspect_after_dry.get("bytes_hex") or "").lower() == before_bytes.lower(), inspect_after_dry)

    destructive = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        _apply_payload(database_sha256, operations, dry_run=False, job_id="u013-partial"),
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["destructive_partial"] = destructive
    _check(result, "U013 destructive patch has partial status", destructive.get("status") == "partial", destructive)
    _check(result, "U013 destructive patch applied six operations", len(destructive.get("applied") or []) == 6, destructive)
    _check(result, "U013 destructive patch has one error", len(destructive.get("errors") or []) == 1, destructive)
    _check(result, "U013 partial error is unmapped op", (destructive.get("errors") or [{}])[0].get("op_id") == "op-unmapped-partial-stop", destructive)

    after = _json_request(
        "POST",
        base_url,
        "/inspect_address",
        {"address": target_hex, "byte_count": 16},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["inspect_after_partial"] = after
    after_bytes = after.get("bytes_hex") or ""
    expected = list(bytes.fromhex(before_bytes[:32]))
    expected[0:4] = bytes.fromhex(multi_new)
    expected[5] = int(middle_new, 16)
    expected[10] = int(repeat_final, 16)
    expected[12] = int(same_old, 16)
    expected_hex = bytes(expected).hex()
    result["expected_code_bytes_after"] = expected_hex
    _check(result, "U013 applied code bytes match expected", after_bytes[:32].lower() == expected_hex.lower(), after)
    _check(result, "U013 disassembly still refreshes after patch", isinstance(after.get("disassembly"), str), after)

    data_after = _json_request(
        "POST",
        base_url,
        "/inspect_address",
        {"address": data_target["address"], "byte_count": 4},
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["data_after_partial"] = data_after
    _check(result, "U013 data patch byte visible", (data_after.get("bytes_hex") or "")[:2].lower() == data_new.lower(), data_after)

    metadata_after = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)["body"]
    result["responses"]["metadata_after_partial"] = metadata_after
    _check(result, "U013 metadata dirty after destructive partial patch", metadata_after.get("dirty") is True, metadata_after)

    rejected = _json_request(
        "POST",
        base_url,
        "/apply_changes",
        _apply_payload(database_sha256, operations[:1], dry_run=False, job_id="u013-rejected-dirty"),
        expected_status=200,
        timeout=10,
    )["body"]
    result["responses"]["rejected_after_dirty"] = rejected
    _check(result, "U013 second destructive apply rejected when dirty", rejected.get("status") == "rejected", rejected)


def main() -> int:
    ida_dir = Path(IDA_DIR)
    dll_path = Path(DLL_PATH)
    stdout = ""
    stderr = ""
    process = None
    result: dict = {"status": "failed", "mode": "u013_patch_bytes_complex_cases", "dll_path": DLL_PATH, "work_dir": str(WORK_DIR), "checks": [], "responses": {}}

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
        _run_u013(str(ready["base_url"]), result)
        result.update({"status": "passed", "ida_executable": str(ida_executable), "ida_log_path": str(IDA_LOG_PATH), "work_dir": str(WORK_DIR), "database_path": str(database_path)})
        _stage("u013_tests_done", {"status": result.get("status")})
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
        print("U013_PATCH_BYTES_COMPLEX_TEST_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            "U013_PATCH_BYTES_COMPLEX_TEST_ERROR="
            + json.dumps({"type": type(exc).__name__, "message": str(exc), "traceback": traceback.format_exc()}, ensure_ascii=False, sort_keys=True),
            file=sys.stderr,
        )
        raise SystemExit(1)
