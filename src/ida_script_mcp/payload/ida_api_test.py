"""Build guest-side IDA open-DLL/plugin-API verification payloads."""
# ruff: noqa: E501

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from textwrap import dedent

from .ida_plugin_install import (
    DEFAULT_GUEST_IDA_DIR,
    IDA_EXECUTABLE_CANDIDATES,
    LEGACY_ROOT_SUPPORT_FILES,
    _read_install_files,
)

DEFAULT_GUEST_DLL_PATH = r"C:\Users\alion\Desktop\test1.dll"
DEFAULT_IDA_TIMEOUT_SECONDS = 180
DEFAULT_IDA_API_TEST_MODE = "basic"


def build_guest_ida_api_test_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    dll_path: str = DEFAULT_GUEST_DLL_PATH,
    ida_timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
    test_mode: str = DEFAULT_IDA_API_TEST_MODE,
    source_root: Path | None = None,
) -> str:
    """Build a standalone guest-side script that opens a DLL in IDA and tests APIs."""

    install_files = _read_install_files(source_root)
    files_b64 = {
        destination: base64.b64encode(content).decode("ascii")
        for destination, content in sorted(install_files.items())
    }
    expected_sha256 = {
        destination: hashlib.sha256(content).hexdigest()
        for destination, content in sorted(install_files.items())
    }

    script = _GUEST_IDA_API_TEST_TEMPLATE
    replacements = {
        "__IDA_DIR_JSON__": json.dumps(ida_dir),
        "__DLL_PATH_JSON__": json.dumps(dll_path),
        "__IDA_TIMEOUT_SECONDS_JSON__": json.dumps(ida_timeout_seconds),
        "__IDA_API_TEST_MODE_JSON__": json.dumps(test_mode),
        "__IDA_EXECUTABLE_CANDIDATES_JSON__": json.dumps(list(IDA_EXECUTABLE_CANDIDATES)),
        "__LEGACY_ROOT_SUPPORT_FILES_JSON__": json.dumps(list(LEGACY_ROOT_SUPPORT_FILES)),
        "__FILES_B64_JSON__": json.dumps(files_b64, ensure_ascii=False),
        "__EXPECTED_SHA256_JSON__": json.dumps(expected_sha256, ensure_ascii=False),
    }
    for placeholder, value in replacements.items():
        script = script.replace(placeholder, value)
    return script


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", default=DEFAULT_GUEST_IDA_DIR)
    parser.add_argument("--dll-path", default=DEFAULT_GUEST_DLL_PATH)
    parser.add_argument("--ida-timeout-seconds", type=int, default=DEFAULT_IDA_TIMEOUT_SECONDS)
    parser.add_argument("--test-mode", default=DEFAULT_IDA_API_TEST_MODE, choices=["basic", "full"])
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        build_guest_ida_api_test_script(
            ida_dir=args.ida_dir,
            dll_path=args.dll_path,
            ida_timeout_seconds=args.ida_timeout_seconds,
            test_mode=args.test_mode,
        ),
        encoding="utf-8",
    )
    print(f"Wrote guest IDA API test payload: {output_path}")


_GUEST_IDA_API_TEST_TEMPLATE = dedent(
    r"""
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

    IDA_DIR = __IDA_DIR_JSON__
    DLL_PATH = __DLL_PATH_JSON__
    IDA_TIMEOUT_SECONDS = __IDA_TIMEOUT_SECONDS_JSON__
    IDA_API_TEST_MODE = __IDA_API_TEST_MODE_JSON__
    IDA_READY_TIMEOUT_SECONDS = min(60, max(15, IDA_TIMEOUT_SECONDS // 3))
    IDA_EXECUTABLE_CANDIDATES = __IDA_EXECUTABLE_CANDIDATES_JSON__
    LEGACY_ROOT_SUPPORT_FILES = __LEGACY_ROOT_SUPPORT_FILES_JSON__
    FILES_B64 = __FILES_B64_JSON__
    EXPECTED_SHA256 = __EXPECTED_SHA256_JSON__

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
        with HEARTBEAT_PATH.open("a", encoding="utf-8") as output:
            output.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
            output.write("\n")
        print("IDA_API_STAGE=" + json.dumps(payload, ensure_ascii=False, sort_keys=True), flush=True)


    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


    def _ida_user_dir() -> Path:
        appdata = os.environ.get("APPDATA")
        if not appdata:
            raise RuntimeError("APPDATA is not set; cannot locate per-user IDA directory")
        return Path(appdata) / "Hex-Rays" / "IDA Pro"


    def _write_bytes_atomic(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        temp_path.write_bytes(content)
        os.replace(temp_path, path)


    def _write_json(path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


    def _tail(path: Path, max_chars: int = 12000) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        return text[-max_chars:]


    def _read_process_pipes(process: subprocess.Popen) -> tuple[str, str]:
        try:
            stdout, stderr = process.communicate(timeout=10)
        except Exception:
            stdout, stderr = "", ""
        return stdout or "", stderr or ""


    def _install_plugin_files() -> Path:
        plugin_dir = _ida_user_dir() / "plugins"
        plugin_dir.mkdir(parents=True, exist_ok=True)
        for legacy_name in LEGACY_ROOT_SUPPORT_FILES:
            legacy_path = plugin_dir / legacy_name
            if legacy_path.exists() or legacy_path.is_symlink():
                legacy_path.unlink()
        for destination, encoded in FILES_B64.items():
            path = plugin_dir / destination
            content = base64.b64decode(encoded.encode("ascii"))
            _write_bytes_atomic(path, content)
            digest = _sha256(path)
            if digest != EXPECTED_SHA256[destination]:
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
        bootstrap_path = work_dir / "ida_api_bootstrap.py"
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


    def _check(result, name, ok, detail=None):
        result["checks"].append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            raise AssertionError(f"check failed: {name}: {detail!r}")


    def _wait_for_ready(process: subprocess.Popen, ready_path: Path, ida_log_path: Path) -> dict:
        deadline = time.monotonic() + IDA_READY_TIMEOUT_SECONDS
        _stage("ida_ready_wait_start", {"timeout_seconds": IDA_READY_TIMEOUT_SECONDS})
        last_status = None
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
                            "last_status": last_status,
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


    def _run_external_api_tests(ready: dict) -> dict:
        base_url = str(ready["base_url"])
        result = {
            "status": "running",
            "mode": IDA_API_TEST_MODE,
            "dll_path": DLL_PATH,
            "ready": ready,
            "checks": [],
            "responses": {},
            "selected_function": None,
        }

        _stage("health_start", {"base_url": base_url})
        health = _health_with_retry(base_url)
        result["responses"]["health"] = health["body"]
        _check(result, "health reports plugin name", health["body"].get("plugin") == "IDA-Script-MCP", health["body"])
        _stage("health_done")

        _stage("metadata_start")
        metadata = _json_request("GET", base_url, "/metadata", expected_status=200, timeout=5)
        result["responses"]["metadata"] = metadata["body"]
        _check(result, "metadata includes input path", bool(metadata["body"].get("input_file_path")), metadata["body"])
        _check(result, "metadata includes database path", "database_path" in metadata["body"], metadata["body"])
        _check(result, "metadata includes dirty state", "dirty_state_known" in metadata["body"], metadata["body"])
        _stage("metadata_done")

        _stage("functions_start")
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
        _check(result, "functions endpoint returns a list", isinstance(functions, list), functions_page["body"])
        _check(result, "functions endpoint returns at least one function", len(functions) > 0, functions_page["body"])
        _check(result, "functions pagination respects limit", functions_page["body"].get("returned", 0) <= 20, functions_page["body"])

        functions_limit_one = _json_request(
            "POST",
            base_url,
            "/functions",
            {"offset": 0, "limit": 1, "include_thunks": True, "include_library_functions": True},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["functions_limit_one"] = functions_limit_one["body"]
        _check(result, "functions limit=1 returns at most one", functions_limit_one["body"].get("returned", 0) <= 1, functions_limit_one["body"])
        _stage("functions_done")

        first_function = functions[0]
        result["selected_function"] = first_function
        start_ea = int(first_function["start_ea"])
        start_ea_hex = hex(start_ea)
        first_name = first_function.get("name") or ""

        if first_name:
            _stage("functions_filter_start", {"name": first_name})
            name_filter = first_name[: max(1, min(4, len(first_name)))]
            functions_filter = _json_request(
                "POST",
                base_url,
                "/functions",
                {
                    "offset": 0,
                    "limit": 5,
                    "name_contains": name_filter,
                    "include_thunks": True,
                    "include_library_functions": True,
                },
                expected_status=200,
                timeout=10,
            )
            result["responses"]["functions_filter"] = functions_filter["body"]
            _check(result, "functions name filter is accepted", "functions" in functions_filter["body"], functions_filter["body"])
            _stage("functions_filter_done")

        if IDA_API_TEST_MODE == "basic":
            result["status"] = "passed"
            return result

        _stage("decompile_start", {"address": start_ea_hex})
        decompile = _json_request(
            "POST",
            base_url,
            "/decompile",
            {"address": start_ea_hex, "include_disassembly": True},
            expected_status=200,
            timeout=30,
        )
        result["responses"]["decompile"] = decompile["body"]
        _check(result, "decompile resolves selected function", decompile["body"].get("found") is True, decompile["body"])
        _check(result, "decompile includes disassembly", isinstance(decompile["body"].get("disassembly"), list), decompile["body"])
        _stage("decompile_done")

        _stage("decompile_bad_address_start")
        decompile_bad = _json_request(
            "POST",
            base_url,
            "/decompile",
            {"address": "not-an-address", "include_disassembly": True},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["decompile_bad_address"] = decompile_bad["body"]
        _check(result, "decompile bad address returns structured not found", decompile_bad["body"].get("found") is False, decompile_bad["body"])
        _stage("decompile_bad_address_done")

        for direction in ("to", "from"):
            _stage(f"xrefs_{direction}_start", {"address": start_ea_hex})
            xrefs = _json_request(
                "POST",
                base_url,
                "/xrefs",
                {"address": start_ea_hex, "direction": direction, "xref_kind": "all", "limit": 20},
                expected_status=200,
                timeout=10,
            )
            result["responses"][f"xrefs_{direction}"] = xrefs["body"]
            _check(result, f"xrefs-{direction} resolves selected target", xrefs["body"].get("found") is True, xrefs["body"])
            _check(result, f"xrefs-{direction} returns a list", isinstance(xrefs["body"].get("xrefs"), list), xrefs["body"])
            _stage(f"xrefs_{direction}_done")

        _stage("xrefs_invalid_direction_start")
        xrefs_invalid = _json_request(
            "POST",
            base_url,
            "/xrefs",
            {"address": start_ea_hex, "direction": "sideways", "xref_kind": "all", "limit": 20},
            expected_status=200,
            timeout=10,
        )
        result["responses"]["xrefs_invalid_direction"] = xrefs_invalid["body"]
        _check(result, "xrefs invalid direction is structured", bool(xrefs_invalid["body"].get("error")), xrefs_invalid["body"])
        _stage("xrefs_invalid_direction_done")

        _stage("execute_disabled_start")
        execute_disabled = _json_request(
            "POST",
            base_url,
            "/execute",
            {"code": "print('must not run in GUI')"},
            expected_status=410,
            timeout=10,
        )
        result["responses"]["execute_disabled"] = execute_disabled["body"]
        _check(result, "GUI /execute is disabled", execute_disabled["body"].get("status") == "rejected", execute_disabled["body"])
        _stage("execute_disabled_done")

        _stage("not_found_start")
        not_found = _json_request("GET", base_url, "/does-not-exist", expected_status=404, timeout=5)
        result["responses"]["not_found"] = not_found["body"]
        _check(result, "unknown GET route returns 404", bool(not_found["body"].get("error")), not_found["body"])
        _stage("not_found_done")

        result["status"] = "passed"
        return result


    def main() -> int:
        ida_dir = Path(IDA_DIR)
        dll_path = Path(DLL_PATH)
        work_dir = Path(tempfile.mkdtemp(prefix="ida-script-mcp-api-test-"))
        ready_path = work_dir / "ida_ready.json"
        heartbeat_path = work_dir / "heartbeat.ndjson"
        result_path = work_dir / "ida_api_test_result.json"
        ida_log_path = work_dir / "ida.log"
        stdout = ""
        stderr = ""
        process = None
        result: dict = {
            "status": "failed",
            "mode": IDA_API_TEST_MODE,
            "dll_path": DLL_PATH,
            "work_dir": str(work_dir),
            "checks": [],
        }

        try:
            _stage("validate_inputs_start", {"ida_dir": str(ida_dir), "dll_path": str(dll_path)})
            if not ida_dir.is_dir():
                raise RuntimeError(f"IDA directory does not exist: {ida_dir}")
            if not dll_path.is_file():
                raise RuntimeError(f"DLL path does not exist: {dll_path}")
            if IDA_API_TEST_MODE not in {"basic", "full"}:
                raise RuntimeError(f"Unsupported IDA API test mode: {IDA_API_TEST_MODE!r}")

            plugin_dir = _install_plugin_files()
            ida_executable = _select_ida_executable(ida_dir)
            database_path = work_dir / (dll_path.stem + ".i64")
            bootstrap_path = _write_bootstrap(work_dir, plugin_dir, ready_path, heartbeat_path)
            _stage("validate_inputs_done", {"ida_executable": str(ida_executable), "plugin_dir": str(plugin_dir)})

            command = [
                str(ida_executable),
                "-A",
                f"-L{ida_log_path}",
                f"-S{bootstrap_path}",
                f"-o{database_path}",
                str(dll_path),
            ]
            _stage("ida_start", {"command": command, "work_dir": str(work_dir)})
            process = subprocess.Popen(
                command,
                cwd=str(work_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            ready = _wait_for_ready(process, ready_path, ida_log_path)
            result = _run_external_api_tests(ready)
            result.update(
                {
                    "ida_executable": str(ida_executable),
                    "ida_log_path": str(ida_log_path),
                    "work_dir": str(work_dir),
                    "database_path": str(database_path),
                }
            )
            _stage("api_tests_done", {"status": result.get("status")})
        except Exception as exc:
            result["status"] = "failed"
            result["failed_stage"] = _tail(heartbeat_path, max_chars=2000)
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
                    "ida_log_tail": _tail(ida_log_path),
                    "heartbeat_tail": _tail(heartbeat_path),
                    "stdout_tail": stdout[-4000:],
                    "stderr_tail": stderr[-4000:],
                }
            )
            _write_json(result_path, result)
            print("IDA_PLUGIN_API_TEST_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)

        return 0 if result.get("status") == "passed" else 1


    if __name__ == "__main__":
        try:
            raise SystemExit(main())
        except Exception as exc:
            print(
                "IDA_PLUGIN_API_TEST_ERROR="
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
    """
).lstrip()


if __name__ == "__main__":  # pragma: no cover
    main()
