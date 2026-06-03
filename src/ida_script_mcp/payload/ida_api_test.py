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
    _read_install_files,
)

DEFAULT_GUEST_DLL_PATH = r"C:\Users\alion\Desktop\test1.dll"
DEFAULT_IDA_TIMEOUT_SECONDS = 900


def build_guest_ida_api_test_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    dll_path: str = DEFAULT_GUEST_DLL_PATH,
    ida_timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
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
        "__IDA_EXECUTABLE_CANDIDATES_JSON__": json.dumps(list(IDA_EXECUTABLE_CANDIDATES)),
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
    from pathlib import Path

    IDA_DIR = __IDA_DIR_JSON__
    DLL_PATH = __BOOTSTRAP_DLL_PATH_JSON__
    IDA_TIMEOUT_SECONDS = __IDA_TIMEOUT_SECONDS_JSON__
    IDA_EXECUTABLE_CANDIDATES = __IDA_EXECUTABLE_CANDIDATES_JSON__
    FILES_B64 = __FILES_B64_JSON__
    EXPECTED_SHA256 = __EXPECTED_SHA256_JSON__

    BOOTSTRAP_TEMPLATE = r'''
    from __future__ import annotations

    import json
    import sys
    import threading
    import time
    import traceback
    import urllib.error
    import urllib.request
    from pathlib import Path

    RESULT_PATH = __RESULT_PATH_JSON__
    PLUGIN_DIR = __PLUGIN_DIR_JSON__
    DLL_PATH = __DLL_PATH_JSON__


    def _json_request(method, base_url, path, payload=None, expected_status=200, timeout=30):
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


    def _write_result(payload):
        path = Path(RESULT_PATH)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


    def _request_exit(plugin_instance, exit_code):
        def do_exit():
            try:
                if plugin_instance is not None:
                    plugin_instance.term()
            except Exception:
                pass
            try:
                import idc

                idc.qexit(int(exit_code))
            except Exception:
                try:
                    import ida_pro

                    ida_pro.qexit(int(exit_code))
                except Exception:
                    pass
            return 1

        try:
            import idaapi

            flags = getattr(idaapi, "MFF_WRITE", 0)
            idaapi.execute_sync(do_exit, flags)
        except Exception:
            do_exit()


    def _run_http_tests(plugin_module, plugin_instance):
        result = {
            "status": "running",
            "dll_path": DLL_PATH,
            "plugin_dir": PLUGIN_DIR,
            "checks": [],
            "responses": {},
            "selected_function": None,
        }
        exit_code = 1
        try:
            port = int(getattr(plugin_module.instance_registry, "port", 0) or 0)
            if port <= 0:
                port = int(getattr(plugin_instance, "port", 13338) or 13338)
            base_url = f"http://127.0.0.1:{port}"
            result["base_url"] = base_url

            health = None
            last_error = None
            for _ in range(60):
                try:
                    health = _json_request("GET", base_url, "/health", expected_status=200, timeout=2)
                    break
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    time.sleep(0.5)
            _check(result, "health endpoint is reachable", health is not None, last_error)
            result["responses"]["health"] = health["body"]
            _check(
                result,
                "health reports plugin name",
                health["body"].get("plugin") == "IDA-Script-MCP",
                health["body"],
            )

            metadata = _json_request("GET", base_url, "/metadata", expected_status=200)
            result["responses"]["metadata"] = metadata["body"]
            _check(result, "metadata includes input path", bool(metadata["body"].get("input_file_path")), metadata["body"])
            _check(result, "metadata includes database path", "database_path" in metadata["body"], metadata["body"])
            _check(result, "metadata includes dirty state", "dirty_state_known" in metadata["body"], metadata["body"])

            functions_page = _json_request(
                "POST",
                base_url,
                "/functions",
                {"offset": 0, "limit": 20, "include_thunks": True, "include_library_functions": True},
                expected_status=200,
            )
            result["responses"]["functions_page"] = functions_page["body"]
            functions = functions_page["body"].get("functions") or []
            _check(result, "functions endpoint returns a list", isinstance(functions, list), functions_page["body"])
            _check(result, "functions endpoint returns at least one function", len(functions) > 0, functions_page["body"])
            _check(result, "functions pagination respects limit", functions_page["body"].get("returned", 0) <= 20, functions_page["body"])

            first_function = functions[0]
            result["selected_function"] = first_function
            start_ea = int(first_function["start_ea"])
            start_ea_hex = hex(start_ea)
            first_name = first_function.get("name") or ""

            functions_limit_one = _json_request(
                "POST",
                base_url,
                "/functions",
                {"offset": 0, "limit": 1, "include_thunks": True, "include_library_functions": True},
                expected_status=200,
            )
            result["responses"]["functions_limit_one"] = functions_limit_one["body"]
            _check(result, "functions limit=1 returns at most one", functions_limit_one["body"].get("returned", 0) <= 1, functions_limit_one["body"])

            if first_name:
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
                )
                result["responses"]["functions_filter"] = functions_filter["body"]
                _check(result, "functions name filter is accepted", "functions" in functions_filter["body"], functions_filter["body"])

            decompile = _json_request(
                "POST",
                base_url,
                "/decompile",
                {"address": start_ea_hex, "include_disassembly": True},
                expected_status=200,
            )
            result["responses"]["decompile"] = decompile["body"]
            _check(result, "decompile resolves selected function", decompile["body"].get("found") is True, decompile["body"])
            _check(result, "decompile includes disassembly", isinstance(decompile["body"].get("disassembly"), list), decompile["body"])

            decompile_bad = _json_request(
                "POST",
                base_url,
                "/decompile",
                {"address": "not-an-address", "include_disassembly": True},
                expected_status=200,
            )
            result["responses"]["decompile_bad_address"] = decompile_bad["body"]
            _check(result, "decompile bad address returns structured not found", decompile_bad["body"].get("found") is False, decompile_bad["body"])

            xrefs_to = _json_request(
                "POST",
                base_url,
                "/xrefs",
                {"address": start_ea_hex, "direction": "to", "xref_kind": "all", "limit": 20},
                expected_status=200,
            )
            result["responses"]["xrefs_to"] = xrefs_to["body"]
            _check(result, "xrefs-to resolves selected target", xrefs_to["body"].get("found") is True, xrefs_to["body"])
            _check(result, "xrefs-to returns a list", isinstance(xrefs_to["body"].get("xrefs"), list), xrefs_to["body"])

            xrefs_from = _json_request(
                "POST",
                base_url,
                "/xrefs",
                {"address": start_ea_hex, "direction": "from", "xref_kind": "all", "limit": 20},
                expected_status=200,
            )
            result["responses"]["xrefs_from"] = xrefs_from["body"]
            _check(result, "xrefs-from resolves selected target", xrefs_from["body"].get("found") is True, xrefs_from["body"])
            _check(result, "xrefs-from returns a list", isinstance(xrefs_from["body"].get("xrefs"), list), xrefs_from["body"])

            xrefs_invalid = _json_request(
                "POST",
                base_url,
                "/xrefs",
                {"address": start_ea_hex, "direction": "sideways", "xref_kind": "all", "limit": 20},
                expected_status=200,
            )
            result["responses"]["xrefs_invalid_direction"] = xrefs_invalid["body"]
            _check(result, "xrefs invalid direction is structured", bool(xrefs_invalid["body"].get("error")), xrefs_invalid["body"])

            execute_disabled = _json_request(
                "POST",
                base_url,
                "/execute",
                {"code": "print('must not run in GUI')"},
                expected_status=410,
            )
            result["responses"]["execute_disabled"] = execute_disabled["body"]
            _check(result, "GUI /execute is disabled", execute_disabled["body"].get("status") == "rejected", execute_disabled["body"])

            not_found = _json_request("GET", base_url, "/does-not-exist", expected_status=404)
            result["responses"]["not_found"] = not_found["body"]
            _check(result, "unknown GET route returns 404", bool(not_found["body"].get("error")), not_found["body"])

            result["status"] = "passed"
            exit_code = 0
        except Exception as exc:
            result["status"] = "failed"
            result["error"] = {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": traceback.format_exc(),
            }
        finally:
            _write_result(result)
            _request_exit(plugin_instance, exit_code)


    def main():
        plugin_instance = None
        try:
            import ida_auto
            import idaapi

            ida_auto.auto_wait()
            if PLUGIN_DIR not in sys.path:
                sys.path.insert(0, PLUGIN_DIR)
            import importlib.util

            plugin_path = str(Path(PLUGIN_DIR) / "ida_script_mcp.py")
            spec = importlib.util.spec_from_file_location("ida_script_mcp_loaded_plugin", plugin_path)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"Cannot load plugin from {plugin_path}")
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            plugin_instance = plugin_module.PLUGIN_ENTRY()
            plugin_instance.init()
            plugin_instance.run(0)
            tester = threading.Thread(
                target=_run_http_tests,
                args=(plugin_module, plugin_instance),
                name="ida-script-mcp-api-test",
                daemon=False,
            )
            tester.start()
        except Exception as exc:
            _write_result(
                {
                    "status": "failed",
                    "dll_path": DLL_PATH,
                    "plugin_dir": PLUGIN_DIR,
                    "checks": [],
                    "error": {
                        "type": type(exc).__name__,
                        "message": str(exc),
                        "traceback": traceback.format_exc(),
                    },
                }
            )
            _request_exit(plugin_instance, 1)


    if __name__ == "__main__":
        main()
    '''


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


    def _tail(path: Path, max_chars: int = 12000) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        return text[-max_chars:]


    def _install_plugin_files() -> Path:
        plugin_dir = _ida_user_dir() / "plugins"
        plugin_dir.mkdir(parents=True, exist_ok=True)
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


    def _write_bootstrap(work_dir: Path, plugin_dir: Path, result_path: Path) -> Path:
        bootstrap_path = work_dir / "ida_api_bootstrap.py"
        bootstrap_text = BOOTSTRAP_TEMPLATE
        replacements = {
            "__RESULT_PATH_JSON__": json.dumps(str(result_path)),
            "__PLUGIN_DIR_JSON__": json.dumps(str(plugin_dir)),
            "__BOOTSTRAP_DLL_PATH_JSON__": json.dumps(str(Path(DLL_PATH))),
        }
        for placeholder, value in replacements.items():
            bootstrap_text = bootstrap_text.replace(placeholder, value)
        bootstrap_path.write_text(bootstrap_text, encoding="utf-8")
        return bootstrap_path


    def _terminate_process(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        try:
            process.terminate()
            process.wait(timeout=10)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass


    def main() -> int:
        ida_dir = Path(IDA_DIR)
        dll_path = Path(DLL_PATH)
        if not ida_dir.is_dir():
            raise RuntimeError(f"IDA directory does not exist: {ida_dir}")
        if not dll_path.is_file():
            raise RuntimeError(f"DLL path does not exist: {dll_path}")

        plugin_dir = _install_plugin_files()
        ida_executable = _select_ida_executable(ida_dir)
        work_dir = Path(tempfile.mkdtemp(prefix="ida-script-mcp-api-test-"))
        result_path = work_dir / "ida_api_test_result.json"
        ida_log_path = work_dir / "ida.log"
        database_path = work_dir / (dll_path.stem + ".i64")
        bootstrap_path = _write_bootstrap(work_dir, plugin_dir, result_path)

        command = [
            str(ida_executable),
            "-A",
            f"-L{ida_log_path}",
            f"-S{bootstrap_path}",
            f"-o{database_path}",
            str(dll_path),
        ]
        process = subprocess.Popen(
            command,
            cwd=str(work_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=IDA_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process(process)
            stdout, stderr = process.communicate(timeout=10)

        if timed_out:
            raise RuntimeError(
                "IDA API test timed out: "
                + json.dumps(
                    {
                        "command": command,
                        "work_dir": str(work_dir),
                        "ida_log_tail": _tail(ida_log_path),
                        "stdout_tail": (stdout or "")[-4000:],
                        "stderr_tail": (stderr or "")[-4000:],
                    },
                    ensure_ascii=False,
                )
            )

        if not result_path.is_file():
            raise RuntimeError(
                "IDA API test result file was not created: "
                + json.dumps(
                    {
                        "returncode": process.returncode,
                        "command": command,
                        "work_dir": str(work_dir),
                        "ida_log_tail": _tail(ida_log_path),
                        "stdout_tail": (stdout or "")[-4000:],
                        "stderr_tail": (stderr or "")[-4000:],
                    },
                    ensure_ascii=False,
                )
            )

        result = json.loads(result_path.read_text(encoding="utf-8"))
        result.update(
            {
                "ida_executable": str(ida_executable),
                "ida_returncode": process.returncode,
                "ida_log_path": str(ida_log_path),
                "ida_log_tail": _tail(ida_log_path),
                "work_dir": str(work_dir),
                "database_path": str(database_path),
            }
        )
        print("IDA_PLUGIN_API_TEST_RESULT=" + json.dumps(result, ensure_ascii=False, sort_keys=True))
        if result.get("status") != "passed":
            return 1
        return 0


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
