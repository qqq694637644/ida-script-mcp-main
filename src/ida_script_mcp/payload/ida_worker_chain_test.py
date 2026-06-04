"""Build guest-side V2.3 worker-chain verification payloads."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from .ida_api_test import DEFAULT_GUEST_DLL_PATH, DEFAULT_IDA_TIMEOUT_SECONDS
from .ida_plugin_install import (
    DEFAULT_GUEST_IDA_DIR,
    IDA_EXECUTABLE_CANDIDATES,
    LEGACY_ROOT_SUPPORT_FILES,
    _read_install_files,
)

RUNTIME_PACKAGE_FILES = (
    "__init__.py",
    "server.py",
    "protocol.py",
    "isolated_manager.py",
    "isolated_protocol.py",
    "worker_runner.py",
    "execution.py",
    "change_protocol.py",
    "change_recorder.py",
    "process_utils.py",
)
USER_SCRIPT_FILES = (
    "worker_chain_user_script.py",
    "worker_timeout_user_script.py",
    "worker_crash_user_script.py",
    "worker_result_missing_user_script.py",
    "worker_recorder_error_user_script.py",
    "u012_set_type_complex_worker_script.py",
)


def _package_source_dir(source_root: Path | None = None) -> Path:
    if source_root is not None:
        return source_root
    return Path(__file__).resolve().parents[1]


def _payload_source_dir() -> Path:
    return Path(__file__).resolve().parent


def _read_runtime_package_files(source_root: Path | None = None) -> dict[str, bytes]:
    package_dir = _package_source_dir(source_root)
    payload: dict[str, bytes] = {}
    missing: list[str] = []
    for relative_name in RUNTIME_PACKAGE_FILES:
        source_path = package_dir / relative_name
        if not source_path.is_file():
            missing.append(str(source_path))
            continue
        payload[f"ida_script_mcp/{relative_name}"] = source_path.read_bytes()
    if missing:
        raise FileNotFoundError("Missing runtime package source files: " + ", ".join(missing))
    return payload


def _read_user_script_files() -> dict[str, bytes]:
    payload_dir = _payload_source_dir()
    files: dict[str, bytes] = {}
    missing: list[str] = []
    for relative_name in USER_SCRIPT_FILES:
        source_path = payload_dir / relative_name
        if not source_path.is_file():
            missing.append(str(source_path))
            continue
        files[relative_name] = source_path.read_bytes()
    if missing:
        raise FileNotFoundError("Missing worker user script files: " + ", ".join(missing))
    return files


def _b64_map(files: dict[str, bytes]) -> dict[str, str]:
    return {
        destination: base64.b64encode(content).decode("ascii")
        for destination, content in sorted(files.items())
    }


def _sha256_map(files: dict[str, bytes]) -> dict[str, str]:
    return {
        destination: hashlib.sha256(content).hexdigest()
        for destination, content in sorted(files.items())
    }


def build_guest_ida_worker_chain_test_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    dll_path: str = DEFAULT_GUEST_DLL_PATH,
    ida_timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
    test_mode: str = "worker_chain",
    source_root: Path | None = None,
) -> str:
    """Build a standalone guest script for V2.3 worker-chain lifecycle tests."""

    user_script_name_by_mode = {
        "worker_chain": "worker_chain_user_script.py",
        "worker_timeout": "worker_timeout_user_script.py",
        "worker_failure_matrix": "worker_crash_user_script.py",
        "u012_set_type_complex": "u012_set_type_complex_worker_script.py",
    }
    try:
        user_script_name = user_script_name_by_mode[test_mode]
    except KeyError as exc:
        raise ValueError(f"Unsupported worker test mode: {test_mode!r}") from exc

    install_files = _read_install_files(source_root)
    runtime_files = _read_runtime_package_files(source_root)
    user_scripts = _read_user_script_files()
    if user_script_name not in user_scripts:
        raise FileNotFoundError(f"Missing user script for {test_mode}: {user_script_name}")
    template_path = _payload_source_dir() / "guest_worker_chain_payload.py"
    script = template_path.read_text(encoding="utf-8")

    replacements = {
        '"__IDA_DIR_JSON__"': json.dumps(ida_dir),
        '"__DLL_PATH_JSON__"': json.dumps(dll_path),
        '"__TEST_MODE_JSON__"': json.dumps(test_mode),
        '"__USER_SCRIPT_FILENAME_JSON__"': json.dumps(user_script_name),
        '"__IDA_TIMEOUT_SECONDS_JSON__"': json.dumps(ida_timeout_seconds),
        '"__IDA_EXECUTABLE_CANDIDATES_JSON__"': json.dumps(list(IDA_EXECUTABLE_CANDIDATES)),
        '"__LEGACY_ROOT_SUPPORT_FILES_JSON__"': json.dumps(list(LEGACY_ROOT_SUPPORT_FILES)),
        '"__PLUGIN_FILES_B64_JSON__"': json.dumps(_b64_map(install_files), ensure_ascii=False),
        '"__PLUGIN_EXPECTED_SHA256_JSON__"': json.dumps(_sha256_map(install_files), ensure_ascii=False),
        '"__RUNTIME_FILES_B64_JSON__"': json.dumps(_b64_map(runtime_files), ensure_ascii=False),
        '"__RUNTIME_EXPECTED_SHA256_JSON__"': json.dumps(_sha256_map(runtime_files), ensure_ascii=False),
        '"__USER_SCRIPT_B64_JSON__"': json.dumps(_b64_map(user_scripts), ensure_ascii=False),
        '"__USER_SCRIPT_SHA256_JSON__"': json.dumps(_sha256_map(user_scripts), ensure_ascii=False),
    }
    for placeholder, value in replacements.items():
        script = script.replace(placeholder, value)

    unreplaced = [
        token
        for token in (
            "__IDA_DIR_JSON__",
            "__DLL_PATH_JSON__",
            "__TEST_MODE_JSON__",
            "__USER_SCRIPT_FILENAME_JSON__",
            "__IDA_TIMEOUT_SECONDS_JSON__",
            "__PLUGIN_FILES_B64_JSON__",
            "__RUNTIME_FILES_B64_JSON__",
            "__USER_SCRIPT_B64_JSON__",
        )
        if token in script
    ]
    if unreplaced:
        raise RuntimeError("Unreplaced worker-chain payload placeholders: " + ", ".join(unreplaced))
    return script


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", default=DEFAULT_GUEST_IDA_DIR)
    parser.add_argument("--dll-path", default=DEFAULT_GUEST_DLL_PATH)
    parser.add_argument("--ida-timeout-seconds", type=int, default=DEFAULT_IDA_TIMEOUT_SECONDS)
    parser.add_argument(
        "--test-mode",
        default="worker_chain",
        choices=[
            "worker_chain",
            "worker_timeout",
            "worker_failure_matrix",
            "u012_set_type_complex",
        ],
    )
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        build_guest_ida_worker_chain_test_script(
            ida_dir=args.ida_dir,
            dll_path=args.dll_path,
            ida_timeout_seconds=args.ida_timeout_seconds,
            test_mode=args.test_mode,
        ),
        encoding="utf-8",
    )
    print(f"Wrote guest IDA worker-chain test payload: {output_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
