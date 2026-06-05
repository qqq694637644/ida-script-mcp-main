"Build the real MCP client end-to-end guest payload for the strict execute plugin."

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

PAYLOAD_SCRIPT_NAME = "U004_real_MCP_client_end-to-end.py"
WORKER_SCRIPT_NAME = "U004_real_MCP_client_worker_script.py"
RUNTIME_PACKAGE_FILES = (
    "__init__.py",
    "server.py",
    "protocol.py",
    "execution.py",
)


def _package_source_dir(source_root: Path | None = None) -> Path:
    if source_root is not None:
        return source_root
    return Path(__file__).resolve().parents[1]


def _payload_source_dir() -> Path:
    return Path(__file__).resolve().parent


def _read_runtime_package_files(source_root: Path | None = None) -> dict[str, bytes]:
    """Read only the runtime modules needed by the strict MCP server."""

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
        raise FileNotFoundError("Missing real MCP runtime package source files: " + ", ".join(missing))
    return payload


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


def build_guest_u004_real_mcp_client_test_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    dll_path: str = DEFAULT_GUEST_DLL_PATH,
    ida_timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
    source_root: Path | None = None,
) -> str:
    """Build a standalone guest script for strict real MCP client testing."""

    install_files = _read_install_files(source_root)
    runtime_files = _read_runtime_package_files(source_root)
    payload_dir = _payload_source_dir()
    template_path = payload_dir / PAYLOAD_SCRIPT_NAME
    worker_script_path = payload_dir / WORKER_SCRIPT_NAME
    template = template_path.read_text(encoding="utf-8")
    worker_script = worker_script_path.read_bytes()

    replacements = {
        '"__IDA_DIR_JSON__"': json.dumps(ida_dir),
        '"__DLL_PATH_JSON__"': json.dumps(dll_path),
        '"__IDA_TIMEOUT_SECONDS_JSON__"': json.dumps(ida_timeout_seconds),
        '"__IDA_EXECUTABLE_CANDIDATES_JSON__"': json.dumps(list(IDA_EXECUTABLE_CANDIDATES)),
        '"__LEGACY_ROOT_SUPPORT_FILES_JSON__"': json.dumps(list(LEGACY_ROOT_SUPPORT_FILES)),
        '"__PLUGIN_FILES_B64_JSON__"': json.dumps(_b64_map(install_files), ensure_ascii=False),
        '"__PLUGIN_EXPECTED_SHA256_JSON__"': json.dumps(_sha256_map(install_files), ensure_ascii=False),
        '"__RUNTIME_FILES_B64_JSON__"': json.dumps(_b64_map(runtime_files), ensure_ascii=False),
        '"__RUNTIME_EXPECTED_SHA256_JSON__"': json.dumps(_sha256_map(runtime_files), ensure_ascii=False),
        '"__WORKER_SCRIPT_B64_JSON__"': json.dumps(base64.b64encode(worker_script).decode("ascii")),
        '"__WORKER_SCRIPT_SHA256_JSON__"': json.dumps(hashlib.sha256(worker_script).hexdigest()),
    }
    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)

    unreplaced = [
        token
        for token in (
            "__IDA_DIR_JSON__",
            "__DLL_PATH_JSON__",
            "__IDA_TIMEOUT_SECONDS_JSON__",
            "__PLUGIN_FILES_B64_JSON__",
            "__RUNTIME_FILES_B64_JSON__",
            "__WORKER_SCRIPT_B64_JSON__",
        )
        if token in template
    ]
    if unreplaced:
        raise RuntimeError("Unreplaced real MCP payload placeholders: " + ", ".join(unreplaced))
    return template


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
        build_guest_u004_real_mcp_client_test_script(
            ida_dir=args.ida_dir,
            dll_path=args.dll_path,
            ida_timeout_seconds=args.ida_timeout_seconds,
        ),
        encoding="utf-8",
    )
    print(f"Wrote real MCP client guest payload: {output_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
