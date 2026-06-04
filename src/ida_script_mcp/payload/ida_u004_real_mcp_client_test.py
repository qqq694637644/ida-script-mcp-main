"""Build the U004 real MCP client end-to-end guest payload."""

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
from .ida_worker_chain_test import _b64_map, _read_runtime_package_files, _sha256_map

PAYLOAD_SCRIPT_NAME = "U004_real_MCP_client_end-to-end.py"
WORKER_SCRIPT_NAME = "U004_real_MCP_client_worker_script.py"


def _payload_source_dir() -> Path:
    return Path(__file__).resolve().parent


def build_guest_u004_real_mcp_client_test_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    dll_path: str = DEFAULT_GUEST_DLL_PATH,
    ida_timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
    source_root: Path | None = None,
) -> str:
    """Build a standalone guest script for U004 real MCP client testing."""

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
        raise RuntimeError("Unreplaced U004 payload placeholders: " + ", ".join(unreplaced))
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
    print(f"Wrote U004 real MCP client guest payload: {output_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
