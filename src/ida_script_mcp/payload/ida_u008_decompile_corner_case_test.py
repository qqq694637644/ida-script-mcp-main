"""Build the U008 /decompile corner-case guest payload."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ida_api_test import DEFAULT_GUEST_DLL_PATH, DEFAULT_IDA_TIMEOUT_SECONDS
from .ida_plugin_install import (
    DEFAULT_GUEST_IDA_DIR,
    IDA_EXECUTABLE_CANDIDATES,
    LEGACY_ROOT_SUPPORT_FILES,
    _read_install_files,
)
from .ida_worker_chain_test import _b64_map, _sha256_map

PAYLOAD_SCRIPT_NAME = "U008_decompile_corner_cases.py"


def _payload_source_dir() -> Path:
    return Path(__file__).resolve().parent


def build_guest_u008_decompile_corner_case_test_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    dll_path: str = DEFAULT_GUEST_DLL_PATH,
    ida_timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
    source_root: Path | None = None,
) -> str:
    """Build a standalone guest script for U008 /decompile corner-case testing."""

    install_files = _read_install_files(source_root)
    template_path = _payload_source_dir() / PAYLOAD_SCRIPT_NAME
    template = template_path.read_text(encoding="utf-8")

    replacements = {
        '"__IDA_DIR_JSON__"': json.dumps(ida_dir),
        '"__DLL_PATH_JSON__"': json.dumps(dll_path),
        '"__IDA_TIMEOUT_SECONDS_JSON__"': json.dumps(ida_timeout_seconds),
        '"__IDA_EXECUTABLE_CANDIDATES_JSON__"': json.dumps(list(IDA_EXECUTABLE_CANDIDATES)),
        '"__LEGACY_ROOT_SUPPORT_FILES_JSON__"': json.dumps(list(LEGACY_ROOT_SUPPORT_FILES)),
        '"__PLUGIN_FILES_B64_JSON__"': json.dumps(_b64_map(install_files), ensure_ascii=False),
        '"__PLUGIN_EXPECTED_SHA256_JSON__"': json.dumps(
            _sha256_map(install_files),
            ensure_ascii=False,
        ),
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
        )
        if token in template
    ]
    if unreplaced:
        raise RuntimeError("Unreplaced U008 payload placeholders: " + ", ".join(unreplaced))
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
        build_guest_u008_decompile_corner_case_test_script(
            ida_dir=args.ida_dir,
            dll_path=args.dll_path,
            ida_timeout_seconds=args.ida_timeout_seconds,
        ),
        encoding="utf-8",
    )
    print(f"Wrote U008 /decompile corner-case guest payload: {output_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
