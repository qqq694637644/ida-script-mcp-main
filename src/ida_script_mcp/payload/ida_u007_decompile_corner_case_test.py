"""Build the U007 /decompile corner-case guest payload."""

from __future__ import annotations

import argparse
from pathlib import Path

from .ida_api_test import (
    DEFAULT_GUEST_DLL_PATH,
    DEFAULT_IDA_TIMEOUT_SECONDS,
    build_guest_ida_api_test_script,
)
from .ida_plugin_install import DEFAULT_GUEST_IDA_DIR

PAYLOAD_SCRIPT_NAME = "U007_decompile_corner_case.py"
TEST_MODE = "decompile_corner_case"


def build_guest_u007_decompile_corner_case_test_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    dll_path: str = DEFAULT_GUEST_DLL_PATH,
    ida_timeout_seconds: int = DEFAULT_IDA_TIMEOUT_SECONDS,
) -> str:
    """Build a standalone guest script for U007 /decompile corner-case testing."""

    return build_guest_ida_api_test_script(
        ida_dir=ida_dir,
        dll_path=dll_path,
        ida_timeout_seconds=ida_timeout_seconds,
        test_mode=TEST_MODE,
    )


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
        build_guest_u007_decompile_corner_case_test_script(
            ida_dir=args.ida_dir,
            dll_path=args.dll_path,
            ida_timeout_seconds=args.ida_timeout_seconds,
        ),
        encoding="utf-8",
    )
    print(f"Wrote U007 /decompile corner-case guest payload: {output_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
