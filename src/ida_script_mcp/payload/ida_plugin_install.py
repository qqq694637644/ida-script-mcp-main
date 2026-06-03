"""Build guest-side IDA plugin installation verification payloads."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from textwrap import dedent

DEFAULT_GUEST_IDA_DIR = r"C:\Users\alion\Desktop\IDAPro8.3"
PLUGIN_INSTALL_FILES = {
    "ida_plugin.py": "ida_script_mcp.py",
    "protocol.py": "ida_script_mcp_support/protocol.py",
    "execution.py": "ida_script_mcp_support/execution.py",
    "change_protocol.py": "ida_script_mcp_support/change_protocol.py",
    "change_recorder.py": "ida_script_mcp_support/change_recorder.py",
}
SUPPORT_PACKAGE_INIT = b'"""Support modules for the IDA Script MCP plugin."""\n'
LEGACY_ROOT_SUPPORT_FILES = (
    "ida_script_mcp_protocol.py",
    "ida_script_mcp_execution.py",
    "ida_script_mcp_change_protocol.py",
    "ida_script_mcp_change_recorder.py",
)
IDA_EXECUTABLE_CANDIDATES = ("ida.exe", "ida64.exe", "idat.exe", "idat64.exe")


def _package_source_dir(source_root: Path | None = None) -> Path:
    if source_root is not None:
        return source_root
    return Path(__file__).resolve().parents[1]


def _read_install_files(source_root: Path | None = None) -> dict[str, bytes]:
    package_dir = _package_source_dir(source_root)
    payload: dict[str, bytes] = {}
    missing: list[str] = []
    for source_name, destination_name in PLUGIN_INSTALL_FILES.items():
        source_path = package_dir / source_name
        if not source_path.is_file():
            missing.append(str(source_path))
            continue
        payload[destination_name] = source_path.read_bytes()
    if missing:
        raise FileNotFoundError("Missing IDA plugin install source files: " + ", ".join(missing))
    payload["ida_script_mcp_support/__init__.py"] = SUPPORT_PACKAGE_INIT
    return payload


def build_guest_ida_plugin_install_script(
    *,
    ida_dir: str = DEFAULT_GUEST_IDA_DIR,
    source_root: Path | None = None,
) -> str:
    """Build a standalone guest-side script that installs and verifies the plugin."""

    install_files = _read_install_files(source_root)
    files_b64 = {
        destination: base64.b64encode(content).decode("ascii")
        for destination, content in sorted(install_files.items())
    }
    expected_sha256 = {
        destination: hashlib.sha256(content).hexdigest()
        for destination, content in sorted(install_files.items())
    }

    return dedent(
        f"""
        from __future__ import annotations

        import base64
        import hashlib
        import importlib.util
        import json
        import os
        import py_compile
        import sys
        import traceback
        from pathlib import Path

        IDA_DIR = {ida_dir!r}
        IDA_EXECUTABLE_CANDIDATES = {list(IDA_EXECUTABLE_CANDIDATES)!r}
        LEGACY_ROOT_SUPPORT_FILES = {list(LEGACY_ROOT_SUPPORT_FILES)!r}
        FILES_B64 = {json.dumps(files_b64, ensure_ascii=False, indent=2)!r}
        EXPECTED_SHA256 = {json.dumps(expected_sha256, ensure_ascii=False, indent=2)!r}


        def _decode_json(text: str) -> dict[str, str]:
            return json.loads(text)


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


        def _load_module_from_path(name: str, path: Path):
            spec = importlib.util.spec_from_file_location(name, str(path))
            if spec is None or spec.loader is None:
                raise RuntimeError(f"Cannot create import spec for {{path}}")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module


        def main() -> int:
            files_b64 = _decode_json(FILES_B64)
            expected_sha256 = _decode_json(EXPECTED_SHA256)
            ida_dir = Path(IDA_DIR)
            if not ida_dir.is_dir():
                raise RuntimeError(f"IDA directory does not exist: {{ida_dir}}")

            ida_executables = [
                str(ida_dir / candidate)
                for candidate in IDA_EXECUTABLE_CANDIDATES
                if (ida_dir / candidate).is_file()
            ]
            if not ida_executables:
                raise RuntimeError(
                    "IDA directory exists but no expected executable was found: "
                    + ", ".join(IDA_EXECUTABLE_CANDIDATES)
                )

            ida_user_dir = _ida_user_dir()
            plugin_dir = ida_user_dir / "plugins"
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
            if remaining_legacy_support_files:
                raise RuntimeError(
                    "Legacy root support files remain in IDA plugins directory: "
                    + ", ".join(remaining_legacy_support_files)
                )

            installed: dict[str, dict[str, object]] = {{}}
            for destination, encoded in files_b64.items():
                path = plugin_dir / destination
                content = base64.b64decode(encoded.encode("ascii"))
                _write_bytes_atomic(path, content)
                digest = _sha256(path)
                if digest != expected_sha256[destination]:
                    raise RuntimeError(f"SHA-256 mismatch for {{path}}")
                py_compile.compile(str(path), doraise=True)
                installed[destination] = {{
                    "path": str(path),
                    "size_bytes": path.stat().st_size,
                    "sha256": digest,
                }}

            support_modules = [
                "ida_script_mcp_support.protocol",
                "ida_script_mcp_support.execution",
                "ida_script_mcp_support.change_protocol",
                "ida_script_mcp_support.change_recorder",
            ]
            sys.path.insert(0, str(plugin_dir))
            imported_support = []
            for module_name in support_modules:
                __import__(module_name)
                imported_support.append(module_name)

            plugin_module = _load_module_from_path(
                "ida_script_mcp_plugin_install_verify",
                plugin_dir / "ida_script_mcp.py",
            )
            plugin_name = getattr(plugin_module, "PLUGIN_NAME", None)
            if plugin_name != "IDA-Script-MCP":
                raise RuntimeError(f"Unexpected plugin name: {{plugin_name!r}}")

            manifest = {{
                "status": "installed",
                "ida_dir": str(ida_dir),
                "ida_executables": ida_executables,
                "ida_user_dir": str(ida_user_dir),
                "plugin_dir": str(plugin_dir),
                "installed": installed,
                "imported_support": imported_support,
                "removed_legacy_support_files": removed_legacy_support_files,
                "remaining_legacy_support_files": remaining_legacy_support_files,
                "plugin_name": plugin_name,
                "plugin_has_ida_runtime": bool(getattr(plugin_module, "HAS_IDA", False)),
            }}
            manifest_path = plugin_dir / "ida_script_mcp_install_manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            manifest["manifest_path"] = str(manifest_path)
            result_json = json.dumps(manifest, ensure_ascii=False, sort_keys=True)
            print("IDA_PLUGIN_INSTALL_VERIFY_RESULT=" + result_json)
            return 0


        if __name__ == "__main__":
            try:
                raise SystemExit(main())
            except Exception as exc:
                print(
                    "IDA_PLUGIN_INSTALL_VERIFY_ERROR="
                    + json.dumps(
                        {{
                            "type": type(exc).__name__,
                            "message": str(exc),
                            "traceback": traceback.format_exc(),
                        }},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    file=sys.stderr,
                )
                raise SystemExit(1)
        """
    ).lstrip()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ida-dir", default=DEFAULT_GUEST_IDA_DIR)
    parser.add_argument("--output", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        build_guest_ida_plugin_install_script(ida_dir=args.ida_dir),
        encoding="utf-8",
    )
    print(f"Wrote guest IDA plugin install payload: {output_path}")


if __name__ == "__main__":  # pragma: no cover
    main()
