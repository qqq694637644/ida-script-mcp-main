"""IDA Script MCP installer.

This module provides installation commands for:
1. Installing the IDA Pro plugin
2. Configuring MCP clients such as Claude, Cursor, VS Code, Windsurf, and Codex
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

try:
    from .installer_data import (
        AUTO_CREATE_CONFIG_DIRS,
        GLOBAL_SPECIAL_JSON_STRUCTURES,
        PROJECT_LEVEL_CONFIGS,
        PROJECT_SPECIAL_JSON_STRUCTURES,
        get_global_configs,
        get_project_configs,
        resolve_client_name,
    )
except ImportError:  # pragma: no cover - local execution fallback
    from installer_data import (
        AUTO_CREATE_CONFIG_DIRS,
        GLOBAL_SPECIAL_JSON_STRUCTURES,
        PROJECT_LEVEL_CONFIGS,
        PROJECT_SPECIAL_JSON_STRUCTURES,
        get_global_configs,
        get_project_configs,
        resolve_client_name,
    )


MCP_SERVER_NAME = "ida-script-mcp"
PLUGIN_NAME = "ida_script_mcp"
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
IDA_PLUGIN_FILE = os.path.join(SCRIPT_DIR, "ida_plugin.py")
IDA_PLUGIN_SUPPORT_FILES = {
    "protocol.py": "ida_script_mcp_protocol.py",
    "execution.py": "ida_script_mcp_execution.py",
}
SERVER_MODULE = "ida_script_mcp.server"


def get_python_executable() -> str:
    """Get the Python executable path for MCP config."""
    venv = os.environ.get("VIRTUAL_ENV")
    if venv:
        if sys.platform == "win32":
            python = os.path.join(venv, "Scripts", "python.exe")
        else:
            python = os.path.join(venv, "bin", "python3")
        if os.path.exists(python):
            return python
    return sys.executable


def _get_ida_user_dir() -> str:
    """Get the per-user IDA directory."""
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def _remove_path(path: str) -> None:
    """Remove a file or directory if it exists."""
    if not os.path.lexists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def _install_link_or_copy(source: str, destination: str) -> bool:
    """Install by symlink when possible, otherwise copy."""
    existing_realpath = os.path.realpath(destination) if os.path.lexists(destination) else None
    if existing_realpath == source:
        return False

    _remove_path(destination)
    try:
        os.symlink(source, destination)
    except OSError:
        shutil.copy(source, destination)
    return True


def is_ida_plugin_installed() -> bool:
    """Check whether the IDA plugin is installed."""
    ida_folder = _get_ida_user_dir()
    return os.path.lexists(os.path.join(ida_folder, "plugins", f"{PLUGIN_NAME}.py"))


def install_ida_plugin(*, uninstall: bool = False, quiet: bool = False) -> bool:
    """Install or uninstall the IDA Pro plugin."""
    ida_folder = _get_ida_user_dir()

    free_licenses = glob.glob(os.path.join(ida_folder, "idafree_*.hexlic"))
    if free_licenses and not uninstall:
        print("IDA Free does not support plugins. Please use IDA Pro.")
        return False

    ida_plugin_folder = os.path.join(ida_folder, "plugins")
    plugin_destination = os.path.join(ida_plugin_folder, f"{PLUGIN_NAME}.py")
    support_destinations = [
        os.path.join(ida_plugin_folder, destination)
        for destination in IDA_PLUGIN_SUPPORT_FILES.values()
    ]

    if uninstall:
        removed_paths = [
            path
            for path in [plugin_destination, *support_destinations]
            if os.path.lexists(path)
        ]
        for path in removed_paths:
            _remove_path(path)

        if removed_paths:
            if not quiet:
                print("Uninstalled IDA Pro plugin")
                for path in removed_paths:
                    print(f"  Removed: {path}")
        elif not quiet:
            print("IDA plugin not installed, nothing to uninstall")
        return True

    install_files = [(IDA_PLUGIN_FILE, plugin_destination)]
    install_files.extend(
        (
            os.path.join(SCRIPT_DIR, source_filename),
            os.path.join(ida_plugin_folder, destination_filename),
        )
        for source_filename, destination_filename in IDA_PLUGIN_SUPPORT_FILES.items()
    )

    missing_files = [source for source, _ in install_files if not os.path.exists(source)]
    if missing_files:
        for source in missing_files:
            print(f"Error: Plugin file not found: {source}")
        return False

    os.makedirs(ida_plugin_folder, exist_ok=True)

    changed_paths = [
        destination
        for source, destination in install_files
        if _install_link_or_copy(source, destination)
    ]

    if changed_paths:
        if not quiet:
            print("Installed IDA Pro plugin (IDA restart required)")
            print(f"  Plugin: {plugin_destination}")
            for destination in support_destinations:
                print(f"  Support: {destination}")
            print("\n  To enable: Edit -> Plugins -> IDA-Script-MCP (Ctrl+Alt+S)")
    elif not quiet:
        print("IDA plugin already up to date")

    return True


def _read_config_file(config_path: str, *, is_toml: bool = False) -> dict | None:
    """Read a JSON or TOML configuration file."""
    try:
        if is_toml:
            try:
                import tomllib
            except ImportError:  # pragma: no cover - python <3.11 fallback
                import tomli as tomllib
            with open(config_path, "rb") as handle:
                return tomllib.load(handle)

        with open(config_path, "r", encoding="utf-8") as handle:
            data = handle.read().strip()
            return json.loads(data) if data else {}
    except (json.JSONDecodeError, OSError, ValueError):
        return None


def _toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _toml_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, str):
        return f'"{_toml_escape(value)}"'
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if value is None:
        return '""'
    raise TypeError(f"Unsupported TOML value type: {type(value)!r}")


def _dump_toml(config: dict) -> str:
    """Serialize a small nested dict into TOML.

    This is intentionally minimal but sufficient for Codex config files used by
    this project.
    """

    lines: list[str] = []

    def emit_table(table: dict, prefix: str = "") -> None:
        scalar_items = []
        nested_items = []
        for key, value in table.items():
            if isinstance(value, dict):
                nested_items.append((key, value))
            else:
                scalar_items.append((key, value))

        if prefix:
            lines.append(f"[{prefix}]")
        for key, value in scalar_items:
            lines.append(f"{key} = {_toml_value(value)}")
        if prefix and (scalar_items or nested_items):
            lines.append("")

        for key, value in nested_items:
            child_prefix = f"{prefix}.{key}" if prefix else key
            emit_table(value, child_prefix)

    emit_table(config)
    rendered = "\n".join(lines).rstrip() + "\n"
    return rendered


def _write_config_file(config_path: str, config: dict, *, is_toml: bool = False) -> None:
    """Write a JSON or TOML configuration file atomically."""
    config_dir = os.path.dirname(config_path)
    os.makedirs(config_dir, exist_ok=True)

    suffix = ".toml" if is_toml else ".json"
    fd, temp_path = tempfile.mkstemp(dir=config_dir, prefix=".tmp_", suffix=suffix, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            if is_toml:
                try:
                    import tomli_w

                    handle.write(tomli_w.dumps(config))
                except ImportError:
                    handle.write(_dump_toml(config))
            else:
                json.dump(config, handle, indent=2)
        os.replace(temp_path, config_path)
    except Exception:
        os.unlink(temp_path)
        raise


def _get_mcp_servers_view(
    config: dict,
    *,
    client_name: str,
    is_toml: bool,
    special_json_structures: dict[str, tuple[str | None, str]],
) -> dict:
    """Get the nested config object that stores MCP servers."""
    if is_toml:
        return config.setdefault("mcp_servers", {})

    if client_name in special_json_structures:
        top_key, nested_key = special_json_structures[client_name]
        if top_key is None:
            return config.setdefault(nested_key, {})
        return config.setdefault(top_key, {}).setdefault(nested_key, {})

    return config.setdefault("mcpServers", {})


def generate_mcp_config(*, client_name: str) -> dict:
    """Generate the MCP server configuration for a client."""
    _ = client_name
    return {
        "command": get_python_executable(),
        "args": ["-m", SERVER_MODULE],
    }


def list_available_clients() -> None:
    """List all supported MCP clients."""
    configs = get_global_configs()
    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return

    print("Available MCP clients:\n")
    for name, (config_dir, _) in configs.items():
        supports_project = name in PROJECT_LEVEL_CONFIGS
        project_marker = " [supports --project]" if supports_project else ""
        status = "found" if os.path.exists(config_dir) else "not found"
        print(f"  {name:<20} ({status}){project_marker}")

    print()
    print("Examples:")
    print("  ida-script-mcp-install install                    # Install plugin only")
    print("  ida-script-mcp-install install claude             # Install plugin + Claude config")
    print("  ida-script-mcp-install install codex              # Install plugin + Codex config")
    print("  ida-script-mcp-install install claude,codex       # Multiple clients")
    print("  ida-script-mcp-install install --project codex    # Project-level config")
    print("  ida-script-mcp-install uninstall                  # Uninstall plugin")
    print("  ida-script-mcp-install list-clients               # List clients")


def install_mcp_client(
    client_name: str,
    *,
    project: bool = False,
    uninstall: bool = False,
    quiet: bool = False,
) -> bool:
    """Install or uninstall a client configuration."""
    if project:
        configs = get_project_configs(os.getcwd())
        special_json_structures = PROJECT_SPECIAL_JSON_STRUCTURES
    else:
        configs = get_global_configs()
        special_json_structures = GLOBAL_SPECIAL_JSON_STRUCTURES

    if not configs:
        print(f"Unsupported platform: {sys.platform}")
        return False

    resolved_name = resolve_client_name(client_name, list(configs.keys()))
    if not resolved_name:
        print(f"Unknown client: '{client_name}'")
        print("Use --list-clients to see available options")
        return False

    config_dir, config_file = configs[resolved_name]
    config_path = os.path.join(config_dir, config_file)
    is_toml = config_file.endswith(".toml")

    if not os.path.exists(config_dir):
        if uninstall:
            if not quiet:
                print(f"Skipping {resolved_name} uninstall")
                print(f"  Config directory not found: {config_dir}")
            return True
        if project or resolved_name in AUTO_CREATE_CONFIG_DIRS:
            os.makedirs(config_dir, exist_ok=True)
        else:
            if not quiet:
                print(f"Skipping {resolved_name} install")
                print(f"  Config directory not found: {config_dir}")
            return False

    config = {}
    if os.path.exists(config_path):
        config = _read_config_file(config_path, is_toml=is_toml) or {}

    mcp_servers = _get_mcp_servers_view(
        config,
        client_name=resolved_name,
        is_toml=is_toml,
        special_json_structures=special_json_structures,
    )

    if uninstall:
        if MCP_SERVER_NAME not in mcp_servers:
            if not quiet:
                print(f"Skipping {resolved_name} uninstall (not configured)")
            return True
        del mcp_servers[MCP_SERVER_NAME]
        action = "Uninstalled"
    else:
        mcp_servers[MCP_SERVER_NAME] = generate_mcp_config(client_name=resolved_name)
        action = "Installed"

    _write_config_file(config_path, config, is_toml=is_toml)

    if not quiet:
        print(f"{action} {resolved_name} MCP config (restart required)")
        print(f"  Config: {config_path}")

    return True


def print_mcp_config() -> None:
    """Print an example MCP configuration snippet in JSON form."""
    config = {
        "mcpServers": {
            MCP_SERVER_NAME: generate_mcp_config(client_name="Generic"),
        }
    }
    print("[MCP CONFIGURATION]\n")
    print(json.dumps(config, indent=2))
    print("\nFor Codex, put the same server block under the TOML [mcp_servers] table.")


def main() -> None:
    """Main entry point for the installer."""
    parser = argparse.ArgumentParser(
        description="IDA Script MCP Installer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s install                    Install IDA plugin only
  %(prog)s install claude             Install plugin + configure Claude
  %(prog)s install codex              Install plugin + configure Codex
  %(prog)s install claude,codex       Install for multiple clients
  %(prog)s install --project codex    Use project-level config
  %(prog)s uninstall                  Uninstall IDA plugin
  %(prog)s --list-clients             List available MCP clients
  %(prog)s --config                   Show MCP config snippet
        """,
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=["install", "uninstall"],
        default="install",
        help="Action to perform (default: install)",
    )
    parser.add_argument(
        "clients",
        nargs="?",
        type=str,
        default="",
        help="Comma-separated list of MCP clients (for example: claude,codex)",
    )
    parser.add_argument(
        "--project",
        action="store_true",
        help="Use project-level configuration instead of global",
    )
    parser.add_argument(
        "--list-clients",
        action="store_true",
        help="List available MCP clients",
    )
    parser.add_argument(
        "--config",
        action="store_true",
        help="Print an example MCP configuration snippet",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress output",
    )
    args = parser.parse_args()

    if args.list_clients:
        list_available_clients()
        return

    if args.config:
        print_mcp_config()
        return

    uninstall = args.action == "uninstall"

    if not install_ida_plugin(uninstall=uninstall, quiet=args.quiet):
        sys.exit(1)

    if args.clients:
        client_list = [client.strip() for client in args.clients.split(",") if client.strip()]
        for client in client_list:
            install_mcp_client(
                client,
                project=args.project,
                uninstall=uninstall,
                quiet=args.quiet,
            )

    if not args.clients and not args.quiet:
        print()
        print("To configure an MCP client, run:")
        print("  ida-script-mcp-install install <client>")
        print()
        print("Use --list-clients to see available clients")


if __name__ == "__main__":
    main()
