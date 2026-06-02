"""Installer data for supported MCP clients."""

from __future__ import annotations

import os
import sys


CLIENT_ALIASES: dict[str, str] = {
    "vscode": "VS Code",
    "vs-code": "VS Code",
    "claude-desktop": "Claude",
    "claude-app": "Claude",
    "claude-code": "Claude Code",
    "cursor": "Cursor",
    "codex": "Codex",
    "codex-cli": "Codex",
    "openai-codex": "Codex",
}

PROJECT_LEVEL_CONFIGS: dict[str, tuple[str, str]] = {
    "Claude Code": ("", ".mcp.json"),
    "Cursor": (".cursor", "mcp.json"),
    "VS Code": (".vscode", "mcp.json"),
    "Windsurf": (".windsurf", "mcp_config.json"),
    "Codex": (".codex", "config.toml"),
}

PROJECT_SPECIAL_JSON_STRUCTURES: dict[str, tuple[str | None, str]] = {
    "VS Code": (None, "servers"),
}

GLOBAL_SPECIAL_JSON_STRUCTURES: dict[str, tuple[str | None, str]] = {
    "VS Code": ("mcp", "servers"),
}

AUTO_CREATE_CONFIG_DIRS: set[str] = {"Codex"}


def get_global_configs() -> dict[str, tuple[str, str]]:
    """Get global MCP client configuration paths for the current platform."""
    home = os.path.expanduser("~")

    if sys.platform == "win32":
        return {
            "Claude": (
                os.path.join(os.getenv("APPDATA", ""), "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (
                os.path.join(home, ".cursor"),
                "mcp.json",
            ),
            "Claude Code": (
                home,
                ".claude.json",
            ),
            "VS Code": (
                os.path.join(os.getenv("APPDATA", ""), "Code", "User"),
                "settings.json",
            ),
            "Windsurf": (
                os.path.join(home, ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Codex": (
                os.path.join(home, ".codex"),
                "config.toml",
            ),
        }

    if sys.platform == "darwin":
        return {
            "Claude": (
                os.path.join(home, "Library", "Application Support", "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (
                os.path.join(home, ".cursor"),
                "mcp.json",
            ),
            "Claude Code": (
                home,
                ".claude.json",
            ),
            "VS Code": (
                os.path.join(home, "Library", "Application Support", "Code", "User"),
                "settings.json",
            ),
            "Windsurf": (
                os.path.join(home, ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Codex": (
                os.path.join(home, ".codex"),
                "config.toml",
            ),
        }

    if sys.platform == "linux":
        return {
            "Claude": (
                os.path.join(home, ".config", "Claude"),
                "claude_desktop_config.json",
            ),
            "Cursor": (
                os.path.join(home, ".cursor"),
                "mcp.json",
            ),
            "Claude Code": (
                home,
                ".claude.json",
            ),
            "VS Code": (
                os.path.join(home, ".config", "Code", "User"),
                "settings.json",
            ),
            "Windsurf": (
                os.path.join(home, ".codeium", "windsurf"),
                "mcp_config.json",
            ),
            "Codex": (
                os.path.join(home, ".codex"),
                "config.toml",
            ),
        }

    return {}


def get_project_configs(project_dir: str) -> dict[str, tuple[str, str]]:
    """Get project-level MCP client configuration paths."""
    result = {}
    for name, (subdir, config_file) in PROJECT_LEVEL_CONFIGS.items():
        config_dir = os.path.join(project_dir, subdir) if subdir else project_dir
        result[name] = (config_dir, config_file)
    return result


def resolve_client_name(input_name: str, available_clients: list[str]) -> str | None:
    """Resolve a client name from an alias or partial match."""
    lower_input = input_name.strip().lower()

    for client in available_clients:
        if client.lower() == lower_input:
            return client

    if lower_input in CLIENT_ALIASES:
        alias_target = CLIENT_ALIASES[lower_input]
        if alias_target in available_clients:
            return alias_target

    matches = [client for client in available_clients if lower_input in client.lower()]
    if len(matches) == 1:
        return matches[0]

    return None
