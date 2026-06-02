"""Tests for IDA Script MCP."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# Add src to path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_script_mcp.installer import (
    _dump_toml,
    _get_ida_user_dir,
    generate_mcp_config,
    get_python_executable,
)
from ida_script_mcp.installer_data import get_global_configs, resolve_client_name
from ida_script_mcp.server import (
    DatabaseInfoInput,
    DecompileFunctionInput,
    ExecuteScriptInput,
    GetXrefsInput,
    ListFunctionsInput,
    find_instance_port,
    get_ida_host,
    get_ida_port,
    list_instances,
)


class TestExecuteScriptInput:
    """Tests for ExecuteScriptInput."""

    def test_code_only(self):
        params = ExecuteScriptInput(code="print('hello')")
        assert params.code == "print('hello')"
        assert params.script_path is None
        assert params.capture_output is True

    def test_script_path_only(self):
        params = ExecuteScriptInput(script_path="/path/to/script.py")
        assert params.code is None
        assert params.script_path == "/path/to/script.py"
        assert params.capture_output is True

    def test_both_code_and_path_are_still_representable(self):
        params = ExecuteScriptInput(
            code="print('hello')",
            script_path="/path/to/script.py",
        )
        assert params.code == "print('hello')"
        assert params.script_path == "/path/to/script.py"

    def test_capture_output_false(self):
        params = ExecuteScriptInput(code="print('hello')", capture_output=False)
        assert params.capture_output is False

    def test_whitespace_stripping(self):
        params = ExecuteScriptInput(code="  print('hello')  ")
        assert params.code == "print('hello')"

    def test_instance_id(self):
        params = ExecuteScriptInput(code="print('hello')", instance_id="crackme.exe")
        assert params.instance_id == "crackme.exe"

    def test_port_parameter(self):
        params = ExecuteScriptInput(code="print('hello')", port=13339)
        assert params.port == 13339


class TestReadToolInputs:
    """Smoke tests for the new structured read-only tool inputs."""

    def test_database_info_input(self):
        params = DatabaseInfoInput(instance_id="sample.exe")
        assert params.instance_id == "sample.exe"
        assert params.port is None

    def test_list_functions_input_defaults(self):
        params = ListFunctionsInput()
        assert params.offset == 0
        assert params.limit == 200
        assert params.include_thunks is False
        assert params.include_library_functions is False

    def test_decompile_input(self):
        params = DecompileFunctionInput(address="0x401000", include_disassembly=True)
        assert params.address == "0x401000"
        assert params.include_disassembly is True

    def test_xrefs_input(self):
        params = GetXrefsInput(name="CreateFileW", direction="to", xref_kind="code")
        assert params.name == "CreateFileW"
        assert params.direction == "to"
        assert params.xref_kind == "code"


class TestConfiguration:
    """Tests for configuration helpers."""

    def test_default_host(self):
        os.environ.pop("IDA_SCRIPT_MCP_HOST", None)
        assert get_ida_host() == "127.0.0.1"

    def test_default_port(self):
        os.environ.pop("IDA_SCRIPT_MCP_PORT", None)
        assert get_ida_port() is None

    def test_env_host(self):
        os.environ["IDA_SCRIPT_MCP_HOST"] = "192.168.1.1"
        assert get_ida_host() == "192.168.1.1"
        os.environ.pop("IDA_SCRIPT_MCP_HOST")

    def test_env_port(self):
        os.environ["IDA_SCRIPT_MCP_PORT"] = "8080"
        assert get_ida_port() == 8080
        os.environ.pop("IDA_SCRIPT_MCP_PORT")


class TestListInstances:
    """Tests for list_instances."""

    def test_list_instances_returns_dict(self):
        result = list_instances()
        assert isinstance(result, dict)


class TestInstanceResolution:
    """Tests for resolving an IDA target by instance id only."""

    def test_find_instance_port_exact_instance_id(self, monkeypatch):
        monkeypatch.delenv("IDA_SCRIPT_MCP_PORT", raising=False)
        monkeypatch.delenv("IDA_SCRIPT_MCP_INSTANCE_ID", raising=False)
        monkeypatch.setattr(
            "ida_script_mcp.server.list_instances",
            lambda: {
                "11580_ida64.dll": {"port": 13338, "database": "ida64.dll"},
                "12076_PathOfExileSteam.exe": {"port": 13339, "database": "PathOfExileSteam.exe"},
            },
        )

        port, label = find_instance_port("11580_ida64.dll")

        assert port == 13338
        assert label == "11580_ida64.dll"

    def test_find_instance_port_unique_instance_id_substring(self, monkeypatch):
        monkeypatch.delenv("IDA_SCRIPT_MCP_PORT", raising=False)
        monkeypatch.delenv("IDA_SCRIPT_MCP_INSTANCE_ID", raising=False)
        monkeypatch.setattr(
            "ida_script_mcp.server.list_instances",
            lambda: {
                "11580_ida64.dll": {"port": 13338, "database": "ida64.dll"},
                "12076_PathOfExileSteam.exe": {"port": 13339, "database": "PathOfExileSteam.exe"},
            },
        )

        port, label = find_instance_port("ida64.dll")

        assert port == 13338
        assert label == "11580_ida64.dll"

    def test_find_instance_port_reports_ambiguous_instance_id_substring(self, monkeypatch):
        monkeypatch.delenv("IDA_SCRIPT_MCP_PORT", raising=False)
        monkeypatch.delenv("IDA_SCRIPT_MCP_INSTANCE_ID", raising=False)
        monkeypatch.setattr(
            "ida_script_mcp.server.list_instances",
            lambda: {
                "11580_ida64.dll": {"port": 13338, "database": "ida64.dll"},
                "22000_helper_ida64.dll": {"port": 13339, "database": "helper_ida64.dll"},
            },
        )

        port, label = find_instance_port("ida64.dll")

        assert port is None
        assert "matched multiple instance ids" in label
        assert "11580_ida64.dll" in label
        assert "22000_helper_ida64.dll" in label

    def test_find_instance_port_does_not_match_database_field(self, monkeypatch):
        monkeypatch.delenv("IDA_SCRIPT_MCP_PORT", raising=False)
        monkeypatch.delenv("IDA_SCRIPT_MCP_INSTANCE_ID", raising=False)
        monkeypatch.setattr(
            "ida_script_mcp.server.list_instances",
            lambda: {
                "11580_target.dll": {"port": 13338, "database": "ida64.dll"},
            },
        )

        port, label = find_instance_port("ida64.dll")

        assert port is None
        assert label == "Instance 'ida64.dll' not found."


class TestInstaller:
    """Tests for installer helpers."""

    def test_get_python_executable(self):
        result = get_python_executable()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_get_ida_user_dir(self):
        result = _get_ida_user_dir()
        assert isinstance(result, str)
        if sys.platform == "win32":
            assert "Hex-Rays" in result or "IDA Pro" in result
        else:
            assert ".idapro" in result

    def test_generate_mcp_config(self):
        result = generate_mcp_config(client_name="Claude")
        assert "command" in result
        assert "args" in result
        assert result["args"] == ["-m", "ida_script_mcp.server"]

    def test_codex_is_supported_globally(self):
        clients = get_global_configs()
        assert "Codex" in clients
        config_dir, config_file = clients["Codex"]
        assert config_file == "config.toml"
        assert Path(config_dir).name == ".codex"

    def test_resolve_codex_alias(self):
        resolved = resolve_client_name("codex", ["Claude", "Codex", "Cursor"])
        assert resolved == "Codex"

    def test_dump_toml_for_codex(self):
        config = {
            "mcp_servers": {
                "ida-script-mcp": {
                    "command": "/usr/bin/python3",
                    "args": ["-m", "ida_script_mcp.server"],
                }
            }
        }
        rendered = _dump_toml(config)
        assert "[mcp_servers.ida-script-mcp]" in rendered
        assert 'command = "/usr/bin/python3"' in rendered
        assert 'args = ["-m", "ida_script_mcp.server"]' in rendered
