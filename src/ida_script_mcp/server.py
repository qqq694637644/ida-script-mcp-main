"""IDA Script MCP Server.

This MCP server connects to one or more running IDA Pro instances through the
local IDA-Script-MCP plugin and exposes a small, high-signal tool surface:

- ``list_ida_instances``
- ``get_ida_database_info``
- ``list_functions``
- ``decompile_function``
- ``get_xrefs``
- ``execute_idapython``

The design intentionally keeps common reverse-engineering reads as dedicated
read-only tools while running public ``execute_idapython`` through an isolated
IDA worker process.
"""

from __future__ import annotations

import argparse
import http.client
import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

try:
    from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
except Exception:  # pragma: no cover - exercised by guest payloads without pydantic.
    StrictBool = bool  # type: ignore[assignment]

    def ConfigDict(**kwargs: Any) -> dict[str, Any]:  # noqa: N802  # type: ignore[no-redef]
        return dict(kwargs)

    def Field(default: Any = None, **_kwargs: Any) -> Any:  # noqa: N802  # type: ignore[no-redef]
        return default

    def model_validator(*_args: Any, **_kwargs: Any):  # type: ignore[no-redef]
        def decorator(func):
            return func

        return decorator

    class BaseModel:  # type: ignore[no-redef]
        """Tiny fallback used only for importing server helpers in guest payloads."""

        def __init__(self, **kwargs: Any):
            annotations: dict[str, Any] = {}
            for cls in reversed(type(self).__mro__):
                annotations.update(getattr(cls, "__annotations__", {}))
            for name in annotations:
                if name == "model_config":
                    continue
                if name in kwargs:
                    setattr(self, name, kwargs.pop(name))
                elif hasattr(type(self), name):
                    setattr(self, name, getattr(type(self), name))
            if kwargs:
                raise ValueError(f"{type(self).__name__} forbids extra fields: {sorted(kwargs)!r}")

        @classmethod
        def model_validate(cls, data: Any):
            if isinstance(data, cls):
                return data
            if not isinstance(data, dict):
                raise ValueError(f"{cls.__name__} requires a dict")
            return cls(**data)

        def model_dump(self, mode: str = "json", exclude: set[str] | None = None) -> dict[str, Any]:
            exclude = exclude or set()
            annotations: dict[str, Any] = {}
            for cls in reversed(type(self).__mro__):
                annotations.update(getattr(cls, "__annotations__", {}))
            return {
                name: getattr(self, name)
                for name in annotations
                if name != "model_config" and name not in exclude and hasattr(self, name)
            }

from .change_protocol import ApplyChangesRequest
from .isolated_manager import IsolatedExecutionManager
from .protocol import (
    DEFAULT_EXECUTE_TIMEOUT_SECONDS,
    MAX_EXECUTE_TIMEOUT_SECONDS,
    ExecuteRequest,
    ExecuteResult,
    ExecutionError,
)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - fallback for local tests without mcp installed

    class FastMCP:  # type: ignore[override]
        """Tiny fallback shim so the module remains importable in test environments."""

        def __init__(self, *_args: Any, **_kwargs: Any):
            self._tools: dict[str, Any] = {}

        def tool(self, name: str | None = None, **_kwargs: Any):
            def decorator(func):
                self._tools[name or func.__name__] = func
                return func

            return decorator

        def run(self, *_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError(
                "The 'mcp' package is required to run the MCP server. "
                "Install project dependencies first."
            )


logging.getLogger("mcp").setLevel(logging.WARNING)

mcp = FastMCP("ida_script_mcp")

INSTANCE_INFO_FILE = Path.home() / ".ida_script_mcp_instances.json"
DEFAULT_IDA_HOST = "127.0.0.1"
DEFAULT_ERROR_HINT = (
    "Make sure IDA Pro is running with the IDA-Script-MCP plugin started. "
    "In IDA, use Edit -> Plugins -> IDA-Script-MCP (Ctrl+Alt+S)."
)


class IdaPluginResponseTimeout(RuntimeError):  # noqa: N818
    """Raised when the IDA plugin does not return an HTTP response in time."""

    def __init__(self, host: str, port: int, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout
        super().__init__(f"IDA plugin at {host}:{port} did not respond within {timeout:g} seconds")


class InstanceTargetInput(BaseModel):
    """Common target selector for tools that operate on a specific IDA instance."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    instance_id: str | None = Field(
        default=None,
        description=(
            "Target IDA instance ID. Use the full instance id from list_ida_instances, "
            "or a unique substring of that instance id such as a database filename."
        ),
    )
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description=(
            "Target IDA instance port. If provided, it takes precedence over instance_id."
        ),
    )


class DatabaseInfoInput(InstanceTargetInput):
    """Input for get_ida_database_info."""


class ListFunctionsInput(InstanceTargetInput):
    """Input for list_functions."""

    offset: int = Field(
        default=0,
        ge=0,
        description="Number of matching functions to skip before returning results.",
    )
    limit: int = Field(
        default=200,
        ge=1,
        le=5000,
        description="Maximum number of functions to return.",
    )
    name_contains: str | None = Field(
        default=None,
        description="Optional case-insensitive substring filter for function names.",
    )
    segment: str | None = Field(
        default=None,
        description="Optional segment name filter, for example '.text' or '__text'.",
    )
    include_thunks: bool = Field(
        default=False,
        description="Whether to include thunk functions.",
    )
    include_library_functions: bool = Field(
        default=False,
        description="Whether to include functions flagged by IDA as library functions.",
    )


class DecompileFunctionInput(InstanceTargetInput):
    """Input for decompile_function."""

    address: str | None = Field(
        default=None,
        description=(
            "Function address like '0x401000'. Provide either address or name. "
            "The address may be the function start or any address inside the function."
        ),
    )
    name: str | None = Field(
        default=None,
        description="Function name like 'main'. Provide either address or name.",
    )
    include_disassembly: bool = Field(
        default=False,
        description=(
            "Whether to include per-instruction disassembly lines. Keep this false unless "
            "you need the raw assembly in addition to pseudocode."
        ),
    )


class GetXrefsInput(InstanceTargetInput):
    """Input for get_xrefs."""

    address: str | None = Field(
        default=None,
        description="Target address like '0x401000'. Provide either address or name.",
    )
    name: str | None = Field(
        default=None,
        description="Target symbol or function name. Provide either address or name.",
    )
    direction: Literal["to", "from"] = Field(
        default="to",
        description="Whether to return xrefs to the target or from the target.",
    )
    xref_kind: Literal["all", "code", "data", "flow"] = Field(
        default="all",
        description="Filter xrefs by kind.",
    )
    limit: int = Field(
        default=200,
        ge=0,
        le=5000,
        description="Maximum number of cross references to return.",
    )


class ExecuteScriptInput(InstanceTargetInput):
    """Input for execute_idapython."""

    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra="forbid",
        strict=True,
    )

    code: str | None = Field(
        default=None,
        description=(
            "Python code to execute inside IDA. Provide either code or script_path. "
            "For multi-line code, send a single string with embedded newlines."
        ),
    )
    script_path: str | None = Field(
        default=None,
        description=(
            "Path to a Python script file to execute inside IDA. Provide either code or "
            "script_path."
        ),
    )
    capture_output: StrictBool = Field(
        default=True,
        description="Whether to capture stdout and stderr from script execution.",
    )
    timeout_seconds: int = Field(
        default=DEFAULT_EXECUTE_TIMEOUT_SECONDS,
        ge=1,
        le=MAX_EXECUTE_TIMEOUT_SECONDS,
        description="Hard timeout for the isolated IDA worker process.",
    )
    collect_changes: StrictBool = Field(
        default=True,
        description="Whether the isolated worker records structured GUI replay changes.",
    )

    @model_validator(mode="after")
    def validate_execute_request(self) -> ExecuteScriptInput:
        self.to_execute_request()
        return self

    def to_execute_request(self) -> ExecuteRequest:
        """Convert MCP input into the shared strict plugin request model."""
        return ExecuteRequest.model_validate(
            {
                "code": self.code,
                "script_path": self.script_path,
                "capture_output": self.capture_output,
                "timeout_seconds": self.timeout_seconds,
            }
        )


def get_ida_host() -> str:
    """Get IDA plugin host from environment or default."""
    return os.environ.get("IDA_SCRIPT_MCP_HOST", DEFAULT_IDA_HOST)


def get_ida_port() -> int | None:
    """Get IDA plugin port from environment."""
    port = os.environ.get("IDA_SCRIPT_MCP_PORT")
    return int(port) if port else None


def get_ida_instance_id() -> str | None:
    """Get IDA instance id from environment."""
    return os.environ.get("IDA_SCRIPT_MCP_INSTANCE_ID")


def is_process_alive(pid: int) -> bool:
    """Check if a process with the given PID is alive."""
    import sys

    if sys.platform == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            process_query_limited_information = 0x1000
            still_active = 259

            handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
            if handle:
                try:
                    exit_code = ctypes.c_ulong()
                    if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                        return exit_code.value == still_active
                finally:
                    kernel32.CloseHandle(handle)
        except Exception:
            pass
        return False

    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def list_instances() -> dict[str, dict[str, Any]]:
    """List all registered live IDA instances."""
    try:
        if not INSTANCE_INFO_FILE.exists():
            return {}
        with open(INSTANCE_INFO_FILE, encoding="utf-8") as handle:
            instances = json.load(handle)
    except Exception:
        return {}

    alive_instances: dict[str, dict[str, Any]] = {}
    for instance_id, info in instances.items():
        pid = info.get("pid")
        if pid and is_process_alive(pid):
            alive_instances[instance_id] = info

    return alive_instances


def _sorted_instance_records(instances: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for instance_id, info in instances.items():
        record = {
            "instance_id": instance_id,
            "pid": info.get("pid"),
            "host": info.get("host"),
            "port": info.get("port"),
            "database": info.get("database"),
            "database_path": info.get("database_path"),
            "platform": info.get("platform"),
            "started_at": info.get("started_at"),
        }
        records.append(record)

    records.sort(
        key=lambda item: (
            str(item.get("database") or ""),
            int(item.get("port") or 0),
            item["instance_id"],
        )
    )
    return records


def _lookup_instance_id_by_port(port: int) -> str | None:
    for instance_id, info in list_instances().items():
        if info.get("port") == port:
            return instance_id
    return None


def find_instance_port(instance_id: str | None = None) -> tuple[int | None, str]:
    """Resolve an IDA instance id to a port.

    Returns:
        Tuple of (port, label_or_error_message).
    """
    env_port = get_ida_port()
    env_instance_id = get_ida_instance_id() or instance_id

    if env_port:
        matched_instance_id = _lookup_instance_id_by_port(env_port)
        return env_port, matched_instance_id or f"port:{env_port}"

    instances = list_instances()
    if not instances:
        return None, "No IDA instances found. Start IDA Pro and enable the plugin."

    if env_instance_id:
        if env_instance_id in instances:
            info = instances[env_instance_id]
            return info.get("port"), env_instance_id

        matches = [
            (current_id, info)
            for current_id, info in instances.items()
            if env_instance_id in current_id
        ]

        if len(matches) == 1:
            current_id, info = matches[0]
            return info.get("port"), current_id

        if len(matches) > 1:
            match_list = [
                f"- {current_id}: {info.get('database', 'unknown')} (port {info.get('port')})"
                for current_id, info in sorted(matches, key=lambda item: item[0])
            ]
            return None, (
                f"Instance selector '{env_instance_id}' matched multiple instance ids.\n"
                + "\n".join(match_list)
            )

        return None, f"Instance '{env_instance_id}' not found."

    if len(instances) == 1:
        current_id, info = next(iter(instances.items()))
        return info.get("port"), current_id

    instance_list = [
        (
            f"- {record['instance_id']}: {record.get('database', 'unknown')} "
            f"(port {record.get('port')})"
        )
        for record in _sorted_instance_records(instances)
    ]
    return None, (
        "Multiple IDA instances found. Specify instance_id or port.\n" + "\n".join(instance_list)
    )


def resolve_target(
    params: InstanceTargetInput | None = None,
    *,
    instance_id: str | None = None,
    port: int | None = None,
) -> tuple[int | None, str | None, str]:
    """Resolve a target selection to a port and instance id when possible."""
    selected_port = port if port is not None else (params.port if params else None)
    selected_instance_id = (
        instance_id if instance_id is not None else (params.instance_id if params else None)
    )

    if selected_port is not None:
        matched_instance_id = _lookup_instance_id_by_port(selected_port)
        label = matched_instance_id or f"port:{selected_port}"
        return selected_port, matched_instance_id, label

    resolved_port, label = find_instance_port(selected_instance_id)
    resolved_instance_id = None if label.startswith("port:") else label
    return resolved_port, resolved_instance_id, label


def make_ida_request(
    endpoint: str,
    *,
    method: str = "GET",
    data: dict[str, Any] | None = None,
    host: str | None = None,
    port: int | None = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Make an HTTP request to the IDA plugin."""
    effective_host = host or get_ida_host()
    effective_port = port
    if effective_port is None:
        effective_port, _, label = resolve_target()
        if effective_port is None:
            raise RuntimeError(label)

    conn = http.client.HTTPConnection(effective_host, effective_port, timeout=timeout)
    try:
        headers = {"Content-Type": "application/json"}
        body = json.dumps(data) if data is not None else None

        conn.request(method, endpoint, body, headers)
        response = conn.getresponse()
        raw_data = response.read().decode("utf-8")

        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {raw_data}")

        if not raw_data:
            return {}
        return json.loads(raw_data)
    except TimeoutError as exc:
        raise IdaPluginResponseTimeout(effective_host, effective_port, timeout) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Failed to connect to IDA plugin at {effective_host}:{effective_port}: {exc}"
        ) from exc
    finally:
        conn.close()


def _tool_error(
    message: str,
    *,
    hint: str | None = None,
    instance_id: str | None = None,
    port: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": message}
    if hint:
        payload["hint"] = hint
    if instance_id is not None:
        payload["instance_id"] = instance_id
    if port is not None:
        payload["port"] = port
    return payload


@mcp.tool(
    name="list_ida_instances",
    annotations={
        "title": "List IDA Instances",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def list_ida_instances() -> dict[str, Any]:
    """List all running IDA instances with the IDA-Script-MCP plugin enabled.

    Examples:
        - Use this first when more than one IDA instance may be running.
        - The returned ``instance_id`` values can be passed to all other tools.
    """
    instances = list_instances()
    records = _sorted_instance_records(instances)

    if not records:
        return {
            "count": 0,
            "instances": [],
            "hint": "No IDA instances found. Start IDA Pro and enable the IDA-Script-MCP plugin.",
        }

    return {
        "count": len(records),
        "instances": records,
    }


@mcp.tool(
    name="get_ida_database_info",
    annotations={
        "title": "Get IDA Database Information",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def get_ida_database_info(params: DatabaseInfoInput) -> dict[str, Any]:
    """Return metadata for the selected IDA database.

    Examples:
        - ``get_ida_database_info({})`` uses the default or only running instance.
        - ``get_ida_database_info({"instance_id": "firmware.bin"})`` targets a specific database.
        - ``get_ida_database_info({"port": 13339})`` targets a specific plugin port.
    """
    port, resolved_instance_id, label = resolve_target(params)
    if port is None:
        return _tool_error(label, hint=DEFAULT_ERROR_HINT)

    try:
        result = make_ida_request("/metadata", port=port, timeout=10.0)
        result.setdefault("instance_id", resolved_instance_id)
        result.setdefault("port", port)
        return result
    except Exception as exc:
        return _tool_error(
            str(exc), hint=DEFAULT_ERROR_HINT, instance_id=resolved_instance_id, port=port
        )


@mcp.tool(
    name="list_functions",
    annotations={
        "title": "List Functions",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def list_functions(params: ListFunctionsInput) -> dict[str, Any]:
    """List functions from the selected IDA database.

    Examples:
        - ``list_functions({"limit": 50})`` returns the first 50 non-library, non-thunk functions.
        - ``list_functions({"name_contains": "decrypt"})`` filters by function name.
        - ``list_functions({"segment": ".text", "include_thunks": true})`` narrows the result set.
    """
    port, resolved_instance_id, label = resolve_target(params)
    if port is None:
        return _tool_error(label, hint=DEFAULT_ERROR_HINT)

    try:
        payload = {
            "offset": params.offset,
            "limit": params.limit,
            "name_contains": params.name_contains,
            "segment": params.segment,
            "include_thunks": params.include_thunks,
            "include_library_functions": params.include_library_functions,
        }
        result = make_ida_request("/functions", method="POST", data=payload, port=port)
        result.setdefault("instance_id", resolved_instance_id)
        result.setdefault("port", port)
        return result
    except Exception as exc:
        return _tool_error(
            str(exc), hint=DEFAULT_ERROR_HINT, instance_id=resolved_instance_id, port=port
        )


@mcp.tool(
    name="decompile_function",
    annotations={
        "title": "Decompile Function",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def decompile_function(params: DecompileFunctionInput) -> dict[str, Any]:
    """Decompile a function by address or name.

    Examples:
        - ``decompile_function({"address": "0x401000"})`` decompiles the function
          containing 0x401000.
        - ``decompile_function({"name": "main"})`` decompiles the function named ``main``.
        - ``decompile_function({"address": "0x401000", "include_disassembly": true})``
          also returns assembly.
    """
    if not params.address and not params.name:
        return _tool_error("Provide either 'address' or 'name'.")
    if params.address and params.name:
        return _tool_error("Provide only one of 'address' or 'name' for decompile_function.")

    port, resolved_instance_id, label = resolve_target(params)
    if port is None:
        return _tool_error(label, hint=DEFAULT_ERROR_HINT)

    try:
        payload = {
            "address": params.address,
            "name": params.name,
            "include_disassembly": params.include_disassembly,
        }
        result = make_ida_request("/decompile", method="POST", data=payload, port=port)
        result.setdefault("instance_id", resolved_instance_id)
        result.setdefault("port", port)
        return result
    except Exception as exc:
        return _tool_error(
            str(exc), hint=DEFAULT_ERROR_HINT, instance_id=resolved_instance_id, port=port
        )


@mcp.tool(
    name="get_xrefs",
    annotations={
        "title": "Get Cross References",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": True,
    },
)
async def get_xrefs(params: GetXrefsInput) -> dict[str, Any]:
    """Return cross references to or from an address or symbol.

    Examples:
        - ``get_xrefs({"address": "0x401000"})`` returns xrefs to 0x401000.
        - ``get_xrefs({"name": "CreateFileW", "direction": "to"})`` finds callers
          and data refs to a symbol.
        - ``get_xrefs({"address": "0x401000", "direction": "from", "xref_kind": "code"})``
          returns outgoing code refs.
        - ``get_xrefs({"address": "0x401000", "direction": "from", "xref_kind": "flow"})``
          returns ordinary-flow refs only.
    """
    if not params.address and not params.name:
        return _tool_error("Provide either 'address' or 'name'.")
    if params.address and params.name:
        return _tool_error("Provide only one of 'address' or 'name' for get_xrefs.")

    port, resolved_instance_id, label = resolve_target(params)
    if port is None:
        return _tool_error(label, hint=DEFAULT_ERROR_HINT)

    try:
        payload = {
            "address": params.address,
            "name": params.name,
            "direction": params.direction,
            "xref_kind": params.xref_kind,
            "limit": params.limit,
        }
        result = make_ida_request("/xrefs", method="POST", data=payload, port=port)
        result.setdefault("instance_id", resolved_instance_id)
        result.setdefault("port", port)
        return result
    except Exception as exc:
        return _tool_error(
            str(exc), hint=DEFAULT_ERROR_HINT, instance_id=resolved_instance_id, port=port
        )


@mcp.tool(
    name="execute_idapython",
    annotations={
        "title": "Execute IDAPython",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": True,
    },
)
async def execute_idapython(params: ExecuteScriptInput) -> dict[str, Any]:
    """Execute Python code in an isolated IDA worker process.

    Public execution never falls back to the GUI ``/execute`` endpoint. The GUI
    plugin is queried only for safe metadata such as the current saved database
    path and dirty state.
    """
    port, resolved_instance_id, label = resolve_target(params)
    if port is None:
        return _tool_error(label, hint=DEFAULT_ERROR_HINT)

    execute_request = params.to_execute_request()
    try:
        gui_context = make_ida_request("/metadata", method="GET", port=port, timeout=10.0)
    except Exception as exc:
        return ExecuteResult(
            status="source_error",
            result=None,
            stdout="",
            stderr="",
            error=ExecutionError(type=type(exc).__name__, message=str(exc), traceback=None),
            timeout_seconds=execute_request.timeout_seconds,
            instance_id=resolved_instance_id,
            port=port,
            isolated=True,
        ).model_dump(mode="json")

    manager = IsolatedExecutionManager()
    result = manager.execute(
        execute_request,
        gui_context=gui_context,
        instance_id=resolved_instance_id,
        port=port,
        collect_changes=params.collect_changes,
    )
    return result.model_dump(mode="json")


class ApplyWorkerChangesInput(ApplyChangesRequest):
    """Input for apply_worker_changes; dry_run defaults to true."""

    instance_id: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)


@mcp.tool(
    name="apply_worker_changes",
    annotations={
        "title": "Apply Worker Changes",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
)
async def apply_worker_changes(params: ApplyWorkerChangesInput) -> dict[str, Any]:
    """Preview or apply a worker ChangeSet through the GUI plugin."""
    port, resolved_instance_id, label = resolve_target(params)
    if port is None:
        return _tool_error(label, hint=DEFAULT_ERROR_HINT)
    try:
        result = make_ida_request(
            "/apply_changes",
            method="POST",
            data=params.model_dump(mode="json", exclude={"instance_id", "port"}),
            port=port,
            timeout=30.0,
        )
        result.setdefault("instance_id", resolved_instance_id)
        result.setdefault("port", port)
        return result
    except Exception as exc:
        return _tool_error(
            str(exc), hint=DEFAULT_ERROR_HINT, instance_id=resolved_instance_id, port=port
        )


def main() -> None:
    """Main entry point for the MCP server."""
    parser = argparse.ArgumentParser(description="IDA Script MCP Server")
    parser.add_argument(
        "--ida-host",
        type=str,
        default=None,
        help="IDA plugin host (default: 127.0.0.1, env: IDA_SCRIPT_MCP_HOST)",
    )
    parser.add_argument(
        "--ida-port",
        type=int,
        default=None,
        help="IDA plugin port (default: auto-detect, env: IDA_SCRIPT_MCP_PORT)",
    )
    parser.add_argument(
        "--ida-instance",
        type=str,
        default=None,
        help="IDA instance id to connect to (env: IDA_SCRIPT_MCP_INSTANCE_ID)",
    )
    parser.add_argument(
        "--transport",
        type=str,
        default="stdio",
        choices=["stdio", "http"],
        help="MCP transport: 'stdio' (default) or 'http'",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for HTTP transport (default: 8765)",
    )
    args = parser.parse_args()

    if args.ida_host:
        os.environ["IDA_SCRIPT_MCP_HOST"] = args.ida_host
    if args.ida_port:
        os.environ["IDA_SCRIPT_MCP_PORT"] = str(args.ida_port)
    if args.ida_instance:
        os.environ["IDA_SCRIPT_MCP_INSTANCE_ID"] = args.ida_instance

    if args.transport == "stdio":
        mcp.run()
    else:
        settings = getattr(mcp, "settings", None)
        if settings is not None and hasattr(settings, "port"):
            settings.port = args.port
        try:
            mcp.run(transport="sse", port=args.port)
        except TypeError:
            mcp.run(transport="sse")


if __name__ == "__main__":
    main()
