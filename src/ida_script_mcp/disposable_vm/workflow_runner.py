"""GitHub Actions entrypoint for disposable VM smoke tests.

The workflow should call this Python file instead of embedding branching logic in
PowerShell. Each IDA test still lives in its own payload script/builder; this
runner only parses workflow inputs, writes the selected payload file, and starts
the host controller.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

if __package__ in {None, ""}:  # Support direct file execution from GitHub Actions.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ida_script_mcp.disposable_vm.host_controller import parse_args, run_controller
from ida_script_mcp.payload.ida_api_test import build_guest_ida_api_test_script
from ida_script_mcp.payload.ida_plugin_install import (
    DEFAULT_GUEST_IDA_DIR,
    build_guest_ida_plugin_install_script,
)
from ida_script_mcp.payload.ida_u004_real_mcp_client_test import (
    build_guest_u004_real_mcp_client_test_script,
)
from ida_script_mcp.payload.ida_u005_multi_ida_instance_test import (
    build_guest_u005_multi_ida_instance_test_script,
)
from ida_script_mcp.payload.ida_u007_decompile_corner_case_test import (
    build_guest_u007_decompile_corner_case_test_script,
)
from ida_script_mcp.payload.ida_u008_xrefs_corner_case_test import (
    build_guest_u008_xrefs_corner_case_test_script,
)
from ida_script_mcp.payload.ida_u010_rename_complex_test import (
    build_guest_u010_rename_complex_test_script,
)
from ida_script_mcp.payload.ida_u011_comment_function_comment_test import (
    build_guest_u011_comment_function_comment_test_script,
)
from ida_script_mcp.payload.ida_u013_patch_bytes_complex_test import (
    build_guest_u013_patch_bytes_complex_test_script,
)
from ida_script_mcp.payload.ida_worker_chain_test import build_guest_ida_worker_chain_test_script

DEFAULT_CONTROLLER_URL = "http://192.168.1.249:8766"
DEFAULT_RESTORE_SCRIPT = r"C:\Users\alion\Scripts\vmware_restore_test1.py"
DEFAULT_DLL_PATH = r"C:\Users\alion\Desktop\test1.dll"
DEFAULT_COMMAND_JSON = '["python", "--version"]'
RESULT_DIR_NAME = "ida-script-mcp-disposable-vm"


@dataclass(frozen=True)
class WorkflowInputs:
    controller_url: str
    port: int
    restore_script: str
    restore_gui: bool
    run_vmware_restore: bool
    restore_extra_args: tuple[str, ...]
    task_action: str
    ida_dir: str
    dll_path: str
    ida_timeout_seconds: int
    ida_api_test_mode: str
    command_json: str
    connect_timeout_seconds: int
    run_timeout_seconds: int
    result_dir: Path


def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _read_github_event_inputs() -> dict[str, object]:
    """Read workflow_dispatch inputs from GitHub's event JSON file.

    This keeps `.github/workflows/*.yml` thin: the workflow does not need to
    expand inputs into a large env block or encode branching logic.
    """

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    path = Path(event_path)
    if not path.is_file():
        return {}
    try:
        event = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Cannot read GitHub event JSON from {path}: {exc}") from exc
    inputs = event.get("inputs")
    if not isinstance(inputs, dict):
        return {}
    return inputs


def _input_value(inputs: dict[str, object], key: str, default: str = "") -> str:
    value = inputs.get(key)
    if value is None:
        # Environment fallback is intentionally only for local tests and manual
        # debugging. The workflow itself reads from GITHUB_EVENT_PATH.
        value = os.environ.get(f"IDA_MCP_{key.upper()}")
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return default
    text = str(value)
    return text if text.strip() else default


def _parse_bool(inputs: dict[str, object], name: str, default: bool) -> bool:
    raw = _input_value(inputs, name, str(default)).strip().lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError(f"workflow input {name!r} must be boolean-like, got {raw!r}")


def _parse_int(inputs: dict[str, object], name: str, default: int) -> int:
    raw = _input_value(inputs, name, str(default)).strip()
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"workflow input {name!r} must be an integer, got {raw!r}") from exc


def _parse_json_string_list(inputs: dict[str, object], name: str, default: str = "[]") -> tuple[str, ...]:
    raw = _input_value(inputs, name, default)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"workflow input {name!r} must be a JSON array of strings: {raw!r}") from exc
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError(f"workflow input {name!r} must be a JSON array of strings: {raw!r}")
    return tuple(item for item in parsed if item.strip())


def _default_result_dir() -> Path:
    runner_temp = os.environ.get("RUNNER_TEMP")
    root = Path(runner_temp) if runner_temp else Path(tempfile.gettempdir())
    return root / RESULT_DIR_NAME


def inputs_from_env() -> WorkflowInputs:
    inputs = _read_github_event_inputs()
    port = _parse_int(inputs, "port", 8766)
    controller_url = _input_value(inputs, "controller_url", DEFAULT_CONTROLLER_URL)
    if not controller_url.strip():
        controller_url = f"http://192.168.1.249:{port}"

    result_dir_raw = _input_value(inputs, "result_dir", "")
    result_dir = Path(result_dir_raw) if result_dir_raw else _default_result_dir()

    return WorkflowInputs(
        controller_url=controller_url.rstrip("/"),
        port=port,
        restore_script=_input_value(inputs, "restore_script", DEFAULT_RESTORE_SCRIPT),
        restore_gui=_parse_bool(inputs, "restore_gui", True),
        run_vmware_restore=_parse_bool(inputs, "run_vmware_restore", True),
        restore_extra_args=_parse_json_string_list(inputs, "restore_extra_args_json"),
        task_action=_input_value(inputs, "task_action", "noop"),
        ida_dir=_input_value(inputs, "ida_dir", DEFAULT_GUEST_IDA_DIR),
        dll_path=_input_value(inputs, "dll_path", DEFAULT_DLL_PATH),
        ida_timeout_seconds=_parse_int(inputs, "ida_timeout_seconds", 180),
        ida_api_test_mode=_input_value(inputs, "ida_api_test_mode", "basic"),
        command_json=_input_value(inputs, "command_json", DEFAULT_COMMAND_JSON),
        connect_timeout_seconds=_parse_int(inputs, "connect_timeout_seconds", 600),
        run_timeout_seconds=_parse_int(inputs, "run_timeout_seconds", 1800),
        result_dir=result_dir,
    )


def _write_script(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"Wrote workflow payload script: {path}", flush=True)
    return path


def _phase3_script() -> str:
    return "\n".join(
        [
            "import platform",
            "import sys",
            "print('phase3 script ok python=' + platform.python_version() + ' executable=' + sys.executable)",
            "",
        ]
    )


def _ida_api_script(inputs: WorkflowInputs, *, test_mode: Optional[str] = None) -> str:
    return build_guest_ida_api_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
        test_mode=test_mode or inputs.ida_api_test_mode,
    )


PayloadBuilder = Callable[[WorkflowInputs], tuple[str, str]]


def _build_plugin_install(inputs: WorkflowInputs) -> tuple[str, str]:
    return "ida_plugin_install_payload.py", build_guest_ida_plugin_install_script(ida_dir=inputs.ida_dir)


def _build_api(inputs: WorkflowInputs) -> tuple[str, str]:
    name = "U006_functions_corner_case.py" if inputs.ida_api_test_mode == "functions_corner" else "ida_plugin_api_test_payload.py"
    return name, _ida_api_script(inputs)


def _build_apply_changes(inputs: WorkflowInputs) -> tuple[str, str]:
    return "ida_plugin_apply_changes_test_payload.py", _ida_api_script(inputs, test_mode="apply_changes")


def _build_worker_chain(inputs: WorkflowInputs) -> tuple[str, str]:
    return "ida_plugin_worker_chain_test_payload.py", build_guest_ida_worker_chain_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
    )


def _build_worker_discovery(inputs: WorkflowInputs) -> tuple[str, str]:
    return "ida_plugin_gui_worker_discovery_test_payload.py", build_guest_ida_worker_chain_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
        test_mode="gui_worker_discovery",
    )


def _build_worker_timeout(inputs: WorkflowInputs) -> tuple[str, str]:
    return "ida_plugin_worker_timeout_test_payload.py", build_guest_ida_worker_chain_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
        test_mode="worker_timeout",
    )


def _build_worker_failure_matrix(inputs: WorkflowInputs) -> tuple[str, str]:
    return "ida_plugin_worker_failure_matrix_test_payload.py", build_guest_ida_worker_chain_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
        test_mode="worker_failure_matrix",
    )


def _build_u004(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U004_real_MCP_client_end-to-end.py", build_guest_u004_real_mcp_client_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
    )


def _build_u005(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U005_multi_IDA_instance_selection.py", build_guest_u005_multi_ida_instance_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
    )


def _build_u007(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U007_decompile_corner_case.py", build_guest_u007_decompile_corner_case_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
    )


def _build_u008(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U008_xrefs_corner_cases.py", build_guest_u008_xrefs_corner_case_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
    )


def _build_u009(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U009_inspect_address_system_test.py", _ida_api_script(inputs, test_mode="inspect_address")


def _build_u010(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U010_rename_complex_cases.py", build_guest_u010_rename_complex_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
    )


def _build_u011(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U011_comment_function_comment_complex.py", build_guest_u011_comment_function_comment_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
    )


def _build_u012(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U012_set_type_complex.py", build_guest_ida_worker_chain_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
        test_mode="u012_set_type_complex",
    )


def _build_u013(inputs: WorkflowInputs) -> tuple[str, str]:
    return "U013_patch_bytes_complex_cases.py", build_guest_u013_patch_bytes_complex_test_script(
        ida_dir=inputs.ida_dir,
        dll_path=inputs.dll_path,
        ida_timeout_seconds=inputs.ida_timeout_seconds,
    )


PAYLOAD_BUILDERS: dict[str, PayloadBuilder] = {
    "ida_plugin_install": _build_plugin_install,
    "ida_plugin_api_test": _build_api,
    "ida_plugin_apply_changes_test": _build_apply_changes,
    "ida_plugin_worker_chain_test": _build_worker_chain,
    "ida_plugin_gui_worker_discovery_test": _build_worker_discovery,
    "ida_plugin_worker_timeout_test": _build_worker_timeout,
    "ida_plugin_worker_failure_matrix_test": _build_worker_failure_matrix,
    "ida_plugin_u004_real_mcp_client_test": _build_u004,
    "ida_plugin_u005_multi_ida_instance_test": _build_u005,
    "ida_plugin_u007_decompile_corner_case_test": _build_u007,
    "ida_plugin_u008_xrefs_corner_case_test": _build_u008,
    "ida_plugin_u009_inspect_address_test": _build_u009,
    "ida_plugin_u010_rename_complex_test": _build_u010,
    "ida_plugin_u011_comment_function_comment_test": _build_u011,
    "ida_plugin_u012_set_type_complex_test": _build_u012,
    "ida_plugin_u013_patch_bytes_complex_test": _build_u013,
}


def _controller_args(inputs: WorkflowInputs) -> list[str]:
    args = [
        "--bind-host",
        "0.0.0.0",
        "--port",
        str(inputs.port),
        "--advertise-url",
        inputs.controller_url,
        "--task-action",
        inputs.task_action,
        "--connect-timeout-seconds",
        str(inputs.connect_timeout_seconds),
        "--timeout-seconds",
        str(inputs.run_timeout_seconds),
        "--result-dir",
        str(inputs.result_dir),
    ]

    if inputs.run_vmware_restore:
        args.extend(["--vmware-restore-script", inputs.restore_script])
        if inputs.restore_gui:
            args.append("--vmware-restore-arg=--gui")
        for restore_arg in inputs.restore_extra_args:
            args.append(f"--vmware-restore-arg={restore_arg}")
    else:
        print("Skipping VMware restore; waiting for an already-running guest agent.", flush=True)

    if inputs.task_action == "command":
        args.extend(["--command-json", inputs.command_json])
        return args

    if inputs.task_action == "python_script":
        script_path = _write_script(inputs.result_dir / "phase3_payload.py", _phase3_script())
        args.extend(["--script-path", str(script_path)])
        return args

    builder = PAYLOAD_BUILDERS.get(inputs.task_action)
    if builder is not None:
        filename, script = builder(inputs)
        script_path = _write_script(inputs.result_dir / filename, script)
        args[7] = "python_script"
        args.extend(["--script-path", str(script_path)])

    return args


def main() -> int:
    _configure_stdio()
    inputs = inputs_from_env()
    inputs.result_dir.mkdir(parents=True, exist_ok=True)
    print(f"Using controller_url={inputs.controller_url}", flush=True)
    print(f"Using result_dir={inputs.result_dir}", flush=True)
    args = _controller_args(inputs)
    print("Starting disposable VM host controller from Python workflow runner.", flush=True)
    parsed = parse_args(args)
    return int(run_controller(parsed))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
