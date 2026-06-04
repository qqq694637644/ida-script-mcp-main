from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ida_script_mcp.payload.ida_api_test import (
    DEFAULT_GUEST_DLL_PATH,
    DEFAULT_GUEST_IDA_DIR,
    DEFAULT_IDA_API_TEST_MODE,
    DEFAULT_IDA_TIMEOUT_SECONDS,
    build_guest_ida_api_test_script,
)
from ida_script_mcp.payload.ida_u004_real_mcp_client_test import (
    build_guest_u004_real_mcp_client_test_script,
)
from ida_script_mcp.payload.ida_u005_multi_ida_instance_test import (
    build_guest_u005_multi_ida_instance_test_script,
)
from ida_script_mcp.payload.ida_u007_decompile_corner_case_test import (
    PAYLOAD_SCRIPT_NAME as U007_PAYLOAD_SCRIPT_NAME,
)
from ida_script_mcp.payload.ida_u007_decompile_corner_case_test import (
    build_guest_u007_decompile_corner_case_test_script,
)
from ida_script_mcp.payload.ida_u013_patch_bytes_complex_test import (
    build_guest_u013_patch_bytes_complex_test_script,
)
from ida_script_mcp.payload.ida_worker_chain_test import (
    build_guest_ida_worker_chain_test_script,
)


def test_build_guest_ida_api_test_script_contains_inputs_and_endpoints() -> None:
    script = build_guest_ida_api_test_script(
        ida_dir=DEFAULT_GUEST_IDA_DIR,
        dll_path=DEFAULT_GUEST_DLL_PATH,
    )

    assert "IDAPro8.3" in script
    assert "test1.dll" in script
    assert f"IDA_TIMEOUT_SECONDS = {DEFAULT_IDA_TIMEOUT_SECONDS}" in script
    assert f'IDA_API_TEST_MODE = "{DEFAULT_IDA_API_TEST_MODE}"' in script
    assert "IDA_PLUGIN_API_TEST_RESULT=" in script
    assert "IDA_API_STAGE=" in script
    assert "legacy_support_cleanup_done" in script
    assert "Legacy root support files remain" in script
    assert "ida_ready.json" in script
    assert "ida_ready_wait_start" in script
    assert "_run_external_api_tests" in script
    assert "functions_offset_beyond_total_start" in script
    assert "xrefs_invalid_kind_start" in script
    assert "threading.Thread" not in script
    assert "_run_http_tests" not in script
    assert "__DLL_PATH_JSON__" not in script
    outer_script = script.split("BOOTSTRAP_TEMPLATE", maxsplit=1)[0]
    assert "DLL_PATH = __BOOTSTRAP_DLL_PATH_JSON__" not in outer_script
    assert "__IDA_DIR_JSON__" not in script
    assert "__IDA_TIMEOUT_SECONDS_JSON__" not in script
    assert "__IDA_API_TEST_MODE_JSON__" not in script
    assert "__BOOTSTRAP_IDA_API_TEST_MODE_JSON__" not in outer_script
    assert '"/metadata"' in script
    assert '"/functions"' in script
    assert '"/decompile"' in script
    assert '"/xrefs"' in script
    assert '"/execute"' in script
    assert '"/apply_changes"' in script
    assert '"/inspect_address"' in script
    assert "_run_apply_changes_tests" in script
    compile(script, "<generated_ida_api_test_payload>", "exec")


def test_build_guest_ida_api_test_script_accepts_custom_paths(tmp_path) -> None:
    ida_dir = tmp_path / "IDA Pro Custom"
    dll_path = tmp_path / "sample.dll"

    script = build_guest_ida_api_test_script(
        ida_dir=str(ida_dir),
        dll_path=str(dll_path),
        ida_timeout_seconds=123,
        test_mode="full",
    )

    assert "IDA Pro Custom" in script
    assert "sample.dll" in script
    assert "IDA_TIMEOUT_SECONDS = 123" in script
    assert 'IDA_API_TEST_MODE = "full"' in script
    compile(script, "<generated_ida_api_test_payload>", "exec")


def test_build_guest_ida_api_test_script_accepts_apply_changes_mode() -> None:
    script = build_guest_ida_api_test_script(test_mode="apply_changes")

    assert 'IDA_API_TEST_MODE = "apply_changes"' in script
    assert '"/apply_changes"' in script
    assert '"/inspect_address"' in script
    assert "database_save_start" in script
    assert "database_save_done" in script
    assert "apply_changes_tests_start" in script
    assert "__IDA_API_TEST_MODE_JSON__" not in script
    outer_script = script.split("BOOTSTRAP_TEMPLATE", maxsplit=1)[0]
    assert "__BOOTSTRAP_IDA_API_TEST_MODE_JSON__" not in outer_script
    compile(script, "<generated_ida_api_test_payload_apply_changes>", "exec")


def test_build_guest_ida_api_test_script_accepts_inspect_address_mode() -> None:
    script = build_guest_ida_api_test_script(test_mode="inspect_address")

    assert 'IDA_API_TEST_MODE = "inspect_address"' in script
    assert '"/inspect_address"' in script
    assert "u009_seed_start" in script
    assert "u009_inspect_address_tests_start" in script
    assert "inspect_byte_count_zero" in script
    assert "inspect_byte_count_negative" in script
    assert "inspect_byte_count_huge" in script
    assert "inspect_unmapped_address" in script
    assert "inspect_data_address" in script
    assert "inspect_instruction_middle" in script
    assert "inspect_seeded_unicode_address" in script
    assert "U009 regular 注释" in script
    assert "U009 repeatable function 注释" in script
    assert 'print("IDA_API_STAGE=" + json.dumps(payload, ensure_ascii=True' in script
    assert '"IDA_PLUGIN_API_TEST_RESULT="' in script
    assert "json.dumps(result, ensure_ascii=True, sort_keys=True)" in script
    assert "__IDA_API_TEST_MODE_JSON__" not in script
    outer_script = script.split("BOOTSTRAP_TEMPLATE", maxsplit=1)[0]
    assert "__BOOTSTRAP_IDA_API_TEST_MODE_JSON__" not in outer_script
    compile(script, "<generated_ida_api_test_payload_inspect_address>", "exec")


def test_build_guest_ida_api_test_script_accepts_functions_corner_mode() -> None:
    script = build_guest_ida_api_test_script(test_mode="functions_corner")

    assert 'IDA_API_TEST_MODE = "functions_corner"' in script
    assert "functions_corner_tests_start" in script
    assert "functions_corner_include_matrix_start" in script
    assert "limit_zero" in script
    assert "offset_negative" in script
    assert "☃_unlikely_*[]" in script
    assert "IDA_PLUGIN_API_TEST_RESULT=" in script
    assert "ensure_ascii=True" in script
    assert "__IDA_API_TEST_MODE_JSON__" not in script
    outer_script = script.split("BOOTSTRAP_TEMPLATE", maxsplit=1)[0]
    assert "__BOOTSTRAP_IDA_API_TEST_MODE_JSON__" not in outer_script
    compile(script, "<generated_ida_api_test_payload_functions_corner>", "exec")


def test_build_guest_ida_api_test_script_accepts_decompile_corner_case_mode() -> None:
    script = build_guest_ida_api_test_script(test_mode="decompile_corner_case")

    assert 'IDA_API_TEST_MODE = "decompile_corner_case"' in script
    assert '"/decompile"' in script
    assert "u007_decompile_corner_cases_start" in script
    assert "_u007_decompile_request" in script
    assert '"middle_address"' in script
    assert '"thunk_or_library"' in script
    assert "duplicate function-name ambiguity" in script
    assert "__IDA_API_TEST_MODE_JSON__" not in script
    compile(script, "<generated_ida_api_test_payload_u007_decompile>", "exec")


def test_disposable_vm_workflow_exposes_apply_changes_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_apply_changes_test" in workflow
    assert "ida_plugin_apply_changes_test_payload.py" in workflow
    assert "--test-mode apply_changes" in workflow
    assert "- apply_changes" in workflow


def test_disposable_vm_workflow_exposes_u006_functions_corner_mode() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "functions_corner" in workflow
    assert "U006_functions_corner_case.py" in workflow
    assert "--test-mode $idaApiTestMode" in workflow


def test_build_guest_ida_worker_chain_test_script_contains_checked_sources() -> None:
    script = build_guest_ida_worker_chain_test_script()

    assert "IDA_WORKER_CHAIN_TEST_RESULT=" in script
    assert "WORKER_CHAIN_STAGE=" in script
    assert "execute_idapython" in script
    assert "apply_worker_changes" in script
    assert "worker_chain_user_script.py" in script
    assert "IDA_SCRIPT_MCP_WORKER_CHAIN_TARGET_EA" in script
    assert "__PLUGIN_FILES_B64_JSON__" not in script
    assert "__RUNTIME_FILES_B64_JSON__" not in script
    assert "__USER_SCRIPT_B64_JSON__" not in script
    compile(script, "<generated_worker_chain_payload>", "exec")


def test_build_guest_ida_worker_timeout_test_script_contains_checked_sources() -> None:
    script = build_guest_ida_worker_chain_test_script(test_mode="worker_timeout")

    assert "IDA_WORKER_CHAIN_TEST_RESULT=" in script
    assert "WORKER_CHAIN_STAGE=" in script
    assert 'TEST_MODE = "worker_timeout"' in script
    assert "worker_timeout_user_script.py" in script
    assert "worker_timeout_execute_start" in script
    assert "hard_timeout" in script
    assert "killed" in script
    assert "worker_process_alive_after_kill" in script
    assert "IDA_SCRIPT_MCP_WORKER_TIMEOUT_SENTINEL" in script
    assert "__TEST_MODE_JSON__" not in script
    assert "__USER_SCRIPT_FILENAME_JSON__" not in script
    assert "__USER_SCRIPT_B64_JSON__" not in script
    compile(script, "<generated_worker_timeout_payload>", "exec")


def test_build_guest_ida_worker_failure_matrix_script_contains_checked_sources() -> None:
    script = build_guest_ida_worker_chain_test_script(test_mode="worker_failure_matrix")

    assert "IDA_WORKER_CHAIN_TEST_RESULT=" in script
    assert "WORKER_CHAIN_STAGE=" in script
    assert 'TEST_MODE = "worker_failure_matrix"' in script
    assert "worker_crash_user_script.py" in script
    assert "worker_result_missing_user_script.py" in script
    assert "worker_recorder_error_user_script.py" in script
    assert "worker_failure_case_start" in script
    assert "worker_failure_matrix_done" in script
    assert "worker_start_error" in script
    assert "worker_crashed" in script
    assert "worker_result_missing" in script
    assert "recorder_error" in script
    assert "source_error" in script
    assert "rejected" in script
    assert "__TEST_MODE_JSON__" not in script
    assert "__USER_SCRIPT_FILENAME_JSON__" not in script
    assert "__USER_SCRIPT_B64_JSON__" not in script
    compile(script, "<generated_worker_failure_matrix_payload>", "exec")


def test_build_guest_u004_real_mcp_client_script_contains_checked_sources() -> None:
    script = build_guest_u004_real_mcp_client_test_script()

    assert "U004_REAL_MCP_CLIENT_TEST_RESULT=" in script
    assert "U004_STAGE=" in script
    assert "U004_real_MCP_client_worker_script.py" in script
    assert "mcp.client.stdio" in script
    assert "mcp.client.sse" in script
    assert "ida_script_mcp.server" in script
    assert "list_ida_instances" in script
    assert "get_ida_database_info" in script
    assert "list_functions" in script
    assert "decompile_function" in script
    assert "get_xrefs" in script
    assert "execute_idapython" in script
    assert "apply_worker_changes" in script
    pip_install_command = (
        '["py", "-3.11", "-m", "pip", "install", "-r", "requirements.txt", '
        '"--proxy", PIP_PROXY]'
    )
    assert pip_install_command in script
    assert "http://192.168.1.249:10810" in script
    assert "__WORKER_SCRIPT_B64_JSON__" not in script
    assert "__RUNTIME_FILES_B64_JSON__" not in script
    compile(script, "<generated_u004_real_mcp_client_payload>", "exec")


def test_build_guest_u005_multi_ida_instance_script_contains_checked_sources() -> None:
    script = build_guest_u005_multi_ida_instance_test_script()

    assert "U005_MULTI_IDA_INSTANCE_TEST_RESULT=" in script
    assert "U005_STAGE=" in script
    assert "U005_multi_IDA_instance_selection.py" in str(
        Path("U005_multi_IDA_instance_selection.py")
    )
    assert "_u005_copy" in script
    assert "shutil.copy2" in script
    assert "list_ida_instances" in script
    assert "get_ida_database_info" in script
    assert "list_functions" in script
    assert "Multiple IDA instances found" in script
    assert "matched multiple instance ids" in script
    assert "port takes precedence over conflicting instance_id" in script
    assert "same directory" in script or "same_dir" in script
    assert "__RUNTIME_FILES_B64_JSON__" not in script
    assert "__PLUGIN_FILES_B64_JSON__" not in script
    compile(script, "<generated_u005_multi_ida_instance_payload>", "exec")


def test_build_guest_u007_decompile_corner_case_script_contains_checked_sources() -> None:
    script = build_guest_u007_decompile_corner_case_test_script()

    assert "IDA_PLUGIN_API_TEST_RESULT=" in script
    assert 'IDA_API_TEST_MODE = "decompile_corner_case"' in script
    assert "u007_decompile_corner_cases_start" in script
    assert "_u007_decompile_request" in script
    assert '"start_address"' in script
    assert '"middle_address"' in script
    assert '"name_query"' in script
    assert '"no_function_address"' in script
    assert '"invalid_address"' in script
    assert '"largest_function"' in script
    assert "Hex-Rays unavailable/failure path" in script
    assert "__IDA_API_TEST_MODE_JSON__" not in script
    compile(script, "<generated_u007_decompile_corner_case_payload>", "exec")


def test_build_guest_u013_patch_bytes_complex_script_contains_checked_sources() -> None:
    script = build_guest_u013_patch_bytes_complex_test_script()

    assert "U013_PATCH_BYTES_COMPLEX_TEST_RESULT=" in script
    assert "U013_STAGE=" in script
    assert "U013_patch_bytes_complex_cases.py" in str(Path("U013_patch_bytes_complex_cases.py"))
    assert "old_bytes mismatch" in script
    assert "op-multi-byte-code" in script
    assert "op-middle-byte-code" in script
    assert "op-same-byte-code" in script
    assert "op-repeat-byte-1" in script
    assert "op-repeat-byte-2" in script
    assert "op-data-byte" in script
    assert "op-unmapped-partial-stop" in script
    assert "destructive patch has partial status" in script
    assert "metadata dirty after destructive partial patch" in script
    assert "__PLUGIN_FILES_B64_JSON__" not in script
    compile(script, "<generated_u013_patch_bytes_complex_payload>", "exec")


def test_disposable_vm_workflow_exposes_worker_chain_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_worker_chain_test" in workflow
    assert "ida_plugin_worker_chain_test_payload.py" in workflow
    assert "ida_script_mcp.payload.ida_worker_chain_test" in workflow


def test_disposable_vm_workflow_exposes_worker_timeout_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_worker_timeout_test" in workflow
    assert "ida_plugin_worker_timeout_test_payload.py" in workflow
    assert "--test-mode worker_timeout" in workflow


def test_disposable_vm_workflow_exposes_worker_failure_matrix_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_worker_failure_matrix_test" in workflow
    assert "ida_plugin_worker_failure_matrix_test_payload.py" in workflow
    assert "--test-mode worker_failure_matrix" in workflow


def test_disposable_vm_workflow_exposes_u004_real_mcp_client_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_u004_real_mcp_client_test" in workflow
    assert "U004_real_MCP_client_end-to-end.py" in workflow
    assert "ida_script_mcp.payload.ida_u004_real_mcp_client_test" in workflow


def test_disposable_vm_workflow_exposes_u009_inspect_address_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_u009_inspect_address_test" in workflow
    assert "U009_inspect_address_system_test.py" in workflow
    assert "--test-mode inspect_address" in workflow


def test_disposable_vm_workflow_exposes_u005_multi_ida_instance_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_u005_multi_ida_instance_test" in workflow
    assert "U005_multi_IDA_instance_selection.py" in workflow
    assert "ida_script_mcp.payload.ida_u005_multi_ida_instance_test" in workflow


def test_disposable_vm_workflow_exposes_u007_decompile_corner_case_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_u007_decompile_corner_case_test" in workflow
    assert U007_PAYLOAD_SCRIPT_NAME in workflow
    assert "ida_script_mcp.payload.ida_u007_decompile_corner_case_test" in workflow


def test_disposable_vm_workflow_exposes_u013_patch_bytes_complex_action() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    workflow_path = (
        repo_root / ".github" / "workflows" / "disposable-vm-guest-agent-smoke.yml"
    )
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "ida_plugin_u013_patch_bytes_complex_test" in workflow
    assert "U013_patch_bytes_complex_cases.py" in workflow
    assert "ida_script_mcp.payload.ida_u013_patch_bytes_complex_test" in workflow


def test_generated_ida_api_payload_file_can_be_written(tmp_path) -> None:
    output = tmp_path / "ida_api_payload.py"
    output.write_text(build_guest_ida_api_test_script(), encoding="utf-8")

    assert output.is_file()
    assert output.read_text(encoding="utf-8").startswith("from __future__ import annotations")
    assert isinstance(output, Path)


def test_generated_ida_api_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "ida_api_payload.py"
    script_path.write_text(
        build_guest_ida_api_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "IDA_PLUGIN_API_TEST_RESULT=" in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "HEARTBEAT_PATH" not in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_apply_changes_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "ida_api_apply_changes_payload.py"
    script_path.write_text(
        build_guest_ida_api_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
            test_mode="apply_changes",
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "IDA_PLUGIN_API_TEST_RESULT=" in result.stdout
    assert '"mode": "apply_changes"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "HEARTBEAT_PATH" not in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_inspect_address_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "U009_inspect_address_system_test.py"
    script_path.write_text(
        build_guest_ida_api_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
            test_mode="inspect_address",
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "IDA_PLUGIN_API_TEST_RESULT=" in result.stdout
    assert '"mode": "inspect_address"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "HEARTBEAT_PATH" not in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_functions_corner_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "U006_functions_corner_case.py"
    script_path.write_text(
        build_guest_ida_api_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
            test_mode="functions_corner",
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "IDA_PLUGIN_API_TEST_RESULT=" in result.stdout
    assert '"mode": "functions_corner"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "HEARTBEAT_PATH" not in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_worker_chain_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "worker_chain_payload.py"
    script_path.write_text(
        build_guest_ida_worker_chain_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "IDA_WORKER_CHAIN_TEST_RESULT=" in result.stdout
    assert '"mode": "worker_chain"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_worker_timeout_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "worker_timeout_payload.py"
    script_path.write_text(
        build_guest_ida_worker_chain_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
            test_mode="worker_timeout",
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "IDA_WORKER_CHAIN_TEST_RESULT=" in result.stdout
    assert '"mode": "worker_timeout"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_worker_failure_matrix_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "worker_failure_matrix_payload.py"
    script_path.write_text(
        build_guest_ida_worker_chain_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
            test_mode="worker_failure_matrix",
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "IDA_WORKER_CHAIN_TEST_RESULT=" in result.stdout
    assert '"mode": "worker_failure_matrix"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_u004_real_mcp_client_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "U004_real_MCP_client_end-to-end.py"
    script_path.write_text(
        build_guest_u004_real_mcp_client_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "U004_REAL_MCP_CLIENT_TEST_RESULT=" in result.stdout
    assert '"mode": "u004_real_mcp_client"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_u005_multi_ida_instance_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "U005_multi_IDA_instance_selection.py"
    script_path.write_text(
        build_guest_u005_multi_ida_instance_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "U005_MULTI_IDA_INSTANCE_TEST_RESULT=" in result.stdout
    assert '"mode": "u005_multi_ida_instance_selection"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "validate_inputs_start" in result.stdout


def test_generated_u013_patch_bytes_complex_payload_reports_missing_ida_dir(tmp_path) -> None:
    script_path = tmp_path / "U013_patch_bytes_complex_cases.py"
    script_path.write_text(
        build_guest_u013_patch_bytes_complex_test_script(
            ida_dir=str(tmp_path / "missing-ida"),
            dll_path=str(tmp_path / "missing.dll"),
            ida_timeout_seconds=15,
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 1
    assert "U013_PATCH_BYTES_COMPLEX_TEST_RESULT=" in result.stdout
    assert '"mode": "u013_patch_bytes_complex_cases"' in result.stdout
    assert "IDA directory does not exist" in result.stdout
    assert "validate_inputs_start" in result.stdout
