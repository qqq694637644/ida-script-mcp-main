# 已测试

Last updated: 2026-06-04

本文件只记录已经通过真实 workflow、实机 IDA/guest VM、或明确单元测试验证的范围。新增通过项时，把对应条目从 `UNTESTED.md` 移到本文件，并写明证据。失败、诊断和修复经验继续写入 `DISPOSABLE_VM_WORKFLOW_LESSONS.md`。

## 已确认的实机 workflow 范围

当前 HostMachine -> disposable guest VM -> IDA 8.3 workflow 已确认测过：

```text
Guest agent 连接
动态 payload 下发
插件安装
IDA 8.3 打开 C:\Users\alion\Desktop\test1.dll
插件 HTTP server 启动
GET  /health
GET  /metadata
POST /functions
POST /decompile
POST /xrefs
POST /execute rejected by default
GET  unknown route -> 404
POST /inspect_address
POST /apply_changes destructive smoke
patch_bytes 修改 DllEntryPoint 首字节
```

## apply_changes 已验证范围

`apply_changes` 已确认覆盖：

```text
bad fingerprint 被拒绝
dry-run 默认不改数据库
rename destructive apply
comment destructive apply
function_comment destructive apply
set_type destructive apply
patch_bytes destructive apply
dirty=true / apply_changes_mutation_flag
第二次 destructive apply 被 dirty/unsaved 状态拒绝
```

## 现有证据索引

| 范围 | 证据 | 备注 |
| --- | --- | --- |
| Phase 1 connectivity / guest agent smoke | workflow run `26900876629` attempt 2 | guest agent 可连接 host controller |
| Phase 2 command payload | workflow runs `26902252502`, rerun `26902716245` | 动态 command payload 可执行 |
| Phase 3 Python script payload | workflow run `26903071347` | guest 可执行动态 Python script payload |
| IDA plugin install | workflow runs `26903926544`, `26907543538` | support-package layout 已验证 |
| IDA API basic smoke | workflow run `26908653405` | 基础 endpoint smoke |
| IDA API full smoke + corner cases | workflow run `26909020426` | 非破坏性 full smoke |
| IDA API full smoke after merge to `main` | workflow run `26921994480`, artifact `7400024008` | `main` baseline 成功，HostMachine runner，guest result `completed/0` |
| apply_changes destructive smoke | workflow run `26918788898` | destructive replay 基础验证 |
| patch_bytes destructive smoke | workflow run `26919752930` | 临时 `test1.i64` 中 patch 首字节，不改原始 DLL |
| U001 full V2.3 worker replay chain | workflow run `26922985347`, artifact `7400373325` | `execute_idapython -> worker ChangeSet -> apply_worker_changes dry-run/destructive -> inspect` |
| U002 worker hard timeout / kill process tree | workflow run `26923418555`, artifact `7400538789` | `execute_idapython` hard timeout killed worker PID and left GUI DB clean |
| U003 worker failure-state matrix | workflow run `26923830535`, artifact `7400695878` | worker_start_error/source_error/crash/missing-result/recorder_error/rejected all passed |
| U004 real MCP client end-to-end | workflow run `26925268750`, artifact `7401236989` | stdio + HTTP/SSE real MCP client, tool schemas/results, read tools, execute structured result, apply dry-run |
| U005 multi-IDA instance selection | workflow run `26925755930`, artifact `7401401506` | same-directory DLL copy, two IDA instances, full/substring/port selectors, ambiguity/missing-instance errors |
| U006 `/functions` corner cases | workflow run `26925694907`, artifact `7401369820` | `functions_corner` mode covered segment/name/include/numeric/invalid parameter semantics; fixture-dependent residuals remain |
| U007 `/decompile` corner case | workflow run `26926171098`, artifact `7401525174` | start/middle/name decompile, no-function/invalid/missing-name structured errors, thunk/import, largest function, Hex-Rays pseudocode path |
| U009 /inspect_address system test | workflow run `26926388631`, artifact `7401596027` | invalid/missing target, byte_count clamp, data/instruction-middle/unmapped, Unicode comments, repeatable comments, clean read-only state |
| U013 patch_bytes complex cases | workflow run `26926417574`, artifact `7401627652` | multi-byte/middle/same/repeated/data patch, old_bytes mismatch, dry-run, partial apply, dirty rejection |
| U012 set_type complex cases | workflow run `26927371932`, artifact `7401910040` | worker-generated `set_type` ChangeSet, invalid declaration failure, dry-run/destructive replay, final type inspect, dirty replay guard |

## 2026-06-04 当前测试结果：main full smoke baseline

Evidence:

- Workflow run: `26921994480`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `main` / `e7b00f0553c7b53437f55bda9f02b7c7497f1ddf`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7400024008`
- Files inspected: `controller_state.json`, `result.json`, artifact file list

Inputs:

```text
task_action=ida_plugin_api_test
ida_api_test_mode=full
ida_timeout_seconds=180
run_timeout_seconds=300
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
controller_state.status=success
controller_state.payload_downloaded=true
guest hello hostname=DESKTOP-QBSO5C3
guest python_version=3.11.7
guest result status=completed
guest result exit_code=0
IDA plugin instance=8052_test1.dll
IDA plugin port=13338
heartbeat reached api_tests_done status=passed
cleanup reached ida_terminate_done
```

Coverage confirmed by this run:

```text
/health
/metadata
/functions
/functions limit=1
/functions name filter
/functions offset beyond total
/decompile
/decompile invalid address
/xrefs to
/xrefs from
/xrefs invalid direction structured error
/xrefs invalid kind structured error
/execute -> HTTP 410 status=rejected
unknown route -> HTTP 404
```

Not covered by this run:

```text
U001/U002/U003 已由 dedicated workflow runs 覆盖。
```

因此核心 V2.3 worker 生命周期测试 U001-U003 均已关闭。


## 2026-06-04 U001：完整 V2.3 worker replay 主链路

Evidence:

- Workflow run: `26922985347`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/testing-handoff-tracker-20260604-bf55c1` / `2df76f58c1f96387eb6bf911926a936c8215d232`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7400373325`
- Files inspected: `controller_state.json`

Inputs:

```text
task_action=ida_plugin_worker_chain_test
ida_timeout_seconds=240
run_timeout_seconds=600
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
controller_state.status=success
controller_state.payload_downloaded=true
guest result status=completed
guest result exit_code=0
payload mode=worker_chain
payload status=passed
IDA plugin instance=116_test1.dll
IDA plugin port=13338
metadata_before.dirty=false
metadata_before.database_sha256=e816ec94aec1cc68b7146d662ccc81e45112d1cd0a23c6b0b1c162dfd79d4b10
execute_idapython.status=ok
execute_idapython.isolated=true
execute_idapython.worker_exit_code=0
execute_idapython.job_id=job-19a39fd40af84ec4848cfac1b58fd9af
execute_idapython.changes contains 2 operations: rename, comment
worker_chain_change_set_summary.operation_count=2
worker_chain_change_set_summary.operation_types=[rename, comment]
apply_worker_changes dry-run status=ok, applied=[], skipped=2
inspect after dry-run kept original name/comment
apply_worker_changes destructive status=ok, applied=2, errors=[]
inspect after apply saw name=mcp_worker_chain_1780534531
inspect after apply saw comment="mcp worker chain comment 1780534531"
metadata_after_apply.dirty=true
metadata_after_apply.dirty_state_method=apply_changes_mutation_flag
cleanup reached ida_terminate_done
```

Coverage confirmed by this run:

```text
MCP server execute_idapython entrypoint
GUI /metadata source context
saved clean IDB/I64 fingerprint
headless IDA worker launch
worker user script from checked-in source file
ChangeRecorder generated ChangeSet
apply_worker_changes dry-run through MCP server
GUI /apply_changes dry-run no-op
apply_worker_changes destructive through MCP server
GUI /apply_changes destructive replay
/inspect_address verified GUI mutation
metadata dirty state changed after destructive replay
```

Notes:

- The guest payload code is checked in as `src/ida_script_mcp/payload/guest_worker_chain_payload.py`, and the worker script is checked in as `src/ida_script_mcp/payload/worker_chain_user_script.py`; the workflow transports generated script text, but the core test logic is reviewable and locally checked.
- Two implementation issues were found and fixed before U001 passed: guest Python lacked `pydantic`, and IDA 8.3 exposed `idc.SetType` but not `idc.set_type` in the worker.
- U002/U003 are now covered by dedicated workflow runs.


## 2026-06-04 U002：worker hard timeout / kill process tree

Evidence:

- Workflow run: `26923418555`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/testing-handoff-tracker-20260604-bf55c1` / `0f689dc805cca38c64296645984877e92228c8ca`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7400538789`
- Files inspected: `controller_state.json`

Inputs:

```text
task_action=ida_plugin_worker_timeout_test
ida_timeout_seconds=240
run_timeout_seconds=600
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
controller_state.status=success
controller_state.payload_downloaded=true
guest result status=completed
guest result exit_code=0
payload mode=worker_timeout
payload status=passed
execute_idapython_timeout.status=timeout
execute_idapython_timeout.isolated=true
execute_idapython_timeout.timeout_seconds=2
execute_idapython_timeout.error.type=WorkerHardTimeout
execute_idapython_timeout.error.message="Worker exceeded hard timeout of 7 seconds"
execute_idapython_timeout.hard_timeout=true
execute_idapython_timeout.killed=true
execute_idapython_timeout.worker_pid=5492
execute_idapython_timeout.worker_exit_code=1
worker_timeout_summary.worker_process_alive_after_kill=false
worker_timeout_summary.sentinel_seen=true
execute_idapython_timeout.changes=[]
metadata_before.dirty=false
metadata_after_timeout.dirty=false
metadata_after_timeout.apply_changes_mutated=false
cleanup reached ida_terminate_done
```

Coverage confirmed by this run:

```text
MCP server execute_idapython timeout path
headless worker process hard timeout
Windows taskkill process-tree cleanup path
worker PID recorded and gone after kill
blocking user script reached execution before kill
no ChangeSet generated on timeout
GUI database stayed clean after worker timeout
```

Notes:

- The worker timeout script is checked in as `src/ida_script_mcp/payload/worker_timeout_user_script.py` and writes a sentinel file before blocking in `time.sleep(999)`.
- Run `26923320696` first proved the timeout assertions but failed in final payload cleanup because `_read_process_pipes` had been accidentally dropped during refactor. Commit `0f689dc805cca38c64296645984877e92228c8ca` fixed that cleanup issue.
- U002/U003 are now covered by dedicated workflow runs.


## 2026-06-04 U003：worker failure-state matrix

Evidence:

- Workflow run: `26923830535`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/testing-handoff-tracker-20260604-bf55c1` / `fa086d2a61f318efb7c4e2dc1dd8d8b7784e55e0`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7400695878`
- Files inspected: `controller_state.json`

Inputs:

```text
task_action=ida_plugin_worker_failure_matrix_test
ida_timeout_seconds=240
run_timeout_seconds=600
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
controller_state.status=success
controller_state.payload_downloaded=true
guest result status=completed
guest result exit_code=0
payload mode=worker_failure_matrix
payload status=passed
worker_failure_matrix.worker_start_error.passed=true
worker_failure_matrix.worker_start_error.actual_status=worker_start_error
worker_failure_matrix.worker_start_error.error_type=IdaExecutableNotConfigured
worker_failure_matrix.worker_start_error.worker_pid=null
worker_failure_matrix.source_error.passed=true
worker_failure_matrix.source_error.actual_status=source_error
worker_failure_matrix.source_error.error_type=FileNotFoundError
worker_failure_matrix.source_error.worker_exit_code=0
worker_failure_matrix.worker_crashed.passed=true
worker_failure_matrix.worker_crashed.actual_status=worker_crashed
worker_failure_matrix.worker_crashed.error_type=WorkerResultMissing
worker_failure_matrix.worker_crashed.worker_exit_code=13
worker_failure_matrix.worker_result_missing.passed=true
worker_failure_matrix.worker_result_missing.actual_status=worker_result_missing
worker_failure_matrix.worker_result_missing.error_type=WorkerResultMissing
worker_failure_matrix.worker_result_missing.worker_exit_code=0
worker_failure_matrix.recorder_error.passed=true
worker_failure_matrix.recorder_error.actual_status=recorder_error
worker_failure_matrix.recorder_error.error_type=RecorderError
worker_failure_matrix.recorder_error.worker_exit_code=1
failure_matrix_dirty_apply.status=ok
failure_matrix_metadata_dirty.dirty=true
worker_failure_matrix.rejected.passed=true
worker_failure_matrix.rejected.actual_status=rejected
worker_failure_matrix.rejected.error_type=GuiDatabaseDirty
worker_failure_matrix.rejected.worker_pid=null
failure matrix all passed=true
cleanup reached ida_terminate_done
```

Coverage confirmed by this run:

```text
worker_start_error via invalid IDA_SCRIPT_MCP_IDA_PATH
source_error via missing script_path inside real headless worker
worker_crashed via checked-in os._exit(13) worker script
worker_result_missing via checked-in os._exit(0) worker script
recorder_error via checked-in invalid mcp_changes.patch_bytes call
rejected via dirty GUI database after explicit /apply_changes mutation
all cases returned structured ExecuteResult statuses
```

Notes:

- The failure scripts are checked in as:
  - `src/ida_script_mcp/payload/worker_crash_user_script.py`
  - `src/ida_script_mcp/payload/worker_result_missing_user_script.py`
  - `src/ida_script_mcp/payload/worker_recorder_error_user_script.py`
- Run `26923741508` first failed before any case executed because the nested `ExecuteParams` class referenced `script_path` with a same-name class attribute. Commit `fa086d2a61f318efb7c4e2dc1dd8d8b7784e55e0` fixed that issue.
- Core V2.3 worker lifecycle tests U001-U003 are now complete.


## 2026-06-04 U004：real MCP client end-to-end

Evidence:

- Workflow run: `26925268750`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/testing-handoff-tracker-20260604-bf55c1` / `2d8d24accc11209f49de07f35d17faa6991e96bd`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7401236989`
- Files inspected: `controller_state.json`, `result.json`, `hello.json`, `vmware_restore.json`

Inputs:

```text
task_action=ida_plugin_u004_real_mcp_client_test
ida_timeout_seconds=240
run_timeout_seconds=900
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
controller_state.status=success
controller_state.payload_downloaded=true
guest result status=completed
guest result exit_code=0
payload mode=u004_real_mcp_client
payload status=passed
guest python_version=3.11.7
U004 dependency install uses py -3.11 -m pip install -r requirements.txt --proxy http://192.168.1.249:10810 when MCP deps are missing
MCP stdio initialize protocolVersion=2025-11-25
MCP stdio serverInfo.name=ida_script_mcp
MCP stdio list_tools contains list_ida_instances/get_ida_database_info/list_functions/decompile_function/get_xrefs/execute_idapython/apply_worker_changes
execute_idapython input schema is wrapped under params and contains timeout_seconds
list_ida_instances count=1 and sees instance 4732_test1.dll on port 13338
get_ida_database_info returns dirty=false and database_sha256 is present
list_functions returns functions and target 0x180001000
decompile_function returns found=true and pseudocode/disassembly
get_xrefs returns a structured xrefs list
execute_idapython returns structured ExecuteResult status=timeout, error.type=WorkerHardTimeout, hard_timeout=true, killed=true
apply_worker_changes dry_run=true returns status=ok, applied=[], skipped=[comment op], errors=[]
MCP HTTP/SSE server starts on 127.0.0.1:8765 and receives GET /sse plus POST /messages requests
HTTP/SSE client list_ida_instances succeeds during payload execution
metadata_after_u004.dirty=false
```

Coverage confirmed by this run:

```text
real MCP stdio transport
real MCP HTTP/SSE transport
real MCP client initialize/list_tools/call_tool flow
real MCP input schema visibility and params wrapper
real MCP read-only tools against live GUI IDA plugin
real MCP execute_idapython tool returns structured result to client
real MCP apply_worker_changes dry-run tool call
U004 test scripts follow U00x naming convention
```

Notes:

- U004 payload source is checked in as `src/ida_script_mcp/payload/U004_real_MCP_client_end-to-end.py`.
- U004 helper worker script is checked in as `src/ida_script_mcp/payload/U004_real_MCP_client_worker_script.py`.
- The builder is `src/ida_script_mcp/payload/ida_u004_real_mcp_client_test.py`.
- The run closed U004 as a real client/transport/tool-result smoke. U001 remains the stronger test for successful worker-generated ChangeSet replay, because isolated worker execution from a separate stdio MCP server process still returns a structured hard-timeout result in this guest environment.


## 2026-06-04 U005：multi-IDA instance selection

Evidence:

- Workflow run: `26925755930`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/testing-handoff-tracker-20260604-bf55c1` / `8146b3c93efd8461e336156f3cb658302184bd2e`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7401401506`
- Files inspected: `controller_state.json`

Inputs:

```text
task_action=ida_plugin_u005_multi_ida_instance_test
ida_timeout_seconds=300
run_timeout_seconds=1200
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
controller_state.status=success
controller_state.payload_downloaded=true
guest result status=completed
guest result exit_code=0
payload mode=u005_multi_ida_instance_selection
payload status=passed
same-directory copy created: C:\Users\alion\Desktop\test1_u005_copy.dll
primary instance: 7388_test1.dll, database=test1.dll, port=13338
copy instance: 2328_test1_u005_copy.dll, database=test1_u005_copy.dll, port=13339
list_ida_instances.count=2
no selector rejects with "Multiple IDA instances found. Specify instance_id or port."
full primary instance_id selects primary port 13338 and dirty=false
full copy instance_id selects copy port 13339 and dirty=false
unique primary filename substring `test1.dll` selects primary
unique copy substring `u005_copy` selects copy
port selector 13339 selects copy
port takes precedence over conflicting instance_id and selects copy
ambiguous selector `test1` is rejected with "matched multiple instance ids"
missing selector `definitely_missing_u005_instance` is rejected with "not found"
list_functions by primary id returns functions and instance_id=7388_test1.dll
list_functions by copy substring returns functions and instance_id=2328_test1_u005_copy.dll
copied DLL cleanup removed the temporary same-directory copy
```

Coverage confirmed by this run:

```text
two IDA GUI processes running concurrently
same-directory DLL copy used for second database
instance registry lists multiple live processes
MCP server tool implementation rejects missing selector when multiple instances exist
full instance_id selection
unique substring instance_id selection
port selection
port-over-instance_id precedence
ambiguous substring rejection
missing instance rejection
selected instance carries through read-only tool results
```

Notes:

- U005 payload source is checked in as `src/ida_script_mcp/payload/U005_multi_IDA_instance_selection.py`.
- The builder is `src/ida_script_mcp/payload/ida_u005_multi_ida_instance_test.py`.
- This run uses direct server tool-function calls after U004 already verified real MCP transports. U005 focuses on multi-instance selector semantics and live IDA registry behavior.




## 2026-06-04 U006：`/functions` corner case

Evidence:

- Workflow run: `26925694907`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/u006-functions-corner-test-20260604-0b169c` / `231cd63172e974dad0a04b8eb5de036c230549a0`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7401369820`
- Files inspected: `controller_state.json`, `result.json`

Inputs:

```text
task_action=ida_plugin_api_test
ida_api_test_mode=functions_corner
ida_timeout_seconds=180
run_timeout_seconds=300
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
controller_state.status=success
controller_state.payload_downloaded=true
guest hello hostname=DESKTOP-QBSO5C3
guest python_version=3.11.7
guest result status=completed
guest result exit_code=0
payload mode=functions_corner
payload status=passed
IDA plugin instance=5264_test1.dll
IDA plugin port=13338
health.status=ok
metadata.dirty=false
functions_page.total=130
functions_limit_one.returned=1
functions_offset_beyond_total.returned=0
functions_offset_beyond_total.functions=[]
functions include-thunks/library matrix returned lists and respected limit=25
functions include-thunks/library totals were monotonic
functions segment=.text filter returned only .text functions
functions missing segment returned returned=0, functions=[]
functions name_contains=SUB_ matched case-insensitively
functions Unicode/special name_contains="\\u2603_unlikely_*[]" returned a valid empty page
functions numeric string params accepted offset="0", limit="2", include_thunks="false", include_library_functions="true"
functions limit=0 -> HTTP 400 field=limit error="limit must be >= 1"
functions limit=-1 -> HTTP 400 field=limit error="limit must be >= 1"
functions limit=5001 -> HTTP 400 field=limit error="limit must be <= 5000"
functions limit="not-an-int" -> HTTP 400 field=limit error="limit must be an integer"
functions offset=-1 -> HTTP 400 field=offset error="offset must be >= 0"
functions offset="not-an-int" -> HTTP 400 field=offset error="offset must be an integer"
functions name_contains=123 -> HTTP 400 field=name_contains
functions segment=123 -> HTTP 400 field=segment
functions include_thunks="not-bool" -> HTTP 400 field=include_thunks
functions include_library_functions="not-bool" -> HTTP 400 field=include_library_functions
cleanup reached ida_terminate_done
```

Coverage confirmed by this run:

```text
/functions segment filter
/functions include_thunks=false/true matrix
/functions include_library_functions=false/true matrix
/functions name_contains case-insensitive behavior
/functions name_contains Unicode/special-character input
/functions numeric string offset/limit and boolean string coercion
/functions limit lower/upper/type validation
/functions offset lower/type validation
/functions name_contains/segment type validation
/functions boolean flag type validation
```

Notes:

- First attempt `26925551740` proved all U006 assertions reached `api_tests_done status=passed`, but failed when final result stdout used `ensure_ascii=False` and Windows guest stdout used GBK, which could not encode `☃`. Commit `231cd63172e974dad0a04b8eb5de036c230549a0` fixed payload stdout by ASCII-escaping final/stage JSON while keeping UTF-8 files.
- This run covers `/functions` boundary semantics on `test1.dll`. Exact fixture-dependent cases still need dedicated binaries/databases: empty database / 0 functions, huge function-count pagination, duplicate function names, and demangled-name fixtures.

## 2026-06-04 U007：`/decompile` corner case

Evidence:

- Workflow run: `26926171098`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit tested: `gpt/u007-decompile-corner-case-20260604-4e30cb` / `4c6b04e495122fdd15c5c5160c601cc6da6ef5d5`
- Merged to handoff branch by merge commit: `9d1cd213d496a8f742d752aa9a22a38984037ea4`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7401525174`
- Files inspected: `result.json`, workflow run/job status

Inputs:

```text
task_action=ida_plugin_u007_decompile_corner_case_test
ida_timeout_seconds=180
run_timeout_seconds=600
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
guest result status=completed
guest result exit_code=0
payload status=passed
IDA plugin instance=8564_test1.dll
IDA plugin port=13338
primary function=OpenPerformanceData
primary function size=1099
/decompile by start address found=true, pseudocode present, disassembly present
/decompile by middle address found=true and resolves same function
/decompile by function name found=true and resolves same function
/decompile missing name returns found=false with structured error
/decompile invalid address returns found=false with structured error
/decompile address 0x0 returns found=false with structured no-function error
/decompile thunk/import-like function RegQueryValueExW found=true, is_thunk=true, pseudocode/disassembly present
/decompile largest observed function completed within timeout and returned disassembly
timings recorded for all U007 decompile probes
```

Coverage confirmed by this run:

```text
/decompile address at function start
/decompile address inside function body
/decompile name query
/decompile missing-name structured error
/decompile invalid-address structured error
/decompile address outside any function structured error
/decompile thunk/import-like function
/decompile largest observed function timing path
Hex-Rays available path returns pseudocode
read-only /decompile path leaves GUI database dirty=false
```

Known unobserved branches:

```text
Hex-Rays unavailable/no-license path was not observed because this guest had Hex-Rays available.
Per-function Hex-Rays failure while disassembly remains available was not observed in test1.dll.
Duplicate function-name ambiguity was not force-created in this read-only payload.
```

Notes:

- U007 payload builder is checked in as `src/ida_script_mcp/payload/ida_u007_decompile_corner_case_test.py`.
- U007 reuses the existing `ida_api_test` guest payload framework with `test_mode=decompile_corner_case`.
- This closes the practical `/decompile` read-only corner-case smoke for the current disposable VM + `test1.dll` baseline. The unobserved branches above remain listed in `UNTESTED.md` as environment/data-construction follow-ups.

## 2026-06-04 U013：patch_bytes complex cases

Evidence:

- Workflow run: `26926417574`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/testing-handoff-tracker-20260604-bf55c1` / `ac7cbab77c933ebb5119b7145a14e7f3307a5d1d`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7401627652`
- Files inspected: `controller_state.json`

Inputs:

```text
task_action=ida_plugin_u013_patch_bytes_complex_test
ida_timeout_seconds=240
run_timeout_seconds=600
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
controller_state.status=success
controller_state.payload_downloaded=true
guest result status=completed
guest result exit_code=0
payload mode=u013_patch_bytes_complex_cases
payload status=passed
IDA plugin instance=4648_test1.dll
IDA plugin port=13338
metadata_before.dirty=false
metadata_before.database_sha256=45982ab9a3d595e6380503c259e51bba2fa1728ca9f7321ac58187ff6ca9dd65
old_bytes mismatch op returned status=error and did not dirty the database
unmapped-only patch returned status=error and did not dirty the database
dry-run complex patch returned status=ok, applied=[], skipped=7, errors=[]
dry-run left original code bytes unchanged: 488d0dd958000048ff25da300000cccc
destructive partial apply returned status=partial
partial apply applied 6 patch_bytes operations
partial apply error op_id=op-unmapped-partial-stop
multi-byte code patch changed 488d0dd9 -> b772f226
middle-byte patch changed byte at target+5 from 00 -> ff
same-byte patch accepted new_bytes == old_bytes at target+12
repeat patch applied twice at target+10, ending at da
data/import patch changed byte at 0x180004000 from ff -> 00
after partial apply code bytes match expected b772f22658ff0048ff25da300000cccc
disassembly still refreshes after patch: mov     bh, 72h
metadata_after_partial.dirty=true
metadata_after_partial.dirty_state_method=apply_changes_mutation_flag
second destructive apply rejected when dirty
```

Coverage confirmed by this run:

```text
old_bytes_hex validation before patching
old_bytes mismatch failure without mutation
multi-byte patch
patch to middle/second byte of an instruction
same-byte patch where new_bytes == old_bytes
repeated patch to the same address in one ChangeSet
patch to data/import address
unmapped/invalid patch error path
partial apply semantics: earlier patch ops remain applied after later error
post-patch inspect_address bytes and disassembly refresh
metadata dirty state after destructive partial apply
second destructive apply rejected while dirty/unsaved
```

Notes:

- U013 payload source is checked in as `src/ida_script_mcp/payload/U013_patch_bytes_complex_cases.py`.
- The builder is `src/ida_script_mcp/payload/ida_u013_patch_bytes_complex_test.py`.
- This test added real GUI replay validation for `old_bytes_hex`; before this, `patch_bytes` did not check the old bytes before writing.
- The final invalid-address error is reported as an old-bytes mismatch because IDA byte getters return `ff` at the high test address; the key assertion is that the op fails before mutation and partial semantics are preserved.


## 2026-06-04 U009：/inspect_address 系统测试

Evidence:

- Workflow run: `26926388631`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/testing-u009-20260604-5b6c55` / `d1a0cde1502d6f76f3257a18275dba00b25ca64c`
- Base branch after merge target: `gpt/testing-handoff-tracker-20260604-bf55c1`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7401596027`
- Files inspected: `result.json` from artifact; workflow/job status from GitHub Actions

Inputs:

```text
task_action=ida_plugin_u009_inspect_address_test
ida_timeout_seconds=240
run_timeout_seconds=900
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
guest result status=completed
guest result exit_code=0
payload mode=inspect_address
payload status=passed
/inspect_address invalid address -> found=false with parse error
/inspect_address missing address/name -> found=false with structured error
byte_count=0/negative -> clamp to 1 and read one byte
byte_count huge -> clamp to 64 and return bounded bytes
data address 0x180004030 resolves and reads bytes
instruction-middle address 0x180001001 resolves and reads bytes
unmapped high address 0x4000000000000000 has no symbol/comment/type/disassembly metadata
unmapped high address all-ff bytes are treated as no real mapped bytes
name lookup returns the seeded target
Unicode regular/repeatable comments round-trip
Unicode function/repeatable function comments round-trip
type text is returned
metadata_after_u009.dirty=false
metadata_after_u009.apply_changes_mutated=false
```

Notes:

- IDA 8.3 normalized the requested Unicode symbol name to an ASCII fallback; Unicode comments/repeatable comments still round-trip.
- IDAPython returned `ffffffffffffffff` for a high unmapped address; U009 asserts no metadata and treats all-`ff` bytes as no real mapped bytes.
- Earlier U009 attempts and fixes are recorded in `DISPOSABLE_VM_WORKFLOW_LESSONS.md`.


## 2026-06-04 U012：set_type complex cases

Evidence:

- Workflow run: `26927371932`, attempt `1`
- Workflow: `Disposable VM guest agent smoke`
- Branch / commit: `gpt/test-u012-20260604-904ed5` / `d59cc0cc81c28566d65013c6a99ba98c8ebd86d8`
- Job: `Host controller and guest agent smoke`
- Runner: `HostMachine`
- Artifact: `disposable-vm-guest-agent-smoke`, artifact id `7401910040`
- Files inspected: `result.json`, workflow run/job status

Inputs:

```text
task_action=ida_plugin_u012_set_type_complex_test
ida_timeout_seconds=180
run_timeout_seconds=1800
connect_timeout_seconds=600
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

Assertions:

```text
workflow conclusion=success
guest result status=completed
guest result exit_code=0
payload mode=u012_set_type_complex
payload status=passed
worker idc_type_aliases.has_SetType=true
worker idc_type_aliases.has_set_type=false
worker-generated ChangeSet operation_count=3
operation_types=[set_type,set_type,set_type]
operation_decls preserve cdecl -> stdcall -> fastcall/function-pointer order
invalid C declaration returns status=error and leaves metadata dirty=false
dry-run status=ok, applied=[], skipped contains all 3 set_type operations
dry-run leaves target type unchanged
destructive replay status=ok, applied contains all 3 set_type operations, errors=[]
/inspect_address after destructive replay reports an inspectable __fastcall prototype with function-pointer argument
metadata dirty=true after destructive replay via apply_changes_mutation_flag
follow-up replay while dirty returns status=rejected with message about unsaved changes
cleanup reached ida_terminate_done
```

Coverage confirmed by this run:

```text
valid set_type replay for complex function prototypes
cdecl/stdcall/fastcall-style declarations
pointer, array, and function-pointer arguments
ordered overwrite of existing function type through repeated set_type operations
worker ChangeRecorder explicit_api set_type capture
GUI apply_changes set_type dry-run and destructive replay
IDA 8.3 idc.SetType real path; idc.set_type absent in this VM
invalid C declaration failure path via IDC type API and ida_typeinf.apply_cdecl failure
dirty database replay guard after destructive apply
```

Notes:

- U012 payload entry is exposed as `ida_plugin_u012_set_type_complex_test` in `.github/workflows/disposable-vm-guest-agent-smoke.yml`.
- The worker script is checked in as `src/ida_script_mcp/payload/u012_set_type_complex_worker_script.py`.
- The generated guest payload logic lives in `src/ida_script_mcp/payload/guest_worker_chain_payload.py` under mode `u012_set_type_complex`.
- Two failed attempts refined the expected assertions before the passing runs:
  - `26926180741`: non-function-address assumption was wrong; IDA 8.3 accepted `set_type` at `ea=1` when the database was clean.
  - `26926363238`: after destructive replay, the follow-up non-function probe was rejected because the GUI database was dirty; this is the correct replay guard behavior and is now asserted.
- Run `26926517859` first passed U012 at commit `5bc828b6b78b4618aaebba2227f298e928cf4a7f`; run `26927371932` re-ran the same VM test after documentation migration at commit `d59cc0cc81c28566d65013c6a99ba98c8ebd86d8`.
- Remaining unverified variants include thiscall/vectorcall-specific declarations and struct/enum/typedef dependency declarations.

## 移入规则

只有满足以下条件才把 `UNTESTED.md` 的条目移到本文件：

1. 有明确证据：workflow run ID、本地命令输出、artifact 内容、日志片段或 CI job 名称。
2. 写清楚测试输入，尤其是 workflow inputs、IDA 路径、DLL 路径、模式和是否 destructive。
3. 写清楚断言：返回状态、HTTP status、artifact/result 字段、数据库 dirty 状态、是否有残留进程。
4. destructive 测试必须说明是否只操作临时数据库。
5. 失败项不要移入本文件，继续保留在 `UNTESTED.md`，并把失败总结写入 `DISPOSABLE_VM_WORKFLOW_LESSONS.md`。
