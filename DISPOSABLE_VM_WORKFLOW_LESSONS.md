# Disposable VM Workflow Lessons

Last updated: 2026-06-04

This document summarizes the workflow failures, fixes, and successful patterns discovered while building the HostMachine -> disposable guest VM -> IDA automation path.

Use this as the short operational memory after context compression.

## Current verified workflow path

The currently verified path is:

```text
GitHub workflow_dispatch
-> HostMachine self-hosted runner
-> host controller
-> VMware restore of guest snapshot `test1`
-> guest agent connects to controller
-> host dynamically sends Python payload
-> guest installs/updates IDA plugin
-> guest launches IDA 8.3 with C:\Users\alion\Desktop\test1.dll
-> IDA auto-analysis completes
-> IDA-Script-MCP HTTP server starts at 127.0.0.1:13338
-> guest payload tests plugin HTTP APIs from outside the IDA process
-> guest kills/terminates IDA in cleanup
-> guest returns result.json to host
-> workflow uploads artifacts and exits by guest exit code
```

Current stable inputs for IDA API smoke:

```text
task_action=ida_plugin_api_test
ida_api_test_mode=full
ida_timeout_seconds=180
run_timeout_seconds=300
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
controller_url=http://192.168.1.249:8766
run_vmware_restore=true
restore_extra_args_json=[]
```

## Success summary

### Verified phases

| Area | Status | Evidence |
| --- | --- | --- |
| Phase 1 connectivity | Passed | `26900876629` attempt 2 |
| Phase 2 command payload | Passed | `26902252502`, rerun `26902716245` |
| Phase 3 Python script payload | Passed | `26903071347` |
| IDA plugin install | Passed | initial `26903926544`, support-package layout `26907543538` |
| IDA API basic smoke | Passed | `26908653405` |
| IDA API full smoke + corner cases | Passed | `26909020426` |
| IDA API full smoke on merged `main` | Passed | `26921994480`, artifact `7400024008` |
| `apply_changes` destructive smoke | Passed | `26918788898` |
| `patch_bytes` destructive smoke | Passed | `26919752930` |
| U001 full V2.3 worker replay chain | Passed | `26922985347`, artifact `7400373325` |
| U002 worker hard timeout / kill process tree | Passed | `26923418555`, artifact `7400538789` |
| U003 worker failure-state matrix | Passed | `26923830535`, artifact `7400695878` |
| U006 `/functions` corner cases | Passed | `26925694907`, artifact `7401369820` |

### Final full-smoke coverage

Run `26909020426` verified these non-destructive plugin behaviors against `test1.dll`:

```text
/health
/metadata
/functions
/functions limit=1
/functions name filter
/functions offset beyond total -> returned=0, functions=[]
/decompile
/decompile invalid address -> found=false
/xrefs direction=to
/xrefs direction=from
/xrefs invalid direction -> structured error
/xrefs invalid xref_kind -> structured error
/execute -> HTTP 410, status=rejected
unknown route -> HTTP 404
```

The final payload completed in about 5.8 seconds. It did not hang, and it cleaned up IDA afterward.

Run `26921994480` repeated the full non-destructive smoke after the branch had been merged to `main`:

```text
workflow conclusion=success
runner=HostMachine
controller_state.status=success
payload_downloaded=true
guest hostname=DESKTOP-QBSO5C3
guest result status=completed
guest result exit_code=0
IDA plugin instance=8052_test1.dll
IDA plugin port=13338
heartbeat reached api_tests_done status=passed
artifact=disposable-vm-guest-agent-smoke / 7400024008
```

This confirms the merged `main` baseline still works for the non-destructive plugin HTTP API path. It does not close the remaining V2.3 worker-chain tests: `execute_idapython -> headless worker -> worker-generated ChangeSet -> apply_worker_changes`.

Run `26922985347` closed U001, the full V2.3 worker-chain test, against the disposable guest VM:

```text
workflow conclusion=success
runner=HostMachine
controller_state.status=success
guest result status=completed
guest result exit_code=0
payload mode=worker_chain
payload status=passed
execute_idapython.status=ok
execute_idapython.isolated=true
execute_idapython.worker_exit_code=0
worker ChangeSet operation_count=2
worker ChangeSet operation_types=[rename, comment]
apply_worker_changes dry-run status=ok, applied=[], skipped=2
apply_worker_changes destructive status=ok, applied=2, errors=[]
inspect after apply saw name=mcp_worker_chain_1780534531
inspect after apply saw comment="mcp worker chain comment 1780534531"
metadata_after_apply.dirty=true
metadata_after_apply.dirty_state_method=apply_changes_mutation_flag
artifact=disposable-vm-guest-agent-smoke / 7400373325
```

This verifies the important V2.3 boundary that worker-generated changes can be reviewed/dry-run and then explicitly replayed into the GUI database.

Run `26923418555` closed U002, the worker hard-timeout/kill-tree test:

```text
workflow conclusion=success
controller_state.status=success
guest result status=completed
guest result exit_code=0
payload mode=worker_timeout
payload status=passed
execute_idapython_timeout.status=timeout
execute_idapython_timeout.hard_timeout=true
execute_idapython_timeout.killed=true
execute_idapython_timeout.worker_pid=5492
execute_idapython_timeout.worker_exit_code=1
worker_timeout_summary.worker_process_alive_after_kill=false
worker_timeout_summary.sentinel_seen=true
execute_idapython_timeout.changes=[]
metadata_after_timeout.dirty=false
metadata_after_timeout.apply_changes_mutated=false
artifact=disposable-vm-guest-agent-smoke / 7400538789
```

This verifies the hard process timeout path and confirms the GUI database remains clean when a worker is killed.

Run `26923830535` closed U003, the worker failure-state matrix:

```text
workflow conclusion=success
controller_state.status=success
guest result status=completed
guest result exit_code=0
payload mode=worker_failure_matrix
payload status=passed
worker_start_error actual_status=worker_start_error error_type=IdaExecutableNotConfigured worker_pid=null
source_error actual_status=source_error error_type=FileNotFoundError worker_exit_code=0
worker_crashed actual_status=worker_crashed error_type=WorkerResultMissing worker_exit_code=13
worker_result_missing actual_status=worker_result_missing error_type=WorkerResultMissing worker_exit_code=0
recorder_error actual_status=recorder_error error_type=RecorderError worker_exit_code=1
rejected actual_status=rejected error_type=GuiDatabaseDirty worker_pid=null
failure_matrix_dirty_apply.status=ok
failure_matrix_metadata_dirty.dirty=true
artifact=disposable-vm-guest-agent-smoke / 7400695878
```

This verifies the main structured failure classifications for isolated worker execution.

Run `26925694907` covered U006, the main `/functions` corner-case semantics, after fixing a Windows console encoding issue found in run `26925551740`:

```text
workflow conclusion=success
controller_state.status=success
guest result status=completed
guest result exit_code=0
payload mode=functions_corner
payload status=passed
functions_page.total=130
functions include_thunks/include_library_functions 2x2 matrix passed
segment=.text filter returned only .text functions
missing segment returned returned=0, functions=[]
name_contains=SUB_ matched case-insensitively
Unicode/special name_contains="\\u2603_unlikely_*[]" returned a valid empty page
numeric string params accepted offset="0" and limit="2"
boolean strings accepted include_thunks="false" and include_library_functions="true"
limit=0/-1/5001/non-int returned HTTP 400 field=limit
offset=-1/non-int returned HTTP 400 field=offset
name_contains/segment non-string returned HTTP 400 with field names
invalid boolean flags returned HTTP 400 with field names
artifact=disposable-vm-guest-agent-smoke / 7401369820
```

Fixture-dependent `/functions` residuals remain: empty database / 0 functions, huge function-count pagination, duplicate function names, and demangled-name fixtures.

## Failure lessons and fixes

### 1. New workflow dispatch can be hard to trigger before GitHub indexes it

Symptom:

```text
workflow_dispatch returned 404 or 422 for a newly added workflow file / workflow id.
```

Lesson:

- A workflow file not yet registered on the default branch or not yet indexed by GitHub can fail API dispatch even if the file exists on the feature branch.
- Once GitHub indexed workflow id `288704375`, direct `workflow_dispatch` worked reliably.

Rule:

- Prefer dispatch by known workflow id once available.
- Avoid adding temporary push triggers unless there is no other path.
- If dispatch fails with 404/422, verify whether the workflow is indexed before changing unrelated logic.

### 2. `controller_url` must include an HTTP scheme

Symptom in guest:

```text
InvalidSchema: No connection adapters were found for '192.168.1.249:8766/hello'
```

Root cause:

- `requests` requires `http://` or `https://`.
- Ping/connectivity can be fine while the URL is still invalid.

Fix:

- Guest agent now normalizes `host:port` to `http://host:port`.

Rule:

- Always use `http://192.168.1.249:8766` in workflow inputs and manual tests.
- Keep guest-side URL normalization in place for operator mistakes.

### 3. Snapshot restore failures are separate from guest-agent failures

Symptoms:

```text
vmware_restore_test1.py --gui reported available snapshot `Snapshot 1`
but target snapshot `test1` was not found
```

and later:

```text
run_vmware_restore=false -> guest_connect_timeout
hello=null
payload_downloaded=false
```

Root cause:

- The restore script expected snapshot `test1`, but the VM snapshot name had changed.
- Skipping restore does not help if no guest agent is already running.

Fix:

- User restored snapshot name back to `test1`.
- Workflow gained `run_vmware_restore` and `restore_extra_args_json` for controlled troubleshooting.

Rule:

- If `controller_state.json` has `hello=null` and `payload_downloaded=false`, do not debug payload code first.
- Check VMware restore metadata, guest power state, and guest agent startup.
- Keep snapshot naming stable or pass explicit restore args only when the restore script supports them.

### 4. IDA support files must not live in the IDA `plugins` root

Symptoms in IDA log:

```text
ida_script_mcp_protocol.py: undefined function ... PLUGIN_ENTRY
ida_script_mcp_execution.py: undefined function ... PLUGIN_ENTRY
ida_script_mcp_change_protocol.py: undefined function ... PLUGIN_ENTRY
ida_script_mcp_change_recorder.py: attempted relative import with no known parent package
```

Root cause:

- IDA scans top-level `.py` files in the `plugins` directory as plugins.
- The support files were not plugins and should not have been installed beside `ida_script_mcp.py`.

Fix:

```text
plugins\ida_script_mcp.py
plugins\ida_script_mcp_support\__init__.py
plugins\ida_script_mcp_support\protocol.py
plugins\ida_script_mcp_support\execution.py
plugins\ida_script_mcp_support\change_protocol.py
plugins\ida_script_mcp_support\change_recorder.py
```

The installer and dynamic payload now also delete legacy root-level support files:

```text
ida_script_mcp_protocol.py
ida_script_mcp_execution.py
ida_script_mcp_change_protocol.py
ida_script_mcp_change_recorder.py
```

Rule:

- Only the real plugin entry file belongs in the IDA `plugins` root.
- Put helper modules in a package directory to avoid IDA scanning them as plugin entries.

### 5. Do not run HTTP client tests inside the IDA process

Old design:

```text
IDA bootstrap.py
-> starts plugin
-> starts tester thread inside IDA
-> tester thread calls HTTP server hosted in the same IDA process
-> qexit from inside IDA
```

Problem:

- This can hang or become hard to observe because the HTTP client, HTTP server, and IDA main-thread `execute_sync` all share the same process.
- When it hangs, HostMachine only sees a long-running IDA process.

Fix:

```text
IDA bootstrap.py
-> ida_auto.auto_wait()
-> starts plugin server
-> writes ida_ready.json

Guest payload outside IDA
-> waits for ida_ready.json
-> calls HTTP endpoints from outside the IDA process
-> writes heartbeat.ndjson
-> terminates/taskkills IDA in finally
```

Rule:

- Keep IDA bootstrap minimal.
- Put orchestration, timeouts, HTTP calls, and cleanup outside the IDA process.
- Treat `ida_ready.json` as the handoff point.

### 6. Every long-running stage needs heartbeat and short timeout

Symptoms before fix:

- Workflow looked stuck during IDA/API tests.
- It was hard to know whether IDA analysis, plugin startup, HTTP calls, or cleanup was blocked.

Fix:

- Default IDA API smoke timeout reduced to `180` seconds.
- Workflow run timeout for smoke reduced to `300` seconds in IDA API tests.
- Payload writes stage lines to `heartbeat.ndjson` and stdout as `IDA_API_STAGE=...`.
- Failure result includes `heartbeat_tail`, `ida_log_tail`, stdout/stderr tails, and failed exception.

Rule:

- First run `ida_api_test_mode=basic`.
- Only run `ida_api_test_mode=full` after basic passes.
- Do not add heavy endpoint coverage without endpoint-specific timeouts.

### 7. Validate generated payloads with executable tests, not only compile tests

Symptom:

```text
NameError: name 'HEARTBEAT_PATH' is not defined
```

Root cause:

- Generated script compiled, but a runtime path called `_stage()` before global paths were initialized.

Fix:

- Initialize `WORK_DIR`, `READY_PATH`, `HEARTBEAT_PATH`, `RESULT_PATH`, and `IDA_LOG_PATH` at module load time.
- Added a generated-payload execution test using a missing IDA directory. It ensures early failure still writes a structured `IDA_PLUGIN_API_TEST_RESULT` rather than crashing with missing globals.

Rule:

- For generated payloads, compile tests are not enough.
- Add at least one subprocess execution test for early failure paths.

### 8. External third-party IDA plugin warnings are not always our failures

Observed warning:

```text
Failed to register action 'patching:nop'
Failed to register action 'patching:revert'
...
```

Root cause:

- These messages come from another IDA plugin named `Patching`, not from `IDA-Script-MCP`.

Rule:

- Do not fail IDA-Script-MCP smoke because unrelated third-party plugin warnings appear.
- Do fail if `IDA-Script-MCP` support files produce `PLUGIN_ENTRY` or import errors.

### 9. Windows guest stdout may use GBK; escape non-ASCII JSON printed to console

Symptom in run `26925551740`:

```text
IDA_API_STAGE reached functions_corner_tests_done
api_tests_done status=passed
IDA_PLUGIN_API_TEST_ERROR={"type":"UnicodeEncodeError", "message":"'gbk' codec can't encode character '\\u2603' ..."}
```

Root cause:

- U006 intentionally sent a Unicode/special `name_contains` probe containing `☃`.
- The payload wrote UTF-8 result files correctly, but the final `print("IDA_PLUGIN_API_TEST_RESULT=" + json.dumps(..., ensure_ascii=False))` tried to write raw `☃` to a Windows console using GBK.

Fix:

- Keep artifact/result files as UTF-8.
- Use `ensure_ascii=True` for JSON printed to stdout/stderr (`IDA_API_STAGE`, `IDA_PLUGIN_API_TEST_RESULT`, `IDA_PLUGIN_API_TEST_ERROR`).

Rule:

- Payload console output must be transport-safe ASCII, because guest console encoding is not guaranteed to be UTF-8.
- Do not remove Unicode endpoint probes; escape them at the console boundary instead.

## Practical workflow rules for the next tests

### Start with the smallest mode

Use `basic` first:

```text
ida_api_test_mode=basic
ida_timeout_seconds=180
run_timeout_seconds=300
```

Then run `full`:

```text
ida_api_test_mode=full
ida_timeout_seconds=180
run_timeout_seconds=300
```

### Keep test categories separated

- Connectivity failures: inspect controller state and guest hello first.
- Restore failures: inspect `vmware_restore.json` first.
- Payload failures: inspect `result.json` stdout/stderr/error first.
- IDA behavior failures: inspect `ida_log_tail` and `heartbeat_tail` first.
- Plugin API failures: inspect `responses` and `checks` in `IDA_PLUGIN_API_TEST_RESULT`.

### Non-destructive tests are safe by default

The verified full smoke is non-destructive. It does not call `apply_changes` and it verifies GUI `/execute` is rejected by default.

### Destructive or database-mutating tests need a separate plan

Do not add `apply_changes` coverage to the standard full smoke yet. It needs:

```text
temporary database copy or disposable IDB
explicit expected fingerprint
operation-specific rollback/verification plan
assertions on dirty state and database identity
dedicated action/mode, not default full smoke
```

## Run index

| Run | Commit | Result | Note |
| --- | --- | --- | --- |
| `26906262507` | `37eee263...` | Failure | VMware restore failed; snapshot name mismatch. |
| `26906429830` | `b7f838e...` | Failure | Restore skipped; guest did not connect. |
| `26906631054` | `6bbcb9a...` | Failure | Guest ran payload; unresolved DLL placeholder caused `NameError`. |
| `26908467008` | `6fc23a4...` | Failure | External harness failed before IDA launch; `HEARTBEAT_PATH` not initialized. |
| `26907543538` | `5e8860e...` | Success | Support package layout install verified. |
| `26908653405` | `f5e7c7b...` | Success | Basic IDA API smoke passed in about 5.2s. |
| `26908795266` | `a2ed1d3...` | Success | Full IDA API smoke passed before extra corner checks. |
| `26909020426` | `bbe8e51...` | Success | Full IDA API smoke passed with extra non-destructive corner checks. |
| `26921994480` | `e7b00f0...` | Success | Merged `main` full non-destructive IDA API smoke passed; artifact `7400024008`. |
| `26922753371` | `fea522e...` | Failure | U001 first attempt failed before worker-chain execution because guest Python lacked `pydantic` for server import. |
| `26922885587` | `98f3768...` | Failure | U001 second attempt reached headless worker; recorder failed on IDA 8.3 `idc.set_type` alias mismatch. |
| `26922985347` | `2df76f5...` | Success | U001 full worker-chain passed; artifact `7400373325`. |
| `26923320696` | `192dd45...` | Failure | U002 timeout assertions passed, but payload cleanup failed because `_read_process_pipes` helper was missing. |
| `26923418555` | `0f689dc...` | Success | U002 worker hard-timeout/kill-tree passed; artifact `7400538789`. |
| `26923741508` | `409ced2...` | Failure | U003 payload failed before first matrix case due nested class `script_path` name resolution. |
| `26923830535` | `fa086d2...` | Success | U003 worker failure-state matrix passed; artifact `7400695878`. |
| `26925551740` | `df09bff...` | Failure | U006 assertions passed, then final stdout failed on GBK `UnicodeEncodeError` for `☃`. |
| `26925694907` | `231cd63...` | Success | U006 `/functions` corner-case mode passed; artifact `7401369820`. |

## Current conclusion

The workflow is now reliable for non-destructive IDA plugin installation and API testing against:

```text
IDA: C:\Users\alion\Desktop\IDAPro8.3
DLL: C:\Users\alion\Desktop\test1.dll
Guest Python: 3.11.7
```

Destructive GUI `/apply_changes`, the full V2.3 MCP worker-chain replay, worker hard-timeout/kill-tree behavior, the U003 worker failure-state matrix, and the U006 `/functions` main corner-case semantics are now verified separately.

The remaining backlog starts after the core V2.3 worker lifecycle work. Next likely areas are:

```text
U004 real MCP client end-to-end
U005 multi-IDA instance selection
U006R fixture-dependent `/functions` residuals
apply_changes/read-only endpoint corner cases
```
