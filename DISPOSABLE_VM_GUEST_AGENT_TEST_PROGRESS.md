# Disposable VM Guest Agent Test Progress

Last updated: 2026-06-04

This file is intentionally kept in the repository root so work can continue after context compression.

## Current focus

Detailed functional testing for the V2.3 isolated-execution related IDA plugin behavior through the disposable guest VM path.

The active guest test binary is:

```text
C:\Users\alion\Desktop\test1.dll
```

The active guest IDA directory is:

```text
C:\Users\alion\Desktop\IDAPro8.3
```

## Verified before this test batch

- Phase 1 connectivity smoke: workflow_dispatch success.
- Phase 2 command smoke: `python --version`, workflow_dispatch success.
- Phase 3 Python script payload smoke: workflow_dispatch success.
- Dynamic IDA plugin install smoke: workflow_dispatch success.
- Guest IDA plugin install result confirmed:
  - plugin directory: `C:\Users\alion\AppData\Roaming\Hex-Rays\IDA Pro\plugins`
  - installed files: `ida_script_mcp.py`, `ida_script_mcp_protocol.py`, `ida_script_mcp_execution.py`, `ida_script_mcp_change_protocol.py`, `ida_script_mcp_change_recorder.py`
  - install manifest written: `ida_script_mcp_install_manifest.json`

## New test target: `ida_plugin_api_test`

New workflow action being implemented:

```text
task_action=ida_plugin_api_test
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
```

The host dynamically generates a guest-side Python payload. The guest-side payload must:

1. Install/update the plugin files from the current repository content.
2. Start IDA against `test1.dll` with an IDAPython bootstrap.
3. Wait for IDA auto-analysis with `ida_auto.auto_wait()`.
4. Start the `IDA-Script-MCP` plugin HTTP server.
5. Test actual plugin HTTP endpoints from a non-main thread so `idaapi.execute_sync` calls can be serviced by IDA's main thread.
6. Write structured result JSON and exit IDA.
7. Return the result through the existing guest-agent `/result` path.

## Endpoint checks planned in first run

- `GET /health`
  - HTTP 200
  - plugin name is `IDA-Script-MCP`
- `GET /metadata`
  - HTTP 200
  - includes input file path
  - includes database path key
  - includes dirty-state key
- `POST /functions`
  - HTTP 200
  - returns a list
  - returns at least one function for `test1.dll`
  - pagination limit is respected
  - name filter is accepted when a function name is available
- `POST /decompile`
  - HTTP 200
  - selected function resolves with `found=true`
  - disassembly list is present when `include_disassembly=true`
  - invalid address returns structured `found=false`
  - Hex-Rays pseudocode is optional; warning is accepted if decompiler/license is unavailable
- `POST /xrefs`
  - HTTP 200
  - selected target resolves for `direction=to`
  - selected target resolves for `direction=from`
  - xrefs fields are lists; empty lists are allowed
  - invalid direction returns a structured error
- `POST /execute`
  - HTTP 410 by default
  - response status is `rejected`
  - proves GUI arbitrary execute is disabled as required by V2.3
- unknown route
  - HTTP 404 with error body

## Corner cases not yet complete

These must be covered before claiming full completion:

- Missing `dll_path` returns a clear failure.
- Missing `ida_dir` returns a clear failure.
- Missing IDA executable under `ida_dir` returns a clear failure.
- IDA process timeout returns a clear failure and includes log tails.
- Plugin server port collision auto-increments and endpoints are still reachable.
- `/functions` with offset beyond total returns an empty page without failure.
- `/decompile` on invalid address returns structured not-found without crashing.
- `/xrefs` invalid direction and invalid kind return structured errors.
- `/execute` remains rejected unless unsafe env var is explicitly set.
- No auto-apply behavior is reachable through public execute path.
- If future tests exercise `apply_changes`, they must avoid destructive writes unless explicitly requested and must validate database fingerprint behavior.
- IDA cleanup after test: no stale IDA process should remain.
- Result artifacts must include enough detail to debug analysis/plugin failures.

## Current implementation status

- `src/ida_script_mcp/payload/ida_api_test.py` added locally.
- Workflow action `ida_plugin_api_test` added locally.
- Local unit tests for generated payload compilation pass.
- First real workflow_dispatch run reached HostMachine but failed before guest connection due VMware snapshot restore mismatch.

## Real workflow runs

### Run 26906262507 attempt 1

```text
Run URL: https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26906262507
Commit: 37eee263d82e100ea9c55368a1a34c37bc4c491a
Inputs: task_action=ida_plugin_api_test, ida_dir=C:\Users\alion\Desktop\IDAPro8.3, dll_path=C:\Users\alion\Desktop\test1.dll
Conclusion: failure
Artifact ID: 7393959742
Result summary: host controller started, but VMware restore script returned 1 before guest connected.
Failure: vmware_restore_test1.py --gui reported available snapshot `Snapshot 1` but target snapshot `test1` was not found.
Next action: workflow now supports run_vmware_restore=false and restore_extra_args_json so IDA API payload can be tested against an already-running guest or with restore-script-specific extra args.
```

### Run 26906429830 attempt 1

```text
Run URL: https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26906429830
Commit: b7f838e05eae1cc9ef16f6c0de3e1dc62b33f687
Inputs: task_action=ida_plugin_api_test, run_vmware_restore=false, connect_timeout_seconds=90, ida_dir=C:\Users\alion\Desktop\IDAPro8.3, dll_path=C:\Users\alion\Desktop\test1.dll
Conclusion: failure
Artifact ID: 7394059553
Result summary: controller started and waited for an already-running guest, but no guest connected.
Failure: controller_state.json status=guest_connect_timeout, hello=null, payload_downloaded=false.
Next action: restore/start guest VM is required before the IDA API payload can execute. The VMware snapshot currently visible to the restore script is `Snapshot 1`, while the script targets `test1`; either restore/rename the VM snapshot to `test1`, or provide restore script arguments that select `Snapshot 1` if the script supports that.
```

### Run 26906631054 attempt 1

```text
Run URL: https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26906631054
Commit: 6bbcb9ad32ba2df26ded6f3f0470c50b591f934b
Inputs: task_action=ida_plugin_api_test, restore_extra_args_json=["--snapshot", "Snapshot 1"], ida_dir=C:\Users\alion\Desktop\IDAPro8.3, dll_path=C:\Users\alion\Desktop\test1.dll
Conclusion: failure
Artifact ID: 7394113496
Result summary: VMware restore using `--snapshot Snapshot 1` succeeded, guest connected, payload downloaded and result uploaded.
Failure: generated guest payload still contained unresolved placeholder `__BOOTSTRAP_DLL_PATH_JSON__` at top-level `DLL_PATH`, producing NameError before IDA launch.
Next action: fixed `src/ida_script_mcp/payload/ida_api_test.py` so top-level DLL_PATH uses `__DLL_PATH_JSON__`; added tests that generated payload contains no unresolved DLL/IDA placeholders.
```

Snapshot note: user reports the VMware snapshot name has been changed back to `test1`; next run should use default restore args with no `restore_extra_args_json` override.

## IDA plugin support-file loading issue

User-provided IDA log showed that `test1.dll` and Hex-Rays loaded, and the main
`IDA-Script-MCP` plugin loaded, but support files in the IDA `plugins` root were
also executed as standalone IDA plugins:

```text
ida_script_mcp_change_protocol.py: undefined function ...PLUGIN_ENTRY
ida_script_mcp_execution.py: undefined function ...PLUGIN_ENTRY
ida_script_mcp_protocol.py: undefined function ...PLUGIN_ENTRY
ida_script_mcp_change_recorder.py: attempted relative import with no known parent package
```

Root cause: dynamic install placed non-plugin support `.py` files directly under
the IDA `plugins` directory. IDA scans top-level `.py` files there as plugins.

Fix implemented locally:

```text
plugins\ida_script_mcp.py                         # only top-level plugin entry
plugins\ida_script_mcp_support\__init__.py
plugins\ida_script_mcp_support\protocol.py
plugins\ida_script_mcp_support\execution.py
plugins\ida_script_mcp_support\change_protocol.py
plugins\ida_script_mcp_support\change_recorder.py
```

The installer and dynamic payloads now remove legacy top-level support files:

```text
ida_script_mcp_protocol.py
ida_script_mcp_execution.py
ida_script_mcp_change_protocol.py
ida_script_mcp_change_recorder.py
```

Next validation: rerun `task_action=ida_plugin_install`, then rerun
`task_action=ida_plugin_api_test` only after the IDA startup log is clean.

## IDA API harness redesign

User manually confirmed `test1.dll` analysis is fast and the plugin starts HTTP
server quickly when IDA is opened manually. The hang risk is therefore not DLL
analysis; it is the old test harness running HTTP client code from inside the
same IDA process that also hosts the plugin server.

New harness design implemented locally:

```text
guest payload starts IDA with -S bootstrap.py
bootstrap.py only runs ida_auto.auto_wait(), loads/starts plugin, writes ida_ready.json
guest payload waits for ida_ready.json with a short ready timeout
guest payload, outside the IDA process, calls HTTP endpoints on 127.0.0.1
guest payload writes stage heartbeats to heartbeat.ndjson and stdout
guest payload terminates/taskkills IDA in finally block
default mode=basic, timeout=180 seconds
```

Basic mode currently covers:

```text
/health
/metadata
/functions
/functions limit=1
optional /functions name filter
```

Full mode keeps the existing heavier checks for `/decompile`, `/xrefs`, rejected
`/execute`, and 404 behavior, but should only run after basic mode is stable.

## Update protocol

After every real workflow run, append:

```text
Run URL:
Commit:
Inputs:
Conclusion:
Artifact ID:
Result summary:
Failures / next action:
```
