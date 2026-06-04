# Testing handoff: disposable VM, IDA workflow, and V2.3 coverage tracker

Last updated: 2026-06-04

This file is the handoff entry point for the next AI/code maintainer. It explains the current testing architecture, the tested/untested tracking process, and the next tests to start. Keep this file concise and operational; put detailed failure lessons in `DISPOSABLE_VM_WORKFLOW_LESSONS.md`.

## Source-of-truth files

| File | Purpose |
| --- | --- |
| `README.md` | Product architecture and supported tools/endpoints. |
| `DISPOSABLE_VM_WORKFLOW_LESSONS.md` | Project-specific success/failure summary for HostMachine -> disposable VM -> IDA workflow. |
| `PORTABLE_WORKFLOW_DEVELOPMENT_LESSONS.md` | General workflow-development lessons and reusable rules. |
| `TESTED.md` | Items that already passed with evidence. |
| `UNTESTED.md` | Backlog of untested or partially tested items. |

## Product test architecture

The V2.3 product boundary is:

```text
AI client / MCP client
  -> ida_script_mcp.server
    -> GUI plugin structured read endpoints
    -> isolated headless IDA worker for arbitrary/custom IDAPython
    -> apply_worker_changes -> GUI plugin /apply_changes replay
```

Key safety rules to preserve while testing:

- Public `execute_idapython` must use isolated worker execution only. It must not fall back to GUI `/execute`.
- GUI `/execute` is rejected by default with HTTP 410 unless the explicit development escape hatch is enabled.
- The GUI database is read live through structured endpoints, but arbitrary user code runs in a copied saved IDB/I64 inside a headless worker.
- Worker-side changes become a structured `ChangeSet`; real GUI mutation happens only through `apply_worker_changes` / `/apply_changes`.
- `/apply_changes` defaults to dry-run and must reject dirty/unsaved/unknown identity/fingerprint mismatch cases.

Important runtime modules:

| Layer | Files | What to inspect first |
| --- | --- | --- |
| MCP server | `src/ida_script_mcp/server.py` | tool schema, instance resolution, metadata calls, `execute_idapython`, `apply_worker_changes` |
| GUI plugin | `src/ida_script_mcp/ida_plugin.py` | HTTP endpoints, metadata/fingerprint/dirty state, `/apply_changes`, `/execute` rejection |
| Isolated execution | `src/ida_script_mcp/isolated_manager.py`, `worker_runner.py`, `execution.py` | DB copy, IDA process launch, timeout/kill, result classification |
| Change protocol | `change_protocol.py`, `change_recorder.py` | `ChangeSet`, fingerprint matching, recorder monkeypatches, `mcp_changes` API |
| Disposable VM | `disposable_vm/host_controller.py`, `guest_vm/agent.py`, `payload/ida_api_test.py` | host/guest protocol, dynamic payloads, IDA bootstrap, artifacts |

## Disposable VM workflow architecture

The real integration workflow is external-machine based:

```text
GitHub workflow_dispatch
  -> HostMachine self-hosted Windows runner
    -> checkout repository
    -> install project package
    -> start host controller
      -> optional VMware restore of guest snapshot
      -> wait for guest /hello
      -> serve dynamic payload
      -> receive guest logs and result
    -> upload controller result directory as artifact
```

Guest VM side:

```text
guest agent starts from snapshot
  -> POST /hello to host controller
  -> GET /payload/{job_id}
  -> execute noop / command / python_script payload
  -> POST /log/{job_id}
  -> POST /result/{job_id}
```

IDA API payload side:

```text
guest python payload
  -> install/update IDA plugin files in guest IDA user plugin dir
  -> remove legacy root-level support files
  -> launch IDA 8.3 against C:\Users\alion\Desktop\test1.dll
  -> run IDA bootstrap with -S
  -> wait for ida_ready.json
  -> call plugin HTTP endpoints from outside IDA process
  -> write heartbeat.ndjson and result JSON
  -> terminate IDA in cleanup
```

Current stable workflow file:

```text
.github/workflows/disposable-vm-guest-agent-smoke.yml
```

Current stable manual-dispatch inputs for full non-destructive smoke:

```text
task_action=ida_plugin_api_test
ida_api_test_mode=full
ida_timeout_seconds=180
run_timeout_seconds=300
connect_timeout_seconds=600
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
restore_extra_args_json=[]
```

Current stable manual-dispatch inputs for destructive `apply_changes` smoke:

```text
task_action=ida_plugin_apply_changes_test
ida_api_test_mode=apply_changes
ida_timeout_seconds=180
run_timeout_seconds=300
connect_timeout_seconds=600
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
restore_extra_args_json=[]
```

## Tested / untested tracking protocol

Use the root tracker files exactly like a work queue:

1. Pick one item from `UNTESTED.md`. Prefer the current priority set U001-U003 unless blocked.
2. Run the smallest test that genuinely proves that item. For external-machine tests, record workflow run ID and artifact names.
3. If the test passes, remove the item from `UNTESTED.md` and append it to `TESTED.md` with evidence.
4. If the test fails, leave the item in `UNTESTED.md`; add the failure signature, root cause, and fix/next step to `DISPOSABLE_VM_WORKFLOW_LESSONS.md`.
5. Do not move partial results into `TESTED.md`; write them as notes under the original `UNTESTED.md` item or in the lessons file.
6. Do not call a workflow “passed” unless GitHub Actions result and guest `result.json` agree.

Use this evidence template when moving an item to `TESTED.md`:

```markdown
### YYYY-MM-DD - Uxxx title

Evidence:
- Workflow run: `<run_id>` / job `<job_name>` / attempt `<n>`
- Commit/branch: `<sha>` / `<branch>`
- Inputs: `<important workflow inputs>`
- Artifacts: `<artifact name>` contains `<files inspected>`

Assertions:
- `<status field or HTTP status>`
- `<database dirty/fingerprint condition>`
- `<process cleanup condition>`

Notes:
- `<risks or follow-up>`
```

## Next tests to start

Start with these, in order:

### 1. U001 full V2.3 worker replay chain

Goal:

```text
execute_idapython
-> headless IDA worker
-> ChangeRecorder generates ChangeSet
-> apply_worker_changes dry-run
-> apply_worker_changes destructive replay
-> inspect_address verifies GUI mutation
```

Why this is first: real `/apply_changes` has been proven, but the core V2.3 claim also requires proving that worker-generated changes can be replayed through the MCP layer.

Current gap: the existing disposable VM workflow can call plugin HTTP endpoints and run `apply_changes`, but it does not yet directly run the MCP `execute_idapython` tool path with current repository code inside the guest.

Suggested implementation approach:

```text
host workflow generates a new python_script payload
payload installs current plugin files
payload also makes current src/ida_script_mcp importable in the guest work dir
payload launches GUI IDA + plugin as ida_api_test does
payload sets IDA_SCRIPT_MCP_IDA_PATH to guest IDA idat/ida executable
payload calls ida_script_mcp.server.execute_idapython directly or through a real MCP client
worker script uses mcp_changes.rename/comment/patch_bytes or IDA monkeypatched APIs
payload calls apply_worker_changes first with dry_run=true
payload calls apply_worker_changes with dry_run=false
payload calls /inspect_address to verify changes
payload records result.json, heartbeat.ndjson, stdout/stderr tails
```

Do not mark U001 tested until the artifact proves both `changes` were produced by worker execution and GUI state changed only after explicit apply.

### 2. U002 worker hard timeout / kill process tree

Goal:

```text
execute_idapython(code='while True: pass', timeout_seconds=<small>)
-> result.status == timeout
-> hard_timeout == true
-> killed == true
-> no leftover worker IDA/idat process
```

Also inspect artifacts: stdout/stderr tails, result metadata, and job dir retention behavior if `IDA_SCRIPT_MCP_KEEP_JOBS=1` is used.

### 3. U003 worker failure-state matrix

Goal: construct real worker cases for:

```text
worker_start_error
worker_crashed
worker_result_missing
recorder_error
source_error
rejected
```

Keep this as a separate mode from U001/U002 so a crash test does not hide the result of the main chain.

## Existing workflow coverage and limits

The current workflow supports these `task_action` values:

```text
noop
command
python_script
ida_plugin_install
ida_plugin_api_test
ida_plugin_apply_changes_test
```

Use these for environment sanity checks and regression of already-proven behaviors. They are not enough by themselves to close U001 because they bypass MCP `execute_idapython` and call the plugin HTTP API directly.

## Artifact checklist for external-machine runs

Every external-machine run should produce or preserve:

```text
controller_state.json
hello.json
payload.json
guest_logs.ndjson
result.json
vmware_restore.json when restore is used
ida_api_test_result.json for IDA API payloads
heartbeat.ndjson for IDA payloads
ida_ready.json for IDA bootstrap
stdout/stderr tails
```

Debug order when a run fails:

```text
1. Was a workflow run created?
2. Was HostMachine runner allocated?
3. Did checkout/install pass?
4. Did host controller start?
5. Did VMware restore return 0?
6. Did guest /hello arrive?
7. Did guest download payload?
8. Did payload launch IDA?
9. Did ida_ready.json appear?
10. Which heartbeat stage was last?
11. Did guest POST /result?
12. Did workflow upload artifact?
```

## Rules for future AI maintainers

- Prefer minimal, evidence-driven changes. Do not add a broad workflow mode before a small targeted payload proves the failure domain.
- Keep destructive tests opt-in and never make them the default workflow mode.
- Keep test driver code outside the IDA process where possible; let IDA bootstrap only start plugin and write readiness.
- Use short layered timeouts and heartbeat stages before adding more coverage.
- Treat HostMachine paths and guest snapshot paths as environment-specific; document every assumption.
- If workflow dispatch fails with 404/422, check GitHub workflow indexing before changing YAML.
- If the guest never connects, debug restore/agent startup before payload code.
- If payload hangs after IDA launch, inspect `heartbeat.ndjson`, `ida_ready.json`, and IDA log tail before changing plugin code.
