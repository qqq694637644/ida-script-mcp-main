# IDA Script MCP

IDA Script MCP connects AI assistants to IDA Pro databases through the Model Context Protocol (MCP). The current branch is a breaking, security-focused rewrite that keeps common reverse-engineering reads simple while moving custom IDAPython queries and database mutations behind headless isolated execution, process-level hard timeouts, explicit replay, fingerprint checks, and real IDA workflow tests.

This README describes the current PR branch, not the older 1.1-era README.

## What this version solves

Earlier versions allowed a convenient but risky pattern: run arbitrary IDAPython directly in the GUI IDA process and optionally apply changes from that execution path. That made it hard to reason about database state, dirty/unsaved databases, worker failures, and repeatability.

The current version solves that by adding a V2.3 isolated execution design and a disposable-VM integration test pipeline:

- **Public `execute_idapython` is isolated-only.** It copies a saved clean IDB/I64 database and runs query/execution code in a separate headless IDA worker process with a hard process timeout. It does not fall back to GUI `/execute`.
- **GUI `/execute` is disabled by default.** The plugin returns HTTP 410 for GUI execute requests unless an explicit development escape hatch is enabled.
- **Only reviewed writes reach the GUI database.** Worker-side changes are represented as a structured `ChangeSet` and replayed through GUI `/apply_changes` or the MCP `apply_worker_changes` tool. Arbitrary user IDAPython query code itself does not execute in the GUI database.
- **Database identity is checked.** Replay uses a saved database SHA-256 fingerprint. Bad fingerprints are rejected.
- **Dirty/unsaved state is fail-closed.** If the GUI database is dirty or identity is unknown, destructive apply is rejected. On IDA 8.3 where some dirty APIs are unavailable, the plugin tracks an internal mutation flag after successful apply.
- **Dry-run is the default.** `/apply_changes` defaults to dry-run and must be explicitly called with `dry_run=false` to mutate the database.
- **IDA 8.3 behavior is handled.** The implementation accounts for real IDA 8.3/IDAPython differences around `patch_bytes`, `patch_byte`, function comments, and type application.
- **Plugin installation is clean.** Only the real plugin entry lives in the IDA `plugins` root. Support modules live in `ida_script_mcp_support/` so IDA does not treat helper files as plugins.
- **The workflow is tested against a real guest IDA.** A HostMachine workflow restores a disposable guest VM, dynamically sends payloads to a guest agent, opens IDA 8.3, loads `test1.dll`, starts the plugin, and verifies real endpoints and destructive apply behavior.

## Architecture

```text
AI client / MCP client
        |
        v
ida-script-mcp server
        |
        |  structured live reads:
        |    GUI plugin read-only endpoints (/metadata, /functions, /decompile, /xrefs)
        |
        |  custom IDAPython queries/execution:
        |    copy saved clean IDB/I64
        |    launch headless IDA worker process
        |    enforce hard process timeout / kill process tree
        |    collect result.json and optional ChangeSet
        |
        |  writes:
        |    apply_worker_changes -> GUI plugin /apply_changes
        |    verify fingerprint and dirty/unsaved state
        v
GUI IDA database is mutated only by explicit apply_changes replay
```

The important boundary is: **structured built-in reads are live read-only GUI endpoint calls; arbitrary/custom IDAPython query code runs in the headless worker copy; writes are explicit GUI replays.** The live GUI IDA process provides metadata and read-only structured analysis endpoints, and it applies reviewed changes, but it is not the execution sandbox for arbitrary query code.

The disposable VM test path adds:

```text
GitHub workflow_dispatch
-> HostMachine self-hosted runner
-> host controller
-> VMware snapshot restore
-> guest VM agent
-> dynamically generated Python payload
-> IDA 8.3 in guest
-> artifact/result upload
```

## MCP tools

| Tool | Purpose | Mutates IDA? |
| --- | --- | --- |
| `list_ida_instances` | Discover running IDA plugin instances. | No |
| `get_ida_database_info` | Read live GUI metadata, hashes, paths, dirty state, and instance info. | No |
| `list_functions` | Read live GUI function lists through the plugin's structured read endpoint. | No |
| `decompile_function` | Read live GUI Hex-Rays pseudocode and optional disassembly. | No |
| `get_xrefs` | Read live GUI xrefs to/from an address or symbol. | No |
| `execute_idapython` | Run IDAPython queries in a headless isolated worker database copy with a hard process timeout. | Worker copy only |
| `apply_worker_changes` | Preview or apply a worker `ChangeSet` to the GUI database. | Yes, only when `dry_run=false` |

The plugin also exposes localhost HTTP endpoints used by the MCP server and workflow tests. `/metadata`, `/functions`, `/decompile`, `/xrefs`, and `/inspect_address` are live read-only GUI endpoints. `/apply_changes` is the explicit GUI write replay endpoint. `/execute` is rejected by default.

```text
GET  /health
GET  /metadata
POST /functions
POST /decompile
POST /xrefs
POST /inspect_address
POST /apply_changes
POST /execute   # rejected by default in GUI mode
```

## Installation

### Runtime requirements

- IDA Pro 8.3+ with IDAPython 3.11 on the IDA side.
- Python 3.11+ for the MCP server package.
- The IDA plugin path itself does **not** require `pydantic` inside IDA's embedded Python; support modules use fallbacks where needed.

### Install from source

```powershell
git clone https://github.com/qqq694637644/ida-script-mcp-main.git
cd ida-script-mcp-main
py -3 -m pip install -e .
```

### Install the IDA plugin

After installing the Python package, install the plugin into IDA's **per-user**
plugin directory:

```powershell
py -3 -m ida_script_mcp.installer install
```

Equivalent console-script form:

```powershell
ida-script-mcp-install install
```

or with a supported MCP client configuration:

```powershell
ida-script-mcp-install install codex
ida-script-mcp-install install claude,codex,cursor
ida-script-mcp-install install --project codex
ida-script-mcp-install --list-clients
```

The installer chooses the IDA user directory automatically:

```text
Windows: %APPDATA%\Hex-Rays\IDA Pro
macOS/Linux: ~/.idapro
```

The current installer layout is:

```text
<IDA user dir>/plugins/ida_script_mcp.py
<IDA user dir>/plugins/ida_script_mcp_support/__init__.py
<IDA user dir>/plugins/ida_script_mcp_support/protocol.py
<IDA user dir>/plugins/ida_script_mcp_support/execution.py
<IDA user dir>/plugins/ida_script_mcp_support/change_protocol.py
<IDA user dir>/plugins/ida_script_mcp_support/change_recorder.py
```

On a normal Windows IDA install this means files like:

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_script_mcp.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_script_mcp_support\protocol.py
```

The installer tries to use symlinks when possible and falls back to copying when
symlinks are unavailable. It also removes old root-level support files such as
`ida_script_mcp_protocol.py`, because IDA scans root-level `plugins/*.py` files
as plugin entrypoints.

Restart IDA after installation, then open a database and enable the plugin from
**Edit -> Plugins -> IDA-Script-MCP**. The installer prints the same reminder:

```text
Installed IDA Pro plugin (IDA restart required)
  To enable: Edit -> Plugins -> IDA-Script-MCP (Ctrl+Alt+S)
```

To uninstall the IDA plugin later:

```powershell
ida-script-mcp-install uninstall
```

If installation fails, check that you are using **IDA Pro** rather than IDA Free;
IDA Free does not support plugins.

Manual fallback: copy `src/ida_script_mcp/ida_plugin.py` to
`<IDA user dir>/plugins/ida_script_mcp.py`, create
`<IDA user dir>/plugins/ida_script_mcp_support/`, and copy these support files
from `src/ida_script_mcp/` into that support package:

```text
protocol.py
execution.py
change_protocol.py
change_recorder.py
```

Do **not** place those support files directly in the `plugins` root.

## Starting the plugin

1. Open IDA Pro and load a database.
2. Start **Edit -> Plugins -> IDA-Script-MCP** or use the plugin hotkey if configured.
3. IDA prints the instance id and endpoints.

Example log:

```text
[IDA-Script-MCP] Plugin loaded (supports multiple instances)
[IDA-Script-MCP] Registered instance: 3396_test1.dll
[IDA-Script-MCP] Server started at http://127.0.0.1:13338
[IDA-Script-MCP] Metadata endpoint: GET http://127.0.0.1:13338/metadata
[IDA-Script-MCP] Functions endpoint: POST http://127.0.0.1:13338/functions
[IDA-Script-MCP] Decompile endpoint: POST http://127.0.0.1:13338/decompile
[IDA-Script-MCP] Xrefs endpoint: POST http://127.0.0.1:13338/xrefs
[IDA-Script-MCP] Inspect address endpoint: POST http://127.0.0.1:13338/inspect_address
[IDA-Script-MCP] Execute endpoint disabled by default; use isolated worker execution
[IDA-Script-MCP] Apply changes endpoint: POST http://127.0.0.1:13338/apply_changes
```

## Starting the MCP server

```powershell
ida-script-mcp
```

Useful options:

```powershell
ida-script-mcp --ida-host 127.0.0.1 --ida-port 13338
ida-script-mcp --ida-instance 3396_test1.dll
ida-script-mcp --transport http --port 8765
```

The default MCP transport is stdio.

## Recommended LLM workflow

1. Run `list_ida_instances` when more than one IDA database may be open.
2. Run `get_ida_database_info` before making assumptions about the active database.
3. Use structured read-only tools first: `list_functions`, `decompile_function`, `get_xrefs`. These read the live GUI database through read-only plugin endpoints.
4. Use `execute_idapython` for long-tail custom IDAPython queries. This path runs in a headless isolated copied database with a process-level timeout.
5. If worker changes are collected, call `apply_worker_changes` first as dry-run.
6. Only call `apply_worker_changes` with `dry_run=false` after checking the fingerprint and confirming the GUI database is clean.

## `execute_idapython` behavior

`execute_idapython` is intentionally isolated and headless:

```text
GUI IDA metadata -> saved clean database fingerprint -> copied IDB/I64
-> headless IDA worker process -> hard timeout / process-tree kill
-> result.json -> optional ChangeSet
```

It can return statuses such as:

```text
completed
failed
rejected
worker_start_error
worker_crashed
worker_result_missing
recorder_error
timeout
```

Important rules:

- The public schema does not expose `in_process`, `isolation`, or `auto_apply` toggles.
- GUI `/execute` is rejected by default.
- Query code runs in the worker database copy. The GUI database is not changed by `execute_idapython` itself.
- Replay requires `apply_worker_changes` / `/apply_changes`.

## `apply_changes` behavior

`apply_changes` is the explicit replay path for database mutations. It supports structured operations such as:

```text
rename
comment
function_comment
set_type
patch_bytes
```

Core safety behavior:

- `dry_run` defaults to true.
- Bad database fingerprints are rejected.
- Dirty/unsaved GUI databases are rejected for destructive apply.
- After successful destructive apply, the plugin marks an internal mutation flag so later applies are rejected even when `idaapi.is_database_modified` is unavailable.
- `patch_bytes` treats IDA 8.3 `ida_bytes.patch_bytes()` returning `None` as success.
- `patch_byte` fallback does not treat return value `0` as a universal failure, because the target byte may already match.
- `function_comment` resolves the function object with `ida_funcs.get_func(ea)` before calling `set_func_cmt`.
- `set_type` falls back across `idc.set_type`, `idc.SetType`, and `ida_typeinf.apply_cdecl()` for IDA 8.3 compatibility.

`/inspect_address` is a read-only validation endpoint used by tests to verify names, comments, types, bytes, and disassembly after apply.

## Disposable VM workflow

The workflow file is:

```text
.github/workflows/disposable-vm-guest-agent-smoke.yml
```

It is manually triggered by `workflow_dispatch` and runs on the HostMachine self-hosted Windows runner. The host side starts a controller, restores the guest VM snapshot, waits for the guest agent, sends a dynamic payload, and uploads artifacts.

### Workflow actions

| `task_action` | Purpose |
| --- | --- |
| `noop` | Connectivity smoke. |
| `command` | Run a list-form command such as `["python", "--version"]`. |
| `python_script` | Send and run a generated Python script. |
| `ida_plugin_install` | Install/update the plugin in the guest IDA user plugin directory and verify layout. |
| `ida_plugin_api_test` | Open a DLL in guest IDA and test read-only plugin endpoints. |
| `ida_plugin_apply_changes_test` | Run destructive `apply_changes` smoke against a temporary IDA database. |

### Stable inputs used for the verified guest

```text
controller_url=http://192.168.1.249:8766
port=8766
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
run_vmware_restore=true
restore_extra_args_json=[]
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
ida_timeout_seconds=180
connect_timeout_seconds=600
```

For API smoke:

```text
task_action=ida_plugin_api_test
ida_api_test_mode=basic  # or full
run_timeout_seconds=300
```

For destructive apply smoke:

```text
task_action=ida_plugin_apply_changes_test
ida_api_test_mode=apply_changes
run_timeout_seconds=300
```

### Guest snapshot dependencies

Base guest agent snapshot:

```powershell
py -3.11 -m pip install -r src\ida_script_mcp\guest_vm\requirements.txt
py -3.11 -m ida_script_mcp.guest_vm.required_imports
```

Automation snapshot for GUI/process automation and API checks:

```powershell
py -3.11 -m pip install -r src\ida_script_mcp\guest_vm\automation_requirements.txt
py -3.11 -m ida_script_mcp.guest_vm.required_automation_imports
```

Current automation requirements:

```text
requests>=2.32.0
pywinauto>=0.6.8
psutil>=5.9.0
```

## Verified workflow results on PR #1

The current PR is open and mergeable as of the last verification notes. The following real workflow runs have passed on the disposable VM path.

| Area | Run | Result |
| --- | --- | --- |
| Connectivity / guest agent smoke | `26900876629` | success |
| Command payload | `26902252502`, rerun `26902716245` | success |
| Python script payload | `26903071347` | success |
| IDA plugin install | `26903926544`, package-layout run `26907543538` | success |
| IDA API basic smoke | `26908653405` | success |
| IDA API full smoke + corner cases | `26909020426` | success |
| `apply_changes` destructive smoke | `26918788898` | success |
| `patch_bytes` destructive apply at `DllEntryPoint` | `26919752930` | success |

### Read-only/full API coverage verified

Run `26909020426` verified:

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

### `apply_changes` coverage verified

Run `26918788898` verified:

```text
bad fingerprint is rejected
default dry-run does not modify the database
destructive apply applies rename/comment/function_comment/set_type
metadata dirty=true after destructive apply
dirty method=apply_changes_mutation_flag
second destructive apply is rejected because the database is dirty/unsaved
```

Run `26919752930` verified real destructive `patch_bytes` against a temporary IDA database created by the workflow:

```text
patch target: 0x180002308 / DllEntryPoint

before:
bytes_hex   = 48895c2408488974
disassembly = mov [rsp+arg_0], rbx

after destructive apply:
bytes_hex   = 90895c2408488974
disassembly = nop

operation:
op_id  = op-patch-byte
op     = patch_bytes
status = applied
```

This patch happens in the temporary workflow IDA database (`test1.i64`) and does not modify the original `test1.dll` file.

## Local validation reported for the latest apply_changes work

The apply_changes verification sequence reported:

```text
python -m ruff check .            # passed
python -m pytest -q               # 144 passed
python -m compileall -q src tests  # passed
git diff --check                  # passed
```

## Important safety notes

- The default read/API workflow is non-destructive.
- GUI `/execute` is rejected by default.
- Destructive apply tests are separate and explicitly named.
- Destructive workflow tests use a temporary IDA database generated by the workflow.
- The current patch-bytes test depends on the sample DLL having `DllEntryPoint` at `0x180002308`. If the DLL changes, parameterize or rediscover the patch target.
- Do not add new mutation behavior to the standard full smoke. Keep mutation tests in the `apply_changes` mode.

## Operational documents

The repository keeps two root workflow-memory documents:

```text
DISPOSABLE_VM_WORKFLOW_LESSONS.md
PORTABLE_WORKFLOW_DEVELOPMENT_LESSONS.md
```

`DISPOSABLE_VM_WORKFLOW_LESSONS.md` is project-specific operational memory for this HostMachine/guest/IDA setup.

`PORTABLE_WORKFLOW_DEVELOPMENT_LESSONS.md` is a project-agnostic playbook for building workflows that drive external machines, VMs, desktop applications, agents, and long-running integration targets.

## Development

Install dev dependencies:

```powershell
py -3 -m pip install -e .[dev]
```

Run local checks:

```powershell
py -3 -m pytest -q
py -3 -m ruff check src tests
py -3 -m compileall -q src tests
```

## Status

This branch has moved beyond unit-only validation. The disposable VM workflow has verified real IDA 8.3 plugin installation, read-only API behavior, negative cases, isolated execution safety boundaries, and destructive `apply_changes` replay including a real `patch_bytes` operation against a temporary IDA database.

The next major risk area is expanding destructive mutation tests beyond the current fixed sample and patch target while keeping database isolation, fingerprint checks, and rollback/cleanup guarantees explicit.
