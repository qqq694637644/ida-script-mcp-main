# Disposable VM guest agent smoke implementation

This document describes the first host-controller / guest-agent implementation
for the disposable VM test architecture.

## Repository layout

```text
src/ida_script_mcp/disposable_vm/
  host_controller.py        # host-side one-shot FastAPI controller

src/ida_script_mcp/guest_vm/
  agent.py                  # guest-side client agent
  required_imports.py       # guest snapshot dependency import check
  requirements.txt          # guest snapshot pip requirements

src/ida_script_mcp/payload/
  disposable_vm.py          # shared JSON protocol models
```

The host remains the only GitHub Actions runner. The guest agent is only a
client and never registers as a GitHub runner.

## Machine dependency model

Guest VM is the only machine that needs manual dependency preparation before a
snapshot is taken. HostMachine is not snapshotted, so the host controller checks
its own host-only runtime imports and installs missing packages before starting.

## HostMachine dependencies

No host-only module needs to be baked into a snapshot. The workflow installs the
project package itself, then the host controller detects these host runtime
imports and installs them with pip if missing:

```text
fastapi>=0.115.0
uvicorn>=0.30.0
```

The automatic install can be disabled for debugging with either:

```powershell
$env:IDA_SCRIPT_MCP_VM_HOST_AUTO_INSTALL = "0"
```

or:

```powershell
--no-auto-install-deps
```

Manual host preinstall remains possible but is not required:

```powershell
py -3 -m pip install -e ".[disposable-vm-host]"
```

## Guest VM snapshot dependencies

Install these inside the guest VM Python 3.11.7 environment before taking the
clean snapshot:

```text
requests>=2.32.0
```

Install from the checked-out repository:

```powershell
py -3.11 -m pip install -r src\ida_script_mcp\guest_vm\requirements.txt
```

Or install with the package extra:

```powershell
py -3.11 -m pip install -e ".[disposable-vm-guest]"
```

Before taking the snapshot, verify the exact imports the guest agent needs:

```powershell
py -3.11 -m ida_script_mcp.guest_vm.required_imports
```

The console entry point is also available after package installation:

```powershell
ida-script-mcp-vm-guest-check-imports
```

If the guest snapshot cannot install the whole repository package, copy the
agent plus `src/ida_script_mcp/guest_vm/requirements.txt` into the snapshot and
install `requests` in that Python 3.11.7 environment.

## Host controller example

```powershell
py -3 -m ida_script_mcp.disposable_vm.host_controller `
  --bind-host 0.0.0.0 `
  --port 8766 `
  --advertise-url http://<host-vmnet-ip>:8766 `
  --task-action noop `
  --connect-timeout-seconds 600 `
  --timeout-seconds 1800 `
  --result-dir "$env:RUNNER_TEMP\ida-script-mcp-disposable-vm" `
  --vmware-restore-script C:\Users\alion\Scripts\vmware_restore_test1.py `
  --vmware-restore-arg=--gui
```

The controller clears `RUNNER_TRACKING_ID` before invoking the VMware restore
script so the GitHub runner cleanup does not kill the VMware child process.

## Guest agent example

Inside the Windows guest snapshot with Python 3.11.7:

```powershell
py -3.11 -m ida_script_mcp.guest_vm.agent `
  --controller-url http://<host-vmnet-ip>:8766 `
  --guest-id ida-test-vm
```

The `--controller-url` value may also be passed as `<host-vmnet-ip>:8766`; the
agent normalizes a missing scheme to `http://` before calling the host.

For autostart, configure the same command in the snapshot. The agent also reads
`IDA_SCRIPT_MCP_CONTROLLER_URL`, `IDA_SCRIPT_MCP_GUEST_ID`,
`IDA_SCRIPT_MCP_GUEST_BOOT_ID`, and `IDA_SCRIPT_MCP_GUEST_WORK_ROOT`.

## Supported phase-1 / phase-2 task actions

`noop` proves connectivity and returns the guest Python version and executable.

`command` executes a list-form command without a shell. If no command is passed,
the host defaults to:

```json
["python", "--version"]
```

A custom command can be supplied as JSON:

```powershell
--task-action command --command-json '["python", "--version"]'
```

The workflow exposes the same command support through these inputs:

```text
task_action=command
command_json=["python", "--version"]
```

`python_script` downloads UTF-8 script text, writes it under the guest job
directory as `payload.py`, and executes it with the guest's current Python
interpreter.

## Host result files

The host controller writes these files under `--result-dir`:

```text
controller_state.json
hello.json
payload.json
guest_logs.ndjson
result.json
vmware_restore.json
controller_error.json
```

Not every file exists for every failure mode. For example, `hello.json` is absent
when the guest never connects.
