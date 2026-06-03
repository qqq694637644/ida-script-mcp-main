# Disposable VM guest agent smoke implementation

This document describes the first host-controller / guest-agent implementation
for the disposable VM test architecture.

## Repository layout

```text
src/ida_script_mcp/disposable_vm/
  host_controller.py        # host-side one-shot FastAPI controller

src/ida_script_mcp/guest_vm/
  agent.py                  # guest-side client agent

src/ida_script_mcp/payload/
  disposable_vm.py          # shared JSON protocol models
```

The host remains the only GitHub Actions runner. The guest agent is only a
client and never registers as a GitHub runner.

## Additional dependencies

Host controller dependencies:

```powershell
py -3 -m pip install -e ".[disposable-vm-host]"
```

This installs:

```text
fastapi>=0.115.0
uvicorn>=0.30.0
```

Guest agent dependencies for the Python 3.11.7 guest snapshot:

```powershell
py -3.11 -m pip install -e ".[disposable-vm-guest]"
```

This installs:

```text
requests>=2.32.0
```

If the guest snapshot cannot install the whole repository package, copy the
agent plus its package dependencies into the snapshot and install `requests` in
that Python 3.11.7 environment.

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

For autostart, configure the same command in the snapshot. The agent also reads
`IDA_SCRIPT_MCP_CONTROLLER_URL`, `IDA_SCRIPT_MCP_GUEST_ID`,
`IDA_SCRIPT_MCP_GUEST_BOOT_ID`, and `IDA_SCRIPT_MCP_GUEST_WORK_ROOT`.

## Supported phase-1 task actions

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
