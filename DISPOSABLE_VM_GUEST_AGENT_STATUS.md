# Disposable VM Guest Agent Status

Last updated: 2026-06-04

This file tracks the implementation status for the disposable VM guest-agent test harness.

## 已实现

### 目录结构

```text
src/ida_script_mcp/disposable_vm/
  host_controller.py

src/ida_script_mcp/guest_vm/
  agent.py
  required_imports.py
  requirements.txt

src/ida_script_mcp/payload/
  disposable_vm.py
```

### Host controller

- 一次性 host-side controller 已实现。
- 使用 FastAPI / uvicorn 提供本地 HTTP 控制接口。
- 已实现接口：
  - `POST /hello`
  - `GET /payload/{job_id}`
  - `POST /log/{job_id}`
  - `POST /result/{job_id}`
  - `GET /health`
- 支持 `noop`、`command`、`python_script` 三种 task action。
- `command` task 支持 JSON list-form command，例如 `["python", "--version"]`。
- 会在启动 VMware restore script 前清理 `RUNNER_TRACKING_ID`。
- 会把 controller state、hello、payload、guest logs、result、VMware restore metadata 写入 result directory。
- HostMachine 不需要提前做快照依赖准备；controller 会检测 host runtime imports，缺失时自动安装：
  - `fastapi>=0.115.0`
  - `uvicorn>=0.30.0`
- 可通过 `IDA_SCRIPT_MCP_VM_HOST_AUTO_INSTALL=0` 或 `--no-auto-install-deps` 禁用 host 自动安装。

### Guest agent

- guest-side client agent 已实现。
- guest 不监听端口，只主动连接 host controller。
- guest 不注册 GitHub runner，不持有 GitHub token。
- 支持启动后 `POST /hello`，下载 payload，执行任务，然后 `POST /result`。
- `noop` task 会返回 guest Python version 和 executable。
- `command` task 使用 list-form command，不通过 shell 执行，并回传 stdout/stderr tail、exit code 和 metadata。
- `python_script` task 会把 UTF-8 payload 写成 `payload.py` 并用 guest 当前 Python 执行。
- guest stdout/stderr 会截断为 tail 后回传，避免结果过大。
- `--controller-url` 支持 `http://host:port`，也支持省略 scheme 的 `host:port`；省略时自动补成 `http://`。

### Guest snapshot dependency files

- 已提供 guest 快照前手动安装依赖清单：

```text
src/ida_script_mcp/guest_vm/requirements.txt
```

- 当前 guest VM Python 3.11.7 需要预装：

```text
requests>=2.32.0
```

- 已提供 guest 依赖导入检查模块：

```powershell
py -3.11 -m ida_script_mcp.guest_vm.required_imports
```

- 已提供 console entry point：

```powershell
ida-script-mcp-vm-guest-check-imports
```

### Workflow

- 已新增手动触发 workflow：

```text
.github/workflows/disposable-vm-guest-agent-smoke.yml
```

- workflow 已支持 Phase 1 connectivity smoke：
  - checkout repository
  - install project package on HostMachine
  - start host controller
  - restore/start VMware guest snapshot
  - wait for guest `/hello`
  - return no-op payload
  - wait for guest `/result`
  - upload logs/artifacts

- workflow 已支持 Phase 2 simple command：
  - input `task_action=command`
  - input `command_json`, default `["python", "--version"]`
  - host controller 将 command payload 下发给 guest
  - guest 执行 list-form command 并回传 stdout/stderr/exit_code

- workflow 已支持 Phase 3 Python script payload：
  - input `task_action=python_script`
  - workflow 将内置 Phase 3 smoke script 写入 HostMachine 临时 payload file
  - host controller 使用 `--script-path` 读取 payload 并下发给 guest
  - guest 将 payload 写入 per-job directory 的 `payload.py` 并用 guest 当前 Python 执行
  - guest 回传 stdout/stderr/exit_code 和 metadata

### Phase 1 verification

- Phase 1 已在 HostMachine self-hosted runner 上通过 workflow_dispatch 实机验证。
- Verified run:

```text
https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26900876629
attempt 2
conclusion=success
runner=HostMachine
```

- 通过的步骤包括：
  - `Set up job`
  - `Check out repository`
  - `Install project package`
  - `Run disposable VM guest agent smoke`
  - `Upload disposable VM smoke logs`

### Phase 2 verification

- Phase 2 已在 HostMachine self-hosted runner 上通过 workflow_dispatch 实机验证。
- Verified run:

```text
https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26902252502
attempt 1
conclusion=success
runner=HostMachine
artifact=disposable-vm-guest-agent-smoke
```

- 验证输入：

```text
task_action=command
command_json=["python", "--version"]
controller_url=http://192.168.1.249:8766
```

- Artifact 中确认：
  - `payload.json` action 为 `command`
  - payload command 为 `["python", "--version"]`
  - `result.json` status 为 `completed`
  - `result.json` exit_code 为 `0`
  - `stdout_tail` 为 `Python 3.11.7\n`
  - guest hello python_version 为 `3.11.7`

### Tests

- 已新增 protocol / host controller / guest agent / guest dependency check 单元测试。
- 最新本地验证：

```text
py -3 -m pytest -q
116 passed

py -3 -m ruff check src tests
All checks passed
```

## 待实现

### Guest snapshot preparation automation

- 在 guest VM Python 3.11.7 中手动安装仍由操作者完成：

```powershell
py -3.11 -m pip install -r src\ida_script_mcp\guest_vm\requirements.txt
```

- 在 guest VM 中运行导入检查：

```powershell
py -3.11 -m ida_script_mcp.guest_vm.required_imports
```

- 配置 guest agent 开机自启。
- 确认 guest agent 使用的 controller endpoint 和 HostMachine VMware network 地址一致。
- 完成 clean snapshot 制作。

### Phase 3 实机验证

- 使用 workflow_dispatch 触发 `Disposable VM guest agent smoke`。
- 输入：

```text
task_action=python_script
controller_url=http://192.168.1.249:8766
```

- 验收：
  - payload action 为 `python_script`
  - guest 写入并执行 `payload.py`
  - guest result 包含 `stdout_tail` 中的 `phase3 script ok python=3.11.7`
  - guest result 包含 `exit_code=0`
  - workflow conclusion 为 success
  - artifact 中保存 `payload.json`、`result.json` 和 `guest_logs.ndjson`

### Phase 4: project deploy/test payload

- host 打包 repository/test payload。
- guest 解包并部署测试环境。
- guest 运行真实 IDA integration deployment/test steps。
- host 收集 logs/artifacts 并按 guest exit code 决定 workflow success/failure。

### 后续增强

- artifact upload endpoint / archive upload。
- 更严格的 payload integrity check。
- 更明确的 host VMware adapter selection 配置。
- guest agent Windows autostart 安装脚本。
- 超时、重试、日志 streaming 的实机调优。
- 多 guest pool scheduling 暂不实现。
