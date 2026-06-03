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
- `command` task 使用 list-form command，不通过 shell 执行。
- `python_script` task 会把 UTF-8 payload 写成 `payload.py` 并用 guest 当前 Python 执行。
- guest stdout/stderr 会截断为 tail 后回传，避免结果过大。

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

- workflow 当前目标是 Phase 1 connectivity smoke：
  - checkout repository
  - install project package on HostMachine
  - start host controller
  - restore/start VMware guest snapshot
  - wait for guest `/hello`
  - return no-op payload
  - wait for guest `/result`
  - upload logs/artifacts

### Tests

- 已新增 protocol / host controller / guest agent / guest dependency check 单元测试。
- 最新本地验证：

```text
py -3 -m pytest -q
112 passed

py -3 -m ruff check src tests
All checks passed
```

## 待实现

### Phase 1 实机验证

- 在 HostMachine self-hosted runner 上触发 `Disposable VM guest agent smoke` workflow。
- 确认 HostMachine 能启动 controller 并调用：

```powershell
C:\Users\alion\Scripts\vmware_restore_test1.py --gui
```

- 确认 guest snapshot 中的 agent 能自动启动并连接 host controller。
- 确认 guest 返回 `exit_code=0`，并在 workflow artifact 中保存：
  - `controller_state.json`
  - `hello.json`
  - `payload.json`
  - `guest_logs.ndjson`
  - `result.json`
  - `vmware_restore.json`

### Guest snapshot preparation

- 在 guest VM Python 3.11.7 中手动安装：

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

### Phase 2: simple command

- 用 workflow 下发 `command` task。
- 首个命令建议：

```json
["python", "--version"]
```

- 验收：guest 返回 Python version、stdout/stderr、`exit_code=0`。

### Phase 3: Python script payload

- 下发 UTF-8 Python script payload。
- guest 写入 per-job directory。
- guest 用 Python 3.11.7 执行 payload。
- host 收集 stdout/stderr/result metadata。

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
