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
  required_automation_imports.py
  requirements.txt
  automation_requirements.txt

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

### Guest automation snapshot dependency files

- 插件本身安装到 IDA 时不强制要求额外三方库；`ida_plugin.py` 和 support files 使用 Python stdlib 与 IDA 自带模块，`pydantic` 相关模型有 fallback。
- guest agent 连接 host controller 的最低三方库仍是 `requests>=2.32.0`。
- 后续“打开 IDA、等待分析完成、测试插件 HTTP API”的 automation snapshot 需要额外预装：

```text
src/ida_script_mcp/guest_vm/automation_requirements.txt
```

- 当前 automation snapshot 预装清单：

```text
requests>=2.32.0
pywinauto>=0.6.8
psutil>=5.9.0
```

- 主自动化库选择 `pywinauto`：用于 Windows GUI/process automation；功能 API 测试继续用 `requests` 调插件 HTTP endpoint；进程发现和清理由 `psutil` 辅助。
- 已提供 automation 导入检查模块：

```powershell
py -3.11 -m ida_script_mcp.guest_vm.required_automation_imports
```

- 已提供 console entry point：

```powershell
ida-script-mcp-vm-guest-check-automation-imports
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

- workflow 已支持 IDA plugin install smoke：
  - input `task_action=ida_plugin_install`
  - input `ida_dir`, default `C:\Users\alion\Desktop\IDAPro8.3`
  - HostMachine 动态读取当前仓库中的 `ida_plugin.py` 和 support files
  - HostMachine 生成 standalone guest-side install/verify Python payload
  - host controller 通过 `python_script` payload 将安装验证脚本下发给 guest
  - guest 验证 IDA directory 和 IDA executable，安装插件文件到 per-user IDA plugins 目录
  - guest 对安装文件做 SHA-256 校验、`py_compile` 校验和 standalone import 校验
  - guest 写入 `ida_script_mcp_install_manifest.json` 并回传 stdout/stderr/exit_code

- workflow 已支持 IDA DLL/plugin API smoke：
  - input `task_action=ida_plugin_api_test`
  - input `ida_dir`, default `C:\Users\alion\Desktop\IDAPro8.3`
  - input `dll_path`, default `C:\Users\alion\Desktop\test1.dll`
  - input `ida_api_test_mode`, default `basic`，可选 `full`
  - input `ida_timeout_seconds`, default `180`
  - HostMachine 动态生成 guest-side payload。
  - guest 安装/更新插件文件，启动 IDA 打开 DLL，等待 `ida_auto.auto_wait()`。
  - IDA 内 bootstrap 只负责启动插件并写 `ida_ready.json`。
  - guest 在 IDA 进程外测试实际 HTTP endpoints，避免 IDA 内部测试线程卡住。
  - 当前覆盖 `/health`、`/metadata`、`/functions`、`/decompile`、`/xrefs`、GUI `/execute` 禁用、未知路由 404。
  - 详细测试进度和 corner case 清单保存在根目录 `DISPOSABLE_VM_GUEST_AGENT_TEST_PROGRESS.md`。

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

### Phase 3 verification

- Phase 3 已在 HostMachine self-hosted runner 上通过 workflow_dispatch 实机验证。
- Verified run:

```text
https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26903071347
attempt 1
conclusion=success
runner=HostMachine
artifact=disposable-vm-guest-agent-smoke
```

- 验证输入：

```text
task_action=python_script
controller_url=http://192.168.1.249:8766
```

- Artifact 中确认：
  - `payload.json` action 为 `python_script`
  - `payload.json` script_text 包含内置 Phase 3 smoke script
  - guest metadata command 使用 Python 3.11.7 执行 per-job `payload.py`
  - `result.json` status 为 `completed`
  - `result.json` exit_code 为 `0`
  - `stdout_tail` 包含 `phase3 script ok python=3.11.7`
  - guest hello python_version 为 `3.11.7`

### IDA plugin install smoke verification

- IDA plugin install smoke 已在 HostMachine self-hosted runner 上通过 workflow_dispatch 实机验证。
- Initial verified run:

```text
https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26903926544
attempt 1
conclusion=success
runner=HostMachine
artifact=disposable-vm-guest-agent-smoke
```

- Support package layout verified run:

```text
https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26907543538
attempt 1
conclusion=success
runner=HostMachine
artifact=disposable-vm-guest-agent-smoke
```

- 验证输入：

```text
task_action=ida_plugin_install
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
controller_url=http://192.168.1.249:8766
```

- Artifact 中确认：
  - guest 验证 `C:\Users\alion\Desktop\IDAPro8.3` 存在。
  - guest 找到 IDA executables: `ida.exe`, `ida64.exe`, `idat.exe`, `idat64.exe`。
  - guest 安装 plugin 到 `C:\Users\alion\AppData\Roaming\Hex-Rays\IDA Pro\plugins`。
  - 已安装 `ida_script_mcp.py` 和 `ida_script_mcp_support` package layout。
  - guest 对安装文件完成 SHA-256 校验和 `py_compile` 校验。
  - guest standalone import 校验通过：`ida_script_mcp_support.protocol`、`ida_script_mcp_support.execution`、`ida_script_mcp_support.change_protocol`、`ida_script_mcp_support.change_recorder`。
  - guest 写入 `ida_script_mcp_install_manifest.json`。
  - `result.json` status 为 `completed`，exit_code 为 `0`。
  - `stdout_tail` 包含 `IDA_PLUGIN_INSTALL_VERIFY_RESULT=` 和 `"status": "installed"`。

### IDA DLL/plugin API smoke verification

- IDA DLL/plugin API smoke 已在 HostMachine self-hosted runner 上通过 workflow_dispatch 实机验证。
- Basic verified run:

```text
https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26908653405
attempt 1
conclusion=success
runner=HostMachine
artifact=disposable-vm-guest-agent-smoke
```

- Full verified run with non-destructive corner cases:

```text
https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26909020426
attempt 1
conclusion=success
runner=HostMachine
artifact=disposable-vm-guest-agent-smoke
```

- 验证输入：

```text
task_action=ida_plugin_api_test
ida_api_test_mode=full
ida_timeout_seconds=180
run_timeout_seconds=300
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
controller_url=http://192.168.1.249:8766
```

- Artifact 中确认：
  - guest 验证 `dll_path` 和 `ida_dir` 存在。
  - guest 安装/更新插件文件，且旧 root-level support files 不再污染 IDA plugin scan。
  - guest 用 IDA 打开 `test1.dll` 并等待 auto-analysis 完成。
  - guest 启动插件 HTTP server，并写入 `ida_ready.json`。
  - guest 从 IDA 进程外测试 `/health`、`/metadata`、`/functions`、`/decompile`、`/xrefs`、GUI `/execute` 禁用和未知路由 404。
  - `/functions` offset beyond total 返回 `returned=0` 和 `functions=[]`。
  - `/xrefs` invalid direction 和 invalid xref_kind 都返回结构化 error。
  - `/execute` 返回 HTTP 410，`status=rejected`。
  - `result.json` status 为 `completed`，exit_code 为 `0`。
  - guest payload 总耗时约 5.8 秒，没有长时间卡住。

### Tests

- 已新增 protocol / host controller / guest agent / guest dependency check 单元测试。
- 最新本地验证：

```text
py -3 -m pytest -q
127 passed

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

### Phase 4: project deploy/test payload

- host 打包 repository/test payload。
- guest 解包并部署测试环境。
- guest 运行真实 IDA integration deployment/test steps。
- host 收集 logs/artifacts 并按 guest exit code 决定 workflow success/failure。

### IDA GUI automation test plan

- 使用 `pywinauto` 作为 Windows GUI/process 自动化库。
- guest-side payload 后续会：
  - 启动 IDA 8.3 并打开指定 DLL。
  - 通过 IDAPython/bootstrap 等待 auto-analysis 完成。
  - 启动或调用已安装的 `IDA-Script-MCP` 插件。
  - 使用 `requests` 测试插件 HTTP endpoints，例如 metadata/functions/decompile/xrefs。
  - 回传 stdout/stderr/result metadata 和 artifact manifest。

### 后续增强

- artifact upload endpoint / archive upload。
- 更严格的 payload integrity check。
- 更明确的 host VMware adapter selection 配置。
- guest agent Windows autostart 安装脚本。
- 超时、重试、日志 streaming 的实机调优。
- 多 guest pool scheduling 暂不实现。
