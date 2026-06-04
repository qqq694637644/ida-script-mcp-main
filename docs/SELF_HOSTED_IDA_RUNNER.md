# Real IDA CI with a self-hosted GitHub Actions runner

This document explains how to run real IDA integration tests for the V2.3 isolated execution implementation.

The repository's normal unit tests do **not** require IDA. Real worker-process validation requires a licensed IDA installation, an IDA Python runtime, and saved clean `.i64` / `.idb` fixtures. Do not commit IDA binaries, license files, or private database fixtures to the repository.

## When to use this

Use GitHub-hosted runners for fast no-IDA checks:

```bash
python -m pytest -q
python -m compileall -q src tests
git diff --check
```

Use a self-hosted runner only for trusted real-IDA integration jobs, such as:

- launching `idat64` / `idat` / `ida64` / `ida` as an isolated worker;
- verifying hard-timeout process-tree kill behavior against real IDA;
- validating that the GUI plugin reports saved `.i64` / `.idb` paths and dirty state correctly;
- replaying worker change sets through GUI `/apply_changes`.

## Requirements

- A private Windows or Linux machine/VM that you control.
- A legal IDA installation and license.
- A Python version supported by this project.
- Saved clean `.i64` / `.idb` fixtures stored outside public commits.
- Repository admin access to add a self-hosted runner.

## Register the runner

1. Open the GitHub repository.
2. Go to **Settings → Actions → Runners → New self-hosted runner**.
3. Select the operating system and architecture of the IDA machine.
4. Run the download and `config` commands shown by GitHub on that machine.
5. Add labels during configuration, for example:
   - `ida`
   - `windows` or `linux`
   - optional IDA version label such as `ida-83` or `ida-90`
6. Start the runner interactively first. Once it works, configure it as a service using GitHub's generated service instructions.

## Runner environment

Set these variables on the runner user/service account or in a protected GitHub Actions environment:

```bash
IDA_SCRIPT_MCP_IDA_PATH=/absolute/path/to/idat64
IDA_SCRIPT_MCP_WORK_DIR=/path/to/scratch/ida-script-mcp-jobs
```

Windows PowerShell example:

```powershell
[Environment]::SetEnvironmentVariable(
  'IDA_SCRIPT_MCP_IDA_PATH',
  'C:\Program Files\IDA Pro 8.3\idat64.exe',
  'User'
)
[Environment]::SetEnvironmentVariable(
  'IDA_SCRIPT_MCP_WORK_DIR',
  'D:\ida-script-mcp-jobs',
  'User'
)
```

Keep IDA license files and private fixtures on the runner machine or fetch them only from private storage in trusted workflows.

## Example workflow

Create a dedicated workflow for real IDA integration tests. Do not mix it with public pull-request jobs.

```yaml
name: ida-integration

on:
  workflow_dispatch:
  push:
    branches:
      - main
      - 'gpt/**'

jobs:
  ida-integration:
    runs-on: [self-hosted, ida]
    timeout-minutes: 60
    env:
      IDA_SCRIPT_MCP_IDA_PATH: ${{ vars.IDA_SCRIPT_MCP_IDA_PATH }}
      IDA_SCRIPT_MCP_WORK_DIR: ${{ runner.temp }}/ida-script-mcp-jobs
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: python -m pip install -e . pytest
      - run: python -m pytest -q tests/integration_ida
```

The `tests/integration_ida` directory is intentionally separate from normal unit tests. Add real IDA tests there when a licensed runner and fixtures are available.

## Security policy

- Prefer private repositories for self-hosted IDA runners.
- Do not run untrusted fork pull-request code on a runner that has IDA installed or licensed.
- Use `workflow_dispatch`, trusted branches, protected environments, or manual approval before running real IDA jobs.
- Do not commit IDA runtime files, license files, `.env` files, or private `.i64` / `.idb` fixtures.
- Keep `IDA_SCRIPT_MCP_KEEP_JOBS=0` for normal CI. If you set it to `1` for debugging, clean `IDA_SCRIPT_MCP_WORK_DIR` periodically; retained job directories contain user scripts, stdout/stderr, copied databases, and replay artifacts.

## Troubleshooting

- If the job never starts, confirm the runner is online and has the `ida` label used by `runs-on`.
- If worker start returns `worker_start_error`, confirm `IDA_SCRIPT_MCP_IDA_PATH` points to an existing executable visible to the runner service account.
- If execution returns `source_error / DatabaseIdentityUnavailable`, confirm the GUI plugin reports a saved database path and can compute the saved database SHA-256.
- If replay returns `rejected`, confirm the GUI database is clean and its saved database SHA-256 matches the worker change set.

---

# 使用 self-hosted GitHub Actions runner 运行真实 IDA CI

本文说明如何为 V2.3 isolated execution 实现运行真实 IDA 集成测试。

仓库里的普通单元测试 **不需要** IDA。真实 worker 进程验证需要合法 IDA 安装、IDA Python runtime，以及已保存且 clean 的 `.i64` / `.idb` fixture。不要把 IDA 二进制、license 文件或私有数据库 fixture 提交进仓库。

## 什么时候需要它

GitHub-hosted runner 只跑快速、无 IDA 的检查：

```bash
python -m pytest -q
python -m compileall -q src tests
git diff --check
```

self-hosted runner 只用于可信的真实 IDA 集成任务，例如：

- 启动 `idat64` / `idat` / `ida64` / `ida` 作为 isolated worker；
- 在真实 IDA 上验证 hard timeout 能杀掉进程树；
- 验证 GUI 插件能正确报告已保存 `.i64` / `.idb` 路径和 dirty 状态；
- 通过 GUI `/apply_changes` replay worker change set。

## 前置要求

- 一台你自己控制的私有 Windows 或 Linux 机器/VM。
- 合法 IDA 安装和 license。
- 本项目支持的 Python 版本。
- 存放在公开 commit 之外的 clean `.i64` / `.idb` fixture。
- 仓库管理员权限，用于添加 self-hosted runner。

## 注册 runner

1. 打开 GitHub 仓库。
2. 进入 **Settings → Actions → Runners → New self-hosted runner**。
3. 选择 IDA 机器的操作系统和架构。
4. 在这台机器上执行 GitHub 页面展示的下载和 `config` 命令。
5. 配置时添加 label，例如：
   - `ida`
   - `windows` 或 `linux`
   - 可选 IDA 版本 label，例如 `ida-83` 或 `ida-90`
6. 先以前台方式启动 runner。确认可用后，再按 GitHub 生成的 service 指令配置为系统服务。

## Runner 环境变量

在 runner 用户/服务账号环境中配置，或者放到受保护的 GitHub Actions environment 中：

```bash
IDA_SCRIPT_MCP_IDA_PATH=/absolute/path/to/idat64
IDA_SCRIPT_MCP_WORK_DIR=/path/to/scratch/ida-script-mcp-jobs
```

Windows PowerShell 示例：

```powershell
[Environment]::SetEnvironmentVariable(
  'IDA_SCRIPT_MCP_IDA_PATH',
  'C:\Program Files\IDA Pro 8.3\idat64.exe',
  'User'
)
[Environment]::SetEnvironmentVariable(
  'IDA_SCRIPT_MCP_WORK_DIR',
  'D:\ida-script-mcp-jobs',
  'User'
)
```

IDA license 文件和私有 fixture 应保存在 runner 机器上，或只在可信 workflow 中从私有存储获取。

## 示例 workflow

为真实 IDA 集成测试创建单独 workflow。不要和公开 PR job 混在一起。

```yaml
name: ida-integration

on:
  workflow_dispatch:
  push:
    branches:
      - main
      - 'gpt/**'

jobs:
  ida-integration:
    runs-on: [self-hosted, ida]
    timeout-minutes: 60
    env:
      IDA_SCRIPT_MCP_IDA_PATH: ${{ vars.IDA_SCRIPT_MCP_IDA_PATH }}
      IDA_SCRIPT_MCP_WORK_DIR: ${{ runner.temp }}/ida-script-mcp-jobs
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: python -m pip install -e . pytest
      - run: python -m pytest -q tests/integration_ida
```

`tests/integration_ida` 目录应与普通单元测试分开。等合法 runner 和 fixture 准备好后，再把真实 IDA 测试放进去。

## 安全策略

- 带 IDA 的 self-hosted runner 优先用于 private repository。
- 不要让不可信 fork PR 代码运行在安装/授权了 IDA 的 runner 上。
- 真实 IDA job 应通过 `workflow_dispatch`、可信分支、受保护 environment 或人工审批触发。
- 不要提交 IDA runtime、license、`.env` 或私有 `.i64` / `.idb` fixture。
- 普通 CI 保持 `IDA_SCRIPT_MCP_KEEP_JOBS=0`。如果为了调试设为 `1`，请定期清理 `IDA_SCRIPT_MCP_WORK_DIR`；保留的 job 目录会包含用户脚本、stdout/stderr、数据库副本和 replay artifacts。

## 排障

- job 不启动：确认 runner 在线，并且有 workflow `runs-on` 使用的 `ida` label。
- 返回 `worker_start_error`：确认 `IDA_SCRIPT_MCP_IDA_PATH` 指向存在的可执行文件，并且 runner 服务账号可访问。
- 返回 `source_error / DatabaseIdentityUnavailable`：确认 GUI 插件能报告已保存数据库路径，并能计算 saved database SHA-256。
- replay 返回 `rejected`：确认 GUI 数据库是 clean 状态，并且 saved database SHA-256 与 worker change set 匹配。
