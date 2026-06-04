# IDA Script MCP

**English** | [中文](#中文)

IDA Script MCP connects MCP-compatible AI assistants to live IDA Pro databases. It
keeps common reverse-engineering reads as small structured tools, while custom
IDAPython runs in a separate headless IDA worker process instead of directly in
the GUI instance.

The project is intentionally local-first: the IDA plugin listens on localhost,
tracks running IDA instances, exposes read-only HTTP endpoints for common
analysis, and uses explicit replayable change sets for worker-side write
operations.

## Highlights

- Multi-instance discovery for several open IDA databases.
- Structured read tools for metadata, function lists, decompilation, xrefs, and
  address inspection through the IDA plugin.
- Isolated `execute_idapython` worker execution with hard timeouts, stdout/stderr
  capture, worker process metadata, retained artifacts, and structured statuses.
- Worker change recording for rename, comments, function comments, type changes,
  and byte patches.
- `apply_worker_changes` for dry-run preview and explicit replay into the GUI
  database.
- Installer support for Claude Desktop, Claude Code, Cursor, VS Code, Windsurf,
  and Codex global/project configs.
- Packaged IDAPython guidance under `ida_script_mcp/resources/idapython/`.

## Requirements

- IDA Pro 8.3 or newer. IDA Free is not supported because it does not support the
  plugin workflow used here.
- Python 3.11 or newer for the MCP server package.
- Windows is currently the supported platform for isolated worker execution. The
  worker discovery path deliberately requires a live GUI `ida64.exe` process and
  a same-directory `idat64.exe`.

Read-only MCP tools and plugin installation are written to be portable where IDA
and Python support them, but the current public `execute_idapython` path is
Windows/fail-fast by design.

## Install

Install the package into the Python environment that will run the MCP server:

```bash
pip install ida-script-mcp
```

Install the IDA plugin and optionally configure one or more MCP clients:

```bash
# Plugin only
ida-script-mcp-install install

# Plugin plus one client config
ida-script-mcp-install install codex

# Multiple clients
ida-script-mcp-install install claude,codex,cursor

# Project-level config for clients that support it
ida-script-mcp-install install --project codex

# Show supported clients
ida-script-mcp-install --list-clients
```

The installer writes the plugin to the per-user IDA plugin directory and installs
support modules under `ida_script_mcp_support/`. Restart IDA after plugin
installation or update.

## Install from source

```bash
git clone https://github.com/qqq694637644/ida-script-mcp-main.git
cd ida-script-mcp-main
pip install -e .
ida-script-mcp-install install codex
```

For development:

```bash
pip install -e ".[dev]"
py -3 -m ruff check src tests
py -3 -m pytest -q
```

## Start the IDA plugin

1. Open IDA Pro and load a database.
2. Use **Edit → Plugins → IDA-Script-MCP** or press `Ctrl+Alt+S`.
3. Watch IDA's output window for the instance id and local endpoints.

Example output:

```text
[IDA-Script-MCP] Server started at http://127.0.0.1:13338
[IDA-Script-MCP] Instance ID: 2540_test1.dll
[IDA-Script-MCP] Metadata endpoint: GET http://127.0.0.1:13338/metadata
[IDA-Script-MCP] Functions endpoint: POST http://127.0.0.1:13338/functions
[IDA-Script-MCP] Decompile endpoint: POST http://127.0.0.1:13338/decompile
[IDA-Script-MCP] Xrefs endpoint: POST http://127.0.0.1:13338/xrefs
[IDA-Script-MCP] Inspect address endpoint: POST http://127.0.0.1:13338/inspect_address
[IDA-Script-MCP] Execute endpoint disabled by default; use isolated worker execution
[IDA-Script-MCP] Apply changes endpoint: POST http://127.0.0.1:13338/apply_changes
```

## Configure MCP clients

The installer is the recommended path. A minimal manual JSON config looks like:

```json
{
  "mcpServers": {
    "ida-script-mcp": {
      "command": "python",
      "args": ["-m", "ida_script_mcp.server"]
    }
  }
}
```

For Codex TOML configs:

```toml
[mcp_servers.ida-script-mcp]
command = "python"
args = ["-m", "ida_script_mcp.server"]
```

Supported client targets include Claude Desktop, Claude Code, Cursor, VS Code,
Windsurf, and Codex. Some clients also support project-level config files such as
`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.windsurf/mcp_config.json`,
and `.codex/config.toml`.

## MCP tools

| Tool | Purpose | Writes? |
| --- | --- | --- |
| `list_ida_instances` | List live IDA plugin instances and their ids/ports. | No |
| `get_ida_database_info` | Return metadata, dirty state, hashes, imagebase, processor, and database paths. | No |
| `list_functions` | Page and filter functions by name, segment, thunk/library inclusion. | No |
| `decompile_function` | Decompile by address or name, optionally with disassembly. | No |
| `get_xrefs` | Return xrefs to/from an address or symbol, with kind filtering. | No |
| `execute_idapython` | Run custom IDAPython in an isolated worker IDA process. | Worker only |
| `apply_worker_changes` | Dry-run or replay a worker-produced ChangeSet into the GUI database. | Optional |

Targeting rules:

- With one live IDA instance, tools can usually omit `instance_id` and `port`.
- With multiple instances, call `list_ida_instances` first and pass either
  `instance_id` or `port` to later tools.
- Environment variables `IDA_SCRIPT_MCP_INSTANCE_ID` and `IDA_SCRIPT_MCP_PORT`
  can select a default target for the MCP server process.

## Read-only analysis workflow

Use structured read tools before asking an assistant to write IDAPython:

1. `list_ida_instances`
2. `get_ida_database_info`
3. `list_functions`
4. `decompile_function`
5. `get_xrefs`

This avoids unnecessary custom scripts for common operations and gives the model
stable, typed responses.

## Isolated IDAPython execution

`execute_idapython` no longer runs public scripts through the GUI `/execute`
endpoint. The server creates a worker job and launches headless IDA with a copied
IDB/I64 database.

Current worker discovery is intentionally strict:

1. Resolve the selected live GUI IDA instance.
2. Read its PID from the instance registry.
3. Resolve that PID to the GUI executable path.
4. Require the executable basename to be `ida64.exe`.
5. Require `idat64.exe` in the same directory.
6. Launch that `idat64.exe` as the isolated worker.

There is no fallback to `IDA_SCRIPT_MCP_IDA_PATH`, `IDA_SCRIPT_MCP_WORKER_MODE`,
or `PATH`. Missing PID, missing executable path, non-`ida64.exe` GUI process, or
missing same-directory `idat64.exe` returns `worker_start_error` and exposes the
problem early.

The GUI database must also be in a known clean state. The worker path refuses to
run if the GUI database dirty state is unknown or dirty. Save the database before
running custom write-capable scripts.

Common `execute_idapython` statuses:

- `ok`
- `timeout`
- `script_error`
- `source_error`
- `worker_start_error`
- `worker_crashed`
- `worker_result_missing`
- `recorder_error`
- `rejected`

## Worker changes and replay

Worker scripts can call IDAPython APIs normally. The worker runtime also records
selected database-changing operations into a structured ChangeSet:

- `rename`
- `comment`
- `function_comment`
- `set_type`
- `patch_bytes`

The worker returns these operations in `changes` and writes artifacts such as
`request.json`, `metadata.json`, `changes.json`, `worker_runtime.json`, stdout,
and stderr.

Replay should be explicit:

1. Run `execute_idapython` and inspect its `changes`.
2. Call `apply_worker_changes` with `dry_run=true` to preview the GUI replay.
3. Call `apply_worker_changes` with `dry_run=false` only after review.

Replay checks the saved GUI database fingerprint before applying operations.

## Security model

- The IDA plugin binds to `127.0.0.1` by default.
- Public MCP `execute_idapython` is isolated; GUI `/execute` is disabled by
  default.
- Custom IDAPython is still arbitrary code and should only be accepted from
  trusted assistants/users.
- `apply_worker_changes` can modify the open IDA database when `dry_run=false`.
- Keep IDA databases saved and clean before worker execution.

There is an unsafe GUI execution escape hatch for internal testing, controlled by
`IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE`; it is not the normal public workflow.

## Useful environment variables

| Variable | Purpose |
| --- | --- |
| `IDA_SCRIPT_MCP_HOST` | IDA plugin host, default `127.0.0.1`. |
| `IDA_SCRIPT_MCP_PORT` | Default target plugin port. |
| `IDA_SCRIPT_MCP_INSTANCE_ID` | Default target instance id. |
| `IDA_SCRIPT_MCP_WORK_DIR` | Directory for isolated worker jobs. |
| `IDA_SCRIPT_MCP_KEEP_JOBS` | Set to `1` to retain worker job artifacts. |
| `IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE` | Enables legacy GUI `/execute`; not recommended. |

`IDA_SCRIPT_MCP_IDA_PATH` and `IDA_SCRIPT_MCP_WORKER_MODE` are intentionally not
used for public worker discovery.

## Disposable VM testing

The repository includes a disposable VM test harness used by GitHub Actions on a
self-hosted Windows runner. Useful entry points include:

- `ida-script-mcp-vm-host-controller`
- `ida-script-mcp-vm-guest-agent`
- `.github/workflows/disposable-vm-guest-agent-smoke.yml`

The workflow contains targeted actions for plugin install, API reads, worker
lifecycle, worker failure matrix, complex apply/replay cases, and GUI-derived
worker discovery.

## License

MIT License

---

<a id="中文"></a>
# IDA Script MCP（中文）

IDA Script MCP 用于把支持 MCP 的 AI 助手连接到正在运行的 IDA Pro 数据库。项目的核心思路是：
高频逆向读取用稳定的结构化工具完成，自定义 IDAPython 则在独立的 headless IDA worker 里执行，
不要直接阻塞或污染 GUI IDA 实例。

插件默认只监听 localhost，会登记当前运行的 IDA 实例，提供常见分析端点，并把 worker 侧产生的写操作
记录成可审查、可 dry-run、可显式回放的 ChangeSet。

## 主要能力

- 支持同时发现多个打开的 IDA 数据库。
- 结构化只读工具：数据库信息、函数列表、反编译、交叉引用、地址检查。
- `execute_idapython` 使用隔离 worker：硬超时、stdout/stderr 捕获、worker PID/退出码、artifact 保留、结构化状态。
- worker 可记录 rename、注释、函数注释、类型修改、字节 patch 等变更。
- `apply_worker_changes` 支持先 dry-run 预览，再显式回放到 GUI 数据库。
- 安装器支持 Claude Desktop、Claude Code、Cursor、VS Code、Windsurf、Codex 的全局/项目配置。
- 随包携带 IDAPython 使用指南：`ida_script_mcp/resources/idapython/`。

## 要求

- IDA Pro 8.3+；IDA Free 不支持本插件工作流。
- MCP server 使用 Python 3.11+。
- 当前公开的隔离 worker 执行路径以 Windows 为目标：必须有正在服务的 GUI `ida64.exe`，并且同目录存在 `idat64.exe`。

只读工具和插件安装逻辑尽量保持可移植；但当前 `execute_idapython` 的 public worker 路径是 Windows/fail-fast 设计。

## 安装

```bash
pip install ida-script-mcp
```

安装 IDA 插件，并按需配置 MCP 客户端：

```bash
# 只安装插件
ida-script-mcp-install install

# 插件 + Codex 配置
ida-script-mcp-install install codex

# 多客户端
ida-script-mcp-install install claude,codex,cursor

# 项目级 Codex 配置
ida-script-mcp-install install --project codex

# 查看支持的客户端
ida-script-mcp-install --list-clients
```

安装器会把插件写入当前用户的 IDA 插件目录，并安装 `ida_script_mcp_support/` 支持包。安装或更新后需要重启 IDA。

源码安装：

```bash
git clone https://github.com/qqq694637644/ida-script-mcp-main.git
cd ida-script-mcp-main
pip install -e .
ida-script-mcp-install install codex
```

开发验证：

```bash
pip install -e ".[dev]"
py -3 -m ruff check src tests
py -3 -m pytest -q
```

## 启动 IDA 插件

1. 打开 IDA Pro 并加载数据库。
2. 选择 **Edit → Plugins → IDA-Script-MCP**，或按 `Ctrl+Alt+S`。
3. 在 IDA 输出窗口查看 instance id 和本地端点。

示例：

```text
[IDA-Script-MCP] Server started at http://127.0.0.1:13338
[IDA-Script-MCP] Instance ID: 2540_test1.dll
[IDA-Script-MCP] Metadata endpoint: GET http://127.0.0.1:13338/metadata
[IDA-Script-MCP] Functions endpoint: POST http://127.0.0.1:13338/functions
[IDA-Script-MCP] Decompile endpoint: POST http://127.0.0.1:13338/decompile
[IDA-Script-MCP] Xrefs endpoint: POST http://127.0.0.1:13338/xrefs
[IDA-Script-MCP] Inspect address endpoint: POST http://127.0.0.1:13338/inspect_address
[IDA-Script-MCP] Execute endpoint disabled by default; use isolated worker execution
[IDA-Script-MCP] Apply changes endpoint: POST http://127.0.0.1:13338/apply_changes
```

## MCP 工具

当前暴露 7 个 MCP 工具：

| 工具 | 用途 | 是否写入 |
| --- | --- | --- |
| `list_ida_instances` | 列出正在运行的 IDA 插件实例。 | 否 |
| `get_ida_database_info` | 返回数据库路径、hash、dirty 状态、imagebase、处理器等信息。 | 否 |
| `list_functions` | 分页/过滤函数列表。 | 否 |
| `decompile_function` | 按地址或名称反编译函数，可附带反汇编。 | 否 |
| `get_xrefs` | 查询到某地址/符号或从某地址/符号发出的 xref。 | 否 |
| `execute_idapython` | 在隔离 worker IDA 中执行自定义 IDAPython。 | 只写 worker 副本 |
| `apply_worker_changes` | 预览或回放 worker 产生的 ChangeSet。 | 可选 |

多 IDA 实例时，先调用 `list_ida_instances`，再把 `instance_id` 或 `port` 传给后续工具。
也可以用 `IDA_SCRIPT_MCP_INSTANCE_ID` 或 `IDA_SCRIPT_MCP_PORT` 设置 MCP server 的默认目标。

## 推荐读取流程

1. `list_ida_instances`
2. `get_ida_database_info`
3. `list_functions`
4. `decompile_function`
5. `get_xrefs`

这些只读工具应优先于临时生成 IDAPython。

## 隔离 IDAPython 执行

public `execute_idapython` 不再走 GUI `/execute`。执行流程是：复制当前已保存的 IDB/I64，启动 headless IDA worker，
在副本中运行脚本，收集结果和变更。

worker executable 发现规则是破坏式、无兜底的：

1. 解析当前服务的 GUI IDA 实例。
2. 从实例登记信息拿 PID。
3. 根据 PID 解析 GUI executable path。
4. executable basename 必须是 `ida64.exe`。
5. 同目录必须有 `idat64.exe`。
6. 用这个 `idat64.exe` 启动 worker。

不会再回退到 `IDA_SCRIPT_MCP_IDA_PATH`、`IDA_SCRIPT_MCP_WORKER_MODE` 或 `PATH`。缺 PID、缺 exe path、GUI 不是
`ida64.exe`、同目录没有 `idat64.exe`，都会直接返回 `worker_start_error`，在开发阶段暴露问题。

GUI 数据库也必须是已知干净状态。执行前请保存数据库；dirty 或 dirty 状态未知时会拒绝执行。

常见状态包括：`ok`、`timeout`、`script_error`、`source_error`、`worker_start_error`、`worker_crashed`、
`worker_result_missing`、`recorder_error`、`rejected`。

## worker 变更和回放

worker 脚本可以正常使用 IDAPython。运行时会把部分数据库写操作记录为结构化 ChangeSet：

- `rename`
- `comment`
- `function_comment`
- `set_type`
- `patch_bytes`

建议流程：

1. 运行 `execute_idapython`，检查 `changes`。
2. 调用 `apply_worker_changes` 并保持 `dry_run=true` 预览。
3. 确认后再设置 `dry_run=false` 回放到 GUI 数据库。

回放前会校验 GUI 数据库 fingerprint，避免把 worker 变更应用到错误数据库。

## 安全边界

- 插件默认绑定 `127.0.0.1`。
- public `execute_idapython` 使用隔离 worker；GUI `/execute` 默认禁用。
- 自定义 IDAPython 仍然是任意代码，只应接受可信用户/助手的脚本。
- `apply_worker_changes(dry_run=false)` 会修改当前 GUI 数据库。
- 执行前保持数据库已保存且干净。

内部测试可通过 `IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE` 打开 legacy GUI `/execute`，但这不是常规工作流。

## 常用环境变量

| 变量 | 用途 |
| --- | --- |
| `IDA_SCRIPT_MCP_HOST` | IDA 插件 host，默认 `127.0.0.1`。 |
| `IDA_SCRIPT_MCP_PORT` | 默认目标端口。 |
| `IDA_SCRIPT_MCP_INSTANCE_ID` | 默认目标实例 id。 |
| `IDA_SCRIPT_MCP_WORK_DIR` | 隔离 worker job 目录。 |
| `IDA_SCRIPT_MCP_KEEP_JOBS` | 设为 `1` 时保留 worker artifacts。 |
| `IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE` | 启用 legacy GUI `/execute`，不推荐。 |

`IDA_SCRIPT_MCP_IDA_PATH` 和 `IDA_SCRIPT_MCP_WORKER_MODE` 不再参与 public worker discovery。

## disposable VM 测试

仓库包含面向自托管 Windows runner 的 disposable VM 测试框架。入口包括：

- `ida-script-mcp-vm-host-controller`
- `ida-script-mcp-vm-guest-agent`
- `.github/workflows/disposable-vm-guest-agent-smoke.yml`

workflow 覆盖插件安装、API 读取、worker 生命周期、worker failure matrix、复杂变更回放，以及 GUI 派生 worker discovery 实机验证。

## 许可证

MIT License
