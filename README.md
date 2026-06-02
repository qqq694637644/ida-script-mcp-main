# IDA Script MCP

**[English](#english)** | **[中文](#chinese)**

---

<span id="english"></span>
## 🇺🇸 English Version

IDA Script MCP connects AI assistants to live IDA Pro instances. It is designed
for reverse-engineering workflows that need both:

- a **small, reliable MCP tool surface** for common read operations, and
- a **full IDAPython escape hatch** for long-tail or write operations.

### What changed in 1.1.0

The server now exposes exactly these six MCP tools:

- `list_ida_instances`
- `get_ida_database_info`
- `list_functions`
- `decompile_function`
- `get_xrefs`
- `execute_idapython`

Common reverse-engineering reads no longer require synthesizing ad-hoc
IDAPython every time. Dedicated read-only tools now call structured plugin
endpoints inside IDA.

### V2.3 isolated execution status on this branch

This branch implements the breaking V2.3 isolated execution design in
`V2.3_ISOLATED_EXECUTION_PLAN.md` to the unit-tested code level. Public
`execute_idapython` is isolated-only: it queries GUI metadata, copies the saved
clean IDB/I64 database, launches a separate IDA worker process, and never falls
back to GUI `/execute`.

Implemented in this branch:

- Strict public execute schema with no public `isolation`, `in_process`, or
  `apply_changes` escape hatch.
- Extended execution statuses such as `worker_start_error`, `worker_crashed`,
  `worker_result_missing`, `recorder_error`, and `rejected`.
- Saved-database source policy: execution requires a saved clean `.i64` / `.idb`
  path and a saved database SHA-256 identity.
- Fail-closed dirty/unsaved policy for both isolated execution and
  `/apply_changes` replay.
- Isolated job directory creation, request serialization, copied database path,
  worker runner generation, and hard timeout process-tree kill support.
- Structured change protocol, explicit `mcp_changes` API, strict monkeypatch
  recording, and GUI `/apply_changes` with per-operation results.
- Replay identity based only on saved database SHA-256; input-file hashes do not
  authorize replay.
- GUI `/execute` is rejected by default. The env-gated dev entrypoint remains,
  but public MCP execution does not route to it.
- Unit tests for protocol validation, isolated manager outcomes, dirty/identity
  rejection, recorder behavior, worker runner error mapping, and GUI replay
  strictness.

Not yet validated in this workspace:

- Real IDA 8.3+ runtime behavior.
- Whether `PATH_TYPE_IDB` / `PATH_TYPE_ID0` consistently returns the saved IDB/I64
  path on all supported IDA versions.
- Whether `idaapi.is_database_modified()` fully covers the dirty/unsaved states
  that matter for your workflow.
- The manual checklist in `V2.3_ISOLATED_EXECUTION_PLAN.md`.
- Real IDA integration tests under `tests/integration_ida`; add those after a
  licensed self-hosted runner and fixtures are available.

Deferred or intentionally not implemented:

- Snapshot diff fallback.
- Auto-apply in `execute_idapython`.
- Public in-process or auto fallback execution mode.
- Treating IDAPython SDK docs as a runtime dependency; they are documentation
  only. Real integration tests require a real IDA runtime.

### Features

- **Multi-instance support** across multiple running IDA databases
- **Structured read tools** for functions, decompilation, and xrefs
- **Full IDAPython execution** when you need custom scripts
- **Codex support** through `~/.codex/config.toml` and project `.codex/config.toml`
- **Packaged reverse-engineering docs** so IDAPython markdown docs can travel with the wheel
- **Localhost-only plugin** by default

### Requirements

- **IDA Pro 8.3+** (IDA Free is not supported)
- **Python 3.11+**
- Windows / macOS / Linux

### Installation

#### Quick start

```bash
"F:\Maye-13.6.0.230528\Tools\ida 8.3\python311\python.exe" -m pip install ida-script-mcp
pip install ida-script-mcp
ida-script-mcp-install install codex
```

#### Other install examples

```bash
# Install only the IDA plugin
"D:\ida\python311\python.exe" -m ida_script_mcp.installer install codex
ida-script-mcp-install install

# Configure multiple MCP clients
ida-script-mcp-install install claude,codex,cursor

# Project-level configuration for Codex
ida-script-mcp-install install --project codex

# List supported clients
ida-script-mcp-install --list-clients
```

The installed IDA plugin/support-file path does not require `pydantic` inside
IDA's embedded Python. The MCP server still uses the normal Python package
dependencies in the environment where `ida-script-mcp` runs.

#### From source

```bash
git clone https://github.com/yourusername/ida-script-mcp.git
cd ida-script-mcp
pip install -e .
ida-script-mcp-install install codex
```

### Starting the IDA plugin

1. Open IDA Pro and load a database.
2. Go to **Edit → Plugins → IDA-Script-MCP** or press `Ctrl+Alt+S`.
3. IDA will print the instance id and local HTTP endpoints.

Example:

```text
[IDA-Script-MCP] Server started at http://127.0.0.1:13338
[IDA-Script-MCP] Instance ID: 12345_sample.exe
[IDA-Script-MCP] Metadata endpoint: GET http://127.0.0.1:13338/metadata
[IDA-Script-MCP] Functions endpoint: POST http://127.0.0.1:13338/functions
[IDA-Script-MCP] Decompile endpoint: POST http://127.0.0.1:13338/decompile
[IDA-Script-MCP] Xrefs endpoint: POST http://127.0.0.1:13338/xrefs
[IDA-Script-MCP] Execute endpoint disabled by default; use isolated worker execution
[IDA-Script-MCP] Apply changes endpoint: POST http://127.0.0.1:13338/apply_changes
```

### Tool overview

| Tool | Purpose | Read-only |
|---|---|---|
| `list_ida_instances` | Discover running IDA instances | Yes |
| `get_ida_database_info` | Get database metadata and counts | Yes |
| `list_functions` | Enumerate functions with filters | Yes |
| `decompile_function` | Get pseudocode and optional disassembly | Yes |
| `get_xrefs` | Read xrefs to/from an address or symbol | Yes |
| `execute_idapython` | Run custom IDAPython | No |

### Recommended workflow

1. Use `list_ida_instances` first when more than one IDA instance is open.
2. Use `get_ida_database_info` to confirm the active database.
3. Use `list_functions`, `decompile_function`, and `get_xrefs` for everyday reading.
4. Use `execute_idapython` only for long-tail queries or write operations such as rename, retype, or patching.

### Reverse-engineering docs for LLMs

The package now ships markdown documentation under:

```text
ida_script_mcp/resources/idapython/
```

This includes:

- `SKILL.md`
- `docs/*.md`

These files are intended to be copied into a Codex local skill or any other
LLM guidance bundle so the model has both an IDA practice guide and IDAPython
module references.

### Supported MCP clients

| Client | Global config | Project config |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` | No |
| Claude Code | `.claude.json` | `.mcp.json` |
| Cursor | `.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code | `settings.json` | `.vscode/mcp.json` |
| Windsurf | `mcp_config.json` | `.windsurf/mcp_config.json` |
| Codex | `~/.codex/config.toml` | `.codex/config.toml` |

### Security note

`execute_idapython` runs arbitrary Python through an isolated worker IDA
process. The GUI plugin is used only for safe metadata and structured change
replay; public execution never falls back to GUI `/execute`.

Set `IDA_SCRIPT_MCP_IDA_PATH` to `idat`, `idat64`, `ida`, or `ida64` before
using isolated execution. The current GUI database must be saved and clean; dirty
or unsaved state is rejected instead of auto-saved. Isolated job directories are
deleted by default; set `IDA_SCRIPT_MCP_KEEP_JOBS=1` to keep them for debugging.
The keep-jobs flag is intentionally strict: values other than `0` or `1` fail
worker setup instead of silently changing behavior.

Script execution returns an explicit `status` such as `ok`, `timeout`,
`script_error`, `source_error`, `worker_start_error`, `worker_crashed`,
`worker_result_missing`, `recorder_error`, or `rejected`. A hard timeout kills the
worker process tree and returns `killed=true`; generated changes are not applied
to the GUI database unless `apply_worker_changes(..., dry_run=false)` is called
explicitly after preview.

### Real IDA CI

Detailed self-hosted runner setup is documented separately in
[`docs/SELF_HOSTED_IDA_RUNNER.md`](docs/SELF_HOSTED_IDA_RUNNER.md). Keep README
focused on the project status; keep runner setup, IDA license handling, and
integration workflow details in that dedicated document.

### License

MIT License

---

<span id="chinese"></span>
## 🇨🇳 中文版本

IDA Script MCP 用来把 AI 助手连接到正在运行的 IDA Pro 实例，目标是兼顾：

- **小而稳定的 MCP 工具面**，用于高频只读分析；
- **完整的 IDAPython 逃生舱**，用于长尾需求和写操作。

### 1.1.0 版本重点

现在 MCP 服务器固定暴露这 6 个工具：

- `list_ida_instances`
- `get_ida_database_info`
- `list_functions`
- `decompile_function`
- `get_xrefs`
- `execute_idapython`

高频逆向读取操作不再需要每次都让模型现写一段 IDAPython。
插件内部增加了结构化端点，直接支持函数列表、反编译和交叉引用查询。

### 当前分支的 V2.3 isolated execution 实现状态

当前分支已经把 `V2.3_ISOLATED_EXECUTION_PLAN.md` 中的破坏性 isolated
execution 方案实现到“单元测试覆盖的代码状态”。公开 `execute_idapython` 已是
isolated-only：它只向 GUI 查询安全 metadata，复制已保存且 clean 的 IDB/I64
数据库，启动独立 IDA worker 进程执行脚本，并且不会回退到 GUI `/execute`。

当前已实现：

- 严格公开 execute schema，不暴露 `isolation`、`in_process` 或
  `apply_changes` 逃生参数。
- 扩展执行状态，包括 `worker_start_error`、`worker_crashed`、
  `worker_result_missing`、`recorder_error` 和 `rejected`。
- 保存数据库来源策略：执行必须拿到已保存的 `.i64` / `.idb` 路径，以及
  saved database SHA-256 身份。
- isolated execution 和 `/apply_changes` replay 都采用 fail-closed 的
  dirty/unsaved 策略。
- isolated job 目录创建、request 序列化、数据库副本路径、worker runner
  生成，以及 hard timeout 进程树 kill。
- 结构化 change protocol、显式 `mcp_changes` API、严格 monkeypatch 记录、
  GUI `/apply_changes` per-operation 结果。
- replay 身份只认 saved database SHA-256；输入文件 hash 不能授权 replay。
- GUI `/execute` 默认拒绝。env-gated dev entrypoint 仍保留，但公开 MCP
  执行路径不会调用它。
- 已补单元测试覆盖 protocol、isolated manager、dirty/identity 拒绝、recorder、
  worker runner 错误映射、GUI replay 严格性。

当前 workspace 尚未验证：

- 真实 IDA 8.3+ runtime 行为。
- `PATH_TYPE_IDB` / `PATH_TYPE_ID0` 在所有支持 IDA 版本中是否稳定返回保存后的
  IDB/I64 路径。
- `idaapi.is_database_modified()` 是否完整覆盖你的工作流所需 dirty/unsaved 状态。
- `V2.3_ISOLATED_EXECUTION_PLAN.md` 中的手工验证 checklist。
- `tests/integration_ida` 下的真实 IDA 集成测试；需要等 licensed self-hosted
  runner 和 fixture 准备好后再添加。

已延期或明确不实现：

- snapshot diff fallback。
- 在 `execute_idapython` 内自动 apply。
- 公开 in-process 或 auto fallback 执行模式。
- 把 IDAPython SDK 文档当作运行时依赖；这些文件只是文档。真实集成测试需要
  真实 IDA runtime。

### 特性

- **多实例支持**，可同时连接多个 IDA 数据库
- **结构化只读工具**，覆盖函数、伪代码、xref 三类高频查询
- **完整 IDAPython 执行能力**，保留自定义脚本能力
- **Codex 支持**，可写入 `~/.codex/config.toml` 和项目级 `.codex/config.toml`
- **随包分发的逆向文档**，IDAPython 的 markdown 文档可以一起打包
- **默认仅绑定本机 localhost**

### 系统要求

- **IDA Pro 8.3+**（不支持 IDA Free）
- **Python 3.11+**
- Windows / macOS / Linux

### 安装

#### 快速开始

```bash
pip install ida-script-mcp
ida-script-mcp-install install codex
```

#### 其他示例

```bash
# 仅安装 IDA 插件
ida-script-mcp-install install

# 同时配置多个 MCP 客户端
ida-script-mcp-install install claude,codex,cursor

# 为 Codex 写入项目级配置
ida-script-mcp-install install --project codex

# 查看支持的客户端
ida-script-mcp-install --list-clients
```

安装到 IDA 的 plugin/support-file 路径不要求 IDA embedded Python 内安装
`pydantic`。MCP server 仍使用运行 `ida-script-mcp` 的普通 Python 环境中的包依赖。

#### 从源码安装

```bash
git clone https://github.com/yourusername/ida-script-mcp.git
cd ida-script-mcp
pip install -e .
ida-script-mcp-install install codex
```

### 启动 IDA 插件

1. 打开 IDA Pro 并加载数据库。
2. 进入 **Edit → Plugins → IDA-Script-MCP**，或者按 `Ctrl+Alt+S`。
3. IDA 会输出实例 id 和本地 HTTP 端点。

### 工具说明

| 工具 | 作用 | 是否只读 |
|---|---|---|
| `list_ida_instances` | 枚举正在运行的 IDA 实例 | 是 |
| `get_ida_database_info` | 获取数据库元信息和统计信息 | 是 |
| `list_functions` | 按条件列出函数 | 是 |
| `decompile_function` | 获取伪代码，可选附带汇编 | 是 |
| `get_xrefs` | 查询某地址或符号的入/出 xref | 是 |
| `execute_idapython` | 执行自定义 IDAPython | 否 |

### 推荐使用流程

1. 多开 IDA 时，先用 `list_ida_instances` 确认目标实例。
2. 用 `get_ida_database_info` 确认当前数据库。
3. 日常读取优先用 `list_functions`、`decompile_function`、`get_xrefs`。
4. 只有在长尾需求或写操作时，才使用 `execute_idapython`。

### 给 LLM 的逆向文档

包内现在自带 markdown 文档，路径为：

```text
ida_script_mcp/resources/idapython/
```

其中包括：

- `SKILL.md`
- `docs/*.md`

这些文件适合直接复制到 Codex local skill，或者其他 LLM 的指导文档目录，
让模型同时具备“怎么高效使用 IDA”的实践指南，以及 IDAPython 模块参考。

### 支持的 MCP 客户端

| 客户端 | 全局配置 | 项目级配置 |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` | 不支持 |
| Claude Code | `.claude.json` | `.mcp.json` |
| Cursor | `.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code | `settings.json` | `.vscode/mcp.json` |
| Windsurf | `mcp_config.json` | `.windsurf/mcp_config.json` |
| Codex | `~/.codex/config.toml` | `.codex/config.toml` |

### 安全提示

`execute_idapython` 会通过隔离的 IDA worker 进程执行任意 Python。
GUI 插件只用于安全元数据读取和结构化变更 replay；公开执行路径不会回退到
GUI `/execute`。

使用隔离执行前，请设置 `IDA_SCRIPT_MCP_IDA_PATH` 指向 `idat`、`idat64`、
`ida` 或 `ida64`。当前 GUI 数据库必须已经保存且处于 clean 状态；dirty、
unsaved 或无法确认状态时都会被拒绝，不会自动保存或降级执行。isolated job
目录默认删除；如需调试可设置 `IDA_SCRIPT_MCP_KEEP_JOBS=1` 保留。该开关只接受
`0` 或 `1`，其他值会让 worker setup 直接失败，不会静默改变行为。

脚本执行会返回明确的 `status`，例如 `ok`、`timeout`、`script_error`、
`source_error`、`worker_start_error`、`worker_crashed`、
`worker_result_missing`、`recorder_error` 或 `rejected`。hard timeout 会杀掉
worker 进程树并返回 `killed=true`。worker 产生的变更不会自动应用到 GUI
数据库，必须先 preview，再显式调用 `apply_worker_changes(..., dry_run=false)`。

### 真实 IDA CI

self-hosted runner 的详细设置已拆到独立文档：
[`docs/SELF_HOSTED_IDA_RUNNER.md`](docs/SELF_HOSTED_IDA_RUNNER.md)。README 只描述
项目状态；runner 安装、IDA license 处理、integration workflow 示例都放在
专门文档中维护。

### 许可证

MIT License
