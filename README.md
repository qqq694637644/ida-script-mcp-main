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
[IDA-Script-MCP] Execute endpoint: POST http://127.0.0.1:13338/execute
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
or unsaved state is rejected instead of auto-saved.

Script execution returns an explicit `status` such as `ok`, `timeout`,
`script_error`, `source_error`, `worker_start_error`, `worker_crashed`,
`worker_result_missing`, `recorder_error`, or `rejected`. A hard timeout kills the
worker process tree and returns `killed=true`; generated changes are not applied
to the GUI database unless `apply_worker_changes(..., dry_run=false)` is called
explicitly after preview.

### Real IDA CI with a self-hosted runner

Unit tests do not require IDA and should continue to run on GitHub-hosted
runners. Real isolated-worker validation needs a legal IDA installation,
license, and saved clean `.i64` / `.idb` fixture, so run it on a controlled
self-hosted runner instead of committing IDA runtime files to the repository.

Setup outline:

1. Prepare a private Windows or Linux machine/VM with IDA installed and licensed.
2. In GitHub, open the repository **Settings → Actions → Runners → New
   self-hosted runner**, choose the OS/architecture, then run GitHub's generated
   download and `config` commands on that machine.
3. Add labels such as `ida`, `windows`, or `linux` when configuring the runner,
   so IDA integration jobs can target only that machine.
4. Configure environment variables on the runner account or service:
   - `IDA_SCRIPT_MCP_IDA_PATH` — full path to `idat64`, `idat`, `ida64`, or `ida`.
   - `IDA_SCRIPT_MCP_WORK_DIR` — scratch directory for isolated worker jobs.
5. Keep IDA binaries, license files, and IDB fixtures out of public commits.
   Store fixtures on the runner or fetch them from private storage only in
   trusted workflows.

Example workflow job:

```yaml
jobs:
  ida-integration:
    runs-on: [self-hosted, ida]
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

Run this workflow only for trusted branches, `workflow_dispatch`, or protected
environments. Do not expose a licensed IDA runner to arbitrary fork pull-request
code.

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
unsaved 或无法确认状态时都会被拒绝，不会自动保存或降级执行。

脚本执行会返回明确的 `status`，例如 `ok`、`timeout`、`script_error`、
`source_error`、`worker_start_error`、`worker_crashed`、
`worker_result_missing`、`recorder_error` 或 `rejected`。hard timeout 会杀掉
worker 进程树并返回 `killed=true`。worker 产生的变更不会自动应用到 GUI
数据库，必须先 preview，再显式调用 `apply_worker_changes(..., dry_run=false)`。

### 使用 self-hosted runner 运行真实 IDA CI

普通单元测试不需要 IDA，应该继续跑在 GitHub-hosted runner 上。真实的
isolated worker 验证需要合法 IDA 安装、license，以及已保存且 clean 的
`.i64` / `.idb` fixture，因此应放在你自己控制的 self-hosted runner 上，
不要把 IDA runtime 提交进仓库。

设置步骤：

1. 准备一台私有 Windows 或 Linux 机器/VM，安装并激活 IDA。
2. 在 GitHub 仓库进入 **Settings → Actions → Runners → New self-hosted
   runner**，选择系统/架构，然后在机器上执行 GitHub 生成的下载和
   `config` 命令。
3. 配置 runner 时加上 `ida`、`windows` 或 `linux` 等 label，确保 IDA
   集成测试只调度到这台机器。
4. 在 runner 用户或服务环境中配置：
   - `IDA_SCRIPT_MCP_IDA_PATH`：`idat64`、`idat`、`ida64` 或 `ida` 的完整路径。
   - `IDA_SCRIPT_MCP_WORK_DIR`：isolated worker job 的临时工作目录。
5. 不要把 IDA 二进制、license 文件、私有 IDB fixture 提交到公开仓库。
   fixture 可以预放在 runner 上，或仅在可信 workflow 中从私有存储获取。

示例 workflow job：

```yaml
jobs:
  ida-integration:
    runs-on: [self-hosted, ida]
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

建议只允许可信分支、`workflow_dispatch` 或受保护 environment 触发这类
workflow。不要让来自 fork PR 的任意代码直接运行在带 IDA license 的
self-hosted runner 上。

### 许可证

MIT License
