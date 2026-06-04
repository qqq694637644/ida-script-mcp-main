# IDA Script MCP

IDA Script MCP 是一个把 AI 助手接入本机 IDA Pro 的 MCP 服务和 IDA 插件组合。它的目标不是把所有逆向动作都交给一段临时脚本，而是提供一组稳定、结构化、可选择目标实例的工具，让模型能可靠读取 IDB，并在确实需要时通过受控的 `execute_idapython` 执行自定义 IDAPython。

项目适合这些场景：

- 让 Claude、Cursor、Codex、VS Code 等 MCP 客户端读取当前 IDA 数据库。
- 多开 IDA 时，让模型先枚举实例，再明确选择要分析的数据库。
- 高频读取使用固定工具，减少模型临时拼 IDAPython 的不确定性。
- 长尾分析或写操作使用隔离后的 `execute_idapython`，并通过变更预览再决定是否写回 GUI 数据库。

## 核心特性

### 1. 本机 IDA 插件

IDA 插件默认只监听 `127.0.0.1`，启动后会注册当前 IDA 实例，并暴露本机 HTTP 端点供 MCP 服务调用。端口默认从 `13338` 开始，端口被占用时会改用后续端口。

插件启动后会在 IDA 输出窗口显示类似信息：

```text
[IDA-Script-MCP] Server started at http://127.0.0.1:13338
[IDA-Script-MCP] Instance ID: 12345_sample.exe
[IDA-Script-MCP] Metadata endpoint: GET http://127.0.0.1:13338/metadata
[IDA-Script-MCP] Functions endpoint: POST http://127.0.0.1:13338/functions
[IDA-Script-MCP] Decompile endpoint: POST http://127.0.0.1:13338/decompile
[IDA-Script-MCP] Xrefs endpoint: POST http://127.0.0.1:13338/xrefs
[IDA-Script-MCP] Inspect address endpoint: POST http://127.0.0.1:13338/inspect_address
[IDA-Script-MCP] Execute endpoint disabled by default; use isolated worker execution
[IDA-Script-MCP] Apply changes endpoint: POST http://127.0.0.1:13338/apply_changes
```

### 2. 多 IDA 实例支持

插件会把正在运行的 IDA 实例写入本机实例注册表。MCP 客户端可以先调用 `list_ida_instances` 查看当前有哪些数据库，再通过 `instance_id` 或 `port` 精确选择目标。

当只打开一个 IDA 实例时，工具会默认使用它；当同时打开多个实例时，建议显式传入目标，避免模型误读或误写其他数据库。

### 3. 结构化只读分析工具

日常读取优先使用专门工具，而不是让模型每次临时生成脚本：

- `get_ida_database_info`：读取数据库路径、文件名、架构、入口、函数数量、dirty 状态等元信息。
- `list_functions`：按分页、名称、thunk/library 选项列出函数。
- `decompile_function`：按地址或函数名获取 Hex-Rays 伪代码，可选附带汇编。
- `get_xrefs`：查询某个地址或符号的入引用、出引用，可按 code/data/flow/all 过滤。

这些工具返回结构化 JSON，适合模型继续推理、筛选和交叉验证。

### 4. 改进后的 `execute_idapython`

`execute_idapython` 是本项目最重要的改进点之一。它保留了完整 IDAPython 能力，但不再默认把用户代码直接塞进 GUI IDA 的 `/execute` 端点执行。

现在的执行模型是：

1. MCP 服务先读取 GUI IDA 的安全上下文，例如当前实例、PID、可执行文件路径、数据库路径、dirty 状态和保存后的数据库指纹。
2. 如果 GUI 数据库状态不安全，例如存在未保存修改、无法确认 dirty 状态、无法计算保存文件哈希，执行会直接拒绝。
3. 服务从当前 GUI `ida64.exe` 所在目录推导同目录的 headless worker，可执行文件通常是 `idat64.exe`。如果无法确认，不会退回到环境变量或 `PATH` 里随便找 IDA。
4. 用户脚本在独立 worker 进程里运行，返回明确的结构化状态、stdout、stderr、错误类型、traceback、worker PID、退出码和超时信息。
5. worker 超时是硬超时，超时后会尝试终止 worker 进程树，避免脚本长期卡住 GUI IDA。
6. 写操作不会直接落到 GUI 数据库。worker 会记录结构化变更集，后续通过 `apply_worker_changes` 预览或写回。

旧式 GUI `/execute` HTTP 端点默认关闭；除非显式设置 `IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE=1`，否则插件会返回拒绝结果。正常用户应使用 MCP 工具 `execute_idapython`。

`execute_idapython` 支持的关键参数：

| 参数 | 说明 |
|---|---|
| `code` | 直接传入一段 IDAPython 代码。|
| `script_path` | 传入脚本文件路径。`code` 和 `script_path` 必须且只能提供一个。|
| `capture_output` | 是否捕获 stdout/stderr，默认 `true`。|
| `timeout_seconds` | worker 硬超时，默认 30 秒，范围 1 到 600 秒。|
| `collect_changes` | 是否记录 worker 内的结构化变更，默认 `true`。|

常见返回状态：

| 状态 | 含义 |
|---|---|
| `ok` | 脚本执行完成。|
| `source_error` | 代码或脚本来源有问题，例如路径不存在、请求不合法。|
| `script_error` | 脚本运行时抛出异常。|
| `timeout` | worker 超过硬超时。|
| `worker_start_error` | worker 启动前置条件不满足。|
| `worker_crashed` | worker 进程异常退出。|
| `worker_result_missing` | worker 退出但没有产生结果文件。|

### 5. 变更预览与写回

`execute_idapython` 可以让 worker 记录 rename、comment、set type、patch bytes 等数据库修改意图，但这些修改不会自动写入 GUI IDA。写回要走 `apply_worker_changes`。

`apply_worker_changes` 的默认模式是 `dry_run=true`，也就是先预览。它会检查数据库指纹、dirty 状态和变更内容，再返回哪些操作会被应用、哪些会被跳过、哪些有错误。确认无误后，再显式关闭 dry-run 写回。

这个设计把“分析脚本运行”和“GUI 数据库修改”分成两步，能减少误操作，也更适合让模型先给出可审阅的修改计划。

### 6. MCP 客户端配置

安装器可以写入常见 MCP 客户端配置，并支持全局配置和部分客户端的项目级配置。

支持的客户端包括：

| 客户端 | 全局配置 | 项目级配置 |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` | 不支持 |
| Claude Code | `.claude.json` | `.mcp.json` |
| Cursor | `.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code | `settings.json` | `.vscode/mcp.json` |
| Windsurf | `mcp_config.json` | `.windsurf/mcp_config.json` |
| Codex | `~/.codex/config.toml` | `.codex/config.toml` |

### 7. 随包分发的 IDAPython 参考文档

包内包含 IDAPython markdown 参考资料：

```text
ida_script_mcp/resources/idapython/
```

其中包括 `SKILL.md` 和 `docs/*.md`。这些资料可以给模型提供 IDAPython 模块参考和实用写法提示，减少模型凭空猜 API 的情况。

## MCP 工具一览

| 工具 | 作用 | 是否只读 |
|---|---|---|
| `list_ida_instances` | 枚举当前可用的 IDA 实例。 | 是 |
| `get_ida_database_info` | 获取目标数据库的元信息。 | 是 |
| `list_functions` | 列出函数，支持分页和过滤。 | 是 |
| `decompile_function` | 反编译指定函数，可选返回汇编。 | 是 |
| `get_xrefs` | 查询某地址或符号的交叉引用。 | 是 |
| `execute_idapython` | 在隔离 worker 中执行自定义 IDAPython。 | 否 |
| `apply_worker_changes` | 预览或写回 worker 记录的结构化变更。 | 否 |

## 安装要求

- IDA Pro 8.3 或更新版本。
- Python 3.11 或更新版本。
- 一个支持 MCP 的客户端。
- 如果要使用 `execute_idapython` 的隔离执行能力，需要 GUI IDA 旁边存在对应的 headless IDA 可执行文件，例如 `idat64.exe`。

## 安装

### 从 PyPI 安装

```bash
pip install ida-script-mcp
ida-script-mcp-install install codex
```

上面的命令会安装 Python 包、安装 IDA 插件，并为 Codex 写入 MCP 配置。

### 配置其他客户端

```bash
# 只安装 IDA 插件
ida-script-mcp-install install

# 安装插件并配置单个客户端
ida-script-mcp-install install claude
ida-script-mcp-install install cursor
ida-script-mcp-install install vscode

# 一次配置多个客户端
ida-script-mcp-install install claude,codex,cursor

# 为支持项目级配置的客户端写入项目配置
ida-script-mcp-install install --project codex

# 查看支持的客户端名称
ida-script-mcp-install --list-clients

# 打印 MCP 配置片段
ida-script-mcp-install --config
```

### 从源码安装

```bash
git clone https://github.com/yourusername/ida-script-mcp.git
cd ida-script-mcp
pip install -e .
ida-script-mcp-install install codex
```

## 启动方式

1. 在系统 Python 环境中安装本包。
2. 运行 `ida-script-mcp-install install <client>` 安装 IDA 插件并写入 MCP 客户端配置。
3. 打开 IDA Pro，加载目标数据库。
4. 在 IDA 菜单中选择 **Edit → Plugins → IDA-Script-MCP**，或按 `Ctrl+Alt+S`。
5. 让 MCP 客户端连接 `ida-script-mcp` 服务。
6. 在客户端里先调用 `list_ida_instances`，确认目标数据库后再继续分析。

也可以手动启动 MCP 服务：

```bash
ida-script-mcp
```

## 推荐使用方式

### 读取优先走结构化工具

先使用 `get_ida_database_info`、`list_functions`、`decompile_function` 和 `get_xrefs`。这些工具返回稳定字段，比临时脚本更容易审阅，也更不容易影响 IDB 状态。

### 多实例时显式选择目标

当 `list_ida_instances` 返回多个实例时，后续调用建议传入 `instance_id` 或 `port`：

```json
{
  "instance_id": "12345_sample.exe"
}
```

也可以用环境变量指定默认目标：

```bash
export IDA_SCRIPT_MCP_INSTANCE_ID="12345_sample.exe"
export IDA_SCRIPT_MCP_PORT="13338"
```

在 Windows PowerShell 中：

```powershell
$env:IDA_SCRIPT_MCP_INSTANCE_ID = "12345_sample.exe"
$env:IDA_SCRIPT_MCP_PORT = "13338"
```

### 写操作先预览

涉及 rename、comment、set type、patch bytes 等写操作时，推荐流程是：

1. 用 `execute_idapython` 在 worker 中生成变更集。
2. 用 `apply_worker_changes` 的默认 dry-run 查看将要写入的内容。
3. 确认目标数据库和变更内容正确后，再显式写回。

## 安全边界

`execute_idapython` 仍然是强能力工具：它能运行 Python，也能间接产生数据库修改。请只在可信环境中使用，并保持插件只绑定本机地址。

本项目当前的安全边界重点是：

- GUI `/execute` 默认关闭。
- 公共 `execute_idapython` 走独立 worker。
- worker 启动前检查 GUI 数据库状态。
- worker 路径从当前 GUI IDA 推导，不随意使用环境变量或 `PATH`。
- worker 超时后尝试终止进程树。
- 写回 GUI 数据库必须走结构化变更和显式 apply。

这些限制不能把任意脚本变成安全脚本，但能把误操作和失控执行的风险降到更容易观察、审阅和中止的范围内。

## 卸载

```bash
ida-script-mcp-install uninstall
```

如需删除某个 MCP 客户端配置中的服务项，可以重新编辑对应客户端配置文件，移除 `ida-script-mcp` server 块。

## 许可证

MIT License
