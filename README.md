# IDA Script MCP

IDA Script MCP 是一个把 AI 助手连接到本机 IDA Pro 的 MCP 插件。它的目标不是把所有逆向分析都塞进一条万能脚本，而是把常见读取操作做成稳定、结构化的工具，同时保留 `execute_idapython` 作为可信场景下的完整 IDAPython 执行入口。

## 主要特性

- **多 IDA 实例支持**：可以发现并选择本机正在运行的多个 IDA 数据库。
- **结构化只读分析工具**：函数列表、数据库信息、反编译结果、交叉引用查询都有独立工具，不需要每次让模型临时拼 IDAPython。
- **完整 IDAPython 执行能力**：`execute_idapython` 支持执行代码字符串或脚本文件，用于重命名、改类型、打补丁、批量分析等长尾任务。
- **严格执行协议**：`/execute` 请求使用统一的严格模型，输入字段明确，结果状态明确，错误信息结构化。
- **执行超时保护**：IDAPython 执行加入 Python bytecode 级软超时，常见死循环会返回 `timeout`，MCP server 侧也有等待插件响应的兜底超时。
- **执行串行化**：同一 IDA 插件进程内一次只运行一个脚本，避免多个写操作并发修改 IDB。
- **输出捕获**：可捕获脚本的 `stdout` 和 `stderr`，返回给 MCP 调用方。
- **默认 localhost**：插件默认只监听本机地址，适合本地 AI 助手和 IDA 协作。
- **随包 IDAPython 参考资料**：包内带有 IDAPython markdown 文档和使用指南，方便模型理解 IDA API。
- **多 MCP 客户端配置**：安装器支持 Claude Desktop、Claude Code、Cursor、VS Code、Windsurf、Codex 等客户端配置。

## 系统要求

- IDA Pro 8.3 或更高版本
- Python 3.11 或更高版本
- Windows、macOS 或 Linux

> IDA Free 不在支持范围内。

## 安装

### 从 PyPI 安装

```bash
pip install ida-script-mcp
ida-script-mcp-install install codex
```

### 使用 IDA 自带 Python 安装插件

如果 IDA 使用独立 Python 环境，可以显式调用 IDA 附带的 Python：

```bash
"D:\ida\python311\python.exe" -m pip install ida-script-mcp
"D:\ida\python311\python.exe" -m ida_script_mcp.installer install codex
```

### 从源码安装

```bash
git clone https://github.com/qqq694637644/ida-script-mcp-main.git
cd ida-script-mcp-main
pip install -e .
ida-script-mcp-install install codex
```

### 安装器常用命令

```bash
# 仅安装 IDA 插件
ida-script-mcp-install install

# 同时配置多个 MCP 客户端
ida-script-mcp-install install claude,codex,cursor

# 写入项目级 Codex 配置
ida-script-mcp-install install --project codex

# 查看支持的客户端
ida-script-mcp-install --list-clients
```

## 启动 IDA 插件

1. 打开 IDA Pro 并加载数据库。
2. 进入 **Edit → Plugins → IDA-Script-MCP**，或者按 `Ctrl+Alt+S`。
3. IDA 会在输出窗口打印实例 ID、端口和本地 HTTP 端点。

示例输出：

```text
[IDA-Script-MCP] Server started at http://127.0.0.1:13338
[IDA-Script-MCP] Instance ID: 12345_sample.exe
[IDA-Script-MCP] Metadata endpoint: GET http://127.0.0.1:13338/metadata
[IDA-Script-MCP] Functions endpoint: POST http://127.0.0.1:13338/functions
[IDA-Script-MCP] Decompile endpoint: POST http://127.0.0.1:13338/decompile
[IDA-Script-MCP] Xrefs endpoint: POST http://127.0.0.1:13338/xrefs
[IDA-Script-MCP] Execute endpoint: POST http://127.0.0.1:13338/execute
```

## MCP 工具

| 工具 | 作用 | 是否只读 |
|---|---|---|
| `list_ida_instances` | 枚举本机正在运行的 IDA 插件实例 | 是 |
| `get_ida_database_info` | 获取当前 IDB 的文件名、架构、入口点、函数数量等信息 | 是 |
| `list_functions` | 按名称、地址、数量等条件列出函数 | 是 |
| `decompile_function` | 获取函数伪代码，并可选返回反汇编 | 是 |
| `get_xrefs` | 查询地址或符号的交叉引用 | 是 |
| `execute_idapython` | 在 IDA 内执行自定义 IDAPython 代码或脚本文件 | 否 |

推荐顺序是：先用 `list_ida_instances` 确认目标 IDA，再用 `get_ida_database_info` 确认数据库，日常读取优先使用 `list_functions`、`decompile_function`、`get_xrefs`。只有在需要写操作或专用逻辑时，再使用 `execute_idapython`。

## `execute_idapython` 的改进

这一版把 `/execute` 重构成严格执行子系统，重点是可控、可观测、结果稳定。

### 严格输入

`execute_idapython` 支持两种来源，但一次只能提供一种：

- `code`：直接传入 IDAPython 代码字符串；
- `script_path`：传入 IDA 所在机器上可读取的 Python 脚本路径。

常用字段：

| 字段 | 默认值 | 说明 |
|---|---:|---|
| `code` | `null` | 要执行的代码字符串 |
| `script_path` | `null` | 要执行的脚本文件路径 |
| `capture_output` | `true` | 是否捕获 `stdout` / `stderr` |
| `timeout_seconds` | `30` | Python bytecode 级软超时时间，范围 1 到 600 秒 |
| `instance_id` | `null` | 多开 IDA 时指定目标实例 |
| `port` | `null` | 直接指定目标插件端口 |

### 结构化结果

执行结果会返回统一字段，便于 AI 助手判断下一步动作：

| 状态 | 含义 |
|---|---|
| `ok` | 脚本执行成功 |
| `timeout` | Python bytecode 执行超过 `timeout_seconds` |
| `script_error` | 脚本运行时异常 |
| `source_error` | 代码、脚本路径或请求格式有问题 |
| `busy` | 当前 IDA 实例已有脚本在运行 |
| `plugin_response_timeout` | MCP server 等待插件响应超时 |

结果中还会包含：

- `result`：表达式返回值，或脚本里的 `result` 变量；
- `stdout` / `stderr`：脚本输出；
- `error.type` / `error.message` / `error.traceback`：结构化错误；
- `duration_seconds`：执行耗时；
- `timeout_seconds`：本次请求使用的超时；
- `instance_id` / `port`：实际命中的 IDA 实例。

### 超时机制

插件内的执行超时使用 `sys.settrace` 做行级检查。普通 Python 死循环、长时间纯 Python 计算等情况会被软中断，并返回：

```json
{
  "status": "timeout",
  "error": {
    "type": "ScriptExecutionTimeout"
  }
}
```

这不是强杀线程或强杀 IDA 进程。它更适合 IDA 这种带 GUI、数据库状态和 native API 的环境：能防住常见脚本错误，又避免粗暴终止导致 IDB 状态不一致。

如果脚本长时间阻塞在 native IDA/C 扩展调用里，Python 层软超时可能要等控制权回到 Python 后才触发。此时 MCP server 侧还有 `timeout_seconds + 5` 秒的响应等待超时，会返回 `plugin_response_timeout`，表示调用方已经停止等待插件响应。

### 示例

执行表达式：

```json
{
  "code": "hex(idaapi.get_imagebase())"
}
```

执行多行代码并返回 `result`：

```json
{
  "code": "import idautils\nresult = len(list(idautils.Functions()))"
}
```

执行脚本文件：

```json
{
  "script_path": "D:/work/ida_scripts/rename_functions.py",
  "timeout_seconds": 120
}
```

指定实例：

```json
{
  "instance_id": "12345_sample.exe",
  "code": "result = idaapi.get_inf_structure().procname"
}
```

## 插件 HTTP 端点

IDA 插件本身提供本地 HTTP 端点，MCP server 会调用这些端点完成操作：

| 端点 | 方法 | 作用 |
|---|---|---|
| `/metadata` | `GET` | 获取数据库和实例元信息 |
| `/functions` | `POST` | 获取函数列表 |
| `/decompile` | `POST` | 反编译函数 |
| `/xrefs` | `POST` | 查询交叉引用 |
| `/execute` | `POST` | 执行严格 IDAPython 请求 |
| `/execution/status` | `GET` | 查看当前执行状态 |

正常使用时不需要手动调用这些端点，直接通过 MCP 工具即可。

## 多实例选择

当同时打开多个 IDA 数据库时，先调用：

```text
list_ida_instances
```

然后在后续工具里传入 `instance_id` 或 `port`。如果只运行一个 IDA 实例，可以不传，服务器会自动选择唯一实例。

## 支持的 MCP 客户端

| 客户端 | 全局配置 | 项目级配置 |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` | 不支持 |
| Claude Code | `.claude.json` | `.mcp.json` |
| Cursor | `.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code | `settings.json` | `.vscode/mcp.json` |
| Windsurf | `mcp_config.json` | `.windsurf/mcp_config.json` |
| Codex | `~/.codex/config.toml` | `.codex/config.toml` |

## 包内 IDAPython 文档

安装包内包含 IDAPython 相关 markdown 文档，路径类似：

```text
ida_script_mcp/resources/idapython/
```

其中包括：

- `SKILL.md`
- `docs/*.md`

这些文档适合给本地 AI 助手作为 IDA API 参考资料，帮助模型更准确地使用 IDAPython。

## 安全说明

`execute_idapython` 可以在 IDA 进程内执行任意 Python，也可以修改 IDB。它应该只和可信助手、可信脚本一起使用。

建议保持默认 localhost 监听，不要把插件端口暴露到不可信网络。对于常规读取任务，优先使用只读工具；对于重命名、改类型、patch bytes 等写操作，再使用 `execute_idapython`。

## 许可证

MIT License
