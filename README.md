# IDA Script MCP

IDA Script MCP 是一套把 AI 助手连接到本机 IDA Pro 的 MCP 服务与 IDA 插件。它为逆向分析提供稳定、结构化、可审阅的工具接口：常见读取操作走专门的只读工具，复杂长尾需求走改进后的 `execute_idapython` 隔离执行路径，数据库写入则通过显式的变更预览和写回完成。

这个项目的重点是让模型更可靠地使用 IDA，而不是每次都临时拼接一段不可控的 IDAPython。

## 主要特性

### 本机 IDA 插件

插件在 IDA 内启动后默认只监听 `127.0.0.1`，供本机 MCP 服务访问。它会注册当前 IDA 实例，并暴露结构化 HTTP 端点。

插件启动后，IDA 输出窗口会显示类似信息：

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

默认端口从 `13338` 开始。如果端口被占用，插件会尝试后续端口。

### 多 IDA 实例支持

当你同时打开多个 IDA 数据库时，插件会把实例信息写入本机注册表。MCP 客户端可以先调用 `list_ida_instances` 查看当前可用实例，再通过 `instance_id` 或 `port` 精确选择目标。

这样可以避免模型在多开 IDA 时读错数据库或把写操作发到错误实例。

### 结构化只读分析

常见逆向读取不需要再依赖临时脚本。MCP 服务提供固定工具读取 IDA 数据：

- `get_ida_database_info`：读取数据库路径、输入文件、处理器架构、入口点、函数数量、dirty 状态等元信息。
- `list_functions`：列出函数，支持分页、名称过滤、thunk/library 选项。
- `decompile_function`：按地址或函数名反编译，返回 Hex-Rays 伪代码，可选附带汇编。
- `get_xrefs`：查询某个地址或符号的入引用、出引用，并可按 code/data/flow/all 过滤。

这些接口返回结构化 JSON，适合模型继续推理、引用和交叉验证。

## `execute_idapython` 的改进

`execute_idapython` 保留了完整 IDAPython 能力，但执行方式已经改成严格的隔离执行模型。它不再默认把用户代码直接塞进 GUI IDA 进程的 `/execute` 端点运行。

新的执行路径是：

1. MCP 服务先读取当前 GUI IDA 的安全上下文，包括实例、PID、IDA 可执行文件路径、数据库路径、dirty 状态和保存后数据库指纹。
2. 如果 GUI 数据库处于未保存状态、dirty 状态未知、数据库路径不可确认或保存文件哈希不可计算，执行会直接拒绝。
3. 服务从当前 GUI `ida64.exe` 所在目录推导同目录的 headless worker，通常是 `idat64.exe`。如果不能确认 worker 路径，不会退回到环境变量或 `PATH` 里随便找 IDA。
4. 用户脚本在独立 worker 进程中运行，而不是在 GUI IDA 进程中运行。
5. worker 返回结构化结果，包括 `status`、`stdout`、`stderr`、错误类型、traceback、worker PID、退出码、超时信息和可选变更集。
6. 超时是进程级硬超时。超时后会尝试终止 worker 进程树，避免脚本卡住 GUI IDA。
7. 数据库写操作不会自动落到 GUI 数据库。worker 只记录结构化变更，后续需要通过 `apply_worker_changes` 预览或写回。

旧式 GUI `/execute` HTTP 端点默认关闭。除非显式设置：

```text
IDA_SCRIPT_MCP_ENABLE_UNSAFE_GUI_EXECUTE=1
```

否则插件会拒绝 GUI `/execute` 请求。普通使用应走 MCP 工具 `execute_idapython`。

### `execute_idapython` 参数

| 参数 | 说明 |
|---|---|
| `code` | 直接传入 IDAPython 代码。|
| `script_path` | 传入脚本文件路径。`code` 和 `script_path` 必须且只能提供一个。|
| `capture_output` | 是否捕获 stdout/stderr，默认 `true`。|
| `timeout_seconds` | worker 硬超时，默认 30 秒，范围 1 到 600 秒。|
| `collect_changes` | 是否记录 worker 内产生的结构化变更，默认 `true`。|
| `instance_id` | 指定目标 IDA 实例。|
| `port` | 直接指定目标插件端口，优先级高于 `instance_id`。|

### 常见返回状态

| 状态 | 含义 |
|---|---|
| `ok` | 脚本执行完成。|
| `source_error` | 请求或脚本来源有问题，例如路径不存在、参数不合法。|
| `script_error` | 用户脚本运行时抛出异常。|
| `timeout` | worker 超过硬超时。|
| `worker_start_error` | worker 启动前置条件不满足。|
| `worker_crashed` | worker 进程异常退出。|
| `worker_result_missing` | worker 退出但没有产生结果文件。|

## 变更预览与写回

`execute_idapython` 可以让 worker 记录 rename、comment、set type、patch bytes 等数据库修改意图，但这些修改不会自动写入 GUI 数据库。

写回要通过 `apply_worker_changes`。它默认是 `dry_run=true`，也就是先预览：

- 检查目标数据库指纹是否匹配。
- 检查 GUI 数据库是否处于可写入状态。
- 展示将被应用、跳过或报错的操作。
- 只有显式设置 `dry_run=false` 时才会真正修改 GUI 数据库。

这个设计把“脚本执行”和“数据库写入”分成两个阶段，让模型生成的修改可以先被人审阅。

## MCP 工具一览

| 工具 | 作用 | 是否只读 |
|---|---|---|
| `list_ida_instances` | 枚举当前可用的 IDA 实例。 | 是 |
| `get_ida_database_info` | 获取目标数据库元信息。 | 是 |
| `list_functions` | 列出函数，支持分页和过滤。 | 是 |
| `decompile_function` | 反编译指定函数，可选返回汇编。 | 是 |
| `get_xrefs` | 查询某地址或符号的交叉引用。 | 是 |
| `execute_idapython` | 在隔离 worker 中执行自定义 IDAPython。 | 否 |
| `apply_worker_changes` | 预览或写回 worker 记录的结构化变更。 | 否 |

## 安装要求

- IDA Pro 8.3 或更新版本。
- IDA 侧需要可用的 IDAPython 3.11。
- MCP 服务侧需要 Python 3.11 或更新版本。
- 使用隔离执行时，GUI IDA 旁边需要有对应的 headless IDA 可执行文件，例如 `idat64.exe`。
- 一个支持 MCP 的客户端，例如 Codex、Claude、Cursor、VS Code 或 Windsurf。

## 安装

### 从源码安装

```powershell
git clone https://github.com/qqq694637644/ida-script-mcp-main.git
cd ida-script-mcp-main
py -3 -m pip install -e .
```

### 安装 IDA 插件

```powershell
py -3 -m ida_script_mcp.installer install
```

也可以使用 console script：

```powershell
ida-script-mcp-install install
```

安装器会把插件安装到 IDA 的用户插件目录，例如：

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_script_mcp.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_script_mcp_support\protocol.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_script_mcp_support\execution.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_script_mcp_support\change_protocol.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_script_mcp_support\change_recorder.py
```

支持模块放在 `ida_script_mcp_support/` 中，避免 IDA 把辅助文件误识别成插件入口。

### 配置 MCP 客户端

```powershell
# 安装插件并配置 Codex
ida-script-mcp-install install codex

# 一次配置多个客户端
ida-script-mcp-install install claude,codex,cursor

# 写入项目级 Codex 配置
ida-script-mcp-install install --project codex

# 查看支持的客户端
ida-script-mcp-install --list-clients

# 打印 MCP 配置片段
ida-script-mcp-install --config
```

支持的客户端：

| 客户端 | 全局配置 | 项目级配置 |
|---|---|---|
| Claude Desktop | `claude_desktop_config.json` | 不支持 |
| Claude Code | `.claude.json` | `.mcp.json` |
| Cursor | `.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code | `settings.json` | `.vscode/mcp.json` |
| Windsurf | `mcp_config.json` | `.windsurf/mcp_config.json` |
| Codex | `~/.codex/config.toml` | `.codex/config.toml` |

## 启动使用

1. 安装 Python 包和 IDA 插件。
2. 打开 IDA Pro，并加载目标数据库。
3. 在 IDA 中选择 **Edit → Plugins → IDA-Script-MCP**，或按 `Ctrl+Alt+S`。
4. 启动你的 MCP 客户端。
5. 先调用 `list_ida_instances` 确认目标实例。
6. 读取分析优先使用结构化只读工具。
7. 只有在结构化工具不能满足需求时，再使用 `execute_idapython`。

如果需要手动启动 MCP 服务：

```powershell
ida-script-mcp
```

## 多实例选择

后续工具调用可以传入 `instance_id`：

```json
{
  "instance_id": "12345_sample.exe"
}
```

也可以直接传入端口：

```json
{
  "port": 13338
}
```

还可以用环境变量设置默认目标。

PowerShell：

```powershell
$env:IDA_SCRIPT_MCP_INSTANCE_ID = "12345_sample.exe"
$env:IDA_SCRIPT_MCP_PORT = "13338"
```

Bash：

```bash
export IDA_SCRIPT_MCP_INSTANCE_ID="12345_sample.exe"
export IDA_SCRIPT_MCP_PORT="13338"
```

## 推荐用法

### 读取优先

日常分析优先使用：

1. `get_ida_database_info`
2. `list_functions`
3. `decompile_function`
4. `get_xrefs`

这些工具更稳定，也更容易让人审阅模型的分析依据。

### 写入谨慎

涉及 rename、comment、set type、patch bytes 等操作时，推荐流程是：

1. 用 `execute_idapython` 在 worker 中生成变更集。
2. 用 `apply_worker_changes` 的默认 dry-run 查看将要写入的内容。
3. 确认目标数据库、数据库指纹和变更内容正确。
4. 再显式设置 `dry_run=false` 写回。

## 安全边界

`execute_idapython` 仍然是强能力工具。它能运行 Python，也能生成数据库修改意图。请只在可信本机环境中使用，并保持插件监听本机地址。

当前设计的安全边界包括：

- GUI `/execute` 默认关闭。
- 公共 `execute_idapython` 走独立 worker。
- worker 启动前检查 GUI 数据库状态。
- worker 路径从当前 GUI IDA 推导，不随意使用环境变量或 `PATH`。
- worker 超时后尝试终止进程树。
- 写回 GUI 数据库必须走结构化变更和显式 apply。

这些限制不能把任意脚本变成安全脚本，但能把误操作和失控执行风险降到更容易观察、审阅和中止的范围内。

## 随包 IDAPython 参考资料

包内包含 IDAPython markdown 参考资料：

```text
ida_script_mcp/resources/idapython/
```

其中包括 `SKILL.md` 和 `docs/*.md`。这些资料可以帮助模型减少凭空猜 API 的情况。

## 卸载

```powershell
ida-script-mcp-install uninstall
```

如果还需要删除 MCP 客户端配置，可以在对应客户端配置文件中移除 `ida-script-mcp` server 块。

## 许可证

MIT License
