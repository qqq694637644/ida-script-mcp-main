# 测试架构与接手方案

Last updated: 2026-06-04

这个文件是给后续 AI 或维护者接手测试工作的入口。它必须回答四个问题：

1. 当前项目到底要测哪条架构链路。
2. 现有 HostMachine / disposable guest VM / IDA workflow 怎么跑。
3. 已测和未测如何迁移、如何记录证据。
4. 下一位维护者应该从哪一个测试开始，不要重复踩哪些坑。

配套文件：

| 文件 | 用途 |
| --- | --- |
| `README.md` | 产品架构、MCP tools、IDA 插件 endpoint、隔离执行设计。 |
| `DISPOSABLE_VM_WORKFLOW_LESSONS.md` | HostMachine -> guest VM -> IDA workflow 的成功/失败经验。 |
| `PORTABLE_WORKFLOW_DEVELOPMENT_LESSONS.md` | 可迁移到其他仓库的 workflow 开发经验。 |
| `TESTED.md` | 已经测过的范围和证据。 |
| `UNTESTED.md` | 未测 backlog。测试通过后从这里移到 `TESTED.md`。 |

## 1. 产品整体测试架构

V2.3 的核心不是“能不能调用 IDA 插件”，而是下面这条安全边界是否成立：

```text
AI / MCP client
  -> ida_script_mcp.server
      -> 结构化只读请求：转发到 GUI IDA 插件 endpoint
      -> 任意/custom IDAPython：进入 headless isolated worker
      -> worker 产出 result.json 和可选 ChangeSet
      -> apply_worker_changes：把 ChangeSet 显式回放到 GUI 插件 /apply_changes
  -> GUI IDA database 只在显式 apply 时被写入
```

因此测试也要分成三层，不要混在一起：

| 层 | 要证明什么 | 典型入口 | 是否会写 GUI 数据库 |
| --- | --- | --- | --- |
| GUI 插件只读层 | `/metadata`、`/functions`、`/decompile`、`/xrefs`、`/inspect_address` 能稳定读 live IDA | guest payload 直接 HTTP 调插件 | 否 |
| 隔离 worker 层 | `execute_idapython` 会复制 saved IDB/I64 并启动 headless IDA worker，超时/崩溃有结构化状态 | MCP server `execute_idapython` | worker copy only |
| 显式回放层 | worker 生成的 `ChangeSet` 只能通过 `apply_worker_changes` / GUI `/apply_changes` 回放，且 fingerprint / dirty state 拦截有效 | MCP server `apply_worker_changes` 或 GUI `/apply_changes` | 仅 `dry_run=false` 时写 |

安全规则必须一直保持：

```text
Public execute_idapython 不允许 fallback 到 GUI /execute
GUI /execute 默认 HTTP 410 rejected
/apply_changes 默认 dry_run=true
fingerprint 不匹配必须 rejected
dirty/unsaved/dirty unknown 必须 rejected
worker timeout 必须杀进程树
worker 进程隔离不是完整安全沙箱，不能把它描述成强沙箱
```

## 2. 代码模块地图

接手时先看这些文件，不要全仓库乱搜：

| 模块 | 文件 | 重点 |
| --- | --- | --- |
| MCP server | `src/ida_script_mcp/server.py` | tool schema、instance 解析、`execute_idapython`、`apply_worker_changes` |
| GUI IDA 插件 | `src/ida_script_mcp/ida_plugin.py` | HTTP handler、metadata、dirty state、fingerprint、`/apply_changes`、`/execute` 410 |
| 隔离执行 manager | `src/ida_script_mcp/isolated_manager.py` | DB copy、IDA executable 发现、worker launch、timeout、kill tree、result 分类 |
| worker runner | `src/ida_script_mcp/worker_runner.py` | IDA batch/auto_wait、确认打开 copied DB、安装 recorder、写 result/changes |
| 执行器 | `src/ida_script_mcp/execution.py` | Python source 编译执行、soft timeout、stdout/stderr 捕获 |
| 变更协议 | `src/ida_script_mcp/change_protocol.py` | `ChangeSet`、operation schema、fingerprint matching |
| 变更记录 | `src/ida_script_mcp/change_recorder.py` | monkeypatch IDAPython 写 API、`mcp_changes` explicit API |
| Host 主控 | `src/ida_script_mcp/disposable_vm/host_controller.py` | `/hello`、`/payload`、`/log`、`/result`、artifact 状态 |
| Guest agent | `src/ida_script_mcp/guest_vm/agent.py` | guest 主动连接 host、下载 payload、执行并回传结果 |
| IDA API payload | `src/ida_script_mcp/payload/ida_api_test.py` | 安装插件、启动 IDA、外部 HTTP 测试、heartbeat/result |

## 3. Disposable VM workflow 总架构

当前真实集成测试不是普通 GitHub-hosted CI，而是 HostMachine 自托管 runner 驱动 VMware guest：

```text
GitHub workflow_dispatch
  -> HostMachine self-hosted Windows runner
      -> checkout repository
      -> py -3 -m pip install -e .
      -> start host controller on 0.0.0.0:8766
      -> optional: run C:\Users\alion\Scripts\vmware_restore_test1.py --gui
      -> wait guest agent POST /hello
      -> serve dynamic payload at /payload/{job_id}
      -> receive guest /log/{job_id}
      -> receive guest /result/{job_id}
      -> upload $RUNNER_TEMP\ida-script-mcp-disposable-vm artifact
```

Guest VM 侧流程：

```text
guest snapshot boots
  -> guest agent starts
  -> POST http://192.168.1.249:8766/hello
  -> GET  http://192.168.1.249:8766/payload/{job_id}
  -> run payload: noop / command / python_script
  -> POST /log/{job_id}
  -> POST /result/{job_id}
```

IDA payload 侧流程：

```text
python_script payload in guest
  -> write plugin files to %APPDATA%\Hex-Rays\IDA Pro\plugins
  -> remove legacy root-level support files
  -> start C:\Users\alion\Desktop\IDAPro8.3\ida64.exe -A -S<bootstrap>
  -> open C:\Users\alion\Desktop\test1.dll into temp test1.i64
  -> bootstrap waits ida_auto.auto_wait()
  -> bootstrap starts IDA-Script-MCP plugin server
  -> bootstrap writes ida_ready.json with base_url / instance_id / database_path
  -> payload outside IDA calls http://127.0.0.1:13338 endpoints
  -> payload writes heartbeat.ndjson and ida_api_test_result.json/result.json
  -> payload terminates IDA and returns exit_code to host
```

## 4. 当前可用 workflow 和输入

Workflow 文件：

```text
.github/workflows/disposable-vm-guest-agent-smoke.yml
```

可用 `task_action`：

```text
noop
command
python_script
ida_plugin_install
ida_plugin_api_test
ida_plugin_apply_changes_test
ida_plugin_worker_chain_test
ida_plugin_worker_timeout_test
ida_plugin_worker_failure_matrix_test
ida_plugin_u004_real_mcp_client_test
ida_plugin_u009_inspect_address_test
```

### 非破坏性 full smoke

```text
task_action=ida_plugin_api_test
ida_api_test_mode=full
ida_timeout_seconds=180
run_timeout_seconds=300
connect_timeout_seconds=600
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
restore_extra_args_json=[]
```

它验证的是 GUI 插件 HTTP API，不验证完整 MCP `execute_idapython` worker replay 主链路。

### destructive apply_changes smoke

```text
task_action=ida_plugin_apply_changes_test
ida_api_test_mode=apply_changes
ida_timeout_seconds=180
run_timeout_seconds=300
connect_timeout_seconds=600
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
restore_extra_args_json=[]
```

它验证 GUI `/apply_changes`，包括 dry-run、bad fingerprint、destructive apply、dirty rejection。它仍然不等于 U001，因为它没有通过 MCP `execute_idapython` 生成 worker `ChangeSet`。

### U009 `/inspect_address` system test

```text
task_action=ida_plugin_u009_inspect_address_test
ida_timeout_seconds=240
run_timeout_seconds=900
connect_timeout_seconds=600
ida_dir=C:\Users\alion\Desktop\IDAPro8.3
dll_path=C:\Users\alion\Desktop\test1.dll
controller_url=http://192.168.1.249:8766
port=8766
run_vmware_restore=true
restore_script=C:\Users\alion\Scripts\vmware_restore_test1.py
restore_gui=true
restore_extra_args_json=[]
```

它验证 GUI `/inspect_address` 的 invalid/missing target、`byte_count` 边界、data/instruction-middle/unmapped 地址、name lookup、Unicode comments、repeatable comments、type readback，以及 repeated inspect 后 GUI DB 仍 clean。


## 5. 当前最新一次测试结果

刚跑完的 U009 `/inspect_address` 系统测试：

| 字段 | 值 |
| --- | --- |
| Workflow run | `26926388631` |
| Workflow | `Disposable VM guest agent smoke` |
| Branch / commit | `gpt/testing-u009-20260604-5b6c55` / `d1a0cde1502d6f76f3257a18275dba00b25ca64c` |
| PR / target | `#6` -> `gpt/testing-handoff-tracker-20260604-bf55c1` |
| Job | `Host controller and guest agent smoke` |
| Runner | `HostMachine` |
| Conclusion | `success` |
| Artifact | `disposable-vm-guest-agent-smoke`, artifact id `7401596027` |
| Guest result | `status=completed`, `exit_code=0` |
| Payload | `mode=inspect_address`, `status=passed` |
| Key warning | IDA 8.3 normalized requested Unicode symbol name to ASCII fallback; Unicode comments/repeatable comments still round-tripped. |

该 run 验证：

```text
/inspect_address invalid address structured error
/inspect_address missing address/name structured error
byte_count=0/negative -> clamp to 1
byte_count huge -> clamp to 64
data address readback
instruction-middle address readback
high unmapped address returns no symbol/comment/type/disassembly metadata
name lookup returns the seeded target
Unicode regular comment readback
Unicode repeatable comment readback
Unicode function comment readback
Unicode repeatable function comment readback
type text readback
metadata_after_u009.dirty=false
metadata_after_u009.apply_changes_mutated=false
```

U001、U002、U003、U004、U009 已通过并移入 `TESTED.md`。U005-U008、U010+ 仍保留在 `UNTESTED.md`。

## 6. 已测/未测迁移规则

`UNTESTED.md` 是待办队列，`TESTED.md` 是证据账本。

### 测试脚本命名规范

所有新增的测试用脚本必须使用 `U00x_测试功能.py` 命名，保证文件名能直接对应 `UNTESTED.md` / `TESTED.md` 里的测试编号和测试目标。不要再使用只有技术实现含义、但看不出对应测试编号的临时脚本名。

示例：

```text
U004_real_MCP_client_end-to-end.py
```

命名规则：

```text
U00x_<short_test_function>.py
```

如果同一个 U 项需要多个辅助脚本，也必须保留同一个编号前缀，例如：

```text
U004_real_MCP_client_bootstrap.py
U004_real_MCP_client_worker_script.py
U004_real_MCP_client_assertions.py
```

核心测试逻辑必须是仓库里的真实 `.py` 文件，允许 workflow/builder 把文件内容打包传给 guest，但不要把主要测试逻辑直接拼成不可 review 的大字符串。

迁移规则：

```text
从 UNTESTED.md 选择一项
-> 运行最小可证明测试
-> 查 GitHub run conclusion
-> 查 artifact JSON，不只看绿色勾
-> 如果通过：从 UNTESTED.md 删除该项，并追加到 TESTED.md
-> 如果失败：保留在 UNTESTED.md，并把失败写入 DISPOSABLE_VM_WORKFLOW_LESSONS.md
```

一项只能在满足这些条件时移入 `TESTED.md`：

1. 有 run ID / commit / branch / artifact id。
2. artifact 里能看到 `controller_state.json`、`result.json` 或 payload 自己的结果文件。
3. 写清楚具体断言，不只写“workflow 绿了”。
4. destructive 测试说明是否只作用于临时 `.i64`。
5. 对 U001 这类链路测试，必须证明每个中间环节都发生了：metadata、DB copy、worker、changes、dry-run、destructive apply、inspect。

证据模板：

```markdown
### YYYY-MM-DD - Uxxx 标题

Evidence:
- Workflow run: `<run_id>` attempt `<n>`
- Commit/branch: `<sha>` / `<branch>`
- Inputs: `<关键 inputs>`
- Artifact: `<artifact name>` / `<artifact id>`
- Files inspected: `controller_state.json`, `result.json`, `<payload result>`

Assertions:
- `<controller_state.status>`
- `<guest result status / exit_code>`
- `<endpoint/tool response>`
- `<database dirty/fingerprint/process cleanup>`

Notes:
- `<风险和后续>`
```

## 7. 下一步真正该测什么

U001 已由 workflow run `26922985347` 通过并移入 `TESTED.md`。U002 已由 workflow run `26923418555` 通过并移入 `TESTED.md`。U003 已由 workflow run `26923830535` 通过并移入 `TESTED.md`。U004 已由 workflow run `26925268750` 通过并移入 `TESTED.md`。U009 已由 workflow run `26926388631` 通过并移入 `TESTED.md`。现在仍建议从 `UNTESTED.md` 中 U005 多 IDA 实例选择开始。

### U001：完整 V2.3 主链路（已通过）

Run `26922985347` 已验证：

```text
execute_idapython
-> headless IDA worker
-> worker-generated ChangeSet(rename, comment)
-> apply_worker_changes dry-run
-> apply_worker_changes destructive replay
-> inspect_address 验证 GUI mutation
```

证据已经移入 `TESTED.md`。后续不要重复跑 U001，除非修改了 execute/worker/apply 链路。

### U002：worker hard timeout / kill process tree（已通过）

Run `26923418555` 已验证：

```text
execute_idapython(script_path=worker_timeout_user_script.py, timeout_seconds=2)
-> result.status == timeout
-> hard_timeout == true
-> killed == true
-> worker_exit_code/worker_pid 有记录
-> worker_process_alive_after_kill == false
-> sentinel_seen == true
-> GUI metadata_after_timeout.dirty == false
```

证据已经移入 `TESTED.md`。后续不要重复跑 U002，除非修改了 worker timeout/kill 逻辑。

### U003：worker 异常状态矩阵（已通过）

Run `26923830535` 已验证：

```text
worker_start_error: IDA_SCRIPT_MCP_IDA_PATH 指向不存在路径
source_error: script_path/source 无效
worker_crashed: os._exit(13) 导致非零退出且没有 result.json
worker_result_missing: os._exit(0) 导致零退出但没有 result.json
recorder_error: mcp_changes.patch_bytes 非法 hex 触发 RecorderError
rejected: GUI dirty 后 execute_idapython 被拒绝且未启动 worker
```

证据已经移入 `TESTED.md`。后续不要重复跑 U003，除非修改了 worker failure classification 逻辑。


### U004：real MCP client end-to-end（已通过）

Run `26925268750` 已验证：

```text
stdio transport initialize/list_tools/call_tool
HTTP/SSE transport initialize/list_tools/list_ida_instances
list_ida_instances/get_ida_database_info/list_functions/decompile_function/get_xrefs
execute_idapython structured result via real MCP client
apply_worker_changes dry-run via real MCP client
schema params wrapper and timeout_seconds visibility
GUI metadata_after_u004.dirty == false
```

证据已经移入 `TESTED.md`。后续不要重复跑 U004，除非修改了 MCP transport/tool schema/tool result 逻辑。

### U009：/inspect_address 系统测试（已通过）

Run `26926388631` 已验证：

```text
invalid/missing target structured error
byte_count=0/负数/超大值边界
data 地址、instruction 中间地址、高 unmapped 地址
name lookup
Unicode regular/repeatable comments
Unicode function/repeatable function comments
type text readback
repeated inspect 后 GUI DB clean
```

证据已经移入 `TESTED.md`。后续不要重复跑 U009，除非修改了 `/inspect_address`、comment/type/name readback、或 IDA 地址读取契约。

## 8. 失败排查顺序

不要一看到失败就改 payload 或插件。按边界排查：

```text
1. GitHub 是否创建 workflow run？没有 -> workflow_dispatch/indexing/ref 问题
2. runner 是否是 HostMachine？不是 -> self-hosted runner 路由问题
3. checkout/install 是否成功？失败 -> Python/package/env 问题
4. host controller 是否启动？失败 -> fastapi/uvicorn/port 问题
5. vmware_restore.json returncode 是否 0？失败 -> snapshot/VMware 问题
6. controller_state.hello 是否非空？空 -> guest agent 未启动/网络不通
7. payload_downloaded 是否 true？false -> guest 没拿到任务
8. payload result 是否 completed exit_code=0？非 0 -> payload 内部失败
9. ida_ready.json 是否出现？没有 -> IDA 启动/bootstrap/plugin 问题
10. heartbeat 最后一项是什么？定位到具体阶段
11. responses/checks 哪个失败？定位 endpoint/tool
12. cleanup 是否执行？看 ida_terminate_done / 残留进程
```

## 9. 接手者的第一天操作建议

1. 先读本文件、`TESTED.md`、`UNTESTED.md`、`DISPOSABLE_VM_WORKFLOW_LESSONS.md`。
2. 不要先改 workflow；先决定要关闭 `UNTESTED.md` 的哪一个 U 项。
3. 如果只是确认环境，跑 `ida_plugin_api_test/full` baseline。
4. 如果要推进下一项覆盖，直接做 `U005_multi_IDA_instance_selection.py` payload；U009 已完成，不要重复跑。
5. 每跑一次外部 workflow，都把 run ID、artifact id、controller/result 关键字段写回文档。
6. 没有 artifact 证据，不要把任何条目移入 `TESTED.md`。
