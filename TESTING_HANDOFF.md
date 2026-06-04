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

## 5. 当前最新一次测试结果

刚跑完的 baseline：

| 字段 | 值 |
| --- | --- |
| Workflow run | `26921994480` |
| Workflow | `Disposable VM guest agent smoke` |
| Branch / commit | `main` / `e7b00f0553c7b53437f55bda9f02b7c7497f1ddf` |
| Job | `Host controller and guest agent smoke` |
| Runner | `HostMachine` |
| Conclusion | `success` |
| Artifact | `disposable-vm-guest-agent-smoke`, artifact id `7400024008` |
| Host controller state | `status=success`, `payload_downloaded=true` |
| Guest | `DESKTOP-QBSO5C3`, Python `3.11.7` |
| Guest result | `status=completed`, `exit_code=0` |
| IDA plugin | instance `8052_test1.dll`, port `13338` |
| Final heartbeat | `api_tests_done`, `status=passed`; cleanup reached `ida_terminate_done` |

该 run 验证：

```text
/health
/metadata
/functions
/functions limit=1
/functions name filter
/functions offset beyond total
/decompile
/decompile invalid address
/xrefs to
/xrefs from
/xrefs invalid direction structured error
/xrefs invalid kind structured error
/execute -> HTTP 410 status=rejected
unknown route -> HTTP 404
```

该 run **没有** 验证：

```text
execute_idapython -> headless worker -> worker-generated ChangeSet -> apply_worker_changes
worker hard timeout / kill process tree
worker crash/result-missing/recorder-error matrix
```

所以 U001-U003 仍保留在 `UNTESTED.md`。

## 6. 已测/未测迁移规则

`UNTESTED.md` 是待办队列，`TESTED.md` 是证据账本。

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

优先级最高的是 `UNTESTED.md` 中 U001-U003。

### U001：完整 V2.3 主链路

目标不是再测 `/apply_changes`，而是证明 worker 产出的 `ChangeSet` 能经 MCP 层回放：

```text
MCP execute_idapython
  -> GUI /metadata
  -> saved clean database fingerprint
  -> copy saved IDB/I64
  -> launch headless IDA worker
  -> worker 执行用户 IDAPython
  -> ChangeRecorder 生成 changes.json
  -> MCP apply_worker_changes dry-run
  -> MCP apply_worker_changes dry_run=false
  -> GUI /apply_changes
  -> /inspect_address 验证 GUI mutation
```

建议实现方式：

```text
新增一个 guest python_script payload 或扩展现有 ida_api_test payload
payload 复用现有插件安装和 IDA bootstrap 逻辑
payload 启动 GUI IDA 插件，拿到 base_url/port/database_path
payload 设置 IDA_SCRIPT_MCP_IDA_PATH 指向 guest IDA idat64/ida64
payload 让 src/ida_script_mcp 在 guest 可 import
payload 直接调用 ida_script_mcp.server.execute_idapython 或真实 MCP client
worker 代码调用 mcp_changes.rename/comment/patch_bytes 或 IDA monkeypatch API
payload 保存 execute_result.json 和 changes.json 摘要
payload 调 apply_worker_changes dry-run 并确认不改 GUI
payload 调 apply_worker_changes dry_run=false 并确认 GUI 改动可 inspect
payload 最终写 v23_worker_chain_result.json
```

U001 通过的最低断言：

```text
execute_result.status == ok
execute_result.isolated == true
execute_result.job_id 非空
execute_result.changes 至少包含一个 operation
apply dry-run status == ok 且 applied=[]
inspect dry-run 后 GUI 未变
apply destructive status == ok 且 applied 非空
inspect destructive 后 GUI 已变
metadata destructive 后 dirty == true 或 apply_changes_mutation_flag == true
```

### U002：worker hard timeout / kill process tree

目标：

```text
execute_idapython(code='while True: pass', timeout_seconds=1~3)
-> result.status == timeout
-> hard_timeout == true
-> killed == true
-> worker_exit_code/worker_pid 有记录
-> 无残留 idat64/ida64 worker 进程
-> GUI 数据库不被修改
```

建议作为独立 `task_action` 或独立 payload mode，不要和 U001 放同一轮，避免死循环/kill 干扰主链路结果。

### U003：worker 异常状态矩阵

至少构造：

```text
worker_start_error: IDA_SCRIPT_MCP_IDA_PATH 指向不存在路径
worker_crashed: worker 进程非零退出且没有有效 ok result
worker_result_missing: worker 不产生 result.json
recorder_error: 真实 IDA recorder 安装或记录异常
source_error: script_path/source 无效
rejected: GUI dirty / dirty unknown / identity missing
```

这个测试应该输出一个矩阵 JSON：

```json
{
  "worker_start_error": "passed",
  "worker_crashed": "passed",
  "worker_result_missing": "passed",
  "recorder_error": "passed",
  "source_error": "passed",
  "rejected": "passed"
}
```

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
4. 如果要推进核心覆盖，直接做 U001 payload。
5. 每跑一次外部 workflow，都把 run ID、artifact id、controller/result 关键字段写回文档。
6. 没有 artifact 证据，不要把任何条目移入 `TESTED.md`。
