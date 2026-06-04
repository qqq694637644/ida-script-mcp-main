# 未测试

Last updated: 2026-06-04

本文件是待测清单。测试通过后，把对应条目从这里删除，移入 `TESTED.md` 并补充证据。失败项保留在这里，同时把失败原因、artifact、run ID 和修复经验写入 `DISPOSABLE_VM_WORKFLOW_LESSONS.md`。

## 当前优先选择开始的测试

核心 V2.3 worker 生命周期测试 U001-U003、真实 MCP client smoke U004、多 IDA 实例选择 U005、`/functions` 主要 corner case U006、`/decompile` corner case U007、`/xrefs` corner case U008、`/inspect_address` 系统测试 U009、comment/function_comment 复杂情况 U011、以及 patch_bytes 复杂情况 U013 已全部通过并移入 `TESTED.md`：

```text
U001 execute_idapython -> worker ChangeSet -> apply_worker_changes
U002 worker hard timeout / kill process tree
U003 worker failure-state matrix
U004 real MCP client end-to-end
U005 multi-IDA instance selection
U006 /functions main corner case
U007 /decompile corner case
U008 /xrefs corner case
U009 /inspect_address system test
U011 comment / function_comment complex
U013 patch_bytes complex cases
```

U006 `/functions` 主要边界语义已由 workflow run `26925694907` 覆盖并移入 `TESTED.md`；仍保留 fixture-dependent residuals。下一轮建议从 U006R、U010/U012/U014 apply_changes、installer / client config coverage 开始。U008/U009/U011 已完成，不要重复跑。


## 已测项目的专门环境补测

U007 已在当前 disposable VM + `test1.dll` 基线上通过并移入 `TESTED.md`。以下 U007 分支本次未实际触发，需要专门 license 状态或构造数据库再测：

- [ ] **U007-F01 `/decompile` Hex-Rays unavailable / no-license path**

  ```text
  没有 Hex-Rays license
  ida_hexrays.init_hexrays_plugin() 返回 false
  /decompile found=true 但 hexrays_available=false
  warning 解释 pseudocode 不可用
  include_disassembly=true 时仍返回 disassembly
  ```

- [ ] **U007-F02 `/decompile` per-function Hex-Rays failure fallback**

  ```text
  Hex-Rays 对某个真实函数失败
  /decompile found=true
  pseudocode=null 或 unavailable
  warning 有结构化说明
  disassembly 仍可用
  ```

- [ ] **U007-F03 `/decompile` duplicate-name ambiguity**

  ```text
  构造或找到重复/歧义函数名
  name 查询返回明确结果或结构化歧义错误
  不误选错误函数
  ```

## MCP 层未测

- [ ] **U006R `/functions` fixture-dependent residuals**

  ```text
  空数据库 / 0 function
  巨大函数数量分页
  函数名重复或 demangled 名称
  ```

  已覆盖并移入 `TESTED.md` 的 U006 范围：segment 过滤、include_thunks/include_library_functions matrix、name_contains 大小写/Unicode/特殊字符输入、limit=0/负数/超大值/非整数、offset 负数/非整数、name_contains/segment/boolean flag 类型错误、numeric string 参数。


## apply_changes 未测风险点

- [ ] **U010 rename 复杂情况**

  ```text
  重名冲突
  非法名称
  空名称
  超长名称
  Unicode 名称
  rename 到已有函数名
  rename 非函数地址
  rename import/library/thunk
  flags 不同组合
  ```

- [ ] **U012 set_type 复杂情况**

  ```text
  非法 C declaration
  复杂函数原型
  stdcall/fastcall/thiscall/vectorcall
  结构体/枚举/typedef 依赖
  指针/数组/函数指针
  已有类型覆盖
  对非函数地址 set_type
  ida_typeinf.apply_cdecl 失败路径
  idc.set_type / idc.SetType fallback 各自真实路径
  ```

- [ ] **U014 partial apply / rollback 语义**

  示例：

  ```text
  op1 rename 成功
  op2 comment 成功
  op3 set_type 失败
  op4 patch_bytes 未执行或失败
  ```

  需要确认：

  ```text
  返回 status 是 partial 还是 error
  applied/skipped/errors 列表是否准确
  已应用的 op 是否保留
  是否没有 rollback
  dirty flag 是否设置
  第二次 apply 是否被 dirty 拒绝
  ```

- [ ] **U015 operation schema 和安全输入**

  ```text
  schema_version 错误
  未知 op
  缺少 op_id
  重复 op_id
  extra fields
  source 非 explicit_api/monkeypatch
  confidence 非 high/medium/low
  database_fingerprint 缺失
  只有 input hash 没有 database_sha256
  dry_run 类型不是 bool
  ```

## 数据库状态未测

- [ ] **U016 GUI 数据库未保存**

  ```text
  新打开 DLL 但没有保存 .i64
  execute_idapython 是否 source_error/rejected
  apply_changes 是否拒绝
  metadata 是否说明 database_identity_known=false
  ```

- [ ] **U017 GUI 数据库已 dirty**

  ```text
  人工修改数据库后执行 execute_idapython
  人工修改数据库后 apply_changes dry-run
  人工修改数据库后 apply_changes destructive
  dirty_state_known
  dirty
  dirty_method
  unsaved
  ```

- [ ] **U018 saved database 文件异常**

  ```text
  database_path 不存在
  database_path 无权限
  database_path 被移动
  database_path 很大
  database sha256 计算失败
  copy database 失败
  ```

## worker / recorder 未测

- [ ] **U019 ChangeRecorder 真实 IDA monkeypatch**

  ```text
  用户脚本调用 idc.set_name
  用户脚本调用 ida_name.set_name
  用户脚本调用 idc.set_cmt
  用户脚本调用 ida_bytes.patch_bytes
  用户脚本调用 idc.patch_byte
  用户脚本调用 set_type
  用户脚本调用 mcp_changes API
  changes.json 内容正确
  source=monkeypatch 或 explicit_api 正确
  old/new bytes 正确
  function_comment 正确识别
  ```

- [ ] **U020 collect_changes=false**

  ```text
  execute_idapython collect_changes=false
  worker 里做修改
  changes 返回空
  不会生成可回放 ChangeSet
  ```

- [ ] **U021 worker 中导入 IDA 模块失败路径**

  ```text
  idaapi 缺失
  ida_auto.auto_wait 返回 False
  idc.qexit 不可用
  worker 打开的 database_copy_path 和预期不一致
  ```

## installer / package 未测

- [ ] **U022 installer CLI 真机路径**

  ```text
  ida-script-mcp-install install
  ida-script-mcp-install uninstall
  重复 install 幂等
  旧 root-level support 文件清理
  symlink 成功路径
  symlink 失败后 copy fallback
  Windows/macOS/Linux IDA user dir
  路径含空格/中文
  ```

- [ ] **U023 MCP client 配置**

  ```text
  codex
  claude
  cursor
  project mode
  生成的 config 文件正确
  已有 config 合并不破坏
  uninstall/overwrite 行为
  路径转义正确
  Windows 路径正确
  ```

## 平台和版本未测

- [ ] **U024 非 Windows**

  ```text
  macOS
  Linux
  idat/idat64 路径发现
  process group kill
  IDA user plugin dir
  symlink 权限
  路径大小写
  ```

- [ ] **U025 IDA 版本差异**

  ```text
  IDA 8.4
  IDA 9.x
  不同 IDAPython API 行为
  Hex-Rays 不同版本
  无 Hex-Rays license
  Python 3.12/3.13 server 环境
  ```

## workflow / guest 未测

- [ ] **U026 guest agent 异常路径**

  ```text
  guest 缺 requests
  guest 缺 pywinauto/psutil
  controller_url 错误
  host controller 端口被占用
  guest 下载 payload 后崩溃
  guest result 上传中断
  guest stdout/stderr 超大
  payload 非 UTF-8
  payload 运行超时
  ```

- [ ] **U027 VMware / runner 稳定性**

  ```text
  restore 脚本成功但 guest agent 未自启
  VMware GUI 弹窗
  runner 被取消时 cleanup
  连续多次 workflow 是否稳定
  IDA 残留进程是否影响下一轮
  artifact 缺失时如何诊断
  ```

## 安全边界未测

- [ ] **U028 GUI `/execute` dev escape hatch**

  ```text
  显式开启 dev env var 后 /execute 行为
  确认 MCP public execute 不会走 GUI /execute
  确认关闭 env var 后恢复 rejected
  ```

- [ ] **U029 worker 不是完整沙箱的边界**

  ```text
  worker 可访问文件系统
  worker 可访问网络
  worker 可启动子进程
  hard timeout 能否杀子进程树
  ```

  这不一定是 bug，但必须作为安全边界说明。

## 性能 / 压力未测

- [ ] **U030 大型数据库**

  ```text
  几万/几十万函数
  巨大 xref
  巨大 decompile
  大 IDB copy 时间
  hash 计算耗时
  worker 启动成本
  artifact 大小
  ```

- [ ] **U031 多轮重复测试**

  ```text
  连续 10 次 basic
  连续 10 次 full
  连续多次 apply_changes smoke
  每次 restore 快照后状态一致
  没有端口泄漏
  没有 IDA 残留进程
  ```

## 扩展 smoke / stress / security 候选矩阵

| ID | 类别 | 未测情形 | 主要风险 | 建议测试方法 |
| --- | --- | --- | --- | --- |
| E001 | 隔离 worker 生命周期 | 在 `execute_idapython` 中执行 `time.sleep(999)` 或死循环，确认 timeout 状态、进程树被杀、GUI 数据库未标脏 | 死进程泄露、调度线程阻塞、无结构化错误 | 在 CI 中注入故障脚本；断言 MCP server 返回对应状态并上传 heartbeat/log tail |
| E002 | 隔离 worker 生命周期 | `sys.exit(137)` 或触发崩溃，应返回 `worker_crashed` | 状态分类错误 | 真实 worker 故障脚本 |
| E003 | 隔离 worker 生命周期 | 删除或损坏 `result.json`，服务器应给 `worker_result_missing` 或 structured recorder/source error | 无结果时误判成功 | 真实 worker 故障脚本 |
| E004 | GUI `/execute` 逃逸开关 | 开启 dev env var 后 `/execute` 可执行，关闭后仍 410 | 绕过隔离、误执行高危脚本 | workflow 参数动态切换，检查 dirty + 410 |
| E005 | apply_changes 深度 | 空 ChangeSet replay 应返回无应用而不是错误 | 空操作误报失败 | dry-run + destructive 两轮 |
| E006 | apply_changes 深度 | 同一符号重复 rename/comment | silent 失败或重复应用混乱 | 构造重复 ChangeSet，检查 status/applied/skipped/errors |
| E007 | apply_changes 深度 | patch_bytes 跨 segment / 只读段 | 数据库损坏、partial apply 不清晰 | 构造 patch 失败，检查 structured error |
| E008 | apply_changes 深度 | `set_type` 非法 C 声明，例如 `int foo(` | 类型解析异常导致崩溃 | dry-run + destructive，检查错误字段 |
| E009 | apply_changes 深度 | apply 时 GUI DB 已 dirty 但 fingerprint 匹配 | 脏库仍写入 | 手动置 dirty 后 destructive apply 必须 rejected |
| E010 | 只读 HTTP 端点边界 | `/functions` 负 offset/limit、超大 limit、非整数字符串 | 500 / 崩溃 | 畸形参数应返回 structured error 或可控 4xx，不应 5xx |
| E011 | 只读 HTTP 端点边界 | `/xrefs` limit 超大 / 负数 / 0 | 500 / 崩溃 | 畸形参数测试 |
| E012 | 只读 HTTP 端点边界 | `/decompile` 地址非函数 / 指向外部段 | 500 / 崩溃 | 断言 found=false 或 structured error |
| E013 | 多实例并发 | 同时打开两份 IDA 数据库，错误 instance_id/port 不得误写 | 误写错库 | guest 启动两份 IDA，随机选错实例调用 replay |
| E014 | 端口冲突 | 预占用 13338，插件应递增到 13339 并正确注册 | MCP 连接失败 | guest 预占端口后启动插件，检查 `/health` 和 registry |
| E015 | 字符集与长文本 | Unicode/emoji/中文符号名、注释、超长函数注释 | 编码错误 / 截断 | rename/comment 后 `/inspect_address` 回读 |
| E016 | 跨版本兼容 | IDA 7.6/7.7/8.4/9.x API 行为差异 | 逻辑分支走错 | 其他 guest snapshot 跑同套 smoke |
| E017 | 性能/资源边界 | 超大 ChangeSet > 10,000 ops dry-run/apply | OOM / GUI 卡死 | 生成大批量 op，测时间和 RSS |
| E018 | 安全 | Worker 脚本尝试 `os.remove(input_file_path)` 等磁盘写 | 误以为完整沙箱 | 明确测试并文档化边界，不把进程隔离当安全沙箱 |
| E019 | 安全 | GUI `apply_changes` 不允许任意路径操作 | 任意文件写 | 确认 replay 只针对 IDA bytes/name/type/comment 操作 |

## 建议测试顺序

```text
1. worker failure-state matrix / crash / missing result / recorder error
4. partial apply failure 语义
5. dirty/unsaved/source_error 真实数据库状态
6. 多实例 instance_id/port 选择
7. installer CLI install/uninstall/legacy cleanup
8. non-Windows / other IDA versions
9. 大型样本性能和重复稳定性
```
