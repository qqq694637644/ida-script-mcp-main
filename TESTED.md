# 已测试

Last updated: 2026-06-04

本文件只记录已经通过真实工作流、实机 IDA/guest VM、或明确单元测试验证的范围。新增通过项时，把对应条目从 `UNTESTED.md` 移到本文件，并写明证据。失败、诊断和修复经验继续写入 `DISPOSABLE_VM_WORKFLOW_LESSONS.md`。

## 已确认的实机 workflow 范围

当前 HostMachine -> disposable guest VM -> IDA 8.3 workflow 已确认测过：

```text
Guest agent 连接
动态 payload 下发
插件安装
IDA 8.3 打开 C:\Users\alion\Desktop\test1.dll
插件 HTTP server 启动
GET  /health
GET  /metadata
POST /functions
POST /decompile
POST /xrefs
POST /execute rejected by default
GET  unknown route -> 404
POST /inspect_address
POST /apply_changes destructive smoke
patch_bytes 修改 DllEntryPoint 首字节
```

## apply_changes 已验证范围

`apply_changes` 已确认覆盖：

```text
bad fingerprint 被拒绝
dry-run 默认不改数据库
rename destructive apply
comment destructive apply
function_comment destructive apply
set_type destructive apply
patch_bytes destructive apply
dirty=true / apply_changes_mutation_flag
第二次 destructive apply 被 dirty/unsaved 状态拒绝
```

## 现有证据索引

| 范围 | 证据 | 备注 |
| --- | --- | --- |
| Phase 1 connectivity / guest agent smoke | workflow run `26900876629` attempt 2 | guest agent 可连接 host controller |
| Phase 2 command payload | workflow runs `26902252502`, rerun `26902716245` | 动态 command payload 可执行 |
| Phase 3 Python script payload | workflow run `26903071347` | guest 可执行动态 Python script payload |
| IDA plugin install | workflow runs `26903926544`, `26907543538` | support-package layout 已验证 |
| IDA API basic smoke | workflow run `26908653405` | 基础 endpoint smoke |
| IDA API full smoke + corner cases | workflow run `26909020426` | 非破坏性 full smoke |
| apply_changes destructive smoke | workflow run `26918788898` | destructive replay 基础验证 |
| patch_bytes destructive smoke | workflow run `26919752930` | 临时 `test1.i64` 中 patch 首字节，不改原始 DLL |

更多成功/失败细节见 `DISPOSABLE_VM_WORKFLOW_LESSONS.md`。

## 移入规则

只有满足以下条件才把 `UNTESTED.md` 的条目移到本文件：

1. 有明确证据：workflow run ID、本地命令输出、artifact 内容、日志片段或 CI job 名称。
2. 写清楚测试输入，尤其是 workflow inputs、IDA 路径、DLL 路径、模式和是否 destructive。
3. 写清楚断言：返回状态、HTTP status、artifact/result 字段、数据库 dirty 状态、是否有残留进程。
4. destructive 测试必须说明是否只操作临时数据库。
5. 失败项不要移入本文件，继续保留在 `UNTESTED.md`，并把失败总结写入 `DISPOSABLE_VM_WORKFLOW_LESSONS.md`。
