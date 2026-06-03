# Disposable VM Guest Agent Architecture

本方案记录当前选定的真实 IDA / guest VM 测试架构：

```text
HostMachine GitHub self-hosted runner
  -> host controller server
  -> VMware snapshot restore/start
  -> snapshot guest client agent
  -> guest-side deploy/test execution
  -> result/log/artifact return to host
```

## 1. Final architecture decision

采用：

```text
HostMachine runner + host controller server + 快照 guest client agent
```

不采用：

```text
guest VM 注册 GitHub runner
guest VM 动态 JIT/ephemeral GitHub runner
host 主动连接 guest server 作为第一阶段方案
```

原因：host 已经是唯一 CI 调度点和快照控制点，guest VM 只需要作为 disposable test target。这样可以避免 guest runner 注册状态、GitHub 调度错位、runner 残留、token 泄露和多 job 编排复杂度。

## 2. Responsibilities

### HostMachine runner

HostMachine 是 GitHub Actions 看到的唯一 self-hosted runner。它负责：

1. 接收 GitHub workflow job。
2. 启动 host controller server。
3. 清理 `RUNNER_TRACKING_ID`，避免 job cleanup 杀掉 VMware 子进程。
4. 调用宿主机 VMware 快照脚本。
5. 等待 guest client agent 主动连接 host controller。
6. 向 guest 下发 deploy/test payload。
7. 接收 guest 执行结果、日志和 artifacts。
8. 根据 guest 返回的 exit code 决定 GitHub job success/failure。

当前已验证的宿主机快照脚本入口：

```powershell
py -3 C:\Users\alion\Scripts\vmware_restore_test1.py --gui
```

当前已验证的 runner：

```text
RUNNER_NAME=HostMachine
COMPUTERNAME=DESKTOP-2GB2KK7
```

### Host controller server

Host controller 是每次 GitHub job 临时启动的本地控制服务。它运行在宿主机上，只服务当前 job。

职责：

1. 监听 guest agent 反连请求。
2. 维护当前 CI job 的唯一 `job_id`。
3. 向 guest 下发任务。
4. 接收 stdout/stderr/result/artifacts。
5. 等待任务完成或超时。
6. 将最终状态转换成 workflow step 的 exit code。

Host controller 不应该长期常驻。每次 workflow job 启动一个新的 controller，job 结束后退出。

### Snapshot guest client agent

Guest VM 快照内预装一个开机自启的 Python client agent。它不是 GitHub runner，也不监听 GitHub job。

职责：

1. VM 启动后自动运行。
2. 主动连接 host controller。
3. 领取本次测试任务。
4. 在 guest 内创建临时工作目录。
5. 接收脚本、zip、wheel 或测试命令。
6. 执行部署和测试。
7. 将日志、结果和 artifacts 回传给 host controller。

Guest agent 不负责快照回滚，不负责 GitHub 状态，不持有 GitHub token。

## 3. Runtime sequence

```text
GitHub Actions starts job on HostMachine
  -> host job starts host controller server
  -> host job clears RUNNER_TRACKING_ID for VMware launch path
  -> host job runs vmware_restore_test1.py --gui
  -> VMware restores clean snapshot and starts guest
  -> guest boots into clean snapshot state
  -> guest client agent autostarts
  -> guest agent POSTs /hello to host controller
  -> host controller returns job/task metadata
  -> guest agent downloads or receives payload
  -> guest agent executes deploy/test inside guest VM
  -> guest agent streams or uploads logs/results/artifacts
  -> host controller writes local result files
  -> host job exits with guest exit_code
```

## 4. Network model

Preferred network direction:

```text
guest -> host
```

The guest acts as a client. This avoids needing stable inbound connectivity from host to guest and avoids opening guest firewall ports for host-initiated RPC.

Host controller should listen on a VMware host-only or NAT-reachable host address, for example:

```text
http://<host-vmnet-ip>:8766
```

Guest snapshot stores this controller endpoint, or discovers it from a small config file. The endpoint should be reachable only from the local VMware network, not from the public internet.

## 5. Minimal protocol

The first implementation should stay small.

### Guest hello

```text
POST /hello
```

Request fields:

```json
{
  "guest_id": "ida-test-vm",
  "hostname": "WIN10-GUEST",
  "agent_version": "0.1",
  "boot_id": "..."
}
```

Response fields:

```json
{
  "job_id": "...",
  "action": "run",
  "payload_url": "http://host:8766/payload/<job_id>",
  "timeout_seconds": 1800
}
```

### Payload download

```text
GET /payload/<job_id>
```

Returns the script or archive that guest should execute.

### Log upload

```text
POST /log/<job_id>
```

May be called once at the end or periodically while the job runs.

### Result upload

```text
POST /result/<job_id>
```

Request fields:

```json
{
  "job_id": "...",
  "status": "completed",
  "exit_code": 0,
  "stdout_tail": "...",
  "stderr_tail": "...",
  "artifacts": []
}
```

## 6. Guest snapshot requirements

The clean guest snapshot should contain only the stable test environment:

```text
Python runtime
IDA / required licensed runtime environment
Guest client agent
Agent autostart configuration
Known host controller endpoint or discovery config
Empty or clean workspace directory
```

It should not contain a registered GitHub runner. It should not contain active test jobs. It should not need any GitHub token.

The snapshot is considered clean by construction: before snapshot creation, no test payload has been delivered and no job has run.

## 7. Host workflow requirements

The host workflow should keep these rules:

1. Run only on `HostMachine`.
2. Use Python for host-side orchestration, not cmd batch logic.
3. Clear `RUNNER_TRACKING_ID` before launching VMware or any long-lived child process.
4. Start host controller before restoring/starting guest.
5. Fail if guest does not connect within a timeout.
6. Fail if guest result is missing or malformed.
7. Always persist host controller logs and guest result metadata.
8. Do not install or register a GitHub runner inside guest.

## 8. Cleanup model

HostMachine should not try to sanitize guest state after each run. The next run starts by restoring the clean snapshot.

Host cleanup only needs to handle host-owned state:

```text
controller server process
controller temp directory
payload archive
result/log/artifact copies
stale VMware lock files if the restore script owns that behavior
```

Guest cleanup can be minimal because the next run restores the clean snapshot. Guest agent may still use a per-job directory for simple log organization.

## 9. Failure handling

The host controller should map failures to clear statuses:

```text
guest_connect_timeout: guest never connected after VM start
payload_download_timeout: guest connected but could not download task
run_timeout: guest accepted task but did not finish before timeout
result_missing: guest did not upload result
result_invalid: uploaded result is malformed
nonzero_exit: guest completed but returned non-zero exit_code
controller_error: host controller failed internally
```

Workflow should exit non-zero for all failure statuses except normal success.

## 10. Security boundary

This is a local disposable VM test harness, not a public remote execution service.

Minimum boundary:

1. Host controller listens only on a local VMware host-only/NAT interface or localhost-forwarded address.
2. Guest agent accepts tasks only from the configured host controller endpoint.
3. Guest does not hold GitHub credentials.
4. Host workflow should avoid printing secrets or tokens.
5. The only durable trust boundary is the clean VM snapshot plus host-controlled payload.

## 11. Implementation phases

### Phase 1: connectivity smoke

Goal: prove the guest client agent can connect back to host after snapshot restore.

Acceptance:

```text
host starts controller
host restores/starts guest
guest POST /hello arrives
host returns a no-op task
guest returns exit_code=0
workflow passes
```

Implementation status:

```text
Implemented and verified by workflow_dispatch on HostMachine.
Verified run: https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26900876629 attempt 2
```

### Phase 2: run simple command

Goal: run a trivial command in guest and return stdout/stderr.

Example task:

```text
python --version
```

Acceptance:

```text
guest returns Python version
guest result includes exit_code=0
host workflow passes
```

Implementation status:

```text
Implemented in host controller, guest agent, and disposable VM workflow.
Workflow inputs: task_action=command, command_json=["python", "--version"]
Verified run: https://github.com/qqq694637644/ida-script-mcp-main/actions/runs/26902252502 attempt 1
Verified result: stdout_tail="Python 3.11.7\n", exit_code=0
```

### Phase 3: upload and execute script

Goal: host sends a Python script payload to guest and guest executes it.

Acceptance:

```text
host payload is written under guest job directory
guest executes payload with timeout
guest uploads result/logs
host workflow uses guest exit_code
```

Implementation status:

```text
Implemented in host controller, guest agent, and disposable VM workflow.
Workflow inputs: task_action=python_script, script_text=<UTF-8 Python script>
Verification status: pending Phase 3 workflow_dispatch run.
```

### Phase 4: project deploy/test payload

Goal: host sends repository/test payload and guest runs real IDA integration deployment/test steps.

Acceptance:

```text
guest deploy succeeds
guest test succeeds/fails deterministically
guest uploads logs/artifacts
host workflow reflects the result
```

## 12. Current verified foundation

Already verified on the current branch:

```text
HostMachine self-hosted runner receives GitHub jobs
HostMachine proxy configuration works
HostMachine can run Python via py -3
HostMachine can invoke vmware_restore_test1.py --gui
VMware restores snapshot test1 and starts guest in gui mode
Clearing RUNNER_TRACKING_ID prevents GitHub runner cleanup from killing vmware-vmx.exe
```

Relevant workflow smoke files:

```text
.github/workflows/host-runner-smoke.yml
.github/workflows/vmware-restore-smoke.yml
.github/workflows/disposable-vm-guest-agent-smoke.yml
```

## 13. Non-goals for first implementation

Do not add these in the first phase:

```text
guest GitHub runner registration
guest JIT/ephemeral runner lifecycle
multi-guest pool scheduling
public network exposure
secret management beyond local test token if needed
long-lived controller daemon
```

The first implementation should prove the host-controller and guest-client loop with one disposable VM and one job at a time.
