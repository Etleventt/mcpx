# Issue #10：观测留存边界实施计划

## 目标

解决 `observation_events` 和任务日志在 Remote Session 长期处于
`active`、`idle` 或 `blocked` 状态时无界增长的问题，确保 retention
配置能够对数据库事件和已完成任务真正生效，并为单个任务的
`command.output` 增加累计输出上限。

依据：[Issue #10](https://github.com/opentokenz/mcpx/issues/10)

## 范围

- 修正 `observation_events` 的 session-status 永久豁免。
- 修正 `terminal_tasks` 及其日志文件的同类永久豁免。
- 为单个 `execution_task_id` 的观测输出增加累计字节上限。
- 增加 retention、观测桥和任务输出的回归测试。
- 更新相关 README 和运行行为说明。

## 非目标

- 不在本 PR 中自动关闭 Remote Session。
- 不改变 MCP 工具协议、任务执行协议或 Session resume 语义。
- 不删除运行中的任务或被 Plan Evidence 引用的任务。
- 不提交、不推送、不创建或更新远程 PR。

## 设计决策

1. 移除会话状态对 retention 的永久豁免，让现有
   `process_event_ttl`、`process_event_max_rows` 和 `terminal_task_ttl`
   对所有会话生效。最近数据仍由 TTL 和最新行数窗口保留。
2. `terminal_tasks` 继续保护运行中的任务和被 Plan Evidence 引用的任务。
3. 单任务观测输出按 `remote_session_id + execution_task_id` 合并统计
   stdout 和 stderr，复用现有持久任务日志的 32 MiB 上限。
4. 达到观测上限时保留上限内内容，写入一次 `truncated=true` 标记，
   后续 chunk 不再写入 `observation_events`；完整任务日志仍是恢复来源。
5. 不依赖客户端主动 close Remote Session 来保证清理正确性，避免本 PR
   改变持久会话生命周期。

## 实施步骤

### 1. 修正 observation retention

文件：

- `internal/state/retention.go`
- `internal/state/retention_test.go`

改动：

- 删除 `observationDeletionQuery` 中对 `active`、`idle`、`blocked`
  会话的永久保护条件。
- 保留 TTL、最新窗口和批量删除逻辑。
- 增加活跃会话中过期事件可清理、近期事件保留的测试。
- 通过 `EXPLAIN QUERY PLAN` 检查查询没有引入明显的相关子查询退化。

### 2. 修正 terminal task retention

文件：

- `internal/state/retention.go`
- `internal/state/retention_test.go`

改动：

- 删除 `deleteTerminalTasks` 对 Remote Session 状态的永久保护条件。
- 保留 `status <> 'running'`、TTL 和 Plan Evidence 保护。
- 使用合法的 `execute` Evidence 类型识别被引用的 terminal task。
- 删除任务记录及其 combined、stdout、stderr 日志文件；运行中任务及被引用任务仍然保留。

### 3. 增加单任务观测输出上限

文件：

- `internal/server/observation_bridge.go`
- `internal/terminal/task.go`
- 必要时补充 `internal/observation` 的共享常量或测试代码

改动：

- 提取可复用的 32 MiB 任务日志上限，避免 server 和 terminal 各自维护
  不一致的硬编码值。
- 在 observation bridge 中按任务和 Remote Session 保存累计输出状态。
- 在脱敏后、入队前计算观测 payload 的累计大小。
- 首次超过上限时只保留预算内内容并产生一次截断标记；后续输出不再
  持久化，但保留任务日志 Resource URI。
- stdout 和 stderr 共用同一任务预算；任务 final 或异常清理时释放状态，
  避免长期运行进程中的 map 无界增长。

### 4. 增加回归测试

文件：

- `internal/state/retention_test.go`
- `internal/server/observation_bridge_test.go`
- `internal/server/observer_integration_test.go`
- `internal/terminal/task_observation_test.go`（按实际实现补充）

覆盖：

- 活跃、空闲和阻塞会话的过期事件清理。
- 活跃会话中已完成任务、运行中任务和 Plan Evidence 任务的差异化处理。
- 单任务跨 stdout/stderr 的累计输出上限。
- 截断标记只产生一次，且不同任务相互隔离。
- final chunk、异常结束和任务日志恢复路径。

### 5. 更新文档

文件：

- `README.md`
- 必要时更新默认配置或 retention 注释

说明 retention 不再因 Remote Session 状态而永久跳过；说明
`command.output` 的观测截断和任务日志恢复路径。

## 验证计划

按以下顺序执行：

```bash
gofmt -w ./cmd ./internal
test -z "$(gofmt -l ./cmd ./internal)"
git diff --check
go test ./internal/state ./internal/server ./internal/observation ./internal/terminal -count=1
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go build -o bin/mcpx-server ./cmd/mcpx-server
```

## 恢复与风险

- 本次不执行数据库迁移；若实现失败，可仅回退本 PR 新增的代码和文档，
  不触碰工作区既有 MCP 未提交改动。
- 活跃会话中过期历史将开始按 retention 清理，这是预期行为，需要在
  README 和 PR 说明中明确。
- 观测事件是 best-effort；超过任务观测预算后以任务日志 Resource URI
  作为恢复入口。
- 若测试显示 32 MiB 共享上限会改变已有任务日志语义，暂停并重新确认
  是否拆分观测上限和任务日志上限。

## 验收标准

- Remote Session 长期不 close 时，`observation_events` 仍受 TTL 和行数
  上限约束。
- 已完成任务及其日志不再因会话状态永久滞留。
- 单任务 `command.output` 的累计持久化量有硬上限。
- 截断行为可观察，完整任务日志仍可恢复。
- 相关测试、全量测试、race、vet 和 build 均通过。
