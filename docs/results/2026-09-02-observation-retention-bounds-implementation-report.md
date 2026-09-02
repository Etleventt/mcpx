# Issue #10：观测留存边界实施报告

## 最终状态

通过。计划范围已实现，针对性测试、全量测试、竞态检测、格式检查、
静态检查和构建均通过。

生成时间：2026-09-02（Asia/Hong_Kong）

## 依据与授权

- 计划文件：`docs/plans/2026-09-02-observation-retention-bounds-implementation.md`
- 外部依据：[Issue #10](https://github.com/opentokenz/mcpx/issues/10)
- 实现授权：用户确认实施计划后回复“继续”。
- 本轮未执行 commit、push 或远程 PR 操作。

## 执行范围

本轮只处理 observation retention、terminal task retention 和单任务观测输出上限。
工作区原有的 MCP `confirmation_key` 未提交改动被保留，未作为本轮 issue #10
功能的一部分修改或回退。

## 计划步骤对照

### 1. 修正 observation retention

- 实际实现：删除 `observationDeletionQuery` 对 `active`、`idle`、`blocked`
  Remote Session 的永久豁免。
- 行为结果：`process_event_ttl` 和 `process_event_max_rows` 对所有会话生效。
- 验证：`TestRetentionBoundsSessionEventsAndReferencedSnapshots`、
  `TestRetentionDeletesExpiredEventsFromOpenSessionStatuses`。
- 状态：已实现，已验证。

### 2. 修正 terminal task retention

- 实际实现：删除已完成任务对 Remote Session 状态的永久豁免；继续保护运行中任务
  和 `execute` 类型 Plan Evidence 引用的任务。
- 额外修正：原查询使用不符合 schema 的 `terminal_task` Evidence 类型，改为合法的
  `execute` 类型。
- 实际实现：清理任务的 combined、stdout、stderr 三类日志文件，避免只删除主日志。
- 验证：`TestRetentionDeletesFinishedTasksFromOpenSessions`、
  `TestRetentionTaskLogFailureKeepsRow`。
- 状态：已实现，已验证。

### 3. 增加单任务观测输出上限

- 实际实现：提取 `terminal.MaxPersistedTaskLogBytes`，作为持久任务日志和观测输出的
  默认 32 MiB 上限。
- 按 `remote_session_id + execution_task_id` 合并计算 stdout/stderr 输出预算。
- 首次超限时保留可容纳的 UTF-8 前缀并设置 `truncated=true`；后续 chunk 不再持久化。
- 任务的两个 final stream 回调完成后释放内存状态，任务日志 Resource URI 保持可用。
- 验证：`TestPrepareTaskOutputBoundsCombinedTaskPayload`、
  `TestObserveTaskOutputPersistsOneTruncationEvent`。
- 状态：已实现，已验证。

### 4. 增加回归测试

- 覆盖活跃、空闲、阻塞会话的过期事件清理。
- 覆盖已完成、运行中和 Plan Evidence 任务的差异化保留。
- 覆盖 sidecar 日志删除、输出跨 stream 累计、单次截断和任务隔离。
- 状态：已实现，已验证。

### 5. 更新文档

- 更新 `README.md` 的 retention、Task 日志和观测截断行为说明。
- 状态：已实现，已验证。

## 实际修改文件

Issue #10 相关新增或修改：

- `internal/state/retention.go`
- `internal/state/retention_test.go`
- `internal/server/observation_bridge.go`
- `internal/server/observation_bridge_test.go`
- `internal/terminal/task.go`
- `README.md`
- `docs/plans/2026-09-02-observation-retention-bounds-implementation.md`

工作区还保留用户此前已有的 MCP 确认协议相关修改，未在本报告中重复列为 issue #10
实现内容。

## 验证证据

以下命令均以仓库根目录、Go 1.26.1+ 开发环境执行并通过：

```text
go test ./internal/state ./internal/server -count=1
go test ./internal/terminal ./internal/observation -count=1
go test ./... -count=1
go test -race ./... -count=1
test -z "$(gofmt -l ./cmd ./internal)"
git diff --check
go vet ./...
go build -o bin/mcpx-server ./cmd/mcpx-server
```

其中全量单测和竞态检测均覆盖本轮变更包；竞态检测未报告 data race。

## 偏差、限制与剩余风险

- 计划原列出可修改 `observer_integration_test.go`；实际覆盖集中在
  `observation_bridge_test.go`，直接测试了 `Runtime.observeTaskOutput` 的入队路径，
  未修改集成测试文件。
- 截断事件采用保留预算内前缀并设置 `truncated=true` 的方式，不回删已持久化的旧 chunk，
  以避免实时序列和 SQLite 删除操作复杂化。
- 32 MiB 上限复用现有任务日志硬上限，未新增配置项或数据库迁移。
- 未执行真实大规模生产数据库回收或磁盘压测；本轮验证使用单测、全量测试、race、vet
  和本地构建，未覆盖生产规模数据的锁竞争与实际回收耗时。

## 后续动作

- 评审通过后，将 issue #10 相关改动与现有 MCP `confirmation_key` 改动拆分为独立提交或
  独立 PR，避免混合无关主题。
- 在真实实例部署前，用备份数据库验证 retention 删除范围和日志恢复入口。
