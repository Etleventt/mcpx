# Portal Runtime 验收记录

日期：2026-09-06。范围：现有 web-mac 定制 Runtime、Lean 工具协议、全局默认确认模式配置，以及设备 OAuth 授权页。本记录不代表整个平台已完成部署或 Windows 真机验收。

## 已验证行为

授权页采用 HTML 上下文转义，区分设备访问口令与平台登录密码。表单提交地址来自配置的 issuer，保留 `/d/<device-id>` 前缀，不根据请求 Host 生成。

授权页不执行脚本、不加载外部资源；表单安全策略允许同源提交及已通过客户端回调校验的 HTTPS 回调源，兼容授权提交后的重定向。合法 loopback 原生客户端回调也纳入测试。敏感 OAuth 响应禁止缓存；授权请求体有大小上限。

内置默认确认模式仍为 standard。设备所有者可通过本机全局配置显式调整，项目配置不能改变全局默认。Lean 协议不要求模型重复生成 purpose/progress_summary。

## 本轮直接执行的验证

| 命令 | 结果 |
| --- | --- |
| `go test ./internal/oauth -count=1` | 退出码 0 |
| `go test -p 4 ./... -count=1` | 全部包通过，退出码 0 |
| `go test -race -p 2 ./internal/oauth ./internal/config ./internal/server -count=1` | 三个包通过，退出码 0 |
| `go vet ./...` | 退出码 0 |
| `gitleaks dir internal --redact` | 扫描约 1.64 MB，未发现匹配的密钥泄露 |

静态密钥扫描只能发现已知模式，不能代替人工检查和完整安全评估。测试使用虚构凭据；未将运行配置、数据库或真实口令纳入源码。

## 交付边界

本轮验证没有替换正在运行的 Runtime，也没有修改已有公网连接地址。Hub 端仍需单独验证授权页响应安全策略、平台账户校验和设备路由。

普通 HTTPS 中转不是对中转运营方不可见的端到端加密。独立本地 OAuth 授权不改变这一传输边界。
