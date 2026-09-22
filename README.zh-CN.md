# Tiana Go SDK

[English](README.md) | **简体中文**

Tiana v1 CONNECT 的原生 Go 传输库，模块路径为
`github.com/tianacloud/sdk-go`，包名为 `tiana`。要求 Go 1.25 或更高版本，
采用 Apache-2.0 许可证。根包为 Hrana HTTP/WebSocket、MySQL、PostgreSQL
和 Git 提供字节隧道，不包含 `database/sql` 驱动或 SQL 查询 API。

## 账户鉴权

独立的 [`auth` 包](docs/authentication.md) 与 CLI 共用 MGR 登录、刷新、
退出登录、账户凭据和已保存 InstanceToken 的查询逻辑。它兼容现有的
`~/.config/tiana` 文件（也支持 XDG_CONFIG_HOME），无需迁移存储格式。
通过参数或文档中说明的环境变量指定 MGR 地址；SDK 不内置部署地址。
根包的 CONNECT 客户端不会隐式读取这些文件或发起登录。
具体用法、授权边界和存储并发约束见鉴权指南。

MGR 除本机回环开发地址外必须使用 HTTPS。Linux/macOS 文件存储会拒绝不安全的
凭据文件，并通过持久锁协调跨进程刷新与写入；自定义存储仍需调用方协调多个客户端。

MGR 请求不会自动跟随 HTTP 重定向，包括同源重定向和调用方提供的重定向策略。
请直接配置最终的 MGR 地址；3xx 响应会以保留原始状态码的 APIError 返回。
账户 access token、refresh token 与 CONNECT 使用的 InstanceToken 是不同的凭据。

## 安装

本仓库发布版本后，可以执行：

```sh
go get github.com/tianacloud/sdk-go@latest
```

对于尚未发布的源码候选版本，请显式使用本地工作副本：

```sh
go mod edit -require=github.com/tianacloud/sdk-go@v0.0.0
go mod edit -replace=github.com/tianacloud/sdk-go=/absolute/path/to/sdk-go
go mod tidy
```

`v0.0.0` 仅为本地 replace 的占位版本，不代表已发布版本。
SDK 当前的 User-Agent 版本为 `0.1.0-dev.1`。
未发布变更见 [CHANGELOG.md](CHANGELOG.md)；这不表示已创建公开标签。

## 打开隧道

```go
package main

import (
    "context"
    "log"
    "os"

    tiana "github.com/tianacloud/sdk-go"
)

func main() {
    // 将 TIANA_ENDPOINT 设置为部署提供的完整主机名。
    cfg := tiana.Config{Endpoint: os.Getenv("TIANA_ENDPOINT")}
    if raw := os.Getenv("TIANA_TOKEN"); raw != "" {
        token, err := tiana.NewToken(raw)
        if err != nil { log.Fatal(err) }
        cfg.Token = token
    }
    client, err := tiana.NewClient(cfg)
    if err != nil { log.Fatal(err) }
    defer client.Close()

    // ctx 控制连接建立过程及返回隧道的整个生命周期。
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    tunnel, err := client.Connect(ctx, tiana.HranaHTTP)
    if err != nil { log.Fatal(err) }
    defer tunnel.Close()
    // 将 tunnel（net.Conn）交给兼容的 Hrana HTTP 传输实现。
}
```

`Config.Endpoint` 必须是完整的部署主机名，例如
`ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test`（仅作示例）。
SDK 会规范化 DNS 大小写，拒绝裸 Endpoint ID、URL 和带端口后缀的输入。
请使用部署连接配置提供的实际主机名。SNI 和 CONNECT authority 使用该主机名，
逻辑端口为 443。`Config.DialAddress` 可选，仅覆盖实际连接的 TCP 地址。
设置 `Config.RootCAs` 时，它会替代系统信任根；SDK 会复制该证书池。
TLS 证书校验保持启用，要求 TLS 1.3 和 ALPN `h2`。

仅当 Endpoint 策略允许匿名访问时，才可省略 `Token`。
提供的令牌必须是规范的 `tia_` InstanceToken。令牌属于其 Client；
不同凭据或信任根应使用不同的 Client。格式化 Token、Config、Client 和 Tunnel
时会脱敏，包括复制后的 Token 值和容器中的 Token。根包 CONNECT 不输出日志。

`HranaHTTP`、`HranaWebSocket`、`MySQL`、`PostgreSQL` 和 `Git`
分别选择 Gateway 的 `hrana-http`、`hrana-websocket`、`mysql`、
`postgresql` 和 `git` profile。隧道透传字节，SDK 不解析应用协议。
数据库协议自身的鉴权仍由调用方单独提供。

## 流行为

- `Connect` 在完整且已结束的 200 响应头通过验证后返回。在此之前不会发送请求
  DATA，并保留服务端先发的数据。
- `Write` 遵循流级和连接级流控。支持并发读写；同一方向的多个调用会串行执行。
- `CloseWrite` 发送 END_STREAM。收到远端 END_STREAM 后，先读完缓冲数据，
  再返回 `io.EOF`。本地写方向仍然开放；对端可能在半关闭宽限期结束后关闭它。
- `Close` 只取消当前流。取消建立隧道时使用的 context，会解除等待中的连接建立、
  读和写；可用 `errors.Is` 判断 `context.Canceled` 及 context 超时。
  `Client.Close` 关闭所有隧道，并等待底层连接的读写协程退出。
- `SetReadDeadline`、`SetWriteDeadline` 和 `SetDeadline` 作用于当前隧道。
  超时错误实现 `net.Error`，可解包为 `os.ErrDeadlineExceeded`。
  帧已入队或正在写入时超时，会终止流，因为无法确定其最终发送结果。
  等待流控额度或入队前超时，则在更新 deadline 后仍可使用该流；
  尚未提交的流控额度会归还。等待入队时也会响应 deadline 更新。

一个 Client 默认通过共享连接支持最多 32 个并发流；
`MaxStreams` 可设为 1–256。每个流的未读 DATA 窗口为 65,535 字节，
单个写入帧最多 16 KiB。响应头限制为 16 KiB、64 个字段。
底层写入受 `ConnectTimeout` 限制（默认 10 秒），
CONNECT 响应的默认超时为 60 秒。取消一个流或收到 RST_STREAM 不会影响其他流。

收到 GOAWAY 后，该连接停止接收新流；ID 不超过对端最后接受值的流可以继续，
未被接受的流会携带 `Unprocessed` 元数据返回。
后续显式调用 `Connect` 时可能建立新连接，同时存活的底层连接最多两个，
包括正在排空的连接。达到流数或连接数限制时返回 `limit` 错误。

## 错误处理

声明 `var connectError *tiana.Error`，通过
`errors.As(err, &connectError)` 获取结构化错误。
`Kind` 区分配置、TCP、TLS、HTTP/2、响应验证、Gateway 拒绝、超时、
取消、关闭和容量限制等错误。`Status`、`Code` 和 `RetryAfter`
包含经过边界限制的 Gateway 元数据；对端响应体、未知错误码和 GOAWAY
调试文本会被丢弃。`RequestID` 用于定位流相关失败。
`403/QUOTA_EXCEEDED` 会保留为不可重试的拒绝错误。
SDK 不暴露 JSON 响应体中的可选配额原因；
请通过 Gateway 的可观测性信息区分计算或存储配额耗尽。

`Committed` 表示已观察到完整的 200 响应，包括成功信封格式不合法的情况。
此后发生失败，隧道内会话的结果可能无法确定。
CONNECT 客户端不会自动重连或重放操作。`Unprocessed` 与 `Retryable()`
含义不同：只有在提交前，收到 1–60,000 毫秒的重试提示，且错误为
`429/CONNECTION_LIMIT`、`503/POLICY_UNAVAILABLE`、
`503/INSTANCE_UNAVAILABLE` 或 `504/ACTIVATION_TIMEOUT` 之一，
才会被标记为可重试。

## 可运行示例与验证

`examples/echo` 将标准输入转发到 echo 上游，并将收到的字节写到标准输出。
它可从 `TIANA_TOKEN_FILE` 读取令牌，从 `TIANA_CA_FILE` 读取自定义信任证书。
使用隔离测试夹具的示例：

```sh
TIANA_ENDPOINT=ep-01j5c9m7q2v8x4k6n3r0t1w2yz.db.example.test \
TIANA_DIAL_ADDRESS=127.0.0.1:12345 \
TIANA_CA_FILE=/path/to/fixture/fixtures/gateway.pem \
go run ./examples/echo < payload.bin
```

以下自包含检查不依赖内部服务：

```sh
go test -race ./...
go vet ./...
python3 scripts/check-public-source.py
bash scripts/consumer-smoke.sh
```

冒烟测试脚本导出**当前源码**，包括尚未提交的变更，在独立的消费方模块中构建
echo 示例，并使用本地合成 TLS/H2 服务验证逐字节一致性和半关闭行为。
需要 Go、Python 3、Bash，以及下载公开 Go 依赖的网络访问能力。
脚本退出时会清理临时测试产物。

`conformance/v1` 是自包含的公开 CONNECT 测试分发，具有独立标识和哈希。
它已适配显式部署主机名，不保证与旧分发逐字节一致。
TLS 夹具使用保留的 `.test` 域名，可通过生成器重新生成，不用于真实部署。

针对固定 Gateway 源码的可复现测试，以及不包含 Git 历史的源码导出方法，
见[验证说明](docs/validation.md)。

## 迁移与限制

本次预发布迁移修改了模块导入路径，并要求完整的 Endpoint 主机名。
之前导出的默认域名后缀常量已移除。
调用方需要修改 import，并显式传入部署提供的主机名；
TLS 信任配置和 `DialAddress` 的覆盖能力仍然保留。

单元测试和消费方冒烟测试使用本地合成服务，不能证明与实际部署的
Gateway、Agent、数据库组合完全兼容，也不验证数据库事务语义。
外部集成测试需要单独启用。GitHub CI 和不使用 replace 的公开安装验证，
分别需要在候选代码推送到评审分支和版本公开发布之后执行。

Go 管理的凭据字符串和库缓冲区无法保证被清零；
原始令牌输入的存储和生命周期由调用方管理。
