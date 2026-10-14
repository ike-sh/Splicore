# 原生 NaiveProxy 出站

使用协议键 `naive / connect / base` 的原生远程节点，配置 TLS、独立的
`username_password` 凭据以及 `options.data.mode`。
HTTPS 模式使用 `transport.kind: "tcp"`、ALPN `h2`；QUIC 模式使用
`transport.kind: "quic"`、ALPN `h3`，需要 `with_quic`。两种载体都代理 TCP。

支持 Basic 认证、padding 自动协商（`auto`、`enabled`、`off`）、有界连接池、
HTTP 多流、额外请求头、连接退休和流截止时间。必须验证 TLS 证书。
H3 拥塞控制仅支持 CUBIC；不支持的算法和流控配置直接拒绝。

完整节点创建示例、选项、范围及默认值参见
[Native NaiveProxy](../../architecture/NAIVE.md#client)。URI 导入导出支持
`naive+https://`、`naive+quic://`，仅携带系统信任及默认选项；自定义 CA 和更丰富
选项应使用规范配置，URI 导出会拒绝丢失这些信息。

原生 UDP、CONNECT-UDP、MASQUE、UDP-over-TCP 未实现。
不声明 Chromium TLS、HTTP 或前置请求指纹一致性，无需 Chromium、Cronet
共享库或外部代理进程。Linux arm64 仍仅为构建验证，真实硬件尚未合格验证。
