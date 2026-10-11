# AnyTLS 出站

使用规范远程节点：协议 `anytls / 2 / base`、TCP 传输、TLS 安全设置、远程端点
以及独立归属的密码凭据。默认验证证书，也支持显式 CA。

选项默认为 `udp: true`、`version: 2`、30 秒空闲检查和超时、
`min_idle_session: 0`、`max_sessions: 128`、`multiplex_streams: 1`、
空 `client_metadata`、`insecure: false`、`uot_mode: "non_connect"`。
`multiplex_streams` 大于 1 时允许有界的活跃会话复用；默认选择最新空闲会话。
UoT2 支持 connected 和 nonconnected 模式。

完整选项限制、版本协商、TLS、URI 和互操作范围见
[原生 AnyTLS](../../architecture/ANYTLS.md)。
