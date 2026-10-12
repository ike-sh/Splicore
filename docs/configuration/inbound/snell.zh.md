# Snell 入站

通过受保护的创建 API/CLI 提交规范文档：

```json
{
  "schema": 1,
  "account_name": "example",
  "name": "snell-v4",
  "listener": {"host": "0.0.0.0", "port": 24443},
  "display_endpoint": {"host": "proxy.example", "port": 24443},
  "settings": {"version": 4, "obfs_mode": "http"}
}
```

必须显式选择版本 4、5 或 6。v4 的 `obfs_mode` 可省略、为 `none` 或
`http`；入站不接受客户端专用的 host、URI、reuse、UDP-port 字段。
v5/v6 的 settings 仍只能包含 version，v6 保留已有流量整形行为。
未知字段、重复字段、null 和不支持的组合会被拒绝。

省略 PSK 会生成密钥；提供 PSK 时须符合 12..255 字节的可移植 ASCII
凭证规则。监听地址必须为 IP。每个入站只有一个账户、绑定和 PSK。
支持 TCP、经 TCP 转发的 UDP、IPv4/IPv6/域名目的地，以及 v4 串行连接复用。
HTTP obfs 只包装首次提交的头部，不提供 TLS 安全。
未实现 TLS obfs、userkey 多用户扩展和 v5 QUIC Proxy Mode。

完整限制及互通范围见 [Native Snell](../../protocol/SNELL.md)。真实硬件仍为
NOT YET QUALIFIED；Linux arm64 仅构建验证。
