# AnyTLS 入站

Splicore 原生 AnyTLS 服务端使用共享 TLS 和托管密码用户。通过 `anytls`
创建 API 配置，不使用 sing-box 入站格式。

设置包含 `tls`，以及可选 `alpn`、`padding_scheme`、`version`（1 或 2）、
`max_sessions`（默认和上限 512）、`max_streams`（默认和上限 128）。
TLS 使用绝对路径 `certificate_file`、`private_key_file`、DNS `server_name`
以及单个 PEM `ca_certificate`。最多 16 个密码身份唯一的用户。
用户变更会重启对应运行代际。

完整创建示例、填充、认证、UoT2 和限制见 [原生 AnyTLS](../../architecture/ANYTLS.md)。
