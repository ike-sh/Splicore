# AnyTLS 客户端元数据

Splicore 默认发送空 `client` 字段。该字段仅用于可选客户端标识，不参与认证或
协议版本协商。

原生 `client_metadata` 选项接受空字符串、`splicore` 或 `splicore/...`，最多
128 字节；拒绝换行、NUL 和冒充其他实现的名称，不自动携带操作系统信息。

配置和版本协商详见 [原生 AnyTLS](../../architecture/ANYTLS.md)。
