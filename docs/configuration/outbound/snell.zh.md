# Snell 出站

规范远程节点使用 `snell/4/base`、TCP transport、`security.kind=none`，以及
由控制面分配身份和所有权的 PSK Credential。端点提供 server host 与 port。
通过受保护的客户端 plan/apply 创建节点和 native proxy 出站。

```json
{
  "schema_version": 1,
  "data": {
    "version": 4,
    "reuse": true,
    "udp": true,
    "obfs_mode": "http",
    "obfs_host": "cover.example",
    "obfs_uri": "/resource?x=1"
  }
}
```

此示例是节点的 options。version 必填。reuse 默认 false，支持串行物理连接
复用；UDP 默认启用，`udp=false` 禁用。可选 `udp_port` 为 1..65535，选择
同一服务器的另一个 TCP UDP-association 端口，不创建额外监听器。

obfs_mode 可省略、为 none 或 http。host、URI 只允许用于 HTTP；Splicore
有意默认使用 localhost 和 /。host 必须为有效主机名或 IP，URI 必须为有界
ASCII 路径及可选 query，不允许空格、控制字符和 fragment。未知、重复、null
和不支持的字段组合被拒绝。UDP 域名在本地解析，托管包流保持固定目标。
保留的经典 record 预算限制大 datagram，详见
[Native Snell](../../protocol/SNELL.md)。

v5/v6 的 options 仍分别只有 version=5/6。v5 显式启用动态 record 和
QUIC Proxy Mode：有效 QUIC v1/v2 Initial 使用 UDP-over-UDP，普通 UDP
保持 UDP-over-TCP，不按端口 443 分类。v6 使用已有独立行为。
未实现 TLS obfs 和 userkey 多用户。官方 Surge 客户端私有分类算法缺少 oracle，
明确标记 SURGE_V5_CLIENT_CLASSIFICATION_ORACLE_UNAVAILABLE；已验证范围详见
[Native Snell](../../protocol/SNELL.md)。
规范 JSON 保留所有支持的字段；sing-box/Mihomo 导入导出支持 v4 reuse、UDP、
HTTP host，但不支持自定义 URI 或另设 UDP 端口的导出。没有新增 Snell URI 格式。
