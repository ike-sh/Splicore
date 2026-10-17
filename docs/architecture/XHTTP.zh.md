# 原生 XHTTP 传输

XHTTP 是 VLESS、VMess、Trojan 共用的流传输方法。层次为：代理协议 →
XHTTP → 可选共享 TLS / REALITY → 网络。它不新增代理认证或协议帧。

| 模式 | 上传 | 下载 | HTTP |
| --- | --- | --- | --- |
| packet-up | 有序、有限大小的请求 | 独立 GET 流 | H1、H2 |
| stream-up | 流式请求 | 独立 GET 流 | H1、H2 |
| stream-one | 单一请求流 | 同一响应流 | H2 |
| auto | 自动选择 | 随所选模式 | H1、H2 |

普通明文或 TLS 的 auto 选择 packet-up。REALITY 的 auto 选择 stream-one；
REALITY 配置 downloadSettings 时选择 stream-up。明文使用 H1，TLS 默认 H2，
单一 http/1.1 ALPN 选择 H1。REALITY 使用 H2，要求 with_utls。
H3 尚未实现，h3 ALPN 会报错。Vision 和 FinalMask 保持原来的 raw VLESS 边界。
XHTTP 不代表支持通用 V2Ray QUIC 或 Mux.Cool。Trojan 要求 TLS。
与 Xray 26.10.10 服务端使用 H1 stream-up 时，服务端 scStreamUpServerSecs
需要设为 -1，避免其响应 keepalive 与请求体读取争用。原生 H1 服务端支持 keepalive。

原生配置使用 transport.kind=xhttp，公共 path、host、headers 位于 transport，
其余选项位于 transport.xhttp。服务端对应 settings.stream_transport。
选项名称兼容 Xray 26.10.10；仅维护一个 XHTTP 实现。

path 自动补齐前导斜杠；session 或 seq 放在 path 时补齐末尾斜杠，保留 query。
拒绝点路径段和无效路径。host 是 HTTP authority，与 TLS SNI 和证书身份独立。
服务端仅在配置 host 时校验。客户端 headers 是请求头，服务端 headers 是响应头。
HTTP 头名称不区分大小写；自定义头不能占用传输的帧、会话、序号、padding、响应状态
或编号上传数据命名空间。元数据键之间也不能冲突。重复键、大小写变体、多值和有歧义
的 token 列表会被拒绝。HTTP authority 通过 host 配置，自定义 Host 头会被拒绝。

整数控制接受单值或范围字符串，例如 100 或 "100-1000"；拒绝倒序和溢出。
padding 默认 100–1000，不可禁用。支持 repeat-x、tokenish，以及 header、query、
cookie、queryInHeader padding。sessionIDPlacement 和 seqPlacement 支持 path、
header、query、cookie；uplinkDataPlacement 支持 auto、body、header、cookie。
header/cookie 上传数据和 GET 上传要求显式 packet-up。
自定义 padding key/placement 要求开启 xPaddingObfsMode。客户端拒绝服务端专用
noSSEHeader、缓冲数量、stream-up keepalive 和 serverMaxHeaderBytes。
自定义 session 字符表不允许重复字符，长度为 1–256；最短配置长度必须独立提供
至少 122 位随机熵，与默认 UUIDv4 一致。十进制至少 37 字符，Base62 至少 21 字符。
不安全的长度或范围会直接报错。使用密码学安全随机源和区分大小写的精确查找；生成
的 ID 在会话活动期间保留，碰撞最多尝试 8 次，然后安全失败。入站仍接受兼容的不同
长度 ID，不受本地生成策略限制。

XMUX 管理 HTTP 连接的并发、数量、复用次数、请求次数、可复用寿命和 H2 keepalive；
maxConnections 与 maxConcurrency 互斥。默认三个 HTTP 客户端、600–900 次请求、
1800–3000 秒可复用寿命。退役不终止已有下载流，关闭出站会回收会话和连接。

downloadSettings 使用独立 endpoint、transport、security 和公开 tls 配置。
两个入口必须到达同一服务端会话所有者，共用一个随机 session identity。
可独立配置目标、TLS 信任和 REALITY；故障和关闭传播到两条腿。
拒绝递归配置、非 XHTTP 下载和 stream-one 的独立下载。

默认单包上限 1000000 字节，最多 8 MiB；默认缓冲 30 包，最多 1024 包。
会话关联与首数据等待共用 30 秒传输预算。HTTP 响应头可先发送以解除客户端启动等待；
仅在收到首应用字节后，才把逻辑连接交给原生代理协议，首字节完整保留。原生认证使用
显式传输认证作用域：5 秒处理预算不计入阻塞的 XHTTP 读写，每次交付等待最多 30 秒。
完整请求认证成功并结束该作用域后，才成为普通应用连接；XHTTP 不解析代理协议或
硬编码认证头长度。作用域最多 64 KiB、1024 次 I/O，总墙钟期限 30720 秒；超限、
缺失数据、取消或关闭会清理会话。这些是资源上限，不保证任意对端调度都能完成。
普通 net.Conn deadline 保持绝对期限语义。缺失包超时仍为 30 秒。
queryInHeader padding 承载单个 URL，路径和无关 query 值可包含逗号；校验解码后的
padding query 值，仍拒绝重复头、多值、重复 padding key 和无效 URL/query 语法。
scMinPostsIntervalMs 默认 30 ms，非正的下限禁用延迟，上限为 20000 ms。
20 秒窗口为下载响应启动和独立上传连接/安全握手各保留现有的 5 秒传输预算，包括
downloadSettings 和 XMUX 退役后重新连接。包大小和 chunk 只会提前结束聚合；padding
及服务端 keepalive 不会延迟上传应用数据。应用无活动或网络故障仍受传输超时约束。
每会话待处理数据最多 32 MiB、总计 128 MiB，
最多 512 会话、每出站最多 128 个 HTTP 客户端。重复包不会重复交付。
传输关闭为完整关闭，不提供 TCP 半关闭。

原生节点导入和持久化保留全部选项。VLESS XHTTP 可导出为 Xray 26.10.10 格式。
无法完整表达的 URI 和其他生态导出会报错。字段默认值、方向限制、下载配置示例及
全部边界见 [完整字段说明](XHTTP.md)。硬件部署仍为 NOT YET QUALIFIED，arm64 为 BUILD ONLY。
