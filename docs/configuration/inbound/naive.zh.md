# 原生 NaiveProxy 入站

使用托管创建协议 `naive`（协议键 `naive / connect / base`，引擎 `native`）。
`settings.mode: "https"` 创建 TLS/H2 TCP 监听；`"quic"` 创建 TLS 1.3/H3 UDP
监听。H3 需要 `with_quic` 构建标签，同时提供两种模式时使用两个明确的入站。

创建文档使用现有 listener、display_endpoint、TLS 和 users 模型，接受 1–16 个
用户名不同的用户。省略密码时由公共凭据服务生成。Account、Binding、Credential
保持独立，禁用账户或绑定不能认证，用户变更和凭据轮换会重启对应运行代。

支持 TCP CONNECT、Basic 认证、原生 padding 协商和并发流。普通 GET/HEAD
前置请求得到最小静态欢迎响应。原生 UDP 代理未实现；不声明 Chromium 的
TLS、HTTP、前置请求指纹一致性，也不依赖 Chromium、Cronet 或外部代理进程。

完整创建示例、TLS 要求、超时、流上限和生命周期参见
[Native NaiveProxy](../../architecture/NAIVE.md#server)。配置采用原生 Core 模型。
