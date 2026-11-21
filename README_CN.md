# Splicore

Splicore 是独立的单二进制代理核心，在同一进程中提供 Server/Client Core、
本地控制、路由、DNS、策略、加密凭据及 SQLite 持久化。无需 Xray、V2Ray、
sing-box 或 Mihomo 代理核心进程，也不提供桌面 UI。

## 下载和验证

[最新正式版本 v0.6.4](https://github.com/ike-sh/Splicore/releases/tag/v0.6.4)。
按平台选择 zip / tar.gz，另下载 SHA256SUMS。Linux 使用
`sha256sum -c SHA256SUMS`。在 Windows 上，以 v0.6.4 为例，使用
`Get-FileHash -Algorithm SHA256 ./splicore-v0.6.4-windows-amd64.zip` 与公开值核对。
解压后只有一个主程序 `splicore` / `splicore.exe`，以及许可证、示例、RUNNING.md
和内部文件校验清单。运行不需要 Go 或 WSL。提供 SHA256，没有声称数字签名。

当前采用 `AMD64_ONLY` 策略，正式 CI 和发布仅覆盖 Linux amd64、Windows amd64。
ARM64 官方支持暂停。v0.6.4 的 ARM64 发行包是历史 `BUILD_ONLY` 资产。
[v0.6.4 资格范围](docs/releases/v0.6.4.md#qualification-scope) 保留当时的测试记录。

真实进程测试覆盖 Help/Version/Check/Run、VLESS 监听和数据传输、错误凭据拒绝、
保留活动连接时 Shutdown、端口释放与持久化重启。不能由此推导所有协议互通已合格。

## 启动和停止

先执行 `./splicore help`、`./splicore version --json`（Windows 加 `.exe`）。
按 [Linux 说明](docs/releases/RUNNING_linux.md) 或
[Windows 说明](docs/releases/RUNNING_windows.md) 配置绝对路径，使用
`key init --file <master.key>` 生成私有密钥，再执行：

```text
splicore check --config <bootstrap.yaml>
splicore run --config <bootstrap.yaml>
splicore status --config <bootstrap.yaml>
splicore stop --config <bootstrap.yaml>
```

`run` 为前台进程，日志在 stderr；已安装 Linux 服务使用 journald。
`stop` 表示请求已接受，监督程序仍应等待进程退出。空状态不会自动监听代理端口；
示例 `distribution/vless-loopback.json` 需显式 plan/apply。Bootstrap YAML 只选择
进程路径，协议资源通过本地 API/CLI 管理。密钥与数据库必须匹配并一同保管，禁止
为遗失密钥的已有数据库随意生成替代 key。Linux 私有目录 0700、文件 0600；
Windows 新 key/state 目录使用私有 DACL。普通高端口无需管理员，TUN/网络操作另需权限。

## 实现与资格范围

代码实现的实验性模块包括 VLESS/Vision/REALITY、VMess、Shadowsocks/SS2022、
Hysteria2、Mieru、Trojan、Snell、TUIC、AnyTLS、TrustTunnel、NaiveProxy，及
XHTTP H1/H2、modern mKCP 等传输。参见[能力矩阵](docs/architecture/CAPABILITY_MATRIX.md)。
**已实现、可构建、原生测试、参考实现互通是不同资格。** v0.5.0 基于 v0.4.0，
恢复原生 [VLESS Encryption](docs/protocol/VLESS_ENCRYPTION.md)：ML-KEM-768/X25519
混合握手、AES-GCM/ChaCha 记录、1-RTT/0-RTT，以及 TLS/REALITY/Vision 组合。
Windows/Linux amd64 均执行官方 Xray v26.10.21 独立对端的双向真实互通；
Android/v2rayNG 实机测试 NOT EXECUTED。其他协议不因 Release 自动获得额外资格。

当前源码新增受管 SOCKS5 服务端入站，默认监听回环，强制用户名密码认证，支持
IPv4、IPv6 和域名 TCP CONNECT。UDP ASSOCIATE 和 BIND 返回 `0x07`。
服务端和客户端的独立资格记录见[入站与出站审计](docs/architecture/INBOUND_OUTBOUND_MATRIX.md)。
实际配置和双端命令见 [SOCKS5 示例](docs/CLI.md#managed-socks5-and-a-local-client)。

当前源码的受管 HTTP Proxy（`http/1.1/base`）支持 HTTP CONNECT、普通 HTTP 转发、
Basic 代理认证、多账户管理和 SQLite 重启恢复。默认监听回环，普通转发每条连接处理
一个请求。CONNECT 可以透传 HTTPS，客户端到代理的 Basic 认证仍为明文。
[HTTP Proxy 示例](docs/CLI.md#managed-http-proxy)

v0.6.2 在 v0.5.0 基线上恢复标准 WireGuard endpoint、XHTTP H3、
Generic HTTP/H2/QUIC、Snell v4/v5 DRS/QUIC 和受管路由/DNS；完整范围见版本化 61 项清单。
ShadowQUIC 恢复未通过正式重连资格，本版不包含该协议。Linux kernel WireGuard
恢复也因并发新建 IPv6 UDP 场景重复失败而隔离；两项均为 ISOLATED_NOT_QUALIFIED。
标准 WireGuard 保留 userspace，显式 kernel 请求返回 KERNEL_NOT_QUALIFIED，auto 报告 userspace 回退。
v0.6.0/v0.6.1 Tag 均保留为未发布候选，不覆盖；修正范围以 v0.6.2 为准。
v0.6.3 同为未发布候选 Tag。v0.6.4 正式版修复 TUIC 认证命令流与 Mieru UDP 接收进展，
发布资格及独立平台检查见 [v0.6.4 发行说明](docs/releases/v0.6.4.md)。
AmneziaWG/Phase37 明确废弃。WAL/P1-B 候选不准入；标准 WireGuard 与 AWG 分开。
Windows WG 接收修复仅丢弃已被 Winsock 消耗的 WSAEMSGSIZE 数据报，其余错误保持原语义，
要求新的原生互通、重复畸形包恢复和完整 Release 门禁，旧 Hotfix 报告结论不被改写。
本机 Windows Symlink 测试可能因 1314 跳过，CI 不允许该例外。WSL2 大 UDP 超时、
历史 SOCKS 诊断、Mieru 大流量性能保留限制；独立 SQLite WAL/P1-B 候选未进入本版本，
未宣称崩溃/断电恢复资格。Phase37 AWG 已废弃。Windows 服务安装/生产备份、TUN、
真实主机网络和硬件仍有资格边界；可选 Windows TUN 需要外供 Wintun DLL/driver，
驱动没有内置。Hysteria v1 不支持；XHTTP H3 与通用 QUIC carrier 需要 with_quic。

## 从源码构建

使用 Go 1.26.3+：Linux 执行 `make build`，Windows 执行
`./scripts/splicore-build.ps1`。默认完整标签为 `with_quic,with_utls,with_gvisor`，
CGO=0；官方构建从最终 main 的精确 Tag Commit 注入版本、提交和时间。
对应源码归档含 vendor 依赖及无需 Git/下载依赖的构建说明。

完整边界见 [Release Notes](docs/releases/v0.6.4.md)、[CHANGELOG](CHANGELOG.md)、
[CLI](docs/CLI.md)、[配置](docs/CONFIGURATION.md)、[安全政策](SECURITY.md)。
开发方向统一维护在 [项目路线图](docs/ROADMAP.md)。
原始 [LICENSE](LICENSE)、[GPL 全文](licenses/GPL-3.0.txt)、[NOTICE](NOTICE.md)
和[第三方许可](THIRD_PARTY_NOTICES.md) 均保留。Splicore 不隶属或获得 SagerNet 背书。
