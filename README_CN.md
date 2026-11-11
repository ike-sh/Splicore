# Splicore

Splicore 是独立的单二进制代理核心，在同一进程中提供 Server/Client Core、
本地控制、路由、DNS、策略、加密凭据及 SQLite 持久化。无需 Xray、V2Ray、
sing-box 或 Mihomo 代理核心进程，也不提供桌面 UI。

## 下载和验证

[正式 v0.5.0 下载](https://github.com/ike-sh/Splicore/releases/tag/v0.5.0)。
按平台选择 zip / tar.gz，另下载 SHA256SUMS。Linux 使用
`sha256sum -c SHA256SUMS`；Windows 使用
`Get-FileHash -Algorithm SHA256 ./splicore-v0.5.0-windows-amd64.zip` 与公开值核对。
解压后只有一个主程序 `splicore` / `splicore.exe`，以及许可证、示例、RUNNING.md
和内部文件校验清单。运行不需要 Go 或 WSL。提供 SHA256，没有声称数字签名。

| 平台 | 构建 | 原生资格 |
| --- | --- | --- |
| Windows amd64 | CGO=0 | 默认/完整标签 Build、Vet、测试和真实 VLESS 进程；Race 未执行 |
| Linux amd64 | CGO=0 | 默认/完整标签 Build、Vet、测试，限定包 Race 和真实 VLESS 进程 |
| Windows arm64 | CGO=0 交叉编译 | BUILD ONLY，未原生运行 |
| Linux arm64 | CGO=0 交叉编译 | BUILD ONLY，未原生运行 |

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

v0.5.0 是基于 v0.4.0 的新增协议能力 minor。相对 v0.3.0 Phase36 Frozen，
WireGuard endpoint、ShadowQUIC、XHTTP H3、部分通用 carrier 及其他历史差异仍待恢复；
不要混用不同基线配置/数据库。v0.3.0 和 v0.4.0 Tag/Release 保持不变。

Windows WireGuard Hotfix 仍 NOT QUALIFIED，Windows Race 未执行，ARM64 仅交叉编译；
本机 Windows Symlink 测试可能因 1314 跳过，CI 不允许该例外。WSL2 大 UDP 超时、
历史 SOCKS 诊断、Mieru 大流量性能保留限制；独立 SQLite WAL/P1-B 候选未进入本版本，
未宣称崩溃/断电恢复资格。Phase37 WIP 隔离。Windows 服务安装/生产备份、TUN、
真实主机网络和硬件仍有资格边界；可选 Windows TUN 需要外供 Wintun DLL/driver，
驱动没有内置。Hysteria v1、XHTTP H3 不支持。

## 从源码构建

使用 Go 1.26.3+：Linux 执行 `make build`，Windows 执行
`./scripts/splicore-build.ps1`。默认完整标签为 `with_quic,with_utls,with_gvisor`，
CGO=0；官方构建从最终 main 的精确 Tag Commit 注入版本、提交和时间。
对应源码归档含 vendor 依赖及无需 Git/下载依赖的构建说明。

完整边界见 [Release Notes](docs/releases/v0.5.0.md)、[CHANGELOG](CHANGELOG.md)、
[CLI](docs/CLI.md)、[配置](docs/CONFIGURATION.md)、[安全政策](SECURITY.md)。
原始 [LICENSE](LICENSE)、[GPL 全文](licenses/GPL-3.0.txt)、[NOTICE](NOTICE.md)
和[第三方许可](THIRD_PARTY_NOTICES.md) 均保留。Splicore 不隶属或获得 SagerNet 背书。
