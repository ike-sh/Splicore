# Splicore Native TUN Runtime Implementation Report

## Verdict

Review checkpoint: the evidence below describes the implementation review.
The subsequent authorized local freeze is recorded in the
[Qualification Fix freeze report](QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md).
Its commit is the new requalification candidate; the review Git action table
below is preserved as review-stage history.

**SPLICORE NATIVE TUN RUNTIME READY FOR REVIEW**

Native TUN implementation 和 ownership/resource 门禁已通过。独立 QF-003
将 inherited libbox profiler 改为公开 Go profiling APIs，仓库全量 default/native
`go test -race ./...` 均真实 PASS；未排除 package，checkptr 保持默认。
Native TUN/core/module 源码与 QF-003 入口 snapshot 相同，原真实 TUN/压力证据有效。
新 Native TUN race ×25、QF-001 ×125、Windows safe、三平台构建与 distribution
比较均 PASS。完整审计见 [QF-003 report](QF_003_PRIVATE_RUNTIME_LINKNAME_RESOLUTION_REPORT.md)。
本状态仅 READY FOR REVIEW；Platform Qualification 继续暂停，未 Freeze。

## Base

| Item | Value |
|---|---|
| Branch | `codex/qf-001-native-tun-iovec-race` |
| HEAD / Frozen base | `75c0b0b8dedaf0e1a3d8580d6825235364963004` |
| Sole parent | `7be20f14ccb59112c98f2fa07c0cab20a436bd88` |
| Working tree | DIRTY，全部 UNSTAGED，包含本轮前已有 QF evidence |
| Index | EMPTY |
| History | frozen Phase 15 未改变 |

## Architecture

Splicore owns TUN runtime：Device 使用权、实际 stack/NIC/link、packet workers、
flow admission、cancellation、drain、join、错误和完整 teardown 均由自己的
adapter/runtime 管理。host journal 拥有 raw FD、Wintun、routes 和恢复记录。
Client Manager 保持现有 routing/policy/outbound/generation/session ownership。
official gVisor 仅负责 TCP/IP stack；没有外部进程或第二套 control plane。

## Dependency Inventory

| Dependency Surface | Before | After | Decision |
|---|---|---|---|
| A / I Device | sing-tun Linux NativeTun | 最小 Linux FD adapter | REPLACE |
| B Network stack | sing-tun 隐藏旧 stack | 持有 official stack，直接 Destroy | REPLACE |
| C / M Packet I/O/buffer | shared iovec、borrowed packet state | copied ingress、immutable egress、per-device writer | REPLACE |
| D TCP | sing-tun forwarder integration | own lazy adapter + existing Manager | REPLACE / KEEP |
| E UDP | NAT packet wrapper | connected full-tuple endpoint + existing outbound | REPLACE / KEEP |
| F DNS | Splicore DNS Engine | 同一 Engine，query/stream snapshot | KEEP / WRAP |
| G routes/system | host journal/netlink | 同一 ownership/recovery | KEEP |
| H Wintun | owned adapter/session/GUID | 增加借用期间 Interrupt，journal 最后 End | KEEP / WRAP |
| J GSO | 无产品 enablement/资格承诺 | plain packet bridge | DEFERRED |
| K checksum | legacy netstack | official stack，无 offload capability | REPLACE |
| L MTU | persisted 1280–9000 | 原 contract | KEEP |
| N / O lifecycle/cancel | hidden Close | owned cancellation、join、Destroy | REPLACE |
| P tests | QF / Phase 13–15 evidence | 保留并增加 own regressions | KEEP / ADD |
| Q tags | `with_gvisor` | inclusion tag 保持；own capability | KEEP |

完整 A–Q 审计见 [architecture](../architecture/NATIVE_TUN_RUNTIME.md)。
sing-tun/旧 SagerNet gVisor 在其他继承 utility/contracts 中保留，active client
TUN 不再通过它们创建或拥有隐藏 stack。

## Dependency Versions

| Dependency | Exact version / change |
|---|---|
| official gVisor | `v0.0.0-20261004063249-f57b8fc79db4` |
| gVisor commit | `f57b8fc79db4d392e8246d07e14c0c71e237afe8` |
| gVisor module sum | `h1:gifqG0saAEtFgFur+Ezlr8U5Nl85VwE0qaQhyweiVmQ=` |
| gVisor go.mod sum | `h1:We1Jh3kDvpcx13qPcI0LTjx3U6pHpis/KFoU/UtJTkM=` |
| sing-tun | `v0.9.3`，未改变 |
| SagerNet gVisor | `v0.0.0-20260727.0-sing-box-mod.1`，未改变 |
| Go minimum | `1.26.3`，由所选正式 dependency 要求 |
| 验证工具链 | Linux / Windows `go1.26.6` |
| grpc | `1.79.1` → `1.80.0`，required MVS |
| go-jose/v4 | `4.1.3` → `4.1.4`，required MVS |
| genproto/googleapis/rpc | `v0.0.0-20260401024825-9d38bb4040a9`，required MVS |

`go mod verify`: PASS，all modules verified。无 `replace`、fork、vendor patch、
module-cache patch 或 broad dependency update。CI、build/package version checks
和 distribution 文档同步 minimum Go。

## Native TUN Components

### Device

内部 contract 为 Read/Write/Start/Interrupt/Close。Linux 非阻塞 TUN 使用标准
Go poller；TUNSETIFF/MTU 完成后才注册 FD。Wintun 借用 session 的 quit event
中断 I/O，runtime 不执行 End/adapter Close。Journal 在 Runtime.Wait 后释放。

### Netstack

一个 production backend。协议 handler 在 NIC Attach/ingress 之前发布。
IPv4/IPv6、TCP/UDP/ICMP 使用 official public APIs；第三方类型仅位于
`internal/splicore/nativetun` implementation/tests。

### Packet Bridge

Ingress 每 packet copy 后交给栈引用管理。Egress 在 link callback 返回前
同步 snapshot 全部字节；bounded 256-packet queue 只保存 owned bytes。
Per-device writer 串行同步 syscall，reject/drain 保证 raw device 释放前无 borrower。

### TCP

callback 在 upstream 启动 goroutine 前预留任务。Lazy acceptance 保持 route/
policy/outbound admission 先于 local handshake。Incomplete handshake 使用
public link registration barrier 和 exact tuple Abort；已建立连接普通 Close，
保留 queued reply/FIN。Complete exactly once。

### UDP

Full tuple endpoint 保持 affinity，交给既有 route/policy/outbound。Idle default
仍为两分钟；reply destination 不变。公开 PMTUDiscoveryDont 配置正常分片。

### DNS

现有 System、UDP、TCP、verified DoT、proxy、bootstrap、cache 均保留。
UDP 每 query 获取 current generation；TCP 持有 stream generation。
DoH/FakeIP 仍 DEFERRED。

### Lifecycle

Prepared/Starting/Running/Draining/Stopping/Stopped/Failed。Start publication
与 cleanup 串行；并发/double Close 都 join 同一个完成结果。Packet worker
failure 保留终态错误，Client status 为 degraded。Cancellation callback join
先于连接所属 generation release。

## Ownership Model

| Resource | Owner | Acquire | Release | Crash behavior |
|---|---|---|---|---|
| TUN FD / Wintun adapter/session | host journal + platform | durable prepare | runtime join 后 lease Restore | OS handle reclamation + journal recovery |
| Stack / NIC / link | native backend | Start | reserved flows/workers join，Destroy/Close | process memory reclaimed |
| Packet workers | Runtime | successful backend Start | cancel/Interrupt/Wait | process exit |
| Ingress bytes | worker → stack refs | copy after Read | InjectInbound 后 drop worker ref | memory reclaimed |
| Egress bytes | link → queue → writer | callback 内 immutable snapshot | synchronous Write return 或 queue drain | memory reclaimed |
| TCP / UDP flows | backend + synchronous dispatcher | bounded tracked admission | close/join，stack Destroy | process exit |
| Generation | Client Manager/query | route/query 前 acquire | cancellation/connection cleanup join 后 release | SQLite intent authoritative |
| Internal eventfd/poller | backend/Go runtime | channel backend NOT PRESENT；Go poller process-wide | 无每 lifetime retained FD | OS reclamation |
| Route lease / DNS interception | existing journal/DNS Engine | durable mutation/query ownership | reverse restore / query join | exact journal identity recovery |

更详细的 [ownership table](../architecture/TUN_RUNTIME_OWNERSHIP.md) 同步到实际代码。

## Lifecycle

### Start

Host journal 启动 device，Runtime 创建/持有 stack、NIC、link 和 workers。
Immutable options copy；handlers 先初始化再 Attach。Second Start 返回错误。

### Running

Exclusive borrowed device、bounded flow/queue admission；Manager 控制 policy
和 generations。无 backend plugin/user selector。

### Drain

Cancel context、reject writes；Interrupt 不释放 raw handle；等待当前 syscall。

### Stop

Close tracked flows；join packet workers、reserved callbacks 和 dispatcher。
Public Destroy 释放 actual stack/NIC/link；queue drain。

### Wait

所有 Runtime borrowers 退出后返回；journal 才可以 Close/Restore device。
多 caller 得到相同 terminal result。

### Failure

Start/cancellation/packet failure 都走同一 cleanup。未借用 device 的失败或
Stop-before-Start 不 Interrupt。Cleanup error 不转换为成功。SIGKILL 由 OS
回收 handles，重启沿用 Phase 15 journal/SQLite recovery，不依赖 graceful Destroy。

## Shutdown Sequence

Cancel/admission stop → writer reject → device Interrupt → writer drain →
tracked connections Close/pending handshake Abort → packet/flow join →
official Destroy → link queue Close/drain → host lease Restore/raw device Close。
接线确保 callback 不会在 Wait 之后才获得未追踪 endpoint。

## Packet Ownership

Reusable ingress scratch 从不被异步保留；每次 copy 形成 stack-owned payload。
Egress 不跨异步 boundary 共享 PacketBuffer/header/backing array；只转移
immutable owned bytes。Writer guard 是单个 device/runtime 的 admission token，
不锁整个 data path，没有 global mutex、pool early return 或新 unsafe pointer。

## QF-001

原 bug：NativeTun.WritePacket 的 shared iovec backing array write/write race。
该 production path 已删除，**QF-001 eliminated by architecture**。旧 guard
移动为 test-only；原五个 QF-001 unit 文件 byte-identical，×25 = 125 PASS。
新 writer/packet/lifecycle package race ×25 PASS；immutable snapshot、short
write、independent devices、Close/drain、concurrent syscall ownership均覆盖。

## QF-002

原 sing-tun/SagerNet dispatcher 每 lifetime 保留一个 StopFD/eventfd。
新 backend 持有 actual official stack，完整 teardown；channel packet link
不创建 backend eventfd。Pure/pollable-FD ×25 PASS，FD/eventfd Δ=0，goroutine stable。
最终真实 TUN ×25 也每 cycle 严格比较 equivalent STOPPED state：FD 14→14、
eventfd 1→1（Go poller）、goroutine 6→6。新 active path 的 QF-002 已解决。

## Findings

### NTUN-001 — Writer ownership

- Surface: device egress。
- Problem: legacy shared iovec race。
- Root cause: 同一 device scratch 有并发 owner。
- Decision/Fix: own bytes + exclusive per-device synchronous writer。
- Regression: preserved QF125 PASS；new package race ×25 PASS。

### NTUN-002 — Stack ownership

- Surface: hidden netstack/StopFD。
- Problem/Root cause: abstraction 无完整 public resource release ownership。
- Decision/Fix: own actual official stack；channel link；public Destroy。
- Regression: pollable/real TUN 25 lifetimes strict resource equality PASS。

### NTUN-003 — Handler/callback publication

- Surface: Attach 与 asynchronous TCP callback。
- Problem/Root cause: handler 后发布，或 callback 启动前无 owned task。
- Decision/Fix: handlers before NIC；Forwarder.HandlePacket 前预留 flow task。
- Regression: traffic/close/default race ×25，pending handshake cancellation PASS。

### NTUN-004 — TCP cancellation and normal Close

- Surface: lazy endpoint creation/Close。
- Problem: handshake 可无界等待；已建立连接不应被 Abort 截断 reply。
- Root cause: cancellation 与 normal Close 未区分。
- Decision/Fix: public registration barrier + exact-tuple Abort 仅用于 pending
  creation；established connection 普通 Close。
- Regression: dropped SYN-ACK cancellation、immediate REJECT、final 56 KiB reply
  before EOF PASS。

### NTUN-005 — Linux poll descriptor order

- Surface: unattached TUN FD。
- Problem: poller 注册时 POLLERR，read 后续永久报 not pollable。
- Root cause: os.NewFile 先于 TUNSETIFF。
- Decision/Fix: configure/MTU 后注册 Go poller。
- Regression: real TUN TCP/UDP/DNS ×25 PASS。

### NTUN-006 — IPv4 fragment identifiers

- Surface: exact candidate 默认 UDP PMTU Want。
- Problem: DF/ID=0 分片导致并发 data 混合重组/checksum reject。
- Root cause: plain packet link 与默认 socket fragmentation policy不匹配。
- Decision/Fix: public PMTUDiscoveryDont；fixture peer 同样使用正常分片策略。
  同步 snapshot 是独立 ownership contract，不将原失败归因于 backing-array race。
- Regression: IPv4/IPv6 4096-byte UDP、8 flows ×8 packets ×25 PASS。

### NTUN-007 — Isolated IPv6 fixture

- Surface: owned veth underlay。
- Problem: 多次 lifetime 后 IPv6 outbound dial timeout/Remote EOF。
- Root cause: addrgenmode none 且没有 link-local，后续 NUD probe失败。
- Decision/Fix: 仅在 disposable fixture 设置 explicit link-local addresses。
- Regression: original failures 保留；正常 NDP 的 real TUN ×25 PASS，无 permanent
  neighbor/sleep/retry。

### NTUN-008 — DNS/cancellation snapshot lifetime

- Surface: upper dispatcher generation reference。
- Problem: UDP DNS endpoint 不应把后续 query 固定于旧 profile；AfterFunc stop
  返回 false 不代表 callback 已 join。
- Root cause: endpoint lifetime 与 query/connection-cleanup lifetime不同。
- Decision/Fix: UDP per-query snapshot；join cancellation callback 后 release。
- Regression: same endpoint DNS profile change、blocked connection Close join
  及 terminal packet failure/degraded status PASS。

### NTUN-009 — Resource measurement states

- Surface: stress end assertion。
- Problem: STOPPED 与 CLOSED 比较将正常 journal FD release误报为泄漏。
- Root cause: baseline resource state不同。
- Decision/Fix: 分别建立 CLOSED baseline；每 cycle STOPPED 仍严格 equality。
- Regression: 首次失败完整保留；修正后 10-minute gate 重跑。

### NTUN-010 — Full repository Go 1.26 build blocker

- Surface: inherited experimental/libbox OOM profiler。
- Problem/Root cause: private linkname `runtime/pprof.parseProcSelfMaps`被 linker拒绝。
- Decision: 初轮受 inherited-source 范围限制而保留 blocker；独立 QF-003 授权
  审计和最小 inherited-source 修复。此项不是 Native TUN regression。
- Fix: Class C retained tooling/test profiler 使用 `runtime/pprof.Lookup/WriteTo`；
  删除其自定义 snapshot builder 和全部 14 个 private runtime bindings。
- Regression: 原 default/native root 失败日志保留；QF-003 重跑两项 `./...` 均 PASS，
  未关闭 linkname checks、race/checkptr 或排除 package。

## Real TUN

最终源码 `TestNativeTUNCompleteLifetime25x` PASS，25 measured lifetimes + warm
lifetime，241.14s；每 lifetime 含 IPv4/IPv6 TCP/UDP 4096-byte echo、DNS TCP/UDP、
Selector/proxy DNS、route restoration。原 `TestPhase13KernelTUN` /
`TestPhase14KernelProviderTUN` PASS，包含 all native protocol入口、retained TCP/UDP、
policy generation、Server/SOCKS/HTTP/mixed/TUN coexistence及 provider rotation。

## Resource Stability

最终 25-cycle real-TUN sampled high-water：

| Resource | Start (stopped) | Peak sampled | End (stopped) |
|---|---:|---:|---:|
| Goroutines | 6 | 46 | 6 |
| FDs | 14 | 39 | 14 |
| Eventfds | 1 | 1 | 1 |
| RSS KiB | 104188 | 160260 | 156924 |
| Listeners | 2 | 2 | 2 |
| Sessions | 0 | 8 | 0 |
| Generations | 1 | 1 | 1 |
| Leases | 1 | 1 | 1 |
| Host generations/interfaces | 0/0 | 1/1 | 0/0 |
| Journal temporaries | 0 | 0 | 0 |

一个 disabled generation/lease 和 journal descriptor 属于 STOPPED Manager；
CLOSED 状态均释放。RSS 是 race process 的 retained resident memory，未宣称
RSS 回到起点或完成性能资格。Stress high-water 是 sampled maximum，不是连续
采样的全局最大值。

## 10-Minute Stress

最终源码 PASS；wall=10m20.489118763s，active=10m7.717498492s，369 rounds。
5904 TCP flows、5904 UDP flows、47232 UDP echoes、5904 DNS replies；workload
errors=0，external DNS escapes=0。每 cycle STOPPED FD=14/eventfd=1/goroutine=6；
CLOSED end FD=13 与独立测得的 CLOSED baseline一致，generations/leases=0。

| Resource | Start (stopped) | Peak sampled | End (closed) |
|---|---:|---:|---:|
| Goroutines | 6 | 2531 | 6 |
| FDs | 14 | 1271 | 13 |
| Eventfds | 1 | 1 | 1 |
| RSS KiB | 131568 | 1757828 | 1541524 |
| Listeners | 2 | 2 | 2 |
| Sessions | 0 | 628 | 0 |
| Generations | 1 | 40 | 0 |
| Leases | 1 | 40 | 0 |
| Host generations/interfaces | 0/0 | 1/1 | 0/0 |
| Journal temporaries | 0 | 0 | 0 |

RSS retained约1.47 GiB，race run采样高点约1.68 GiB。Owned resource counts严格归还；
这次执行未证明 RSS回到起点或完成 performance qualification。

Concurrent/repeated 16 TCP (64 KiB)、16 UDP (4096-byte ×8)、16 DNS；每 round
DIRECT/Snell Selector 更新 generation，10 次 TUN lifetime。每 cycle checks
FD/eventfd/listener/session/generation/lease/interface/journal equality。

## TCP

Local IPv4/IPv6 traffic、rejection-before-accept、pending handshake cancellation、
normal EOF/final response、concurrent shutdown、retained generation PASS。

## UDP

IPv4/IPv6 fragmentation、full-tuple affinity、multi-flow repeated packet echo、
policy/outbound handoff及 cancellation/endpoint release PASS；idle default不变。

## DNS

UDP/TCP interception、current UDP query snapshot、cache/negative/binding、System、
bootstrap、verified DoT、proxy DNS、in-flight shutdown PASS。Owned namespace
external DNS escape counters 为 TCP=0 / UDP=0。

## IPv4 / IPv6

Build/unit/owned isolated real TUN IPv4/IPv6 PASS。WSL evidence 不扩展为 native
Ubuntu 或 Windows 系统资格。ICMPv4/v6 local echo保留；forwarded ICMP保持既有
rejection合同，使用 official rejection helper，无 own wire implementation。

## GSO

DEFERRED。旧产品未 enable/承诺 qualified GSO；本轮保留 plain packet MTU路径，
不启用新 offload。Official stack执行 checksum/fragmentation。

## Windows

Final build/unit/safe fake-driver integration：PASS，Go test exit=0。
Toolchain `go1.26.6` ≥minimum。Wintun borrower Interrupt/Wait 不 End/关闭 adapter，
journal 最后 exactly-once release 测试通过。Windows race NOT EXECUTED（CGO/race
prerequisites缺失）。没有 real Windows TUN、route、WinINET mutation。

## Linux amd64

产品默认/native/shared race、真实 isolated TUN：PASS；default checkptr。
最终 product gate：default 91.96s、native 124.93s、shared 34.25s，均 exit=0。

## Linux arm64

Build PASS，native Linux arm64 artifact/metadata生成成功。真实 arm64 runtime
qualification仍待冻结后验收。

## Race / Checkptr

| Scope | Result |
|---|---|
| New native writer/packet/lifecycle `-race -count=25` | PASS |
| Preserved original five QF tests ×25 | PASS，125 executions |
| Product default `./internal/splicore/... ./cmd/splicore/...` | PASS |
| Product native `with_gvisor,with_quic,with_utls` | PASS |
| Shared `./common/... ./adapter/... ./transport/...` | PASS |
| Whole repository default `./...` | PASS，QF-003 rerun 128.21s |
| Whole repository native `./...` | PASS，QF-003 rerun 178.34s |
| Default checkptr | ON，所有 race/real TUN 成功执行路径无 checkptr failure |

没有关闭 race/checkptr、链接检查、panic recover、test skip、sleep/retry workaround。
旧失败/诊断记录位于 evidence `attempts/`，未删除；外部 diagnostic overlays 未进入
production source。

## Native Protocol Regression

Snell、Hysteria2、TUIC、VLESS plain/TLS/REALITY、Mieru、DIRECT、REJECT：PASS。
`TestPhase11NativeSelfInteropMatrix`、`TestNativeVLESSSecurityAndSharedNode`、
`TestVLESSNonVisionDefaultRaceTraffic`及 server/outbound lifecycle suites。
真实 TUN protocol matrix另含 Snell/HY2/TUIC/VLESS/Mieru/DIRECT；TLS/REALITY 使用
既有 local synthetic fixtures。未改 protocol wire。

## Routing / DNS / Policy

Phase 12 matcher、Domain/CIDR、Selector、URL-Test、Fallback、Load-Balance、affinity、
DNS/health snapshot、generation retention、TUN→route→policy→outbound PASS。

## Phase 15 Regression

| Finding | Rerun coverage | Result |
|---|---|---|
| H15-001 | HTTP shutdown/readiness/forced handler join | PASS |
| H15-002 | candidate closed/stale/concurrent consumption、snapshot ×25 | PASS |
| H15-003 | System Bootstrap owner、in-flight DNS shutdown | PASS |
| H15-004 | stale provider/RuleSet failure/success/revision cases | PASS |
| H15-005 | SQLite concurrent Close/install release | PASS |
| H15-006 | support cancellation/projection cleanup | PASS |
| H15-007 | stopped native handle admission | PASS |
| H15-008 | journal temporary cleanup/unsafe file rejection/process crash | PASS |
| H15-009 | native diagnostics/doctor/support | PASS |

原 [Phase 15 freeze report](PHASE_15_FREEZE_REPORT.md)未改变。所有原 fuzz seed tests
随 product test运行；未新增 fuzz/performance资格宣称。

## TUN / Underlay

Production egress total=55，Unknown=0；after audit PASS。Backend 不创建 OS
outbound sockets，沿用 Manager classified/protected dialers。UID/mark rules、
dynamic DNS reconciliation、host route journal继续拥有 underlay保护。

## Dependency Boundary

独立 QF-003 仅修改 inherited repository 的 oomprofile implementation；
external sing-box/sing-tun/gVisor/Mieru module source modifications 均为 0。
Wire reimplementation=0。官方类型未扩散到 domain/application/API/CLI/SQLite/
routing/policy。Secret scan：PASS，findings=0，tests synthetic only。

## Xray Boundary

E runtime/control=0；F suspicious=0；G ClientProfile=10（actual count）。
FinalMask/Sudoku OUT OF SCOPE；没有引入 Xray process/artifact/adapter。

## Distribution

Linux amd64、Linux arm64、Windows amd64 build/package PASS，234.58s。
Single Splicore daemon，外部 sing-box/gVisor/Xray
process dependency=0。Artifacts、licenses、SBOM、checksums仅写入 external evidence
directory；dirty implementation verification，不是 release/frozen candidate。
Artifact checksum/source audit PASS，1499 个 Go/module source files与最终
worktree一致；ADR最终文字和本最终报告在 packaging snapshot之后完成，不将
该 source archive描述为最终文档或 frozen snapshot。

## Files Changed

| Module | Files |
|---|---|
| Native Runtime | 新 `internal/splicore/nativetun/` runtime/backend/TCP/ICMP，ownership/lifecycle/packet/resource tests |
| Client Runtime | `tun.go`、`host.go`、`status.go`；新 DNS/cancellation/degraded tests；旧 stack/stub删除；guard转 test-only |
| Host Network | 新 `device_linux.go`、`native_device_test.go`；platform Device contracts/capabilities、Wintun Interrupt；旧 Windows stack bridge删除 |
| Real TUN tests | 新 `native_tun_lab_linux_test.go`；更新既有 QF stress resources/policy/baselines，保留原 unit evidence |
| Dependency/build | `go.mod`、`go.sum`、CI `test.yml`、build.ps1、package.py最低版本检查 |
| Documentation | ADR0036/README、CLIENT_RUNTIME、DISTRIBUTION、architecture/ownership、本 report |

已有两份 QF reports unchanged；完整路径和 entry/hash audit写入 external
`source-audit.json`。无 production protocol、schema、upstream source修改。

## Migrations

NONE。Persisted TUNSettings.Stack兼容输入保留；empty/gvisor进入一个 backend，
原 unsupported system仍拒绝。没有新用户 stack selector或 database migration。

## Documentation

ADR0036 remains Proposed；[architecture](../architecture/NATIVE_TUN_RUNTIME.md) /
[ownership](../architecture/TUN_RUNTIME_OWNERSHIP.md)同步。Minimum Go文档及版本检查
同步。Historical Freeze reports保持 immutable。

## Blockers

**NONE。** NTUN-010 / QF-003 是 inherited repository-wide test blocker，
与 QF-001 packet ownership 和 QF-002 TUN lifecycle/resource blockers 分开。
原失败 `runtime/pprof.parseProcSelfMaps` 已通过 Class C public API replacement
解决；default/native 全仓库 race 均 PASS。没有 Native TUN source 修改。

## Platform Qualification

**PAUSED PENDING REVIEW AND FREEZE**。没有将 dirty worktree作为 qualified
candidate；没有 Fix Freeze、resume 或延长到正式 qualification soak。

## Git Actions

- staged: NO
- committed: NO
- pushed: NO
- tagged: NO
- released: NO
- frozen: NO
- Index: EMPTY
- History rewrite: NO

Evidence root: `D:/splicore-validation/native-tun-runtime-20261005/`，包括 entry
snapshot、原失败 attempts、final command/exit/duration logs、underlay/source/Xray/
secret audits和 distribution metadata。

QF-003 evidence root: `D:/splicore-validation/qf-003-20261005/`。原 evidence
目录不变；本报告是 current implementation report，不改变历史 Freeze reports。

**SPLICORE NATIVE TUN RUNTIME READY FOR REVIEW**
