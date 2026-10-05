# Splicore QF-003 Private Runtime Linkname Resolution Report

## Verdict

Review checkpoint: the following evidence and Git actions belong to QF-003
review. The subsequent [Qualification Fix freeze](QUALIFICATION_FIX_NATIVE_TUN_FREEZE_REPORT.md)
records the new candidate and fresh freeze-stage gates; its commit must be
used for requalification. This report does not claim qualification passed.

**SPLICORE NATIVE TUN RUNTIME READY FOR REVIEW**

**QF-003 RESOLVED — PRIVATE RUNTIME ABI REMOVED**，仅指 inherited oomprofile
boundary；不宣称清除了其他 inherited 或 dependency-owned hooks。
Class C public API replacement；Native TUN implementation、module versions 和
已通过的 real-TUN/stress source 均未改变。全部必需 gates PASS。
Platform Qualification 继续 **PAUSED PENDING REVIEW AND FREEZE**。

## QF-003

### Exact Link Failure

| Item | Captured value |
|---|---|
| QF003_MISSING_SYMBOL | `runtime/pprof.parseProcSelfMaps` |
| Exact error | `link: github.com/sagernet/sing-box/experimental/libbox/internal/oomprofile: invalid reference to runtime/pprof.parseProcSelfMaps` |
| Original location | `experimental/libbox/internal/oomprofile/linkname.go:42` |
| Failed test binaries | `experimental/libbox.test`、`experimental/boxdd.test` |
| Toolchain / host | `go1.26.6 linux/amd64`，CGO=1 |
| Project minimum | Go `1.26.3`，未降级/修改 |
| Default tags | none |
| Native / distribution tags | `with_gvisor,with_quic,with_utls`；package script 顺序为 `with_quic,with_utls,with_gvisor`，同一集合 |

修复前重新执行，未排除任何 package：

```text
go test -x -race -count=1 -timeout 600s ./...
go test -x -race -count=1 -tags with_gvisor,with_quic,with_utls -timeout 600s ./...
```

两项 exit=1，分别 103.73s / 166.20s。完整 compiler/linker trace、error、
command、GOOS/GOARCH/tags/toolchain 保存在 `logs/before-*-full-race.*`。
两项共四条 private-symbol error，去重后仅上面的一个 target。
Go linker 在首个 invalid reference 停止；不据此宣称其余声明单独可链接。

这是被拒绝的 private reference，不是新增 Native TUN 编译失败。所选 Go
源码中该函数仍存在，但不提供这个外部 pull 所需的受支持公开 API。
`api-audit/stdlib-targets.json` 记录了 exact toolchain 的相关源码声明。

最小本地 link reproducer：复制 QF-003 入口 snapshot 的原 oomprofile 文件，
建立仅依赖标准库的 external fixture，调用原 `WriteFile`，执行 `go build
-race -x`。相同 invalid reference 稳定重现；compiler 与 linker command 均已
捕获。复制的 private targets byte-identical，没有引入新 target 或 workaround。
替换后同一入口构建 PASS，六类输出均通过 `go tool pprof -top -symbolize=none`。

### All linkname.go declarations

以下是原文件的全部 12 项。Public API 一栏按诊断需求说明，不假设私有
数据布局/函数与 exported API 一一对应。全部 **Required by Splicore = NO**。

| Local Symbol | Runtime Target | Public API Equivalent / decision | Used By oomprofile? | Required by Splicore? |
|---|---|---|---|---|
| runtimeMemProfileInternal | runtime.pprof_memProfileInternal | `runtime.MemProfile` 提供公开 records；实际采用 heap/allocs `Profile.WriteTo` | YES，writeHeapInternal | NO |
| runtimeBlockProfileInternal | runtime.pprof_blockProfileInternal | `runtime.BlockProfile`；实际采用 block `Profile.WriteTo` | YES，writeBlock → writeCycleProfile | NO |
| runtimeMutexProfileInternal | runtime.pprof_mutexProfileInternal | `runtime.MutexProfile`；实际采用 mutex `Profile.WriteTo` | YES，writeMutex → writeCycleProfile | NO |
| runtimeThreadCreateInternal | runtime.pprof_threadCreateInternal | `runtime.ThreadCreateProfile`；实际采用 threadcreate `Profile.WriteTo` | YES，writeThreadCreate closure | NO |
| runtimeGoroutineProfileWithLabels | runtime.pprof_goroutineProfileWithLabels | `runtime.GoroutineProfile` 不提供这些 label pointers；goroutine `Profile.WriteTo` 提供标准 profile/labels | YES，writeGoroutine → writeRuntimeProfile | NO |
| runtimeCyclesPerSecond | runtime/pprof.runtime_cyclesPerSecond | 无 exported runtime cycle-frequency counter；block/mutex `Profile.WriteTo` 负责单位转换 | YES，writeCycleProfile | NO |
| runtimeMakeProfStack | runtime.pprof_makeProfStack | 无 exact internal scratch-stack API；输出交给 `Profile.WriteTo` | YES，writeCycleProfile | NO |
| runtimeFrameStartLine | runtime/pprof.runtime_FrameStartLine | `runtime.Frame.Line` 不是函数 start line；无 exact exported equivalent，使用标准 profile symbolization | YES，builder.emitLocation | NO |
| runtimeFrameSymbolName | runtime/pprof.runtime_FrameSymbolName | `runtime.Frame.Function` 公开但不承诺私有命名细节；使用标准 writer | YES，pcDeck.tryAdd / builder.emitLocation | NO |
| runtimeExpandFinalInlineFrame | runtime/pprof.runtime_expandFinalInlineFrame | `runtime.CallersFrames` 提供公开 frames；不重建私有 PC-array representation | YES，builder.appendLocsForStack | NO |
| stdParseProcSelfMaps | runtime/pprof.parseProcSelfMaps | 无 exported mapping-parser API；`Profile.WriteTo` 负责平台 mapping | YES，Linux profileBuilder.readMapping | NO |
| stdELFBuildID | runtime/pprof.elfBuildID | 无 exact exported pprof build-ID reader；不需要独立实现 | **NO，declaration only** | NO |

此外，原 `mapping_darwin.go` 的 `machVMRegion` / `procRegionFilename` 绑定
`runtime/pprof.mach_vm_region` / `runtime/pprof.proc_regionfilename`，由
`readMapping → machVMInfo / regionFilename` 使用。随过时 custom mapping
实现删除。此 boundary 共删除 **14 个** private bindings。

### Actual local symbol/call graph

```text
libbox.CommandServer / boxdd.daemon
  → oomkiller.NewRecorder(libbox.OOMRecorderOptions(startedService))
  → Recorder snapshot callback
  → for six names: libbox.writeOOMProfile
  → oomprofile.WriteFile
    → profileWriters[name]
      → heap/allocs: writeHeap/writeAlloc → writeHeapInternal
        → runtimeMemProfileInternal → writeHeapProto
      → goroutine: writeGoroutine → writeRuntimeProfile
        → runtimeGoroutineProfileWithLabels → writeCountProfile
      → threadcreate: writeThreadCreate → writeRuntimeProfile closure
        → runtimeThreadCreateInternal → writeCountProfile
      → block/mutex: writeBlock/writeMutex → writeCycleProfile
        → runtimeBlockProfileInternal/runtimeMutexProfileInternal
        → runtimeCyclesPerSecond + runtimeMakeProfStack
      → common builder: newProfileBuilder → readMapping
        → Linux stdParseProcSelfMaps / Darwin machVMInfo / Windows snapshot
      → appendLocsForStack → runtimeExpandFinalInlineFrame
        → pcDeck.tryAdd / emitLocation
        → runtimeFrameSymbolName + runtimeFrameStartLine
```

`stdELFBuildID` 无 caller。逐个源码位置保存在 `api-audit/symbol-usages.json`。
实际唯一 direct importer 是 `experimental/libbox/oom_report.go:14`，调用在
`writeOOMProfile`；Splicore doctor/support/daemon/API/CLI 无此调用链。

## Package Classification

**CLASS C — retained inherited tooling/test boundary。**

`cmd/splicore` 不使用它，Splicore 没有把 libbox OOM report 定义为正式 optional
product feature。但 retained libbox/boxdd 有真实 source importer，libbox build
tool/FFI、inherited build workflow 和 repository tests 仍存在。libbox 的 semver
test 与 boxdd 的 peer-authentication test 会形成相应 test binary；原来没有
专门验证 oomprofile 输出的测试，本轮补充了格式/labels/error regression。

因此不能把 package 当成 orphaned Class D 直接删除，也不需要重写整个
libbox/mobile boundary。保留 package、`WriteFile` signature、recorder wiring
和六个名字，仅替换其内部实现，是本次可验证的最小范围。

## Production Reachability

**PRODUCTION_REACHABILITY = NOT REACHABLE**，指 libbox 和 oomprofile。

Actual shipped root 只有 **`cmd/splicore`**。`go list -json ./cmd/...` 另外枚举
15 个 inherited main packages（14 个 internal tools + `cmd/sing-box`）；
README、`scripts/splicore-build.ps1`、package script 和 distribution assets
均只选择 Splicore root。这些 inherited commands 不在 Splicore 发行选择中。

| Root / Surface | libbox | oomprofile | Evidence |
|---|---|---|---|
| daemon / server / client runtime | NOT REACHABLE | NOT REACHABLE | cmd/splicore → app → application/owned engines |
| API / CLI | NOT REACHABLE | NOT REACHABLE | 同一 production dependency closure |
| doctor / support bundle | NOT REACHABLE | NOT REACHABLE | owned CLI/operations/application，包含于同一 closure |
| Linux amd64 distribution | NOT REACHABLE | NOT REACHABLE | native deps + actual binary nm/buildinfo |
| Windows amd64 distribution | NOT REACHABLE | NOT REACHABLE | native deps + actual PE binary nm/buildinfo |
| Linux arm64 distribution | NOT REACHABLE | NOT REACHABLE | native deps + actual binary nm/buildinfo |

修复前/后均执行完整 `go list -deps -json ./cmd/splicore`，default/native
分别使用实际 GOOS/GOARCH、CGO=0（发行配置）：

| Platform | Default packages | Native/distribution packages | Result |
|---|---:|---:|---|
| Linux amd64 | 701 | 788 | 两者均 NOT REACHABLE |
| Windows amd64 | 708 | 791 | 两者均 NOT REACHABLE |
| Linux arm64 | 698 | 787 | 两者均 NOT REACHABLE |

每个平台 default 和正式 distribution tags 都检查，而不是搜索字符串推断。
`graphs-before/` / `graphs-after/` 保存完整 GoFiles/Imports/module graph。
额外保留 Linux/Darwin inherited libbox package graph，确认 platform-only
mapping 和 private declarations，不扩大为 Darwin/mobile 资格验收。

Import/reference audit 共有 188 行：inherited build tooling/CI 38，docs/history
11，boxdd source 22，libbox source/internal import 111，test-only 1，reusable
oomkiller recorder 5。Production importer 0，未把 package 声明/文本命中
算成 Go import。分类和来源见 `boundary-audit/reference-classification.json`。

## experimental/libbox Inventory

| Package | Splicore ACTIVE | Retained OPTIONAL tooling/test | DEAD proved | Action |
|---|---|---|---|---|
| experimental/libbox | NO | YES，FFI/build tools、boxdd、semver tests | NO | 保留 source/API/wiring |
| internal/oomprofile | NO | YES，libbox OOM recorder direct importer | NO | Class C，公开 API replacement |
| internal/procfs | NO | YES，libbox service importer | NO | 保留 |
| internal/runtimeinfo | NO | YES，libbox OOM snapshot importer | NO | 保留；badlinkname variants 不在 shipped tags |

没有证明整棵树都是 dead，也没有删除其他 package。此处 OPTIONAL 是
repository-tooling status，不是 Splicore 支持的 optional 产品承诺。

## Decision

**REIMPLEMENTED USING PUBLIC GO API**。

`runtime/pprof.Lookup(name).WriteTo(file, 0)` 代替私有 records、unsafe labels、
frame expansion、custom protobuf encoder 和 OS mapping copies。输出仍有六类
profiles 和原文件命名，错误仍返回、失败文件仍删除；文件仅在 WriteTo
返回后 Close，一次 Close。Unknown profile 在创建文件前拒绝。

公开 writer 生成 **gzip-compressed pprof protobuf**；原实现输出 raw protobuf。
这一诊断 representation 变化明确记录，不声称 byte-compatible。标准 Go
pprof consumer 全部接受，新 tests 验证六组 sample types 和 goroutine labels。
libbox/boxdd 传递/归档 profile bytes 的调用接口未改变。没有新网络能力、
协议 wire、产品 client/server/mobile API 或 production diagnostics feature。

Capture 使用标准库分配/压缩，**best effort under OOM**；不保证低内存时
取得快照，不保证旧 custom metadata/stack ordering 的 byte-level 等价。
没有在 OOM callback 中增加 forced GC 或更改 recorder policy。

## Private Runtime Linkname Inventory

Repository declarations：**55 → 41**；全部 14 个本 blocker bindings 删除。

| Retained source group | Declarations | Selected in shipped matrix | Classification |
|---|---:|---|---|
| common/badtls registry/std + uTLS | 14 | NO，badlinkname tag | inherited optional dependency/TLS hooks |
| common/ktls | 7 | NO，badlinkname tag | inherited optional dependency hooks |
| common/tlsfragment Darwin | 1 | NO | platform-only dependency hook |
| transport/v2rayhttp legacy/go127 | 4 | 仅 legacy 1 项 | production-selected target 为 x/net/http2，不是 Go runtime；其余 go1.27+badlinkname |
| protocol/bridge Linux/Darwin | 5 | NO，package 不可达 | inherited utility/dependency hooks |
| protocol/tailscale tvOS | 1 | NO | inherited optional platform hook |
| service/oomkiller badcleanup | 2 | NO，badlinkname tag | inherited optional JSON cache hooks |
| libbox Darwin signal / Android pidfd / runtimeinfo | 7 | NO | inherited private runtime/os source，保留且未认证这些 build variants |

Current production-selected **repository private Go runtime hooks = 0**。
不是把所有 remaining source 删除；本轮不为剩余 hooks 授予 architecture exception。

Selected external dependency source 另有 77 条 linkname declarations，其中
21 条直接指向 `runtime.*`；模块分布：x/sys 6、x/net 2、sing 9、sing-tun 5、
tfo-go 1、sing-mux 1、uTLS 14、quic-go 1、bigfft 7、official gVisor 14、
SagerNet gVisor 17。它们是 **dependency/upstream-owned**，使用此前批准和
验收的版本，未修改/复制/重命名；不能据此宣称整个 dependency closure 没有
private ABI 风险。完整 targets/platform inventory 在
`boundary-audit/dependency-linkname-inventory.json`，保留为后续 dependency
boundary review，不是 QF-003 的未解决 linker failure。

原则已加入 [Fork Boundary](../architecture/FORK_BOUNDARY.md)：production
Splicore 不得依赖 private Go runtime linknames，除非另有明确 architecture
exception。此次修复使用公开 API，不新增 exception、unsafe、linker flags、
Go-version mapping、checkptr/race bypass 或 package exclusion。

QF-003 unresolved private symbols：**NONE**。

## Files Changed

仅列本轮增量；此前 Native TUN/QF implementation changes 原样保留且 UNSTAGED。

| Change | Paths |
|---|---|
| Rewrite | experimental/libbox/internal/oomprofile/oomprofile.go |
| Add meaningful regression | experimental/libbox/internal/oomprofile/oomprofile_test.go |
| Delete obsolete implementation | 同 package 的 builder.go、protobuf.go、linkname.go、mapping_linux.go、mapping_windows.go、mapping_darwin.go、defs_darwin_amd64.go、defs_darwin_arm64.go |
| Current boundary/docs | README.md；docs/architecture/FORK_BOUNDARY.md；docs/architecture/NATIVE_TUN_RUNTIME.md；docs/adr/0036-official-gvisor-eventfd-lifecycle.md |
| Current reports | 本 report；NATIVE_TUN_RUNTIME_IMPLEMENTATION_REPORT.md |

Native TUN/hostnetwork/clientruntime/application/engine/API/CLI production Go
files 和 tests、go.mod/go.sum/build/package scripts：本轮 **zero edits**。
入口 snapshot 中 354 个 protected product/source/module 文件全部 byte-identical；
2106 个既有文件保持原 hash。
历史 Freeze reports、先前 QF reports 与 external evidence 保留。

## Full Race

### Default

`go test -race -count=1 -timeout 600s ./...`：**PASS**，exit=0，128.21s。

### Native Tags

`go test -race -count=1 -tags with_gvisor,with_quic,with_utls -timeout 600s ./...`：
**PASS**，exit=0，178.34s。包括 libbox、boxdd、新 profiler tests。

Additional shared `./common/... ./adapter/... ./transport/...` native race：
**PASS**，49.76s。全部保持 default checkptr；无 exclusion/skip flags、race=false、
linker-check bypass。完整 command/exit/logs 在 external `logs/`。

## Native TUN Regression

| Gate | Result |
|---|---|
| Native TUN package race ×25 | PASS，16.31s，ownership/lifecycle/resource tests |
| Original QF-001 five tests ×25 | PASS，125 executions，25.13s |
| QF-002 resource teardown | PASS；package regression，之前真实 TUN source-equivalent |
| Prior real TUN ×25 | PASS 复用，每 cycle STOPPED FD 14→14 / eventfd 1→1 / goroutine 6→6 |
| Prior original real-TUN matrix | PASS 复用，Native TUN/source/modules 未变 |
| Prior 10-minute stress | PASS 复用；active 10m07.717s，369 rounds，errors/DNS escapes=0 |

Stress STOPPED baseline FD14，CLOSED end FD13 与独立 CLOSED baseline 相等；
goroutines/eventfd归还，不混淆测量状态。RSS retained 的原限制仍有效；不新增
performance/native Ubuntu/Windows/arm64 runtime qualification 宣称。
`source-audit.json` 记录全部 protected files hash 等价和 reused evidence hashes。
不是因为测试慢而省略复验；QF-003 profiler 不在 production/lab graph，actual
三平台 product bytes 也相同，故 untouched real-TUN/stress 证据可按要求复用。

## Builds

Go1.26.6，CGO=0，readonly、trimpath、buildvcs=false、正式 native tags。
修复前后固定 identity 的 actual binaries 均成功构建，bytes 和 SHA256 相同：

| Target | Bytes | SHA256 | Result |
|---|---:|---|---|
| Linux amd64 | 65157227 | c5407e1a95ae02e78815099451d094ebc7e718cf4d362bede93058972a33fa3b | PASS，byte-identical |
| Windows amd64 | 59782144 | a5e41eeecd05b678a5c34742701473b90a68815a90567cf758d31893629ed948 | PASS，byte-identical |
| Linux arm64 | 61845566 | 5739583f741dd76e9cc78f934e15ba4a2abe660f30dd90fbcd13407ebf3b9568 | PASS，byte-identical |

每个实际二进制还执行 `go version -m` 和 `go tool nm`：libbox / oomprofile
symbols 均 0。标准库本身可能拥有同名 private target；没有把它们误判成
oomprofile importer，也不声称删除了 Go runtime 自身的内部函数。

## Windows Safe Tests

Go1.26.6 Windows amd64，CGO=0：default **PASS 63.84s**；native **PASS 70.98s**。
两项覆盖完整 `internal/splicore/...`、`cmd/splicore/...` 和 inherited
oomprofile/libbox/boxdd tests。没有 real Windows TUN/routes/WinINET mutation。
Windows race **NOT EXECUTED**，现有环境缺少 CGO/race prerequisites；不将 safe
suite 表述为 Windows race 或 host qualification。

## Distribution

**PASS**。正式 root、实际 distribution tag set 的三平台 Go graph/linked
module identity 未变；actual fixed-identity binaries **byte-identical**，这是
commands/API/CLI/capabilities/runtime dependency 保持的直接证据，不仅是源码
搜索。Native/default product suite 也覆盖 doctor/support/API/CLI。

Binary size 变化=0；未删除任何 production capability。不同 source snapshot
使用其自己的 provenance metadata，不把 fixed comparison binaries称为 frozen
release。发行材料均仅位于 external evidence，未经 stage/commit/publish/freeze。

## Underlay

重新执行 owned callsite audit：**PASS**；production surfaces=55，
**Production egress Unknown=0**。本轮 production source unchanged。

## Xray

Repository reference 分类审计：**E=0 / F=0 / G=10**（actual ClientProfile count）。
无 runtime/control/process/artifact 回归，FinalMask/Sudoku 未进入范围。

## Historical / Upstream Integrity

HEAD `75c0b0b8dedaf0e1a3d8580d6825235364963004` 和 sole parent
`7be20f14ccb59112c98f2fa07c0cab20a436bd88` 不变。
sing-box v1.14.1 baseline provenance 不变；仅本仓库 inherited source 的
oomprofile 按新授权修改，明确不再宣称整个 inherited tree byte-identical。

External sing-box/sing-tun/official及SagerNet gVisor/Mieru dependency source
modifications = **0**；`go mod verify` **PASS**。没有 module/cache source patch、
replace、fork、新 dependency 或 Go baseline 变化。先前所有 implementation
Go/module source files byte-identical；historical Freeze reports 不改。
Modified/new files + external evidence 的 secret scan：**0 real findings**；
最终扫描数量及 evidence hashes 见 `source-audit.json`。

## Blockers

**NONE** for the requested review gates。依赖 hook inventory 和原平台/RSS
qualification limits透明保留；不将 READY FOR REVIEW 扩展为平台资格通过。

## Platform Qualification

**PAUSED PENDING REVIEW AND FREEZE**。ADR0036 仍 Proposed。未 Freeze，未恢复
qualification，未签名、发布、tag 或执行第三方 targets。

## Git

- Branch: `codex/qf-001-native-tun-iovec-race`
- HEAD: unchanged
- Working tree: DIRTY，全部变更 UNSTAGED
- staged: NO
- committed: NO
- pushed: NO
- tagged: NO
- released: NO
- frozen: NO
- index: EMPTY
- history rewritten: NO

Evidence root: `D:/splicore-validation/qf-003-20261005/`，含 entry hashes/diff、
before/after full race traces、minimal compiler/link repro、六类 pprof consumer
logs、12项 usage graph、完整 production/import/tag/linkname inventories、
actual before/after binaries/nm/buildinfo、targeted/Windows/module/secret/
underlay/Xray/integrity records。原 Native TUN evidence root 未被覆盖。

**SPLICORE NATIVE TUN RUNTIME READY FOR REVIEW**
