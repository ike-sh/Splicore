# Splicore Phase 17 Independent Core Decoupling Report

## Verdict

**PHASE 17 FROZEN**

Current verdict is established by the appended consolidated freeze metadata
and the canonical Independent Core Transition Freeze Report. Earlier checkpoints
below preserve the implementation and failed-review history.

## Historical checkpoints — preserved

## Round 2 continuation: Snell stage acceptance and HY2 investigation

Evidence below appends to the preceding historical checkpoints. It does not
replace the remaining Phase 17 hard gates.

- Owned Snell v4/v6 wire compared with pinned references: 960 complete wire
  cases, 96 PSKs and five payload sizes; continuous classic stream growth
  matched. Eight both-role local TCP/UDP reference rows passed. Command/datagram
  fuzz: 988,193 executions; record fuzz: 129,620; zero crashes. A discovered
  IPv6 parser case remains a regression seed.
- Current owned Snell race binary passed nine CLI/API reference rows and ten
  negative cases, including server v5/v6, 16 concurrent flows, 4 MiB payload,
  reconnect, restart, account attribution, listener release and shutdown.
  `snell-stage/final-binary-*` holds acceptance; failed attempts remain intact.
  Command-one payload/EOF and managed half-close/shutdown tests passed x10 race.
- Reference Mihomo starts its SOCKS listener before completing ApplyConfig.
  Fixture readiness now uses synchronous local controller config application
  before the single payload attempt. It uses no payload retries or sleeps.
- HY2 now owns bounded application frames, immutable authentication, stream
  half-close, private lazy client transports and joined datagram workers on
  independent apernet/quic-go. Official HY2 SDK is an external oracle only.
  UDP decoding transfers fresh bytes; fragment assembly has one dispatcher
  owner and bounded storage; direction locks protect packet deadlines/writes.
- HY2 stage binary passed 12 local reference client rows plus auth/TLS negatives,
  per-user attribution, disable/re-enable, cached-peer reconnect without test
  retries, SQLite restart and shutdown. Owned regression x10 race passed;
  actual wire mutation fuzz: 1,006,865 executions in 20 seconds, zero crashes.
- Full application race exposed dual-stack localhost resolution choosing an
  AAAA address for an IPv4-only proxy listener. Managed IPv4 preference has
  been restored. The actual failing application subtest and owned x10 race
  passed after that change. Earlier product failure log remains preserved.
- Official SDK both-role attempt 2 timed out, and bounded attempt 3 identified
  the exact limit: the SDK's 4096-byte send buffer includes the application
  header; Serialize returns -1 for a 4096-byte pure payload, and SendMessage
  silently drops it. This was an oracle capability mismatch, not suppressed
  by a production workaround. Attempt 4 passed both roles with 1/900/4000/2048
  bytes, including real fragmentation. Owned 4096-byte payload coverage remains.
  All failed logs remain under `hysteria2-stage/official-sdk-both-roles*`.
- QUIC substrate default congestion is CUBIC; prior managed HY2 glue used BBR.
  Managed settings expose neither bandwidth nor congestion. Application wire
  headers remain auto. Congestion implementation equivalence is not claimed.
- Boundary incident: one broad filename enumeration accidentally returned
  NoBrand directory paths. No NoBrand contents were opened or inspected.
  Subsequent searches are confined to this repository and validation paths.

Current status remains **PHASE 17 NOT READY FOR REVIEW**. TUIC/VLESS migration,
source and graph elimination, final regression and remaining hard gates continue.

**DEPENDENCY DECOUPLING BLOCKER — Snell v6:** the audited independent OpenSnell
candidate explicitly rejects v6. The pinned sing-snell v6 source is readable as
an authorized behavior reference; preliminary source behavior notes now exist.
A complete verified contract, original Splicore implementation and new real
TCP/UDP interoperability evidence do not yet exist. A direct candidate swap
would lose an existing capability. This finding rejects that replacement; it
does not establish that an owned rewrite is impossible. sing-snell remains an
unresolved migration/readiness item, never an accepted final dependency.

Module identity migration and two bounded unused-source removal steps are complete.
The runtime migrations are incomplete: the root graph still has **55** SagerNet
modules. The required zero-dependency and migrated-protocol acceptance gates
have not passed. No compatibility shim, copied tree, fork, module-cache patch,
new protocol, capability downgrade or disabled checker was introduced.

## Starting State

- Branch: `codex/phase-16-native-shadowsocks`.
- HEAD: `b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c`, unchanged.
- Phase 16: READY FOR REVIEW, unstaged, not frozen.
- Index: EMPTY at entry and after changes.
- New authorization supersedes the Phase 16 Review/Freeze prerequisite.
- Go minimum remains 1.26.3.

### Phase 16 preservation

Directory: `D:/splicore-validation/phase16-pre-decoupling-20261006`.

Preserved a complete binary/full-index tracked and untracked patch, diff/stat/name
status, complete file hash manifest, full worktree archive, go.mod/go.sum,
implementation report and external evidence references. **2,143 files**, **28
untracked files**, **121 evidence references**; archive members were individually
hash verified. No stash/reset/restore/stage/commit was used.

After migration, all **376** files under `internal/splicore` and `cmd/splicore`
match the preserved snapshot after normalizing only the module namespace in
memory. No internal test was deleted. The Phase 16 implementation report remains
byte-identical. Evidence: `after-summary-final.json` and preservation manifests.

## Module Identity

Before: `github.com/sagernet/sing-box`.

After: `github.com/ike-sh/Splicore`.

Migrated local Go imports, nested test-module require/replace, protobuf
go_package metadata and active build/link paths. The first identity pass changed
994 files and 3,236 path references. Legal attribution lines and historical docs
were excluded. Structural Go import audit: **OLD_LOCAL_IMPORTS = 0**, across all
build tags, tracked/untracked files and the separate test module.

`go list ./...` reports the new main-module namespace. Native-tag Linux amd64,
Windows amd64 and Linux arm64 build metadata all report
`mod github.com/ike-sh/Splicore (devel)`.

### Descriptor correction

The first default test attempt found descriptor corruption introduced by textual
replacement inside generated protobuf raw strings. That failure is preserved in
`stage-b/default-tests.log`. Re-serialized five FileDescriptorProto values using
the pinned protobuf library, changing only go_package. `proto.Equal` checks after
restoring that option confirmed all wire definitions were preserved. The repaired
complete suite passed. No protobuf library/runtime source was modified.

## SagerNet Dependency Graph

| Measurement | Before | Current | Required |
| --- | ---: | ---: | ---: |
| External direct SagerNet modules | 29 | 26 | 0 |
| External indirect SagerNet modules | 29 | 29 | 0 |
| External module names | 58 | 55 | 0 |
| All SagerNet graph names, including old main module | 59 | 55 | 0 |
| Old local Go imports | present | 0 | 0 |
| Remaining SagerNet source imports | present | 2,407 | 0 |

The 2,407 source imports comprise 2,197 production-source classifications
(including inherited unreachable source), 194 test imports and 16 tooling
imports. These are source counts, not a count of executed runtime packages.
All 1,481 surviving Go files were parsed structurally, regardless of build tags.
The nested test module still has SagerNet dependencies and is also unfinished.

Before evidence includes `go mod graph`, `go mod why -m`, module metadata,
production `go list -deps` and `go list -test -deps` for Linux default/native,
Windows native and Linux arm64 native. All six inspected list modes had zero
package errors. Source inventory found 48 sing utility packages and 2,111 uses
before removal. Full inventories are in `DEPENDENCY_DECOUPLING_MATRIX.{json,md}`,
`SING_USAGE_INVENTORY.{json,md}`, `before/` and `stage-c-leaves/source-audit.json`.

The independent parent `github.com/anytls/sing-anytls v0.0.11` previously pulled
sing into the graph. Its unused AnyTLS source, registration, options and root
require/sum entries have now been removed. Other SagerNet parents remain pending.

### Before / current module inventory

Decisions below are migration plans; REMAINS is never removal evidence.

| Module | Before | Current | Decision / pending replacement |
| --- | --- | --- | --- |
| github.com/sagernet/asc-go | v0.0.0-20260827085112-8f8226245b0d | REMOVED | REMOVED unused mobile/App Store tooling |
| github.com/sagernet/bbolt | v0.0.0-20260823094646-e24805439c9c | REMAINS | REMOVE — inherited cache persists outside managed SQLite product model |
| github.com/sagernet/cors | v1.2.1 | REMAINS | REMOVE — inherited Clash API |
| github.com/sagernet/cronet-go | v0.0.0-20260912104727-0d28acc44093 | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/all | v0.0.0-20260912104727-0d28acc44093 | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/android_386 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/android_amd64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/android_arm | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/android_arm64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/darwin_amd64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/darwin_arm64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/ios_amd64_simulator | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/ios_arm64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/ios_arm64_simulator | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_386 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_386_musl | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_amd64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_amd64_musl | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_arm | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_arm64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_arm64_musl | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_arm_musl | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_loong64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_loong64_musl | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_mips64le | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_mipsle | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_mipsle_musl | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_riscv64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/linux_riscv64_musl | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/tvos_amd64_simulator | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/tvos_arm64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/tvos_arm64_simulator | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/windows_amd64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/cronet-go/lib/windows_arm64 | v0.0.0-20260912104006-c10c03c318db | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/fswatch | v0.1.2 | REMAINS | REPLACE — fsnotify for remaining watcher use |
| github.com/sagernet/gliderssh | v0.3.4-0.20260531100337-2194faca5648 | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/gomobile | v0.1.12 | REMOVED | REMOVED unused mobile/App Store tooling |
| github.com/sagernet/gvisor | v0.0.0-20260727.0-sing-box-mod.1 | REMAINS | REMOVE — official gvisor.dev/gvisor; remove inherited TUN/Tailscale |
| github.com/sagernet/netlink | v0.0.0-20260814022025-64455d367bbf | REMAINS | REPLACE — official netlink or existing host layer |
| github.com/sagernet/nftables | v0.3.0-mod.4 | REMAINS | REMOVE — inherited sing-tun autoroute |
| github.com/sagernet/quic-go | v0.61.0-sing-box-mod.7 | REMAINS | REPLACE — official quic-go or official Hysteria QUIC dependency |
| github.com/sagernet/sing | v0.9.4 | REMAINS | REWRITE — stdlib, owned Destination and lifecycle contracts |
| github.com/sagernet/sing-cloudflared | v0.1.3-0.20260706062323-d9787e794aa3 | REMOVED | removed unused Cloudflared source, registration, options and root module requirement |
| github.com/sagernet/sing-mux | v0.3.6 | REMAINS | REMOVE — inherited sing-box mux config is not an active product feature |
| github.com/sagernet/sing-openconnect | v0.0.0-20260810065514-53aa8058f8df | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/sing-openvpn | v0.0.0-20260729104525-103eb5fe5eb6 | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/sing-quic | v0.7.0 | REMAINS | REPLACE — independent QUIC/Hysteria libraries and owned TUIC framing |
| github.com/sagernet/sing-shadowsocks | v0.2.8 | REMAINS | REWRITE — existing owned wire code, stdlib EVP derivation/address codec |
| github.com/sagernet/sing-shadowsocks2 | v0.2.1 | REMAINS | REMOVE — existing owned SS2022 wire implementation |
| github.com/sagernet/sing-shadowtls | v0.2.1 | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/sing-snell | v0.0.0-20260829071736-20f2eaec77c3 | REMAINS | TEMPORARY BLOCKER — Snell v6 independent library/spec needs validation; v4/v5 candidate OpenSnell |
| github.com/sagernet/sing-tun | v0.9.3 | REMAINS | REWRITE — owned platform device I/O, official gVisor |
| github.com/sagernet/sing-usbip | v0.0.0-20260817040617-28bd42667eca | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/sing-vmess | v0.2.8 | REMAINS | REWRITE — owned VLESS framing; remove inherited VMess |
| github.com/sagernet/smux | v1.5.50-sing-box-mod.1 | REMAINS | REMOVE — inherited SSH transport |
| github.com/sagernet/tailscale | v1.102.1-sing-box-1.14-mod.5 | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/wireguard-go | v0.0.6 | REMAINS | REMOVE — remove proven unused inherited parent/source/registration |
| github.com/sagernet/ws | v0.0.0-20231204124109-acfe8907c854 | REMAINS | REMOVE — inherited custom V2Ray websocket transport |

## Dependency Replacements

| Removed | Replacement | Reason / regression |
| --- | --- | --- |
| sagernet/asc-go | none; remove unused App Store command | outside product closure; remaining command tests and full race pass |
| sagernet/gomobile | none; remove unused mobile build command | outside product closure; remaining command tests and full race pass |
| sagernet/sing-cloudflared | none; remove unused Cloudflared feature | outside product closure; full default/native race and builds pass |
| anytls/sing-anytls | none; remove unused AnyTLS feature | eliminates an independent parent that imported sing |
| anthropics/anthropic-sdk-go | none; remove unused CCM service | no AI capability in the Splicore product set |
| openai/openai-go/v3 | none; remove unused OCM service | no AI capability in the Splicore product set |
| cretz/bine | none; remove unused Tor feature | no Tor capability in the Splicore product set |

No runtime library replacement is claimed complete. Independent candidates were
audited using fixed Go 1.26.6 / GOTOOLCHAIN=local: OpenSnell v1.0.4 requires Go
1.24.0, official Hysteria core/v2 v2.13.0 requires Go 1.26.0, official quic-go
v0.63.0 requires Go 1.26.0. None was added to the production module. No minimum-Go
exception was needed.

## Removed Inherited Features

Actually removed: App Store publishing/version command, mobile libbox build
command, their two dependencies and the inherited multi-product publication
workflow. Replaced the giant inherited Makefile with local Splicore build/default
and native test/race targets. Required module downloads remain the ordinary Go
dependency operation; there is no toolchain auto-download in the recorded runs.

Removed source is archived and hash verified in
`stage-c-mobile-tooling-removed.tar.gz`. A second bounded step removed CCM/OCM
AI services, AnyTLS, Cloudflared and Tor, including their source/options and
registration. Its 31 deleted files are separately archived and hash verified in
`stage-c-unused-leaves-removed.tar.gz`; no test was deleted. Their five parent
requirements and sums were removed. OpenVPN, OpenConnect, Tailscale, WireGuard,
Cronet and other inherited surfaces have **not** yet been removed. The initial
reachability plan identifies 82 unused package entries;
that plan is not represented as completed deletion.

## Protocol Layout

Current owned validation/domain integration remains under
`internal/splicore/protocol/{shadowsocks,snell,hysteria2,tuic,vless,mieru}`.
Runtime factories remain under `internal/splicore/engine/native`.
Inherited root `protocol/` still contains non-product and dependency-coupled
adapters. Root protocol layout cleanup, including mandatory `protocol/mieru`,
is **NOT COMPLETE**.

## Mieru

Official `github.com/enfein/mieru/v3 v3.38.0` is unchanged. Splicore continues
to own SDK mapping, socket hooks, user attribution and lifecycle. No SDK source
was copied. Root `protocol/mieru` integration ownership remains a pending gate.

## Shadowsocks

### Classic

Existing six-method product set, TCP/UDP client/server, account/provider/API/CLI,
backup, policy and TUN integration remain. Existing classic framing is owned by
Splicore, but sing-shadowsocks password derivation and sing address serialization
are still present. These have not been relabeled as independent replacements.

### 2022

Existing SIP022/SIP023 framing, AES multi-user identities, ChaCha single-user,
session/timestamp/replay bounds and per-direction buffers remain byte-identical
after import normalization. Inherited sing-shadowsocks2 source/dependencies are
still present and await removal. No method, UDP capability or replay check was
disabled.

### Crypto libraries and wire ownership

Current owned code uses standard AES/GCM/HKDF/random and x/crypto ChaCha/XChaCha,
with independent BLAKE3 primitives. No crypto primitive was implemented. The
remaining key-derivation/address dependencies must be removed and revalidated
against the 28-row external interoperability baseline.

## Snell

Current managed server v5/v6, client mapping v4/v6 and TCP/UDP-over-TCP are
preserved, still backed by sing-snell. Current v6 profile is encrypted/default;
other modes and QUIC Proxy Mode are not added.

Pinned public OpenSnell v1.0.4, commit
`b682576a0b05c35f125d443478be82c0c24f6ce7`, supports v4/v5. A separate local
module ran its real constructor under default race/checkptr: v4/v5 construction
accepted, v6 explicitly rejected. Evidence: `opensnell-probe/version-boundary.log`.
This is a candidate boundary test, not protocol traffic acceptance. No socket was
opened by the probe, and its independent module graph contains zero SagerNet
nodes.

The [public OpenSnell v6 status](https://raw.githubusercontent.com/missuo/opensnell/main/SNELL_V6.md)
states that OpenSnell's v6 implementation is not published. The
[official Snell v6 announcement](https://nssurge.com/blog/snell-v6/) describes a
PSK-derived profile affecting salt/framing/padding/shaping, but does not supply
the complete executable wire contract. Current
[Mihomo source](https://raw.githubusercontent.com/MetaCubeX/mihomo/Meta/transport/snell/snell.go)
also does not provide a v6 replacement. These findings reject the audited direct
replacement options; they do not prove an owned implementation is impossible.
The local pinned sing-snell v6 source is available as an authorized reference.
Source follow-up hashes 20 exact candidate/reference files without modifying
them. `SNELL_V6_SOURCE_BEHAVIOR_NOTES.md` records preliminary observations of
key derivation, per-direction nonce/state, salt placement, record associated
data, padding/mixing, framing, UDP and reuse. It explicitly leaves complete
profile arithmetic and normative vectors unverified.

Before removing sing-snell, derive and independently verify the required v6
behavior notes/profile vectors from permitted references, implement framing
with standard primitives and owned state, and pass real v6 TCP/UDP interop plus
negative/fuzz/lifetime gates. No source was copied or translated into a local
sing-snell mirror to bypass that work. The candidate swap is unsafe because it
loses v6; the original owned rewrite remains authorized and incomplete. No
additional licensed Surge runtime is imposed as a new acceptance requirement.

## Hysteria2

Existing native password identity/TCP/UDP/static TLS behavior is unchanged.
sing-quic remains. Official Hysteria is an independently maintained candidate;
socket injection, user attribution, cancellation, replay/security behavior and
interoperability have not yet been integrated or qualified.

## TUIC

Existing v5 UUID/password, cubic/native UDP and disabled 0-RTT profile remains.
sing-quic remains. Official quic-go plus owned framing/auth/UDP/lifecycle is
planned. No congestion/profile downgrade or new QUIC crypto was introduced.

## VLESS

Native plain/TLS/REALITY remains; Vision stays DEFERRED. sing-vmess/vless and
shared TLS/address/runtime helpers have not yet been removed. Existing regression
tests pass, without introducing Xray runtime.

## QUIC Boundary

Owned adapter design and integration are pending. No external library concrete
types were newly exposed to the domain. The existing SagerNet QUIC stack remains
an unresolved dependency, not an accepted exception.

## Network Abstraction

Detailed sing usage inventory exists for network interfaces, metadata, buffers,
logging, errors, service context, deadline/packet wrappers and task helpers. A
standard-library-first migration remains pending. No API mirror or singcompat
package was created. Per-connection buffer/state ownership remains unchanged.

## TUN Boundary

Splicore Native TUN continues to use exact official gVisor and owned lifecycle,
NIC/link/session/runtime with the existing host journal. The retained inherited
stack/device/route helpers and legacy tests still pull sing-tun/SagerNet gVisor.
No Native TUN runtime behavior changed. Final dependency removal and real kernel
25-lifecycle resource acceptance are pending.

## Product Identity

Active `cmd/splicore`, module imports and build/link metadata use Splicore.
Inherited `cmd/sing-box`, Docker/release surfaces still exist and await cleanup.
Product runtime CLI tests pass. Historical names, source attribution and external
client export format names are preserved deliberately.

## API / CLI

Existing management/API/CLI semantics are unchanged after namespace normalization.
Full Go tests and the Windows safe CLI package pass. No endpoint was added.

## SQLite

No migration/schema/domain data change. Complete SQLite regression tests are
included in passing default/native race suites.

## Providers

Existing SS/SS2022 and existing protocol node/provider integration remains.
Management/provider/routing-policy tests are included in passing suites.

## Backup / Restore

Existing encrypted backup/restore tests pass in full suites. Storage and provider
reference code is source-equivalent; no credential ownership change.

## Interoperability

| External gate after runtime migration | Current result |
| --- | --- |
| SS/SS2022 28+ rows | NOT RUN; historical Phase 16 evidence preserved |
| Snell TCP/UDP, v5/v6 | NOT RUN for an independent implementation |
| Hysteria2 / TUIC | NOT RUN for replacement libraries |
| VLESS plain/TLS/REALITY | native local regressions PASS; new external gate pending |
| Official Mieru | local regressions PASS; final external gate pending |

Historical reference successes are not reused as Phase 17 feature acceptance.

## Tests

All evidence is under `D:/splicore-validation/phase17-core-decoupling-20261006`.

| Gate | Result | Evidence |
| --- | --- | --- |
| Stage B complete default go test ./... | PASS after descriptor repair | stage-b-repaired/default-tests.log |
| Stage B internal/cmd full Native race | PASS | stage-b-repaired/native-race.log |
| Stage C remaining tool/CLI tests | PASS | recorded command result |
| Stage C default go test -race ./... | PASS | stage-c/default-race.log |
| Stage C complete native-tag race ./... | PASS | stage-c/native-full-race.log |
| Stage C leaf removal complete default go test ./... | PASS | stage-c-leaves/default-tests.log |
| Stage C leaf removal default race ./... | PASS | stage-c-leaves/default-race.log |
| Stage C leaf removal full native-tag race ./... | PASS | stage-c-leaves/native-full-race.log |
| Shared package race | PASS as part of full default/native suites | same full logs |
| Default checkptr | ON; no override | recorded commands / go-env.txt |
| Windows safe native/clientruntime/hostnetwork/CLI | PASS | windows-safe/tests.log; exit-code.txt = 0 |
| Windows safe after leaf removal | PASS | windows-safe-leaves/tests.log; exit-code.txt = 0 |
| Independent candidate constructor boundary | EXPECTED v6 REJECT | opensnell-probe/version-boundary.log |

Native tags: `with_gvisor,with_quic,with_utls`. Fixed toolchains: Go 1.26.6
linux/amd64 and windows/amd64. Every recorded runner uses `GOTOOLCHAIN=local`.
Inventory/candidate downloads explicitly record proxy/sumdb; regression gates use
the existing fixed toolchain and cached modules. No automatic toolchain download,
race/checkptr suppression, panic recovery, sleep/retry masking or test deletion.
The separate inherited test module was inventoried by source and module identity;
its complete Docker/reference suite was not executed here.

## Fuzz

No new framing/parser was implemented. Existing fuzz seed tests run in complete
suites. New mutation runs and strengthened malformed/auth/replay/time/bounds
acceptance for rewritten codecs remain **NOT RUN / NOT SATISFIED**.

## Resource Stability

Local lifecycle regressions pass. The new real kernel Native TUN 25-lifecycle
resource gate, goroutine/FD/eventfd/listener/session/generation/lease measurements
are **NOT RUN**. Historical evidence is preserved and is not asserted as new
runtime-rewrite acceptance.

## Stress

New >=10-minute mixed all-protocol TCP/UDP/DNS/routing/policy/TUN stress:
**NOT RUN**. Actual new mixed-stress duration: 0. The Phase 16 historical 10-minute
SS stress remains historical. No 60-minute qualification soak was rerun.

## Builds

| Platform | Native-tag build | Module metadata | Runtime scope |
| --- | --- | --- | --- |
| Linux amd64 | PASS | github.com/ike-sh/Splicore | development regressions |
| Windows amd64 | PASS | github.com/ike-sh/Splicore | safe local tests only |
| Linux arm64 | PASS | github.com/ike-sh/Splicore | BUILD ONLY; runtime NOT CERTIFIED |

Evidence: `stage-c-leaves/build-*.log` and `stage-c-leaves/metadata-*.txt`, plus
the preserved earlier `stage-c` build evidence. No release assets
were produced in the repository or published.

## Underlay

Audit PASS: **Unknown=0**, production surfaces=60, test surfaces=117.
Evidence: `underlay-leaves/inventory-after.{json,md}`, with earlier evidence
preserved in `underlay/`. Runtime socket constructions and
protection invariants are unchanged. Final audit after dependency migration is
still required.

## Xray

The Phase 16 classified E=0/F=0/G=10 boundary is retained by complete internal
source equivalence after namespace normalization and passing registry/retired
engine regressions. No production engine subprocess was added; external core
processes remain 0. Current stage has no new profile/runtime mapping. Final full
Phase 17 classification after future runtime migration remains pending.

## Dependency Licenses

No production replacement dependency was added. Existing legal files are
byte-identical. OpenSnell audit source carries GPL-3.0-or-later; it is only a
module-cache candidate and was not copied into this repository. Exact replacement
license review remains a gate for each eventual production addition.

## Source Attribution

LICENSE/NOTICE unchanged and hash verified against preservation manifest.
Copyright/SPDX lines were excluded from namespace replacement. No batch copyright
rename. Deleted tooling source is preserved externally and in unchanged Git
history. No upstream module/runtime cache file was edited.

## go.mod / go.sum

Main module changed; Go minimum unchanged. asc-go/gomobile/sing-cloudflared and
four unused independent parent require/sum entries were removed. All other
SagerNet requirements remain pending. No replace-to-shim,
vendor, fork or local runtime replacement. The nested test module's local
Splicore require/replace was migrated; its SagerNet imports and graph remain a
final blocking gate. Final go mod tidy/full graph audit is incomplete.

## Files Added

- docs/architecture/INDEPENDENT_CORE_DEPENDENCIES.md
- docs/adr/0038-remove-sager-net-core-dependency-graph.md (Proposed)
- docs/reports/PHASE17_SINGBOX_DECOUPLING_REPORT.md

## Files Modified

Namespace migration in Go source, nested go.mod, protobuf metadata and build
scripts; five repaired raw descriptors; root go.mod/go.sum; Makefile; architecture
and ADR indexes. Exact before-Phase17 file lists/hashes are external in
`stage-b-identity-changes.json`, `stage17-files-modified-final.txt` and the snapshot.
Original Phase 16 changes remain unstaged and were not reset.

## Files Removed

- .github/workflows/build.yml
- cmd/internal/app_store_connect/main.go
- cmd/internal/build_libbox/main.go
- 31 unused CCM/OCM, AnyTLS, Cloudflared and Tor source/option/registration files,
  enumerated in `stage-c-unused-leaves-removed.json` and
  `stage17-files-removed-final.txt`.

No internal protocol, lifecycle, fuzz or qualification test was removed.

## Findings

### DEC17-001 — Preserve unstaged Phase 16

Before: 2,143 files, 28 untracked files; risk of losing uncommitted implementation.
Replacement: verified external patch/archive/hash/evidence snapshot.
Files: preservation directory; no Git mutation.
Regression: all 376 internal/product files source-equivalent after namespace
normalization; original Phase 16 report unchanged.

### DEC17-002 — Real module identity migration

Before: old main module/import/link paths.
Replacement: exact github.com/ike-sh/Splicore identity.
Files: stage-b-identity-changes.json; five generated raw descriptors.
Regression: initial descriptor panic captured; reserialization/equality repair;
complete tests/race and three build metadata gates PASS. Old local imports=0.

### DEC17-003 — Remove unused App Store/mobile dependencies

Before: asc-go/gomobile used only by excluded inherited build/publishing tools.
Replacement: remove those commands/workflow; local product Makefile targets.
Files: three removals, Makefile, go.mod/go.sum.
Regression: remaining commands/CLI, default/native full race and builds PASS.
Current direct/indirect SagerNet counts=26/29 after the additional bounded leaf
removal below. Other removal classifications remain plans.

### DEC17-004 — Base runtime coupling remains

Before/usage: sing metadata/buffers/tasks/logging and box/router/DNS/DIRECT
constructors span product engines and inherited source. Replacement: standard
types and narrow owned contracts, not an API mirror. Files: detailed usage/matrix
inventories. Regression: unchanged-runtime tests pass; replacement regression is
pending. Stage D/E/F/H/I/J/K are not complete.

### DEC17-005 — Snell v6 dependency decoupling blocker

Before/usage: sing-snell implements current server v5/v6 and client v4/v6.
Candidate: independent OpenSnell v1.0.4 explicitly rejects v6; OpenSnell's public
v6 implementation is unavailable. The official announcement does not give a
complete wire contract. The permitted pinned sing-snell v6 reference source is
available and was reviewed; an original owned rewrite is not ruled out.
Files: candidate provenance/metadata, independent constructor probe,
`snell-source-followup.json`, `SNELL_V6_SOURCE_BEHAVIOR_NOTES.md`.
Regression: expected v6 rejection under race/checkptr PASS; independent Splicore
v6 implementation and wire/security/interoperability acceptance NOT AVAILABLE.
Required resolution: complete verified behavior notes/vectors, owned implementation and
real TCP/UDP reference gates. Residual sing-snell is not accepted.

### DEC17-006 — Preserve qualification/evidence boundaries

Historical report remains hash-identical; all gaps remain OPEN. Current worktree
is NOT PLATFORM QUALIFIED YET. No qualification restart, new freeze, production
diagnostics, acceptance weakening or public modification.

### DEC17-007 — Remove unused AI/protocol parent dependencies

Before/usage: CCM/OCM AI services and AnyTLS/Cloudflared/Tor were inherited
source outside the product closure, with registrations/options and five parent
requirements. AnyTLS's independently named parent pulled sing transitively.
Replacement: remove those unsupported surfaces in one bounded step.
Files: 31 archived deletions, include/registry.go, go.mod/go.sum.
Regression: targeted internal/product tests, complete default tests/race,
native full race, Windows safe tests and three builds PASS. No test deletion.
Source imports fell by 64; root SagerNet module count fell from 56 to 55.

## Platform Qualification

Historical candidate: `b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c`.
Historical status: **PARTIALLY PASSED**. GAP-01/02/03/04 remain OPEN.
Current implementation: **NOT PLATFORM QUALIFIED YET**.

Canonical report remains:
`D:/splicore-validation/platform-requalification-20261005/PLATFORM_REQUALIFICATION_FINAL_REPORT.md`.
SHA256 unchanged:
`18065f3ca3c5f34f5ac8d8e0d52b34a80218f7a6f4ab418f256467c80996bba7`.

## Public Git

No public snapshot/GitHub/v0.1.0 was accessed or modified. No remote Git action.

## NoBrand

NOT ACCESSED.

## Secrets

Secret-redaction/support-bundle regression gates are included in passing suites.
No new real secret input was created or printed. The new final whole-worktree
secret classification scan is not claimed complete: real/unresolved final counts
are **NOT ASSERTED**. A ready verdict requires that final scan as well.

## Blockers

1. DEC17-005: the audited independent direct replacement rejects required Snell
   v6; a complete verified owned v6 port has not been implemented. Reference
   source is available; this is an unresolved migration/readiness item, not a
   conclusion that the authorized rewrite is impossible.
2. Remaining dependency migrations and mandatory final gates are incomplete:
   SagerNet module graph=55, source imports=2,407, root Mieru integration absent,
   and replacement interop/mutation/resource/mixed-stress gates pending.

The current worktree is a buildable, tested intermediate state. No residual
dependency is accepted, and no Review/Freeze is performed. The zero-dependency
objective and mandatory runtime-rewrite acceptance are not complete.

## Git Actions

staged: NO; committed: NO; pushed: NO; tagged: NO; released: NO; frozen: NO.
Index: **EMPTY**. Branch and HEAD unchanged. Worktree: **UNSTAGED / DIRTY**.

**PHASE 17 NOT READY FOR REVIEW**

---

# Round 2 / Final Implementation — in progress

This section appends implementation evidence. The Round 1 findings above remain
historical. No ready, review, freeze or platform certification claim is made.

## Preservation and real dependency roots

External `round2-prestate/` preserves the full pre-round archive, patch, file
hashes, go.mod/go.sum and inventories; 2,112 members verified. Actual all-tag
Go AST import roots and native product/test closure are recorded in
`SAGERNet_IMPORT_ROOT_MAP.{json,md}` and `SAGERNet_DECOUPLING_DAG.{json,md}`:
63 families, 152 local package edges. Migration follows product leaves first,
then replaces inherited runtime/router roots and removes non-product trees.

## Completed foundation migrations

- Owned canonical SOCKS address codec and Snell-specific address contract;
  standard net/netip semantic endpoints and fixed address/key vectors.
- SS/SS2022 native server/client no longer compose inherited box/router or
  Shadowsocks libraries. Protected target sockets, joined TCP half-close relay,
  per-target UDP sockets, bounded queues and authenticated migration preserved.
- Atomic traffic counters and immutable lookahead snapshots; no buffer pool
  crossing Close/read ownership. A real inherited CachedConn read/Close race
  found by full application tests is isolated at the transitional boundary
  using atomic cache transfer and a reader-owned snapshot. Upstream cache and
  runtime files were not patched.
- Managed DNS uses independent miekg/dns plus stdlib TLS and protected sockets;
  UDP truncation to TCP and ID filtering preserved and regression-tested.
- Local HTTP uses stdlib parser; local SOCKS/UDP uses owned RFC1928 framing.
  Existing application/client acceptance tests migrated without dropping checks.
- Linux routes/rules use independent netlink v1.3.1; socket protection uses
  owned SO_MARK control. Windows production control remains injected.
- QF-001 test helpers use official gvisor.dev types; Native TUN lifecycle
  implementation unchanged.
- Root `protocol/mieru` owns Compiler/OutboundFactory entry points. Existing
  owned SDK integration and tests moved to `protocol/mieru/backend`, keeping
  SDK types there. All original lifecycle/EOF/UDP/admission tests retained.
- Minimal helpers: traffic, netaddr, neterror, clientconfig, relay, and owned
  testfixture. No sing utility/service registry clone was introduced.

## Foundation checkpoint verification

Evidence directory:
`D:/splicore-validation/phase17-core-decoupling-20261006/round2-foundations/`.
Fixed preinstalled Go 1.26.6, GOTOOLCHAIN=local; project minimum 1.26.3.

| Gate | Result |
| --- | --- |
| Ownership reproducer `TestInheritedLookaheadTransferReadCloseOwnership` x10 | PASS |
| Mieru / traffic / address / SOCKS / SS wire / underlay / hostnetwork / DNS race | PASS |
| Default `go test -race ./...` | PASS |
| Native `with_gvisor,with_quic,with_utls` full race | PASS |
| Default checkptr | ON / PASS |

This checkpoint precedes the subsequent Snell migration and is not the final
Round 2 gate. The initial module metadata failure remains external evidence:
netlink's old Go graph required an additional x/sys v0.10.0 **go.mod checksum**.
Verified cached metadata and `go list -mod=mod` resolved it; selected x/sys stays
v0.47.0, Go requirement unchanged, no bulk dependency upgrade.

| Stage | SagerNet source imports | Full graph modules |
| --- | ---: | ---: |
| Round 1 start/end | 2,407 | 55 |
| Round 2 foundation checkpoint (1,505 Go files) | 2,354 | 55 |

Old local module imports remain 0. Foundation elimination is not the final
graph cleanup: inherited trees still keep dependencies reachable.

## Snell implementation underway

External `SNELL_WIRE_SPEC_NOTES.md` records the researched v4/v5/v6 contract,
PSK recipe arithmetic, per-direction ownership, commands, EOF and server reuse.
New `protocol/snell/wire` uses standard AES-GCM and x/crypto Argon2id/BLAKE2b;
immutable table-based v6 recipe and owned record/tunnel/packet state. Managed
Snell server/client now use protected sockets directly, without box/router
constructors. Original profile validation and version mapping remain.

Owned record bounds/negative cases, 10 sequential requests over one transport,
half-close response, pending-read concurrent UDP write and 128 Close/read/write
ownership cycles pass race/checkptr. Full native package tests pass. The
external pinned-reference byte differential and binary interop gates remain
in progress; no Snell replacement acceptance is asserted yet.

## Remaining hard gates

Complete Snell differential/interop; independent HY2/TUIC and VLESS/REALITY
migrations; inherited source and module graph removal to zero; full final
interop/mutation fuzz/TUN25/10-minute mixed stress/resource/underlay/build/binary
and license/secret audits. Historical qualification remains PARTIALLY PASSED,
current qualification NOT RE-RUN, all historical evidence preserved.

**PHASE 17 NOT READY FOR REVIEW**

---

# Round 2 / Final Implementation — accepted local development gates

## Verdict

**PHASE 17 READY FOR REVIEW**

This final section supersedes the earlier in-progress verdicts and blockers.
Their failed attempts, original text and external evidence remain preserved.
Review, Freeze and publication have not been performed.

Evidence root: D:/splicore-validation/phase17-core-decoupling-20261006/.
Final summary: round2-final-audit-attempt2/summary.json.
The older final-audit/summary.json remains the Round 1 record.

## Starting State

Continued the authorized Phase 16/17 unstaged worktree on
codex/phase-16-native-shadowsocks, HEAD
b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c. Index remained EMPTY.
The start had 2,407 SagerNet imports and 55 SagerNet graph modules.

## Preservation Evidence

round2-prestate preserves the full pre-round archive/patch, 2,112 hash-verified
members, go.mod/go.sum and imports/module/product closure inventories.
Phase 16 preservation and all previous failed probes remain intact.
The final outside-repository archive, file hashes, diff, file lists and gate
hashes are under round2-final-audit-attempt2. No stash/reset/restore was used.

## Module Identity

module github.com/ike-sh/Splicore; minimum Go 1.26.3 unchanged.
Verification used preinstalled Go 1.26.6, GOTOOLCHAIN=local, default checkptr.
Toolchain records accompany Linux builds/tests and Windows safe tests.
Qualification was not used to download or silently switch a toolchain.

## SagerNet Import Reduction

| Stage | Imports |
| --- | ---: |
| Round 2 start | 2407 |
| Foundation checkpoint, 1505 Go files | 2354 |
| Final, all tags, 421 current Go files | 0 |

Go AST ImportsOnly counts production=0, tests=0, tooling=0, old local
github.com/sagernet/sing-box imports=0. This counts imports, not historical
copyright or client export format names. The final AST inventory is
round2-source-imports-final.json.

Actual SAGERNet_IMPORT_ROOT_MAP has 63 dependency families; the local DAG has
152 edges. Its JSON/Markdown preserves import sites, packages, product surfaces
and leaf-first dispositions. Live leaves were migrated first; inherited router
and unsupported feature roots were removed after their product closure ceased
to need them. Foundation declarations are small owned APIs, not a utility clone.

## SagerNet Module Graph

| Stage | Modules |
| --- | ---: |
| Start | 55 |
| Foundation checkpoint; inherited roots still present | 55 |
| After runtime migration, dead-root removal and tidy | 0 |
| Final full graph | 0 |

Direct requirements=0; go.sum references=0; full module graph nodes=0.
No replacement pulls SagerNet transitively. Final Linux production/test closure
has 694 packages, Windows has 697; both contain zero SagerNet packages and zero
production imports of testfixture/testkit. Graph-only metadata nodes missing
from the offline cache are identified separately from linked code.

## Dependency Families Removed

1118 inherited Go/proto files outside audited Linux/Windows product and test
closure were retired, together with the obsolete nested test module.
Removed surfaces include old box/router/control runtime, unsupported protocols,
mobile/AI packaging, unused transports and inherited platform frameworks.
39 additional dead workflow/packaging/helper files have a dedicated manifest.
Supported product tests remain; moved tests retain their behavior assertions.
Foundation/Phase2/Phase3/Phase4 composition helpers remain for historical
product regression tests. NativeCore contains the current owned protocol
modules, rather than inherited unsupported feature registrations.

## Replacement Foundations

### Network

Use net.Conn/net.PacketConn/net.Listener and the existing owned ports/underlay.
clientio tracks pending dials, cancellation and sockets; relay joins both
directions and preserves half-close. packetio uses bounded copied-byte queues
and direction locks. QUIC receives protected packet sockets.

### Address

domain/access.Endpoint plus net/netip owns semantic destinations.
The shared SOCKS address codec bounds IPv4/IPv6/domain/port.
Snell, VLESS and QUIC protocols retain their distinct wire codecs.
Numeric IPv6 domain literals are normalized; failing mutation seeds remain.

### Buffer

Caller-owned byte slices, fresh decoded datagrams and immutable prefix
snapshots replace upstream mutable caches. No cross-flow scratch buffer or
early pool return is introduced. Read owns its prefix even when the supplied
source buffer is cleared and concurrent Close occurs. Mutable cipher/frame
state belongs to a connection and direction.

### Logging

Owned application logging and existing error boundaries remain; upstream
logger interfaces are gone. Small neterror mappings use standard errors.
This migration does not redesign product log formatting.

### Task/Context

Use context, sync, atomic and the existing joined generation/session owners.
No general service locator or upstream task utility hierarchy is cloned.

### DNS

The owned DNS/routing engine uses miekg/dns and standard TLS with protected
sockets. Response-ID filtering, truncated UDP fallback to TCP, bootstrap
protection and detour selection have regression coverage.
Inherited sing-box DNS control logic is removed.

### QUIC

TUIC composes independent quic-go; HY2 composes official AperNet QUIC/HTTP3.
Owned boundaries cover TLS, streams, datagrams, cancellation, deadlines,
authentication and close. No QUIC primitive or TCP/IP stack is implemented.

### TUN

The existing owned Native TUN lifecycle, device/session/route ownership and
official gvisor.dev/gvisor remain. Independent netlink, x/sys and Windows
components replace remaining framework utilities. There is one gVisor.
WinDivert64.sys and its existing license remain byte-identical to HEAD.

## Protocol Layout

- internal/splicore/protocol/address and socks: owned bounded shared codecs.
- internal/splicore/protocol/shadowsocks/wire: classic AEAD and SS2022.
- protocol/snell/wire: owned versioned handshake, record, command and packet wire.
- protocol/hysteria2/{wire,backend}: owned HY2 wire/lifecycle over independent QUIC.
- protocol/tuic/{wire,backend}: owned TUIC v5 over independent quic-go.
- protocol/vless/{wire,backend}: owned plain/TLS/REALITY integration.
- protocol/mieru/{module,backend}: owned SDK boundary and registration.
- internal/splicore/engine/native: current managed server/client adapter composition.

## Mieru

protocol/mieru owns Compiler and OutboundFactory registration.
Config/credential mapping, SDK construction, lifecycle, payload attribution
and errors stay in backend. enfein/mieru types do not enter domain/API/CLI/SQLite.
Official Mieru 3.38.0 and pinned Mihomo: 24 rows PASS with TCP/UDP underlays,
two identities and IPv4/IPv6/domain endpoints; auth negatives, binding isolation,
SQLite recovery, stats, listener release and secret gates PASS.

## Shadowsocks Classic

Owned canonical AEAD composition uses standard AES-GCM / x/crypto ChaCha20,
HKDF, fresh salts, directional nonce state, bounded records and replay checks.
TCP and UDP framing/address codecs are independent of sing-shadowsocks.

## Shadowsocks 2022

Owned SS2022 composition retains PSK validation, identity/multi-user handling,
TCP headers/body, UDP session/timestamp/replay/padding and nonce bounds.
BLAKE3 is a mature independent primitive; no cryptographic primitive is written.
Implementation/reference differential and malformed-input regressions remain.

### METHOD_PARITY_BEFORE_AFTER

| Method (present before and after) | Server TCP | Server UDP | Client TCP | Client UDP |
| --- | --- | --- | --- | --- |
| aes-128-gcm | PASS | PASS | PASS | PASS |
| aes-256-gcm | PASS | PASS | PASS | PASS |
| chacha20-ietf-poly1305 | PASS | PASS | PASS | PASS |
| 2022-blake3-aes-128-gcm | PASS | PASS | PASS | PASS |
| 2022-blake3-aes-256-gcm | PASS | PASS | PASS | PASS |
| 2022-blake3-chacha20-poly1305 | PASS | PASS | PASS | PASS |

All original 28 SS/SS2022 both-role sing-box/Mihomo interoperability rows pass
with the owned runtime; no Phase 16 method is removed.

## Snell

Snell v6: **RESTORED AND ACCEPTED** in the owned implementation.
Server v5/v6 and client v4/v6 remain. SNELL_WIRE_SPEC_NOTES.md records version
contracts, PSK recipe, encryption, commands, stream/UDP and EOF behavior.
960 complete byte comparisons over 96 PSKs and five payload sizes match pinned
reference behavior; eight both-role reference rows pass.
The final race binary passes nine CLI/API traffic rows and ten expected rejects,
large payload/concurrency/reconnect/restart/statistics/shutdown.
OpenSnell's refusal of v6 remains a rejected candidate finding, now resolved by
the owned wire, rather than used as a capability downgrade.

## Hysteria2

Own bounded request/response/datagram frames, immutable authentication,
fragment assembly and joined directional workers. Official SDK both roles and
12 external CLI/API rows PASS; datagram fragmentation and negative trust/auth
checks are covered. Lazy transports are per flow and receive protected sockets.
The substrate uses default CUBIC; the inherited runtime used BBR.
Managed settings expose neither. Application capability and wire interoperability
are preserved; identical congestion/performance behavior is **not claimed**.
Official SDK's 4096-byte send buffer includes framing. Its reference payload is
4000 bytes; owned 4096-byte payload coverage remains.

## TUIC

Owned v5 authentication, TLS exporter token, TCP stream and native UDP datagram
framing preserve the managed cubic/native/0-RTT-disabled profile.
Fragmentation, packet ownership, close/cancel/deadline and account attribution
regressions pass. External server-side matrix: 12 rows PASS.
Owned clients to pinned reference servers pass TCP/UDP for both users.

## VLESS

Plain/TLS/REALITY use owned request/XUDP framing and protected target dialing.
Immutable UUID/account state and bounded payloads replace upstream abstractions.
REALITY composes the independent TLS implementation and standard X25519;
certificate verification uses supplied DER without reflection/private pointers.
External matrices: plain 4, TLS 4, REALITY 12 rows PASS with trust/auth negatives,
two users, IPv4/IPv6/domain, concurrency, 4 MiB and restart/cleanup/statistics.
Native clients to reference plain/TLS/REALITY servers pass for both users.
Vision remains Deferred/Unsupported. No new specialized mode is introduced.

## Dependency Table

| Removed SagerNet module | Pinned old version | Replacement / disposition | Status |
| --- | --- | --- | --- |
| github.com/sagernet/bbolt | v0.0.0-20260823094646-e24805439c9c | existing owned SQLite persistence; inherited state owner retired | REMOVED |
| github.com/sagernet/cors | v1.2.1 | owned local HTTP API; inherited HTTP service retired | REMOVED |
| github.com/sagernet/cronet-go | v0.0.0-20260912104727-0d28acc44093 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/all | v0.0.0-20260912104727-0d28acc44093 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/android_386 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/android_amd64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/android_arm | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/android_arm64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/darwin_amd64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/darwin_arm64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/ios_amd64_simulator | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/ios_arm64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/ios_arm64_simulator | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_386 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_386_musl | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_amd64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_amd64_musl | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_arm | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_arm64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_arm64_musl | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_arm_musl | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_loong64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_loong64_musl | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_mips64le | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_mipsle | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_mipsle_musl | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_riscv64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/linux_riscv64_musl | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/tvos_amd64_simulator | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/tvos_arm64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/tvos_arm64_simulator | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/windows_amd64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/cronet-go/lib/windows_arm64 | v0.0.0-20260912104006-c10c03c318db | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/fswatch | v0.1.2 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/gliderssh | v0.3.4-0.20260531100337-2194faca5648 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/gvisor | v0.0.0-20260727.0-sing-box-mod.1 | gvisor.dev/gvisor (one official implementation) | REMOVED |
| github.com/sagernet/netlink | v0.0.0-20260814022025-64455d367bbf | vishvananda/netlink v1.3.1 + owned SO_MARK protection | REMOVED |
| github.com/sagernet/nftables | v0.3.0-mod.4 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/quic-go | v0.61.0-sing-box-mod.7 | independent quic-go / official AperNet QUIC fork | REMOVED |
| github.com/sagernet/sing | v0.9.4 | stdlib + owned endpoint/traffic/clientio/packetio/relay contracts | REMOVED |
| github.com/sagernet/sing-mux | v0.3.6 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/sing-openconnect | v0.0.0-20260810065514-53aa8058f8df | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/sing-openvpn | v0.0.0-20260729104525-103eb5fe5eb6 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/sing-quic | v0.7.0 | owned HY2/TUIC wire and backend; independent QUIC substrates | REMOVED |
| github.com/sagernet/sing-shadowsocks | v0.2.8 | owned classic AEAD wire and native adapters | REMOVED |
| github.com/sagernet/sing-shadowsocks2 | v0.2.1 | owned SS2022 wire and native adapters | REMOVED |
| github.com/sagernet/sing-shadowtls | v0.2.1 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/sing-snell | v0.0.0-20260829071736-20f2eaec77c3 | owned Snell v4/v5/v6 wire and native adapters | REMOVED |
| github.com/sagernet/sing-tun | v0.9.3 | owned Native TUN device/hostnetwork + official gVisor | REMOVED |
| github.com/sagernet/sing-usbip | v0.0.0-20260817040617-28bd42667eca | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/sing-vmess | v0.2.8 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/smux | v1.5.50-sing-box-mod.1 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/tailscale | v1.102.1-sing-box-1.14-mod.5 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/wireguard-go | v0.0.6 | Retired inherited nonproduct closure; no replacement required | REMOVED |
| github.com/sagernet/ws | v0.0.0-20231204124109-acfe8907c854 | Retired inherited nonproduct closure; no replacement required | REMOVED |

Independent selected versions and rationale:

| Module | Version | Purpose / why stdlib insufficient | License evidence |
| --- | --- | --- | --- |
| miekg/dns | v1.1.72 | DNS wire, resource records and transport framing beyond net.Resolver | BSD license copied |
| vishvananda/netlink | v1.3.1 | Linux route/rule netlink encoding; stdlib lacks this API | Apache 2.0 copied |
| quic-go/quic-go | v0.63.0 | Mature QUIC streams/datagrams; stdlib has no QUIC | MIT copied |
| apernet/quic-go | v0.63.1-0.20261004180939-a10df75c260c | Official independent HY2-compatible QUIC/HTTP3 substrate | MIT copied |
| enfein/mieru/v3 | v3.38.0, retained | Official Mieru implementation; no wire rewrite | GPLv3 text and source notices retained |
| metacubex/utls | v1.8.7, retained | Required REALITY handshake API absent from crypto/tls | Copied license/copyright |
| gvisor.dev/gvisor | v0.0.0-20261004063249-f57b8fc79db4, retained | Official userspace TCP/IP stack | Copied license/notices |
| lukechampine.com/blake3 | v1.3.0, retained | SS2022 cryptographic primitive absent from stdlib | Copied license/copyright |
| golang.zx2c4.com/wintun | v0.0.0-20230126152724-0fa3db229ce2 | Windows driver API absent from stdlib | Copied license/copyright |

No go get -u, independent bulk upgrade, module-cache patch or upstream clone.
The complete selected version/license inventory is THIRD_PARTY_NOTICES.md.

## Interoperability

| Campaign | Actual traffic result |
| --- | --- |
| SS/SS2022 both roles, sing-box + Mihomo | 28 rows PASS |
| Snell differential and both-role reference | 960 comparisons / 8 rows PASS |
| Snell final managed race binary | 9 rows / 10 expected rejects PASS |
| HY2 official SDK, both roles | PASS |
| HY2 managed binary, external clients | 12 rows PASS |
| TUIC managed binary, external clients | 12 rows PASS |
| VLESS plain / TLS / REALITY | 4 / 4 / 12 rows PASS |
| TUIC + VLESS native clients to pinned servers | 8 rows PASS |
| Mieru official + Mihomo | 24 rows PASS |

Pinned reference binaries run only as outside-repository local test peers.
The unified final campaign uses one zero-SagerNet race artifact:
9c7d5793f1decc32f607be249f0dbdb5d8bab04ea0d36a12e531e3332d91cdd9.
It also runs the SS/Mieru ecosystem gates. Client-role and official SDK
campaigns are separate pinned evidence.

round2-interop-final-audit contains accepted copies from the actual per-campaign
result paths, with original path/result/log hashes. The first unified invocation
ran a library without calling its HY2/TUIC entry points: exit 0 and empty logs
were rejected, despite its erroneous PASS banner. The corrected wrappers
produced real traffic. Shared-root snapshots copied by that runner can contain
old campaigns; those stale snapshots are not acceptance evidence.
Later provenance strings and the worker-name test correction have no wire change;
fresh final three-platform builds/full race and the targeted lifecycle test pass.

## Fuzz

| Entry / accepted log | Requested mutation | Actual command duration | Executions | Accepted crashes |
| --- | ---: | ---: | ---: | ---: |
| round2-final-verification/fuzz-uri-attempt2.log | 20s | 21.653s | 208034 | 0 |
| round2-final-verification/fuzz-ShadowsocksClassicTCPFrame.log | 20s | 20.119s | 229655 | 0 |
| round2-final-verification/fuzz-ShadowsocksClassicUDPDatagram.log | 20s | 20.248s | 363012 | 0 |
| round2-final-verification/fuzz-Shadowsocks2022TCPFrame.log | 20s | 20.141s | 281029 | 0 |
| round2-final-verification/fuzz-Shadowsocks2022UDPDatagram.log | 20s | 20.112s | 437316 | 0 |
| round2-final-verification/fuzz-shared-address-attempt2.log | 20s | 21.031s | 767397 | 0 |
| round2-final-verification/fuzz-ss-address-attempt2.log | 20s | 20.084s | 543465 | 0 |
| round2-final-verification/fuzz-tcp-classic-and-2022-attempt2.log | 20s | 20.924s | 482670 | 0 |
| round2-final-verification/fuzz-udp-classic-and-2022-attempt2.log | 20s | 21.515s | 469669 | 0 |
| round2-final-verification/fuzz-tuic-attempt2.log | 20s | 23.706s | 545223 | 0 |
| snell-stage/fuzz-command-datagram.log | 20s | 21.211s | 988193 | 0 |
| snell-stage/fuzz-record.log | 20s | 21.035s | 129620 | 0 |
| hysteria2-stage/fuzz-wire.log | 20s | 20.098s | 1006865 | 0 |
| vless-stage/fuzz-wire-attempt2.log | 20s | 23.421s | 652467 | 0 |

Every entry ran actual mutation, not just corpus replay. Mutation target was
20 seconds; command durations include corpus/setup/shutdown overhead and are
taken from each accepted log. The fuzz progress lines retain observed mutation
duration/execution counts. Earlier discovered failures are not erased:
numeric IPv6 domain canonicalization seeds remain in shared address, Snell,
VLESS and TUIC regression corpora. Accepted reruns have zero crashes.
Combined classic/2022 fuzz remains, with separate classic and 2022 entry points.

## Race / Checkptr

| Gate | Result |
| --- | --- |
| Default go test -race ./... | PASS |
| Full native with_gvisor,with_quic,with_utls race | PASS |
| Shared foundations, adapters and protocol packages race | PASS |
| Owned prefix Read/Close ownership reproducer x10 | PASS |
| All address corpus/wire regressions x10 | PASS |
| Updated current-backend worker lifecycle test | PASS |
| Windows safe native-tag full tests | PASS, non-race |
| Default checkptr | ON / PASS |

No official runtime/cache file was patched. The old inherited mutable lookahead
cache boundary was retired after a transitional ownership repro; current prefix
copies caller bytes and Read owns its state. Close does not reclaim that prefix.
Atomic counters and narrow per-direction locks guard owned mutable state.
No checker disable, panic recovery, skipped acceptance, sleep or payload retry
is used to mask defects. Windows race is not claimed without its local CGO
prerequisites.

## Native TUN x25

PASS: 25 actual TUN start/traffic/policy/stop cycles inside disposable Linux
mount/network namespaces, including all seven protocol families, IPv4/IPv6,
TCP/UDP and proxied DNS. Test duration 1238.30 seconds.
Every stopped cycle: goroutines 27, FDs 22, eventfd 1, listeners 6, sessions 0,
generations 1, leases 1, host generations/interfaces/journal temporaries 0.
FD delta=0; eventfd delta=0; goroutines stable.
Snell has no binding mutation API; no unsupported mutation is invented.
Its joined client generation/flow release is checked directly.
The disabled manager intentionally owns the remaining generation and lease.

## Mixed Stress

PASS: 10m28.570790904s, from a new local run; 15 rounds including warmup,
errors=0. Each offered round covers SS, SS2022, Snell, HY2, TUIC, VLESS and Mieru,
IPv4/IPv6 TCP/UDP, DNS, selector routing/policy updates and actual Native TUN.
No failed I/O is retried. Final direct target DNS leak counters: TCP=0, UDP=0.
Namespace test exit=0; peer and namespace workers are joined/removed.
The target records real TCP and UDP traffic, not just successful process startup.
This is Phase 17 development stress, not the historical 60-minute qualification.

## Resource Stability

### TUN x25 start / observed peak / end

| Metric | Start | Observed peak | End / stopped |
| --- | ---: | ---: | ---: |
| Goroutines | 27 | 158 | 27 |
| FDs | 22 | 55 | 22 |
| EventFDs | 1 | 1 | 1 |
| Listeners | 6 | 6 | 6 |
| Sessions | 0 | 14 | 0 |
| TCPActive | 0 | 0 | 0 |
| UDPActive | 0 | 8 | 0 |
| TCPTotal | 3 | 96 | 78 |
| UDPTotal | 2 | 64 | 52 |
| Generations | 1 | 7 | 1 |
| Leases | 1 | 7 | 1 |
| RSSKiB | 143896 | 224420 | 221140 |

### Mixed stress start / observed peak / stopped

| Metric | Start | Observed peak | End / stopped |
| --- | ---: | ---: | ---: |
| Goroutines | 27 | 380 | 27 |
| FDs | 22 | 107 | 22 |
| EventFDs | 1 | 1 | 1 |
| Listeners | 6 | 6 | 6 |
| Sessions | 0 | 38 | 0 |
| TCPActive | 0 | 0 | 0 |
| UDPActive | 0 | 20 | 0 |
| TCPTotal | 3 | 297 | 45 |
| UDPTotal | 2 | 198 | 30 |
| Generations | 1 | 19 | 1 |
| Leases | 1 | 19 | 1 |
| RSSKiB | 217028 | 343108 | 329180 |

These are sampled maxima at workload boundaries, not continuously measured
instantaneous maxima. Short-lived TCP flows finish before snapshots, hence
TCPActive observed peak=0; successful TCP traffic and TCPTotal are measured.
SocketFDs/HostGenerations/Interfaces in the inherited peak helper are not true
peak measurements and are omitted from the peak table. Their stopped values
are directly read: SocketFDs=11, HostGenerations=0, Interfaces=0, temporaries=0.
TCPTotal/UDPTotal reset on runtime/binding reconstruction; they are not global
traffic totals. RSS ends above start and is reported without claiming a
long-duration memory plateau. No production diagnostics were added.
Stopped goroutines/FDs/eventfd/listeners/generations/leases return to baseline,
with zero active server sessions; a long-soak qualification leak verdict is
outside this run.

## Routing / DNS / Policy

Complete default/native and shared regression suites PASS, including selector
generation leases, DNS ID/fallback/caching/bootstrap, TCP/UDP routing,
quota/session/speed behavior and protected underlay purposes.
IPv4 preference for an IPv4-only localhost proxy was corrected after a real
application failure; that exact failure and final application suites pass.

## API / CLI

Full API, CLI, account, credential, binding, plan/apply/export and shared-service
regressions PASS. External matrices also exercise the managed API/CLI runtime.
Doctor/support bundle and diagnostic secret-redaction regressions PASS.

## Backup / Restore

Owned SQLite backup/restore, crash/WAL and protocol credential regressions PASS.
Product tests were preserved rather than replaced with implementation-only
checks. Mieru and other managed interop campaigns verify persisted recovery.

## Provider / RuleSet

Full provider/ruleset/routing regression suites PASS.
Pinned numeric destinations, redirect/DNS policies, snapshot endpoint leases
and protected bootstrap/provider fetch remain owned. No ambient bypass
constructor is introduced.

## Distribution

| Platform | Build / identity / license coverage | SHA256 |
| --- | --- | --- |
| linux-amd64 | PASS | 07e00b9c956bfbbd61a47b5cbe7b218f8f07123cd49e91be5c7ba346009a006c |
| windows-amd64 | PASS | 5ec2a14a0d013720fcbdeb62bf497242ba357032e2db240a71d73b18c839caf8 |
| linux-arm64 | PASS | 078e9f51a1d0ab3ae3effb48dfa44576fbc06f6ff44646f1f2493f34c590c3c7 |

Linux amd64, Windows amd64 and Linux arm64 native-tag build PASS.
Windows safe full tests PASS; live Windows host-network mutation is not run.
Linux arm64 is BUILD ONLY / runtime NOT CERTIFIED.
Retired publication/mobile packaging no longer references inherited commands.
Remaining distribution build tags are with_gvisor,with_quic,with_utls.
Old GODEBUG/checklinkname linker overrides were removed.

## Binary Identity

All three final go version -m inventories identify main module
github.com/ike-sh/Splicore, SagerNet dependencies=0, Xray dependencies=0.
go tool nm: active sagernet/sing-box package paths=0.
All linked selected module versions match the preserved third-party licenses.
Hashes above refer to final release-style builds; interop race artifact identity
is recorded separately.

## Underlay

Unknown=0; 71 production construction/delegation surfaces and 133 test surfaces.
Final-complete inventory covers dial/listen/packet/DNS/health/provider and the
new root protocol backends, protected QUIC packet injection, REALITY target,
Mieru hooks and native relay paths. This reviewed source guard is supplemented
by constructor invariants, race tests and actual isolated TUN/DNS leak evidence.

## Xray Boundary

E=0; F=0; G=10.
Historical references, research/test oracles, intentional rejection and
ordinary client config export are classified separately. No Xray or sing-box
production subprocess or runtime dependency remains.
Production os/exec sites are owned service install/recovery/diagnostics calls
(systemctl/useradd/journalctl/Splicore recovery), not proxy cores.
Final source text audit excludes prohibited NoBrand paths and reports that scope.

## License / Attribution

Root LICENSE unchanged:
650d5e3b99a446fb38e820fa87a49562e0c79eab868fff58618ac487a58e554c.
NOTICE and required inherited copyrights remain.
69 locally materialized selected modules / 95 verbatim license, NOTICE and
AUTHORS texts are copied and hash verified; three linked binary inventories
have full notice coverage. go mod verify: all modules verified.
Graph-only non-linked modules are listed separately, not described as bundled
code. Independent module notices supplement the retained derivative GPL terms.
WinDivert64.sys SHA256 unchanged:
8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2.

## go.mod

module github.com/ike-sh/Splicore; go 1.26.3.
github.com/sagernet/* direct/indirect requirements=0.
Selected official gVisor only; no second SagerNet gVisor.
Final source migration precedes tidy; no broad dependency upgrade.

## go.sum / graph

github.com/sagernet/* checksum references=0; graph modules=0.
The netlink legacy x/sys go.mod checksum did not change selected x/sys v0.47.0.
Final complete module graph and go mod verify logs are preserved.

## Files Added

189 files versus unchanged HEAD, including prior Phase 16 work, owned
wire/backend/foundations, replacement regressions, preserved fuzz corpora and
third-party notices. Full list: round2-final-audit-attempt2/files-added.txt.

## Files Modified

304 files versus HEAD. Full list:
round2-final-audit-attempt2/files-modified.txt.
Includes identity imports, owned adapter composition, DNS/platform glue,
underlay audit, protocol metadata, packaging and documentation.

## Files Removed

1199 files versus HEAD. Full list:
round2-final-audit-attempt2/files-removed.txt.
Closure/removal manifests separate retired inherited source, tooling and
packaging from moved retained product tests.

## Findings

- DEC17-008: retired inherited mutable cache ownership after Read/Close repro;
  current immutable prefix and x10/default race/checkptr pass.
- DEC17-009: rejected OpenSnell v6 candidate; owned differential/interop restores
  required v6 and resolves DEC17-005.
- DEC17-010: owned HY2/TUIC/VLESS and Mieru boundary replace remaining live roots;
  unsupported inherited closure retirement removes imports/graph to zero.
- DEC17-011: numeric IPv6 parser mutations found noncanonical semantic roundtrip;
  normalize parsed IP and preserve all failing seeds and accepted mutations.
- DEC17-012: official HY2 SDK 4096 framing limit; oracle adjusted to supported
  payload with owned 4096 coverage retained. CUBIC/BBR difference disclosed.
- DEC17-013: discarded first unified interop PASS due to empty HY2/TUIC logs;
  corrected entry points and audited actual nested result paths supply acceptance.
- DEC17-014: initial lab attempted unsupported Snell binding mutation; failed
  attempt retained, test now checks supported joined lifetime without that call.
- DEC17-015: current worker-name leak assertion replaces deleted upstream name.
- DEC17-016: offline metadata enumeration and Windows GBK aggregation failures
  are retained. Cached code builds passed; final UTF-8 aggregate and -e metadata
  enumeration succeed without toolchain/dependency policy changes.
- DEC17-017: boundary filename enumeration and owned fixture reads are disclosed
  below. External NoBrand system/repository was not accessed.
- DEC17-018: resource peak sampling scope is explicit; stopped ownership return
  passes. No continuous TCP peak, congestion equivalence, long memory plateau
  or native host qualification is inferred.
- Earlier native-race run encountering a newly arriving address corpus, VLESS
  stats optional zero counter omission, IPv4 localhost preference and client-role
  feature-profile fixture failures remain in original attempt directories.
  They were corrected concretely; successful repetitions do not erase them.

## Platform Qualification

Historical candidate b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c:
PARTIALLY PASSED. Current qualification: NOT RE-RUN.
GAP-01 long-soak goroutine stability NOT MEASURED; GAP-02 safe Windows destructive
target unavailable; GAP-03 native Ubuntu host-network target unavailable;
GAP-04 Linux arm64 BUILD ONLY / runtime NOT CERTIFIED. These gaps remain OPEN.
The 10-minute development test does not reclassify historical GAP-01.

Canonical report is unchanged at
D:/splicore-validation/platform-requalification-20261005/PLATFORM_REQUALIFICATION_FINAL_REPORT.md:
18065f3ca3c5f34f5ac8d8e0d52b34a80218f7a6f4ab418f256467c80996bba7.

## Public GitHub

UNCHANGED. No remote/public snapshot action, release, tag or publication.

## NoBrand

External project/repository/system: NOT ACCESSED.
Boundary incidents prevent an unqualified blanket claim: an earlier broad
filename enumeration returned outside NoBrand paths; contents were not opened.
A later repository source scan read three existing owned Splicore
tests/fixtures/nobrand JSON texts, not the external NoBrand project.
Those historical scans remain evidence; final broad scans and snapshot exclude
NoBrand paths and record exclusions. No NoBrand configuration/system is changed.

## Secret Scan

real=0; unresolved=0 within the final declared scanned source scope.
All candidates have redacted classifications: schema/import/error/dynamic
credential access, synthetic local test input, variable references or historical
documentation. The three expanded-pattern hits are owned negative-test URLs or
an example.org local fixture, not operational secrets.
NoBrand paths are excluded; this is not a claim to have audited that project.
Original pending-candidate evidence is preserved; the final reviewed inventory
supersedes it. Interop diagnostic/log/argv/database secret gates also pass.

## Git State

HEAD: b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c.
Branch: codex/phase-16-native-shadowsocks.
Changes: DIRTY / UNSTAGED. Index: EMPTY.

staged: NO; committed: NO; pushed: NO; tagged: NO; released: NO;
frozen: NO; Review performed: NO.

## Blockers

NONE for the requested Phase 17 development review gates.
The explicitly recorded historical qualification gaps and measurement/performance
limits remain; this verdict does not imply certification or Freeze.

**PHASE 17 READY FOR REVIEW**


# Review Fix Round 1

Date: 2026-10-06. Verdict: **PHASE 17 READY FOR RE-REVIEW**.

The independent review verdict was **PHASE 17 REVIEW FAILED**, with R17-001 MAJOR and R17-002/R17-003 MINOR. That report and all original failing evidence are preserved at `D:/splicore-validation/phase17-review-20261006/PHASE17_REVIEW_REPORT.md`. This append retains the preceding implementation history; it does not declare Review Passed or Freeze.

- R17-001: Queue admission and active writes now observe Close and live deadlines. VLESS uses one parent-owned writer, zero buffered queue entries and at most one immutable in-flight frame; child cancellation releases association/caller state without closing siblings. Parent shutdown interrupts and joins retained work. TUIC independent uni streams honor request cancellation and stream-credit waits. Original unchanged reproducer x100 and targeted race x25 PASS; sibling isolation, deadline reset/clear, concurrent Close, ordering, caller scratch reuse, parent join and resource baselines PASS.
- R17-002: HY2 length uses crypto/rand.Int, content uses rejection sampling below 248 into the same 62-character alphabet, with production crypto/rand.Reader and error propagation/fail-closed authentication. Original half-open ranges preserved; bounds, bias rejection and RNG errors tested. HY2 production math/rand=0.
- R17-003: canonical HY2 docs now describe owned application framing/lifetimes over independent AperNet QUIC/HTTP3. **Correction to earlier CUBIC statements in this report:** pinned NewCubicSender is constructed with `reno=true` (including path reset), so current HY2 uses Reno mode, not active CUBIC or BBR. No public HY2 CC selector exists; existing strict settings/URI/external-import guards reject unsupported CC fields, verified by regression tests with production importer unchanged. No configuration breaking change. Resource sampling limits remain explicit.

Default/full default race/native race/shared race PASS; default checkptr ON. Original QF-001 ownership x10 and QF-002 lifecycle PASS; 14 mutation fuzz targets ×20s PASS. VLESS plain/TLS/REALITY and all packet/runtime consumers PASS.

Fresh isolated real TUN x25 PASS: goroutines 27→27, FD 22→22, eventfd 1→1; stopped sessions/associations zero. Fresh mixed stress 10m27.595074062s, 15 rounds including warmup, errors=0, all seven families TCP/UDP/DNS/routing/policy/Native TUN; HY2 padding paths exercised. Workload-boundary snapshots are sampled observations, not continuous maxima or CC telemetry.

Linux amd64/arm64 and Windows amd64 builds PASS. Windows full safe suite PASS with external bounded loopback port guard for existing TCP-only fixture selection versus UDP exclusions; initial failure log and all guard cleanup evidence preserved. No Windows host network mutation or destructive qualification. SagerNet source/direct/graph/binary=0/0/0/0. Underlay Unknown=0; secrets real=0/unresolved=0. go.mod/go.sum, root LICENSE, WinDivert asset, upstream runtime files and historical canonical qualification report unchanged.

Evidence and complete fix report: `D:/splicore-validation/phase17-review-fix1-20261006/PHASE17_REVIEW_FIX_ROUND1_REPORT.md`; structured summary: `summary.json`; exact scope: `final-fix-scope-audit.json`.

HEAD remains `b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c`, branch `codex/phase-16-native-shadowsocks`, working tree DIRTY/UNSTAGED, index EMPTY. stage/commit/push/tag/release/freeze: NO. Public GitHub UNCHANGED; NoBrand NOT ACCESSED. Historical qualification remains PARTIALLY PASSED; current development validation does not close any qualification gap. No next phase started.


# Independent Re-Review — Failed

Date: 2026-10-06. Verdict: **PHASE 17 RE-REVIEW FAILED**. Canonical evidence: `D:/splicore-validation/phase17-rereview-20261006/PHASE17_REREVIEW_REPORT.md`. VLESS's original200 cases passed, but actual TUIC and HY2 contextless datagram queue saturation each failed30/30 child-close/live-deadline cases (RR17-001/RR17-002). R17-002/R17-003 remained CLOSED. Original review, Fix1 and this re-review history and evidence remain intact.

# Review Fix Round 2

Date: 2026-10-06. Verdict: **PHASE 17 READY FOR RE-REVIEW**.

R17-001, RR17-001 and RR17-002: **FIXED — PENDING RE-REVIEW**. R17-002/R17-003: CLOSED / unchanged. Independent re-review still decides closure.

Child packet write admission/completion now share packetio.Queue's cancellation/live-deadline contract. TUIC/HY2 use one unbuffered parent-owned writer with copied frames and explicit parent shutdown join. At handoff one physical operation commits; child cancellation releases caller state, and the parent owns that one frame until completion/close. No dead buffered requests, per-write workers, capacity increase, polling, retry, recovery, global data-path lock or upstream patch.

The expanded audit also reproduced the same lifecycle family in SS/SS2022 shared reply writes, Snell's first-write handshake read and the Mieru SDK deadline-snapshot adapter boundary. SS listener owns one cancellable-handoff writer; Snell constructor owns its existing reply read under the handshake deadline; Mieru's local adapter owns write Queue/session worker and registers its complete joined lifetime with clientio.Owner. Codec/settings/wire behavior unchanged; no upstream Mieru modifications. A VLESS test now uses a valid address while parent cancellation propagates, retaining its closed-error assertion. Every failed/intermediate validation campaign is preserved and explained in the external full report.

Final-code unchanged original TUIC/HY2 x100 (300 cases each) and VLESS x100 (200 cases): PASS. New real QUIC six-case lifecycle + same-parent sibling/reopen x100 (1200 cases): PASS. Targeted lifecycle race x25, three-way25000 cycles, Mieru adapter10000 cycles, full default/default-race/native-race/shared-race, QF001 x10 and native QF002: PASS. Default checkptr ON.14 mutation fuzz targets x20s, fresh local interop for all seven families, three-platform builds and Windows safe suite: PASS.

Fresh final isolated TUN25: PASS; goroutines29→29, FD22→22, eventfd1→1, stopped sessions0. Two listener-owned SS workers explain the service baseline27→29. Final mixed TUN stress 10m23.669812217s plus concurrent real datagram pressure 12m0.26592144s, 23640 pressure cases, 19700 same-parent association reopens, expected cancel/timeout 43340, valid race outcomes 7880, unexpected errors0. Parent workers/pending requests/associations return0. RSS and sampled peak limitations are recorded without a long-soak leak certification.

SagerNet0/0/0/0, underlay Unknown0, secret real0/unresolved0. Fixed preinstalled Go1.26.6 with GOTOOLCHAIN=local recorded; go.mod/go.sum, HY2 crypto RNG/Reno docs, LICENSE, WinDivert asset and canonical historical qualification report unchanged. Historical qualification remains PARTIALLY PASSED; all gaps remain OPEN and current work is development validation only.

Full report: `D:/splicore-validation/phase17-review-fix2-20261006/PHASE17_REVIEW_FIX_ROUND2_REPORT.md`; summary: `summary.json`; final acceptance evidence: `accepted/`; complete consumer audit: `root-cause/CONSUMER_AUDIT.md`.

HEAD b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c, branch codex/phase-16-native-shadowsocks, DIRTY/UNSTAGED, index EMPTY. stage/commit/push/tag/release/freeze: NO. Public GitHub UNCHANGED; NoBrand NOT ACCESSED. No independent re-review or next phase started.


## Final Independent Re-Review and consolidated freeze — 2026-10-07 (Asia/Shanghai)

**PHASE 17 FROZEN**. Final Independent Re-Review: **PASSED**.
This freeze consolidates Phase 16 Native Shadowsocks / Shadowsocks 2022,
Phase 17 Independent Core Decoupling and Review Fix Rounds 1, 2 and 3.
ADR 0038 is Accepted. All seven findings are CLOSED; no known implementation
blocker remains. Earlier failed checkpoints and original unsuccessful campaigns
remain preserved as historical evidence.

Final review: `D:/splicore-validation/phase17-final-rereview-20261006/PHASE17_FINAL_REREVIEW_REPORT.md`.
Reviewed source manifest SHA256:
`20518050931238fe4a25711e1119bef6a29e9048b5140f38a874307dbd2e040c`.
The freeze changes only documentation/status metadata after that review; Go,
modules, runtime configuration, test logic and build-critical bytes are preserved.

Canonical scope, commit identity and qualification gaps:
[Independent Core Transition Freeze Report](PHASE17_INDEPENDENT_CORE_FREEZE_REPORT.md).
The local consolidated commit's sole parent is
`b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c`, with message
`feat(core): establish independent core with native shadowsocks`.
The containing-commit lookup and external final report record its resolved hash.
Historical platform qualification remains **PARTIALLY PASSED**. Current freeze:
**NOT REQUALIFIED / NOT PLATFORM QUALIFIED YET**; qualification is NOT RE-RUN.
Public GitHub UNCHANGED; NoBrand NOT ACCESSED; next development NOT STARTED.
