# Splicore Phase 16 Native Shadowsocks / Shadowsocks 2022 Implementation Report

## Verdict

**PHASE 16 IMPLEMENTATION REVIEWED**

Implementation and the applicable Phase 16 acceptance gates passed. ADR 0037
is Accepted for the consolidated Phase 16 + Phase 17 freeze. Phase 16 changes
were consolidated into the Phase 17 Independent Core Transition freeze commit.
The sections below preserve Phase 16 implementation history and its original
unstaged checkpoint; validation ran on 2026-10-05/06. See the final freeze metadata
at the end of this report.

Evidence root: `D:/splicore-validation/phase16-shadowsocks-20261005/`.
Raw logs, binaries, private disposable fixtures and audit JSON remain outside Git.

## Base

| Item | Value |
|---|---|
| Branch | `codex/phase-16-native-shadowsocks` |
| HEAD | `b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c` |
| Frozen parent/base | Same commit; no new commit |
| Working tree | DIRTY; implementation and documentation UNSTAGED |
| Index | EMPTY |
| Go minimum | 1.26.3, unchanged |
| Validation toolchains | Fixed preinstalled Go 1.26.6, Linux/Windows amd64 |
| GOTOOLCHAIN | `local`; offline GOPROXY/GOSUMDB |

The entry baseline was checked before implementation. The final source manifest
records each changed file's SHA256 and unchanged HEAD/index. No history repair,
automatic reset or public repository operation occurred.

## Protocol Architecture

Splicore owns registration, credentials, accounts, bindings, native listener
admission, authentication, relay lifetime, outbounds, cancellation, sessions,
SQLite authority, management, diagnostics and validation. SS traffic uses the
existing shared routing, DNS, policy, underlay and stats engines.

The server reuses the already integrated protected server router/DNS/DIRECT
infrastructure with an empty inherited inbound registry. It registers no
inherited Shadowsocks runtime. The client uses injected protected dials and
clientio ownership. There is no subprocess engine or imported external core.

The [architecture](../architecture/SHADOWSOCKS_RUNTIME.md) includes
`PHASE16_PROTOCOL_INTEGRATION_INVENTORY`, comparing Snell, HY2, TUIC, VLESS and
Mieru on registration/account/binding/credential/runtime/stats/API/CLI/backup/
diagnostics. Its integration template reuses proven generation, transaction,
credential, routing and metering contracts. Wire-specific identities stay local.

## Protocol ID Decision

**SS_PROTOCOL_ID_DECISION:** ProtocolID `shadowsocks`, WireVersion `2017` or
`2022`, FeatureProfile `base`. Validated methods select the edition. This shares
one compiler/outbound family while keeping distinct key, identity, framing,
timestamp and replay semantics explicit. SS2022 is not modeled as a classic
cipher substitution.

## Engine

`native`.

## Methods

### Shadowsocks

| Method | Key bytes | TCP | UDP | Server | Client | Interop |
|---|---:|---|---|---|---|---|
| aes-128-gcm | 16 | PASS | PASS | PASS | PASS | sing-box / Mihomo |
| aes-256-gcm | 32 | PASS | PASS | PASS | PASS | sing-box / Mihomo |
| chacha20-ietf-poly1305 | 32 | PASS | PASS | PASS | PASS | sing-box / Mihomo |

Canonical modern AEAD methods only. Classic password derivation uses the existing
sing-shadowsocks EVP key function, then standard HKDF-SHA1 `ss-subkey`. TCP frames
are at most 16383 bytes; UDP uses an independent salt and a zero AEAD nonce.
Obsolete stream ciphers and custom transports were not added.

### Shadowsocks 2022

| Method | Key bytes | TCP | UDP | Server | Client | Interop |
|---|---:|---|---|---|---|---|
| 2022-blake3-aes-128-gcm | 16 | PASS | PASS | PASS | PASS | sing-box / Mihomo |
| 2022-blake3-aes-256-gcm | 32 | PASS | PASS | PASS | PASS | sing-box / Mihomo |
| 2022-blake3-chacha20-poly1305 | 32 | PASS | PASS | PASS | PASS | sing-box / Mihomo |

AES supports single PSK and SIP023 identity/account PSKs. ChaCha is single-user.
The method and identity inventories are documented in the architecture.

## Domain Model

### Account

Existing immutable Account IDs own server user credentials. Classic listener
authentication tries a bounded list of at most 16 distinct passwords; AES2022
SIP023 authenticates an account identity. Disable A leaves B usable, and native
matrix assertions reject bytes/sessions attributed to untouched users.

### Binding

Existing Binding IDs link Account, Inbound, Listener and Credential. TCP/UDP
listeners share the configured endpoint. Generic creation can project the
additional UDP listener. Runtime replacement remains coordinated by Application
Service and SQLite commit/admission fences.

### Credential

Classic uses PasswordPayload. SS2022 uses exact-length canonical base64
PSKPayload. SIP023 server identity uses the existing OwnerInboundID/vault model;
it is absent from settings. Account/inbound keys are single keys. Duplicate
credentials, invalid key relationships and missing identity material fail before
preparation/activation. Missing creation material is generated using crypto/rand.

### Node

Remote credentials use OwnerNodeID, separate from server accounts. Node IDs
remain stable through rename/provider replacement. AES node credentials can
contain a bounded SIP023 chain of at most eight keys. Nodes retain endpoint,
method, UDP capability and credential reference, without runtime objects.

### Outbound

Existing proxy Outbound IDs reference Node IDs and select the native factory.
Routing/policy select the shared leased adapter; generations own its lifetime.
An active SOCKS TCP connection survives provider credential replacement, while
new flows use the committed replacement node generation.

## Credential Security

Existing encrypted secret storage and vault ownership are reused. API default
reads, CLI diagnostics, SQLite/WAL and extracted support bundle content were
scanned against synthetic runtime credentials. Authorized export is the explicit
reveal boundary. No secret is passed through process argv. Error messages and
formatters redact credentials; no raw encrypted packet or full credential URI is
logged. Temporary private peer configs were removed and children joined.

Derived temporary key material is cleared where practical. Go's copies, strings
and cipher schedules do not provide a guarantee of immediate memory erasure.

## Server Runtime

### TCP

Owned accept loop, admission gate, authentication, destination decode, shared
protected routing, account metering, connection tracking and worker joins.
At most 256 raw connections; initial handshakes have a five-second deadline.
Closing disables admission, closes listeners/connections, shuts down the routing
stack and joins owned workers. An all-disabled account list leaves a healthy
listener that cannot authenticate a user.

SS-local connection wrappers preserve CloseWrite through inherited tracking and
metering. Actual targets replying after client EOF pass for classic and 2022.
Backpressure tests use unbuffered net.Pipe in both directions: an unread frame
blocks and Close releases the writer. Default race remains enabled.

### UDP

Owned receive loop authenticates/decrypts, extracts the destination and admits a
bounded routed target association. Its identity includes authenticated user,
destination, and classic source or SS2022 client SessionID. Every target uses the
existing router/DNS/address-family selection. Independent target sockets handle
two numeric remotes and a subsequent domain/IPv6 destination on Linux/Windows.

`SS_UDP_RESOURCE_MODEL`: at most 128 routed target associations per inbound;
eight queued datagrams each; 90-second idle expiry; joined shutdown. SS2022
authenticated source migration updates the client session's routed targets.
Independent response SessionIDs/counters prevent nonce reuse between targets.
Payload buffers belong to the decoded datagram/connection; no shared scratch,
unsafe pointer or pool early return was introduced.

## Client Runtime

### TCP

Context-aware protected underlay dial, pending-handshake/socket registration with
clientio, canonical framing and shared client session accounting. Read/write
state has separate narrow locks and directional nonces. Close interrupts pending
I/O and follows existing generation/lease retirement.

### UDP

Real connected protected UDP socket and packet adapter, used by SOCKS UDP
ASSOCIATE and Native TUN. Multiple destinations use the same logical client
association, with per-target server routing. Client response replay windows are
capped at 128 server sessions per packet adapter and expire after 90 seconds.
Decode work per client ReadFrom is bounded to 64 rejected packets.

## SS2022 Semantics

### Identity

SIP023 AES identity headers map to immutable account credentials, with inbound
identity key ownership. AES native multi-user matrices, external client users A/B
and managed disable/attribution tests pass. ChaCha has no SIP023 identity chain.

### Key Material

Canonical exact 16/32-byte base64 PSKs; no password derivation or oversized-key
hashing. Existing pinned BLAKE3 provides canonical session/identity derivation
contexts. AEAD and block operations use mature crypto implementations.

### Replay

Authentication and semantic checks precede replay admission. One Application
Service compiler retains replay state across inbound restart/disable/rollback.
Its registry admits at most 128 inbounds; retired entries are reclaimed lazily
after five minutes. Each inbound has 8192 salt entries and 512 authenticated UDP
windows. Capacity rejects new admission without evicting recent replay history.
Classic salt retention is five minutes; SS2022 request salts 60 seconds; UDP
windows 90 seconds with a 1024-packet sliding window. Actual authenticated TCP
replay after restart is rejected; fresh TCP/UDP traffic then passes.

### Timestamp

Authenticated wall-clock tolerance is 30 seconds. Cache expiry uses monotonic
time. Unit tests cover 30/31-second limits, expiry and integer overflow.

### Padding

Crypto/rand generates permitted padding of 1–900 bytes. Parsers bound and
validate padding/variable headers. Empty UDP payload, 32 KiB practical payload,
framing limits, malformed authenticated lengths and fragmented/coalesced data
are covered by unit/mutation/native/reference tests.

### UDP

Canonical AES block/AEAD and ChaCha XChaCha framing, client/server session IDs,
directional packet counters and authenticated replay windows. Target association
expiry does not discard recent session replay history.

## URI / Profile

Bounded `ss://` parser and lossless exporter. Classic accepts standard base64url
userinfo and bounded legacy authority encoding. SIP002 SS2022 uses percent
userinfo, including supported AES key chains; no invented URI scheme.
Plugins, ambiguous queries and lossy exports return canonical errors.
URI cannot encode disabled UDP; structured sing-box/Mihomo profiles preserve it.
Decoded controls, oversized input, malformed encoding, host/port and identity
confusion are rejected. Successful URI/profile reimport retains the credential
and protocol semantics. Known tested export versions are 1.14.1 / 1.19.30.

## Provider Integration

Existing preview/apply, encrypted source, strict validation, stable Node IDs,
outbound generation and failure rollback are reused. Actual SS2022 provider
refresh runs with TCP/UDP traffic and held TCP across replacement; ten refreshes
preserve ID, and a failed refresh preserves the published generation.

## API

Existing `/api/v1` creation, account/binding, node/outbound, import/export,
provider, status/stats and diagnostics endpoints. Real transport/API creation
and managed six-method traffic matrix pass. Malformed import does not commit.
No protocol-specific resource API or direct protocol database write was added.

## CLI

Existing Application Service-backed protocol creation validate/plan/apply,
inspect/export, node/inbound listing, doctor and support commands were executed
against the real local daemon. CLI/API use the same service. Interop harness
asserts diagnostics/argv/logs do not contain synthetic credentials.

## SQLite / Migration

Schema 8; existing models/vault suffice. No migration, go.mod or go.sum change.
Full internal regression includes existing databases and protocol state.

## Backup / Restore

Actual SQLite maintenance backup/restore includes classic/AES2022 server
accounts/bindings/inbound identity, imported nodes/outbounds and SS2022 provider
nodes/references. Canonical client/server state retains IDs/references; backup
bytes contain no synthetic plaintext credentials. Restored encrypted provider
source can refresh, and authorized client export can reveal the restored key.

## Doctor

Passive committed-state projection validates protocol settings, key material,
credential ownership and binding references, using existing module validation.
Checks report safe generic detail and IDs. Existing node validation remains in
client diagnostics. Doctor does not probe a target or perform a destructive fix.
Real CLI/API doctor and Phase 15 diagnostics regression pass.

## Support Bundle

Shared diagnostics show safe protocol/method, IDs, sessions and payload bytes.
Actual support tar member contents pass synthetic secret scanning. The
support-cancellation/artifact cleanup regressions also pass. No production
metrics sampler or second stats engine was added.

## Routing

Existing server protected target route and client domain/CIDR/outbound dispatch.
Actual loopback numeric/domain targets, IPv4/IPv6 kernel TUN and existing Phase
12 route regression pass. No protocol-owned domain/CIDR decision engine.

## DNS

Existing protected resolver/dial abstraction. TUN TCP/UDP port 53 hijack uses
proxied TCP DNS through both SS families; direct/bootstrap query counters stay
zero and isolated target leak counters are zero. UDP targets resolve through the
router, including subsequent domains after an IPv4 target on Windows.

## Policy

Real SS classic and SIP023 nodes pass Selector, URL-Test HTTP health probes,
Fallback primary disable/recovery and round-robin Load-Balance. Four TCP flows
split 2/2; a held UDP association addresses two targets without advancing the
selection on every packet. Linux race and Windows safe managed tests pass.
There is no SS-specific policy engine.

## Native TUN

Real kernel TUN in owned disposable WSL mount/network namespaces, with isolated
veth/target fixture. Existing owned Native TUN/underlay is used; no bypass stack.
Each workload includes both SS families, IPv4/IPv6 TCP 32 KiB, UDP 32 KiB ×8,
Selector generation changes and proxied TCP/UDP DNS hijack. Route/rule snapshots,
interface cleanup, generations/leases and server active sessions are checked.

`TestPhase16TUNLifetime25`: PASS, 374.20 seconds, 25 measured lifetimes plus a
warm lifetime. This is local implementation acceptance; it does not certify a
native Ubuntu host or destructive Windows host networking.

## Interoperability

Two independent ecosystem reference peers, pinned local binaries:

- sing-box 1.14.1: SHA256 `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9`.
- Mihomo 1.19.30: SHA256 `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494`.

All reference traffic is localhost in an isolated namespace. No third-party
target/subscription was used. Reference peers are validation artifacts.
Native self-interoperability additionally covers all six methods, AES single
and multi-user, TCP/UDP, lifecycle and management.

The raw reference matrix contains **28 rows**, each with TCP and UDP PASS.
AES multi-user server rows are distinct account A/B runs; these are not duplicate
claims. External reference servers were exercised in single-user mode.

| Client | Server | Method | Mode/account | TCP | UDP | Result |
|---|---|---|---|---|---|---|
| sing-box | Splicore | aes-128-gcm | single | PASS | PASS | PASS |
| mihomo | Splicore | aes-128-gcm | single | PASS | PASS | PASS |
| Splicore | sing-box | aes-128-gcm | single | PASS | PASS | PASS |
| Splicore | mihomo | aes-128-gcm | single | PASS | PASS | PASS |
| sing-box | Splicore | aes-256-gcm | single | PASS | PASS | PASS |
| mihomo | Splicore | aes-256-gcm | single | PASS | PASS | PASS |
| Splicore | sing-box | aes-256-gcm | single | PASS | PASS | PASS |
| Splicore | mihomo | aes-256-gcm | single | PASS | PASS | PASS |
| sing-box | Splicore | chacha20-ietf-poly1305 | single | PASS | PASS | PASS |
| mihomo | Splicore | chacha20-ietf-poly1305 | single | PASS | PASS | PASS |
| Splicore | sing-box | chacha20-ietf-poly1305 | single | PASS | PASS | PASS |
| Splicore | mihomo | chacha20-ietf-poly1305 | single | PASS | PASS | PASS |
| sing-box | Splicore | 2022-blake3-aes-128-gcm | multi user A | PASS | PASS | PASS |
| mihomo | Splicore | 2022-blake3-aes-128-gcm | multi user A | PASS | PASS | PASS |
| sing-box | Splicore | 2022-blake3-aes-128-gcm | multi user B | PASS | PASS | PASS |
| mihomo | Splicore | 2022-blake3-aes-128-gcm | multi user B | PASS | PASS | PASS |
| Splicore | sing-box | 2022-blake3-aes-128-gcm | single | PASS | PASS | PASS |
| Splicore | mihomo | 2022-blake3-aes-128-gcm | single | PASS | PASS | PASS |
| sing-box | Splicore | 2022-blake3-aes-256-gcm | multi user A | PASS | PASS | PASS |
| mihomo | Splicore | 2022-blake3-aes-256-gcm | multi user A | PASS | PASS | PASS |
| sing-box | Splicore | 2022-blake3-aes-256-gcm | multi user B | PASS | PASS | PASS |
| mihomo | Splicore | 2022-blake3-aes-256-gcm | multi user B | PASS | PASS | PASS |
| Splicore | sing-box | 2022-blake3-aes-256-gcm | single | PASS | PASS | PASS |
| Splicore | mihomo | 2022-blake3-aes-256-gcm | single | PASS | PASS | PASS |
| sing-box | Splicore | 2022-blake3-chacha20-poly1305 | single | PASS | PASS | PASS |
| mihomo | Splicore | 2022-blake3-chacha20-poly1305 | single | PASS | PASS | PASS |
| Splicore | sing-box | 2022-blake3-chacha20-poly1305 | single | PASS | PASS | PASS |
| Splicore | mihomo | 2022-blake3-chacha20-poly1305 | single | PASS | PASS | PASS |

Source: `interop/results.json`, `interop/matrix-accepted.log`,
`interop/cleanup.json`. Actual CLI/API and support secret safety are PASS.

## Findings

### SS16-001

Surface: cached classic library service/reader. Observation: missing salt replay
filter, unchecked peer length slicing, NAT identity omitting user, mutable user
map replacement. Risk: replay, panic, isolation/lifetime races. Decision:
retain mature crypto/derivation; own canonical bounded framing and lifecycle.
Implementation: immutable keys, bounded replay/state and native ownership.
Regression: wire fuzz, native/managed multi-user matrix, default race and churn.

### SS16-002

Surface: cached SS2022 service/client. Observation: replay insertion before
authentication, unbounded cache admission, non-crypto padding RNG and oversized
PSK hashing. Risk: violates managed bounds/strict key requirements. Decision:
own canonical glue using existing crypto libraries. Implementation: validated
exact PSKs, crypto/rand and authenticated bounded admission. Regression:
timestamp/window/frame tests, SIP023/reference interop, fuzz and race.

### SS16-003

Surface: persisted listener order/export/import. Observation: SQLite orders
listeners by ID, exporter needed ExportDescriber, Mihomo udp:false was lost.
Risk: incomplete/nondeterministic management contract. Decision/Implementation:
validate listener transport sets, describe exports and preserve UDP flag.
Regression: managed six-method/profile reimport and explicit UDP capability test.

### SS16-004

Surface: half-close through inherited tracking/meter wrappers. Observation:
target response after EOF was lost because the outer interface hid CloseWrite.
Risk: response truncation/lifetime error. Decision/Implementation: SS-local
forwarding wrappers preserve half-close and existing tracking ownership.
Regression: actual post-EOF target responses, lifecycle race and Windows safe.
Inherited runtime/module files remain unchanged.

### SS16-005

Surface: one UDP association with subsequent targets. Observation: first IPv4
route socket could not also handle domains/IPv6 on Windows. Risk: target loss or
resolver bypass. Decision/Implementation: bounded destination-aware routed
associations, existing router/DNS and independent response SessionIDs/counters.
Regression: all six methods with two numeric targets plus domain on Linux/Windows.

### SS16-006

Surface: resource measurement in a shared package test process. Observation:
unrelated preceding protocol teardown changed FD baseline 15→9. Risk:
incomparable stopped-state assertion. Decision/Implementation: run the same
resource test once in a fresh copy of its test binary. Regression: strict FD
equality, default race/checkptr, 4000 malformed UDP/256 bad TCP/512 valid UDP
associations. No sleep, I/O retry or relaxed FD criterion.

Compatibility decisions `SS16-COMPAT-001/002` remain explicit in architecture:
SIP022 initial salt/fixed header uses one read and rejects short reads; subsequent
frames support fragmentation. SIP002 SS2022 userinfo uses percent encoding.

## Race / Checkptr

| Gate | Result | Evidence |
|---|---|---|
| Default `go test -race ./...` | PASS | race/default-full-review.log |
| Native tagged `go test -race ./...` | PASS | race/native-full-review.log |
| Shared common/adapter/transport race | PASS | race/shared-review.log |
| Complete internal tagged unit tests | PASS | race/unit-review.log |
| SS native suite ×10, including lifecycle25/churn | PASS | race/native-final-10x.log |
| Backpressure/URI/isolation matrix ×10 | PASS | race/backpressure-isolation-uri-10x.log |
| Managed policies/backup/stats compatibility | PASS | race/policy-backup-stats-final.log |
| Actual restart replay / performance | PASS | race/restart-performance-accepted.log |
| Invalid intent before activation | PASS | race/invalid-intent-review.log |
| Actual TUN25 and mixed stress, race binary | PASS | stress/tun-accepted-lifecycle-and-soak.log |

Checkptr: **default ON**. No race/checkptr disable, panic recovery or acceptance
test omission. Whole-repository runs include inherited packages. After those
runs, additional test-only assertions were verified by targeted race; production
runtime/wire inputs did not change.

## Fuzz

Real mutation runs, four workers; requested bounded duration 25 seconds each.

| Target | Actual seconds | Executions | Crashes | Result |
|---|---:|---:|---:|---|
| FuzzShadowsocksURI | 26.055 | 76,727 | 0 | PASS |
| FuzzShadowsocksTCPFrame | 25.111 | 782,866 | 0 | PASS |
| FuzzShadowsocksUDPDatagram | 25.144 | 895,701 | 0 | PASS |
| FuzzShadowsocksAddress | 25.139 | 1,054,360 | 0 | PASS |

Evidence: `fuzz/FuzzShadowsocksURI-local-cache.log` and
`fuzz/FuzzShadowsocks{TCPFrame,UDPDatagram,Address}.log`.
TCP/UDP mutation also constructs authenticated plaintext to reach parsers beyond
the AEAD tag gate. Address/URI targets verify successful round trips.

The earlier URI run in `FuzzShadowsocksURI-final.log` ended with context deadline
exceeded after progress stopped; it is **not a PASS** and was preserved. The
subsequent documented diagnostic run used a separate Linux filesystem GOCACHE
and passed. Execution progress also paused in that run; the exact fuzz-worker
stall cause was not established. Source review found bounded pure parser/export
code, and no crash corpus or production parser hang was demonstrated. The report
does not claim that changing the cache fixed a protocol defect.

## Resource Stability

Comparable stopped state, actual SS server/client TUN ×25:

| Resource | Start | Sampled peak | End |
|---|---:|---:|---:|
| Goroutines | 11 | 40 | 11 |
| FDs | 17 | 26 | 17 |
| EventFDs | 1 | 1 | 1 |
| TCP listeners in the lab namespace | 3 | 3 | 3 |
| Client sessions | 0 | 4 | 0 |
| Server TCP active | 0 | present during traffic; no separate peak sampled | 0 |
| Server UDP active | 0 | present during traffic; no separate peak sampled | 0 |
| Client generations | 1 | 2 | 1 |
| Client leases | 1 | 2 | 1 |
| Host generations / TUN interfaces / journal temporaries | 0 / 0 / 0 | TUN active during work | 0 / 0 / 0 |
| RSS KiB, race process | 104,188 | 150,908 | 144,448 |

TCP/UDP active counts are checked explicitly at stopped boundaries. The session
peak above is the shared client count, not invented per-transport measurements.
RSS is retained process memory and did not return to entry RSS; equivalent
resource ownership is established by the FD/worker/session/generation checks.
This short run does not certify long-term memory stability.

Bounded abuse/churn separately restores its isolated FD/goroutine baseline.
The ×10 suite reports FD 8→peak74→8 and goroutines 3→peak198→3; fixture FD counts
differ from the standalone process baseline because stdout ownership differs.
There are no residual server active sessions. Expiry uses the actual worker with
test-aged state, rather than a sleep or traffic retry.

## 10-Minute Stress

- Actual workload duration: **10m11.736618287s**, 49 rounds; test duration 625.25s.
- Mixed SS and SIP023, TCP/UDP, IPv4/IPv6, routing, Selector changes, proxied DNS
  and real Native TUN. Work offered on a fixed three-second ticker; actual work
  takes longer. Failed I/O is never retried.
- I/O errors: **0**. Fixture DNS leak counters: TCP 0 / UDP 0.
- At rounds 20/30/40, resources stabilized at goroutines197, FDs84,
  sessions38, generations19, leases19. UDP idle retirement retains old generations
  until their sessions finish; this bounded active plateau returns to baseline.
- Stop: goroutines11, FDs17, sockets6, eventfd1, listeners3, sessions0,
  generations1, leases1; host generation/interface/temporary count0.
- RSS start144524, sampled peak303852, stopped300664 KiB under race.

The log's peak object does not update every qfTUNResources field. In particular
its SocketFDs6/HostGenerations0/Interfaces0 are baseline copies, not valid active
peaks. Actual active sample logs show SocketFDs72, HostGenerations1/Interfaces1.
The report uses those observed samples and does not infer missing peaks.

## Performance Sanity

Actual native loopback server/client, race enabled, echo integrity verified:

| Method | TCP payload | TCP echo rate | UDP payload / packets | UDP round trips/s |
|---|---:|---:|---|---:|
| aes-128-gcm | 4 MiB | 125.54 MiB/s | 1200 bytes / 128 | 3593.11 |
| 2022-blake3-aes-128-gcm, multi | 4 MiB | 50.50 MiB/s | 1200 bytes / 128 | 3598.96 |

These are local sanity measurements, not platform performance guarantees. No
machine-specific speed threshold or crypto shortcut was introduced. The
bounded abuse tests and completed stress expose no pathological CPU/I/O stall.
Allocation/CPU profiles were not necessary for a remaining observed regression.

## Existing Protocol Regression

Snell, Hysteria2, TUIC, VLESS plain/TLS/REALITY and Mieru: PASS in native
self-interop/security/lifecycle suites. DIRECT/REJECT, SOCKS TCP/UDP, HTTP/Mixed,
routing/DNS/policies/provider generations also PASS in the full native race run.
Vision remains Deferred/Unsupported; its scope was not changed.

## Phase 15 Regression

| Finding | Actual regression | Result |
|---|---|---|
| H15-001 | HTTP shutdown/readiness/forced handler join | PASS |
| H15-002 | closed/stale/concurrent candidates; ownership25x | PASS |
| H15-003 | bootstrap/health DNS owner cancellation | PASS |
| H15-004 | late provider failure/success cannot replace authority | PASS |
| H15-005 | concurrent SQLite Close/install release | PASS |
| H15-006 | canceled support/projection leaves no artifact | PASS |
| H15-007 | stopped native handle rejects stale activation | PASS |
| H15-008 | journal temporary/crash/symlink/permissions | PASS |
| H15-009 | native diagnostics/failures/passive health | PASS |

Exact successful test names are recorded in `reports/acceptance-review.json`,
derived from `race/native-full-review.log`, rather than inherited freeze claims.

## Native TUN Regression

QF-001: five original targeted ownership/shutdown/generation/error tests PASS.
QF-002: official owned backend targeted FD/eventfd lifecycle25x PASS:
FD7/7/7, eventfd1/1/1, goroutine2/2/2. Packet ownership IPv4/IPv6 TCP/UDP, syscall
join and native goroutine lifecycle tests PASS. Actual Phase16 TUN25 supplies
new shared client/runtime resource regression. No one-hour qualification rerun.

## Platform Builds

### Linux amd64

PASS, native tags `with_gvisor,with_quic,with_utls`, CGO_ENABLED=0. Fixed
Go1.26.6/local. Final artifact SHA256:
`6ca4ba259e4cc7e271b958d7ca811de68a5f2b0a27f4fb8f8fc67ece7cc2938d`.
Linux default/native race and actual isolated TUN acceptance also PASS.

### Windows amd64

PASS, native cross build plus fixed Windows Go1.26.6 safe suites. Native SS
TCP/UDP methods, multidestination domain handling, lifecycle/half-close,
management/provider/policy and shared client/ports tests PASS. Windows race was
not run because the local CGO/race prerequisites are unavailable. No destructive
host TUN/route/WinINET/networking qualification was performed.
Final cross artifact SHA256:
`e797b1b9ee2e75460c8c500990814929081c1a3527de429e96aa128857cf09d1`.

### Linux arm64

PASS, native tags, CGO_ENABLED=0, build only. Runtime NOT CERTIFIED.
Final artifact SHA256:
`320a05520edc3840663f0d42542c55fa61663916086a487fe7eb3f22b4cdabc5`.

Evidence: `artifacts/*-final-build.log`, final build hashes/toolchain records,
`race/windows-review-safe.log`, `race/windows-review-management-safe.log`.

## Underlay

Production surfaces: **60**. Unknown: **0**.

Five SS surfaces: protected server construction, local TCP/UDP ingress,
protected client TCP and UDP calls. Health/DNS reuse audited shared surfaces;
reference interop calls are test-only. The reviewed exact-call inventory and
protection invariants remain enforced. No new unclassified egress was allowed.
Evidence: `reports/underlay-review-final/inventory-after.{json,md}`.

## Xray Boundary

E=**0**, F=**0**, G=**10 actual**. New documentation references are classified;
historical source/profile classifications remain preserved. FinalMask/Sudoku
runtime count remains0; Vision deferred. No Xray dependency/engine/runtime added.
Evidence: `reports/xray-boundary-review.json`.

## Dependencies

No module added or upgraded; go.mod/go.sum unchanged. `go mod verify`: PASS.
No local replace, fork, vendor patch or automatic toolchain download.

| Module/library | Version | Purpose | License |
|---|---|---|---|
| Go standard library | toolchain1.26.6 | AES/GCM, HKDF-SHA1, randomness, sockets | BSD-3-Clause |
| github.com/sagernet/sing-shadowsocks | v0.2.8, existing | Canonical EVP password key derivation only | GPL-3.0-or-later |
| golang.org/x/crypto | v0.54.0, existing | ChaCha20-Poly1305 / XChaCha20-Poly1305 | BSD-3-Clause |
| lukechampine.com/blake3 | v1.3.0, existing | Canonical BLAKE3 derivation/hash | MIT |

The project's GPL-3.0-or-later license is retained. Existing copyright/license
files were read and hashed; public source/notice obligations remain compatible.
Peer binaries are not production dependencies or distribution inputs.

## Upstream Modifications

- sing-box module/source modifications: **0**.
- sing-tun source modifications: **0**.
- gVisor source modifications: **0**.
- Mieru source modifications: **0**.
- SS library module-cache modifications: **0**.
- Inherited repository runtime files changed: **0**.

All Go changes are under owned `internal/splicore`; module verification passes.

## Wire Implementation

Local necessary canonical glue: method validation, bounded TCP/UDP framing,
SIP023 identity headers, timestamps, padding, replay/window admission and
connection buffer/nonce ownership. Address handling delegates to the existing
shared SOCKS address serializer and domain endpoint validation.

Reused primitives: stdlib AES/block/GCM/HKDF/random; existing x/crypto
ChaCha/XChaCha; existing BLAKE3; existing canonical EVP derivation. No hand-written
AES/ChaCha/Poly1305/BLAKE3/AEAD primitive or modified wire format. Library runtime
reuse was rejected for the concrete bounds/ownership findings SS16-001/002.

## Files Changed

- `docs/adr/0037-native-shadowsocks-editions-and-credential-ownership.md`
- `docs/adr/README.md`
- `docs/architecture/README.md`
- `docs/architecture/SHADOWSOCKS_RUNTIME.md`
- `docs/development/README.md`
- `docs/reports/PHASE16_NATIVE_SHADOWSOCKS_IMPLEMENTATION_REPORT.md`
- `internal/splicore/app/app.go`
- `internal/splicore/application/creation.go`
- `internal/splicore/application/inbounds.go`
- `internal/splicore/application/service.go`
- `internal/splicore/application/shadowsocks_backup_linux_test.go`
- `internal/splicore/application/shadowsocks_policy_test.go`
- `internal/splicore/application/shadowsocks_test.go`
- `internal/splicore/application/shadowsocks_tun_linux_test.go`
- `internal/splicore/engine/native/meters.go`
- `internal/splicore/engine/native/shadowsocks.go`
- `internal/splicore/engine/native/shadowsocks_acceptance_test.go`
- `internal/splicore/engine/native/shadowsocks_outbound.go`
- `internal/splicore/engine/native/shadowsocks_stress_linux_test.go`
- `internal/splicore/engine/native/shadowsocks_test.go`
- `internal/splicore/engine/native/shadowsocks_udp.go`
- `internal/splicore/exporter/shadowsocks.go`
- `internal/splicore/nodeimport/external.go`
- `internal/splicore/nodeimport/import.go`
- `internal/splicore/nodeimport/shadowsocks_test.go`
- `internal/splicore/operations/client_diagnostics.go`
- `internal/splicore/operations/diagnostics.go`
- `internal/splicore/ports/creation.go`
- `internal/splicore/ports/ports.go`
- `internal/splicore/ports/runtime.go`
- `internal/splicore/ports/runtime_test.go`
- `internal/splicore/protocol/shadowsocks/creation.go`
- `internal/splicore/protocol/shadowsocks/shadowsocks.go`
- `internal/splicore/protocol/shadowsocks/shadowsocks_test.go`
- `internal/splicore/protocol/shadowsocks/uri.go`
- `internal/splicore/protocol/shadowsocks/wire/address.go`
- `internal/splicore/protocol/shadowsocks/wire/backpressure_test.go`
- `internal/splicore/protocol/shadowsocks/wire/crypto.go`
- `internal/splicore/protocol/shadowsocks/wire/replay.go`
- `internal/splicore/protocol/shadowsocks/wire/tcp.go`
- `internal/splicore/protocol/shadowsocks/wire/udp.go`
- `internal/splicore/protocol/shadowsocks/wire/wire_test.go`
- `internal/splicore/registry/native_core.go`
- `scripts/splicore-shadowsocks-interop.py`
- `scripts/splicore-underlay-audit.py`
- `scripts/splicore-underlay-callsite-inventory.json`

The source manifest records exact hashes and all changes remain unstaged.
No validation binary, stress log, pcap or profile is stored in the repository.

## Migration

**NONE**. Existing schema/migrations unchanged.

## Documentation / ADR

- [Native Shadowsocks architecture](../architecture/SHADOWSOCKS_RUNTIME.md),
  including integration inventory/template, method/UDP resource models and findings.
- [ADR0037](../adr/0037-native-shadowsocks-editions-and-credential-ownership.md): **Proposed**.
- Maintained architecture/ADR/development indexes link the new artifacts.
- Historical ADRs, freeze reports and canonical qualification report unchanged.

## Secret Scan

Real: **0**. Unresolved: **0**.
Scope: changed source/tests/docs/scripts plus actual CLI/API/SQLite/support/log
artifacts scanned by the interop harness. Fixture keys are synthetic/CSPRNG;
no real node, credential, private subscription or target was introduced.
Evidence: `reports/secret-review.json`, interop harness assertions/results.

## Blockers

**NONE** for Phase16 implementation review. Admission caps, explicit unsupported
exports and the documented fuzz infrastructure diagnostic are not silently
removed from the report. Review may require further changes before a freeze.

## Platform Qualification Boundary

Still **PLATFORM QUALIFICATION PARTIALLY PASSED**, frozen candidate
`b698b76032a9dfb9c4eadf3ed421f30c2ec6e24c`. All four gaps remain open:

- GAP-01: long-soak goroutine stability NOT MEASURED; not a confirmed leak/defect.
- GAP-02: safe Windows destructive target unavailable.
- GAP-03: native Ubuntu host-network target unavailable.
- GAP-04: Linux arm64 BUILD ONLY / runtime NOT CERTIFIED.

Canonical report remains
`D:/splicore-validation/platform-requalification-20261005/PLATFORM_REQUALIFICATION_FINAL_REPORT.md`,
SHA256 `18065f3ca3c5f34f5ac8d8e0d52b34a80218f7a6f4ab418f256467c80996bba7`.
New short Phase16 evidence does not overwrite or upgrade that verdict.

## Git Actions

- staged: **NO**
- committed: **NO**
- pushed: **NO**
- tagged: **NO**
- released: **NO**
- frozen: **NO**

## Public GitHub

**UNCHANGED**. Public clean snapshot and v0.1.0 were not accessed or modified.

## NoBrand-OneClick

**NOT ACCESSED**.

**PHASE 16 READY FOR REVIEW**. Stop for maintainer review; do not freeze or publish.


## Consolidated freeze metadata — 2026-10-07 (Asia/Shanghai)

**PHASE 16 IMPLEMENTATION REVIEWED**. ADR 0037 is Accepted. Phase 16 changes
were consolidated into the Phase 17 Independent Core Transition freeze commit.
There is no standalone Phase 16 freeze commit or fabricated Phase 16 hash.

The implementation and earlier Git-action sections above retain the historical
Phase 16 checkpoint. The final consolidated identity, seven CLOSED findings,
verified evidence and current Git state belong to the
[Phase 17 freeze report](PHASE17_INDEPENDENT_CORE_FREEZE_REPORT.md).
Historical qualification remains PARTIALLY PASSED; this freeze is NOT REQUALIFIED.
No public publication or next development phase is included.
