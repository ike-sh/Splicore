# Native Shadowsocks runtime (Phase 16)

Status: Phase 16 implementation for review; ADR 0037 remains Proposed. Acceptance
evidence is recorded in the [implementation report](../reports/PHASE16_NATIVE_SHADOWSOCKS_IMPLEMENTATION_REPORT.md).
No freeze or public release is performed.

## PHASE16_PROTOCOL_INTEGRATION_INVENTORY

The audit covers `internal/splicore`, not inherited unregistered adapters.

| Surface | Snell | HY2 | TUIC | VLESS | Mieru |
|---|---|---|---|---|---|
| registration | 5/6 protocol keys | 2/base | 5/base | security profiles | 2/base |
| account | immutable account ID | same | same | same | same |
| binding | one | up to 16 | up to 16 | up to 16 | up to 16 |
| credential | PSK | password | UUID + password | UUID; inbound private key for REALITY | username + password |
| server runtime | native compiler; inherited adapter | native owned QUIC listener; sing-quic | same QUIC ownership | native listener; sing-vmess | owned SDK listener factories and relay |
| client outbound | owned inherited adapter | owned inherited adapter | owned inherited adapter | owned inherited adapter | SDK; clientio owner |
| stats | shared meter | shared meter; binding ID | same | same | shared meter; username to binding |
| API | shared creation/binding/export services | same | same | same | same |
| CLI | Application Service | same | same | same | same |
| backup | SQLite/vault shared backup | same | same | inbound secret reference included | same |
| diagnostics | registry + validated derived state | same | same | same; Vision deferred | same |

Repeated semantics to reuse: committed state projection, pending/start/health/commit/admission, immutable runtime generations, encrypted credential storage, identity references, exporter dispatch, clientio cancellation and close ownership, shared meters, underlay scopes, routing/policy/DNS client flow dispatch. Crypto identities and wire session semantics stay protocol-local. No new generic framework for hypothetical protocols.

## SS_PROTOCOL_ID_DECISION

Use ProtocolID `shadowsocks`, WireVersion `2017` or `2022`, FeatureProfile `base`, EngineID `native`. A method selects its edition. This preserves one compiler/outbound family while keeping different identity, framing and replay contracts explicit. SS2022 is not merely a cipher substitution. SIP023 AES identities are a server mode; the optional ChaCha method has no SIP023 multi-user identity header.

## SS_METHOD_MATRIX

| Method | Family | Key/salt bytes | TCP | UDP | Server/client | Interop target |
|---|---|---:|---|---|---|---|
| aes-128-gcm | AEAD 2017 | 16 | required | required | native | sing-box, Mihomo |
| aes-256-gcm | AEAD 2017 | 32 | required | required | native | sing-box, Mihomo |
| chacha20-ietf-poly1305 | AEAD 2017 | 32 | required | required | native | sing-box, Mihomo |

Password derivation follows canonical EVP_BytesToKey, then HKDF-SHA1 with `ss-subkey`. These are legacy *derivation requirements* of the modern AEAD wire format; no stream cipher is introduced. Frame length is capped at 16383. UDP uses an independent salt and a zero AEAD nonce.

## SS2022_METHOD_MATRIX

| Method | Key/salt bytes | Identity model | TCP/UDP | Replay / timestamp / padding |
|---|---:|---|---|---|
| 2022-blake3-aes-128-gcm | 16 | single PSK or SIP023 inbound identity PSK + account PSK | required | SIP022 |
| 2022-blake3-aes-256-gcm | 32 | same | required | SIP022 |
| 2022-blake3-chacha20-poly1305 | 32 | single account PSK | required | SIP022; UDP XChaCha construction |

Keys are exact-length canonical base64; password derivation or oversized-key hashing is rejected. BLAKE3 uses the canonical context strings. TCP request salts live for 60 seconds after authenticated timestamp validation (30-second wall-clock tolerance). UDP session/packet identities use authenticated sliding windows and retain session state at least 60 seconds. Nonces are directional; salts/session IDs and padding randomness use crypto/rand.

## Credential ownership

Classic accounts use PasswordPayload. SS2022 accounts and inbound identity keys use PSKPayload. Node PSKs may contain a bounded SIP023 key chain; account/inbound keys cannot. An inbound-owned identity PSK is stored in the existing vault, never Settings or plaintext SQLite. Explicit authorized client projection may disclose the identity PSK together with that account's key; private REALITY material remains excluded. Rotation publishes a replacement immutable runtime, never mutates a live library user map. Rename preserves every ID.

## SS_UDP_RESOURCE_MODEL

One listener receive loop owns datagram admission. Routed target associations
include user, destination and either classic source or SS2022 client session ID.
Each association owns one router-selected socket, two copy directions, and an
8-datagram queue. An inbound admits at most 128 associations and 256 raw TCP
connections. Handshakes have a 5-second deadline; UDP target associations expire
after 90 seconds of idle time. Shutdown closes listeners/sockets and joins workers.

Every destination goes through the existing protected router and DNS resolution.
This also handles subsequent domains/IPv6 targets on Windows after an IPv4 target.
SS2022 source changes update all routed targets of the authenticated client session.
Each response association has an independent CSPRNG server session ID and nonce
counter. Client packet readers remember at most 128 server replay windows for
90 seconds. Read/write directions have separate narrow locks and owned buffers.

Replay state survives socket expiry and inbound generation replacement. The
Application Service compiler holds at most 128 inbound replay entries, each with
8192 salt entries and 512 authenticated UDP windows. Classic salts live 5 minutes,
SS2022 request salts 60 seconds; UDP windows live 90 seconds. Retired inbound state
is reclaimed lazily after 5 minutes. Capacity rejects new admission and never
evicts recent replay history. No unbounded target/source history or buffer pool is
introduced. Practical encrypted datagram maximum is 65507 bytes.

## Initial findings

### SS16-001

Surface: cached sing-shadowsocks v0.2.8 service and reader.
Observation: classic service has no salt replay filter; reader slices a fixed buffer with peer-declared lengths; multi-user NAT key omits account identity; service user maps are replaced without synchronization.
Risk: replay acceptance, malformed authenticated frame panic, attribution/isolation errors, live mutation races.
Decision: do not reuse that service as the managed server. Reuse mature crypto primitives and canonical derivation; own bounded framing/lifecycle glue locally. Never patch module cache.
Implementation: protocol-local wire package, immutable key lists and bounded
compiler/session replay state; crypto primitives and canonical EVP derivation reused.
Regression: wire unit/mutation fuzz, native matrix, managed multi-user disable,
provider rotation with retained sessions, abuse/churn and default race tests.

### SS16-002

Surface: cached SS2022 library services/client.
Observation: request replay insertion precedes authentication; UDP caches have no explicit count cap; padding lengths use math/rand; oversized PSKs may be hashed.
Risk: fails Phase 16 bounds, crypto randomness and exact-key requirements.
Decision: explicit validation and protocol-local canonical glue with mature crypto libraries; no upstream changes.
Implementation: strict PSK lengths/encoding, CSPRNG salts/session IDs/padding,
authenticated semantic validation before replay commit, fixed resource caps.
Regression: timestamp overflow, padding/frame boundaries, replay/window mutation
fuzz, SIP023 interop, default race and resource shutdown tests.

### SS16-003

Surface: persisted listener projection and client export contract.
Observation: SQLite listener ordering follows IDs, not transport; exporter dispatch
also requires an ExportDescriber. Initial management tests exposed both omissions.
Risk: nondeterministic export validation and an incomplete API/CLI export surface.
Decision: validate the listener transport set independent of row order and provide
the standard description. Preserve Mihomo `udp:false` in external import.
Implementation: Shadowsocks module/exporter and external node import.
Regression: managed six-method matrix, profile reimport and explicit UDP flag test.

### SS16-004

Surface: existing server router's direct optional CloseWrite check.
Observation: inherited tracking/counting wrappers retain the underlying socket
but hide its half-close interface. A target replying after EOF lost its response.
Risk: truncated application response and incorrect connection lifetime.
Decision: SS-local outer wrappers preserve CloseWrite while retaining tracking
and metering ownership. Inherited runtime and module-cache files remain unchanged.
Implementation: SS outbound registry injects a tracking adapter; ingress wrapper
forwards half-close to its owned wire connection.
Regression: classic/2022 actual TCP target replies after EOF, Read/Write/Close race,
Windows safe tests and complete native protocol regression.

### SS16-005

Surface: one UDP client association addressing multiple targets.
Observation: a router socket prepared for IPv4 cannot also address subsequent
domains/IPv6 on every platform. Windows exposed the assumption.
Risk: target-dependent UDP loss or bypassing the existing DNS/routing abstraction.
Decision: bound routed associations by authenticated session and destination,
retaining replay protection independently. Never introduce protocol-owned DNS.
Implementation: destination-aware association identity and authenticated session
source migration; independent server session nonces; bounded client response windows.
Regression: one packet adapter addressing two numeric targets and a domain in all
six methods, with both loopback families, on Linux and Windows.

### SS16-006

Surface: test resource measurement in a shared package process.
Observation: preceding protocol tests can still retire unrelated library resources;
a baseline of 15 FDs became 9 after the SS test, causing an equality false failure.
Risk: comparing different stopped states obscures meaningful resource evidence.
Decision: execute this same abuse/churn test once in a fresh copy of its test
binary, retaining strict FD equality and default race/checkptr. No I/O retry.
Implementation: test-only child process; production diagnostics unchanged.
Regression: isolated 4000 malformed UDP packets, 256 bad TCP handshakes, 512
authenticated target associations; owned Close returns FD/goroutine baseline.

## Runtime and framework contract

The native handle owns listener admission, authentication, connections, routing
callbacks, target associations and worker joins. It uses the existing protected
server router/DNS/DIRECT infrastructure with an empty inherited inbound registry.
It does not import an external SS runtime or launch a core. The client factory
obtains only injected underlay dials, registers pending work/socket ownership with
clientio, and participates in the existing generation/lease retirement model.

Shared meters expose payload bytes, aggregate sessions and optional TCP/UDP
session totals/active counts. Server UDP counts are routed target associations;
client UDP counts are the existing logical client associations/packet counters.
Stats projections are dimensions, never quantities to sum across projections.
Older stats responses lacking the optional transport counters remain readable.

SQLite schema remains 8. Accounts, bindings, inbound identity credentials, remote
nodes and provider references reuse existing models. API default reads redact
credentials. Explicit authorized exports are the reveal boundary. Creation,
preview/apply, rename, rotation, disable, restart/rollback and backup all pass
through Application Service. Doctor passively validates committed module settings,
credential lengths/encoding and binding references; it performs no network probe.

### Error classes

| Condition | Behavior |
|---|---|
| unknown method/key encoding/length/relationship | canonical Invalid before activation |
| listener conflict | PortConflict; candidate closed, no partial domain commit |
| authentication/frame/replay/timestamp failure | safe wire error; stream closed or packet dropped |
| authenticated resource capacity reached | admission rejected; recent replay history retained |
| remote dial/cancellation | existing protected dial/ownership errors; fixed handshake error |
| unsupported/lossy export | UnsupportedExport; no stripped fields or custom URI scheme |

Crypto failures never log credentials, encrypted packets, or full URIs. Shared
frameworks do not currently expose a server error counter; this stage does not
create a second accounting engine. No unsafe pointer or shared scratch buffer is
used by SS wire/runtime glue.

### Protocol integration template

1. Audit canonical semantics and current protocol/library integration surfaces.
2. Register a protocol key, capabilities and strict local creation/profile codec.
3. Reuse encrypted credential ownership and immutable runtime projections.
4. Compile a prepared native handle with admission closed until SQLite commit.
5. Own every listener, accepted flow, callback, socket and worker join.
6. Register a node factory with protected dials and generation-owned clientio.
7. Use shared routing/DNS/policy/meters; retain wire-specific state locally.
8. Add lossless import/export and generic management/API/CLI integration tests.
9. Verify actual peers, kernel TUN, default race/checkptr, mutation fuzz, comparable
   resource states, stress, platform builds, egress/secret/dependency boundaries.

Only the additional listener projection, opt-in server credential projection,
transport meter counters and passive module validation are generalized here.

### SS16-COMPAT-001

Canonical SIP022 requires one read for salt plus fixed header and rejects short initial reads. Subsequent frame fragmentation is valid. The byte-by-byte acceptance gate must distinguish this initial header rule from ordinary framed payload fragmentation. No implicit read-full compatibility extension will be added to SS2022's initial header.

### SS16-COMPAT-002

SIP002 SS2022 userinfo must use percent-encoded method/password, not base64url. Classic base64url userinfo and legacy whole-authority base64 can be parsed with explicit bounds. Plugins cannot be represented by this native profile and must be rejected, not silently discarded.

## Source authority

- [Canonical AEAD wire and derivation](https://shadowsocks.org/doc/aead.html)
- [SIP004](https://github.com/shadowsocks/shadowsocks-org/issues/30)
- [SIP007](https://github.com/shadowsocks/shadowsocks-org/issues/42)
- [SIP022](https://shadowsocks.org/doc/sip022.html)
- [SIP023](https://shadowsocks.org/doc/sip023.html)
- [SIP002](https://shadowsocks.org/doc/sip002.html)
- Local immutable dependency source: sing-shadowsocks v0.2.8, sing-shadowsocks2 v0.2.1.

Required external reference runs, race, fuzz, lifecycle, TUN, stress and build
evidence must be taken from the implementation report and its external logs,
not inferred from this architecture. Reference peers are sing-box 1.14.1 and
Mihomo 1.19.30; their binary hashes are pinned in the interop evidence.

The frozen platform qualification remains PARTIALLY PASSED with all four evidence
gaps open. Phase 16's isolated WSL acceptance does not certify native Windows
destructive networking, native Ubuntu host networking or Linux arm64 runtime.
