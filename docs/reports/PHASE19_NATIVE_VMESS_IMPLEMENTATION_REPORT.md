# Splicore Phase 19 Native VMess Implementation Report

## Verdict

PHASE 19 READY FOR REVIEW

Implementation evidence only. Independent review and freeze have not been performed.

## Base

- Frozen base / HEAD: `1f0e1925f0f67a37e8d3d496a7e56ed7daff02a7`.
- Sole parent: `dabe4030fb82f272b8e1035779e2b8c4da9b0600`.
- Branch: `codex/phase-19-native-vmess`.
- Entry: exact HEAD, clean worktree, empty index verified before branching.
- Exit: DIRTY / UNSTAGED; index EMPTY. No commit or history rewrite.
- External evidence: `D:/splicore-validation/phase19-native-vmess-20261007/`.
- `entry/git.json`, `entry/verification.json`, `entry/source.json` and authoritative `request.txt` preserve the entry contract.

## Scope

Native modern VMess server/client, TCP, standard UDP, IPv4/IPv6/domain, multi-user, all selected modern data modes, raw TCP/shared TLS, generic management and Native TUN. Protocol tests and implementation audits are completed independently of historical Platform Qualification. Inbound payload_security selects the default for exported clients; each authenticated request selects its own supported wire payload mode. It is not a server restriction to one cipher.

## Compatibility Boundary

### Modern AEAD
SUPPORTED. No malformed-modern-to-legacy fallback.
### alterId=0
SUPPORTED and the selected peer baseline.
### Legacy alterId>0
DEFERRED / UNSUPPORTED. Management returns `unsupported_legacy_vmess`; genuine legacy traffic from sing-box/Mihomo rejects. Current Xray ignores the old alterId config field and sends modern AEAD even when set to 1; successful traffic in that probe does not establish legacy support.
### Raw TCP
SUPPORTED and mandatory. Modern AEAD authenticates headers without outer TLS.
### TLS
Shared TLS snapshot/client configuration; verification, SNI and explicit CA retained. No insecure public setting exists. Wrong SNI and untrusted CA reject. Minimum TLS 1.2.
### Unsupported Transports
WS/gRPC/HTTPUpgrade/XHTTP/h2/mKCP/VMess QUIC, Mux/XUDP/packetaddr, uTLS, REALITY and camouflage: UNSUPPORTED / DEFERRED. Standard Xray UDP interop sets `XRAY_CONE_DISABLED=true`; default cone-to-Mux behavior is outside this baseline.

## Protocol Identity

ProtocolID: `vmess`. EngineID: `native`. Splicore owns framing and runtime adapters; external peer processes occur only in tests/evidence tooling.

## Specification / Sources

Research preceded implementation: `spec/VMESS_SPEC_NOTES.md`, `spec/VMESS_CURRENT_COMPATIBILITY_MATRIX.md`, source/library provenance JSON, pinned source hashes/licenses and release metadata.

- [Canonical VMess](https://www.v2fly.org/en_US/developer/protocols/vmess.html).
- [Xray v26.3.27](https://github.com/XTLS/Xray-core/tree/v26.3.27/proxy/vmess), external oracle module v1.260327.0; MPL-2.0 reference.
- [sing-box v1.14.2](https://github.com/SagerNet/sing-box/tree/v1.14.2/protocol/vmess), active sing-vmess v0.2.8.
- [Mihomo v1.19.32](https://github.com/MetaCubeX/mihomo/blob/v1.19.32/adapter/outbound/vmess.go), active MetaCubeX/sing-vmess v0.2.5.

The retained Mihomo transport/vmess package is not its active runtime. Current active libraries, actual binaries and traffic are distinguished from schemas. No upstream VMess runtime was copied into production; external vectors use fixed synthetic inputs. No legally derived runtime source is claimed.

## Architecture

### protocol/vmess
`protocol/vmess/wire` owns auth, KDF, bounded headers, replay and chunks. `protocol/vmess/backend` owns stream/packet IO.
### Server
`internal/splicore/engine/native/vmess.go`: owned listener, bounded raw/TLS handshake, protected target dials, shared joined TCP/UDP relay and generic traffic counters.
### Client
`vmess_outbound.go`: protected proxy dial, shared TLS, eager request/lazy response authentication, clientio-owned sockets, standard bound UDP.
### Shared Core Integration
Managed module, native registry/app composition, existing vault/Application Service, Node/Provider, exports/imports, diagnostics and underlay. No protocol-local routing, DNS, policy, SQLite, generic TLS or parallel account store.

## Authentication

### Credential
Encrypted generic UUID payload. Dashed case-insensitive 16-byte UUID; arbitrary valid versions accepted. Account/Credential IDs retain domain identity. UUID and derived/session material redact outside controlled exports.
### Auth ID
Protocol-required command-key MD5; nested HMAC-SHA256 KDF; AES block over timestamp/random/CRC32, exactly pinned to independent vectors. Four random bytes use crypto/rand.
### Time
Wire functions accept time explicitly; compiler supplies the production clock. No scattered wire time.Now.
### Clock Skew
Inclusive ±120 Unix seconds. Signed/unsigned/negative/expiry overflow rejects; tests cover -121/-120/-119/0/119/120/121 and integer extremes.
### Multi-user
Two users and arbitrary UUID versions tested in actual raw/TLS traffic. Candidate trials are one snapshotted AES block per configured user, maximum 16; full candidate scan, generic remote close. The 16-user stress measures bounded candidate work. No perfect timing-resistance claim.

## Replay Protection

### Key
Three opaque fixed SHA256 tokens per authenticated request: command-key/AuthID context plus both directional data key/nonce contexts. No plaintext UUID in cache.
### TTL
Strictly after timestamp+120; inclusive acceptance boundary retained. Up to 240 seconds from earliest acceptance. High-water validation prevents clock rollback resurrecting retired windows.
### Capacity
65,536 tokens; at most 21,845 contemporary three-token requests. Atomic fail-closed admission; no eviction of valid-window records.
### Concurrent Duplicate
64 synchronized contenders: exactly one success. Captured auth and fresh auth with intentionally repeated session context reject. Replay persists across listener generations.
### Cleanup
Compiler-owned lazy bounded heap/map, no workers/timers/FD. Entries remain intentionally until expiry; listener Close does not clear replay history. In-process only; restart persistence and a lifetime nonce-collision proof are not claimed.

## KDF / Test Vectors

`vectors/independent-vectors.json`, `vectors/provenance.json`, `vectors/xray-oracle.log` and independent tests protect command key, AuthID/CRC32/timestamp, nested KDF labels/path, request header length/payload key and nonce, response material/header labels, SHAKE advancement and ChaCha expansion. Reports omit raw UUID, derived keys and session material.

## Request Header

### AEAD Length
AuthID16 + encrypted length18 + connection nonce8 + authenticated header. Length authentication precedes allocation; decoded supported length 47–316.
### AEAD Payload
Exact canonical labels/associated data, version, session material, response marker, options, security/padding, reserved byte, command, port/address and FNV1a checksum.
### Options
Chunk1, mask4, global padding8 supported. Reuse2, authenticated length16 and unknown bits reject. Padding requires mask and encrypted data.
### Address
IPv4=1, domain=2, IPv6=3; bounds/port/address validation before routing.
### Commands
TCP=1; standard UDP=2. Mux and extensions reject. Fragmented one-byte reads and coalesced request/first payload are tested.

## Response Header

Both AEAD length/content authenticate before exposing payload. Response marker must match; dynamic command/length fields reject. Options may be zero or exactly echo request options, matching current independent peers. Wrong tags, marker, truncation and unrelated options terminate the client.

## Payload Security Matrix

| Mode | Server | Client | TCP | UDP | External Interop |
|---|---|---|---|---|---|
| auto | concrete3/4 | architecture resolution | PASS | PASS | all selected directions/raw+TLS |
| aes-128-gcm | wire3 | PASS | PASS | PASS | all selected directions/raw+TLS |
| chacha20-poly1305 | wire4 | PASS | PASS | PASS | all selected directions/raw+TLS |
| none | wire5 | PASS | PASS | PASS | all selected directions/raw+TLS |
| zero / CFB / legacy | reject | reject | UNSUPPORTED | UNSUPPORTED | explicit rejection |

Auto: AES on amd64/arm64/s390x, otherwise ChaCha. None/TCP can be unframed; header remains AEAD. Each claimed mode has unit, real native server/client and external traffic evidence.

## Nonce / Counter

Independent directional key/IV/state. uint16 BE counter + IV[2:12]; 65535 once, then terminal before wrap. Random session key/IV/marker use crypto/rand; response key/IV derive separately by SHA256. Repeated session contexts reject within replay window. No custom primitive or incompatible nonce substitution.

## Chunking

### Framing
Encrypted payload or none chunks preserve bounded body semantics; empty chunk is EOF. Independent data state per direction.
### Length
Wire body ≤16,384; UDP oversized datagrams reject without segmentation.
### Masking
Direction-local SHAKE128; padding selection advances before length mask.
### Authenticated Length
DEFERRED / REJECTED. Current optional experiment reuses request direction contexts across directions; no required baseline peer enables it. No invented replacement.
### Padding
Supported encrypted global padding with masking. Random content uses crypto/rand; failure propagates. Invalid option combinations and malformed/truncated/tagged chunks reject.

## TCP

### Raw TCP
PASS; mandatory baseline for all content modes and two users.
### Outer TLS
PASS; shared verified wrapper on the same protected socket. TLS raw socket closes before lock joins.
### Fragmentation
ReadFull handles one-byte reads, split lengths/tags/header and coalesced data.
### First Payload
PASS; eager header, server-first data and 131,071-byte transfers. Lazy response validates before payload exposure.
### Partial Write
Failed request/data writes retire raw/frame owner. Positive short writes loop synchronously; subsequent write cannot continue a contaminated frame. No background tail writer.
### Half-Close
PASS raw/TLS for AES/ChaCha/none: upload EOF permits target response after EOF, through existing shared relay.

## UDP

### Canonical Semantics
Command2 binds one stream to one request target; one datagram per chunk, no address extension. Empty and oversized datagrams reject.
### Association Model
Backend Packet owns one stream; existing client flow registry owns per-destination associations. No duplicate VMess destination map.
### Framing
PASS fragmented/coalesced chunk streams; no split/coalesced datagrams. Partial error terminalizes contaminated stream.
### Target/Destination Model
Exact outbound target required. Server-bound domain permits same-port numeric resolved reply metadata; reply maps back to bound domain.
### Idle Lifecycle
Shared relay five-second idle; actual stream EOF and new association's actual reply tested in VM-UDP-L4. Shared target reader/idle/replacement tests and original historical companions verify target lifecycle.
### Registry
Identity-safe shared delete-if-owner. Reader death retires or fails clearly; parent joins workers. Shared 128-target bound.
### Reply Path
Real local/native/external/TUN TCP-carried UDP request/reply, including IPv4/domain/IPv6. Native datagrams include 16,000 bytes; external frontend matrix uses 1/128/1000/1200 because peer SOCKS frontends have smaller practical limits. No claim all peers carry 16,000-byte datagrams.

## vmess://

### Import
Bounded strict base64 JSON; encoded ≤4096, decoded ≤3072. Exact lowercase fields, duplicate/unknown/null/control/UTF8/UUID/port/address rejection. Supported v/ps/add/port/id/aid/scy/net/type/tls/sni/alpn fields.
### Export
Faithful supported subset only. Unsupported transport/security/legacy/fingerprint/camouflage reject. Explicit CA cannot be silently dropped; URI/Mihomo reject it, sing-box retains it. URI rejects UDP-disabled profiles.
### Round Trip
PASS semantic comparison for all modes, raw/shared TLS supported subset. Actual CLI exports loaded by sing-box/Mihomo and real TCP/UDP returned.
### Unsupported Fields
`unsupported_legacy_vmess`, `unsupported_transport`, `unsupported_security`; URI validation errors stay redacted. Selected core CLIs expose config loaders, not ecosystem URI generators: actual generated peer share links are UNAVAILABLE, not invented.

## Account / Credential / Binding

Generic encrypted UUID credentials and Application Service transactions. Create/disable/delete/rotate/unrelated-user/rollback/held-session/reference guards tested over API and real runtime. No separate VMess database.

## Node

Generic immutable IDs, UUID credential refs, transport/TLS/security/UDP options. Native capability and create/import/export integrate existing resources.

## Provider

Preview/validate/apply/rollback/refresh; rotated source, stable node IDs, held old sessions and unrelated users covered. Unsupported fields preserve classified issues.

## API

Existing /api/v1 resources and Application Service. Real management transport tests pass; no parallel API. Ordinary output, errors and exports without reveal redact UUID/derived keys.

## CLI

PASS: import/create/inspect/export, inbound user/account creation, binding mutation and four classified invalid cases. Intentional exports checked separately; ordinary output secret matches=0. cli/acceptance5 and cli/results.json.

## SQLite

NONE: no migration. Existing schema8 and encrypted secret vault. go.mod/go.sum and historical migrations unchanged.

## Backup / Restore

PASS: Account/Credential/Node/binding/TLS/provider IDs and encrypted credential source restore; reconstructed runtime, provider refresh and exports work. No UUID/derived command key in ordinary SQLite or diagnostics.

## Doctor

PASS existing generic checks plus VMess/resolved payload mode redacted metadata. No UUID/auth/session material.

## Support Bundle

PASS generic bundle/archive secret checks, synthetic UUID and derived key leak tests. Internal IDs and safe protocol metadata only.

## Stats

Shared traffic.Counter and generic client/account/binding/node counters; native two-user upload/download attribution and management TCP/UDP traffic tested. No VMess stats store.

## Routing

Protected existing routing/snapshot engine; no local route engine. Real TUN selector and IPv4/IPv6 proxy target traffic tested.

## DNS

Shared resolver/underlay; real TUN hijack and proxied TCP DNS tested. Bootstrap leakage counter must stay zero.

## Policy

Selector, URLTest, Fallback and LoadBalance including UDP affinity pass in application tests; TUN selector/proxied DNS tested.

## Native TUN

TCP: PASS; UDP: same required gate. Disposable mount/network namespaces/veth/real target fixtures; unprivileged traffic helpers. Host namespace is separate; kernel target leak counts must be zero. Final 10-minute mixed source gate is reported below. This is scoped implementation validation, not full qualification.

## Lifecycle Matrix

| Surface | Close | Live Deadline | Parent Close | Partial Frame | Registry Cleanup | Result |
|---|---|---|---|---|---|---|
| VMess TCP | L1 PASS | L2 PASS | L5 PASS | request L3 / data L4 PASS | clientio/server owner | PASS |
| VMess UDP | L1 PASS | L2 PASS | L5 PASS | PASS | L3 reader / native L4 idle replacement | PASS |
| TLS pending open | PASS | bounded handshake | pending-parent PASS | socket retired | clientio joins | PASS |
| Shared UDP target | PASS | shared deadline | PASS | backend terminal | reader/idle/old-owner companions | PASS |

Synchronization barriers precede Close/deadline/failure; assertions require terminal subsequent writes and actual replacement replies. Packet Close joins admitted writes and their cancellation callbacks.

## Clock Tests

PASS exact inclusive past/future edges, extremes/negative conversion, expiry boundary and rollback. Clock-invalid authentication traffic counted separately. No long sleeps used for protocol clock tests.

## Replay Tests

PASS same AuthID, concurrent duplicate, deliberate session material reuse, cross-generation capture, capacity and injected expiry. race/lifecycle-complete retained the successful wire stress even though its later native fixture assertion failed; final full default/native/shared race also runs these tests.

## Security

### Cryptography
Standard Go AES/GCM/HMAC/MD5/SHA256/CRC32/FNV and x/crypto ChaCha; SHAKE from Go crypto/sha3. MD5 only required canonical compositions.
### Randomness
crypto/rand for auth/session/header/global padding; injected failures reject. No math/rand security fallback.
### Authentication
Modern-only, generic remote close, maximum16 users, five-second/512-socket pre-auth. 1,000 actual bad auth/clock/tag/truncation attempts and 32 pending shutdown connections cleanly reject.
### Replay
Atomic bounded compiler bank, no eviction/reuse within window; capacity and rollback tests.
### Bounds
Authenticated header length before allocation; 316 header /16,384 chunk /4096 URI bounds. Valid-checksum malformed fields, authenticated oversized lengths, chunks/tags/padding and mutation fuzz protect them.
### Secret Redaction
Ordinary API/CLI/doctor/support/SQLite assertions include UUID and derived command key. Only explicit controlled synthetic exports reveal UUID. Final whole-tree and external evidence scans must be real0/unresolved0.

## Interoperability

| Peer | Version | Direction | Transport | Security | TCP | UDP | Result |
|---|---|---|---|---|---|---|---|
| xray-core | 26.3.27 | peer client → Splicore server | raw TCP | auto | PASS | PASS | PASS |
| xray-core | 26.3.27 | Splicore client → peer server | raw TCP | auto | PASS | PASS | PASS |
| sing-box | 1.14.2 | peer client → Splicore server | raw TCP | auto | PASS | PASS | PASS |
| sing-box | 1.14.2 | Splicore client → peer server | raw TCP | auto | PASS | PASS | PASS |
| mihomo | 1.19.32 | peer client → Splicore server | raw TCP | auto | PASS | PASS | PASS |
| xray-core | 26.3.27 | peer client → Splicore server | raw TCP | aes-128-gcm | PASS | PASS | PASS |
| xray-core | 26.3.27 | Splicore client → peer server | raw TCP | aes-128-gcm | PASS | PASS | PASS |
| sing-box | 1.14.2 | peer client → Splicore server | raw TCP | aes-128-gcm | PASS | PASS | PASS |
| sing-box | 1.14.2 | Splicore client → peer server | raw TCP | aes-128-gcm | PASS | PASS | PASS |
| mihomo | 1.19.32 | peer client → Splicore server | raw TCP | aes-128-gcm | PASS | PASS | PASS |
| xray-core | 26.3.27 | peer client → Splicore server | raw TCP | chacha20-poly1305 | PASS | PASS | PASS |
| xray-core | 26.3.27 | Splicore client → peer server | raw TCP | chacha20-poly1305 | PASS | PASS | PASS |
| sing-box | 1.14.2 | peer client → Splicore server | raw TCP | chacha20-poly1305 | PASS | PASS | PASS |
| sing-box | 1.14.2 | Splicore client → peer server | raw TCP | chacha20-poly1305 | PASS | PASS | PASS |
| mihomo | 1.19.32 | peer client → Splicore server | raw TCP | chacha20-poly1305 | PASS | PASS | PASS |
| xray-core | 26.3.27 | peer client → Splicore server | raw TCP | none | PASS | PASS | PASS |
| xray-core | 26.3.27 | Splicore client → peer server | raw TCP | none | PASS | PASS | PASS |
| sing-box | 1.14.2 | peer client → Splicore server | raw TCP | none | PASS | PASS | PASS |
| sing-box | 1.14.2 | Splicore client → peer server | raw TCP | none | PASS | PASS | PASS |
| mihomo | 1.19.32 | peer client → Splicore server | raw TCP | none | PASS | PASS | PASS |
| xray-core | 26.3.27 | peer client → Splicore server | TCP+verified TLS | auto | PASS | PASS | PASS |
| xray-core | 26.3.27 | Splicore client → peer server | TCP+verified TLS | auto | PASS | PASS | PASS |
| sing-box | 1.14.2 | peer client → Splicore server | TCP+verified TLS | auto | PASS | PASS | PASS |
| sing-box | 1.14.2 | Splicore client → peer server | TCP+verified TLS | auto | PASS | PASS | PASS |
| mihomo | 1.19.32 | peer client → Splicore server | TCP+verified TLS | auto | PASS | PASS | PASS |
| xray-core | 26.3.27 | peer client → Splicore server | TCP+verified TLS | aes-128-gcm | PASS | PASS | PASS |
| xray-core | 26.3.27 | Splicore client → peer server | TCP+verified TLS | aes-128-gcm | PASS | PASS | PASS |
| sing-box | 1.14.2 | peer client → Splicore server | TCP+verified TLS | aes-128-gcm | PASS | PASS | PASS |
| sing-box | 1.14.2 | Splicore client → peer server | TCP+verified TLS | aes-128-gcm | PASS | PASS | PASS |
| mihomo | 1.19.32 | peer client → Splicore server | TCP+verified TLS | aes-128-gcm | PASS | PASS | PASS |
| xray-core | 26.3.27 | peer client → Splicore server | TCP+verified TLS | chacha20-poly1305 | PASS | PASS | PASS |
| xray-core | 26.3.27 | Splicore client → peer server | TCP+verified TLS | chacha20-poly1305 | PASS | PASS | PASS |
| sing-box | 1.14.2 | peer client → Splicore server | TCP+verified TLS | chacha20-poly1305 | PASS | PASS | PASS |
| sing-box | 1.14.2 | Splicore client → peer server | TCP+verified TLS | chacha20-poly1305 | PASS | PASS | PASS |
| mihomo | 1.19.32 | peer client → Splicore server | TCP+verified TLS | chacha20-poly1305 | PASS | PASS | PASS |
| xray-core | 26.3.27 | peer client → Splicore server | TCP+verified TLS | none | PASS | PASS | PASS |
| xray-core | 26.3.27 | Splicore client → peer server | TCP+verified TLS | none | PASS | PASS | PASS |
| sing-box | 1.14.2 | peer client → Splicore server | TCP+verified TLS | none | PASS | PASS | PASS |
| sing-box | 1.14.2 | Splicore client → peer server | TCP+verified TLS | none | PASS | PASS | PASS |
| mihomo | 1.19.32 | peer client → Splicore server | TCP+verified TLS | none | PASS | PASS | PASS |

40 mode/transport/direction rows, 120 IPv4/domain/IPv6 host subtests. Every host transfers 131,071 TCP bytes and four real UDP datagrams. Xray and sing-vmess are independent runtime families; Mihomo/sing-box active libraries are related and are not counted as independent families. Official peer hashes, actual version/help output and exclusive configs/logs are retained. The final matrix uses the final VMess wire/runtime bytes without a diagnostic overlay; later import validation and formatting edits are recorded separately and covered by final-source tests.

## Mihomo Compatibility

Client direction PASS for all4 mode labels ×raw/TLS×IPv4/domain/IPv6. Readiness waits for Match rule load, not merely a listening socket; no traffic retry. Actual exported raw auto config also loaded and returned TCP/UDP. Explicit CA export remains rejected rather than weakened; interop uses a synthetic local CA fingerprint for that peer.

## Legacy Compatibility Probe

alterId>0: DEFERRED / UNSUPPORTED. Actual sing-box/Mihomo positive-ID attempts return no target payload. Xray ignores its obsolete config field and modern traffic succeeds through the AEAD-only native decoder; pinned MemoryAccount has no alterId. Splicore URI/config explicitly reject legacy intent. No P19-LEGACY-DECISION expansion was necessary.

## Fuzz

| Target | Duration | Executions | Interesting inputs | Crashes | Timeouts |
|---|---:|---:|---:|---:|---:|
| FuzzAuthID | 30s | 1021586 | 1 | 0 | 0 |
| FuzzAEADHeader | 30s | 820556 | 6 | 0 | 0 |
| FuzzRequestModel | 30s | 1313304 | 8 | 0 | 0 |
| FuzzResponse | 30s | 1053944 | 5 | 0 | 0 |
| FuzzAESChunk | 30s | 655122 | 7 | 0 | 0 |
| FuzzChaChaChunk | 30s | 509859 | 12 | 0 | 0 |
| FuzzNoneChunk | 30s | 799498 | 5 | 0 | 0 |
| FuzzUDPChunks | 30s | 555414 | 14 | 0 | 0 |
| FuzzVMessURI | 30s | 237644 | 57 | 0 | 0 |

Nine distinct cipher/parser targets cover all seven required surfaces, with actual mutations (6,966,927 executions total). No crash, unexplained hang or unbounded allocation observed. External build cache/corpus; no raw fuzz logs committed.

## Race

### Targeted
PASS wire/backend, native modes/lifecycle/half-close/idle/auth, managed/import/export/diagnostics, API/provider/policy/backup.
### Default
PASS full `go test -race -count=1 ./...` in isolated loopback namespace.
### Native
PASS full tags `with_gvisor,with_quic,with_utls` race suite.
### Shared
PASS complete shared network/IO/protocol race suite. Full plain default tests PASS as well. Commands/UTC/durations/env/exit recorded per gate.

## Checkptr

ON. No -d=checkptr=0 or suppression. Exact Go1.26.6 compiler Debug.Checkptr=1 source hash and -race binary metadata retained in module audit. GORACE exit_sleep_ms=0 applies only to lab process exit waiting; detection remains enabled.

## Resource Lifecycle

Resource metrics use separate, explicitly scoped probes; peaks are sampled, not mathematical maxima. Focused native listener lifecycle: goroutines4→4, FD9→9, sessions/associations/workers/listeners0 at stop; replay peak150 and0 after injected expiry. 10,000 real sessions: goroutines5→4, FD10→9, replay peak60,000 and0 after injected expiry; registry/sessions0. Shared target churn10000 and competition1000 are exercised in the full/shared race gates. No confirmed socket/goroutine/eventfd/session/association/replay ownership leak.

| Resource / probe | Start | Sampled Peak | End |
|---|---:|---:|---:|
| Native goroutines (x25) | 4 | 5 at cycle samples | 4 |
| Native FD (x25) | 9 | not continuously sampled | 9 |
| Native replay (x25) | 0 | 150 | 0 after expiry |
| Native replay (10k) | 0 | 60000 | 0 after expiry |
| Native registry/sessions (10k) | 0 | 1 at thousand-cycle samples | 0 |

The real TUN start/peak/end table below adds FD/eventfd/listener/session/association worker/RSS/generation/lease sampling. Live-window replay entries intentionally survive listener shutdown; focused bank snapshots measure their eventual cleanup.

## Lifecycle x25

PASS focused native raw/TLS/modes/users lifecycle and backend blocking/partial/parent contracts. race/native-corrected-fixture plus final native/full/shared gates. Initial FD diagnostic failure came from the Go echo fixture splice pipe pool; explicit joined echo IO removed fixture descriptors. Original failures retained.

## Native TUN x25

| Resource | Start | Sampled Peak | End |
|---|---:|---:|---:|
| Goroutines | 13 | 33 | 13 |
| FDs | 21 | 25 | 21 |
| SocketFDs | 10 | not sampled | 10 |
| EventFDs | 1 | 1 | 1 |
| Listeners | 9 | 9 | 9 |
| Sessions | 0 | 1 | 0 |
| TCPActive | 0 | 0 | 0 |
| UDPActive | 0 | 1 | 0 |
| SharedTargetReaders | 0 | 1 | 0 |
| SharedIdleWorkers | 0 | 1 | 0 |
| RSSKiB | 95240 | 185912 | 173948 |
| Generations | 1 | 1 | 1 |
| Leases | 1 | 1 | 1 |
| HostGenerations | 0 | not sampled | 0 |
| Interfaces | 0 | not sampled | 0 |
| JournalTemporaries | 0 | not sampled | 0 |

SharedTargetReaders represent target associations/readers; SharedIdleWorkers represent their timers. TCPActive/UDPActive are VMess plus other server counters in mixed scope. Session/worker/association terminal values and host generation/temporary/interface cleanup are checked. Sampled RSS may warm and fluctuate; no RSS equality gate is claimed.
Evidence: tun/lifetime25-final; 25 complete stop/start cycles, eight VMess mode/user nodes, IPv4/IPv6 TCP/UDP, DNS/routing/policy. Lab profiles use raw TCP for auto/ChaCha and TLS for AES/none, with both users in each selected mode; the native and external matrices independently cover every mode with both transports. This run preceded the final nested TLS import validation and formatting changes; VMess wire/runtime and this lab were unchanged. Full plain/default/native/shared race gates and the ten-minute mixed lab use the final Go-source snapshot. Original slower run interrupted deliberately after first validated cycle to adjust only race process exit sleep; raw record remains FAIL/interrupted. Entire optimized x25 rerun is the gate.

## Mixed Stress

| Resource | Start | Sampled Peak | End |
|---|---:|---:|---:|
| Goroutines | 38 | 197 | 38 |
| FDs | 31 | 69 | 31 |
| SocketFDs | 20 | not sampled | 20 |
| EventFDs | 1 | 1 | 1 |
| Listeners | 15 | 15 | 15 |
| Sessions | 0 | 15 | 0 |
| TCPActive | 0 | 0 | 0 |
| UDPActive | 0 | 5 | 0 |
| SharedTargetReaders | 0 | 1 | 0 |
| SharedIdleWorkers | 0 | 1 | 0 |
| RSSKiB | 170376 | 311584 | 282220 |
| Generations | 1 | 8 | 1 |
| Leases | 1 | 8 | 1 |
| HostGenerations | 0 | not sampled | 0 |
| Interfaces | 0 | not sampled | 0 |
| JournalTemporaries | 0 | not sampled | 0 |

SharedTargetReaders represent target associations/readers; SharedIdleWorkers represent their timers. TCPActive/UDPActive are VMess plus other server counters in mixed scope. Session/worker/association terminal values and host generation/temporary/interface cleanup are checked. Sampled RSS may warm and fluctuate; no RSS equality gate is claimed.
Duration/workload/security counts: 
```text
vmess_tun_lab_linux_test.go:284: mixed VMess(all modes/two users/raw+TLS)/Trojan/SS/SS2022/Snell/HY2/TUIC/VLESS/Mieru TUN TCP/UDP IPv4/IPv6 routing/policy/proxied DNS duration=18m10.04107104s rounds=11 actual_target_expirations=11 same_association_recreations=11 expected_security_rejections=352 unexpected_errors=0 start={qfTUNResources:{Goroutines:38 FDs:31 SocketFDs:20 EventFDs:1 Listeners:15 Sessions:0 Generations:1 Leases:1 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:170376} TCPActive:0 UDPActive:0 TCPTotal:3 UDPTotal:2 SharedTargetReaders:0 SharedIdleWorkers:0} peak={qfTUNResources:{Goroutines:197 FDs:69 SocketFDs:20 EventFDs:1 Listeners:15 Sessions:15 Generations:8 Leases:8 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:311584} TCPActive:0 UDPActive:5 TCPTotal:563 UDPTotal:332 SharedTargetReaders:1 SharedIdleWorkers:1} stopped={qfTUNResources:{Goroutines:38 FDs:31 SocketFDs:20 EventFDs:1 Listeners:15 Sessions:0 Generations:1 Leases:1 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:282220} TCPActive:0 UDPActive:0 TCPTotal:33 UDPTotal:22 SharedTargetReaders:0 SharedIdleWorkers:0}
vmess_tun_lab_linux_test.go:300: VMess auth security metrics={Accepted:88 DuplicateRejected:88 InvalidClockRejected:88 InvalidAuthRejected:88 BadTagRejected:88 Unexpected:0}
```

Required final-source workload is at least10 minutes: VMess all modes/two users/raw+TLS, Trojan, SS, SS2022, Snell, HY2, TUIC, VLESS, Mieru, real Native TUN IPv4/IPv6 TCP/UDP, Routing/DNS/Policy. Valid acceptance and duplicate/clock/auth/tag failures are separate counters; no failed traffic retry. Actual target idle/recreation companions included. Kernel target TCP/UDP leaks must be0. Existing source seal records all Go/module bytes for final comparison.

The successful final run records 18m10.041s of timed stress and 1207.003s total job time including setup/warm-up/teardown. The 11 rounds, 88 valid authentications and 352 expected rejections include one warm-up round and ten timed rounds. Final resources: goroutines38→38, FD31→31, eventfd1→1, sessions/target readers/idle workers0; kernel target TCP0/UDP0. The timer is checked between complete traffic rounds; the run exceeds its ten-minute minimum. RSS170376→peak311584→282220 KiB is sampled resident memory after warm-up, not a retained-heap or equality measurement.

## VMess Stress

### Auth churn
1,000 actual invalid auth/clock/tag/truncated handshakes, 32 pending shutdown readers, clean resources; 5,000 invalid AuthID candidate trials at16 users.
### Replay
22,000 unique wire admissions: 21,845 valid,155 capacity rejects;22,000 duplicate rejects;22,000 clock-invalid rejects;peak65,535/final0;unexpected accepts0. Race-enabled duration19.526s and allocated total2,476,185,112 bytes across all request/KDF/oracle loops, not retained memory.
### TCP
10,000 actual native session cycles; percycle TCP128 bytes plus four UDP datagrams. Native all-mode traffic uses131,071 bytes; external rows total15,728,520 TCP application bytes each direction.
### UDP
10,000 cycles with1/128/8192/16000-byte datagrams, actual replies, terminal cleanup. Native idle5s followed by replacement actual reply. Shared reader/old-owner/idle companions verify registry identity.
### User rotation
Native old/new auth and managed/API/provider held-generation/unrelated-user tests PASS.
### Lifecycle
Focused churn46.788s for10,000 cycles (race job72.343s including build); frame/deadline/Close/parent/TLS tests cover strong deterministic equivalents. Rough sanity:244,490,000 application bytes in each direction across combined TCP/UDP churn, about5.2MB/s during this race/local fixture workload. This is not a comparative performance benchmark or TCP-only throughput claim.

## Existing Protocol Regression

SS, SS2022, Snell, HY2, TUIC, VLESS, Mieru, Trojan, DIRECT and REJECT remain PASS in full default/native/shared suites and mixed real TUN workload. The extra legacy uncadenced TestQF001TUNBoundedStress FAILED again; its finite Snell admission saturation is the same pre-existing Phase18 limitation and is not relabelled PASS. Actual QF001 deterministic x100 and bounded mixed traffic are the regression gates. Diagnostic cap analysis and unchanged frozen Snell source evidence are retained. No old protocol/runtime source was rewritten.

## Historical Finding Regression

| Finding | State | New Phase19 evidence |
|---|---|---|
| R17-001 | CLOSED | original VLESS lifecycle x25 / shared IO gates |
| R17-002 | CLOSED | unchanged cryptographic randomness / HY2 suite |
| R17-003 | CLOSED | unchanged canonical HY2 contract / full regression |
| RR17-001 | CLOSED | original TUIC backpressure cancellation x25 |
| RR17-002 | CLOSED | original HY2 backpressure cancellation x25 |
| VLESS_PARTIAL_FRAME | CLOSED | independent partial deadline x25 |
| VLESS_ASSOCIATION_REGISTRY | CLOSED | independent closed association churn x25 |
| T18R-001 | CLOSED | preserved deterministic completion copy x100, real TLS/Trojan reply/old-owner/timer companions x100, shared target churn |

QF-001 WritePacket ownership: PASS deterministic x100 plus bounded real mixed TUN UDP traffic. Extra uncadenced Snell overload remains FAIL / pre-existing admission limit, separately diagnosed. QF-002 eventfd: PASS complete lifetime FD x25. Original authorized dialer-only T18 copy x25 still exhibits the previously documented early Read signal race; its failure is retained, not relabelled PASS. Existing Phase18 T18RR-001 note and saved cleanup-completion fixtures explain this distinction; production cleanup and real replies remain proven. No historical artifact was edited.

## SagerNet Audit

Source0 / Direct0 / Full graph0 / Binary metadata0. `audits/module-summary.json` and `final-source/audits/summary.json`; all three final production binaries audited. External sing-box peer/oracle is outside the module; not counted as a production dependency.

## Module Identity

`github.com/ike-sh/Splicore`; minimum Go1.26.3 unchanged; actual Go1.26.6. No replace directive. go.mod/go.sum unchanged. go mod verify PASS; checkptr ON.

## Dependencies Added

NONE. Existing x/crypto used. No new major crypto/runtime package, Go minimum increase or vendored core. License/notice files remain unchanged and95 copied notice files match the official dependency cache.

## Upstream Modifications

gVisor0; Mieru0; quic-go0; Xray0; sing-box0; other0 local upstream changes. External study/oracle/peer binaries do not modify production sources. Module verification PASS.

## Underlay

Previous75 production surfaces; new VMess4; final79 production /165 test surfaces; Unknown0. Reviewed new local listener/protected outbound/protected TCP+UDP target paths and construction invariants. Initial missing-inventory failure retained; four actual additions reconciled without ignoring unknown calls.

## Xray Boundary

Active runtime0; external interop only YES. Actual complete classified source/test/tool/doc audit **E=0/F=0/G=16** (previous10 +6 new test/oracle peer textual surfaces); production G remains5. No supervisor/downloaded production artifact/config execution path. FinalMask runtime0; Sudoku runtime0; Vision DEFERRED. External Xray and its oracle are categoryG. No Xray exporter expansion was needed; existing serialization stays bounded.

## Platform Builds

Linux amd64 PASS; Windows amd64 PASS genuine native implementation; Linux arm64 PASS **BUILD ONLY**. Windows safe loopback/wire/lifecycle tests PASS, no host TUN/route mutation. Binary module metadata captures retained. No arm64 execution or runtime certification claimed.

## Platform Qualification

Historical **PARTIALLY PASSED**. Phase18 frozen base **NOT REQUALIFIED**. Current Phase19 **NOT PLATFORM QUALIFIED**. Linux arm64 **BUILD ONLY**. All historical qualification gaps remain OPEN. Protected qualification report hash unchanged; no full qualification run.

## Documentation

[Native VMess runtime](../architecture/VMESS_RUNTIME.md), architecture index and this report. Pre-implementation external specification/current peer/payload/data-option matrices retained; final observed matrix and limitations in this report. Old review/fix/freeze/qualification reports preserved.

## ADR

[0040 modern VMess and replay/clock ownership](../adr/0040-modern-vmess-and-replay-clock-ownership.md): **Proposed**, real compatibility/replay ownership decision. No Accepted/review/freeze status advance.

## Findings

### P19-001

Surface: none TCP.

Observation: Current sing-vmess emits unframed none/TCP.

Risk: Rejecting it prevents current compatibility.

Decision: Accept modern authenticated header with none/options0/TCP only.

Implementation: Separate raw/framed Conn path.

Regression evidence: native/external allmode raw/TLS and half-close.

### P19-002

Surface: Response options.

Observation: Xray sends0; current sing-vmess echoes request options.

Risk: Overstrict declaration rejects valid peers.

Decision: Accept0 or exact echo, reject unrelated options/commands.

Implementation: ReadResponse validation.

Regression evidence: response declaration unit and final40-row matrix.

### P19-003

Surface: Authenticated length.

Observation: Current optional construction reuses request contexts across directions.

Risk: Required nonce-separation invariant conflicts.

Decision: DEFERRED/reject; no invented cipher.

Implementation: Request/options validation.

Regression evidence: valid-checksum rejection/default independent peer traffic.

### P19-004

Surface: Standard UDP/Xray.

Observation: Default cone mode can select Mux.

Risk: Could misclassify unsupported extensions as failed standard UDP.

Decision: Pin standard command2 via XRAY_CONE_DISABLED; Mux/XUDP deferred.

Implementation: External peer env only.

Regression evidence: finalbidirectional4mode raw/TLS UDP matrix.

### P19-005

Surface: Domain UDP reply.

Observation: Target socket reports resolved numeric source.

Risk: Exact domain comparison would blackhole replies.

Decision: Server-bound domain same-port numeric metadata maps to bound destination.

Implementation: Packet server-aware metadata check; outbound exact target retained.

Regression evidence: backend durable domain reply test / three-peer domain UDP.

### P19-006

Surface: External UDP size.

Observation: Peer SOCKS frontends have smaller limits than native datagram framing.

Risk: Large frontend failures could become false native limits.

Decision: Record practical1200-byte peer matrix and16000 native separately.

Implementation: Harness sizes; no native limit coercion.

Regression evidence: originalfailedattempts plus finalactualreplymatrix/native16k.

### P19-007

Surface: Resource fixture.

Observation: Go TCP echo splice pool retained pipe descriptors.

Risk: FD fixture cache resembled socket leak.

Decision: Use explicit IO with joined fixture sockets.

Implementation: VMess-specific echo helper; old artifacts untouched.

Regression evidence: rawFD maps; finalx25 FD9→9.

### P19-008

Surface: Mihomo readiness.

Observation: SOCKS listens before rule configuration finishes.

Risk: First payload may hit unloaded routing.

Decision: Wait controller Match rule; no traffic retries.

Implementation: Interop readiness condition.

Regression evidence: attempts1–3 retained; finalallmode IPv4/domain/IPv6 PASS.

### P19-009

Surface: Packet shutdown.

Observation: Conn directional joins alone do not join send cancellation tail.

Risk: Close could return before admitted operation callback completes.

Decision: Packet owns admission waitgroup and parent callback completion.

Implementation: Interrupt socket then join writes/callback/Conn.

Regression evidence: backendL1/L2/L5 and finalrace/shared/TUN.

### P19-010

Surface: Legacy probe.

Observation: Xray ignores obsolete alterId field; sing families actually select legacy.

Risk: Config acceptance can be misreported as legacy wire support.

Decision: Keepmodernonly; classify actual field-ignore separately.

Implementation: No legacy parser/coercion added.

Regression evidence: exporter-and-legacy-run5 actualtraffic + URIstrictreject.

### P19-011

Surface: Historical fixture barrier.

Observation: Dialer-corrected T18 fake signals before terminal Read returns.

Risk: Immediate retry assertion can race legitimate retirement.

Decision: Preserve original failure and reuse already saved completion companions.

Implementation: No Phase19 relay/source/fixture assertion weakening.

Regression evidence: completionx100 plus real TLSreplyx100; T18RR-001 historicalNOTE.

### P19-012

Surface: Nested TLS configuration import.

Observation: encoding/json accepts case-folded field aliases; conflicting insecure/verification declarations could collapse before validation.

Risk: Unsupported or ambiguous TLS intent could be silently coerced.

Decision: Require exact nested TLS names and reject null scalar flags/names, aliases and extensions; preserve optional null ALPN/certificate arrays emitted by our exporter.

Implementation: VMess external importer field whitelist before producing generic verified TLS settings.

Regression evidence: TestExternalTLSConflictingFields, race/final-tls-import, and all final-source test gates.

### P19-013

Surface: Existing Snell admission limit.

Observation: Extra uncadenced QF TUN workload hit the frozen 256-socket registry cap; one UDP association owns two entries.

Risk: Offered load above the finite admission bound produces resets/timeouts.

Decision: Preserve failure and capacity bounds; distinguish overload from the required WritePacket ownership regression.

Implementation: Diagnostic-only overlay observes rejection at256; frozen Snell source is byte-identical, no production change.

Regression evidence: tun/qf001-final FAIL; diagnostic/qf-cap2 FAIL as expected, diagnostic/qf-cap-analysis2.json confirms cap; deterministic QF001x100 PASS and bounded mixed gate.

## Known Limitations

Legacy alterId/non-AEAD, zero/CFB, optional authenticated length, connection reuse, unsupported transports, Mux/XUDP/packetaddr/uTLS/REALITY remain unsupported/deferred. Xray standard UDP requires selected cone-disabled baseline. External frontend datagram sizes, Mihomo client-only direction, exact pinned exporter versions and unavailable core URI generators are explicit. URI/Mihomo explicit CA and URI UDP-disabled export reject loss. Maximum16 users,512 accepted sockets,65536 replay tokens and shared128 targets bound work; full replay bank denies new requests until expiry. Existing Snell socket registry256 (two entries per UDP association) rejects uncadenced overload, observed again in the preserved extra QF lab. In-process replay and rollback high-water can deny service after major clock jumps; restart persistence is absent. Sampled metrics and local scoped implementation tests do not close historical platform gaps.

## Secret Scan

real0 / unresolved0 in complete tracked+untracked repository and external Phase19 evidence. Synthetic UUID/TLS/URI/export/log candidates classified by file/line hashes without matched values. Three existing strong test fixtures require reviewed whole-file byte identity. Final scans regenerated after report. No live user nodes/subscriptions used.

## Blockers

NONE.

## Git Actions

stagedNO / committedNO / pushedNO / taggedNO / releasedNO / frozenNO. IndexEMPTY; HEAD unchanged. No automatic independent review or Phase20.

## Public GitHub

UNCHANGED by this work. No public write, push, tag or release action; user-designated v0.1.0 public release left untouched.

## NoBrand-OneClick

NOT ACCESSED. No scan, read, write or integration against that project.

## Evidence Integrity

External raw evidence and all earlier failed/interrupted attempts retained. Final protected comparison covers6884 historical/review/fix/freeze artifacts; source/report/evidence hashes and command chronology retained outside Git. Go/module source bytes are compared against runtime-source snapshot. Raw binaries/configs/logs remain outside repository.

# PHASE 19 READY FOR REVIEW


# Review Fix Round 1

## Independent Review History

The initial independent review verdict was **PHASE 19 REVIEW FAILED**:
P19R-001 MAJOR (managed JSON alias collapse), P19R-002 MAJOR (pre-read authentication clock),
and P19R-003 MAJOR (external preview reason collapse). The original report and all evidence
remain sealed at `D:/splicore-validation/phase19-vmess-review-20261007/`.

## Fix Result

**PHASE 19 READY FOR RE-REVIEW**.
P19R-001, P19R-002 and P19R-003 are **FIXED — PENDING RE-REVIEW**, never CLOSED here.

- Bounded VMess raw-object/presence checks reject exact duplicates and unequal existing
  case aliases before struct decoding; equal aliases still undergo semantic validation.
  URI/external exact field whitelists remain exact. Mihomo SNI ambiguity is classified.
- Native authentication samples the existing compiler clock after complete AuthID ReadFull.
  Inclusive120-second skew, independent5-second deadline and atomic replay bank are retained.
- Typed redacted causes survive URI/config/canonical/provider/API/CLI preview. Strict rejected
  previews issue no apply token; lenient plans apply only valid candidates.
- Original alias/API reproductions race x25 PASS; authorized clock synchronization copy x100
  PASS with old-source negative control. The exact original clock fixture's now-impossible
  pre-send barrier failure is preserved, with explicit user authorization for its companion.
- Final default/default race/native race/shared race PASS; checkptr ON;9 fuzz targets30s each,
  6,708,691 mutations; representative external TCP/UDP smoke PASS; real native TUN x25 PASS;
  mixed workload11m5.072238602s,224 expected rejections,0 unexpected errors,0 DNS leaks.
- An initial Mihomo first IPv4 SOCKS EOF is preserved. Five fullTLS repeats pass; the same EOF
  also occurs with the pre-fix native auth path. Its exact peer/startup trigger is unproven;
  the fix scope does not expand. Original Snell PRE-EXISTING NON-BLOCKING LIMIT remains.
- Linux amd64/Windows amd64/Linux arm64 builds PASS; arm64 BUILD ONLY. SagerNet0/0/0/0,
  Underlay Unknown0, new dependencies0, migrationsNONE, secret real0/unresolved0.

Full report and raw evidence: `D:/splicore-validation/phase19-vmess-review-fix1-20261007/`.
Historical qualification **PARTIALLY PASSED**; Phase19 **NOT PLATFORM QUALIFIED**.
ADR0040 remains Proposed. HEAD/index unchanged; worktree DIRTY/UNSTAGED. No stage/commit/push/
tag/release/freeze/public GitHub write, NoBrand-OneClick access, independent re-review or Phase20.

# Final Review Chronology and Freeze Metadata — 2026-10-08

## Current Implementation Status

**PHASE 19 IMPLEMENTATION REVIEWED**.
The earlier sections retain their original stage-specific verdicts and evidence;
this section records the final accepted state and is authoritative for status.

| Stage | Recorded result |
|---|---|
| Implementation | READY FOR REVIEW |
| Initial Independent Review | FAILED; P19R-001/002/003 MAJOR |
| Fix Round 1 | READY FOR RE-REVIEW; three findings FIXED — PENDING RE-REVIEW |
| First Re-Review | FAILED; P19R-001/002/003 CLOSED; P19RR-001 MAJOR OPEN |
| Fix Round 2 | P19RR-001 RESOLVED — PENDING RE-REVIEW |
| Final Independent Re-Review | PASSED — READY TO FREEZE; all four findings CLOSED; new BLOCKER=0/MAJOR=0 |

P19R-001 preserves raw member presence, duplicate/conflicting alias rejection and
order-independent validity. P19R-002 reads the complete AuthID before fresh clock
validation; delayed expired authentication has target dial/bytes/reply=0. The
original stale-clock authenticated reply and original fixture failure remain
preserved. P19R-003 retains typed redacted causes across parser, service, preview
and apply; strict rejected previews have no apply token.

P19RR-001: **CLOSED — HARNESS / MIHOMO STARTUP READINESS ARTIFACT**.
Original clean-start20 had18 success/2 EOF with IPv4 always first, initially
conflating startup and address family. IPv4/domain/IPv6 first can fail; later
flows succeed. Failed windows precede VMess admission and target traffic.
Mihomo `/rules` availability does not establish TCP admission readiness. The
same startup behavior reproduced against Splicore, Xray and sing-box; corrected
readiness gives each25/25 attempts and75/75 actual target replies. The corrected
repository harness's100 saved Mihomo repetitions pass. Splicore production fix:
**NONE**; no sleep/retry/peer special case/wire/runtime change. The same-config
configuration completion transaction is test-harness readiness, never a business
traffic retry. The previous Match-rule-only readiness conclusion is historical.

Final fixed-source evidence:9 fuzz targets,30s each,**6,708,691 mutations**,
crashes0/timeouts0; default/native/shared race PASS, checkptr ON; real TUN x25
PASS; mixed stress **11m5.072238602s**,224 expected security rejections,
unexpected0/DNS leaks0. The initial6,966,927 fuzz and18m10s stress remain historical.
The extra uncadenced Snell QF failure remains **PRE-EXISTING NON-BLOCKING LIMIT**.

Canonical local reports (all original failures/evidence retained):

- Initial Review: `D:/splicore-validation/phase19-vmess-review-20261007/PHASE19_VMESS_REVIEW_REPORT.md`
- Fix1: `D:/splicore-validation/phase19-vmess-review-fix1-20261007/PHASE19_VMESS_REVIEW_FIX1_REPORT.md`
- First Re-Review: `D:/splicore-validation/phase19-vmess-rereview-20261007/PHASE19_VMESS_REREVIEW_REPORT.md`
- Fix2: `D:/splicore-validation/phase19-vmess-rereview-fix2-20261007/PHASE19_VMESS_REREVIEW_FIX2_REPORT.md`
- Final Review: `D:/splicore-validation/phase19-vmess-final-rereview-20261008/PHASE19_VMESS_FINAL_REREVIEW_REPORT.md`
- [Canonical Freeze identity and scope](PHASE19_NATIVE_VMESS_FREEZE_REPORT.md).

Freeze identity is the single commit containing the canonical Freeze report;
actual hash, final verdict and postcommit verification are resolved externally
in `D:/splicore-validation/phase19-native-vmess-freeze-20261008/` after success.
This metadata does not assert commit success during preparation. ADR0040 remains
Proposed: independent acceptance of its status is not explicitly established.
Qualification remains PARTIALLY PASSED historically, Phase19 NOT REQUALIFIED /
NOT PLATFORM QUALIFIED; Linux arm64 BUILD ONLY. No platform gap is closed.
