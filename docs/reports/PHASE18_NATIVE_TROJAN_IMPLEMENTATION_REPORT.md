# Splicore Phase 18 Native Trojan Implementation Report

## Verdict

**PHASE 18 IMPLEMENTATION REVIEWED**

Current state: final independent re-review **PASSED**; T18R-001 **CLOSED**, new BLOCKER=0 and MAJOR=0. The authorized local Phase 18 freeze completed after exact-index EOL recovery and is recorded in [the canonical Freeze report](PHASE18_NATIVE_TROJAN_FREEZE_REPORT.md). Original implementation/review/fix handoffs and their Git states remain historical records below. Historical platform qualification remains **PARTIALLY PASSED**; Phase 18 remains **NOT PLATFORM QUALIFIED**; arm64 remains **BUILD ONLY**. No publication or release is performed.

Initial implementation evidence root: `D:/splicore-validation/phase18-native-trojan-20261007/`. Current Review Fix Round 1 evidence root: `D:/splicore-validation/phase18-trojan-review-fix1-20261007/`. Raw output, command arguments, UTC start, actual exit and elapsed time are retained in each `.log` / `.result.json` pair. Diagnostic failures are retained and separately explained below. The report contains no password, digest, raw credential URI or private key value.

## Base

| Item | Verified state |
|---|---|
| Frozen base / current HEAD | `dabe4030fb82f272b8e1035779e2b8c4da9b0600` |
| Base message | `feat(core): establish independent core with native shadowsocks` |
| Branch | `codex/phase-18-native-trojan` |
| Entry | CLEAN; index EMPTY (`entry-git.json`) |
| Handoff working tree | DIRTY / UNSTAGED |
| Index | EMPTY |
| Module | `github.com/ike-sh/Splicore` |
| Minimum Go / validation toolchain | 1.26.3 / 1.26.6 |

No reset, restore, amend, rebase or frozen-history rewrite occurred.

## Protocol

ProtocolID: **trojan**. EngineID: **native**. Wire version: `standard`; feature profile: `base`.

Active independent implementation is visible under `protocol/trojan/wire` and `protocol/trojan/backend`; configuration integration lives under `internal/splicore/protocol/trojan`. Native registry and application outbound registration expose the protocol through existing generic services.

Scope: standard TLS Trojan, server/client, TCP CONNECT, UDP ASSOCIATE, multiple users and generic management. WS, gRPC, HTTP upgrade, plaintext, mux, camouflage, fingerprint spoofing, proprietary extensions and VMess are excluded.

## Specification

Research preceded coding. `spec/TROJAN_PROTOCOL_SPEC_NOTES.md`, `spec/sources.json` and downloaded reference material record source URLs and retrieved hashes. Sources are behavior references only; their implementation source was not copied into the repository.

- [Canonical Trojan protocol](https://trojan-gfw.github.io/trojan/protocol.html).
- [Original Trojan v1.16.0](https://github.com/trojan-gfw/trojan/tree/v1.16.0).
- [Mihomo v1.19.30](https://github.com/MetaCubeX/mihomo/tree/v1.19.30).
- [sing-box v1.14.1](https://github.com/SagerNet/sing-box/tree/v1.14.1).
- [sing-box Trojan inbound and optional fallback](https://sing-box.sagernet.org/configuration/inbound/trojan/).

CONNECT=1, UDP ASSOCIATE=3. TLS precedes the application header; no Trojan success response precedes TCP payload. Addresses use IPv4/domain/IPv6 tags 1/3/4 and network-order ports. UDP frames remain inside the authenticated TLS stream.

### Compatibility decisions

| ID | Classification / decision |
|---|---|
| T18-COMPAT-001 | Canonical uint16 payload permits 0–65,535 bytes. Mihomo 1.19.30 splits/rejects above 8,192: implementation-specific behavior, not adopted. Its real peer matrix covers whole datagrams up to 8,192. Socket/IP payload limits remain independent of the wire limit. |
| T18-COMPAT-002 | Canonical CRLF delimiters are enforced. Mux 0x7f and unknown commands reject. Lenient peer parsing does not relax Splicore parsing. |
| T18-COMPAT-003 | Mihomo 1.19.30 Trojan UDP reader converts numeric addresses only; reverse domain UDP fails in that peer. Numeric IPv4/IPv6 UDP PASS. Domain UDP PASS against sing-box and self. Failed domain attempts and pinned source inspection are preserved. |

Managed passwords retain the existing 12–255 UTF-8 byte policy with no whitespace/control characters. This is a management admission policy, not an additional canonical wire field.

## Architecture

### protocol/trojan

Wire code owns request/datagram encoding, strict bounded parsing, SHA-224 derivation and constant-time authentication. Backend code owns stream/packet IO, request commit, deadlines and close. It contains no routing, account database or external-core runtime.

### Server Runtime

The compiler validates and snapshots TLS material and derives immutable user credentials. The handle owns its TCP listener, accepted raw sockets, handshake/auth workers and relay workers. Admission is capped at 512 accepted sockets. Five-second handshake/auth budgets follow existing runtime convention. Close rejects admission, cancels, closes sockets, joins workers and clears derived key bytes.

### Client Runtime

The native factory uses the shared TLS builder and protected proxy underlay. `clientio.Owner` owns pending opens and published TCP/UDP sockets. Requests are sent eagerly after verified TLS. One stream belongs to one TCP connection or UDP association; no reuse or mux is introduced.

### TLS / Authentication / Credential

Shared TLS snapshots, encrypted credentials, existing Account/Credential/Binding and Node models remain authoritative. Runtime stores only derived wire credentials; TLS private keys remain in the required owned TLS configuration. Public/profile projections contain references and redacted metadata.

### Routing

Server target dials and client proxy dials use shared protected dialers. Shared routing, DNS, policy, stats and TUN own their respective decisions; Trojan does not implement a private routing/resolver subsystem.

### Lifecycle

Parent owners close and join actual IO and cancellation callbacks. No detached datagram writer or growing client destination registry is introduced. Server sockets unregister by unique connection owner. Shared UDP targets use the existing bounded/expiring relay owner.

## Authentication

- Derivation: standard `crypto/sha256.Sum224`, encoded as 56 lowercase hex bytes, followed by CRLF.
- Comparison: `crypto/subtle` fixed-size comparisons across every configured credential; no early user-match return. Duplicate derived identities reject. No claim of perfect TLS/network side-channel resistance is made.
- Multi-user: A/B both carry TCP/UDP; per-binding shared counters attribute their traffic; wrong credentials reject. Rotation/disable/delete preserve B's credential and new-session access.
- Secret handling: passwords use the existing encrypted vault. Derived credentials are secret-equivalent and redacted. Raw headers, password URIs and private keys are excluded from ordinary API, logs, doctor and support output. Explicit authorized export remains the existing disclosure boundary.

## TLS

### Server

Go `crypto/tls` owns TLS. Shared snapshot validation checks cert/key pair, leaf/chain, validity and configured name before activation. Missing/malformed cert or key, mismatched pair and occupied listener fail cleanly. Runtime owns listener/handshake shutdown.

### Client

Verified system trust or the existing explicit CA is mandatory. The shared model provides no insecure trust option. Imported attempts to disable TLS/verification reject; `InsecureSkipVerify` is not enabled.

### SNI / Verification / Certificates

Connect address and TLS verification/server name are distinct. Valid name succeeds; wrong SNI, wrong CA, untrusted system CA, expired and not-yet-valid verification clocks reject. All certificate/key fixtures are generated synthetically at runtime or retained externally.

Static snapshots are replaced through runtime generations. `TestTrojanTLSCertificateGenerationReplacement` verifies that preparing new material leaves the old TLS snapshot usable, then replacement rejects the old CA and allows verified TCP/UDP with the new CA. Managed binding replacement/rollback is independently covered. No watcher, automatic ACME or hot reload subsystem is added.

### Handshake timeout

Server TLS/auth and client TLS/request establishment use a five-second bound, shortened by caller deadlines. Parent Close interrupts and joins pending client TLS and server pre-auth sockets.

### ALPN

Optional bounded ALPN uses the shared model. No h2/http/1.1 offer is forced; canonical Trojan has no required HTTP ALPN. URI export rejects tokens containing commas to avoid lossy reconstruction.

## Trojan Fallback Decision

**DEFERRED.** The canonical specification describes fallback, and sing-box exposes optional fallback. Phase 18 explicitly permits deferral. Invalid TLS/auth/request connections close generically. No fallback HTTP endpoint, HTTP server or camouflage behavior is supplied. This is an explicit product limitation, not a claim that fallback is absent from the canonical specification.

## Server TCP

TLS → bounded auth/request decode → protected target dial → shared full-duplex relay. Fragmented header and coalesced first payload retain exact boundaries. Runtime Stop closes and joins relay workers; shared counters track user/TCP/bytes.

## Client TCP

Routing/Node → protected TCP underlay → verified TLS → eager CONNECT → stream. Real loopback/self and both mature peers verify IPv4, IPv6 and domain TCP, including 1 MiB per destination. Server-first and client write-half close preserve reverse-direction response; full Close aborts raw IO before TLS close.

## Server UDP

UDP ASSOCIATE remains inside TLS. Each frame carries its own destination; the request destination does not restrict subsequent frames. Shared relay bounds 128 target sockets per association and expires idle targets after five seconds. Target sockets use protected ServerTarget dialing. **History:** the initial target-expiry claim was disproved by T18R-001 independent review; only association read inactivity existed then. Independent target expiry/retirement is implemented in Review Fix Round 1 below.

## Client UDP

SOCKS UDP / Native TUN / routing / policy use the native packet adapter and an authenticated TLS association. Empty payload, numeric/domain addresses and payload integrity are tested. No segmentation or custom UDP extension is introduced.

## UDP Association Lifecycle

Start/open → authenticated stream → synchronous framed IO → timeout/error/child Close/parent Close → terminal association → joined writers/readers/callbacks. Independent TLS associations survive sibling failure. Targets sharing one poisoned stream retire together; this is the minimal framing owner.

The cancellable shared queue has one admitted operation and no buffered datagram backlog. Encoded frame storage is private and immutable during IO. Queued cancellation touches no wire. Every failed admitted TLS write, including zero bytes, terminalizes its association because Go TLS memoizes write errors. EOF/deadline read failures retain socket error semantics while closing the framing owner.

## Framing

### Request

56 digest hex bytes + CRLF + command + SOCKS address/port + CRLF. Fixed auth length, one-byte domain bound, finite header and strict delimiters. Arbitrary byte fragmentation and coalescing are supported.

### TCP transition

The decoder consumes exactly the header; remaining bytes immediately belong to the target stream. There is no success response, fake handshake or mux negotiation.

### UDP packets

Address/port + big-endian uint16 length + CRLF + exactly that payload. Unit tests cover 0 through the 65,535 wire boundary, truncation, repeated/coalesced frames, malformed delimiters and invalid address/port forms. Oversized encoder input rejects. A too-small caller receive buffer consumes/drops one full datagram and returns `io.ErrShortBuffer`.

### Partial-write semantics

Failed or short request commits close the stream. Failed admitted UDP frames retire their TLS association; later writes cannot report success on a corrupted stream. Partial and zero-byte failures, dynamic deadlines, concurrent Close and parent cancellation have deterministic regression tests.

## Account / Credential

Existing generic encrypted Account/Credential/Binding storage supports creation, multiple users, references, enable/disable, rotate and delete. The existing binding endpoint/CLI gains optional generic `action=rotate` with a write-only credential and `action=delete`.

Rotation preserves credential ID and increments credential/binding revisions. Deletion atomically removes exclusively referenced binding/credential/account. Cross-inbound or other references reject and reconstruct the committed runtime. No protocol-specific account database or API is added.

All affected inbound sessions close during generation replacement, including B's active sessions when A changes. This follows the existing controlled generation architecture; B's unchanged credentials and new TCP/UDP sessions remain usable. Tests verify old/new password, disable/re-enable/delete, rollback and reference safety.

## Node

Generic stable immutable Node IDs reference encrypted remote credentials, endpoint, mandatory TLS/SNI, UDP capability and metadata. Node and Outbound remain distinct; references use IDs. Referenced deletion rejects and unreferenced deletion succeeds.

## URI

### Import

Common `trojan://` supports escaped password, IPv4/IPv6/domain, default port 443, SNI/peer, ALPN and fragment. Only known standard TLS/plain TCP parameters accept. Insecure, custom transport/fingerprint, mux, unknown and duplicate parameters reject as unsupported/invalid according to generic import classifications.

Bounds cover URI length (4,096), UTF-8, percent encoding, controls/newlines, raw userinfo delimiters, valid hosts/ports and display labels. URI, credential and request formatters redact secrets.

### Export

Only faithful exports succeed. URI rejects explicit CA, disabled UDP or comma-bearing ALPN. Sing-box supports explicit CA round trip. Mihomo uses verified CA fingerprint export; fingerprint-only imports reject because the shared model cannot reconstruct a CA from a digest.

### Round trip

URI and public-trust Mihomo/sing-box semantic round trips PASS. Canonical Node/export shape retains immutable references. Unsupported/lossy trust/transport variants reject explicitly.

## Provider

Existing preview/validate/token apply/transaction/generation/rollback services import Trojan. Tests run 20 concurrent transfers across 10 refreshes, retain a held stream, preserve stable Node IDs through credential refresh/rename, reject a failed refresh without changing committed state, preserve policy references and enforce delete safety. Source secrets enter the encrypted provider/credential path; preview/output does not retain raw passwords.

## API

Existing `/api/v1` creation, binding, node, management, export, stats and diagnostics services are reused. API and CLI share Application Service; generic binding rotate/delete extends the existing schema without adding Trojan-only routes. Optimistic revisions, operation commit and rollback are preserved.

## CLI

Actual race-binary daemon validation PASS (`cli/smoke4.log`, `cli-results.json`): URI import preview/apply, direct Node validate/plan/apply, list/get, explicit secret export, server account creation validate/plan/apply, inbound inspection and binding disable. Real interop also uses CLI account creation and per-user exports. Ordinary output was checked for password/digest absence; intentional export was checked privately.

Earlier CLI fixture attempts remain retained: a self-signed CA was rejected as a server leaf; copied private-key permissions from the Windows-mounted evidence directory required restoring 0600; the runner used `system` instead of the existing `status` command. These harness errors were corrected without weakening production validation.

## SQLite / Migration

**NONE.** Generic tables already represent passwords, TLS references, accounts, nodes and providers. New generic user writer methods perform owner-bound encryption and transactional reference checks. go.mod/go.sum, public README and existing migration files are unchanged.

## Backup / Restore

`TestPhase18TrojanBackupRestore` verifies restored stable account/node/provider IDs, credential/CA references and runtime reconstruction. SQLite bytes are checked for plaintext synthetic passwords. Existing backup vault/key ownership remains unchanged.

## Doctor

Existing validation/doctor paths identify Trojan and reject missing/invalid credential or TLS state without secret values. No dependency-internal runtime object or raw secret is exposed. Full operations/unknown-field regression gates PASS.

## Support Bundle

Trojan server/client diagnostic projections retain protocol, stable identity, TLS/SNI and shared status. The support artifact test scans for plaintext passwords, SHA-224 digests and private-key PEM; all absent. Raw password URIs are omitted. Existing generic secret redaction is reused.

## Stats

Shared traffic counters expose active/TCP/UDP sessions and bytes; server users are attributed by binding/account identity and client flows by Node/Outbound. A's traffic does not increment B's counters. No Trojan-specific stats subsystem or polling worker is introduced.

## Routing

Existing routing actions and domain/CIDR policy apply. Real TUN traffic selects every native proxy through a generic group; server target/proxy sockets remain protected. DIRECT and REJECT regression tests PASS.

## DNS

Shared DNS/bootstrap and dial abstractions apply. Real TUN TCP/UDP DNS hijack uses proxied DNS per selected protocol; bootstrap/leak sentinels remain zero. Domain TCP/UDP is independently covered against sing-box/self, without adding an ambient resolver bypass for Mihomo's domain limitation.

## Policy

Trojan participates in Selector, URL-Test, Fallback and Load-Balance, including UDP affinity. Application tests and the TUN soak's selector/generation changes PASS. No protocol-specific group implementation is added.

## Native TUN

TCP: **PASS**. UDP: **PASS**. IPv4/IPv6 and proxied TCP/UDP DNS: **PASS**.

Trojan-only real isolated kernel TUN x25 PASS; all-protocol real TUN mixed stress PASS. Tests use disposable mount/network namespaces, assert route/rule snapshot restoration, owned interface removal, session cleanup, generation/lease baselines and no journal temporaries. Host Windows TUN/qualification is not run.

## Lifecycle Matrix

| Surface | Close | Live Deadline | Parent Close | Partial Write | Registry Cleanup | Result |
|---|---|---|---|---|---|---|
| TCP stream / CONNECT commit | interrupts blocked IO | interrupts blocked IO | pending TLS + relay joined | failed request terminal | clientio unregister | PASS |
| UDP association | interrupts active/queued IO; repeat/concurrent safe | updates active/queued write | abort/join callback and IO | any admitted failure terminal | no client destination registry | PASS |
| Independent UDP sibling | independent TLS owner | independent | shared client parent closes both | other association survives | each owner closes independently | PASS |
| Server UDP target flows | shared bounded relay | shared idle/socket contract | association/runtime owns targets | association is framing owner | identity-aware expiry + close remove targets | PASS in Round 1; initial claim failed T18R-001 review |
| Server listener/auth workers | raw socket close | five-second request budget | runtime joins | malformed/truncated close | accepted socket registry empty | PASS |
| TUN/client generations | shared manager stop | shared packet contract | joined stack/device ownership | QF ownership regression | generations/leases return to baseline | PASS |

Deterministic barriers/synctest cover blocked writes, queue admission, sibling isolation and callback joins. Backend churn performs **10,000 create/use/close cycles**, logging registry=0, sessions=0, goroutines=2, FDs=7 at every 1,000-cycle sample. Parent/child competition performs 1,000 cycles; partial frame tests repeat 100 failures.

## Interoperability

External peers are isolated test processes only. Pinned versions, archive/binary hashes, raw peer output and the Splicore binary hash are in `interop/raw-final/results.json`.

| Client | Server | Peer version | TCP | UDP | TLS Verify | SNI | Result |
|---|---|---|---|---|---|---|---|
| mihomo synthetic-A | Splicore | 1.19.30 | PASS | PASS | PASS | PASS | PASS |
| mihomo synthetic-B | Splicore | 1.19.30 | PASS | PASS | PASS | PASS | PASS |
| Splicore | mihomo | 1.19.30 | PASS | PASS (numeric) | PASS | PASS | PASS |
| Splicore | Splicore | Phase18 | PASS | PASS | PASS | PASS | PASS |
| sing-box synthetic-A | Splicore | 1.14.1 | PASS | PASS | PASS | PASS | PASS |
| sing-box synthetic-B | Splicore | 1.14.1 | PASS | PASS | PASS | PASS | PASS |
| Splicore | sing-box | 1.14.1 | PASS | PASS | PASS | PASS | PASS |
| Splicore | Splicore | Phase18 | PASS | PASS | PASS | PASS | PASS |

Each row exercises 3 × 1 MiB TCP to IPv4/IPv6/domain. UDP tests use 0/1/1,400/8,192 bytes, numeric IPv4/IPv6 and domain where supported. Reverse Mihomo domain UDP is **PEER_UNSUPPORTED_T18-COMPAT-003**, not PASS; sing-box and self cover it. External two-user → Splicore rows verify A/B independently. No external production engine or module dependency is added.

## Fuzz

Actual mutation (not seed-only), all PASS. Duration column is the requested mutation budget; wall time/actual fuzzer progress remain in raw logs. Trojan URI final progress reached 46.04 seconds while minimizing interesting input; no crash occurred.

| Target | Mutation budget | Executions | Crashes | Timeouts |
|---|---:|---:|---:|---:|
| `FuzzTrojanRequest` | 45 s | 1,438,886 | 0 | 0 |
| `FuzzTrojanUDPFrame` | 45 s | 1,691,568 | 0 | 0 |
| `FuzzTrojanURI` | 45 s | 42,395 | 0 | 0 |
| `FuzzSOCKSAddress` | 30 s | 810,752 | 0 | 0 |
| `FuzzRequestAndXUDP` | 30 s | 1,088,991 | 0 | 0 |
| `FuzzCommandsAndPackets` | 30 s | 1,044,865 | 0 | 0 |
| `FuzzTCPAndDatagram` | 30 s | 1,293,069 | 0 | 0 |
| `FuzzURI` | 30 s | 26,571 | 0 | 0 |
| `FuzzFeed` | 30 s | 86,018 | 0 | 0 |

Address coverage uses the existing generic SOCKS-address target. The initial misspelled target attempt is retained and excluded from PASS counts. No Go TLS-internal fuzzing is claimed.

## Race

### Targeted

Fresh count=1 Phase18/native/protocol/import/application plus VLESS/TUIC/HY2 lifecycle targeted race PASS (32.489 s). Includes user reference rollback, provider deletion, framed write terminality, churn and owner competition.

### Default

Full `go test -race -count=1 ./...` PASS (95.424 s), including the final certificate generation replacement test.

### Native

Full `go test -race -count=1 -tags=with_gvisor,with_quic,with_utls ./...` PASS (127.956 s), after the certificate replacement regression was added. Original full native PASS is also retained.

### Shared

Full shared engine/client/packet/relay/underlay/network/runtime/address/protocol package race PASS (48.442 s). Production source remained identical; no disabling flags.

The first certificate-test build incorrectly called runtime lifecycle methods on the narrower PreparedRuntime interface; those compile failures remain in `race/native-final.log` and `tests/default-final.log`. The test now uses the actual owned native handle, and fresh final full gates pass. Production source was unaffected.

## Checkptr

**ON.** Pinned Go compiler's race instrumentation sets `Debug.Checkptr = 1`; compiler source hash and `go version -m` race metadata are recorded in `audits/module-summary.json`. No `checkptr=0`, nocheckptr build relaxation or disabling `GODEBUG` was used.

## Resource Lifecycle

Trojan-only real TUN x25 measured stopped → active work boundary → stopped. These are sampled peaks, not continuous maxima. TCP has already finished at these sample boundaries; sampled TCP active=0 does not mean no TCP traffic occurred. Trojan server UDP active corresponds to one TLS association per active UDP session.

| Resource | Start | Peak (sampled) | End |
|---|---:|---:|---:|
| Goroutines | 6 | 18 | 6 |
| FDs (all) | 14 | 18 | 14 |
| Socket FDs | 3 | not aggregated | 3 |
| eventfds | 1 | 1 | 1 |
| TCP listeners | 2 | 2 | 2 |
| Client flow sessions | 0 | 1 | 0 |
| Server TCP active (sampled) | 0 | 0 | 0 |
| Server UDP active / Trojan associations | 0 | 1 | 0 |
| Client generations | 1 | 1 | 1 |
| Underlay leases | 1 | 1 | 1 |
| Host generations | 0 | not aggregated | 0 |
| TUN interfaces | 0 | not aggregated | 0 |
| Journal temporaries | 0 | not aggregated | 0 |
| RSS KiB | 82016 | 115856 | 115856 |

Fields marked not aggregated have exact start/end observations but the x25 sampler did not aggregate their active maximum. Mixed peaks below combine the final summary with the logged active sample; they remain sampled observations.

The stopped client manager intentionally retains one disabled generation and lease, plus its journal descriptor. CLOSED state is checked separately by QF-002: FD **6/6/6**, eventfd **1/1/1**, goroutines **2/2/2** across 25 complete device/dispatcher lifetimes. No allowance hides a per-lifetime retained eventfd. Registry/association closure is additionally verified in native x25 and backend churn tests.

RSS is measured under race instrumentation and retained allocator/TLS/runtime caches. It is not expected to equal warmed start RSS; no platform memory certification is claimed. FD/goroutine/listener/session/ownership baselines, including every stopped TUN cycle, are enforced exactly by assertions.

## x25 Lifecycle

- Native Trojan server/client TCP/UDP start/close x25: PASS, listener/session/connection registry empty after every stop.
- Real Trojan TUN complete client lifetime x25: PASS, 229.624 s runner wall time; 25 route/rule/interface/resource restorations.
- QF-002 dispatcher/device FD/eventfd lifetime x25: PASS.
- An earlier diagnostic all-frozen-protocol TUN x25 also completed PASS (1,392.525 s); it predates the final source snapshot and is supplementary evidence only.

## Stress

Actual mixed active workload and owned stop duration: **10m12.225699022s**; runner wall time: **666.443 s**; completed rounds: **13** (including warm-up). Coverage: Trojan, SS, SS2022, Snell, HY2, TUIC, VLESS, Mieru; TCP/UDP, IPv4/IPv6, routing, selector policy/generation changes, proxied TCP/UDP DNS and real Native TUN. Offered workload uses a fixed cadence and does not retry failed IO.

Expected errors in this mixed workload: **0**. Unexpected errors: **0**. External unproxied DNS leak sentinel TCP/UDP: **0/0**. Selected Trojan paths exercise actual TLS connect/disconnect, CONNECT and UDP ASSOCIATE. Domain traffic and multi-user/negative/deadline cases are covered separately, not falsely described as simultaneous soak traffic.

Trojan-specific additional stress: 1,000 invalid TLS/auth/truncated requests (8 workers); expected rejection count 1,000, unexpected=0, server registry end=0; after full server close goroutines 3→2 and FDs 8→7. Backend 10,000 association cycles, 1,000 parent/child races and active/queued deadline/Close tests separately cover terminal write and ownership stress.

Mixed boundary observations:

| Resource | Start | Peak (sampled) | Stopped |
|---|---:|---:|---:|
| Goroutines | 30 | 335 | 30 |
| FDs (all) | 23 | 93 | 23 |
| Socket FDs | 12 | 81 | 12 |
| eventfds | 1 | 1 | 1 |
| TCP listeners | 7 | 7 | 7 |
| Client flow sessions | 0 | 33 | 0 |
| Server TCP active (sampled) | 0 | 0 | 0 |
| Client generations | 1 | 17 | 1 |
| Underlay leases | 1 | 17 | 1 |
| Host generations | 0 | 1 | 0 |
| TUN interfaces | 0 | 1 | 0 |
| Journal temporaries | 0 | 0 | 0 |
| RSS KiB | 148292 | 324140 | 303452 |

Combined server UDP active (different protocols; not a universal association metric): **0/15/0**. Retired client generations are retained only while active UDP flows own them and return to the stopped baseline. Mixed peak observations are resource trends, not measured instantaneous maximum throughput/latency.

### Preserved extra load failure

The legacy `TestQF001TUNBoundedStress` extra uncadenced Snell load **FAILED** after 56.05 s (`tun/qf001.log`). It is not counted as a passing stress gate. Diagnostic-only overlays sampled 112 active Snell UDP sessions before concurrent TCP/UDP work, and measured the existing Snell socket registry at **256 on every rejected admission**. Native Snell production bytes match frozen HEAD exactly. TCP EOF and UDP/DNS timeout under that saturation are confirmed admission exhaustion, not QF-001 packet scratch corruption. Original and instrumented failures remain intact.

The required QF-001 deterministic ownership reproducer x100 PASS, QF-002 x25 PASS, real TUN x25 PASS, and the above final mixed workload >=10 minutes PASS. Admission limits were not raised and production was not changed to accommodate the extra overload test. The first instrumentation wrapper incorrectly required a pre-round sample >=120, although it observed 112; that diagnostic assertion failure is retained, and direct rejection instrumentation resolved the cause.

## Security

### TLS / Authentication / Constant-time comparison

TLS1.2+, verified names/trust, strict auth encoding and full constant-time fixed-size user scan; generic rejection exposes neither expected credential nor user identity. Default verification is never weakened. No credential-prefix oracle or early-match return is introduced.

### Randomness

Passwords/generated IDs and synthetic keys use existing `crypto/rand` services; TLS/crypto primitives use Go. No custom TLS/hash/encryption or protocol-specific pseudo-random authentication exists.

### Secret redaction

Encrypted storage, redacted Format methods, generic error text, private explicit export boundary and artifact password/digest/key scans PASS. Server/runtime structures retain derived credentials only; ordinary Node/provider rows retain credential references.

### Parser bounds

Finite authentication/header/domain/URI/ALPN fields and uint16 UDP payload; 512 accepted socket cap; 128 active-target bound with idle expiry (implemented in Round 1 after independent review disproved the initial claim); one owned active writer, no unbounded buffered packet queue. Malformed/truncated/application and unsupported transport/security variants reject.

### Invalid-auth churn

Invalid TLS/password/truncated request flood x1,000 PASS; no retained accepted sockets or sessions after stop. Resource/IO parent cleanup is race checked. This establishes bounded development validation, not a comprehensive network side-channel or platform DoS certification.

An additional compiled race-test process measured invalid-auth flood CPU and memory with `/usr/bin/time -v`: user CPU **3.25 s**, system CPU **0.30 s**, process peak RSS **65088 KiB**; exit 0. These are process totals including test/race overhead, not a production throughput or isolated authentication cost benchmark (`security/authflood-cpu-rss.log`).

## Performance Sanity

Final interop transfers 3 MiB TCP plus empty/small/8 KiB datagrams per row in **0.120–0.198 s** of local workload wall time. This includes multiple verified TLS sessions and confirms non-pathological local TCP/UDP operation. It is not a throughput benchmark or a TLS-handshake microbenchmark. RSS trends and finite resource/session counts are above; no fastest-protocol or certified-capacity claim is made.

## Existing Protocol Regression

| Protocol / action | Evidence | Result |
|---|---|---|
| Shadowsocks | full default/native/shared tests + real mixed TCP/UDP | PASS |
| Shadowsocks 2022 | full tests, multi-user/secret/import regressions + mixed | PASS |
| Snell | full tests + mixed within admission; extra saturation explicitly failed/classified | PASS required regressions |
| Hysteria2 | full native/shared, original backpressure x25 + mixed | PASS |
| TUIC | full native/shared, original backpressure x25 + mixed | PASS |
| VLESS plain | full native/shared, partial/registry/lifecycle x25 + mixed | PASS |
| VLESS TLS | existing TLS native tests, full native/shared | PASS |
| VLESS REALITY | existing REALITY native tests, full native/shared | PASS |
| Mieru | full tests, generic client/packet integration + mixed | PASS |
| DIRECT | shared routing/TUN/policy tests | PASS |
| REJECT | generic routing/policy rejection tests | PASS |

Frozen protocol production implementations are unchanged. No new external interoperability claim is made for frozen protocols in Phase18; their current regression gates are actual full/native/shared/TUN results.

## Phase17 Finding Regression

| Finding | State | Fresh evidence |
|---|---|---|
| R17-001 | CLOSED | original VLESS lifecycle x25; shared/native packet writers |
| R17-002 | CLOSED | unchanged crypto-random HY2 production; full HY2 regression |
| R17-003 | CLOSED | unchanged canonical HY2 docs/config gates; full regression |
| RR17-001 | CLOSED | original TUIC datagram backpressure cancellation x25 |
| RR17-002 | CLOSED | original HY2 datagram backpressure cancellation x25 |
| VLESS_PARTIAL_FRAME | CLOSED | original independent partial deadline x25 + current terminal frame tests |
| VLESS_ASSOCIATION_REGISTRY | CLOSED | original independent churn x25 + current 10,000 churn / 25,000 owner competition |

Original reproducer source is read-only under `phase17-final-rereview-20261006/probes`; Phase18 results are stored under this phase's `regressions/`. Each original top-level reproducer executed 25 times under race with no race reports or timeout. Evidence verification preserves prior source/evidence bytes; no giant review workflow was executed.

## Native TUN Regression

QF-001: **PASS**, deterministic concurrent device write/ownership/shutdown/generation tests x100. QF-002: **PASS**, complete FD/eventfd resource lifetimes x25. Real isolated TUN x25: **PASS**. The separate uncadenced Snell saturation load remains explicitly FAIL/classified above and is not relabelled as a reproducer PASS.

## SagerNet Audit

| Surface | Count |
|---|---:|
| Source imports (AST, tracked+untracked, all build tags) | 0 |
| Direct modules | 0 |
| Module graph | 0 |
| Binary modules (all three platform binaries) | 0 |

External sing-box peer is not a production dependency. Source audit, graph, module verify and binary metadata are retained under `audits/`.

## Module Identity

`github.com/ike-sh/Splicore`; minimum Go **1.26.3**; replace directives **0**. Existing package/module identity is preserved.

## Dependencies Added

**NONE.** go.mod/go.sum are byte unchanged. Standard library crypto/TLS and existing Splicore helpers suffice.

## Upstream Modifications

gVisor: **0**. Mieru: **0**. quic-go: **0**. Other dependencies: **0 local upstream source modifications**. `go mod verify` PASS. No copied Xray/sing-box/Trojan-Go protocol source. Existing attribution/license files are unchanged; **69 modules / 95 notice files** match module-cache bytes. Historical SagerNet derivative attribution is preserved despite zero current dependency counts.

## Underlay

Before: **71 production surfaces**. New Trojan: **4** (owned local listener, protected server TCP target, protected server UDP target, protected outbound proxy TCP dial). Final: **75 production**, **143 test surfaces**, **Unknown=0**. TLS adds no independent unprotected dial. Reviewed scanner inventory and construction invariants are updated; complete final audit PASS.

## Xray Boundary

**E=0, F=0, G=10 actual.** Same complete classified source/test/tool/doc scope as the frozen final audit; production-only G=5 is a narrower metric and is not substituted. All 10 G text surfaces are unchanged, with current line numbers recorded. No Xray runtime, supervisor, downloader or production subprocess is added. FinalMask runtime=0; Sudoku runtime=0; Vision **DEFERRED**.

## Platform Builds

| Platform | Build | Scope |
|---|---|---|
| Linux amd64 | PASS | native tags; real isolated runtime tests |
| Windows amd64 | PASS | safe loopback parser/TLS/lifecycle tests PASS (27.861 s); no host TUN/qualification |
| Linux arm64 | PASS | BUILD ONLY; runtime NOT CERTIFIED |

Build logs/metadata/hashes remain outside the repository. Production bytes are unchanged across final binaries/interop/TUN and the final source manifest; later changes are tests/documentation only.

## Platform Qualification

Historical: **PARTIALLY PASSED**. Frozen Phase17: **NOT REQUALIFIED**. Current Phase18: **NOT PLATFORM QUALIFIED**. No qualification workflow was rerun. GAP-01/02/03 remain **OPEN**; GAP-04 arm64 remains **BUILD ONLY / runtime NOT CERTIFIED**.

Protected historical report SHA-256 remains `18065f3ca3c5f34f5ac8d8e0d52b34a80218f7a6f4ab418f256467c80996bba7`; exact file and verification are in `audits/protected-qualification.json`.

## Documentation

Added [Trojan runtime architecture](../architecture/TROJAN_RUNTIME.md); architecture index updated. Public README is untouched. This report is the implementation handoff; raw artifacts remain external.

## ADR

[ADR 0039](../adr/0039-native-standard-trojan-tls-and-association-ownership.md), **Proposed**: mandatory shared TLS, derived credential boundary, explicit fallback deferral, association ownership and generic user mutations. ADR index updated. Review decides acceptance.

## Findings

### T18-001 — Admitted TLS write errors poison the framing owner

Surface: UDP-over-TLS writes. Observation: partial frame failure desynchronizes peers and Go TLS memoizes even zero-byte write errors. Risk: subsequent false-success writes. Decision: every failed admitted write retires its association; queued cancellation does not touch wire. Implementation: shared cancellable queue plus terminal packet owner. Regression: partial/short/zero-write errors, deadline/Close and independent sibling tests PASS.

### T18-002 — Repeated Close must join the parent callback once

Surface: Packet Close/context.AfterFunc. Observation: calling stop again after an already-stopped callback returns false without a future done notification. Risk: repeated Close deadlock. Decision: separate retirement-once and close/join-once. Implementation: `closeOnce` joins admitted writes/readers/callbacks once. Regression: repeated/concurrent Close and 1,000 parent/child races PASS.

### T18-003 — Existing management lacked generic rotation/deletion

Surface: Account/Credential/Binding management. Observation: enable/disable existed, rotate/delete were required. Risk: protocol-specific database/API or unsafe reference bypass. Decision: extend existing generic binding operation and optional writer. Implementation: owner-bound encryption, optimistic revisions, exclusive-reference checks, atomic delete and runtime rollback. Regression: A/B lifecycle, node/cross-inbound reference rejection and restored traffic PASS; affected inbound session replacement is explicitly documented.

### T18-004 — External UDP behavior differs at payload/domain boundaries

Surface: Mihomo 1.19.30 Trojan. Observation: >8,192 splitting/rejection and reverse domain address conversion failures. Risk: silently altered datagram boundaries or misleading interoperability claim. Decision: canonical framing with explicit T18-COMPAT-001/003 scope. Implementation: numeric peer matrix; domain tested against independent sing-box/self. Regression: pinned real peer matrix PASS within its recorded capabilities; failed attempts retained.

### T18-005 — URI and peer trust fields can be lossy

Surface: import/export. Observation: URI cannot represent explicit CA/disabled UDP; comma ALPN cannot round trip; CA fingerprint alone cannot reconstruct trust anchor. Risk: weakening trust/capability during round trip. Decision: reject unsupported/lossy forms. Implementation: strict parser/typed unsupported mapping and bounded faithful exporters. Regression: semantic URI/provider format round trips, malformed/security/null option rejection and mutation fuzz PASS.

### T18-006 — Legacy uncadenced load saturates frozen Snell admission

Surface: extra QF bounded-stress harness. Observation: registry reaches 256, direct diagnostic rejection records confirm admission exhaustion; production byte-identical to frozen base. Risk: mislabelling overload as QF packet corruption or claiming the failed load passed. Decision: retain FAIL evidence and exact cause, keep finite production caps, use the required deterministic QF reproducer and bounded final mixed workload. Implementation: external diagnostic overlays only. Regression: deterministic QF x100, complete resources x25 and final mixed stress PASS; overload evidence remains FAIL.

## Secret Scan

Real: **0**. Unresolved: **0**. Complete tracked+untracked source/tests/fixtures/scripts/docs/report scan. Matched values are not recorded; candidates are line/file hashes and classifications. Three pre-existing strong synthetic fixtures are allowed only when whole-file bytes equal the previously reviewed source. New fixtures use synthetic passwords and runtime/external generated TLS keys. Final scan and manifest are regenerated after this report.

## Validation Gate Records

| Recorded job | Result | Actual runner duration |
|---|---|---:|
| `tests/default-final2` | PASS | 65.710 s |
| `race/default-final2` | PASS | 95.424 s |
| `race/native-final2` | PASS | 127.956 s |
| `race/shared` | PASS | 48.442 s |
| `race/targeted` | PASS | 32.489 s |
| `race/tls-replacement` | PASS | 16.167 s |
| `interop/final` | PASS | 20.643 s |
| `tun/lifetime25` | PASS | 229.624 s |
| `tun/qf001-deterministic` | PASS | 14.627 s |
| `tun/qf002-resource` | PASS | 7.703 s |
| `stress/mixed10m` | PASS | 666.443 s |
| `security/authflood-cpu-rss` | PASS | 2.254 s |
| `windows/safe-tests` | PASS | 27.861 s |
| `cli/smoke4` | PASS | 19.435 s |
| `regressions/vless-partial` | PASS | 6.344 s |
| `regressions/vless-registry` | PASS | 6.229 s |
| `regressions/vless-lifecycle` | PASS | 6.410 s |
| `regressions/tuic-lifecycle` | PASS | 12.366 s |
| `regressions/hy2-lifecycle` | PASS | 11.734 s |
| `builds/splicore-linux-amd64` | PASS | 20.825 s |
| `builds/splicore-windows-amd64.exe` | PASS | 24.767 s |
| `builds/splicore-linux-arm64` | PASS | 26.284 s |

The original source snapshot was captured at 2026-10-06T17:16:23Z. Two management test refinements and one new certificate-generation test followed; production source did not change. Fresh targeted/native-final2/default-final2/default-race-final2 results cover these final tests. The TUN binary's selected test bodies and production bytes match final source; documents/report were added afterward. Exact source differences, retained failed attempts and final evidence seal are external. No byte-identical all-file snapshot claim is made for the entire validation period.

## Blockers

**Historical initial handoff claim; superseded by PHASE 18 REVIEW FAILED / T18R-001.** Fallback deferral, managed password policy, lossy URI rejection, Mihomo UDP limitations and historical qualification gaps are documented limits. Independent review remains pending by design.

## Git Actions

Staged: **NO**. Committed: **NO**. Pushed: **NO**. Tagged: **NO**. Released: **NO**. Frozen: **NO**. Index: **EMPTY**. All implementation changes remain **UNSTAGED** on the authorized branch and base HEAD.

## Public GitHub

**UNCHANGED.** No remote write, tag, release or v0.2.0 preparation. Public v0.1.0 remains unchanged by this work.

## NoBrand-OneClick

**NOT ACCESSED.** No read, write or traversal of the separate project.

# PHASE 18 READY FOR REVIEW

# Review Fix Round 1

## Review history

Initial handoff: **PHASE 18 READY FOR REVIEW**. Independent review: **PHASE 18 REVIEW FAILED**, exactly one MAJOR finding **T18R-001**. All earlier review/implementation evidence is preserved. Initial target cleanup/expiry claims were inaccurate; history remains above.

Current finding: **FIXED — PENDING RE-REVIEW**. Handoff: **PHASE 18 READY FOR RE-REVIEW**. No independent re-review, closure or freeze.

## Root cause and fix

Inherited shared relay kept bare sockets after reply reader exit, allowing readerless stale reuse. Association inactivity was mistaken for target expiry. Now each association owns ACTIVE target objects, explicit terminal retirement and delete-if-same-owner. Registry state is synchronized; IO, callbacks, Close and joins occur outside its mutex. Parent cancellation directly closes targets, including blocked writes. Closing rejects new registration, empties the registry and joins all reader/timer workers.

## Idle expiry contract

Existing relay idle argument remains **5 seconds** for Trojan, consistent with VLESS/TUIC/HY2; no new config/dependency. Valid outbound admission, successful sends and inbound remote reads advance activity. One timer worker checks/rearms latest activity. Quiet targets expire while siblings keep association alive. Existing terminal-on-read-error policy remains, without busy retry. Target write failures retire/drop that datagram without replay; TLS frame failures keep association-terminal semantics.

## Validation

Final-source full tests, default/native/shared race, target race **x25** (25,000 competition cycles), Trojan packet/deadline/Close/partial-frame/buffer regression **x25**, all **9** mutation fuzz targets, three builds, Windows safe tests, exact-version real peer TCP/UDP matrix, real Native TUN **x25**, and mixed stress **10m34.647753425s**: **PASS**, checkptr **ON**.

Registry churn: 10,000 cycles / 20,000 controlled sockets, final targets/readers/entries 0. Focused sibling/user/exit/expiry/recreation stress: 10,000 cycles, registry sampled peak 3, final 0, unexpected 0. Mixed kernel evidence proves 12 real quiet socket expirations and same-association recreations with repeated replies. Controlled fixtures and real kernel evidence are distinguished; resource peaks are sampled.

Original exact dead-reader probe and panic are preserved: its dialer returned the same failed/closed socket and Read double-closed a channel. User authorized an independent-socket corrected fixture retaining test bodies/barriers/assertions/timeout. Corrected probe **PASS x25**; new regression requires eight actual replacement replies. Original exact idle probe itself **PASS x25**. No original failure is relabeled PASS.

Initial extra native race failed at an unchanged SS ephemeral test port conflict; initial mixed fixture omitted required credential schema/state/stamp. Both logs remain. Final native gate PASS; mixed fixture now reads actual committed node/credential and final mixed gate PASS. Earlier runs are superseded. Snell classification remains **PRE-EXISTING NON-BLOCKING LIMIT**, with unchanged source/evidence.

## Evidence and scope

Full fix report: D:/splicore-validation/phase18-trojan-review-fix1-20261007/PHASE18_TROJAN_REVIEW_FIX1_REPORT.md. Machine summary: summary.json. All raw final-source gates, command exits/durations, resource/fuzz/peer matrices and chronology remain outside repository under D:/splicore-validation/phase18-trojan-review-fix1-20261007/.

Five changed files: shared relay lifecycle, its tests, necessary Trojan TUN stress test, canonical runtime doc and this report. SagerNet source/direct/graph/binary **0/0/0/0**, underlay Unknown **0**, new dependencies **0**, secret real/unresolved **0/0**. Historical **PARTIALLY PASSED**; Phase18 **NOT PLATFORM QUALIFIED**; arm64 **BUILD ONLY**. Authorized HEAD unchanged; index EMPTY; all changes UNSTAGED. No stage/commit/push/tag/release/freeze or next phase.

# PHASE 18 READY FOR RE-REVIEW


# Final Independent Re-Review and Local Freeze

## Status history

| Checkpoint | Verdict / finding |
|---|---|
| Original implementation | PHASE 18 READY FOR REVIEW |
| Original independent review | PHASE 18 REVIEW FAILED; T18R-001 MAJOR |
| Review Fix Round 1 | PHASE 18 READY FOR RE-REVIEW; FIXED — PENDING RE-REVIEW |
| Final independent re-review | PHASE 18 RE-REVIEW PASSED — READY TO FREEZE; T18R-001 CLOSED |
| Initial local Freeze attempt | BLOCKED — strict staged/raw snapshot identity; no commit |
| Authorized EOL recovery and local freeze | PHASE 18 FROZEN; exactly one forward commit |

Final re-review report:
D:/splicore-validation/phase18-trojan-rereview-20261007/PHASE18_TROJAN_REREVIEW_REPORT.md.
Corrected cleanup/lifecycle and actual reply cases each **x100 PASS**; targeted
race **x25 PASS**, **25,000** competition cycles, race/panic/deadlock=0.
All **1,146** repository files stayed byte-equivalent throughout re-review;
**1,998** historical evidence files were verified unchanged.

T18RR-001 is a non-blocking fixture evidence NOTE: the preserved Fix Round corrected
fake notified before terminal Read returned. Its exact x100 attempt had one reader
assertion failure (99 PASS / 1 FAIL; idle 100 PASS), retained as a failure.
Deterministic cleanup bookkeeping strengthens the completion barrier without
removing assertions or extending the one-second timeout. That external copy and
real verified TLS/Trojan UDP reply companions each pass x100. Original fixture and
all raw evidence remain outside Git and unchanged; no failure is relabelled PASS.

Freeze changed only documentation/status metadata; reviewed implementation and
tests are unchanged. The first Freeze attempt was BLOCKED; no commit was created and
that transaction staging was undone. ADR 0039 is Accepted based on final re-review.
The [Freeze report](PHASE18_NATIVE_TROJAN_FREEZE_REPORT.md) separates reused review
evidence from fresh quick gates and records the immutable commit identification
convention. The blocking byte differences, unchanged HEAD and incomplete
staged/post-commit gates are recorded externally in
D:/splicore-validation/phase18-native-trojan-freeze-20261007/PHASE18_FREEZE_FINAL_REPORT.md.

Historical qualification: **PARTIALLY PASSED**. Freeze: **NOT REQUALIFIED**.
Candidate: **NOT PLATFORM QUALIFIED**. arm64: **BUILD ONLY / runtime NOT CERTIFIED**.
Snell remains **PRE-EXISTING NON-BLOCKING LIMIT**. Fallback remains
**DEFERRED — NON-BLOCKING**. No push, tag, release, public update or Phase19 work.

# PHASE 18 IMPLEMENTATION REVIEWED


## EOL Normalization Recovery

Initial Freeze Attempt: BLOCKED — EOL byte drift, no commit. Recovery:
**PASS — Git index EOL normalization independently verified**.
The eleven known non-Go files are CRLF/LF-only, with encoding/BOM, final newline,
logical line count and per-line bytes preserved. Go source/go.mod/go.sum raw drift=0;
Class C implementation drift=0. Candidate source, complete quick gates, three builds,
secret/SagerNet/Underlay audits and actual TUIC JSON production consumers PASS.
Fixture tests verify unchanged placeholder rejection and identical positive creation
after documented TLS placeholders are filled in memory. No implementation or
fixture semantic change was made. Final report/tree/commit identity and post-commit
gates are external in D:/splicore-validation/phase18-freeze-eol-recovery-20261007/.
The initial blocked evidence directory remains immutable. No publication or
requalification; T18R-001 CLOSED and final re-review PASSED remain unchanged.

# PHASE 18 FROZEN
