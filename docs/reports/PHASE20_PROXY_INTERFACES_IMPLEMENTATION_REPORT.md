# Splicore Phase 20 Native SOCKS5 / HTTP / Mixed Implementation Report

## Verdict

PHASE 20 IMPLEMENTATION REVIEWED

Targeted Independent Re-Review passed; P20R-001 is CLOSED. The historical
implementation and failed Review chronology below is preserved. The authorized
Freeze is prepared with a commit-contingent repository report; its final receipt
is recorded externally after the single commit and postcommit gates succeed.
Phase20 remains NOT PLATFORM QUALIFIED; Linux arm64 is BUILD ONLY.

## Base

| Item | Verified value |
|---|---|
| Frozen base / HEAD | `401b9e8b6032197108548ada7a4472440dfc65fc` |
| Sole parent | `1f0e1925f0f67a37e8d3d496a7e56ed7daff02a7` |
| Commit message | `feat(protocol): add native vmess server and client` |
| Branch | `codex/phase-20-proxy-interfaces` |
| Entry | CLEAN, Index EMPTY; `entry/prestate.txt` |
| Final worktree | DIRTY / UNSTAGED |
| Final Index | EMPTY |
| Validated implementation manifest | `implementation-manifest-v2.json` |
| Manifest SHA-256 | `a0b67a5045e7d3532227308e9c827f715cfeccbb060f288558acc7fac3c85593` |

Evidence root **E**: `D:/splicore-validation/phase20-proxy-interfaces-20261008/`.
Paths below are relative to E unless a repository path is explicitly stated.
`audit/source-manifest.json` covers final files; `audit/change-manifest.json`
records changes. Go/module/audit-script bytes are checked against the implementation
seal after final validation. Final binaries and raw commands have separate hashes
and result records. Documentation changes do not alter the tested implementation.

## Existing Surface Audit

The preimplementation [PHASE20_EXISTING_PROXY_SURFACE_AUDIT](D:/splicore-validation/phase20-proxy-interfaces-20261008/PHASE20_EXISTING_PROXY_SURFACE_AUDIT.md)
classified every relevant surface as A complete, B partial, C test-only,
D compatibility/helper or E missing. The existing SOCKS/HTTP/Mixed listeners,
Manager, routing generations, UDP ownership and HTTP streaming were consolidated.
RFC1929, strict bounded HTTP/Mixed parsing and native upstream factories were
completed. Existing address codec, underlay, clientio, generic resources,
transactions and test fixtures were reused. The previous SOCKS helper is now thin
delegation, with one canonical wire implementation.

## Architecture

`ProtocolID=socks5/http`, `EngineID=native`. Mixed is an ingress mode and cannot
be a remote Node protocol. Client ingress and TUN feed shared routing/DNS/policy
and statistics before selected outbound IO. Protocol packages own framing;
native adapters own protected sockets; Manager owns listeners, sessions and
immutable policy/auth generations. No protocol-local database, DNS, policy,
external-core runtime or server-protocol registration was added.

See [PROXY_INTERFACES.md](../architecture/PROXY_INTERFACES.md) and
[Proposed ADR 0041](../adr/0041-generic-proxy-interfaces-and-credentials.md).
Canonical RFC1928/1929/9110/9112 and curl DNS conventions were reviewed before
implementation in `PHASE20_PROTOCOL_NOTES.md`.

## SOCKS5 Inbound

### Negotiation

No-auth and RFC1929 username/password; unsupported methods return FF. Negotiation,
method count and auth lengths are bounded. Short positive writes complete;
a partial frame with a terminal error ends the stream. Auth-required profiles
do not negotiate a no-auth downgrade.

### Authentication

Shared account-owned encrypted username/password credentials, immutable eligible
binding snapshots and constant-time hashed comparison. Disabled, expired,
inactive or absent identities reject. Credential input and formatters are redacted.
Authentication is cleartext on a plaintext transport and provides no encryption.

### CONNECT

Target enters shared route selection, DNS and policy. Canonical failure responses
map refusal/network/host failures intentionally; a timeout is general failure,
not falsely TTL expiry. Unsupported BIND returns command unsupported.

### UDP ASSOCIATE

Real RFC1928 relay. TCP control owns the local UDP socket, retained generation,
bounded destination registry and joined readers. Peer IP plus requested/first
valid source port pins the client. Foreign sources and malformed packets cannot
claim another association. Maximum 32 target flows per association.

### Address Types

IPv4, IPv6 and DOMAIN are supported. Truncated address/port, zero/invalid domain
and unknown ATYP reject. DOMAIN framing is bounded to protocol limits. Stream
targets require a valid nonzero port; wildcard association source is allowed.

### FRAG Policy

FRAG=0 supported; FRAG!=0 safely dropped without reassembly. Complete datagrams
are bounded to 65507 bytes.

### Lifecycle

Existing canonical two-minute idle expiry refreshes on valid sends and replies.
Reader death marks terminal before closing; retirement is delete-if-same-owner.
Read/write failure removes dead state before reuse. Control Close, parent Close,
route replacement and idle expiry release sockets/workers; cancellation prevents
blocked retirement publication. `race/targeted-v2.log` and final shared race
exercise real associations, delayed old-owner retirement and 256 association churn.

## SOCKS5 Outbound

### CONNECT

Native protected proxy TCP dial, bounded handshake, all address types and
clientio-owned published connections. Independent RFC wire fixture and mature
sing-box serve actual TCP payloads with no-auth and RFC1929.

### UDP ASSOCIATE

Native TCP-controlled association plus protected UDP socket. Payload frames
carry destination/source ATYP. Composite ownership includes both sockets and a
single joined control watcher. Control EOF terminalizes and autonomously unregisters.
Fresh opens produce independent associations; short positive UDP frames terminalize.

### Authentication

Explicit auth option and typed UsernamePassword credential. No-auth has a strict
nonsecret encrypted marker in the mandatory generic credential slot; never sent
on wire. Unexpected credential kinds or ignored credential values reject.

### Remote DNS

When shared policy leaves a domain unresolved, DOMAIN is passed unchanged to the
upstream. Controlled resolver counter remains zero for native TCP/UDP destination
domains. Managed DNS/policy resolution remains authoritative and protected.

### Relay Address

Explicit BND.ADDR is used, including the independent fixture's relay 127.0.0.2
with TCP peer 127.0.0.1. Unspecified BND IP uses the connected TCP peer IP;
zero BND port rejects. Explicit domain relay endpoints use protected resolution.

### Lifecycle

Pending-open cancellation, parent Close, blocked-write live deadlines,
half-close and 25 TCP-control EOF association cycles pass. No detached composite
watcher, adapter registry entry or dead relay reuse remains.

## HTTP Inbound

### CONNECT

Strict authority host:port, IPv6 brackets, conflicting raw Host rejection and
no request body framing. Shared route selection then 200/tunnel transition.
Buffered bytes, including coalesced application bytes, are retained.

### Plain HTTP

HTTP/1.1 absolute-form requests use net/http, shared route/DNS/policy and
origin-form forwarding with streamed bodies. One request per client connection;
Connection:close, no persistent proxy keep-alive or pipeline promise.

### Authentication

Optional Basic through the same account pairs as SOCKS/Mixed. Missing/bad auth
receives 407 with a Basic Proxy-Authenticate challenge; no credential values
appear in error bodies or diagnostics.

### Header Safety

64 KiB total, 8 KiB line, 129 lines, strict CRLF, bounded authority and Basic
decode. Duplicate Host/Proxy-Authorization/CL/TE, CL+TE, malformed method/URL,
userinfo and conflicting authority reject. Connection-nominated fields and
standard hop fields are stripped in both directions; end-to-end headers remain.

### Credential Leakage Protection

Local origin captures show Proxy-Authorization absent. Proxy-Connection and
Connection-nominated test fields are absent too. CONNECT uses authorization only
in the proxy handshake; tunneled echo bytes exactly match application payload.

### Lifecycle

Client Close cancels a stalled origin response after request completion.
Parent Close joins the body/detection reader and cancels transport. CONNECT
CloseWrite retains downstream response. Truncated/invalid messages reject
boundedly; response streaming uses no unbounded body allocation. Final targeted
and shared race pass the cancellation/half-close companions and inherited HTTP
buffering/header/teardown tests.

## HTTP Outbound

### CONNECT

Native protected TCP connection and bounded net/http response parsing. All
successful 2xx accepted; informational responses bounded to eight. Partial reads
and coalesced server-first data are supported. Successful CONNECT ignores HTTP
body length/transfer framing. Malformed/error/auth-required responses reject.

### Authentication

Optional Basic, strict bounded typed pair. No credentials are injected into
tunneled bytes. Mature sing-box no-auth/Basic cases transfer actual payloads.

### TCP-only Capability

UDP UNSUPPORTED. Factory capability and runtime network support both say TCP
only; packet open returns a typed unsupported error. No HTTP UDP/MASQUE invention.

## Mixed Inbound

### Detection

05 selects SOCKS5; valid bounded HTTP method token followed by space selects HTTP.
Buffered Peek does not consume business bytes. Unknown traffic rejects.

### Bounds

Maximum 33 inspected bytes and shared five-second handshake deadline. One TCP
listener, no second internal listener. 256 incomplete detection disconnects join
with zero remaining sessions and errors_total=256; parent shutdown wakes readers.

### Authentication

The same eligible account pairs authenticate RFC1929 or HTTP Basic on the same
listener; live REST rotation proves both forms. No duplicate user store.

### SOCKS UDP

UDP is SOCKS5 UDP ASSOCIATE only. HTTP traffic through Mixed remains TCP-only.

## Account / Credential / Binding

Existing Account, Binding and Credential types are reused. Local Bindings reside
in LocalInbound JSON because the legacy server SQL binding FK references managed
server inbounds. Max128 bindings/listener; unique IDs/accounts/usernames; account
and credential ownership checked in prepare, commit and committed-state reads.
Account status/expiry and binding enabled state gate new authentication. Binding
rotation closes sessions after commit while preserving unchanged upstream adapters
and passive health. Exclusive obsolete local secrets are removed; accounts and
server-used credentials remain. Existing live generic account mutation restrictions
are unchanged and documented.

## Node / Provider

Immutable IDs, generic Node/Outbound references and transactional provider
generation handling. URI schemes socks/socks5/socks5h/http; explicit canonical,
Mihomo and sing-box import/export. SOCKS URI exports use socks5h; shared DNS
policy takes precedence. HTTPS proxy transport/path/query/partial credentials
reject. Provider preview/validation/apply remains generic; invalid HTTP+UDP refresh
preserves committed nodes/outbounds and prior generation. Actual provider and
explicit secret export/round-trip companions pass.

## API / CLI

`/api/v1/local-bindings` CRUD and `/{id}/credential` rotation plus existing
local-inbounds/nodes/outbounds/client/capabilities use Application Service and
global committed revision checks. CLI list/get/validate/plan/apply shares the
same service. Live REST/CLI/Doctor companions pass without credential disclosure.
OpenAPI is updated for binding routes, listener auth/LAN fields, account stats,
session attribution, capabilities and errors; all internal references resolve.
Evidence: `race/targeted-v2.log`, `audit/openapi.json`.

## SQLite

Schema 8 unchanged; NO NEW MIGRATION. Credentials remain encrypted in the existing
vault and accounts remain generic. Local listener JSON stores references/auth
intent, never raw pairs. Commit and committed-state reads reject invalid references.
go.mod, go.sum, existing migration files and frozen license inputs are unchanged.

## Backup / Restore

Maintenance backup/restored runtime preserves inbound, account, binding,
credential, SOCKS/HTTP node IDs and auth settings with schema8. Backup bytes contain
no plaintext synthetic pair; after restore authentication and actual payload pass.
Linux maintenance behavior is tested; no Windows maintenance qualification claim.

## Routing

Every ingress target enters shared selection; private/local addresses follow
normal generic rules. No inbound direct net.Dial bypass, protocol-specific SSRF
policy or ambient environment HTTP proxy is introduced. DIRECT and REJECT remain
shared actions. Final isolated TUN/stress exercises selectors and actual routed IO.

## DNS

Shared configured DNS/detours remain authoritative. SOCKS DOMAIN and HTTP
authority preserve domains if policy does not need resolution. Upstream numeric
endpoint controlled DNS test produces zero local destination lookup calls;
upstream bootstrap/DIRECT/explicit domain BND resolution remains legitimate.
The isolated TUN lab exercises TCP/UDP DNS interception and proxied DNS; bootstrap
counter stays zero and target namespace DNS bypass counters are zero.

## Policy

Selector rejects HTTP UDP; URL-Test, Fallback and Load-Balance filter HTTP-only
members for UDP. Static impossible UDP-only rules and UDP DNS detours reject.
Actual TUN load-balance fallback transfers UDP through SOCKS while HTTP selector
UDP is unavailable. All four group types have deterministic capability tests.

## Native TUN

Real Linux kernel TUN under owned disposable mount/network namespaces, protected
proxy peers and nested target namespace. IPv4/IPv6 TCP through SOCKS and HTTP,
UDP through SOCKS, shared routes, proxied DNS and policy. Routes/rules/interfaces
are checked against pre-run snapshots after every stop; no host settings escape
the lab. Driver target leak counters TCP=0/UDP=0.

## Capability Matrix

| Surface | TCP | UDP | Auth | Routing | DNS | Policy | Interop |
|---|---|---|---|---|---|---|---|
| SOCKS5 Inbound | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| SOCKS5 Outbound | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| HTTP Inbound | PASS | N/A | PASS | PASS | PASS | PASS | PASS |
| HTTP Outbound | PASS | UNSUPPORTED | PASS | PASS | PASS | PASS | PASS |
| Mixed Inbound | PASS | SOCKS-only | PASS | PASS | PASS | PASS | PASS |

## Authentication Matrix

| Surface | No auth | Valid pair | Wrong pair | Rotation / disclosure |
|---|---|---|---|---|
| SOCKS ingress | PASS | RFC1929 PASS | Reject PASS | x25 rotations PASS; redacted |
| HTTP ingress | PASS | Basic PASS | 407 PASS | Rotation PASS; origin header absent |
| Mixed ingress | PASS | Both forms PASS | Reject PASS | One pair, both forms after rotation PASS |
| SOCKS upstream | PASS | Mature RFC1929 PASS | Native handshake rejects errors | Typed credential validation PASS |
| HTTP upstream | PASS | Mature Basic PASS | Non2xx/407 reject | Typed credential validation PASS |

No real upstream credentials were used. All fixture identities are synthetic.

## External Interoperability

| Peer/Client | Version | Direction | Surface | TCP | UDP | Auth | Result |
|---|---|---|---|---|---|---|---|
| curl | 8.5.0, Ubuntu security-patched build | Client → Splicore | SOCKS5 | PASS | N/A | No-auth / RFC1929 | PASS |
| curl | Same | Client → Splicore | HTTP plain / CONNECT | PASS | N/A | No-auth / Basic | PASS |
| curl | Same | Client → Splicore | Mixed SOCKS / HTTP plain / CONNECT | PASS | N/A | Both configurations | PASS |
| Independent RFC byte peer | Phase20 fixture, repository source bound | Splicore → peer | SOCKS CONNECT / UDP | PASS | PASS | No-auth / RFC1929 | PASS |
| sing-box | 1.14.2, revision af6e64c3b69e6132ebaee0e1a3d24e93903f6709 | Splicore / TUN → mature server | SOCKS5 | PASS | PASS | No-auth / RFC1929 | PASS |
| sing-box | Same | Splicore / TUN → mature server | HTTP CONNECT | PASS | UNSUPPORTED | No-auth / Basic | PASS |

sing-box binary SHA-256:
`fc9c6e6ab345f045b16a0ed10d1ff28d68e8e56e7749fca30738d1406e98d7b8`.
Only an external local interoperability peer; no production import/dependency.
Version, exact synthetic configs, TCP admission readiness and raw peer output are
in `interop/*-versions.json`, `interop/*-sing-box.json`, `interop/*-peer.log`.
Final-source mature interoperability is exercised in `tun/final-v2.log` and
`stress/final-v2.log`; curl 12-case actual-payload matrix in `race/targeted-v2.log`.
Earlier dedicated `interop/mature-upstream2.log` is retained supporting evidence.

## DNS Leak Validation

`TestPhase20SOCKSOutboundRemoteDNSRelayLifetime`: controlled resolver Dial calls=0;
IPv4/IPv6/domain TCP and DOMAIN UDP payloads PASS; destination domains remain
unchanged. Final TUN/soak query counters require proxied DNS queries>0,
bootstrap queries=0 and target namespace bypass TCP=0/UDP=0. Numeric local peers
avoid confusing endpoint bootstrap with destination resolution. Tests do not
claim that managed policy never legitimately resolves domains.

## HTTP Proxy-Authorization Leak Test

Actual local origin observed absence for no-auth/auth HTTP/Mixed forwarding.
Header fixture also verifies nominated hop fields absent in requests/responses.
CONNECT echo integrity verifies handshake authorization is not appended to
application data. Status, REST, CLI and Doctor companions omit passwords/raw pairs.
Support bundle uses the existing explicitly redacted client projection, exposing
listener kind/auth/LAN intent and counts without credentials. A final external
test overlay also opens the actual generated support archive and verifies no
fixture credential, username/password field or Proxy-Authorization appears.

## Lifecycle Matrix

| Surface | Close | Deadline | Parent Close | Registry Cleanup | Result |
|---|---|---|---|---|---|
| SOCKS TCP ingress/upstream | PASS | Live blocked-write PASS | PASS | Session/generation PASS | PASS |
| SOCKS UDP ingress | Control/idle PASS | Idle refresh PASS | PASS | Reader death, same-key owner and 256 churn PASS | PASS |
| SOCKS UDP upstream | Control EOF x25 PASS | Dynamic write PASS | PASS | Composite owner/watch join PASS | PASS |
| HTTP CONNECT | Half-close/Close PASS | Shared socket deadline PASS | PASS | Buffered stream owner PASS | PASS |
| Plain HTTP | Client cancellation PASS | Bounded headers / shared dial timeout PASS | Stalled body cancellation PASS | Owned reader / transport PASS | PASS |
| Mixed | Early disconnect x256 PASS | 5s bounded detection | PASS | Session errors=256, no residue | PASS |

Native target close and inherited malformed/partial framing, source ownership,
UDP idle expiry, response/header and policy tests run in complete race suites.
No production timing sleep, retry or protocol/client special-case was introduced.

## Fuzz

Actual mutation, two workers, configured 20 seconds each; no seed-only substitute.

| Target | Configured duration | Executions | Result |
|---|---|---|---|
| Negotiation | 20s | 888948 | PASS |
| Request | 20s | 875381 | PASS |
| Packet | 20s | 838127 | PASS |
| ProxyURI | 20s | 32328 | PASS |
| Authority | 20s | 538010 | PASS |
| MixedDetection | 20s | 568344 | PASS |

Total executions: 3741138. Crashes:0. Mutation timeouts:0. All six runners
exit0; exact fuzz flags and stdout are in `fuzz/*.result.json` and `fuzz/*.log`.
The last implementation correction changes application session restart behavior;
the six fuzz target functions/parsers remain the tested implementations.

## Race / Checkptr

| Gate | Final evidence | Result |
|---|---|---|
| Targeted race, including curl | `race/targeted-v2.log` | PASS |
| Full default tests | `tests/full-default-v2.log` | PASS |
| Full default race | `race/default-v2.log` | PASS |
| Full native race, gVisor/QUIC/uTLS tags | `race/native-final.log` | PASS |
| Shared/protocol/backend race | `race/shared-v2.log` | PASS |
| Final negative/security companion | `race/security-companion2.log` | PASS |

Checkptr ON: Go1.26.6 race compiler default `Debug.Checkptr=1`; no disabling flag.
CGO enabled for race; readonly offline module cache and `/tmp` for Unix-safe
temporary ownership. Final race logs have no race detector/checkptr reports.
The security companion is an external Go test overlay against sealed source:
loopback default, implicit LAN rejection, deliberate LAN+Doctor warning,
BIND REP7, invalid ATYP REP8, exact407/Basic challenge, truncated streaming body
502 with joined cleanup, and actual support archive secret absence. Its source
and overlay mapping remain in `checks/`; repository production bytes are unchanged.

## Resource x25

One warm-up plus 25 measured start/use/stop cycles for authenticated SOCKS5,
HTTP and Mixed. Measured675 valid streams,75 rejected authentication attempts,
150 credential rotations; warm-up adds27 valid/3 invalid/6 rotations.
Account byte attribution and redacted status pass. Final-source resource record:

```text
x25 TCP/auth churn=675 valid plus 75 invalid rotations=150 start={Goroutines:4 FDs:12 Listeners:0 Sessions:0 UDPWorkers:0} peak={Goroutines:7 FDs:15 Listeners:3 Sessions:0 UDPWorkers:0} end={Goroutines:4 FDs:12 Listeners:0 Sessions:0 UDPWorkers:0}
```

Additional256 real UDP association payload cycles end with UDPActive0 and
256 upload/download packet counts. Mixed early disconnect churn256 leaves no
session/reader residue. Existing composite outbound EOF/deadline tests pass.
Start/peak/end sampling occurs in-process; settled socket/worker checks are the
leak gate. The native echo fixture uses joined explicit read/write to keep the Go
TCP splice pipe pool outside descriptor accounting, without a production workaround.

## TUN x25

One warm-up plus25 measured real isolated TUN start/use/stop cycles on the final
binary. Both upstream authentication modes, IPv4/IPv6 TCP, SOCKS UDP,
HTTP plain/CONNECT/Mixed ingress, route/DNS/policy and HTTP UDP reject/fallback.

```text
x25 successful_tcp_payloads=936 successful_udp_payloads=312 start={qfTUNResources:{Goroutines:6 FDs:14 SocketFDs:3 EventFDs:1 Listeners:6 Sessions:0 Generations:1 Leases:1 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:98572} TCPActive:0 UDPActive:0 TCPTotal:0 UDPTotal:0 SharedTargetReaders:0 SharedIdleWorkers:0} peak={qfTUNResources:{Goroutines:48 FDs:30 SocketFDs:3 EventFDs:1 Listeners:9 Sessions:6 Generations:5 Leases:5 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:179008} TCPActive:0 UDPActive:0 TCPTotal:0 UDPTotal:0 SharedTargetReaders:0 SharedIdleWorkers:0} end={qfTUNResources:{Goroutines:6 FDs:14 SocketFDs:3 EventFDs:1 Listeners:6 Sessions:0 Generations:1 Leases:1 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:171548} TCPActive:0 UDPActive:0 TCPTotal:0 UDPTotal:0 SharedTargetReaders:0 SharedIdleWorkers:0}
```

Driver test_exit0 and leak counters0/0. Each stopped sample checks equal FDs,
goroutines, eventfds/listeners, generations and leases; sessions, target readers,
idle workers, host generations/interfaces/journal temporaries are zero. Server
protocol counters printed as zero in this focused proxy run are not payload
counts; the explicit successful payload counts above record exercised traffic.
RSS start/peak/end are recorded; race/allocator retained memory is not equated
with an FD/socket/worker leak. Evidence `tun/final-v2.log`, result JSON and binary hash.

## Mixed Stress

Duration: 11m7.608838089s (minimum ten minutes after start, final source).
Expected errors: 192 deliberate VMess replay/auth/clock/tag rejections;
HTTP-only UDP selection also rejects deterministically before IO.
Unexpected errors: **0**.

```text
mixed SOCKS5(TCP/UDP/auth)/HTTP(CONNECT/plain/auth)/Mixed/VMess(all modes/two users/raw+TLS)/Trojan/SS/SS2022/Snell/HY2/TUIC/VLESS/Mieru TUN TCP/UDP IPv4/IPv6 routing/policy/proxied DNS duration=11m7.608838089s rounds=6 successful_tcp_payloads=1080 successful_udp_payloads=552 expected_security_rejections=192 unexpected_errors=0 start={qfTUNResources:{Goroutines:39 FDs:32 SocketFDs:21 EventFDs:1 Listeners:20 Sessions:0 Generations:1 Leases:1 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:202840} TCPActive:0 UDPActive:0 TCPTotal:9 UDPTotal:4 SharedTargetReaders:0 SharedIdleWorkers:0} peak={qfTUNResources:{Goroutines:231 FDs:86 SocketFDs:21 EventFDs:1 Listeners:23 Sessions:18 Generations:11 Leases:11 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:306740} TCPActive:0 UDPActive:4 TCPTotal:769 UDPTotal:324 SharedTargetReaders:0 SharedIdleWorkers:0} stopped={qfTUNResources:{Goroutines:39 FDs:32 SocketFDs:21 EventFDs:1 Listeners:20 Sessions:0 Generations:1 Leases:1 HostGenerations:0 Interfaces:0 JournalTemporaries:0 RSSKiB:290572} TCPActive:0 UDPActive:0 TCPTotal:54 UDPTotal:24 SharedTargetReaders:0 SharedIdleWorkers:0}
```

Includes SOCKS TCP/UDP, HTTP CONNECT/plain, both Mixed forms, VMess all payload
modes/two users/raw+TLS, Trojan, VLESS, SS/SS2022, HY2, TUIC, Mieru, Snell,
real TUN, IPv4/IPv6, shared routing, proxied DNS and policy. Fixed30-second offered
cadence; no failed IO retry. Endpoint/route/interface ownership is restored and
namespace bypass counters remain0/0. Evidence `stress/final-v2.log` and result JSON.

## Existing Protocol Regression

Complete default/native/shared race suites preserve SS, SS2022, Snell, HY2, TUIC,
VLESS, Mieru, Trojan, VMess, DIRECT and REJECT. Mixed stress transfers actual
traffic across every listed available native protocol. The regression that reset
passive health after unrelated listener creation is corrected and its old native
failure is retained, followed by complete final native PASS.

## Historical Finding Regression

| Finding | Status after Phase20 |
|---|---|
| R17-001 / R17-002 / R17-003 | CLOSED |
| RR17-001 / RR17-002 | CLOSED |
| VLESS_PARTIAL_FRAME / VLESS_ASSOCIATION_REGISTRY | CLOSED |
| T18R-001 | CLOSED |
| P19R-001 / P19R-002 / P19R-003 / P19RR-001 | CLOSED |

Frozen-base statuses retained. This phase does not independently close/re-review
those findings. Existing backend/owner/relay regressions and final all-protocol
stress pass. Phase19 startup artifact evidence/harness history remains untouched.

## Findings

### P20-001 — SOCKS authentication and partial framing

- Surface: existing SOCKS codec and local ingress.
- Observation: partial no-auth support lacked canonical RFC1929 and complete writes.
- Risk: incomplete generic auth and inconsistent short-write framing.
- Decision: complete one codec and retain existing helper delegation.
- Implementation: bounded method/auth/address/packet parsing and WriteFull.
- Regression evidence: negotiation/partial frame tests, actual curl/mature payload,
  mutation fuzz and final targeted/full race PASS.
- Status: RESOLVED — READY FOR REVIEW.

### P20-002 — UDP dead owner retirement

- Surface: local UDP target registry and new upstream composite association.
- Observation: dead target must be removed before reuse; delayed notification must
  not retire its replacement. Control EOF must terminate upstream UDP autonomously.
- Risk: stale reply blackhole, live-owner deletion or socket/watcher residue.
- Decision: explicit identity and terminal ownership.
- Implementation: dead flag, key+owner retirement, delete-if-same-owner,
  cancellation-safe publication and tracked joined composite watcher.
- Regression evidence: delayed owner replacement payload, control EOFx25,
  blocked writes/live deadlines, UDP churn256 and TUNx25 PASS.
- Status: RESOLVED — READY FOR REVIEW.

### P20-003 — HTTP ambiguity, proxy credentials and stalled bodies

- Surface: existing HTTP forwarding/CONNECT/Mixed parser and streaming lifetime.
- Observation: strict raw header conflicts and authenticated forwarding needed
  completion; client disconnect could leave a stalled origin response waiting.
- Risk: parser disagreement, credentials reaching origin or retained body worker.
- Decision: bound pre-read around net/http and maintain explicit transport ownership.
- Implementation: strict header/authority/Basic bounds and hop stripping;
  post-request disconnect watcher cancels transport and joins on shutdown.
- Regression evidence: actual captured origin headers, 2xx/server-first parsing,
  CONNECT half-close, stalled client/parent cancellation, Mixed churn256 and race PASS.
- Status: RESOLVED — READY FOR REVIEW.

### P20-004 — HTTP UDP capability and node representation

- Surface: native upstream factories, generic node import/export and policy.
- Observation: HTTP CONNECT has no generic UDP; Node requires credential reference
  even for no-auth proxy peers.
- Risk: silently selecting an incapable UDP node or discarding configured secrets.
- Decision: explicit TCP-only capability and strict nonsecret no-auth marker;
  Proposed ADR documents generic local binding placement and shared DNS semantics.
- Implementation: network-aware selection/static validation and exact credential
  validation; SOCKS URI export uses socks5h.
- Regression evidence: four policy groups, provider failed-refresh retention,
  export round-trips, controlled local DNS=0, backup/restore and actual TUN fallback.
- Status: RESOLVED — READY FOR REVIEW; architectural proposal remains Proposed.

### P20-005 — Unrelated listener creation discarded passive health

- Surface: ApplyClient session restart decision.
- Observation: first native full race failed offline passive-health assertions for
  the five existing expansion protocols after a local listener was added.
- Risk: misleading outbound health and unnecessary adapter replacement.
- Decision: separate local authentication session refresh from upstream rebuilding.
- Implementation: explicit runtime restart rebuilds; local auth changes close
  sessions after commit while unchanged upstream adapters retain their health.
- Regression evidence: original `race/native.log` preserved; final complete
  `race/native-final.log` PASS plus auth rotation/resource and complete race companions.
- Status: RESOLVED — READY FOR REVIEW.

## Preserved Investigation / Harness Evidence

Every generated raw failure, old harness/config/log and preliminary binary remains.
Initial Unix ownership failures used an inherited Windows temp path; `/tmp` fixes
the fixture environment. Initial targeted compile failure was an unused test import.
An initial mature HTTP fixture used18 instead of19 expected payload bytes; its
assertion was corrected. Early resource fixture FD growth came from Go's TCP splice
pipe cache and was removed from the fixture's accounting through joined explicit IO.
The first underlay audit correctly flagged the stale reviewed callsite inventory;
new protected calls were audited, inventory/invariants updated, final Unknown0.
Native passive-health regression above was a production correction and is reported
separately. Earlier TUN/stress snapshots are supporting/preliminary runs and do not
substitute for final `*-v2` gates. No failure is deleted or relabeled as a PASS.
The first external security companion invocation was split by PowerShell argument
parsing before Go could read the overlay; its raw failure and correctly quoted
successful command are both retained.

## SagerNet

Source:0. Direct:0. Graph:0. Binary:0.
AST source imports include all Go files/build tags; go.mod direct/module graph and
all three final binary metadata inventories contain no SagerNet module. External
sing-box is a local evidence peer, not a production dependency. `audit/final-gates.json`.

## Module Identity

`github.com/ike-sh/Splicore` unchanged.

## Dependencies

New modules:0. Minimum Go1.26.3 unchanged; toolchain Go1.26.6 for validation.
go.mod/go.sum raw hashes equal entry; no replace, module verification PASS.
Frozen official-cache license/provenance/notice files are unchanged. New production
proxy code uses stdlib and existing internal owners; no imported peer/fixture code.

## Underlay

Unknown:0. Production surfaces:81; test-only surfaces:195.
SOCKS target TCP/UDP delegates to leased selected adapters; proxy TCP/control/UDP
relay and HTTP TCP use injected protected dialers. Local ingress is explicitly
classified and validated. New proxy constructor/clientio invariants are enforced.
`underlay-final/inventory-after.json`, reviewed repository callsite inventory,
final TUN payload/leak counters and existing fake-host/underlay regressions agree.

## Builds

| Target | Result | Scope |
|---|---|---|
| Linux amd64 | PASS | Native tagged CGO0 binary |
| Windows amd64 | PASS | Real portable common proxy implementation; native tagged CGO0 binary |
| Linux arm64 | PASS | BUILD ONLY |

Final platform metadata and artifact SHA-256: `audit/final-gates.json` and
`builds/metadata-*-v2*.log`. Windows proxy code uses the common real socket paths,
not stubs. This phase does not claim full Windows runtime/platform qualification.

## Secret Scan

real:0. unresolved:0.
Fresh complete tracked/untracked text/signature scan with frozen entry hash binding,
explicitly inspected changed code/API/docs/synthetic fixtures, unchanged binary
artifacts and omitted values. Final report included. Generated evidence uses only
synthetic accounts/passwords, reserved domains and controlled local addresses;
external peer/config/build provenance is recorded. No real upstream credentials.
`audit/secret-scan.json`, `audit/external-secret-scan.json`.

## Known Limitations

- SOCKS BIND UNSUPPORTED / DEFERRED; nonzero UDP FRAG UNSUPPORTED / DROP.
- HTTP UDP UNSUPPORTED; HTTP/2, HTTP/3, MASQUE, CONNECT-UDP DEFERRED.
- Digest, NTLM, Negotiate DEFERRED; MITM/interception/cache OUT OF SCOPE.
- HTTPS upstream proxy DEFERRED; plain HTTP proxy keep-alive/pipelining unsupported.
- System Proxy/PAC PHASE21; WS/gRPC/XHTTP NOT PHASE20.
- Shared DNS policy can legitimately resolve before proxying; URI import adds no
  independent local-resolution override. SOCKS URI export intentionally uses socks5h.
- Listener protocol replacement on the same occupied port can fail preparation;
  stop first or choose a new port. Failure preserves the previous runtime.
- Existing generic live account-mutation restrictions remain; local binding
  disable/delete/rotation provide the authenticated listener management boundary.
- Snell **PRE-EXISTING NON-BLOCKING LIMIT**: frozen256 socket admission, UDP consumes
  two entries. Its historical uncadenced qualification stress saturation is retained;
  Phase20 offered workload remains bounded and does not claim overload capacity.
- No confirmed socket/goroutine/worker leak; race/Go allocator RSS retention is
  recorded explicitly and is not a platform memory qualification claim.

## Platform Qualification

Historical: **PARTIALLY PASSED**.
Phase20: **NOT PLATFORM QUALIFIED**.
Linux arm64: **BUILD ONLY**.
No full Platform Qualification executed; implementation gates do not alter history.

## Public GitHub

UNCHANGED. Current public release remains v0.1.0. No push/tag/release or public write.

## NoBrand-OneClick

NOT ACCESSED.

## Git Actions

staged:NO; committed:NO; pushed:NO; tagged:NO; released:NO; frozen:NO.
Index:EMPTY. HEAD remains the exact frozen base; all Phase20 changes UNSTAGED.
No reset/rebase/amend/squash or frozen-history rewrite.

## Blockers

NONE.

# PHASE 20 READY FOR REVIEW

## Independent Review

**PHASE 20 REVIEW FAILED**

P20R-001: **BLOCKER**.

Observation: Proxy-Authorization supplied through an HTTP chunked request trailer
leaked to the origin. The unchanged isolated Review reproducer confirmed **3/3**
leaks. The ordinary header was stripped correctly. This was a newly discovered
inherited defect: frozen HEAD also sanitized Trailer before body consumption.
Original Review evidence is preserved at
`D:/splicore-validation/phase20-proxy-interfaces-review-20261008/`.

## Review Fix Round 1

P20R-001: **FIXED — PENDING RE-REVIEW**.

The HTTP inbound forwarding request now owns a cloned Header map and a separate
allowed Trailer declaration map. The existing proxy/hop policy is applied before
removing Connection, so nominated trailer names remain excluded. Framing/routing
fields are also excluded from trailers. Go populates incoming trailer values at
body EOF; the streaming wrapper copies only declared safe values and their slices
into the outgoing map before returning EOF to the writer. Incoming late mutation
cannot reintroduce forbidden fields. Body bytes, terminal errors and Close remain
delegated. No whole-body buffering or global transport sanitizer was added.

The symmetric response forwarding boundary uses independent maps and the same EOF
copy, preserving safe declarations while excluding proxy/nominated response fields.
Authentication is still decided from the ordinary request header before forwarding.
HTTP upstream CONNECT Basic authentication remains independently scoped and intact.
Routing, DNS, policy, CONNECT relay, SOCKS and shared lifecycle code are unchanged.

User-approved scope clarification: HTTP remains one request per client connection
with Connection: close. Same-connection keep-alive/pipelining remains unsupported;
reconnection and alternating forbidden/safe/empty trailers verify request isolation.

Fix-round results, source scope, immutable evidence hashes and raw validation logs:
`D:/splicore-validation/phase20-proxy-interfaces-review-fix1-20261008/PHASE20_PROXY_INTERFACES_REVIEW_FIX1_REPORT.md`.
At Fix Round1 exit, P20R-001 awaited Independent Re-Review. No Freeze, stage,
commit, push, tag, release or Phase21 action occurred during that Fix round.

## Targeted Independent Re-Review — Final Chronology

**PHASE 20 RE-REVIEW PASSED — READY TO FREEZE**.

P20R-001: **CLOSED**, original severity BLOCKER. New BLOCKER0 / MAJOR0.
The exact original helper was independently rerun100 times:0 leaks. Ordinary
Header, forbidden declaration and late Trailer credentials were absent at origin;
safe trailers remained preserved. Client credential A authenticated only Splicore;
configured upstream credential B authenticated only the upstream proxy; origin
received neither. HTTP remains one request per TCP connection / Connection: close.

Chronology: Implementation READY FOR REVIEW → Initial Independent Review FAILED,
historical3/3 leak → Fix Round1 READY FOR RE-REVIEW / FIXED — PENDING RE-REVIEW →
Targeted Independent Re-Review PASSED / P20R-001 CLOSED → IMPLEMENTATION REVIEWED.
Historical evidence is preserved at all four original external roots.

Canonical Re-Review report:
`D:/splicore-validation/phase20-proxy-interfaces-rereview-20261008/PHASE20_PROXY_INTERFACES_REREVIEW_REPORT.md`.
Verified final Fix fuzz2,695,710 (initial Phase20 separately3,741,138), custom
filter108,711; final fixed-source stress11m20.950227807s, unexpected errors0.
Full/default/native/shared race/checkptr and all three builds passed. Exact source
identity MATCH; repository files were unchanged during Re-Review.

## Freeze Receipt

The canonical [Phase20 Freeze report](PHASE20_PROXY_INTERFACES_FREEZE_REPORT.md)
is prepared before the sole authorized forward commit. Its identity is the commit
containing that report, with parent401b9e8b6032197108548ada7a4472440dfc65fc and
message `feat(client): add native socks5 http and mixed proxy interfaces`.
It activates only after commit, exact candidate/committed tree equality, clean
checkout and postcommit gates. Final status/hash and evidence live in
`D:/splicore-validation/phase20-proxy-interfaces-freeze-20261008/`.
No postcommit repository edit, second commit or amend is needed. Freeze is local;
public GitHub, tags/releases and Phase21 remain outside this work.
