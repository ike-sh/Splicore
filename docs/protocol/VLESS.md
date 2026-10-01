# VLESS / REALITY native candidate

- Documentation status: Canonical
- Audience: Operators, protocol and client developers
- Last reviewed: 2026-10-02
- Owner: Protocol maintainers
- Responsibility: Phase 5 canonical surface, secrets, engine bindings and qualification limits.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

VLESS and REALITY remain **Experimental**. Vision is **DEFERRED / UNSUPPORTED**.
Current support is flow-none only; its default safety and interoperability gates
are recorded in the [final report](../reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md).
The [initial report](../reports/PHASE_5_VLESS_REALITY_NATIVE_VERTICAL_SLICE_REPORT.md)
preserves the original Vision implementation and failed safety evidence.

## Identity and supported candidate surface

Protocol ID is `vless`, wire version `0`. Security selects the `plain`, `tls` or
`reality` feature profile under the same protocol. Engine ID is a separate `native`
placement. The registry also declares a `vless` → `xray` binding with availability
`not_compiled` and runtime_implemented=false. Selecting it fails before pending,
generation, storage or runtime side effects. No Xray executable/config is produced.

One IP TCP listener, one independent display endpoint and up to 16 UUID Bindings.
Transport is `tcp`; packet_encoding is explicitly `xudp`. UDP payload travels over
TCP using the existing XUDP path; there is no UDP listener. WebSocket, gRPC,
HTTPUpgrade, arbitrary transport/options, packetaddr selection and general mux
configuration are excluded. Account-owned UUIDs can be supplied or securely generated.

Canonical flow is `none` for plain, static TLS and REALITY. Requests for
`xtls-rprx-vision` fail with typed unsupported-operation errors, including config,
API/CLI/import, protocol validation, runtime building and ClientProfile. Exporters
and URI import reject with UnsupportedExport. No silent downgrade or flow removal.
Capabilities advertise Vision=false and supported flows=[none]. Static TLS uses the shared explicit
CA/SNI/protected-file contract. REALITY requires `with_utls`; without it the
feature profile reports not_compiled and creation rejects. No claim of Stable.

| Capability | Candidate support / qualification |
|---|---|
| TCP, IPv4, IPv6, domain endpoint | Baseline-supported; REALITY live matrix covers all three |
| UDP payload / UDP transport | XUDP over TCP / no UDP transport |
| Native multi-user | Yes, up to 16 configured; Alice/Bob same listener |
| Inbound/Binding stats | Authenticated routed payload and sessions, runtime generation |
| Account stats | Binding identity maps to Account; no persistent aggregate billing |
| HotUserUpdate / HotReload | false / false; affected inbound reconcile/restart |
| TLS / REALITY | Static TLS / existing upstream REALITY constructor |
| Vision | **DEFERRED / UNSUPPORTED**; rejected before commit, runtime and export |
| Quota, rate, max sessions | Unsupported; metadata-only policies remain metadata |

## REALITY material

| Value | Owner / representation / export |
|---|---|
| UUID | Account-owned typed UUID Credential; encrypted; explicit client export only |
| Private key | Inbound-owned PrivateKeyPayload, algorithm=x25519; existing AES-256-GCM vault; never client data |
| Public key | PublicKey, raw URL-safe base64 32 bytes; standard-library X25519 derivation; public settings/client TLS |
| Short IDs | Even hex, 0–16 characters, zero-padded to 8 bytes; up to 16; duplicate padded values reject |
| Empty IDs | Omitted/empty list means all-zero ID; empty string is a valid ID; client receives the selected first ID |
| ServerName | Explicit DNS allowlist/SNI; never replaced by display host |
| Target | Independent host/port for the upstream REALITY handshake; absent from client profiles |
| Listener | Actual local IP/port; absent from client profiles |
| Display endpoint | Public client host/port, independent of the other three values |

Write-only `server_secret.private_key` is separate from settings. Omission generates
a key during apply, before pending. A supplied public/private pair must match.
Committed settings contain the derived public key, never private key material or
a private-key file. Credentials use the existing owner/kind/schema-bound AEAD AAD.
Schema 4 adds a generic private_key kind, with no protocol or Account columns.

Ordinary inbound reads redact settings and omit UUID payloads. Doctor, audit and
formatters omit secrets. Export reveals only an authorized user's UUID; public key,
selected short ID and SNI come from public settings. Client projection does not
read the server-secret repository port. Automated Mihomo/sing-box/URI/API leak
checks are blocking gates. Synthetic tests generate all private material externally.

## Runtime and exporters

Native composes the exact sing-vmess service and sing-box TLS/REALITY constructors
inside an owned minimal Box. No wire source is copied. Users are immutable after
construction. Start owns TLS, a two-second target TCP reachability probe and the
listener; admission opens after commit. Handshakes have a five-second bound.
The target probe proves reachability, not target TLS compatibility or sustained health.
Close cancels, closes raw unauthenticated/authenticated sockets, closes TLS/router
and waits for the owned work. Reconcile interrupts all users and resets counters.
SQLite committed intent, including encrypted server credentials, is recovery authority.

Mihomo 1.19.30: VLESS type/server/port/uuid/network=tcp/udp=true/packet-encoding=xudp,
no flow field, TLS servername and either CA fingerprint or REALITY public-key/
short-id with chrome client-fingerprint. sing-box 1.14.1: VLESS outbound with explicit
packet_encoding=xudp, no flow field, TLS server_name and explicit CA or uTLS/chrome/REALITY
public_key/short_id. Wrong UUID/pbk/sid/SNI must not forward authenticated payload;
REALITY camouflage/fallback can still contact the target.

URI export supports plain and REALITY with strict host/IPv6 bracket/UUID/query
escaping, type=tcp, security, SNI, pbk, sid, fp=chrome and packetEncoding=xudp.
Supported exports omit flow; an imported Vision flow is rejected.
The parser supports this bounded dialect. URI import by reference clients is not
qualified. Explicit-CA TLS URI rejects because its trust material cannot be
faithfully represented. Surge returns UnsupportedExport.

## Vision blocker

The pinned sing-vmess v0.2.8 Vision path converts TLS pointers through uintptr.
Default Go 1.26 race builds terminate at vision.go:87 under checkptr. A diagnostic
build disabling checkptr **only in this dependency** still reports actual shared
state races between VisionConn.Read and filterTLS/Write. That build is not a passing
race gate. Production-build traffic checks do not clear this failure.
The independent memory-only reproducer failed 10/10 with default checkptr and
10/10 with actual races in the diagnostic build. Classification: upstream dependency
defect. Vision is now rejected and unreachable from the managed runtime. A compiler
hard gate runs before TLS material access; users register only empty wire flow, so
a Vision request fails the existing flow mismatch check before construction.

Upstream source/dependency versions remain unchanged. [ADR 0017](../adr/0017-defer-vision-dependency-safety.md)
owns deferral and re-enable criteria: reviewed fixed release or approved patch, then
default checkptr, race, original reproducer 10x, both clients, regressions and secret
gates must all pass. No automatic re-enable after an upstream release.

Source references: [baseline inbound](../../protocol/vless/inbound.go),
[baseline outbound](../../protocol/vless/outbound.go),
[REALITY server](../../common/tls/reality_server.go),
[pinned Mihomo VLESS](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/adapter/outbound/vless.go),
[pinned dependency Vision](https://github.com/SagerNet/sing-vmess/blob/v0.2.8/vless/vision.go).
