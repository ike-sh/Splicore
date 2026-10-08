# Splicore Phase 20 Native SOCKS5 / HTTP / Mixed Proxy Interfaces Freeze Report

# PHASE 20 IMPLEMENTATION REVIEWED — FREEZE RECEIPT REQUIRED

## Verdict

Final Targeted Independent Re-Review: **PASSED — READY TO FREEZE**. P20R-001 CLOSED; new BLOCKER0 / MAJOR0; known implementation blockers NONE KNOWN.

This repository report is prepared before the authorized single commit. Freeze identity activates only when that commit succeeds and the external receipt verifies its exact tree, sole parent, clean checkout and postcommit gates. The final **PHASE 20 FROZEN** verdict is recorded externally after success. No premature successful status or second documentation commit is created. Freeze means REVIEWED + FROZEN only.

## Commit

PHASE_20_FREEZE_COMMIT: **the commit containing this report**.

Exact message: `feat(client): add native socks5 http and mixed proxy interfaces`.

Sole parent: `401b9e8b6032197108548ada7a4472440dfc65fc`. Branch: `codex/phase-20-proxy-interfaces`. Exactly one forward local commit. Resolve after success:

    git log -1 --format=%H -- docs/reports/PHASE20_PROXY_INTERFACES_FREEZE_REPORT.md

Actual hash, candidate/committed tree and final verdict belong to the external final receipt under `D:/splicore-validation/phase20-proxy-interfaces-freeze-20261008/`. This follows the Phase17/18/19 convention and avoids a self-referential commit hash.

## Base

Phase19 FROZEN: `401b9e8b6032197108548ada7a4472440dfc65fc`; message `feat(protocol): add native vmess server and client`. Freeze entry: expected branch, DIRTY / UNSTAGED, Index EMPTY. All1207 repository files matched Targeted Re-Review entry/final hashes before documentation edits.

## Scope

Entire Phase20 — Native SOCKS5 / HTTP / Mixed Proxy Interfaces: inbounds/outbounds, CONNECT/UDP ASSOCIATE, no-auth/RFC1929/Basic, IPv4/IPv6/DOMAIN, shared Routing/DNS/Policy, generic Account/Credential/Binding/Node/Provider, API/CLI/SQLite/backup/restore, Native TUN, lifecycle/stats/doctor/support, reviewed tests/fuzz and P20R-001. It is not merely a trailer fix. Freeze edits only this report, implementation/architecture status and ADR phase metadata; Go/module/test/fixture/schema/migration semantics are immutable.

## Surface Identity

SOCKS5 ProtocolID `socks5`, EngineID `native`; HTTP ProtocolID `http`, EngineID `native`. Mixed is a shared local listener mode, not a remote Node protocol. Actual factories and canonical codecs are owned by Splicore. External production core0; no production sing-box/Xray/Mihomo subprocess for these surfaces. External peers are validation tools only.

## SOCKS5 Inbound

CONNECT SUPPORTED; UDP ASSOCIATE SUPPORTED; NO AUTH and RFC1929 username/password SUPPORTED; IPv4/IPv6/DOMAIN SUPPORTED. Canonical bounded RFC codec, shared management/listener/runtime. BIND UNSUPPORTED/DEFERRED; UDP FRAG!=0 UNSUPPORTED. No encryption is conferred by plaintext proxy authentication.

## SOCKS5 Outbound

Native upstream CONNECT and UDP ASSOCIATE when UDP is enabled; no-auth/RFC1929. Generic Node validation/import/export/provider, protected underlay and clientio socket owner. DOMAIN is preserved to upstream where shared policy selects remote resolution; live deadlines, control ownership, reader join and half-close follow reviewed contracts.

## SOCKS5 UDP ASSOCIATE

TCP control connection owns the association; control Close/EOF terminates UDP and joins readers. Source address binding/anti-hijack and identity-safe cleanup PASS. Registry has bounded lifetime/target count, idle expiry, reader-death cleanup, replacement safety and joined parent shutdown. Existing source-binding/ownership regressions and real TUN payloads are accepted, hash-verified evidence; no Freeze rerun.

## Authentication

SOCKS NONE/USERPASS and HTTP NONE/Basic share generic account-owned username/password credentials. At most128 eligible binding pairs per listener, immutable hashed constant-time comparisons. Enabled/account-active/expiry/credential checks enforced; rotation uses new credential ID and restarts affected sessions after commit. Missing/invalid ordinary HTTP Header cannot authenticate via late Trailer. Basic/RFC1929 are cleartext on plaintext transport; no encryption claim.

## Remote DNS

For managed remote-resolution DOMAIN policy, exact domain is sent to upstream SOCKS proxy. Accepted evidence: local resolver calls0. Shared routing modes requiring IP/CIDR/bootstrap resolution legitimately resolve first; no blanket assertion that every domain always bypasses local resolution. socks5h export preserves intended remote DNS semantics; no protocol-local resolver engine.

## HTTP Inbound

HTTP/1.1 absolute-form plain forwarding and CONNECT SUPPORTED; no-auth/Basic SUPPORTED. Bounded pre-read, strict critical field/framing/authority checks; shared routing/DNS/policy and leased protected dialer. Request body remains streaming. Owned sanitized Header/allowed Trailer maps and EOF safe-value copying prevent proxy credentials crossing to origin; response metadata ownership follows the same reviewed boundary.

## HTTP Outbound

Native authenticated/no-auth CONNECT SUPPORTED, successful2xx and bounded informational handling; any tunneled TCP application is supported under reviewed transport scope. Configured Proxy-Authorization reaches upstream proxy, not origin. Generic UDP UNSUPPORTED and explicit capability controlled. HTTP/2 proxy, HTTP/3, MASQUE, CONNECT-UDP, Digest/NTLM deferred; MITM outside scope.

## HTTP Connection Contract

**ONE REQUEST PER CLIENT TCP CONNECTION / Connection: close**. Keep-alive and same-connection second request/pipelining NOT SUPPORTED. Cross-request verification uses new connections, not invented keep-alive functionality. Re-Review36 independent alternating connections plus60 canonical reconnections passed with no stale metadata; actual connection EOF verified.

## HTTP Credential Trust Boundary

Credential A authenticates client to Splicore HTTP inbound only. Credential B authenticates Splicore to upstream HTTP proxy only. Complete upstream CONNECT+tunnel wire contains B and no A; complete origin metadata/raw wire contains neither. Ordinary Header, Trailer declaration and late-populated forbidden Trailer values are stripped. Safe application Trailer remains preserved; upstream Basic is not globally deleted. Actual two-hop200 reply and streaming payload PASS.

## Mixed Inbound

One TCP listener detects SOCKS5 or HTTP with bounded non-destructive pre-read and existing handshake deadline. SOCKS and HTTP use the same shared framework and auth pairs. UDP is SOCKS5 association semantics only; HTTP does not gain UDP. Fragmented/coalesced detection, actual payload and cancellation coverage PASS.

## Capability Matrix

| Surface | TCP | UDP | Auth |
|---|---|---|---|
| SOCKS5 Inbound | YES | YES | NONE / USERPASS |
| SOCKS5 Outbound | YES | YES when enabled | NONE / USERPASS |
| HTTP Inbound | YES | NO | NONE / Basic |
| HTTP Outbound | YES | NO | NONE / Basic |
| Mixed Inbound | YES | SOCKS5 only | Shared pairs, according to path |

## Default Listener Safety

Default host `127.0.0.1`; explicit `::1` supported. Numeric nonloopback/wildcard bind requires deliberate `allow_lan=true`. Doctor diagnoses public unauthenticated listeners. Authenticated listener with no eligible binding rejects all clients. No implicit public open proxy. Actual normalization/validation and accepted Review exposure tests verified.

## Account / Credential / Binding

Existing generic encrypted vault, Account IDs and write-only credential ingress. Local Bindings stored in LocalInbound JSON because existing SQL server-binding FK targets managed server inbounds. Validation occurs during prepare/commit/committed-state reads; rotation cleanup preserves unrelated accounts/server credentials. No separate proxy account database.

## Node / Provider

Generic immutable Nodes with native socks5/http capability and typed username/password or exact no-auth marker. URI/external import/export preserves protocol/remote DNS/auth/UDP semantics. Shared Provider preview/apply/refresh/rollback and redaction remain authoritative; no shadow provider path.

## API / CLI

Existing `/api/v1` and Application Service; generic local-inbound/node/outbound APIs plus local-binding list/create/get/update/delete/credential rotation. Shared If-Match revision checks and prepare/transaction pipeline. CLI local-binding list/get/validate/plan/apply delegates to service; node/export/Provider operations remain generic. Stats/doctor/support use redacted shared projections; no independent management transport.

## SQLite

Migrations: **NONE**. Existing schema8 retained; migration/schema files unchanged from frozen base. Local-listener JSON accommodates generic bindings/auth references. Reviewed state-commit/read validation remains; Freeze creates no database/schema change.

## Backup / Restore

Accepted management evidence verifies encrypted Account/Credential/local Bindings, SOCKS/HTTP Node IDs/auth options and reconstructed runtime after restore; actual authentication/payload works and plaintext synthetic pairs absent from backup bytes. Linux maintenance evidence does not qualify Windows platform maintenance.

## Routing / DNS / Policy

Existing shared snapshots, routing, DNS and Policy selector/URLTest/fallback/load-balance. No protocol-owned routing engine or new system resolver bypass. HTTP outbound is TCP only; capability validation rejects HTTP-selected UDP, filters incompatible members for UDP policy and rejects impossible UDP detours. DIRECT remains UDP capable.

## Native TUN

Accepted isolated real Linux kernel TUN integration: TCP→SOCKS, UDP→SOCKS and TCP→HTTP. HTTP UDP remains unsupported/capability controlled. Shared gVisor/host-network/socket ownership unchanged. Real TUN x25 and final fixed-source stress evidence reused by identity; no destructive platform rerun.

## Interoperability

Evidence paths in the following historical matrix refer to `D:/splicore-validation/phase20-proxy-interfaces-20261008/`.

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

Final fixed-source/re-review credential boundary and curl chunked payload proof are preserved. All versions/directions are historical recorded evidence; Freeze starts no new peer or network experiment.

## Review History

Implementation READY FOR REVIEW → Initial Independent Review **FAILED** → P20R-001 **BLOCKER**,3/3 leaked → Fix Round1 READY FOR RE-REVIEW / **FIXED — PENDING RE-REVIEW**,100/100 protected → Targeted Independent Re-Review **PASSED — READY TO FREEZE**, exact original helper independently100 repetitions/0 leaks → P20R-001 **CLOSED**. Historical failed evidence is preserved. Canonical roots are implementation, initial Review, Fix1 and Re-Review under `D:/splicore-validation/`; all469 input files are protected by entry/final integrity manifests. ADR0041 remains Proposed; only its Phase status metadata is finalized.

## P20R-001 Closure

Original severity **BLOCKER**; chunked Proxy-Authorization Trailer leaked to origin, a credential trust-boundary violation. Historical3/3 leak retained; Fix100/100 protected; independent unchanged original helper100/100 protected,0 leaks. Header/declaration/late Trailer ownership, case variants, safe Trailer, streaming/errors, auth decision, two-hop, Mixed, race/lifecycle and no new BLOCKER/MAJOR all15 closure criteria pass. Final **CLOSED**. Source/evidence identity MATCH. See external `phase20-proxy-interfaces-rereview-20261008/p20r001-closure.md`.

## Fuzz

Initial Phase20: **3,741,138** executions. Fix Round1 additional: **2,695,710**, including Splicore-owned HTTPForwardTrailers **108,711**. Separately verified from final raw fuzz counts, not merged into an inaccurate total. Crashes0; reported timeouts0; final jobs PASS. No Freeze fuzz run.

## Race / Checkptr

Default race PASS; native race PASS; shared race PASS; checkptr **ON**, bundled compiler default with no disabling override. Full tests PASS; fresh Re-Review targeted race ownership/EOF/error/Close/cancellation/concurrency/lifecycle PASS. Expensive evidence is bound to reviewed fixed source; no long rerun.

## Resource Tests

Initial reviewed proxy churn25:675 valid TCP/auth payloads,75 invalid rejects,150 rotations; goroutines4→4 and FDs12→12. Fresh Re-Review HTTP metadata churn25/200 streams: G4→4, FD12→12, sessions0, leaks0. Registry replacement/control shutdown/cancellation tests pass. Allocator RSS retention is not a heap/platform qualification.

## TUN x25

Final accepted real TUN25 measured lifetimes: **PASS**,936 TCP /312 UDP payloads; G6→6, FD14→14, sessions0. Exact unchanged TUN/source/evidence identity verified in Re-Review. Historical whole-source snapshot differs only in the documented later HTTP/docs/tests delta; reuse concerns unchanged shared TUN surfaces, not whole-snapshot raw equality.

## Mixed Stress

Authoritative final fixed-source workload: **11m20.950227807s**,1320 TCP /552 UDP payloads,192 expected security rejects, unexpected errors0, DNS bypass UDP0/TCP0. G39→39, FD32→32, sessions0. Includes plain/chunked safe+forbidden Trailer HTTP, CONNECT, Mixed HTTP/SOCKS, upstream Basic, historical protocols, IPv4/IPv6, routing/policy/proxied DNS. Initial implementation **11m7.608838089s** remains separate historical evidence. No new stress during Freeze.

## Existing Protocol Regression

SS, SS2022, Snell, HY2, TUIC, VLESS, Mieru, Trojan, VMess, DIRECT and REJECT accepted regression state **PASS**. Existing native default/shared suites and final fixed-source mixed payload stress verified. No unrelated protocol is changed during Freeze.

## Historical Finding Regression

All remain **CLOSED**: `R17-001`, `R17-002`, `R17-003`, `RR17-001`, `RR17-002`, `VLESS_PARTIAL_FRAME`, `VLESS_ASSOCIATION_REGISTRY`, `T18R-001`, `P19R-001`, `P19R-002`, `P19R-003`, `P19RR-001`, `P20R-001`. No new BLOCKER/MAJOR. Snell remains **PRE-EXISTING NON-BLOCKING LIMIT**: frozen256 socket admission; UDP uses two entries; prior uncadenced saturation is not reclassified or fixed here.

## SagerNet

Required exact candidate/postcommit gate: **Source0 / Direct0 / Graph0 / Binary0**. AST all Go files/build tags/nested modules, offline graph and metadata on all three fresh native-tag builds. Nonzero blocks Freeze. External sing-box peer is not a production module/core.

## Module Identity

`module github.com/ike-sh/Splicore`; no replace/vendor identity shim. Go module/source identity preserved and fresh go mod verify/go list ./... required before staging, on candidate and after commit.

## Dependencies / Attribution

Phase20-added dependencies: **NONE**.

| Module | Version | Purpose | License |
|---|---|---|---|
| NONE | — | No new dependency | Existing attribution unchanged |

Existing95 notice files cover69 audited modules and remain byte-identical to the reviewed source and official local module cache. Freeze adds/removes no modules or licenses; existing notices are not rewritten.

## Underlay

Actual Phase20 production surface count: **81**, test surfaces203; Unknown **0**. Recalculated from current reviewed source; candidate/postcommit must agree. New metadata wrapper owns no socket/dial call; forwarding retains protected leased adapter.

## Xray Boundary

Fresh reviewed final source inventory: **E=0 / F=0 / G=16**, active Xray runtime0. G is an audited legacy/interop/test reference category, not16 active runtimes; non-test Go subset5. Counts are recalculated on exact candidate and postcommit source, not assumed from Phase19. External interoperability YES where historical fixtures used peers. New production sing-box/Xray/Mihomo subprocesses0.

## Builds

Fresh quick builds required at prestage, exact candidate and exact committed tree:

| Platform | Gate | Qualification |
|---|---|---|
| Linux amd64 | PASS required | NOT REQUALIFIED |
| Windows amd64 | PASS required | NOT REQUALIFIED |
| Linux arm64 | PASS required | BUILD ONLY |

Native gVisor/QUIC/uTLS tags; CGO_ENABLED=0; offline/read-only module env. No published binaries or release archives.

## Secret Scan

Exact candidate and committed-tree source scans require **real0 / unresolved0**. Ordinary proxy Header/Trailer/Basic/SOCKS/URI fixture strings are synthetic; known classifications bind to reviewed hashes and changed status/report metadata is inspected. Values omitted; no real credentials used. All raw evidence/scripts/binaries stay outside repository.

## Known Limitations

SOCKS BIND unsupported/deferred; UDP FRAG!=0 unsupported; HTTP UDP unsupported; HTTP inbound keep-alive unsupported (one request/Connection: close); HTTP/2 proxy, HTTP/3, MASQUE, CONNECT-UDP, Digest/NTLM deferred; MITM out of scope; System Proxy/PAC Phase21/deferred. Existing live account-mutation and occupied-port protocol switch limits are unchanged. Snell PRE-EXISTING NON-BLOCKING LIMIT retained.

## Platform Qualification

Historical **PARTIALLY PASSED**. Phase20 **NOT REQUALIFIED**; frozen Phase20 **NOT PLATFORM QUALIFIED**. Linux arm64 **BUILD ONLY / runtime NOT CERTIFIED**. Known implementation blockers: **NONE KNOWN** if all Freeze gates succeed. Freeze means REVIEWED + FROZEN only, not certified.

| Gap | Retained canonical boundary |
|---|---|
| GAP-01 OPEN | Historical packaged-daemon qualified long-duration goroutine measurement missing; short tests do not close it. |
| GAP-02 OPEN | Safe destructive Windows real-network target unavailable; Windows race compiler prerequisite absent. |
| GAP-03 OPEN | Native Ubuntu host-network target unavailable; isolated WSL kernel TUN is supplemental evidence. |
| GAP-04 BUILD ONLY | Actual Linux arm64 runtime target unavailable; runtime NOT CERTIFIED. |

Canonical platform qualification report hash is protected; no qualification rerun.

## Git State

Entry: expected frozen base, DIRTY / UNSTAGED, Index EMPTY. Every changed/new file belongs to the explicit Phase20 manifest. Exact future tree is produced by git write-tree and materialized by git archive, not a worktree copy. Authorized docs plus raw-identical implementation or proven CRLF↔LF-only metadata normalization only; non-EOL implementation drift0, Go/module raw drift0. Persistent Git config/.gitattributes unchanged. After the sole commit: exact candidate tree MATCH, CLEAN worktree and Index EMPTY required.

## Public GitHub

**UNCHANGED**. User-provided existing public release v0.1.0 remains untouched; no remote access/public write, push, tag or release. No v0.2.0 created.

## NoBrand-OneClick

**NOT ACCESSED**.

## Actions Not Performed

No implementation/parser/lifecycle/API/database/dependency/test semantic changes; no new interoperability/network probes/captures/scans; no long stress/TUN/fuzz/platform rerun; no reset/rebase/amend/squash/history rewrite; no push/tag/release/public update; no Phase21/System Proxy/PAC/WS/gRPC/XHTTP work. Exactly one local forward commit is authorized, contingent on gates.
