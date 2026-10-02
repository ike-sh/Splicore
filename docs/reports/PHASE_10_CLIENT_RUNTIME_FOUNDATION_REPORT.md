# Splicore Phase 10 Client Runtime Foundation Report

- Documentation status: Historical
- Audience: Maintainers and client/server runtime reviewers
- Last reviewed: 2026-10-03
- Owner: Core maintainers
- Responsibility: Phase 10 implementation, local acceptance evidence and explicit limits.
- Lifecycle: Preserve this acceptance snapshot; later qualifications require a new report.

## Baseline

Phase 9 Freeze: **FROZEN** at `d47ef2c584654eaa8eaa965ef26b7acc24881e1f`.
Entry HEAD == main == Phase 9; worktree CLEAN, index EMPTY. Branch:
`codex/phase-10-client-runtime-foundation`. This implementation is unstaged and
uncommitted. Entry evidence includes 1907 source hashes, 19 protected historical
report/migration hashes and 145 NoBrand tracked-file hashes.

Evidence root: `D:\splicore-validation\phase10-20261002`.
Native temporary/service fixtures: `/root/splicore-p10-20261002`.
`entry.json`, `linux-gates.json`, `windows-gates.json`, `build-gates.json`,
`service-gates.json`, safe `live-responses` and final audit records are external.
No production targets or credentials; no downloads, Docker query/touch or NoBrand edits.

## Status

Client Runtime: **Experimental**. Server Runtime: **UNCHANGED behavior**, existing
Experimental feature scopes retained. No public release or Phase 10 freeze.
One existing binary and systemd service own both roles.

## Architecture

| Principle | Result |
| --- | --- |
| Node != Outbound | PASS: resource identity separate from engine-specific use. |
| Server Account != Remote Node | PASS: separate tables, models and credential owners. |
| Protocol != Engine | PASS: Snell ProtocolID with native EngineID and exact pair registry. |
| ClientProfile != Runtime Outbound | PASS: third-party export projection retained separately. |
| Single daemon | PASS: shared Application, API, CLI, vault, journal and SQLite. |

See [Client Runtime](../architecture/CLIENT_RUNTIME.md),
[Routing Model](../architecture/ROUTING_MODEL.md) and
[ADR 0022](../adr/0022-client-runtime-domain.md).

## Domain

- RemoteNode: immutable UUID, renameable name, ProtocolKey, IPv4/IPv6/domain endpoint,
  credential reference, typed TCP/none options and bounded schema-versioned metadata.
- Credential: existing generic encrypted vault abstraction, extended with RemoteNode
  owner and node-specific AAD. No node.snell_psk or protocol-specific storage column.
- Outbound: independent ID/name/kind, NodeID and EngineID; builtin `direct` is not a protocol.
- LocalInbound: independent SOCKS5 client listener; defaults to loopback/no-auth.
- MinimalRoute: committed default outbound plus optional per-local selected override.
- ClientSession: ephemeral ID/references/counters; no Account/Binding conflation.

References reject dangling deletion and preserve identity through rename. Limits:
128 nodes, 129 outbounds, 32 local listeners, 4096 accepted sessions.

## Protocol Registry

Snell Server and Client: **SUPPORTED / Experimental**, same ProtocolID.
Native Inbound and Outbound roles: true. Other protocols and Xray: inbound only.
Effective engine implementation roles use protocol/engine intersection.
Central protocol switches added: **0**. Version dispatch stays in the Snell module.

## Outbound Registry

DIRECT: builtin real TCP dialer. Snell/native: registered embedded adapter factory.
Unsupported protocol/engine pair rejection: **PASS**, including Snell/Xray.
Registry construction rejects duplicate/nil registrations and publishes immutable entries.
No new NativeClientEngine or external client implementation process.

## Local SOCKS

Listen: configurable loopback IP/port; real 127.0.0.1 and ::1 traffic verified.
Default binding: loopback. TCP CONNECT: **PASS**. UDP ASSOCIATE: **DEFERRED**,
explicit reply 7. Auth: no-auth only. LAN exposure default: **NO**; all unauthenticated
non-loopback listener addresses reject. Handshake and remote dial deadlines: five seconds.

## DIRECT

IPv4, IPv6 and Domain TCP: **PASS**, through the actual Local SOCKS and client runtime.
Domains use OS resolution; no separate advanced DNS engine.

## Snell Outbound

Protocol: `snell`. Engine: `native`. Versions: server5→client4 and6→6;
canonical mapping reused by exporter. Silent downgrade: **NO**.
TCP: **PASS**. Remote adapter UDP: **PASS** for v5/v6 through optional
ClientPacketDialer, independently tested from local SOCKS UDP.
Credential: encrypted generic node-owned PSK. Native inherited wire implementation
is embedded inside an owned Box; source/wire changes **0**.

## End-to-End

Application → Local SOCKS → Splicore Client → Snell → Splicore Server → Target:
**PASS**. Separate Splicore A server and Splicore B client/server instances are used.
Installed B is the actual `splicore.service`, not a test replacement daemon.
DIRECT takes the same client routing path.

## Interoperability

| Direction | Result |
| --- | --- |
| Splicore Client → Splicore Server v5/v6 | PASS: unit and installed-service traffic. |
| Splicore Client → pinned sing-box 1.14.1 Snell reference server v5/v6 | PASS: installed-service fixture. |
| Existing third-party Client → Splicore Server | PASS: 48 installed server smoke cells across six lifecycle stages. |

Pinned reference server SHA256:
`9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9`.
External reference processes are servers for client acceptance; existing server
regression clients remain separate reference evidence. The Splicore client is embedded.

## Stress

16 concurrent client connections: **PASS**, plus simultaneous B server traffic.
4 MiB integrity: **PASS**, SHA256
`3cab7815c40973b8fb036c7a2a69b3649882622a4a0a2f1a980efa4ef8545577`.
Reconnect, abnormal remote close, abnormal local close and session cleanup: **PASS**.
Established sessions retain their generation during route/credential replacement.

Inherited Snell command-1 EOF/half-close may close the tunnel; Phase 10 does not
change that frozen contract. Tests read the full fixed-length echoed payload before
ending the application session. Full duplex EOF semantics are not newly qualified.

## Server + Client Coexistence

Server inbound active, client SOCKS active, concurrent traffic and isolation: **PASS**.
An offline A produces failed passive outbound health while B DIRECT/self-server/API/CLI
remain live. Restoring A allows new client traffic without restarting B.

## Transaction

Create/validate/plan/apply: **PASS**. HMAC plan binds raw canonical document to the
shared global revision. Pending journal precedes adapter construction and closed-admission
socket bind; committed SQLite precedes activation. Network I/O stays outside SQL.

Port conflict, missing credential, invalid node/endpoint/port/version/engine,
referenced deletion, missing route/outbound and injected startup failure: **PASS**
as clean failures. Abort closes only candidates and compensates pending state.
Injected commit failure after candidate writes proves rollback preserves committed
revision, listener and established session. Successful restart advances one revision
and closes old sessions after commit. No sleep, retry masking, recover or skipped tests.

## Recovery

SQLite authority: **PASS**, forward-only schema 5 with generic client tables and
exactly-one credential owner. Populated schema2/3/4 migration preserves existing
credentials/bindings. Old migrations remain unchanged.
Actual service restart, local SOCKS/outbound reconstruction and resumed traffic: **PASS**.
Client listener restoration failure reports degraded client state while existing
server/API remain available. Corrupt committed state remains a storage error.

## Stats

LocalInbound, Outbound, Node and Session payload/session observations: **PASS**.
Counters use atomics; snapshot generations retain fixed counter pointers. Deleted
resources are pruned without invalidating old sessions. Active sessions return to zero.
Double-counting policy: these are separate views of the same payload; **never sum
them for billing**. Durable usage, quotas and client policy enforcement are deferred.

Passive health distinguishes configured/available/active/last error. Availability is
set by downstream payload, not Node existence or startup. Last error is a fixed code.
The available/error pair is atomically published as one immutable observation.

## API

Remote Node CRUD/credential rotation, Outbound CRUD, LocalInbound CRUD, default Route,
client runtime/lifecycle and validate/plan/apply: **PASS** in existing `/api/v1`.
CRUD uses If-Match global revision and GET ETag; stale revision returns 409.
Unknown path 404; wrong method 405/Allow; strict bounded JSON and no query parameters.
Secrets redacted: **PASS**. Write-only credential input is absent from read responses.
OpenAPI 3.1 validates static schemas and 13 captured safe live API/CLI responses,
including real client state, resource, plan and apply replies.

## CLI

Client status/lifecycle, node/outbound/local-inbound management and route plan/apply:
**PASS**. Same binary, same protected control transport. Resource mutation files and
saved plans follow shared transactional semantics. Unified status separates
server_runtimes and client_runtime. See [CLI](../CLI.md).

## Doctor / Support Bundle

Doctor client counts, listeners, route and passive health: **PASS**, no active node probes.
Support bundle includes client.redacted.json; fixed projections drop names, raw domains,
IDs, metadata/options and errors. Hostile-input and installed decompressed archive
secret scans: **PASS** across eight projections. Secrets leaked: **NO**.

## Security

SOCKS default: loopback; unauthenticated LAN listeners reject. Credential logs: **NONE**.
Generic API stored credential secrets: **NONE**. Support bundle: **REDACTED**.
All traffic uses synthetic loopback fixtures. Node domains stay canonical; local
resolution selects the remote server. Snell target domains are forwarded to the
remote server; DIRECT target domains resolve locally. Advanced DNS is deferred.

## Race

Default race: **PASS**, with default checkptr enabled. Shared runtime race: **PASS**.
Route publication is atomic; narrow locks protect reference acquisition and maps.
Sessions own generations, sockets and counters. Each payload direction owns buffers;
no shared scratch/backing-array reuse, early pool return or new unsafe pointer.
Final connection Close precedes release of the session's generation reference,
so a connection can safely return resources to a retired adapter/pool. The minimal
local reproducer fails on the prior source with one unclosed connection at adapter
retirement, then passes ten times with default race after the ownership fix.

Fresh commands (Linux Go 1.26.6, with_quic/with_utls):

```sh
go test -count=1 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore
go test -race -count=1 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore
go test -race -count=10 -tags with_quic,with_utls ./internal/splicore/application -run 'TestClient|TestSnellOutboundRemoteUDP' -timeout 240s
go test -race -count=10 ./internal/splicore/clientruntime -run TestRetiredGenerationClosesAfterSessionConnection
go test -race -count=1 ./common/... ./adapter/... ./transport/... ./route/... ./protocol/snell
go vet -tags with_quic,with_utls ./internal/splicore/... ./cmd/splicore
```

All PASS. No GODEBUG/gcflags/checkptr or race disabling. Existing unrelated inherited
unsafe-pointer vet findings remain in their frozen ledger; no full upstream-vet claim.

## Fuzz

RemoteNode, Endpoint, Outbound, Route and Snell adapter options: **PASS**, separate
bounded three-second fuzz campaigns with two workers. No wire/crypto fuzzing.
Seed/corpus/cache artifacts remain outside the repository.

## Server Regressions

Snell, Hysteria2, TUIC, VLESS Native, VLESS Xray, FinalMask/Sudoku and Mieru:
**PASS**. Eight installed profiles (Mieru TCP/UDP separately) at initial/restart/
crash-recovery/upgrade/rollback/reinstall yield **48/48 PASS**. Frozen feature limits
remain: Vision unsupported, bounded Sudoku scope and deferred strict policies.

## Distribution Regression

Package/build, install/start, non-root low ports, doctor/support, normal upgrade,
failing schema5→6 migration rollback, retained-state uninstall/reinstall and safe
purge: **PASS**. Client campaigns across six stages yield **90/90 PASS**, plus
16 concurrent connections and 4 MiB per campaign. Same unit restores client intent;
unrelated Xray process remains unaffected by the owned parent crash test.

The disposable outer systemd init teardown reaches its existing 20-second timeout;
product lifecycle gates finish successfully. Final lab MainPID is zero and cgroup
has no processes; only owned failed-unit bookkeeping is reset. This is recorded,
not presented as clean outer-init termination.

Early failed attempts are retained externally: missing namespace DNS fixture caused
remote-domain traffic failure. A loopback-only localhost A/AAAA fixture fixes the
environment without forwarding or runtime changes. An extra diagnostic restart
consumed the unit's start-rate budget; it was removed while retaining required
restart/crash gates. No traffic retry or acceptance condition was relaxed.

## Platform

Linux amd64 Ubuntu 24.04 WSL2: actual runtime/service PASS, Go 1.26.6.
Windows amd64: full owned tests and actual native client E2E PASS, Go 1.26.2;
no Windows service/production UDS qualification. Linux arm64: compile PASS only,
not a runtime qualification. All artifacts/source copies remain external.

## Runtime Source Audit

sing-box runtime source modified: **0**. Mieru source modified: **0**.
Xray source/artifact changed: **0**. Wire changes: **0**.
Changes stay in owned internal/splicore, cmd/splicore tests, scripts and docs.
Historical Phase 0–9 reports and migrations 0001–0004 remain hash-identical.

## Scalability

| Metric added by Phase 10 | Count |
| --- | --- |
| Central protocol switches | 0 |
| Central client protocol switches | 0 |
| Application protocol branches | 0 |
| Storage protocol-specific columns | 0 |
| Node protocol-specific credential fields | 0 |
| Exporter engine branches | 0 |
| Additional product binaries | 0 |
| Additional product services | 0 |

Protocol version/credential-kind validation remains inside its owning module or
generic secret boundary. Resource/action/kind dispatch is protocol-neutral.

## Deferred

HY2, TUIC, VLESS native/Xray and Mieru outbounds; local SOCKS UDP; advanced routing,
DNS engine, policy groups, TUN, system proxy automation, subscriptions/providers,
URL-Test/fallback/load balancing, active health probing, durable usage and NoBrand
migration. Server and client remain Experimental, with no stable release.

## Git

Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**. Release: **NONE**.
HEAD/main/refs/remotes remain unchanged from the entry checkpoint. Worktree contains
the reviewable implementation; index remains empty. Real NoBrand repository unchanged.

## Final Result

**CLIENT RUNTIME FOUNDATION READY FOR REVIEW**.

## Blockers

None within the qualified Phase 10 scope. Deferred features and platform limitations
above are explicit and are not claimed as passing acceptance.
