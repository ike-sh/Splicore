# Splicore Phase 3 Hysteria2 Vertical Slice Report

- Documentation status: Historical
- Audience: Maintainers and implementation reviewers
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Phase 3 implementation, actual qualification, limitations and review gates.
- Lifecycle: Preserve the accepted implementation, failure timeline and freeze evidence.

## Baseline

Phase 2 Freeze Commit / historical entry HEAD / main:
`5bc50a69b0df2c3dc9ede86015c9e4a6b86e2981`.
Branch: `codex/phase-3-hysteria2-vertical-slice`; worktree/index were clean at the
original Phase 3 implementation entry. Independent WSL acceptance started with
the existing unstaged Phase 3 implementation.
Upstream: sing-box v1.14.1, `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
Module: `github.com/sagernet/sing-box`; sole remote: upstream
`https://github.com/SagerNet/sing-box.git`. Pinned sing-quic: v0.7.0.
No dependency/module edits or upstream runtime edits are required.

Fresh evidence is external at `D:\splicore-validation\phase3-20261001`.
It was moved from the task's C-drive Temp directory after C exhausted space.
Earlier task evidence was preserved on D with junctions retaining its original
paths. No repository log/binary/private fixture is used as domain authority.

## Current Status

**PHASE 3 LOCALLY FROZEN**, Hysteria2 **Experimental**. Independent Ubuntu WSL2
acceptance and the final architecture/freeze gates passed on 2026-10-01.
The containing commit is the unique Phase 3 freeze; full SHA, commit statistics,
main fast-forward and reserved Phase 4 branch checks are recorded externally in
`D:\splicore-validation\phase3-freeze-20261001` and the final freeze response.
TUIC implementation has not started. Historical failures/review statuses below
remain intact; the final disposition section supersedes their pending review items.

## Initial Implementation Status (historical)

Hysteria2: **Experimental**, never Stable. Snell remains Experimental.
Implementation and initial full race-server interop pass; final gates are listed
below. No large-scale field, production NoBrand or stable release claim.

## Architecture

| Area | Realized boundary |
|---|---|
| Account | Generic identity/status, no protocol password/TLS columns |
| Binding | Account/Inbound/Credential authorization; native user identity is immutable Binding ID |
| Credential | Typed generic password, secure generation/validation, encrypted existing AEAD/AAD path |
| Inbound | UDP listener, independent DisplayEndpoint, bounded static TLS settings and 1–16 users |
| Protocol | HY2 metadata/capabilities/validation/runtime intent/profile, no HTTP/SQL/NoBrand |
| Engine | One Native Engine with protocol compiler map; shared lifecycle contract |
| TLS | Existing sing-box TLS constructor, protected file snapshot, required CA/chain/SNI validation |
| ClientProfile | Endpoint/password/QUIC/UDP/CA/SNI/h3; no Engine/server private key/policy enforcement |
| Exporter | Existing format registry dispatches protocol-key maps to pinned client mappings |

Create coordination is shared by Snell/HY2. SQLite committed state is authority.
The exact service used by the stock inbound supplies HY2 wire/QUIC/congestion/UDP.
Splicore owns admission, lifecycle and authenticated routing meters. See
[profile](../protocol/HYSTERIA2.md) and [ADR 0014](../adr/0014-hysteria2-runtime-composition.md).

## Protocol Registration

Adding Hysteria2 required changes outside protocol module/registration:

| Files/area | Reason |
|---|---|
| domain/access and storage/sqlite credentials + migration 0003 | Generic password kind/payload and encrypted schema-3 persistence |
| ports/runtime, ports/export, clientprofile | Multi-Binding repository/lifecycle/stats/export contracts; explicit CA trust |
| engine/native engine, HY2 adapter, meters, TLS owner helpers | Shared compiler dispatch, UDP admission, existing service/TLS composition, payload attribution |
| exporter dispatch/HY2 and Snell description | Protocol-key routing and content-shape envelopes; no Engine-based export |
| application runtime/HY2 and Snell/service | Shared create coordinator, authorized multi-Binding projection/recovery/export and replacement compensation |
| API, transport, CLI | Three HY2 commands, Binding enable/disable, protocol selection and explicit export Binding |
| app composition, version, cmd identity test | Phase3 composition and database schema identity 3 |
| tests, scripts, fixture and canonical docs | Cross-protocol regression, platform/interop/contract evidence |

Central switch additions: API path/CLI command dispatch for the new public
operations; generic password tagged-data encode/decode. **No central protocol
switch in Native Engine compile, runtime projection, recovery or exporter dispatch.**
There is no SnellNativeEngine/Hysteria2NativeEngine control-plane duplication.
Architecture result: **CONCERN**: adding the second protocol required broad changes
to shared contracts for passwords/multi-user/TLS and public commands. Runtime and
export dispatch remain protocol-neutral and share the Native Engine. Per-protocol
creation schemas/resource builders and transport command methods still grow with
new protocols; Phase3 bootstraps preserved Phase2 composition before replacing its
HY2 placeholder. A generic validated document port may reduce future growth, but
was not expanded into unrelated CRUD/Panel infrastructure.

## Capabilities

| Capability | Actual managed HY2 result |
|---|---|
| TCP | QUIC streams, authenticated routed payload |
| UDP | QUIC transport and proxied UDP payload |
| IPv4 / IPv6 / Domain | Display endpoint independently verified for both clients/users |
| MultiUserNative | true, 1–16 configured users/Inbound, distinct passwords |
| NativeStats / PerUserStats | true, aggregate and per-Binding payload/routed sessions |
| HotUserUpdate | false; Users mutation = Restart of affected Inbound |
| HotReload | false; arbitrary listener/TLS mutation not implemented |
| TLS | Required static leaf/key, one CA, TLS 1.3/h3 |
| Obfs | Deferred; unknown input rejects |
| Other | 64 managed Inbounds; no masquerade/hopping/realm/advanced QUIC options/URI |

## Baseline Source Audit

Audit uses the pinned source, not mutable current documentation:
[inbound](../../protocol/hysteria2/inbound.go),
[options](../../option/hysteria2.go), [outbound](../../protocol/hysteria2/outbound.go),
[tests](../../test/hysteria2_test.go), and
[sing-quic service](https://github.com/SagerNet/sing-quic/blob/v0.7.0/hysteria2/service.go).

Stock inbound requires TLS, binds UDP, passes TLS/options to NewService and maps
passwords to native identities. Its public user name is routing metadata, not a
wire username. TCP streams and UDP associations carry that authenticated identity.
Stock listener/service are private, so its outer constructor cannot supply Splicore's
precommit gate. UpdateUsers replaces a map without synchronization; only call it
before service start. Start creates the QUIC listener; cancellation closes sessions;
shutdown must retain the writable socket briefly for close notifications.

Baseline supports salamander/gecko obfs, file/proxy/string masquerade, up/down
bandwidth, ignore-client-bandwidth, advanced QUIC, BBR profile and realm. None of
these advanced fields is exposed without managed testing. Bandwidth negotiation
selects connection-level congestion behavior; it is not per-Account speed policy.
The managed service uses BBR with IgnoreClientBandwidth=true and no policy-derived
SendBPS/ReceiveBPS. Static TLS is snapshotted instead of enabling file watchers.
Pinned upstream tests are retained; own real-client harness adds multi-user,
strict trust, revocation and ownership/recovery coverage.

## TLS

Ephemeral synthetic EC CA/leaf/key only. No real production material.
Regular bounded files reject symlinks; Linux key and parent require private mode
and runtime owner. Construction checks matching pair, leaf not CA, server usage,
validity, chain and DNS SAN/SNI against one explicit public CA.
Runtime sends that CA with its certificate chain.
Display address/listener/SNI/certificate identity remain independent.
Wrong SNI and wrong CA fail for both real clients, with verification enabled.
Invalid/missing/expired/mismatched key/cert/trust cases reject in tests.
No key contents enter SQLite, ordinary API, profile, export or diagnostics.

Mihomo 1.19.30 pins the **non-leaf CA**, preserving chain/validity/SNI verification
in its [fingerprint verifier](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/component/ca/fingerprint.go).
Its static proxy captures a CA pool before
[ApplyConfig resets it](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/hub/executor/executor.go);
top-level custom-certifactes alone parsed but failed actual trusted-CA traffic.
Leaf pinning would skip SNI in that pinned verifier, so it is not used.
sing-box uses explicit CA PEM, SNI and insecure=false.

## Runtime

Start/Health/Stop/Restart/SQLite Recovery/UDP reuse: initial real race-server PASS.
Health means listener readiness; independent traffic qualification proves actual
protocol operation. UDP conflict is typed port_conflict, closes failed candidate
and commits no resources. Admission drops UDP reads before commit.
Close clears admission/cancels, permits writes for a bounded 100 ms grace, then
closes service/socket/Box. This is not a guarantee of delivered close packets
on arbitrary networks. Forced clients cannot block shutdown; clients reconnect.

## Transaction

Create: validate → plan → pending → build TLS/runtime → start → health → SQL commit
→ activate. One shared coordinator serves both protocols. Invalid credentials/TLS,
bad pair/chain, UDP conflict and injected prepare/start/health/commit failures
publish no resources. Binding replacement journals, closes only its Inbound,
starts with admission closed and commits before activation. Failure reconstructs
the old committed projection; failed compensation reports recovery required.
Known interrupted pending create/replace journals are failed on recovery.
SQLite preserves two Accounts/Bindings/passwords/policies and disabled state;
import files/client configs are removed and never become recovery authority.

## Multi-user

Alice and Bob, distinct random passwords on one Inbound, simultaneous traffic.
16 concurrent connections across users. Wrong password fails.
Password identity test uses Alice's credential with Bob's client label: attributed
bytes increment Alice, never Bob. HY2 has no transmitted username to impersonate.
Disable Alice invalidates saved configs for both clients; Bob reconnects.
Re-enable and actual daemon restart recovery pass. HotUserUpdate=false; replacement
interrupts other users on the same Inbound, without restarting the daemon.
General Account mutation/rotation remains deferred; recovery filters unavailable
or disabled Accounts as well as disabled Bindings.

## Stats

Inbound: authenticated routed payload upload/download and routed sessions.
Binding: same units, attributed by immutable native Binding ID.
Account: only the Binding correspondence in this one-Binding-per-created-Account
slice; **no durable cross-Inbound Account aggregation or billing endpoint**.
Connections: TCP streams/UDP associations, not raw QUIC handshakes.
Counters are atomic runtime-generation meters; replacement/recovery resets them.
They cannot establish durable quota/rate enforcement.

## Traffic Policy

Two distinct TrafficPolicy records/Binding references persist. Explicit
policy_mode=metadata_only required when supplied; plans/views say policy_enforced=false.
Quota/upload/download metadata never enters native bandwidth options or exports.
Native enforcement: **NONE**. Shared quota/speed/session limits and durable usage
remain deferred, even though payload can exceed stored metadata values.

## ClientProfile

Validated independent IPv4/IPv6/domain Endpoint, typed password, QUIC transport,
UDP capability, TLS explicit CA/SNI/h3. Protocol options are bounded empty base
options; obfs unsupported. No runtime listener/Engine config, server private key
or TrafficPolicy-to-bandwidth mapping. Formatting/default JSON redact credentials.

## Exporters

| Target | Exact version | Content shape | Result |
|---|---|---|---|
| Mihomo | 1.19.30 | mihomo-config-fragment containing proxies, CA fingerprint/SNI/h3/skip-cert-verify=false | Parser and real TCP/UDP PASS |
| sing-box | 1.14.1 | sing-box-outbound, CA PEM/SNI/h3/insecure=false | Parser and real TCP/UDP PASS |
| URI | Any | none | Deferred, no invented grammar |
| Surge | Any | none | UnsupportedExport |

Unknown versions/features reject. Multi-user export requires explicit binding_id;
disabled/unavailable exports reject. Secret-bearing content is returned only by
the explicit authorized export route. Safe envelopes redact content before archival.

## Interop Matrix

All rows run Splicore on Linux amd64 with race instrumentation, trusted synthetic
CA, correct independent hy2.test SNI. Each TCP/UDP entry includes integrity.

| Client | Version | User | Endpoint type | TCP | UDP | TLS | Result |
|---|---|---|---|---|---|---|---|
| Mihomo | 1.19.30 | Alice | IPv4 | PASS | PASS | verified CA/SNI | PASS |
| Mihomo | 1.19.30 | Bob | IPv4 | PASS | PASS | verified CA/SNI | PASS |
| Mihomo | 1.19.30 | Alice | IPv6 | PASS | PASS | verified CA/SNI | PASS |
| Mihomo | 1.19.30 | Bob | IPv6 | PASS | PASS | verified CA/SNI | PASS |
| Mihomo | 1.19.30 | Alice | Domain | PASS | PASS | verified CA/SNI | PASS |
| Mihomo | 1.19.30 | Bob | Domain | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | Alice | IPv4 | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | Bob | IPv4 | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | Alice | IPv6 | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | Bob | IPv6 | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | Alice | Domain | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | Bob | Domain | PASS | PASS | verified CA/SNI | PASS |

Endpoints: 127.0.0.1, ::1, localhost. Evidence: hysteria2-interop-results.json.
Both clients reject wrong password/SNI/CA (six negative cases PASS).

## Stress / Lifecycle

16 concurrent connections/cell across users; 4 MiB TCP/cell with integrity/stats.
32 UDP sequence packets/cell, distinct synthetic payload sizes and exact echoes.
Disconnect/reconnect/abnormal stream close; saved client reconnect after Binding
reconstruction and daemon restart; forced client kill/shutdown/UDP reuse: PASS.
No panic/deadlock/data race in successful diagnostic logs. Each Mihomo process
uses a separate private home (shared cache locking caused an earlier test failure).
Early reconnect failure exposed premature UDP close; bounded writable close grace
fixed it. No chaos-network, exhaustive soak or field-scale qualification.

## Regression

Snell: **PASS**, nine real endpoint/client/version cells, TCP/UDP, 16 connections,
4 MiB, negative PSK/version/port cases, restart and listener release on race server.
Evidence: snell-interop-results.json; Surge remains contract-only.
Original sing-box: final exact default-tag Linux CI pending infrastructure recovery.
Windows inherited CI has WinDivert/tlsspoof environment failures; preserve them.
The schema-3 command identity test found by root CI was corrected, not dismissed
as upstream. Initial disk-full build errors are invalidated and rerun separately.

## Platform

Windows: own unit tests and both binary builds PASS. Development only; production
control transport and real runtime interop are Linux. Linux amd64 own unit/race,
HY2 fuzz and Splicore build/race build PASS before disk failure.
Latest Linux amd64/arm64 Splicore and default-tag sing-box cross-compilation:
**PASS** on Windows Go 1.26.2 (CGO_ENABLED=0). Native Linux Go 1.26.6 final
build/CI/vet and fresh runtime response collection remain pending rerun.
Docker: pinned golang:1.26.6 image digest
`sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6`.
Validation container: splicore-phase3-validation; source mount read-only.

## Security

Credential: generated 32 random bytes/43 base64url chars; supplied 12–255 UTF-8
bytes with no Unicode whitespace/control; encrypted generic password schema.
Private key: external protected static files; no plaintext database/API/export.
Logs/API/Doctor: redacted settings and metadata/counters only, explicit secret
export boundary. Wrong auth/trust fail. Ephemeral HY2 private files clean in finally.
Secret scan: successful HY2/Snell logs and ordinary API PASS. Final repository
artifact/history/secret audit PASS. HY2 cleanup in the successful harness passed;
old Snell private-state cleanup was attempted through the container filesystem,
but removal returns I/O error. It remains required after infrastructure recovery.
No claim of perfect Go heap zeroization or Windows production DACL provisioning.

## Upstream Runtime Modifications

Count: **0**. New runtime composition lives only under internal/splicore.
No wire, QUIC, TLS, UDP framing or congestion-control reimplementation.
LICENSE/provenance/module/upstream runtime source remain unchanged.

## Initial Validation Results (historical)

| Gate | Initial actual status |
|---|---|
| Own unit/runtime/transaction/recovery/TLS/multi-user/export | Windows final PASS (including cmd); Linux PASS before interruption |
| Populated schema-2→3 ciphertext/AAD/FK/trigger preservation | PASS |
| Precommit UDP drop / UDP conflict / rollback / replacement compensation | PASS |
| Full real HY2 + Snell race-server interop | PASS |
| Linux race | PASS |
| HY2 canonical fuzz | Linux PASS, 137,958 executions / 5 seconds |
| Snell fuzz | Windows PASS, 110,404 executions; prior wrong Linux target is invalidated |
| Own vet | Windows PASS |
| Linux amd64/arm64 both binary cross-builds | PASS (Go 1.26.2 Windows host, CGO disabled) |
| Docs/OpenAPI static | PASS: 64 Markdown documents, 589 links, 22 operations / 13 implemented |
| Latest multi-user view omission contract | Windows actual API/transport/recovery test PASS |
| Live responses/export envelope schema validation | Pending fresh Linux collection; old saved views correctly reject empty legacy IDs |
| git diff --check / untracked whitespace | PASS |

Test sources:
[application](../../internal/splicore/application/hysteria2_test.go),
[protocol](../../internal/splicore/protocol/hysteria2/hysteria2_test.go),
[native](../../internal/splicore/engine/native/hysteria2_test.go),
[exporter](../../internal/splicore/exporter/hysteria2_test.go),
[migration](../../internal/splicore/storage/sqlite/password_migration_test.go),
[registry](../../internal/splicore/registry/phase3_test.go),
[harness](../../scripts/splicore-hysteria2-interop.py).

### Pinned client dependencies

| Client | Archive SHA-256 | Executable SHA-256 |
|---|---|---|
| Mihomo 1.19.30 | cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553 | 20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494 |
| sing-box 1.14.1 | 12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f | 9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9 |

Official archives are checksum verified; downloaded binaries remain external.
Doc tools: markdown-it-py 3.0.0 / openapi-spec-validator 0.7.2, external target.

### Latest cross-build artifact hashes

These are local review artifacts, not releases or runtime-interop binaries.

| Artifact | SHA-256 |
|---|---|
| splicore-linux-amd64 | d7e223973240125534bb5dc8cc33c677f4d631e9efacfb0ce298ee0bf953b5e0 |
| splicore-linux-arm64 | 653dbc5b6edcbc9d8551731146a9a046d1c57614f61155be86d0995413c93423 |
| sing-box-linux-amd64 | b94fa727db6fc43f31a5b6234147adc3dac8778a9a9c8f0c56bee619572fc427 |
| sing-box-linux-arm64 | 1e54aafd38c647fefb5ec731e9e08838463ce8e8218639f3487c41a834ac039e |
| splicore-windows-amd64.exe | 372b0c9940ce2a92faa56a440d0552b3b6503d112ca67275d40268fc23518e59 |
| sing-box-windows-amd64.exe | 944a2682d65c0e203e32e13da2bda9866ef596d1315e7d2e829b83d5aafeb7f6 |

Evidence ledger: linux-gates.tsv (incomplete after disk failure), windows-gates.json,
final-windows-gates.json, cross-build-gates.json, multiuser-view-contract.log,
docs-static-results.json, repo-audit.json and safe interop summaries/logs. The
earlier Linux subset-tag CI is smoke only: it failed missing build-tag symbols,
container netns/tlsspoof permissions and the now-fixed command identity expectation;
it is not an exact-default-tag gate. Inherited unsafe.Pointer vet findings remain
historical observations; Phase 3 final default-tag vet is not falsely claimed run.

## NoBrand

Real changes/access: **NONE**. Synthetic logical migration: **PASS** in real
validate/plan/apply/SQLite recovery; name/listener/display/password/TLS/SNI mapping.
Obfs rejects/deferred. No old-state extraction path or production importer invented.
See [mapping](../integration/NOBRAND_MIGRATION.md) and
[template](../../tests/fixtures/nobrand/hysteria2.json).

## Documentation

Canonical README/index/context/architecture/protocol capability/engine/client/
interop/API/OpenAPI/storage/version/domain/policy/transaction/lifecycle/security/
testing/NoBrand updated. New HY2 profile, workflow and ADR 0014.
Historical Phase 0/1/2 reports/evidence and migrations 0001/0002: **UNCHANGED**, final
Git byte comparison PASS. No upstream documentation mass edit.

## Git

Stage: NONE. Commit: NONE. Push: NONE. Tag: NONE. Release: NONE.
HEAD/main remain Phase 2 freeze. Changes stay local in working tree for review;
sole remote remains upstream. No origin creation/publication/real NoBrand operation.
Index remains empty and SHA-256 unchanged during final edits:
`f845c43bce8b62e4011dd537abe7425215eeee58c9e879b8c5bcdec0f0f83b28`.

## Deferred

TUIC, VLESS/REALITY, Mieru, Xray, Panel, real quota/speed/session enforcement,
durable Account usage/billing, NoBrand production canary, Stable designation,
HY2 obfs/masquerade/hopping/realm/advanced QUIC, URI, general Account mutation,
credential rotation, TLS/listener hot reload/delete, ACME/multiple CA bundles,
generic idempotent importer/full crash compensation and production field testing.

## Architecture Deviations

The outer stock inbound privately owns UDP and has no transactional admission port.
The adapter composes its exact pinned underlying service plus existing TLS/Box
Router instead of calling outer NewInbound. This documented realization deviation
preserves all protocol wire implementations and zero upstream patches.
Per-Inbound replacement/counter reset and bounded close grace are visible behavior.
HMAC/revision synchronous commands/listener-health gates remain bounded experimental
contracts; broader generic asynchronous CRUD/reconcile/durable usage are future.

## Initial Final Result (historical)

**NOT READY** pending final native Linux regression/interop response collection
and cleanup of inaccessible temporary container state. Implementation, static docs,
Windows, cross-build and repository audits are complete; this is not an approval
or release of the incomplete gates.

## Initial Blockers (historical)

C-drive exhaustion interrupted Linux validation after own unit/race/fuzz/build.
Docker engine/container binaries now return I/O errors. External evidence has been
migrated to D and Windows validation rerun; Linux remaining gates require recovered
Docker infrastructure. Conditional restart authorization was received in the final
acceptance request, but the pre-restart guard found an active non-Splicore Redis
workload. **DOCKER RESTART BLOCKED BY ACTIVE NON-SPLICORE WORKLOAD**; no restart
or workload stop was performed. The container's old Snell temporary
state cannot yet be removed (I/O error). Fresh HY2 response/export-envelope fixtures
must be recollected from the latest binary, then schema validated. Do not count
failed/incomplete infrastructure gates as PASS.

## Splicore Phase 3 Final Acceptance Report — blocked preflight (historical)

### Previous Status

**HYSTERIA2 VERTICAL SLICE NOT READY**. Docker I/O failure left Linux revalidation,
latest response schema validation and temporary container-state cleanup incomplete.

### Docker Recovery

Read-only preflight attempted docker version, docker info, docker ps -a (JSON/no
truncation), and docker compose ls (JSON). All four hung without stdout/stderr;
bounded waits ended by terminating only these task-owned CLI processes. Complete
empty streams and timeout/exit-code records are external in
docker-preflight-results.json and pre-docker-*.stdout.log / *.stderr.log. No success
or daemon error text is invented. Direct read-only container metadata lookup failed:
`cat: can't open '/proc/160/root/var/lib/docker/containers/090c038b3fc26486fbb644d659c07b53038b79209ed5dc597b997a20ef2cdee0/config.v2.json': I/O error`.

Linux process/cgroup inspection establishes two active container tasks:

| Container ID | Name | Image | State / process | Compose project | Ports | Splicore ownership |
|---|---|---|---|---|---|---|
| 090c038b3fc26486fbb644d659c07b53038b79209ed5dc597b997a20ef2cdee0 | Unavailable; metadata I/O / API timeout | Unavailable; Redis process is not an image-version assertion | Active redis-server, PID 600, matching Docker cgroup and shim | Unavailable | Process listens on *:6379; host published ports unavailable | Not a confirmed Splicore resource; disposable ownership unproven |
| 3bbe0bd8780a392f1d8dd7c8b9eb76f67189980f06de6d347c3abe8ef2b727e4 | splicore-phase3-validation (known creation identity) | Pinned golang:1.26.6 from this task's setup; fresh inspect unavailable | Active sleep infinity, PID 50122, matching shim | No Compose project used by this task; fresh labels unavailable | No port publishing used by this task; fresh inspect unavailable | Confirmed Phase 3 validation container |

This is a partial inventory, not a claim that stopped containers or all Docker
resources were enumerated. Evidence: docker-active-workload-evidence.log; Desktop
electron logs also record Headers Timeout Error while inspecting the Redis ID.
The Redis workload cannot be assumed disposable or approved for interruption.

Restart allowed: **NO under the supplied guard**.
Docker recovery: **NOT ATTEMPTED**.
Post-restart comparison: **NOT APPLICABLE**.
Other projects modified/stopped/deleted/rebuilt: **NONE**.
No prune/reset/upgrade/reinstall/VM deletion or resource cleanup was performed.
The maintainer must decide how to handle the active non-Splicore workload before
an engine restart can be attempted.

### Environment Failure Classification

Initial failure: Docker Desktop/container filesystem I/O after C-drive exhaustion.
Evidence: disk exhaustion in prior gates, I/O errors on container binaries/files,
current metadata I/O error and four unresponsive Docker commands.
Classification: **ENVIRONMENT for the observed infrastructure failure**; the
specific underlying Docker storage fault is not fully diagnosed. This does not
classify unrun Linux tests as passing or exclude future CODE/TEST failures.
Functional code changes in this acceptance attempt: **NONE**.
Remediation/retest: **BLOCKED**, so no successful normal restart is claimed.

### Runtime, Protocol and Verification

Hysteria2 remains **Experimental**. Runtime start/health/stop/restart/recovery/UDP
conflict, dual-user password identity/revocation, trusted synthetic CA/SNI, QUIC
and UDP, transaction rollback, per-Inbound/Binding payload/session stats,
Mihomo/sing-box exports, the 12-cell interop matrix and stress results above are
**previous evidence, not a new final-acceptance run**. No durable Account usage,
URI/Surge HY2 support, policy enforcement or new capability is claimed.

Linux suite/race/fuzz/interop/TLS/Snell regression and latest API response validation
were **NOT RERUN**, as the user explicitly requires stopping this round when an
active non-Splicore workload blocks restart. Previous Windows/compile/static-doc
results remain historical observations for this implementation. No functional
runtime edit was made to mask the Docker fault.

### Cleanup and Git

Temporary Docker state and final residue gates: **PENDING**. No container/network/
volume/image was deleted, including any resource with uncertain ownership.
Repository artifacts and upstream/wire/history audits remain as recorded above;
this acceptance attempt changes only this Phase 3 report in the repository.
Branch, HEAD/main and index remain unchanged. Stage/commit/fast-forward main/
Phase 4 branch/push/tag/release: **NONE**.

### Final Result

**HYSTERIA2 VERTICAL SLICE NOT READY**.

Exact blocker: **DOCKER RESTART BLOCKED BY ACTIVE NON-SPLICORE WORKLOAD**
(Redis container 090c038b3fc2; name/image/Compose metadata unavailable). After the
maintainer resolves this guard, Docker recovery, the complete Linux acceptance
chain, fresh response/export-envelope validation and scoped temporary-state cleanup
remain required before READY FOR REVIEW.

## Splicore Phase 3 Independent WSL Final Acceptance Report

### Previous Status

**HYSTERIA2 VERTICAL SLICE NOT READY**. The original blockers were Docker Desktop
I/O failure, unresponsive daemon queries and the protected Redis workload whose
ownership/persistence/interruptibility remained unknown. The latest authorization
allows independent Ubuntu WSL2 qualification and defers that external cleanup.
The preceding implementation/Docker/Redis sections remain historical evidence.

### WSL Environment

| Field | Observed value |
|---|---|
| Distribution | Ubuntu-24.04, Ubuntu 24.04.4 LTS |
| WSL | WSL2; host WSL package 2.6.2.0 |
| Kernel | 6.6.87.2-microsoft-standard-WSL2 |
| Architecture | x86_64 / linux/amd64 |
| Go | Isolated official Go 1.26.6; existing compatible Go absent |
| Native filesystem | ext4, /dev/sdf; about 953 GiB virtual free at preflight |
| Physical disk budget | C about 2 GiB free; D about 456 GiB free initially, 450 GiB after builds |
| Memory | 15 GiB total, about 14 GiB available at preflight; 4 GiB swap |
| IPv4 / IPv6 | 127.0.0.1 and ::1 TCP/UDP bind PASS; real client traffic PASS |
| DNS | proxy.golang.org resolved; module downloads succeeded; endpoint localhost uses local host resolution |
| Principal | root; default user could not traverse the existing mode-0700 /usr/bin |

The distribution was started under the explicit authorization. No existing system
permissions, Git safe.directory settings or Windows Go installation were changed.
Minimal official Ubuntu dependencies were installed after checking absence: GCC /
libc development dependencies for race and tcpdump / libpcap dependencies for
inherited root CI. GCC 13.3.0, Python 3.12.3, OpenSSL 3.0.13 and Git 2.43.0 were used.
No Docker/containerd/Redis/database server/desktop package was installed.

Go source: `https://go.dev/dl/go1.26.6.linux-amd64.tar.gz`.
Archive SHA256: `708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89`.
Official version metadata was saved and checked. WSL's initial go.dev TLS download
failed, so Windows downloaded the same pinned archive; Linux verified its SHA256.
SDK, GOCACHE, GOMODCACHE and compile work directories were isolated on D.

### Validation Workspace

Source: current Windows working tree, including tracked baseline, modified Phase 3
files and untracked source/tests/docs. No clone of HEAD was used.
Native location: `/root/splicore-validation/phase3-wsl-20261001/src`.
Runtime: sibling `runtime`; test fixtures: `/root/splicore-p3-tmp-20261001`.
All acceptance SQLite, UDS, CA/key, runtime state and original runtime logs were
on ext4. Windows repository modified by test runtime: **NO**.

Initial snapshot verification: **PASS**, 1,756 files,
9,152,118 bytes, exact list/size/SHA256.
Manifest SHA256: `cc09a4c99dbc03c55fc669a6c759ec67511004e3ef63491d24adfd2c453bd703`.
Three uninitialized upstream client gitlinks were recorded by commit ID; their
directories were empty and no application source was omitted. Git metadata,
ignored build/runtime/cache artifacts and secrets were not copied. Tracked
historical documentation evidence was retained unchanged for link verification.
The manifest was verified before the final native test run. The Windows audit
also verifies all 100 owned source/test/fixture files against that tested manifest.

A post-run strict full-file-set check rejected additional generated files. Python
interop import creates __pycache__; that check did not exclude generated caches.
It is recorded as a failed auxiliary check, not a new source-integrity PASS. The
initial exact snapshot verification remains the acceptance evidence. The native
copy and generated files were then removed by the scoped cleanup.

### Build

| Gate | Result |
|---|---|
| Native Splicore linux/amd64 | PASS, CGO_ENABLED=1 |
| Native original sing-box linux/amd64 | PASS, CGO_ENABLED=1 |
| Splicore amd64 race runtime | PASS; real HY2 and Snell clients used this binary |
| Splicore linux/arm64 compile | PASS, CGO_ENABLED=0 |
| Original sing-box linux/arm64 compile | PASS, CGO_ENABLED=0 |

Default sing-box tags and release/LDFLAGS were read from the snapshot; upstream
version was explicitly set to 1.14.1. All builds use `-buildvcs=false` because the
unrelated repository at Ubuntu filesystem root has dubious ownership. No Git
safety exemption was added. These disposable snapshot binaries report Splicore
commit `unknown` / default dirty false; that is missing stamping, **not a claim
that the Phase 3 worktree is clean**. Branch/base/diff identity comes from the
verified manifest and Windows Git audit. No release artifact was produced.

| Review artifact | SHA256 |
|---|---|
| splicore-linux-amd64 | 47d2456d4050308e3012290810a8386a21e48434070f5da594e0e9637fd01b14 |
| sing-box-linux-amd64 | 6e5e686c2306878db96e0ed084a42fc4da139d968464001673fbbdb7979d6766 |
| splicore-linux-arm64 | 7c4256bfeb6d45ee14687fdcc26cd49e4d5808fa354a152f258e5160a898eeae |
| sing-box-linux-arm64 | eb600534a239a06b2f22ebac262fc2f731520b9754ce785cf8c752ef4b4ad343 |

Race runtime SHA256:
`d2ecba9100bd91733bb8e06ea166ff88040afac24ea48f94934d3a6d69da667b`.
The local review binaries on D are outside the repository; the native race runtime
was removed. Binary versions/build tags/client identities are in binary-identity.txt.

### Hysteria2

Status: **Experimental**. Create, start, listener health, stop, restart and SQLite
recovery: **PASS** in the unit/race suites and actual process/client interop.
UDP listener release and same-port reuse after stop/restart: **PASS**.
No production or Stable qualification is implied.

### Multi-user

Alice/Account A/Binding A/Credential A: **PASS**.
Bob/Account B/Binding B/Credential B: **PASS** on the same Inbound.
16 simultaneous routed sessions across both users: **PASS**.
Wrong password: **EXPECTED FAIL**, for both reference clients; server stays healthy.
Alice password with Bob's local label authenticates/attributes Alice, never Bob:
**PASS**. The protocol transmits a password identity, no user-selected username.

Disabled Binding: Alice's saved exports fail for both clients after committed
reconstruction; Bob's existing client reconnects. Disable persists through daemon
restart, then re-enable restores traffic. **HotUserUpdate=false**, Users=Restart;
reconstruction interrupts all users on that Inbound and resets generation counters.
General Account mutation API is deferred; recovery filters unavailable/disabled
Accounts. No unsupported hot update or separate Account billing API is claimed.

### TLS

Synthetic native EC CA/leaf/key: **PASS**. Explicit trusted CA and independent
`hy2.synthetic.test` SNI: **PASS**. Wrong SNI and untrusted CA: **EXPECTED FAIL**
for both clients. Insecure verification was not used.
Mihomo pins the non-leaf CA fingerprint and verifies chain/SNI; sing-box receives
explicit CA PEM with insecure=false. Key permissions/ownership/symlink and
bad-pair/chain/identity validation tests pass on Linux.
Private key leakage in Git/report/sanitized diagnostics: **NONE**.
Native synthetic private material: **REMOVED**.

### QUIC / UDP

Real password-authenticated HY2 QUIC: **PASS**, using the race-built server and
pinned actual clients. TCP proxy connect/request/echo integrity: **PASS**.
UDP request/response/integrity: **PASS**, including 32 ordered synthetic datagrams
per matrix cell. IPv4, IPv6 and Domain endpoints: **PASS**, independently in WSL.

Both interop entrypoints ran in new network namespaces with only the loopback
interface. A dual-stack wildcard listener therefore had no external interface.
All listener/echo/SOCKS ports were ephemeral. Namespace listener captures before
and after are empty outside test activity; no production ports were allocated.
Listener `::`, display `localhost` and TLS SNI `hy2.synthetic.test` remain distinct;
changing display endpoints did not mutate listeners or SNI.

### Transactions

Successful validate/plan/apply and committed multi-user create: **PASS**.
Invalid input/config rollback: **PASS**. TLS failure (key/certificate/identity/CA):
**PASS**. UDP port conflict: **PASS**, typed rejection, no committed candidate.
Injected compile/start/health/storage failure and replacement compensation:
**PASS**. Failed/pending journals are handled and committed revision is preserved.
Two-user SQLite recovery and disabled Binding recovery: **PASS**.
SQLite committed state is authority; import content is erased after apply and
generated client/engine JSON is never recovery authority.

### Stats

| Granularity | Actual support |
|---|---|
| Inbound | SUPPORTED: authenticated routed payload upload/download and routed sessions |
| Binding | SUPPORTED: same units attributed by immutable Binding ID |
| Account | Binding correspondence only; durable cross-Inbound aggregation/billing DEFERRED |
| Connections | SUPPORTED: active/total TCP streams and UDP associations; not raw QUIC handshakes |

Tests: **PASS**; actual payload counters increase and password identity stays
isolated. Counters are per runtime generation and reset on reconstruction/recovery.
TrafficPolicy is persisted metadata only, policy_enforced=false. No quota/rate/
shared usage enforcement or durable usage estimate is claimed.

### Client Interoperability

The following is **new independent WSL evidence**, not reused Docker PASS output.
Each cell uses verified synthetic CA/correct SNI, real TCP/UDP and two-user traffic.

| Client | Version | Executable SHA256 | User | Endpoint type | TCP | UDP | TLS | Result |
|---|---|---|---|---|---|---|---|---|
| mihomo | 1.19.30 | 20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494 | Alice | IPv4 | PASS | PASS | verified CA/SNI | PASS |
| mihomo | 1.19.30 | 20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494 | Bob | IPv4 | PASS | PASS | verified CA/SNI | PASS |
| mihomo | 1.19.30 | 20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494 | Alice | IPv6 | PASS | PASS | verified CA/SNI | PASS |
| mihomo | 1.19.30 | 20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494 | Bob | IPv6 | PASS | PASS | verified CA/SNI | PASS |
| mihomo | 1.19.30 | 20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494 | Alice | Domain | PASS | PASS | verified CA/SNI | PASS |
| mihomo | 1.19.30 | 20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494 | Bob | Domain | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | 9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9 | Alice | IPv4 | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | 9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9 | Bob | IPv4 | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | 9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9 | Alice | IPv6 | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | 9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9 | Bob | IPv6 | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | 9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9 | Alice | Domain | PASS | PASS | verified CA/SNI | PASS |
| sing-box | 1.14.1 | 9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9 | Bob | Domain | PASS | PASS | verified CA/SNI | PASS |

Official archives were reverified: Mihomo
`cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553`;
sing-box `12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f`.
Client version outputs and executable hashes match the pinned existing dependency
records. Wrong-password/wrong-SNI/untrusted-CA produce six expected rejections;
disabled Alice adds the seventh negative result. No unpinned latest client was used.

### Stress

Concurrency: **PASS**, 16 simultaneous connections per endpoint/client group across
users. Large transfer: **PASS**, 4,194,304 bytes per user/cell, exact echo integrity
and attributable counters. UDP: 32 sequenced packets per user/cell.
Reconnect, abnormal stream reset, existing-client reconnect after reconstruction/
daemon restart and forced client termination: **PASS**. Server shutdown completes;
no panic, deadlock or race report in the successful diagnostic logs.

### Snell Regression

Same Ubuntu/ext4/race server environment: **PASS**. Mihomo 1.19.30 Snell v5 and
sing-box 1.14.1 Snell v5/v6 × IPv4/IPv6/Domain: **nine real cells PASS**.
TCP/UDP integrity, 16 connections, 4 MiB, reconnect/abnormal close, wrong PSK/
version/port, SQLite restart and listener release: **PASS**.
No Snell wire code was changed; its harness only adds task PID recording.

### Registry Scalability

Central protocol switches in Native Engine compiler, recovery/runtime projection
and exporter dispatch: **0**. API adds one HY2 command-route group with three
operation cases; CLI has five HY2 validation/plan/apply/schema availability choices.
Credential tagged-data encode/decode adds two generic password cases.
Engine/export registries remain protocol-key maps, with one Native Engine.

Changes outside the protocol module/registration are explicitly listed in the
Architecture/Protocol Registration section above: generic password persistence,
multi-Binding contracts, shared create/replace coordination, stats/TLS/profile,
application commands, CLI/API and tests/docs. Result: **ARCHITECTURE CONCERN**
for broad shared-contract/public-command growth and per-protocol creation builders;
the concern is retained for review. It is not concealed by READY FOR REVIEW, and
there is no second control plane or central runtime protocol switch proliferation.

### API

Static OpenAPI: **PASS**, 22 operations / 13 implemented routes.
Live response validation: **PASS** against actual HTTP bodies over native UDS.
Schema fixtures cover System (two actual reads), CapabilityPage, RuntimeInboundPage,
RuntimeInboundView, Hysteria2Plan, Hysteria2Applied and RuntimeTransaction;
18 live export envelopes are validated after content redaction.
Routes: GET system/capabilities/inbounds/inbounds/{id}; HY2 plan/apply;
Inbound Binding command; generic Inbound export envelope. HY2 validate/display
commands are also exercised by unit/interop tests; no schema claim is made for
uncollected command fixtures or deferred endpoints.
Snell's five fresh query fixtures also pass; its collection contains HY2 command/
export fixtures from the immediately preceding run, which remain labeled HY2.
Latest multi-user omission contract rejects legacy empty binding_id/account_id;
the fresh latest response passes. CLI status/capabilities exactly equal the actual
API queries: **PASS**, shared Application Service, no CLI-specific protocol state.

### Tests

| Gate | Actual result |
|---|---|
| Complete Splicore unit suite including cmd | PASS, native fixtures |
| Complete own Linux race suite | PASS |
| Existing runtime/transaction/storage/migration/security/export tests | PASS |
| Real HY2 and Snell interop | PASS, race server |
| Own vet | PASS |
| Exact upstream default-tag/ldflags/root CI | PASS after minimal tcpdump install |
| Extra full upstream vet | FAIL: two existing unsafe.Pointer findings, unchanged upstream source |
| Markdown/governance/links/static OpenAPI | PASS; final post-report run recorded externally |
| Fresh actual response/export-envelope schemas | PASS |
| Secret/whitespace/history/index/source audit | PASS; final rerun recorded externally |

Six existing short fuzz entrypoints (including the added exporter target) ran with
two workers and 5-second fuzz budgets; all actually executed mutations:

| Target | Executions | Result |
|---|---|---|
| fuzz-endpoint | 177,284 | PASS |
| fuzz-config | 31,098 | PASS |
| fuzz-snell | 108,680 | PASS |
| fuzz-snell-export | 78,448 | PASS |
| fuzz-hysteria2 | 62,487 | PASS |
| fuzz-hysteria2-export | 80,625 | PASS |

Additional full vet findings are preserved at unchanged
daemon/managed_service.go:75:12 and experimental/libbox/debug.go:10:11.
This extra checker is not the enabled upstream lint gate; exact root CI passes.
The separate test/go.mod Docker/reference suite was not run and is not covered by
the root CI claim. Windows historical results are preserved, not relabeled WSL.

### Environment / Test Retry Timeline

| Attempt | Classification / correction |
|---|---|
| Default Ubuntu shell denied | ENVIRONMENT; root used, /usr/bin permissions untouched |
| Initial /tmp snapshot absent on later invocation | ENVIRONMENT; moved validation copy to persistent root ext4 |
| Test TempDir followed compile GOTMPDIR on D | ENVIRONMENT CONFIGURATION; invalid results retained; test process unsets GOTMPDIR, native suites rerun PASS |
| Automatic VCS stamping discovered unrelated / Git repository | ENVIRONMENT; -buildvcs=false, five builds rerun PASS |
| Inherited TLS spoof tests lacked tcpdump | ENVIRONMENT; required minimal package installed, whole exact root CI rerun PASS |
| Initial namespace guard read host-mounted sysfs | TEST ORCHESTRATION; guard now inspects ip link inside namespace, both existing entrypoints rerun PASS |
| Auxiliary post-run strict file-set check included generated files | AUXILIARY CHECK FAILED; initial exact snapshot PASS is retained, cleanup PASS; no invented final source checksum result |

The initial TempDir attempt is not accepted as a native state test. Its temporary
fixtures were removed by normal test cleanup; a final scan of the task's D compile
temp directory finds no private-key/PEM/DB/UDS files. Only corrected native results
enter the final gate assessment. Implementation acceptance additions are a real
HY2 exporter fuzz invariant test, the shared TLS test helper's testing.TB support,
CLI/API response equality and child PID records in existing interop entrypoints.
Docker issue caused functional runtime code changes: **NO**. Environment work did
not patch protocol/wire/upstream code or weaken permission/authentication checks.

### Upstream Audit

Runtime source modifications: **0**. Wire changes: **0**.
Other upstream protocols modified: **0**. Dependency/module/license/provenance
files: unchanged. All changed/untracked files are within the owned Splicore scope.
The latest audit confirms 100 tested owned source files unchanged since snapshot,
42 protected history/evidence/migration files unchanged and no repository runtime
artifacts/secrets. Historical Phase 0/1/2 reports and migrations 0001/0002 remain intact.

### Docker

Docker Desktop restarted: **NO**. Redis modified: **NO**.
Docker resources modified or queried in this round: **NO**.
Original Docker test residue: **unable to inspect; not claimed removed**.
Cleanup: **DEFERRED**, classified **EXTERNAL ENVIRONMENT CLEANUP**.
Splicore code acceptance blocker: **NO**, under the latest authorization because
independent WSL coverage completed, Windows has no test runtime artifacts and
WSL test state was cleaned. Protected unknown Redis workload and unhealthy Docker
remain external matters; no new query, kill, restart or cleanup was attempted.

### WSL Cleanup

47 recorded child PIDs/executable identities: **exited**. No task server/client/
echo process remains. Before/after namespace listeners and final host ps/ss:
**CLEAN of task listeners/processes**; existing system DNS/time services remain.
Native validation workspace, SQLite, UDS and test temp directories: **REMOVED**.
TLS private keys/temporary CA/secret-bearing client configs/bootstrap key:
**REMOVED**. Temporary native Mihomo/sing-box/race binaries: **REMOVED**.
Original temporary /tmp path and both final native task paths were checked absent;
no task named network namespaces remain. No ambiguous path deletion or bulk kill
was used. Safe text/JSON evidence, pinned tool/archive cache and nonsecret review
builds remain external on D. The Windows repository has no runtime state.

### Documentation

Phase 3 report: **UPDATED**, preserving initial implementation, Docker failure,
Redis DO NOT RESTART and this independent WSL acceptance timeline.
Canonical Phase 3 workflow, development context and matrix reflect current review
status/commands/environment. Phase 0/1/2 reports/evidence: **UNCHANGED**.
Final post-report Markdown/link/OpenAPI/response/governance checks: **PASS**,
64 documents, 590 local links, 22 operations / 13 implemented routes.
Both fresh HY2 and Snell query bundles pass actual response validation.
Final source/history/secret/index audit and git diff --check: **PASS**; fresh output
is in the evidence ledger.

### Git

Branch: `codex/phase-3-hysteria2-vertical-slice`.
HEAD/main: `5bc50a69b0df2c3dc9ede86015c9e4a6b86e2981`.
Index unchanged:
`f845c43bce8b62e4011dd537abe7425215eeee58c9e879b8c5bcdec0f0f83b28`.
Windows entry: 47 modified tracked files / 29 untracked files; final: 48 modified
tracked files / 29 untracked files. The extra tracked change records child PIDs
in the existing Snell regression harness. Exact path inventories remain external.
Stage: **NONE**. Commit: **NONE**. Push: **NONE**. Tag: **NONE**.
Release: **NONE**. No main advancement, Phase 3 freeze, origin creation or Phase 4
branch. Current implementation remains uncommitted and unstaged for maintainer review.

### Final Result

**HYSTERIA2 VERTICAL SLICE READY FOR REVIEW**.
HY2/Snell remain Experimental. This is acceptance evidence for review, not a freeze,
merge, Stable designation, production release or authorization to publish.

### Blockers

**None for the specified independent Phase 3 code acceptance scope.**
The visible architecture concern, extra inherited vet findings and bounded stats/
mutation/export limitations remain review items, not silently marked PASS.

### Deferred External Environment Work

Docker Desktop recovery: **DEFERRED**.
Redis ownership/persistence/interruptibility confirmation: **DEFERRED**.
Old Docker test residue cleanup: **DEFERRED**, not performed/verified.
These do not block Splicore code acceptance under the latest explicit authorization.
NoBrand production access, durable Account billing/policy enforcement, advanced
HY2 features/URI and future protocols/engines remain deferred as listed above.

### Independent Evidence Ledger

External root: `D:\splicore-validation\phase3-wsl-20261001`.
Source manifest/snapshot-verification, entry Git snapshots, preflight/loopback/
WSL version, pinned Go download metadata/hash, package logs, original gates.tsv,
builds-explicit.tsv, upstream-retest.tsv, interop-retest.tsv and acceptance-gates.json
record the initial failures and successful scoped reruns. Fresh HY2/Snell summaries,
separate response bundles, redacted export envelopes, sanitized runtime logs,
recorded child PIDs, binary-identity, final docs/audit and cleanup.json provide the
actual final evidence. No private key/client secret configuration is archived.

## Phase 3 freeze disposition and validation

### Concern, evidence, cause and impact

Original concern: adding HY2 required broad shared-contract/public-command changes,
per-protocol creation schemas/builders and a Phase2-to-Phase3 composition chain.
Classification: **NON-BLOCKING TECHNICAL DEBT**. Changes outside normal extension
points: **MEDIUM**. This freeze changes documentation only; runtime, test, fixture
and validation-script bytes match the independently accepted snapshot.

The actual code review verifies these points rather than assuming the earlier
READY FOR REVIEW conclusion:

| Review | Evidence / affected files | Why it appeared / impact / disposition |
|---|---|---|
| A: central protocol dispatch growth | API's two route switches; six CLI protocol ifs; SQLite display allowlist; phase composition filters | Typed public commands and incremental composition grow. Bounded debt; no protocol switch in compilation/projection/recovery |
| B: Engine-specific leakage | Domain/access, SQLite writer/credentials/runtime, application preparation/export, API, exporter dispatch | No Engine schema/options branch in domain/storage/API/export. Native options remain in native adapters; module checks its supported native realization |
| C: protocol columns | Generic PasswordPayload, encrypted credentials kind constraint in migration 0003; existing Account/Inbound/Binding columns | HY2 exposed a missing generic credential shape. No password/TLS/HY2 columns in Account/Binding/Inbound; opaque settings retain protocol ownership |
| D: service bypass | API commands call service interfaces; CLI stateful commands use those same interfaces via transport; offline validate calls application decoder | No second writer or runtime authority. Offline validation has no state mutation |
| E/F: module SQL/HTTP coupling | HY2 module imports domain/profile/ports/strict JSON and standard crypto; import audit covers domain/ports/protocol | No SQL driver/repository implementation/HTTP/API dependency |
| G: RuntimeConfig in ClientProfile | HY2 BuildClientProfile emits display endpoint/password/QUIC/public CA/SNI/h3; exporter consumes that profile | No Box options, Engine, server key/file paths, listener or policy in client projection |
| H: listener/display/SNI/certificate | Module settings + native TLS Verify with DNSName; display update writes display rows only | Listener binds UDP IP/port; clients dial display endpoint; explicit SNI is checked against certificate identity. No conflation |
| I: lifecycle/transaction duplication | Shared commitCandidate; registry-based prepare/projection/EnableRuntime; single SetBinding replacement coordinator | Protocol resource builders differ, while journal/start/health/commit/admit and compensation stay shared. Generic methods in protocol-named files are organizational debt |
| J: third protocol cost | Real Protocol/Engine/export maps; generic Credential/Binding and shared coordinator; typed transport command growth and display allowlist | No architecture/schema rewrite required. Phase 4 must address command registration, display availability and direct composition before repeating those bounded patterns |

Protocol Registry: **PASS**. Engine Registry: **PASS**. Account/Binding/Credential
separation, committed SQLite authority, ClientProfile/runtime separation and shared
Application Service: **PASS**. Failed input/runtime/storage compensation and restart
recovery are exercised by fresh unit/smoke tests and immutable real-client acceptance.

Canonical resolution: [architecture disposition](../ARCHITECTURE.md#phase-3-extensibility-disposition),
[development context](../DEVELOPMENT_CONTEXT.md) and
[ADR 0014 amendment](../adr/0014-hysteria2-runtime-composition.md#freeze-review-and-follow-up).
They record current behavior, acceptability, affected files, Phase 4 triggers and
target changes. Broad lifecycle duplication, domain/Engine contamination or a second
authority would reopen a BLOCKING review. No Phase 4 implementation occurs here.

### Actual branch counts

Count non-test Go switch statements and individual protocol-selection/allowlist if
sites; exclude comments/method names and generic credential-kind dispatch.

| Category | Count / exact locations |
|---|---|
| Central protocol switches | **2**, HTTP routes at `internal/splicore/api/snell.go:44,64` |
| Central protocol-choice / allowlist if sites | **8**: CLI `internal/splicore/cli/inbound.go:53,59,86,96,110,121`; API `internal/splicore/api/snell.go:13`; SQLite `internal/splicore/storage/sqlite/runtime.go:217` |
| Core runtime compile / projection / recovery protocol switches | **0** |
| Central Engine switches | **0** |
| Exporter protocol switches | **0**, Dispatcher uses ProtocolKey maps |
| Protocol-local switches | **0** in modules; **2** client-format switches in `internal/splicore/exporter/snell.go:60` and `internal/splicore/exporter/hysteria2.go:29` |
| Protocol-key validation ifs | **4**: one per Snell/HY2 module and one per corresponding exporter |
| Composition filters, separate from runtime dispatch | **2**: `internal/splicore/registry/phase2.go:17` and `internal/splicore/registry/phase3.go:19` |
| New HY2-specific core branches | **1**, SQLite display allowlist; no runtime/recovery/Engine branch |
| New HY2 transport sites/cases | **11**: six CLI conditionals + API prefix guard/route group/three operations; composition adds one filter separately |
| Generic password additions | **3** tagged-data cases: domain ValidatePayload + SQLite encode/decode, not protocol or Engine switches |

Migration 0003 restores the unchanged Snell single-Binding trigger from 0002 when
rebuilding credentials/Bindings. This is an existing protocol-specific SQL constraint,
not a new HY2 branch; there is no HY2-specific SQL column/trigger.

### Phase 3 change topology

The explicit inventory has **77 files**. Test files are grouped separately so the
following counts are disjoint; module/adapter tests still qualify their own areas.
Full paths are in external change-topology.json and the staged name-status record.

| Group | Count | Files / scope |
|---|---|---|
| HY2 module | 1 | `internal/splicore/protocol/hysteria2/hysteria2.go` |
| Native adapters / compiler dispatch | 6 | native engine, HY2, Snell, meters and both TLS-owner platform files |
| Shared framework / composition | 9 | app composition, ClientProfile, domain/access, strict JSON, ports/{ports,runtime,export}, registry/phase3 and version |
| Core / application | 4 | application/{runtime,hysteria2,snell,service} |
| Storage / schema | 5 | SQLite bindings, credentials, runtime, migrations registration and new 0003_password.sql; 0001/0002 unchanged |
| API / transport / CLI | 4 | api/snell, cli/inbound, transport/{snell,hysteria2} |
| Exporters | 3 | dispatch, hysteria2 and Snell export description |
| Tests / validation infrastructure | 15 | cmd/app/HY2/native/exporter/registry/storage/version tests, TLS testkit, doc checker, both interop scripts and synthetic NoBrand fixture |
| Documentation / OpenAPI | 30 | README, canonical architecture/context/API/OpenAPI/specifications/testing/development/protocol docs, ADR 0014 and this Phase 3 report |

Most out-of-module changes implement generic multi-user/password/TLS contracts once.
Shared runtime paths are reusable; identified edge/composition/storage boilerplate
requires a bounded Phase 4 refactor, with **MEDIUM** cost rather than a failed core
abstraction. No TUIC code, dependency change or upstream runtime patch is included.

### Capabilities and authority

TCP, UDP transport/payload, IPv4, IPv6, DomainEndpoint, MultiUserNative (1–16),
native authenticated payload/session stats, per-Binding stats, static TLS and QUIC:
**SUPPORTED**. HotUserUpdate=false; Users=Restart affected Inbound; HotReload=false.
Obfs/masquerade/hopping/URI/advanced QUIC controls remain deferred or rejected.
Persistent Account aggregate usage/billing: **DEFERRED**. TrafficPolicy is metadata
only, policy_enforced=false. No expanded capability or Stable claim is made.

Distinct Accounts/Bindings/Credentials for Alice and Bob share one Inbound. Password
identity maps to immutable Binding IDs; Account/Binding store no protocol credentials.
Runtime options are private generated artifacts; restart uses committed SQLite plus
required TLS material references. Listener, display endpoint, explicit SNI and leaf
identity retain distinct roles; exports contain only authorized client data.

### Quick freeze gates and source integrity

Windows Go 1.26.2: full Splicore + cmd tests **PASS**, both binaries **PASS** (sing-box
with exact default tags/ldflags and upstream version), own vet **PASS**.
The initial Windows unit attempt **FAIL** is retained: a long GOTMPDIR made two
absent-daemon Unix socket tests return unavailable. Repeating the full suite with a
short task-owned `D:\spf3tmp` succeeds, with no source change or relaxed assertion.

Ubuntu-24.04 WSL2 Go 1.26.6 remains healthy. A fresh native ext4 snapshot copy runs
the full Splicore + cmd unit gate **PASS**, own vet **PASS**, critical HY2 multi-user/
TLS/UDP conflict/replacement/recovery/startup/admission/port reuse smoke **PASS** and
Snell apply/display/recovery/rollback/revision/interrupted-journal regression smoke
**PASS**. Tests use native temporary state via the test-exec wrapper; compile caches
stay external on D. The recorded cleanup removes only this freeze's owned native
copy/temp directories and Windows temporary roots; no runtime keys/state enter Git.

The immutable independent WSL campaign remains valid: amd64 builds, arm64 compile,
unit/race, six fuzz targets, 12 HY2 real cells, nine Snell real cells, dual-user/TLS/
QUIC/UDP/IPv4/IPv6/domain, transactions/recovery/stats/concurrency/4 MiB/reconnect/
abnormal close, exact upstream root CI and live API schemas: **PASS**. This freeze
does not claim to rerun that complete traffic campaign. Current metadata/schema
checks revalidate its actual archived response bundles, not freshly collected traffic.

Acceptance Source Match: **PASS**, all **103** owned functional Go/Python/SQL/JSON/
shell/PowerShell files, including source/tests/fixtures, exact set/size/SHA256 against
the accepted manifest. The earlier 100-file audit omitted three unchanged shell/
PowerShell gate scripts from its selector; this broader match covers them too.
Manifest SHA256: `cc09a4c99dbc03c55fc669a6c759ec67511004e3ef63491d24adfd2c453bd703`.
**42** protected reports/evidence/historical migrations match. Architecture disposition
changes docs only, so no runtime evidence is invalidated. The staged gate compares
the actual index bytes against the same manifest before committing.

Final Markdown/local links/OpenAPI, both accepted live response/export-envelope
bundles, source/history/import/secret audit and inclusive git diff --check: **PASS**.
OpenAPI retains 22 operations / 13 implemented routes. Final exact document/link
counts and command exits are recorded externally after these documentation edits.

### Vet baseline classification

**KNOWN UPSTREAM BASELINE**:

- `daemon/managed_service.go:75:12`: possible misuse of unsafe.Pointer.
- `experimental/libbox/debug.go:10:11`: possible misuse of unsafe.Pointer.

Both exact source expressions are `*(*int)(unsafe.Pointer(uintptr(0))) = 0`.
Their complete files are byte-identical to Git blobs in pristine upstream v1.14.1
and Phase 2, independently checked during this freeze. The original extra-vet FAIL
log remains unchanged; default upstream root CI PASS is a separate recorded gate.
New Splicore findings: **NONE**, fresh Windows and Linux own vet pass. Upstream is
not patched to silence these findings.

### Auxiliary whole-file check

Original auxiliary result: **FAIL**. Reason: strict post-test file set included
generated files; Python __pycache__ is reproducible. The exact original extra-file
inventory was not retained before cleanup, so no claim identifies every original
extra or retrospectively changes the failure to PASS.

Classification: **NON-GATING AUXILIARY CHECK**. It is an external one-off snapshot
helper, not a project formal gate. The original initial exact snapshot PASS and
formal Git/diff/secret/process/listener/key/runtime cleanup PASS remain evidence.
The already adjusted external helper is copied into this freeze directory, with
explicit `__pycache__` component / `.pyc` exclusions only. It still checks every
manifest file's presence/size/hash and rejects all other extras; it does not omit
source trees or remove the check. No archived helper/result/report is overwritten.

Updated helper/result: **PASS**, fresh 1,756-file / 9,152,118-byte native reconstruction
passes before tests and again after full unit/smoke and two actual generated Python
bytecode caches. This bounded reproduction is separate from the historical failed
post-run check. Acceptance impact: **NONE**.

### Security, external debt and Git procedure

Credential redaction **PASS**; no TLS/CA private material, HY2 password, Snell PSK,
real API/GitHub/NoBrand credential, Redis data or production endpoint is staged.
Credential values in tests are synthetic; the NoBrand fixture is an uninstantiated
synthetic template. Protected local API/revision/error/redaction contracts remain
unchanged. No real NoBrand installation is accessed.

Upstream runtime files modified: **0**. Wire changes: **0**. Other upstream protocol
changes: **0**. Phase 3 dependency/module/license changes: **0**.
Docker touched/queried: **NO**. Redis/TeleLedger touched: **NO**. Docker Desktop
recovery, unconfirmed Redis ownership (likely TeleLedger) and old test residue:
**DEFERRED EXTERNAL ENVIRONMENT CLEANUP**, not a Splicore code acceptance blocker.

The authorized procedure explicitly stages the approved 77 paths, checks index
stat/name-status/whitespace/secrets/source equality, creates exactly one commit
`feat(protocol): add experimental Hysteria2 vertical slice`, proves its Phase 2
parent and Phase 1/0/upstream ancestry, fast-forwards main with --ff-only, then
creates `codex/phase-4-tuic-vertical-slice` from frozen main and stops. Commit SHA
and final Git checks are external to avoid a second/self-referential commit.
Origin/push/new tag/release: **NONE**. TUIC implementation: **NOT STARTED**.
