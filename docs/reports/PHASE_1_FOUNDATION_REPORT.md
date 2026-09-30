# Splicore Phase 1 Foundation Report

- Documentation status: Historical
- Audience: Maintainers and Foundation reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Phase 1 implementation, scoped acceptance evidence and review limits.
- Lifecycle: Completed review snapshot; subsequent changes require a new acceptance record.

## Baseline

- Phase 0 Freeze: `687425bdbfff6c76f900035068c23a03c4547062`.
- Upstream: SagerNet/sing-box v1.14.1.
- Upstream commit / freeze parent: `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
- Initial branch/HEAD/main/remotes/clean worktree gate passed before implementation.
- Required canonical context and ADRs were read before code changes.

## Repository

Path: `D:\code\Splicore`. Branch: `codex/phase-1-foundation`.
HEAD and main remain the Phase 0 freeze. Working tree contains uncommitted
Foundation changes; index is empty of staged changes. Upstream is the sole
remote; origin is absent. Full upstream ancestry/tags are retained.

## Identity

Splicore **devel**, development channel; Config Schema **1**, DB Schema **1**,
Protocol ABI **1**, API **v1**. Product version is independent of upstream.
Full commit and dirty state are exposed, with UTC linker build time or unknown
for plain go build, actual Go version/platform and pinned upstream tag/full SHA.
Build metadata never rewrites tracked source.

## Product Command

| Gate / command | Result and scope |
|---|---|
| splicore build | PASS Windows amd64, Linux amd64 and Linux arm64 compile |
| retained sing-box build | PASS Windows minimal/CI/official tags; Linux minimal/CI tags and arm64 CI tags |
| version | PASS independent, daemon-free identity |
| status | PASS normal not running when absent; canonical System JSON when present |
| doctor | PASS actual Foundation checks, explicit unavailable/offline limits |
| capabilities | PASS application/HTTP/CLI placeholder capabilities |
| validate | PASS strict real bootstrap schema; unknown/runtime fields rejected |
| run | PASS isolated Linux UDS daemon lifecycle and shutdown; no host install |

Windows development uses httptest for running API/CLI tests; no production
Windows transport or TCP fallback is supplied. Build/test usage is in
[Foundation workflow](../development/FOUNDATION.md).

## New Packages

All owned code is additive under cmd/splicore and internal/splicore.

| Package | Purpose / dependency direction |
|---|---|
| cmd/splicore | process entry → app/cli/version |
| internal/splicore/app | explicit composition → application/registries/adapters |
| internal/splicore/domain/identity | UUID/revision/UTC/metadata/errors/transactions/events → standard library |
| internal/splicore/domain/access | Account/Binding/Credential/Inbound/Endpoint → identity/secret |
| internal/splicore/domain/policy | nullable TrafficPolicy/reset → identity |
| internal/splicore/domain/secret | default redaction and explicit reveal → standard library |
| internal/splicore/clientprofile | canonical sensitive client projection → domain |
| internal/splicore/ports | repository/protocol/engine/exporter/cipher contracts → domain/profile |
| internal/splicore/registry | immutable compiled registries and placeholders → ports/domain |
| internal/splicore/secretvault | injected AES-256-GCM cipher → ports/domain |
| internal/splicore/storage/sqlite | repositories, locks and forward migrations → ports/domain/driver |
| internal/splicore/application | shared queries and Account commands → ports/registries/domain/version |
| internal/splicore/api | HTTP parsing/serialization/error mapping → application/domain |
| internal/splicore/transport | protected Linux UDS, bounded client/server and httptest adapter → application |
| internal/splicore/cli | Foundation commands → application/config/transport/version |
| internal/splicore/config | strict process bootstrap → domain errors/YAML decoder |
| internal/splicore/version | independent product/build/schema identity → standard library |

Domain/ports import no HTTP, SQLite driver, upstream runtime options or engine config.
CLI/HTTP/application issue no SQL. No protocol runtime or child-process package is added.

## Domain

Account has opaque identity, name, active/suspended/closed state, enabled,
expiry, bounded nonsecret metadata, revision and UTC stamps, with no protocol secrets.
Binding references Account/Inbound/Credential and an optional policy override ID.
Credential has exactly one Account or Inbound owner and tagged typed secret payload.
Payload kinds support PSK, UUID, UUID+password and username+password; no giant
protocol credential struct or Mieru implementation exists.

Inbound has protocol/wire/feature identity, private engine placement, separate
Listener/DisplayEndpoint sets, tags, versioned settings and revision. Persistence
accepts only empty protocol settings until real schema validation is implemented.
Endpoint host and port are separate; tests include reserved IPv4/IPv6, DNS/punycode
and rejected malformed numeric IPs, URLs, ports, whitespace, zones and controls.
TrafficPolicy nullable integer limits/reset/max sessions have validation only.
Resource/global revisions are signed 64-bit with overflow checks; API emits strings.

## Protocol Registry

Concrete ABI 1 ports separate metadata/capabilities, validation, credential,
runtime intent and ClientProfile construction. Explicit constructor composition
has sorted iteration, duplicate/unsupported ABI rejection and typed unknown errors.
The registry maps are immutable and safe for concurrent reads; adapters must
protect their own values. Tests exercise concurrent reads and metadata isolation.

Snell 6, Hysteria2 2, TUIC 5 and VLESS 0 are metadata-only placeholders reporting
not_compiled/unqualified. Effective traffic capabilities are false/unsupported.
Typed groups distinguish transport/payload/families/endpoints, native identity/
stats/policy, mutation, TLS/REALITY and client compatibility. No wire claim is made.
VLESS metadata uses the actual sing-vmess v0.2.8 wire constant 0; the former
Phase 0 illustrative value 1 was corrected without changing protocol behavior.

## Engine Registry

Native is compiled metadata with RuntimeImplemented=false. Xray is not_compiled
metadata. Both Supports/Compile return typed NotImplemented. Tests express
VLESS+native and VLESS+xray-compatibility while Account/Binding/Profile remain
engine-neutral. No Xray download/start/config/supervisor exists.

## Client Profile

Canonical profile separates endpoint/authentication/TLS/transport/options/metadata
from runtime intent/config. Engine ID, actual listener and private server config
are absent. Default credential/profile/settings formatting and JSON are redacted.
Mihomo, sing-box, Surge, URI and JSON exporter placeholders return NotImplemented
with no rendered bytes. Implemented exporters: **NONE**; all are deferred.

## Storage

Driver: modernc.org/sqlite **v1.59.0**, matching libc **v1.75.7**, SQLite **3.53.4**.
Driver license BSD-3-Clause, SQLite public domain, bundled sqlite-vec MIT;
transitive notices are reviewed in the [dependency audit](../development/DEPENDENCIES_PHASE_1.md).
CGO=0 works on Windows/Linux amd64 and Linux arm64 compile; minimum Go 1.25.5
tests pass. v1.60.1 was rejected for requiring Go 1.26.

SQLite committed revision is sole domain authority; bootstrap owns process paths.
WAL/FULL/foreign_keys/busy_timeout(5000) apply through the DSN on every physical
connection. A four-connection bounded pool and serialized writer callbacks keep
transactions short. Installation OS locking precedes migrations and domain access.

DB Schema 1 has a checksummed embedded 0001_initial forward migration, atomic
schema/node identity initialization, FK/quick_check and metadata validation.
Existing invalid/missing installation identity fails; it is never silently reminted.
No ad hoc ALTER/down migration is used. Snapshot/reopen is tested with VACUUM INTO.
Power-loss, arm64 execution, production workload capacity and upgrade backup
orchestration remain future production storage qualification.

## Database Tests

| Case | Result |
|---|---|
| Fresh DB / schema 1 migration / repeat | PASS |
| Migration failure / schema rollback / retry | PASS |
| Close/reopen/existing identity and generation | PASS |
| Newer schema / checksum / wrong metadata / corrupt file | PASS fail closed |
| Missing node identity | PASS fail closed |
| Resource revision and global generation conflict | PASS typed conflict |
| Concurrent competing generation writes | PASS one commit, remaining conflicts |
| Multi-resource callback failure | PASS rollback and failed journal |
| Per-connection WAL/FULL/FKs/busy timeout | PASS |
| Process exit before commit / WAL reopen | PASS committed state preserved, pending journal retained |
| Pending journal mutation fence | PASS refuses mutation |
| Credential ciphertext / owner/protocol matching / tamper | PASS |
| Missing encryption key | PASS refuses credential write/reveal |
| Coherent snapshot/reopen | PASS |

All databases, keys, fixtures and sockets use temporary filesystems; no project
DB, real user state, NoBrand deployment or host service is touched.

## Application Service

CLI → local HTTP client → API → application queries → repository; direct injected
application queries are also supported in tests. Account create/update commands
share the repository transaction boundary. Creation ports for other Foundation
resources enforce ownership within the writer transaction; full update/rotation
and external CRUD are deferred.

The CLI test compares decoded status, HTTP System and direct service System.
The actual isolated Linux binary additionally compares CLI/HTTP System bytes.
Both tests pass. There is no second CLI implementation of system/domain state.

## API

Implemented: GET /api/v1/system and GET /api/v1/capabilities only. Capability
pagination is bounded, deterministic and fenced by committed revision/build
identity. ETags are quoted revisions. Problem bodies use fixed safe messages and
request IDs; typed revision conflict maps to future-compatible HTTP 409.

Linux production target is /run/splicore/splicore.sock; tests use private temporary
paths. UDS permissions/owner and SO_PEERCRED are tested. Windows uses httptest.
Public TCP binding: **NONE**. OpenAPI marks exactly two Foundation operations;
all other frozen operations remain deferred. Dirty identity and Foundation
diagnostic summary are declared additive System/Version schema extensions.
API schema validation results are included under Tests.

## Transaction

Transaction ID/state pending/committed/failed, global base/target revision and
Actor/RequestID/UTC/failure code exist. Pending identity persists before the short
SQL apply; resource changes, global generation and successful outcome commit
together. Failure rolls back resources and stores a safe code independently.
Process crash leaves pending state, System recovery_required and a mutation fence.
Runtime apply/health/compensation, durable candidate payloads, idempotency and
full audit persistence remain deferred. RequestID is correlation only.

## Security

Secret values redact String/GoString/all fmt verbs/default JSON; Credential,
ClientProfile and opaque settings redact default diagnostics. Application/HTTP/
CLI errors discard untrusted messages; tests use adversarial dummy payloads.
AES-256-GCM has random nonce and credential/owner/kind/schema associated data;
tampering/owner substitution fails. Cipher keys are injected, never stored in DB.
The command provisions no production key and performs no credential writes.

Linux requires current-owned 0700 state/control directories, private DB/WAL/SHM/
lock files and socket 0660 inside the private directory. Owner/root are admitted;
group operator access is deferred. Existing socket paths are not auto-replaced.
Windows reparse/type checks and process locking exist; production DACL provisioning
remains deferred. Production management transport is Linux only.
Secret/fixture scan results are included under Tests; no support bundle upload exists.

## Diagnostics

Version works offline. Status absence is normal. Doctor uses real path existence
and application Foundation facts for storage/schema/migrations/registries/transport;
offline integrity is explicitly uninspected. Health is degraded/Foundation-only,
never invented Snell/Mieru/Xray health. Secret value types and safe error/diagnostic
projections are reusable support-bundle groundwork; bundle/diagnose are deferred.

## Tests

| Gate | Result / limits |
|---|---|
| Own unit/contract/storage/migration/application/API/CLI/redaction | PASS all 17 packages on Windows and Linux |
| Linux race | PASS all owned packages, CGO=1 test compiler |
| Windows race | NOT RUN: host CGO=0, no qualified race compiler |
| Endpoint fuzz | PASS 2-second smoke; 92,754 executions |
| ID fuzz | PASS 2-second smoke; 105,289 executions |
| Config fuzz | PASS 2-second smoke; 21,776 executions |
| Go minimum | PASS Linux Go 1.25.5 owned tests |
| Configured root lint / format | PASS pinned golangci-lint v2.14.0 |
| Own supplementary vet | PASS |
| Docs / metadata / Markdown / relative links / OpenAPI / actual responses | PASS 56 Markdown documents, 486 local links, 13 operations and live response schemas |
| Inclusive tracked + untracked whitespace / secret scan / history protection | PASS 41 historical files within 1,615 protected tracked files unchanged |
| Reproducible Windows artifact | PASS equal SHA-256 with fixed build metadata |

Linux API coverage was 92.4%, config 97.2%, SQLite about 75%. Main is verified by
real binary smoke/builds; package coverage does not qualify protocol traffic.
Early test directory/Windows URI/absent-socket defects were repaired and relevant
gates rerun. A missing optional file inspector was replaced by direct ELF inspection.
Fresh raw logs/results remain in external temp directory
`C:\Users\admin\AppData\Local\Temp\splicore-phase1-20261001`.

## Cross Platform

Windows amd64: Go 1.26.2, CGO=0 builds and owned tests PASS.
Linux amd64: Go 1.26.6 image
`sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6`,
CGO=0 builds/tests/full root CI PASS, CGO=1 race PASS.
Linux arm64: both commands compile with CGO=0; execution NOT RUN.
Tests used read-only source mounts and isolated SYS_ADMIN/NET_ADMIN/NET_RAW plus
seccomp=unconfined and container-only tcpdump; no host networking/service install.

Artifacts are review outputs, not releases. Windows splicore size 12,342,272 bytes;
Linux amd64 size 16,575,440 bytes; Linux arm64 size 15,801,478 bytes.
Both ELF artifacts have the correct machine type and no dynamic interpreter.
Windows reproducibility SHA-256:
`f5089fa74cd9af4de45820c493413420d42ab1dabc3e746c47dad6081f6d4136`.
Fixed UTC build time `2026-10-01T00:00:00Z` is an explicit reproducibility input.

## Upstream Runtime Modifications

Count: **0**. No inherited protocol/transport/route/DNS/TLS/QUIC/adapter/option/
runtime source, workflow, release flags, LICENSE or NOTICE is modified.
Wire changes: **NONE**. Root module path and retained command are preserved.

## Upstream Regression

Phase 0 and Phase 1 both build the Windows/Linux retained commands. Final Linux
complete root CI PASS with no test-name exclusions. Windows complete root CI
still fails in common/tlsspoof and common/windivert: WinDivert cross-disk rename
and SCM access failures match the inherited environment limitations.
Final Windows supplementary root tests excluding ^TestIntegration PASS.

Supplementary root vet retains exactly the three inherited unsafe.Pointer findings:
daemon/managed_service.go:75, experimental/libbox/debug.go:10 and
experimental/boxdd/authenticode_windows.go:95. Own vet and root lint pass.

Windows supplementary attempts also observed public TLS fragment handshake
timeout/EOF. The unchanged frozen HEAD temporary copy reproduced EOF in the same
public-network test; focused current tests and the final supplementary root run
passed. The new observation is documented as baseline network flakiness, not
hidden or patched. New Splicore regressions after final verification: **NONE**.
Separate test/go.mod Docker interop, macOS/mobile and real Splicore interop remain
NOT RUN; Foundation introduces no protocol qualification claim.

## Dependencies Added

Exact names/versions/purpose/licenses and graph upgrades are listed in the
[dependency audit](../development/DEPENDENCIES_PHASE_1.md). New SQLite/libc/mathutil/
memory/humanize/strftime/bigfft plus selected isatty and x/tools/x/mod upgrades
are CGO-free on the command path. YAML v3 is promoted from an existing dependency.
Original module minimum and x/sys selection remain unchanged. go mod verify PASS.
Cross-platform impact: larger binary/dependency graph; no C cross compiler needed.

## Documentation

Canonical context/overview/index, domain/ERD, SDK/engines/profiles, storage/security/
transaction/version/diagnostics, API/OpenAPI, testing/development/fork docs are updated.
Foundation workflow and exact dependency audit are added. ADRs 0002, 0007, 0008
and 0012 record implementation refinements while retaining proposed review status.
ADR added: **NONE**. Historical Phase 0 reports/source map/ledger/evidence modified:
**NONE**, verified against freeze bytes.

## Diff

Final inclusive counts: **83 files**, **5,380 insertions**, **128 deletions**.
Categories: owned code, owned tests, canonical docs/report, dependencies and own
build/test/check scripts. Upstream runtime category: **0 files**.
Tracked git diff alone omits additions; final audit includes untracked files
using a separate external comparison tree and never stages them.

## Git

Commit: **NONE**. Push: **NONE**. origin: **NONE**. Tag: **NONE**. Release: **NONE**.
No reset/clean/checkout overwrite or upstream-history rewrite occurred.
HEAD/main remain the freeze; changes are uncommitted for maintainer review.

## Deferred

Mieru; Xray runtime; FinalMask; Sudoku; Panel; Payment; Orders;
Full Subscription Delivery; Real Quota Enforcement; Protocol Runtime Migration;
Native Custom Protocol. Also deferred: entitlement/usage, live auth/policy hooks,
imports, candidate/runtime compensation, key deployment/rotation/recovery,
Windows production transport/DACL, public control auth/RBAC, production backup/
load/power-loss qualification, actual exporters and third-party interop.

## Architecture Deviations

Core boundaries are preserved. Implementation refinements are explicit:

| Decision | Reason | Record | Impact |
|---|---|---|---|
| Narrow Foundation table/runtime scope | Explicit Phase 1 request supersedes broader Phase 0 staging recommendation | Updated domain/ERD/context | Entitlement/usage/reference traffic deferred; authority unchanged |
| Combined immutable registries | Avoid empty per-protocol/engine/exporter packages | Architecture/SDK | Future adapters implement ports; no Account/Binding changes |
| Standard-library flag dispatcher | Small six-command Foundation surface | ADR 0002/fork boundary | Recommended Cobra/completions deferred; application contracts unchanged |
| Four-connection bounded pool with serialized writer | Minimal short-transaction foundation | ADR 0007/storage | Separate writer/read pools deferred; one writer at a time and per-connection pragmas retained |
| Injection-only AES-GCM key handling | Deployment provisioning still unresolved | Security/storage | No plaintext fallback; command cannot persist/reveal credentials without key |

No parallel architecture, upstream runtime or wire deviation is introduced.

## Final Result

**FOUNDATION READY FOR REVIEW**.

## Blockers

None for the authorized Foundation scope. Known baseline/platform limitations
and deferred production runtime/key/interop qualification remain explicit above.
