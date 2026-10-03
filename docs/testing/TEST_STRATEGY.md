# Test strategy

- Documentation status: Canonical
- Audience: All developers and reviewers
- Last reviewed: 2026-10-03
- Owner: Test maintainers
- Responsibility: Meaningful implementation/interop/failure gates and reporting scope.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Current implemented gates

Phase 3 adds HY2 strict option/password/TLS validation, native multi-user ownership,
per-Binding stats, precommit UDP drop, UDP conflicts, pending/build/start/health/commit
failure compensation, Binding replacement rollback, SQLite recovery and populated
schema-2→3 ciphertext preservation. Real pinned clients test trusted CA/SNI, all
endpoint types, TCP/UDP, wrong password/SNI/CA, 16 connections, 4 MiB, sequence
integrity, revocation/re-enable and existing-client reconnect after actual daemon
restart. Linux race/fuzz and Windows/Linux/arm64 gates accompany Snell real regression.
See [HY2 workflow](../development/PHASE_3_HYSTERIA2.md) and
[report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md). Wire/TLS crypto is not reimplemented or fuzzed here.

Actual pinned clients exercise TCP/UDP integrity, IPv4/IPv6/domain endpoints, auth/version/port/stopped failures, concurrent transfers, race, restart and external evidence. See [workflow](../development/PHASE_2_SNELL.md) and [matrix](INTEROP_MATRIX.md).

Phase 1 implements Foundation unit/contract/migration, process-crash, Linux
race and endpoint/config/ID fuzz tests. Runtime/interop/accounting layers below
remain future gates. Phase 0 actual results live in
[baseline](../architecture/UPSTREAM_BASELINE.md) and its evidence directory.

Run the independent suite with `go test ./internal/splicore/... ./cmd/splicore`,
`scripts/splicore-test.ps1`, or `sh scripts/splicore-test.sh`. Upstream Makefile,
workflows, tags and test semantics are unchanged. Results and platform limits
live in the [Phase 1 report](../reports/PHASE_1_FOUNDATION_REPORT.md).

| Layer | Required meaningful checks |
|---|---|
| Unit | domain ownership, entitlement ceiling/reset/DST, selector narrowing, revision/idempotency and redaction |
| Contract | protocol/engine/repository/exporter implementations conform to ports; API shapes/errors/preconditions; unsupported capability rejects |
| Migration | numbered forward migrations, checksum/newer-schema rejection, coherent backup/restore, NoBrand import idempotency/ownership |
| Runtime | multi-Inbound start/stop/drain, same-port replacement, user/credential cutoff, listeners/TLS/UDP and no leaked sessions |
| Interop | actual pinned third-party clients, auth/isolation/TCP/UDP/families/domain/reconnect/transfer; exporter render alone insufficient |
| Differential | upstream reference vs Splicore config translation/traffic/reconnect/UDP/error behavior for unchanged wire protocols |
| Concurrency | concurrent Account operations, generation fences, one shared quota/rate across protocols, reset/rotate while active |
| Race | `go test -race` on supported CGO/toolchain/platform modules; protocol/lifecycle/state tests required, not just domain values |
| Fuzz | config/URI/frame/subscription parsers, exporter escaping, import/migration and API validation; seeded truncated/oversized/adversarial corpora |
| Failure injection | DB/disk write failure, listener conflict, process/child crash, invalid config, partial migration, shutdown during mutation, restart at every journal phase |
| Field beta | opt-in per-protocol migration, server/client digests, support bundles, rollback drill and stable qualification evidence |

Crash matrix verifies committed generation, no unauthorized candidate admission,
no double-counted usage, bounded uncertain reservations and no falsely completed
rollback. Old sessions retain identity and current revocations. Cross-engine strict
policy is blocked until enforcement coverage is demonstrated.

## Upstream commands and scope

Root CI `.github/workflows/test.yml` runs Go ~1.25/~1.26 on Windows/macOS/Linux,
uses DEFAULT_BUILD_TAGS_OTHERS + release/LDFLAGS; Unix executes tests as root.
The root `./...` excludes separate `test/go.mod`. Makefile `test` additionally
runs root untagged tests, then `go mod tidy` and tests in `test`; many tests need
Docker/reference images/public networking. Do not call root CI coverage the full
Docker interoperability suite. If running that suite later, tidy/build in an
isolated copy to preserve upstream baseline files.

Lint workflow uses golangci-lint latest across OS/arch; Phase 0 pins the observed
tool v2.14.0 for reproducibility and checks host Windows configuration. Go vet is
an additional check; it is not in the enabled upstream linters. Formatting checks
use `golangci-lint fmt --diff` without rewriting upstream files.

Qualification rules: explicit PASS/FAIL/NOT RUN/SKIP with reason and scope,
captured commands/toolchain/tags/full SHA/artifact digests, no green by modifying
upstream. Environment-only integration limitations remain visible. Platform
mobile/Apple toolchains and Surge license/access are future-specific gates.

## Phase 4 shared infrastructure gates

[TUIC workflow](../development/PHASE_4_TUIC.md) requires native WSL unit/race/both
builds/arm64, settings/creation/credential/export fuzz, own vet/root CI, 12 TUIC cells
and full HY2/Snell regressions. Docs/OpenAPI/live responses, secret/diff/index and
protected-source gates apply. Shared refactors preserve TLS/private files, attribution,
pending admission, compensation and port release. Account disable uses production
creation/recovery rather than SQL state mutation.

## Phase 5 supported-surface safety

Vision is deferred/unsupported under [ADR 0017](../adr/0017-defer-vision-dependency-safety.md).
Config/API/CLI/import, protocol, runtime builder, ClientProfile and exporters must
reject it; a fake engine construction counter remains zero and bypassed validation
must not commit SQLite state. Flow-none native tests cover plain/TLS/REALITY single
and dual users, 16 concurrency, 4 MiB integrity, reconnect and abnormal close under
default race/checkptr. Fixed-version real clients verify the non-Vision matrix and
secret gates. [Final evidence](../reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md) owns
actual outcomes; preserve earlier diagnostic failures and frozen Phase 0–4 reports.

## Phase 6 external engine gates

Process fixtures test precommit admission, OS listener ownership, concurrent
close/traffic, double lifecycle calls, unrelated child survival, early exit,
timeout, conflict, exclusive root lease and stale cleanup. The explicit pinned
integration tag fails if the reference artifact is missing and proves shared
Account/UUID placement, profile/export equality, transaction compensation and
SQLite regeneration. Run default race/checkptr, process tests 10x, path/renderer
fuzzing, fresh protocol regressions, Windows manager/build, arm64 compile,
secret/doc/OpenAPI/live API and source/dependency/history/index audits.

## Phase 7 specialized extension gates

[Phase 7 workflow](../development/PHASE_7_XRAY_EXTENSIONS.md) requires typed parser,
feature intersection/version/hash, renderer-owned config snapshot, profile/exporter,
secret filtering/redaction, transaction admission/compensation and SQLite recovery.
Default race/checkptr run over full Splicore and affected shared packages; supervisor
and pinned masked transaction/recovery tests repeat ten times. Fuzz bounded parser
and renderer inputs. Managed API-to-exporter-to-real-Xray traffic is independent of
the preliminary raw reference probe. Fresh native REALITY, Xray standard and three
old protocol regressions, docs/OpenAPI/live schemas/secret scans/diff audit are gates.
No Stable, masked UDP or REALITY combination claim follows from TCP acceptance.

## Phase 8 Mieru ownership gates

[Workflow](../development/PHASE_8_MIERU.md) requires native lifecycle 10x with
joined goroutine/socket cleanup, default race/checkptr, two inbounds/two users,
commit admission and response-after-upload-EOF regression. Managed official/Mihomo
binary matrix supplements embedding probes; source/reference quota tests remain
separate. Fuzz only canonical credentials/import/profile/export adapters. Windows
units/build, Linux runtime/race/interop, arm64 compile, formal docs/live schemas,
fresh six old-protocol critical regressions and source/license/secret/Git audits.

## Phase 9 installed-service gates

The [distribution gate](../DISTRIBUTION.md#distribution-gate) builds deterministic
amd64/arm64 packages and Windows binaries, verifies inventories/checksums and runs
default race/checkptr plus support secret tests. A disposable nested systemd lab
tests first initialization, non-root low TCP/UDP ports, all installed protocol
smokes, restart, parent/managed-child crash and unrelated Xray survival. It performs
an ordinary update and an external schema5 failure fixture with snapshot rollback,
then program-only uninstall, retained-state reinstall and explicit safe purge.
Symlinks and same-filesystem bind mounts must reject purge before deletion.
Raw secrets injected into the actual unit journal must be absent from every
decompressed support-bundle member. No fixture modifies production migrations.

## Phase 10 client gates

Unit/control tests cover canonical node/outbound/local/route references, roles,
vault ownership, port conflict, injected startup and commit failure, stale revision,
REST/CLI methods and hostile support redaction. In-process A/B data-path tests prove
SOCKS→DIRECT and SOCKS→Snell→Splicore with IPv4/IPv6/domain, v5→v4/v6→v6, 4 MiB
SHA256 integrity, 16 concurrent connections, route/credential generation retention,
abnormal local/remote close, reconnect, restart and simultaneous server/client traffic.
Client recovery failure preserves server/API. Phase 11 adds local SOCKS UDP admission
and ownership tests alongside adapter packet tests. Deterministic ownership tests use notifications, not sleep/retry.

Run complete owned package tests and default race/checkptr, 10 repeated client
race runs, affected inherited shared package race tests and owned vet. Bounded
fuzz covers RemoteNode, Endpoint, Outbound, Route and Snell adapter options only;
no wire/crypto fuzzing. Windows exercises actual native traffic; Linux arm64 remains
compile only. Installed-service lab tests use loopback-only namespaces, two owned
Splicore instances and pinned sing-box reference **servers**; the client is Splicore.
Retain installed regression smoke for all server protocols plus install/upgrade/
failed-forward-migration rollback/reinstall, doctor/support and cleanup gates.
Evidence remains outside the checkout; [interop](INTEROP_MATRIX.md) owns exact fixtures.

The service lab supplies a loopback-only localhost A/AAAA DNS fixture because its
resolv.conf points to 127.0.0.1. It never forwards queries. Echo serves both address
families on one target port; remote-domain tests do not depend on address order.

## Phase 11 expansion gates

Run the owned suite with `-race -count=1 -tags with_quic,with_utls,splicore_xray_integration`
and the exact pinned Xray artifact. No GODEBUG/checkptr/race suppression. Shared
common/protocol/adapter packages retain their own race gate. UDP, Mieru and Xray
lifecycle tests each run ten times. Canonical options/public security/SOCKS address
parsers receive bounded fuzzing only; wire/crypto implementations are not fuzzed.

Self interop proves each adapter, REALITY negatives, credentials, IPv4/IPv6/domain,
4 MiB, 16 TCP/UDP mixed sessions, rotation and reconnect. The disposable installed
unit additionally runs all outbounds alongside eight frozen server fixtures, service
restart/crash/upgrade/rollback/reinstall and pinned sing-box reference servers. All
fixtures/artifacts/evidence stay external; no host or third-party targets are used.

## Phase 12 gates

Run owned default race/checkptr with with_quic,with_utls,splicore_xray_integration;
affected DNS/TLS/clientio/jsonstrict race packages; complete Windows tests/build and
actual local routing/DNS smoke, recording Windows race NOT EXECUTED. Arm64 build only.
Synthetic 1k/10k compile/match benchmarks include allocations. Network-free bounded
fuzz covers canonical domain/CIDR/ports/group/DNS validation and rule compilation.
No wire/TLS/QUIC fuzz, skipped tests, suppression, sleep/retry masking or external targets.

A–H run actual Application/SOCKS and owned adapters: domain Selector→Snell/DIRECT,
IPv4→HY2/IPv6→TUIC, three outbound HTTP probes, ordered Fallback down/recovery,
RR/UDP association affinity, proxy/direct DNS counters, 100-rule/group/DNS atomic update
with old TCP/UDP retained, and server/client restart coexistence. Ten race repetitions
cover graph swap/selection/cache/scheduler/cancellation. The installed campaign driver
splicore-network-smoke.py retains loopback DNS/HTTP/echo fixtures across restart/crash/
upgrade/rollback/reinstall and verifies SQLite graph/selector restoration.
