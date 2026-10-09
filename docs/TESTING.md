# Host Integration Testing

- Documentation status: Canonical
- Audience: Developers and maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Safe local gates and qualification boundaries.
- Lifecycle: Update with implemented host operations and evidence.

Run default race/checkptr on owned and affected shared packages. Portable Windows
models exercise Manager/Lease with stateful backends, per-stage faults, external
edits, restart journals and double cleanup. Run Wintun and Core bypass matrices
ten times. Native Windows runs ordinary fixture tests, compile and symbol/ABI
resolution only; full race NOT EXECUTED. Do not invoke real Windows mutations.

Fuzz Core/legacy journal parsing, desired sets and endpoint/mapped
normalization. Fuzz never calls a real backend. Linux kernel lifecycle/route/DNS/
policy gates use owned disposable namespaces. Upgrade/rollback/uninstall/purge use
an owned nested service lab. Preserve prior evidence externally.

Component fixture PASS, runtime integration and real certification are distinct.
Actual adapter underlay integration and endpoint-generation fixtures complement
the model tests; real Windows qualification is pending and guards remain.
See [test strategy](testing/TEST_STRATEGY.md), [Windows](PLATFORM_WINDOWS.md)
and [recovery](RECOVERY.md).

## Underlay closure gates

Actual adapters run against the production WindowsBackend contract with a stateful
fake host/journal and socket spies. Cover DIRECT IPv4/IPv6/domain TCP/UDP, Native
client/server paths, VLESS TLS/REALITY, QUIC packet creation, Mieru TCP/UDP hooks,
DNS/bootstrap/DoT/health, native protected ownership and unavailable-platform refusal.
Dynamic DNS, old/new/shared refs, reused TUN/DNS changes and child/process cleanup
run ten times with default race/checkptr. Faults include empty resolution, missing
capability, stubs/dependency cycles, provision/readback/journal failure and external
mutation. SDK worker completion is observed after owned socket closure.

Run `python scripts/splicore-underlay-audit.py --output <private-evidence-directory>`
to classify every owned socket creation/delegation against the reviewed callsite
inventory. A changed raw socket call or unknown function fails; review its complete
call chain before updating the inventory. This guard complements runtime tests and
does not prove upstream behavior alone. Fuzz resolved sets and existing host journal/
Windows desired set parsers without real mutation. Acceptance binds a functional
source manifest to tests, builds and local package/service qualification.

## Phase 14 acceptance

Provider tests use owned localhost HTTP/echo/protocol servers only. Lifecycle tests
exercise ten nodes, 10x rename/reorder/credential rotation/failure, 304, stale removal,
proxy fetch and offline restart; rules tests verify actual routing after atomic swap.
Commit fault occurs after writing candidate/source data inside the SQLite transaction
and proves rollback plus old traffic. Scheduler injects clock ticks/barriers to prove
four-worker bounds/cancellation without sleeps. API/CLI/support tests check secret
and immutable-kind boundaries. Backup uses coherent SQLite snapshot and offline restore.

```sh
go test -race -tags with_gvisor,with_quic,with_utls ./internal/splicore/... ./cmd/splicore -count=1
go test -race -tags with_gvisor,with_quic,with_utls ./internal/splicore/application -run TestPhase14 -count=10
go test -race -run '^$' -fuzz '^FuzzURI$' -fuzztime=10s -parallel=2 ./internal/splicore/nodeimport
```

Race/checkptr remain default. Feed/fingerprint/rules/URL/diff fuzz targets are local
pure/fixture parsing, never live internet. Real TUN acceptance needs owned disposable
Linux namespaces with splicore_tun_lab tag; it asserts interface reuse, old streams,
concurrent server/client/16 TUN flows and restore. Do not run on real host routes.
Distribution upgrades Phase 13 schema 7 to schema 8 and qualifies failed schema 9
rollback in a new external source copy. The [Phase 14 report](reports/PHASE_14_CLIENT_MANAGEMENT_PROVIDERS_REPORT.md)
owns commands/results and precise platform qualification limits.
