# Test strategy

- Documentation status: Canonical
- Audience: All developers and reviewers
- Last reviewed: 2026-10-01
- Owner: Test maintainers
- Responsibility: Meaningful implementation/interop/failure gates and reporting scope.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Current Phase 2 implementation

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
