# Phase 3 Hysteria2 validation workflow

- Documentation status: Canonical
- Audience: Contributors and reviewers
- Last reviewed: 2026-10-01
- Owner: Test maintainers
- Responsibility: Reproduce bounded HY2 qualification using external synthetic evidence.
- Lifecycle: Update with Phase 3 test commands or pinned client dependencies.

## Entry and scope

Historical entry branch `codex/phase-3-hysteria2-vertical-slice`, parent/main
`5bc50a69b0df2c3dc9ede86015c9e4a6b86e2981`. Entry was clean. Initial Phase 3 scope
authorized local HY2 implementation and verification. The final freeze authorization
permits one commit, fast-forward main and the reserved Phase 4 branch, then stops.
Publication and TUIC implementation remain unauthorized in that freeze scope.
No real NoBrand installation is read or changed. Historical reports/migrations
0001 and 0002 are immutable. See [profile](../protocol/HYSTERIA2.md) and
[acceptance report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md).

## Package gates

```sh
go test ./internal/splicore/... ./cmd/splicore
go test -race ./internal/splicore/... ./cmd/splicore
go test ./internal/splicore/domain/access -run '^$' -fuzz '^FuzzEndpoint$' -fuzztime 5s -parallel 2
go test ./internal/splicore/config -run '^$' -fuzz '^FuzzDecode$' -fuzztime 5s -parallel 2
go test ./internal/splicore/protocol/snell -run '^$' -fuzz '^FuzzSettings$' -fuzztime 5s -parallel 2
go test ./internal/splicore/exporter -run '^$' -fuzz '^FuzzExport$' -fuzztime 5s -parallel 2
go test ./internal/splicore/protocol/hysteria2 -run '^$' -fuzz '^FuzzHysteria2Settings$' -fuzztime 5s -parallel 2
go test ./internal/splicore/exporter -run '^$' -fuzz '^FuzzHysteria2Export$' -fuzztime 5s -parallel 2
go build -o /external/splicore ./cmd/splicore
go build -race -o /external/splicore-race ./cmd/splicore
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /external/splicore-arm64 ./cmd/splicore
```

Repeat Windows package tests and both binary builds. Build inherited sing-box
with the repository's default tags/ldflags and explicit upstream version 1.14.1.
Keep inherited root CI failures and vet findings separate from Splicore gates;
never patch upstream to make them disappear. Independent Ubuntu WSL2 is the
authorized final acceptance environment; Docker and its workloads remain untouched.
Use a compatible existing Go >=1.25.5 or an isolated checksum-pinned toolchain.
Linux private fixtures, SQLite, UDS and runtime logs must live on native ext4.
Build/tool caches may live on D. Go 1.26 `testing.TempDir()` prefers `GOTMPDIR`,
so when that build directory is on DrvFS, run tests with
`-exec 'env -u GOTMPDIR'` and a short native `TMPDIR`; retain the inherited CI's
sudo execution with `-exec 'sudo env -u GOTMPDIR'`. Do not weaken permission checks.
Snapshot tracked and untracked working-tree files, verify list/size/SHA256, and
run the existing entrypoints from that native source copy.
Windows test/compile temporary roots also need short paths: Go 1.26 prefers
GOTMPDIR for testing.TempDir, and long paths can exceed Unix socket address limits
even in absent-daemon tests. Keep failed attempts and corrected rerun results.

## Real interop

Prepare external `clients/` with [pinned downloads](../../scripts/splicore-clients.py).
The script verifies official archive SHA-256 before extracting Mihomo 1.19.30
and sing-box 1.14.1. Reuse verified archives when network downloads are unavailable.

```sh
python3 scripts/splicore-clients.py /external/clients
python3 scripts/splicore-hysteria2-interop.py /external
python3 scripts/splicore-snell-interop.py /external
```

The HY2 harness requires OpenSSL, creates a temporary EC CA/leaf/key, starts real
clients and checks their parsers first. Each Mihomo instance has a separate private
home directory to avoid cache-lock conflicts. It tests Alice/Bob on one Inbound,
all three address types, trusted CA/correct SNI, wrong password/SNI/CA, TCP/UDP
integrity, 16 concurrent connections, 4 MiB per user/cell, reconnect, per-user
attribution, disable/re-enable, actual daemon restart with existing clients,
abnormal client kill, socket reuse and secret boundaries. Reconnect retries are
bounded; the report records their actual outcome. Run against the race-built server
to exercise third-party traffic under race instrumentation.
CLI status/capabilities are compared to actual API system/capabilities responses.
Child PIDs/executable identities are recorded for precise residue checks.
For independent acceptance, execute the unchanged interop entrypoints in a new
network namespace with only `lo` enabled. Their dual-stack wildcard listener then
has no external interface; all traffic uses ephemeral loopback ports. Capture
namespace listeners before and after, and host listeners independently.

The synthetic NoBrand fixture is a template: substitute external ephemeral TLS
references/CA and credentials before validate/plan/apply. Removing the import
after apply must not affect SQLite recovery. Private certs, keys, configs and
SQLite state are removed in finally. Retain only safe logs, live metadata and
JSON summaries. Phase 2 Snell harness inputs are also private; remove its state
and secret-bearing client configs after the regression run.

## Documentation and final gates

Build a Git-derived inventory including tracked owned documentation and untracked
new Markdown; validate it with [doc checker](../../scripts/splicore-doc-check.py)
and its pinned dependencies. Validate live HY2 plan/apply/Binding/query responses
against OpenAPI, and check explicitly secret-bearing export envelopes without
archiving credentials. Scan owned changes and external diagnostics for secrets,
panic and data-race reports. Verify historical bytes, zero upstream runtime diff,
unchanged HEAD/main/index/remotes, no repository artifacts and `git diff --check`.
