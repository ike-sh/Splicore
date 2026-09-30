# Foundation dependency audit

- Documentation status: Canonical
- Audience: Maintainers and dependency/license reviewers
- Last reviewed: 2026-10-01
- Owner: Storage / Core maintainers
- Responsibility: Foundation dependency selection, exact versions, licensing and build impact.
- Lifecycle: Update with dependency changes and renewed qualification.

## Driver selection

modernc.org/sqlite **v1.59.0** declares Go 1.25.0, x/sys v0.47.0 and libc
**v1.75.7**. Its translated SQLite is **3.53.4**. The repository minimum remains
Go 1.25.5 and libc is pinned exactly as the driver's go.mod recommends.
v1.60.1 was inspected and rejected because it requires Go 1.26.0 and a newer
x/sys. Sources: [pinned driver documentation](https://pkg.go.dev/modernc.org/sqlite@v1.59.0)
and [pinned module declaration](https://gitlab.com/cznic/sqlite/-/blob/v1.59.0/go.mod).

Before adding the root dependency, an independent temporary module ran WAL on
Windows and isolated Linux amd64 and cross-built Linux amd64/arm64 with CGO=0.
The final Foundation adds lock/busy/per-connection pragmas, migrations,
credential encryption, optimistic concurrency, process-crash WAL recovery and
coherent VACUUM INTO/reopen tests. It does not claim production workload capacity.

Alternatives: mattn/go-sqlite3 adds a C compiler/libc cross toolchain; PostgreSQL
adds a service; flat files do not provide this transaction model. Pure Go fits
the existing CGO=0 build matrix, with increased binary and dependency size.

## New requirements and version changes

All entries below are CGO-free on the Foundation dependency path. Licenses were
read from exact downloaded module sources; originals are not copied/edited.

| Module | Version | Purpose | License |
|---|---|---|---|
| modernc.org/sqlite | v1.59.0 | SQLite adapter; direct | BSD-3-Clause; translated SQLite public domain; bundled sqlite-vec MIT |
| modernc.org/libc | v1.75.7 | driver's exact translated libc support | BSD-3-Clause; bundled musl/go-netdb MIT and Go BSD notices |
| modernc.org/mathutil | v1.7.1 | driver/libc numeric support | BSD-3-Clause |
| modernc.org/memory | v1.12.1 | driver/libc allocation support | BSD-3-Clause; retained Go/mmap notices |
| github.com/dustin/go-humanize | v1.0.1 | libc formatting support | MIT |
| github.com/mattn/go-isatty | v0.0.24 | selected terminal support; graph moves from v0.0.23 | MIT |
| github.com/ncruces/go-strftime | v1.0.0 | libc date formatting | MIT |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | mathutil integer arithmetic | BSD-3-Clause |
| golang.org/x/tools | v0.48.0 | libc module graph requirement; moves from v0.47.0 | BSD-3-Clause |
| golang.org/x/mod | v0.38.0 | selected tools module dependency; moves from v0.37.0 | BSD-3-Clause |

gopkg.in/yaml.v3 v3.0.1 was already selected and is promoted from indirect to
direct for strict bootstrap decoding (MIT/Apache-2.0 dual licensing). Existing
google/uuid and x/sys selections stay unchanged. Full modernc generator/test
modules appear in the module graph but are not automatically binary imports;
the actual command dependency path is checked with go list -deps.

## Platform and distribution limits

Windows amd64 and Linux amd64 build/run; Linux arm64 compiles without a C cross
compiler. Linux CGO=0 artifacts are checked for absence of a dynamic interpreter.
Race tests use CGO=1 plus the Go image's compiler; this does not change production
CGO requirements. Windows race is unavailable with the current CGO=0 host setup.
Artifact sizes and hashes are recorded in the [Phase 1 report](../reports/PHASE_1_FOUNDATION_REPORT.md).

No dependency is introduced into upstream runtime code. Root module graph changes
can affect inherited builds, so both upstream binary and regression gates are
rerun. GPL-3.0-or-later and upstream naming/attribution remain unchanged; a future
distributed artifact must bundle applicable dependency notices. This phase
publishes no binary/release and makes no licensing clearance claim for future
protocol or external engine implementations.
