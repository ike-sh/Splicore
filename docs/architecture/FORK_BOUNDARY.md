# Fork and product identity boundary

- Documentation status: Canonical
- Audience: Core developers and upstream reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Namespace, composition, adapters and product command transition strategy.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Recommendation: retain upstream module path for Phase 0; introduce Splicore
packages and its own command in Phase 1. Publish only Splicore identity once a
derivative product exists. Upstream networking packages remain the reference.

| Conflict risk | Extension area | Approach |
|---|---|---|
| Low | new domain/application/ports/storage/export/API packages | depend only on inward contracts; avoid upstream JSON in signatures |
| Low | own composition root | create separate upstream registries, register typed adapters, pass to `box.Context` |
| Low–medium | protocol constructors | wrap typed inbound factories, supplying an authenticated router decorator for policy/usage; retain actual upstream constructors |
| Medium | registration / optional capabilities | explicit Splicore registration tables; avoid editing upstream include lists for every protocol |
| Medium | lifecycle, service, CLI/build/packaging | own orchestration and command; minimal audited hooks only if construction cannot expose needed mechanisms |
| High | option/config schema, Box constructor | translate public domain into private option structs; do not expand upstream JSON into public Account concepts |
| High | users, shared stats and route fast paths | first use stable metadata names and constructor/router wrappers; patch only with demonstrated unsupported hooks |
| High | listener/TLS/REALITY/QUIC/DNS/route rewrites | preserve foundation; protocol-specific fixes narrowly scoped and differential-tested |

Router decorators can intercept authenticated `RouteConnectionEx` and packet
calls to enforce admission and wrap payload streams. `ConnectionTracker` itself
cannot reject with an error and is too late for all admission cases. Constructing
own registries permits wrappers without modifying all protocols. All decorator
methods must preserve upstream Router behavior, including PreMatch/flow paths;
Phase 1 must test bypass paths before claiming coverage. A public extension hook
proposal to upstream is preferable to recurring invasive local changes.

## Module path alternatives

* **A: rename now**. Independent import identity immediately, but changes at least
  667 Go files / 1,905 imports and module-relative tooling; high merge churn before design.
* **B: preserve Phase 0, migrate Phase 1 wholesale**. Clean current evidence but
  simply postpones the same churn. Only justified if publishing a Go library soon.
* **C: gradual namespace (recommended)**. Preserve root foundation path while
  placing product logic in `internal/splicore`; publish a distinct binary. Once a
  real repository identity and public library scope are fixed, reassess a separate
  Splicore module with a pinned local foundation/replacement or deliberate path
  migration. Do not accidentally import remote upstream for local fork code.

Root module remains upstream in Phase 0. Product version/build identity is
independent of Go import identity; do not release a fork as an official upstream
module version. Keep replacement and nested test module semantics in sync when
eventually migrating. No guessed GitHub owner or new remote is created.

## Binary/service transition

Phase 0: leave `cmd/sing-box`, Makefile/release/completions/service files intact;
build upstream only into temporary evidence directories. Phase 1: add
`cmd/splicore` with an independent Cobra root, version identity, domain commands
and local API client. Add own build/packaging/service assets and completions;
use `/etc/splicore/splicore.yaml`, `/var/lib/splicore/state.db`,
`/run/splicore/splicore.sock`, `splicore.service`. Phase 2: qualify own packaging
and remove upstream-named artifacts from **Splicore release selection**, preserving
source files useful for merging/testing. Never mass-replace branding in network code.

Relevant actual baseline assets: `cmd/sing-box/cmd.go`, Makefile `NAME/MAIN`,
`.github/workflows/build.yml`, `.fpm_*`, `release/config`, `release/local`,
`release/completions`, `cmd/internal/build_shared/tag.go`.
