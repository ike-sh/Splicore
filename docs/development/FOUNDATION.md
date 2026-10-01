# Foundation development workflow

- Documentation status: Canonical
- Audience: Contributors and Foundation reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Current build/test commands, bootstrap and runnable Foundation scope.
- Lifecycle: Update with Foundation process interfaces and gates.

## Current Phase 2 implementation

This document preserves Foundation contracts/workflow. Current daemon also implements Phase 2 Snell with DatabaseSchema 2; see [current workflow](PHASE_2_SNELL.md). Foundation composition remains for independent placeholder tests.

## Build and test

Keep binaries and logs outside the repository. The module remains
`github.com/sagernet/sing-box`; both independent commands can be built.

```powershell
./scripts/splicore-build.ps1 -Output "$env:TEMP/splicore.exe"
./scripts/splicore-test.ps1 -count=1
```

```sh
CGO_ENABLED=0 go build -trimpath -o /tmp/splicore ./cmd/splicore
sh scripts/splicore-test.sh -count=1
CGO_ENABLED=1 go test -race ./internal/splicore/... ./cmd/splicore
```

Plain go build uses Go VCS commit/dirty metadata and unknown build time.
The PowerShell build entrypoint injects product version, full SHA, dirty and UTC
time with linker flags. It never rewrites source. For reproducible builds supply
the same `-BuildTime`, toolchain, source and output-independent flags.
Build retained sing-box using its own tags and release/LDFLAGS as documented in
the [baseline ledger](../architecture/UPSTREAM_BASELINE.md).

## Bootstrap Config Schema 1

The only live file schema is strict process bootstrap YAML (JSON is also valid).
Absolute state/control paths are required. Domain imports and protocol runtime
settings are unsupported; duplicate/unknown fields, aliases, extra documents,
excess depth and oversized input fail validation.

```yaml
schema: 1
state_directory: /var/lib/splicore
api:
  unix_socket: /run/splicore/splicore.sock
```

This is a Linux target example, not an installed host service. For local tests
use private directories below a temporary filesystem. The command creates
configured directories only when explicitly started with `run --config`.

## Commands

| Command | Foundation behavior |
|---|---|
| `splicore version` | independent identity; no daemon needed |
| `splicore status --config bootstrap.yaml` | canonical System JSON; absent daemon prints not running |
| `splicore capabilities --config bootstrap.yaml` | effective placeholder capabilities from application/API |
| `splicore doctor --config bootstrap.yaml` | version/platform/path existence and daemon Foundation checks; no runtime probes or repair |
| `splicore validate bootstrap.yaml` | only strict bootstrap schema validation |
| `splicore run --config bootstrap.yaml` | local read daemon, SQLite authority and protected Linux UDS |

Windows supports builds/unit tests, including HTTP semantics and CLI through
httptest. The command has no Windows production server or public TCP fallback.
Linux UDS uses 0700 current-owned directory, 0660 socket and captured peer
credentials; existing socket paths need operator review, never automatic deletion.

## Historical Foundation maturity and recovery

System reports degraded/Foundation-only, or recovery_required for pending
journals. Neither means proxy traffic is implemented. SQLite is authoritative;
bootstrap contains no Accounts/Inbounds. No key provisioning is configured by
the command: credential writes/reveals need an explicitly injected Cipher port.
After a crash, pending identity blocks further domain mutation. Automatic
reconciliation and runtime compensation require a later coordinator stage.

Use the [dependency audit](DEPENDENCIES_PHASE_1.md),
[current report](../reports/PHASE_1_FOUNDATION_REPORT.md),
[API index](../api/README.md) and [test strategy](../testing/TEST_STRATEGY.md).
Phase 1 is frozen locally under the explicit freeze instruction: one Foundation
commit, fast-forward of main and preparation of the Phase 2 branch. The current
Phase 2 request now authorizes Snell implementation. No staging, commit, push,
origin creation, tag or release is authorized for Phase 2.
