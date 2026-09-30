# Upstream baseline and validation ledger

- Documentation status: Historical
- Audience: Maintainers and validation reviewers
- Last reviewed: 2026-10-01
- Owner: Upstream maintainers
- Responsibility: Phase 0 baseline commands, toolchains and observed scoped results.
- Lifecycle: Frozen snapshot; only typo, broken-link or factual corrections.

Reviewed 2026-10-01 (Asia/Shanghai). Runtime source unchanged throughout Phase 0.

| Item | Value |
|---|---|
| Splicore upstream | SagerNet/sing-box |
| Baseline tag | v1.14.1 (published stable; not draft/prerelease) |
| Full commit | `1ac1a339cb1223e9c70eae14c44411c75033c02d` |
| Author date | 2026-09-14 23:29:15 +08:00 |
| Commit date | 2026-09-15 01:21:37 +08:00 |
| Release published | 2026-09-15 00:06:50 UTC |
| Go module | `github.com/sagernet/sing-box`, module go directive **1.25.5**, no toolchain directive |
| Test CI | Go ~1.25 / ~1.26; Windows/macOS/Linux |
| Release build CI | standard toolchain 1.26.8; platform/special toolchains differ |
| Observed Windows toolchain | go1.26.2 windows/amd64, CGO_ENABLED=0 |
| Observed isolated Linux toolchain | go1.26.6 linux/amd64, CGO_ENABLED=0, root |
| Upstream remote | `https://github.com/SagerNet/sing-box.git`, sole remote `upstream` |
| Ancestry | full clone, shallow=false; 2,723 ancestors including HEAD; contained in fetched upstream/stable and upstream/testing |
| License | GPL-3.0-or-later plus upstream naming/association wording; preserved |
| Main / work branch | main and codex/phase-0-architecture both at baseline SHA |

## Commands chosen from actual upstream files

Makefile `ci_build` builds minimal and default-tag variants. `.github/workflows/test.yml`
uses DEFAULT_BUILD_TAGS_OTHERS and release/LDFLAGS; Unix uses root (`-exec sudo`).
Windows packaging uses DEFAULT_BUILD_TAGS_WINDOWS (includes naive/purego). We
translated these invocations into PowerShell, preserved flags, used pinned local
toolchains (`GOTOOLCHAIN=local`) and wrote binaries outside the repository.
Did not execute Makefile's mutable `read_tag@latest` version helper or release targets.
Build version for the Windows official-tag artifact was explicitly `1.14.1`.

```powershell
$tags = (Get-Content release/DEFAULT_BUILD_TAGS_OTHERS -Raw).Trim()
$winTags = (Get-Content release/DEFAULT_BUILD_TAGS_WINDOWS -Raw).Trim()
$ldflags = (Get-Content release/LDFLAGS -Raw).Trim()
$env:GOTOOLCHAIN = 'local'
go version
go env -json
go build -trimpath -ldflags $ldflags -o <temporary-minimal.exe> ./cmd/sing-box
go build -trimpath -tags $tags -ldflags $ldflags -o <temporary-ci.exe> ./cmd/sing-box
go build -trimpath -tags $winTags -ldflags "-X github.com/sagernet/sing-box/constant.Version=1.14.1 $ldflags -s -w -buildid=" -o <temporary-windows.exe> ./cmd/sing-box
go test -count=1 -v -tags $tags -ldflags $ldflags ./...
go vet -tags $tags ./...
golangci-lint run --timeout=10m
golangci-lint fmt --diff
```

The three relevant tag lists and shared linker flags remain exactly upstream.
`release/LDFLAGS` includes runtime godebug defaults and `-checklinkname=0`.
`badlinkname`/`tfogo_checklinkname0` signal the required linkage behavior.
`with_v2ray_api` is not in default test tags; default tags include QUIC/uTLS and
the ancillary features specified in the baseline files. Build docs still list
older version requirements; module/workflow evidence takes precedence.

## UPSTREAM_BASELINE_BUILD / UPSTREAM_BASELINE_TEST

| Gate | Initial result / scope |
|---|---|
| Windows minimal / CI tags / Windows official tags build | PASS, all exit 0 |
| Windows complete root CI tests | FAIL, exit 1; tlsspoof/windivert integrations |
| Windows supplementary ordinary tests | PASS with `-skip '^TestIntegration'`; not a complete CI pass |
| Linux CI tags build | PASS, exit 0 |
| Linux complete root CI tests, restricted container | FAIL: namespace permission and missing tcpdump |
| Linux complete root CI tests, suitable isolated environment | PASS, exit 0, no test-name exclusions |
| Additional Windows go vet | FAIL, three upstream unsafe.Pointer diagnostics |
| Upstream Windows lint configuration | PASS, 0 issues; golangci-lint v2.14.0 (built Go1.27.0) |
| Read-only format check | PASS, no diff; golangci-lint fmt --diff |

**Build passes; Linux complete root CI tests pass; Windows complete root CI tests
do not pass in this host environment. Do not report an unqualified global TEST PASS.**

Linux image identity: `golang:1.26.6`, digest
`sha256:0d1d3a794be25f809dd2cb3160d8c73276c4056a9f8242a138e908ddeee7b6b6`.
Source bind mount was read-only. NET_ADMIN/NET_RAW alone were insufficient for
namespace test; the successful isolated retry added SYS_ADMIN and
`seccomp=unconfined`, and installed tcpdump 4.99.5-2 inside the disposable container.
No host networking, Docker socket or production service was attached. Test/build
caches live in dedicated Docker volumes; test binaries live in temporary storage.

## Failures and unexecuted scopes

* Windows logs show `WinDivert64.sys.tmp → WinDivert64.sys` cross-disk rename
  failure and `open SCM: Access is denied`. These are observed host/driver
  integration failures; the exact cross-disk root cause is not established.
  No privilege escalation or upstream patch was performed.
* `go vet`: `daemon/managed_service.go:75`, `experimental/libbox/debug.go:10`,
  `experimental/boxdd/authenticode_windows.go:95`, possible unsafe.Pointer misuse.
  The first two are deliberate debug crash paths; the third requires separate
  upstream review. Vet is supplementary, not an enabled upstream lint check.
* Separate `test/go.mod` Docker/reference interoperability suite is NOT RUN;
  root CI does not traverse it. Makefile test would tidy that module; no tracked
  module files were modified to simulate its execution.
* macOS/Android/iOS builds, full lint OS/arch matrix, with_v2ray_api optional-tag
  tests and race builds are NOT RUN here. Their toolchain/platform gates remain explicit.
* Splicore third-party interop is planned, not executed in Phase 0.

## Post-document verification

Final repeated results and the document-inclusive diff check are recorded in
[the Phase 0 report](../PHASE_0_ARCHITECTURE_REPORT.md) and
[evidence](evidence/README.md). Source equality with HEAD proves no upstream runtime,
module or workflow edits. Repeated environment failures remain failures.

Future sync: [stable release procedure](UPSTREAM_SYNC.md). Preserve full SHA,
release identity, flags/toolchains, source modifications and scoped results at
each baseline change. Reference: [official release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.1).
