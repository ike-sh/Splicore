# Phase 6 Xray engine workflow

- Documentation status: Canonical
- Audience: Maintainers, reviewers and future distributors
- Last reviewed: 2026-10-02
- Owner: Engine maintainers
- Responsibility: Fixed reference, bootstrap settings and Phase 6 acceptance gates.
- Lifecycle: Update when artifact qualification or adapter contracts change.

## Baseline and reference

Phase 5 freeze: `afacb248440aedb6ac5a2f0d14ad7defedddb627`.
Phase 6 branch: `codex/phase-6-xray-engine-duality`; Phase 6 is locally frozen in
the commit containing the [acceptance report](../reports/PHASE_6_XRAY_ENGINE_DUALITY_REPORT.md).
Its sole parent is Phase 5 and its message is
`feat(engine): add Xray compatibility engine duality`.
sing-box baseline remains v1.14.1. All supported protocols/engines are Experimental.

Windows abnormal Xray child-exit/parent-crash qualification remains
**DEFERRED PLATFORM QUALIFICATION** because the Start-to-Job-Object-assignment
interval is unqualified. Windows build/unit/integration PASS does not qualify that
lifecycle. Xray arm64 runtime remains **NOT CERTIFIED**; Splicore arm64 compile PASS
does not qualify the external artifact.

Reference: [official v26.3.27](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27),
binary version 26.3.27, release build d2758a0 / Go 1.26.1. The inspected newer
releases were prereleases; this reference selects an explicit stable release.
No latest URL or automatic version following is used.

| Platform | Official archive SHA256 | Extracted binary SHA256 |
|---|---|---|
| Linux amd64 | `23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae` | `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` |
| Windows amd64 | `d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad` | `15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1` |
| Linux arm64, provided but not runtime-qualified | `4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c` | Not downloaded; adapter rejects an unqualified node artifact |

Archives come only from versioned official release assets. The test downloader
checks the official release API asset digest before extraction. No binary is stored
in Git. Only xray, LICENSE and README were extracted; optional geo databases and
Windows wintun/scripts are unused. [Licensing](../architecture/LICENSE_BOUNDARIES.md).

## Bootstrap and selection

Optional Schema 1 bootstrap fields:

```yaml
xray:
  binary_path: /opt/splicore/engines/xray-v26.3.27
  runtime_directory: /run/splicore/engines/xray
```

An omitted runtime_directory defaults to `<state_directory>/engines/xray`.
Use a dedicated directory owned by the daemon; Linux permissions must be 0700.
Paths must be clean and absolute. Symlinked binaries/runtime roots are rejected.
Core verifies exact platform binary SHA256 and version before execution. Core
does not download. Missing Xray is reported as unavailable and native-only startup
continues. Recovery of a committed Xray inbound requires the artifact and fails
clearly if unavailable. Operator input is a trusted deployment boundary.

Canonical creation selects `engine: native` or `engine: xray` with `protocol: vless`.
Offline CLI `inbound validate` checks domain and placement; daemon validate/plan/apply
also check node availability. Illegal pairs reject with UnsupportedEngineForProtocol;
there is no fallback. Both engines reject Vision. Public settings contain no Xray JSON.

Status/capabilities/doctor expose reference/installed version, last availability
result and safe runtime identity/health. PID/config paths are diagnostics, never
commands or authoritative state. Stats are unsupported for the Xray adapter and
zero counters must not be read as measured usage.

Strict quota/upload/download policy requests for VLESS/Xray reject with
UnsupportedPolicyForEngine / unsupported_policy_for_engine (HTTP 422) before
availability, pending state or child construction. Malformed policy fields remain
invalid. Explicit metadata_only records are preserved without enforcement claims.

After an abrupt daemon exit, review the stale control socket and confirm that no
listener remains before removing that exact owned path. Startup deliberately
refuses an existing socket. Xray generation artifacts are cleaned automatically
under the exclusive runtime-root lease and regenerated from SQLite on recovery.

## Gates

Use Ubuntu-24.04 WSL2 ext4 runtime directories and a loopback-only network/mount
namespace with a synthetic hosts file. Docker/Redis/TeleLedger and real NoBrand
remain untouched. Run fixed Mihomo 1.19.30 and sing-box 1.14.1 clients with verified
hashes against both placements; plain/TLS/REALITY, Alice/Bob, REALITY IPv4/IPv6/domain,
TCP/XUDP, negative UUID/key/short-ID/SNI, reconcile and SQLite recovery.

```sh
go test -tags with_quic,with_utls ./internal/splicore/...
go test -race -tags with_quic,with_utls ./internal/splicore/...
go test -race -count=10 -run TestSupervisor ./internal/splicore/engine/xray
SPLICORE_XRAY_BINARY=/absolute/verified/xray go test \
  -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/application
```

The explicit integration tag requires the pinned binary and fails when absent;
unit/process fixtures require no downloaded executable. Fuzz path and renderer
boundaries; do not fuzz Xray crypto. Validate native VLESS and Snell/HY2/TUIC
regressions, shared race tests, Windows build/manager tests, arm64 compilation,
OpenAPI/live API/docs/links, secret scan and unchanged upstream/dependencies.
Default race/checkptr stays enabled. Keep failures as evidence; never retry payloads
to qualify a failing cell. The authorized freeze repaired main to Phase 5 without
changing worktree/index bytes, committed the approved Phase 6 paths once and
fast-forwarded main. Push/tag/release NONE. Phase 7 implementation is not started.

Actual outcomes, full matrix, retained failures and platform limits:
[Phase 6 acceptance report](../reports/PHASE_6_XRAY_ENGINE_DUALITY_REPORT.md).
