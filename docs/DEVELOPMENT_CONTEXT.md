# Development context

Documentation status: Current architecture correction
Audience: Maintainers and operators
Last reviewed: 2026-10-04
Owner: Splicore maintainer
Responsibility: Independent native Server + Client Core boundary
Lifecycle: Experimental; Phase 14 local freeze

## Current maintainer decision

Splicore is an independent Server + Client Core. Registry: native only. Xray is
outside Splicore runtime/distribution; FinalMask/Sudoku are out of scope. Future
NoBrand chooses an independent runtime and owns its artifact/lifecycle. Native
VLESS plain/TLS/REALITY flow-none remains Experimental; Vision is Deferred/Unsupported.
[ADR 0035](adr/0035-xray-runtime-removed-from-core.md) supersedes Phase 6/7 direction.

## Source and Git boundary

Workspace: `D:\code\Splicore`. Branch: `codex/phase-14-client-management-providers`.
Phase 13 base/main: `b0de8c16e1c810cb851c400b5d03987924d5eff8`, sole parent
`d09f5f10797aa63798419fa77ffd676257f1b609`. The maintainer authorized one forward
Phase 14 freeze commit with exactly this Phase 13 base as its sole parent.
The [freeze report](reports/PHASE_14_FREEZE_REPORT.md) records the accepted scope
and gates; its identity is the commit containing that report. Main stays at
Phase 13. No push, tag, release, history rewrite or Phase 15 work is authorized.
Historical Phase 0–13 reports and existing migrations remain unchanged.

Frozen phases progressed through foundation, Snell, HY2, TUIC, native VLESS,
historical Xray/FinalMask, embedded Mieru, distribution, client runtime, outbound
expansion, routing/DNS/policy and TUN/system integration. Their reports describe
past acceptance, not current product support. Phase 14 imports/providers and the
architecture correction are accepted in the local Experimental freeze.

## Retained contracts

- Native server/client: Snell, HY2, TUIC, VLESS and Mieru; DIRECT/REJECT builtins.
- Local SOCKS TCP/UDP, HTTP, TUN and independent server/client lifecycle.
- Selector, URL-Test, Fallback, Load-Balance, RouteRule, DNS and RuleSet.
- Protected native egress, dynamic endpoint DNS, old generations/shared refs,
  reused TUN, Wintun/WinINET and durable host journal ownership.
- Provider imports/RuleSet sources, persistent random UUID identity, encryption,
  bounded revision/single-use previews, atomic Prepare/SQLite/Activate, serialized
  refresh, four-worker scheduler, offline recovery and reference-safe deletion.
- Ordinary ClientProfile exports remain independent of server engine selection.

## Experimental upgrade and import

Generic engine storage remains schema 8; there were no Xray-only tables requiring
a new migration. Startup/migration and installer preflight reject retired Xray or
transport-mask intent, preserving data/history. Disabled retired records are also
rejected. Remove records with the old experimental build before upgrade. Native-only
old databases pass. The installer strips obsolete bootstrap/receipt metadata only
after safe preflight; `serve` rejects the obsolete bootstrap section.

Imports with Xray, FinalMask/Sudoku or engine-specific mask options show Unsupported
and produce no runnable stripped node. Exact outbound Xray pairs return
`UnsupportedEngineForProtocol`. No automatic native conversion exists.

## Validation environment and limitations

Use only existing local Windows/WSL and owned disposable namespaces/service labs.
No third-party traffic probes, external scans, actual Windows routes/DNS/WinINET/
Wintun mutation or real NoBrand repository access. Toolchains: Windows Go1.26.2,
WSL Go1.26.6; offline caches. Default Linux race/checkptr is required. Do not use
GODEBUG/gcflags suppression, sleeps/retry masking or skipped acceptance gates.

Existing qualifications remain: Windows race not executed, native Windows host
networking/native Ubuntu auto-route not certified, Linux arm64 build-only. WSL
nested systemd cleanup may leave failed bookkeeping despite MainPID0/cgroup empty;
record actual process/network cleanup without claiming native-init certification.

Evidence and before/after artifacts:
`D:\splicore-validation\xray-boundary-20261004`. Pre-correction Phase 14 source,
artifacts and reports remain retained. See [correction report](reports/ARCHITECTURE_CORRECTION_XRAY_BOUNDARY_REPORT.md),
[testing](TESTING.md), [client](architecture/CLIENT_RUNTIME.md),
[provider](architecture/PROVIDER_MODEL.md), and [distribution](DISTRIBUTION.md).
