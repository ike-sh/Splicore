# Development context

Documentation status: Current architecture correction
Audience: Maintainers and operators
Last reviewed: 2026-10-09
Owner: Splicore maintainer
Responsibility: Independent native Server + Client Core boundary
Lifecycle: Experimental; Phase 21 cleanup awaiting targeted review

## Current maintainer decision

Splicore is an independent Server + Client Core. Registry: native only. Xray is
outside Splicore runtime/distribution; FinalMask/Sudoku are out of scope. Future
NoBrand chooses an independent runtime and owns its artifact/lifecycle. Native
VLESS plain/TLS/REALITY flow-none remains Experimental; Vision is Deferred/Unsupported.
[ADR 0035](adr/0035-xray-runtime-removed-from-core.md) supersedes Phase 6/7 direction.

## Source and Git boundary

Branch: `codex/phase-21-shared-transport`. Frozen Phase20 HEAD is
`1ef9458a2c06aa974e721db2fe4f271bb9068ef6`. Current Phase21 shared transport passed
targeted Re-Review; Deep Core Purge must receive targeted independent review before
Freeze. Work remains unstaged, Index empty. No commit, push, tag, release or Phase22
is included. Historical reports and migrations remain preserved.

[Core scope](architecture/CORE_SCOPE.md) defines the current product boundary.
TUN and Core-owned network recovery remain active. Desktop desired state and OS
Internet Settings mutation are removed; frozen 0007 storage is inert.

## Retained contracts

- Native server/client: SS/SS2022, Snell, HY2, TUIC, VLESS, Mieru, Trojan, VMess, SOCKS5 and HTTP; DIRECT/REJECT builtins.
- Local SOCKS5 TCP/UDP, HTTP, Mixed, TUN and independent server/client lifecycle.
- Selector, URL-Test, Fallback, Load-Balance, RouteRule, DNS and RuleSet.
- Protected native egress, dynamic endpoint DNS, old generations/shared refs,
  reused TUN, Wintun and durable host journal ownership.
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
