# Splicore Core Scope

- Documentation status: Canonical
- Audience: Maintainers and operators
- Last reviewed: 2026-10-09
- Owner: Core maintainers
- Responsibility: Authoritative product and production dependency boundary.
- Lifecycle: Update only with reviewed Core scope changes.

Splicore is an independent proxy core, usable as server and client Core.

## Core

Protocols: SS, SS2022, Snell, HY2, TUIC, VLESS, Mieru, Trojan, VMess,
SOCKS5, HTTP and Mixed ingress; DIRECT and REJECT routing actions.
Shared transports: Raw, WebSocket, HTTPUpgrade, gRPC, TLS and the supported
REALITY integration. Native TUN, routing, DNS, policy, configuration, runtime,
API/CLI, accounts, credentials, bindings, nodes, providers, SQLite, backup/restore,
stats, doctor, support bundles and Core distribution/lifecycle are Core.

## Not Core

System Proxy desktop control, WinINET, WinHTTP proxy management, Desktop PAC
ownership, GUI, tray and desktop UX are outside this product. There are no
configuration, API, CLI or normal runtime writers for these features.
Splicore Client Core is a reusable proxy runtime. Android/Apple/Desktop application
shells are upper-layer products and are not part of this repository.
External Xray, sing-box and Mihomo processes are interoperability test peers only.
Vision remains unsupported; FinalMask/Sudoku are not Splicore runtime capabilities.

## Rule

OS-specific code is allowed only when required for Core networking/runtime.
Windows TUN is Core. Windows System Proxy is not Core.

## Container Packaging

Docker / Docker Compose / container-image publication are not part of the
Splicore Core repository product surface. Docker may be used externally for
development/testing only; local validation definitions belong outside this repository.
Docker builds are not a Phase Freeze gate, Docker images are not Splicore release
artifacts, and Docker runtime is not a platform qualification target. Native Core
binary builds are the repository distribution check unless product scope is
explicitly changed in the future.

## Historical storage

Frozen migrations 0001–0008 are byte-identical. Migration 0007 and its
client_host_profiles table are HISTORICAL / DEPRECATED / INERT. TUN configuration
already lives in local_inbounds; no extraction migration is necessary. Core never
reads or writes the old desired-state table. Physical backups retain it, while
current config exports omit it. Old config fields receive typed invalid errors.

Private recovery logs may retain restored desktop steps as opaque history.
The decoder cannot create or activate them; incomplete legacy debt returns a typed
unsupported diagnostic and preserves the journal without OS writes. Core route,
interface and Wintun recovery keep scope/generation/conflict and shutdown guards.

## Validation boundary

Phase 21 cleanup requires targeted independent review before Freeze. Historical
platform qualification remains PARTIALLY PASSED; Phase 21 is NOT PLATFORM QUALIFIED.
Linux arm64 is BUILD ONLY. Frozen reports and ADR rationale remain historical truth.
