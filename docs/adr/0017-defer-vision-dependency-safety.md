# ADR 0017 — Defer Vision due to upstream dependency concurrency defects

- Documentation status: Canonical
- Audience: Maintainers and protocol/engine reviewers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Define the Vision deferral, enforcement boundaries and re-enable gates.
- Lifecycle: Update only through an explicit dependency evaluation and reviewed acceptance evidence.

## Status

Accepted for the Phase 5 candidate by the current product decision. Phase 5 is not frozen.

## Context

The initial Phase 5 implementation accepted flow-none and Vision with VLESS/static
TLS/REALITY. Production Vision traffic passed functional checks, then the pinned
sing-vmess v0.2.8 implementation failed default checkptr and actual Read/Write race
gates. This is an upstream dependency defect. No evidence attributes the race to
Splicore wrappers, counters, buffer pooling, concurrent Close or transaction ownership.

## Evidence

NewVisionConn converts TLS pointers through uintptr and default race builds fail
checkptr at its private-buffer field lookup. VisionConn.Read and Write both access
shared mutable TLS filtering state, including numberOfPacketToFilter and isTLS;
writeAccess protects only Write. The independent memory-only reproducer failed
10/10 under default checkptr and 10/10 with real races in the diagnostic build.
The latter disabled checkptr only for diagnosis and is not acceptance evidence.

Original outcomes remain in the [initial report](../reports/PHASE_5_VLESS_REALITY_NATIVE_VERTICAL_SLICE_REPORT.md).
The external sanitized triage report and reproducer remain at
`D:\splicore-validation\go-race-triage-20261002`. Full stacks are excluded from
canonical operator documentation. [Final acceptance](../reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md)
records the supported surface separately.

## Decision

Vision is **DEFERRED / UNSUPPORTED**. Canonical settings accept only `flow=none`.
Vision inputs return a typed unsupported operation error, and exporters return
UnsupportedExport. Config/import/API/CLI, protocol validation, runtime construction,
ClientProfile and all exporters reject it. They never remove the requested flow,
warn-and-continue or downgrade to ordinary VLESS. A runtime hard gate precedes TLS
material access and construction; managed service users always register empty wire
flow. A client's Vision request fails the existing flow mismatch check before
VisionConn construction. Capability Vision is false; supported flows contain only none.
No experimental compatibility migration is added for unfrozen Vision state.

## Why not patch the dependency now

The sing-box v1.14.1 baseline and sing-vmess v0.2.8 pin remain unchanged. No source
patch, vendoring, replace/fork, dependency upgrade, monkey patch or sanitizer disable
is authorized for this phase. A dependency patch/upgrade is a separate evaluation.
The Splicore shared concurrency model is not changed to hide the dependency defect.

## Why REALITY remains supported

REALITY and Vision are separate options. Flow-none REALITY uses the existing TLS
handshake and VLESS/XUDP paths without VisionConn. Its default checkptr/race traffic,
fixed-version client interoperability and secret gates must pass independently.
Server private key remains server-only; client projection carries UUID, public key,
short ID, server name and display endpoint, never the server target or listener.

## Re-enable criteria

First require an upstream fixed release or explicit maintainer approval for a
reviewed dependency patch. Then require default checkptr PASS, race PASS, the
original reproducer 10/10 PASS, Mihomo and sing-box interoperability PASS, prior
protocol regressions PASS and secret gates PASS. Re-enable requires a reviewed
product decision; publishing a newer dependency does not enable Vision automatically.
An upstream baseline sync remains a separate task.

## Consequences

VLESS and REALITY remain Experimental. Vision-dependent configurations and exports
are rejected before authoritative commit or runtime construction. Future flow
extensions remain protocol-owned; Protocol=vless and Engine=native/xray stay
independent. Xray remains an unavailable structural placeholder. The historical
implementation and failed evidence are preserved; no Stable, tag or release is made.
