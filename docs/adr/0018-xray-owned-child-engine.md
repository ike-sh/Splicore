# ADR 0018: Owned Xray compatibility engine

- Documentation status: Canonical
- Audience: Engine, application and security maintainers
- Last reviewed: 2026-10-02
- Owner: Engine maintainers
- Responsibility: Phase 6 external process, admission and artifact boundary.
- Lifecycle: Preserve rationale; supersede with a numbered decision.

## Status

Accepted for the Experimental Phase 6 local freeze.

## Decision

Fill the existing EngineID `xray` placement with an adapter for the exact official
Xray `v26.3.27` binary. ProtocolID remains `vless`. Phase5 composition remains a
historical fixture; Phase6 composition shares its protocols/native compilers/exporters.
Account, Binding, UUID Credential, server-secret vault, Endpoint and ClientProfile
retain their existing models. Xray is neither a Go dependency nor SQLite authority.
See [reference and operations](../development/PHASE_6_XRAY.md).

The child runs one private VLESS inbound and direct outbound. Splicore owns the
public TCP listener, closes precommit connections, and activates byte forwarding
after commit. The relay parses no protocol or crypto. Xray receives loopback peer
addresses; original source-IP policy is not supported. The private loopback socket
belongs to the trusted local runtime boundary. No public raw Xray JSON is accepted.

Compile snapshots mutable intent and TLS files into handle-owned configuration
bytes. Start creates a random generation directory under an exclusively leased
runtime root, writes protected configuration, clears owned byte buffers, validates
the configuration with the pinned child and starts the owned process. Health checks
both process state and ownership of the expected listening socket. Integration
acceptance additionally requires actual authenticated client payloads.

Linux uses a process group and parent-death SIGKILL; termination targets only the
retained process handle. Windows uses a kill-on-close Job Object. The Windows
development launcher assigns the child immediately after start; sudden parent
termination in that short interval is not production-qualified. Normal stop and
manager ownership tests are required on both platforms; Linux is the runtime gate.

The Wait owner reaps the child, closes/join sockets and workers, records safe exit
status, and deletes its generation. An exclusive kernel lease permits stale
generation cleanup on recovery without trusting or killing PIDs from disk. SQLite
regenerates artifacts after deletion. Automatic restart is not implemented;
unexpected exit marks the runtime failed/degraded until explicit recovery.

Abrupt daemon termination also leaves the existing control socket file. Its
transport requires operator review and removal after confirming the listener is
dead. Xray recovery does not bypass that control-socket safeguard. The isolated
acceptance harness reviews and removes only its own stale socket before restart.

## Capabilities and limits

Capabilities intersect protocol and engine support. Build availability and the
last artifact validation result are separate. Optional missing binaries do not
block a native-only daemon. A committed Xray placement requires that exact engine
on recovery and fails startup with an unavailable result if missing; no fallback.

Xray static user changes restart only the affected child and interrupt its users.
HotUserUpdate and HotReload are false. Attributed/per-user/persistent stats are
deferred; relay wire bytes are not presented as authenticated payload usage.
Strict quota/speed/session policies remain unsupported and fail closed. Explicit
metadata-only policy records are not enforcement claims.

The existing canonical REALITY build gate `with_utls` remains for both placements.
Vision stays DEFERRED / UNSUPPORTED under [ADR 0017](0017-defer-vision-dependency-safety.md).
FinalMask, Sudoku and other Xray-exclusive features are not rendered or enabled.

## Security and distribution

Linux runtime directories/config use 0700/0600; Windows generation directories
use protected user/SYSTEM DACLs. Config artifacts contain UUID/private-key material
and remain outside the repository and ordinary API. Argv has only paths; environment
is allowlisted. Raw child output is streamed to a discard sink, with a bounded
counter; version output capture is capped at 4096 bytes. Errors are fixed safe
messages, never child output. Runtime status exposes identity and paths, not content.

No Xray source, protocol framing or cryptography is copied/modified. An operator
provides an absolute pinned binary path; Core performs no download. Future packaging
must follow [license boundaries](../architecture/LICENSE_BOUNDARIES.md), including
MPL covered-source and notice obligations. No separate `xray.service` is created.
