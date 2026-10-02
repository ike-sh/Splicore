# ADR 0019: Xray specialized feature source and secret boundary

- Documentation status: Canonical
- Audience: Engine, API, exporter and security maintainers
- Last reviewed: 2026-10-02
- Owner: Engine maintainers
- Responsibility: Phase 7 FinalMask/Sudoku provenance, scope and shared secret ownership.
- Lifecycle: Preserve rationale; supersede with a numbered decision.

## Status

Accepted for the Experimental Phase 7 local freeze. No Stable designation.

## Source decision

Official XTLS/Xray-core v26.3.27, commit
`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`, contains FinalMask and Sudoku.
The read-only audit verified the mask registry, TCP config, Sudoku constructor,
password handling and license against the pinned source manifest. The existing
Phase 6 Linux/Windows artifacts are sufficient; no fork, dependency, download
or artifact replacement is required. Source files remain external and unchanged.

FinalMask is a framework. Sudoku is its TCP mask in this phase. Upstream config
is `streamSettings.finalmask.tcp`, a single entry with `type: sudoku` and settings
`password`, `ascii`, `paddingMin`, `paddingMax`. Password is a string seed, not
hex-decoded bytes: imported letter case is preserved. The independently audited
NoBrand profile is `prefer_ascii`, padding 0–3. Broader upstream support is outside
the public contract. A raw Xray probe is reference evidence; managed acceptance
requires Splicore validate/plan/apply, exporter and runtime traffic.

## Decision

Keep ProtocolID `vless` and EngineID `xray`. Add typed engine options inside
existing generic VLESS settings JSON; schema remains 4. Expose exactly one Sudoku
TCP mask, plain security and flow none. Other masks/chains, custom parameters,
TLS/REALITY combinations and native placement reject before availability/pending.
Masked UDP/XUDP is NOT QUALIFIED. Vision stays unsupported under
[ADR 0017](0017-defer-vision-dependency-safety.md).

Feature descriptors carry transport/security/flow, UDP qualification and exact
client support. Effective capabilities intersect protocol and engine descriptors.
Node availability uses the Phase 6 exact platform SHA256 and version checks.
Missing, unrecognized or mismatched binaries cannot enable these features.

The password is an inbound-owned, client-needed shared transport secret. It uses
the existing encrypted Password credential kind and vault; each Account retains
its UUID and Binding. Omission generates a password before pending. Import accepts
exactly 32 hex characters. Ordinary settings, APIs, formatting and logs omit it.
There are no feature columns, Account fields or Binding fields.

After account/Binding authorization, a narrow client secret repository selects
only active inbound-owned passwords before decrypting. Server private keys never
cross that port. ClientProfile adds typed transport requirements with a redacted
secret; its core contains no Engine ID. Only explicit authorized export returns
the UUID and shared password.

Reuse the existing VLESS exporter with format `xray`, exact client version 26.3.27,
and content shape `xray-outbound`. Client behavior follows transport requirements,
not server placement. Mihomo, sing-box, Surge and URI reject masked profiles.
No duplicate exporter, supervisor, wire framing or crypto implementation is added.

## Runtime and qualification

Reuse [ADR 0018](0018-xray-owned-child-engine.md) compile snapshots, protected
ephemeral config, admission after commit, child health, compensation and SQLite
regeneration. Stats remain unsupported, reconcile restarts the affected child,
and abnormal child exit requires explicit recovery. Linux amd64 is the runtime
acceptance environment. Windows sudden child/parent termination qualification
and Xray arm64 runtime certification remain deferred.

## Alternatives

Independent protocol IDs, arbitrary Xray JSON, plaintext option passwords,
engine-specific exporter copies and separate supervisors would duplicate domain
authority or bypass authorization. A fork would introduce an unnecessary source
and supply-chain boundary. Broader mask combinations require independent review,
client evidence and tests before expanding this contract.

See [Phase 7 workflow](../development/PHASE_7_XRAY_EXTENSIONS.md) and
[client compatibility](../architecture/CLIENT_COMPATIBILITY.md).
