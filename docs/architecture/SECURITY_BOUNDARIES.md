# Security boundaries

- Documentation status: Canonical
- Audience: All developers and security reviewers
- Last reviewed: 2026-10-02
- Owner: Security maintainers
- Responsibility: Secret handling, transport authorization, imports, files and executable trust.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Phase 1 implements typed redaction, injected AES-256-GCM credential encryption,
Linux directory/socket ownership and peer identity, plus installation locks.
The table includes future deployment requirements beyond this foundation.

Phase 3 encrypts account-owned protocol passwords with the existing AEAD/AAD
boundary. Supplied passwords reject whitespace/control characters; generated
passwords use 32 random bytes. GET/doctor/journal/error output remains redacted;
explicit Binding-scoped client export may reveal a password, never a TLS key.
Static leaf/key files are bounded/regular, reject symlinks, check Linux private
mode/owner, validate pair/chain/validity/SNI and snapshot into runtime TLS.
One explicit CA and a non-CA leaf are required. Client verification stays enabled;
Mihomo pins the non-leaf CA so its verifier still checks SNI and validity. Private
keys stay outside SQLite and exports. Tests create/clean ephemeral synthetic material.
See [HY2 security contract](../protocol/HYSTERIA2.md).

| Boundary | Required behavior |
|---|---|
| Secrets at rest | encrypted credential payloads via reviewed AEAD/envelope scheme and standard library; external protected master key with key ID/rotation; DB backup alone must not decrypt credentials |
| Passwords vs client secrets | API/operator passwords use reviewed password verification; protocol credentials needed for runtime/export may require recoverable encryption, not irreversible hashes alone |
| Unix socket | `/run/splicore` protected directory, socket 0660 for explicitly permitted operators, owner/mode checked, peer credential identity captured; membership grants control authority, not merely transport access |
| Future API/TLS | separate control principal authentication, request authorization, bounded requests/timeouts, anti-replay/idempotency; no public default bind; browser origins/CSRF protections when relevant |
| Subscription | random independent token/verifier and public listener; can read scoped client material, cannot manage resources; TLS, token/log/path redaction and rate controls |
| Credentials | decrypt only on scoped runtime/export path; do not put secret in Account/metadata/errors/argv/environment; no promise of perfect Go heap zeroization |
| Logs/audit/bundles | structured allowlisted fields and typed secret redaction; unknown protocol settings redacted wholesale; no raw runtime JSON or credentials in errors |
| Child processes | pinned trusted absolute executable, no shell, allowlisted environment, 0600 private rendered config, limited identity/cgroup/process ownership; no arbitrary user-supplied executable paths through API |
| Imports | reject unknown schema/fields/IDs, illegal ownership/references, oversized/deep payloads, duplicate keys, unsupported policies and dangerous listeners |
| Paths/files | normalize and resolve allowed roots, protect symlink/TOCTOU boundaries, exclusive create and permission checks; archive entries reject absolute/`..` paths and symlinks |
| DB/key permissions | 0700 state directory, 0600 DB/WAL/backups/keys and equivalent ACLs; refuse writable startup on unsafe key ownership; no auto-delete of failed DB |

Keys use existing mature cryptographic constructions; choose exact storage backend
and key provisioning before enabling production credential writes. Exportable UUIDs,
PSKs/passwords and shared Snell server PSK remain secret even if not visually
password-like. Public REALITY keys are distinguished from private keys in types.

Foundation key material is explicitly injected through a Cipher port, never
stored in SQLite. AES-GCM binds ciphertext to credential ID, owner, kind and
schema; nonce randomness, tamper and owner substitution have tests. The command
does not provision keys and cannot persist/reveal credentials without one.
Deployment key recovery/rotation remains deferred. Windows has process locking
and reparse-point rejection for development, but production DACL provisioning
is not implemented; production control transport is Linux only.
Linux state/control directories require current ownership and mode 0700;
DB/WAL/SHM/lock files require no group/other access. The socket is 0660 inside
the private directory; only the owner and privileged root are admitted, with
SO_PEERCRED captured. Group operator access requires a later reviewed directory
permission/identity policy. Existing socket paths are never auto-replaced.

Redaction is data-type driven before serialization, with adversarial fixtures for
URIs/YAML/protobuf-shaped payloads, query tokens, exceptions and child output.
Crash dumps can contain secrets despite log redaction: exclude raw dumps from
default support bundles and require explicit privileged handling. No automatic upload.

Security failures fail closed where authorization/accounting is uncertain.
The native data plane's upstream compatibility APIs must not expose mutation paths
that bypass the application/revision coordinator. Existing route/security policy
is preserved; import exposes curated stable controls rather than an arbitrary
upstream JSON escape hatch.

## TUIC and shared support

UUID/password are both secret values in typed encrypted Credential. No default
metadata/doctor/journal/error/log reveal; scoped export returns the pair. Shared TLS
loader/password rules retain Linux owner/mode, trust/SNI/snapshot protection. Wrong
UUID/password combinations fail before routing. No qualified v4/token/0-RTT/insecure.

## REALITY key and export boundary

REALITY private key is an inbound-owned typed X25519 server secret in the existing
encrypted Credential vault. Standard-library X25519 generates/derives keys; no new
cryptographic scheme. Public settings carry public key, short IDs, SNI and target;
write-only server_secret carries optional private input. Client projection has no
server-secret field/reader. UUID remains secret despite being a user identifier.
Ordinary GET/doctor/errors/journal/logs omit UUID/private key; authorized export may
reveal UUID and public client fields only. Blocking tests traverse Mihomo/sing-box/
URI/API outputs. Synthetic external fixtures and raw DB/log checks cover leak gates.
Crash dumps/support bundles remain sensitive; no perfect Go heap zeroization claim.

Display endpoint, listener, SNI and target stay distinct typed values. Wrong REALITY
auth can invoke camouflage fallback but must not route authenticated user payload.
Vision's upstream race/checkptr defects require fail-closed rejection before
commit, TLS material access, runtime construction or export. Capability Vision=false;
no sanitizer suppression or upstream patch. [Decision](../adr/0017-defer-vision-dependency-safety.md).

## Owned Xray process artifacts

Exact binary digest/version and absolute non-symlink paths are mandatory. Generation
IDs are random and never formed from unchecked inbound/engine input. An exclusive
kernel root lease bounds stale cleanup; retained process handles bound termination.
No recorded PID is trusted for recovery cleanup. Direct exec uses an allowlisted
environment, fixed arguments and no secrets outside protected configuration.
Linux generation/config modes are 0700/0600; Windows protects the user/SYSTEM DACL.
Raw child output is discarded; safe counters and exit codes alone reach status.
Version capture is capped at 4096 bytes. Config snapshots are handle-owned; mutable
caller slices and TLS file content cannot change a prepared generation.
The private loopback listener is inside the trusted local runtime boundary and
receives loopback source addresses. Public admission remains closed before commit.
For platform limits and ownership details see [ADR 0018](../adr/0018-xray-owned-child-engine.md).

## Shared transport secrets

Sudoku password is inbound-owned and client-needed; it is distinct from per-Account
UUID and server-only REALITY private key. Exact 32 hex-character import preserves
case; omission generates with crypto/rand before pending. Existing authenticated
encrypted vault/AAD persistence is reused. No plaintext settings, ordinary API,
logs, argv or environment. Explicit authorized Xray export returns the shared seed.
ClientSharedSecretRepository filters active inbound-owned Password rows before
decrypting; private keys cannot enter that port. Profile/config artifacts remain
sensitive, transient and protected. Feature availability requires the exact pinned
artifact; unknown raw JSON/masks/fields reject. No new wire or unsafe pointer code.
[ADR 0019](../adr/0019-xray-specialized-feature-boundary.md).
