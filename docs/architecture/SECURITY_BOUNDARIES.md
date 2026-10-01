# Security boundaries

- Documentation status: Canonical
- Audience: All developers and security reviewers
- Last reviewed: 2026-10-01
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
