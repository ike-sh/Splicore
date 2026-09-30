# Security boundaries

- Documentation status: Canonical
- Audience: All developers and security reviewers
- Last reviewed: 2026-10-01
- Owner: Security maintainers
- Responsibility: Secret handling, transport authorization, imports, files and executable trust.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Proposed design; no custom encryption or auth implementation in Phase 0.

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
and key provisioning in Phase 1 after platform/deployment review. Exportable UUIDs,
PSKs/passwords and shared Snell server PSK remain secret even if not visually
password-like. Public REALITY keys are distinguished from private keys in types.

Redaction is data-type driven before serialization, with adversarial fixtures for
URIs/YAML/protobuf-shaped payloads, query tokens, exceptions and child output.
Crash dumps can contain secrets despite log redaction: exclude raw dumps from
default support bundles and require explicit privileged handling. No automatic upload.

Security failures fail closed where authorization/accounting is uncertain.
The native data plane's upstream compatibility APIs must not expose mutation paths
that bypass the application/revision coordinator. Existing route/security policy
is preserved; import exposes curated stable controls rather than an arbitrary
upstream JSON escape hatch.
