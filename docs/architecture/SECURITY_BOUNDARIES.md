# Security boundaries

- Documentation status: Canonical
- Audience: All developers and security reviewers
- Last reviewed: 2026-10-04
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

## Independent core runtime boundary

Splicore owns native runtime only. No external supervisor, process configuration,
transport-mask shared-secret exporter or artifact lifecycle remains. Retired
Xray/mask state rejects before migration/replacement; imports never discard
features into ordinary VLESS. Real NoBrand is untouched. Historical Phase 6/7
security reports remain unchanged and superseded by [ADR 0035](../adr/0035-xray-runtime-removed-from-core.md).

## Phase 8 Mieru secrets and globals

Ordinary API, CLI, doctor and profile/runtime formatting redact username/password
credential material; protected per-binding export explicitly returns it. Private
protobuf never enters public API or support formatting. The official locked
NilFormatter suppresses embedded logger output; no fatal/signals/CLI path is used.
Upstream synchronized cipher caches retain templates after Stop, so complete secret
erasure is not claimed. Shared username metrics are excluded from billing and quota
authority. Owned raw sockets/sessions close on rollback/restart/Stop.
[Audit and limits](../adr/0020-mieru-owned-native-embedding.md).

## Client listeners and remote secrets

Unauthenticated local SOCKS defaults to 127.0.0.1 and accepts loopback IPs only;
::1 is qualified where available. Wildcard, LAN and domain listener hosts reject.
Handshake/dial deadlines and session/resource caps bound admitted work. There is
no automated LAN exposure, system proxy or remote health probing.

Remote credentials use the same AEAD vault with node-specific authenticated context:
`Splicore/remote-credential/<credential ID>/<node ID>/<kind>/<schema>`.
Exactly one owner is enforced; server credential AAD remains unchanged. Creation/
rotation credential values are explicit write-only inputs. Node/status/plan/CLI
queries contain references only. Options are adapter-validated; arbitrary secrets
are not stored as Snell Node fields. Support bundles discard all free-form names,
domains, metadata, options and errors, retaining fixed enums and address classes.
Rotation validates before commit; malformed replacement preserves old intent and
sessions. Passive startup cannot prove a syntactically valid remote key is accepted.
Remote rejection is observed on actual traffic, without fallback or active probes.
DNS semantics are documented in [routing](ROUTING_MODEL.md).

## Client UDP and public security

SOCKS TCP and UDP bind the configured loopback IP only. An association accepts only
its TCP peer IP, then its requested source port or the first valid packet's port.
Foreign IP/port, invalid reserved bytes and fragments cannot claim or use the relay.
TCP EOF, idle expiry, changed route/adapter, stop and daemon shutdown close flows
and join workers before releasing generation ownership. Limits are 32 target flows
per association and a two-minute idle timeout; no unauthenticated LAN relay is exposed.

ClientTLS cannot represent certificate keys or a REALITY private key. Passive
health is per native adapter lease so retired traffic cannot mark a replacement
adapter healthy. FinalMask/Sudoku are out of scope; Vision remains unsupported.

## Phase 12 resolver and policy boundary

Operator-controlled HTTP/HTTPS probes disallow userinfo/redirects/non-HTTP schemes,
have bounded timeout/body/workers and never attach proxy credentials to target headers.
They have no public default URL. DoT verifies configured server name and trust; no
insecure skip is available. DoH is deferred pending bounded response allocation.
Explicit DNS detour failures never fall back to DIRECT/System. Separate bootstrap
requires System or IP-only DIRECT UDP/TCP and cannot depend on unresolved proxy itself.
Domain RuleSets cannot smuggle IP/source rules into DNS. UUID references/cycles and
canonical size/depth bounds validate before activation. General API/status/support
remain redacted; graph intent contains no credential payload fields.

## Phase 13 host integration

Host mutations require the existing protected Application plan/apply/revision boundary. Private journal owner/ACL, size/shape validation and an exclusive lock precede writes. Corruption fails degraded; external changes are retained. HTTP stays loopback, headers bounded and proxy credentials stripped. Support bundles expose owned counts/enums and redacted metadata, never full host network/proxy data. See [system integration](../SYSTEM_INTEGRATION.md).

Windows schema-2 records bind adapter GUID/route identity to generation/owner.
WinINET LAN snapshots/intermediates remain private and reject sensitive PAC values.
Exact-state comparisons preserve external C; failed child cleanup retains Wintun
parent debt. No registry setter, guessed adapter-name deletion or reboot is used.
Original activation guards remain pending real Windows platform qualification;
fixture PASS does not certify real Windows mutation. See [recovery](../RECOVERY.md).

## Underlay ownership and privacy

Typed construction capabilities fail closed when required socket/child protection
cannot be verified. They preserve logical route/DNS/health selection. Infrastructure
addresses are bounded; arbitrary DIRECT/server targets are never retained as a
browsing history. Status/doctor/support expose only strategy, generation IDs, counts
and redacted error classes. Socket verification and control metadata use narrow
locks; payload reads/writes and scratch buffers remain per connection. Windows real
activation remains guarded. No upstream, credentials, wire or external targets are
modified by the underlay integration.

## Phase 14 remote sources and secret input

[Provider](PROVIDER_MODEL.md) defines verified HTTP(S), full-answer address validation,
numeric dial pinning, redirect revalidation, auth stripping, explicit private-source
opt-in and wire/decompression caps. No insecure TLS/file/command/Unix fetch. Each
fetch owns the existing runtime snapshot and typed underlay lease; dependency cycles
reject. Full source URL/auth/validators are encrypted; no feed history is stored.
API/CLI read/preview/errors never return URI/source/credential content. Import files
and explicit exports are protected operator inputs/results, not passive diagnostics.
Support bundles project fixed provider enums/counts/ages, dropping names/URLs/metadata.
Regular-file identity/size checks reject symlink/device/socket imports. Canonical and
external unknown fields reject; REALITY server private fields, Vision and client masks
cannot enter a runnable node. No public subscription listener or telemetry is added.
