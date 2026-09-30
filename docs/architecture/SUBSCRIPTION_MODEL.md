# Subscription boundary

- Documentation status: Canonical
- Audience: Client and application developers
- Last reviewed: 2026-10-01
- Owner: Client / Core maintainers
- Responsibility: Export-access scope, token lifecycle and authorized profile selection.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Account is a proxy user's authorization/usage identity. Subscription is a scoped
credential for fetching exported connection information. One Account can create
multiple independently named, expired, narrowed and revocable Subscriptions for
different clients/devices. Revoking a download token does not revoke already
downloaded protocol credentials; actual proxy revocation requires Binding or
Credential mutation.

Issue at least 256 random token bits via secure RNG; store a verifier digest,
never plaintext in ordinary subscription rows. High-entropy token verification
does not need a human-password hashing scheme. Compare verifiers safely and
separate token purposes; API admin credentials and subscription tokens cannot be
exchanged. Account IDs are public identifiers, not tokens.

Rotation: create new token generation through an application transaction, revoke
old token immediately by default; bounded overlap is explicit and displayed in
the plan. Revoke marks token/subscription state durably; expiry checks server UTC.
One-time reveal uses protected short-lived result storage, then deletes it;
routine GET/audit never returns token plaintext. Rate-limit lookups and token
attempts, use TLS for public transport, bound response/body sizes.

Separate public listener/origin handles `/sub/{token}` (or later an Authorization
header alternative); it has no admin handlers. Access logs redact the entire
token segment, query tokens and headers. Responses are `Cache-Control: no-store`,
avoid cross-user shared caches, and do not redirect with secrets. Errors do not
reveal Account existence. Public listener is opt-in, never implicitly opened by
Phase 1 local API configuration.

Selection evaluates Subscription selector ∩ Entitlement selector ∩ enabled,
authorized Bindings/Account/Inbound/valid Credential, then builds canonical profiles
and exports requested allowed target format/version. Always read a single committed
generation; never export pending new credentials/endpoints. Subscription `last_used_at`
is a bounded ancillary update, not a mutation that restarts the data plane.

No full subscription server is implemented in Phase 0. Exporters can be used by
local CLI/API without Subscriptions, and Subscriptions can later reuse those same
exporters without protocol/Engine coupling.
