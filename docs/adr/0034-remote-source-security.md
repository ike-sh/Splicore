# Remote Source Security and SSRF Boundary

- Documentation status: Canonical
- Audience: Core, client and integration maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Phase 14 implemented decisions and alternatives.
- Lifecycle: Update with implemented contracts and qualified evidence.

## Status

Accepted for the authorized Experimental Phase 14 local freeze, 2026-10-04.

## Decision

Remote source URLs and auth are encrypted write-only inputs. Fetch is bounded verified
HTTP(S), no ambient proxy, revalidated redirects and pinned validated DNS answers.
Default private/loopback denial has an explicit internal-source opt-in; link-local and
metadata endpoints remain forbidden. Reuse committed runtime selection and typed
underlay leases; reject transitive provider bootstrap cycles. Encrypt validators too
because an upstream may echo credential material. No raw feed persistence or public
fetch/export endpoint. Tradeoff: complete-address validation may reject mixed public/
private DNS answers, and no automatic fallback/retry or OAuth exists.
See [Provider](../architecture/PROVIDER_MODEL.md) and [security](../architecture/SECURITY_BOUNDARIES.md).
