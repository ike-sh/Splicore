# Remote Subscription and Proxy Providers

- Documentation status: Canonical
- Audience: Core, client and integration maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Source ownership, protected fetching, generations, scheduling and recovery.
- Lifecycle: Update with implemented contracts and qualified evidence.

## Domain and authority

Phase 14 implements Experimental remote subscription ingestion as ProxyProvider.
Provider is an update source; canonical SQLite nodes/outbounds are startup authority.
Account remains server authorization. Provider ID is immutable; name and source URL
are editable metadata and never node identity. RuleSetProvider uses a separate typed
resource with shared fetch/scheduler infrastructure, described [here](RULESET_PROVIDER.md).
The earlier [subscription export-token design](SUBSCRIPTION_MODEL.md) remains deferred.
No public subscription serving endpoint is added.

Provider config includes kind/format, refresh cadence, independent refresh_enabled,
DIRECT/Outbound/PolicyGroup fetch action, private-address policy, strict/lenient mode,
empty/removal guards and optional generated outbounds/engine. Read views add safe
origin display, generation, timestamps, fetch status and fixed error classes.
Refresh-disabled does not disable nodes. Use batch disable for that independent action.

Full URL, bearer/basic/header auth, ETag and Last-Modified are encrypted in generic
provider_sources with the existing vault and `Splicore/provider-source/1/<ID>` AAD.
No raw feed cache exists. General read API/CLI returns no full URL/auth/validator/feed.
RedactURL removes all user, path, query and fragment data, including unknown token keys.
Source URLs containing userinfo/fragment reject; display retains scheme/host only.
Passwords for nodes retain existing encrypted credential ownership/AAD.

## Protected HTTP fetching

| Boundary | Implemented behavior |
| --- | --- |
| Schemes / TLS | HTTP/HTTPS only; normal verified HTTPS and SNI, no skip option. |
| Timeout | 15s whole request, 5s TLS handshake, 10s response headers. |
| Allocation | 16 KiB headers, 2 MiB wire and decompressed body; gzip only, other encodings reject. |
| Content type | Empty/plain/JSON/YAML/octet-stream only; HTML/unsupported types reject. |
| Redirect | At most 3; scheme, address and target policy rechecked; HTTPS downgrade rejects. |
| Auth | Bearer, Basic, Authorization or X-Api-Key explicit header; bounded values, no CR/LF/NUL. |
| Cross-origin | Remove auth and conditional validators; do not forward source credentials. |
| Environment | No ambient HTTP proxy, pooled keepalive or implicit compression. |
| DNS | Resolve full answer, validate every address, pin one numeric address for dial. |

Default SSRF policy rejects loopback/RFC1918/ULA, link-local/metadata, multicast,
unspecified, documented/reserved/benchmark ranges and CGNAT. Explicit allow_private
permits loopback/RFC1918/ULA for operator-owned internal subscriptions; link-local and
reserved ranges remain denied. DNS rebinding cannot bypass the pinned validated dial.
This is operator-managed source input; it is not a public arbitrary URL fetch service.

Every fetch owns one committed runtime snapshot and a typed ProviderFetch underlay
lease. DIRECT target protection is ready before dial; HTTP socket/body cleanup
finishes before lease release. Outbound/PolicyGroup selection reuses existing runtime
adapters, bootstrap DNS and group health. Failure never silently switches to DIRECT.
Provider → fetch action → all possible group members → node → owning provider graph
is validated transitively; self/cross-provider cycles fail closed before publication.
TUN generation reconciliation and endpoint protection remain Phase 13 mechanisms.

## Preview, generation and failure

Create/update/delete/refresh-preview return a redacted token plan. Manual `refresh`
performs that same complete validation/preparation/transaction immediately. Feed
parsing is complete before diff and commit. Node matching is defined in [Node](NODE_MODEL.md).
Successful 200 refresh advances the provider generation; SQLite nodes, credentials,
source validators and global revision commit together. A 304 does not advance provider
generation or rebuild runtime; diagnostic timestamp/global revision may still change.

Default empty rejection and max_delete_percent=50 prevent accidental clearing.
Explicit empty_is_authoritative plus appropriate threshold is required for authoritative
empty proxy feeds. Threshold range is 1–100; zero means default, not zero tolerated
deletions. Referenced disappeared nodes remain stale and continue using last-good
settings. Deletion of referenced provider resources is blocked. No dangling references.

Network/parse/validation/commit failure keeps old generation and established traffic.
Safe error classes are fetch_failed, parse_failed, validation_failed, apply_failed,
safety_guard and revision_changed. Failure diagnostics are a separate metadata commit;
failure metadata itself cannot replace serving resources. Preview alone does not write
failure diagnostics. Prepared-but-uncommitted adapters and leases are aborted.
SQLite commits before Activate, as in prior phases; host activation failure after commit
is degraded committed intent with recovery debt, not falsely reported rollback.

## Scheduler and concurrency

One coordinator ticker and four workers, bounded queue and four global fetch slots.
Same provider's refresh/validate/apply lifecycle serializes. Preview releases its lock
after creation; apply's global revision detects intervening refresh/delete/config change.
Client application mutex protects control metadata/commit, never HTTP fetch or payload.
Scheduler lifecycle has a narrow Start/Stop mutex; cancellation waits active ownership
and worker exit. No goroutine-per-provider timers, sleeps or failed-operation retries.

Configured interval is 60s–30 days, default one hour. Deterministic 0–30s jitter
staggers providers. Bounded exponential failure backoff never shortens configured
cadence. Production ticks use monotonic time; persisted wall times are diagnostics.
Startup restores SQLite and runtime before scheduler, then waits full cadence+jitter;
no initial fetch storm or online prerequisite. Client runtime must be started for fetch.

## Health and recovery

Provider health reports update availability only. Node connectivity is existing
passive adapter/PolicyGroup URL-Test health; fetch success does not mark nodes healthy.
No automatic test of every imported node. Selectors/fallback/load balance reference
explicit stable outbound IDs and retain their Phase 12 snapshot/session behavior.
Provider/tag dynamic membership is deferred. No second health scheduler is introduced.

Offline restart restores last-good nodes, sources and RuleSets from schema 8. Backup
includes provider metadata, encrypted sources/credentials, nodes and tags; original
master key must accompany a stopped/coherent backup. Default uninstall preserves all
state; purge removes it. One existing binary and service own management/scheduler.
See [operations](../OPERATIONS.md), [storage](STORAGE_MODEL.md) and [report](../reports/PHASE_14_CLIENT_MANAGEMENT_PROVIDERS_REPORT.md).
