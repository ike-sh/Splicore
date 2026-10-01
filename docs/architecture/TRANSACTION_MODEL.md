# Transaction, revision and audit model

- Documentation status: Canonical
- Audience: Core, API and storage developers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Journal, generation fences, runtime compensation, idempotency and audit.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

There is no atomic transaction spanning SQLite, kernel sockets and child processes.
Splicore uses a durable coordinator with generation fences and compensation.
Do not promise zero downtime or undo already transferred traffic.

## Implemented runtime transactions

Phase 3 uses one shared create coordinator for Snell/HY2: pending journal → build
→ start → listener health → SQL commit → activate. HY2 owns a UDP gate dropping
reads before commit. Invalid credential/TLS, keypair/chain failure, UDP conflict,
startup/health/commit faults publish no resources and close the candidate.
Binding enable/disable journals a replacement, stops only its Inbound and admits
the candidate after commit. Failure reconstructs its old committed projection;
failed reconstruction reports recovery required. All sessions on that Inbound close;
counters reset. Restart recovers committed SQLite plus required TLS file references,
never client exports/import files. Interrupted known runtime operations fail before
reconstruction. See [HY2 contract](../protocol/HYSTERIA2.md) and [ADR 0014](../adr/0014-hysteria2-runtime-composition.md).

Validate → revision/HMAC plan check → short SQL BeginOperation (`snell_create`
or `runtime_create`) → compile without sockets → Start with closed admission → listener Health
→ short SQL commit of resources/global revision/journal → Activate.
Invalid input and compile failures publish no resources. Start/health/storage
failures close candidates and mark failed with an independent bounded context.
Storage failure tests reject after Account/Inbound SQL insertion and prove rollback.
Display updates check resource/global revisions and do not touch sockets/routes.

Restart reconstructs committed resources only from SQLite. Interrupted known runtime
journals become failed; no candidate granted traffic before commit. Unknown pending
Foundation operations remain fenced for review. Any failed committed restore cleans
previously restored handles and fails startup. Crash after commit before Activate
recovers committed state at restart. Listener Health is readiness; actual auth and
payload qualification is provided by independent interop tests.

No generic idempotency, durable candidate payload, arbitrary update recovery or
full audit ledger is claimed. RequestID is correlation. The broader normal-mutation
design below remains future work.

```text
VALIDATED → PLANNED → PENDING → APPLYING → HEALTHY → COMMITTED
                           \ failure → ROLLING_BACK → ROLLED_BACK
                                                   → RECOVERY_REQUIRED
```

## Normal mutation

1. Validate syntactic/domain/capability/ownership/secret constraints without side effects.
2. Plan against committed generation G and engine/build identity. Pin normalized
   input, expiry and secret references; report listeners, drain/restart and deletions.
3. Coordinator serializes runtime-affecting operations. Check resource If-Match
   and global base generation again under short writer transaction. Persist operation,
   candidate changes and undo/reconstruction references. Committed rows remain G.
4. Apply outside SQL transaction. Preflight resources possible in isolation; admission
   gate blocks candidate traffic. Reused sockets may require drain/stop-old/start-new;
   plan explicitly declares disruption. Internal controlled probes can test candidate.
5. Check listener readiness, protocol/auth probe, required engine health and policy
   identity mapping. Health is bounded and records evidence, not only process liveness.
6. In one SQL transaction publish resource changes and generation G+1, success
   audit and operation outcome. Only then open candidate admission. Any activation
   failure is reconciled to the **committed** G+1, reported degraded, not falsely rolled back.

During apply reads return committed G with operation status. Candidate endpoints
and ClientProfiles are not exported. Existing sessions retain immutable generation
identity; mixed-generation drain is explicit and policies consult current revocation
state. Changes requiring destructive credential cutoff must declare session termination.

## Failure and recovery

| Crash/failure point | Recovery |
|---|---|
| before pending intent | nothing applied; retry same idempotency key |
| pending or partial runtime apply, before commit | reconstruct G from SQLite, clean/reap owned candidate resources; mark rolled back only after health |
| health success, before DB commit | G remains authority; compensation/reconstruction required |
| DB commit durable, admission not activated | reconstruct/activate G+1; operation is committed but may be degraded |
| rollback listener/child restore fails | RECOVERY_REQUIRED, affected admissions blocked; committed state retained, diagnostics available |
| shutdown during mutation | stop accepting new operations; bounded finish or leave durable intent for startup recovery |
| disk full/write failure | do not publish generation; block unsafe admission, compensate from durable committed snapshot |

Never keep a long SQL write transaction open during network health. Pending payloads
with secrets are encrypted or refer to secret records; redacted plan digest alone
cannot reconstruct runtime. Startup holds installation lock, validates DB, reconciles
nonterminal operations and child ownership before accepting mutation/traffic.
Runtime observations cannot promote a pending candidate into domain authority.
If commit result is uncertain, re-read committed generation/operation before compensation.

## Concurrency and idempotency

Each mutable resource has a revision; global generation fences multi-resource
plans. API revisions are decimal strings; resource ETags are quoted revision values.
Stale supplied revision returns **409 Conflict** as the chosen v1 contract (even
though generic HTTP If-Match implementations often use 412); missing required
precondition returns 428. Independent resource revisions do not bypass runtime
serialization or plan-generation checks.

Idempotency scope is `(actor, route, key)`, persisted with keyed payload digest
and operation/result IDs. Same key/same input returns the same operation; different
input returns 409. No secret plaintext/hash suitable for offline attack in audit.
One-time credential/token delivery uses short-lived encrypted result storage and
an authenticated reveal operation; retries must not mint a different secret.

Audit records actor, action, resource, old/new revision, timestamp, result,
request_id, transaction_id and redacted field names. Record attempt/failure and
commit outcome; mutation success audit is atomic with domain commit. Usage and
irreversible traffic are independent of config rollback. Backup restore is an
upgrade recovery operation with its own audit, not a routine mutation rollback.
