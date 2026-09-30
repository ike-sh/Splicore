# Configuration and state authority

- Documentation status: Canonical
- Audience: Domain and application developers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Bootstrap, import-command and committed-domain authority boundaries.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Decision: SQLite committed domain generation is the sole domain authority.
No file watcher may mutate Accounts/Inbounds independently. Runtime, profiles and
upstream JSON are derived projections with an applied generation and digest.

| Data | Authority |
|---|---|
| storage location, API transport, logging, trusted engine path | `/etc/splicore/splicore.yaml` bootstrap, process-level; restart classification |
| Accounts/Bindings/Credentials/Inbounds/endpoints/policies/subscriptions | committed SQLite generation |
| pending mutation intent | durable transactions journal; not committed domain state |
| usage/audit | append/settlement records in SQLite, not import-controlled |
| listeners/active sessions/health | observed runtime, never replacement domain authority |
| DNS/fake IP/rule-set caches | upstream operational cache, disposable according to its own semantics |
| declarative input | versioned command document, consumed through validate/plan/apply |

Import envelope: `config_schema`, `document_id`, `owner_scope`,
`base_revision`, `mode(merge|reconcile)`, `resources`, explicit secret inputs/references.
Stable import keys map to random resource IDs; names never implicitly identify a
resource. Dry-run resolves mappings/selectors, validates protocol capabilities,
references, listener conflicts and secrets, and returns a redacted plan, hash,
expected revision, expiration, restart/drain impact and destructive changes.

NoBrand uses `validate → plan → apply(plan_id, base_revision, idempotency_key)`.
The stored plan pins normalized input and engine/protocol build identity. No
re-read of a mutable input file at apply. Stale/expired/different build plans reject;
changes outside the import owner scope remain untouched. Reconcile deletion
requires explicit deletion intent and dependency/impact reporting in the plan.
Same document retry is idempotent. Unknown fields/schema/features reject; no
automatic conversion of raw sing-box/Mita/Xray JSON into the public contract.

SQLite availability is required for domain mutation and strict admission.
Bootstrap reload cannot silently select a different state database. Restore/import
must preserve Node identity deliberately and revoke/regenerate imported public
tokens where necessary. Bulk state export is redacted by default; secret-bearing
encrypted backup is a separate privileged operation.

Alternative file authority is simple for immutable deployments but undermines
API concurrency and durable usage; dual file/DB write authority introduces conflict
resolution and security races. An explicit offline import mode can submit commands
while the daemon is stopped, taking the same process/storage lock and journal rules.
