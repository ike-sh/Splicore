# NoBrand-OneClick integration and gradual migration

- Documentation status: Canonical
- Audience: Integration and deployment developers
- Last reviewed: 2026-10-01
- Owner: Integration maintainers
- Responsibility: Future NoBrand import, rollout, field-test and rollback boundaries.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

NoBrand-OneClick is a first distribution/field-test consumer of Splicore, not
Splicore's product identity or code owner. Existing installation/source is not
inspected or modified in Phase 0; importer mappings need real old-state fixtures
in their later stage. Do not invent old schema or PSK/UUID extraction locations.

```text
pin qualified stable manifest → download matching platform artifact
 → verify digest/provenance → generate public Splicore declarative document
 → validate → plan → apply → inspect operation → health
```

NoBrand understands Splicore config/API/version/capabilities only. Native/private
engine config rendering belongs to Splicore. Installer uses a qualified stable
pin, not latest upstream/GitHub commit, and verifies digest before replacing binary.
Manifest declares compatible config/DB/ABI/API and upgrade/backup requirements.

## Per-protocol rollout

| Stage | Migration gate / flag |
|---|---|
| A | `migration.snell`: qualified exact client/profile; Account binding/PSK+userkey model, one-account quota and reconnect |
| B | `migration.hysteria2`, `migration.tuic` independently: QUIC/UDP/families/congestion/policy and endpoint checks |
| C | `migration.vless_reality`: UUID/flow/SNI/public key/target and third-party compatibility |
| D | `migration.mieru`: only after native Stage 3 and official-client gate |
| Special | `engine.xray_compatibility`: FinalMask/Sudoku only with identified reference fork and child lifecycle/stats/policy gates |

Defaults off until qualification; flags are Splicore/installer rollout selection,
not hidden runtime bypasses. Track node/account/protocol migration state and source
ownership keys. Dual binaries can coexist temporarily for different protocols;
one actual listener owner per address/port. Plan downtime, stop old service, apply
new owned listener, health and reconnect; on failure restore old service/config
without racing the same port. Success records checkpoint before disabling old startup.

Snapshot old config/state/service topology, secure credentials and version; validate
import mapping and display endpoint separately. Missing usage history is labeled
unknown/incomplete, never implicitly reset to give extra quota. Conversion preserves
credential and wire behavior unless rotation is explicitly planned. No Big Bang.

Rollback restores compatible binary/state/service checkpoint with usage
reconciliation; schema-aware restore after a forward migration differs from config
rollback. Never delete old services/state just because process readiness succeeded.
Field beta collects local redacted support bundles (manual sharing), client/server
versions, TCP/UDP/reconnect/policy results and rollback evidence. NoBrand must not
reach SQLite directly or generate sing-box/Mieru/Xray runtime JSON after migration.
