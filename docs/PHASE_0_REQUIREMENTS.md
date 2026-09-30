# Phase 0 requirement traceability

- Documentation status: Historical
- Audience: Maintainers and historical reviewers
- Last reviewed: 2026-10-01
- Owner: Project maintainers
- Responsibility: Traceability to the original Phase 0 brief; not a live backlog.
- Lifecycle: Frozen snapshot; only typo, broken-link or factual corrections.

User brief section → evidence/design document. Documents are proposals unless
they describe verified baseline facts; implementations are not claimed.

| Brief section | Coverage |
|---|---|
| 0–1 product/scope | ARCHITECTURE.md, report, NOTICE; independent product, architecture-only |
| 2–6 directory/clone/tag/branches/history | UPSTREAM_BASELINE.md, UPSTREAM.md, captured Git metadata; empty-directory check passed |
| 7 license | LICENSE_BOUNDARIES.md, NOTICE.md, preserved original LICENSE/headers |
| 8–9 baseline build/test | UPSTREAM_BASELINE.md and evidence logs; scoped PASS/FAIL/NOT RUN |
| 10 complete source tree / A–J | UPSTREAM_ARCHITECTURE_MAP.md and FORK_BOUNDARY.md |
| 11 fixed principles | ARCHITECTURE.md and related design contracts |
| 12 entities | DOMAIN_MODEL.md, DATABASE_ERD.md |
| 13 cases A–E | DOMAIN_MODEL.md scenario table, POLICY_USAGE.md |
| 14–15 protocol contract/capabilities | PROTOCOL_SDK.md, INTEROP_MATRIX.md |
| 16 engine model | ENGINE_MODEL.md, RUNTIME_LIFECYCLE.md |
| 17 Mieru roadmap | MIERU_INTEGRATION.md, ADR 0010; official API research only |
| 18 future native protocol | NATIVE_PROTOCOL_GUIDELINES.md |
| 19–21 clients/profile/exporters | CLIENT_COMPATIBILITY.md, SUBSCRIPTION_MODEL.md |
| 22 real interop gate | INTEROP_MATRIX.md |
| 23 state authority | CONFIG_STATE_AUTHORITY.md, ADR 0003 |
| 24–26 SQLite/ERD/migration | STORAGE_MODEL.md, DATABASE_ERD.md, ADR 0007 |
| 27–29 transaction/revision/audit | TRANSACTION_MODEL.md, API_V1_DESIGN.md |
| 30–34 API/transport/subscription boundary | API_V1_DESIGN.md, openapi-skeleton.yaml, SUBSCRIPTION_MODEL.md |
| 35–36 diagnostics/bundle | DIAGNOSTICS.md, SECURITY_BOUNDARIES.md |
| 37–38 version/channel | VERSION_MODEL.md, ADR 0012 |
| 39–41 NoBrand/migration/service | NOBRAND_MIGRATION.md, RUNTIME_LIFECYCLE.md |
| 42–45 sync/conflicts/module/binary | UPSTREAM_SYNC.md, FORK_BOUNDARY.md, ADR 0002/0011 |
| 46 ADR | docs/adr/0001–0012, each six required sections |
| 47–50 architecture/dependencies/packages/static registry | ARCHITECTURE.md, PROTOCOL_SDK.md |
| 51 security | SECURITY_BOUNDARIES.md |
| 52–56 tests/race/fuzz/failure/differential | TEST_STRATEGY.md, INTEROP_MATRIX.md |
| 57–60 permitted file scope/recheck/Git state | report/evidence; no runtime edits, no skeleton packages, no commit/push/tag/release |
| 61 questions 1–38 | report answer table and linked specifications |
| 62 full report format | PHASE_0_ARCHITECTURE_REPORT.md |
| 63 technical conflicts/alternatives | transaction atomicity, external policy limits, Snell version/client qualification and Mieru lifecycle findings; ADR alternatives |

## Explicit technical conflicts discovered

1. SQLite commit cannot atomically commit sockets/children. Durable intent,
   admission fences, compensation and startup reconstruction replace an impossible
   ACID claim; existing network implementation remains reusable.
2. Native stats do not prove durable strict quota/rate enforcement. Aggregate
   policy requires authenticated hooks and clear units; unsupported external
   combinations reject instead of silently weakening guarantees.
3. Snell multi-user server support does not prove Mihomo/Surge userkey support.
   Client/profile qualification and per-binding listener fallback preserve wire
   compatibility at the cost of explicit port/resource allocation.
4. Mieru official embedded Server is a useful extension point but cannot be
   configured after start and Stop does not close established sessions. Prototype
   must own session cleanup/fresh generations; no daemon-code copy required.
