# Version and qualification model

- Documentation status: Canonical
- Audience: Core and release developers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Independent product, build, schema, API and client-qualification identities.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

| Identity | Meaning / compatibility rule |
|---|---|
| Splicore version | product SemVer; Phase 0 has no product release/version tag |
| Git commit | full source identity; dirty worktree reported explicitly |
| Build time | UTC timestamp, independent of source/version |
| Go version/platform | actual compiler and GOOS/GOARCH/build tags |
| Upstream baseline | stable tag + full SHA, separately recorded from product version |
| Config Schema | integer public bootstrap/declarative/profile schema contract; migration/acceptance ranges explicit |
| Database Schema | monotonic forward migration version/checksum, independent of config |
| Protocol ABI | internal source-port contract version; not binary `.so` ABI |
| API | `/api/v1` public contract, additive evolution within v1; incompatible change needs a new API version |
| Protocol/client qualification | exact wire feature + server/client versions + platform + evidence revision |

Future illustrative output `Splicore 0.4.0 / Config 2 / DB 4 / ABI 1 / API v1`
is an example, not assigned Phase 0 versions. New protocol options cannot silently
change existing ClientProfile semantics. Stable old clients need documented
acceptance/migration windows for schema updates.

Channels: stable, beta, nightly. Stable means qualified gates passed, not merely
highest GitHub tag. NoBrand defaults to a pinned qualified stable manifest with
artifact digest/platform/schema ranges and qualification evidence. Upstream's
newest release, testing branch or arbitrary HEAD never automatically changes that
pin. Field beta builds identify their commit/channel and can be rolled back with
schema-aware state backup. No channel/tag/release is created here.
