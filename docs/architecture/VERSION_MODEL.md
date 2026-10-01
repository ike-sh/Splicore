# Version and qualification model

- Documentation status: Canonical
- Audience: Core and release developers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Independent product, build, schema, API and client-qualification identities.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

## Current Phase 2 implementation

DatabaseSchema is now 3; ConfigSchema and ProtocolABI stay 1, API stays v1. Bootstrap
key_file is optional but real credentials require it. Upstream Snell/HY2 wire versions
are unchanged. The schema increment adds generic password credentials.

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

Phase 1 assigns **devel**, Config Schema 1, Database Schema 1, Protocol ABI 1
and API v1. Version/commit/dirty/build time can be injected with linker flags;
Go VCS metadata supplies commit/dirty fallback, otherwise commit is unknown.
Build time defaults to unknown for plain go build; the build script injects UTC.
The JSON version projection explicitly includes dirty and development channel.
No generated source or public module identity is introduced.

Channels: stable, beta, nightly. Stable means qualified gates passed, not merely
highest GitHub tag. NoBrand defaults to a pinned qualified stable manifest with
artifact digest/platform/schema ranges and qualification evidence. Upstream's
newest release, testing branch or arbitrary HEAD never automatically changes that
pin. Field beta builds identify their commit/channel and can be rolled back with
schema-aware state backup. No channel/tag/release is created here.
