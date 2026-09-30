# Upstream provenance

- Documentation status: Canonical
- Audience: Developers and distributors
- Last reviewed: 2026-10-01
- Owner: Upstream maintainers
- Responsibility: Current baseline provenance, history policy and independent project identity.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Reviewed on 2026-10-01 (Asia/Shanghai).

| Item | Value |
|---|---|
| Project | SagerNet/sing-box |
| Remote | `https://github.com/SagerNet/sing-box.git` (only `upstream`) |
| Stable tag | `v1.14.1` |
| Commit | `1ac1a339cb1223e9c70eae14c44411c75033c02d` |
| Commit date | 2026-09-15 01:21:37 +08:00 |
| Release publication | 2026-09-15 00:06:50 UTC |
| Module | `github.com/sagernet/sing-box` |
| License | GPL-3.0-or-later; upstream also states a derivative naming/association condition |

Splicore is an independent derivative project based in part on SagerNet/sing-box.
Splicore is not affiliated with or endorsed by SagerNet. Original upstream
copyright and GPL licensing terms are preserved. It is a new product and has
no IDC ownership or NoBrand-OneClick product identity.

Source history and existing tags are retained. `main` and
`codex/phase-0-architecture` were created directly from the stable tag; this phase
does not move upstream packages or change module imports. `testing` is an inherited
local clone branch and upstream's default branch, **not** the Splicore baseline.
The release commit is an ancestor of both fetched `upstream/stable` and
`upstream/testing`. Release `target_commitish=testing` does not make a published
stable tag a testing baseline.

Evidence: [official release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.1),
[baseline source](https://github.com/SagerNet/sing-box/tree/1ac1a339cb1223e9c70eae14c44411c75033c02d),
[baseline validation](architecture/UPSTREAM_BASELINE.md),
[sync procedure](architecture/UPSTREAM_SYNC.md).
