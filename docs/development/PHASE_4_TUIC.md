# Phase 4 TUIC workflow

- Documentation status: Canonical
- Audience: Developers and acceptance reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Native WSL2 execution, pinned clients and reproducible gates.
- Lifecycle: Update with reviewed implementation or qualification changes.

Starts at Phase 3 freeze `94555d9608ebcc36c5a396bc06a5743cce4e0788`
on codex/phase-4-tuic-vertical-slice. Implementation acceptance is preserved in
the report; the subsequent Phase 4 Freeze authorizes one reviewed commit,
main fast-forward and a reserved Phase 5 branch. Push/tag/release NONE.
[Report](../reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md) records results;
[profile](../protocol/TUIC.md) owns behavior.

## Environment and evidence

Ubuntu-24.04 WSL2 root is explicit due existing default-user shell permissions;
unrelated permissions remain untouched. Source/runtime/TLS/state/socket use native
ext4. Go1.26.6 toolchain/module/build/work caches stay D; Windows Go1.26.2 uses short
D temp path. Evidence: `D:\splicore-validation\phase4-20261001`; native root:
`/root/splicore-validation/phase4-20261001`. Snapshot tracked/untracked source without
staging, record SHA256, protect historical/upstream sources. Use buildvcs=false in
isolated source because unrelated `/` Git state is unchanged. Test executor unsets
GOTMPDIR and uses short native TMPDIR.

Pinned clients: [downloader](../../scripts/splicore-clients.py). Archives/binaries
external; every archive SHA verifies. Campaign uses isolated loopback-only network
namespace, checks ip link, runs race server. Native secrets/configs private; PID
record and exact owned cleanup. No Docker dependency.

## Gates

Windows all owned/command tests and both builds; WSL unit/race/both builds/arm64,
settings/creation/credential/export fuzz, own vet and exact original root CI.
[TUIC campaign](../../scripts/splicore-tuic-interop.py),
[HY2 regression](../../scripts/splicore-hysteria2-interop.py) and
[Snell regression](../../scripts/splicore-snell-interop.py) use fixed clients.
[Shared QUIC campaign](../../scripts/splicore-quic-interop.py) owns TLS fixtures,
client/process helpers, payload/stress/stat/recovery gates. TUIC adds UUID/pair
isolation and disabled Account creation/recovery through production commands.

Actual CLI validate/plan/apply, scoped export/live metadata, Binding reconcile and
SQLite recovery after input erasure. Two clients × two users × three endpoints:
12 cells TCP/UDP, 32 sequenced UDP responses, 16 concurrent and 4MiB SHA256 integrity.
Wrong UUID/password/SNI/CA, kill/reconnect/shutdown/socket reuse mandatory.

[Doc checker](../../scripts/splicore-doc-check.py) validates links/OpenAPI/live
responses with --responses EXTERNAL --protocol tuic (or hysteria2/snell).
Secret/diff/index/protected-source/dependency/import/scalability audits are gates.

Docker issue/old residue DEFERRED EXTERNAL ENVIRONMENT CLEANUP. Docker/Redis/
TeleLedger and real NoBrand untouched; no queries/cleanup/reference Docker tests.

## Local freeze

Final acceptance remains immutable at `D:\splicore-validation\phase4-20261001`.
Fresh evidence is `D:\splicore-validation\phase4-freeze-20261001`. Verify all 131
functional files against that acceptance before reusing its full 33-cell/race/fuzz/
arm64/root-CI results. Repeat TUIC/HY2/Snell critical smoke, Windows/Linux owned
units/builds, own vet, docs/OpenAPI/live schemas, source/secret/whitespace audits.
The external smoke runner restricts only endpoint loops to IPv4 (4/4/3 cells),
retaining both fixed clients, QUIC users and all existing traffic/failure/recovery
assertions without modifying repository source. Report/docs-only freeze edits need
targeted docs gates; runtime edits require corresponding protocol acceptance.

Stage explicit reviewed paths, audit staged blobs, create one commit with message
`feat(protocol): add experimental TUIC vertical slice`, verify the Phase 3 sole
parent and baseline ancestry, then fast-forward main with `--ff-only`. Create
`codex/phase-5-vless-reality-vertical-slice` from main, verify CLEAN, and stop.
VLESS/REALITY implementation is NOT STARTED; TUIC remains Experimental.
