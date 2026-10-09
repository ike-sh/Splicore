# Phase 5 VLESS / REALITY validation workflow

- Documentation status: Canonical
- Audience: Developers and validation maintainers
- Last reviewed: 2026-10-02
- Owner: Development maintainers
- Responsibility: Reproduce Phase 5 code, protocol/engine and security gates.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Read [supported surface and Vision deferral](../protocol/VLESS.md) and the
[final report](../reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md).
The branch starts at Phase 4 freeze 2a9c0f3e14de29050c1228ce013b2f1ad4556946.
No staging, commit, push, tag or release is authorized in this implementation phase.

Use `with_quic,with_utls` for complete compiled coverage. No-tag builds also receive
unit/build coverage and must reject REALITY rather than claiming runtime support.
Windows: units and both executables; native WSL2 ext4: units/race/fuzz/runtime/interop;
Linux arm64: compile only. Original root-module tests use pinned release tags/ldflags.
The Docker-dependent nested test module is not run; Docker/Redis/TeleLedger and the
real NoBrand installation remain untouched. External cleanup remains deferred.

All Go caches/temp directories, SQLite, master keys, TLS material, pinned clients,
binaries, fuzz output, snapshots, logs and response artifacts live outside the repo.
Snapshot includes exact bytes and a SHA256 manifest; native extraction is verified.
Pinned client archives/executables are validated before reuse; do not upgrade them.

```text
go test -count=1 -tags with_quic,with_utls ./internal/splicore/...
go test -race -count=1 -tags with_quic,with_utls ./internal/splicore/...
go build -race -tags with_quic,with_utls -o /external/splicore ./cmd/splicore
python3 scripts/splicore-vless-interop.py /external/runtime reality none
```

Run interop in a fresh loopback-only network **and mount** namespace. Bind a private
synthetic hosts file only inside that namespace so target.synthetic.test resolves
to the local synthetic TLS 1.3 target. The actual host's /etc/hosts is unchanged.
Each campaign has a separate state and cleans private inputs in finally.
The script verifies both clients/users and all REALITY endpoint types, 16 concurrent,
4 MiB integrity, XUDP sequences, negative credentials/security, attribution, reconcile,
SQLite restart, existing-client reconnect, forced client kill and listener reuse.
Vision is rejected by the campaign and all managed entry points. TCP reuse checks set SO_REUSEADDR
to match native listener semantics and distinguish TIME_WAIT from a live listener.

Vision is DEFERRED / UNSUPPORTED under [ADR 0017](../adr/0017-defer-vision-dependency-safety.md).
Formal gates always use default checkptr and race. Do not rebuild diagnostic
sanitizer exceptions for acceptance; preserve the original triage evidence externally.

Required tests include all Vision rejection boundaries, fake builder count=0,
transaction rollback if creation validation is bypassed, and a Vision wire request
rejected before construction. The native traffic test drives flow-none plain/TLS/
REALITY with single/dual user, 16 concurrency, 4 MiB, reconnect and abnormal close;
run it under default race for ten iterations. Real client campaigns verify the full
non-Vision matrix, negative credentials, leak gates, reconcile and recovery.
Verify fixed client SHA256 before reuse; no latest client or dependency upgrade.

Fresh final evidence lives at `D:\splicore-validation\phase5-vision-deferred-20261002`.
Historical Phase 0–4 reports/evidence and migrations 0001–0003 remain immutable.
Audit source scope, dependency/archive equality, index and refs, worktree secrets,
docs/OpenAPI/live responses and all prior protocol/client regressions before review.
