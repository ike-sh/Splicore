# Phase 8 Mieru qualification workflow

- Documentation status: Canonical
- Audience: Developers and qualification reviewers
- Last reviewed: 2026-10-02
- Owner: Test maintainers
- Responsibility: Reproduce native Mieru ownership and protected managed acceptance.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Pin official v3.38.0/full commit and client archive/executable SHA256 before use.
Keep clients, binaries, state, logs, caches and private configs outside Git.
The [source roadmap](../architecture/MIERU_INTEGRATION.md) and
[implementation ADR](../adr/0020-mieru-owned-native-embedding.md) define the scope.

## Required gates

1. `go test -count=1 -tags with_quic,with_utls ./internal/splicore/... ./cmd/splicore/...`.
2. Linux default `go test -race` with the same tags; add splicore_xray_integration
   and SPLICORE_XRAY_BINARY pointing to the existing exact Xray artifact for integration gates.
3. `TestMieruNativeMultiInboundLifecycle10x`: ten cycles on each underlay, two
   inbounds, two users, 16 concurrent transfers, UDP and 4 MiB integrity. Joined
   Close gives exact binding/inbound sums, active zero and goroutines back to baseline.
4. Admission-before-Activate, response-after-upload-EOF, conflict, startup/health/
   commit compensation, closed DB plaintext scan and SQLite reopen identity tests.
5. Build splicore-race-default, official Mieru and pinned Mihomo outside source.
   Run [managed driver](../../scripts/splicore-mieru-interop.py) with runtime/evidence
   directories in a Linux network/mount namespace containing only loopback and
   synthetic hosts. No external proxy targets. Every payload is attempted once.
6. Official client uses foreground `mieru run`, private MIERU_CONFIG_JSON_FILE,
   no update check; no permanent daemon server. Mihomo opens its SOCKS listener
   before tunnel.OnRunning, so the driver uses one synchronous same-config PUT
   on its private UDS controller as a readiness barrier before any payload.
   This waits on the actual executor mutex; no sleeps or traffic retry.
7. Official/Mihomo × Alice/Bob × IPv4/IPv6/domain × TCP/UDP underlays, exact
   payload counters, mixed 16 concurrency, 4 MiB hash, reconnect/abrupt close,
   multi-inbound isolation, expected wrong credentials, recovery and binding reconcile.
   Abrupt UDP peer exit has no reliable EOF; joined inbound Close is the cleanup gate.
8. Fuzz only FuzzCanonicalCreation and FuzzMieruProfileExporter for bounded campaigns;
   do not fuzz/rewrite official wire/crypto. Run formal OpenAPI/live-response/docs checks.
9. Fresh Snell/HY2/TUIC/VLESS-native/VLESS-xray critical client cells plus Sudoku
   feature campaign on the current candidate default-race binary. Record exact scope.
10. Windows full units/build, Linux amd64 gates, Linux arm64 compile, selected
    dependency/license/build-size audit and final source/NoBrand/Git scope hashes.

Official quota reference testing is separate from Splicore feature acceptance.
All children are joined; private keys/configs/databases deleted in finally, safe
envelopes redact export content before archival. Scan live secrets against logs,
ordinary API/CLI/doctor, argv and closed SQLite bytes. No Docker query/touch.
Phase 8 is locally frozen after the authorized single commit and main fast-forward;
push/tag/release NONE. The Phase 9 branch is prepared; implementation has not started.
[Freeze report](../reports/PHASE_8_FREEZE_REPORT.md). Exact integration evidence:
[Phase 8 report](../reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md).
