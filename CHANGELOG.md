# Changelog

## v0.6.2

Qualified convergence scope with UDP session cancellation joining its in-flight
socket-close callback before retirement. Preserve the original immediate rebind,
five-second shutdown deadline and all traffic/resource assertions; require a
deterministic blocked-close ownership regression on both native profiles.
v0.6.0 and v0.6.1 tags stay immutable and unpublished. Scope and exclusions remain
explicit in [the release notes](docs/releases/v0.6.2.md).

## v0.6.1 — unpublished candidate

Qualified native historical convergence on v0.5.0: XHTTP H3, HTTP/H2/QUIC
carriers, standard WireGuard, Snell v4/v5, managed routing/DNS/timestamps and
Mieru deadline ownership. ShadowQUIC restoration is ISOLATED_NOT_QUALIFIED and
excluded after its formal v0.6.0 peer restart campaign failed. The Linux kernel
WireGuard backend is also isolated after repeated hosted concurrent fresh IPv6
UDP failure; standard userspace WireGuard remains. The unpublished
v0.6.0 tag remains immutable. AWG is retired and WAL/P1-B remains excluded.
ARM64 remains BUILD ONLY. See [scope and qualification](docs/releases/v0.6.1.md).

## v0.6.0 — unpublished candidate

Restores native XHTTP H3, HTTP/H2/QUIC carriers, ShadowQUIC, standard WireGuard,
Snell v4/v5 DRS/QUIC and managed routing/DNS/timestamp behavior on the v0.5.0 line.
Includes typed Windows UDP truncation recovery, Mieru deadline adaptation and
strict independent-peer, lifecycle, native platform and full Linux Race gates.
AmneziaWG is retired; WAL/P1-B remains excluded. ARM64 remains BUILD ONLY.
See [scope and qualification limits](docs/releases/v0.6.0.md).

## v0.5.0

Adds native VLESS Encryption to the v0.4.0 single-binary mainline through PR #6.

- Hybrid ML-KEM-768/X25519 handshakes, AES-GCM/ChaCha20-Poly1305 records,
  native/xorpub/random modes, and bounded 1-RTT/0-RTT ticket/replay handling.
- Encrypted inbound-owned decryption credentials, public client projections,
  offline `vlessenc` key generation and fail-closed pinned Xray JSON export.
- Native TLS/REALITY and Vision composition, plain/encrypted/Sudoku process
  regressions, and independent official Xray-core v26.10.21 peer tests.
- Canonical-checkout preflight, versioned local hooks, one-main development
  policy, and feature-presence/native interoperability release gates.

Windows/Linux amd64 are natively qualified within the documented scope; both
ARM64 targets remain BUILD ONLY. Android/v2rayNG device testing and Windows
Race are NOT EXECUTED. Other historical gaps remain deferred, and the Windows
WireGuard Hotfix remains NOT QUALIFIED. See [release notes](docs/releases/v0.5.0.md).

## v0.4.0

First downloadable binary release of the current native foreground core. This
pre-1.0 minor version explicitly separates the current capability/configuration
line from v0.3.0 Frozen; it is not a backward-compatible v0.3.1 patch.

- Windows owner-restricted local pipe and Linux private Unix control transport.
- Single-binary help/version/check/run/stop, real native VLESS listener/traffic,
  graceful shutdown and persisted restart, using the existing native core.
- Current-main Hysteria protected-underlay and Provider Fetch lifecycle fixes.
- Four CGO0 targets; native amd64 qualification on Windows/Linux, ARM64 build only.
- Tag-only release automation, source/third-party notices, archive manifests,
  checksums and downloaded-product verification.

Frozen WireGuard endpoints, ShadowQUIC, VLESS Encryption, XHTTP H3 and extra
generic stream carriers are not restored. Phase37, unadmitted SQLite WAL changes
and the unqualified Windows WireGuard Hotfix are excluded. See the full
[v0.4.0 release notes](docs/releases/v0.4.0.md) for qualification limits.

## v0.3.0

Historical Phase36 Frozen source release. Its existing tag/release and capability
history remain unchanged; this changelog does not retroactively redefine them.
