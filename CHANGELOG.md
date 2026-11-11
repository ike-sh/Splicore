# Changelog

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
