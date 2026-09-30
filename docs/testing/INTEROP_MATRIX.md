# Third-party interoperability release matrix

- Documentation status: Canonical
- Audience: Protocol, client and test developers
- Last reviewed: 2026-10-01
- Owner: Test maintainers
- Responsibility: Planned third-party protocol/client qualification cells and evidence rules.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

All entries are **planned / NOT RUN for Splicore** in Phase 0. Baseline unit tests
are not a substitute. Pin server full commit/build tags, client version/digest,
wire feature, exporter schema and OS/network setup for each qualification row.

| Protocol/profile | Target clients | Conditions |
|---|---|---|
| Snell v5 server / compatible v4 client | Mihomo, sing-box; Surge where licensed/testing possible | upstream excludes v5 QUIC; test shared PSK/single-user and separately userkey-supported multi-user; no blanket version claim |
| Snell v6 | sing-box; Mihomo/Surge only when verified version supports features | mode/key-length and userkey profile explicit; unknown targets unqualified |
| Hysteria2 | Mihomo, sing-box; official reference for differential | TLS, auth, UDP and obfuscation variants separately |
| TUIC | Mihomo, sing-box | UUID/password, UDP modes, congestion/session/reconnect behavior |
| VLESS/REALITY | Mihomo, compatible Xray client, sing-box reference | UUID/flow/transport/security and public endpoint/SNI/target separation |
| Mieru (future) | official client; Mihomo only if tested implementation supports it | native embedding and TCP/UDP underlays, auth/MTU/traffic-pattern variants |
| FinalMask/Sudoku (future) | exact fork-compatible reference client | identify provenance/wire spec first; not stock Xray assumed support |
| New native protocol (future) | independent reference and qualified native client | specification/vectors/security review required |

Every supported cell covers TCP, UDP **payload** where supported, IPv4, IPv6,
domain endpoint, DNS/route behavior, authentication success/failure, cross-user
isolation, reconnect, large transfer, concurrent sessions, abnormal close and
server restart. Add rate/quota/expiry/rotation checks across two simultaneous
protocol bindings on one Account. Underlay UDP is a separate matrix dimension.

Use N/A only for a declared unsupported capability. A failed claimed capability
blocks that profile/client combination; do not turn it into N/A after failure.
Golden render and target client's config-check must precede live tests, but both
are insufficient alone. Reject silent feature omission in exported subscriptions.

Surge live testing requires a legally usable installation/platform. If unavailable,
record the contract/render result separately and keep **Surge live interop unqualified**.
An unrelated client pass cannot clear this gate. Release manifests contain qualified
client/profile pairs, limitations and evidence links; capability endpoint reports
compiled vs qualified distinctly.
