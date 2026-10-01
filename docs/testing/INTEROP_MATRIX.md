# Third-party interoperability release matrix

- Documentation status: Canonical
- Audience: Protocol, client and test developers
- Last reviewed: 2026-10-01
- Owner: Test maintainers
- Responsibility: Planned third-party protocol/client qualification cells and evidence rules.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Phase 2 has real Snell traffic qualification below; other profiles remain
**planned / NOT RUN**. Pin server source/build, client version/digest, feature,
export contract and OS/network setup for each row. Baseline unit tests are separate.

## Verified experimental Snell cells

| Server | Client | Client version | Server/client wire | TCP | UDP payload | IPv4 endpoint | IPv6 endpoint | Domain endpoint | Result |
|---|---|---|---|---|---|---|---|---|---|
| Splicore native | Mihomo | 1.19.30 | 5 / 4 | PASS | PASS | PASS | PASS | PASS | experimental PASS |
| Splicore native | sing-box | 1.14.1 | 5 / 4 | PASS | PASS | PASS | PASS | PASS | experimental PASS |
| Splicore native | sing-box | 1.14.1 | 6 / 6 | PASS | PASS | PASS | PASS | PASS | experimental PASS |
| Splicore native | Mihomo | 1.19.30 | 6 / unsupported | N/A | N/A | contract | contract | contract | UnsupportedExport |
| Splicore native | Surge | Mac 6.7.0 / iOS 5.20.0 | 5 / 4; 6 / 6 | NOT RUN | NOT RUN | contract | contract | contract | exporter contract only |

Actual endpoint literals are 127.0.0.1, ::1 and localhost. Each live cell exercises
TCP/UDP payload integrity, 16 concurrent connections, 4 MiB transfer, reconnect,
abnormal close, session cleanup and counter growth. Wrong PSK/version/port and
stopped server fail without panic; committed state survives actual daemon restart.
Surge has no licensed runtime in this Linux/Windows environment. It remains
unqualified for live traffic; its IPv6 formatting follows official host/port grammar
without parser validation. No multi-user/policy/obfs/QUIC mode qualification.

See [Phase 2 report](../reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md) for archive
and executable hashes, platform gates and exact limits. The
[workflow](../development/PHASE_2_SNELL.md) describes reproducing external evidence.

## Future profile targets

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
