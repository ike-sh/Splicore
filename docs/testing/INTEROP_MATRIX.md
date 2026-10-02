# Third-party interoperability release matrix

- Documentation status: Canonical
- Audience: Protocol, client and test developers
- Last reviewed: 2026-10-02
- Owner: Test maintainers
- Responsibility: Planned third-party protocol/client qualification cells and evidence rules.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Phases 2–4 have real Snell, Hysteria2 and TUIC qualification below; other profiles remain
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

## Verified experimental Hysteria2 cells

The full 12-cell HY2 matrix and nine-cell Snell regression were independently
repeated on Ubuntu-24.04 WSL2, using native ext4 state and a race-built server.
Both IPv4 and IPv6 passed again. Loopback-only network namespaces isolate the
existing entrypoints; temporary state/keys/clients were removed. Fresh actual
evidence, hashes and the external Docker cleanup deferral are in the
[Phase 3 acceptance report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md).

| Client | Version | User | Endpoint | TCP | UDP payload / QUIC transport | Trusted CA / correct SNI | Result |
|---|---|---|---|---|---|---|---|
| Mihomo | 1.19.30 | Alice, Bob | IPv4 / IPv6 / domain | PASS | PASS / PASS | PASS | 6 cells PASS |
| sing-box | 1.14.1 | Alice, Bob | IPv4 / IPv6 / domain | PASS | PASS / PASS | PASS | 6 cells PASS |

All 12 cells use 127.0.0.1, ::1 or localhost with independent `hy2.test` SNI.
Each checks 4 MiB integrity, 16 concurrent connections across users, 32 sequenced
UDP packets, reconnect, abnormal close and attributed counter growth under the
race-built server. Wrong password/SNI/CA fail for both clients. A password identifies
its Binding irrespective of a client's local label: Alice's password used with
Bob's label increments Alice only. Saved Alice configs fail after Binding disable;
Bob reconnects. SQLite restart retains disabled state; existing clients reconnect;
re-enable, forced client kill, daemon shutdown and UDP port reuse pass.
Mihomo uses the non-leaf CA pin; sing-box uses explicit CA PEM. No insecure PASS path.
Surge UnsupportedExport; URI/obfs/masquerade are unqualified/deferred.
See [HY2 support](../protocol/HYSTERIA2.md), [workflow](../development/PHASE_3_HYSTERIA2.md)
and [full evidence report](../reports/PHASE_3_HYSTERIA2_VERTICAL_SLICE_REPORT.md).

## Future profile targets

| Protocol/profile | Target clients | Conditions |
|---|---|---|
| Snell v5 server / compatible v4 client | Mihomo, sing-box; Surge where licensed/testing possible | upstream excludes v5 QUIC; test shared PSK/single-user and separately userkey-supported multi-user; no blanket version claim |
| Snell v6 | sing-box; Mihomo/Surge only when verified version supports features | mode/key-length and userkey profile explicit; unknown targets unqualified |
| Hysteria2 | Mihomo, sing-box; official reference for differential | TLS, auth, UDP and obfuscation variants separately |
| TUIC | Mihomo, sing-box | UUID/password, UDP modes, congestion/session/reconnect behavior |
| VLESS/REALITY | Mihomo, compatible Xray client, sing-box reference | UUID/flow/transport/security and public endpoint/SNI/target separation |
| Mieru additional profiles | official client/Mihomo | Nondefault MTU/multiplex/pattern variants require separate runtime qualification; default Phase 8 matrix below |
| FinalMask/Sudoku | official Xray 26.3.27 JSON client | bounded plain TCP Sudoku, prefer_ascii/padding0–3; managed Phase 7 gates |
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

## Verified experimental TUIC v5 cells

| Client | Version | SHA256 | User | Endpoint | TCP | UDP | TLS | Result |
|---|---|---|---|---|---|---|---|---|
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | 127.0.0.1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | 127.0.0.1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | ::1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | ::1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Alice | localhost | PASS | PASS | CA + tuic.synthetic.test | PASS |
| mihomo | 1.19.30 | `20ba567571d9ca642bedecbb01f8092cab0f1679100087ef1a4a2efac0ed5494` | Bob | localhost | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | 127.0.0.1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | 127.0.0.1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | ::1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | ::1 | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Alice | localhost | PASS | PASS | CA + tuic.synthetic.test | PASS |
| sing-box | 1.14.1 | `9334a1c1fe97234911afaedd37226667ebdb3dab2abe383f2c4ae1387706dad9` | Bob | localhost | PASS | PASS | CA + tuic.synthetic.test | PASS |

Each native WSL2 cell uses a race-built server, explicit trusted CA and independent
tuic.synthetic.test SNI, TCP/UDP, 16 concurrent, 4 MiB SHA256 integrity, 32 UDP
sequence responses, reconnect/abnormal close/stats. Wrong UUID/password/SNI/CA and
cross-user UUID/password combination reject. Disabled Binding/Account creation and
SQLite recovery, existing-client reconnect, client kill and UDP release PASS.
Full HY2 12-cell and Snell nine-cell regression PASS after shared refactor.
See [Phase 4 report](../reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md) for client archive
hashes, capability limits, source/platform gates and external cleanup deferral.

## Phase 5 VLESS / REALITY candidate

| Surface | Clients | Users / endpoints | Actual outcome |
|---|---|---|---|
| REALITY, flow none | Mihomo 1.19.30 / sing-box 1.14.1 | Alice/Bob × IPv4/IPv6/domain, 12 cells | TCP/XUDP PASS, default race binary |
| Plain, flow none | Same | Alice/Bob × IPv4, 4 cells | TCP/XUDP PASS, default race binary |
| Static TLS, flow none | Same | Alice/Bob × IPv4, 4 cells | trusted TCP/XUDP PASS, default race binary |
| Vision | All managed inputs/exporters | N/A | DEFERRED / UNSUPPORTED; rejection PASS |
| VLESS URI | Bounded parser/exporter | IPv4/IPv6/domain contract | PASS contract; reference client import NOT QUALIFIED |
| Surge | No qualified VLESS profile | N/A | UnsupportedExport |

Passing campaigns retain concurrency 16, 4 MiB integrity, XUDP sequence, reconnect,
abnormal close, attribution, disable/re-enable, committed SQLite recovery, process
kill and socket release. REALITY wrong UUID/pbk/sid/SNI both clients reject user
payload and retain healthy server. Default checkptr and race remain enabled.
Native Go traffic tests also run ten iterations with single/dual users, 16 concurrent,
4 MiB, reconnect and abnormal close. Vision rejection tests include a missed creation
validator, no authoritative commit, fake builder count=0, direct compiler rejection
and a Vision wire request rejected before constructor dispatch.

The [final report](../reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md) records exact fresh
matrix cells, versions, executable hashes and regression/platform gates. The
[initial report](../reports/PHASE_5_VLESS_REALITY_NATIVE_VERTICAL_SLICE_REPORT.md)
preserves original Vision functional passes and safety failures; they are not part
of the current supported surface. Phase 5 is locally frozen; no Stable declaration.

## Phase 6 Xray duality gate

Compare native/xray using the same script, profiles and fixed clients. Per-engine
campaigns record Alice/Bob TCP/XUDP, REALITY IPv4/IPv6/domain endpoints, concurrency,
large integrity, negative auth/key/short-ID/SNI, reconcile and SQLite regeneration.
Xray counters are unsupported and must stay zero; traffic qualification uses echo
integrity, not native accounting assertions. Actual child crash detection, degraded
health, secret artifact removal and explicit recovery are additional Xray gates.
See [workflow](../development/PHASE_6_XRAY.md) for reference hashes and isolation.

Phase 6 acceptance: native/xray REALITY 12 cells each, plain/TLS four cells per
engine/security, **40/40 PASS** on the same final default-race binary. Snell nine,
Hysteria2 twelve and TUIC twelve regression cells pass. Parent-death cleanup and
unrelated-Xray survival also pass on Linux. See the
[Phase 6 report](../reports/PHASE_6_XRAY_ENGINE_DUALITY_REPORT.md) for exact rows,
private control-socket review after abrupt exit and platform qualification limits.

## Phase 7 managed FinalMask / Sudoku acceptance

| Client | Version | SHA256 | Feature | REALITY | User | TCP | UDP | Result |
|---|---|---|---|---|---|---|---|---|
| Xray | 26.3.27 | `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` | FinalMask TCP / Sudoku | Unsupported combination | Alice | PASS | NOT QUALIFIED | PASS |
| Xray | 26.3.27 | `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed` | FinalMask TCP / Sudoku | Unsupported combination | Bob | PASS | NOT QUALIFIED | PASS |

These cells use Splicore canonical API creation and authorized exporter output,
the existing pinned child supervisor and a default-race Splicore binary on native
ext4 in a loopback-only namespace. Plain TCP, flow none, prefer_ascii, padding0–3;
32 KiB, concurrency16, 4 MiB integrity, reconnect and abnormal close PASS.
Missing mask/wrong password/wrong UUID reject payload; unknown mask rejects config.
Binding reconcile, SQLite ephemeral regeneration, child crash/manual recovery,
ordinary API/CLI secret redaction and socket release PASS. The new managed feature
harness has no payload retry or sleep. Raw reference probes are excluded.
Mihomo/sing-box/Surge/URI masked exports reject; Vision remains unsupported.

Fresh Phase 7 regressions: native REALITY12, standard Xray plain4, Snell9,
Hysteria2 12 and TUIC12 cells PASS. Both features remain Experimental; FinalMask
qualification covers Sudoku only. [Report](../reports/PHASE_7_XRAY_VLESS_EXTENSIONS_REPORT.md).

## Phase 8 managed Mieru matrix

| Client | Version | Users | Endpoint | Underlays | TCP | UDP | Cells |
|---|---|---|---|---|---|---|---|
| Official Mieru | 3.38.0 | Alice / Bob | 127.0.0.1 / ::1 / localhost | TCP / UDP | PASS | PASS | 12 |
| Mihomo | 1.19.30 | Alice / Bob | 127.0.0.1 / ::1 / localhost | TCP / UDP | PASS | PASS | 12 |
| sing-box | 1.14.1 | N/A | N/A | N/A | UnsupportedExport | UnsupportedExport | 0 |

Managed Splicore server uses default-race/checkptr build, SQLite creation/export,
real echo sockets and one-attempt payload tests in a loopback-only namespace.
Each positive cell sends 4 MiB and checks SHA256, reconnect and abrupt close; each
client/endpoint/underlay pair carries 16 mixed Alice/Bob transfers simultaneously.
Two inbounds share usernames but have distinct passwords; cross-inbound auth rejects,
stats stay isolated, restart/reconcile recovery passes. Native 10-cycle tests assert
joined Stop A preserves B and goroutines return to baseline. Source-only embedding
and quota probes are reference evidence and do not replace this matrix.
Exact executable hashes, failures retained and platform limits: [Phase 8 report](../reports/PHASE_8_MIERU_NATIVE_INTEGRATION_REPORT.md).
