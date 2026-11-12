# P2 implementation and evidence map

The baseline is current `origin/main`, with the complete 61-item inventory in
`distribution/historical-features.json`. This map adds measurements to admitted
implementations; it does not admit an excluded historical candidate.

| Area | Current implementation / existing regression | New measurement |
| --- | --- | --- |
| TCP / UDP | `engine/native`, `engine/clientio`, `engine/packetio` | Real OS targets, generated/verified directional streams, paced datagrams |
| VLESS | `engine/native/vless*`, `protocol/vless` | Raw flow-none TCP and XUDP |
| Snell | `engine/native/snell*`, `protocol/snell` | v4/v5/v6 TCP and UDP, existing reuse settings |
| Mieru | `protocol/mieru/backend` | Native TCP and UDP library carriers, TCP/UDP application payload |
| HTTP/H2/QUIC | `streamtransport/native_http.go`, `native_quic.go`; `engine/native/phase31_test.go` | VLESS TLS over generic HTTP, H2 and QUIC streams |
| Standard WireGuard | `wireguardendpoint`; independent `interop_test.go` | Explicit userspace endpoints; real encrypted UDP underlay and in-memory native IP stacks |
| Core/process lifecycle | `cmd/splicore/runtime_test.go`, `clientruntime/*lifecycle_test.go` | Repeated fixture startup/close plus existing process/rebind gates |
| Connection ownership | `engine/clientio/owner_test.go`, native lifecycle tests | Establish/ready/close samples, OS resources/goroutines |
| Buffers / queues | `engine/packetio/*test.go`, protocol/session tests | Allocation/heap trends and optional Go profiles |
| DNS / routing | `networkruntime/*test.go`, native `phase31_dns*`, protected-underlay tests | Existing real resolver/target and negative security gates; no separate DNS throughput SLO |
| UDP sessions | `clientruntime/proxy_udp_lifecycle_test.go`, protocol packet lifecycle tests | Concurrent mixed sessions, per-sequence integrity/loss/RTT |

Paths above are relative to `internal/splicore` unless rooted at `protocol/` or
`cmd/`. Names of existing tests are retained unchanged. The CI performance smoke
is additional to the full default/full/native/Race qualification matrix.

AWG/Phase37, ShadowQUIC, kernel WireGuard and historical SQLite WAL/P1-B
candidates remain outside this performance support inventory. Broad real-hardware
TUN/Wintun and WAN behavior require separate execution. Physical ARM64 is not
inferred from a build or from emulated execution.
