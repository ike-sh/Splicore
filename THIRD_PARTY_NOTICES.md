# Third-party notices — Phase 17 internal development snapshot

- Documentation status: Experimental
- Audience: Maintainers and distributors
- Last reviewed: 2026-10-06
- Owner: Splicore maintainers
- Responsibility: Exact selected module license/copyright texts.
- Lifecycle: Regenerate after dependency graph changes.

Root LICENSE and NOTICE.md remain authoritative for Splicore derivative provenance.
Phase 21 adds independent Gorilla WebSocket v1.5.3 (BSD-2-Clause) and uses the
already selected grpc-go v1.80.0 (Apache-2.0) directly. Their complete notices are
listed below. No Xray, sing-box or Mihomo implementation source is imported.
This inventory records locally materialized selected modules, including test/tool
dependencies. Full graph-only non-linked nodes are listed in external evidence;
they are not represented as linked product code. No publication is performed.

License/copyright/NOTICE/AUTHORS texts below are preserved verbatim from the
selected module cache. go mod verify passed. Concrete product modules are also
verified against the three binary metadata inventories.

| Module | Selected version | Preserved notices |
| --- | --- | --- |
| github.com/andybalholm/brotli | v1.1.0 | [LICENSE](licenses/third-party/github.com/andybalholm/brotli/v1.1.0/LICENSE) |
| github.com/apernet/quic-go | v0.63.1-0.20261004180939-a10df75c260c | [LICENSE](licenses/third-party/github.com/apernet/quic-go/v0.63.1-0.20261004180939-a10df75c260c/LICENSE) |
| github.com/cespare/xxhash/v2 | v2.3.0 | [LICENSE.txt](licenses/third-party/github.com/cespare/xxhash/v2/v2.3.0/LICENSE.txt) |
| github.com/dustin/go-humanize | v1.0.1 | [LICENSE](licenses/third-party/github.com/dustin/go-humanize/v1.0.1/LICENSE) |
| github.com/enfein/mieru/v3 | v3.38.0 | [LICENSE](licenses/third-party/github.com/enfein/mieru/v3/v3.38.0/LICENSE) |
| github.com/go-logr/logr | v1.4.3 | [LICENSE](licenses/third-party/github.com/go-logr/logr/v1.4.3/LICENSE) |
| github.com/go-logr/stdr | v1.2.2 | [LICENSE](licenses/third-party/github.com/go-logr/stdr/v1.2.2/LICENSE) |
| github.com/gofrs/uuid/v5 | v5.5.1 | [LICENSE](licenses/third-party/github.com/gofrs/uuid/v5/v5.5.1/LICENSE) |
| github.com/gorilla/websocket | v1.5.3 | [LICENSE](licenses/third-party/github.com/gorilla/websocket/v1.5.3/LICENSE) |
| github.com/golang/protobuf | v1.5.4 | [AUTHORS](licenses/third-party/github.com/golang/protobuf/v1.5.4/AUTHORS), [LICENSE](licenses/third-party/github.com/golang/protobuf/v1.5.4/LICENSE) |
| github.com/google/btree | v1.1.3 | [LICENSE](licenses/third-party/github.com/google/btree/v1.1.3/LICENSE) |
| github.com/google/go-cmp | v0.7.0 | [LICENSE](licenses/third-party/github.com/google/go-cmp/v0.7.0/LICENSE) |
| github.com/google/pprof | v0.0.0-20260802141513-ef3492d7dac3 | [AUTHORS](licenses/third-party/github.com/google/pprof/v0.0.0-20260802141513-ef3492d7dac3/AUTHORS), [LICENSE](licenses/third-party/github.com/google/pprof/v0.0.0-20260802141513-ef3492d7dac3/LICENSE) |
| github.com/google/uuid | v1.6.0 | [LICENSE](licenses/third-party/github.com/google/uuid/v1.6.0/LICENSE) |
| github.com/hashicorp/golang-lru/v2 | v2.0.7 | [LICENSE](licenses/third-party/github.com/hashicorp/golang-lru/v2/v2.0.7/LICENSE) |
| github.com/klauspost/compress | v1.19.1 | [LICENSE](licenses/third-party/github.com/klauspost/compress/v1.19.1/LICENSE) |
| github.com/klauspost/cpuid/v2 | v2.3.0 | [LICENSE](licenses/third-party/github.com/klauspost/cpuid/v2/v2.3.0/LICENSE) |
| github.com/mattn/go-isatty | v0.0.24 | [LICENSE](licenses/third-party/github.com/mattn/go-isatty/v0.0.24/LICENSE) |
| github.com/metacubex/utls | v1.8.7 | [LICENSE](licenses/third-party/github.com/metacubex/utls/v1.8.7/LICENSE) |
| github.com/miekg/dns | v1.1.72 | [AUTHORS](licenses/third-party/github.com/miekg/dns/v1.1.72/AUTHORS), [COPYRIGHT](licenses/third-party/github.com/miekg/dns/v1.1.72/COPYRIGHT), [LICENSE](licenses/third-party/github.com/miekg/dns/v1.1.72/LICENSE) |
| github.com/ncruces/go-strftime | v1.0.0 | [LICENSE](licenses/third-party/github.com/ncruces/go-strftime/v1.0.0/LICENSE) |
| github.com/quic-go/go-ossfuzz-seeds | v0.1.0 | [LICENSE](licenses/third-party/github.com/quic-go/go-ossfuzz-seeds/v0.1.0/LICENSE) |
| github.com/quic-go/qpack | v0.6.0 | [LICENSE.md](licenses/third-party/github.com/quic-go/qpack/v0.6.0/LICENSE.md) |
| github.com/quic-go/quic-go | v0.63.0 | [LICENSE](licenses/third-party/github.com/quic-go/quic-go/v0.63.0/LICENSE) |
| github.com/refraction-networking/utls | v1.8.2 | [LICENSE](licenses/third-party/github.com/refraction-networking/utls/v1.8.2/LICENSE) |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | [LICENSE](licenses/third-party/github.com/remyoudompheng/bigfft/v0.0.0-20230129092748-24d4a6f8daec/LICENSE) |
| github.com/stretchr/testify | v1.12.1 | [LICENSE](licenses/third-party/github.com/stretchr/testify/v1.12.1/LICENSE) |
| github.com/vishvananda/netlink | v1.3.1 | [LICENSE](licenses/third-party/github.com/vishvananda/netlink/v1.3.1/LICENSE) |
| github.com/vishvananda/netns | v0.0.5 | [LICENSE](licenses/third-party/github.com/vishvananda/netns/v0.0.5/LICENSE) |
| go.opentelemetry.io/auto/sdk | v1.2.1 | [LICENSE](licenses/third-party/go.opentelemetry.io/auto/sdk/v1.2.1/LICENSE) |
| go.opentelemetry.io/otel | v1.43.0 | [LICENSE](licenses/third-party/go.opentelemetry.io/otel/v1.43.0/LICENSE) |
| go.opentelemetry.io/otel/metric | v1.43.0 | [LICENSE](licenses/third-party/go.opentelemetry.io/otel/metric/v1.43.0/LICENSE) |
| go.opentelemetry.io/otel/sdk | v1.43.0 | [LICENSE](licenses/third-party/go.opentelemetry.io/otel/sdk/v1.43.0/LICENSE) |
| go.opentelemetry.io/otel/sdk/metric | v1.43.0 | [LICENSE](licenses/third-party/go.opentelemetry.io/otel/sdk/metric/v1.43.0/LICENSE) |
| go.opentelemetry.io/otel/trace | v1.43.0 | [LICENSE](licenses/third-party/go.opentelemetry.io/otel/trace/v1.43.0/LICENSE) |
| go.uber.org/mock | v0.5.2 | [AUTHORS](licenses/third-party/go.uber.org/mock/v0.5.2/AUTHORS), [LICENSE](licenses/third-party/go.uber.org/mock/v0.5.2/LICENSE) |
| go.yaml.in/yaml/v3 | v3.0.5 | [LICENSE](licenses/third-party/go.yaml.in/yaml/v3/v3.0.5/LICENSE), [NOTICE](licenses/third-party/go.yaml.in/yaml/v3/v3.0.5/NOTICE) |
| golang.org/x/crypto | v0.54.0 | [LICENSE](licenses/third-party/golang.org/x/crypto/v0.54.0/LICENSE) |
| golang.org/x/exp | v0.0.0-20260410095643-746e56fc9e2f | [LICENSE](licenses/third-party/golang.org/x/exp/v0.0.0-20260410095643-746e56fc9e2f/LICENSE) |
| golang.org/x/mod | v0.38.0 | [LICENSE](licenses/third-party/golang.org/x/mod/v0.38.0/LICENSE) |
| golang.org/x/net | v0.57.0 | [LICENSE](licenses/third-party/golang.org/x/net/v0.57.0/LICENSE) |
| golang.org/x/sync | v0.22.0 | [LICENSE](licenses/third-party/golang.org/x/sync/v0.22.0/LICENSE) |
| golang.org/x/sys | v0.47.0 | [LICENSE](licenses/third-party/golang.org/x/sys/v0.47.0/LICENSE) |
| golang.org/x/text | v0.40.0 | [LICENSE](licenses/third-party/golang.org/x/text/v0.40.0/LICENSE) |
| golang.org/x/time | v0.15.0 | [LICENSE](licenses/third-party/golang.org/x/time/v0.15.0/LICENSE) |
| golang.org/x/tools | v0.48.0 | [LICENSE](licenses/third-party/golang.org/x/tools/v0.48.0/LICENSE) |
| golang.zx2c4.com/wintun | v0.0.0-20230126152724-0fa3db229ce2 | [LICENSE](licenses/third-party/golang.zx2c4.com/wintun/v0.0.0-20230126152724-0fa3db229ce2/LICENSE) |
| golang.zx2c4.com/wireguard/windows | v0.5.3 | [COPYING](licenses/third-party/golang.zx2c4.com/wireguard/windows/v0.5.3/COPYING) |
| gonum.org/v1/gonum | v0.17.0 | [AUTHORS](licenses/third-party/gonum.org/v1/gonum/v0.17.0/AUTHORS), [LICENSE](licenses/third-party/gonum.org/v1/gonum/v0.17.0/LICENSE) |
| google.golang.org/genproto/googleapis/rpc | v0.0.0-20260401024825-9d38bb4040a9 | [LICENSE](licenses/third-party/google.golang.org/genproto/googleapis/rpc/v0.0.0-20260401024825-9d38bb4040a9/LICENSE) |
| google.golang.org/grpc | v1.80.0 | [AUTHORS](licenses/third-party/google.golang.org/grpc/v1.80.0/AUTHORS), [LICENSE](licenses/third-party/google.golang.org/grpc/v1.80.0/LICENSE), [NOTICE.txt](licenses/third-party/google.golang.org/grpc/v1.80.0/NOTICE.txt) |
| google.golang.org/protobuf | v1.36.11 | [LICENSE](licenses/third-party/google.golang.org/protobuf/v1.36.11/LICENSE) |
| gopkg.in/check.v1 | v0.0.0-20161208181325-20d25e280405 | [LICENSE](licenses/third-party/gopkg.in/check.v1/v0.0.0-20161208181325-20d25e280405/LICENSE) |
| gopkg.in/yaml.v3 | v3.0.1 | [LICENSE](licenses/third-party/gopkg.in/yaml.v3/v3.0.1/LICENSE), [NOTICE](licenses/third-party/gopkg.in/yaml.v3/v3.0.1/NOTICE) |
| gvisor.dev/gvisor | v0.0.0-20261004063249-f57b8fc79db4 | [AUTHORS](licenses/third-party/gvisor.dev/gvisor/v0.0.0-20261004063249-f57b8fc79db4/AUTHORS), [LICENSE](licenses/third-party/gvisor.dev/gvisor/v0.0.0-20261004063249-f57b8fc79db4/LICENSE) |
| lukechampine.com/blake3 | v1.3.0 | [LICENSE](licenses/third-party/lukechampine.com/blake3/v1.3.0/LICENSE) |
| modernc.org/cc/v4 | v4.29.2 | [LICENSE](licenses/third-party/modernc.org/cc/v4/v4.29.2/LICENSE) |
| modernc.org/ccgo/v4 | v4.35.0 | [LICENSE](licenses/third-party/modernc.org/ccgo/v4/v4.35.0/LICENSE) |
| modernc.org/fileutil | v1.4.0 | [AUTHORS](licenses/third-party/modernc.org/fileutil/v1.4.0/AUTHORS), [LICENSE](licenses/third-party/modernc.org/fileutil/v1.4.0/LICENSE) |
| modernc.org/gc/v2 | v2.6.5 | [LICENSE](licenses/third-party/modernc.org/gc/v2/v2.6.5/LICENSE) |
| modernc.org/gc/v3 | v3.1.5 | [LICENSE](licenses/third-party/modernc.org/gc/v3/v3.1.5/LICENSE) |
| modernc.org/goabi0 | v0.2.0 | [AUTHORS](licenses/third-party/modernc.org/goabi0/v0.2.0/AUTHORS), [LICENSE](licenses/third-party/modernc.org/goabi0/v0.2.0/LICENSE) |
| modernc.org/libc | v1.75.7 | [AUTHORS](licenses/third-party/modernc.org/libc/v1.75.7/AUTHORS), [LICENSE](licenses/third-party/modernc.org/libc/v1.75.7/LICENSE), [LICENSE-3RD-PARTY.md](licenses/third-party/modernc.org/libc/v1.75.7/LICENSE-3RD-PARTY.md) |
| modernc.org/mathutil | v1.7.1 | [AUTHORS](licenses/third-party/modernc.org/mathutil/v1.7.1/AUTHORS), [LICENSE](licenses/third-party/modernc.org/mathutil/v1.7.1/LICENSE) |
| modernc.org/memory | v1.12.1 | [AUTHORS](licenses/third-party/modernc.org/memory/v1.12.1/AUTHORS), [LICENSE](licenses/third-party/modernc.org/memory/v1.12.1/LICENSE), [LICENSE-GO](licenses/third-party/modernc.org/memory/v1.12.1/LICENSE-GO), [LICENSE-LOGO](licenses/third-party/modernc.org/memory/v1.12.1/LICENSE-LOGO), [LICENSE-MMAP-GO](licenses/third-party/modernc.org/memory/v1.12.1/LICENSE-MMAP-GO) |
| modernc.org/opt | v0.2.0 | [AUTHORS](licenses/third-party/modernc.org/opt/v0.2.0/AUTHORS), [LICENSE](licenses/third-party/modernc.org/opt/v0.2.0/LICENSE) |
| modernc.org/sortutil | v1.2.1 | [AUTHORS](licenses/third-party/modernc.org/sortutil/v1.2.1/AUTHORS), [LICENSE](licenses/third-party/modernc.org/sortutil/v1.2.1/LICENSE) |
| modernc.org/sqlite | v1.59.0 | [AUTHORS](licenses/third-party/modernc.org/sqlite/v1.59.0/AUTHORS), [LICENSE](licenses/third-party/modernc.org/sqlite/v1.59.0/LICENSE), [LICENSE-SQLITE](licenses/third-party/modernc.org/sqlite/v1.59.0/LICENSE-SQLITE), [LICENSE-SQLITE_VEC](licenses/third-party/modernc.org/sqlite/v1.59.0/LICENSE-SQLITE_VEC) |
| modernc.org/strutil | v1.2.1 | [AUTHORS](licenses/third-party/modernc.org/strutil/v1.2.1/AUTHORS), [LICENSE](licenses/third-party/modernc.org/strutil/v1.2.1/LICENSE) |
| modernc.org/token | v1.1.0 | [LICENSE](licenses/third-party/modernc.org/token/v1.1.0/LICENSE) |

## Replacement dependency decisions

| Module/version | Purpose | Why standard library is insufficient | License text |
| --- | --- | --- | --- |
| github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c | HY2 QUIC/HTTP3 transport | Go has no QUIC/HTTP3 substrate; use official fork, no protocol primitive rewrite | MIT |
| github.com/quic-go/quic-go v0.63.0 | TUIC QUIC/datagrams | Go has no QUIC substrate | MIT |
| github.com/metacubex/utls v1.8.7 | Existing independent REALITY/TLS integration | Standard TLS lacks required REALITY API and client handshake profile | BSD terms |
| github.com/miekg/dns v1.1.72 | Managed DNS wire, TTL, TCP/UDP and TLS exchange | net.Resolver does not expose required DNS transport/answer policy | BSD terms |
| github.com/vishvananda/netlink v1.3.1 | Existing owned Linux route/underlay host boundary | net has no netlink route/rule API | Apache-2.0 |
| gvisor.dev/gvisor v0.0.0-20261004063249-f57b8fc79db4 | Official Native TUN TCP/IP stack | No standard userspace TCP/IP stack; custom implementation prohibited | Apache-2.0 |
| github.com/enfein/mieru/v3 v3.38.0 | Official Mieru protocol SDK | Preserve official protocol without custom rewrite | GPLv3 text; source headers GPL-3.0-or-later |
| lukechampine.com/blake3 v1.3.0 | SS2022 BLAKE3 primitive | Standard library lacks BLAKE3; custom primitive prohibited | MIT |

Exact source/notice hashes: external round2-license-attempt2/inventory.json.
SagerNet full graph nodes: 0. No local replace directive, vendored substitute,
cache-source modification or external-core production subprocess was added.

Orphan WinDivert binaries and their adjacent license were removed from the active
tree in Phase 21 Deep Core Purge; their exact bytes remain in precleanup evidence.
No retained source embeds or derives from those driver assets. Historical sing-box GPL attribution remains even
though its active Go dependencies and inherited dead runtime were removed.
