# sing-box v1.14.1 architecture map

- Documentation status: Historical
- Audience: Core developers and upstream reviewers
- Last reviewed: 2026-10-01
- Owner: Upstream maintainers
- Responsibility: Source observations pinned to sing-box v1.14.1 and its full commit.
- Lifecycle: Frozen snapshot; only typo, broken-link or factual corrections.

Evidence scope: commit `1ac1a339cb1223e9c70eae14c44411c75033c02d`.
Paths below refer to **actual baseline source**, not hypothetical future packages.
The tree has 1,557 tracked files, 1,153 Go files; 667 Go files contain 1,905
upstream module-path import occurrences (`rg`, before document additions).
Full baseline ancestry contains 2,723 commits.

## A. Startup and construction

```text
cmd/sing-box/main.go: main → mainCommand.Execute
cmd/sing-box/cmd.go: preRun → include.Context
  → box.Context + context service registries
cmd/sing-box/cmd_run.go: run → readConfig → mergeOptionsList
  → readConfigAt: json.UnmarshalExtendedContext[option.Options]
  → option.Inbound.UnmarshalJSONContext: type → registry.CreateOptions
run → create → box.New(box.Options) → manager.Create → registry.Create
  → protocol/<name>.NewInbound (service/auth/TLS/listener objects)
create → Box.Start → staged manager.Start → inbound.Start → socket bind
```

Registration precedes parsing, since contextual JSON decoding needs an options
factory. `include/registry.go` explicitly composes registries; `include/quic.go`
and other build-tag files choose available implementations. The `box.Context`
function registers both adapter and option registry interfaces.

`box.go:New` retrieves six registries (inbound/outbound/endpoint/DNS/service/
certificate provider), creates logger, network namespace manager, managers,
DNS router, network manager, connection manager, HTTP client manager and router.
It registers these through `github.com/sagernet/sing/service` context DI,
initializes route and DNS rules, constructs configured resources through factories,
and creates optional cache/Clash/V2Ray/NTP services. This context is a dependency
container; it is not Splicore domain state.

## B–D. Interfaces, factories and listeners

`adapter/inbound.go:Inbound` embeds `Lifecycle` and exposes `Type()` and `Tag()`.
Optional `TCPInjectableInbound` and `UDPInjectableInbound` add handler contracts.
`adapter/inbound/adapter.go` supplies type/tag infrastructure;
`common/listener` supplies listener lifecycle, addresses, namespace/socket options,
accept loops and packet handling. TLS, transport and mux are separate helpers.

`adapter/inbound/registry.go:Register[Options]` wraps a typed constructor into
maps of option factories and runtime constructors under a mutex. This is an
explicit registry with generic factory helpers, not a generated global protocol
switch. Some implementations use local switches (Snell versions, TLS and transports).
Duplicate registry entries overwrite upstream maps; Splicore must reject duplicates
in its own composition before passing them downstream.

`adapter/inbound/manager.go:Create` calls the factory; a running manager executes
all start stages before publishing the new instance. TCP is bound by
`common/listener/listener_tcp.go:ListenTCP`; UDP by `listener_udp.go:ListenUDP`.
Snell uses listener `Start` for TCP; VLESS either uses that path or passes sockets
to transport `Serve/ServePacket`. Hysteria2/TUIC bind UDP and give PacketConn to
the sing-quic service, which owns QUIC sessions and streams. QUIC is not a third
independent OS socket type.

## E. User/auth model

| Inbound | Observed authentication storage |
|---|---|
| Snell | `protocol/snell/inbound.go`: v5/v6 `NewMultiService[int]` and `UpdateUsers`, optional per-user `userkey` plus shared server PSK; single-key service when no users |
| VLESS | `protocol/vless/inbound.go`: typed users, indexed UUID/flow arrays passed to sing-vmess VLESS service |
| Hysteria2 | `protocol/hysteria2/inbound.go`: indexed password/name arrays passed to sing-quic `UpdateUsers` |
| TUIC | `protocol/tuic/inbound.go`: indexed UUID/password/name arrays passed to sing-quic |
| Shadowsocks management | `adapter/ssm.go` ManagedSSMServer contract, `service/ssmapi/user.go`: protocol-specific `UpdateUsers` |

Authenticated indexes use `auth.UserFromContext[int]`, then protocol code sets
`adapter.InboundContext.User` when a name exists. An unnamed user may leave
metadata.User empty. There is no cross-protocol persistent Account/Binding/
Credential abstraction. Generated names must therefore be stable **Binding IDs**,
with a generation-scoped lookup, never display names or raw credentials.

Snell inbound accepts versions 5/6; outbound accepts 4/6. Upstream documents v5
without QUIC mode as wire-compatible with v4. Do not claim v5 QUIC, older server
versions, or generic Mihomo support from this statement. Multi-user `userkey`
support must be checked for each client/version independently.

## F. Traffic statistics

`adapter/router.go:ConnectionTracker` hooks TCP, packet and flow routing;
`route/router.go:AppendTracker` adds trackers and `route/route.go` invokes them
after route selection. `common/trafficcontrol/{manager,tracker}.go` wraps connections
with atomic upload/download counters, records metadata/chain and exposes totals,
events and active/closed connection snapshots. These are process-local statistics.

`experimental/v2rayapi/stats.go` optionally counts selected inbound, outbound
and user names, uses atomic counters, and supports reset queries. It is gated by
`with_v2ray_api`, which is **not** in DEFAULT_BUILD_TAGS_OTHERS.
`service/ssmapi/traffic.go` adds Shadowsocks management accounting. None supplies
Splicore durable quota authority or exactly-once usage ingestion. Do not sum
router, native and V2Ray counters for the same payload.

## G. API boundaries

* `experimental/clashapi/server.go`: logs, traffic, connections, groups/proxies,
  route rules, rule sets, DNS/cache and limited configuration compatibility.
* `experimental/clashapi/configs.go`: PATCH changes mode; PUT `updateConfigs`
  returns no content without replacing a Box. A success response is not a full reload.
* `service/api/server.go`: newer API service attaches `daemon.StartedService`,
  gRPC/h2c/TLS and optional dashboard. `daemon/started_service.proto` supplies
  status/log/connection/group streams and endpoint tools. `daemon/instance.go`
  checks/formats **upstream** configs. ManagedService delegates stop/reload.
* `experimental/libbox`: platform/client embedding and command compatibility;
  `experimental/boxdd` manages an upstream daemon/platform integration.
* `experimental/v2rayapi`: stats gRPC compatibility; no Splicore resource API.

Reuse socket, logging, lifecycle and tracker mechanisms behind adapters. Do not
expose these schemas or management paths as `/api/v1`, and do not allow them to
bypass Splicore revision/state authority.

## H–I. State and reload

`option/*.go` models runtime config in memory. `experimental/cachefile/cache.go`
uses sagernet/bbolt for group selections/mode, rule sets, fake IP, DNS cache and
rejected-response cache. It is an operational cache, not a user database.
`service/ssmapi/cache.go` is a separate protocol management persistence concern.

`cmd_run.go:run` on SIGHUP checks config, closes/cancels the old Box, re-reads
files and creates a replacement; failed new startup has no automatic last-known-good
rollback. File edits between check and read are another consistency window.
Manager `Create/Remove` permits internal dynamic mutation, but replacement starts
the new listener **before** closing the old one: same-address replacement can fail.
There is no shared public hot-user interface for these four target protocols,
even where private library services expose UpdateUsers. No durable transaction,
revision fencing or rollback journal exists.

## Lifecycle and remaining tree

`adapter/lifecycle.go`: Initialize → Start → PostStart → Started; adapter helpers
bridge legacy Start methods. `Box.preStart/start` initialize managers, start
outbound/DNS/network/connection then routing, internal services/endpoints,
certificates, inbounds/services, then post-start and started stages. `Box.Close`
closes services/inbounds/certificates/endpoints/outbounds/router/connection/DNS/
network, HTTP clients, internal services and logger; time monitors report stalls.
Startup errors trigger Close, not transactional recovery.

| Tree | Responsibility and evidence |
|---|---|
| `option`, `schema` | contextual typed config parsing and schema descriptions |
| `protocol` | inbound/outbound adapters; group selectors, TUN and endpoints also present |
| `transport` | V2Ray HTTP/WS/gRPC/QUIC/HTTPUpgrade, mux-related and device bridges |
| `common/tls` | NewServer selects std TLS or REALITY; REALITY implementation gated `with_utls`; client engines include platform TLS/uTLS; ECH/ACME/kTLS helpers |
| `route`, `route/rule` | route matching/actions/sniffing, rule sets, dial/connection/network management |
| `dns`, `dns/transport` | DNS rule routing, transports/cache, fake IP and local resolvers |
| `adapter/platform.go`, `common/process`, `common/netns` | interface, permissions, process attribution and OS/network namespace abstractions |
| `service`, `adapter/service` | auxiliary services and generic registry; not application domain services |
| `log` | factory, observable/platform logging and contextual IDs |
| `include`, OS suffixes, `//go:build` | compiled capabilities, platform stubs and library inclusion |
| `cmd/internal`, `release`, workflows | version/build/linker flags, packaging/completions/services and release orchestration |
| `test` | separate Go module with Docker/reference integration tests; root `./...` does not traverse it |

## J. Merge hotspots

Highest conflict: global `option` schema, `box.go` construction/order, protocol
authentication internals, router fast paths, shared listener/TLS/QUIC code.
Medium: include registration and service/daemon hooks, build flags/scripts.
Lowest: new Splicore directories and own docs/adapters. See
[fork boundary](FORK_BOUNDARY.md) for concrete insertion points and limitations.
