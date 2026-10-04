# System Integration

- Documentation status: Canonical
- Audience: Core developers and operators
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Host network intent, ownership, restoration and platform qualification.
- Lifecycle: Update with the supported ownership and qualification boundary.

TUN is Experimental and opt-in. SOCKS5, HTTP and mixed listeners use the existing
client runtime, routing/DNS/policy graph, outbound adapters and counters. One daemon,
one service, no protocol fields in the host plan, and no upstream source edits.
Phase 13 is locally frozen under its [freeze report](reports/PHASE_13_FREEZE_REPORT.md),
without changing platform qualification or Windows activation guards.

## Transaction and recovery

SQLite schema 7 owns desired LocalInbound/HostIntegration configuration. The separate
private `StateDirectory/host-network/journal.json` owns operational before/after
records only. Persist all snapshots and intents, create interface/addresses, start
the official gVisor stack, apply capture/proxy steps, read back and acknowledge each
write, then commit/publish. Rollback stops packet readers before releasing the device
and compensates in reverse order. Stop failures after the SQLite commit return an
error and degraded health with the committed transaction, rather than pretending
the desired-state transaction was rolled back.

Compare current state with both recorded states; retain external changes and report
conflict. Never flush a route table, reset a network stack, modify shell profiles or
clear somebody else's proxy. Corrupt/oversized/foreign-owned journals reject; no
guessed deletion. Narrow control locks do not serialize payload I/O.

Linux scope includes boot ID, network namespace and service UID. Rules/routes in
unused tables/priorities protect the dedicated daemon UID through the existing main
table, including dynamic node DNS IPs, native servers and managed DNS.
Applications under the daemon UID bypass capture; use the dedicated service account.
If an existing VPN redirects the main table, that remains the underlay authority;
full roaming and arbitrary VPN coexistence are not certified.

## Platform limits

[Linux](PLATFORM_LINUX.md) has owned dual-stack auto-route and TCP/UDP53 interception.
WSL disposable namespaces provide kernel evidence, never native host certification.
[Windows](PLATFORM_WINDOWS.md) has separate owned Wintun adapter/session operations,
typed LAN WinINET API snapshots and transactional bypass reconciliation. Stateful
fixtures cover partial creation, exact restoration and external mutation. Runtime
underlay sockets consume the unified protection contract, exercised through actual
adapters and the fake Windows journal/backend. The original activation guards and
auto-route rejection remain before mutation. Fixture PASS does not qualify an actual
Windows host transaction or application traffic. Development-host mutation tests
are prohibited; real Windows TUN/auto-route/WinINET remain NOT CERTIFIED.

Host DNS configuration is never changed. Intercept only traffic crossing TUN on
UDP/TCP53, using the shared managed DNS engine. DoH, FakeIP and full roaming are
deferred; ICMP forwarding is rejected. DNS IP/domain observations are bounded,
TTL-limited and removed for competing names; shared-IP routing can use CIDRs.

Use protected API/CLI plan/apply operations. `network repair` requires stopped client
listeners, repairs only recorded resources and has no system-wide reset. `doctor`
is passive. Support bundles expose counts, enums and redacted TUN metadata.

See [local inbound](architecture/LOCAL_INBOUND_MODEL.md), [client runtime](architecture/CLIENT_RUNTIME.md),
[ownership ADR](adr/0027-tun-host-network-ownership.md),
[journal ADR](adr/0028-network-mutation-journal.md),
[proxy ADR](adr/0029-system-proxy-restoration.md),
[Windows ownership ADR](adr/0030-windows-host-network-ownership.md),
[recovery](RECOVERY.md), [testing](TESTING.md),
[source audit](development/PHASE_13_TUN_AUDIT.md).

## Unified runtime underlay

Routing/DNS/policy selects the logical action first. A daemon-shared typed factory
then creates the selected runtime's protected TCP or packet capability. It never
chooses DIRECT/proxy or bypasses a user LAN rule. Purpose, runtime ID and generation
identify DIRECT, proxy infrastructure, arbitrary server target, DNS/bootstrap,
health, provider fetch or local control. Arbitrary target history is not stored.

Native adapters inject protected registries and a per-adapter NetworkManager into
unmodified official dialers; QUIC UDPListener uses the same Control. Mieru official
Dialer/PacketDialer/Resolver hooks share the provider. There is no external-child
protection path or process runtime. No artifact/wire edits.

New snapshots bootstrap fresh before reuse-key calculation and endpoint preparation.
Effective infrastructure protections are desired plus all retained generations.
Protection is prepared/read back before publication; adapter/query/socket workers
retire before endpoint refs release. Reused TUN keeps its interface identity.
Cleanup failure retains reference/journal debt and reports degraded health. Crash
recovery restores journaled ownership, never invents references to dead sockets.

Linux uses the mature RoutingMark primitive plus journaled daemon UID/main-table
rules and resource readback. Windows composes mature interface binding with durable
endpoint reconciliation and mandatory readback; the native backend remains
unqualified. System DNS stubs and independent mDNS/resolved paths reject when their
protection cannot be guaranteed. Configure an explicit bootstrap-safe UDP/TCP/DoT
resolver; DoT keeps the original TLS name. No-TUN paths perform no route or socket
protection mutation or privilege check.

See [ADR 0031](adr/0031-unified-underlay-protection.md) and the
[current closure report](reports/PHASE_13_UNDERLAY_RUNTIME_CLOSURE_REPORT.md).
