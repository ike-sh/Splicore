# Linux Host Integration

- Documentation status: Canonical
- Audience: Core developers and operators
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Linux device, policy routes, privileges and recovery qualification.
- Lifecycle: Update with the supported ownership and qualification boundary.

Reuse pinned official sing-tun/gVisor through public APIs with external device
configuration and upstream host DNS disabled. Splicore owns address/route/rule CRUD
through the pinned netlink API. Tables 24000–24999 and priorities 10000–10999 are
selected only when unused by routes and rules; protocol 198 tags owned routes.
Existing routes, VPNs, interfaces and DNS files are preserved. Exact rule action,
selectors, metrics, attributes and installed interface index protect restoration.

TUN requires `/dev/net/tun` and CAP_NET_ADMIN. Standard SOCKS/HTTP service retains
CAP_NET_BIND_SERVICE only. The package ships optional `splicore-tun.conf` for the
same service; an operator explicitly installs this drop-in before enabling TUN.
NoNewPrivileges and Protect* hardening stay enabled. Use a dedicated service UID:
that UID's native sockets bypass capture via the existing main table.
Packet marks provide a second reserved underlay exception, without firewall writes.

The journal is service-owned 0700/0600, exclusive-locked and fsync/atomic replaced.
Normal shutdown restores; ExecStopPost and next start recover stale owned records.
Uninstall/purge stop first and run recovery as the original service UID with only
NET_ADMIN in the helper; failure retains installation/state. No journal chown.
Administrator-created drop-ins are administrator-owned and require explicit removal.

IPv4/IPv6 TCP/UDP, six outbounds, DNS leak detection, policy affinity and process
recovery are exercised in disposable WSL namespaces. Native Ubuntu networking,
physical interface changes and sudden power-loss qualification remain NOT CERTIFIED.
Linux arm64 is build-only. Headless desktop system proxy is UNSUPPORTED.
See [system integration](SYSTEM_INTEGRATION.md).

## Underlay socket and child verification

The daemon-shared provider applies the mature socket RoutingMark primitive in
required mode. Journaled daemon UID/main-table rules protect existing sockets and
native sockets before TUN is published; Lease.Verify reads back live owned
and borrowed resources. A lost socket control/readback degrades runtime health and
rejects new protected sockets.
