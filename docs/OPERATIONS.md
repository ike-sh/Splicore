# Experimental Linux Operations

- Documentation status: Canonical
- Audience: Linux operators and service maintainers
- Last reviewed: 2026-10-02
- Owner: Distribution maintainers
- Responsibility: Main-unit lifecycle, permissions, diagnostics and hardening.
- Lifecycle: Update with systemd unit and service behavior.

## Lifecycle

```sh
sudo systemctl start splicore.service
sudo systemctl stop splicore.service
sudo systemctl restart splicore.service
sudo systemctl status splicore.service
sudo /usr/local/bin/splicore service health --config /etc/splicore/splicore.yaml
sudo /usr/local/bin/splicore doctor --config /etc/splicore/splicore.yaml
```

Reload is unsupported; use restart after bootstrap changes. Domain changes use
the canonical local [API](api/README.md), independent of bootstrap. One unit
owns all protocol listeners and optional Xray children. SQLite restores committed
runtimes before READY notification. Health checks report degraded/restoration
failures rather than creating fallback users. SIGTERM uses the existing graceful
runtime shutdown. systemd handles restart on unexpected exit, with a bounded
restart rate and a 30-second shutdown deadline.

`RuntimeDirectoryPreserve` stays at systemd's default `no`: stopped/crashed
generations lose their transient UDS and Xray configs before the next start.
The generic standalone socket listener still rejects an existing socket for
operator review. No stale PID from SQLite is ever killed.

## User and low ports

`splicore:splicore` is a dedicated system identity with a non-login shell and
no automatically created home. The long-running daemon and Xray child inherit
only `CAP_NET_BIND_SERVICE` for TCP/UDP ports below 1024. No root daemon,
CAP_NET_ADMIN, firewall change or broad network privilege is required.

## Unit hardening

| Setting | Reason / limit |
| --- | --- |
| NoNewPrivileges | Prevent exec from acquiring additional privileges. |
| PrivateTmp | Isolate incidental temporary files; all durable paths stay canonical. |
| ProtectSystem=strict | Make system trees read-only; declared state/runtime directories remain writable. |
| ProtectHome | Block root/user home data; TLS/engine material must live in the service state layout. |
| ProtectKernelTunables/Modules/Logs | Block unrelated kernel administration and kernel log access. |
| ProtectControlGroups | Child engine cannot administer cgroups. |
| RestrictAddressFamilies | AF_UNIX control plus IPv4/IPv6 proxy traffic and AF_NETLINK interface discovery. |
| CapabilityBoundingSet / AmbientCapabilities | CAP_NET_BIND_SERVICE only, inherited by the managed engine. |
| LimitNOFILE=65536 | Bound FD use while allowing representative concurrent proxy sessions. |
| KillMode=mixed | SIGTERM goes to the owner; final cgroup cleanup catches surviving owned children. |
| UMask=0077 | Keep credentials, DB and generated engine configs private. |

These choices follow the primary systemd v255
[exec](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.exec.xml),
[service](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.service.xml)
and [kill](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd.kill.xml)
contracts. They require runtime qualification with the actual protocols.
SELinux/AppArmor are not certified; no system security mechanism is disabled.
arm64 package build is separate from arm64 runtime qualification.

## Logs and crash records

Logs go to journald, whose retention is configured by the host; no permanent
working-directory or `/tmp` logs are created. Unit log submission is rate-limited.
Treat raw local journal access as sensitive. Do not upload raw panic stacks or
credentials. Use the allowlisted [support bundle](SUPPORT_BUNDLE.md).

ExecStopPost records sanitized process exit classification in 0600 JSON under
`/var/lib/splicore/crashes`, retaining 16 records. It stores version/commit,
component/engine/protocol enums and timestamp, never raw exception text.
Parent SIGKILL is handled by Xray's existing Linux Pdeathsig and the unit cgroup;
unrelated Xray processes are outside that ownership boundary.
