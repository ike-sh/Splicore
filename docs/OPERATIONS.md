# Experimental Linux Operations

- Documentation status: Canonical
- Audience: Linux operators and service maintainers
- Last reviewed: 2026-10-04
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
owns all native protocol listeners. SQLite restores committed
runtimes before READY notification. Health checks report degraded/restoration
failures rather than creating fallback users. SIGTERM uses the existing graceful
runtime shutdown. systemd handles restart on unexpected exit, with a bounded
restart rate and a 30-second shutdown deadline.

`RuntimeDirectoryPreserve` stays at systemd's default `no`: stopped/crashed
generations lose their transient UDS before the next start.
The generic standalone socket listener still rejects an existing socket for
operator review. No stale PID from SQLite is ever killed.

## User and low ports

`splicore:splicore` is a dedicated system identity with a non-login shell and
no automatically created home. The long-running daemon inherits
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
| ProtectControlGroups | Runtime cannot administer cgroups. |
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
Daemon SIGKILL is recovered by systemd from committed SQLite; no external core is owned.

## Client and server in the installed unit

The same splicore.service restores schema-5 client intent after server restoration.
No client unit or binary is installed. Use `splicore client status/start/stop/restart`
with the same bootstrap. Stop releases local listeners and sessions and preserves
server runtimes; restart rebuilds client adapters in one committed operation.
Systemctl restart reconstructs both roles from SQLite before READY. Client listener
recovery failure reports degraded client state while the server/API remain available.
Remote offline affects that outbound's passive health; DIRECT and server traffic stay
live. Doctor observes counts/listeners/route without remote probes. Detailed commands:
[CLI](CLI.md); lifecycle and ownership: [Client Runtime](architecture/CLIENT_RUNTIME.md).

## Phase 11 client operations

The same unit restores every enabled adapter from schema-5 SQLite state. Offline
remote nodes do not fail startup; actual traffic sets that lease's passive health.
Other adapters, DIRECT, server listeners and management stay available. Node endpoint
or credential changes rebuild only affected leases; label/route changes reuse adapters.
Established TCP streams retain their generation, while affected UDP associations close
on committed route/adapter changes. Explicit client restart rebuilds adapters and closes
old sessions after commit. Mieru uses official APIs in-process with no extra unit. Snell/Mieru UDP domains use per-flow local
resolution; other proxy UDP domains resolve remotely. See [client runtime](architecture/CLIENT_RUNTIME.md).

## Phase 12 graph recovery

Review a canonical network export, validate, save plan, then apply via the existing
core. No daemon restart is needed for route/selector/DNS updates or DNS cache flush.
Existing TCP/UDP keep their old snapshot; new sessions use the committed graph.
Node hostname bootstrap is distinct from destination DNS and must be explicit.
Offline detours/group failure do not imply DIRECT. Inspect policy status, DNS stats
and a no-I/O route explain before explicitly running dns lookup.

Systemd restart/upgrade/rollback rebuilds rules/sets/groups/DNS and persistent selector
from schema 7 SQLite (the network profile migration 6 is retained). Health, compiled matches and cache are memory only; restart removes
them without losing canonical intent. Corrupt committed graph reports degraded client
health; server/API stay live, data is preserved. Stop, back up and restore a verified
database rather than deleting user intent. Phase 13 host integration scope and platform limits are described below.

## Phase 13 host integration

Host journal recovery precedes desired client restoration. ExecStopPost restores only recorded resources under the service owner. A corrupt/conflicting journal is degraded; stop client then use `network repair` for reconcile. Do not delete journal or reset host networking. Doctor/bundles use redacted summaries. Windows auto-route rejects; native Linux and Windows qualification are pending. See [system integration](SYSTEM_INTEGRATION.md).

Windows typed WinINET restoration preserves external changes; unexpected owned
listener exit restores the prior snapshot or reports debt. Wintun failed child
cleanup retains its parent adapter. Original Windows activation guards remain
pending real Windows platform qualification. See [recovery](RECOVERY.md).

## Underlay diagnostics

Status and doctor include strategy, active generation/lease/infrastructure counts,
reconcile failures and unprotected required runtime counts. Protection/readback or
retirement failure marks client/server health degraded. Support summaries exclude
arbitrary DIRECT/server target history and credentials. Configure explicit safe
DNS/bootstrap when required System resolution rejects. An unqualified
platform rejects before launch. No-TUN SOCKS/HTTP operation needs no extra privilege.

## Phase 14 provider operations

Restore canonical SQLite state and original master key before runtime/scheduler start.
Provider unavailable does not prevent offline startup. Start Client Runtime before
manual/automatic fetch; management alone requires no TUN/admin privilege. Scheduler
waits cadence+jitter, max four workers; refresh-disabled preserves serving nodes.
Review preview guards and references before deletion; stale nodes deliberately retain
last-good new-session behavior. Batch disable stops new sessions independently.
Use encrypted source writes and owner-only import/export files. General list/doctor/
support is passive/redacted. No raw feed cache exists; protect SQLite backup plus key.
Default uninstall retains providers/nodes/credentials/tags/rules; purge removes state.
See [providers](architecture/PROVIDER_MODEL.md), [CLI](CLI.md), [recovery](RECOVERY.md).
