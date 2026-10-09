# Operations and platform limits

## Native Linux service

[splicore.service](../distribution/splicore.service) runs one Core under a
dedicated `splicore` account. It owns Server Core and Client Core, persistent
SQLite state and the local API socket.

```sh
sudo systemctl start splicore.service
sudo systemctl stop splicore.service
sudo systemctl restart splicore.service
sudo systemctl status splicore.service
sudo /usr/local/bin/splicore service health --config /etc/splicore/splicore.yaml
sudo /usr/local/bin/splicore doctor --config /etc/splicore/splicore.yaml
```

Reload is unsupported; restart after bootstrap changes. Domain changes use the
application API. Committed runtimes are restored from SQLite before readiness.
Client restoration failure reports degraded health and preserves stored intent.

The standard unit uses `CAP_NET_BIND_SERVICE`, private state/runtime directories,
`UMask=0077`, bounded restart/shutdown and filesystem hardening. Optional TUN
requires the retained [drop-in](../distribution/splicore-tun.conf) at
`/etc/systemd/system/splicore.service.d/20-tun.conf`; it adds `CAP_NET_ADMIN`
to the same dedicated-user service. No desktop proxy manager is installed.

## Recovery and privacy

Status/doctor are passive. Routing/DNS/policy changes use committed graph snapshots;
existing sessions can retain the earlier snapshot. Provider startup can use stored
last-good state without a download. Logs go to journald; raw logs may be sensitive.
Use a [redacted support bundle](SUPPORT_BUNDLE.md) for diagnostics.

Host networking recovery acts only on recorded owned resources. On journal
conflicts, stop the client and inspect `network repair`; do not delete the journal
or reset unrelated host networking. Back up the database with its original key
before upgrades or recovery. See [upgrade and backup](UPGRADE.md).

## Qualification limits

Platform support remains experimental and partially qualified. Native Linux
auto-route and real Windows host networking have unqualified areas; Windows
auto-route remains guarded. Windows production local API transport and service
installation are unavailable. Linux arm64 is build-only. A build result does not
certify driver, privilege, route/DNS recovery or host integration behavior.
