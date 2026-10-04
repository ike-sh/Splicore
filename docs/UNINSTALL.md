# Experimental Linux Uninstall

- Documentation status: Canonical
- Audience: Linux operators and integration authors
- Last reviewed: 2026-10-02
- Owner: Distribution maintainers
- Responsibility: Program removal, retained state and explicit purge safety.
- Lifecycle: Update with ownership validation or removal behavior.

## Remove the program

```sh
sudo /usr/local/bin/splicore package uninstall
```

The command stops and disables the sole unit, removes its binary/unit and reloads
systemd. It retains `/etc/splicore`, SQLite, credentials, key, engine artifacts,
backups and the non-login service identity. Reinstall using the pinned local
[installer](INSTALLATION.md); retained bootstrap and domain state are reused.
Do not reuse the service UID for another principal.

## Purge

```sh
sudo /usr/local/bin/splicore package uninstall --purge
```

`--purge` is the explicit destructive authorization. It additionally deletes
only `/etc/splicore`, `/var/lib/splicore` and `/var/lib/splicore-upgrades` after
validating ownership markers, fixed clean paths and complete trees. Symlinks,
foreign-owned entries, mount boundaries and special files reject. The account
and root-owned installation lock are retained. Journald data remains under the
host's journald retention policy. No firewall rules are added or removed.

If the program has already been removed, reinstall it first and then purge.
Back up matching DB/key/config before purge; deleted credentials cannot be
recovered without that backup. Run destructive validation only in a disposable
environment.

## Phase 13 host integration

Stop before removal, restore the private host journal as the original service UID, and refuse removal/purge on recovery failure. Domain state remains by default. Purge validates paths after restoration. Never chown a journal, flush a table or remove an unrelated adapter. Administrator-installed service drop-ins are not automatically removed; remove the optional TUN profile explicitly when retiring it. See [system integration](SYSTEM_INTEGRATION.md).
