# Experimental Linux Upgrade

- Documentation status: Canonical
- Audience: Operators and distribution reviewers
- Last reviewed: 2026-10-04
- Owner: Distribution maintainers
- Responsibility: Local atomic replacement, consistent backups and rollback boundaries.
- Lifecycle: Update whenever replacement or migration behavior changes.

## Pinned update

Use the same [installation command](INSTALLATION.md) with the exact candidate B
archive and independently trusted SHA256. The installer serializes package
operations using a root-owned lock outside the transient runtime directory.
It rejects unowned installation paths, symlinks, incompatible schema boundaries
and binaries/units whose bytes differ from the prior receipt.

For an existing installed program, it stops the unit and creates a private
transaction directory under `/var/lib/splicore-upgrades/`. It saves the old
binary, unit, bootstrap, receipt, master key and a consistent SQLite snapshot.
The database installation lock must be available. `VACUUM INTO` reads SQLite
coherently; copying a live WAL database is never used.

Candidate binary and unit replacement use same-directory temporary files,
fsync and rename. Bootstrap stays operator-owned. If the old service was active
or `--start` is supplied, systemd waits for READY, then the installer checks
actual API health and candidate identity. The new receipt is written last.

## Failed candidate

On start, migration or health failure, the installer stops the candidate,
restores the old program/config/key/database snapshot, reloads the unit and
restarts the old service when it was previously active. Backups remain private
and available for operator inspection. The command reports failure even when
automatic rollback succeeds.

The stopped database's exact WAL/SHM sidecars are removed before restoring its
snapshot. Never restore a database without its matching key. Existing migrations
are unchanged. A committed forward-only migration cannot be reversed by running
an older binary against the new database: rollback restores the original snapshot.
No changes acknowledged after that snapshot are retained in rollback. Keep the
control API quiet throughout the upgrade maintenance window.

## Backup and interruption

For a separate offline snapshot:

```sh
sudo systemctl stop splicore.service
sudo install -d -m 700 /absolute/private/backup
sudo /usr/local/bin/splicore state backup \
  --source /var/lib/splicore/state.db --output /absolute/private/backup/state.db
```

Preserve the master key and bootstrap in that protected backup location.
Do not overwrite an existing snapshot. Restart the unit after backup.

Automatic rollback covers reported command failures. Host power loss or killing
the installer between replacements requires operator recovery from the retained
transaction backup; an inconsistent receipt fails closed on the next install.
Stop the unit, restore all matching files and their documented owners/modes,
run daemon-reload and start, then verify doctor and API health. No automatic
power-loss transaction recovery is claimed by this experimental foundation.
Backups contain credentials: retain only the recovery generations you need and
remove obsolete backups deliberately as root. No online update server exists.

## Phase 13 host integration

Phase12 schema 6 upgrades through new migration 0007; historical migrations remain untouched. With TUN/host integration disabled, upgrade changes no routes, DNS, proxy or interfaces. Active owned mutations must restore on service stop before replacing binaries; failures retain recoverable state. See [system integration](SYSTEM_INTEGRATION.md).

## Phase 14 schema boundary

Phase 13 schema 7 upgrades forward to schema 8 via generic migration 0008. Providers
require no downloads/new daemon at install. Old rows/master key/bootstrap remain
coherent. Failed future schema 9 is tested only in an owned external fault fixture;
production migrations are unchanged. Rollback restores stopped coherent pre-upgrade
DB/key/binary checkpoint, not a down migration. Provider generation/source validators
participate in normal state snapshot and default uninstall retention.

## Retired experimental engine state

Before replacing installed files, the corrected installer takes an owned coherent
backup and rejects any Xray inbound/outbound/provider or transport-mask intent.
Disabled retired records also reject. The error identifies the resource class;
the old installation/database/key are retained and the old service restarts.
Remove those records with the previous experimental build, then upgrade. Never
change their engine to native as an upgrade shortcut.

With native-only state, forward upgrade passes. Retired bootstrap and receipt
metadata are accepted only by the installer and stripped after safe preflight;
normal serve rejects obsolete Xray bootstrap fields. Schema stays generic at 8;
no historical migration is edited and no cleanup deletes records automatically.
