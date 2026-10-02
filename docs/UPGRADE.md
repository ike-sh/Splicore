# Experimental Linux Upgrade

- Documentation status: Canonical
- Audience: Operators and distribution reviewers
- Last reviewed: 2026-10-02
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
