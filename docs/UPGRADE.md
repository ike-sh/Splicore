# Upgrade and backup

For an installation created by the native package installer, use the
[same installer](INSTALLATION.md) with a trusted exact archive and SHA256.
It verifies ownership and compatibility before replacing files. It stops the
service and preserves the prior binary, unit, bootstrap, receipt, master key and
a coherent SQLite snapshot in a private transaction directory.

On reported start, migration or health failure, it restores the matching prior
files and restarts the previously active service. The command still reports the
failed upgrade. Do not run an older binary against a forward-migrated database;
rollback uses the original database snapshot and matching key. Keep the control
API quiet during an upgrade. Power loss or a killed installer can require manual
recovery from the retained backup.

For a separate offline database backup:

```sh
sudo systemctl stop splicore.service
sudo install -d -m 700 /absolute/private/backup
sudo /usr/local/bin/splicore state backup \
  --source /var/lib/splicore/state.db --output /absolute/private/backup/state.db
```

Preserve the master key and bootstrap in the same protected backup generation,
then restart the service. A verified source produces both `state.db` and
`state.db.witness`; preserve them together. Existing snapshot destinations are
rejected. Backups contain credentials. A live WAL database must not be backed
up by copying only its main database file.

An installation created before commit witnesses needs an explicit baseline
before the new Core will start. The Linux package installer detects this before
replacement and prints the required command; it never creates the baseline.
Use the candidate binary from the verified package at a root-owned path that is
executable by the `splicore` service account:

```sh
candidate=/absolute/verified-package/splicore
generation=/var/lib/splicore-upgrades/manual-pre-witness-YYYYMMDDTHHMMSSZ
sudo systemctl stop splicore.service
sudo install -d -m 700 "$generation"
sudo "$candidate" state backup \
  --source /var/lib/splicore/state.db --output "$generation/state.db"
sudo install -m 600 /var/lib/splicore/master.key "$generation/master.key"
sudo install -m 600 /etc/splicore/splicore.yaml "$generation/splicore.yaml"
sudo -u splicore "$candidate" state integrity \
  --source /var/lib/splicore/state.db
sudo -u splicore "$candidate" state establish-witness \
  --source /var/lib/splicore/state.db --acknowledge-current-state
# Keep the old Core stopped. Now run the verified package installer with --start.
```

Do not restart the old binary between baseline establishment and package
installation. The retained generation and Vault key are the rollback unit. The
installer now restores or removes the witness sidecars to match that exact DB
generation; a pending witness in a backup is rejected.

Windows foreground operation has no production `state backup` command. Stop the
old process and wait for all listeners to close, create a new protected backup
directory, and copy `state.db`, any retained `state.db-wal`/`state.db-shm`, the
Vault key and bootstrap as one generation. Run the verified new `splicore.exe`
`state integrity` and explicit `state establish-witness` commands as the same
Windows user that owns the state directory, then keep the old executable stopped
until the new Core has passed health and traffic checks.

The resulting `legacy_baseline` does not claim proof of older acknowledgements.
A damaged or mismatched existing witness is evidence to preserve, not a baseline
to replace. See [storage integrity](architecture/STORAGE_INTEGRITY.md).

Rollback after the new Core has accepted a business mutation always restores the
complete older DB/WAL/SHM, Vault key and matching witness generation. Preserve
the failed generation first. Never retain the candidate witness beside an older
DB, never delete only a witness to make an older executable start, and never run
the older executable against the forward state.

Retired external-engine or unsupported transport-mask intent is rejected during
upgrade; disabled records also count. Resolve it through the previous installation
before upgrading. Do not change an engine field to native as a shortcut. No
historical SQL migration is edited or record deleted automatically.
