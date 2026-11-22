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
before the new Core will start. While the service is stopped, first retain the
old coherent backup and Vault key, then run the new binary's read-only
`state integrity` command and, only after accepting that current snapshot, run
`state establish-witness --acknowledge-current-state`. The resulting
`legacy_baseline` does not claim proof of older acknowledgements. A damaged or
mismatched existing witness is evidence to preserve, not a baseline to replace.
See [storage integrity](architecture/STORAGE_INTEGRITY.md).

Retired external-engine or unsupported transport-mask intent is rejected during
upgrade; disabled records also count. Resolve it through the previous installation
before upgrading. Do not change an engine field to native as a shortcut. No
historical SQL migration is edited or record deleted automatically.
