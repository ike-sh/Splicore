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
then restart the service. Existing snapshot destinations are rejected. Backups
contain credentials. A live WAL database must not be backed up by copying only
its main database file.

Retired external-engine or unsupported transport-mask intent is rejected during
upgrade; disabled records also count. Resolve it through the previous installation
before upgrading. Do not change an engine field to native as a shortcut. No
historical SQL migration is edited or record deleted automatically.
