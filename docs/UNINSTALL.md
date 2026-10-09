# Uninstall

For an installation owned by the native package installer:

```sh
sudo /usr/local/bin/splicore package uninstall
```

The command stops/disables the service, removes its binary/unit and reloads
systemd. Configuration, SQLite, the master key, backups and the locked service
identity remain for a later reinstall. Do not reuse that identity for another
principal. Owned host networking recovery must succeed before removal proceeds.

Explicitly add `--purge` only when removal of the retained configuration, state
and upgrade backups is intended. Ownership/path checks still apply. The installer
does not remove unrelated networking or another product's files. A manually
deployed source build has no package receipt; manage that deployment's files
through the mechanism used to install it.
