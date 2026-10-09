# Redacted support bundles

```sh
sudo install -d -m 700 /absolute/private/support
sudo /usr/local/bin/splicore support-bundle \
  --config /etc/splicore/splicore.yaml \
  --output /absolute/private/support/splicore-support.tar.gz
```

The destination must be new in a private directory owned by the invoking
principal. Output is 0600; existing files and symlink paths are rejected.
Generation does not upload anything. Offline generation marks unavailable data.

The archive contains bounded projections of version, system/doctor health,
redacted configuration/listeners/client state, sanitized crash records and unit
journal summaries. Provider diagnostics omit source URLs, authentication and raw
feed contents. No database/WAL, master key, raw bootstrap, credential payload,
raw journal messages or panic stack is copied. Projection fields are allowlisted.

Inspect the extracted summary before deliberately sharing it. Explicit secret
export is a separate operation and is never support-bundle input.
