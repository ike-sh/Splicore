# Redacted Local Support Bundle

- Documentation status: Canonical
- Audience: Operators, support reviewers and security maintainers
- Last reviewed: 2026-10-02
- Owner: Security and distribution maintainers
- Responsibility: Bundle content, private output and blocking secret tests.
- Lifecycle: Update with each new diagnostic field or input source.

```sh
sudo install -d -m 700 /absolute/private/support
sudo /usr/local/bin/splicore support-bundle \
  --config /etc/splicore/splicore.yaml \
  --output /absolute/private/support/splicore-support.tar.gz
```

The destination must be a new file in a 0700 directory owned by the invoking
principal. Output is 0600; existing files and symlink paths reject. No upload
occurs. Offline generation is supported and marks unavailable information.

## Archive contract

| File | Included |
| --- | --- |
| version.json | Validated build identity, platform and compiled schema versions. |
| system.json | Health enum, DB schema, registry/pending counts and engine availability. |
| doctor.json | Fixed check names, statuses and safe details; no raw errors. |
| config.redacted.json | Schema and canonical-path/configured booleans only. |
| listeners.json | Protocol/engine/health/transport enums, address class, low-port flag and binding count. |
| journal.summary.json | At most 128 recent unit entries summarized by priority; no MESSAGE, cursor or hostname. |
| crashes.json | At most 16 validated, re-projected exit records. |

No real listener hosts, account/inbound/binding IDs or names, tags, client export,
DB/WAL, keys, raw bootstrap, raw Xray JSON, journal messages or panic stacks are
copied. Redaction uses allowlisted projections instead of trying to recognize
every password substring. Journald is bounded by entry count, field filtering,
scanner size and command timeout. Individual archive projections are bounded.

The blocking test injects synthetic Snell PSK, HY2/TUIC/Mieru passwords, VLESS
UUID, REALITY private key and API token into diagnostic input fields and crash
records, then scans every decompressed file. Installed-system validation also
injects those values into local journald and verifies the produced archive.
Changing the bundle contract requires this gate. Operators should still review
the extracted summary before deliberately sharing it.
