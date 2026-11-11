# Splicore on Linux

The archive contains one core executable, `splicore`. No separate proxy core or
language runtime is needed. amd64 has native process qualification; arm64 is
**BUILD ONLY**, with no native runtime qualification.

Verify the downloaded archive against the release's SHA256SUMS before unpacking.
Inside the unpacked directory, `sha256sum -c SHA256SUMS` verifies its contents.

```sh
./splicore help
./splicore version --json
```

For an ordinary user, create a bootstrap with private, absolute paths. Use a
local POSIX filesystem that enforces permissions. This example stores persistent
data under the user's home directory; keep the generated key with its database.

```sh
data_dir="$HOME/.local/state/splicore"
install -d -m 700 "$data_dir"
cat > "$data_dir/bootstrap.yaml" <<EOF
schema: 1
state_directory: $data_dir/state
key_file: $data_dir/keys/master.key
api:
  unix_socket: $data_dir/ctl/core.sock
EOF
chmod 600 "$data_dir/bootstrap.yaml"
./splicore key init --file "$data_dir/keys/master.key"
./splicore check --config "$data_dir/bootstrap.yaml"
./splicore run --config "$data_dir/bootstrap.yaml"
```

From another terminal in the unpacked directory:

```sh
./splicore status --config "$HOME/.local/state/splicore/bootstrap.yaml"
./splicore stop --config "$HOME/.local/state/splicore/bootstrap.yaml"
```

`run` stays in the foreground and writes Ready/errors to stderr; redirect stderr
to a file if desired. Ctrl+C/SIGTERM or `stop` requests graceful shutdown. `stop`
success means the request was accepted; a service supervisor should also wait for
the process to exit. Private directories must have mode 0700 and state/key files
0600. The Unix socket path must fit the platform length limit; use a shorter
private path if your home directory is unusually long. Do not weaken permissions
to accommodate a filesystem that does not enforce them.

The included `examples/splicore.yaml` is a system-installation path example;
customize ownership/paths before using it. A new database has no proxy listeners.
To create the included loopback VLESS example while the daemon runs:

```sh
./splicore check --config "$HOME/.local/state/splicore/bootstrap.yaml" --protocol vless --file examples/vless-loopback.json
./splicore inbound plan --config "$HOME/.local/state/splicore/bootstrap.yaml" --protocol vless --file examples/vless-loopback.json > "$HOME/.local/state/splicore/plan.json"
./splicore inbound apply --config "$HOME/.local/state/splicore/bootstrap.yaml" --protocol vless --file examples/vless-loopback.json --plan "$HOME/.local/state/splicore/plan.json"
```

The example listens only on 127.0.0.1:10810 and generates its user credential.
Use the explicit inbound export command for a client profile. Select verified
TLS/REALITY or explicitly configured VLESS Encryption before exposing a listener
remotely. `check` does not reserve ports,
probe destinations or prove all client credentials are usable.

CGO is disabled. Linux ELF has no dynamic interpreter; normal kernel facilities
are still required. TUN requires the device and privileges, and Hysteria UDP
port-range rules need nft/CAP_NET_ADMIN. These privileged features, all-protocol
interoperability, WSL2 large-UDP behavior and crash/power-loss recovery are outside
this release's VLESS process qualification. No drivers are bundled.

This v0.5.0 line is not a drop-in v0.3.0 Frozen upgrade. WireGuard endpoints,
ShadowQUIC, XHTTP H3 and additional generic stream carriers remain pending.
Native VLESS Encryption is restored, with ML-KEM-768/X25519 handshakes and
AES-GCM/ChaCha records. Generate keys with `splicore vlessenc` (use `.exe` on
Windows), set inbound `server_secret.decryption` and public client
`options.data.encryption`, and follow the tagged
[VLESS Encryption configuration](https://github.com/ike-sh/Splicore/blob/v0.5.0/docs/protocol/VLESS_ENCRYPTION.md).
Generator output contains private key material; store it privately. Sudoku is
obfuscation, not encryption. Android/v2rayNG real-device traffic is NOT EXECUTED.
Phase37 and unadmitted SQLite WAL candidates remain excluded.
Keep backups and do not mix frozen database/configuration trees.

Source and detailed limits: https://github.com/ike-sh/Splicore/releases/tag/v0.5.0
and https://github.com/ike-sh/Splicore/tree/v0.5.0/docs
