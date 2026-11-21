# Splicore on Windows

The archive contains one core executable, `splicore.exe`. No WSL, Go installation
or separate proxy core is needed. The amd64 archive has native process
qualification.

Verify the archive with `Get-FileHash -Algorithm SHA256` and the published
SHA256SUMS. Inside the unpacked directory, the second SHA256SUMS lists each
included file, including the executable.

```powershell
./splicore.exe help
./splicore.exe version --json
```

Choose an absolute local data path owned by the same user who runs the core.
The example uses D:; change it if that drive is absent. Ordinary high-port
listeners do not require elevation. Existing broadly accessible data/key
directories are rejected; the core does not silently re-ACL them.

```powershell
$data = 'D:/Splicore'
New-Item -ItemType Directory -Force $data | Out-Null
$bootstrap = @"
schema: 1
state_directory: $data/state
key_file: $data/keys/master.key
api:
  unix_socket: $data/control/core.sock
"@
[IO.File]::WriteAllText("$data/bootstrap.yaml", $bootstrap, (New-Object Text.UTF8Encoding($false)))
./splicore.exe key init --file "$data/keys/master.key"
./splicore.exe check --config "$data/bootstrap.yaml"
./splicore.exe run --config "$data/bootstrap.yaml"
```

From another terminal in the unpacked directory:

```powershell
./splicore.exe status --config D:/Splicore/bootstrap.yaml
./splicore.exe stop --config D:/Splicore/bootstrap.yaml
```

`run` stays in the foreground and writes Ready/errors to stderr. `stop` success
means the request was accepted; also wait for process exit when supervising it.
Windows archive qualification exercised `stop`, active-stream closure and
restart. Console Ctrl+C/SIGTERM injection was `NOT_EXECUTED`. The unified
CI includes a separate native Windows amd64 Race gate.

The bootstrap's `api.unix_socket` is a stable identity for a local user-restricted
named pipe, not a socket file or public TCP API port. New key/state directories
receive a current-user/SYSTEM DACL. Files may have the exact OS-supplied token
default owner; pipe server authentication still requires the user SID. Preserve
the original master key with the database; key init refuses to overwrite it.

A new database has no proxy listeners. Use `examples/vless-loopback.json` with
the documented inbound check/plan/apply commands to create a loopback-only
VLESS listener. Write plan JSON as UTF-8 without BOM (PowerShell 7 defaults to
this); for Windows PowerShell 5 use WriteAllText with UTF8Encoding(false).
Select verified TLS/REALITY or explicitly configured VLESS Encryption before
remote deployment. `check` is static
validation, not a guarantee of port availability or every client credential.

CGO is disabled. Normal Windows OS DLLs are used. Optional TUN requires an
operator-supplied Wintun DLL/driver and privileges; it is not embedded in this
binary and is not qualified here. Windows service installation and production
backup remain unavailable. The typed Winsock UDP receive recovery has v0.6.4
native amd64 evidence. The historical Windows WireGuard Hotfix remains unqualified.
The native SOCKS5 UDP gate covers the relay and real application payloads on
loopback. Historical workload measurements remain open. [Release limits](https://github.com/ike-sh/Splicore/blob/v0.6.5/docs/releases/v0.6.5.md#known-limits)

Use the same CLI to create a managed HTTP Proxy or SOCKS5 listener. SOCKS5
UDP is opt-in. Allow the advertised UDP range for the intended peers in Windows
Defender Firewall before testing a remote relay. [Managed inbound examples](https://github.com/ike-sh/Splicore/blob/v0.6.5/docs/CLI.md#managed-socks5-and-a-local-client)

Follow the [upgrade guide](https://github.com/ike-sh/Splicore/blob/v0.6.5/docs/UPGRADE.md)
when migrating from the v0.3.0 Frozen line. v0.6.5 includes standard userspace
WireGuard, XHTTP H3 and additional generic stream carriers. ShadowQUIC remains
`ISOLATED_NOT_QUALIFIED`.
Native VLESS Encryption is restored, with ML-KEM-768/X25519 handshakes and
AES-GCM/ChaCha records. Generate keys with `splicore vlessenc` (use `.exe` on
Windows), set inbound `server_secret.decryption` and public client
`options.data.encryption`, and follow the tagged
[VLESS Encryption configuration](https://github.com/ike-sh/Splicore/blob/v0.6.5/docs/protocol/VLESS_ENCRYPTION.md).
Generator output contains private key material; store it privately. Sudoku is
obfuscation, not encryption. Android/v2rayNG real-device traffic is NOT EXECUTED.
Phase37 and unadmitted SQLite WAL candidates remain excluded.

See the [v0.6.5 release and qualification limits](https://github.com/ike-sh/Splicore/releases/tag/v0.6.5)
and the [tagged documentation](https://github.com/ike-sh/Splicore/tree/v0.6.5/docs).
