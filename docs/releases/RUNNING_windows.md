# Splicore on Windows

The archive contains one core executable, `splicore.exe`. No WSL, Go installation
or separate proxy core is needed. amd64 has native process qualification; arm64
is **BUILD ONLY**, with no native runtime qualification.

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
Windows qualification exercised `stop`, active-stream closure and restart;
console Ctrl+C/SIGTERM injection and Windows Race were not executed.

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
backup remain unavailable. The Windows WireGuard hotfix remains NOT QUALIFIED.
Historical SOCKS UDP and Mieru throughput qualifications remain open; the local
symlink privilege exception does not establish symlink safety on every host.

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

Source and detailed limits: https://github.com/ike-sh/Splicore/releases/tag/v0.5.0
and https://github.com/ike-sh/Splicore/tree/v0.5.0/docs
