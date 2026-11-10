# Security policy

The current downloadable line is v0.4.x. Pre-1.0 protocol and platform features
remain bounded by the documented qualification matrix; a successful build does
not certify host networking, every protocol combination or crash recovery.
There is no guaranteed support period for historical releases.

Do not publish vault keys, decrypted credentials, private configurations or
unredacted support bundles in public issues. Use GitHub's private **Report a
vulnerability** facility on this repository when available. If it is unavailable,
request a private reporting channel from the maintainer without posting exploit
details or secrets publicly. This project does not claim an external security
audit or a guaranteed response time.

Only use official versioned assets and verify SHA256SUMS. Checksums detect
corruption; no cryptographic release signature is supplied. Preserve private
state/key permissions. The control API is local and privileged; do not expose
or bridge its Unix socket/named pipe to an untrusted network or user.

See [release limits](docs/releases/v0.4.0.md) before deploying experimental
protocols or privileged TUN/host-network features.
