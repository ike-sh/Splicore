# AnyTLS inbound

Splicore's native AnyTLS server requires shared TLS and managed password users.
Use the `anytls` creation API, not a sing-box inbound document.

The settings contain `tls`, optional `alpn`, `padding_scheme`, `version` (1 or 2),
`max_sessions` (default/max 512), and `max_streams` (default/max 128).
TLS uses absolute `certificate_file` and `private_key_file` paths, a DNS
`server_name`, and one PEM `ca_certificate` for client profile trust.
At most 16 unique users are supported. User changes restart the generation.

See [Native AnyTLS](../../architecture/ANYTLS.md) for a complete creation example,
padding, authentication, UoT2, limits and peer compatibility limits.
