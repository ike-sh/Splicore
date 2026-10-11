# AnyTLS client metadata

Splicore sends an empty `client` setting by default. This field is optional
client identification, not authentication or protocol version negotiation.

The native `client_metadata` option accepts an empty string, `splicore`, or
`splicore/...` up to 128 bytes. It rejects line breaks, NUL and names that
impersonate another implementation. It never automatically includes OS details.

See [Native AnyTLS](../../architecture/ANYTLS.md) for configuration and negotiated
protocol behavior.
