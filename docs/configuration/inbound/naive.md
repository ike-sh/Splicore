# Native NaiveProxy inbound

Use the managed `naive` creation protocol (`naive / connect / base`, engine
`native`). Server settings select `mode: "https"` for one TLS/H2 TCP listener or
`mode: "quic"` for one TLS 1.3/H3 UDP listener. H3 requires `with_quic`.

The shared creation envelope carries listener, display endpoint, TLS settings and
1–16 users with distinct usernames. Passwords omitted during creation are
generated. Existing Account, Binding and username/password Credential ownership,
disabled states and generation restart semantics apply.

TCP destinations, Basic authentication, native padding negotiation and concurrent
CONNECT streams are supported. Ordinary GET/HEAD preambles receive a minimal
static welcome response. Native UDP payload is not implemented. Chromium
TLS/HTTP/preamble fingerprint parity is not claimed.

See [Native NaiveProxy](../../architecture/NAIVE.md#server) for the complete server
creation example, limits, deadlines and account lifecycle. The native Core does
not use sing-box JSON configuration or a Chromium/Cronet runtime.
