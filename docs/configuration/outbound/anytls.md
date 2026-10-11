# AnyTLS outbound

Use a canonical remote node with protocol `anytls / 2 / base`, TCP transport,
TLS security, endpoint and a separately owned password credential. TLS
verification is enabled by default; explicit CA trust is supported.

Options default to `udp: true`, `version: 2`, 30-second idle check and timeout,
`min_idle_session: 0`, `max_sessions: 128`, `multiplex_streams: 1`, empty
`client_metadata`, `insecure: false` and `uot_mode: "non_connect"`.
`multiplex_streams` above 1 permits bounded active session reuse. Default reuse
selects the newest idle session. Both UoT2 connected and nonconnected modes work.

See [Native AnyTLS](../../architecture/ANYTLS.md) for exact option bounds,
version negotiation, TLS, URI/export restrictions and peer limitations.
