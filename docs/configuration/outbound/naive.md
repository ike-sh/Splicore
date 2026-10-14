# Native NaiveProxy outbound

Use a canonical remote node with protocol `naive / connect / base`, TLS security,
a separately owned `username_password` credential and `options.data.mode`.
HTTPS mode uses transport kind `tcp` and ALPN `h2`; QUIC mode uses kind `quic` and
ALPN `h3`. H3 requires `with_quic`. Both carry TCP CONNECT payload.

The client supports Basic authentication, native padding (`auto`, `enabled`,
`off`), bounded connection pools, HTTP stream multiplexing, extra headers,
connection retirement and stream deadlines. TLS certificate verification is
mandatory. QUIC congestion control is CUBIC only; unsupported algorithms and
flow-control options are rejected.

See [Native NaiveProxy](../../architecture/NAIVE.md#client) for a canonical node
creation example and the complete supported options. URI import/export supports
`naive+https://` and `naive+quic://` with system trust/default options; use canonical
configuration for custom CAs and richer settings.

Native UDP, CONNECT-UDP, MASQUE and UDP-over-TCP extensions are not implemented.
Chromium TLS/HTTP/preamble fingerprint parity is not claimed. No Chromium,
Cronet shared library or external proxy process is required.
