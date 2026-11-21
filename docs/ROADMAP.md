# Splicore roadmap

Main is the development and release baseline. The `AMD64_ONLY` policy covers
Linux amd64 and Windows amd64. The [qualification contract](releases/QUALIFICATION.md)
defines the gates for each release. ARM64 support is paused. Historical
qualification and unresolved findings remain in their release and issue records.

| Priority | Work | Evidence required |
| --- | --- | --- |
| 1 | Linux and Windows amd64 Core stability | Native process, socket, lifecycle, negative security and Race gates |
| 2 | Real network performance and reliability | Reproducible native measurements with stated conditions and performance targets |
| 3 | In-house UDP transport and secure handshakes | Loss, cancellation and resource ownership tests plus handshake and rejection evidence |
| 4 | Multi-protocol operation and interoperability | Native traffic and pinned independent peers for each claimed protocol capability |
| 5 | SQLite persistence and failure recovery | Acknowledged data and revision recovery, encrypted state, and fail-closed mutation checks |
| 6 | Build, release and deployment quality | Exact source and package identity, dual-platform downloaded smoke, and documented deployment scope |

Managed HTTP/1.1 joins SOCKS5 under the native inbound lifecycle. HTTP
qualification covers independent curl, client-to-server Core chaining and
recovery on the supported amd64 platforms. The direction matrix records the
connection and transport scope.

The capability and direction matrices record current protocol boundaries and
independent-peer evidence. [Capabilities](architecture/CAPABILITY_MATRIX.md) · [Direction audit](architecture/INBOUND_OUTBOUND_MATRIX.md)
Review the [historical inventory](../distribution/historical-features.json)
before releases and keep unqualified candidates outside production. ARM64
re-admission requires a maintainer support decision and fresh native evidence.
