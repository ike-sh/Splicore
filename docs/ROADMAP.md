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

Managed HTTP/1.1 joins SOCKS5 under the native inbound lifecycle. The first
official run for PR #24 failed on a Linux amd64 Snell v5 Race timeout and a
Windows amd64 protected DNS fallback test. The bounded main/PR comparisons
did not reproduce either failure. The tracker issues retain both unresolved
findings. The official workflow governs candidate assembly and downloaded smoke.
[PR #24](https://github.com/ike-sh/Splicore/pull/24) · [Linux Snell #25](https://github.com/ike-sh/Splicore/issues/25) · [Windows DNS #26](https://github.com/ike-sh/Splicore/issues/26)

PR #24 and the merged main tree passed the full native amd64 gates and
downloaded smoke. The two historical failures remain unresolved.
[PR qualification](https://github.com/ike-sh/Splicore/actions/runs/44874906356) · [Main qualification](https://github.com/ike-sh/Splicore/actions/runs/44877182215)

The managed SOCKS5 UDP increment covers authenticated association, protected
target routing and dual-Core traffic. The same Official release workflow
requires both platforms to execute the UDP product smoke before publication.
[SOCKS5 UDP settings](CONFIGURATION.md#managed-socks5)

The capability and direction matrices record current protocol boundaries and
independent-peer evidence. [Capabilities](architecture/CAPABILITY_MATRIX.md) · [Direction audit](architecture/INBOUND_OUTBOUND_MATRIX.md)
Review the [historical inventory](../distribution/historical-features.json)
before releases and keep unqualified candidates outside production. ARM64
re-admission requires a maintainer support decision and fresh native evidence.
