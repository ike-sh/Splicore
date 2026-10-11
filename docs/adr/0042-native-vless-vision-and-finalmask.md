# ADR 0042: Native VLESS Vision and reusable TCP masks

Status: Experimental native implementation.

## Context

The previous Vision dependency had private-memory/checkptr and concurrency
defects. Its deferral evidence in ADR 0017 remains historical truth. Removing
external runtime ownership in ADR 0035 remains the product boundary.

## Decision

Implement Vision as a dedicated VLESS flow, using owned bounded framing,
synchronized TLS detection, record-limited security reads and owned plaintext
drain at the direct transition. Do not import SagerNet or Xray runtime code.
Use existing TLS and uTLS/REALITY APIs and preserve their normal TLS key exchange.

Place reusable TCP FinalMask wrappers below security. First configured mask is
innermost; preserve half-close and deadline behavior across the complete chain.
Use strict bounded Splicore domain config. Implement Sudoku dictionaries,
wire alphabets, classic and packed encoders independently from observable
behavior. External Xray is a fixed wire reference and test peer only.

## Consequences

Native plain VLESS, raw TLS/REALITY Vision and bounded TCP masks become available
as experimental implementation profiles. Vision admits TCP only and rejects HTTP
transports; unsupported fields and aliases reject without downgrade. Export and
platform qualification remain separate from native wire implementation.
Earlier ADRs retain their historical rationale. No external core runtime,
VLESSENC, XHTTP, UDP mask suite or new XUDP surface is introduced.

Configuration and interoperability limits: [VLESS](../protocol/VLESS.md),
[FinalMask](../architecture/FINALMASK.md).
