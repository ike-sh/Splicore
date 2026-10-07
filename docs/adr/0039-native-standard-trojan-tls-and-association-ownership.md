# ADR 0039: Native standard Trojan TLS and association ownership

Status: Accepted

Date: 2026-10-07

## Context

The independent core must implement standard Trojan server/client TCP and UDP
without restoring external cores or a SagerNet dependency. Trojan puts a
secret-equivalent password digest and UDP frames inside TLS, so an association's
failed framed IO and shutdown must have one explicit owner.

## Decision

Use Go TLS and SHA-224 and independently implement canonical application framing
in `protocol/trojan`. Reuse shared TLS snapshots, verified trust, encrypted
credentials, generation replacement, protected dialing and joined relays.

Keep plaintext secrets at the vault/profile export boundary; runtime generations
hold fixed derived credentials and scan every user with constant-time comparison.
One TLS stream owns one CONNECT or UDP association; no mux or stream reuse is
added. Every failed admitted UDP TLS write retires that association. Full Close
aborts the raw socket and joins IO/callback ownership. Separate associations remain
independent; a poisoned shared frame stream cannot preserve its sibling targets.

Extend the generic binding generation transaction for credential rotation and
exclusive managed-user deletion, using current tables and owner-bound encryption.
Reference conflicts roll back and reconstruct the committed generation.

Defer fallback explicitly. The canonical specification describes it and reference
implementations offer it, but Phase 18 permits deferral and excludes transport
camouflage. Invalid requests close generically without exposing expected credentials.

## Consequences

The current public trust policy remains secure; insecure imports and lossy URI
exports reject. Static certificate replacement uses generation replacement. User
mutations close the affected inbound's sessions, then preserve unrelated users'
new-session access. No migration, dependency, external production process or
protocol-specific account store is introduced. Peer-specific UDP limits remain
visible compatibility decisions instead of changing canonical datagrams.

Implementation gates and peer evidence are recorded in the Phase 18 implementation
report. Accepted after the final independent Phase 18 re-review passed on
2026-10-07 with T18R-001 CLOSED. The first Freeze attempt was blocked by eleven
CRLF/LF byte differences. Authorized exact-index EOL recovery preserved reviewed
semantics and completed the local Phase 18 freeze. Publication and platform
qualification remain separate authorization.
