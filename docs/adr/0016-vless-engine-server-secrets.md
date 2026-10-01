# ADR 0016: VLESS engine placement and inbound server secrets

- Documentation status: Canonical
- Audience: Domain, engine and storage developers
- Last reviewed: 2026-10-02
- Owner: Architecture maintainers
- Responsibility: Record bounded Phase 5 foundation changes and their security boundary.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

Status: accepted for the implementation candidate; runtime qualification remains
subject to the [non-Vision final gates](../reports/PHASE_5_FINAL_ACCEPTANCE_REPORT.md).
Vision is deferred separately by [ADR 0017](0017-defer-vision-dependency-safety.md).

Protocol identity is independent of engine placement. VLESS wire 0 has plain/TLS/
REALITY profiles. Engine metadata declares supported protocol IDs, the registry lists
implementations per protocol, creation accepts a bounded engine selector (default
native), and plan/inbound API output exposes resolved engine separately. A future
xray binding is representable but not compiled or executable. Engine-neutral VLESS
validation accepts that domain intent; the native compiler rejects an intent placed
on another engine. Placeholder compile/selection rejects without side effects.
Account, Binding, Subscription and the central ClientProfile gain no engine fields.

Inbound ownership already exists on Credential. Extend the generic closed payload
set with PrivateKeyPayload{algorithm, secret material}. Schema 4 only extends the
credential-kind CHECK; all earlier migrations/checksums are immutable. Existing
ciphertext/AAD, FKs, bindings, policies and Snell constraint survive migration.
Use the existing vault rather than adding encryption. No protocol-specific column.

Optional ServerMaterializer creates/derives typed server material at apply time.
Creation resources commit inbound-owned credentials in the same transaction.
RuntimeIntent carries a separate server credential list; recovery/reconcile loads
it through an optional explicit server-secret repository port. Client projection
has no such port or field and uses only public settings. A private key can never
be copied into generic metadata, ClientProfile options or runtime target fields.

Application/HTTP/CLI/storage do not gain VLESS branches. Direct Phase 5 composition
registers protocols, native compiler map and format dispatch maps. A new native
engine identity guard is generic placement validation, not a protocol-to-engine
switch. Prior composition roots remain test fixtures.

Native VLESS composes unmodified pinned service/TLS constructors with owned TCP
admission, raw socket cancellation and immutable Binding attribution. REALITY is
a security profile, never a new top-level protocol. Vision's inherited checkptr
and data-race failures are retained as blocking evidence; this ADR does not waive
runtime safety qualification. No Xray/FinalMask/Sudoku runtime is added.

See [separation ADR](0005-protocol-engine-separation.md),
[engine model](../architecture/ENGINE_MODEL.md),
[storage](../architecture/STORAGE_MODEL.md) and
[security](../architecture/SECURITY_BOUNDARIES.md).
