# Future NoBrand deployment boundary

Documentation status: Current architecture correction
Audience: Maintainers and operators
Last reviewed: 2026-10-04
Owner: Splicore maintainer
Responsibility: Independent native Server + Client Core boundary
Lifecycle: Experimental; Phase 14 local freeze; external migration not started

NoBrand-OneClick is the future deployment/orchestration layer. Splicore is an
independent Server + Client Core; it never installs or controls another core.

```text
NoBrand-OneClick
├── Splicore: native supported server/client protocols
└── independent Xray: specialized VLESS FinalMask / Sudoku
```

NoBrand chooses the runtime by protocol/mode, downloads the pinned artifact,
verifies its hash, installs/starts the appropriate independent service and owns
its lifecycle. Splicore provides one native core binary, local API/CLI, SQLite
state and capability/export contracts. Its API need not know another service's
status. Ordinary VLESS/native stays in Splicore. Vision remains unsupported;
FinalMask/Sudoku are out of scope for Splicore. No fallback or feature stripping.

This is a future design only. No changes, access, installation or migration are
made in the real NoBrand-OneClick repository. Future migration needs its own
authority, backups, acceptance and rollback design. [ADR 0035](../adr/0035-xray-runtime-removed-from-core.md).

## Historical mapping links

<a id="phase-4-synthetic-tuic-mapping"></a>
<a id="synthetic-vless--reality-mapping"></a>

These anchors preserve links from the immutable Phase 4/5 reports. Those
synthetic mapping checkpoints are historical evidence; the current independent
native-core deployment boundary above supersedes their migration direction.
