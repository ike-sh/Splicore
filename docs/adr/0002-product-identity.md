# ADR 0002 — Independent product and gradual namespace

- Documentation status: Canonical
- Audience: Developers and decision reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: ADR 0002 rationale, alternatives, consequences and decision review triggers.
- Lifecycle: Preserve decision rationale; update reviewed status and link superseding ADRs.

## Status

Proposed for maintainer review. Date: 2026-10-01 (Asia/Shanghai).

## Context

Splicore is a new independent server product, unrelated to IDC branding or renaming NoBrand-OneClick. Upstream names/imports currently span 667 Go files and 1,905 import occurrences. Naming conditions and attribution must coexist with maintainable source history.

## Decision

Preserve LICENSE/copyright, add NOTICE/non-affiliation, retain module path and command source in Phase 0. Recommend gradual internal/splicore namespace and a separate cmd/splicore in Phase 1; first derivative distribution uses splicore binary/service/package identity. Public module ownership is not guessed.

## Alternatives

A: immediate wholesale path rename gives import independence with high churn. B: wholesale rename in Phase 1 postpones that same churn. C: gradual namespace preserves foundation imports and adds product composition first; preferred until a public Go library actually needs independent import identity.

## Consequences

Phase 1 implements the recommended separate cmd/splicore and internal/splicore
composition while retaining the original module and cmd/sing-box. New tests and
build scripts do not alter upstream workflows or publishing identity.
The small Foundation dispatcher uses standard-library flags; the earlier
Cobra/completion recommendation is deferred until the command surface needs it.

Build identity, product version and public API do not depend on Go module path. Own packaging/completions/service assets need qualification; source preserving upstream commands does not mean publishing a sing-box-branded derivative. Future module replacement must resolve to local fork code.

## Future Review

Revisit public repository/module ownership and library export scope before distributing a Go module; reassess exact naming/licensing requirements before binary release.

Details: [architecture specification](../architecture/FORK_BOUNDARY.md).
