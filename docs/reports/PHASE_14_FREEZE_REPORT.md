# Splicore Phase 14 Freeze Report

- Documentation status: Historical freeze checkpoint
- Audience: Maintainers and reviewers
- Last reviewed: 2026-10-04
- Owner: Splicore maintainer
- Responsibility: Authorized Phase 14 scope, corrected architecture, validation and Git closure
- Lifecycle: Preserve this local Experimental freeze snapshot; later work uses a new report

## Status

**PHASE 14 FROZEN**

This report describes the one authorized forward commit containing this report.
It does not authorize publication, deployment migration or Phase 15 work.

## Phase

Phase 14 — Client Management / Providers + Xray Boundary Architecture Correction.

## Base

Phase 13: `b0de8c16e1c810cb851c400b5d03987924d5eff8`.
Its sole parent: `d09f5f10797aa63798419fa77ffd676257f1b609`.
Entry branch: `codex/phase-14-client-management-providers`; HEAD and main were
the Phase 13 base. Entry index was empty; the exact accepted inventory contained
111 modified, 35 deleted and 48 untracked files. Main remains at Phase 13.

The maintainer explicitly authorized a scope manifest, exact-file staging,
one Phase 14 forward commit with Phase 13 as its sole parent, and immediate stop.
No amend, reset, rebase, squash, history rewrite, push, tag or release is used.

## Architecture

- Splicore is an independent native Server Core and Client Core.
- The only registered runtime engine is `EngineID=native`.
- Native Snell, Hysteria2, TUIC, VLESS and embedded Mieru remain Experimental;
  DIRECT and REJECT remain builtins.
- Native VLESS supports plain/TLS/REALITY flow-none; REALITY requires `with_utls`.
- Xray server/client runtime, child supervisor/lifecycle, executable dependency,
  distribution artifact and dedicated underlay owner are absent.
- `RuntimeConfig != ClientProfile`; ClientProfile has no engine or runtime owner.
- Xray-compatible ClientProfile export is an external serialization contract.
- FinalMask and Sudoku are out of scope. Vision is DEFERRED / UNSUPPORTED.

See [architecture](../ARCHITECTURE.md), [engine model](../architecture/ENGINE_MODEL.md)
and [ADR 0035](../adr/0035-xray-runtime-removed-from-core.md).

## Delivered

- Node management: immutable persistent random UUID identity, independent remote
  node and outbound intent, metadata/tags, manual and provider provenance,
  reference-aware batch update/delete and explicit secret export.
- URI and management import: bounded parsing, canonical and supported external
  representations, strict/lenient previews, explicit Unsupported diagnostics,
  no stripping of unsupported engine/mask features into runnable nodes.
- Management transactions: revision-bound previews, capacity/expiry limits,
  single-use apply tokens, preparation before commit, activation after commit,
  rollback and retained committed-state authority.
- Proxy providers: encrypted sources/authentication, protected bounded fetching,
  redirect and complete DNS-answer validation, body/node limits, cancellation,
  persistent generations, stable identity, serialized transactional refresh,
  enable/update/delete operations and bounded four-worker scheduling.
- RuleSet Providers: bounded supported text/JSON representations, reference-safe
  generation replacement, persisted rules, offline recovery and transactional
  integration with routing/DNS/policy.
- SQLite schema 8 management storage, separate encrypted credential ownership,
  consistent backup/recovery, restart/SIGKILL recovery and retained provider state.
- Shared application services, API/OpenAPI, CLI, diagnostics, doctor and redacted
  support bundles; protected provider/client/server egress and lifetime ownership.
- Native server/client, SOCKS TCP/UDP, HTTP, TUN, routing/DNS/policy groups and
  Phase 13 host journal/underlay safety regressions remain intact.

ADRs [0032](../adr/0032-provider-generation-node-identity.md),
[0033](../adr/0033-management-preview-transaction.md) and
[0034](../adr/0034-remote-source-security.md) are accepted for this Experimental
local checkpoint. Deferred import/export formats and platform qualifications
are retained; this freeze adds no capability.

## Xray Boundary Correction

Phase 6/7 actually implemented the historical Xray Compatibility direction.
The maintainer subsequently identified that direction as an architecture
misunderstanding. [ADR 0035](../adr/0035-xray-runtime-removed-from-core.md)
supersedes it for the current product; existing Git history and historical
reports remain unchanged. The accepted correction removes active Xray runtime,
owned JSON rendering, process/artifact management, engine capability registration,
mask features and dedicated child-underlay infrastructure.

Future independent external-core orchestration belongs to NoBrand-OneClick.
Its real repository was neither accessed nor changed. The
[pre-correction Phase 14 report](PHASE_14_CLIENT_MANAGEMENT_PROVIDERS_REPORT.md)
and [correction acceptance report](ARCHITECTURE_CORRECTION_XRAY_BOUNDARY_REPORT.md)
retain their implementation/review-time statements; this separately authorized
freeze records the subsequent corrected acceptance.

Legacy persisted `EngineID=xray`, including disabled records, continues to fail
closed with `unsupported_engine_for_protocol` before migration/replacement or
runtime activation. Data, encrypted secrets, bindings and migration history are
preserved, without silent native conversion, process launch or Xray download.
Native-only historical state continues to upgrade normally.

## ClientProfile Compatibility

`Xray-compatible ClientProfile export != Xray runtime support`.

Ordinary `format=xray` remains legal in the ClientProfile/export namespace.
It serializes only plain TCP/flow-none/XUDP VLESS to an external outbound JSON
fragment. Target version `26.3.27` is a string format contract, not an executable
version probe. TLS and REALITY return UnsupportedExport for this exporter;
Vision, FinalMask, Sudoku, engine options and managed process fields reject.
The generic remote-node aggregate exporter does not support xray.

The installed inbound API/CLI export service only reads authorized committed
state and projects a ClientProfile. It does not select/change EngineID, prepare
or activate a runtime, create bindings, save runtime artifacts or mutate the
distribution. Runtime capabilities remain native-only.

Final boundary classification: E active Xray runtime/engine/control = 0;
F suspicious/unresolved = 0; G external ClientProfile compatibility = 10
(eight product/schema references plus two export-only rejection-test lines).
Historical, legacy-rejection, documentation and test references remain permitted.
Freeze does not require G=0 or string-level elimination of xray.

## Validation

Use **previous full review evidence + final freeze gates**. Exact commands,
exits, logs, source/file hashes and artifact provenance are stored outside Git at
`D:/splicore-validation/phase14-freeze-20261004`.

| Gate | Freeze-stage evidence |
| --- | --- |
| Formatting | gofmt verification of owned Go files; PASS |
| Static | Tagged go vet, explicit diff/whitespace/source scope audits; PASS |
| Linux units/race | Complete owned package and cmd suite, production tags, race enabled and default checkptr; PASS |
| Windows units | Complete safe owned package and cmd suite; PASS; race not executed |
| Shared race | Affected dialer, DNS, route, native protocol and client I/O packages; PASS |
| Phase 14 | Node/import/provider/RuleSet, encryption, backup/recovery, transactional and legacy-rejection tests included in the complete suite; PASS |
| ClientProfile boundary | External Go overlay verifies plain export, pinned version, TLS/REALITY/Vision/mask/process rejection and native-only registry; PASS |
| Native runtime | Snell/HY2/TUIC/VLESS/Mieru and lifecycle/rollback regressions in complete owned/shared suites; PASS |
| Routing/DNS/policy | Complete owned and shared regressions; PASS |
| TUN/system safety | Safe Windows guards and underlay ownership tests; real kernel TUN/provider tests only in owned isolated WSL namespaces; PASS |
| Underlay static | Production Unknown=0; no host networking mutation |
| Documentation | Canonical Markdown metadata/links and OpenAPI checks; reused unchanged installed response schemas; PASS |
| Secrets | Pre-stage candidate literal scan, reviewed synthetic fixtures and staged-source check; PASS |
| Distribution | Fresh Linux amd64, Windows amd64 and Linux arm64 builds; manifests/integrity/source provenance; PASS |
| Reproducibility | Two independent caches initially empty, all three platforms; after the final documentation link fixes, both builds regenerate the exact final source using their separate populated caches; identical final artifacts and source archives; PASS |
| Staged smoke | Staged source matches reviewed manifest; compile and critical deterministic unit/boundary gates; PASS |

The commit is created only after these gates succeed. The external final record
binds actual counts/results and the sole-parent commit to the reviewed staged
source; no old artifact is relabeled as a freeze build.

## Safety

Race detection remains enabled on Linux; checkptr retains its default setting.
No sleep/retry masking, recover-based panic suppression, checkptr/race disabling,
skipped acceptance tests or global data-path serialization is introduced.

The previous complete corrected review qualified 42 fuzz targets, lifecycle
stress, provider/runtime ten-run campaigns, provider FD/goroutine stability,
live API/CLI read-only export, populated legacy rejection, support redaction,
installed upgrade/rollback/reinstall/purge and offline recovery. Those expensive
qualifications are reused against unchanged production/parser source.
Freeze-stage non-document edits only normalize CRLF to LF in three test files
and three audited scripts/inventory files; they have no semantic changes.
No parser/fuzz implementation changed; no long fuzz campaign is claimed rerun.

The previous populated legacy campaign covered seven cases, 21 tables,
27 encrypted credentials and six bindings. The previous ClientProfile live
campaign compared all 21 table snapshots, runtime/underlay, EngineID, binding,
credential, process, socket and distribution state before/after API/CLI export
with no Xray executable available. The current targeted rejection/boundary
tests also pass. Previous support bundles contained eight redacted members and
no credential values/private keys. Public evidence retains no exported secrets.

All live traffic remains inside owned WSL labs. Docker Desktop, Redis and
TeleLedger were not accessed; no real Windows network activation was performed.

## Distribution

One Splicore core binary and its native service/configuration/license files;
no Xray binary, URL, checksum, component manifest or artifact requirement.
The workflow retains the removal of its obsolete `--xray` argument.

Freeze packages are local Experimental development candidates. They are built
before the freeze commit, so their Git metadata honestly records the Phase 13
base and a dirty candidate. Their source digest/archive and staged Git tree are
verified identical, and the external post-commit provenance record maps that
exact source to the actual freeze commit. Build metadata is not fabricated to
contain the not-yet-created commit hash. No package is published or released.

## Platform Qualification

### Windows amd64

Build, units and safe integration PASS. Real TUN, real auto-route and real
WinINET **NOT CERTIFIED**. Windows race **NOT EXECUTED**. Unsafe activation
continues to FAIL CLOSED; these limitations are not a freeze blocker.

### Linux amd64

Build, units, race/default checkptr and owned isolated WSL runtime/traffic
qualification PASS. Native Ubuntu host-network destructive qualification
**DEFERRED / NOT CERTIFIED**; WSL evidence does not certify native init/network.

### Linux arm64

**BUILD ONLY; RUNTIME NOT CERTIFIED**.

## Historical Integrity

Phase 0–13 frozen history, Phase 6/7 historical reports, Phase 13 reports and
existing migrations remain unchanged. No upstream sing-box runtime or official
Mieru source is modified; dependency versions remain unchanged. The new schema
8 management migration is the only additional migration.

## Git / Freeze Identity

Freeze commit: **this commit** (the commit containing this report).
Message: `feat(client): add management providers and correct xray boundary`.
Sole parent: `b0de8c16e1c810cb851c400b5d03987924d5eff8`.
Branch: `codex/phase-14-client-management-providers`.

The externally retained exact file manifest is staged with explicit paths,
including reviewed deletions. STAGED SET must equal REVIEWED FREEZE MANIFEST;
the complete staged source must equal package source provenance. After the one
commit, index is EMPTY and working tree CLEAN. The final external report gives
the actual hash/statistics, avoiding a self-referential hash or amend.

Push: NO. Tag: NO. Release: NO. Main update: NO. NoBrand changes: NO.
Phase 15: NOT STARTED.
