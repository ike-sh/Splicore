# Splicore Phase 18 Native Trojan Freeze Report

# PHASE 18 FROZEN

## Verdict

**PHASE 18 FROZEN** — implementation reviewed and locally frozen.
Original independent review FAILED; T18R-001 MAJOR was corrected in Review Fix
Round 1 and CLOSED by final independent re-review. New BLOCKER=0, MAJOR=0.
Known implementation blockers: **NONE KNOWN**.
Historical qualification: **PARTIALLY PASSED**. Freeze: **NOT REQUALIFIED**.
Current candidate: **NOT PLATFORM QUALIFIED**. arm64: **BUILD ONLY**.

## Commit

- PHASE_18_FREEZE_COMMIT: **the commit containing this report**.
- Message: feat(protocol): add native trojan server and client.
- Sole parent: dabe4030fb82f272b8e1035779e2b8c4da9b0600.
- Branch: codex/phase-18-native-trojan.
- Exactly one forward commit; no merge, amend or separate documentation commit.

Resolve the immutable hash after commit with:

    git log -1 --format=%H -- docs/reports/PHASE18_NATIVE_TROJAN_FREEZE_REPORT.md

This follows Phase17: a committed report cannot contain its own future object
hash. The full resolved hash, sole parent, final clean Git state and actual
post-commit quick gates are recorded externally in
D:/splicore-validation/phase18-freeze-eol-recovery-20261007/PHASE18_FREEZE_EOL_RECOVERY_REPORT.md
and summary.json. This preserves exactly one commit and a CLEAN working tree.

## Base

Phase17 freeze: **dabe4030fb82f272b8e1035779e2b8c4da9b0600**.
Base message: feat(core): establish independent core with native shadowsocks.

## Scope

Complete Phase18 Native Trojan: server/client, TLS, TCP CONNECT, UDP ASSOCIATE,
multi-user authentication, encrypted Account/Binding/Credential integration,
Node/Provider/URI, generic API/CLI mutations, backup/restore, routing/DNS/policy,
Native TUN, stats/doctor/support, pinned interoperability, lifecycle hardening
and Review Fix Round 1 reader cleanup/identity-safe unregister/target idle expiry.
The freeze contains reviewed implementation, tests, shared integration and docs.
Freeze itself changes documentation/status only.

PHASE18_FREEZE_CHANGE_MANIFEST and STAGED_PHASE18_FREEZE_MANIFEST classify every
file externally. Raw logs/hashes, binaries, temporary TLS material and runtime
state remain outside Git. Module files/migrations/schema are unchanged.

## Protocol Identity

ProtocolID: **trojan**. EngineID: **native**. Wire version: standard; profile: base.
Splicore owns protocol/trojan/wire and protocol/trojan/backend;
internal/splicore/protocol/trojan owns managed configuration and URI integration.
Go TLS/crypto and shared Splicore services provide the runtime. No production
sing-box, Xray, trojan-go or external proxy subprocess is used. Peer processes
exist only in external interoperability validation.

## Capability Matrix

| Capability | Actual final scope |
|---|---|
| Server | Native TLS listener, bounded auth and TCP/UDP relay |
| Client | Native verified TLS outbound; owned pending/published sockets |
| TLS | Mandatory; system trust or explicit CA; minimum TLS1.2 |
| TCP CONNECT | Standard command1, eager request, bidirectional payload PASS |
| UDP ASSOCIATE | Standard command3, canonical frames over TLS PASS |
| IPv4 | Real TCP/UDP peer and TUN traffic PASS |
| IPv6 | Real TCP/UDP peer and TUN traffic PASS |
| Domain target | TCP PASS; UDP PASS with sing-box/self; Mihomo peer caveat |
| Multi-user | A/B TCP/UDP, attribution, mutations/rollback PASS |
| URI import | Strict standard TLS/TCP; escaped credential and defaults |
| URI export | Faithful subset; lossy trust/UDP/ALPN forms reject |

## TLS

Mandatory verified Go TLS. Connect endpoint and verification/SNI name are separate.
Optional bounded ALPN follows the shared model; no required HTTP ALPN is invented.
The shared public model exposes no insecure verification option; insecure imports
reject. Server cert/key/leaf/chain/name/validity are validated and snapshotted before
activation. Static replacement follows controlled generation ownership. No ACME,
watcher or fingerprint spoofing feature. TLS/auth establishment budget: five
seconds or earlier caller deadline. Close interrupts and joins pending IO.

## Authentication

Canonical SHA-224(password), fixed lowercase ASCII hex authentication. Matching
compares all fixed-size user credentials with crypto/subtle, without early return;
duplicate derived identities reject. Shared encrypted vault owns passwords;
runtime generations retain derived credentials. Ordinary projections/logs/errors/
support redact secret-equivalent material. Explicit authorized export is the
existing disclosure boundary. Rotation preserves credential identity and replaces
the inbound generation; reference conflicts roll back. Affected inbound sessions
close; B's credentials and new sessions remain valid. No actual secret is printed.

## TCP

Bounded fragmented/coalesced request parsing consumes exactly the header;
coalesced payload remains for the protected CONNECT target. Full duplex relay
joins both directions. Eager requests allow server-first traffic. Client write-half
close preserves reverse response; full Close aborts raw IO before TLS Close.
Failed/short request commits close the framing owner; no subsequent false-success
write can follow a contaminated frame.

## UDP

Canonical address/port + uint16 length + CRLF + exact payload over TLS.
Fragmented/coalesced parsing, empty payload and wire ceiling65,535 are supported;
kernel UDP/IP limits are separate. A short buffer consumes/drops one datagram with
io.ErrShortBuffer. One stream owns an association; no mux/segmentation or detached
datagram writer. Cancellable write admission is bounded. Every failed admitted
TLS frame write, including zero-byte TLS error, terminalizes that association;
queued cancellation touches no stream. Separate associations are independent.

## Idle Expiry / Target Lifecycle

Parent association owns a private host/port endpoint map capped at128 active
targets. Each target owns its protected ServerTarget socket, private scratch,
reader, terminal/Close state and one positive-idle timer worker.

Timeout source: existing generic relay idle argument; Trojan passes **five seconds**.
Outbound admission refreshes before IO to serialize against expiry; successful
outbound completion and inbound remote reads refresh again. Time only advances.
Sibling traffic cannot keep a quiet target alive. Timer events check current
activity and pointer identity; stale T1 events rearm for refreshed T2.

Every target reader error is terminal under inherited policy. Retirement marks
terminal, signals stop and deletes only if registry[K] is that exact owner.
Socket Close runs once outside the mutex; reader/timer completion is joined.
Old A cleanup/timer cannot delete or close B. Next datagram creates a fresh
protected socket/reader under the same parent/key. Target write error/short write
retires locally and drops that datagram without uncertain replay.

Parent shutdown marks closing and detaches/stops owners under the mutex, unlocks,
closes framed parent and target sockets and joins all admitted workers.
Late registration rejects. No map lock spans dial, IO, callback/Close or Wait.
Framed parent write failure retains association-terminal semantics.

## T18R-001 Closure

**T18R-001 — CLOSED.** Original MAJOR: reader could terminate while its target
registry entry remained discoverable, producing later successful-looking writes
without reply readers. Documented target idle expiry was absent.
Final correction implements terminal cleanup, delete-if-same-owner, real expiry,
refresh, replacement safety and parent joins. Actual reply recovery is verified.
Original REVIEW FAILED and all failure evidence remain preserved.

Original fake reused one socket per dial and could not model a real new dial after
correct cleanup. User authorized preserving it and using independent sockets.
Final cleanup/lifecycle and actual reply cases each PASS x100. T18RR-001 NOTE
records the preserved intermediate copy's premature notification:99 reader PASS /
1 FAIL; idle100 PASS. Failure remains failure. Necessary cleanup bookkeeping
strengthens completion without removed assertions or increased one-second timeout;
the final deterministic suite passes. Raw external fixtures are not staged.

## Fallback

**DEFERRED — NON-BLOCKING.** Canonical specification describes fallback and peers
expose it; Phase18 explicitly permits deferral. Invalid TLS/auth/request closes
generically. This is a product limitation, not a claim of absent standard behavior.

## Interoperability

Pinned real peers: **Mihomo1.19.30**, **sing-box1.14.1**.

| Client | Server | TCP | UDP | TLS/SNI |
|---|---|---|---|---|
| Mihomo1.19.30, A/B | Splicore | PASS | PASS,12 datagrams/user | verified |
| Splicore | Mihomo1.19.30 | PASS | PASS,8 numeric datagrams | verified |
| sing-box1.14.1, A/B | Splicore | PASS | PASS,12 datagrams/user | verified |
| Splicore | sing-box1.14.1 | PASS | PASS,12 incl. domain | verified |
| Splicore | Splicore, two controls | PASS | PASS,12/control | verified |

Eight audited rows; TCP3MiB/row. Peer binary/archive and Splicore hashes are external.
Mihomo >8,192-byte split/reject (T18-COMPAT-001) and domain UDP conversion limitation
(T18-COMPAT-003) remain peer limits. Strict CRLF and unsupported mux/command
rejection remain (T18-COMPAT-002). Canonical datagrams are not silently changed.

## Lifecycle

Server owns accepted/pre-auth sockets (cap512), listener, TLS/auth generation and
joined workers. Clientio owns pending opens/published sockets. Packet owner commits
private frames synchronously and joins admitted writes, reads and cancellation
callbacks, preserving live deadlines. Old reader/timer/socket ownership ends on
retirement; replacement/shutdown leaves no permanent registry or worker residue.

## Routing / DNS / Policy

Shared routing, resolver and policy groups remain authoritative. Target/proxy
sockets use approved protected dialers; Trojan adds no private resolver/routing
subsystem. Real mixed TUN traffic covers shared routing, DNS and policy paths.

## Native TUN

Real isolated Native TUN → Trojan TCP/UDP, IPv4/IPv6 and proxied DNS/routing/policy:
**x25 PASS**. Stopped target readers/timers/sessions=0, routes/rules restored,
direct TCP/UDP leaks=0. Supplemental isolated WSL evidence is not host qualification.

| Resource | x25 Start / Sampled peak / End | Mixed Start / Sampled peak / End |
|---|---|---|
| Goroutines | 6 /19 /6 | 30 /314 /30 |
| FDs | 14 /18 /14 | 23 /91 /23 |
| Sessions | 0 /1 /0 | 0 /29 /0 |
| Target readers | 0 /1 /0 | 0 /1 /0 |
| Idle workers | 0 /1 /0 | 0 /1 /0 |
| EventFDs | 1 /1 /1 | 1 /1 /1 |
| Listeners | 2 /2 /2 | 7 /7 /7 |

Peaks are sampled. Legacy sampler did not aggregate SocketFDs/HostGenerations/
Interfaces/JournalTemporaries peaks; those fields remain null externally and raw
accumulators are retained. RSS allocator retention is not claimed to return to
baseline. Controlled PendingWrites=0 is fixture bookkeeping.

## Management Integration

Existing Account/Binding/Credential, owner-bound encryption, immutable Nodes,
reference checks and optimistic generation transactions are reused.
Generic rotate/delete extends the existing writer/endpoint, with exclusive
references and rollback. No schema/migration or Trojan-specific account store.

## URI / Provider

Strict escaped URI, IPv4/IPv6/domain, default443, SNI/peer, optional ALPN and label.
Duplicate/unknown/insecure/extension options reject. URI cannot faithfully represent
explicit CA, disabled UDP or comma ALPN, so those exports reject. Pinned peer config
formats use reviewed trust/capability mappings; fingerprint alone cannot reconstruct
a CA and rejects. Provider preview/apply/refresh preserves encrypted sources,
stable IDs, committed credentials and reference safety.

## API / CLI

Existing Application Service supports creation and binding mutation.
Optional rotate with write-only credential or delete uses the existing binding
API/CLI. No protocol-specific management service or new command engine.

## Backup / Restore

Existing encrypted backup/restore covers Trojan credential/reference integrity.
Ordinary reports contain no raw credential URI or private key material.

## Stats / Doctor / Support Bundle

Shared user/session/TCP/UDP/byte counters attribute A/B traffic. Doctor/support
projections recognize Trojan under the existing redaction policy; no raw digest,
header or private key is emitted.

## Review Evidence

### REUSED VERIFIED REVIEW EVIDENCE

Final-source Fix Round and final re-review implementation/module bytes match.
Long gates below were audited and reused; they were not rerun during Freeze.

| Gate | Verified result |
|---|---|
| Full default tests | PASS |
| Default/native/shared race | PASS |
| checkptr | ON |
| Nine fuzz targets | PASS;5,628,303 executions, crashes/timeouts0 |
| Bidirectional external interop | Eight pinned rows PASS as above |
| Native TUN | x25 PASS |
| Mixed stress | 10m34.647753425s,12 rounds; unexpected0, direct leaks0 |
| Real target expiry/recreation | 12 kernel-inode sequences, same TLS association |
| Target churn | 10,000 cycles,20,000 controlled sockets, final owners0 |
| Final corrected/real reply cases | each x100 PASS |
| Final targeted race | x25 PASS,25,000 competition cycles |
| Native TCP/UDP/framing contracts | x25 PASS |

Reports:

- Implementation: PHASE18_NATIVE_TROJAN_IMPLEMENTATION_REPORT.md.
- Original review: D:/splicore-validation/phase18-trojan-review-20261007/PHASE18_TROJAN_REVIEW_REPORT.md.
- Fix: D:/splicore-validation/phase18-trojan-review-fix1-20261007/PHASE18_TROJAN_REVIEW_FIX1_REPORT.md.
- Final review: D:/splicore-validation/phase18-trojan-rereview-20261007/PHASE18_TROJAN_REREVIEW_REPORT.md.

Re-review preserved1,146 repository files and verified1,998 historical evidence
files unchanged. Freeze also protects final review artifacts. Retained historical
failures are not counted as final-source passes.

## Freeze Quick Gates

### FREEZE QUICK GATES

Exact extracted index candidate: go mod verify; go list ./...; all-Go AST
SagerNet source/direct/graph/three-binary audits; module identity; production
Underlay; full candidate secret scan; Linuxamd64/Windowsamd64/Linuxarm64 native
builds and targeted TUIC production consumer tests: **PASS**.
Final documentation is restaged and a new final tree is verified before commit.
Required post-commit gates use a fresh extraction of the exact frozen commit/tree;
actual final hashes/results/cwd/UTC/duration/exit are recorded externally in
D:/splicore-validation/phase18-freeze-eol-recovery-20261007/.
No full-suite, long stress/fuzz or destructive qualification rerun.
All Go/test/module bytes are exactly reviewed; the eleven authorized non-Go
EOL differences preserve normalized bytes. Freeze documentation is separately audited.

## Existing Protocol Regression

Final default/native/shared races and mixed traffic cover SS/SS2022/Snell/HY2/TUIC/
VLESS/Mieru. Shared relay change is the reviewed Phase18 fix; Freeze adds no fix.
Legacy Snell saturation remains **PRE-EXISTING NON-BLOCKING LIMIT** with actual FAIL.

## Phase17 Finding Regression

| Finding | Retained reviewed status |
|---|---|
| R17-001 | CLOSED |
| R17-002 | CLOSED |
| R17-003 | CLOSED |
| RR17-001 | CLOSED |
| RR17-002 | CLOSED |
| VLESS_PARTIAL_FRAME | CLOSED |
| VLESS_ASSOCIATION_REGISTRY | CLOSED |

Frozen closure evidence, unchanged affected codecs/backends and final Phase18
native/shared regression evidence support these statuses. No finding reopened.

## SagerNet Audit

Source imports **0** / Direct **0** / Graph **0** / Binary modules **0**.
Exact index candidate and frozen commit audits are recorded externally.
Existing required derivative attribution remains.

## Module Identity

**github.com/ike-sh/Splicore**. Minimum Go1.26.3; toolchain Go1.26.6.
No replace directive, dual module identity or compatibility shim.

## Dependencies / Attribution

Phase18-added modules: **NONE**.

| Module | Version | Purpose | License |
|---|---|---|---|
| NONE | — | Standard library and existing reviewed modules | — |

go.mod/go.sum unchanged. go mod verify PASS; local gVisor/Mieru/quic-go/other
module-cache source modifications=0. LICENSE, NOTICE.md, THIRD_PARTY_NOTICES.md and
95 notices for69 modules are unchanged and match cache bytes.
Historical SagerNet attribution is retained.

## Underlay

Actual production surfaces: **75**; test surfaces: **144**; **Unknown=0**.
Trojan: owned local TLS ingress, protected server TCP target, protected server UDP
target/recreation and protected client proxy TCP dial. Probes use shared approved
outbound paths; TLS adds no separate socket bypass.

## Xray Boundary

Actual verified **E=0 / F=0 / G=10**, full source/test/tool/doc scope.
Same ten reviewed G rows remain unchanged; no active external-core runtime.
FinalMask runtime0, Sudoku runtime0; Vision DEFERRED.

## Platform Builds

| Platform | Fresh quick build | Qualification |
|---|---|---|
| Linux amd64 | PASS | NOT REQUALIFIED |
| Windows amd64 | PASS | NOT REQUALIFIED |
| Linux arm64 | PASS | BUILD ONLY; runtime NOT CERTIFIED |

## Platform Qualification

Historical: **PARTIALLY PASSED**. Phase18 Freeze: **NOT REQUALIFIED**.
Current candidate: **NOT PLATFORM QUALIFIED**. Implementation blockers: **NONE KNOWN**.

| Gap | Retained canonical boundary |
|---|---|
| GAP-01 OPEN | Qualified long-duration goroutine measurement unavailable on historical frozen packaged daemon; earlier soak interval goroutines missing. Short current tests do not close it. |
| GAP-02 OPEN | Windows destructive real-network safe target unavailable; Windows race compiler prerequisite also absent. |
| GAP-03 OPEN | Native Ubuntu host-network target unavailable; isolated WSL kernel TUN is supplemental evidence. |
| GAP-04 BUILD ONLY | Linux arm64 actual runtime target unavailable; runtime NOT CERTIFIED. |

No qualification rerun. Protected report SHA256 remains
18065f3ca3c5f34f5ac8d8e0d52b34a80218f7a6f4ab418f256467c80996bba7.

## Known Limitations

Fallback DEFERRED — NON-BLOCKING; standard TLS/TCP scope excludes WS/gRPC/HTTP upgrade/
plaintext/mux/camouflage/fingerprint extensions. Managed-password and faithful
export restrictions remain. Mihomo UDP size/domain limits remain. Historical
Snell limit, arm64 runtime gap and GAP01–04 remain. T18RR-001 fixture NOTE remains;
raw failures preserved. These limits are not removed by Freeze.

## Git State

Branch: codex/phase-18-native-trojan.
Commit: containing this report; full hash recorded externally after commit.
Message: feat(protocol): add native trojan server and client.
Sole parent: dabe4030fb82f272b8e1035779e2b8c4da9b0600.
Final working tree: **CLEAN**. Index: **EMPTY**.
Explicit audited path staging; exactly one forward local commit.

## Public GitHub

**UNCHANGED by this transaction**. User-designated public versionv0.1.0 is not
updated. No remote write, v0.2.0 preparation or release publication.

## NoBrand-OneClick

**NOT ACCESSED**.

## Actions Not Performed

No push, tag, release, public update, rebase, amend, squash, history rewrite,
new fix/refactor, dependency patch, destructive qualification, Phase19 or VMess.
All raw evidence remains external.

## Initial Freeze Block — Preserved History

Initial Freeze Attempt: **BLOCKED — EOL byte drift**. Eleven raw-byte mismatches;
Go source/module drift=0; commit not created; staging was undone.
The following account describes that earlier authorization and outcome. Its old
evidence remains immutable in D:/splicore-validation/phase18-native-trojan-freeze-20261007/.


The initial working snapshot exactly matched all1,146 final re-review files.
Only six authorized Freeze documentation/status files were modified. Explicit
staging included exactly41 authorized Phase18 paths; no unexpected path.

The staged complete tree has11 pre-existing files whose raw bytes differ from
the reviewed working-tree snapshot: ten historical docs and
tests/fixtures/nobrand/tuic.json. Every difference is CRLF versus LF only.
Every extracted blob already equals the frozen Phase17 Git blob; Go/module
drift=0 and no implementation behavior change was detected. Nevertheless,
this request requires strict raw-byte identity, including fixtures, and provides
no line-ending normalization exception. Therefore Freeze stops without a commit.

No unrelated file was modified or staged to make the comparison pass.
This transaction's41 staged paths were unstaged explicitly, retaining the working
files and authorized documentation. HEAD/history and all protected evidence remain
unchanged. ADR0039 architecture acceptance and T18R-001 CLOSED remain valid.
This block does not reopen the implementation review.

See external staged/source-identity.json and staged/snapshot-drift-analysis.json
for exact paths/hashes and the proven newline-only differences. Raw staged archive
and intended/staged manifests remain outside Git.

## EOL Normalization Recovery

Recovery: **PASS — Git index EOL normalization independently verified**.
Reviewed semantics are preserved. Git index normalization only.

- Exact drift list reused from sealed prior Freeze evidence: ten historical
  Markdown files and tests/fixtures/nobrand/tuic.json, exactly eleven.
- Current working bytes match reviewed SHA256. Candidate blobs equal Phase17 blobs.
- Only CRLF -> LF normalization is used. Encoding/BOM, final newline, logical line
  counts, all per-line bytes, blank lines, tabs and trailing whitespace match.
- Raw Go production/tests/go.mod/go.sum drift=0; other implementation drift=0.
- Existing core.autocrlf=input originates from Git system config. core.eol and
  core.safecrlf are unset; repository .gitattributes absent; text/eol/encoding
  attributes unspecified for all eleven. No persistent configuration is modified.
- Explicit audited 41 paths are staged with per-command core.autocrlf=false to
  preserve reviewed new Go bytes. The eleven baseline blobs are not modified/staged.
- Exact candidate exported from git write-tree/git archive and every blob object
  ID independently verified. Class A=1130, Class B=11, unauthorized Class C=0;
  six separately authorized Freeze documentation/status paths are audited.
- Actual fixture consumers: strict JSON, TUIC creation/settings, registry creation
  and JSON compaction used for creation digest. Exact template rejection and positive
  typed drafts after in-memory TLS placeholder filling match. All targeted tests PASS.
  The fixture is unrelated to T18R-001; no EOL protocol/golden/script input is present.
- All candidate quick gates PASS. Secret real/unresolved=0/0; SagerNet0/0/0/0;
  Underlay75 production/144 test/Unknown0; three builds PASS (arm64 BUILD ONLY).
- No implementation/test/fixture semantic change; original review and failed
  attempts remain preserved. Initial candidate tree: 689ceafde29935ab6a9e732d753a1aa94143d966.
- Updating this report changes the tree. The final candidate is rewritten and
  verified; the exact final tree and committed-tree equality are recorded externally
  in final-tree-verification.json and PHASE18_FREEZE_EOL_RECOVERY_REPORT.md.

Final commit/tree identities are resolved without a self-referential report hash:

    git log -1 --format=%H -- docs/reports/PHASE18_NATIVE_TROJAN_FREEZE_REPORT.md
    git rev-parse HEAD^{tree}

# PHASE 18 FROZEN
