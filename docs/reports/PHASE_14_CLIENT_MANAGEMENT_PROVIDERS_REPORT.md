# Splicore Phase 14 Client Management Providers Report

- Documentation status: Historical
- Audience: Maintainers and acceptance reviewers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Phase 14 implemented scope, reproducible local acceptance and retained qualifications.
- Lifecycle: Preserve this candidate evidence after review; create a new record for later acceptance.

## Baseline

Phase 13 Freeze: `b0de8c16e1c810cb851c400b5d03987924d5eff8`.
Branch: `codex/phase-14-client-management-providers`; entry working tree CLEAN.
Upstream sing-box v1.14.1 / `1ac1a339cb1223e9c70eae14c44411c75033c02d` unchanged.
Xray official v26.3.27 / `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`, same pinned artifact.
Official Mieru dependency v3.38.0 unchanged. SQLite schema 7→8; config schema 1,
protocol ABI 1, protected API v1 unchanged.

Evidence root: `D:\splicore-validation\phase14-20261004` (WSL `/mnt/d/splicore-validation/phase14-20261004`).
New owned service root: `/root/splicore-p14-20261004`. Prior evidence was preserved.
Windows Go 1.26.2 / WSL Ubuntu-24.04 Go 1.26.6. Modules and checksums offline;
no third-party traffic probes, downloads, Docker queries, NoBrand access or host Windows
network mutations. Entry manifest hashes 2069 tracked regular files / 1312 protected paths.

## Status

Node Management: Experimental, canonical CRUD plus preview/apply batch.
URI Import: bounded audited HY2/TUIC/VLESS/Mieru subsets; unsupported entries explicit.
Canonical Import: schema 1, all five supported protocols, explicit secret export/reimport.
Proxy Provider: Experimental, encrypted sources, guarded transactional generations.
RuleSet Provider: Experimental, canonical and bounded Mihomo formats.
Subscription: remote ingestion implemented as ProxyProvider; Account/export-token/public
subscription serving remains separate and deferred. No Stable designation.

Contracts: [Node](../architecture/NODE_MODEL.md), [Import](../architecture/IMPORT_MODEL.md),
[Provider](../architecture/PROVIDER_MODEL.md), [RuleSet Provider](../architecture/RULESET_PROVIDER.md).

## Node Identity

Immutable ID: persistent random UUID v4, never URL/name/index/fingerprint as resource ID.
Provider stable identity: scoped hashed source-native key, or non-secret normalized fingerprint.
Fingerprint: normalized protocol/endpoint/transport/public security/options; excludes IDs,
credentials, names/order/tags/metadata/provenance/state. Native keys are hashed before reads.
Credential rotation preserves Node: PASS, stable native key and new encrypted credential reference.
Rename preserves refs: PASS. Reorder preserves IDs: PASS, also generated Outbound IDs.
Same key with incompatible protocol rejects Conflict; replacement requires new source key.
Different provider keys may share endpoint/credentials as separate nodes. Same key with
different credentials in one feed rejects ambiguity. Manual/provider overlap never merges
ownership. Manual exact duplicates compare settings and actual credentials; changed
manual credentials can remain separate identities. Display names may collide/builtin names
do not overwrite ID-based selection. No provider/tag dynamic membership implemented.

Installed regression discovered command dispatch intercepted the previous node apply
--file/--plan flow. The minimal compatibility branch now retains that CRUD transaction
while node apply --plan alone uses management tokens; a regression fixture and full
Windows/Linux tests cover both. Preliminary service-driver empty-list handling was
also fixed in external test code; failed trials remain in evidence.

## Import

Preview: Add/Update/Unchanged/Conflict/Remove/Unsupported/Invalid with fixed change codes.
Dry-run: no SQLite/resource/runtime mutation; remote preview may perform fetch.
Strict: default; invalid/unsupported prevents apply. Lenient: explicit valid-entry apply;
ambiguity/reference/empty/removal guards remain blocking. Redaction: URI/raw source/auth/
candidate secrets absent from response/errors/log formatting.
Plans: max32 complete bounded in-memory snapshots, five-minute expiry, random single-use
token and global revision. Restart/expiry/consumption/stale revision requires re-preview.
Apply uses existing runtime preparation and atomic repository transaction, never importer
runtime construction. A fault after writing nodes/credentials/source validators rolls back
all state and preserves old traffic. Metadata replacement can move folders without
changing provenance; provider ownership transfers are unsupported.

## URI Support

| Protocol | Accepted / boundary |
| --- | --- |
| Snell | URI unsupported; no audited formal sharing contract. Canonical/external fragments available. |
| Hysteria2 | Official hy2/hysteria2 auth/host/default443/SNI/system-trust, insecure=0; advanced/unsafe fields reject. |
| TUIC | Audited Mihomo v1.19.30 **unofficial temporary dialect**, UUID:password/mandatory port/SNI/h3/cubic/native. Token/v4/extensions reject. |
| VLESS | Existing bounded TCP/flow-none/XUDP/plain or REALITY public sharing contract; Vision and masks reject. |
| Mieru | Official v3.38.0 mierus simple URL and mieru base64 protobuf config via official parser, strict representable fields. |
| Unsupported | Unknown schemes, Snell URI, Vision, client masks, server private keys, insecure/unknown extensions. |

Source/runtime reference evidence is distinguished from Splicore acceptance: real tests
import canonical all five protocols and URI VLESS/Mieru then pass actual traffic. HY2/TUIC
URI parsing is covered; owned all-protocol traffic validates their canonical runtime.
No claim of external URI-client interoperability beyond audited dialect/fields.

Source audit: [official Hysteria URI](https://v2.hysteria.network/docs/developers/URI-Scheme/),
[Mihomo v1.19.30 converter](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/common/convert/converter.go),
[official Mieru v3.38.0 URL implementation](https://github.com/enfein/mieru/blob/v3.38.0/pkg/appctl/url.go),
existing [VLESS contract](../protocol/VLESS.md). Versions/unknown-field/trust boundaries
are documented in Import Model; no invented URI or runtime feature added.

## External Config Import

Mihomo: bounded proxies-only JSON/YAML. sing-box: supported outbound object/outbounds wrapper.
Mieru: official client config, one representable server/binding per profile.
Xray: full/client-profile import deferred; bounded VLESS URI remains available.
Scope: canonical node definitions only; no policy/server config passthrough/raw storage.
Unknown/duplicate/cross-protocol fields reject; YAML aliases/anchors/merges/custom tags/
multiple documents/size-depth bombs reject. CA-pin formats not represented by canonical
trust reject without downgrade. Auto detection only obvious canonical JSON/URI; explicit
base64 strict bounded decode. Export supports canonical all five plus existing exact-version
Mihomo/sing-box/VLESS URI, bounded HY2 URI and official Mieru config. External compatibility
details expose Snell v5 server/v4 client mapping in API and CLI stderr. TUIC/Mieru/Snell URI
export deferred; unsupported selected node makes the export fail, not disappear silently.

## Provider

Fetch: existing committed runtime DIRECT/outbound/group plus typed ProviderFetch lease.
HTTPS verification: normal verified TLS/SNI, no skip. Timeout: 15s total/5s handshake/10s headers.
Body limit: 2MiB wire + 2MiB decoded; headers16KiB, gzip bounded, other encodings reject.
Redirect: max3, target/scheme revalidation, HTTPS downgrade reject, cross-origin auth and
validators stripped. SSRF policy: default deny private/loopback/link-local/metadata/reserved;
explicit allow_private permits internal loopback/RFC1918/ULA, never link-local/reserved.
Complete DNS answers validated then numeric address pinned. No ambient proxy/second stack.
Auth: explicit bearer/basic/Authorization/X-Api-Key, encrypted and bounded, CR/LF/NUL reject.
ETag: encrypted persisted conditional fetch. Last-Modified: same. 304 does not advance
provider generation/runtime; successful diagnostics may advance global revision.
Scheduler: one ticker coordinator, four workers/slots, bounded queue, same-provider full
refresh serialization, cancellation/join, narrow lifecycle/control locks, no payload lock.
Cadence60s–30days/default1hour; deterministic0–30s jitter, no initial startup fetch.
Backoff: bounded exponential, never shortens configured interval; monotonic timers.
refresh_enabled controls updates only; batch disable controls nodes separately.

## Generation

Initial: candidate validated/prepared before commit/publication. Refresh: complete atomic
canonical generation and encrypted validators. Failed refresh: old generation/traffic stays,
safe fetch/parse/validation/apply/safety/revision error classifications. Empty feed: rejected
by default; explicit authoritative empty + threshold required. Mass delete guard: default50%,
configurable1–100; zero means default. Old generation: established TCP/UDP leases retained;
no daemon/server/TUN restart. Host activation failure after SQLite commit remains degraded
committed intent with recovery debt under existing Prepare/Activate semantics.

## Node Removal

Unreferenced: node and owned generated outbounds removed transactionally.
Referenced: retain stable node/outbound ID and mark stale; no dangling reference/cascade.
Stale state: current explicit policy permits new sessions on last-good settings. Operator
can batch disable to refuse new sessions. Orphan handling: retain while reference remains;
future valid feed reactivates same identity, later unreferenced removal can delete it.
Provider delete preview blocks references including manual outbounds, groups/routes/DNS/
local selections/fetch dependencies. Tags/disabled/operator metadata survive refresh.

## Credentials

Rotation: validated replacement encrypted record/reference, same logical node/outbound IDs.
Rollback: PASS, candidate write fault preserves state/source validators/old traffic.
Secret storage: existing master vault/AAD plus provider-specific source AAD. No raw feed cache.
Logs: fixed errors/redacting formatters; API: passive GET/preview contains no credential/source
payload. Explicit export requires reveal_secrets and yields only client secrets, never
REALITY server private key. CLI imports via owner-only regular file/stdin; URI argv rejects.

## RuleSet Provider

Formats: canonical-rules, Mihomo domain/ipcidr/classical bounded domain/CIDR matchers.
Fetch: same protected infrastructure and independent typed API. Compile: complete existing
match/network validation before commit. Atomic swap: future sessions new snapshot, old
sessions old ownership. Failure rollback: old rules preserved on invalid/commit failure.
Limits: 2MiB raw/decoded, 10000 rules, existing field/depth/regex/CIDR compile budgets.
Empty RuleSet always rejects because canonical RuleSet requires nonempty rules, including
with empty_is_authoritative. Recursive/local reference/hint/action inputs reject.
MRS/sing-box binary/full rules import deferred. [Mihomo contract](https://wiki.metacubex.one/config/rule-providers/content/).

## Policy Integration

Provider nodes: generated or manual outbounds with stable references; generated owner
cannot be forged. Dynamic membership: deferred; tags are annotations, not selectors/security.
Health: provider fetch status separate from node connectivity. Selector/URL-Test/Fallback/
Load-Balance: existing Phase12 committed snapshot and bounded health infrastructure;
no refresh-triggered probe storm or duplicate health scheduler. Node/outbound counters
retain immutable ID identity; unchanged adapters retain passive health; replacement
credential health starts unproven. Ephemeral counters reset on daemon restart as before.

## Underlay

Provider fetch protected: PASS, typed construction/endpoint lease plus runtime fixture/TUN.
New node publish protection: PASS, reused Phase13 prepare/readback-before-publication.
Dynamic endpoint: existing bootstrap/reconciliation, original logical name preserved,
no second route-bypass algorithm. Transitive provider→fetchgroup/outbound→node ownership
cycles reject. Unknown egress inventory: 0;65 production/114 test surfaces (expected0). Payload paths use no
global mutex. HTTP body/socket cleanup precedes temporary lease/snapshot release.

## Offline Recovery

SQLite: schema8 last-good canonical nodes/credentials/tags/providers/rules and encrypted
source validators. No raw remote cache or online authority. Last-good generation: restored
before runtime/listeners/scheduler. No network startup requirement: PASS. Traffic: PASS
after owned source shutdown and restart; SQLite MaintenanceBackup/restore with original
master key restores encrypted state without refetch. Plain backup scan contains no secrets.
Installed service persistence: PASS after real systemctl restart, failed-upgrade rollback
and uninstall/reinstall with both source fixtures already shut down. No refetch.
The source URL/auth/validator state remains encrypted in the retained SQLite/key checkpoint.

## API

Protected /api/v1 imports/preview+apply, nodes/import-preview+batch-preview+export,
providers and separate rule-set-providers collections/resource/refresh-preview/refresh.
GET safe metadata; create/update/delete return previews. Strict4MiB envelope/no queries;
endpoint identity/kind enforced. token/revision governs apply; stale409. Source write-only;
read-only diagnostics cannot be supplied as nonzero config. Exact machine contract and
live-response validation: [API](../api/API_V1_DESIGN.md).

## CLI

node import/import-uri/apply/batch/export; provider/ruleset-provider create/update/delete/
list/get/refresh-preview/refresh/apply. Secret file/stdin only; regular file/size/identity
checks. Export one selected scope + explicit reveal, exact external client version.
Generic compatibility details on stderr. Existing protected transport/service reused.
[Commands](../CLI.md). No public endpoint/new process.

## Doctor

Passive provider/ruleset/degraded/stale counts, scheduler/active refresh observations.
No provider fetch/probe occurs. Corrupt provider/client state yields a fixed diagnostic
classification while Server Runtime/control queries remain available.

## Support Bundle

Provider secrets: NONE. Raw subscription: NONE. URL secrets: omitted from bundle;
redacted scheme/host-only ordinary provider reads. Bundle projects only fixed enums,
generation/node/stale counts and update age; drops names/URLs/auth/validators/tags/metadata.
Hostile source projection and installed support secret gate protect this boundary.

## Race

Default: PASS, Linux final full owned+cmd tests with -race, default checkptr.
Shared: PASS, dialer/dns/route/direct/Snell/HY2/TUIC/VLESS/clientio.
Refresh/Scheduler/Reconcile/Shutdown: PASS, entire Phase14 test suite count10.
Actual TUN binary: compiled with -race and default checkptr; wrapper gate metadata reports
outer Python command as race not requested, so use the explicit compile command/log.
No GODEBUG/gcflags/checkptr suppression, skipped test, recover panic or sleep workaround.
Windows race: NOT EXECUTED, retained qualification limit.

## 10x

Refresh: PASS. Credential rotation: PASS. Rename/reorder: PASS. Failed refresh: PASS.
RuleSet updates: PASS, real route reject/allow. Scheduler start/stop: PASS. Final entire
Phase14 suite also count10; bounded scheduler clock/cancellation, commit rollback,
API/CLI secrecy and backup restore included. Real TUN held connection/rotation10x covered.

## Fuzz

URI/Feed/Fingerprint/Diff/RuleSet/URL sanitizer: PASS, each10s, -race/defaultcheckptr,
parallel2, local-only. ProviderDiff builds bounded local repository fixtures; no internet.
Pure parsing/canonical normalization seeds include duplicate/unsupported/base64 cases.
Exact gate logs record corpus/executions; no panic/race observed.

## Limits

Response/input/decoded: 2MiB. Nodes:128 unchanged. Outbounds:129 unchanged.
Providers:64. Plans:32×boundedcandidate/5min. URI:4096bytes. Node line:16KiB.
Rules:10000; compile has existing structural bounds. Decompression:2MiB decoded gzip.
API envelope4MiB; CLI file/stdin2MiB. Worker/queue concurrency4. DNS answer32addresses.
UTF-8 labels/tags/metadata validated; names can collide without overwriting resources.

## Security

SSRF: validated all DNS addresses + pinned numeric dial, explicit internal opt-in.
TLS: verified; redirect: revalidated/no downgrade/no cross-origin auth forwarding.
Secrets: encrypted source/validator and existing node credential vault, redacted passive
outputs, no raw feed/cache. No telemetry: PASS. No public subscription listener.
Provider config is operator-owned input; exported files remain secret-bearing.

## Regressions

Server: PASS, final full owned critical five-protocol native/Xray tests.
Client: PASS, local ingress/six outbound placements/disable-enable/canonical roundtrip.
Routing/DNS/Policy: PASS, full owned/shared gates and atomic remote RuleSet traffic.
TUN/Underlay: PASS, Phase13+14 actual owned kernel lab, reuse/restore and inventory.
Distribution: PASS: clean install/restart/parent-child crash/Phase13 schema7→8 upgrade/fault schema9 rollback/doctor/support/default uninstall-retain/reinstall/purge.
Installed owned provider fixture restores ten nodes, two providers, tags/folder metadata
and RuleSet generation1 with source unavailable, then passes actual proxy traffic.
Final local packaging uses candidate-final/update.json; final-service-accepted-gates.json
and final-docs-live.json are the exact artifact/campaign evidence after documentation freeze.
Historical/upstream/dependency/migration protection: PASS,1312 protected paths unchanged;historical reports/migrations0001–0007/dependencies/upstream preserved.

## Architecture Metrics

Protocol-specific provider tables:0. Protocol-specific API resources:0.
New services:0. New binaries:0. Direct runtime config storage:0. New upstream files:0.
Parser protocol mapping stays in nodeimport; Application diff/fetch/batch is generic.
One existing manager/repository/vault/scheduler/data plane; schema8 two generic tables.

## Acceptance Scenarios

| Scenario | Evidence / result |
| --- | --- |
| A manual import | TestPhase14ImportAllProtocolsTraffic: canonical five/URI VLESS+Mieru, preview/apply/real echo PASS. Other audited URI parsers PASS. |
| B provider initial | TestPhase14ProviderLifecycleTraffic:10nodes/stablegeneratedoutbounds/realtraffic PASS. |
| C reorder | Reversed source10x; node/outbound identity persists PASS. |
| D rename | Labels10x and references unchanged PASS. |
| E credential rotation | Two owned Snell servers, same native key10x, old held/new traffic PASS. |
| F removal | Unreferenced deleted; referenced stale/traffic remains; delete guards PASS. |
| G fetch failure | 10x old canonical generation/traffic preserved PASS. |
| H invalid feed | Strict no partial apply, invalid rules retained, postwritecommitfault PASS. |
| I empty feed | Default empty and mass-deletion guards PASS. |
| J validators | ETag/304 no provider generation/runtime churn PASS. |
| K proxy fetch | Independent manual Snell outbound fetch PASS; self dependency rejects. |
| L remote rules | 10x atomic route reject/allow and invalid update rollback PASS. |
| M offline | Source shut down, SQLite restart/backuprestore last-good traffic PASS. |
| N reconcile10x | Final -race suite count10 and per-scenario10x PASS. |
| O shared server/client/TUN | TestPhase14KernelProviderTUN: rotation10x, held old stream,16concurrentTUNflows plus local ingress/server, same interface, restore PASS. |

## Gate Evidence

| Gate | Result | Elapsed |
| --- | --- | --- |
| linux-final-owned-race-2 | PASS | 134.64s |
| windows-final-owned-2 | PASS | 101.89s |
| linux-final-phase14-race-10x-2 | PASS | 96.37s |
| linux-final-shared-race | PASS | 22.16s |
| linux-final-vet | PASS | 27.58s |
| linux-final-tun-race | PASS | 106.97s |
| linux-final-fuzz-URI | PASS | 30.55s |
| linux-final-fuzz-Feed | PASS | 22.27s |
| linux-final-fuzz-Fingerprint | PASS | 22.24s |
| linux-final-fuzz-Rules | PASS | 22.37s |
| linux-final-fuzz-URL | PASS | 19.89s |
| linux-final-fuzz-ProviderDiff | PASS | 71.75s |

Logs and JSON under the external evidence root contain exact commands/exit/timing.
The final owned gate covers all local packages and cmd; shared gate covers affected
upstream packages without modifying them. The latest full/10x gates include the existing node CRUD CLI compatibility fix.
Shared/fuzz/kernel TUN gates precede only that CLI/control-test change; their runtime
network/parser implementations are identical. Later documentation/API-checker edits
do not change Go production source. Packaging provenance
records full source snapshot, and final audit binds its production hash to these gates.

## Distribution and Documentation Evidence

The complete service campaign starts from the frozen Phase13 package and upgrades
to the Phase14 candidate. It checks original DB/key/bootstrap retention and exact
historical migration checksums, then injects a schema9 DDL/failure fixture in a new
external source copy to verify coherent rollback. One existing non-root service
continues all server/client protocol and routing/DNS/policy regressions. Active TUN
uninstall/purge/restoration and partial permission failures reuse the owned lab.
No host Windows or external system is mutated. Native Ubuntu qualification remains
separate from this WSL nested-systemd evidence.

Records: package-final-gates.json (three platforms, source/archive reproducibility),
final-service-accepted-gates.json (exact final artifacts), phase14-upgrade/rollback/
reinstall.json (installed offline provider authority), cleanup.json and
network-restore-readback.json, final-docs-live.json, evidence-secret-gate-final.json,
underlay-authoritative/inventory-after.json, final-source-audit.json.
Nested systemd shutdown may retain timeout/failed bookkeeping as in Phase13; cleanup
requires MainPID0 and an empty/nonexistent owned cgroup before reset-failed. This
does not certify native-platform init shutdown. Actual route/readback restore and
no remaining lab process are checked independently.

Documentation:137 owned Markdown documents,111 machine operations; static links and
real server/client/host/provider/preview responses validated. Six protocol/runtime
and six network campaign snapshots use their pinned pre-upgrade/current schema.
Secret scan covers safe evidence/docs and all eight support archive members;
zero credential values/private keys. Import/export files remain private operator data.
ADRs0032–0034 record identity/generation, preview transaction and remote-source security.
Final source audit preserves1312 protected paths and checks tracked/new whitespace,
empty staging, exact branch/HEAD/main and identical owned Go source to tested build.

## Platform

Linux amd64: full runtime under existing Ubuntu24.04 WSL2, actual isolated namespaces and
owned service lab. Native Ubuntu qualification remains NOT CERTIFIED.
Windows: full safe owned tests and build; HTTP/provider fixtures only, no real host TUN/
routes/DNS/WinINET changes. Windows full race NOT EXECUTED.
Linux arm64: build-only, runtime NOT CERTIFIED. Xray client TCP half-close unqualified
and Vision/masked client features unsupported as in prior phases.

## Git

Stage:NONE. Commit:NONE. Push:NONE. Tag:NONE. Release:NONE.
HEAD/branch/index/main and Git history preserved. All Phase14 changes remain unstaged.
ADRs0032–0034 proposed for review; no freeze/merge/publication performed.

## Deferred

GUI, Panel, commercial subscriptions/payment, cloud sync, public subscription serving,
NoBrand migration, native platform qualification, Vision, client FinalMask/Sudoku,
Stable designation, provider/tag dynamic membership, Xray profile/MRS/sing-box binary
rules import, TUIC/Mieru/Snell URI export, durable usage and rawfeedhistory/OAuth.

## Final Result

CLIENT MANAGEMENT PROVIDERS READY FOR REVIEW

## Blockers

None within the bounded local Phase14 scope. Native platform/format feature limitations
remain explicitly Deferred; they are not certified by these fixtures.
