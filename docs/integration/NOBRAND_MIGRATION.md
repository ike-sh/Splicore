# NoBrand-OneClick integration and gradual migration

- Documentation status: Canonical
- Audience: Integration and deployment developers
- Last reviewed: 2026-10-02
- Owner: Integration maintainers
- Responsibility: Future NoBrand import, rollout, field-test and rollback boundaries.
- Lifecycle: Update with relevant design/code changes under the documentation policy.

NoBrand-OneClick is a first distribution/field-test consumer of Splicore, not
Splicore's product identity or code owner. Existing installation/source is not
inspected or modified in Phase 0; importer mappings need real old-state fixtures
in their later stage. Do not invent old schema or PSK/UUID extraction locations.

```text
pin qualified stable manifest → download matching platform artifact
 → verify digest/provenance → generate public Splicore declarative document
 → validate → plan → apply → inspect operation → health
```

NoBrand understands Splicore config/API/version/capabilities only. Native/private
engine config rendering belongs to Splicore. Installer uses a qualified stable
pin, not latest upstream/GitHub commit, and verifies digest before replacing binary.
Manifest declares compatible config/DB/ABI/API and upgrade/backup requirements.

## Per-protocol rollout

### Phase 3 synthetic Hysteria2 mapping

The [HY2 template](../../tests/fixtures/nobrand/hysteria2.json) is materialized
with external ephemeral CA/key references and synthetic credentials by the real
interop harness. Validate/plan/apply and SQLite recovery use only this fixture;
no real NoBrand source, installation or state was read or changed.

| Logical legacy value | Canonical HY2 import |
|---|---|
| name | `name`; explicit `users[].account_name` |
| actual bind | IP `listener.host` and `listener.port` (UDP) |
| public address | independent `display_endpoint.host` and `port` |
| password | optional private `users[].password`; omission generates |
| TLS/SNI | explicit `settings.tls.server_name`, public CA, certificate/key file references |
| obfs / masquerade | deferred; input rejects rather than dropping |

TLS identity never follows a display-address change. Migration must provision
protected files separately; production keys are not fixture material. Existing
passwords require the portable validation contract or planned rotation. TrafficPolicy
is explicit metadata only. This is logical mapping, not a claim about old extraction
paths or a production importer. See [HY2 workflow](../development/PHASE_3_HYSTERIA2.md).

### Phase 2 synthetic Snell mapping

The [synthetic fixture](../../tests/fixtures/nobrand/snell.json) and actual CLI
validate/plan/apply/export tests define the bounded managed import contract.
No real NoBrand state or installation was inspected or modified. Mapping below
describes logical legacy values, not invented legacy files/extraction locations.

| Logical NoBrand value | Canonical Snell import |
|---|---|
| name | `name` and explicit `account_name` |
| listen address/port | `listener.host` (IP) / `listener.port` |
| public address/port | `display_endpoint.host` / `display_endpoint.port` |
| PSK | optional private `psk`; omission generates a new key |
| version | `settings.version`: 5 or 6 |

A logical legacy v4 TCP profile requires an explicitly reviewed v5-server/v4-client
compatibility conversion; `settings.version=4` is rejected. A v5 profile depending
on QUIC Proxy Mode cannot be migrated to this managed profile. Native multi-user
userkey, obfs and non-default v6 modes also fail rather than being dropped.
Preserve a supplied PSK only when it satisfies the portable validation contract;
incompatible values need an explicitly planned rotation. Phase 2 creates fresh
Account/Binding IDs and has no upsert/idempotent production importer.

DisplayEndpoint never changes listener, routing or egress. NoBrand must use the
Splicore application/CLI/API and explicit secret export; it must not write SQLite
or render native server options. See [Snell workflow](../development/PHASE_2_SNELL.md).
Real canary/production rollout and stable qualification remain deferred.

| Stage | Migration gate / flag |
|---|---|
| A | `migration.snell`: qualified exact client/profile; Account binding/PSK+userkey model, one-account quota and reconnect |
| B | `migration.hysteria2`, `migration.tuic` independently: QUIC/UDP/families/congestion/policy and endpoint checks |
| C | `migration.vless_reality`: UUID/flow/SNI/public key/target and third-party compatibility |
| D | `migration.mieru`: only after native Stage 3 and official-client gate |
| Special | `vless` + `engine:xray`: audited official v26.3.27 FinalMask/Sudoku, bounded typed options and client/lifecycle gates |

Defaults off until qualification; flags are Splicore/installer rollout selection,
not hidden runtime bypasses. Track node/account/protocol migration state and source
ownership keys. Dual binaries can coexist temporarily for different protocols;
one actual listener owner per address/port. Plan downtime, stop old service, apply
new owned listener, health and reconnect; on failure restore old service/config
without racing the same port. Success records checkpoint before disabling old startup.

Snapshot old config/state/service topology, secure credentials and version; validate
import mapping and display endpoint separately. Missing usage history is labeled
unknown/incomplete, never implicitly reset to give extra quota. Conversion preserves
credential and wire behavior unless rotation is explicitly planned. No Big Bang.

Rollback restores compatible binary/state/service checkpoint with usage
reconciliation; schema-aware restore after a forward migration differs from config
rollback. Never delete old services/state just because process readiness succeeded.
Field beta collects local redacted support bundles (manual sharing), client/server
versions, TCP/UDP/reconnect/policy results and rollback evidence. NoBrand must not
reach SQLite directly or generate sing-box/Mieru/Xray runtime JSON after migration.

## Phase 4 synthetic TUIC mapping

[TUIC fixture](../../tests/fixtures/nobrand/tuic.json) materializes only synthetic
UUID/password/CA and native protected file references; real NoBrand was not accessed.

| Logical field | TUIC document |
|---|---|
| bind | IP listener.host/port; UDP |
| public endpoint | independent display_endpoint.host/port |
| credential | users[].uuid/password together, or omit both to generate |
| TLS/SNI | shared settings.tls explicit CA and cert/key file references |
| wire/options | version=5; cubic; native; zero_rtt_handshake=false |
| disabled identity | enabled Binding; account_enabled Account |

Logical contract only; no production extractor/canary. Policies metadata_only; no
enforcement. Input/runtime JSON never recovery authority. [Workflow](../development/PHASE_4_TUIC.md).

## Synthetic VLESS / REALITY mapping

Real `D:\code\NoBrand-OneClick` remains untouched. [Synthetic fixture](../../tests/fixtures/nobrand/vless-reality.json)
maps name, local listener, display endpoint, UUID, flow, public REALITY material,
short IDs, server name and target into the typed VLESS creation command. Engine
selection is separate and defaults native. REALITY private input uses write-only
server_secret.private_key; omission generates it. The fixture has no private key.
An importer must derive/check public key, protect private input, and use plan/apply;
it must not write SQLite or generate sing-box server JSON. Future exports cannot
recover server material for migration. Production canary remains deferred.

| Logical legacy value | Canonical VLESS import |
|---|---|
| Name | name / users[].account_name |
| Listener / display endpoint | Independent listener and display_endpoint host/port |
| UUID | Optional secret users[].uuid; the synthetic fixture omits both users' UUIDs for secure generation |
| Flow | settings.flow=none only; Vision rejected, never silently downgraded |
| REALITY private/public key | Write-only server_secret.private_key / derived settings.reality.public_key |
| Short IDs | settings.reality.short_ids; bounded padded baseline semantics |
| Server name / target | Independent settings.reality.server_name / target host/port |

## Future Xray selection

Splicore-side imports may select the existing `vless` protocol with `engine: xray`;
the typed UUID/REALITY fields and Account/Binding/Credential remain unchanged.
Distributors may provision the reviewed pinned binary and bootstrap path, subject
to license/source obligations. They must inspect build support and node availability,
and must never generate Xray runtime JSON, edit SQLite or create xray.service.
Missing required engine fails unavailable without fallback. Strict policies remain
unsupported; metadata-only policy is not enforcement. Vision is rejected on both
engines. FinalMask/Sudoku now use the bounded Phase 7 typed profile; see below.
Real NoBrand changes remain NONE.

## Audited Sudoku migration contract

The read-only source audit found FinalMask TCP/Sudoku on official Xray v26.3.27;
no fork is required. Splicore public input uses engine_options.finalmask.tcp with
one type=sudoku, ascii=prefer_ascii, padding_min=0, padding_max=3. This maps to
Xray streamSettings.finalmask.tcp with camelCase paddingMin/paddingMax internally.
Import the exact existing 32 hex-character password through write-only top-level
transport_secret.password; never hex-decode or change case. Keep UUID per Account
and Binding. The shared seed is encrypted and inbound-owned. Authorized Xray
26.3.27 JSON output includes it; other masked client formats reject. Production
migration is DEFERRED; real NoBrand changes NONE. No config edit, install, scan
or migration is performed in NoBrand. [Contract](../development/PHASE_7_XRAY_EXTENSIONS.md).

## Phase 8 synthetic Mieru mapping

[Synthetic canonical fixture](../../tests/fixtures/nobrand/mieru.json) maps name
to inbound name; listener host/port to actual endpoint; display host/port to independent
DisplayEndpoint; transport/MTU/multiplex to bounded settings; account_name to shared
Account; username/password to encrypted UsernamePasswordCredential and Binding.
Quota is not mapped to native enforcement: rolling MiB semantics differ. Explicit
metadata_only may preserve policy metadata without enforcement. Generic Splicore
validate/plan/apply consumes this document, never a mita config. No changes to real
D:/code/NoBrand-OneClick; read-only entry/final hashes and Git state are compared.
