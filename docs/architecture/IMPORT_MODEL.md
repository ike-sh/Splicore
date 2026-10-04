# Client Import Contract

- Documentation status: Canonical
- Audience: Core, client and integration maintainers
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Bounded parsers, preview, format boundaries and explicit secret export.
- Lifecycle: Update with implemented contracts and qualified evidence.

## Pipeline and transaction

Source → bounded parser → candidates → protocol validation → dedup/reference plan →
redacted preview → runtime preparation → one SQLite transaction → activation.
Importers never instantiate an engine and raw runtime configuration is never authority.

Preview is a dry run: no SQLite/resource/runtime mutation. It may fetch remote content,
then caches one bounded complete candidate in daemon memory. Responses contain only
Add/Update/Unchanged/Conflict/Remove/Unsupported/Invalid entries, IDs, index and fixed
change codes. Applicable plans receive a random single-use token, committed revision
and five-minute expiry. At most 32 plans remain cached; shutdown clears them. Restart,
expiry, consumption or any intervening mutation requires a new preview.

Strict is default: any invalid/unsupported entry prevents apply. Explicit lenient
applies valid candidates and reports rejected entries. Ambiguous identity and unsafe
references remain blocking in both modes. Provider empty/removal guards still apply.
No raw URI, credential, candidate settings or source auth appears in preview/errors.

## Canonical node document, schema 1

This client format is independent of SQLite/config schemas and runtime JSON:

```json
{"schema_version":1,"nodes":[{"key":"optional-public-native-key","node":{"name":"display","protocol":{"protocol":"snell","wire_version":"6","feature_profile":"base"},"endpoint":{"host":"example.test","port":443},"transport":{"kind":"tcp"},"security":{"kind":"none"},"options":{"schema_version":1,"data":{"version":6}},"metadata":{}},"credential":{"kind":"psk","value":"REDACTED"}}]}
```

`key` is optional and primarily a provider matching hint, at most 120 bytes.
Candidates cannot assign Node/Credential IDs, provenance or lifecycle state.
Unknown/duplicate JSON fields, invalid UTF-8 and unsupported protocol settings reject.
Credentials use the existing PSK/password/UUID/UUIDPassword/UsernamePassword kinds;
pair values are strict JSON strings with their two canonical fields. Explicit
canonical export covers all five supported client protocols and round trips.

## URI audit and exact supported subsets

| Input | Accepted scope / rejected extensions |
| --- | --- |
| Snell | Unsupported URI: no formal audited sharing contract. Canonical, Mihomo and sing-box node fragments are available. |
| hysteria2 / hy2 | [Official URI](https://v2.hysteria.network/docs/developers/URI-Scheme/): auth, host, optional port default 443, SNI, insecure=0; system trust. Obfs/pin/ECH/hopping/realm/insecure reject. |
| tuic | [Mihomo v1.19.30 converter](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/common/convert/converter.go) dialect, explicitly temporary/unofficial: UUID:password, mandatory port, SNI, h3, cubic, native UDP, disable_sni=0. Token/v4 and extensions reject. |
| vless | Existing audited [project contract](../protocol/VLESS.md): TCP, UUID, flow none, XUDP, plain or REALITY public fields/chrome. Vision rejects; explicit CA TLS cannot be represented by this sharing subset. |
| mierus | [Official v3.38.0 URL parser](https://github.com/enfein/mieru/blob/v3.38.0/pkg/appctl/url.go): simple URL with user/password, profile, one port/protocol binding, approved multiplex level. |
| mieru | Same official source: bounded base64 protobuf client config, unknown protobuf fields rejected recursively; only representable bounded profiles accepted. |

Mieru uses official parsing followed by canonical validation; multi-server/range/binding,
handshake mode, traffic pattern and unknown fields reject. No invented URI scheme.
No parser introduces new wire capability. Vision and out-of-scope FinalMask/Sudoku, server
private keys and unvalidated protocol extensions reject without fallback.

## External input and export

Mihomo accepts only `proxies` JSON/YAML fragments; sing-box accepts an outbound object
or an `outbounds` wrapper. The importer rejects whole policy/server configs and unknown
fields, including cross-protocol options. Mieru accepts its bounded official client
config with one representable server/binding per profile. No raw config is persisted.
Mihomo CA-pin fields not represented by canonical trust reject rather than downgrade.
Independent Xray deployment is outside Splicore; binary MRS is deferred; VLESS URI is available.

Format is explicit (`canonical`, `uri`, `base64`, `mihomo`, `sing-box`, `mieru`). `auto`
only recognizes obvious canonical JSON or URI; ambiguous input fails. Base64 is strict
and bounded, never recursively decoded. YAML rejects aliases, anchors, merges,
duplicate keys, custom tags, trailing documents and excessive depth/node count.

Explicit export requires `reveal_secrets=true`; only client secrets are exported.
Canonical covers every supported node. Existing Mihomo/sing-box exporters keep exact
target/version/trust restrictions; Mieru official client config requires 3.38.0.
URI output supports existing VLESS sharing subset and bounded HY2 with system trust;
TUIC/Mieru/Snell URI export is deferred. Unsupported selected nodes fail the whole export.
External export details show server/client wire version and compatibility; CLI prints
these to stderr. Snell v5 external v4 compatibility is explicit, never silent downgrade.
Native Mieru export aggregates canonical profiles, not provider raw content.

## Limits and local files

Input/decoded/gzip body 2 MiB; nodes 128; URI 4096 bytes; node line 16 KiB; rules 10000.
API management envelope 4 MiB; CLI file/stdin 2 MiB. CLI opens only regular bounded
files and checks identity after opening; no symlinks/devices/sockets. Use private files
or stdin; URI argv is rejected to avoid shell-history/process-list exposure. Import
documents and explicit exports are secret-bearing and require owner-only storage.
See [CLI](../CLI.md), [API](../api/API_V1_DESIGN.md), [security](SECURITY_BOUNDARIES.md).
