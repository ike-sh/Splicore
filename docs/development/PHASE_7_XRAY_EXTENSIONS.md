# Phase 7 Xray VLESS specialized extensions

- Documentation status: Canonical
- Audience: Runtime maintainers and acceptance reviewers
- Last reviewed: 2026-10-02
- Owner: Engine maintainers
- Responsibility: Reproduce the bounded FinalMask/Sudoku integration and its qualification limits.
- Lifecycle: Update supported scope and validation commands together.

## Contract

Protocol `vless`, Engine `xray`; both FinalMask and Sudoku remain Experimental.
FinalMask contains exactly one Sudoku TCP mask. Only plain security and flow none,
ASCII `prefer_ascii` and padding 0–3 are accepted. No custom tables, mask chains,
UDP masks, TLS/REALITY combinations or Vision. Masked UDP/XUDP is NOT QUALIFIED.
The existing generic settings persistence and encrypted credentials require no
migration. [ADR 0019](../adr/0019-xray-specialized-feature-boundary.md) owns the decision.

Canonical VLESS settings add:

```json
{
  "security": "none",
  "flow": "none",
  "transport": "tcp",
  "packet_encoding": "xudp",
  "engine_options": {
    "finalmask": {
      "tcp": [{
        "type": "sudoku",
        "settings": {"ascii": "prefer_ascii", "padding_min": 0, "padding_max": 3}
      }]
    }
  }
}
```

Creation uses `engine: xray` and the existing users/UUID/endpoint fields.
Optional top-level `transport_secret.password` imports an exact 32 hex-character
string; omission generates it before pending. Never put the password in settings.
Explicit null, duplicate and unknown fields reject. An authorized export request
uses `format: xray`, `client_version: 26.3.27` and the selected `binding_id`.
Its `xray-outbound` content is sensitive and contains the client-needed password.
All other exporter formats reject masked profiles.

## Unchanged artifact boundary

- Source: official XTLS/Xray-core v26.3.27,
  commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`, MPL-2.0.
- Linux amd64 executable SHA256:
  `8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed`.
- Windows amd64 executable SHA256:
  `15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1`.
- No bundled runtime, download, fork, source patch or artifact replacement.
- Source/runtime reference evidence is separate from managed feature acceptance.

## Gates

Use offline Go caches, an absolute pinned `SPLICORE_XRAY_BINARY` path and native
ext4 under Ubuntu-24.04 WSL2. Keep logs, keys, DBs, configs, binaries and fuzz cache
outside Git. Default checkptr and race remain enabled.

```sh
go test -count=1 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore/...
go test -race -count=1 -tags with_quic,with_utls,splicore_xray_integration ./internal/splicore/... ./cmd/splicore/...
go test -race -count=10 -tags with_utls,splicore_xray_integration -run TestXrayPinnedSudoku ./internal/splicore/application
go test -race -count=10 -tags with_utls -run TestSupervisor ./internal/splicore/engine/xray
go test -run '^$' -fuzz '^FuzzMaskOptionParser$' -fuzztime 10s -parallel 4 ./internal/splicore/transportmask
go test -tags with_utls -run '^$' -fuzz '^FuzzRendererBoundary$' -fuzztime 10s -parallel 4 ./internal/splicore/engine/xray
go test -tags with_utls -run '^$' -fuzz '^FuzzSudokuRendererBoundary$' -fuzztime 10s -parallel 4 ./internal/splicore/engine/xray
```

Run `scripts/splicore-sudoku-interop.py` with a fresh external root containing a
default-race Splicore binary, inside a private loopback-only mount/network namespace.
It creates canonical intent through Splicore API, then feeds authorized exporter
output to the exact pinned Xray client. Alice/Bob each cover 32 KiB echo, concurrency
16, 4 MiB integrity, reconnect and abnormal close. Negative masks/passwords/UUIDs,
client export rejection, binding reconcile, graceful SQLite restart, config
regeneration, child crash/manual recovery, API/CLI redaction and socket release
are required. Secret inputs are private and removed after children join.

Fresh native REALITY, Xray standard flow-none, Snell/Hysteria2/TUIC campaigns are
regressions. Validate owned Markdown, OpenAPI and live response schemas; archive
only sanitized evidence with manifests. Upstream source/dependencies and Phase 0–6
reports remain unchanged. Docker, Redis and TeleLedger remain untouched.

Windows abnormal child exit/parent crash: DEFERRED PLATFORM QUALIFICATION.
Xray arm64 runtime: NOT CERTIFIED; cross compilation is build evidence only.
Vision, Mieru, Panel, unified enforcement, persistent usage, production NoBrand
migration and Stable remain deferred. The authorized [local freeze](../reports/PHASE_7_FREEZE_REPORT.md)
creates one Phase 7 commit and fast-forwards main. Push/tag/release NONE.
Phase 8 branch creation is complete; Mieru implementation is NOT STARTED.
