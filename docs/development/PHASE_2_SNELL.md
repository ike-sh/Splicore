# Phase 2 Snell workflow

- Documentation status: Canonical
- Audience: Contributors, operators of synthetic test instances and reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Reproducible Snell commands, client dependencies and validation.
- Lifecycle: Update with actual build/test contracts; keep fresh evidence external.

## Build and bootstrap

Run owned tests with `go test ./internal/splicore/... ./cmd/splicore` and build
`go build -o /external/splicore ./cmd/splicore`. Linux is the production control
target. Windows builds/tests use development transport; no Windows service is added.

Provision a key explicitly:

```sh
splicore key init --file /private/splicore/key
```

The parent directory must be private. Key creation never overwrites an existing file.
Use a bootstrap file containing process paths only:

```yaml
schema: 1
state_directory: /private/splicore/state
key_file: /private/splicore/key
api:
  unix_socket: /private/splicore/control.sock
```

Start `splicore run --config /private/bootstrap.yaml`. A missing key_file can serve
an empty metadata instance, but credential writes fail closed. Restart with committed
credentials requires the original key. Bootstrap does not contain protocol state.

## Canonical import and automation

[Synthetic NoBrand fixture](../../tests/fixtures/nobrand/snell.json) creates a fresh
Account, Binding, Credential and Inbound. PSK is omitted to request secure generation;
an explicitly supplied portable PSK is accepted as a private input field.

```sh
splicore inbound validate --file /private/snell.json
splicore inbound plan --config /private/bootstrap.yaml --file /private/snell.json > /private/plan.json
splicore inbound apply --config /private/bootstrap.yaml --file /private/snell.json --plan /private/plan.json
splicore inbound list --config /private/bootstrap.yaml
splicore inbound get --config /private/bootstrap.yaml --id INBOUND_UUID
splicore inbound export --config /private/bootstrap.yaml --id INBOUND_UUID --format sing-box --client-version 1.14.1 > /private/client-export.json
```

Output is JSON. Exit 0 means success; exit 1 means rejection/failure and prints a
safe typed domain code. Only export output contains PSK. The export envelope's
content is a node/outbound; a caller assembles the full target client config.
Plan digest binds compact JSON content, exact field order and committed revision
with a daemon-local HMAC. Restart or a mutation requires replan; no generic
idempotency-key or offline database mutation contract is supplied.

Display changes use `inbound display --id ... --file /private/display.json --config ...`
with `endpoint`, `resource_revision`, `revision`; revisions are decimal strings.
Listener remains fixed. Generic CRUD/delete/rotation and account mutation are deferred.
The [OpenAPI contract](../api/openapi-skeleton.yaml) marks nine implemented routes.

## Reference clients and reproducible Linux interop

Download pinned official Linux amd64 clients using
`python scripts/splicore-clients.py /external/clients`. It verifies archive SHA256
on every run, extracts only the expected executable and records executable SHA256.
Download failure is DEPENDENCY_UNAVAILABLE; mismatch is CHECKSUM_MISMATCH.
Cache/tools/binaries are never placed in Git. No root dependency was added.

The external evidence directory must contain `splicore`, `clients/mihomo` and
`clients/sing-box`. Run:

```sh
python3 scripts/splicore-snell-interop.py /external/evidence
```

The harness runs real binaries, private daemon/key/state, local synthetic TCP/UDP
echo servers, API and actual CLI fixture validate/plan/apply, exported client nodes,
IPv4/IPv6/localhost server endpoints, wrong PSK/version/port/stopped server,
16 connections, 4 MiB integrity, reconnect, abnormal close, session cleanup,
listener release and SQLite-only daemon restart. Generated inputs/client configs
contain synthetic secrets and remain external. Logs/results are independently
scanned. Use a native Linux directory for state; Windows bind mounts may not
preserve required ownership/permissions. Containers use read-only repository mounts,
native private `/tmp` state and copy only safe results/logs externally.

Build `go build -race` for the server to check actual concurrent traffic; the harness
rejects panic/data-race logs. Run owned `go test -race`, `go vet`, and short fuzz:

```sh
go test ./internal/splicore/protocol/snell -run='^$' -fuzz=FuzzSettings -fuzztime=3s -parallel=2
go test ./internal/splicore/exporter -run='^$' -fuzz=FuzzExport -fuzztime=3s -parallel=2
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o /external/splicore-arm64 ./cmd/splicore
```

Full upstream Linux CI uses the unchanged release default tags/linker flags and
isolated container capabilities/tcpdump described in the historical baseline.
Windows complete upstream integration has known WinDivert environment limitations;
do not label a filtered run as full CI. See [report](../reports/PHASE_2_SNELL_VERTICAL_SLICE_REPORT.md).
