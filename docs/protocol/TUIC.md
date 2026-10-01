# TUIC experimental managed profile

- Documentation status: Canonical
- Audience: Developers and acceptance reviewers
- Last reviewed: 2026-10-01
- Owner: Core maintainers
- Responsibility: Pinned v5 credentials, settings, capabilities and limits.
- Lifecycle: Update with reviewed implementation or qualification changes.

## Pinned source and supported profile

Uses sing-box v1.14.1 (`1ac1a339cb1223e9c70eae14c44411c75033c02d`)
and sing-quic v0.7.0. TUIC Version constant is 5; v4/token and older versions are
unsupported. Authentication binds UUID bytes and password through TLS exporter
key material. Password is not a username. Native multiple users are supported;
unsynchronized UpdateUsers is called only before Start. HotUserUpdate=false.
Binding mutation restarts only its Inbound, interrupting sessions/resetting counters.

Managed settings require version=5, congestion_control=cubic, udp_relay_mode=native,
zero_rtt_handshake=false and shared static TLS. Adapter explicitly supplies h3 ALPN
and TLS 1.3. Fixed auth timeout 3s, heartbeat 10s, UDP timeout 5s. Upstream supports
new_reno/bbr, QUIC stream UDP and 0-RTT; these variants are unqualified/rejected in
managed settings. Upstream server still accepts both datagram and stream UDP wire;
the managed client contract qualifies native datagrams only.

## Creation and identity

Use [fixture](../../tests/fixtures/nobrand/tuic.json) with
`splicore inbound validate/plan/apply --protocol tuic`. API:
`/api/v1/creation/{protocol}/validate|plan|apply`; explicit
`/api/v1/tuic/validate|plan|apply` aliases have the same generic response shapes.
Each of 1–16 users creates distinct Account, Binding and typed encrypted UUIDPassword
Credential. Both UUID/password may be omitted to generate; partial pairs/null/empty
and duplicate UUID bytes reject. Supplied UUID is 36-character dashed hex,
case-insensitive, nonzero; UUID version unrestricted. Generated UUID is random v4,
password uses 32 random bytes. Password is 12–255 UTF-8 bytes without Unicode
control/space characters. Policy requires metadata_only; enforcement is deferred.

User enabled=false disables Binding; account_enabled=false creates disabled Account
through the production service. Explicit null flags reject; omitted flags default
to enabled. Neither disabled identity is projected/exportable; recovery uses the
same filters. General live Account mutation/credential rotation remain deferred.

## TLS, lifecycle and statistics

Listener, DisplayEndpoint, SNI and certificate identity are independent. Shared TLS
validates bounded regular files, symlinks/owner/mode, key pair, leaf/chain/validity/SNI
against one explicit CA, then snapshots. No watcher/ACME/live renewal/private key in
SQLite. Linux private key/parent protection is enforced; Windows is development only.

HY2/TUIC share Box/router, UDP ownership/admission/health, cancellation/100ms close
grace/socket release, immutable Binding routing and payload/session meters. Factories
own protocol auth/options; no wire/QUIC/crypto copying. Pending listeners cannot route
payload; failures compensate from committed SQLite, never generated JSON.

Inbound and Binding authenticated payload bytes plus total/active routed sessions are
observable. Account identity joins Binding→Account; durable cross-Inbound aggregates
are deferred. Counters reset on replacement/restart and exclude QUIC/TLS overhead.

## Client projection and qualification

ClientProfile has v5 key, public endpoint, typed UUID/password, explicit CA/SNI/h3,
QUIC/UDP and bounded options, with no upstream struct. Mihomo 1.19.30 receives no v4
token, native relay/cubic/reduce-rtt=false/skip-cert-verify=false and non-leaf CA pin.
sing-box 1.14.1 receives equivalent outbound with explicit CA/insecure=false.
Reference [Mihomo source](https://github.com/MetaCubeX/mihomo/blob/v1.19.30/adapter/outbound/tuic.go)
and [baseline inbound](https://github.com/SagerNet/sing-box/blob/v1.14.1/protocol/tuic/inbound.go).
Surge returns UnsupportedExport; URI deferred, no invented grammar.

Status is Experimental. See [matrix](../testing/INTEROP_MATRIX.md),
[workflow](../development/PHASE_4_TUIC.md) and
[report](../reports/PHASE_4_TUIC_VERTICAL_SLICE_REPORT.md).
