# Minimal Client Routing

- Documentation status: Canonical
- Audience: Client and control-plane developers
- Last reviewed: 2026-10-02
- Owner: Core maintainers
- Responsibility: Committed default/selected route selection and snapshot publication.
- Lifecycle: Update when route semantics or policy boundaries change.

## Implemented selection

Each LocalInbound selects its `selected_outbound` when present; otherwise it uses
the committed Route `default_outbound`. The default is builtin `direct`.
Every selected/default reference must exist. Deleting a referenced outbound rejects.
Outbound references a Node by UUID and an engine independently; names are labels.

The data path reads an immutable in-memory generation. It never reads SQLite for
each packet or connection decision. The shared global revision and HMAC plan protect
control-plane mutations. A successful commit precedes snapshot swap; a failed build,
bind or commit leaves the prior snapshot active. Established sessions retain the
old generation until close. Restart explicitly ends them after commit.

## DNS semantics

Remote node domains are stored unchanged and resolved locally by the native adapter
when dialing the remote server. DIRECT target domains use the operating-system
resolver. SOCKS domain targets through Snell are passed as domains to the remote
protocol/server for target resolution. This distinction is part of the contract;
there is no FakeIP or advanced DNS engine in Phase 10.

## Extension boundary

The Route aggregate and runtime selection remain independent of engine configuration.
Future route rules must be typed, validated and separately qualified before admission.
Route rules and policy groups are separate concepts. Domain/IP/Geo/process rules,
RuleSets, providers, URL-Test, fallback/load balancing, subscriptions and policy
groups are **DEFERRED / NOT IMPLEMENTED**. TUN and system-proxy automation are not
implemented. See [client runtime](CLIENT_RUNTIME.md) and [capabilities](CAPABILITY_MATRIX.md).
