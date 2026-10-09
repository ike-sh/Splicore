# Core architecture

Splicore separates protocol wire implementations from application policy and
persistent management. `cmd/splicore` composes the independent Core.

- Domain types describe accounts, bindings, encrypted credentials, nodes, client
  intent, routing/DNS/policy and provider ownership.
- Application services validate, plan and commit resource changes with revision
  guards. SQLite is the persistent authority; the bootstrap config selects paths.
- API/CLI invoke application queries and commands, rather than writing SQL or
  protocol state directly.
- Native protocol adapters implement server/client streams and packets, with
  explicit runtime-generation and credential ownership.
- Shared transport/TLS, underlay protection, local ingress and native TUN compose
  around those protocol adapters. Protocol framing and authentication remain
  protocol-owned.
- Distribution and service operations preserve coherent database/key identity,
  owned host networking recovery and bounded redacted diagnostics.

Server Core and Client Core run in the same daemon. Client configuration is not
an external GUI or desktop proxy controller. Mieru is embedded; no external core
child process is required.

See [scope](architecture/CORE_SCOPE.md), [capabilities](architecture/CAPABILITY_MATRIX.md),
[shared transports](architecture/SHARED_TRANSPORT.md), [API](api/README.md),
[configuration](CONFIGURATION.md) and [operations](OPERATIONS.md).
