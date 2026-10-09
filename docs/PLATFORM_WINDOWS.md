# Windows Host Integration

- Documentation status: Canonical
- Audience: Core developers and operators
- Last reviewed: 2026-10-04
- Owner: Core maintainers
- Responsibility: Windows source adapter and qualification limits.
- Lifecycle: Update with the supported ownership and qualification boundary.

SOCKS/HTTP/mixed require no administrator privileges. TUN creation/addresses/routes
require an operator-supplied Wintun DLL and elevation. No DLL/driver is downloaded,
installed, upgraded or uninstalled by Splicore. The cached Go Wintun wrapper is MIT;
no distributable DLL/version is approved. Driver availability/version are passive
doctor observations, not traffic qualification. DLL lookup avoids PATH/current-dir.

## Implementation and activation

The owned adapter uses the pinned public Wintun API directly to separate
CreateAdapter from StartSession. A random GUID, generation and owner are durable
before creation. Partial candidates retain exact handles through failed cleanup.
Read/write admission, interruption and worker joins precede session/adapter release;
driver ring memory is copied before passing it to official gVisor. Native orphan
recovery selects the exact GUID and Wintun service through SetupAPI, including
nonpresent devices. It never removes adapters by name or requests a reboot.

Desktop Internet Settings management is outside Core. Frozen schema remains
inert; see [Core scope](architecture/CORE_SCOPE.md).

WindowsBypassPlan projects canonical node/DNS/health/control dependencies,
checks cycles before resolution, normalizes mapped IPv4 and merges endpoint reasons.
Reconciliation installs/verifies new protection before removing unused owned routes.
Identical pre-existing routes are borrowed, never deleted or counted as owned.
External edits/journal failures remain degraded; completed history stays bounded.

**Windows activation remains blocked before mutation.** The original TUN
capability guard and auto-route rejection remain. These implemented and tested
components now share the production underlay factory with DIRECT, DNS/bootstrap,
health, Native server/client and Mieru socket owners. Stateful backend spies observe
actual adapter sockets. Fresh bootstrap, retained generation
leases and reused TUN reconciliation are implemented. Real activation remains
unqualified: the default Windows provider rejects required mode before mutation.

Real Windows TUN and auto-route runtime are **NOT CERTIFIED**; Windows full
race is **NOT EXECUTED**. Portable models run under WSL default race/checkptr. Native
Windows uses ordinary fixtures, compilation and symbol/ABI checks, without invoking
network mutations. Upstream source edits remain zero. See
[ownership ADR](adr/0030-windows-host-network-ownership.md) and [recovery](RECOVERY.md).

Journal files/directories use the current SID and SYSTEM-only protected DACL, machine GUID hash plus SID scope,
exclusive lock and WRITE_THROUGH atomic replace. Existing broad ACLs reject rather
than being silently rewritten. Developer-host route/DNS/proxy/driver mutation tests
are prohibited. See [system integration](SYSTEM_INTEGRATION.md).

## Runtime underlay fixtures

The production WindowsBackend contract requires a lease, SocketControl and Readback.
The fixture substitutes physical route/interface operations only; real Native client
and server sockets, DIRECT, DNS and health pass through the production factory.
Dynamic endpoint updates retain old/shared refs and preserve borrowed or externally
changed routes. Unsupported native platform capabilities remain typed unsafe_underlay.
System resolver bypass is unknown and rejects; explicit managed DNS remains usable.
These are implementation proofs. They do not permit activation on this developer
host or certify Wintun/auto-route. See [system integration](SYSTEM_INTEGRATION.md).
