"""Audit owned egress construction/delegation; reject unclassified call sites.

This is a review guard, not a proof of upstream behavior. Default race/checkptr,
actual adapters, fake host readback and the isolated kernel lab supply that proof.
"""
import argparse
import hashlib
import json
import pathlib
import re

parser = argparse.ArgumentParser()
parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
parser.add_argument("--output", type=pathlib.Path, required=True)
args = parser.parse_args()
pattern = re.compile(r"net\.(?:Dial(?:er|Timeout|Context|TCP|UDP|Unix)?|Listen(?:Config|Packet|TCP|UDP|Unix)?|DefaultResolver|Resolver)\b|\.(?:DialContext|ListenPacket|LookupNetIP|LookupIP|LookupIPAddr)\(|\b(?:transport|c\.transport)\.(?:Dial|DialEarly|Listen)\(|\bn\.(?:Dial|Resolve)\(|\bdial\(callCtx,|api\.NewClient\(|server\.NewServer\(|cmd\.Start\(")
signature = re.compile(r"^func\s+(?:\([^)]*\)\s+)?([A-Za-z_][A-Za-z_0-9]*)\(")
prefix = "internal/splicore/"
rules = {}

def rule(path, functions, classification, purpose, evidence):
    for fn in functions.split():
        rules[(prefix + path, fn)] = (classification, purpose, evidence)

rule("clientruntime/runtime.go", "PrepareWithRestart", "Intentionally Local", "application ingress", "Validated local listen endpoint; no remote dial")
rule("clientruntime/runtime.go", "serveStream DialContext", "Protected", "DIRECT / selected outbound", "Logical selectRoute -> leased adapter -> injected provider")
rule("clientruntime/http.go", "serveHTTP", "Protected", "HTTP selected outbound", "Snapshot-owned selected adapter; target route chosen before protection")
rule("clientruntime/udp.go", "serveUDP", "Intentionally Local", "SOCKS UDP relay", "Loopback relay; selected remote packet adapter is separately protected")
rule("clientruntime/udp.go", "ListenPacket", "Protected", "DIRECT UDP", "Protected connected UDP socket per association")
rule("clientruntime/tun.go", "servePacket", "Protected", "TUN selected outbound", "Snapshot ref retained until packet workers joined")
rule("clientruntime/lease.go", "DialContext ListenPacket", "Protected", "adapter delegation", "Reference-counted adapter; production constructors require factory")
rule("clientruntime/provider.go", "Dial", "Protected", "Provider HTTP fetch", "Pinned numeric destination; snapshot-held selected adapter or ProviderFetch temporary endpoint lease and protected DIRECT")
rule("remotesource/fetch.go", "Fetch", "Protected", "Provider HTTP transport delegation", "Checked complete DNS answer; numeric pin; per-redirect policy; generation-owned FetchNetwork; no ambient proxy")
rule("app/app.go", "Serve", "Intentionally Local", "local control ingress", "Owned Unix socket listener")
rule("engine/clientconfig/packet.go", "PacketSocket", "Protected", "QUIC proxy socket and bootstrap DNS", "Injected purpose-specific protected resolver and numeric remote-bound UDP socket")
rule("engine/native/snell_outbound.go", "dial ListenPacket", "Protected", "Snell proxy TCP underlay / UDP bootstrap DNS", "Injected ProxyUnderlay and DNSBootstrap dialers; flow-local Tunnel state; client owner joins sockets")
rule("engine/native/snell.go", "serve serveUDP", "Protected", "Snell server TCP/UDP target", "Injected ServerTarget dialer; handle owns and joins accepted/target sockets")
rule("engine/native/snell.go", "Start", "Intentionally Local", "server ingress", "Owned bound ingress; no remote socket construction")
for path in ("engine/native/hysteria2.go", "engine/native/tuic.go"):
    rule(path, "Start", "Intentionally Local", "QUIC server ingress", "Owned admission-gated UDP listener; target sockets use separate injected dialer")
    rule(path, "tcp udp", "Protected", "QUIC server TCP/UDP target", "Injected ServerTarget dialer; relay owns each remote socket")
rule("engine/native/vless.go", "Compile", "Protected", "VLESS server target / REALITY probe", "Protected context for TLS/REALITY and explicit protected DIRECT")
rule("engine/native/vless.go", "Start", "Intentionally Local", "VLESS server ingress", "Owned admission listener")
rule("engine/native/vless.go", "serve", "Protected", "VLESS server TCP/UDP target", "Injected ServerTarget dialer; per-connection parser and per-session packet ownership")
rule("engine/native/vless_outbound.go", "open", "Protected", "VLESS proxy underlay", "Injected purpose-specific dialer; TLS/REALITY wraps the owned socket")
rule("engine/native/shadowsocks.go", "serve", "Protected", "Shadowsocks server TCP target", "Injected ServerTarget dialer; native handle owns authenticated stream")
rule("engine/native/shadowsocks_udp.go", "routePacket", "Protected", "Shadowsocks server UDP target", "Injected ServerTarget connected UDP socket; bounded association owns reader/socket")
rule("engine/native/shadowsocks.go", "Start", "Intentionally Local", "Shadowsocks TCP/UDP ingress", "Validated owned listeners; remote target uses protected router")
rule("engine/native/shadowsocks_outbound.go", "DialContext ListenPacket", "Protected", "Shadowsocks client TCP/UDP", "Required injected underlay dialer; owner tracks pending dials and sockets")
rule("networkruntime/dns.go", "dialPurpose DialContext ListenPacket question", "Protected", "DNS/bootstrap/health", "Typed direct provider or protected selected adapter; numeric bootstrap, unchanged DoT SNI")
rule("networkruntime/underlay.go", "systemLookup", "Protected", "System DNS", "Protected resolver or typed unsafe_underlay rejection")
rule("underlay/factory.go", "Resolver LookupNetIP LookupIP dialNumeric DialContext ListenPacket", "Protected", "socket/resolver boundary", "Raw OS sockets only here with Control; DefaultResolver branches require no TUN")
rule("transport/client.go", "UnixClient", "Intentionally Local", "local control", "Protected daemon UDS transport only")
rule("transport/listener_linux.go", "Listen", "Intentionally Local", "UDS API ingress", "Owned Unix socket")
rule("operations/service.go", "NotifyReady", "Intentionally Local", "systemd notify", "Validated local Unix datagram address")
rule("operations/diagnostics_linux.go", "journalSummary", "Intentionally Local", "bounded local journalctl", "Fixed journalctl local unit read; no external runtime or target")

def backend_rule(path, functions, classification, purpose, evidence):
    for fn in functions.split():
        rules[("protocol/" + path, fn)] = (classification, purpose, evidence)

for protocol in ("hysteria2", "tuic"):
    backend_rule(protocol + "/backend/client.go", "connect", "Protected", "private QUIC transport", "Transport.Conn is the injected protected packet socket; QUIC never creates a default socket")
    backend_rule(protocol + "/backend/server.go", "NewServer", "Intentionally Local", "QUIC listener delegation", "Transport.Conn is the native handle's owned UDP ingress")
backend_rule("vless/backend/reality.go", "RealityServer", "Protected", "REALITY target", "Native constructor injects ServerTarget DialContext; cancellation owns both sockets")
backend_rule("mieru/backend/mieru.go", "Compile", "Intentionally Local", "Mieru SDK construction", "Store injects both listener factories before Start; no SDK-created ambient ingress")
backend_rule("mieru/backend/mieru.go", "Listen ListenPacket", "Intentionally Local", "Mieru ingress", "Injected SDK listener hooks; handle owns and joins ingress")
backend_rule("mieru/backend/mieru.go", "route", "Protected", "Mieru TCP/UDP target", "Injected ServerTarget dialer; independent target ownership")
backend_rule("mieru/backend/mieru_outbound.go", "Build DialContext ListenPacket dial", "Protected", "Mieru proxy underlay", "SDK config injects Dialer, PacketDialer and DNSBootstrap Resolver; clientio owns sockets")

rows, unknown = [], []
for root in ("internal/splicore", "cmd/splicore", "protocol"):
    for path in sorted((args.root / root).rglob("*.go")):
        name = path.relative_to(args.root).as_posix()
        content = path.read_text(encoding="utf-8-sig")
        test = path.name.endswith("_test.go") or "/testkit/" in name or "/engine/testfixture/" in name
        if not test and any(imp in content for imp in ('internal/splicore/testkit"', 'internal/splicore/engine/testfixture"')):
            unknown.append({"file": name, "reason": "production imports test-only backend"})
        fn = "<package>"
        for number, line in enumerate(content.splitlines(), 1):
            match = signature.match(line)
            if match:
                fn = match[1]
                # Include one-line function bodies without scanning signature
                # types as socket creation.
                line = line.split("{", 1)[1] if "{" in line else ""
            if line.strip().startswith("//") or not pattern.search(line):
                continue
            selected = ("Test Only", "fixture", "Owned local test harness") if test else rules.get((name, fn))
            # A SOCKS association has one local ingress creation and one protected
            # remote adapter call. Classify them individually.
            if name == prefix + "clientruntime/udp.go" and fn == "serveUDP" and "pd.ListenPacket" in line:
                selected = ("Protected", "SOCKS selected UDP outbound", "Leased protected adapter; association owns socket and generation")
            if selected is None:
                selected = ("Unknown", "unreviewed", "Review required")
                unknown.append({"file": name, "line": number, "function": fn, "call": line.strip()})
            rows.append(dict(file=name, line=number, function=fn, classification=selected[0], purpose=selected[1], protection=selected[2], call=line.strip()))

# Constructor enforcement and essential socket/ownership gates must remain in
# the production implementation even when the scanner sees the same function.
invariants = {
    prefix + "engine/clientconfig/packet.go": ["underlay.DialerFrom", "underlay.DNSBootstrap", "protected.ListenPacket", "address.String()"],
    prefix + "engine/native/shadowsocks.go": ["underlay.FromContext", "underlay.DialerFrom(ctx, underlay.ServerTarget)", "h.protected = protected"],
    prefix + "engine/native/shadowsocks_outbound.go": ["underlay.DialerFrom", "d.protected.DialContext", "d.owner.Conn"],
    prefix + "engine/native/snell.go": ["underlay.DialerFrom(ctx, underlay.ServerTarget)", "h.protected.DialContext"],
    prefix + "engine/native/hysteria2.go": ["underlay.DialerFrom(ctx, underlay.ServerTarget)", "h.protected.DialContext"],
    prefix + "engine/native/tuic.go": ["underlay.DialerFrom(ctx, underlay.ServerTarget)", "h.protected.DialContext"],
    prefix + "engine/native/vless.go": ["underlay.DialerFrom(ctx, underlay.ServerTarget)", "dialer.DialContext", "h.protected.DialContext"],
    "protocol/mieru/backend/mieru.go": ["underlay.DialerFrom(ctx, underlay.ServerTarget)", "StreamListenerFactory: h", "PacketListenerFactory: h", "h.protected.DialContext"],
    "protocol/mieru/backend/mieru_outbound.go": ["underlay.DialerFrom", "PacketDialer: d", "Resolver: d.resolver"],
    "protocol/hysteria2/backend/client.go": ["config.Socket(ctx)", "quic.Transport{Conn: packet}"],
    "protocol/tuic/backend/client.go": ["config.Socket(ctx)", "quic.Transport{Conn: packet}"],
    "protocol/hysteria2/backend/server.go": ["quic.Transport{Conn: packet,", "transport.Listen"],
    "protocol/tuic/backend/server.go": ["quic.Transport{Conn: packet,", "transport.Listen"],
    "protocol/vless/backend/reality.go": ["local.DialContext", "dial(callCtx, network, address)", "owned.Store", "<-done"],
    prefix + "underlay/factory.go": ["Control: d.Control", "remote !=", "f.required.Load() == 0", "l.released = false", "f.effectiveLocked()"],
}
for name, needles in invariants.items():
    path = args.root / name
    if not path.exists():
        unknown.append({"file": name, "reason": "obsolete constructor invariant; review replacement"})
        continue
    text = path.read_text()
    for needle in needles:
        if needle not in text:
            unknown.append({"file": name, "reason": "missing invariant " + needle})

manifest = args.root / "scripts/splicore-underlay-callsite-inventory.json"
observed = sorted((row["file"], row["function"], row["call"]) for row in rows if row["classification"] != "Test Only")
if not manifest.exists() or observed != sorted(tuple(row) for row in json.loads(manifest.read_text())):
    unknown.append({"file": str(manifest.relative_to(args.root)), "reason": "owned socket calls changed; update the reviewed inventory after auditing the new path"})

args.output.mkdir(parents=True, exist_ok=True)
record = dict(result="FAIL" if unknown else "PASS", unknown=unknown, unknown_production_callsites=len(unknown), production_surfaces=sum(r["classification"] != "Test Only" for r in rows), test_surfaces=sum(r["classification"] == "Test Only" for r in rows), rows=rows)
(args.output / "inventory-after.json").write_text(json.dumps(record, indent=2) + "\n")
lines = ["# Runtime Egress Surface Inventory (after integration)", "", "Reviewed owned construction and delegation. New file/function socket surfaces fail this audit.", "", "| Source | Function | Class | Purpose | Protection |", "| --- | --- | --- | --- | --- |"]
for row in rows:
    if row["classification"] != "Test Only":
        lines.append("| " + " | ".join(str(row[k]).replace("|", "\\|") for k in ("file", "function", "classification", "purpose", "protection")) + " |")
lines += ["", "Test-only surfaces are listed in inventory-after.json. No host mutation is performed."]
(args.output / "inventory-after.md").write_text("\n".join(lines) + "\n")
print(json.dumps({k: v for k, v in record.items() if k != "rows"}, indent=2))
raise SystemExit(bool(unknown))
