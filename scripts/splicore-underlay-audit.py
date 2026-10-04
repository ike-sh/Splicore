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
pattern = re.compile(r"net\.(?:Dial(?:er|Timeout|Context|TCP|UDP|Unix)?|Listen(?:Config|Packet|TCP|UDP|Unix)?|DefaultResolver|Resolver)\b|\.(?:DialContext|ListenPacket|LookupNetIP|LookupIP|LookupIPAddr)\(|box\.New\(|api\.NewClient\(|server\.NewServer\(|cmd\.Start\(")
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
rule("engine/native/client_box.go", "buildClientBox", "Protected", "Snell/HY2/TUIC/VLESS client", "protectedOutbounds registry -> official common/dialer -> TCP/UDP socket Control")
rule("engine/native/snell_outbound.go", "DialContext ListenPacket", "Protected", "Native client / UDP DNS", "Official outbound from protected box; injected System-safe resolver")
rule("engine/native/underlay.go", "Exchange", "Protected", "Native System DNS", "Required mode uses protected resolver; independent resolved/mDNS paths reject")
rule("engine/native/snell.go", "Compile", "Protected", "Snell server target", "Explicit protected DIRECT final outbound and protected DNS registry")
rule("engine/native/snell.go", "Start", "Intentionally Local", "server ingress", "Owned bound ingress; no remote socket construction")
rule("engine/native/quic.go", "newQUICRuntime", "Protected", "HY2/TUIC server target", "Explicit protected DIRECT final outbound; official UDPListener Control")
rule("engine/native/quic.go", "Start", "Intentionally Local", "QUIC server ingress", "Owned public packet ingress; remote target uses protected outbound")
rule("engine/native/vless.go", "Compile", "Protected", "VLESS server target / REALITY probe", "Protected context for TLS/REALITY and explicit protected DIRECT")
rule("engine/native/vless.go", "Start", "Intentionally Local", "VLESS server ingress", "Owned admission listener")
rule("engine/native/mieru.go", "Compile route", "Protected", "Mieru server target", "SDK listener hooks own ingress; final TCP/UDP target uses injected provider")
rule("engine/native/mieru.go", "Listen ListenPacket", "Intentionally Local", "Mieru server ingress", "Official server listener hooks; final target is a distinct protected socket")
rule("engine/native/mieru_outbound.go", "Build DialContext ListenPacket dial", "Protected", "Mieru client TCP/UDP", "Official v3.38.0 Dialer, PacketDialer, Resolver hooks + clientio ownership")
rule("engine/xray/runtime.go", "Start", "Protected", "Xray process + ingress", "ChildLease.Verify -> owned launch -> generation/PID Bind; public/private listen is ingress")
rule("engine/xray/engine.go", "runOwned", "Intentionally Local", "Xray version/config validation", "Pinned artifact metadata or run -test; no active runtime; sole Wait owner")
rule("engine/xray/runtime.go", "relay", "Intentionally Local", "Xray local relay", "Literal 127.0.0.1 private owned child listener")
rule("engine/xray/outbound.go", "handshake ListenPacket", "Intentionally Local", "Xray private SOCKS", "Literal loopback TCP; UDP reply validated loopback + nonzero port")
rule("engine/xray/client_port_other.go", "reserveClientListeners", "Intentionally Local", "Xray private reservations", "Literal loopback TCP/UDP")
rule("engine/xray/client_port_windows.go", "reserveClientListeners", "Intentionally Local", "Xray private reservations", "Same loopback reservations with exclusive Windows port handling")
rule("networkruntime/dns.go", "dialPurpose DialContext ListenPacket question", "Protected", "DNS/bootstrap/health", "Typed direct provider or protected selected adapter; numeric bootstrap, unchanged DoT SNI")
rule("networkruntime/underlay.go", "systemLookup", "Protected", "System DNS", "Protected resolver or typed unsafe_underlay rejection")
rule("underlay/factory.go", "Resolver LookupNetIP LookupIP dialNumeric DialContext ListenPacket", "Protected", "socket/resolver boundary", "Raw OS sockets only here with Control; DefaultResolver branches require no TUN")
rule("transport/client.go", "UnixClient", "Intentionally Local", "local control", "Protected daemon UDS transport only")
rule("transport/listener_linux.go", "Listen", "Intentionally Local", "UDS API ingress", "Owned Unix socket")
rule("operations/service.go", "NotifyReady", "Intentionally Local", "systemd notify", "Validated local Unix datagram address")
rule("operations/diagnostics_linux.go", "journalSummary", "Intentionally Local", "bounded local journalctl", "Fixed journalctl local unit read; no external runtime or target")

rows, unknown = [], []
for root in ("internal/splicore", "cmd/splicore"):
    for path in sorted((args.root / root).rglob("*.go")):
        name = path.relative_to(args.root).as_posix()
        content = path.read_text(encoding="utf-8-sig")
        test = path.name.endswith("_test.go") or "/testkit/" in name
        if not test and 'internal/splicore/testkit"' in content:
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
    "engine/native/client_box.go": ["underlay.FromContext", "protectedOutbounds", "protectedDNS"],
    "engine/native/mieru_outbound.go": ["underlay.DialerFrom", "PacketDialer: d", "Resolver: d.resolver"],
    "engine/native/underlay.go": ["service.ExtendContext", "mdns.IsLocalDomain", "t.d.LookupNetIP"],
    "engine/xray/outbound.go": ["factory.AcquireChild", "IsLoopback()"],
    "engine/xray/runtime.go": ["h.underlay.Verify", "h.underlay.Bind", "cmd.Wait()", "h.underlay.Close()"],
    "underlay/factory.go": ["Control: d.Control", "remote !=", "f.required.Load() == 0", "l.released = false", "f.effectiveLocked()"],
}
for name, needles in invariants.items():
    text = (args.root / prefix / name).read_text()
    for needle in needles:
        if needle not in text:
            unknown.append({"file": prefix + name, "reason": "missing invariant " + needle})

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
