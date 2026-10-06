"""Linux-only real binary interop. All artifacts and synthetic secrets stay external.

Usage: python3 scripts/splicore-snell-interop.py /external/evidence
Requires splicore, clients/mihomo, clients/sing-box built/downloaded beforehand.
"""
import concurrent.futures
import hashlib
import http.client
import json
import os
import pathlib
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time

class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=15)
        self.path = str(path)
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)

class EchoTCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    # Accept the declared 16-client campaign without saturating the echo fixture.
    request_queue_size = 64
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except OSError:
            pass
class EchoUDP(socketserver.ThreadingUDPServer):
    daemon_threads = True
class UDPEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)

def free_port(host="127.0.0.1"):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family) as s:
        s.bind((host, 0))
        return s.getsockname()[1]

def exact(s, size):
    b = bytearray()
    while len(b) < size:
        block = s.recv(min(size - len(b), 65536))
        if not block:
            raise RuntimeError("closed before complete payload")
        b.extend(block)
    return bytes(b)

def socks(port, dest, cmd=1):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(5)
    try:
        s.sendall(b"\x05\x01\x00")
        if exact(s, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS authentication failed")
        host, dp = dest
        addr = b"\x01" + socket.inet_aton(host)
        s.sendall(b"\x05" + bytes([cmd]) + b"\x00" + addr + struct.pack("!H", dp))
        reply = exact(s, 4)
        if reply[1] != 0:
            raise RuntimeError("SOCKS command rejected")
        kind = reply[3]
        host = socket.inet_ntoa(exact(s, 4)) if kind == 1 else socket.inet_ntop(socket.AF_INET6, exact(s, 16)) if kind == 4 else exact(s, exact(s, 1)[0]).decode()
        bound = struct.unpack("!H", exact(s, 2))[0]
        return s, (host, bound)
    except BaseException:
        s.close()
        raise

def tcp_payload(port, destination, size=32768):
    payload = (b"Splicore-Synthetic-Payload-Phase2-" * ((size // 34) + 100))[:size]
    s, _ = socks(port, destination)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            received = pool.submit(exact, s, len(payload))
            s.sendall(payload)
            data = received.result(timeout=15)
        if hashlib.sha256(payload).digest() != hashlib.sha256(data).digest():
            raise RuntimeError("payload integrity failed")
        return len(data)
    finally:
        s.close()

def udp_payload(port, destination):
    control, bound = socks(port, ("0.0.0.0", 0), 3)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(5)
            if bound[0] in ("0.0.0.0", "::"):
                bound = ("127.0.0.1", bound[1])
            payload = b"Splicore-Synthetic-UDP-Phase2" * 30
            head = b"\x00\x00\x00\x01" + socket.inet_aton(destination[0]) + struct.pack("!H", destination[1])
            s.sendto(head + payload, bound)
            data, _ = s.recvfrom(65536)
            if data[3] == 1:
                offset = 10
            elif data[3] == 4:
                offset = 22
            else:
                offset = 7 + data[4]
            if data[offset:] != payload:
                raise RuntimeError("UDP integrity failed")
            return len(payload)
    finally:
        control.close()

def wait_port(p, proc):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("process exited before listener")
        try:
            with socket.create_connection(("127.0.0.1", p), timeout=.2):
                return
        except OSError:
            os.sched_yield()
    raise RuntimeError("listener readiness timeout")

def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            raise RuntimeError("shutdown timeout")

def wait_mihomo_config(controller, path, proc, proxy_name):
    # The listener opens before the reference tunnel enters OnRunning.
    # Complete a synchronous local apply before the single payload attempt.
    deadline = time.monotonic() + 10
    while True:
        if proc.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError("reference controller readiness timeout")
        conn = http.client.HTTPConnection("127.0.0.1", controller, timeout=1)
        try:
            conn.request("GET", "/proxies")
            response = conn.getresponse()
            state = json.loads(response.read())
            if response.status == 200 and proxy_name in state.get("proxies", {}):
                break
        except OSError:
            os.sched_yield()
        finally:
            conn.close()
    conn = http.client.HTTPConnection("127.0.0.1", controller, timeout=10)
    try:
        conn.request("PUT", "/configs?force=true", body=json.dumps({"path": str(path)}), headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        if response.status != 204:
            raise RuntimeError("reference configuration barrier failed")
    finally:
        conn.close()

def main():
    root = pathlib.Path(sys.argv[1]).resolve()
    if pathlib.Path(__file__).resolve().parent.parent in root.parents:
        raise SystemExit("evidence must be external")
    os.umask(0o077)
    work = root / "interop"
    work.mkdir(mode=0o700, exist_ok=True)
    state = work / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    api = work / "control.sock"
    key = state / "key"
    exe = str(root / "splicore")
    if not key.exists():
        subprocess.run([exe, "key", "init", "--file", str(key)], check=True, stdout=subprocess.DEVNULL)
    bootstrap = work / "bootstrap.yaml"
    bootstrap.write_text(f"schema: 1\nstate_directory: {state}\nkey_file: {key}\napi:\n  unix_socket: {api}\n")
    tcp = EchoTCP(("127.0.0.1", 0), Echo)
    udp = EchoUDP(("127.0.0.1", 0), UDPEcho)
    for server in (tcp, udp):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    destination = tcp.server_address
    udp_destination = udp.server_address
    logs, processes, rows = [], [], []
    def launch(args, name):
        f = open(work / (name + ".log"), "wb")
        logs.append(f)
        p = subprocess.Popen(args, stdout=f, stderr=subprocess.STDOUT)
        processes.append(p)
        with (work / "processes.jsonl").open("a", encoding="utf-8") as record:
            record.write(json.dumps({"pid": p.pid, "name": name, "executable": args[0]}) + "\n")
        return p
    def start_server():
        proc = launch([exe, "run", "--config", str(bootstrap)], "server-" + str(len(processes)))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("Splicore startup failure")
            try:
                request("GET", "/api/v1/system")
                return proc
            except OSError:
                os.sched_yield()
        raise RuntimeError("Splicore API timeout")
    def request(method, path, data=None):
        conn = UnixHTTP(api)
        try:
            body = json.dumps(data).encode() if data is not None else None
            conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
            res = conn.getresponse()
            raw = res.read()
            if res.status != 200:
                raise RuntimeError("control operation rejected " + str(res.status))
            return json.loads(raw)
        finally:
            conn.close()
    def client_config(client, outbound, proxy_port, name):
        path = work / (name + ".json")
        if client == "mihomo":
            controller = free_port()
            config = {"external-controller": "127.0.0.1:" + str(controller), "socks-port": proxy_port, "allow-lan": False, "bind-address": "127.0.0.1", "ipv6": True, "mode": "rule", "log-level": "silent", "proxies": [outbound], "rules": ["MATCH," + outbound["name"]]}
            args = [str(root / "clients" / client), "-d", str(work), "-f", str(path)]
        else:
            config = {"log": {"disabled": True}, "dns": {"servers": [{"type": "local", "tag": "local"}]}, "route": {"default_domain_resolver": "local"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": proxy_port}], "outbounds": [outbound]}
            args = [str(root / "clients" / client), "run", "-c", str(path)]
        path.write_text(json.dumps(config))
        proc = launch(args, name)
        wait_port(proxy_port, proc)
        if client == "mihomo":
            wait_mihomo_config(controller, path, proc, outbound["name"])
        return proc
    failures = []
    try:
        daemon = start_server()
        ids = {}
        listen_ports = {}
        secrets = []
        for version in (5, 6):
            p = free_port("::")
            listen_ports[version] = p
            fixture = {"schema": 1, "account_name": "synthetic-interop", "name": "synthetic-snell-v" + str(version), "listener": {"host": "::", "port": p}, "display_endpoint": {"host": "127.0.0.1", "port": p}, "settings": {"version": version}, "psk": os.urandom(32).hex()}
            fixture["listener"] = {"host": "::", "port": p}
            fixture["display_endpoint"] = {"host": "127.0.0.1", "port": p}
            fixture["settings"]["version"] = version
            request("POST", "/api/v1/snell/validate", fixture)
            plan = request("POST", "/api/v1/snell/plan", fixture)
            if version == 5:
                fixture_file = work / "synthetic-owned.json"
                fixture_file.write_text(json.dumps(fixture, indent=2))
                def cli(*args):
                    return json.loads(subprocess.check_output([exe, "inbound", *args], stderr=subprocess.DEVNULL))
                cli("validate", "--file", str(fixture_file))
                plan = cli("plan", "--file", str(fixture_file), "--config", str(bootstrap))
                saved_plan = work / "plan.json"
                saved_plan.write_text(json.dumps(plan))
                result = cli("apply", "--file", str(fixture_file), "--plan", str(saved_plan), "--config", str(bootstrap))
                fixture_file.write_text("{}")  # restart must not reread import files
            else:
                result = request("POST", "/api/v1/snell/apply", {"document": fixture, "digest": plan["digest"], "revision": plan["revision"]})
            ids[version] = result["inbound_id"]
        clients = [("mihomo", "1.19.30", 5), ("sing-box", "1.14.1", 5), ("sing-box", "1.14.1", 6)]
        for client, client_version, version in clients:
            for endpoint in ("127.0.0.1", "::1", "localhost"):
                item = request("GET", "/api/v1/inbounds/" + ids[version])
                page = request("GET", "/api/v1/inbounds")
                request("POST", "/api/v1/inbounds/" + ids[version] + "/display", {"endpoint": {"host": endpoint, "port": listen_ports[version]}, "resource_revision": item["inbound"]["revision"], "revision": page["snapshot_revision"]})
                exported = request("POST", "/api/v1/inbounds/" + ids[version] + "/export", {"format": client, "client_version": client_version})
                outbound = json.loads(exported["content"])
                secrets.append(outbound["psk"])
                proxy_port = free_port()
                name = client + "-v" + str(version) + "-" + str(len(rows))
                proc = client_config(client, outbound, proxy_port, name)
                try:
                    before = {k: int(v) for k, v in request("GET", "/api/v1/inbounds/" + ids[version])["stats"].items()}
                    size = tcp_payload(proxy_port, destination)
                    udp_size = udp_payload(proxy_port, udp_destination)
                    tcp_payload(proxy_port, destination)  # reconnect
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        list(pool.map(lambda _: tcp_payload(proxy_port, destination), range(16)))
                    large = tcp_payload(proxy_port, destination, 4 << 20)
                    s, _ = socks(proxy_port, destination)
                    s.sendall(b"abnormal-close")
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    s.close()
                    after = {k: int(v) for k, v in request("GET", "/api/v1/inbounds/" + ids[version])["stats"].items()}
                    if after["upload_bytes"] - before["upload_bytes"] < large + size or after["download_bytes"] - before["download_bytes"] < large + size or after["sessions_total"] <= before["sessions_total"]:
                        raise RuntimeError("stats did not account for actual payload")
                    row = {"server": "Splicore", "client": client, "client_version": client_version, "server_version": version, "client_wire_version": outbound["version"], "endpoint": endpoint, "tcp": "PASS", "udp": "PASS", "concurrent": 16, "large_bytes": large, "reconnect": "PASS", "abnormal_close": "PASS", "upload_delta": after["upload_bytes"] - before["upload_bytes"], "download_delta": after["download_bytes"] - before["download_bytes"], "result": "PASS"}
                    rows.append(row)
                    print(json.dumps(row), flush=True)
                finally:
                    stop(proc)
                deadline = time.monotonic() + 5
                while int(request("GET", "/api/v1/inbounds/" + ids[version])["stats"]["sessions_active"]) != 0:
                    if time.monotonic() > deadline:
                        raise RuntimeError("closed client retained active sessions")
                    os.sched_yield()
                if endpoint == "127.0.0.1":
                    for failure in ("wrong-psk", "wrong-version", "wrong-port"):
                        bad = dict(outbound)
                        if failure == "wrong-psk":
                            bad["psk"] = "SyntheticWrongPSKPhase200001"
                        elif failure == "wrong-version":
                            bad["version"] = 6 if version == 5 else 4
                            if client == "mihomo":
                                bad["version"] = 3  # v6 unsupported by Mihomo parser
                        else:
                            bad["port" if client == "mihomo" else "server_port"] = free_port()
                        bp = free_port()
                        wrong = client_config(client, bad, bp, name + "-" + failure)
                        rejected = False
                        try:
                            tcp_payload(bp, destination, 128)
                        except (OSError, RuntimeError, TimeoutError):
                            rejected = True
                        finally:
                            stop(wrong)
                        if not rejected:
                            raise RuntimeError("failure interop unexpectedly passed")
                        failures.append({"client": client, "server_version": version, "case": failure, "result": "PASS"})
        # Safe live responses for the OpenAPI validator; no export content is saved.
        for filename, path in [("system-response.json", "/api/v1/system"), ("http-system-response.json", "/api/v1/system"), ("capabilities-response.json", "/api/v1/capabilities"), ("inbounds-response.json", "/api/v1/inbounds"), ("inbound-response.json", "/api/v1/inbounds/" + ids[6])]:
            (root / filename).write_text(json.dumps(request("GET", path), indent=2))
        # Real daemon restart, identity preservation, no canonical input on restart.
        before = request("GET", "/api/v1/inbounds")
        stop(daemon)
        for p in listen_ports.values():
            with socket.socket(socket.AF_INET6) as s:
                s.bind(("::", p))
        daemon = start_server()
        after = request("GET", "/api/v1/inbounds")
        if before["snapshot_revision"] != after["snapshot_revision"] or {i["inbound"]["id"] for i in before["items"]} != {i["inbound"]["id"] for i in after["items"]}:
            raise RuntimeError("restart authority failed")
        for version in (5, 6):
            exported = request("POST", "/api/v1/inbounds/" + ids[version] + "/export", {"format": "sing-box", "client_version": "1.14.1"})
            pp = free_port()
            proc = client_config("sing-box", json.loads(exported["content"]), pp, "restart-v" + str(version))
            tcp_payload(pp, destination)
            udp_payload(pp, udp_destination)
            if version == 6:
                stop(daemon)
                try:
                    tcp_payload(pp, destination, 128)
                    raise RuntimeError("stopped server accepted payload")
                except (OSError, TimeoutError):
                    pass
                except RuntimeError as e:
                    if str(e) == "stopped server accepted payload":
                        raise
                failures.append({"client": "sing-box", "server_version": 6, "case": "server-stopped", "result": "PASS"})
            stop(proc)
        # Scan only diagnostics/logs/metadata, never the explicitly secret client configs.
        for f in logs:
            f.flush()
        for p in work.glob("*.log"):
            content = p.read_text(errors="replace")
            if "panic" in content.lower() or "data race" in content.lower() or any(secret in content for secret in secrets):
                raise RuntimeError("diagnostic secret or panic detected")
        report = {"matrix": rows, "failures": failures, "restart": "PASS", "shutdown_listener_release": "PASS", "secret_log_scan": "PASS", "surge": "CONTRACT_ONLY"}
        (root / "interop-results.json").write_text(json.dumps(report, indent=2) + "\n")
        print("INTEROP PASS", flush=True)
    finally:
        for p in reversed(processes):
            stop(p)
        for f in logs:
            f.close()
        tcp.shutdown()
        udp.shutdown()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Do not expose client configuration or arbitrary subprocess output.
        print("INTEROP FAILED: " + type(e).__name__, file=sys.stderr)
        raise SystemExit(1) from None
