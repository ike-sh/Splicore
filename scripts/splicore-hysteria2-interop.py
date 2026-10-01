"""Linux real HY2 interop: trusted synthetic CA, two password identities, QUIC/TCP/UDP.

Usage: python3 scripts/splicore-hysteria2-interop.py /external/evidence
Requires splicore and checksum-pinned clients/{mihomo,sing-box}. Private inputs
are removed in finally; only metadata, logs and summaries are retained.
"""
import concurrent.futures
import copy
import importlib.util
import json
import os
import pathlib
import secrets
import shutil
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time

spec = importlib.util.spec_from_file_location("snell_interop", pathlib.Path(__file__).with_name("splicore-snell-interop.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def udp_sequence(proxy, destination, count=32):
    control, bound = helper.socks(proxy, ("0.0.0.0", 0), 3)
    total = 0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            if bound[0] in ("::", "0.0.0.0"):
                bound = ("127.0.0.1", bound[1])
            header = b"\x00\x00\x00\x01" + socket.inet_aton(destination[0]) + struct.pack("!H", destination[1])
            for sequence in range(count):
                payload = struct.pack("!I", sequence) + bytes([sequence % 256]) * (800 + sequence)
                sock.sendto(header + payload, bound)
                data, _ = sock.recvfrom(65536)
                offset = 10 if data[3] == 1 else 22 if data[3] == 4 else 7 + data[4]
                if data[offset:] != payload:
                    raise RuntimeError("UDP sequence/integrity mismatch")
                total += len(payload)
    finally:
        control.close()
    return total


def main():
    root = pathlib.Path(sys.argv[1]).resolve()
    repo = pathlib.Path(__file__).resolve().parent.parent
    if root.is_relative_to(repo):
        raise SystemExit("evidence must be external")
    os.umask(0o077)
    work = root / "hysteria2-interop"
    work.mkdir(mode=0o700, exist_ok=True)
    private = work / "private"
    private.mkdir(mode=0o700, exist_ok=True)
    state = private / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    api = private / "control.sock"
    key = state / "key"
    exe = str(root / "splicore")
    processes, logs, rows, failures, passwords = [], [], [], [], []
    export_envelopes = []
    tcp = helper.EchoTCP(("127.0.0.1", 0), helper.Echo)
    udp = helper.EchoUDP(("127.0.0.1", 0), helper.UDPEcho)
    for server in (tcp, udp):
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def launch(args, name):
        log = open(work / (name + ".log"), "wb")
        logs.append(log)
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        processes.append(proc)
        with (work / "processes.jsonl").open("a", encoding="utf-8") as record:
            record.write(json.dumps({"pid": proc.pid, "name": name, "executable": args[0]}) + "\n")
        return proc

    def request(method, path, data=None, expected=200):
        conn = helper.UnixHTTP(api)
        try:
            conn.request(method, path, json.dumps(data).encode() if data is not None else None, {"Content-Type": "application/json"})
            response = conn.getresponse()
            raw = response.read()
            if response.status != expected:
                raise RuntimeError("control status mismatch: " + str(response.status))
            return json.loads(raw)
        finally:
            conn.close()

    bootstrap = private / "bootstrap.yaml"

    def start_server():
        proc = launch([exe, "run", "--config", str(bootstrap)], "server-" + str(len(processes)))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError("Splicore startup failure")
            try:
                request("GET", "/api/v1/system")
                return proc
            except OSError:
                time.sleep(.05)
        raise RuntimeError("Splicore startup timeout")

    def start_client(client, exported, name):
        port = helper.free_port()
        path = private / (name + ".json")
        if client == "mihomo":
            config = {"socks-port": port, "allow-lan": False, "bind-address": "127.0.0.1", "ipv6": True, "mode": "rule", "log-level": "silent"}
            config.update(exported)
            config["rules"] = ["MATCH," + config["proxies"][0]["name"]]
            client_home = private / (name + "-home")
            client_home.mkdir(mode=0o700, exist_ok=True)
            args = [str(root / "clients/mihomo"), "-d", str(client_home), "-f", str(path)]
            check = args + ["-t"]
        else:
            config = {"log": {"disabled": True}, "dns": {"servers": [{"type": "local", "tag": "local"}]}, "route": {"default_domain_resolver": "local"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}], "outbounds": [exported]}
            args = [str(root / "clients/sing-box"), "run", "-c", str(path)]
            check = [str(root / "clients/sing-box"), "check", "-c", str(path)]
        path.write_text(json.dumps(config), encoding="utf-8")
        with open(work / (name + "-check.log"), "wb") as log:
            subprocess.run(check, check=True, stdout=log, stderr=subprocess.STDOUT)
        proc = launch(args, name)
        helper.wait_port(port, proc)
        return proc, port

    def view():
        return request("GET", "/api/v1/inbounds/" + inbound_id)

    def snapshot(v):
        return {b["binding_id"]: {k: int(value) for k, value in b["stats"].items()} for b in v["bindings"]}

    def export(client, version, binding):
        envelope = request("POST", "/api/v1/inbounds/" + inbound_id + "/export", {"format": client, "client_version": version, "binding_id": binding})
        expected = "mihomo-config-fragment" if client == "mihomo" else "sing-box-outbound"
        if envelope["content_shape"] != expected:
            raise RuntimeError("export content shape wrong")
        safe = dict(envelope)
        safe["content"] = "[REDACTED]"
        export_envelopes.append(safe)
        return json.loads(envelope["content"])

    def toggle(binding, enabled):
        v = view()
        target = next(b for b in v["bindings"] if b["binding_id"] == binding)
        page = request("GET", "/api/v1/inbounds")
        result = request("POST", "/api/v1/inbounds/" + inbound_id + "/binding", {"binding_id": binding, "enabled": enabled, "resource_revision": target["revision"], "revision": page["snapshot_revision"]})
        (root / "binding-transaction-response.json").write_text(json.dumps(result), encoding="utf-8")

    def assert_denied(port):
        try:
            helper.tcp_payload(port, tcp.server_address, 128)
        except (OSError, RuntimeError, TimeoutError):
            return
        raise RuntimeError("invalid client accepted payload")

    def reconnect_tcp(port):
        deadline = time.monotonic() + 20
        while True:
            try:
                return helper.tcp_payload(port, tcp.server_address)
            except (OSError, RuntimeError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("existing client failed to reconnect") from None
                time.sleep(.2)

    try:
        subprocess.run([exe, "key", "init", "--file", str(key)], check=True, stdout=subprocess.DEVNULL)
        bootstrap.write_text(f"schema: 1\nstate_directory: {state}\nkey_file: {key}\napi:\n  unix_socket: {api}\n", encoding="utf-8")
        ca_key, ca_cert = private / "ca.key", private / "ca.pem"
        cert_key, csr, cert = private / "server.key", private / "server.csr", private / "server.pem"
        extensions = private / "extensions.cnf"
        extensions.write_text("subjectAltName=DNS:hy2.synthetic.test\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n", encoding="utf-8")
        commands = [
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1", "-subj", "/CN=Splicore Synthetic CA", "-addext", "basicConstraints=critical,CA:TRUE"],
            ["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(cert_key), "-out", str(csr), "-subj", "/CN=hy2.synthetic.test"],
            ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "1", "-extfile", str(extensions)],
        ]
        for command in commands:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::", 0))
            listen_port = sock.getsockname()[1]
        fixture = json.loads((repo / "tests/fixtures/nobrand/hysteria2.json").read_text(encoding="utf-8"))
        fixture["listener"] = {"host": "::", "port": listen_port}
        fixture["display_endpoint"] = {"host": "127.0.0.1", "port": listen_port}
        fixture["settings"]["tls"].update(certificate_file=str(cert), private_key_file=str(cert_key), ca_certificate=ca_cert.read_text(encoding="utf-8"))
        for user in fixture["users"]:
            password = secrets.token_urlsafe(32)
            passwords.append(password)
            user["password"] = password
        fixture_file = private / "synthetic-nobrand.json"
        fixture_file.write_text(json.dumps(fixture), encoding="utf-8")
        daemon = start_server()
        # Actual CLI validates/plans/applies the synthetic migration document.
        def cli(*args):
            return json.loads(subprocess.check_output([exe, "inbound", *args, "--protocol", "hysteria2"], stderr=subprocess.DEVNULL))
        cli("validate", "--file", str(fixture_file))
        planned = cli("plan", "--file", str(fixture_file), "--config", str(bootstrap))
        (root / "hysteria2-plan-response.json").write_text(json.dumps(planned), encoding="utf-8")
        plan_file = private / "plan.json"
        plan_file.write_text(json.dumps(planned), encoding="utf-8")
        applied = cli("apply", "--file", str(fixture_file), "--plan", str(plan_file), "--config", str(bootstrap))
        (root / "hysteria2-apply-response.json").write_text(json.dumps(applied), encoding="utf-8")
        inbound_id = applied["inbound_id"]
        identities = {u["account_name"]: b["binding_id"] for u, b in zip(fixture["users"], applied["bindings"])}
        fixture_file.write_text("{}", encoding="utf-8")
        # Domain policies persist independently; no runtime/export bandwidth mapping.
        with sqlite3.connect(state / "state.db") as db:
            policy_rows = db.execute("SELECT quota_bytes,upload_bps,download_bps FROM traffic_policies ORDER BY quota_bytes").fetchall()
        if policy_rows != [(1048576, 1000, None), (2097152, None, 2000)]:
            raise RuntimeError("traffic policy domain data corrupted")
        for client, version in (("mihomo", "1.19.30"), ("sing-box", "1.14.1")):
            for endpoint in ("127.0.0.1", "::1", "localhost"):
                v = view()
                page = request("GET", "/api/v1/inbounds")
                request("POST", "/api/v1/inbounds/" + inbound_id + "/display", {"endpoint": {"host": endpoint, "port": listen_port}, "resource_revision": v["inbound"]["revision"], "revision": page["snapshot_revision"]})
                if view()["inbound"]["listeners"] != v["inbound"]["listeners"]:
                    raise RuntimeError("display changed actual listener")
                running = {}
                before = snapshot(view())
                for user, binding in identities.items():
                    projected = export(client, version, binding)
                    node = projected["proxies"][0] if client == "mihomo" else projected
                    if node.get("sni", node.get("tls", {}).get("server_name")) != "hy2.synthetic.test":
                        raise RuntimeError("display changed SNI")
                    proc, proxy = start_client(client, projected, f"{client}-{len(rows)}-{user}")
                    running[user] = (proc, proxy)
                ports = [p for _, p in running.values()]
                helper.tcp_payload(ports[0], tcp.server_address, 128)
                print("TCP SMOKE PASS " + client + " " + endpoint, flush=True)
                helper.tcp_payload(ports[0], tcp.server_address)
                print("TCP SEQUENTIAL PASS " + client + " " + endpoint, flush=True)
                helper.tcp_payload(ports[1], tcp.server_address)
                print("TCP BOB PASS " + client + " " + endpoint, flush=True)
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                    list(pool.map(lambda n: helper.tcp_payload(ports[n % 2], tcp.server_address), range(16)))
                for user, (proc, proxy) in running.items():
                    sent = helper.tcp_payload(proxy, tcp.server_address)
                    udp_bytes = udp_sequence(proxy, udp.server_address)
                    helper.tcp_payload(proxy, tcp.server_address)  # reconnect
                    large = helper.tcp_payload(proxy, tcp.server_address, 4 << 20)
                    stream, _ = helper.socks(proxy, tcp.server_address)
                    stream.sendall(b"synthetic-abnormal-close")
                    stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    stream.close()
                    after = snapshot(view())[identities[user]]
                    prior = before[identities[user]]
                    if after["upload_bytes"] - prior["upload_bytes"] < sent + large + udp_bytes or after["download_bytes"] - prior["download_bytes"] < sent + large + udp_bytes:
                        raise RuntimeError("per-user payload counters incomplete")
                    row = {"client": client, "version": version, "user": user, "endpoint": endpoint, "tcp": "PASS", "udp": "PASS", "tls": "verified synthetic CA / correct SNI", "concurrent": 16, "large_bytes": large, "udp_packets": 32, "upload_delta": after["upload_bytes"] - prior["upload_bytes"], "download_delta": after["download_bytes"] - prior["download_bytes"], "result": "PASS"}
                    rows.append(row)
                    print(json.dumps(row), flush=True)
                for proc, _ in running.values():
                    helper.stop(proc)
                deadline = time.monotonic() + 12
                while int(view()["stats"]["sessions_active"]):
                    if time.monotonic() > deadline:
                        raise RuntimeError("client close leaked sessions")
                    time.sleep(.1)
                if endpoint == "127.0.0.1":
                    valid = export(client, version, identities["Alice"])
                    for case in ("wrong-password", "wrong-sni", "untrusted-ca"):
                        bad = copy.deepcopy(valid)
                        node = bad["proxies"][0] if client == "mihomo" else bad
                        if case == "wrong-password":
                            node["password"] = "SyntheticWrongPasswordPhase3"
                        elif case == "wrong-sni":
                            if client == "mihomo": node["sni"] = "wrong.synthetic.test"
                            else: node["tls"]["server_name"] = "wrong.synthetic.test"
                        else:
                            if client == "mihomo": node["fingerprint"] = "00" * 32
                            else: node["tls"].pop("certificate")
                        proc, proxy = start_client(client, bad, client + "-" + case)
                        try:
                            assert_denied(proxy)
                        finally:
                            helper.stop(proc)
                        failures.append({"client": client, "case": case, "result": "PASS"})
        # Password is the identity; an Alice credential cannot select Bob's attribution.
        client, version = "sing-box", "1.14.1"
        alice = export(client, version, identities["Alice"])
        bob = export(client, version, identities["Bob"])
        impersonation = copy.deepcopy(bob)
        impersonation["password"] = alice["password"]
        before = snapshot(view())
        proc, proxy = start_client(client, impersonation, "password-identity")
        helper.tcp_payload(proxy, tcp.server_address)
        helper.stop(proc)
        after = snapshot(view())
        if after[identities["Bob"]]["upload_bytes"] != before[identities["Bob"]]["upload_bytes"] or after[identities["Alice"]]["upload_bytes"] <= before[identities["Alice"]]["upload_bytes"]:
            raise RuntimeError("password authenticated as wrong identity")
        print("PASSWORD IDENTITY PASS", flush=True)
        # Keep authenticated client processes across per-Inbound reconciliation.
        pa, ppa = start_client(client, alice, "disable-Alice")
        pb, ppb = start_client(client, bob, "disable-Bob")
        helper.tcp_payload(ppa, tcp.server_address)
        helper.tcp_payload(ppb, tcp.server_address)
        toggle(identities["Alice"], False)
        print("BINDING DISABLE COMMITTED", flush=True)
        assert_denied(ppa)
        reconnect_tcp(ppb)
        print("BOB RECONNECT PASS", flush=True)
        for c, v in (("mihomo", "1.19.30"), ("sing-box", "1.14.1")):
            # Previously exported Alice credential fails after reconcile for both clients.
            saved = export(c, v, identities["Bob"])
            node = saved["proxies"][0] if c == "mihomo" else saved
            node["password"] = alice["password"]
            proc, proxy = start_client(c, saved, c + "-disabled")
            assert_denied(proxy)
            helper.stop(proc)
        failures.append({"client": "both", "case": "disabled-binding / Alice password", "result": "PASS"})
        before_restart = request("GET", "/api/v1/inbounds")
        helper.stop(daemon)
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::", listen_port))
        daemon = start_server()
        print("SQLITE RESTART STARTED", flush=True)
        after_restart = request("GET", "/api/v1/inbounds")
        if before_restart["snapshot_revision"] != after_restart["snapshot_revision"] or before_restart["items"][0]["inbound"]["id"] != after_restart["items"][0]["inbound"]["id"]:
            raise RuntimeError("SQLite authority changed on restart")
        assert_denied(ppa)
        reconnect_tcp(ppb)
        udp_sequence(ppb, udp.server_address)
        toggle(identities["Alice"], True)
        reconnect_tcp(ppa)
        reconnect_tcp(ppb)
        # Save safe live responses only; explicit exports are never saved publicly.
        for filename, path in [("system-response.json", "/api/v1/system"), ("http-system-response.json", "/api/v1/system"), ("capabilities-response.json", "/api/v1/capabilities"), ("inbounds-response.json", "/api/v1/inbounds"), ("inbound-response.json", "/api/v1/inbounds/" + inbound_id)]:
            data = request("GET", path)
            text = json.dumps(data, indent=2)
            if any(p in text for p in passwords) or "PRIVATE KEY" in text:
                raise RuntimeError("ordinary API disclosed secrets")
            (root / filename).write_text(text, encoding="utf-8")
        for command, path in (("status", "/api/v1/system"), ("capabilities", "/api/v1/capabilities")):
            result = json.loads(subprocess.check_output([exe, command, "--config", str(bootstrap)], stderr=subprocess.DEVNULL))
            if result != request("GET", path):
                raise RuntimeError("CLI/API shared query response mismatch: " + command)
        print("CLI/API SHARED SERVICE PASS", flush=True)
        request("POST", "/api/v1/inbounds/" + inbound_id + "/export", {"format": "surge", "client_version": "6.7.0", "binding_id": identities["Alice"]}, expected=422)
        # Force-kill both clients, then stop with no QUIC sessions blocking shutdown.
        for proc in (pa, pb):
            proc.kill()
            proc.wait(timeout=5)
        helper.stop(daemon)
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.bind(("::", listen_port))
        for log in logs:
            log.flush()
        for path in work.glob("*.log"):
            content = path.read_text(encoding="utf-8", errors="replace")
            if "panic" in content.lower() or "data race" in content.lower() or "PRIVATE KEY" in content or any(p in content for p in passwords):
                raise RuntimeError("secret/panic/race in diagnostic log")
        report = {"matrix": rows, "negative": failures, "password_identity": "PASS", "binding_reconcile": "PASS", "policy_metadata": "PASS", "sqlite_recovery": "PASS", "existing_client_reconnect_after_restart": "PASS", "abnormal_kill_shutdown": "PASS", "udp_listener_release": "PASS", "secret_boundary": "PASS", "surge": "UnsupportedExport", "uri": "DEFERRED"}
        report["cli_api_shared_service"] = "PASS"
        (root / "hysteria2-interop-results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        (root / "export-envelopes-response.json").write_text(json.dumps(export_envelopes, indent=2) + "\n", encoding="utf-8")
        print("HYSTERIA2 INTEROP PASS", flush=True)
    finally:
        for proc in reversed(processes):
            helper.stop(proc)
        for log in logs:
            log.close()
        tcp.shutdown()
        udp.shutdown()
        # The final target is resolved and checked before recursive cleanup.
        if private.resolve().parent != work.resolve():
            raise RuntimeError("private cleanup target escaped work directory")
        shutil.rmtree(private)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("HYSTERIA2 INTEROP FAILED: " + type(error).__name__ + ": " + str(error) if isinstance(error, RuntimeError) else "HYSTERIA2 INTEROP FAILED: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1) from None
