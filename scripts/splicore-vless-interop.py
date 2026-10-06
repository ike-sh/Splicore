"""Pinned Linux VLESS traffic qualification. Synthetic inputs stay external.

Usage: python3 scripts/splicore-vless-interop.py /external/runtime [reality|tls|none] [none]
Run inside a loopback-only network/mount namespace. hosts maps target.synthetic.test
to loopback; the real host configuration is unchanged. Reference clients are pinned
by splicore-clients.py. Each campaign has its own state, logs and result file.
"""
import base64
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("quic_helper", pathlib.Path(__file__).with_name("splicore-quic-interop.py"))
quic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quic)
helper = quic.helper


def main():
    root = pathlib.Path(sys.argv[1]).resolve()
    security = sys.argv[2] if len(sys.argv) > 2 else "reality"
    flow = sys.argv[3] if len(sys.argv) > 3 else "none"
    engine = sys.argv[4] if len(sys.argv) > 4 else "native"
    assert engine == "native"
    assert security in ("reality", "tls", "none")
    if flow != "none":
        raise RuntimeError("requested VLESS flow is unsupported")
    repo = pathlib.Path(__file__).resolve().parent.parent
    assert not root.is_relative_to(repo), "evidence must be external"
    os.umask(0o077)
    prefix=os.environ.get("SPLICORE_INTEROP_RUN_PREFIX", "")
    assert prefix in ("", "production-", "final-", "acceptance-")
    label = prefix + f"vless-{security}-{flow}"
    work = root / label
    work.mkdir(mode=0o700, exist_ok=False)
    private = work / "private"
    private.mkdir(mode=0o700)
    state = private / "state"
    state.mkdir(mode=0o700)
    api, key = private / "c.sock", state / "key"
    bootstrap = private / "bootstrap.yaml"
    binary=os.environ.get("SPLICORE_INTEROP_BINARY", "splicore")
    assert binary in ("splicore", "splicore-production", "splicore-race-default")
    exe = str(root / binary)
    processes, logs, matrix, negative, forbidden, envelopes = [], [], [], [], [], []
    tcp = helper.EchoTCP(("127.0.0.1", 0), helper.Echo)
    udp = helper.EchoUDP(("127.0.0.1", 0), helper.UDPEcho)
    servers = [tcp, udp]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def launch(args, name):
        log = (work / (name + ".log")).open("wb")
        logs.append(log)
        process = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        with (work / "processes.jsonl").open("a", encoding="utf-8") as record:
            record.write(json.dumps({"pid": process.pid, "name": name, "executable": args[0]}) + "\n")
        return process

    def request(method, path, data=None, expected=200):
        connection = helper.UnixHTTP(api)
        try:
            connection.request(method, path, json.dumps(data).encode() if data is not None else None, {"Content-Type": "application/json"})
            response = connection.getresponse()
            body = response.read()
            if response.status != expected:
                raise RuntimeError(f"control status {response.status}, expected {expected}, path {path}")
            value = json.loads(body)
            if expected == 200 and path.endswith("/export"):
                if any(secret in body.decode() for secret in forbidden[:1]):
                    raise RuntimeError("BLOCKING SECURITY GATE: private key in API export")
            return value
        finally:
            connection.close()

    def start_server():
        process = launch([exe, "run", "--config", str(bootstrap)], "server-" + str(len(processes)))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("Splicore startup failed")
            try:
                request("GET", "/api/v1/system")
                return process
            except OSError:
                os.sched_yield()
        raise RuntimeError("Splicore startup timeout")


    def start_client(client, exported, name):
        port = helper.free_port()
        path = private / (name + ".json")
        if client == "mihomo":
            config = {"socks-port": port, "allow-lan": False, "bind-address": "127.0.0.1", "ipv6": True, "mode": "rule", "log-level": "silent"}
            config.update(exported)
            config["rules"] = ["MATCH," + config["proxies"][0]["name"]]
            home = private / (name + "-home")
            home.mkdir(mode=0o700, exist_ok=True)
            controller = helper.free_port()
            config["external-controller"] = f"127.0.0.1:{controller}"
            path = home / "config.json"
            args = [str(root / "clients/mihomo"), "-d", str(home), "-f", str(path)]
            check = args + ["-t"]
        else:
            config = {"log": {"disabled": True}, "dns": {"servers": [{"type": "local", "tag": "local"}]}, "route": {"default_domain_resolver": "local"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}], "outbounds": [exported]}
            args = [str(root / "clients/sing-box"), "run", "-c", str(path)]
            check = [str(root / "clients/sing-box"), "check", "-c", str(path)]
        path.write_text(json.dumps(config), encoding="utf-8")
        with (work / (name + "-check.log")).open("wb") as log:
            subprocess.run(check, check=True, stdout=log, stderr=subprocess.STDOUT)
        process = launch(args, name)
        helper.wait_port(port, process)
        if client == "mihomo":
            helper.wait_mihomo_config(controller, path, process, config["proxies"][0]["name"])
        return process, port

    def view():
        return request("GET", "/api/v1/inbounds/" + inbound_id)

    def snapshot():
        return {b["binding_id"]: {k: int(v) for k, v in b["stats"].items()} for b in view()["bindings"]}

    def export(client, version, binding):
        result = request("POST", "/api/v1/inbounds/" + inbound_id + "/export", {"format": client, "client_version": version, "binding_id": binding})
        if any(secret in result["content"] for secret in forbidden[:1]) or '"private_key"' in result["content"] or '"target"' in result["content"]:
            raise RuntimeError("BLOCKING SECURITY GATE: server material in client config")
        safe = dict(result)
        safe["content"] = "[REDACTED]"
        envelopes.append(safe)
        if client == "uri":
            assert result["content"].startswith("vless://")
            return result["content"]
        return json.loads(result["content"])

    def toggle(binding, enabled):
        selected = next(b for b in view()["bindings"] if b["binding_id"] == binding)
        page = request("GET", "/api/v1/inbounds")
        result = request("POST", "/api/v1/inbounds/" + inbound_id + "/binding", {"binding_id": binding, "enabled": enabled, "resource_revision": selected["revision"], "revision": page["snapshot_revision"]})
        (work / "binding-transaction-response.json").write_text(json.dumps(result), encoding="utf-8")

    def denied(proxy):
        before = snapshot()
        try:
            helper.tcp_payload(proxy, tcp.server_address, 128)
        except (OSError, RuntimeError, TimeoutError):
            after = snapshot()
            if any(after[b]["upload_bytes"] != before[b]["upload_bytes"] for b in before):
                raise RuntimeError("denied credential routed payload")
            if view()["health"] != "healthy":
                raise RuntimeError("negative traffic harmed server")
            return
        raise RuntimeError("invalid client forwarded proxy traffic")

    def reconnect(proxy):
        return helper.tcp_payload(proxy, tcp.server_address)


    try:
        subprocess.run([exe, "key", "init", "--file", str(key)], check=True, stdout=subprocess.DEVNULL)
        bootstrap.write_text(f"schema: 1\nstate_directory: {state}\nkey_file: {key}\napi:\n  unix_socket: {api}\n", encoding="utf-8")
        sni = "target.synthetic.test"
        ca_key, ca_cert = private / "ca.key", private / "ca.pem"
        cert_key, csr, cert = private / "server.key", private / "server.csr", private / "server.pem"
        extensions = private / "extensions.cnf"
        extensions.write_text(f"subjectAltName=DNS:{sni}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n", encoding="utf-8")
        for command in [
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(ca_key), "-out", str(ca_cert), "-days", "1", "-subj", "/CN=Splicore Synthetic CA", "-addext", "basicConstraints=critical,CA:TRUE"],
            ["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(cert_key), "-out", str(csr), "-subj", "/CN=" + sni],
            ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(cert), "-days", "1", "-extfile", str(extensions)],
        ]:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # A target must serve the reference engine's concurrent TLS probes and
        # handshakes independently. openssl s_server is a serial test fixture.
        target_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        target_context.minimum_version = ssl.TLSVersion.TLSv1_3
        target_context.maximum_version = ssl.TLSVersion.TLSv1_3
        target_context.set_ecdh_curve("X25519")
        target_context.set_alpn_protocols(["http/1.1"])
        target_context.load_cert_chain(str(cert), str(cert_key))
        class SyntheticTarget(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(8)
                try:
                    with target_context.wrap_socket(self.request, server_side=True) as connection:
                        if connection.recv(4096):
                            connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nsynthetic")
                except (OSError, ssl.SSLError):
                    pass
        decoy = helper.EchoTCP(("127.0.0.1",0),SyntheticTarget)
        servers.append(decoy)
        target_port = decoy.server_address[1]
        threading.Thread(target=decoy.serve_forever,daemon=True).start()
        with socket.socket(socket.AF_INET6) as sock:
            sock.bind(("::", 0))
            listen_port = sock.getsockname()[1]
        settings = {"security": security, "flow": flow, "transport": "tcp", "packet_encoding": "xudp"}
        fixture = {"schema": 1, "engine": engine, "name": label, "listener": {"host": "::", "port": listen_port}, "display_endpoint": {"host": "127.0.0.1", "port": listen_port}, "settings": settings, "users": [{"account_name": "Alice", "uuid": str(uuid.uuid4())}, {"account_name": "Bob", "uuid": str(uuid.uuid4())}]}
        server_key = ""
        if security == "reality":
            der = subprocess.check_output(["openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"], stderr=subprocess.DEVNULL)
            public_der = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=der, capture_output=True, check=True).stdout
            server_key = base64.urlsafe_b64encode(der[-32:]).decode().rstrip("=")
            public_key = base64.urlsafe_b64encode(public_der[-32:]).decode().rstrip("=")
            settings["reality"] = {"public_key": public_key, "short_ids": ["abcd", "", "0123456789abcdef"], "server_name": sni, "target": {"host": sni, "port": target_port}}
            fixture["server_secret"] = {"private_key": server_key}
            forbidden.append(server_key)
        else:
            # The first gate value represents the server secret, never a user UUID.
            forbidden.append(cert_key.read_text(encoding="utf-8"))
            if security == "tls":
                settings["tls"] = {"server_name": sni, "certificate_file": str(cert), "private_key_file": str(cert_key), "ca_certificate": ca_cert.read_text(encoding="utf-8")}
        forbidden.extend(u["uuid"] for u in fixture["users"])
        daemon = start_server()
        fixture_file = private / "synthetic-owned.json"
        fixture_file.write_text(json.dumps(fixture), encoding="utf-8")
        def cli(*args):
            result = subprocess.run([exe, "inbound", *args, "--protocol", "vless"], capture_output=True)
            if result.returncode:
                raise RuntimeError("CLI rejected operation: " + result.stderr.decode(errors="replace"))
            return json.loads(result.stdout)
        cli("validate", "--file", str(fixture_file))
        planned = cli("plan", "--file", str(fixture_file), "--config", str(bootstrap))
        assert planned["engine"] == engine and planned["protocol"]["protocol"] == "vless"
        (work / "plan-response.json").write_text(json.dumps(planned), encoding="utf-8")
        plan_file = private / "plan.json"
        plan_file.write_text(json.dumps(planned), encoding="utf-8")
        applied = cli("apply", "--file", str(fixture_file), "--plan", str(plan_file), "--config", str(bootstrap))
        (work / "apply-response.json").write_text(json.dumps(applied), encoding="utf-8")
        inbound_id = applied["inbound_id"]
        identities = {u["account_name"]: b["binding_id"] for u, b in zip(fixture["users"], applied["bindings"])}
        baseline_revision = request("GET", "/api/v1/inbounds")["snapshot_revision"]
        vision = copy.deepcopy(fixture)
        vision["settings"]["flow"] = "xtls-rprx-vision"
        rejections = []
        for action in ("validate", "plan", "apply"):
            body = {"document": vision, "digest": "unused", "revision": baseline_revision} if action == "apply" else vision
            problem = request("POST", "/api/v1/creation/vless/" + action, body, expected=501)
            assert problem["code"] == "not_implemented"
            rejections.append({"entry": action, "result": "REJECTED", "problem": problem})
        fixture_file.write_text(json.dumps(vision), encoding="utf-8")
        rejected = subprocess.run([exe, "inbound", "validate", "--protocol", "vless", "--file", str(fixture_file)], capture_output=True)
        assert rejected.returncode != 0 and not rejected.stdout and b"not_implemented" in rejected.stderr
        assert not any(secret in rejected.stderr.decode() for secret in forbidden)
        assert request("GET", "/api/v1/inbounds")["snapshot_revision"] == baseline_revision
        capabilities = request("GET", "/api/v1/capabilities")
        for capability in capabilities["items"]:
            if capability["protocol"] == "vless":
                assert capability["features"]["vision"] is False
                assert capability["features"]["supported_flows"] == ["none"]
                for implementation in capability["engine_implementations"]:
                    assert implementation["features"]["vision"] is False
        (work / "vision-rejection-response.json").write_text(json.dumps(rejections, indent=2), encoding="utf-8")

        policy_rejections = []
        policy_code = "invalid"
        policy_status = 400
        for limit in ("quota_bytes", "upload_bps", "download_bps"):
            strict = copy.deepcopy(fixture)
            strict["users"][0]["traffic_policy"] = {limit: 100}
            for action in ("validate", "plan", "apply"):
                body = {"document": strict, "digest": "unused", "revision": baseline_revision} if action == "apply" else strict
                problem = request("POST", "/api/v1/creation/vless/" + action, body, expected=policy_status)
                assert problem["code"] == policy_code
                policy_rejections.append({"limit": limit, "entry": action, "result": "REJECTED", "problem": problem})
            fixture_file.write_text(json.dumps(strict), encoding="utf-8")
            rejected = subprocess.run([exe, "inbound", "validate", "--protocol", "vless", "--file", str(fixture_file)], capture_output=True)
            assert rejected.returncode != 0 and not rejected.stdout and policy_code.encode() in rejected.stderr
            assert not any(secret in rejected.stderr.decode() for secret in forbidden)
        assert request("GET", "/api/v1/inbounds")["snapshot_revision"] == baseline_revision
        (work / "policy-rejection-response.json").write_text(json.dumps(policy_rejections, indent=2), encoding="utf-8")
        fixture_file.write_text("{}", encoding="utf-8")
        endpoints = ("127.0.0.1", "::1", "localhost") if security == "reality" else ("127.0.0.1",)
        for client, version in (("mihomo", "1.19.30"), ("sing-box", "1.14.1")):
            for endpoint in endpoints:
                old = view()
                page = request("GET", "/api/v1/inbounds")
                request("POST", "/api/v1/inbounds/" + inbound_id + "/display", {"endpoint": {"host": endpoint, "port": listen_port}, "resource_revision": old["inbound"]["revision"], "revision": page["snapshot_revision"]})
                assert old["inbound"]["listeners"] == view()["inbound"]["listeners"]
                before = snapshot()
                running = {}
                for user, binding in identities.items():
                    config = export(client, version, binding)
                    node = config["proxies"][0] if client == "mihomo" else config
                    assert node["server"] == endpoint
                    if security != "none":
                        assert (node.get("servername") if client=="mihomo" else node.get("tls", {}).get("server_name")) == sni
                    running[user] = start_client(client, config, f"{client}-{len(matrix)}-{user}")
                proxies = [proxy for _, proxy in running.values()]
                for proxy in proxies:
                    helper.tcp_payload(proxy, tcp.server_address, 128)
                print(f"TCP SMOKE PASS {security} {flow} {client} {endpoint}", flush=True)
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                    list(pool.map(lambda n: helper.tcp_payload(proxies[n % 2], tcp.server_address), range(16)))
                for user, (process, proxy) in running.items():
                    sent = helper.tcp_payload(proxy, tcp.server_address)
                    udp_bytes = quic.udp_sequence(proxy, udp.server_address)
                    reconnect(proxy)
                    large = helper.tcp_payload(proxy, tcp.server_address, 4 << 20)
                    stream, _ = helper.socks(proxy, tcp.server_address)
                    stream.sendall(b"synthetic-reset")
                    stream.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    stream.close()
                    counters = snapshot()[identities[user]]
                    delta = {k: counters[k] - before[identities[user]].get(k, 0) for k in counters}
                    if engine == "native" and (delta["upload_bytes"] < sent + large + udp_bytes or delta["download_bytes"] < sent + large + udp_bytes):
                        raise RuntimeError("attributed payload counters incomplete")
                    row = {"client": client, "version": version, "sha256": next(c["binary_sha256"] for c in json.loads((root / "clients/clients.json").read_text(encoding="utf-8")) if c["client"] == client), "user": user, "endpoint": endpoint, "security": security, "flow": flow, "tcp": "PASS", "udp": "PASS", "concurrent": 16, "large_bytes": large, "udp_packets": 32, "reconnect": "PASS", "abnormal_close": "PASS", "upload_delta": delta["upload_bytes"], "download_delta": delta["download_bytes"], "result": "PASS"}
                    matrix.append(row)
                    row["engine"] = engine
                    print(json.dumps(row), flush=True)
                for process, _ in running.values():
                    helper.stop(process)
                deadline = time.monotonic() + 12
                while int(view()["stats"]["sessions_active"]):
                    if time.monotonic() > deadline:
                        raise RuntimeError("closed clients retained active sessions")
                    os.sched_yield()
                if security != "tls":
                    export("uri", "", identities["Alice"])
                if endpoint == "127.0.0.1":
                    valid = export(client, version, identities["Alice"])
                    cases = ["wrong-uuid"] + (["wrong-pbk", "wrong-sid", "wrong-sni"] if security == "reality" else ["wrong-sni", "wrong-ca"] if security == "tls" else [])
                    for case in cases:
                        bad = copy.deepcopy(valid)
                        node = bad["proxies"][0] if client == "mihomo" else bad
                        if case == "wrong-uuid":
                            node["uuid"] = str(uuid.uuid4())
                        elif case == "wrong-sni":
                            if client == "mihomo": node["servername"] = "wrong.synthetic.test"
                            else: node["tls"]["server_name"] = "wrong.synthetic.test"
                        elif case == "wrong-ca":
                            if client == "mihomo": node["fingerprint"] = "00" * 32
                            else: node["tls"].pop("certificate")
                        else:
                            options = node["reality-opts"] if client == "mihomo" else node["tls"]["reality"]
                            options[("public-key" if client == "mihomo" else "public_key") if case == "wrong-pbk" else ("short-id" if client == "mihomo" else "short_id")] = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=") if case == "wrong-pbk" else "ffff"
                        process, proxy = start_client(client, bad, client + "-" + case)
                        try: denied(proxy)
                        finally: helper.stop(process)
                        negative.append({"client": client, "case": case, "result": "PASS", "meaning": "no authenticated proxy payload; REALITY camouflage may connect to target"})
        # UUID attribution follows authenticated Binding, irrespective of client tag.
        alice = export("sing-box", "1.14.1", identities["Alice"])
        bob = export("sing-box", "1.14.1", identities["Bob"])
        relabelled = copy.deepcopy(bob)
        relabelled["uuid"] = alice["uuid"]
        before = snapshot()
        process, proxy = start_client("sing-box", relabelled, "credential-identity")
        helper.tcp_payload(proxy, tcp.server_address)
        helper.stop(process)
        after = snapshot()
        if engine == "native":
            assert after[identities["Alice"]]["upload_bytes"] > before[identities["Alice"]]["upload_bytes"]
        assert after[identities["Bob"]]["upload_bytes"] == before[identities["Bob"]]["upload_bytes"]
        pa, ppa = start_client("sing-box", alice, "disable-Alice")
        pb, ppb = start_client("sing-box", bob, "disable-Bob")
        helper.tcp_payload(ppa, tcp.server_address)
        helper.tcp_payload(ppb, tcp.server_address)
        toggle(identities["Alice"], False)
        denied(ppa)
        reconnect(ppb)
        before_restart = request("GET", "/api/v1/inbounds")
        helper.stop(daemon)
        with socket.socket(socket.AF_INET6) as sock:
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.bind(("::", listen_port))
        daemon = start_server()
        after_restart = request("GET", "/api/v1/inbounds")
        assert before_restart["snapshot_revision"] == after_restart["snapshot_revision"]
        assert before_restart["items"][0]["inbound"]["id"] == after_restart["items"][0]["inbound"]["id"]
        denied(ppa)
        reconnect(ppb)
        quic.udp_sequence(ppb, udp.server_address)
        toggle(identities["Alice"], True)
        reconnect(ppa)
        reconnect(ppb)
        request("POST", "/api/v1/inbounds/" + inbound_id + "/export", {"format": "surge", "client_version": "6.7.0", "binding_id": identities["Alice"]}, expected=422)
        for filename, path in [("system-response.json", "/api/v1/system"), ("http-system-response.json", "/api/v1/system"), ("capabilities-response.json", "/api/v1/capabilities"), ("inbounds-response.json", "/api/v1/inbounds"), ("inbound-response.json", "/api/v1/inbounds/" + inbound_id)]:
            value = request("GET", path)
            text = json.dumps(value, indent=2)
            if any(secret in text for secret in forbidden): raise RuntimeError("ordinary API secret leak")
            (work / filename).write_text(text, encoding="utf-8")
        doctor = subprocess.check_output([exe, "doctor", "--config", str(bootstrap)], stderr=subprocess.DEVNULL).decode()
        if any(secret in doctor for secret in forbidden): raise RuntimeError("doctor secret leak")
        (work / "doctor-response.json").write_text(doctor, encoding="utf-8")
        for command, path in (("status", "/api/v1/system"), ("capabilities", "/api/v1/capabilities")):
            assert json.loads(subprocess.check_output([exe, command, "--config", str(bootstrap)], stderr=subprocess.DEVNULL)) == request("GET", path)
        for process in (pa, pb):
            process.kill();process.wait(timeout=5)
        helper.stop(daemon)
        with socket.socket(socket.AF_INET6) as sock:
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.bind(("::", listen_port))
        for log in logs: log.flush()
        for path in work.glob("*.log"):
            text = path.read_text(encoding="utf-8", errors="replace")
            if "panic" in text.lower() or "data race" in text.lower() or any(secret in text for secret in forbidden): raise RuntimeError("diagnostic secret/panic/race gate")
        # Closed DB and WAL contain ciphertext, never the supplied server key or UUIDs.
        for path in state.glob("state.db*"):
            if any(secret.encode() in path.read_bytes() for secret in forbidden): raise RuntimeError("plaintext secret at rest")
        result = {"engine":engine,"matrix": matrix, "negative": negative, "server_binary":binary,"server_sha256":hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest(), "security": security, "flow": flow, "secret_leak_gate": "PASS", "credential_identity": "PASS", "binding_reconcile": "PASS", "sqlite_recovery": "PASS", "existing_client_reconnect": "PASS", "forced_client_kill": "PASS", "clean_shutdown": "PASS", "tcp_listener_release": "PASS", "uri": "UnsupportedExport for explicit CA TLS" if security == "tls" else "PASS", "surge": "UnsupportedExport", "cli_api_shared_service": "PASS"}
        result.update({"strict_policy_rejection":"PASS", "strict_policy_error":policy_code})
        (work / "interop-results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        (work / "export-envelopes-response.json").write_text(json.dumps(envelopes, indent=2) + "\n", encoding="utf-8")
        print(label + " INTEROP PASS", flush=True)
    finally:
        for process in reversed(processes): helper.stop(process)
        for log in logs: log.close()
        for server in servers: server.shutdown()
        if private.resolve().parent != work.resolve(): raise RuntimeError("cleanup escaped campaign")
        shutil.rmtree(private)


if __name__ == "__main__":
    main()
