"""Managed Mieru acceptance; run in a Linux namespace containing only loopback.

Arguments: external runtime directory, external evidence directory.
Requires current splicore-race-default and SHA-pinned clients/clients.json.
Secrets and owned children are removed on every exit. Traffic is never retried.
"""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
helpers = pathlib.Path(__file__).with_name("splicore-snell-interop.py")
spec = importlib.util.spec_from_file_location("local_fixture", helpers)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def wait_ready(proc, predicate):
    # Observe readiness only. No payload, authentication or failed test is retried.
    deadline = time.monotonic() + 15
    while not predicate():
        if proc.poll() is not None:
            raise RuntimeError("owned process exited before readiness")
        if time.monotonic() >= deadline:
            raise RuntimeError("readiness deadline")
        os.sched_yield()


def listening(port):
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in pathlib.Path(path).read_text().splitlines()[1:]:
            fields = line.split()
            if int(fields[1].split(":")[1], 16) == port and fields[3] == "0A":
                return True
    return False


def main():
    root, evidence = map(lambda p: pathlib.Path(p).resolve(), sys.argv[1:3])
    source = pathlib.Path(__file__).resolve().parent.parent
    assert not root.is_relative_to(source) and not evidence.is_relative_to(source)
    assert len(subprocess.check_output(["ip", "-o", "link", "show"]).splitlines()) == 1
    os.umask(0o077)
    evidence.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mieru-private-", dir=root) as private_path:
        work = pathlib.Path(private_path)
        exe = str(root / "splicore-race-default")
        records = {r["client"]: r for r in json.loads((root / "clients/clients.json").read_text())}
        for name, version in (("mieru", "3.38.0"), ("mihomo", "1.19.30")):
            assert records[name]["version"] == version
            assert hashlib.sha256((root / "clients" / name).read_bytes()).hexdigest() == records[name]["binary_sha256"]
        versions = {}
        for name, arg in (("mieru", "version"), ("mihomo", "-v")):
            value = subprocess.check_output([str(root / "clients" / name), arg], stderr=subprocess.STDOUT).decode()
            assert records[name]["version"] in value
            versions[name] = value.strip()
        (evidence / "client-versions.json").write_text(json.dumps(versions, indent=2) + "\n")
        state = work / "state"
        state.mkdir(mode=0o700)
        key = state / "key"
        api = work / "control.sock"
        subprocess.run([exe, "key", "init", "--file", str(key)], check=True, stdout=subprocess.DEVNULL)
        bootstrap = work / "bootstrap.yaml"
        bootstrap.write_text(f"schema: 1\nstate_directory: {state}\nkey_file: {key}\napi:\n  unix_socket: {api}\n")
        tcp = fixture.EchoTCP(("127.0.0.1", 0), fixture.Echo)
        udp = fixture.EchoUDP(("127.0.0.1", 0), fixture.UDPEcho)
        echo_threads = []
        for server in (tcp, udp):
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            echo_threads.append(thread)
        children, logs, passwords, rows, envelopes = [], [], [], [], []
        expected = {}
        binding_ids = {}
        ids, ports = {}, {}

        def launch(args, name, env=None):
            log = (evidence / (name + ".log")).open("wb")
            logs.append(log)
            proc = subprocess.Popen(args, env=env, stdout=log, stderr=subprocess.STDOUT)
            children.append(proc)
            with (evidence / "owned-processes.jsonl").open("a") as f:
                f.write(json.dumps({"pid": proc.pid, "name": name, "executable": args[0]}) + "\n")
            return proc

        def request(method, path, data=None, rejected=False):
            conn = fixture.UnixHTTP(api)
            try:
                conn.request(method, path, body=json.dumps(data).encode() if data is not None else None,
                             headers={"Content-Type": "application/json"})
                res = conn.getresponse()
                raw = res.read()
                assert not any(p.encode() in raw for p in passwords) or path.endswith("/export")
                if rejected:
                    assert res.status >= 400
                    return json.loads(raw)
                if res.status != 200:
                    raise RuntimeError("control operation rejected at " + path + ": " + str(res.status))
                return json.loads(raw)
            finally:
                conn.close()

        def start_server():
            proc = launch([exe, "run", "--config", str(bootstrap)], "server-" + str(len(children)))
            wait_ready(proc, lambda: any(str(api) in line and line.split()[3] == "00010000"
                                        for line in pathlib.Path("/proc/net/unix").read_text().splitlines()[1:]))
            request("GET", "/api/v1/system")
            return proc

        def view(transport):
            return request("GET", "/api/v1/inbounds/" + ids[transport])

        def display(transport, host):
            v = view(transport)
            page = request("GET", "/api/v1/inbounds")
            request("POST", "/api/v1/inbounds/" + ids[transport] + "/display",
                    {"endpoint": {"host": host, "port": ports[transport]},
                     "resource_revision": v["inbound"]["revision"], "revision": page["snapshot_revision"]})

        def exported(transport, user, client):
            version = records[client]["version"]
            result = request("POST", "/api/v1/inbounds/" + ids[transport] + "/export",
                             {"format": client, "client_version": version, "binding_id": binding_ids[transport][user]})
            envelopes.append(dict(result, content="[REDACTED]"))
            return json.loads(result["content"])

        def start_client(client, config, name):
            proxy = fixture.free_port()
            home = work / name
            home.mkdir(mode=0o700)
            path = home / "client.json"
            if client == "mieru":
                config = dict(config, rpcPort=fixture.free_port(), socks5Port=proxy,
                              socks5ListenLAN=False, loggingLevel="ERROR", advancedSettings={"noCheckUpdate": True})
                path.write_text(json.dumps(config))
                env = dict(os.environ, MIERU_CONFIG_JSON_FILE=str(path))
                proc = launch([str(root / "clients/mieru"), "run"], name, env)
            else:
                outbound = config["proxies"][0]
                controller = home / "controller.sock"
                wrapper = {"socks-port": proxy, "allow-lan": False, "bind-address": "127.0.0.1", "ipv6": True,
                           "external-controller-unix": str(controller), "mode": "rule", "log-level": "silent",
                           "proxies": [outbound], "rules": ["MATCH," + outbound["name"]]}
                path.write_text(json.dumps(wrapper))
                proc = launch([str(root / "clients/mihomo"), "-d", str(home), "-f", str(path)], name)
            wait_ready(proc, lambda: listening(proxy))
            if client == "mihomo":
                # A bound SOCKS listener precedes tunnel.OnRunning in v1.19.30.
                # Its synchronous config API joins ApplyConfig under the executor mutex.
                # Apply the same fixture once before the first payload; no traffic retry.
                wait_ready(proc, lambda: controller.exists())
                conn = fixture.UnixHTTP(controller)
                try:
                    conn.request("PUT", "/configs?force=true", body=json.dumps({"path": str(path)}),
                                 headers={"Content-Type": "application/json"})
                    response = conn.getresponse()
                    response.read()
                    assert response.status == 204, "Mihomo configuration readiness barrier failed"
                finally:
                    conn.close()
            return proc, proxy

        def transfer(transport, user, proxy, kind="tcp", size=32768):
            count = fixture.udp_payload(proxy, udp.server_address) if kind == "udp" else fixture.tcp_payload(proxy, tcp.server_address, size)
            # Every recorded event updates the same expected inbound and binding source.
            with expected_lock:
                expected[transport][user] += count
            return count

        def check_stats(transport):
            # An abruptly stopped UDP client cannot reliably signal peer teardown.
            # Its server session may remain until upstream idle expiry or owned Close.
            # Native lifecycle tests assert zero after joining Close, without polling.
            v = view(transport)
            per = {b["binding_id"]: b["stats"] for b in v["bindings"]}
            for user, count in expected[transport].items():
                stats = per[binding_ids[transport][user]]
                assert int(stats["upload_bytes"]) == count and int(stats["download_bytes"]) == count
            assert int(v["stats"]["upload_bytes"]) == sum(expected[transport].values())
            assert int(v["stats"]["download_bytes"]) == sum(expected[transport].values())
            return v

        def binding(transport, user, enabled):
            v = view(transport)
            b = next(b for b in v["bindings"] if b["binding_id"] == binding_ids[transport][user])
            page = request("GET", "/api/v1/inbounds")
            return request("POST", "/api/v1/inbounds/" + ids[transport] + "/binding",
                           {"binding_id": b["binding_id"], "enabled": enabled,
                            "resource_revision": b["revision"], "revision": page["snapshot_revision"]})

        def rejected_traffic(client, config, name):
            proc, proxy = start_client(client, config, name)
            rejected = False
            try:
                fixture.tcp_payload(proxy, tcp.server_address, 128)
            except (OSError, RuntimeError, TimeoutError):
                rejected = True
            finally:
                fixture.stop(proc)
            assert rejected, "invalid credential accepted"

        expected_lock = threading.Lock()
        cleanup_errors = []
        try:
            daemon = start_server()
            for transport in ("tcp", "udp"):
                port = fixture.free_port("::")
                ports[transport] = port
                users = []
                for user in ("Alice", "Bob"):
                    password = "Phase8-" + transport + "-" + user + "-" + os.urandom(18).hex()
                    passwords.append(password)
                    users.append({"account_name": user + "-" + transport, "username": user, "password": password})
                doc = {"schema": 1, "name": "synthetic-mieru-" + transport,
                       "listener": {"host": "::", "port": port}, "display_endpoint": {"host": "127.0.0.1", "port": port},
                       "settings": {"transport": transport, "mtu": 1500, "multiplex": "default"}, "users": users}
                canonical = work / (transport + "-import.json")
                canonical.write_text(json.dumps(doc))
                subprocess.run([exe, "inbound", "validate", "--protocol", "mieru", "--file", str(canonical)], check=True, stdout=subprocess.DEVNULL)
                request("POST", "/api/v1/creation/mieru/validate", doc)
                plan = request("POST", "/api/v1/creation/mieru/plan", doc)
                applied = request("POST", "/api/v1/creation/mieru/apply", {"document": doc, "digest": plan["digest"], "revision": plan["revision"]})
                ids[transport] = applied["inbound_id"]
                binding_ids[transport] = {u: b["binding_id"] for u, b in zip(("Alice", "Bob"), applied["bindings"])}
                expected[transport] = {"Alice": 0, "Bob": 0}
                canonical.unlink()
                if transport == "tcp":
                    (evidence / "mieru-plan-response.json").write_text(json.dumps(plan, indent=2))
                    (evidence / "mieru-apply-response.json").write_text(json.dumps(applied, indent=2))
                    # A committed second inbound on the same port is rejected, with no pending journal entry.
                    conflict = dict(doc, name="synthetic-conflict")
                    cp = request("POST", "/api/v1/creation/mieru/plan", conflict)
                    request("POST", "/api/v1/creation/mieru/apply", {"document": conflict, "digest": cp["digest"], "revision": cp["revision"]}, rejected=True)
            for transport in ("tcp", "udp"):
                for endpoint in ("127.0.0.1", "::1", "localhost"):
                    display(transport, endpoint)
                    for client in ("mieru", "mihomo"):
                        active = []
                        for user in ("Alice", "Bob"):
                            config = exported(transport, user, client)
                            proc, proxy = start_client(client, config, "cell-" + str(len(rows)))
                            active.append((user, proc, proxy))
                            transfer(transport, user, proxy)
                            transfer(transport, user, proxy, "udp")
                            transfer(transport, user, proxy)  # a new TCP connection
                            large = transfer(transport, user, proxy, size=4 << 20)
                            abrupt, _ = fixture.socks(proxy, tcp.server_address)
                            abrupt.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                            abrupt.close()
                            transfer(transport, user, proxy, size=1024)
                            row = {"client": client, "version": records[client]["version"], "sha256": records[client]["binary_sha256"],
                                   "user": user, "endpoint": endpoint, "underlay": transport, "tcp": "PASS", "udp": "PASS",
                                   "large_bytes": large, "hash_integrity": "PASS", "reconnect": "PASS", "abnormal_close": "PASS", "result": "PASS"}
                            rows.append(row)
                            print(json.dumps(row), flush=True)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                            barrier = threading.Barrier(16)
                            def mixed(n):
                                barrier.wait(timeout=10)
                                user, _, proxy = active[n % 2]
                                transfer(transport, user, proxy, "udp" if n % 4 >= 2 else "tcp", 1024)
                            list(pool.map(mixed, range(16)))
                        for _, proc, _ in active:
                            fixture.stop(proc)
                        check_stats(transport)
            negatives = []
            for client in ("mieru", "mihomo"):
                original = exported("tcp", "Alice", client)
                bad = json.loads(json.dumps(original))
                if client == "mieru":
                    bad["profiles"][0]["user"]["password"] = "SyntheticWrongPasswordPhase8"
                else:
                    bad["proxies"][0]["password"] = "SyntheticWrongPasswordPhase8"
                rejected_traffic(client, bad, "wrong-" + client)
                cross = json.loads(json.dumps(original))
                if client == "mieru":
                    cross["profiles"][0]["servers"][0]["portBindings"][0] = {"port": ports["udp"], "protocol": "UDP"}
                else:
                    cross["proxies"][0].update(port=ports["udp"], transport="UDP")
                rejected_traffic(client, cross, "cross-inbound-" + client)
                negatives.append({"client": client, "wrong_password": "EXPECTED REJECT", "cross_inbound_credential": "EXPECTED REJECT"})
            # Both inbounds and users carry traffic at once; equal usernames use different secrets.
            active = []
            for transport in ("tcp", "udp"):
                for user in ("Alice", "Bob"):
                    proc, proxy = start_client("mieru", exported(transport, user, "mieru"), "isolation-" + transport + user)
                    active.append((transport, user, proc, proxy))
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(lambda n: transfer(active[n % 4][0], active[n % 4][1], active[n % 4][3]), range(16)))
            for _, _, proc, _ in active:
                fixture.stop(proc)
            for transport in ("tcp", "udp"):
                check_stats(transport)
            before = request("GET", "/api/v1/inbounds")
            fixture.stop(daemon)
            # The closed SQLite database contains ciphertext, not live credential strings.
            for path in state.glob("*.db*"):
                assert not any(p.encode() in path.read_bytes() for p in passwords)
            daemon = start_server()
            after = request("GET", "/api/v1/inbounds")
            assert before["snapshot_revision"] == after["snapshot_revision"]
            assert {v["inbound"]["id"] for v in before["items"]} == {v["inbound"]["id"] for v in after["items"]}
            for transport in ("tcp", "udp"):
                assert {b["binding_id"] for b in view(transport)["bindings"]} == set(binding_ids[transport].values())
                expected[transport] = {"Alice": 0, "Bob": 0}
                proc, proxy = start_client("mieru", exported(transport, "Alice", "mieru"), "recovered-" + transport)
                transfer(transport, "Alice", proxy)
                transfer(transport, "Alice", proxy, "udp")
                fixture.stop(proc)
                check_stats(transport)
            # Restart reconciliation removes a user; the other inbound continues.
            removed = exported("tcp", "Alice", "mieru")
            transaction = binding("tcp", "Alice", False)
            (evidence / "binding-transaction-response.json").write_text(json.dumps(transaction, indent=2))
            rejected_traffic("mieru", removed, "disabled-Alice")
            proc, proxy = start_client("mieru", exported("udp", "Bob", "mieru"), "B-after-A-replace")
            transfer("udp", "Bob", proxy)
            fixture.stop(proc)
            binding("tcp", "Alice", True)
            proc, proxy = start_client("mieru", exported("tcp", "Alice", "mieru"), "reenabled-Alice")
            fixture.tcp_payload(proxy, tcp.server_address)
            fixture.stop(proc)
            for fmt, ver in (("sing-box", "1.14.1"), ("surge", "5"), ("uri", "3.38.0"), ("xray", "26.3.27"), ("mieru", "unknown")):
                request("POST", "/api/v1/inbounds/" + ids["tcp"] + "/export", {"format": fmt, "client_version": ver, "binding_id": binding_ids["tcp"]["Alice"]}, rejected=True)
            for filename, path in (("system-response.json", "/api/v1/system"), ("http-system-response.json", "/api/v1/system"),
                                   ("capabilities-response.json", "/api/v1/capabilities"), ("inbounds-response.json", "/api/v1/inbounds"),
                                   ("inbound-response.json", "/api/v1/inbounds/" + ids["tcp"])):
                (evidence / filename).write_text(json.dumps(request("GET", path), indent=2))
            for args in (("capabilities",), ("doctor",), ("inbound", "list")):
                output = subprocess.check_output([exe, *args, "--config", str(bootstrap)], stderr=subprocess.STDOUT)
                assert not any(p.encode() in output for p in passwords)
            for proc in children:
                if proc.poll() is None:
                    argv = pathlib.Path(f"/proc/{proc.pid}/cmdline").read_bytes()
                    assert not any(p.encode() in argv for p in passwords)
            fixture.stop(daemon)
            for transport, port in ports.items():
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM) as sock:
                    sock.bind(("::", port))
            for log in logs:
                log.flush()
            for path in evidence.glob("*.log"):
                content = path.read_bytes()
                assert not any(p.encode() in content for p in passwords)
                assert not any(s in content for s in (b"WARNING: DATA RACE", b"fatal error: checkptr", b"panic:"))
            (evidence / "export-envelopes-response.json").write_text(json.dumps(envelopes, indent=2))
            report = {"result": "PASS", "matrix": rows, "negative_auth": negatives,
                      "mixed_concurrency": 16, "multi_inbound_concurrent": "PASS", "exact_payload_stats": "PASS",
                      "sqlite_recovery": "PASS", "binding_replace_isolation": "PASS", "shutdown_listener_release": "PASS",
                      "unsupported_exports": "EXPECTED REJECT", "secret_diagnostics_database_argv_scan": "PASS",
                      "runtime_binary_sha256": hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest()}
            (evidence / "interop-results.json").write_text(json.dumps(report, indent=2) + "\n")
            print("MANAGED MIERU INTEROP PASS", flush=True)
        finally:
            for proc in reversed(children):
                try:
                    fixture.stop(proc)
                except Exception as error:
                    cleanup_errors.append(type(error).__name__)
            for log in logs:
                log.close()
            for server, thread in zip((tcp, udp), echo_threads):
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                if thread.is_alive():
                    cleanup_errors.append("echo thread retained")
            assert work.resolve().parent == root and work.name.startswith("mieru-private-")
            shutil.rmtree(work)
            (evidence / "cleanup.json").write_text(json.dumps({"children_joined": all(p.poll() is not None for p in children),
                                                             "private_directory_removed": not work.exists(), "errors": cleanup_errors}, indent=2))
            if cleanup_errors:
                raise RuntimeError("owned resource cleanup failed")

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Bounded local failure location, never arbitrary subprocess/config output.
        import traceback
        frames = traceback.extract_tb(error.__traceback__)
        print(json.dumps({"result": "FAIL", "type": type(error).__name__, "locations": [f"{pathlib.Path(f.filename).name}:{f.lineno}:{f.name}" for f in frames]}), file=sys.stderr)
        raise SystemExit(1) from None
