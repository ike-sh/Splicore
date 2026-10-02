"""Managed Splicore FinalMask/Sudoku acceptance with the pinned Xray client.

Run only inside the existing loopback-only Linux network/mount namespace.
Usage: python3 scripts/splicore-sudoku-interop.py /external/runtime
The public API supplies canonical typed options; the client consumes the authorized
Splicore exporter output. No mask algorithm or wire implementation lives here.
"""
import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("local_fixture", Path(__file__).with_name("splicore-snell-interop.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def main():
    os.umask(0o077)
    root = Path(sys.argv[1]).resolve()
    repo = Path(__file__).resolve().parent.parent
    assert not root.is_relative_to(repo)
    work = root / "sudoku-interop"
    work.mkdir(mode=0o700, exist_ok=False)
    private = work / "private"
    private.mkdir(mode=0o700)
    state = private / "state"
    state.mkdir(mode=0o700)
    api, key, bootstrap = private / "c.sock", state / "key", private / "bootstrap.yaml"
    exe = str(root / "splicore-race-default")
    xray = Path(os.environ["SPLICORE_XRAY_BINARY"]).resolve()
    digest = hashlib.sha256(xray.read_bytes()).hexdigest()
    assert digest == "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed"
    version = subprocess.check_output([str(xray), "version"], env={"LANG": "C"}, timeout=5).decode().split()[1]
    assert version == "26.3.27"
    children, logs, matrix, negative, envelopes, problems = [], [], [], [], [], []
    secret_values = [secrets.token_hex(16).upper(), str(uuid.uuid4()), str(uuid.uuid4())]
    password = secret_values[0]
    target = helper.EchoTCP(("127.0.0.1", 0), helper.Echo)
    thread = threading.Thread(target=target.serve_forever, daemon=True)
    thread.start()

    def save(name, value):
        (work / name).write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def launch(args, name):
        log = (work / (name + ".log")).open("wb")
        logs.append(log)
        child = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env={"PATH": os.environ["PATH"], "LANG": "C"})
        children.append(child)
        with (work / "processes.jsonl").open("a") as record:
            record.write(json.dumps({"pid": child.pid, "executable": args[0], "name": name}) + "\n")
        return child

    def request(method, path, body=None, expected=200):
        conn = helper.UnixHTTP(api)
        try:
            conn.request(method, path, json.dumps(body).encode() if body is not None else None, {"Content-Type": "application/json"})
            response = conn.getresponse()
            data = response.read()
            assert response.status == expected, "unexpected control response status"
            result = json.loads(data)
            if not (expected == 200 and path.endswith("/export")):
                assert not any(value in data.decode() for value in secret_values), "ordinary API secret leak"
            return result
        finally:
            conn.close()

    def start_server():
        child = launch([exe, "run", "--config", str(bootstrap)], "server-" + str(len(children)))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            assert child.poll() is None, "managed daemon exited during readiness"
            try:
                request("GET", "/api/v1/system")
                return child
            except OSError:
                pass
        raise RuntimeError("managed daemon readiness timeout")

    def ready(port, child):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            assert child.poll() is None, "pinned client exited before readiness"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    return
            except OSError:
                pass
        raise RuntimeError("pinned client readiness timeout")

    def client(outbound, name, check_only=False):
        port = helper.free_port()
        config = {"log": {"loglevel": "none"}, "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": {"udp": False}}], "outbounds": [outbound]}
        path = private / (name + ".json")
        path.write_text(json.dumps(config), encoding="utf-8")
        path.chmod(0o600)
        checked = subprocess.run([str(xray), "run", "-test", "-config", str(path)], env={"LANG": "C"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if check_only:
            return checked.returncode
        assert checked.returncode == 0, "exported client config rejected"
        child = launch([str(xray), "run", "-config", str(path)], name)
        ready(port, child)
        return child, port

    def view():
        return request("GET", "/api/v1/inbounds/" + inbound_id)

    def export(binding):
        result = request("POST", "/api/v1/inbounds/" + inbound_id + "/export", {"format": "xray", "client_version": version, "binding_id": binding})
        assert result["content_shape"] == "xray-outbound"
        node = json.loads(result["content"])
        assert node["streamSettings"]["finalmask"]["tcp"][0]["settings"]["password"] == password
        assert "engine" not in node and "private_key" not in result["content"]
        safe = dict(result)
        safe["content"] = "[REDACTED]"
        envelopes.append(safe)
        return node

    def denied(proxy):
        accepted = False
        try:
            helper.tcp_payload(proxy, target.server_address, 128)
            accepted = True
        except (OSError, RuntimeError, TimeoutError):
            pass
        assert not accepted, "invalid client routed authenticated payload"
        assert view()["health"] == "healthy", "negative traffic harmed runtime"

    def toggle(binding, enabled):
        current = next(b for b in view()["bindings"] if b["binding_id"] == binding)
        revision = request("GET", "/api/v1/inbounds")["snapshot_revision"]
        txn = request("POST", "/api/v1/inbounds/" + inbound_id + "/binding", {"binding_id": binding, "enabled": enabled, "resource_revision": current["revision"], "revision": revision})
        save("binding-transaction-response.json", txn)

    def artifact_check():
        runtime = view()["runtime"]
        artifact = Path(runtime["config_artifact"])
        assert artifact.resolve().is_relative_to(private.resolve())
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
        assert stat.S_IMODE(artifact.parent.stat().st_mode) == 0o700
        node = json.loads(artifact.read_text())["inbounds"][0]
        assert node["streamSettings"]["finalmask"]["tcp"][0]["settings"]["password"] == password
        return runtime, artifact

    try:
        print("START canonical validation and managed creation", flush=True)
        subprocess.run([exe, "key", "init", "--file", str(key)], check=True, stdout=subprocess.DEVNULL)
        bootstrap.write_text(f"schema: 1\nstate_directory: {state}\nkey_file: {key}\napi:\n  unix_socket: {api}\nxray:\n  binary_path: {xray}\n  runtime_directory: {private / 'xray'}\n", encoding="utf-8")
        daemon = start_server()
        port = helper.free_port()
        document = {"schema": 1, "engine": "xray", "name": "synthetic-sudoku", "listener": {"host": "127.0.0.1", "port": port}, "display_endpoint": {"host": "127.0.0.1", "port": port},
            "settings": {"security": "none", "flow": "none", "transport": "tcp", "packet_encoding": "xudp", "engine_options": {"finalmask": {"tcp": [{"type": "sudoku", "settings": {"ascii": "prefer_ascii", "padding_min": 0, "padding_max": 3}}]}}},
            "transport_secret": {"password": password}, "users": [{"account_name": "Alice", "uuid": secret_values[1]}, {"account_name": "Bob", "uuid": secret_values[2]}]}
        source = private / "canonical.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        subprocess.run([exe, "inbound", "validate", "--protocol", "vless", "--file", str(source)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for case in ["native", "reality", "tls", "vision", "unknown-mask", "invalid-padding", "raw-json"]:
            bad = copy.deepcopy(document)
            expected, code = 422, "unsupported_engine_feature"
            if case == "native": bad["engine"] = "native"
            elif case in ["reality", "tls"]: bad["settings"]["security"] = case
            elif case == "vision": bad["settings"]["flow"] = "xtls-rprx-vision"; expected, code = 501, "not_implemented"
            elif case == "unknown-mask": bad["settings"]["engine_options"]["finalmask"]["tcp"][0]["type"] = "unknown"; expected, code = 400, "invalid"
            elif case == "invalid-padding": bad["settings"]["engine_options"]["finalmask"]["tcp"][0]["settings"]["padding_max"] = 255; expected, code = 400, "invalid"
            else: bad["streamSettings"] = {}; expected, code = 400, "invalid"
            for action in ["validate", "plan", "apply"]:
                body = {"document": bad} if action == "apply" else bad
                problem = request("POST", "/api/v1/creation/vless/" + action, body, expected)
                assert problem["code"] == code
                problems.append({"case": case, "action": action, "problem": problem, "result": "REJECTED"})
        assert request("GET", "/api/v1/inbounds")["snapshot_revision"] == "0"
        save("feature-rejection-response.json", problems)
        request("POST", "/api/v1/creation/vless/validate", document)
        plan = request("POST", "/api/v1/creation/vless/plan", document)
        save("plan-response.json", plan)
        applied = request("POST", "/api/v1/creation/vless/apply", {"document": document, "digest": plan["digest"], "revision": plan["revision"]})
        save("apply-response.json", applied)
        inbound_id = applied["inbound_id"]
        identities = {user: applied["bindings"][i]["binding_id"] for i, user in enumerate(["Alice", "Bob"])}
        source.unlink()
        running, nodes = {}, {}
        print("START exported Xray client traffic: Alice/Bob", flush=True)
        for user in ["Alice", "Bob"]:
            node = export(identities[user]); nodes[user] = node
            process, proxy = client(node, "xray-" + user)
            running[user] = process, proxy
            helper.tcp_payload(proxy, target.server_address, 32768)
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                assert sum(pool.map(lambda _: helper.tcp_payload(proxy, target.server_address), range(16))) == 16 * 32768
            assert helper.tcp_payload(proxy, target.server_address, 4 * 1024 * 1024) == 4 * 1024 * 1024
            helper.tcp_payload(proxy, target.server_address, 1024)
            aborted, _ = helper.socks(proxy, target.server_address); aborted.close()
            matrix.append({"client": "xray", "version": version, "sha256": digest, "feature": "finalmask/sudoku", "reality": "UNSUPPORTED", "security": "none", "user": user, "tcp": "PASS", "udp": "NOT QUALIFIED", "concurrency": 16, "large_bytes": 4194304, "reconnect": "PASS", "abnormal_close": "PASS", "result": "PASS"})
        assert nodes["Alice"]["streamSettings"]["finalmask"] == nodes["Bob"]["streamSettings"]["finalmask"]
        print("START negative client and credential cases", flush=True)
        for user in identities:
            for target_format, target_version in [("mihomo", "1.19.30"), ("sing-box", "1.14.1"), ("surge", "6.7.0"), ("uri", ""), ("xray", "unknown")]:
                problem = request("POST", "/api/v1/inbounds/" + inbound_id + "/export", {"format": target_format, "client_version": target_version, "binding_id": identities[user]}, 422)
                assert problem["code"] == "unsupported_export"
                negative.append({"case": "unsupported-client", "client": target_format, "user": user, "result": "PASS"})
        for case in ["missing-mask", "wrong-password", "wrong-uuid", "unknown-mask-runtime"]:
            bad = copy.deepcopy(nodes["Alice"])
            if case == "missing-mask": bad["streamSettings"].pop("finalmask")
            elif case == "wrong-password": bad["streamSettings"]["finalmask"]["tcp"][0]["settings"]["password"] = secrets.token_hex(16)
            elif case == "wrong-uuid": bad["settings"]["vnext"][0]["users"][0]["id"] = str(uuid.uuid4())
            else: bad["streamSettings"]["finalmask"]["tcp"][0]["type"] = "unknown"
            if case == "unknown-mask-runtime": assert client(bad, case, check_only=True) != 0
            else:
                process, proxy = client(bad, case)
                try: denied(proxy)
                finally: helper.stop(process)
            negative.append({"case": case, "result": "PASS", "meaning": "config rejected or no authenticated payload"})
        toggle(identities["Alice"], False)
        print("START binding reconcile and SQLite restart", flush=True)
        denied(running["Alice"][1]); helper.tcp_payload(running["Bob"][1], target.server_address)
        revision = request("GET", "/api/v1/inbounds")["snapshot_revision"]
        old, artifact = artifact_check()
        helper.stop(daemon)
        assert not artifact.exists()
        daemon = start_server()
        regenerated, _ = artifact_check()
        assert regenerated["generation"] != old["generation"]
        assert request("GET", "/api/v1/inbounds")["snapshot_revision"] == revision
        denied(running["Alice"][1]); helper.tcp_payload(running["Bob"][1], target.server_address)
        toggle(identities["Alice"], True)
        for process, proxy in running.values(): helper.tcp_payload(proxy, target.server_address)
        # The live child PID is checked against this campaign's artifact before signaling.
        crashed, artifact = artifact_check()
        print("START owned child crash and manual recovery", flush=True)
        assert Path(f"/proc/{crashed['pid']}/exe").resolve() == xray
        revision = request("GET", "/api/v1/inbounds")["snapshot_revision"]
        os.kill(crashed["pid"], 9)
        deadline = time.monotonic() + 5
        while view()["health"] != "degraded":
            assert time.monotonic() < deadline, "owned child crash was not observed"
        assert request("GET", "/api/v1/system")["health"] == "degraded"
        assert request("GET", "/api/v1/inbounds")["snapshot_revision"] == revision
        helper.stop(daemon); daemon = start_server()
        artifact_check()
        for process, proxy in running.values(): helper.tcp_payload(proxy, target.server_address)
        for filename, path in [("system-response.json", "/api/v1/system"), ("http-system-response.json", "/api/v1/system"), ("capabilities-response.json", "/api/v1/capabilities"), ("inbounds-response.json", "/api/v1/inbounds"), ("inbound-response.json", "/api/v1/inbounds/" + inbound_id)]: save(filename, request("GET", path))
        print("START live API/CLI and secret boundary checks", flush=True)
        for command in ["status", "capabilities", "doctor"]:
            value = subprocess.check_output([exe, command, "--config", str(bootstrap)], stderr=subprocess.DEVNULL)
            assert not any(secret in value.decode() for secret in secret_values)
            save(command + "-cli-response.json", json.loads(value))
        cap = request("GET", "/api/v1/capabilities")
        plain = next(p for p in cap["items"] if p["protocol"] == "vless" and p["feature_profile"] == "plain")
        for engine in plain["engine_implementations"]:
            for feature in engine["features"]["engine_features"]:
                assert feature["supported"] == (engine["engine"] == "xray")
                assert not feature["udp_qualified"] and feature["security"] == "none"
        for engine in request("GET", "/api/v1/system")["engines"]:
            if engine["engine"] == "xray": assert all(f["available"] for f in engine["features"])
        stats = view()["stats"]
        assert all(int(value) == 0 for value in stats.values()), "invented Xray attributed stats"
        save("export-envelopes-response.json", envelopes)
        for child, proxy in running.values(): helper.stop(child)
        helper.stop(daemon)
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
        for log in logs: log.flush()
        for path in work.glob("*.log"):
            content = path.read_text(errors="replace")
            assert "data race" not in content.lower() and "panic" not in content.lower()
            assert not any(secret in content for secret in secret_values), "diagnostic secret leak"
        for path in state.glob("*.db*"): assert not any(secret.encode() in path.read_bytes() for secret in secret_values)
        save("interop-results.json", {"result": "PASS", "scope": "MANAGED SPLICORE FEATURE ACCEPTANCE", "matrix": matrix, "negative": negative,
            "server_sha256": hashlib.sha256(Path(exe).read_bytes()).hexdigest(), "payload_retry": False,
            "multi_user_shared_transport_secret": "PASS", "canonical_validate_plan_apply": "PASS", "capability_composition": "PASS",
            "binding_reconcile": "PASS", "sqlite_recovery": "PASS", "ephemeral_regeneration": "PASS", "child_crash_manual_recovery": "PASS",
            "secret_boundary": "PASS", "unsupported_client": "PASS", "listener_release": "PASS", "udp": "NOT QUALIFIED", "reality": "UNSUPPORTED"})
        print("MANAGED SPLICORE FINALMASK/SUDOKU INTEROP PASS", flush=True)
    finally:
        for child in reversed(children): helper.stop(child)
        for log in logs: log.close()
        target.shutdown(); target.server_close(); thread.join(timeout=5)
        assert private.resolve().parent == work.resolve()
        shutil.rmtree(private)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        import traceback
        frame = traceback.extract_tb(error.__traceback__)[-1]
        print("SUDOKU INTEROP FAILED: " + type(error).__name__ + " at " + Path(frame.filename).name + ":" + str(frame.lineno), file=sys.stderr)
        raise SystemExit(1) from None
