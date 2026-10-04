"""Validate owned Markdown/OpenAPI and optional live runtime response fixtures.

Requires markdown-it-py==3.0.0 and openapi-spec-validator==0.7.2.
Inventory is JSON with an `owned` list generated from Git (see Foundation workflow).
"""

import argparse
import collections
import json
import pathlib
import re
import subprocess
import unicodedata
import urllib.parse

from jsonschema import Draft202012Validator, FormatChecker
from markdown_it import MarkdownIt
from openapi_spec_validator import validate


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("inventory", type=pathlib.Path)
    parser.add_argument("--responses", type=pathlib.Path)
    parser.add_argument("--protocol", choices=["snell","hysteria2","tuic","vless","mieru"],default="hysteria2")
    args = parser.parse_args()
    root = args.root.resolve()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8-sig"))
    markdown = MarkdownIt("commonmark").enable("table")
    documents, anchors = {}, {}

    def historical(name):
        return name.startswith("docs/reports/") or name.startswith("docs/PHASE_") or name.startswith("docs/development/PHASE_") or (name.startswith("docs/adr/") and re.match(r"docs/adr/00(?:[0-2][0-9]|3[0-4])-", name))

    def frozen_source(name):
        result = subprocess.run(["git", "--no-optional-locks", "show", "HEAD:" + name], cwd=root, capture_output=True)
        assert result.returncode == 0, ("historical reference absent from frozen HEAD", name)
        return result.stdout.decode("utf-8-sig")

    def slug(text):
        text = re.sub(r"<[^>]*>", "", text).strip().lower()
        text = "".join(c for c in text if c in "-_ " or unicodedata.category(c)[0] in "LN")
        return text.replace(" ", "-")

    def parse_document(name):
        text = (root / name).read_text(encoding="utf-8-sig")
        tokens = markdown.parse(text)
        known, repeats = set(), collections.Counter()
        for i, token in enumerate(tokens):
            if token.type == "heading_open":
                plain = "".join(c.content for c in tokens[i + 1].children or [] if c.type in {"text", "code_inline"})
                base = slug(plain)
                known.add(base + ("-" + str(repeats[base]) if repeats[base] else ""))
                repeats[base] += 1
        known.update(re.findall(r"<(?:a|span)\s+(?:id|name)=[\"']([^\"']+)", text))
        anchors[name] = known
        return text, tokens

    for name in inventory["owned"]:
        if not name.endswith(".md"):
            continue
        text, tokens = parse_document(name)
        assert text.strip() and tokens and tokens[0].type == "heading_open", name
        for field in ["Documentation status", "Audience", "Last reviewed", "Owner", "Responsibility", "Lifecycle"]:
            values = re.findall(r"^(?:- )?" + re.escape(field) + r": (.+)$", text, re.M)
            assert len(values) == 1 and values[0].strip(), (name, field)
        documents[name] = (text, tokens)

    graph, links = collections.defaultdict(set), 0
    for name, (text, tokens) in documents.items():
        for token in tokens:
            for child in token.children or []:
                if child.type not in {"link_open", "image"}:
                    continue
                href = child.attrGet("href" if child.type == "link_open" else "src")
                parsed = urllib.parse.urlsplit(href)
                if parsed.scheme or parsed.netloc:
                    continue
                path = urllib.parse.unquote(parsed.path)
                target = ((root / name).parent / path if path else root / name).resolve()
                assert target.is_relative_to(root), (name, href)
                target_name = target.relative_to(root).as_posix()
                if not target.exists():
                    assert historical(name), (name, href)
                    frozen_source(target_name)
                if parsed.fragment:
                    if target_name not in anchors and target.suffix == ".md":
                        parse_document(target_name)
                    fragment = urllib.parse.unquote(parsed.fragment)
                    if fragment not in anchors.get(target_name, set()):
                        assert historical(name), (name, href)
                        archived = frozen_source(target_name)
                        assert fragment in {slug(h) for h in re.findall(r"^#{1,6} (.+)$", archived, re.M)}, (name, href)
                graph[name].add(target_name)
                links += 1
        for source in re.findall(r"`([A-Za-z0-9_./-]+\.go)`", text):
            if not (root / source).is_file() and not re.search(r"https://github.com/[^)\s]+/" + re.escape(source), text):
                assert historical(name), (name, source)
                frozen_source(source)
    reached, stack = set(), ["README.md"]
    while stack:
        name = stack.pop()
        if name not in reached:
            reached.add(name)
            stack.extend(graph[name] - reached)
    assert set(documents) <= reached, set(documents) - reached

    spec = json.loads((root / "docs/api/openapi-skeleton.yaml").read_text(encoding="utf-8-sig"))
    validate(spec)
    operations, implemented = [], []

    def refs(value):
        if isinstance(value, dict):
            if "$ref" in value:
                assert value["$ref"].startswith("#/")
                node = spec
                for key in value["$ref"][2:].split("/"):
                    node = node[key.replace("~1", "/").replace("~0", "~")]
            for child in value.values():
                refs(child)
        elif isinstance(value, list):
            for child in value:
                refs(child)

    refs(spec)
    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            if method in {"get", "post", "put", "patch", "delete"}:
                operations.append(operation["operationId"])
                assert operation["x-implementation-status"] in {"foundation", "phase2", "phase3", "phase4", "phase5", "phase10", "phase12", "phase13", "phase14", "deferred"}
                if operation["x-implementation-status"] in {"foundation", "phase2", "phase3", "phase4", "phase5", "phase10", "phase12", "phase13", "phase14"}:
                    implemented.append((method, path))
    assert len(operations) == len(set(operations))
    client_operations = [(method, "/api/v1/" + collection + suffix)
        for collection in ["nodes", "outbounds", "local-inbounds"]
        for suffix, methods in [("", ["get", "post"]), ("/{id}", ["get", "put", "delete"])]
        for method in methods]
    client_operations += [("post", "/api/v1/nodes/{id}/credential"),
        ("get", "/api/v1/client/route"), ("put", "/api/v1/client/route"),
        ("get", "/api/v1/client/runtime")]
    client_operations += [("post", "/api/v1/client/runtime/" + action) for action in ["start", "stop", "restart"]]
    client_operations += [("post", "/api/v1/client/" + action) for action in ["validate", "plan", "apply"]]
    client_operations += [(method, "/api/v1/"+collection+suffix)
        for collection in ["route-rules","rule-sets","policy-groups","dns/servers","dns/rules"]
        for suffix, methods in [("",["get","post"]),("/{id}",["get","put","delete"])]
        for method in methods]
    client_operations += [(method,path) for path,methods in {
        "/api/v1/routes":["get","put"],"/api/v1/routes/explain":["post"],
        "/api/v1/policy-groups/status":["get"],"/api/v1/policy-groups/{id}/select":["post"],
        "/api/v1/dns/profile":["get","put"],"/api/v1/dns/lookup":["post"],
        "/api/v1/dns/cache/status":["get"],"/api/v1/dns/cache/flush":["post"]}.items() for method in methods]
    client_operations += [("get","/api/v1/client/host-integration"),("put","/api/v1/client/host-integration"),("get","/api/v1/client/host-network"),("post","/api/v1/client/host-network/repair")]
    client_operations += [(method,"/api/v1/"+collection+suffix)
        for collection in ["providers","rule-set-providers"]
        for suffix,methods in [("",["get","post"]),("/{id}",["get","put","delete"]),("/{id}/refresh",["post"]),("/{id}/refresh-preview",["post"])]
        for method in methods]
    client_operations += [("post","/api/v1/"+path) for path in ["imports/preview","imports/apply","nodes/import-preview","nodes/batch-preview","nodes/export"]]
    assert sorted(implemented) == sorted(client_operations + [
        ("get", "/api/v1/capabilities"), ("get", "/api/v1/system"),
        ("get", "/api/v1/inbounds"), ("get", "/api/v1/inbounds/{id}"),
        ("post", "/api/v1/snell/validate"), ("post", "/api/v1/snell/plan"),
        ("post", "/api/v1/snell/apply"), ("post", "/api/v1/inbounds/{id}/export"),
        ("post", "/api/v1/inbounds/{id}/display"),
        ("post", "/api/v1/hysteria2/validate"), ("post", "/api/v1/hysteria2/plan"),
        ("post", "/api/v1/hysteria2/apply"), ("post", "/api/v1/inbounds/{id}/binding")] + [("post", "/api/v1/"+prefix+"/"+action) for prefix in ["tuic","creation/{protocol}"] for action in ["validate","plan","apply"]])
    assert spec["paths"]["/api/v1/inbounds/{id}/export"]["post"]["x-secret-returning"] is True
    assert not {"password", "psk", "token", "uuid", "secret_data"} & set(spec["components"]["schemas"]["Account"]["properties"])
    assert not {"password", "psk", "token", "value", "secret_data"} & set(spec["components"]["schemas"]["RemoteNode"]["properties"])
    assert spec["components"]["schemas"]["ClientCredentialInput"]["properties"]["value"]["writeOnly"] is True
    assert spec["components"]["schemas"]["ProviderSource"]["writeOnly"] is True
    assert spec["components"]["schemas"]["ProviderAuth"]["properties"]["value"]["writeOnly"] is True
    if args.responses:
        pairs=[("system-response.json","System"),("http-system-response.json","System"),("capabilities-response.json","CapabilityPage"),("inbounds-response.json","RuntimeInboundPage"),("inbound-response.json","RuntimeInboundView")]
        client_pairs = [("client-runtime-response.json", "ClientRuntimeStatus"),
            ("client-node-response.json", "RemoteNode"), ("client-outbound-response.json", "ClientOutbound"),
            ("client-local-response.json", "LocalInbound"), ("client-route-response.json", "ClientRoute"),
            ("client-plan-response.json", "ClientPlan"), ("client-apply-response.json", "ClientResult")]
        if (args.responses / "client-runtime-response.json").exists():
            pairs.extend(client_pairs)
            if "HostNetworkStatus" in spec["components"]["schemas"]:
                pairs.extend([("host-integration-response.json", "HostIntegration"),
                              ("host-network-response.json", "HostNetworkStatus")])
        if (args.responses / "tun-local-response.json").exists():
            pairs.extend([("tun-local-response.json", "LocalInbound"),
                          ("tun-runtime-response.json", "ClientRuntimeStatus"),
                          ("active-host-network-response.json", "HostNetworkStatus")])
        if args.protocol!="snell":
            prefix=args.protocol;schema={"tuic":"TUIC","hysteria2":"Hysteria2","vless":"VLESS","mieru":"Mieru"}[prefix]
            pairs.extend([(("plan-response.json" if prefix=="vless" else prefix+"-plan-response.json"),schema+"Plan"),(("apply-response.json" if prefix=="vless" else prefix+"-apply-response.json"),schema+"Applied"),("binding-transaction-response.json","RuntimeTransaction")])
        for filename,schema in pairs:
            instance = json.loads((args.responses / filename).read_text(encoding="utf-8-sig"))
            document = {"$ref": "#/components/schemas/" + schema, "components": spec["components"]}
            Draft202012Validator(document, format_checker=FormatChecker()).validate(instance)
        for filename in ["providers-response.json", "ruleset-providers-response.json"]:
            if (args.responses / filename).exists():
                document = {"type":"array","items":{"$ref":"#/components/schemas/Provider"},"components":spec["components"]}
                Draft202012Validator(document, format_checker=FormatChecker()).validate(json.loads((args.responses / filename).read_text(encoding="utf-8-sig")))
        if (args.responses / "management-preview-response.json").exists():
            document = {"$ref":"#/components/schemas/ManagementPreview","components":spec["components"]}
            Draft202012Validator(document, format_checker=FormatChecker()).validate(json.loads((args.responses / "management-preview-response.json").read_text(encoding="utf-8-sig")))
        # Safe envelopes replace content before archival; the harness checks live secrets.
        envelopes = args.responses / "export-envelopes-response.json"
        document = {"$ref": "#/components/schemas/ClientExportResult", "components": spec["components"]}
        instances = json.loads(envelopes.read_text(encoding="utf-8-sig")) if envelopes.exists() else []
        assert instances or args.protocol=="snell", "missing live export envelopes"
        for instance in instances:
            Draft202012Validator(document, format_checker=FormatChecker()).validate(instance)
    result = {"result": "PASS", "markdown_documents": len(documents), "local_links": links, "operations": len(operations), "implemented_reads": implemented, "live_responses_checked": bool(args.responses)}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
