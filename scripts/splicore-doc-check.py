"""Validate owned Markdown/OpenAPI and optional live runtime response fixtures.

Requires markdown-it-py==3.0.0 and openapi-spec-validator==0.7.2.
Inventory is JSON with an `owned` list generated from Git (see Foundation workflow).
"""

import argparse
import collections
import json
import pathlib
import re
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
    args = parser.parse_args()
    root = args.root.resolve()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8-sig"))
    markdown = MarkdownIt("commonmark").enable("table")
    documents, anchors = {}, {}

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
                assert target.is_relative_to(root) and target.exists(), (name, href)
                target_name = target.relative_to(root).as_posix()
                if parsed.fragment:
                    if target_name not in anchors and target.suffix == ".md":
                        parse_document(target_name)
                    assert urllib.parse.unquote(parsed.fragment) in anchors.get(target_name, set()), (name, href)
                graph[name].add(target_name)
                links += 1
        for source in re.findall(r"`([A-Za-z0-9_./-]+\.go)`", text):
            assert (root / source).is_file() or re.search(r"https://github.com/[^)\s]+/" + re.escape(source), text), (name, source)
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
                assert operation["x-implementation-status"] in {"foundation", "phase2", "phase3", "deferred"}
                if operation["x-implementation-status"] in {"foundation", "phase2", "phase3"}:
                    implemented.append((method, path))
    assert len(operations) == len(set(operations))
    assert sorted(implemented) == sorted([
        ("get", "/api/v1/capabilities"), ("get", "/api/v1/system"),
        ("get", "/api/v1/inbounds"), ("get", "/api/v1/inbounds/{id}"),
        ("post", "/api/v1/snell/validate"), ("post", "/api/v1/snell/plan"),
        ("post", "/api/v1/snell/apply"), ("post", "/api/v1/inbounds/{id}/export"),
        ("post", "/api/v1/inbounds/{id}/display"),
        ("post", "/api/v1/hysteria2/validate"), ("post", "/api/v1/hysteria2/plan"),
        ("post", "/api/v1/hysteria2/apply"), ("post", "/api/v1/inbounds/{id}/binding")])
    assert spec["paths"]["/api/v1/inbounds/{id}/export"]["post"]["x-secret-returning"] is True
    assert not {"password", "psk", "token", "uuid", "secret_data"} & set(spec["components"]["schemas"]["Account"]["properties"])
    if args.responses:
        for filename, schema in [("system-response.json", "System"), ("http-system-response.json", "System"), ("capabilities-response.json", "CapabilityPage"), ("inbounds-response.json", "RuntimeInboundPage"), ("inbound-response.json", "RuntimeInboundView"), ("hysteria2-plan-response.json", "Hysteria2Plan"), ("hysteria2-apply-response.json", "Hysteria2Applied"), ("binding-transaction-response.json", "RuntimeTransaction")]:
            instance = json.loads((args.responses / filename).read_text(encoding="utf-8-sig"))
            document = {"$ref": "#/components/schemas/" + schema, "components": spec["components"]}
            Draft202012Validator(document, format_checker=FormatChecker()).validate(instance)
        # Safe envelopes replace content before archival; the harness checks live secrets.
        envelopes = args.responses / "export-envelopes-response.json"
        document = {"$ref": "#/components/schemas/ClientExportResult", "components": spec["components"]}
        instances = json.loads(envelopes.read_text(encoding="utf-8-sig"))
        assert instances, "missing live export envelopes"
        for instance in instances:
            Draft202012Validator(document, format_checker=FormatChecker()).validate(instance)
    result = {"result": "PASS", "markdown_documents": len(documents), "local_links": links, "operations": len(operations), "implemented_reads": implemented, "live_responses_checked": bool(args.responses)}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
