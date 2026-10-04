"""Deterministic development artifacts; output must be outside the checkout.

Requires Go and Git, uses the existing local module cache. Never stages source,
downloads engine artifacts, signs, publishes or follows a latest release.
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import tarfile

REPO = pathlib.Path(__file__).resolve().parent.parent
TAGS = "with_quic,with_utls,with_gvisor"
VP = "github.com/sagernet/sing-box/internal/splicore/version"
XRAY = {"version": "26.3.27", "strategy": "separate-pinned-artifact", "sha256": {
    "linux/amd64": "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed",
    "windows/amd64": "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1"}}

def run(*args, env=None):
    if args and args[0] == "git":
        args = ("git", "--no-optional-locks", *args[1:])
    return subprocess.check_output(args, cwd=REPO, env=env).decode().strip()

def source_snapshot():
    names = sorted(set(run("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0")) - {""})
    result = {}
    for name in names:
        p = REPO / name
        if p.is_symlink():
            result[name] = hashlib.sha256(os.readlink(p).encode()).hexdigest()
        elif p.is_file():
            result[name] = hashlib.sha256(p.read_bytes()).hexdigest()
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    return result, hashlib.sha256(encoded).hexdigest()

def archive(path, entries, epoch):
    with path.open("xb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=epoch, compresslevel=9) as gz, tarfile.open(mode="w", fileobj=gz, format=tarfile.USTAR_FORMAT) as tar:
        for name, (data, mode) in sorted(entries.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mode, item.mtime = len(data), mode, epoch
            item.uid = item.gid = 0
            item.uname = item.gname = ""
            tar.addfile(item, io.BytesIO(data))

def licenses(env):
    template = "{{with .Module}}{{if .Replace}}{{.Replace.Path}}|{{.Replace.Version}}|{{.Replace.Dir}}{{else}}{{.Path}}|{{.Version}}|{{.Dir}}{{end}}{{end}}"
    rows = sorted(set(run("go", "list", "-deps", "-tags", TAGS, "-f", template, "./cmd/splicore", env=env).splitlines()) - {""})
    files, inventory = {}, []
    for row in rows:
        module, version, directory = row.split("|", 2)
        if pathlib.Path(directory).resolve() == REPO:
            continue
        base = pathlib.Path(directory)
        candidates = sorted(p for p in base.iterdir() if p.is_file() and re.match(r"(?i)^(LICENSE|COPYING|NOTICE|COPYRIGHT)(?:[._-].*)?$", p.name))
        if not candidates:
            raise RuntimeError("Linked dependency has no license/notice: " + module)
        prefix = "licenses/" + hashlib.sha256((module + "@" + version).encode()).hexdigest()[:16]
        paths = []
        for p in candidates:
            name = prefix + "/" + p.name
            if not re.fullmatch(r"[A-Za-z0-9._/-]+", name) or ".." in name:
                raise RuntimeError("Unsupported license filename: " + name)
            files[name] = (p.read_bytes(), 0o644)
            paths.append(name)
        inventory.append({"module": module, "version": version, "licenses": paths})
    # Go runtime is linked too.
    goroot = pathlib.Path(run("go", "env", "GOROOT", env=env))
    files["licenses/go/LICENSE"] = ((goroot / "LICENSE").read_bytes(), 0o644)
    return files, inventory

def package_document(data, included):
    # Minimal package docs keep links to included files; source-only links are
    # described as source references, not broken links inside the tarball.
    text = data.decode("utf-8")
    def link(match):
        label, target = match.groups()
        if "://" in target or target in included or target == "LICENSE":
            return match.group(0)
        if target == "../distribution/splicore.yaml":
            return "[" + label + "](../splicore.yaml)"
        return label + " (source checkout: `" + target + "`)"
    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, text).encode("utf-8")

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=pathlib.Path, required=True)
    p.add_argument("--version", default="0.0.0-dev")
    p.add_argument("--epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    p.add_argument("--platform", action="append", choices=["linux/amd64", "linux/arm64", "windows/amd64"])
    a = p.parse_args()
    output = a.output.resolve()
    if output.is_relative_to(REPO) or a.epoch <= 0 or not re.fullmatch(r"0\.0\.0-dev(?:[.+-][A-Za-z0-9.-]+)?", a.version):
        p.error("external output, explicit SOURCE_DATE_EPOCH/--epoch and development version required")
    output.mkdir(parents=True, exist_ok=True)
    snapshot, digest = source_snapshot()
    sha = run("git", "rev-parse", "HEAD")
    dirty = bool(run("git", "status", "--porcelain"))
    build_time = datetime.datetime.fromtimestamp(a.epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    toolchain = run("go", "version").split()[2]
    ld = " ".join(f"-X {VP}.{k}={v}" for k, v in {"ProductVersion": a.version, "Commit": sha, "Dirty": str(dirty).lower(), "BuildTime": build_time, "SourceDigest": digest, "BuildTags": TAGS}.items())
    results = []
    schema_source = (REPO / "internal/splicore/version/version.go").read_text()
    schemas = {key: int(re.search(r"\b" + name + r"\s*=\s*(\d+)", schema_source).group(1)) for key, name in {"config_schema":"ConfigSchema", "db_schema":"DatabaseSchema", "protocol_abi":"ProtocolABI"}.items()}
    for platform in a.platform or ["linux/amd64", "linux/arm64", "windows/amd64"]:
        goos, goarch = platform.split("/")
        env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0", GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local")
        name = f"splicore-{a.version}-{goos}-{goarch}"
        binary = output / (name + (".exe" if goos == "windows" else ".bin"))
        if binary.exists():
            raise RuntimeError("Refusing to overwrite build artifact")
        subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", TAGS, "-ldflags", ld, "-o", str(binary), "./cmd/splicore"], cwd=REPO, env=env, check=True)
        if goos == "windows":
            results.append({"platform": platform, "file": binary.name, "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "qualification": "build-only"})
            continue
        entries, inventory = licenses(env)
        for dst, src in {"splicore": binary, "splicore.service": REPO/"distribution/splicore.service", "splicore-tun.conf": REPO/"distribution/splicore-tun.conf", "splicore.yaml": REPO/"distribution/splicore.yaml", "install.sh": REPO/"scripts/install.sh", "LICENSE": REPO/"LICENSE", "NOTICE.md": REPO/"NOTICE.md"}.items():
            entries[dst] = (src.read_bytes(), 0o755 if dst in ("splicore", "install.sh") else 0o644)
        for doc in ("INSTALLATION", "UPGRADE", "UNINSTALL", "OPERATIONS", "SUPPORT_BUNDLE", "DISTRIBUTION"):
            included = {name+".md" for name in ("INSTALLATION", "UPGRADE", "UNINSTALL", "OPERATIONS", "SUPPORT_BUNDLE", "DISTRIBUTION")}
            entries[f"docs/{doc}.md"] = (package_document((REPO/f"docs/{doc}.md").read_bytes(), included), 0o644)
        entries["NOTICE.md"] = (package_document(entries["NOTICE.md"][0], {"LICENSE"}), 0o644)
        entries["docs/DEPENDENCY_LICENSES.md"] = (("# Linked dependency licenses\n\nGenerated from the actual target's Go dependency graph.\n\n" + "\n".join(f"- `{x['module']}@{x['version']}`: " + ", ".join(x["licenses"]) for x in inventory) + "\n").encode(), 0o644)
        manifest = {"schema": 1, "product": "Splicore", "version": a.version, "channel": "development", "qualification": "experimental", "git_commit": sha, "source_dirty": dirty, "source_sha256": digest, "build_time": build_time, "go_version": toolchain, "goos": goos, "goarch": goarch, "build_tags": TAGS, "config_schema": schemas["config_schema"], "db_schema": schemas["db_schema"], "db_schema_min": 1, "protocol_abi": schemas["protocol_abi"], "api_version": "v1", "upstream_tag": "v1.14.1", "upstream_commit": "1ac1a339cb1223e9c70eae14c44411c75033c02d", "optional_xray": XRAY, "files": {k: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "mode": mode} for k, (data, mode) in sorted(entries.items())}}
        manifest.update(schemas)
        entries["manifest.json"] = ((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(), 0o644)
        entries["SHA256SUMS"] = (("".join(hashlib.sha256(data).hexdigest() + "  " + n + "\n" for n, (data, _) in sorted(entries.items()))).encode(), 0o644)
        tarpath = output / (name + ".tar.gz")
        archive(tarpath, entries, a.epoch)
        results.append({"platform": platform, "file": tarpath.name, "sha256": hashlib.sha256(tarpath.read_bytes()).hexdigest(), "qualification": "experimental", "archive_manifest": "manifest.json"})
    if source_snapshot() != (snapshot, digest):
        raise RuntimeError("Source changed during build")
    source_entries = {}
    for name in snapshot:
        file = REPO/name
        if file.is_symlink():
            raise RuntimeError("Source archive requires an explicit symlink policy")
        source_entries[name] = (file.read_bytes(), 0o755 if name.startswith("scripts/") and name.endswith(".sh") else 0o644)
    source_entries["SOURCE_PROVENANCE.json"] = ((json.dumps({"git_commit":sha,"source_dirty":dirty,"source_sha256":digest,"files":snapshot},sort_keys=True,indent=2)+"\n").encode(),0o644)
    source_file = output/f"splicore-{a.version}-source.tar.gz"
    archive(source_file, source_entries, a.epoch)
    metadata = {"schema": 1, "product": "Splicore", "version": a.version, "channel": "development", "qualification": "experimental", "git_commit": sha, "source_sha256": digest, "source_dirty": dirty, "build_time": build_time, "go_version": toolchain, "config_schema": schemas["config_schema"], "db_schema": schemas["db_schema"], "protocol_abi": schemas["protocol_abi"], "api_version": "v1", "artifacts": results, "optional_xray": XRAY, "source_changed_by_build": False, "publication": "local-only", "url_policy": "exact-version-sha256-platform; no Latest"}
    metadata.update(schemas)
    metadata["source"]={"file":source_file.name,"sha256":hashlib.sha256(source_file.read_bytes()).hexdigest(),"dependency_sources":"Exact go.mod/go.sum versions; no dependency source edits. Provision the recorded Go module cache to rebuild offline."}
    (output/"update.json").write_text(json.dumps(metadata, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps(metadata))

if __name__ == "__main__":
    main()
