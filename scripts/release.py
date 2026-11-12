#!/usr/bin/env python3
"""Build, qualify and verify official archives using only Python/Go/Git.

Publishing is deliberately owned by the tag-only workflow, not this script.
"""
import argparse
import collections
import datetime
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import runpy
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TAGS = "with_quic,with_utls,with_gvisor"
TARGETS = ("linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64")
VP = "github.com/ike-sh/Splicore/internal/splicore/version"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(args, **kwargs):
    return subprocess.check_output(args, cwd=ROOT, text=True, **kwargs).strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    return (bool(name) and not PurePosixPath(name).is_absolute()
            and all(part not in ("", ".", "..") for part in name.split("/"))
            and not any(char in name for char in "\\:\x00\r\n"))


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def identity():
    import runpy
    # Source presence complements the native regression/interop release gates.
    runpy.run_path(str(ROOT / 'scripts/dev/check-features.py'))['check'](ROOT, verbose=False)
    version = (ROOT / "distribution/RELEASE_VERSION").read_text().strip()
    require(re.fullmatch(r"v0\.[1-9][0-9]*\.[0-9]+", version), "invalid pre-1.0 release version")
    require(not command(["git", "status", "--porcelain"]), "release source must be clean")
    commit = command(["git", "rev-parse", "HEAD"])
    epoch = int(command(["git", "show", "-s", "--format=%ct", "HEAD"]))
    return dict(version=version, commit=commit, tree=command(["git", "rev-parse", "HEAD^{tree}"]),
                epoch=epoch, build_time=datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                build_tags=TAGS, cgo_enabled=0)


def native_target():
    system = {"Linux": "linux", "Windows": "windows"}.get(platform.system())
    arch = {"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64", "ARM64": "arm64"}.get(platform.machine())
    return f"{system}-{arch}"


def goenv(target, cgo="0"):
    system, arch = target.split("-")
    env = os.environ.copy()
    env.update(GOENV="off", GOTOOLCHAIN="local", GOTELEMETRY="off", GOFLAGS="-mod=readonly",
               GOOS=system, GOARCH=arch, CGO_ENABLED=cgo)
    for key in ("NOTIFY_SOCKET", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "WATCHDOG_PID", "WATCHDOG_USEC"):
        env.pop(key, None)
    return env


def flags(meta):
    return " ".join(f"-X={VP}.{key}={value}" for key, value in {
        "ProductVersion": meta["version"], "Commit": meta["commit"], "Dirty": "false",
        "BuildTime": meta["build_time"], "BuildTags": TAGS}.items())


def binary_format(data, target):
    system, arch = target.split("-")
    if system == "linux":
        require(data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64")
        require(struct.unpack_from("<H", data, 18)[0] == {"amd64": 62, "arm64": 183}[arch], "ELF architecture mismatch")
        offset = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        types = [struct.unpack_from("<I", data, offset + n * size)[0] for n in range(count)]
        require(2 not in types and 3 not in types, "ELF has dynamic section/interpreter")
        return dict(format="ELF64", architecture=arch, interpreter=False, dynamic_section=False)
    require(data[:2] == b"MZ", "expected Windows PE")
    off = struct.unpack_from("<I", data, 0x3c)[0]
    require(data[off:off + 4] == b"PE\0\0", "invalid PE signature")
    coff = off + 4
    machine, count = struct.unpack_from("<HH", data, coff)
    require(machine == {"amd64": 0x8664, "arm64": 0xaa64}[arch], "PE architecture mismatch")
    optsize = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    require(struct.unpack_from("<H", data, opt)[0] == 0x20b, "expected PE32+")
    rva = struct.unpack_from("<I", data, opt + 112 + 8)[0]
    sections = [struct.unpack_from("<IIII", data, opt + optsize + i * 40 + 8) for i in range(count)]

    def at(value):
        for virtual_size, address, raw_size, pointer in sections:
            if address <= value < address + max(virtual_size, raw_size):
                return pointer + value - address
        raise RuntimeError("invalid PE RVA")

    imports = []
    if rva:
        pos = at(rva)
        while any(data[pos:pos + 20]):
            name = at(struct.unpack_from("<I", data, pos + 12)[0])
            imports.append(data[name:data.index(b"\0", name)].decode().lower())
            pos += 20
    require(set(imports) <= {"kernel32.dll"}, "unexpected PE static DLL import")
    return dict(format="PE32+", architecture=arch, static_imports=imports,
                optional_driver="Windows TUN requires external Wintun; not bundled or qualified")


def native_identity(binary, meta, target):
    value = json.loads(command([str(binary), "version", "--json"]))
    for key in ("version", "commit", "build_time", "build_tags"):
        require(value[key] == meta[key], f"native version mismatch: {key}")
    require(value["cgo_enabled"] == "0" and not value["dirty"] and value["platform"] == target.replace("-", "/"), "native build metadata mismatch")
    require("splicore run" in command([str(binary), "help"]), "offline help missing")
    return value


def build(out, target):
    meta = identity()
    env = goenv(target)
    goversion = command(["go", "env", "GOVERSION"], env=env)
    match = re.fullmatch(r"go(\d+)\.(\d+)\.(\d+)", goversion)
    require(match and tuple(map(int, match.groups())) >= (1, 26, 3), "Go >=1.26.3 required")
    binary = out / target / ("splicore.exe" if target.startswith("windows") else "splicore")
    binary.parent.mkdir(parents=True, exist_ok=True)
    build_tmp = out / target / "build-tmp"
    build_tmp.mkdir(exist_ok=True)
    env["GOTMPDIR"] = str(build_tmp)
    if target.startswith("windows") and os.name == "nt":
        env.update(TEMP=str(build_tmp), TMP=str(build_tmp))
    require(not binary.exists(), "refusing to replace a release build")
    subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-tags=" + TAGS,
                    "-ldflags=" + flags(meta), "-o", str(binary), "./cmd/splicore"], cwd=ROOT, env=env, check=True)
    if target != native_target():
        for tags in ([], ["-tags=" + TAGS]):
            subprocess.run(["go", "build", "-mod=readonly", *tags, "./..."], cwd=ROOT, env=env, check=True)
    info = command(["go", "version", "-m", str(binary)], env=env)
    require("CGO_ENABLED=0" in info and "-tags=" + TAGS in info, "missing build settings")
    require("GOOS=" + target.split("-")[0] in info and "GOARCH=" + target.split("-")[1] in info, "build settings target mismatch")
    if "vcs.revision=" in info:
        require("vcs.revision=" + meta["commit"] in info and "vcs.modified=false" in info, "VCS mismatch")
    data = binary.read_bytes()
    meta.update(target=target, go_version=goversion, binary_sha256=digest(data), bytes=len(data),
                binary_format=binary_format(data, target), automatic_vcs_metadata="vcs.revision=" in info)
    (out / target / "go-build-info.txt").write_text(info + "\n", encoding="utf-8")
    if target == native_target():
        meta["native_version"] = native_identity(binary, meta, target)
    save(out / target / "build.json", meta)
    print(json.dumps(meta), flush=True)


def run_logged(args, env, directory, name):
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    timeout = False
    try:
        result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, timeout=2100)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as failure:
        code, stdout, stderr, timeout = -1, failure.stdout or b"", failure.stderr or b"", True
    (directory / (name + ".stdout")).write_bytes(stdout)
    (directory / (name + ".stderr")).write_bytes(stderr)
    status = dict(command=args, started_at=started, exit_code=code, result="TIMEOUT" if timeout else "PASS" if code == 0 else "FAIL")
    tests, counts = {}, collections.Counter()
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("Test") and event["Action"] in ("pass", "fail", "skip"):
            tests[event["Package"] + "/" + event["Test"]] = event["Action"]
            counts[("subtest_" if "/" in event["Test"] else "parent_") + event["Action"]] += 1
    status.update(test_counts=dict(counts), tests=tests)
    save(directory / (name + ".json"), status)
    print(name, json.dumps({k: v for k, v in status.items() if k != "tests"}), flush=True)
    if code:
        sys.stdout.buffer.write(stdout)
        sys.stderr.buffer.write(stderr)
    require(code == 0, f"{name}: {status['result']}; original stdout/stderr retained")
    return status


def qualify(out, target):
    require(target == native_target(), "qualification must run natively")
    for name in ("SPLICORE_VLESS_ENCRYPTION_REFERENCE", "SPLICORE_XHTTP_H3_REFERENCE", "SPLICORE_PHASE34_WG_REFERENCE", "SPLICORE_PHASE34_XRAY_REFERENCE"):
        require(Path(os.environ.get(name, "")).is_file(), "qualification requires pinned independent peers; use scripts/dev/fetch-restoration-references.py: " + name)
    require(not target.startswith("linux") or os.environ.get("SPLICORE_PRIVATE_NETNS") == "1", "Linux qualification requires scripts/dev/isolated-linux.py")
    meta = json.loads((out / target / "build.json").read_text())
    require(meta["commit"] == identity()["commit"], "qualification source differs from build")
    binary = out / target / ("splicore.exe" if target.startswith("windows") else "splicore")
    require(digest(binary.read_bytes()) == meta["binary_sha256"], "qualification binary changed")
    directory = out / "qualification" / target
    directory.mkdir(parents=True, exist_ok=True)
    env = goenv(target)
    env["SPLICORE_RUNTIME_BINARY"] = str(binary)
    summary = {}
    persistence_evidence = directory / "persistence"
    persistence_evidence.mkdir(exist_ok=True)
    env["SPLICORE_PERSISTENCE_EVIDENCE"] = str(persistence_evidence)
    # Linux needs a private POSIX filesystem. Windows uses a canonical checkout
    # path: hosted TEMP can contain an 8.3 alias rejected by private-file policy.
    temp_parent = None
    if target.startswith("windows"):
        temp_parent = out / "runtime-tmp"
        temp_parent.mkdir(exist_ok=True)
        print("Windows ambient TEMP:", tempfile.gettempdir(), "resolved:", Path(tempfile.gettempdir()).resolve(), flush=True)
    with tempfile.TemporaryDirectory(prefix="sr-", dir=temp_parent) as runtime_tmp:
        if target.startswith("linux"):
            os.chmod(runtime_tmp, 0o700)
            require(Path(runtime_tmp).stat().st_mode & 0o077 == 0, "Linux qualification needs a private POSIX temp directory")
            env.update(TMPDIR=runtime_tmp, GOTMPDIR=runtime_tmp)
        else:
            env.update(TEMP=runtime_tmp, TMP=runtime_tmp, GOTMPDIR=runtime_tmp)
        for profile, tags in (("default", []), ("full", ["-tags=" + TAGS])):
            for action in ("build", "vet", "test"):
                args = ["go", action, "-mod=readonly"]
                if action == "test":
                    args += ["-json", "-count=1", "-timeout=1200s"]
                    if target.startswith("windows"):
                        # Keep unrelated packages' CPU-heavy crypto/mask fixtures
                        # from consuming each other's bounded I/O budgets. Their
                        # internal multi-stream/concurrent-user tests still run.
                        args += ["-p=1"]
                result = run_logged(args + tags + ["./..."], env, directory, profile + "-" + action)
                if action == "test":
                    validator = runpy.run_path(str(ROOT / "scripts/dev/qualification_policy.py"))["validate"]
                    result["behavior_policy"] = validator(ROOT, result, target, profile)
                    save(directory / (profile + "-test.json"), result)
                summary[profile + "-" + action] = result
        if target.startswith("linux"):
            env["CGO_ENABLED"] = "1"
            summary["race"] = run_logged(["go", "test", "-race", "-json", "-count=1", "-timeout=1200s", "-tags=" + TAGS,
                                          "./internal/splicore/...", "./protocol/..."], env, directory, "race")
            summary["race"]["behavior_policy"] = runpy.run_path(str(ROOT / "scripts/dev/qualification_policy.py"))["validate"](ROOT, summary["race"], target, "race")
            save(directory / "race.json", summary["race"])
        else:
            summary["race"] = dict(result="NOT_EXECUTED", reason="Windows race is outside this release qualification; no configured native C toolchain")
    summary["all_native_gates_passed"] = True
    save(out / target / "qualification.json", summary)


def archive_name(version, target):
    return f"splicore-{version}-{target}" + (".zip" if target.startswith("windows") else ".tar.gz")


def write_archive(path, prefix, files, epoch, executable=()):
    require(not path.exists(), "refusing to overwrite an archive")
    if path.suffix == ".zip":
        stamp = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).timetuple()[:6]
        with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(prefix + "/" + name, stamp)
                info.external_attr = ((0o100755 if name in executable else 0o100644) << 16)
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    else:
        with path.open("xb") as file, gzip.GzipFile(filename="", mode="wb", fileobj=file, mtime=epoch) as compressed, tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(prefix + "/" + name)
                info.size, info.mode, info.mtime = len(data), 0o755 if name in executable else 0o644, epoch
                archive.addfile(info, io.BytesIO(data))


def package(out, target):
    meta = json.loads((out / target / "build.json").read_text())
    require(meta["commit"] == identity()["commit"], "package source differs from build")
    native = target.endswith("amd64")
    qualification = json.loads((out / target / "qualification.json").read_text()) if native else {"result": "BUILD_ONLY", "reason": "cross-compiled; native ARM64 not executed"}
    binary_name = "splicore.exe" if target.startswith("windows") else "splicore"
    binary = (out / target / binary_name).read_bytes()
    require(digest(binary) == meta["binary_sha256"], "package binary changed")
    files = {binary_name: binary, "BUILD_INFO.json": (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode()}
    for name in ("LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.md"):
        files[name] = (ROOT / name).read_bytes()
    for file in sorted((ROOT / "licenses").rglob("*")):
        if file.is_file():
            files[file.relative_to(ROOT).as_posix()] = file.read_bytes()
    system = target.split("-")[0]
    files["RUNNING.md"] = (ROOT / f"docs/releases/RUNNING_{system}.md").read_bytes()
    files["examples/splicore.yaml"] = (ROOT / ("distribution/splicore-windows.yaml" if system == "windows" else "distribution/splicore.yaml")).read_bytes()
    files["examples/vless-loopback.json"] = (ROOT / "distribution/vless-loopback.json").read_bytes()
    files["SHA256SUMS"] = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(files.items())).encode()
    transfer = out / "transfer"
    transfer.mkdir(exist_ok=True)
    name = archive_name(meta["version"], target)
    write_archive(transfer / name, name.removesuffix(".tar.gz").removesuffix(".zip"), files, meta["epoch"], [binary_name])
    save(transfer / (target + ".json"), dict(build=meta, qualification=qualification, archive=name,
                                            archive_sha256=digest((transfer / name).read_bytes()),
                                            qualification_status="NATIVE_TESTED" if native else "BUILD_ONLY"))


def source_archive(out, final, meta):
    source = out / "source"
    require(not source.exists(), "source export already exists")
    source.mkdir()
    tracked = command(["git", "ls-files"]).splitlines()
    require(all(not (ROOT / name).is_symlink() for name in tracked), "source symlinks require explicit packaging support")
    for name in tracked:
        destination = source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    subprocess.run(["go", "mod", "vendor", "-o", str(source / "vendor")], cwd=ROOT, env=goenv("linux-amd64"), check=True)
    save(source / "SOURCE_ID.json", meta)
    (source / "BUILDING.md").write_text(
        "# Corresponding source\n\nThis archive includes the exact tracked release source and vendored Go dependencies.\n"
        "Use Go 1.26.3. From this directory, select GOOS/GOARCH, set CGO_ENABLED=0, then run:\n\n"
        "```sh\ngo build -mod=vendor -trimpath -tags=" + TAGS + " -ldflags='" + flags(meta) + "' -o splicore ./cmd/splicore\n```\n"
        "Use splicore.exe on Windows. Driver and system-network qualification limits remain unchanged.\n", encoding="utf-8")
    # Prove this source distribution builds without Git metadata or a module download.
    env = goenv("linux-amd64")
    env.update(GOFLAGS="-mod=vendor", GOPROXY="off", GOSUMDB="off")
    rebuilt = out / "source-rebuilt-splicore"
    subprocess.run(["go", "build", "-mod=vendor", "-trimpath", "-tags=" + TAGS, "-ldflags=" + flags(meta),
                    "-o", str(rebuilt), "./cmd/splicore"], cwd=source, env=env, check=True)
    native_identity(rebuilt, meta, "linux-amd64")
    files = {p.relative_to(source).as_posix(): p.read_bytes() for p in source.rglob("*") if p.is_file()}
    name = f"splicore-{meta['version']}-source.tar.gz"
    executable = [line.split("\t", 1)[1] for line in command(["git", "ls-files", "--stage"]).splitlines()
                  if line.startswith("100755 ")]
    write_archive(final / name, name.removesuffix(".tar.gz"), files, meta["epoch"], executable)
    return name


def assemble(out):
    meta = identity()
    final = out / "final"
    final.mkdir(exist_ok=True)
    require(not list(final.iterdir()), "final asset directory must be empty")
    rows = []
    for target in TARGETS:
        row = json.loads((out / "transfer" / (target + ".json")).read_text())
        require(all(row["build"][key] == meta[key] for key in ("version", "commit", "tree", "build_tags", "build_time")), "mixed source identities")
        require(row["archive"] == archive_name(meta["version"], target), "unexpected archive name")
        path = out / "transfer" / row["archive"]
        require(digest(path.read_bytes()) == row["archive_sha256"], "transfer checksum mismatch")
        if target.endswith("amd64"):
            require(row["qualification"].get("all_native_gates_passed"), "behavior qualification policy incomplete")
            require(all(row["qualification"][p + "-" + a]["result"] == "PASS" for p in ("default", "full") for a in ("build", "vet", "test")), "native qualification incomplete")
            if target.startswith("linux"):
                require(row["qualification"]["race"]["result"] == "PASS", "Linux race did not pass")
        shutil.copyfile(path, final / path.name)
        rows.append(row)
    source_name = source_archive(out, final, meta)
    assets = {p.name: digest(p.read_bytes()) for p in final.iterdir()}
    manifest = dict(release=meta, platforms=rows, assets=assets, corresponding_source=source_name,
                    signing="SHA256 only; no digital signature supplied", windows_race="NOT_EXECUTED",
                    arm64_runtime="NOT_EXECUTED / BUILD_ONLY")
    save(final / "RELEASE_MANIFEST.json", manifest)
    (final / "SHA256SUMS").write_text("".join(f"{digest(p.read_bytes())}  {p.name}\n" for p in sorted(final.iterdir())), encoding="utf-8")
    notes = (ROOT / "docs/releases" / (meta["version"] + ".md")).read_text(encoding="utf-8")
    (out / "RELEASE_NOTES.md").write_text(notes.replace("{{COMMIT}}", meta["commit"]), encoding="utf-8")
    verify(final)


def archive_files(path):
    files = {}
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for item in archive.infolist():
                require(not item.is_dir() and (item.external_attr >> 16) & 0o170000 != 0o120000, "archive link or directory")
                require(item.filename not in files, "duplicate archive member")
                files[item.filename] = archive.read(item)
    else:
        with tarfile.open(path, "r:gz") as archive:
            for item in archive:
                require(item.isfile(), "archive contains non-regular member")
                require(item.name not in files, "duplicate archive member")
                files[item.name] = archive.extractfile(item).read()
    for name in files:
        require(safe_name(name), "unsafe archive member")
    return files


def checksums(text):
    result = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
        require(match is not None, "invalid checksum record")
        checksum, name = match.groups()
        require(name not in result and safe_name(name), "unsafe/duplicate checksum name")
        result[name] = checksum
    return result


def verify(directory, extract_target=None, extract_dir=None):
    manifest = json.loads((directory / "RELEASE_MANIFEST.json").read_text())
    meta = manifest["release"]
    version = meta["version"]
    require(re.fullmatch(r"v0\.[1-9][0-9]*\.[0-9]+", version), "invalid manifest version")
    expected = {archive_name(version, target) for target in TARGETS} | {f"splicore-{version}-source.tar.gz", "RELEASE_MANIFEST.json"}
    sums = checksums((directory / "SHA256SUMS").read_text())
    require(set(sums) == expected and {p.name for p in directory.iterdir()} == expected | {"SHA256SUMS"}, "asset inventory mismatch")
    require(manifest["assets"] == {name: sums[name] for name in expected if name != "RELEASE_MANIFEST.json"}, "manifest/checksum inventory mismatch")
    for name, checksum in sums.items():
        require(digest((directory / name).read_bytes()) == checksum, "download checksum mismatch: " + name)
    require([row["build"]["target"] for row in manifest["platforms"]] == list(TARGETS), "platform inventory mismatch")
    for row in manifest["platforms"]:
        target = row["build"]["target"]
        require(all(row["build"][key] == meta[key] for key in ("version", "commit", "tree", "build_time", "build_tags")), "manifest source mismatch")
        name = archive_name(version, target)
        prefix = name.removesuffix(".tar.gz").removesuffix(".zip") + "/"
        files = archive_files(directory / name)
        require(all(n.startswith(prefix) for n in files), "archive root mismatch")
        files = {n[len(prefix):]: data for n, data in files.items()}
        require(all(safe_name(name) for name in files), "unsafe relative package member")
        inner = checksums(files["SHA256SUMS"].decode())
        require(set(inner) == set(files) - {"SHA256SUMS"}, "inner inventory mismatch")
        require(all(digest(files[n]) == value for n, value in inner.items()), "inner checksum mismatch")
        binary_name = "splicore.exe" if target.startswith("windows") else "splicore"
        require({n for n in files if n.endswith(".exe") or n == "splicore"} == {binary_name}, "expected one core executable")
        require(digest(files[binary_name]) == row["build"]["binary_sha256"], "binary identity mismatch")
        require(json.loads(files["BUILD_INFO.json"]) == row["build"], "archive metadata mismatch")
        binary_format(files[binary_name], target)
        for required in ("LICENSE", "NOTICE.md", "THIRD_PARTY_NOTICES.md", "licenses/GPL-3.0.txt", "RUNNING.md", "examples/splicore.yaml", "examples/vless-loopback.json"):
            require(required in files, "missing packaged resource: " + required)
        if extract_target == target:
            require(extract_dir is not None and not extract_dir.exists(), "extraction destination must be new")
            for member, data in files.items():
                path = extract_dir / member
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            binary = extract_dir / binary_name
            if os.name != "nt":
                binary.chmod(0o755)
            if target == native_target():
                native_identity(binary, meta, target)
    source = archive_files(directory / manifest["corresponding_source"])
    prefix = f"splicore-{version}-source/"
    require(all(name.startswith(prefix) for name in source), "source archive root mismatch")
    require(prefix + "vendor/modules.txt" in source and json.loads(source[prefix + "SOURCE_ID.json"]) == meta, "corresponding source incomplete")
    print(f"Verified {len(sums) + 1} official assets for {version} at {meta['commit']}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("identity", "build", "qualify", "package", "assemble", "verify"))
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--output", type=Path, default=ROOT / "build/release")
    parser.add_argument("--extract-dir", type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    if args.action == "identity":
        print(json.dumps(identity(), sort_keys=True))
    elif args.action in ("build", "qualify", "package"):
        require(args.target is not None, "target required")
        {"build": build, "qualify": qualify, "package": package}[args.action](out, args.target)
    elif args.action == "assemble":
        assemble(out)
    else:
        verify(out, args.target, args.extract_dir.resolve() if args.extract_dir else None)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
