"""Download pinned Linux amd64 interop clients into an external private cache."""
import gzip
import hashlib
import io
import json
import os
import pathlib
import sys
import tarfile
import urllib.request

CLIENTS = [
    ("mihomo", "1.19.30", "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.30/mihomo-linux-amd64-v1-v1.19.30.gz", "cbe553d0319a414bd3a372c5976a252155b2c4882b66bce88a4d6bba9571a553"),
    ("sing-box", "1.14.1", "https://github.com/SagerNet/sing-box/releases/download/v1.14.1/sing-box-1.14.1-linux-amd64.tar.gz", "12cb2816b52febb356f6a885b740cc8758c3f30b8ae0ca8edba80f0d2d35343f"),
]

def main():
    root = pathlib.Path(sys.argv[1]).resolve()
    repo = pathlib.Path(__file__).resolve().parent.parent
    if root.is_relative_to(repo):
        raise SystemExit("client cache must be outside the repository")
    root.mkdir(parents=True, exist_ok=True)
    results = []
    for name, version, url, checksum in CLIENTS:
        archive = root / (name + ".archive")
        if not archive.exists():
            req = urllib.request.Request(url, headers={"User-Agent": "Splicore-interop"})
            try:
                with urllib.request.urlopen(req, timeout=60) as response:
                    data = response.read(100 << 20)
            except Exception:
                raise SystemExit("DEPENDENCY_UNAVAILABLE: " + name) from None
            if hashlib.sha256(data).hexdigest() != checksum:
                raise SystemExit("CHECKSUM_MISMATCH: " + name)
            archive.write_bytes(data)
        data = archive.read_bytes()
        if hashlib.sha256(data).hexdigest() != checksum:
            raise SystemExit("CHECKSUM_MISMATCH: " + name)
        if name == "mihomo":
            binary = gzip.decompress(data)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                matches = [m for m in tar if m.isfile() and m.name.endswith("/sing-box")]
                if len(matches) != 1:
                    raise SystemExit("INVALID_ARCHIVE: sing-box")
                binary = tar.extractfile(matches[0]).read()
        output = root / name
        output.write_bytes(binary)
        if os.name != "nt":
            os.chmod(output, 0o700)
        results.append({"client": name, "version": version, "archive_sha256": checksum, "binary_sha256": hashlib.sha256(binary).hexdigest()})
    (root / "clients.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results))

if __name__ == "__main__":
    main()
