#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
export GOTELEMETRY=off GOTOOLCHAIN=local
go_version=$(go env GOVERSION)
if [[ ! "$go_version" =~ ^go([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
  printf 'Cannot identify a stable Go toolchain\n' >&2; exit 1
fi
major=${BASH_REMATCH[1]}; minor=${BASH_REMATCH[2]}; patch=${BASH_REMATCH[3]}
if (( major < 1 || major == 1 && (minor < 26 || minor == 26 && patch < 3) )); then
  printf 'Splicore requires Go 1.26.3 or newer\n' >&2; exit 1
fi
export GOOS=${GOOS:-$(go env GOHOSTOS)} GOARCH=${GOARCH:-$(go env GOHOSTARCH)} CGO_ENABLED=0
case "$GOOS/$GOARCH" in windows/amd64|windows/arm64|linux/amd64|linux/arm64) ;; *) printf 'Unsupported build target: %s/%s\n' "$GOOS" "$GOARCH" >&2; exit 1 ;; esac
version=${SPLICORE_VERSION:-devel}
tags=${SPLICORE_BUILD_TAGS:-with_quic,with_utls,with_gvisor}
stamp=${SPLICORE_BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
[[ "$version" =~ ^[A-Za-z0-9.+-]+$ && "$tags" =~ ^[a-z0-9_,]+$ && "$stamp" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || { printf 'Invalid build metadata\n' >&2; exit 1; }
commit=$(git rev-parse HEAD)
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { printf 'Cannot identify source commit\n' >&2; exit 1; }
dirty=false
[[ -z "$(git status --porcelain)" ]] || dirty=true
suffix=''; [[ "$GOOS" != windows ]] || suffix=.exe
output=${SPLICORE_OUTPUT:-$root/build/$GOOS-$GOARCH/splicore$suffix}
[[ "$output" == /* ]] || output="$root/$output"
if [[ -e "$output" ]]; then
  [[ -f "$output" && -f "$output.sha256" ]] || { printf 'Refusing to overwrite an untracked build output\n' >&2; exit 1; }
  expected=$(<"$output.sha256")
  actual=$(sha256sum -- "$output"); actual=${actual%% *}
  [[ "$expected" =~ ^[0-9a-f]{64}$ && "$expected" == "$actual" ]] || { printf 'Existing output differs from the recorded build hash\n' >&2; exit 1; }
fi
mkdir -p -- "$(dirname -- "$output")" "$root/build/tmp"
export GOTMPDIR="$root/build/tmp" TMPDIR="$root/build/tmp"
export GOCACHE=${GOCACHE:-$root/build/cache/$GOOS} GOMODCACHE=${GOMODCACHE:-$root/build/modules} GOPATH=${GOPATH:-$root/build/gopath}
vp=github.com/ike-sh/Splicore/internal/splicore/version
flags="-X=$vp.ProductVersion=$version -X=$vp.Commit=$commit -X=$vp.Dirty=$dirty -X=$vp.BuildTime=$stamp -X=$vp.BuildTags=$tags"
go build -mod=readonly -trimpath -tags "$tags" -ldflags "$flags" -o "$output" ./cmd/splicore
hash=$(sha256sum -- "$output"); hash=${hash%% *}
printf '%s\n' "$hash" > "$output.sha256"
printf 'Built %s (%s/%s, CGO=0, commit=%s, dirty=%s)\n' "$output" "$GOOS" "$GOARCH" "$commit" "$dirty"
