#!/bin/sh
# Local, explicitly pinned artifact entrypoint. No downloads or firewall changes.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$(id -u)" = 0 ] || fail 'Installation requires root.'
if [ "${1-}" = '--uninstall' ]; then
    shift
    [ "$#" = 0 ] || { [ "$#" = 1 ] && [ "$1" = '--purge' ]; } || fail 'Invalid uninstall arguments.'
    exec /usr/local/bin/splicore package uninstall "$@"
fi
artifact=''; checksum=''; start=''
while [ "$#" -gt 0 ]; do
    case "$1" in
        --artifact) [ "$#" -ge 2 ] || fail 'Missing artifact.'; artifact=$2; shift 2 ;;
        --sha256) [ "$#" -ge 2 ] || fail 'Missing SHA256.'; checksum=$2; shift 2 ;;
        --start) start=--start; shift ;;
        *) fail 'Usage: install.sh --artifact FILE --sha256 SHA256 [--start] | --uninstall [--purge]' ;;
    esac
done
case "$artifact" in /*) ;; *) fail 'Artifact path must be absolute.' ;; esac
[ -f "$artifact" ] && [ ! -L "$artifact" ] || fail 'Artifact must be a regular local file.'
[ "${#checksum}" = 64 ] || fail 'Expected SHA256 is required.'
case "$checksum" in *[!0-9a-f]*) fail 'Invalid SHA256.' ;; esac
[ "$(stat -c %s "$artifact")" -le 268435456 ] || fail 'Artifact exceeds size limit.'
stage=$(mktemp -d /var/tmp/splicore-install.XXXXXXXX)
trap 'rm -f -- "$stage/artifact.tar.gz" "$stage/members" "$stage/types"; rm -rf -- "$stage/package"; rmdir -- "$stage"' EXIT HUP INT TERM
# Private copy pins verified bytes across archive inspection and extraction.
cp -- "$artifact" "$stage/artifact.tar.gz"
actual=$(sha256sum "$stage/artifact.tar.gz"); actual=${actual%% *}
[ "$actual" = "$checksum" ] || fail 'Artifact SHA256 mismatch.'
tar -tzf "$stage/artifact.tar.gz" > "$stage/members"
count=0
while IFS= read -r member; do
    case "$member" in ''|/*|*..*|*\\*|*[!A-Za-z0-9._/-]*) fail 'Unsafe archive member.' ;; esac
    case "$member" in splicore|splicore.service|splicore-tun.conf|splicore.yaml|install.sh|manifest.json|SHA256SUMS|LICENSE|NOTICE.md|docs/*.md|licenses/*) ;; *) fail 'Unknown archive member.' ;; esac
    count=$((count+1)); [ "$count" -le 258 ] || fail 'Too many archive members.'
done < "$stage/members"
[ "$count" -ge 9 ] || fail 'Incomplete archive.'
[ "$(sort "$stage/members" | uniq | wc -l)" -eq "$count" ] || fail 'Duplicate archive member.'
# Reject all links, devices, directories and other special entries before tar writes.
tar -tvzf "$stage/artifact.tar.gz" > "$stage/types"
total=0
while read -r type owner bytes rest; do
    case "$type" in -*) ;; *) fail 'Only regular archive files are allowed.' ;; esac
    case "$bytes" in ''|*[!0-9]*) fail 'Invalid archive member size.' ;; esac
    [ "$bytes" -le 134217728 ] || fail 'Archive member exceeds size limit.'
    total=$((total+bytes)); [ "$total" -le 268435456 ] || fail 'Expanded artifact exceeds size limit.'
done < "$stage/types"
rm -- "$stage/members" "$stage/types"
mkdir -m 700 "$stage/package"
tar -xzf "$stage/artifact.tar.gz" --no-same-owner --no-same-permissions -C "$stage/package"
find "$stage/package" -type f -exec chmod 644 {} +
# Manifest/file checks happen before account, service or installation mutations.
chmod 755 "$stage/package/splicore" "$stage/package/install.sh"
"$stage/package/splicore" package verify --directory "$stage/package" >/dev/null
if [ -n "$start" ]; then
    "$stage/package/splicore" package install --directory "$stage/package" --start
else
    "$stage/package/splicore" package install --directory "$stage/package"
fi
