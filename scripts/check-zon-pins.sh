#!/usr/bin/env bash
# Dependabot has no Zig ecosystem, so build.zig.zon dependencies are invisible
# to it. This enforces what actually protects us, and reports what does not.
#
#   default    integrity rules; every dependency must be content-addressed
#   --strict   also fail when a pinned GitHub dependency is behind upstream
#
# Integrity here rests on the .hash field, not the URL: Zig verifies the
# fetched archive against it, so a moved tag or a swapped artifact fails the
# build rather than being silently accepted. A dependency without a .hash has
# no such protection, which is why a missing hash is an error and not a note.
set -euo pipefail

ZON="${1:-build.zig.zon}"
STRICT=0
[ "${2:-}" = "--strict" ] && STRICT=1
[ "${1:-}" = "--strict" ] && { STRICT=1; ZON="build.zig.zon"; }

[ -f "$ZON" ] || { echo "FAIL: $ZON not found"; exit 1; }

rc=0
fail() { echo "FAIL: $*"; rc=1; }
note() { echo "note: $*"; }

# Pull (name, url, hash) triples. Dependency names are the .foo = .{ keys that
# carry a .url, which distinguishes them from .name/.version/.paths scalars.
mapfile -t DEPS < <(awk '
    /^[[:space:]]*\.[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*\.\{/ {
        name = $0
        sub(/^[[:space:]]*\./, "", name)
        sub(/[[:space:]]*=.*$/, "", name)
        cur = name; url = ""; hash = ""
        next
    }
    /\.url[[:space:]]*=/  { u = $0; sub(/^.*\.url[[:space:]]*=[[:space:]]*"/, "", u);  sub(/".*$/, "", u);  url = u  }
    /\.hash[[:space:]]*=/ { h = $0; sub(/^.*\.hash[[:space:]]*=[[:space:]]*"/, "", h); sub(/".*$/, "", h); hash = h }
    /^[[:space:]]*\},[[:space:]]*$/ {
        if (cur != "" && url != "") print cur "\t" url "\t" hash
        cur = ""; url = ""; hash = ""
    }
' "$ZON")

[ "${#DEPS[@]}" -gt 0 ] || { echo "FAIL: no dependencies parsed from $ZON (parser drift?)"; exit 1; }

echo "== $ZON: ${#DEPS[@]} dependencies =="

for line in "${DEPS[@]}"; do
    IFS=$'\t' read -r name url hash <<< "$line"

    case "$url" in
        https://*) ;;
        *) fail "$name: URL is not https ($url)"; continue ;;
    esac

    # The load-bearing rule. Without a hash Zig has nothing to verify against.
    if [ -z "$hash" ]; then
        fail "$name: no .hash — the archive would be accepted unverified"
        continue
    fi

    # Immutability of the URL is a freshness/reproducibility property, not a
    # security one, because the hash already pins the bytes. Report, don't fail.
    ref=""
    case "$url" in
        *"/archive/refs/tags/"*)
            ref="${url##*/archive/refs/tags/}"; ref="${ref%.tar.gz}"
            note "$name: pinned to tag $ref (mutable upstream; .hash still pins the bytes)"
            ;;
        *"/archive/"*)
            ref="${url##*/archive/}"; ref="${ref%.tar.gz}"
            if [ "${#ref}" -eq 40 ] && [ -z "${ref//[0-9a-f]/}" ]; then
                echo "  ok  $name: commit ${ref:0:8}"
            else
                note "$name: pinned to non-commit ref $ref"
            fi
            ;;
        *) note "$name: unrecognised URL shape, cannot classify ref" ;;
    esac

    [ "$STRICT" = "1" ] || continue
    command -v gh >/dev/null 2>&1 || { note "gh unavailable; skipping freshness"; continue; }

    repo=$(printf '%s' "$url" | sed -n 's#^https://github.com/\([^/]*/[^/]*\)/archive/.*#\1#p')
    [ -n "$repo" ] || continue

    latest=$(gh api "repos/$repo/releases/latest" --jq .tag_name 2>/dev/null || true)
    if [ -n "$latest" ] && [ -n "$ref" ] && [ "$latest" != "$ref" ]; then
        head=$(gh api "repos/$repo/commits/$latest" --jq .sha 2>/dev/null || true)
        if [ "$head" != "$ref" ]; then
            fail "$name: pinned at ${ref:0:12}, upstream latest release is $latest"
        fi
    fi
done

exit $rc
