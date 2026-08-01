#!/usr/bin/env python3
"""Check build.zig.zon dependency pins.

Dependabot has no Zig ecosystem, so these dependencies are invisible to it.

Zig already enforces the integrity property at build time: a URL dependency
without a matching .hash fails the build, so archives are content-addressed and
a moved tag breaks loudly rather than swapping bytes silently. This script does
not try to re-implement that. It enforces the parts Zig does not check (https,
hash presence at review time rather than build time) and, with --strict, reports
dependencies that have fallen behind upstream.

Entries are found by brace matching, so every dependency is accounted for
whatever its layout. If the file cannot be parsed the script fails rather than
reporting success on a partial read.
"""
import re
import subprocess
import sys

HEX40 = re.compile(r"^[0-9a-f]{40}$")


def block(text, start):
    """Return (body, end_index) for the .{ ... } beginning at start."""
    depth, i, n = 0, start, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i], i + 1
        i += 1
    raise ValueError("unbalanced braces")


def strip_comments(text):
    """Remove // comments that are not inside string literals.

    A naive regex eats the // in https:// and silently truncates every URL,
    which then unbalances the braces around it.
    """
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            out.append(c)
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    out.append(text[i])
                    i += 1
                out.append(text[i])
                i += 1
            if i < n:
                out.append(text[i])
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse(text):
    text = strip_comments(text)
    m = re.search(r"\.dependencies\s*=\s*\.(?=\{)", text)
    if not m:
        return []
    body, _ = block(text, text.index("{", m.end() - 1))

    deps, i = [], 0
    entry = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\.(?=\{)")
    while True:
        m = entry.search(body, i)
        if not m:
            break
        inner, i = block(body, body.index("{", m.end() - 1))
        u = re.search(r'\.url\s*=\s*"([^"]*)"', inner)
        h = re.search(r'\.hash\s*=\s*"([^"]*)"', inner)
        deps.append((m.group(1), u.group(1) if u else None, h.group(1) if h else None))
    return deps


def upstream_latest(repo):
    try:
        out = subprocess.run(
            ["gh", "api", f"repos/{repo}/releases/latest", "--jq", ".tag_name"],
            capture_output=True, text=True, timeout=30,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    strict = "--strict" in sys.argv[1:]
    path = args[0] if args else "build.zig.zon"

    try:
        text = open(path).read()
    except OSError as e:
        print(f"FAIL: cannot read {path}: {e}")
        return 1

    try:
        deps = parse(text)
    except ValueError as e:
        print(f"FAIL: cannot parse {path}: {e}")
        return 1

    if not deps:
        print(f"FAIL: no dependencies parsed from {path} (format change?)")
        return 1

    print(f"== {path}: {len(deps)} dependencies ==")
    rc = 0
    for name, url, hash_ in deps:
        if url is None:
            # A path dependency is legitimate; anything else is a parse failure
            # we refuse to paper over.
            if re.search(rf"\.{re.escape(name)}\s*=\s*\.\{{[^}}]*\.path\s*=", text, re.S):
                print(f"  ok  {name}: local path dependency")
            else:
                print(f"FAIL: {name}: no .url and no .path — cannot classify")
                rc = 1
            continue

        if not url.startswith("https://"):
            print(f"FAIL: {name}: URL is not https ({url})")
            rc = 1
            continue

        if not hash_:
            print(f"FAIL: {name}: no .hash — archive would not be content-addressed")
            rc = 1
            continue

        ref = None
        if "/archive/refs/tags/" in url:
            ref = url.split("/archive/refs/tags/")[1].removesuffix(".tar.gz")
            print(f"note: {name}: pinned to tag {ref} (mutable upstream; .hash pins the bytes)")
        elif "/archive/" in url:
            ref = url.split("/archive/")[1].removesuffix(".tar.gz")
            if HEX40.match(ref):
                print(f"  ok  {name}: commit {ref[:8]}")
            else:
                print(f"note: {name}: pinned to non-commit ref {ref}")
        else:
            print(f"note: {name}: unrecognised URL shape, cannot classify ref")

        if not strict or not ref:
            continue
        m = re.match(r"https://github\.com/([^/]+/[^/]+)/archive/", url)
        if not m:
            continue
        latest = upstream_latest(m.group(1))
        if latest and latest != ref:
            print(f"FAIL: {name}: pinned at {ref[:12]}, upstream latest release is {latest}")
            rc = 1

    return rc


if __name__ == "__main__":
    sys.exit(main())
