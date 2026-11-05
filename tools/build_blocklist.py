#!/usr/bin/env python3
"""
Build blocklist.bin for esp32c3_adblock_v2.ino

Usage:
    python build_blocklist.py blocklist.bin [SOURCE ...]

SOURCE = URL or local file; hosts format ("0.0.0.0 ads.example.com"),
plain domain list, or AdGuard "||ads.example.com^" rules.
Default source: StevenBlack hosts.

File format: "ADB1" + 4 zero bytes, then sorted unique 40-bit hashes, 5 bytes each (big-endian).
Hash = FNV-1a 64, folded (h ^= h >> 40), low 40 bits -- identical to the sketch.
"""
import re
import sys
import urllib.request

DEFAULT = ["https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"]
M64 = 0xFFFFFFFFFFFFFFFF
M40 = (1 << 40) - 1
OK_CHARS = re.compile(r"^[a-z0-9._-]+$")


def hash40(b: bytes) -> int:
    h = 0xCBF29CE484222325
    for c in b:
        h ^= c
        h = (h * 0x100000001B3) & M64
    h ^= h >> 40
    return h & M40


def valid(d: str) -> bool:
    return (3 < len(d) <= 253 and "." in d and not d.startswith(".")
            and d[-1].isalpha() and OK_CHARS.match(d) is not None
            and d != "localhost.localdomain")


def domains_from(text: str):
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("@@"):
            continue
        if line.startswith("||") and line.endswith("^"):       # AdGuard basic rule
            toks = [line[2:-1]]
        else:
            toks = line.split()
            toks = toks if len(toks) == 1 else toks[1:]        # hosts: drop IP column
        for t in toks:
            t = t.lower()
            if valid(t):
                yield t


def load(src: str) -> str:
    if src.startswith(("http://", "https://")):
        with urllib.request.urlopen(src, timeout=60) as r:
            return r.read().decode("utf-8", "ignore")
    with open(src, encoding="utf-8", errors="ignore") as f:
        return f.read()


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    out, sources = sys.argv[1], (sys.argv[2:] or DEFAULT)
    hashes = set()
    for s in sources:
        n0 = len(hashes)
        for d in domains_from(load(s)):
            hashes.add(hash40(d.encode()))
        print(f"{s}: +{len(hashes) - n0} unique hashes")
    arr = sorted(hashes)
    with open(out, "wb") as f:
        f.write(b"ADB1\0\0\0\0")
        for h in arr:
            f.write(h.to_bytes(5, "big"))
    print(f"wrote {out}: {len(arr)} entries, {8 + 5 * len(arr)} bytes")
    if 8 + 5 * len(arr) > 700_000:
        print("WARNING: > ~700 KB; with the default 1.5 MB LittleFS partition keep it under ~140k domains "
              "(old + temp copy must both fit).")


if __name__ == "__main__":
    main()
