#!/usr/bin/env python3
"""
dmmb_offline_mac.py -- macOS driver for the offline .dmmb extractor.

Decrypts a .dmmb with YOUR installed DMMbookviewer + CypherGuard.framework and
YOUR machine's cached license (/Users/Shared/.Cypher License Information/...)
instead of downloading page images from the DMM web viewer. Crypto stays
inside CypherGuard.framework; this machine's own device key unwraps the cached
service key -- nothing is reimplemented and no keys leave the official stack.

Requirement: the book must have a LOCAL license (open it once in
DMMbookviewer while online). Fully offline afterwards.

The Windows driver is the sibling file dmmb_offline_win.py; the shared entry
point dmmb_offline.py picks the right one for the current platform. See
docs/macos.md and docs/windows.md.

How it works: builds + runs dmmb_offline_dump_mac.m (x86_64, under Rosetta),
which hosts the viewer's own pipeline -- capsulizedFileWithContentsOfFile /
loadServiceToCapsulizedFile / lookupLocalLicense / applyLicense /
per-file loader+interpreter -> CPContentDecryptor -- writing each entry's
ORIGINAL bytes to <outdir>. See the .m header + docs/macos.md.

Usage:
  python3 dmmb_offline_mac.py book.dmmb out_offline [--timeout N] [--build-only]

Outputs: outdir/<pos>_<entry> -- pages in reading order, the extension set from
the detected content kind (.jpg/.png/.zip/.xml) -- plus manifest.json in the
same layout as the Windows backend (index, name, file, bytes, encrypted,
expected_size, kind).
Exit codes: 0 ok, 2 no local license, 3 decrypt failure, 4 usage/io error.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "dmmb_offline_dump_mac.m")
BIN = os.path.join(HERE, "dmmb_offline_dump_mac")


def build():
    r = subprocess.run(["clang", "-arch", "x86_64", "-framework", "Foundation",
                        "-o", BIN, SRC], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr[-3000:], file=sys.stderr)
        raise SystemExit("build failed")
    print(f"built {BIN} ({os.path.getsize(BIN)} bytes)")


def _utf8():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv):
    _utf8()
    if "--build-only" in argv:
        build()
        return 0
    args = [a for a in argv if not a.startswith("--")]
    timeout = 600
    for i, f in enumerate([a for a in argv if a.startswith("--")]):
        if f == "--timeout" and i + 1 < len(argv):
            try:
                timeout = int(argv[argv.index(f) + 1])
            except ValueError:
                pass
    if len(args) < 2:
        print("usage: dmmb_offline_mac.py <file.dmmb> <outdir> [--timeout N]",
              file=sys.stderr)
        return 4
    dmmb, outdir = os.path.abspath(args[0]), os.path.abspath(args[1])
    if not os.path.exists(BIN) or \
            os.path.getmtime(SRC) > os.path.getmtime(BIN):
        build()
    if not os.path.isfile(dmmb):
        print(f"no such file: {dmmb}", file=sys.stderr)
        return 4
    os.makedirs(outdir, exist_ok=True)
    print(f"offline dump of {os.path.basename(dmmb)} ...")
    try:
        proc = subprocess.run(["arch", "-x86_64", BIN, dmmb, outdir],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print("timed out", file=sys.stderr)
        return 3
    sys.stderr.write(proc.stderr[-2000:] if proc.stderr else "")
    man = os.path.join(outdir, "manifest.json")
    if os.path.exists(man):
        entries = json.load(open(man))
        kinds = {}
        for e in entries:
            kinds[e.get("kind", "?")] = kinds.get(e.get("kind", "?"), 0) + 1
        print(f"entries: {len(entries)} kinds={kinds}")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
