#!/usr/bin/env python3
"""
dmmb_offline.py -- cross-platform entry point for the offline .dmmb extractor.

Decrypts a .dmmb using YOUR installed DMMbookviewer and YOUR machine's cached
license, without downloading page images from the DMM web viewer. Each platform
drives its own viewer stack, so no crypto is reimplemented on either:

  macOS   -> dmmb_offline_mac.py   Objective-C helper + CypherGuard.framework
  Windows -> dmmb_offline_win.py   C++ helper hosted inside DMMbookviewer.exe

Requirement (both platforms): the book must have a LOCAL license (open it once
in DMMbookviewer while online). Fully offline afterwards.

Usage:
  python3 dmmb_offline.py book.dmmb out_dir
Exit codes: 0 ok, 2 no local license, 3 decrypt failure, 4 usage/io error.
See docs/macos.md and docs/windows.md.
"""
import os
import sys


def _utf8():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv):
    _utf8()
    if os.name == "nt":
        import dmmb_offline_win as impl
    else:
        import dmmb_offline_mac as impl
    return impl.main(argv)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except OSError as e:
        print(str(e), file=sys.stderr)
        sys.exit(4)
