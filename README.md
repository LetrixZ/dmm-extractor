# dmmb-tools

Extract original page images from DMM `.dmmb` book capsules you own.

Three extraction paths share one container parser, and all three write the same
on-disk layout in the same reading order:

```
out/0000_0001.jpg … out/0101_0102.jpg   # pages, reading order (cover first)
out/0102_index.bin                       # plaintext capsule entries
out/manifest.json
```

| method | platform | backend | needs |
|---|---|---|---|
| **Web download** (`dmmb_extract.py`) | **cross-platform** | Python 3 stdlib HTTP | your DMM session cookies |
| Offline (`dmmb_offline_mac.py`) | macOS | [`dmmb_offline_dump_mac.m`](dmmb_offline_dump_mac.m) — Objective-C, drives the viewer's classes + `CypherGuard.framework` | installed DMMbookviewer + cached license |
| Offline (`dmmb_offline_win.py`) | Windows | [`dmmb_offline_dump_win.cpp`](dmmb_offline_dump_win.cpp) + [`dmmb_offline_worker_win.cpp`](dmmb_offline_worker_win.cpp) — C++, hosted inside `DMMbookviewer.exe` | installed DMMbookviewer + cached license |

**The web download is the primary method**: it is **cross-platform** (macOS,
Windows and Linux; Python 3 stdlib only, no native build, no license store) and
uses only your own DMM account. The two **native offline extractors** — one per
platform — drive your **installed DMMbookviewer and its cached license** for a
fully offline decrypt. Neither offline backend reimplements any crypto or
extracts keys: each calls the same official entry points its own viewer uses.

A **container inspector** (`dmmb_inspect.py`) reads the plaintext structure
without any license.

| file | platform | what |
|---|---|---|
| `dmmb_extract.py` | **any** | web path: licensed page JPEGs via DMM viewer APIs (stdlib only) |
| `dmmb_offline.py` | any | cross-platform offline entry point: picks the platform driver |
| `dmmb_offline_mac.py` | macOS | driver: builds/runs the Objective-C helper |
| `dmmb_offline_dump_mac.m` | macOS | ObjC dumper: drives the viewer + CypherGuard through the app's unlock pipeline |
| `dmmb_offline_win.py` | Windows | driver/CLI: environment + license report, builds/runs the native host + worker |
| `dmmb_offline_dump_win.cpp` | Windows | controller: parses the capsule, injects the worker, reports |
| `dmmb_offline_worker_win.cpp` | Windows | worker DLL: drives the viewer's own SDK + cached license; writes files + `manifest.json` |
| `dmmb_win_common.h` | Windows | shared container parser + key-free host/worker contract |
| `dmmb_inspect.py` | any | container inspector: INI/DNBF/DNBA/index.bin/fileinfo as JSON (no keys needed) |
| [`docs/macos.md`](docs/macos.md) | — | `.dmmb` format + DRM, and the macOS stack |
| [`docs/windows.md`](docs/windows.md) | — | the Windows stack and how the pipeline maps onto it |

## Web download (cross-platform)

```sh
# paste a Cookie header from your logged-in browser
python3 dmmb_extract.py --dmmb book.dmmb --doujin-id d_012345 --out pages_out \
  --cookie 'login_secure_id=...; login_session_id=...'
# -> pages_out/0000_0001.jpg ... pages_out/0102_index.bin + manifest.json
```

Runs on any OS with Python 3 (macOS / Windows / Linux); stdlib only, nothing to
build. It downloads the original page JPEGs through the official DMM web viewer
APIs using your own DMM session cookies (the same account that owns the book),
so no capsule crypto is reimplemented. `--manifest-only` / `--dry-run` parse and
plan without a cookie; `--dump-enc` also saves the raw encrypted payloads. Its
`manifest.json` is a rich object (capsule metadata + download plan); the offline
tools record the same page fields as a plain array.

## Offline usage (both platforms)

The book must have been opened **once while online**, so a license is cached
(macOS: `/Users/Shared/.Cypher License Information/`; Windows:
`C:\Cypher License Information\`). Fully offline afterwards.

```sh
python3 dmmb_offline.py book.dmmb out_dir
# -> out_dir/0000_0001.jpg ...   (decrypted pages, in reading order)
#    out_dir/0102_index.bin
#    out_dir/manifest.json
```

`dmmb_offline.py` dispatches to the platform driver; you can also run a driver
directly (`dmmb_offline_mac.py`, `dmmb_offline_win.py`).

## macOS

```sh
# inspect (no license needed)
python3 dmmb_inspect.py book.dmmb

# offline decrypt
python3 dmmb_offline.py book.dmmb out_dir
```

The helper builds with Xcode CLT (`clang -arch x86_64`; the viewer is
x86_64-only and runs under Rosetta on Apple Silicon). See
[`docs/macos.md`](docs/macos.md).

## Windows

```powershell
python dmmb_offline_win.py doctor            # install + license store + DLL/ordinal report
python dmmb_offline_win.py inspect book.dmmb
# -> service GUID + content_id + "local license present: YES"
python dmmb_offline_win.py dump book.dmmb out_win
# -> out_win\0000_0001.jpg ... 0101_0102.jpg  (decrypted pages, in reading order)
```

What it does:

- Builds a small C++ **controller** and a **worker DLL** (VS 2022 C++ tools, x64).
- The viewer's crypto/license SDK only finishes initialization **inside the
  viewer** process, so `dump` starts/attaches to `DMMbookviewer.exe` and loads
  the worker DLL into it. The worker calls the official SDK — the same ordinals
  the viewer uses — via the cached-license fast path (no network).
- Only paths and progress cross the process boundary; `manifest.json` is built
  inside the worker, so no key material or decrypted bytes leave it, and each
  output file is named after its detected kind (`.jpg`, …) in reading order.

Requirements and limits (pinned viewer `3.2.0.0`, `ctlicis.dll 3.1.6.9`,
`ctcrypt.dll 2.0.6.2`; multi-file v1 capsules only; keep the viewer idle during
extraction) are in [`docs/windows.md`](docs/windows.md).

## Notes & scope

All paths are for capsules you own. They do not implement ciphers, unwrap keys
outside the official stack, or perform server-side license issuance — see the
"Scope" section of each platform's notes.
