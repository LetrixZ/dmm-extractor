# DMM capsule (`.dmmb`) on Windows — implementation notes

Part of the two-platform [dmmb-tools](../README.md) project. The **container**
format is identical on both platforms and is described in
[`macos.md`](macos.md); this document covers the **Windows** viewer stack, the
local license store, and the Windows backend
([`dmmb_offline_dump_win.cpp`](../dmmb_offline_dump_win.cpp) controller +
[`dmmb_offline_worker_win.cpp`](../dmmb_offline_worker_win.cpp) worker) that
drives it.

> Status: **implemented.** The Windows backend reproduces the same pipeline the
> macOS backend does, against the installed viewer's own SDK. No crypto or key
> unwrapping is reimplemented: the worker calls the same official entry points
> the viewer uses. Verified on real licensed capsules (102-page and 30-page
> books).

Everything here was observed on the machine that produced this repo:

```
DMMbookviewer.exe 3.2.0.0   (DMMBooks x64)
install:  C:\Program Files\DMM\DMMbookviewer\
license:  C:\Cypher License Information\Services\<SERVICE-GUID>\
```

---

## 1. The two viewer stacks

Both platforms drive the same conceptual pipeline, but each viewer exposes it
differently. The Windows backend therefore talks to the Windows viewer's own
facilities rather than to any macOS construct:

| macOS backend | Windows backend |
|---|---|
| `#import <Foundation/Foundation.h>` | plain C++ (no ObjC runtime) |
| `dlopen()` of a Mach-O `.app` binary | PE `LoadLibrary`; the app is an **EXE** |
| ObjC classes `CPCapsulizedFile`, `CPSecurityLibraryManager`, … | C++ classes inside `DMMbookviewer.exe` (RTTI, §4) |
| `__CPIR_*` selectors + `objc_msgSend` | C++ vtable calls / ordinal C exports |
| `/Users/Shared/.Cypher License Information/` | `C:\Cypher License Information\` (§3) |

The container parsing (INI / DNBE / DNBA / DNBF / index.bin) is identical on
both and implemented in pure Python (`dmmb_inspect.py`) and in
`dmmb_win_common.h` for the native Windows backend.

---

## 2. Windows binaries

| file | version | packed | exports |
|---|---|---|---|
| `DMMbookviewer.exe` | 3.2.0.0 | no | none |
| `cguard.dll` (CypherGuard) | 3.2.3.3 | **Themida** | 36, ordinal-only |
| `ctlicis.dll` (license client) | 3.1.6.9 | **Themida** | 910, ordinal-only |
| `ctcrypt.dll` | 2.0.6.2 | **Themida** | 108, ordinal-only |

- The `.themida` section means the crypto/license code is **packed**, but the
  export table still resolves: `LoadLibrary` +
  `GetProcAddress(h, MAKEINTRESOURCE(ord))` works.
- The **high-level DRM glue lives in the unpacked EXE**; its MSVC RTTI names are
  present verbatim (`drm::cypherguard::{license_provider,decryptor,
  pcts_decrypt_stream}`, `drm::abstract_decryptor`, `hyperbook::dmmb_resource`,
  `dmmb::{bad_magic,decryptor_needed,invalid_file_format,file_not_found}`, …).
- The EXE embeds the **same allow-list config blob** as the macOS build
  (`VwABAS0AuF8BDrZfOsvwQOx9M2pU2T40…`, cf. `kAccessCode()` in the `.m`) and
  passes the executable's `.urd` file (`DMMbookviewer_exe.urd`) alongside it.

### 2.1 Exports the EXE actually calls (delay-load by ordinal)

No import names at all — pure ordinals, `/DELAYLOAD`ed. IAT slots at
`ImageBase 0x140000000`:

| DLL | ordinals (IAT RVA) |
|---|---|
| `cguard.dll` | `8 16 17 18 20 38 39 12 15` (`0x4BA158`–`0x4BA198`) |
| `ctcrypt.dll` | `41 43 23 42 22 94 1` (`0x4BA1A8`–`0x4BA1D8`) |
| `ctlicis.dll` | `306 307 49 314 42 311 89 79 601 603 602 300 304 302 301 34 106 36 258 92 57 33 32 7 2 3 88 332` (`0x4BA1E8`–`0x4BA2C0`) |

---

## 3. Local license store (`C:\Cypher License Information\`)

Windows equivalent of `/Users/Shared/.Cypher License Information/`:

```
C:\Cypher License Information\Services\{01234567-89AB-CDEF-0123-456789ABCDEF}\
    hif                         116 B   device/host info
    huk                         104 B   device ("unique") key
    info                        648 B   service record
    Policies\P0ABCDEF1          636 B   policy record
    Contents\C0001E240\         content_id 0x0001E240 = 123456
        info                   4202 B
        <28-char license id>   549 B   license blob
    Contents\C00039447\         content_id 0x00039447 = 234567
        info                   4202 B
        <28-char license id>   549 B   license blob
```

Facts used by the Windows backend:

- The service GUID is the capsule's DRM-footer GUID (§2.3 of the container
  notes), emitted as **`uuid.UUID(bytes_le=…)`** of `auth_block+108`.
- **Content directory name = `"C"` + `content_id` as 8 uppercase hex digits**
  (`123456 → "C0001E240"`).
- The directory names above are illustrative; on a real machine each is keyed by
  the capsule's own GUID and content id, so the offline path is testable there.

Confirm the mapping yourself without decrypting anything:

```powershell
python dmmb_offline_win.py inspect book.dmmb
```

---

## 4. Recovered SDK signatures

The EXE's `ctcore` wrapper classes (`sub_140058xxx`) and the DRM resource class
(`sub_140127130`) pin every argument type. The worker uses exactly these
(ordinals, x64 `__fastcall`, i.e. `rcx, rdx, r8, r9` then the stack):

**Startup / allow-list** (mirrors the `.m` header's init block). All three
calls exist in the EXE at `0x14000AEC0` and `0x14000B170`:

```
ctlicis!2(config_blob_ansi, 2, NULL, "…DMMbookviewer_exe.urd", 0x19B19D4C) -> u32
cguard !8(2, NULL, "…DMMbookviewer_exe.urd", 0x19B19D4C)                 -> u32
cguard 18()                                   -> context           (create)
cguard 38(ctx)                                -> bool              (valid?)
cguard 15(ctx, 2, 0)                          -> bool
cguard 39(ctx, 832, hwnd, 0x8001)             -> bool
cguard 12(ctx, 4, hwnd)                       -> bool
cguard 20(ctx, &detail) / 17(ctx) / 16(ctx)   error query / release / free
```

These report failure (`2`) from a plain standalone process, and the
window-context chain is bound to the GUI, so a standalone host cannot finish
this handshake. **The worker instead runs inside the viewer after the viewer has
completed it** (§6).

**Capsule open + cached-license fast path** (the offline path; `sub_140058770`
→ `ctlicis_306`, `sub_140058830` → `ctlicis_49/314/307/258/42/88/89`,
`sub_140058960` → auth type):

```
ctlicis 32()                                       -> capsule handle (create; 0 on failure)
ctlicis 34(capsule, "file", 8)                     -> u32    open DRM/auth block, flags = 8
ctlicis 79(capsule)                                -> u32    auth type (2 = moving/web, needed for the offline path)
ctlicis 300()                                      -> auth handle (0 on failure)
ctlicis 304(auth, capsule, 0x2000)                 -> u32    apply the LOCAL cached license (no HTTP)
ctlicis 106(capsule, key)                          -> u32    copy the 16-byte content key into the ctcrypt key object
ctlicis 36(capsule)                                -> u32    finalize / apply
ctlicis 92(capsule, &detail)                       -> u32    error query
ctlicis 258(auth,    &detail)                      -> u32    error query
ctlicis 33(capsule) / 301(auth)                    release / free
```

`ctlicis 32` returns **null on failure**, not an error code; a failed `34` is
retried while the error reads `3` (service not ready). `0x2000` selects the
cached-license (no network) path — the HTTP provider (`ctlicis 601/603/602`) is
never called.

**Per-entry stream decrypt** (Nemucod-style `ctcrypt`, stream model):

```
ctcrypt 22()                        -> key object    (0 on failure)
ctcrypt 41()                        -> stream object (0 on failure)
ctcrypt 43(stream, 0, key)          -> u32    bind key/algorithm to the stream
ctcrypt 94(stream, in, n, out, &out_n, &position, is_final) -> u32
ctcrypt 42(stream) / 23(key)        free
ctcrypt  1(stream, &detail)         error query
```

`ctcrypt 94` is fed the whole plaintext-of-the-capsule region; the position
pointer is ledger state the SDK owns. The EXE passes a `flush` flag computed as
"this is the last chunk in the 4096-block window" (`sub_140058170`); the worker
passes `is_final` on the final read of each entry, which yields byte-exact
output on both sample books.

**Container entry metadata** (`sub_14012C3B0` / `sub_14012C4E0`) confirm the
`DNBA`/`DNBF` magics and that both byte orders are recognised. Encrypted
entries carry flag bit `0x1000`; `index.bin` is plaintext (`flag 0`) and is
copied through unchanged.

---

## 5. Pipeline stages, macOS vs Windows (implemented)

| macOS backend (`dmmb_offline_dump_mac.m`) | Windows backend | status |
|---|---|---|
| `dlopen` viewer + CypherGuard | viewer already hosts the SDK; worker injected | done |
| allow-list init + context init | `ctlicis 2` + `cguard 8/18/38/15/39/12` (viewer startup) | done (by the viewer) |
| `CPSecurityLibraryManager sharedManager` + 3 inits | same startup handshake | done (by the viewer) |
| `capsulizedFileWithContentsOfFile:error:` | `ctlicis 32` + `ctlicis 34(handle,file,8)` | done |
| `loadServiceToCapsulizedFile:` + `lookupLocalLicense` + `applyLicense` | `ctlicis 79` + `304(auth,capsule,0x2000)` | done (offline) |
| `__CPIR_3gCXLasSyrMNtB58:` (16-byte key) | `ctlicis 106(capsule,key)` | done |
| `__CPIR_lvQQsXOCAF0pDlss` (unlock charge) | `ctlicis 36(capsule)` | done |
| `packagingFilesSummary` + per-entry decryptors | `DNBA` walk + `ctcrypt 41/43/94` stream | done |
| output original bytes + `manifest.json` | same | done |

---

## 6. Implementation in this repo

| file | role |
|---|---|
| `dmmb_offline_win.py` | driver/CLI: `doctor`, `inspect`, `dump`; builds both binaries |
| `dmmb_offline_dump_win.cpp` | controller: parses the capsule, finds/starts the viewer, injects the worker, reports |
| `dmmb_offline_worker_win.cpp` | worker DLL: runs the SDK pipeline inside the viewer and writes files + `manifest.json` |
| `dmmb_win_common.h` | shared container parser + key-free IPC struct |
| `docs/windows.md` | this document |

### Why the worker runs inside the viewer

The SDK only finishes initialization inside the process that ran the app's
startup sequence (the `ctlicis 2` / `cguard 8…` handshake plus the window-bound
context). A standalone host calling those ordinals directly gets `2`
(failure), and there is no supported way to recreate that state. So the
controller injects a tiny worker DLL (`LoadLibraryW` via `CreateRemoteThread`)
into the running viewer, calls the exported `DmmbExtract`, and removes the DLL
afterwards. The controller and worker are both ours — nothing is injected into
a third-party process.

The worker:

- never calls `ctlicis 3` (engine shutdown) or the `cguard` init path — the
  viewer owns those, and the worker must not disturb them;
- only touches the capculed-file/auth/key/stream objects it allocates, and each
  has its own release ordinal (`33` / `301` / `23` / `42`);
- never performs network I/O: it uses only the cached-license path (`304 …,
  0x2000`);
- writes real output only after a successful `ctcrypt 94`, commit-by-rename;
  interrupted or failing entries leave at most a `*.partial` file;
- names each output file after the **detected content kind** (`.jpg`/`.png`/
  `.zip`/`.xml`) so Windows opens it directly, while `manifest.json` records the
  original entry name (`"name"`) alongside the on-disk `"file"`;
- writes the pages **in reading order**. The capsule stores entries in an
  arbitrary physical order (e.g. `0034, 0031, 0037, …`), but the entry filename
  is the page id and ascending page id is the order the viewer displays. The
  worker sorts by that page id and prefixes each file with its reading position
  (`0000_0001.jpg … 0101_0102.jpg`); entries with non-numeric names
  (`index.bin`) keep their relative position at the end.

### Communication contract (key-free)

Only paths, progress counters and a diagnostic message cross the process
boundary (`struct dmmb::Request` in `dmmb_win_common.h`). No decrypted bytes,
key material or handles are exchanged. The manifest is formatted **inside** the
worker, so only paths and lengths leave.

### Build

```powershell
python dmmb_offline_win.py build      # host + worker (MSVC 2022, x64)
python dmmb_offline_win.py doctor     # install + license store + ordinal report
python dmmb_offline_win.py inspect book.dmmb
python dmmb_offline_win.py dump    book.dmmb out_win
```

---

## 7. Scope, limits, and failure modes

- **Format scope:** multi-file v1 capsules (footer size `0x3c`, the `.dmmb`
  flavour) with `DNBA` entries in layout 1 (u32 CRC32) or layout 2 (SHA-256),
  using `ctlicis` auth type **2**. Unsupported capsules are rejected with exit
  4 before the viewer is touched.
- **Version scope:** the DLL ordinals are pinned to the versions in §2; `dump`
  refuses to run against a different set rather than guess. `doctor` still
  reports what it resolves.
- **License scope:** offline only. A capsule with no cached license exits **2**
  with the "open it once while online" hint; the web/HTTP licence acquisition
  path is deliberately not implemented.
- **Keep the viewer idle** while extracting: the worker runs on the viewer's
  own thread, so a busy viewer slows it down. If the worker does not return in
  time the controller exits rather than freeing memory a live thread still
  references.
- **Do not stress-test against a live retail license.** The SDK is used exactly
  as the viewer uses it, offline, on own-content copies. The `huk`/`hif`/`info`
  device state lives on the machine; running this against a borrowed store is
  not supported.

Out of scope (kept out on purpose): reimplementing any cipher, extracting or
logging keys, deriving the service key from `huk`/`hif`, and the server-backed
license-issue/lookup flow.
