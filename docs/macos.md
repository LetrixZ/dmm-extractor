# DMM capsule (`.dmmb`) — format, DRM, and macOS notes

Part of the two-platform [dmmb-tools](../README.md) project. The **container
format** below is identical on macOS and Windows; everything specific to the
Windows viewer stack and its backend lives in [`windows.md`](windows.md).

Analysis of **DMMbookviewer 3.1.32.0** (macOS) and a sample multi-file capsule.

- Binary: `/Applications/DMMbookviewer.app/Contents/MacOS/DMMbookviewer`
  - x86_64 Mach-O, 6,379,152 bytes
  - md5 `a2457fe1ee89d92317e5ebaf76630def`
  - sha256 `6af578fe2d022b12e6b569c4c424ff047e1e34ae8dce13581b711dd18594e4ef`
- IDA session: `dmmbookviewer` (DB at `/private/tmp/opencode/dmmre/DMMbookviewer.bin.i64`), annotated.
- Sample: a ~118 MB multi-file v1 capsule (not included in this repo).
- Helper: `dmmb_inspect.py` (parses the **unencrypted** structure only).

> Scope: this documents the container format and the macOS app's architecture.
> It does **not** describe or implement key unwrapping / content decryption.

---

## 1. TL;DR

A `.dmmb` is a **capsule**: an INI metadata block, a `DNBE` marker, a `DNBF` directory
footer, and a chain of `DNBA` file entries. Image payloads (`.dmmj`) are encrypted
(AES‑PCTS, key wrapped and bound to the account/device); the manifest `index.bin` and
the DRM footer are stored in the clear. The DRM is **CypherGuard** (CypherTec): the
viewer's `CypherGuard.framework` does the crypto, and `CPSecurityLibraryManager` /
`CPLicenseIssueRequest` / `CPLicenseLookupRequest` obtain a *service key* from the
license server, after which the capsule is unlocked.

---

## 2. Container layout

```
0x00            small fixed preamble (14 bytes)
0x14            UTF-16LE INI  "[general] ..."  (BOM FF FE)
~0xEE           "DNBE" + u32 total file size, zero padded
~0x1F0          header / fileinfo block  (duplicated by index.bin)
0x7AE ...       chain of DNBA entries (header + payload each)
EOF-60          "DNBF" directory footer (15 x u32)
```

### 2.1 Metadata INI

```
[general]
version=1.1
page_info=0
content_id=123456
capsulize_date=2026/01/02 3:04:5
sample_edition=0
```

### 2.2 Version detection

`cp_detect_capsule_version` (0x1000DC41A) reads a **u32 LE at EOF‑4**; the value equals
the footer size and selects the parser class:

| value | size | class | format |
|---|---|---|---|
| `0x90` | 144 | `__CPIR_uzQWB2uzytOOTYU_` | single‑file v1 (`.dmmr`) |
| `0xF6` | 246 | `__CPIR_uzQWB2uzytOOTYU_` | single‑file v2 |
| `0x3C` | 60  | `__CPIR_bhuR4T3uiwkfp8iH` | **multi‑file v1 (`.dmmb`)** |
| `0x60` | 96  | `__CPIR_bhuR4T3uiwkfp8iH` | multi‑file v2 |

Entry point: `+[CPCapsulizedFile capsulizedFileWithContentsOfFile:error:]` (0x1000e5878).

### 2.3 `DNBF` footer

`cp_read_capsule_footer_DNBF` (0x1000DA9B4): seek `EOF-60`, read 15 × u32; field 0 must be `DNBF`.

| idx | sample value | meaning |
|---|---|---|
| 0 | `DNBF` | magic |
| 1 | `0x1F2` | contents‑name offset |
| 2 | `0` | contents‑name length (chars) |
| **3** | `0x7AE` | **first DNBA entry offset** |
| **4** | `0x67` (103) | **entry count** |
| 5 | `0x070A45D7` | (data region end) |
| 6 | `0xDFC0` | (size) |
| 7 | `0x1F2` | — |
| 10 | `0x206` | (fileinfo header offset) |
| 11 | `0x00010200` | version/flags |
| **12** | `0x206` | **DRM footer offset** |
| 14 | `0x3C` | footer size (== version byte) |

### 2.4 `DNBA` entries

`cp_read_entry_magic_DNBA` (0x1000DAD3C) reads the 8‑byte prefix:
`"DNBA"` | `u16 version` (must be 0) | `u16 layout` (1 = V1, 2 = V2).
Then `cp_read_entry_header_v1/v2` parse the body at `base = entry+8`.

**V1 body** (`cp_read_entry_header_v1`, 0x1000DADBA):

| off | type | meaning |
|---|---|---|
| +0x00 | u32 | flag — bit0 = checksum present, **bit12 `0x1000` = payload encrypted** |
| +0x04 | u32 | attributes (0x80 on files) |
| +0x08 | u64 | mtime (Windows FILETIME) |
| +0x10 | u32 | payload size |
| +0x14 | u32 | CRC32 of stored payload |
| +0x18 | u16 | filename length (chars incl. NUL) |
| +0x1A | u16 | pad length |
| +0x1C | UTF‑16LE | filename (`\` → `/`) |

`data_offset = base + 0x1C + 2*nameLen + padLen`; `next_entry = data_offset + size`.

**V2 body** (`cp_read_entry_header_v2`, 0x1000DAFBE): same idea but `u64 size` at +0x10,
**SHA‑256[32] at +0x18** instead of CRC32, nameLen at +0x38, filename at +0x3C.

Sample entry `0034.dmmj`: flag `0x1000`, attrs `0x80`, mtime `2026-01-02 03:04:05`,
size `0x100000` (1,048,576), crc32 `A1B2C3D4`, data @ `0x7E6`.
Verified: `next = data_offset + size` holds for all 103 entries.

---

## 3. DRM footer (`_cp_footer1`)

`cp_read_drm_footer1` (0x1000DA380): read `u64 size` at `DNBF[12]`, then the 144‑byte
struct at `DNBF[12] + size − 136`. For this file: `DNBF[12]=0x206`, `size=1440`, struct @ `0x71E`.

| field | off | sample | note |
|---|---|---|---|
| var0/var1 | 0x00/0x02 | 1 / 1 | version |
| var2 | 0x04 | `0x00300002` | — |
| var4 | 0x0C | `0x474` | — |
| var5 | 0x10 | `0x9C` | — |
| **preiv** | 0x1C | `00112233445566778899aabbccddeeff` | 16‑byte IV precursor |
| blk2 | 0x2C | `ffeeddccbbaa99887766554433221100` | 16‑byte block |
| sha256 | 0x3C | `00…00` | 32‑byte hash (zero here) |
| fileinfo_delta | 0x5C | 0 | + `drm_off + 8` = fileinfo offset |
| fileinfo_size | 0x60 | `0x470` (1136) | fileinfo blob length |
| flags | 0x68 | `00 00 06 00` | — |
| **guid** | 0x6C | `67452301 ab89 efcd 0123456789abcdef` | → **`01234567-89AB-CDEF-0123-456789ABCDEF`** |
| var19 | 0x7C | `"ctlic.dll\0…"` | license client module name |
| var20 | 0x8C | `0x90` | — |

**Cross‑check:** the GUID decodes to `01234567-89AB-CDEF-0123-456789ABCDEF`, which is
exactly the directory name under
`/Users/Shared/.Cypher License Information/Services/` — i.e. footer1's GUID keys the
local license cache. The fileinfo blob is at `0x20E` (526), length 1136.

---

## 4. `index.bin` / fileinfo (TLV manifest)

`cp_parse_fileinfo_tlv` (0x1000DC75C) parses it into a dictionary keyed by the type id:

```
header : u32 @ +0 (0x00010000) ; u32 count @ +4 ; records start at +8
record : u32 size (incl. 8-byte hdr) | u32 type | payload[size-9]
```

| type | kind |
|---|---|
| 1, 7, 0x16 | UTF‑16 string (`\n` unescaped) |
| 2, 3, 4, 6 | string (parsed) — **type 4 = raw ASCII** (the server URL) |
| 8, 9 | string → number |
| 0xA | UTF‑8 string via `NSScanner` (also sets keys 10 & 24) |
| 0xB | string → number |
| 0xC | file list (newline‑separated) — *not handled by the parser, skipped* |
| 0xD | XML (`NSXMLDocument`, key 13) |

**This file's `index.bin`** (entry, plaintext, 1440 bytes, crc‑checked):

| type | value |
|---|---|
| 1 | `DMM.com(同人)` |
| 12 | 103 filenames, newline‑separated |
| 4 | `http://virgo.cypherlicense.com/luigi/servlet/CypherServer` |

followed by a **304‑byte trailing blob** = the license record (`03 00 00 00` + ciphertext).

The same 1136‑byte fileinfo is also embedded near the file start (at `0x20E`); `index.bin`
is a duplicate so the reader can find the manifest from either end.

---

## 5. Struct reference (from the binary's C++ type library)

```
GUID_t       = { u32; u16; u16; u8[8] }                       // 16 B

_cp_footer1  = { u16; u16; u32 x6; u8[16]; u8[16]; u8[32];
                 u32; u32; u32; u8 x4; GUID_t; u8[16]; u32; i64; u64 }   // 160 B
_cp_footer2  = { GUID_t; u16 x2; u32 x2; u64 x3; u8[32]; u8[16]; u8[16];
                 u8[32]; u64 x2; u8[32]; u8 x2; GUID_t; char[16]; u32; i64; u64 } // 272 B
_cp_fileInfo1= { char[4]; u32; u16 x2; u32 x7; u16 x2; i32 x3; i64;
                 u32 x3; u16 x2; u8[16]; int[15]; char* }               // 168 B
_cp_fileInfo2= { GUID_t; char[4]; u32; u16 x2; u8[32]; u16 x2; i32;
                 int[16]; i64; u32; char[8]; char[4]; i16 x2; char* x2 } // 184 B
```

`_cp_footer1`/`_cp_footer2` are the DRM footers (v1/v2); `_cp_fileInfo1`/`_cp_fileInfo2`
are the fileinfo headers. `footer2`/`fileInfo2` belong to the v2 capsule variants
(`0x60`/`0xF6`) and are not exercised by this v1 file.

---

## 6. License / DRM flow

Classes: `CPCapsulizedFile`, `CPSecurityLibraryManager`, `CPLicenseIssueRequest`,
`CPLicenseLookupRequest`, `_CPDRMInfoV1/V2_OBF`, `_CPPackagingFileSummary`,
`___AccountNote`, and `drm::cypherguard::ctcore_handle<CPCapsulizedFile>`.
Crypto primitives live in `CypherGuard.framework`.

**Request builders**

- `+[CPLicenseIssueRequest requestForCapsulizedFile:]` (0x1000E60F1)
  - reads `authenticationType` (1/2/3), `serviceID`, `contentsID`
  - validates service ID / content ID / auth type against an allow‑list singleton
    (`__CPIR_t_0C8i9vQfEfuH2v`); raises `CPUseRightsException` otherwise
  - builds a request via
    `initWithServerURL_:serviceID_:policyID_:contentsID_:type_:authBeforeIssue_`
  - attaches a context object (`serviceName`, `messageFlag`)
  - when auth type 2/3 + automatic auth, pulls `userID`/`password` from `___AccountNote`
    (keyed by NSUserDefaults `"<serviceID>:AuthAsDefaultKey"`)
- `+[CPLicenseLookupRequest requestForLeashedCapsulizedFile:]` (0x1000E6CA1)
  - builds a lookup with `serviceID`, `contentsID`, `policyID`, `serverURL`, `revocable=1`

**Service resolution**

`-[CPSecurityLibraryManager loadServiceToCapsulizedFile:error:]` (0x1000E3623)
1. if `isOffline` → error 256
2. validate `serviceID` against the allow‑list
3. look up a cached license; if `isValid`, apply its `serviceKey` to the capsule
   (`__CPIR_7S9UatrW3q4a87OH:__CPIR_U6KYLdRHorN5IewD:`)
4. otherwise perform a server request over `serverURL` (progress‑dialog variants) and
   apply the returned `serviceKey`

**Endpoints observed in strings**

```
http://virgo.cypherlicense.com/luigi/servlet/CypherServer   (embedded in the capsule)
https://api.book.dmm.com/1.0/drm/auth/
https://accounts.dmm.com/service/login/...
dev.cyphertec.jp
appid=pc_dmmbooks   authkey=...
```

**Local cache** (`/Users/Shared/.Cypher License Information/Services/<GUID>/`):
`info`, `Policies/`, `Contents/<id>/`, `huk` (device key) — all stored encrypted.

---

## 7. This file at a glance

| | |
|---|---|
| content_id | 123456 |
| capsule | multi‑file v1 (`.dmmb`), ~118 MB |
| entries | 103 (102 encrypted `.dmmj`, 1 plaintext `index.bin`) |
| entry layout | V1 (CRC32), flag `0x1000` = encrypted |
| service GUID | `01234567-89AB-CDEF-0123-456789ABCDEF` |
| preiv | `00112233445566778899aabbccddeeff` |
| license URL | `http://virgo.cypherlicense.com/luigi/servlet/CypherServer` |

---

## 8. IDA annotations applied

Renamed (saved in the IDB):

```
0x1000DC41A cp_detect_capsule_version      0x1000DADBA cp_read_entry_header_v1
0x1000DA9B4 cp_read_capsule_footer_DNBF    0x1000DAEB8 cp_read_entry_filename_v1
0x1000DAD3C cp_read_entry_magic_DNBA       0x1000DAFBE cp_read_entry_header_v2
0x1000DA380 cp_read_drm_footer1            0x1000DB0BC cp_read_entry_filename_v2
0x1000DC75C cp_parse_fileinfo_tlv          0x1000E0F96 cp_read_contents_name
0x1000E1F1C cp_filetime_to_date            0x1000DCEE0/DCFFB/DD108/DD245/DD351 cp_tlv_add_*
```

Function comments added at each (version table, DNBF field map, V1/V2 bodies, footer1
offsets, TLV type table).

---

## 9. Helper script

`dmmb_inspect.py <file.dmmb>` prints JSON: metadata, footer fields, every entry
(name/size/flags/mtime/checksum/offsets), the `index.bin` TLV, and the DRM footer1
fields + fileinfo TLV. It reads **only** the plaintext structure — it performs no
decryption and needs no keys.
