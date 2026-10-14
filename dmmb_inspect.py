#!/usr/bin/env python3
"""
dmmb_inspect.py -- reader for the UNENCRYPTED structure of a DMM "capsule" (.dmmb).

This does NOT decrypt anything. It only parses the container framing and the
plaintext manifest (index.bin / fileinfo) that the DMMbookviewer reads before
any license is applied:

    [INI metadata][DNBE][ ... header/fileinfo ... ][DNBA entries...][DNBF footer]

Reverse-engineered from DMMbookviewer 3.1.32.0 (see the accompanying notes).
"""
import json
import struct
import sys
from datetime import datetime, timedelta

EPOCH = datetime(1601, 1, 1)


def _utf8():
    """Windows consoles default to cp1252; titles are Japanese. Force UTF-8."""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def filetime(q):
    try:
        return (EPOCH + timedelta(microseconds=q / 10)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def utf16(b, o, nchars):
    return b[o:o + 2 * nchars].decode("utf-16le", "replace").rstrip("\x00")


# ---------------------------------------------------------------- metadata INI
def parse_ini(data):
    # UTF-16LE "[general]..." block sits near the start (BOM ff fe)
    bom = data.find(b"\xff\xfe", 0, 0x100)
    if bom < 0:
        return {}
    end = data.find(b"D\x00N\x00B\x00E\x00", bom)  # up to "DNBE"
    if end < 0:
        end = 0x200
    txt = data[bom + 2:end].decode("utf-16le", "replace")
    out = {}
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


# ---------------------------------------------------------------- DNBF footer
FOOTER_FIELDS = [
    "magic", "contents_name_off", "contents_name_len", "first_entry_off",
    "entry_count", "field5", "field6", "field7", "field8", "field9",
    "field10", "field11", "drm_footer_off", "field13", "footer_size",
]


def parse_footer(data):
    fo = len(data) - 60
    vals = [u32(data, fo + 4 * i) for i in range(15)]
    d = {FOOTER_FIELDS[i]: vals[i] for i in range(15)}
    d["_off"] = fo
    d["magic"] = struct.pack("<I", vals[0]).decode("latin1")
    return d


# ---------------------------------------------------------------- DNBA entries
def parse_entries(data, first, count):
    entries = []
    off = first
    for _ in range(count):
        magic = data[off:off + 4]
        if magic != b"DNBA":
            break
        ver = u16(data, off + 4)
        typ = u16(data, off + 6)
        base = off + 8
        if typ == 1:
            flag = u32(data, base + 0)
            attrs = u32(data, base + 4)
            mtime = u64(data, base + 8)
            size = u32(data, base + 16)
            checksum = u32(data, base + 20)
            nlen = u16(data, base + 24)
            pad = u16(data, base + 26)
            name = utf16(data, base + 28, nlen)
            data_off = base + 28 + 2 * nlen + pad
            algo, chk = "crc32", "%08x" % checksum
        else:  # V2
            flag = u32(data, base + 0)
            attrs = u32(data, base + 4)
            mtime = u64(data, base + 8)
            size = u64(data, base + 16)
            checksum = data[base + 24:base + 56]
            nlen = u16(data, base + 56)
            pad = u16(data, base + 58)
            name = utf16(data, base + 60, nlen)
            data_off = base + 60 + 2 * nlen + pad
            algo, chk = "sha256", checksum.hex()
        entries.append({
            "offset": off, "version": ver, "layout": typ, "flag": flag,
            "flag_encrypted": bool(flag & 0x1000),
            "attributes": attrs, "mtime": filetime(mtime),
            "size": size, "checksum_algo": algo, "checksum": chk,
            "name": name, "data_offset": data_off,
        })
        off = data_off + size
    return entries


# ---------------------------------------------------------------- fileinfo TLV
def parse_tlv(blob):
    """index.bin / fileinfo: u32 @+4 = record count; records = {u32 size, u32 type, payload}."""
    if len(blob) < 8:
        return {"error": "too small"}
    count = u32(blob, 4)
    recs = []
    pos = 8
    for _ in range(count):
        if pos + 8 > len(blob):
            break
        size = u32(blob, pos)
        typ = u32(blob, pos + 4)
        if size < 9 or pos + size > len(blob):
            break
        payload = blob[pos + 8: pos + size - 1]
        recs.append({"type": typ, "size": size, "payload": payload})
        pos += size
    return {"count": count, "records": recs, "trailing": len(blob) - pos}


def describe_tlv(recs):
    out = []
    for r in recs:
        t, p = r["type"], r["payload"]
        if t == 12:
            val = p.decode("utf-8", "replace").splitlines()
            out.append({"type": t, "kind": "file-list", "count": len(val), "files": val})
        elif t in (1, 2, 3, 4, 6, 7, 8, 9, 0xA, 0xB, 0x16):
            try:
                val = p.decode("utf-16le", "replace").rstrip("\x00")
            except Exception:
                val = p.hex()
            out.append({"type": t, "kind": "string", "value": val})
        elif t == 13:
            out.append({"type": t, "kind": "xml", "value": p.decode("utf-8", "replace")})
        else:
            out.append({"type": t, "kind": "blob", "hex": p[:64].hex(), "len": len(p)})
    return out


# ---------------------------------------------------------------- DRM footer1
def parse_footer1(data, drm_off):
    """_cp_footer1: read u64 size at drm_off, struct sits at drm_off+size-136."""
    size = u64(data, drm_off)
    fo = drm_off + size - 136
    f = {
        "var0": u16(data, fo + 0x00), "var1": u16(data, fo + 0x02),
        "var2": u32(data, fo + 0x04), "var3": u32(data, fo + 0x08),
        "var4": u32(data, fo + 0x0c), "var5": u32(data, fo + 0x10),
        "var6": u32(data, fo + 0x14), "var7": u32(data, fo + 0x18),
        "preiv": data[fo + 0x1c:fo + 0x2c].hex(),
        "blk2": data[fo + 0x2c:fo + 0x3c].hex(),
        "sha256": data[fo + 0x3c:fo + 0x5c].hex(),
        "fileinfo_delta": u32(data, fo + 0x5c),
        "fileinfo_size": u32(data, fo + 0x60),
        "var13": u32(data, fo + 0x64),
        "flags": list(data[fo + 0x68:fo + 0x6c]),
        "guid": data[fo + 0x6c:fo + 0x7c].hex(),
        "var19": data[fo + 0x7c:fo + 0x8c].hex(),
        "var20": u32(data, fo + 0x8c),
    }
    f["_size_at_drm_off"] = size
    f["_struct_off"] = fo
    # fileinfo blob = fileinfo_delta + (drm_off + 8) for size fileinfo_size
    fi_off = f["fileinfo_delta"] + drm_off + 8
    f["_fileinfo_off"] = fi_off
    f["_fileinfo_blob"] = data[fi_off:fi_off + f["fileinfo_size"]]
    return f


def main(path):
    data = open(path, "rb").read()
    rep = {"file": path, "size": len(data), "version_byte": hex(u32(data, len(data) - 4))}

    ver = u32(data, len(data) - 4)
    rep["capsule"] = {0x90: "single v1", 0xF6: "single v2",
                      0x3C: "multi v1 (dmmb)", 0x60: "multi v2 (dmmb)"}.get(ver, "?")

    rep["metadata"] = parse_ini(data)
    foot = parse_footer(data)
    rep["footer"] = {k: (hex(v) if isinstance(v, int) else v) for k, v in foot.items()}
    rep["footer"]["magic"] = foot["magic"]

    entries = parse_entries(data, foot["first_entry_off"], foot["entry_count"])
    rep["entry_count"] = len(entries)
    rep["entries"] = entries
    rep["encrypted_entries"] = sum(1 for e in entries if e["flag_encrypted"])
    rep["plaintext_entries"] = [e["name"] for e in entries if not e["flag_encrypted"]]

    # manifest entry (index.bin) is stored in the clear
    idx = next((e for e in entries if e["name"] == "index.bin"), None)
    if idx:
        blob = data[idx["data_offset"]:idx["data_offset"] + idx["size"]]
        rep["index_bin_tlv"] = describe_tlv(parse_tlv(blob)["records"])

    # DRM footer1 + its fileinfo blob
    try:
        f1 = parse_footer1(data, foot["drm_footer_off"])
        blob = f1.pop("_fileinfo_blob")
        rep["drm_footer1"] = f1
        rep["fileinfo_tlv"] = describe_tlv(parse_tlv(blob)["records"])
    except Exception as e:
        rep["drm_footer1_error"] = str(e)

    print(json.dumps(rep, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    _utf8()
    main(sys.argv[1] if len(sys.argv) > 1 else "book.dmmb")
