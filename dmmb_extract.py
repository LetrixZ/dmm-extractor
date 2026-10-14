#!/usr/bin/env python3
"""
dmmb_extract.py -- extract original page images for a DMM doujin you own.

What it does:
  1. Parses the UNENCRYPTED structure of a .dmmb capsule (INI / DNBF / DNBA /
     index.bin manifest) and writes manifest.json + any plaintext entries.
  2. Downloads the ORIGINAL page JPEGs through the official DMM web viewer
     APIs using YOUR OWN DMM session cookies (login_secure_id /
     login_session_id, or a full Cookie header). Same account that owns the
     book; no capsule crypto is reimplemented.

Why not decrypt the .dmmb directly in Python:
  .dmmj payloads are encrypted with CypherGuard (AES-PCTS family); the content
  key is unwrapped inside CypherGuard.framework / DMMbookviewer from a
  device-bound service key + license server response (see docs/macos.md,
  section 6). Reimplementing that unwrapping in pure Python would mean
  extracting device keys and cloning proprietary crypto -- fragile and a DRM
  bypass. The web viewer path below uses the licensed server-side render of
  the exact same pages (1333x2000 JPEGs) with your own credentials.

Inputs (one of):
  --cookie 'login_secure_id=...; login_session_id=...; ...'
  --cookie-file cookies.txt            (raw Cookie header or Netscape jar)
  --login-secure-id ... --login-session-id ...
  or env DMM_COOKIE / LOGIN_SECURE_ID / LOGIN_SESSION_ID
  Optional CloudFront signed cookies (auto-captured from the API session when
  the server sets them; pass explicitly only if your session needs it):
  --cloudfront-cookie 'CloudFront-Key-Pair-Id=...; CloudFront-Policy=...; CloudFront-Signature=...'

Examples:
  python3 dmmb_extract.py --dmmb book.dmmb --doujin-id d_012345 --out pages_out --cookie 'login_secure_id=...; login_session_id=...'
  python3 dmmb_extract.py --dmmb book.dmmb --doujin-id d_012345 --out pages_out --manifest-only
  python3 dmmb_extract.py --dmmb book.dmmb --dry-run

Outputs in --out:
  manifest.json      parsed capsule + download plan
  clear/             plaintext capsule entries (index.bin, ...)
  pages/*.jpg        original page images (cover first)
"""
import argparse
import base64
import http.cookiejar
import json
import os
import struct
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

EPOCH = datetime(1601, 1, 1)
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")


# ------------------------------------------------------------ capsule parsing
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


def parse_ini(data):
    bom = data.find(b"\xff\xfe", 0, 0x100)
    if bom < 0:
        return {}
    end = data.find(b"D\x00N\x00B\x00E\x00", bom)
    if end < 0:
        end = 0x200
    out = {}
    for line in data[bom + 2:end].decode("utf-16le", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("[") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k] = v
    return out


FOOTER_FIELDS = ["magic", "contents_name_off", "contents_name_len",
                 "first_entry_off", "entry_count", "field5", "field6",
                 "field7", "field8", "field9", "field10", "field11",
                 "drm_footer_off", "field13", "footer_size"]


def parse_footer(data):
    fo = len(data) - 60
    vals = [u32(data, fo + 4 * i) for i in range(15)]
    d = {FOOTER_FIELDS[i]: vals[i] for i in range(15)}
    d["_off"] = fo
    d["magic"] = struct.pack("<I", vals[0]).decode("latin1")
    return d


def parse_entries(data, first, count):
    entries = []
    off = first
    for _ in range(count):
        if data[off:off + 4] != b"DNBA":
            break
        typ = u16(data, off + 6)
        base = off + 8
        if typ == 1:
            flag = u32(data, base)
            size = u32(data, base + 16)
            nlen, pad = u16(data, base + 24), u16(data, base + 26)
            name = utf16(data, base + 28, nlen)
            doff = base + 28 + 2 * nlen + pad
        else:
            flag = u32(data, base)
            size = u64(data, base + 16)
            nlen, pad = u16(data, base + 56), u16(data, base + 58)
            name = utf16(data, base + 60, nlen)
            doff = base + 60 + 2 * nlen + pad
        entries.append({"name": name, "offset": off, "data_offset": doff,
                        "size": size, "layout": typ,
                        "encrypted": bool(flag & 0x1000), "flag": flag})
        off = doff + size
    return entries


def parse_tlv(blob):
    if len(blob) < 8:
        return []
    count = u32(blob, 4)
    recs, pos = [], 8
    for _ in range(count):
        if pos + 8 > len(blob):
            break
        size, typ = u32(blob, pos), u32(blob, pos + 4)
        if size < 9 or pos + size > len(blob):
            break
        recs.append({"type": typ, "size": size,
                     "payload": blob[pos + 8:pos + size - 1]})
        pos += size
    return recs


def index_file_list(blob):
    for r in parse_tlv(blob):
        if r["type"] == 12:
            return r["payload"].decode("utf-8", "replace").splitlines()
    return []


def parse_dmmb(path):
    with open(path, "rb") as f:
        data = f.read()
    meta = parse_ini(data)
    foot = parse_footer(data)
    entries = parse_entries(data, foot["first_entry_off"], foot["entry_count"])
    idx = next((e for e in entries if e["name"] == "index.bin"), None)
    files = (index_file_list(data[idx["data_offset"]:idx["data_offset"] + idx["size"]])
             if idx else [])
    return {"data": data, "metadata": meta, "footer": foot,
            "entries": entries, "index_files": files, "index_entry": idx}


# ----------------------------------------------------------------- HTTP layer
# A shared cookie jar: configuration_pack.json replies with Set-Cookie for
# CloudFront-Key-Pair-Id / CloudFront-Policy / CloudFront-Signature
# (Domain=dmm.co.jp). Those must be replayed to the *.contents.doujin.dmm.co.jp
# hosts, so we capture them by name and force-attach on image downloads.
_JAR = http.cookiejar.CookieJar()
_OPENER = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_JAR))
CLOUDFRONT_COOKIE_NAMES = ("CloudFront-Key-Pair-Id", "CloudFront-Policy",
                           "CloudFront-Signature")


def cloudfront_cookie_header():
    parts = []
    for c in _JAR:
        if c.name in CLOUDFRONT_COOKIE_NAMES:
            parts.append(f"{c.name}={c.value}")
    return "; ".join(parts)


def full_cookie_header(session_cookie, extra=""):
    cf = cloudfront_cookie_header()
    bits = [b for b in (session_cookie.strip("; "), cf, extra.strip("; "))
            if b]
    seen, out = set(), []
    for bit in "; ".join(bits).split(";"):
        bit = bit.strip()
        if not bit or bit.split("=", 1)[0] in seen:
            continue
        seen.add(bit.split("=", 1)[0])
        out.append(bit)
    return "; ".join(out)
def build_cookie_header(args):
    if args.cookie:
        return args.cookie.strip()
    if args.cookie_file:
        txt = open(args.cookie_file, encoding="utf-8").read().strip()
        if txt.startswith("#") or "\t" in txt:  # Netscape jar -> last fields
            parts = []
            for line in txt.splitlines():
                if not line or line.startswith("#"):
                    continue
                cols = line.split("\t")
                if len(cols) >= 7:
                    parts.append(f"{cols[5]}={cols[6]}")
            return "; ".join(parts)
        return txt.splitlines()[0] if "\n" in txt else txt
    env = os.environ.get("DMM_COOKIE", "")
    if env:
        return env
    sid = args.login_secure_id or os.environ.get("LOGIN_SECURE_ID", "")
    sess = args.login_session_id or os.environ.get("LOGIN_SESSION_ID", "")
    if sid and sess:
        return f"login_secure_id={sid}; login_session_id={sess}"
    return ""


def api_get(url, cookie, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Cookie": cookie,
                                               "Accept": "application/json"})
    with _OPENER.open(req, timeout=timeout) as r:
        return r.read(), r.headers


def api_get_json(url, cookie, timeout=30):
    raw, _ = api_get(url, cookie, timeout)
    return json.loads(raw.decode("utf-8"))


def get_folder_structure(doujin_id, cookie):
    url = ("https://www.dmm.co.jp/dc/doujin/api/mylibraries/"
           f"folder-structures/{doujin_id}")
    body = api_get_json(url, cookie)
    return body["data"]


def get_configuration_pack(reader_id, start, end, cookie, shop="adult_doujin"):
    def fetch(payload):
        b64 = base64.b64encode(payload.encode()).decode()
        url = ("https://www.dmm.co.jp/dc/doujin/api/viewers/contents/"
               f"{b64}/configuration_pack.json")
        return api_get_json(url, cookie)
    try:
        return fetch(f"product_id={reader_id},start_file_no={start},"
                     f"end_file_no={end}")["configuration"]
    except Exception:
        return fetch(f"shop={shop},product_id={reader_id},start_file_no={start},"
                     f"end_file_no={end}")["configuration"]


def content_root_from_icon(icon_url):
    """https://host/bb/st_doujin/d_012/d_012345st/d_012345st0001t.jpg
    -> https://host/bb/st_doujin/d_012/d_012345st"""
    p = urllib.parse.urlsplit(icon_url)
    segs = p.path.rstrip("/").split("/")
    segs = segs[:-1]  # drop thumbnail filename
    return f"{p.scheme}://{p.netloc}" + "/".join(segs) if segs[0] == "" else \
        f"{p.scheme}://{p.netloc}/" + "/".join(s for s in segs if s)


def download_page(session_cookie, page_url, timeout=60, tries=4, extra=""):
    last = None
    for i in range(tries):
        try:
            cookie = full_cookie_header(session_cookie, extra)
            req = urllib.request.Request(page_url, headers={
                "User-Agent": UA, "Cookie": cookie,
                "Referer": "https://www.dmm.co.jp/", "Accept": "image/*,*/*"})
            with _OPENER.open(req, timeout=timeout) as r:
                blob = r.read()
            if len(blob) > 2 and blob[:2] == b"\xff\xd8":
                return blob
            last = f"bad magic {blob[:8].hex()} len={len(blob)}"
        except Exception as e:
            last = str(e)
        time.sleep(1.5 * (i + 1))
    raise RuntimeError(f"GET {page_url}: {last}")


# ------------------------------------------------------------------------ main
def _utf8():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main(argv=None):
    _utf8()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dmmb", required=True)
    ap.add_argument("--doujin-id", default="",
                    help="e.g. d_012345 (folder id from DMM library)")
    ap.add_argument("--reader-id", default="",
                    help="e.g. d_012345st (from folder-structures; overrides lookup)")
    ap.add_argument("--out", default="dmmb_out")
    ap.add_argument("--cookie", default="")
    ap.add_argument("--cookie-file", default="")
    ap.add_argument("--login-secure-id", default="")
    ap.add_argument("--login-session-id", default="")
    ap.add_argument("--cloudfront-cookie", default="",
                    help="extra CloudFront cookies appended to session cookie")
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=0)
    ap.add_argument("--manifest-only", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--dump-enc", action="store_true",
                    help="also dump raw encrypted .dmmj payloads as .enc (not decrypted)")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args(argv)

    cap = parse_dmmb(a.dmmb)
    data, meta = cap["data"], cap["metadata"]
    entries, files = cap["entries"], cap["index_files"]
    enc = sum(1 for e in entries if e["encrypted"])
    print(f"capsule: {a.dmmb} ({len(data)} bytes) content_id={meta.get('content_id')}")
    print(f"entries: {len(entries)} ({enc} encrypted, "
          f"{len(entries) - enc} plaintext), index list: {len(files)} files")

    os.makedirs(a.out, exist_ok=True)
    cleardir = os.path.join(a.out, "clear")
    os.makedirs(cleardir, exist_ok=True)
    for e in entries:
        if not e["encrypted"]:
            p = os.path.join(cleardir, os.path.basename(e["name"]))
            if a.overwrite or not os.path.exists(p):
                with open(p, "wb") as f:
                    f.write(data[e["data_offset"]:e["data_offset"] + e["size"]])
    if a.dump_enc:
        encdir = os.path.join(a.out, "enc")
        os.makedirs(encdir, exist_ok=True)
        for e in entries:
            if e["encrypted"]:
                p = os.path.join(encdir, os.path.basename(e["name"]) + ".enc")
                if a.overwrite or not os.path.exists(p):
                    with open(p, "wb") as f:
                        f.write(data[e["data_offset"]:e["data_offset"] + e["size"]])

    manifest = {"dmmb": os.path.basename(a.dmmb), "size": len(data),
                "metadata": meta,
                "entries": [{k: e[k] for k in ("name", "size", "encrypted",
                                              "flag", "layout")} for e in entries],
                "index_files": files, "doujin_id": a.doujin_id,
                "note": ("Encrypted .dmmj payloads are NOT decrypted locally; "
                         "page images below come from the licensed web viewer.")}

    cookie = build_cookie_header(a)
    if a.cloudfront_cookie:
        cookie = (cookie + "; " + a.cloudfront_cookie.strip("; ")) if cookie \
            else a.cloudfront_cookie
    if a.dry_run or a.manifest_only or not cookie:
        if not cookie and not (a.dry_run or a.manifest_only):
            print("no DMM session cookie given; wrote manifest + clear/ only.",
                  file=sys.stderr)
        manifest["pages"] = []
        json.dump(manifest, open(os.path.join(a.out, "manifest.json"), "w"),
                  indent=2, ensure_ascii=False)
        print(f"wrote {a.out}/manifest.json + {len(os.listdir(cleardir))} clear files")
        return 0

    if not a.doujin_id and not a.reader_id:
        print("need --doujin-id (e.g. d_012345) or --reader-id", file=sys.stderr)
        return 2

    struct_data = get_folder_structure(a.doujin_id, cookie) if not a.reader_id \
        else None
    reader_id = a.reader_id or struct_data["name"]
    lib_files = struct_data["files"] if struct_data else []
    if a.start <= 0:
        a.start = lib_files[0]["imageNo"] if lib_files else 1
    if a.end <= 0:
        a.end = lib_files[-1]["imageNo"] if lib_files else a.start
    print(f"library: reader_id={reader_id} imageNo {a.start}..{a.end}")

    config = get_configuration_pack(reader_id, a.start, a.end, cookie)
    contents = config.get("contents", [])
    if not contents:
        raise SystemExit("configuration_pack.json returned no contents")
    icons = [f.get("icon") for f in lib_files if f.get("icon")]
    root = content_root_from_icon(icons[0]) if icons else None
    if not root:
        raise SystemExit("cannot derive content root (no icon URL in library)")
    print(f"content root: {root}, pages: {len(contents)}")

    pages, pagedir = [], os.path.join(a.out, "pages")
    os.makedirs(pagedir, exist_ok=True)
    for i, c in enumerate(contents):
        xhtml = c.get("file", "")
        stem = os.path.splitext(os.path.basename(xhtml.replace("\\", "/")))[0]
        url = f"{root}/item/xhtml/{stem}.xhtml/0.jpeg"
        outp = os.path.join(pagedir, f"{i:04d}_{stem}.jpg")
        if os.path.exists(outp) and not a.overwrite:
            pages.append({"index": i, "xhtml": xhtml, "url": url,
                          "file": os.path.basename(outp), "cached": True})
            continue
        blob = download_page(cookie, url)
        with open(outp, "wb") as f:
            f.write(blob)
        pages.append({"index": i, "xhtml": xhtml, "url": url,
                      "file": os.path.basename(outp), "bytes": len(blob)})
        print(f"[{i + 1}/{len(contents)}] {stem} {len(blob)} bytes")
    manifest["reader_id"] = reader_id
    manifest["content_root"] = root
    manifest["pages"] = pages
    json.dump(manifest, open(os.path.join(a.out, "manifest.json"), "w"),
              indent=2, ensure_ascii=False)
    print(f"done: {len(pages)} images in {pagedir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
