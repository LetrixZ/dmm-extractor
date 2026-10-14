// Shared, key-free container/IPC definitions for the Windows host and worker.
#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace dmmb {
namespace fs = std::filesystem;
static_assert(sizeof(void*) == 8, "Build the host and worker for x64");
struct Failure : std::runtime_error {
  int code;
  Failure(int c, const std::string& s) : std::runtime_error(s), code(c) {}
};
inline std::string Utf8(const std::wstring& w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(),
                             static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  if (!n) throw Failure(4, "Invalid UTF-16 filename");
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(),
                      static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
  return s;
}
inline std::wstring Wide(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                             static_cast<int>(s.size()), nullptr, 0);
  if (!n) throw Failure(4, "Invalid UTF-8 string");
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                      static_cast<int>(s.size()), w.data(), n);
  return w;
}
inline std::string WinError(const char* action) {
  return std::string(action) + " (Windows error " + std::to_string(GetLastError()) + ")";
}
struct Handle {
  HANDLE h = INVALID_HANDLE_VALUE;
  explicit Handle(HANDLE v = INVALID_HANDLE_VALUE) : h(v) {}
  ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
};
inline uint16_t U16(const uint8_t* p) {
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
inline uint32_t U32(const uint8_t* p) {
  return p[0] | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t U64(const uint8_t* p) { return U32(p) | (uint64_t(U32(p + 4)) << 32); }
inline void Range(uint64_t off, uint64_t n, uint64_t size) {
  if (off > size || n > size - off) throw Failure(4, "Truncated or invalid capsule range");
}
class Input {
  Handle file;
 public:
  uint64_t size = 0;
  explicit Input(const fs::path& path) : file(CreateFileW(path.c_str(), GENERIC_READ,
      FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)) {
    if (file.h == INVALID_HANDLE_VALUE) throw Failure(4, WinError("Open input"));
    LARGE_INTEGER n{};
    if (!GetFileSizeEx(file.h, &n) || n.QuadPart < 0) throw Failure(4, WinError("Input size"));
    size = static_cast<uint64_t>(n.QuadPart);
  }
  void Read(uint64_t off, void* out, DWORD n) {
    Range(off, n, size);
    LARGE_INTEGER pos{}; pos.QuadPart = static_cast<LONGLONG>(off);
    if (!SetFilePointerEx(file.h, pos, nullptr, FILE_BEGIN)) throw Failure(4, WinError("Seek input"));
    DWORD got = 0;
    if (!ReadFile(file.h, out, n, &got, nullptr) || got != n) throw Failure(4, "Short input read");
  }
  std::vector<uint8_t> Read(uint64_t off, DWORD n) {
    std::vector<uint8_t> b(n); Read(off, b.data(), n); return b;
  }
};
inline void Write(HANDLE h, const void* p, DWORD n) {
  DWORD done = 0;
  if (!WriteFile(h, p, n, &done, nullptr) || done != n) throw Failure(4, WinError("Write output"));
}
struct Entry {
  uint64_t offset = 0, size = 0;
  uint32_t flags = 0;
  std::wstring name;
};
struct Capsule {
  uint64_t drm_offset = 0, drm_size = 0;
  uint32_t content = 0;
  std::string guid;
  std::vector<Entry> entries;
};
inline Capsule Parse(Input& in) {
  Capsule c;
  if (in.size < 60) throw Failure(4, "Capsule is too small");
  auto foot = in.Read(in.size - 60, 60);
  if (U32(foot.data() + 56) != 60)
    throw Failure(4, "Unsupported capsule footer (this tool supports multi-file v1 / 0x3c)");
  if (memcmp(foot.data(), "DNBF", 4)) throw Failure(4, "Missing DNBF footer");
  uint64_t end = in.size - 60;
  uint64_t drm = U32(foot.data() + 48);
  auto n = in.Read(drm, 8);
  c.drm_offset = drm + 8;
  c.drm_size = U64(n.data());
  if (c.drm_size < 144) throw Failure(4, "Invalid DRM block size");
  Range(c.drm_offset, c.drm_size, end);
  auto auth = in.Read(c.drm_offset + c.drm_size - 144, 144);
  if (U32(auth.data() + 140) != 144) throw Failure(4, "Unsupported DRM footer");
  const auto* g = auth.data() + 108;
  char guid[40];
  snprintf(guid, sizeof(guid), "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
      U32(g), U16(g + 4), U16(g + 6), g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
  c.guid = guid;
  auto head = in.Read(0, static_cast<DWORD>(std::min<uint64_t>(in.size, 65536)));
  const std::wstring key = L"content_id=";
  bool found = false;
  for (size_t i = 0; i + key.size() * 2 <= head.size(); ++i) {
    if (memcmp(head.data() + i, key.data(), key.size() * 2)) continue;
    uint64_t value = 0;
    size_t p = i + key.size() * 2, start = p;
    while (p + 1 < head.size() && U16(head.data() + p) >= '0' && U16(head.data() + p) <= '9') {
      value = value * 10 + U16(head.data() + p) - '0';
      if (value > UINT32_MAX) throw Failure(4, "content_id overflow");
      p += 2;
    }
    if (p == start) throw Failure(4, "Invalid content_id");
    c.content = static_cast<uint32_t>(value); found = true; break;
  }
  if (!found) throw Failure(4, "Missing content_id");
  uint64_t off = U32(foot.data() + 12);
  uint32_t count = U32(foot.data() + 16);
  if (!count || count > end / 36) throw Failure(4, "Invalid entry count");
  for (uint32_t i = 0; i < count; ++i) {
    Range(off, 8, end);
    auto prefix = in.Read(off, 8);
    if (memcmp(prefix.data(), "DNBA", 4) || U16(prefix.data() + 4) != 0)
      throw Failure(4, "Invalid DNBA entry header");
    auto type = U16(prefix.data() + 6);
    if (type != 1 && type != 2) throw Failure(4, "Unsupported DNBA entry layout");
    DWORD len = type == 1 ? 28 : 60;
    Range(off + 8, len, end);
    auto b = in.Read(off + 8, len);
    Entry e;
    e.flags = U32(b.data());
    e.size = type == 1 ? U32(b.data() + 16) : U64(b.data() + 16);
    auto nchars = U16(b.data() + len - 4), pad = U16(b.data() + len - 2);
    uint64_t nameoff = off + 8 + len;
    Range(nameoff, uint64_t(nchars) * 2 + pad, end);
    auto name = in.Read(nameoff, static_cast<DWORD>(nchars) * 2);
    for (size_t j = 0; j < name.size(); j += 2) {
      wchar_t ch = U16(name.data() + j);
      if (!ch) {
        if (j + 2 != name.size()) throw Failure(4, "Embedded NUL in entry name");
      } else e.name += ch;
    }
    Utf8(e.name); // Reject malformed UTF-16 before writing any output.
    e.offset = nameoff + uint64_t(nchars) * 2 + pad;
    Range(e.offset, e.size, end);
    c.entries.push_back(e);
    off = e.offset + e.size;
  }
  return c;
}
inline fs::path LicensePath(const fs::path& root, const Capsule& c) {
  wchar_t id[16]; swprintf_s(id, L"C%08X", c.content);
  return root / L"Services" / Wide("{" + c.guid + "}") / L"Contents" / id;
}
inline std::wstring OutputName(const Entry& e, size_t position) {
  std::wstring base = e.name;
  auto p = base.find_last_of(L"/\\");
  if (p != std::wstring::npos) base.erase(0, p + 1);
  for (auto& ch : base)
    if (ch < 32 || std::wstring(L"<>:\"/\\|?*").find(ch) != std::wstring::npos) ch = L'_';
  while (!base.empty() && (base.back() == L'.' || base.back() == L' ')) base.pop_back();
  if (base.empty()) base = L"entry-" + std::to_wstring(position);
  // Leave room for the index and temporary-file suffix within an NTFS component.
  if (base.size() > 200) {
    base.resize(200);
    if (base.back() >= 0xd800 && base.back() <= 0xdbff) base.pop_back();
  }
  wchar_t prefix[32]; swprintf_s(prefix, L"%04zu_", position);
  return prefix + base;
}
// The capsule stores entries in an arbitrary physical order, but the entry
// filename (e.g. "0034.dmmj") is the page id and ascending page id is the
// reading order the viewer itself uses. Entries whose name is not purely
// numeric (e.g. index.bin) sort after the pages, keeping their physical order.
inline bool PageId(const Entry& e, uint64_t* out) {
  std::wstring base = e.name;
  auto slash = base.find_last_of(L"/\\");
  if (slash != std::wstring::npos) base.erase(0, slash + 1);
  auto dot = base.find_last_of(L'.');
  std::wstring stem = dot == std::wstring::npos ? base : base.substr(0, dot);
  if (stem.empty() || stem.size() > 18) return false;
  uint64_t v = 0;
  for (wchar_t ch : stem) {
    if (ch < L'0' || ch > L'9') return false;
    v = v * 10 + static_cast<uint64_t>(ch - L'0');
  }
  *out = v;
  return true;
}
inline std::vector<size_t> ReadingOrder(const Capsule& c) {
  std::vector<size_t> order(c.entries.size());
  for (size_t i = 0; i < order.size(); ++i) order[i] = i;
  std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
    uint64_t pa = 0, pb = 0;
    bool va = PageId(c.entries[a], &pa), vb = PageId(c.entries[b], &pb);
    if (va != vb) return va;               // numeric page names first
    if (va && pa != pb) return pa < pb;    // ascending page id
    return false;                          // stable: keep physical order
  });
  return order;
}
inline std::string Json(const std::string& s) {
  std::string out = "\"";
  for (unsigned char ch : s) {
    if (ch == '"' || ch == '\\') { out += '\\'; out += ch; }
    else if (ch < 32) { char escaped[7]; snprintf(escaped, sizeof(escaped), "\\u%04x", ch); out += escaped; }
    else out += ch;
  }
  return out + '"';
}
// Give decrypted images a file extension Windows will open by double-click.
// The manifest still carries the entry's original name, so nothing is lost.
inline std::wstring WithKindExtension(const std::wstring& name, const std::string& kind) {
  std::wstring ext;
  if (kind == "jpeg") ext = L"jpg";
  else if (kind == "png") ext = L"png";
  else if (kind == "zip") ext = L"zip";
  else if (kind == "xml") ext = L"xml";
  else return name;  // Unknown kind: keep the original entry extension.
  auto dot = name.find_last_of(L'.');
  auto sep = name.find_last_of(L"/\\");
  bool has_ext = dot != std::wstring::npos && dot != 0 &&
                 (sep == std::wstring::npos || dot > sep);
  return has_ext ? name.substr(0, dot + 1) + ext : name + L"." + ext;
}
// Only paths, progress and diagnostics cross the process boundary.
struct Request {
  uint32_t magic = 0x444d4d42;
  uint32_t version = 1;
  wchar_t input[32768]{};
  wchar_t output[32768]{};
  uint32_t ok = 0, failed = 0;
  char message[2048]{};
};
} // namespace dmmb
