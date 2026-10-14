// Runs inside the installed viewer, after its official SDK initialization.
// Ordinal signatures are from DMMbookviewer 3.2.0.0; see docs/windows.md.
#include "dmmb_win_common.h"
#include <memory>

namespace {
using namespace dmmb;
using Object = void*;
template<class F> F Export(HMODULE module, WORD ordinal) {
  auto p = GetProcAddress(module, MAKEINTRESOURCEA(ordinal));
  if (!p) throw Failure(4, "Missing SDK ordinal " + std::to_string(ordinal));
  return reinterpret_cast<F>(p);
}
struct Sdk {
  HMODULE lic = nullptr, crypt = nullptr;
  Object capsule = nullptr, auth = nullptr, key = nullptr, stream = nullptr;
  Object (*create_capsule)() = nullptr;
  void (*free_capsule)(Object) = nullptr;
  uint32_t (*open)(Object, const wchar_t*, uint32_t) = nullptr;
  uint32_t (*capsule_error)(Object, uint32_t*) = nullptr;
  uint32_t (*auth_type)(Object) = nullptr;
  Object (*create_auth)() = nullptr;
  void (*free_auth)(Object) = nullptr;
  uint32_t (*local)(Object, Object, uint32_t) = nullptr;
  uint32_t (*auth_error)(Object, uint32_t*) = nullptr;
  Object (*create_key)() = nullptr;
  void (*free_key)(Object) = nullptr;
  uint32_t (*transfer)(Object, Object) = nullptr;
  uint32_t (*finalize)(Object) = nullptr;
  Object (*create_stream)() = nullptr;
  void (*free_stream)(Object) = nullptr;
  uint32_t (*configure)(Object, uint32_t, Object) = nullptr;
  uint32_t (*decrypt)(Object, const void*, uint32_t, void*, uint32_t*, uint64_t*, BOOL) = nullptr;
  uint32_t (*crypt_error)(Object, uint32_t*) = nullptr;

  ~Sdk() {
    if (stream && free_stream) free_stream(stream);
    if (key && free_key) free_key(key);
    if (auth && free_auth) free_auth(auth);
    if (capsule && free_capsule) free_capsule(capsule);
    if (crypt) FreeLibrary(crypt);
    if (lic) FreeLibrary(lic);
  }
  std::string Error(uint32_t (*f)(Object, uint32_t*), Object obj) {
    uint32_t detail = 0, code = f(obj, &detail);
    return "SDK error " + std::to_string(code) + "/" + std::to_string(detail);
  }
  void Open(const fs::path& path) {
    // The viewer owns initialization and shutdown. Never initialize or shut down
    // its global engine from the worker. Module presence alone is not readiness.
    for (unsigned attempt = 0; attempt < 120; ++attempt) {
      if (GetModuleHandleExW(0, L"ctlicis.dll", &lic)) break;
      Sleep(500);
    }
    if (!lic) throw Failure(4, "Viewer did not load ctlicis.dll within 60 seconds");
#define L(member, ordinal) member = Export<decltype(member)>(lic, ordinal)
    L(create_capsule, 32); L(free_capsule, 33); L(open, 34); L(capsule_error, 92);
    L(auth_type, 79); L(create_auth, 300); L(free_auth, 301); L(local, 304);
    L(auth_error, 258); L(transfer, 106); L(finalize, 36);
#undef L
    for (unsigned attempt = 0; attempt < 120; ++attempt) {
      capsule = create_capsule();
      if (!capsule) throw Failure(3, "SDK capsule allocation failed");
      if (open(capsule, path.c_str(), 8)) break;
      uint32_t detail = 0, code = capsule_error(capsule, &detail);
      if (code != 3 || attempt == 119) throw Failure(3, "Open DRM block: " + Error(capsule_error, capsule));
      free_capsule(capsule); capsule = nullptr;
      Sleep(500);
    }
    if (auth_type(capsule) != 2) throw Failure(3, "Unsupported SDK authentication type (expected cached-license type 2)");
    auth = create_auth();
    if (!auth) throw Failure(3, "SDK authentication allocation failed");
    // This is the viewer's fast cached-license path. Its HTTP provider and
    // service/license acquisition fallback are never invoked by this worker.
    if (!local(auth, capsule, 0x2000))
      throw Failure(2, "Cached license rejected: " + Error(auth_error, auth) +
          ". Open this book once in DMMbookviewer while online, then retry.");
    wchar_t exe[32768];
    DWORD n = GetModuleFileNameW(nullptr, exe, _countof(exe));
    if (!n || n == _countof(exe)) throw Failure(4, "Cannot locate viewer installation");
    crypt = LoadLibraryExW((fs::path(exe).parent_path() / L"ctcrypt.dll").c_str(),
                           nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!crypt) throw Failure(4, WinError("Load ctcrypt.dll"));
#define C(member, ordinal) member = Export<decltype(member)>(crypt, ordinal)
    C(create_key, 22); C(free_key, 23); C(create_stream, 41); C(free_stream, 42);
    C(configure, 43); C(decrypt, 94); C(crypt_error, 1);
#undef C
    key = create_key();
    if (!key) throw Failure(3, "SDK key-object allocation failed");
    if (!transfer(capsule, key)) throw Failure(3, "Apply license: " + Error(capsule_error, capsule));
    if (!finalize(capsule)) throw Failure(3, "Finalize license: " + Error(capsule_error, capsule));
    stream = create_stream();
    if (!stream) throw Failure(3, "SDK decrypt-stream allocation failed");
    if (!configure(stream, 0, key)) throw Failure(3, "Configure decryptor: " + Error(crypt_error, stream));
  }
};
struct Temporary {
  fs::path path;
  ~Temporary() { if (!path.empty()) DeleteFileW(path.c_str()); }
};
std::string Kind(const std::vector<uint8_t>& b) {
  if (b.size() >= 3 && b[0] == 255 && b[1] == 216 && b[2] == 255) return "jpeg";
  if (b.size() >= 4 && b[0] == 'P' && b[1] == 'K') return "zip";
  if (b.size() >= 4 && !memcmp(b.data(), "\x89PNG", 4)) return "png";
  if (b.size() >= 5 && !memcmp(b.data(), "<?xml", 5)) return "xml";
  return "bin";
}
void Commit(const fs::path& temp, const fs::path& dest) {
  if (!MoveFileExW(temp.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    throw Failure(4, WinError("Commit output"));
}
DWORD Extract(Request& r) {
  Input input(r.input);
  auto cap = Parse(input);
  fs::path out(r.output);
  fs::create_directories(out);
  // A fresh staging directory prevents collisions with another extraction.
  wchar_t tempdir[32768], tempname[32768];
  DWORD n = GetTempPathW(_countof(tempdir), tempdir);
  if (!n || n >= _countof(tempdir) || !GetTempFileNameW(tempdir, L"dmm", 0, tempname))
    throw Failure(4, WinError("Create temporary DRM file"));
  Temporary drmfile{tempname};
  {
    Handle f(CreateFileW(drmfile.path.c_str(), GENERIC_WRITE, 0, nullptr,
                         TRUNCATE_EXISTING, FILE_ATTRIBUTE_TEMPORARY, nullptr));
    if (f.h == INVALID_HANDLE_VALUE) throw Failure(4, WinError("Open temporary DRM file"));
    uint8_t b[65536];
    for (uint64_t off = 0; off < cap.drm_size;) {
      DWORD amount = static_cast<DWORD>(std::min<uint64_t>(sizeof(b), cap.drm_size - off));
      input.Read(cap.drm_offset + off, b, amount); Write(f.h, b, amount); off += amount;
    }
  }
  Sdk sdk;
  sdk.Open(drmfile.path);
  std::string manifest = "[\n", first_error;
  bool io_failure = false;
  const auto order = ReadingOrder(cap);
  for (size_t position = 0; position < order.size(); ++position) {
    const auto& e = cap.entries[order[position]];
    try {
      if (e.flags & ~0x1001u) throw Failure(3, "Unsupported entry flags: " + std::to_string(e.flags));
      auto name = OutputName(e, position);
      Temporary tmp{out / (name + L".partial")};
      uint64_t written = 0, stream_position = 0;
      std::vector<uint8_t> prefix;
      {
        Handle f(CreateFileW(tmp.path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
        if (f.h == INVALID_HANDLE_VALUE) {
          tmp.path.clear(); // Do not delete an existing file belonging to another run.
          throw Failure(4, WinError("Create output"));
        }
        uint8_t encrypted[4096], plain[4096];
        for (uint64_t off = 0; off < e.size;) {
          DWORD count = static_cast<DWORD>(std::min<uint64_t>(sizeof(encrypted), e.size - off));
          input.Read(e.offset + off, encrypted, count);
          uint32_t got = count;
          const void* bytes = encrypted;
          if (e.flags & 0x1000) {
            got = sizeof(plain);
            if (!sdk.decrypt(sdk.stream, encrypted, count, plain, &got, &stream_position, off + count == e.size))
              throw Failure(3, "Decrypt entry: " + sdk.Error(sdk.crypt_error, sdk.stream));
            if (got > sizeof(plain)) throw Failure(3, "Invalid SDK output length");
            bytes = plain;
          }
          Write(f.h, bytes, got);
          if (prefix.size() < 5) {
            auto p = static_cast<const uint8_t*>(bytes);
            prefix.insert(prefix.end(), p, p + std::min<size_t>(got, 5 - prefix.size()));
          }
          written += got; off += count;
        }
      }
      const std::string kind = Kind(prefix);
      const std::wstring file = WithKindExtension(name, kind);
      Commit(tmp.path, out / file);
      tmp.path.clear(); // The file now lives at its final name.
      if (r.ok++) manifest += ",\n";
      manifest += "  {\"index\": " + std::to_string(position) + ", \"name\": " + Json(Utf8(e.name)) +
          ", \"file\": " + Json(Utf8(file)) + ", \"bytes\": " + std::to_string(written) +
          ", \"encrypted\": " + ((e.flags & 0x1000) ? "true" : "false") +
          ", \"expected_size\": " + std::to_string(e.size) + ", \"kind\": " + Json(kind) + "}";
    } catch (const Failure& ex) {
      ++r.failed;
      io_failure |= ex.code == 4;
      if (first_error.empty()) first_error = "Entry " + std::to_string(position) + ": " + ex.what();
    }
  }
  manifest += "\n]\n";
  Temporary tempmanifest{out / L"manifest.json.partial"};
  {
    Handle f(CreateFileW(tempmanifest.path.c_str(), GENERIC_WRITE, 0, nullptr,
                        CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (f.h == INVALID_HANDLE_VALUE) { tempmanifest.path.clear(); throw Failure(4, WinError("Create manifest")); }
    if (manifest.size() > MAXDWORD) throw Failure(4, "Manifest too large");
    Write(f.h, manifest.data(), static_cast<DWORD>(manifest.size()));
  }
  Commit(tempmanifest.path, out / L"manifest.json");
  tempmanifest.path.clear();
  strncpy_s(r.message, first_error.c_str(), _TRUNCATE);
  return io_failure ? 4 : r.failed ? 3 : 0;
}
} // namespace

extern "C" __declspec(dllexport) DWORD WINAPI DmmbExtract(void* argument) {
  auto* r = static_cast<dmmb::Request*>(argument);
  if (!r || r->magic != 0x444d4d42 || r->version != 1 ||
      r->input[_countof(r->input) - 1] || r->output[_countof(r->output) - 1]) return 4;
  try { return Extract(*r); }
  catch (const dmmb::Failure& ex) {
    strncpy_s(r->message, ex.what(), _TRUNCATE); return ex.code;
  } catch (const std::exception& ex) {
    strncpy_s(r->message, ex.what(), _TRUNCATE); return 4;
  } catch (...) {
    strcpy_s(r->message, "Unexpected worker exception"); return 3;
  }
}
