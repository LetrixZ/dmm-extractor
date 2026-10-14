// Windows offline .dmmb extractor: controller for the in-viewer SDK worker.
// Build both binaries with: python dmmb_offline_win.py build
//   (or manually, from this directory:
//      cl /nologo /std:c++17 /EHsc /W4 /MT /utf-8 /D_CRT_SECURE_NO_WARNINGS ^
//         dmmb_offline_dump_win.cpp /Fe:dmmb_offline_dump_win.exe /link version.lib
//      cl /nologo /std:c++17 /EHsc /W4 /MT /utf-8 /D_CRT_SECURE_NO_WARNINGS /LD ^
//         dmmb_offline_worker_win.cpp /Fe:dmmb_offline_worker_win.dll )
// The worker DLL reuses the installed viewer's initialized SDK and cached
// license; both binaries must sit next to each other.
// See docs/windows.md for supported versions and recovered signatures.
// Run:
//   dmmb_offline_dump_win.exe doctor
//   dmmb_offline_dump_win.exe inspect <file.dmmb>
//   dmmb_offline_dump_win.exe decrypt <file.dmmb> <outdir>
// Exit codes (match the macOS helper): 0 ok, 2 no local license,
//                                      3 decrypt failure, 4 usage/io error.
#include "dmmb_win_common.h"
#include <winver.h>
#include <tlhelp32.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <memory>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "user32.lib")

namespace {

// --- the ordinals DMMbookviewer.exe actually imports (see notes §2) ---------
const unsigned short kCguardOrdinals[] = {17, 16, 8, 18, 38, 15, 39, 12, 20};
const unsigned short kCtlicisOrdinals[] = {
    306, 307, 49,  314, 42,  311, 89,  79,  601, 603, 602, 300, 304, 302,
    301, 34,  106, 36,  258, 92,  57,  33,  32,  7,   2,   3,   88,  332};
const unsigned short kCtcryptOrdinals[] = {43, 23, 42, 41, 22, 94, 1};

const wchar_t* kDefaultInstall = L"C:\\Program Files\\DMM\\DMMbookviewer";
const wchar_t* kDefaultLicense = L"C:\\Cypher License Information";

// --- tiny helpers -----------------------------------------------------------
std::wstring Widen(const std::string& s) {
  if (s.empty()) return L"";
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
  std::wstring w(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
  return w;
}
std::string Narrow(const std::wstring& w) {
  if (w.empty()) return "";
  int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0,
                              nullptr, nullptr);
  std::string s(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr,
                      nullptr);
  return s;
}
bool Exists(const std::wstring& p) {
  DWORD a = GetFileAttributesW(p.c_str());
  return a != INVALID_FILE_ATTRIBUTES;
}

std::string FileVersion(const std::wstring& path) {
  DWORD dummy = 0, len = GetFileVersionInfoSizeW(path.c_str(), &dummy);
  if (!len) return "?";
  std::vector<BYTE> buf(len);
  if (!GetFileVersionInfoW(path.c_str(), 0, len, buf.data())) return "?";
  VS_FIXEDFILEINFO* fi = nullptr;
  UINT flen = 0;
  if (!VerQueryValueW(buf.data(), L"\\", (void**)&fi, &flen) || !fi) return "?";
  char s[64];
  snprintf(s, sizeof(s), "%u.%u.%u.%u", HIWORD(fi->dwProductVersionMS),
           LOWORD(fi->dwProductVersionMS), HIWORD(fi->dwProductVersionLS),
           LOWORD(fi->dwProductVersionLS));
  return s;
}

// True when the PE has a Themida section (packed => name-stripped ordinals).
bool IsThemida(const std::wstring& path) {
  HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                         OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  std::vector<char> data;
  DWORD sz = GetFileSize(h, nullptr);
  if (sz != INVALID_FILE_SIZE && sz < (64u << 20)) {
    data.resize(sz);
    DWORD got = 0;
    ReadFile(h, data.data(), sz, &got, nullptr);
    data.resize(got);
  }
  CloseHandle(h);
  const char* needle = ".themida";
  for (size_t i = 0; i + 8 <= data.size(); ++i)
    if (memcmp(data.data() + i, needle, 8) == 0) return true;
  return false;
}

std::wstring Join(const std::wstring& dir, const std::wstring& name) {
  if (dir.empty()) return name;
  wchar_t last = dir.back();
  return dir + (last == L'\\' || last == L'/' ? L"" : L"\\") + name;
}

// --- environment ------------------------------------------------------------
struct Env {
  std::wstring install = kDefaultInstall;
  std::wstring license = kDefaultLicense;
};

int Doctor(const Env& env) {
  printf("install dir : %s\n", Narrow(env.install).c_str());
  printf("license dir : %s\n\n", Narrow(env.license).c_str());

  struct Dll { const wchar_t* name; unsigned short const* ords; int n; };
  const Dll dlls[] = {
      {L"cguard.dll", kCguardOrdinals, (int)(sizeof(kCguardOrdinals) / 2)},
      {L"ctlicis.dll", kCtlicisOrdinals, (int)(sizeof(kCtlicisOrdinals) / 2)},
      {L"ctcrypt.dll", kCtcryptOrdinals, (int)(sizeof(kCtcryptOrdinals) / 2)},
  };

  int resolved_total = 0, ord_total = 0;
  for (const Dll& d : dlls) {
    ord_total += d.n;
    std::wstring p = Join(env.install, d.name);
    if (!Exists(p)) {
      printf("  %-12s MISSING (%s)\n", Narrow(d.name).c_str(), Narrow(p).c_str());
      continue;
    }
    HMODULE h = LoadLibraryExW(p.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!h) {
      printf("  %-12s load failed (err %lu)\n", Narrow(d.name).c_str(),
             GetLastError());
      continue;
    }
    int ok = 0;
    for (int i = 0; i < d.n; ++i)
      if (GetProcAddress(h, MAKEINTRESOURCEA(d.ords[i]))) ++ok;
    resolved_total += ok;
    printf("  %-12s v%-9s %s  ordinals %d/%d resolved\n",
           Narrow(d.name).c_str(), FileVersion(p).c_str(),
            IsThemida(p) ? "[Themida-packed]" : "[plain]", ok, d.n);
    FreeLibrary(h);
  }

  printf("\nlicense store:\n");
  std::wstring services = Join(env.license, L"Services");
  if (!Exists(services)) {
    printf("  (none at %s)\n", Narrow(services).c_str());
    return 2;
  }
  int nsvc = 0, ncont = 0;
  WIN32_FIND_DATAW fd;
  HANDLE f = FindFirstFileW(Join(services, L"*").c_str(), &fd);
  if (f == INVALID_HANDLE_VALUE) {
    printf("  (empty)\n");
    return 2;
  }
  do {
    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
    if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
      continue;
    ++nsvc;
    printf("  %s\n", Narrow(fd.cFileName).c_str());
    std::wstring contents = Join(Join(services, fd.cFileName), L"Contents");
    WIN32_FIND_DATAW cd;
    HANDLE c = FindFirstFileW(Join(contents, L"*").c_str(), &cd);
    if (c != INVALID_HANDLE_VALUE) {
      do {
        if (!(cd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(cd.cFileName, L".") == 0 || wcscmp(cd.cFileName, L"..") == 0)
          continue;
        printf("      %s\n", Narrow(cd.cFileName).c_str());
        ++ncont;
      } while (FindNextFileW(c, &cd));
      FindClose(c);
    }
  } while (FindNextFileW(f, &fd));
  FindClose(f);
  printf("  services: %d, cached contents: %d\n", nsvc, ncont);
  printf("\nordinals resolved: %d/%d\n", resolved_total, ord_total);
  return resolved_total == ord_total ? 0 : 4;
}

// --- capsule: pull service GUID + content_id --------------------------------
int Inspect(const Env& env, const std::wstring& capsule) {
  dmmb::Input in(capsule);
  auto cap = dmmb::Parse(in);
  printf("capsule     : %s\n", Narrow(capsule).c_str());
  printf("entries     : %zu\n", cap.entries.size());
  printf("service GUID: %s\n", cap.guid.c_str());
  printf("content_id  : %u  -> Contents\\C%08X\n", cap.content, cap.content);
  std::wstring lic = dmmb::LicensePath(env.license, cap).wstring();
  printf("local license present: %s\n",
         Exists(Join(lic, L"info")) ? "YES" : "no");
  printf("  %s\n", Narrow(lic).c_str());
  return Exists(Join(lic, L"info")) ? 0 : 2;
}

uintptr_t ModuleBase(DWORD pid, const wchar_t* filename) {
  dmmb::Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
  if (snap.h == INVALID_HANDLE_VALUE) throw dmmb::Failure(4, dmmb::WinError("Enumerate viewer modules"));
  MODULEENTRY32W m{}; m.dwSize = sizeof(m);
  if (Module32FirstW(snap.h, &m)) do {
    if (!_wcsicmp(m.szModule, filename)) return reinterpret_cast<uintptr_t>(m.modBaseAddr);
  } while (Module32NextW(snap.h, &m));
  return 0;
}

DWORD FindViewer(const std::wstring& exe) {
  dmmb::Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (snap.h == INVALID_HANDLE_VALUE) throw dmmb::Failure(4, dmmb::WinError("Enumerate processes"));
  PROCESSENTRY32W p{}; p.dwSize = sizeof(p);
  DWORD found = 0;
  if (Process32FirstW(snap.h, &p)) do {
    if (_wcsicmp(p.szExeFile, L"DMMbookviewer.exe")) continue;
    dmmb::Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.th32ProcessID));
    wchar_t path[32768]; DWORD n = _countof(path);
    if (!h.h || !QueryFullProcessImageNameW(h.h, 0, path, &n))
      throw dmmb::Failure(4, "Cannot access running viewer; run viewer and tool as the same user");
    if (_wcsicmp(path, exe.c_str())) continue;
    if (found) throw dmmb::Failure(4, "Multiple matching viewers are running; close extra instances");
    found = p.th32ProcessID;
  } while (Process32NextW(snap.h, &p));
  return found;
}

uintptr_t RemoteSystemFunction(DWORD pid, const char* name) {
  auto proc = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), name);
  MEMORY_BASIC_INFORMATION info{};
  if (!proc || !VirtualQuery(reinterpret_cast<void*>(proc), &info, sizeof(info)))
    throw dmmb::Failure(4, "Cannot resolve Windows loader function");
  wchar_t path[32768];
  if (!GetModuleFileNameW(static_cast<HMODULE>(info.AllocationBase), path, _countof(path)))
    throw dmmb::Failure(4, dmmb::WinError("Locate loader module"));
  auto remote = ModuleBase(pid, dmmb::fs::path(path).filename().c_str());
  if (!remote) throw dmmb::Failure(4, "Viewer loader module is missing");
  return remote + reinterpret_cast<uintptr_t>(proc) - reinterpret_cast<uintptr_t>(info.AllocationBase);
}

DWORD RemoteCall(HANDLE process, uintptr_t proc, void* argument, DWORD timeout) {
  dmmb::Handle thread(CreateRemoteThread(process, nullptr, 0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(proc), argument, 0, nullptr));
  if (!thread.h) throw dmmb::Failure(4, dmmb::WinError("Start viewer worker"));
  DWORD wait = WaitForSingleObject(thread.h, timeout);
  if (wait != WAIT_OBJECT_0) {
    // Do not free a running thread's code or argument memory. The controller
    // exits; the viewer retains them until it exits, rather than risking UAF.
    fprintf(stderr, "Viewer worker did not finish; close the viewer before retrying.\n");
    ExitProcess(4);
  }
  DWORD result = 4;
  if (!GetExitCodeThread(thread.h, &result)) throw dmmb::Failure(4, dmmb::WinError("Worker result"));
  return result;
}
struct RemoteMemory {
  HANDLE process;
  void* p;
  RemoteMemory(HANDLE h, const void* data, size_t size) : process(h),
      p(VirtualAllocEx(h, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
    if (!p) throw dmmb::Failure(4, dmmb::WinError("Allocate worker request"));
    if (!WriteProcessMemory(h, p, data, size, nullptr)) {
      VirtualFreeEx(h, p, 0, MEM_RELEASE); throw dmmb::Failure(4, dmmb::WinError("Write worker request"));
    }
  }
  ~RemoteMemory() { VirtualFreeEx(process, p, 0, MEM_RELEASE); }
};
int Decrypt(const Env& env, const std::wstring& capsule, const std::wstring& outdir) {
  using namespace dmmb;
  const auto input = fs::absolute(capsule).lexically_normal();
  const auto out = fs::absolute(outdir).lexically_normal();
  Input in(input);
  const auto cap = Parse(in);
  if (!fs::is_regular_file(LicensePath(env.license, cap) / L"info")) {
    fprintf(stderr, "No cached license. Open the book once in DMMbookviewer while online, then retry.\n");
    return 2;
  }
  if (_wcsicmp(env.license.c_str(), kDefaultLicense))
    throw Failure(4, "DMM_LICENSE_DIR is an inspection override; the viewer SDK uses its own machine license store");
  const auto exe = fs::absolute(fs::path(env.install) / L"DMMbookviewer.exe").lexically_normal();
  if (FileVersion(exe.wstring()) != "3.2.0.0" ||
      FileVersion(Join(env.install, L"ctlicis.dll")) != "3.1.6.9" ||
      FileVersion(Join(env.install, L"ctcrypt.dll")) != "2.0.6.2")
    throw Failure(4, "Unsupported installed SDK: expected viewer 3.2.0.0, ctlicis 3.1.6.9, ctcrypt 2.0.6.2");
  wchar_t self[32768];
  DWORD n = GetModuleFileNameW(nullptr, self, _countof(self));
  if (!n || n == _countof(self)) throw Failure(4, "Cannot locate worker directory");
  auto dll = fs::path(self).parent_path() / L"dmmb_offline_worker_win.dll";
  if (!fs::is_regular_file(dll)) throw Failure(4, "Missing worker DLL; run python dmmb_offline_win.py build");
  // Serialize this tool's SDK sessions, including sessions from other terminals.
  Handle mutex(CreateMutexW(nullptr, FALSE, L"Local\\DmmbOfflineDumpWorkerV1"));
  if (!mutex.h) throw Failure(4, WinError("Create worker lock"));
  DWORD lock = WaitForSingleObject(mutex.h, 0);
  if (lock != WAIT_OBJECT_0 && lock != WAIT_ABANDONED) throw Failure(4, "Another offline extraction is running");
  struct Unlock { HANDLE h; ~Unlock() { ReleaseMutex(h); } } unlock{mutex.h};
  DWORD pid = FindViewer(exe.wstring());
  if (!pid) {
    std::wstring command = L"\"" + exe.wstring() + L"\"";
    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_SHOWMINNOACTIVE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, exe.parent_path().c_str(), &si, &pi))
      throw Failure(4, WinError("Start DMMbookviewer"));
    Handle started(pi.hProcess), mainthread(pi.hThread);
    pid = pi.dwProcessId;
    WaitForInputIdle(started.h, 60000);
    fprintf(stderr, "Started DMMbookviewer (PID %lu).\n", pid);
  }
  Handle process(OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
      PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid));
  if (!process.h) throw Failure(4, WinError("Open viewer process"));
  auto request = std::make_unique<Request>();
  if (input.wstring().size() >= _countof(request->input) || out.wstring().size() >= _countof(request->output))
    throw Failure(4, "Path too long");
  wcscpy_s(request->input, input.c_str()); wcscpy_s(request->output, out.c_str());
  const auto dllpath = dll.wstring();
  // Load locally to obtain the exported worker's RVA, never an EXE-private RVA.
  HMODULE local = LoadLibraryExW(dll.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
  if (!local) throw Failure(4, WinError("Map worker DLL"));
  auto entry = GetProcAddress(local, "DmmbExtract");
  if (!entry) { FreeLibrary(local); throw Failure(4, "Worker DLL export is missing"); }
  uintptr_t offset = reinterpret_cast<uintptr_t>(entry) - reinterpret_cast<uintptr_t>(local);
  FreeLibrary(local);
  RemoteMemory remote_path(process.h, dllpath.c_str(), (dllpath.size() + 1) * sizeof(wchar_t));
  RemoteCall(process.h, RemoteSystemFunction(pid, "LoadLibraryW"), remote_path.p, 60000);
  auto base = ModuleBase(pid, dll.filename().c_str());
  if (!base) throw Failure(4, "Viewer could not load worker DLL");
  struct Unload {
    HANDLE process; DWORD pid; uintptr_t base;
    ~Unload() { try { RemoteCall(process, RemoteSystemFunction(pid, "FreeLibrary"), reinterpret_cast<void*>(base), 60000); } catch (...) {} }
  } unload{process.h, pid, base};
  RemoteMemory remote_request(process.h, request.get(), sizeof(Request));
  fprintf(stderr, "Using viewer PID %lu; extracting %zu entries with its cached license...\n", pid, cap.entries.size());
  DWORD rc = RemoteCall(process.h, base + offset, remote_request.p, 30 * 60 * 1000);
  if (!ReadProcessMemory(process.h, remote_request.p, request.get(), sizeof(Request), nullptr))
    throw Failure(4, WinError("Read worker result"));
  request->message[sizeof(request->message) - 1] = 0;
  if (request->message[0]) fprintf(stderr, "%s\n", request->message);
  if (rc > 4) {
    fprintf(stderr, "Worker terminated unexpectedly (0x%08lx).\n", rc); return 3;
  }
  fprintf(stderr, "done: %u ok, %u failed -> %s\n", request->ok, request->failed, Utf8(out.wstring()).c_str());
  return static_cast<int>(rc);
}

}  // namespace

int Run(int argc, wchar_t** argv) {
  SetConsoleOutputCP(CP_UTF8);
  Env env;
  if (const wchar_t* e = _wgetenv(L"DMMBOOKVIEWER_DIR")) env.install = e;
  if (const wchar_t* e = _wgetenv(L"DMM_LICENSE_DIR")) env.license = e;

  std::wstring cmd = argc > 1 ? argv[1] : L"doctor";
  if (cmd == L"doctor") return Doctor(env);
  if (cmd == L"inspect") {
    if (argc < 3) { printf("usage: inspect <file.dmmb>\n"); return 4; }
    return Inspect(env, argv[2]);
  }
  if (cmd == L"decrypt") {
    if (argc < 4) { printf("usage: decrypt <file.dmmb> <outdir>\n"); return 4; }
    return Decrypt(env, argv[2], argv[3]);
  }
  if (argc == 3) return Decrypt(env, argv[1], argv[2]);
  printf("usage: dmmb_offline_dump_win.exe {doctor|inspect <f>|decrypt <f> <out>}\n");
  return 4;
}

int wmain(int argc, wchar_t** argv) {
  try { return Run(argc, argv); }
  catch (const dmmb::Failure& ex) { fprintf(stderr, "%s\n", ex.what()); return ex.code; }
  catch (const std::exception& ex) { fprintf(stderr, "%s\n", ex.what()); return 4; }
}
