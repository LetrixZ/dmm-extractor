#!/usr/bin/env python3
"""
dmmb_offline_win.py -- Windows driver/CLI for the offline .dmmb extractor.

The Windows driver, sibling of dmmb_offline_mac.py. On Windows the viewer's DRM
glue lives inside DMMbookviewer.exe (C++) alongside the Themida-packed
ordinal-only DLLs cguard.dll / ctlicis.dll / ctcrypt.dll, so the backend is a
native C++ host: dmmb_offline_dump_win.cpp. See docs/windows.md.

The native host loads dmmb_offline_worker_win.dll into the installed viewer
(starting the viewer if needed). The worker reuses the initialized official
SDK and its cached-license fast path. It never invokes the HTTP license
provider. Keep the viewer open and idle until extraction completes.

Usage:
  python dmmb_offline_win.py doctor
  python dmmb_offline_win.py inspect <file.dmmb>
  python dmmb_offline_win.py dump <file.dmmb> <outdir>     # builds + runs host
  python dmmb_offline_win.py build [--build-only]

Environment overrides:
  DMMBOOKVIEWER_DIR   install dir   (default C:\\Program Files\\DMM\\DMMbookviewer)
  DMM_LICENSE_DIR     inspection only (the SDK uses its own machine store)

Exit codes (same as the macOS driver): 0 ok, 2 no local license,
                                       3 decrypt failure, 4 usage/io error.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "dmmb_offline_dump_win.cpp")
BIN = os.path.join(HERE, "dmmb_offline_dump_win.exe")
WORKER_SRC = os.path.join(HERE, "dmmb_offline_worker_win.cpp")
WORKER_BIN = os.path.join(HERE, "dmmb_offline_worker_win.dll")
HEADER = os.path.join(HERE, "dmmb_win_common.h")
INSTALL = os.environ.get("DMMBOOKVIEWER_DIR",
                         r"C:\Program Files\DMM\DMMbookviewer")
LICENSE = os.environ.get("DMM_LICENSE_DIR", r"C:\Cypher License Information")


def _utf8():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def sh_shell(cmd, cwd=None):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", cwd=cwd)


# --------------------------------------------------------------- host build
def find_vcvars():
    vswhere = os.path.join(os.environ.get("ProgramFiles(x86)", ""),
                           "Microsoft Visual Studio", "Installer", "vswhere.exe")
    if os.path.isfile(vswhere):
        r = sh([vswhere, "-latest", "-products", "*",
                "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property", "installationPath"])
        root = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
        if root:
            bat = os.path.join(root, "VC", "Auxiliary", "Build", "vcvars64.bat")
            if os.path.isfile(bat):
                return bat
    for base in (r"C:\Program Files\Microsoft Visual Studio\2022",
                 r"C:\Program Files (x86)\Microsoft Visual Studio\2022"):
        for ed in ("Enterprise", "Professional", "Community", "BuildTools"):
            bat = os.path.join(base, ed, "VC", "Auxiliary", "Build",
                               "vcvars64.bat")
            if os.path.isfile(bat):
                return bat
    return None


def build():
    for path in (SRC, WORKER_SRC, HEADER):
        if not os.path.isfile(path):
            print("missing source: %s" % path, file=sys.stderr)
            return 4
    vcvars = find_vcvars()
    cl_in_path = sh(["cmd", "/c", "cl /?"]).returncode == 0
    if vcvars is None and not cl_in_path:
        print("no MSVC found; install VS 2022 C++ tools, then run 'build'. "
              "Manual:\n"
              "  cl /std:c++17 /EHsc dmmb_offline_dump_win.cpp "
              "/Fe:dmmb_offline_dump_win.exe /link version.lib", file=sys.stderr)
        return 4
    flags = 'cl /nologo /std:c++17 /EHsc /W4 /MT /utf-8 /D_CRT_SECURE_NO_WARNINGS '
    builddir = os.path.join(HERE, "build")
    os.makedirs(builddir, exist_ok=True)
    # Keep object files and the worker's import library in build/ (the host and
    # worker binaries themselves live next to the driver, like on macOS).
    compile_cmd = (
        flags + '"%s" /Fe:"%s" /link version.lib user32.lib && ' % (SRC, BIN) +
        flags + '/LD "%s" /Fe:"%s" /link /IMPLIB:"%s"' % (
            WORKER_SRC, WORKER_BIN,
            os.path.join(builddir, "dmmb_offline_worker_win.lib")))
    inner = ('call "%s" >nul 2>&1 && %s' % (vcvars, compile_cmd)
             if vcvars else compile_cmd)
    r = sh_shell(inner, cwd=builddir)
    if r.returncode != 0 or not all(os.path.isfile(p) for p in (BIN, WORKER_BIN)):
        sys.stderr.write((r.stdout or "")[-2000:])
        sys.stderr.write((r.stderr or "")[-2000:])
        return 4
    if r.stdout:
        print(r.stdout.rstrip())
    print("built host + worker in %s" % HERE)
    return 0


def ensure_built():
    if (not all(os.path.isfile(p) for p in (BIN, WORKER_BIN)) or
            max(os.path.getmtime(p) for p in (SRC, WORKER_SRC, HEADER)) >
            min(os.path.getmtime(p) for p in (BIN, WORKER_BIN))):
        return build()
    return 0


# --------------------------------------------------------------- commands
def cmd_doctor(_args):
    if not os.path.isdir(INSTALL):
        print("install not found: %s" % INSTALL, file=sys.stderr)
        return 4
    print("install dir : %s" % INSTALL)
    print("license dir : %s" % LICENSE)
    for dll in ("cguard.dll", "ctlicis.dll", "ctcrypt.dll"):
        p = os.path.join(INSTALL, dll)
        print("  %-12s %s" % (dll, "present" if os.path.isfile(p) else "MISSING"))
    svc = os.path.join(LICENSE, "Services")
    n = 0
    if os.path.isdir(svc):
        for name in os.listdir(svc):
            cont = os.path.join(svc, name, "Contents")
            kids = os.listdir(cont) if os.path.isdir(cont) else []
            print("  %s  contents: %s" % (name, ", ".join(kids) or "(none)"))
            n += len(kids)
    else:
        print("  license store not found: %s" % svc)
    print("cached contents: %d" % n)
    # delegate DLL/ordinal detail to the native host when available
    rc = ensure_built()
    if rc:
        return rc
    r = sh([BIN, "doctor"])
    print("\n[native host]\n" + (r.stdout or "").rstrip())
    sys.stderr.write(r.stderr or "")
    return r.returncode


def cmd_inspect(args):
    if not args:
        print("usage: inspect <file.dmmb>", file=sys.stderr)
        return 4
    path = args[0]
    if not os.path.isfile(path):
        print("no such file: %s" % path, file=sys.stderr)
        return 4
    rc = ensure_built()
    return rc or subprocess.run([BIN, "inspect", os.path.abspath(path)]).returncode


def cmd_dump(args):
    if len(args) < 2:
        print("usage: dump <file.dmmb> <outdir>", file=sys.stderr)
        return 4
    dmmb, outdir = os.path.abspath(args[0]), os.path.abspath(args[1])
    if not os.path.isfile(dmmb):
        print("no such file: %s" % dmmb, file=sys.stderr)
        return 4
    rc = ensure_built()
    if rc:
        return rc
    print("offline dump of %s ..." % os.path.basename(dmmb), flush=True)
    r = subprocess.run([BIN, "decrypt", dmmb, outdir], text=True,
                       encoding="utf-8", errors="replace")
    return r.returncode


def main(argv):
    _utf8()
    if not argv:
        return cmd_doctor([])
    cmd, rest = argv[0], argv[1:]
    if cmd == "doctor":
        return cmd_doctor(rest)
    if cmd == "inspect":
        return cmd_inspect(rest)
    if cmd in ("dump", "decrypt"):
        return cmd_dump(rest)
    if cmd in ("build", "--build-only"):
        return build()
    # drop-in: 1 positional -> inspect, 2 positional -> dump
    if len(argv) == 1 and argv[0].lower().endswith(".dmmb"):
        return cmd_inspect(argv)
    if len(argv) == 2:
        return cmd_dump(argv)
    print("usage: dmmb_offline_win.py {doctor|inspect <f>|dump <f> <out>|build}",
          file=sys.stderr)
    return 4


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except OSError as e:
        print(str(e), file=sys.stderr)
        sys.exit(4)
