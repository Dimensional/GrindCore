"""MSVC for the reference builders on Windows (build_7zip_ref.py, build_zstd_ref.py, build_lz4_ref.py): Visual Studio's
vcvarsall, found with vswhere, for the target architecture, and a .def for the names a reference must export. The C
compiler is MSVC's default (/Gd), so a reference's callbacks are __cdecl even on x86, where GrindCore's are __stdcall
(/Gz). Stdlib only, Python 3.6+."""
import os
import platform
import struct
import subprocess
import sys


def arch_name(arch=None):
    """x64, x86 or arm64: `arch` if given, else this host's CPU, else this Python's bitness."""
    if arch:
        return arch
    m = platform.machine().lower()
    if m in ("arm64", "aarch64"):
        return "arm64"
    if struct.calcsize("P") == 4:
        return "x86"
    return "x64"


def vswhere():
    return os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                        "Microsoft Visual Studio", "Installer", "vswhere.exe")


def write_def(path, functions, data=()):
    with open(path, "w") as f:
        f.write("EXPORTS\n" + "".join("  %s\n" % n for n in functions) + "".join("  %s DATA\n" % n for n in data))


def run(arch, steps, cwd):
    """Run cmd steps (joined with &&) in cwd after vcvarsall for `arch`; exits on failure. An arm64 target on an x64
    host cross-compiles (vcvarsall x64_arm64), as CI does."""
    component = "Microsoft.VisualStudio.Component.VC.Tools." + ("ARM64" if arch == "arm64" else "x86.x64")
    vs = subprocess.check_output([vswhere(), "-latest", "-products", "*", "-requires", component, "-property",
                                  "installationPath"], universal_newlines=True).strip().splitlines()
    if not vs:
        sys.exit("no Visual Studio with %s (vswhere found none)" % component)
    vcvars = os.path.join(vs[0], "VC", "Auxiliary", "Build", "vcvarsall.bat")
    host = platform.machine().lower()
    vcarch = "x64_arm64" if arch == "arm64" and host in ("amd64", "x86_64") else arch
    line = 'call "%s" %s >nul && %s' % (vcvars, vcarch, " && ".join(steps))
    print(line)
    # one string with /s: a list would be re-quoted with \" escapes, which cmd.exe doesn't understand
    r = subprocess.call('cmd /d /s /c "%s"' % line, cwd=cwd)
    if r:
        sys.exit("build failed (%d)" % r)
