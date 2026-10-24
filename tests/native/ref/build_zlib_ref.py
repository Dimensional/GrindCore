"""Build official zlib 1.3.1 and zlib-ng 2.2.1 as shared libraries: the references for gctest/test_zlib.py.

GrindCore vendors .NET 8's zlib 1.3.1 and .NET 9's zlib-ng 2.2.1 (external/dotnet8_0, external/dotnet9_0), with
Nanook's compress3/uncompress3 added (audit/other-codecs.md 4.2.1). The references are the releases themselves:
  zlib 1.3.1     the release tarball (its published SHA-256); the 15 library sources compiled with only the define its
                 configure writes into zconf.h off Windows (Z_HAVE_UNISTD_H).
  zlib-ng 2.2.1  GitHub's archive of tag 2.2.1 (SHA-256 recorded at the first fetch, 2026-10-04), configured by its own
                 CMake with the options GrindCore's wrapper sets (external/dotnet9_0/zlib-ng_v2_2_1.cmake):
                 ZLIB_COMPAT=ON, WITH_ARMV6=OFF, WITH_RVV=OFF. zlib-ng's probes then pick the same CPU-specific code
                 as in GrindCore's build. It needs cmake, and Ninja on Windows (Visual Studio's, found by vcvarsall).
                 On 32-bit ARM it's built with gcc: the release built with clang <= 16 crashes there (SIGBUS in its
                 NEON Adler-32, audit/platforms.md 10.7), which GrindCore's own build works around.
Unix, macOS, and Windows with MSVC (msvc.py: --arch x64/x86/arm64, default this machine's); stdlib only, Python 3.6+.
Off Windows the libraries are linked -Bsymbolic, so their calls into themselves can't bind to another zlib already in
the process (Python's own). On Windows zlib 1.3.1 exports the functions the tests bind through a .def
(gctest/test_zlib.py REF_FUNCTIONS); zlib-ng's CMake exports its whole API.

  python3 build_zlib_ref.py [--out DIR] [--cc cc] [--cflags=...] [--tarballs DIR] [--arch x64|x86|arm64]
  -> DIR/libzlibref-1.3.1.so and DIR/libzlibngref-2.2.1.so (.dylib on macOS, .dll on Windows).
     Point GC_REF_ZLIB at DIR (gctest --refs does) and run: python3 -m gctest --lib ... -k test_zlib

--tarballs names a folder that may already hold zlib-1.3.1.tar.gz and zlib-ng-2.2.1.tar.gz; whatever is found there is
verified the same way. For osx-x64 on Apple Silicon use --cflags="-arch x86_64" (CMake gets it as
CMAKE_OSX_ARCHITECTURES); for a 32-bit Linux reference, build inside the i386 image.
"""
import argparse
import glob
import hashlib
import os
import platform
import shlex
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)  # embeddable Pythons leave it off
import msvc  # noqa: E402

# name -> (URL, SHA-256)
PINNED = {
    "zlib-ng-2.2.1.tar.gz": ("https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.2.1.tar.gz",
                             "ec6a76169d4214e2e8b737e0850ba4acb806c69eeace6240ed4481b9f5c57cdf"),
    "zlib-1.3.1.tar.gz": ("https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz",
                          "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"),
}
ZLIB_SOURCES = ("adler32", "compress", "crc32", "deflate", "gzclose", "gzlib", "gzread", "gzwrite", "infback",
                "inffast", "inflate", "inftrees", "trees", "uncompr", "zutil")


def fetch(name, out, tarballs):
    url, sha256 = PINNED[name]
    path = os.path.join(tarballs or out, name)
    if not os.path.exists(path):
        path = os.path.join(out, name)
        with urllib.request.urlopen(url, timeout=120) as r, open(path, "wb") as f:
            f.write(r.read())
    with open(path, "rb") as f:
        got = hashlib.sha256(f.read()).hexdigest()
    if got != sha256:
        sys.exit("%s: SHA-256 %s, expected %s" % (path, got, sha256))
    return path


def unpack(name, out, tarballs):
    with tarfile.open(fetch(name, out, tarballs)) as t:
        top = t.getnames()[0].split("/")[0]
        src = os.path.join(out, top)
        if not os.path.isdir(src):
            if hasattr(tarfile, "data_filter"):     # 3.12+ (and backports): no absolute paths or links out
                t.extractall(out, filter="data")
            else:
                t.extractall(out)
    return src


def default_cc():
    """init-compiler.sh's choice: $CC, then the newest clang-N (or clangN) from 30 down to 8, then clang, then cc."""
    if os.environ.get("CC"):
        return os.environ["CC"]
    for n in range(30, 7, -1):
        for name in ("clang-%d" % n, "clang%d" % n):
            if shutil.which(name):
                return name
    return "clang" if shutil.which("clang") else "cc"


def ext():
    return ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"


def build_zlib(a, src):
    lib = os.path.join(a.out, "libzlibref-1.3.1" + ext())
    sources = [os.path.join(src, n + ".c") for n in ZLIB_SOURCES]
    if sys.platform == "win32":
        sys.path.insert(0, os.path.dirname(HERE))   # tests/native, for gctest's list of the functions the tests bind
        from gctest.test_zlib import REF_FUNCTIONS
        work = lib + ".work"
        os.makedirs(work, exist_ok=True)
        msvc.write_def(os.path.join(work, "ref.def"), [n for n, _, _ in REF_FUNCTIONS])
        cl = 'cl /nologo /c /O2 /Oi /Gy /MT /DNDEBUG /W3 /I"%s"%s %s' % (
            src, " " + a.cflags if a.cflags else "", " ".join('"%s"' % f for f in sources))
        objs = " ".join(n + ".obj" for n in ZLIB_SOURCES)
        msvc.run(msvc.arch_name(a.arch), [cl, 'link /nologo /DLL /DEF:ref.def /OUT:"%s" %s' % (lib, objs)], work)
    else:
        # Z_HAVE_UNISTD_H as zlib's configure sets it in zconf.h: the gz functions need <unistd.h> (newer compilers
        # reject the implicit close()); deflate and inflate don't use it
        cmd = [a.cc, "-O2"] + shlex.split(a.cflags) + [
               "-fPIC", "-dynamiclib" if sys.platform == "darwin" else "-shared", "-o", lib, "-I", src,
               "-DZ_HAVE_UNISTD_H"] + sources
        if sys.platform != "darwin":
            cmd += ["-Wl,-Bsymbolic", "-Wl,-z,defs"]
        subprocess.check_call(cmd)
    print(lib)


def build_zlib_ng(a, src):
    lib = os.path.join(a.out, "libzlibngref-2.2.1" + ext())
    b = lib + ".work"
    flags = shlex.split(a.cflags)
    osx_arch = None
    if "-arch" in flags:    # macOS: CMake takes the architecture on its own, or it adds the host's -arch as well
        i = flags.index("-arch")
        osx_arch = flags[i + 1]
        del flags[i:i + 2]
    opts = ["-S", src, "-B", b, "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_SHARED_LIBS=ON", "-DZLIB_COMPAT=ON",
            "-DWITH_ARMV6=OFF", "-DWITH_RVV=OFF", "-DZLIB_ENABLE_TESTS=OFF", "-DZLIBNG_ENABLE_TESTS=OFF",
            "-DWITH_GTEST=OFF"]
    if sys.platform == "win32":
        flags_opt = ' -DCMAKE_C_FLAGS="%s"' % " ".join(flags) if flags else ""
        msvc.run(msvc.arch_name(a.arch), ["cmake -G Ninja -DCMAKE_C_COMPILER=cl %s%s" % (
            " ".join('"%s"' % o for o in opts), flags_opt), 'cmake --build "%s"' % b], a.out)
        built = glob.glob(os.path.join(b, "*.dll"))
    else:
        cc = a.cc
        if platform.machine().lower().startswith("arm") and struct.calcsize("P") == 4 and "clang" in cc:
            # 32-bit ARM: clang <= 16 gives zlib-ng's NEON Adler-32 32-byte-aligned loads on 16-byte-aligned data, a
            # SIGBUS (audit/platforms.md 10.7; GrindCore's build includes zlib-ng_arm32_neon_ld4.h against it). gcc
            # doesn't, so the release builds unmodified; the compiler doesn't change what deflate writes.
            cc = shutil.which("gcc") or cc
            print("zlib-ng on 32-bit ARM: %s instead of %s" % (cc, a.cc))
        opts += ["-DCMAKE_C_COMPILER=" + cc, "-DCMAKE_C_FLAGS=" + " ".join(flags)]
        if osx_arch:
            opts.append("-DCMAKE_OSX_ARCHITECTURES=" + osx_arch)
        if sys.platform != "darwin":
            opts.append("-DCMAKE_SHARED_LINKER_FLAGS=-Wl,-Bsymbolic")
        subprocess.check_call(["cmake"] + opts)
        subprocess.check_call(["cmake", "--build", b, "-j", str(os.cpu_count() or 2)])
        pat = "libz*.dylib" if sys.platform == "darwin" else "libz.so*"
        built = [p for p in glob.glob(os.path.join(b, pat)) if not os.path.islink(p)]
    if len(built) != 1:
        sys.exit("zlib-ng: expected one library in %s, found %s" % (b, built or "none"))
    shutil.copyfile(built[0], lib)
    print("%s (from %s)" % (lib, os.path.basename(built[0])))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    ap.add_argument("--cc", default=default_cc(), help="default: as GrindCore.build picks it (see above)")
    ap.add_argument("--cflags", default="", help='extra compiler flags, e.g. --cflags="-arch x86_64" or --cflags=-m32')
    ap.add_argument("--tarballs", help="a folder that may already hold the release archives")
    ap.add_argument("--arch", choices=("x64", "x86", "arm64"), help="Windows: the target (default: this machine)")
    a = ap.parse_args()
    a.out = os.path.abspath(a.out)  # MSVC and CMake build in work folders under it
    os.makedirs(a.out, exist_ok=True)
    build_zlib(a, unpack("zlib-1.3.1.tar.gz", a.out, a.tarballs))
    build_zlib_ng(a, unpack("zlib-ng-2.2.1.tar.gz", a.out, a.tarballs))
    if sys.platform != "win32":
        print(subprocess.check_output([a.cc, "--version"]).decode(errors="replace").splitlines()[0])


if __name__ == "__main__":
    main()
