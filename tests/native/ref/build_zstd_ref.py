"""Build official zstd, plus its contrib/seekable_format extension, from an exact release tarball (default: the two
versions GrindCore vendors, 1.5.2 and 1.5.7) as small shared libraries: the references for gctest/test_zstd.py.

The tarball comes from github.com/facebook/zstd's release page and is checked against the SHA-256 file published
beside it. lib/common, lib/compress, lib/decompress and contrib/seekable_format/zstdseek_*.c are compiled unmodified
with the system C compiler, with the multithreading and namespace settings of zstd's own lib/Makefile. The assembly
Huffman decoder is left out (ZSTD_DISABLE_ASM, as GrindCore builds it); it changes speed, never output. Unix and macOS;
stdlib only, Python 3.6+.

  python3 build_zstd_ref.py [--version 1.5.7 ...] [--out DIR] [--cc cc] [--cflags "..."] [--tarballs DIR]
  -> DIR/libzstdref-<version>.so (.dylib on macOS). Point GC_REF_ZSTD at DIR and run: python3 -m gctest --lib ... -k ZStd

For osx-x64 on Apple Silicon, cross-compile natively with --cflags "-arch x86_64": the Command Line Tools' xcrun is
arm64-only, so cc can't run under Rosetta (arch -x86_64).
"""
import argparse
import glob
import hashlib
import os
import shlex
import subprocess
import sys
import tarfile
import urllib.request

URL = "https://github.com/facebook/zstd/releases/download/v%s/zstd-%s.tar.gz"


def fetch(version, out, tarballs):
    """The release tarball, from --tarballs if it's there, else downloaded; verified against the published SHA-256."""
    name = "zstd-%s.tar.gz" % version
    path = os.path.join(tarballs or out, name)
    if not os.path.exists(path):
        path = os.path.join(out, name)
        with urllib.request.urlopen(URL % (version, version), timeout=120) as r, open(path, "wb") as f:
            f.write(r.read())
    with urllib.request.urlopen(URL % (version, version) + ".sha256", timeout=60) as r:
        want = r.read().decode().split()[0]
    with open(path, "rb") as f:
        got = hashlib.sha256(f.read()).hexdigest()
    if got != want:
        sys.exit("%s: SHA-256 %s, but the release says %s" % (path, got, want))
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", action="append", help="repeatable; default 1.5.2 and 1.5.7")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    ap.add_argument("--cflags", default="", help='extra compiler flags, e.g. "-arch x86_64" or "-m32"')
    ap.add_argument("--tarballs", help="a folder that may already hold zstd-<version>.tar.gz")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for version in a.version or ["1.5.2", "1.5.7"]:
        src = os.path.join(a.out, "zstd-" + version)
        if not os.path.isdir(src):
            with tarfile.open(fetch(version, a.out, a.tarballs)) as t:
                if hasattr(tarfile, "data_filter"):     # 3.12+ (and backports): no absolute paths or links out
                    t.extractall(a.out, filter="data")
                else:
                    t.extractall(a.out)
        lib, seek = os.path.join(src, "lib"), os.path.join(src, "contrib", "seekable_format")
        sources = sorted(glob.glob(os.path.join(lib, "common", "*.c")) + glob.glob(os.path.join(lib, "compress", "*.c")) +
                         glob.glob(os.path.join(lib, "decompress", "*.c")) +
                         [os.path.join(seek, "zstdseek_compress.c"), os.path.join(seek, "zstdseek_decompress.c")])
        so = os.path.join(a.out, "libzstdref-%s%s" % (version, ".dylib" if sys.platform == "darwin" else ".so"))
        cmd = [a.cc] + shlex.split(a.cflags) + [
               "-O2", "-fPIC", "-dynamiclib" if sys.platform == "darwin" else "-shared", "-o", so,
               "-DZSTD_MULTITHREAD", "-DXXH_NAMESPACE=ZSTD_", "-DZSTD_DISABLE_ASM",
               "-I" + lib, "-I" + os.path.join(lib, "common"), "-I" + seek, "-pthread"] + sources
        if sys.platform != "darwin":
            # both versions export the same ZSTD_* names; -Bsymbolic keeps each library's calls inside itself
            cmd += ["-Wl,-Bsymbolic", "-Wl,-z,defs"]
        subprocess.check_call(cmd)
        print(so)


if __name__ == "__main__":
    main()
