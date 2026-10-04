"""Build official LZ4 from an exact release tarball (default: 1.10.0, the version GrindCore vendors) as a small shared
library: the reference for gctest/test_lz4.py.

The tarball comes from github.com/lz4/lz4's release page and is checked against the SHA-256 file published beside it.
lib/lz4.c, lz4hc.c, lz4frame.c and xxhash.c are compiled unmodified with the system C compiler, as GrindCore compiles
them (no extra defines). Unix and macOS; stdlib only, Python 3.6+.

  python3 build_lz4_ref.py [--version 1.10.0] [--out DIR] [--cc cc] [--cflags "..."] [--tarballs DIR]
  -> DIR/liblz4ref-<version>.so (.dylib on macOS). Point GC_REF_LZ4 at DIR and run: python3 -m gctest --lib ... -k Lz4

For osx-x64 on Apple Silicon, cross-compile natively with --cflags "-arch x86_64" (the Command Line Tools' xcrun can't
run under Rosetta); for a 32-bit Linux reference, build inside the i386 image.
"""
import argparse
import hashlib
import os
import shlex
import subprocess
import sys
import tarfile
import urllib.request

URL = "https://github.com/lz4/lz4/releases/download/v%s/lz4-%s.tar.gz"


def fetch(version, out, tarballs):
    """The release tarball, from --tarballs if it's there, else downloaded; verified against the published SHA-256."""
    name = "lz4-%s.tar.gz" % version
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
    ap.add_argument("--version", action="append", help="repeatable; default 1.10.0")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
    ap.add_argument("--cc", default=os.environ.get("CC", "cc"))
    ap.add_argument("--cflags", default="", help='extra compiler flags, e.g. "-arch x86_64" or "-m32"')
    ap.add_argument("--tarballs", help="a folder that may already hold lz4-<version>.tar.gz")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for version in a.version or ["1.10.0"]:
        src = os.path.join(a.out, "lz4-" + version)
        if not os.path.isdir(src):
            with tarfile.open(fetch(version, a.out, a.tarballs)) as t:
                if hasattr(tarfile, "data_filter"):     # 3.12+ (and backports): no absolute paths or links out
                    t.extractall(a.out, filter="data")
                else:
                    t.extractall(a.out)
        lib = os.path.join(src, "lib")
        sources = [os.path.join(lib, f) for f in ("lz4.c", "lz4hc.c", "lz4frame.c", "xxhash.c")]
        so = os.path.join(a.out, "liblz4ref-%s%s" % (version, ".dylib" if sys.platform == "darwin" else ".so"))
        cmd = [a.cc] + shlex.split(a.cflags) + [
               "-O2", "-fPIC", "-dynamiclib" if sys.platform == "darwin" else "-shared", "-o", so,
               "-I" + lib] + sources
        if sys.platform != "darwin":
            cmd += ["-Wl,-Bsymbolic", "-Wl,-z,defs"]
        subprocess.check_call(cmd)
        print(so)


if __name__ == "__main__":
    main()
