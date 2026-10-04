"""Build official fast-lzma2 as small shared libraries: the references for gctest/test_fl2.py.

GrindCore vendors fast-lzma2 1.0.1 through mcmilk's 7-Zip-zstd (external/mcmilk/C/fast-lzma2). Every file it keeps is
byte-identical to Conor McCarthy's v1.0.1 release (github.com/conor42/fast-lzma2, tag v1.0.1 = commit 9d13017d) apart
from line endings; it leaves out upstream's xxhash.c/.h (GrindCore links zstd 1.5.7's) and its x86-64 assembler
decoder. Three builds come from two pinned GitHub archives (the project publishes no tarballs of its own):

  1.0.1        tag v1.0.1, the C sources as released: the same code GrindCore compiles.
  master       commit 967306d3 (2026-09-12), v1.0.1 plus upstream's two later encoder fixes: b44b79b9 (the match table's
               matches[-1] access) and a793db99 (RMF_handleRepeat reading past the end of the block).
  1.0.1-asm    (--asm, x86-64 Linux only) 1.0.1 with its lzma_dec_x86_64.S decoder and -DLZMA2_DEC_OPT, as upstream's
               own Makefile and Visual Studio project build it on x86-64. For the speed comparison; output is the same.
               The .S needs GNU as (binutils), which clang reaches with -fno-integrated-as.

Sources are compiled with no extra defines (upstream's Makefile adds only -Wall -O2 -pthread -fPIC). Unix and macOS;
stdlib only, Python 3.6+. The compiler defaults to the one GrindCore.build picks (eng/common/native/init-compiler.sh):
$CC if set, else the highest-numbered clang-N on PATH, else clang, else cc.

  python3 build_fl2_ref.py [--out DIR] [--cc cc] [--cflags=...] [--tarballs DIR] [--asm]
  -> DIR/libfl2ref-1.0.1.so, DIR/libfl2ref-master.so (.dylib on macOS), and with --asm DIR/libfl2ref-1.0.1-asm.so.
     Point GC_REF_FL2 at DIR and run: python3 -m gctest --lib ... -k Fl2

--tarballs names a folder that may already hold the archives (for hosts or containers without network access);
whatever is found there is verified the same way. Pass --cflags with "=" (--cflags=-m32), since a value starting with
"-" is otherwise read as an option. For osx-x64 on Apple Silicon use --cflags="-arch x86_64"; for a 32-bit Linux
reference, build inside the i386 image.
"""
import argparse
import glob
import hashlib
import os
import platform
import shlex
import shutil
import subprocess
import sys
import tarfile
import urllib.request

REPO = "https://github.com/conor42/fast-lzma2/archive/"
# name -> (archive name, commit, SHA-256 of GitHub's archive as fetched 2026-09-28)
SOURCES = {
    "1.0.1": ("refs/tags/v1.0.1.tar.gz", "9d13017df02e3a0c6cdd1dfd87e141a6a5e2ba30",
              "60fd0a031fb0a153ba4f00799aed443ce9f149b203c59e17e558afbfafe8bf64"),
    "master": ("967306d39daacf9a14ad923c86fa7f9c4552b59b.tar.gz", "967306d39daacf9a14ad923c86fa7f9c4552b59b",
               "5da66fd2c4aa7a7e24739b3b011a2fb2276d562bbab2cc873ee716e41c4e57bf"),
}


def fetch(out, tarballs, name):
    archive, commit, sha256 = SOURCES[name]
    local = "fast-lzma2-%s.tar.gz" % commit[:8]
    path = os.path.join(tarballs or out, local)
    if not os.path.exists(path):
        path = os.path.join(out, local)
        with urllib.request.urlopen(REPO + archive, timeout=120) as r, open(path, "wb") as f:
            f.write(r.read())
    with open(path, "rb") as f:
        got = hashlib.sha256(f.read()).hexdigest()
    if got != sha256:
        sys.exit("%s: SHA-256 %s, expected %s" % (path, got, sha256))
    return path


def unpack(out, tarballs, name):
    with tarfile.open(fetch(out, tarballs, name)) as t:
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


def build(a, src, label, asm=False):
    sources = sorted(glob.glob(os.path.join(src, "*.c")))
    so = os.path.join(a.out, "libfl2ref-%s%s" % (label, ".dylib" if sys.platform == "darwin" else ".so"))
    # --cflags come after -O2, so they can override it. No -fvisibility=hidden: fast-lzma2.h marks its API default
    # visibility anyway, and the reference exists to export it.
    cmd = [a.cc, "-O2"] + shlex.split(a.cflags) + ["-pthread", "-fPIC",
           "-dynamiclib" if sys.platform == "darwin" else "-shared", "-o", so] + sources
    if asm:
        # The .S uses GNU as syntax (the SHL operator) that clang's integrated assembler rejects, so it goes to
        # binutils' as. GrindCore's clang builds would need the same flag (or SHL rewritten as <<) to adopt it.
        obj = os.path.join(a.out, "lzma_dec_x86_64.o")
        subprocess.check_call([a.cc, "-fno-integrated-as", "-c", "-DMS_x64_CALL=0",
                               os.path.join(src, "lzma_dec_x86_64.S"), "-o", obj])
        cmd[1:1] = ["-DLZMA2_DEC_OPT"]
        cmd.append(obj)
    if sys.platform != "darwin":
        cmd += ["-Wl,-Bsymbolic", "-Wl,-z,defs"]
    subprocess.check_call(cmd)
    print(so)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
    ap.add_argument("--cc", default=default_cc(), help="default: as GrindCore.build picks it (see above)")
    ap.add_argument("--cflags", default="", help='extra compiler flags, e.g. --cflags="-arch x86_64" or --cflags=-m32')
    ap.add_argument("--tarballs", help="a folder that may already hold the pinned archives")
    ap.add_argument("--asm", action="store_true", help="also build 1.0.1 with upstream's x86-64 assembler decoder")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for name in ("1.0.1", "master"):
        build(a, unpack(a.out, a.tarballs, name), name)
    if a.asm:
        if sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64") and "-m32" not in a.cflags:
            build(a, unpack(a.out, a.tarballs, "1.0.1"), "1.0.1-asm", asm=True)
        else:
            print("--asm: upstream's assembler decoder is x86-64 only (and ELF here); skipped")
    print(subprocess.check_output([a.cc, "--version"]).decode(errors="replace").splitlines()[0])


if __name__ == "__main__":
    main()
