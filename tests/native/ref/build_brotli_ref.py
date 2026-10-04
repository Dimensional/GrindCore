"""Build official Brotli 1.1.0 (the version GrindCore vendors) as a small shared library, and fetch Brotli's own test
fixtures: the references for gctest/test_brotli.py.

The source is GitHub's archive of tag v1.1.0 (commit ed738e84): Brotli publishes no tarball of its own, so the archive
is checked against a pinned SHA-256, the value Homebrew's brotli 1.1.0 formula also publishes. c/common, c/dec and
c/enc are compiled unmodified with no extra defines: official Brotli as released. (GrindCore's copy adds .NET's
cast-only MSVC-warning patch, google/brotli@85d88cbf, and since audit/native-fixes builds with
BROTLI_ENCODER_CLEANUP_ON_OOM plus the encode.c out-of-memory checks, other-codecs.md 4.3.1. None of that changes any
output; it only changes what a failed encoder allocation does, which the tests check on GrindCore directly.)
Unix and macOS; stdlib only, Python 3.6+.

The compiler defaults to the one GrindCore.build picks (eng/common/native/init-compiler.sh): $CC if set, else the
highest-numbered clang-N on PATH, else clang, else cc. It matters for Brotli, unlike zstd or LZ4: for some inputs,
qualities 10 and 11 give compiler-dependent (all valid) output. Measured on 300 KB of mixed data, where 490 of 492
one-shot cases agree everywhere: on linux-x64, clang 14 differs from GrindCore's build (clang 15), while clang 15 and
gcc 11 match it; on linux-arm, gcc 12 differs from GrindCore's build (clang 14), while clang 14 matches it with or
without GrindCore.build's flags. So a reference is only comparable when it's built with the same compiler.

The fixtures (tests/testdata: each *.compressed* file and its original) aren't in the archive (export-ignore). They're
downloaded from the same commit and each is checked against its pinned git blob hash. They need no compiler, so
--fixtures-only works on Windows too.

  python3 build_brotli_ref.py [--out DIR] [--cc cc] [--cflags "..."] [--tarballs DIR] [--fixtures-only]
  -> DIR/libbrotliref-1.1.0.so (.dylib on macOS) and DIR/brotli-1.1.0-testdata/.
     Point GC_REF_BROTLI at DIR and run: python3 -m gctest --lib ... -k Brotli

--tarballs names a folder that may already hold brotli-1.1.0.tar.gz and brotli-1.1.0-testdata/ (for hosts or
containers without network access); whatever is found there is verified the same way. For osx-x64 on Apple Silicon,
cross-compile natively with --cflags "-arch x86_64"; for a 32-bit Linux reference, build inside the i386 image.
"""
import argparse
import glob
import hashlib
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import urllib.request

VERSION = "1.1.0"
COMMIT = "ed738e842d2fbdf2d6459e39267a633c4a9b2f5d"
URL = "https://github.com/google/brotli/archive/refs/tags/v%s.tar.gz" % VERSION
SHA256 = "e720a6ca29428b803f4ad165371771f5398faba397edf6778837a18599ea13ff"
RAW = "https://raw.githubusercontent.com/google/brotli/%s/tests/testdata/%%s" % COMMIT

# tests/testdata at the tag: every *.compressed* file and its original, with its git blob SHA-1 (git ls-tree v1.1.0).
# Left out: bb.binast (12 MB) and random_chunks, which have no compressed counterpart.
FIXTURES = {
    "10x10y": "3f9cf8651c95f006109c6d04e15fe3e26e477fe1",
    "10x10y.compressed": "3769516d943745d67d3873caf4e9149e95d4b73d",
    "64x": "caa41718cb20530713fa29098bed86e019eebd32",
    "64x.compressed": "74d0be10a7ded87c29f81b65a8637ce52e2d0c88",
    "alice29.txt": "703365523b944b721362a0fdf7a8255b313e9dd6",
    "alice29.txt.compressed": "37d86e253e9d812e7749cab674b9ee55f23083c0",
    "asyoulik.txt": "88dc7b60fe2afeeedd1ba1bb5d4229b17b29b041",
    "asyoulik.txt.compressed": "3a7621100f1e18d80cd82d1f86589dbeeca6c655",
    "backward65536": "40efb3c113eed183d35b0db57fea058d52a94bae",
    "backward65536.compressed": "07152197db668cd60dcc8141fc9d81e8d34c350e",
    "compressed_file": "37d86e253e9d812e7749cab674b9ee55f23083c0",
    "compressed_file.compressed": "8834f3275a80e77f03dd99010f43b5024255b515",
    "compressed_repeated": "9870b5fdc7539c0f60b6770a7d632cdc24b250a9",
    "compressed_repeated.compressed": "092754589e7f7578dbc7dce8bf19de55c5cab94c",
    "cp1251-utf16le": "d1cb042b7977aa5d3dbd723dff604d4e64b9a6e8",
    "cp1251-utf16le.compressed": "2706963b78155d1dcb572cfb54f92a9560b4afac",
    "cp852-utf8": "fa14705c156df0227e5847800c93cb233063741e",
    "cp852-utf8.compressed": "12ba6c24700de7615d34766d27442aab11b068c8",
    "empty": "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
    "empty.compressed": "f8fa5a235408d5c6f2c2844e44cd98c1fa666ac8",
    "empty.compressed.00": "f8fa5a235408d5c6f2c2844e44cd98c1fa666ac8",
    "empty.compressed.01": "17bb347215fa2296e66e5509cdf088198192dfc1",
    "empty.compressed.02": "c183df6a308637ea8e1bbb578785c74bec7f8599",
    "empty.compressed.03": "ae60db8f353e6d0c7236869d63d9524d87ea5b14",
    "empty.compressed.04": "8fac0345cf82c2639ad62d7c6e7293aeb9d8c2e9",
    "empty.compressed.05": "98c9dcca28ece4dfb96567a3e0f8150390c38af3",
    "empty.compressed.06": "84f606f03773fcfdd2d2d115cce07a9b854c698b",
    "empty.compressed.07": "0941d53684a142062238e6ca1e2b781ad15a62f3",
    "empty.compressed.08": "e440e5c842586965a7fb77deda2eca68612b1f53",
    "empty.compressed.09": "7813681f5b41c028345ca62a2be376bae70b7f61",
    "empty.compressed.10": "c7930257dfef505fd996e1d6f22f2f35149990d0",
    "empty.compressed.11": "f11c82a4cb6cc2e8f3bdf52b5cdeaad4d5bb214e",
    "empty.compressed.12": "1c8a0e7976207fb9f03ed7e260950b62b8b9d396",
    "empty.compressed.13": "851c75cc5e74cf97d145360755d116d2409881f2",
    "empty.compressed.14": "0d758c9c7bc06c1e307f05d92d896aaf0a8a6d2c",
    "empty.compressed.15": "152f9ed5aa2d840c4a115d34ac0271262ca416ef",
    "empty.compressed.16": "e136a792a1a4cfae18581449863d6a4c915112f1",
    "empty.compressed.17": "81f0388bf825cf858828b03ba404b8202f303e18",
    "empty.compressed.18": "524e34198448e64a47cfb1ec9c5a2f2e5aac73c3",
    "lcet10.txt": "25dda6b3f1bf96b34f94531fd845d4e1a248cdfb",
    "lcet10.txt.compressed": "b7d0f633c437f8260595df40f03f044d6f598e82",
    "mapsdatazrh": "037118364250cbd2a53e267440000d2179c7875f",
    "mapsdatazrh.compressed": "77bfa4717e6606fd110481504d495319769c7589",
    "monkey": "47408cd685dc7256fa95f1abdb47a072138a041d",
    "monkey.compressed": "bbcf134402c5e5b921d339850cdc2e1d815e88a7",
    "plrabn12.txt": "34088b82cd029bcd3b6b0d1adc956f95734699a9",
    "plrabn12.txt.compressed": "1750fa5c7b2a8d30fa094b793f1b6c419eced367",
    "quickfox": "ff3bb63948b4b24796d2acd259915f2a9d972638",
    "quickfox.compressed": "b5deebc42f4277d50d4d02f127819cf298e1f662",
    "quickfox_repeated": "2ed134ebc9b194b4da63f8891888cf7929b200e4",
    "quickfox_repeated.compressed": "f9d79767896a1102f5a060cdcefd651eac6bb8e9",
    "random_org_10k.bin": "faf8a3a7bccf43893e85ceeac529048f128b1953",
    "random_org_10k.bin.compressed": "5ffbaa049ade136051cf0cf3fa05571a74c6734d",
    "ukkonooa": "1072b69b4fa079b36330958f87f0bc15c343db65",
    "ukkonooa.compressed": "f39f068d7ea93d939faff47954cbb3d6049f63bb",
    "x": "500c0709ca24338426091ca19777e13a1920ebdf",
    "x.compressed": "2a44b5def2201712a8261bdb95a5528341e0570b",
    "x.compressed.00": "33e3a98e06889f59227f3444fa4cd905169f7f14",
    "x.compressed.01": "9c8249b1649c5c049d78c26d072b5006921d158b",
    "x.compressed.02": "3a5890db755a997b460335fbc5fb2f4118cbe900",
    "x.compressed.03": "842e7995c39db5cb06e968ab2ad958cbaee150ca",
    "xyzzy": "fbfb23d1efdb5ce7f2f24518ee1bd718a037a17d",
    "xyzzy.compressed": "e6982cef480da0d7674729f4de32f76968c7402b",
    "zeros": "6d23118f0d0084657a974875123ddc1b9a0738dd",
    "zeros.compressed": "bf05b53c176ae15216eaf5d8d496e7fe9e685142",
}


def blob_sha1(data):
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def fetch_tarball(out, tarballs):
    name = "brotli-%s.tar.gz" % VERSION
    path = os.path.join(tarballs or out, name)
    if not os.path.exists(path):
        path = os.path.join(out, name)
        with urllib.request.urlopen(URL, timeout=120) as r, open(path, "wb") as f:
            f.write(r.read())
    with open(path, "rb") as f:
        got = hashlib.sha256(f.read()).hexdigest()
    if got != SHA256:
        sys.exit("%s: SHA-256 %s, expected %s" % (path, got, SHA256))
    return path


def fetch_fixtures(out, tarballs):
    """DIR/brotli-<version>-testdata with every pinned fixture, each verified by its git blob hash."""
    dest = os.path.join(out, "brotli-%s-testdata" % VERSION)
    have = os.path.join(tarballs, "brotli-%s-testdata" % VERSION) if tarballs else None
    os.makedirs(dest, exist_ok=True)
    for name, want in sorted(FIXTURES.items()):
        target = os.path.join(dest, name)
        data = None
        for candidate in (target, os.path.join(have, name) if have else None):
            if candidate and os.path.exists(candidate):
                with open(candidate, "rb") as f:
                    data = f.read()
                if blob_sha1(data) == want:
                    break
                data = None
        if data is None:
            with urllib.request.urlopen(RAW % name, timeout=120) as r:
                data = r.read()
        if blob_sha1(data) != want:
            sys.exit("%s: git blob %s, expected %s" % (name, blob_sha1(data), want))
        if not os.path.exists(target) or open(target, "rb").read() != data:
            with open(target, "wb") as f:
                f.write(data)
    return dest


def default_cc():
    """init-compiler.sh's choice: $CC, then the newest clang-N (or clangN) from 30 down to 8, then clang, then cc."""
    if os.environ.get("CC"):
        return os.environ["CC"]
    for n in range(30, 7, -1):
        for name in ("clang-%d" % n, "clang%d" % n):
            if shutil.which(name):
                return name
    return "clang" if shutil.which("clang") else "cc"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "out"))
    ap.add_argument("--cc", default=default_cc(), help="default: as GrindCore.build picks it (see above)")
    ap.add_argument("--cflags", default="", help='extra compiler flags, e.g. "-arch x86_64" or "-m32"')
    ap.add_argument("--tarballs", help="a folder that may already hold brotli-%s.tar.gz and its testdata" % VERSION)
    ap.add_argument("--fixtures-only", action="store_true", help="fetch and verify the fixtures; build nothing")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    print(fetch_fixtures(a.out, a.tarballs))
    if a.fixtures_only:
        return
    src = os.path.join(a.out, "brotli-" + VERSION)
    if not os.path.isdir(src):
        with tarfile.open(fetch_tarball(a.out, a.tarballs)) as t:
            if hasattr(tarfile, "data_filter"):     # 3.12+ (and backports): no absolute paths or links out
                t.extractall(a.out, filter="data")
            else:
                t.extractall(a.out)
    c = os.path.join(src, "c")
    sources = sorted(f for d in ("common", "dec", "enc") for f in glob.glob(os.path.join(c, d, "*.c")))
    so = os.path.join(a.out, "libbrotliref-%s%s" % (VERSION, ".dylib" if sys.platform == "darwin" else ".so"))
    # --cflags come after -O2, so they can override it (e.g. -O3 with GrindCore.build's flags). Leave out
    # -fvisibility=hidden: it hides Brotli's own API, which the reference exists to export.
    cmd = [a.cc, "-O2"] + shlex.split(a.cflags) + [
           "-fPIC", "-dynamiclib" if sys.platform == "darwin" else "-shared", "-o", so,
           "-I" + os.path.join(c, "include")] + sources + ["-lm"]
    if sys.platform != "darwin":
        cmd += ["-Wl,-Bsymbolic", "-Wl,-z,defs"]
    subprocess.check_call(cmd)
    print("%s (%s)" % (so, subprocess.check_output([a.cc, "--version"]).decode(errors="replace").splitlines()[0]))


if __name__ == "__main__":
    main()
