"""Time-boxed fuzzing of a decoder with libFuzzer and AddressSanitizer (the workspace's audit/native-tests.md, "Fuzzing").

  python3 fuzz/fuzz.py fl2 [--minutes 30] [--cc clang-15] [--out fuzz/out]

Builds the harness (fuzz/<target>_decode.c) with GrindCore's own copy of the library's sources, writes a seed corpus
of valid streams made with Python's lzma, and runs libFuzzer in one process for the time given. Needs Linux and a clang
with libFuzzer; the linux-x64 build image has one (clang-15). Inputs libFuzzer finds interesting are added to
<out>/<target>-corpus, so a later run carries on from them; findings are <out>/<target>-crash-*, -leak-*, -timeout-*
(reproduce one with: <out>/<target>_decode <file>). Plain Python 3.6+, standard library only.

The harness is compiled -O1 -g, the usual fuzzing build, not with GrindCore's -O3: the same source, so the same
bugs, but not the same machine code.
"""
import argparse
import glob
import lzma
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", "..", ".."))  # GrindCore
EXT = os.path.join(ROOT, "external")
FL2 = os.path.join(EXT, "mcmilk", "C", "fast-lzma2")
XXH = os.path.join(EXT, "facebook", "zstd_v1_5_7", "common")  # FL2 links shared_xxhash: this xxhash.c, ZSTD_ names

# target -> (sources, include directories, extra flags), the sources and includes as GrindCore's CMake builds them
TARGETS = {
    # external/mcmilk/mcmilk-fast-lzma2.cmake's FL2_SOURCES_BASE, plus facebook-shared_xxhash.cmake. ASan checks writes
    # only: the decoder's known over-read (other-codecs.md 4.4.1 finding 10) is a read and would stop every run.
    "fl2": ([os.path.join(FL2, s) for s in ("dict_buffer.c", "fl2_common.c", "fl2_compress.c", "fl2_decompress.c",
                                            "fl2_pool.c", "fl2_threading.c", "lzma2_dec.c", "lzma2_enc.c",
                                            "radix_bitpack.c", "radix_mf.c", "radix_struct.c", "range_enc.c", "util.c")]
            + [os.path.join(XXH, "xxhash.c")],
            [FL2, os.path.join(EXT, "mcmilk", "C", "7z-deps"), XXH],
            ["-mllvm", "-asan-instrument-reads=0"]),
    # external/sevenzip/sevenzip-lzma_v25_01.cmake's C decoders (its assembler one is win-x64 only); reads checked too
    "lzma": ([os.path.join(EXT, "sevenzip", "lzma", s) for s in ("LzmaDec.c", "Lzma2Dec.c")],
             [os.path.join(EXT, "sevenzip", "lzma")], []),
}


def default_cc():
    """As GrindCore.build picks it: $CC, else the highest-numbered clang-N on PATH, else clang."""
    if os.environ.get("CC"):
        return os.environ["CC"]
    best = None
    for d in os.environ.get("PATH", "").split(os.pathsep):
        for p in glob.glob(os.path.join(d, "clang-[0-9]*")):
            n = os.path.basename(p)[len("clang-"):]
            if n.isdigit() and (best is None or int(n) > best[0]):
                best = (int(n), p)
    return best[1] if best else "clang"


def dict_prop(size):
    """The LZMA2 dictionary property byte for at least `size` bytes."""
    for p in range(41):
        if (2 | (p & 1)) << (p // 2 + 11) >= size:
            return p
    return 40


def seed_inputs():
    r = random.Random(1)
    return [b"", b"a", bytes(range(256)) * 8, b"the quick brown fox jumps over the lazy dog. " * 200,
            bytes(r.randrange(256) for _ in range(3000)), bytes(r.randrange(4) for _ in range(20000))]


def lzma2_seeds(corpus, prefix="seed"):
    """A property byte (for FL2, with no hash flag) and a raw LZMA2 stream from liblzma, which FL2 decodes as its own."""
    n = 0
    for data in seed_inputs():
        for preset in (0, 6, 9 | lzma.PRESET_EXTREME):
            for d in (1 << 16, 1 << 20):
                raw = lzma.compress(data, format=lzma.FORMAT_RAW,
                                    filters=[{"id": lzma.FILTER_LZMA2, "preset": preset, "dict_size": d}])
                with open(os.path.join(corpus, "%s-%03d" % (prefix, n)), "wb") as f:
                    f.write(bytes([dict_prop(d)]) + raw)
                n += 1
    return n


def lzma_seeds(corpus):
    """LZMA2 seeds as above, plus LZMA ones: 5 property bytes (lc/lp/pb, the dictionary size) and a raw LZMA stream
    with its end marker. The harness reads every input both ways."""
    n = lzma2_seeds(corpus, "seed2")
    for data in seed_inputs():
        for lc, lp, pb in ((3, 0, 2), (0, 2, 0), (4, 0, 4)):
            for d in (1 << 16, 1 << 20):
                raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA1, "preset": 6,
                                    "dict_size": d, "lc": lc, "lp": lp, "pb": pb}])
                with open(os.path.join(corpus, "seed1-%03d" % n), "wb") as f:
                    f.write(bytes([(pb * 5 + lp) * 9 + lc]) + d.to_bytes(4, "little") + raw)
                n += 1
    return n


SEEDS = {"fl2": lzma2_seeds, "lzma": lzma_seeds}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", choices=sorted(TARGETS))
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--cc", default=default_cc())
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    a = ap.parse_args()
    sources, includes, flags = TARGETS[a.target]
    os.makedirs(a.out, exist_ok=True)
    exe = os.path.join(a.out, a.target + "_decode")
    cmd = ([a.cc, "-g", "-O1", "-fsanitize=fuzzer,address", "-pthread"] + flags + ["-I" + i for i in includes]
           + ["-o", exe, os.path.join(HERE, a.target + "_decode.c")] + sources)
    print("$ " + " ".join(cmd), flush=True)
    subprocess.check_call(cmd)
    corpus = os.path.join(a.out, a.target + "-corpus")
    if not os.path.isdir(corpus):
        os.makedirs(corpus)
        print("%d seeds in %s" % (SEEDS[a.target](corpus), corpus), flush=True)
    prefix = os.path.join(a.out, a.target + "-")
    before = set(glob.glob(prefix + "crash-*") + glob.glob(prefix + "leak-*") + glob.glob(prefix + "timeout-*"))
    run = [exe, "-max_total_time=%d" % int(a.minutes * 60), "-timeout=10", "-rss_limit_mb=2560", "-print_final_stats=1",
           "-artifact_prefix=" + prefix, corpus]
    # With the kernel's full address randomisation (vm.mmap_rnd_bits=32), clang 15's ASan crashes or hangs at start in
    # a share of runs (3 of 10 measured; the workspace's audit/native-tests.md, "Sanitizer builds"). setarch -R turns
    # it off; in Docker that needs --security-opt seccomp=unconfined.
    arch = os.uname().machine
    if subprocess.call(["setarch", arch, "-R", "true"], stderr=subprocess.DEVNULL) == 0:
        run = ["setarch", arch, "-R"] + run
    else:
        print("warning: setarch -R isn't allowed here, so address randomisation stays on and ASan may crash at start "
              "(in Docker, add --security-opt seccomp=unconfined)", flush=True)
    print("$ " + " ".join(run), flush=True)
    rc = subprocess.call(run)
    found = sorted(set(glob.glob(prefix + "crash-*") + glob.glob(prefix + "leak-*") + glob.glob(prefix + "timeout-*")) - before)
    print("libFuzzer exit %d; %d new finding(s)%s" % (rc, len(found), "".join("\n  " + f for f in found)))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
