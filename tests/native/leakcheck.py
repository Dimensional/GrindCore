"""Leak and memory-error pass for GrindCore's native library: runs the native suite and extra leak scenarios in one
process under a checker, then reports only findings whose stack goes through GrindCore.

  Linux:  python3 leakcheck.py --lib libGrindCore.so            (needs valgrind; memcheck, leaks + memory errors)
  macOS:  python3 leakcheck.py --lib libGrindCore.dylib         (uses the system `leaks` tool; leaks only)
  Any:    python3 leakcheck.py --lib ... --scenarios-only --no-checker   (just runs the scenarios)

Child-process probes in the suite (crashes, hangs) run outside the checker on purpose. Stdlib only, Python 3.6+."""
import argparse
import ctypes
import os
import re
import subprocess
import sys
import zlib

try:
    import bz2
except ImportError:
    bz2 = None

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------- scenarios: API sequences worth checking for leaks, run inside the checked process ----------

def scenario_lzma2_prepare_after_mt_encode(L):
    """audit/lzma.md 3.3 note: Lzma2Enc_EncodeMultiCallPrepare NULLs coders[1..], outBufs[] and the MtCoder without
    freeing them. Sequence: a multi-threaded Encode2 on a handle, then the multi-call Prepare on the same handle."""
    from gctest import lzma_util as U
    data = U.data(3 << 20)
    enc = L.SZ_Lzma2_v25_01_Enc_Create()
    p = L.struct.CLzma2EncProps()
    L.SZ_Lzma2_v25_01_Enc_Construct(ctypes.byref(p))
    p.lzmaProps.level, p.lzmaProps.numThreads = 1, 1
    p.numBlockThreads_Max, p.numTotalThreads, p.blockSize = 2, 2, 1 << 20
    L.SZ_Lzma2_v25_01_Enc_Normalize(ctypes.byref(p))
    L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(p))
    out = ctypes.create_string_buffer(len(data) + (1 << 16))
    n = ctypes.c_size_t(len(out))
    rc = L.SZ_Lzma2_v25_01_Enc_Encode2(enc, out, ctypes.byref(n), data, len(data), None)
    rc2 = L.SZ_Lzma2_v25_01_Enc_EncodeMultiCallPrepare(enc)
    L.SZ_Lzma2_v25_01_Enc_Destroy(enc)
    return "Encode2 (2 threads) rc=%d, then EncodeMultiCallPrepare rc=%d, then Destroy" % (rc, rc2)


def scenario_lzma_streams_abandoned(L):
    """LZMA and LZMA2 stream encoders destroyed mid-stream, repeatedly (the §3.3 sequence), must free everything."""
    from gctest import lzma_util as U
    U.find_mode_offset(L)
    for i in range(5):
        U.lzma_stream_abandoned(L, seed=i)
    return "5 abandoned LZMA stream encoders"


def scenario_create_destroy_loops(L):
    """Create/destroy pairs many times: a per-call leak shows up as many identical records."""
    from gctest import lzma_util as U
    for _ in range(50):
        L.SZ_Lzma_v25_01_Enc_Destroy(L.SZ_Lzma_v25_01_Enc_Create())
        L.SZ_Lzma2_v25_01_Enc_Destroy(L.SZ_Lzma2_v25_01_Enc_Create())
    for _ in range(10):
        U.block_encode(L, U.data(64 << 10))
        U.encode(L, U.data(256 << 10))
    return "50 LZMA/LZMA2 encoder create/destroy pairs, 10 block and 10 LZMA2 stream encodes"


def scenario_zlib_bzip2_error_paths(L):
    """zlib/zlib-ng and BZip2 handles that fail to initialise, or are ended mid-stream, must still free everything:
    the PAL callocs its z_stream before deflateInit2/inflateInit2 and frees it only in End."""
    from gctest import sample
    from gctest.test_zlib import LIBS, zlibng_state
    data = sample.mixed(300000, seed=90)
    prefixes = [p for n, p in LIBS if p != LIBS[1][1] or zlibng_state()[0] == "ok"]
    for p in prefixes:
        f = lambda n: getattr(L, p + n)
        for _ in range(20):
            s = L.struct.PAL_ZStream()
            f("DeflateInit2_")(ctypes.byref(s), 10, 8, 15, 8, 0)      # invalid level: fails after the PAL's calloc
            f("DeflateEnd")(ctypes.byref(s))
            s = L.struct.PAL_ZStream()
            f("InflateInit2_")(ctypes.byref(s), 7)                    # invalid windowBits
            f("InflateEnd")(ctypes.byref(s))
        for wbits in (-15, 15, 31):                                   # ended mid-stream, with state and window allocated
            s = L.struct.PAL_ZStream()
            f("DeflateInit2_")(ctypes.byref(s), 9, 8, wbits, 9, 0)
            src, out = ctypes.create_string_buffer(data), ctypes.create_string_buffer(4096)
            s.nextIn, s.availIn = ctypes.addressof(src), len(data)
            s.nextOut, s.availOut = ctypes.addressof(out), len(out)
            f("Deflate")(ctypes.byref(s), 0)
            f("DeflateEnd")(ctypes.byref(s))
            c = zlib.compressobj(6, zlib.DEFLATED, wbits)
            stream = c.compress(data) + c.flush()
            s = L.struct.PAL_ZStream()
            f("InflateInit2_")(ctypes.byref(s), wbits)
            src = ctypes.create_string_buffer(stream[:len(stream) // 2])
            s.nextIn, s.availIn = ctypes.addressof(src), len(stream) // 2
            s.nextOut, s.availOut = ctypes.addressof(out), len(out)
            f("Inflate")(ctypes.byref(s), 0)
            f("InflateEnd")(ctypes.byref(s))
        n = ctypes.c_uint32(10)
        f("Compress3")(ctypes.create_string_buffer(10), ctypes.byref(n), data, len(data), 6, 15, 8, 0)   # no room
        bad = bytearray(zlib.compress(data))
        bad[len(bad) // 2] ^= 0x55
        n, m = ctypes.c_uint32(len(data)), ctypes.c_uint32(len(bad))
        f("Uncompress3")(ctypes.create_string_buffer(len(data)), ctypes.byref(n), bytes(bad), ctypes.byref(m), 15)
    B = "SZ_BZip2_v1_0_8_"
    i, o = ctypes.c_int64(), ctypes.c_int64()
    out = ctypes.create_string_buffer(4096)
    for _ in range(10):
        c = L.struct.SZ_BZip2_v1_0_8_CompressionContext()
        getattr(L, B + "CreateCompressionContext")(ctypes.byref(c), 0, 0)          # invalid block size
        getattr(L, B + "FreeCompressionContext")(ctypes.byref(c))
    c = L.struct.SZ_BZip2_v1_0_8_CompressionContext()
    getattr(L, B + "CreateCompressionContext")(ctypes.byref(c), 9, 0)
    getattr(L, B + "CompressStream")(ctypes.byref(c), out, len(out), data, len(data), 0, ctypes.byref(i), ctypes.byref(o))
    getattr(L, B + "FreeCompressionContext")(ctypes.byref(c))                     # ended mid-stream
    stream = bz2.compress(data) if bz2 else None
    if stream:
        d = L.struct.SZ_BZip2_v1_0_8_DecompressionContext()
        getattr(L, B + "CreateDecompressionContext")(ctypes.byref(d), 0)
        getattr(L, B + "DecompressStream")(ctypes.byref(d), out, len(out), stream, len(stream), ctypes.byref(i), ctypes.byref(o))
        getattr(L, B + "FreeDecompressionContext")(ctypes.byref(d))
        bad = bytearray(stream)
        bad[len(bad) // 2] ^= 0x55
        n = ctypes.c_size_t(len(data))
        getattr(L, B + "DecompressBlock")(ctypes.create_string_buffer(len(data)), ctypes.byref(n), bytes(bad), len(bad), 0)
    return "%s: 20 failed inits + End each, 3 streams ended mid-way each way, Compress3 out of room, Uncompress3 " \
           "on corrupt data; BZip2: 10 failed creates, streams freed mid-way, corrupt block" % \
           " and ".join(n for n, p in LIBS if p in prefixes)


def scenario_lzma_decoders_corrupt(L):
    """The LZMA/LZMA2 decoders on corrupt input, in the checked process (test_lzma_dec's sweeps run in children,
    which the checker doesn't follow): every truncation and 300 random bit flips of each of lzmadec_util's sweep
    streams, one-shot with FINISH_ANY and FINISH_END and streamed in 61/97-byte steps, plus the decoders' allocate,
    reallocate and free paths."""
    import random
    from gctest import lzmadec_util as D
    A, r, n = D.Api(L), random.Random(7), 0
    for name, kind, props, s, data in D.sweep_streams(L):
        cases = [s[:t] for t in range(len(s) + 1)]
        for _ in range(300):
            b = r.randrange(len(s) * 8)
            m = bytearray(s)
            m[b // 8] ^= 1 << (b % 8)
            cases.append(bytes(m))
        for m in cases:
            D.one_shot(A, kind, props, m, len(data) + 64, D.FINISH_ANY)
            D.one_shot(A, kind, props, m, len(data), D.FINISH_END)
            D.stream(A, kind, props, m, 61, 97, D.FINISH_ANY)
            n += 3
    for kind, props in (("lzma", D.lzma_props_bytes(3, 0, 2, 1 << 16)), ("lzma", D.lzma_props_bytes(8, 4, 4, 1 << 20)),
                        ("lzma2", 10), ("lzma2", 20)):
        d = A.new(kind)
        for _ in range(3):
            A.allocate(kind, d, props)
            A.allocate(kind, d, props, probs_only=True)
        A.free(kind, d, probs_only=True)
        A.free(kind, d)
        A.free(kind, d)
    return "%d corrupt-input decodes over %d sweep streams; allocate/reallocate/free on 4 decoders" % (
        n, len(D.sweep_streams(L)))


SCENARIOS = [scenario_lzma2_prepare_after_mt_encode, scenario_lzma_streams_abandoned, scenario_create_destroy_loops,
             scenario_zlib_bzip2_error_paths, scenario_lzma_decoders_corrupt]


def run_inside(lib, pattern, scenarios_only, only=None):
    """The checked process: the suite (tests that don't need a child process), then the scenarios."""
    sys.path.insert(0, HERE)
    import gcnative
    import gctest
    import unittest
    gctest.LIB = L = gcnative.load(lib)
    if not scenarios_only:
        suite = unittest.defaultTestLoader.discover(os.path.join(HERE, "gctest"), pattern="test_*.py", top_level_dir=HERE)
        flat = []
        stack = [suite]
        while stack:
            s = stack.pop()
            for t in s:
                (stack.append(t) if isinstance(t, unittest.TestSuite) else flat.append(t))
        chosen = [t for t in flat if (not pattern or any(p in t.id() for p in pattern))]
        r = unittest.TextTestRunner(verbosity=0, stream=sys.stdout).run(unittest.TestSuite(chosen))
        print("LEAKCHECK suite: %d tests, %d failures, %d errors, %d skipped" % (
            r.testsRun, len(r.failures), len(r.errors), len(r.skipped)), flush=True)
    for s in SCENARIOS:
        if not only or any(o in s.__name__ for o in only):
            print("LEAKCHECK scenario %s: %s" % (s.__name__, s(L)), flush=True)


def real_executable():
    """The interpreter binary itself. On macOS, python3 can be a launcher that execs the framework's Python.app
    binary, and `leaks` then reports nothing; so ask the running process for its image path."""
    if sys.platform != "darwin":
        return sys.executable
    buf, size = ctypes.create_string_buffer(4096), ctypes.c_uint32(4096)
    if ctypes.CDLL(None)._NSGetExecutablePath(buf, ctypes.byref(size)) == 0:
        return os.path.realpath(buf.value.decode())
    return sys.executable


GC_FRAME = re.compile(r"(?:at|by) 0x[0-9A-Fa-f]+: .*(?:libGrindCore|GrindCore\.dll|/src/native/)")
NOT_RECORDS = ("Memcheck, a memory error detector", "HEAP SUMMARY", "LEAK SUMMARY", "ERROR SUMMARY")


def gc_records(text):
    """Valgrind text output -> its records (separated by bare "==pid==" lines) with a stack frame in GrindCore: the
    library itself, or with its debug info loaded, a source file under the build tree's src/native/."""
    blocks = re.split(r"\n==\d+==\s*\n", text)
    return [b for b in blocks if GC_FRAME.search(b) and not any(k in b for k in NOT_RECORDS)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True)
    ap.add_argument("-k", dest="pattern", action="append", help="only suite tests whose id contains this (repeatable)")
    ap.add_argument("--scenarios-only", action="store_true")
    ap.add_argument("--scenario", action="append", help="only scenarios whose name contains this (repeatable). On "
                    "shipped builds the LZMA scenarios in sequence hang in the multicallMode defect (lzma.md 3.3): "
                    "e.g. --scenario zlib")
    ap.add_argument("--no-checker", action="store_true")
    ap.add_argument("--save", help="write the checker's complete output here")
    ap.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()
    if a.inside or a.no_checker:
        run_inside(os.path.abspath(a.lib), a.pattern, a.scenarios_only, a.scenario)
        return 0
    me = [real_executable(), os.path.abspath(__file__), "--inside", "--lib", os.path.abspath(a.lib)] + \
        [x for p in (a.pattern or []) for x in ("-k", p)] + (["--scenarios-only"] if a.scenarios_only else []) + \
        [x for s in (a.scenario or []) for x in ("--scenario", s)]
    env = dict(os.environ, PYTHONMALLOC="malloc")
    marker = os.path.basename(a.lib).split(".")[0]  # libGrindCore / GrindCore
    if sys.platform == "darwin":
        env["MallocStackLogging"] = "1"
        p = subprocess.run(["leaks", "--atExit", "--"] + me, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        text = p.stdout.decode(errors="replace")
        if a.save:
            with open(a.save, "w") as f:
                f.write(text)
        print("\n".join(l for l in text.splitlines() if l.startswith("LEAKCHECK")))
        m = re.search(r"(\d+) leaks? for (\d+) total leaked bytes", text)
        leaks = [b for b in re.split(r"\n(?=STACK OF )", text) if marker in b and "LEAK" in b]
        print("leaks: %s; with %s in the stack: %d" % (m.group(0) if m else "no summary", marker, len(leaks)))
        for b in leaks[:10]:
            print(b[:1500] + "\n")
        return 0 if not leaks else 1
    vg = ["valgrind", "--tool=memcheck", "--leak-check=full", "--show-leak-kinds=definite,indirect",
          "--errors-for-leak-kinds=definite", "--num-callers=30", "--trace-children=no", "--fullpath-after="]
    p = subprocess.run(vg + me, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    text = p.stdout.decode(errors="replace")
    if a.save:
        with open(a.save, "w") as f:
            f.write(text)
    print("\n".join(l for l in text.splitlines() if l.startswith("LEAKCHECK")))
    recs = gc_records(text)
    errors = [b for b in recs if "are definitely lost" not in b and "are indirectly lost" not in b]
    leaks = [b for b in recs if "are definitely lost" in b or "are indirectly lost" in b]
    summary = re.search(r"==\d+== ERROR SUMMARY: .*", text)
    print("valgrind: %s" % (summary.group(0).split("== ", 1)[1] if summary else "no summary"))
    print("records with %s in the stack: %d memory errors, %d leaks" % (marker, len(errors), len(leaks)))
    for b in (errors + leaks)[:12]:
        print(re.sub(r"==\d+== ", "", b)[:1800] + "\n")
    return 0 if not recs else 1


if __name__ == "__main__":
    sys.exit(main())
