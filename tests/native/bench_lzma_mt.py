"""LZMA/LZMA2 multithreaded encoding at the C level, through GrindCore's existing exports (audit/lzma.md 3.7): what
7-Zip's own threading gives, as the target for GrindCore.net's streams. Not part of the test suite. Stdlib only.

  python3 bench_lzma_mt.py MB --lib libGrindCore [--level 5] [--threads 1,2,4,8,16] [--blocks auto,4,16]

  - LZMA2: Lzma2Enc_Encode2 (one call, the whole input), numBlockThreads = numTotalThreads = T, blockSize = solid (T 1
    only), auto (4 x dictionary, at least 1 MiB) or N MiB. 7-Zip's MtCoder encodes blocks in parallel, each starting
    with a dictionary reset; the output must not depend on T for a given block size, which this checks.
  - LZMA: LzmaEnc_MemEncode with numThreads 1 and 2 (the two-thread match finder; a single LZMA stream has no other
    parallelism), checking whether the output changes.
Every output is decoded back with GrindCore's decoder."""
import argparse
import ctypes
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcnative
from gctest import sample
from gctest import lzmadec_util as D

SOLID = (1 << 64) - 1
AUTO = 0


def lzma2(L, data, level, threads, block):
    p = L.struct.CLzma2EncProps()
    L.SZ_Lzma2_v25_01_Enc_Construct(ctypes.byref(p))
    p.lzmaProps.level, p.lzmaProps.numThreads = level, 1
    p.numBlockThreads_Max, p.numTotalThreads, p.blockSize = threads, threads, block
    L.SZ_Lzma2_v25_01_Enc_Normalize(ctypes.byref(p))
    enc = L.SZ_Lzma2_v25_01_Enc_Create()
    try:
        L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(p))
        prop = L.SZ_Lzma2_v25_01_Enc_WriteProperties(enc)
        dst = ctypes.create_string_buffer(len(data) + len(data) // 2 + (1 << 16))
        dl = ctypes.c_size_t(len(dst))
        t = time.perf_counter()
        rc = L.SZ_Lzma2_v25_01_Enc_Encode2(enc, dst, ctypes.byref(dl), data, len(data), None)
        t = time.perf_counter() - t
        if rc:
            raise RuntimeError("Encode2 rc %d" % rc)
        return t, prop, dst.raw[:dl.value], p.blockSize, p.numBlockThreads_Reduced, p.lzmaProps.dictSize
    finally:
        L.SZ_Lzma2_v25_01_Enc_Destroy(enc)


def lzma1(L, data, level, threads):
    p = L.struct.CLzmaEncProps()
    L.SZ_Lzma_v25_01_EncProps_Init(ctypes.byref(p))
    p.level, p.numThreads = level, threads
    enc = L.SZ_Lzma_v25_01_Enc_Create()
    try:
        L.SZ_Lzma_v25_01_Enc_SetProps(enc, ctypes.byref(p))
        pb, pn = ctypes.create_string_buffer(5), ctypes.c_size_t(5)
        L.SZ_Lzma_v25_01_Enc_WriteProperties(enc, pb, ctypes.byref(pn))
        dst = ctypes.create_string_buffer(len(data) + len(data) // 2 + (1 << 16))
        dl = ctypes.c_size_t(len(dst))
        t = time.perf_counter()
        rc = L.SZ_Lzma_v25_01_Enc_MemEncode(enc, dst, ctypes.byref(dl), data, len(data), 1, None)
        t = time.perf_counter() - t
        if rc:
            raise RuntimeError("MemEncode rc %d" % rc)
        return t, pb.raw[:5], dst.raw[:dl.value]
    finally:
        L.SZ_Lzma_v25_01_Enc_Destroy(enc)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mb", type=int)
    ap.add_argument("--lib", required=True)
    ap.add_argument("--level", type=int, default=5)
    ap.add_argument("--threads", default="1,2,4,8,16")
    ap.add_argument("--blocks", default="auto,4,16")
    ap.add_argument("--data", default="mixed", choices=("mixed", "text"))
    a = ap.parse_args()
    L = gcnative.load(a.lib)
    A = D.Api(L)
    data = getattr(sample, a.data)(a.mb << 20, seed=13)
    n = len(data)
    print("%s, %d MiB of %s, level %d, %d logical CPUs" % (gcnative.target(), a.mb, a.data, a.level, os.cpu_count()))

    def check(kind, props, out):
        r = D.one_shot(A, kind, props, out, n, D.FINISH_END)
        return "ok" if r.rc == 0 and r.out == data else "DECODE FAILED (%s)" % D.RC.get(r.rc, r.rc)

    print("\nLZMA2, Lzma2Enc_Encode2")
    t1, prop, solid, _, _, dic = lzma2(L, data, a.level, 1, SOLID)
    print("  %-14s %3s  %7.2f s  %6.1f MiB/s  ratio %.5f  dict %d MiB  %s" % (
        "solid", 1, t1, n / t1 / 2**20, len(solid) / n, dic >> 20, check("lzma2", prop, solid)))
    for b in a.blocks.split(","):
        block = AUTO if b == "auto" else int(b) << 20
        first = None
        for t in [int(x) for x in a.threads.split(",")]:
            dt, prop, out, bs, reduced, dic = lzma2(L, data, a.level, t, block)
            same = "" if first is None else ("same bytes" if out == first else "DIFFERENT bytes")
            first = first or out
            print("  %-14s %3d  %7.2f s  %6.1f MiB/s  ratio %.5f (+%.3f%%)  %4.1fx  %d threads used  %s %s" % (
                "block %s MiB" % (bs >> 20), t, dt, n / dt / 2**20, len(out) / n, 100.0 * (len(out) - len(solid)) / len(solid),
                t1 / dt, reduced, check("lzma2", prop, out), same))

    print("\nLZMA, LzmaEnc_MemEncode")
    base = None
    for t in (1, 2):
        dt, props, out = lzma1(L, data, a.level, t)
        base = base or (dt, out)
        print("  numThreads %d  %7.2f s  %6.1f MiB/s  ratio %.5f  %4.2fx  %s %s" % (
            t, dt, n / dt / 2**20, len(out) / n, base[0] / dt, check("lzma", props, out),
            "" if t == 1 else ("same bytes" if out == base[1] else "DIFFERENT bytes")))


if __name__ == "__main__":
    main()
