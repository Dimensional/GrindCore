"""LZMA/LZMA2 decoding speed at the C level (audit/lzma.md 3.6): GrindCore's 7-Zip decoders against official 7-Zip
25.01's C and assembler decoders (ref/build_7zip_ref.py; GC_REF_7ZIP names lib7zref, lib7zref-asm next to it is used
too), liblzma (Python's lzma, i.e. xz's decoder), and GrindCore's other LZMA2 decoder, Fast-LZMA2's (FL2_decompress on
the same LZMA2 stream behind an FL2 property byte without the hash bit). Not part of the test suite. Stdlib only.

  python3 bench_lzma_dec.py MB --lib libGrindCore [--reps 3]

Streams: MB MiB of sample.text and of sample.mixed (which has incompressible stretches, i.e. LZMA2 uncompressed
chunks), each encoded by GrindCore as LZMA (LzmaEncode, level 5, 16 MiB dictionary, end mark) and as solid LZMA2
(Lzma2Enc_Encode2, level 5). Every decoder decodes every stream into one buffer; the time is the native call only,
best of --reps, and the output is checked against the data."""
import argparse
import ctypes
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcnative
from gctest import sample
from gctest import lzmadec_util as D

try:
    import lzma
except ImportError:
    lzma = None


def best(f, reps):
    t_best, out = None, None
    for _ in range(reps):
        t, out = f()
        t_best = t if t_best is None else min(t_best, t)
    return t_best, out


def one_shot_timer(api, kind, props, stream, n):
    src = ctypes.create_string_buffer(stream, len(stream))
    dst = ctypes.create_string_buffer(n + 64)

    def run():
        t = time.perf_counter()
        rc, w, u, st = api.one_shot_raw(kind, dst, n, src, len(stream), props, D.FINISH_END)
        t = time.perf_counter() - t
        if rc or st not in (D.FINISHED_WITH_MARK, D.MAYBE_FINISHED_WITHOUT_MARK) or w != n:
            raise RuntimeError("%s: rc %d status %d, %d bytes" % (api.name, rc, st, w))
        return t, dst.raw[:n]
    return run


def streaming_timer(api, kind, props, stream, n, in_step=2 << 20, out_step=1 << 20):
    """DecodeToBuf in GrindCore.net's sizes (2 MiB of input, 1 MiB of output per call): decodes into the decoder's own
    dictionary, then copies out."""
    src = ctypes.create_string_buffer(stream, len(stream))
    base = ctypes.addressof(src)
    out = ctypes.create_string_buffer(n + 64)

    def run(keep=src):                           # keep: the closure must hold the buffer, not only its address
        d = api.new(kind)
        api.allocate(kind, d, props)
        api.init(kind, d)
        pos = done = 0
        t = time.perf_counter()
        while True:
            k = min(in_step, len(stream) - pos)
            rc, w, u, st = api.to_buf(kind, d, ctypes.addressof(out) + done, min(out_step, n - done), base + pos, k,
                                      D.FINISH_ANY)
            pos += u
            done += w
            if rc or st == D.FINISHED_WITH_MARK or (u == 0 and w == 0):
                break
        t = time.perf_counter() - t
        api.free(kind, d)
        return t, out.raw[:done]
    return run


def fl2_timer(L, prop, stream, n):
    frame = bytes([prop]) + stream               # FL2 frame: dictionary property, no hash bit, then LZMA2
    src = ctypes.create_string_buffer(frame, len(frame))
    dst = ctypes.create_string_buffer(n + 64)

    def run():
        t = time.perf_counter()
        r = L.FL2_decompress(dst, n, src, len(frame))
        t = time.perf_counter() - t
        if r != n:
            raise RuntimeError("FL2_decompress returned %d" % r)
        return t, dst.raw[:n]
    return run


def xz_timer(kind, props, stream, n):
    if kind == "lzma":
        alone = props + b"\xff" * 8 + stream

        def run():
            t = time.perf_counter()
            out = lzma.decompress(alone, format=lzma.FORMAT_ALONE)
            return time.perf_counter() - t, out
    else:
        filt = [{"id": lzma.FILTER_LZMA2, "dict_size": min(D.dict_size(props), 1 << 30)}]

        def run():
            dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filt)
            t = time.perf_counter()
            out = dec.decompress(stream)
            return time.perf_counter() - t, out
    return run


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mb", type=int)
    ap.add_argument("--lib", required=True)
    ap.add_argument("--reps", type=int, default=3)
    a = ap.parse_args()
    L = gcnative.load(a.lib)
    gc = D.Api(L)
    refs, errors = D.references(L)
    print("%s, GrindCore %s (assembler decoder: %s); references: %s%s" % (
        gcnative.target(), os.path.basename(a.lib), "yes" if D.asm_decoder_expected() else "no",
        ", ".join(n for n, _ in refs) or "none", (" (%s)" % "; ".join(errors)) if errors else ""))
    if lzma is not None:
        print("liblzma: Python %s" % sys.version.split()[0])
    for dname, gen in (("text", sample.text), ("mixed", sample.mixed)):
        data = gen(a.mb << 20, seed=12)
        n = len(data)
        streams = [("LZMA", "lzma") + D.gc_lzma(L, data, dict_bytes=1 << 24, level=5, end_mark=1),
                   ("LZMA2", "lzma2") + D.gc_lzma2_blocks(L, data, level=5, block=(1 << 64) - 1, threads=1)]
        for sname, kind, props, stream in streams:
            print("\n%s %d MiB as %s: %d bytes (ratio %.4f)" % (dname, a.mb, sname, len(stream), len(stream) / n))
            rows = [("GrindCore, one-shot", one_shot_timer(gc, kind, props, stream, n)),
                    ("GrindCore, DecodeToBuf 2 MiB in / 1 MiB out", streaming_timer(gc, kind, props, stream, n))]
            rows += [("%s, one-shot" % rn, one_shot_timer(r, kind, props, stream, n)) for rn, r in refs]
            if kind == "lzma2":
                rows.append(("GrindCore's Fast-LZMA2 decoder (FL2_decompress)", fl2_timer(L, props, stream, n)))
            if lzma is not None:
                rows.append(("liblzma (Python lzma)", xz_timer(kind, props, stream, n)))
            base = None
            for label, run in rows:
                t, out = best(run, a.reps)
                ok = out == data
                mbs = n / t / (1 << 20)
                base = base or mbs
                print("  %-48s %8.1f MiB/s  %5.2fx%s" % (label, mbs, mbs / base, "" if ok else "  WRONG OUTPUT"))


if __name__ == "__main__":
    main()
