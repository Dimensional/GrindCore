"""Fast-LZMA2 speed at the C level (audit/other-codecs.md 4.4.1, Performance): GrindCore's build against official
1.0.1 builds (ref/build_fl2_ref.py, --asm for the assembler decoder), and GrindCore.net's call pattern (a flush after
every 2 MiB write) against the library's intended one. Level 6, sample.mixed data; the first library's output is the
one the others are compared with. Not part of the test suite. Stdlib only.

  python3 bench_fl2.py encode MB THREADS name=lib [name=lib ...]
      one-shot encode/decode per library, then GrindCore.net's stream pattern on the first
      e.g. bench_fl2.py encode 64 8 grindcore=.../libGrindCore.so official=ref/out/libfl2ref-1.0.1.so
  python3 bench_fl2.py decode MB name=lib [name=lib ...]
      multithreaded decoding: FL2_decompressMt and the streaming decoder at 1-8 threads, on frames written with
      the default FL2_p_resetInterval (4) and with 1. A decoder can only use as many threads as the frame has
      dictionary resets (fast-lzma2.h, "Decompression context")
  python3 bench_fl2.py blocks name=lib
      FastLzma2Block's native calls per block size and thread count: FL2_compressCCtx with a reused context but
      the level passed on every call (as OnCompress does), and FL2_decompressMt, which builds a context (and a
      thread pool) on every call (as OnDecompress does), against a reused FL2_DCtx"""
import ctypes, lzma, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcnative
from gctest import sample, fl2_util as F


def timed(f, reps=1):
    best, out = None, None
    for _ in range(reps):
        t = time.perf_counter()
        out = f()
        dt = time.perf_counter() - t
        best = dt if best is None else min(best, dt)
    return best, out


def wrapper_pattern(api, data, level, threads, chunk=2 << 20):
    """FastLzma2Encoder.EncodeData per 2 MiB OnWrite: compressStream, copy output, flushStream until no output; then
    endStream once at the end. Threads > 1 -> FL2_createCStreamMt(threads, dualBuffer 1)."""
    s = F.CStream(api, threads, 1 if threads > 1 else 0, out_step=chunk * 3 // 2 + 32)
    s.init(level)
    out = bytearray()
    for i in range(0, len(data), chunk):
        out += s.write(data[i:i + chunk])
        while True:                              # the wrapper's flush loop: stops when a call writes nothing
            s._out()
            r = api.check("FL2_flushStream", s.s, ctypes.addressof(s.ob))
            out += s.out.raw[:s.ob.pos]
            if s.ob.pos == 0:
                break
    out += s.end()
    s.close()
    return bytes(out)


def libs_of(args):
    return [(a.split("=", 1)[0], F.Api(gcnative.load(a.split("=", 1)[1]), a)) for a in args]


def encode_main(args):
    mb, threads = int(args[0]), int(args[1])
    libs = libs_of(args[2:])
    t = time.perf_counter()
    data = sample.mixed(mb << 20, seed=11)
    print("data %d MiB (%.1fs to make), threads %d, cpus %d" % (mb, time.perf_counter() - t, threads, os.cpu_count()))
    level = 6
    base = None
    for name, api in libs:
        enc, f = timed(lambda: api.compress(data, level, threads), 2)
        base = base or f
        same = "same" if f == base else "DIFFERENT"
        dec, d = timed(lambda: api.decompress(f, len(data)), 3)
        assert d == data
        print("%-10s one-shot  enc %6.2fs (%6.1f MB/s) ratio %.4f %s | dec %5.2fs (%6.1f MB/s)" % (
            name, enc, mb / enc, len(f) / len(data), same, dec, mb / dec))
    for name, api in libs[:1]:
        s_enc, f2 = timed(lambda: stream_whole(api, data, level, threads))
        w_enc, f3 = timed(lambda: wrapper_pattern(api, data, level, threads))
        for how, e, f in (("stream 1 MiB writes", s_enc, f2), ("wrapper pattern", w_enc, f3)):
            assert api.decompress(f, len(data)) == data
            print("%-10s %-20s enc %6.2fs (%6.1f MB/s) ratio %.4f" % (name, how, e, mb / e, len(f) / len(data)))
    e, x = timed(lambda: lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "preset": 6}]))
    d, _ = timed(lambda: lzma.decompress(x, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "preset": 6}]))
    print("liblzma    preset 6  enc %6.2fs (%6.1f MB/s) ratio %.4f | dec %5.2fs (%6.1f MB/s)  (1 thread)" % (
        e, mb / e, len(x) / len(data), d, mb / d))


def stream_whole(api, data, level, threads):
    s = F.CStream(api, threads, 1 if threads > 1 else 0, out_step=4 << 20)
    s.init(level)
    out = bytearray()
    for i in range(0, len(data), 1 << 20):
        out += s.write(data[i:i + (1 << 20)])
    out += s.end()
    s.close()
    return bytes(out)


def frame_with(api, data, level, threads, reset_interval):
    s = F.CStream(api, threads, 0, out_step=4 << 20)
    s.set(F.LEVEL, level)
    s.set(F.RESET_INTERVAL, reset_interval)
    s.init(0)
    f = s.compress(data, 1 << 20)
    s.close()
    return f


def decode_main(args):
    mb = int(args[0])
    libs = libs_of(args[1:])
    data = sample.mixed(mb << 20, seed=12)
    print("data %d MiB, level 6 (16 MiB dictionary), cpus %d" % (mb, os.cpu_count()))
    for name, api in libs:
        for ri in (4, 1):
            f = frame_with(api, data, 6, 8, ri)
            print("%-10s resetInterval %d: frame %d bytes" % (name, ri, len(f)))
            for threads in (1, 2, 4, 8):
                t1, d = timed(lambda: api.decompress(f, len(data), threads), 2)
                assert d == data
                def stream():
                    ds = api.dstream(threads)
                    try:
                        return ds.decode(f, 1 << 20, 1 << 20)[0]
                    finally:
                        ds.close()
                t2, d = timed(stream, 2)
                assert d == data
                print("    %d threads: FL2_decompressMt %5.2fs (%6.1f MB/s)  stream %5.2fs (%6.1f MB/s)" % (
                    threads, t1, mb / t1, t2, mb / t2))


def blocks_main(args):
    (name, api), = libs_of(args[:1])
    print("FastLzma2Block's native calls, level 6, cpus %d; total 32 MiB per case" % os.cpu_count())
    for bs in (64 << 10, 1 << 20, 16 << 20):
        blocks = [sample.mixed(bs, seed=100 + i) for i in range(max(1, (32 << 20) // bs))]
        for threads in (1, 8):
            c = api.cctx(threads)
            t, frames = timed(lambda: [c.compress(b, level=6) for b in blocks])
            c.close()
            t_mt, _ = timed(lambda: [api.decompress(f, bs, threads) for f in frames])
            d = api.dctx(threads)
            t_reuse, _ = timed(lambda: [d.decompress(f, bs) for f in frames])
            d.close()
            mb = len(blocks) * bs / (1 << 20)
            print("  block %6d KiB x %4d, %d threads: compress %6.1f MB/s | decompressMt per call %6.1f MB/s | reused DCtx %6.1f MB/s" % (
                bs >> 10, len(blocks), threads, mb / t, mb / t_mt, mb / t_reuse))


if __name__ == "__main__":
    {"encode": encode_main, "decode": decode_main, "blocks": blocks_main}[sys.argv[1]](sys.argv[2:])
