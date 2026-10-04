"""Compressed-output determinism: compress a fixed, generated corpus with every codec at several settings and print one
SHA-256 per (codec, setting, input). Run it with two libraries (a release and a new build) and on every RID, then diff
the outputs: an identical line means byte-identical compressed output.
Only stateless calls and library-allocated contexts whose layout hasn't changed since GrindCore.net v0.9.0 are used,
so it runs against older builds too. Python 3.6+, stdlib only.
  python determinism.py --lib <libGrindCore.so | GrindCore.dll | libGrindCore.dylib> [--out file]"""
import argparse, ctypes, hashlib, os, random, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcnative  # noqa: E402
from gctest import brotli_util, fl2_util, lz4_util, lzma_util, sample, zstd_util  # noqa: E402


def corpus():
    """Fixed inputs, the same on every Python 3 and host (Mersenne Twister with an int seed, getrandbits only)."""
    r = random.Random(20261003)
    letters = b"abcdefghijklmnopqrstuvwxyz"
    words = [bytes(letters[r.getrandbits(32) % 26] for _ in range(2 + r.getrandbits(32) % 8)) for _ in range(3000)]
    text = b" ".join(words[r.getrandbits(32) % len(words)] for _ in range(240000))[: 1 << 20]
    noise = r.getrandbits(8 * (256 << 10)).to_bytes(256 << 10, "little")
    # structured binary: records with counters and repeated headers, like disc sectors or tables
    rec = b"".join(b"HDR!" + i.to_bytes(4, "little") + bytes([i & 0xFF]) * 24 + noise[i * 32:i * 32 + 32] for i in range(4096))
    # plus the suite's own 70 KB samples, on which x87 floating point changed zstd 1.5.2's L5/L9 output (build-exam.md)
    return [("empty", b""), ("text-100B", text[:100]), ("text-1M", text), ("noise-256K", noise),
            ("zeros-1M", bytes(1 << 20)), ("records-256K", rec), ("mixed-2.5M", text + noise + bytes(512 << 10) + rec + text[:256 << 10]),
            ("s-text-70K", sample.text(70000)), ("s-mixed-70K", sample.mixed(70000))]


def raw(lib, name, *argtypes):
    f = getattr(lib, name)
    f.restype, f.argtypes = ctypes.c_int32, list(argtypes)
    return f


def codecs(L, lib):
    u32p, sizep = ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_size_t)
    zc = {"zlib-1.3.1": raw(lib, "DN8_ZLib_v1_3_1_Compress2", ctypes.c_char_p, u32p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int32),
          "zlib-ng-2.2.1": raw(lib, "DN9_ZLibNg_v2_2_1_Compress2", ctypes.c_char_p, u32p, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int32)}
    bz = raw(lib, "SZ_BZip2_v1_0_8_CompressBlock", ctypes.c_char_p, sizep, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int32, ctypes.c_int32)

    def zlib_like(f, level):
        def run(data):
            n = ctypes.c_uint32(len(data) + len(data) // 4 + 4096)  # zlib-ng's deflate_quick (L1) expands noise past 1%
            dst = ctypes.create_string_buffer(n.value)
            rc = f(dst, ctypes.byref(n), data, len(data), level)
            return dst.raw[:n.value] if rc == 0 else "rc %d" % rc
        return run

    def bzip2(block):
        def run(data):
            n = ctypes.c_size_t(len(data) + len(data) // 100 + 600)
            dst = ctypes.create_string_buffer(n.value)
            rc = bz(dst, ctypes.byref(n), data, len(data), block, 0)
            return dst.raw[:n.value] if rc >= 0 else "rc %d" % rc
        return run

    z7, z2 = zstd_util.ZStd(L, "1.5.7"), zstd_util.ZStd(L, "1.5.2")
    br, fl2, lz4 = brotli_util.pal(L), fl2_util.grindcore(L), lz4_util.Lz4(L)

    def zstd(z, level):
        return lambda data: (lambda r: r[1] if r[1] is not None else "rc %d" % r[0])(z.compress_block(data, level))

    def brotli(q):
        return lambda data: (lambda r: r[1] if r[0] else "failed")(br.compress(data, quality=q, lgwin=22))

    def lz4hc(level):
        return lambda data: (lambda r: r[1] if r[0] > 0 else ("" if r[0] == 0 and not data else "rc %d" % r[0]))(lz4.compress_hc(data, level))

    def lz4f(level):
        return lambda data: lz4.frame_encoder(lz4_util.prefs(lz4.Prefs, level=level)).encode(data, 1 << 16)

    def lzma_block(level):
        return lambda data: (lambda r: r["stream"] if r["rc"] == 0 else "rc %d" % r["rc"])(lzma_util.block_encode(L, data, level))

    def lzma2_stream(level):
        return lambda data: (lambda r: r["stream"] if r["rc"] == 0 else "rc %d" % r["rc"])(lzma_util.encode(L, data, level))

    out = []
    for name, f in zc.items():
        out += [(name, "L%d" % lv, zlib_like(f, lv)) for lv in (1, 6, 9)]
    out += [("bzip2-1.0.8", "B%d" % b, bzip2(b)) for b in (1, 9)]
    out += [("zstd-1.5.7", "L%d" % lv, zstd(z7, lv)) for lv in (-5, 1, 3, 5, 9, 19)]
    out += [("zstd-1.5.2", "L%d" % lv, zstd(z2, lv)) for lv in (1, 3, 5, 9, 19)]
    out += [("brotli-1.1.0", "Q%d" % q, brotli(q)) for q in (1, 5, 9, 10, 11)]
    out += [("lz4-1.10.0", "HC%d" % lv, lz4hc(lv)) for lv in (9, 12)]
    out += [("lz4f-1.10.0", "L%d" % lv, lz4f(lv)) for lv in (0, 9)]
    out += [("lzma-25.01", "L%d" % lv, lzma_block(lv)) for lv in (1, 5, 9)]
    out += [("lzma2-stream", "L%d" % lv, lzma2_stream(lv)) for lv in (1, 5)]
    out += [("fl2-1.0.1", "L%d" % lv, (lambda lv: lambda data: fl2.compress(data, level=lv))(lv)) for lv in (1, 6, 10)]
    out += [("fl2-1.0.1", "L6-T2", lambda data: fl2.compress(data, level=6, threads=2))]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True)
    ap.add_argument("--out")
    ap.add_argument("--skip", action="append", default=[], help="a codec to leave out (repeatable), e.g. zlib-ng-2.2.1 "
                    "for shipped linux-arm builds, whose NEON Adler-32 dies of SIGBUS (audit/platforms.md 10.7)")
    a = ap.parse_args()
    L = gcnative.load(a.lib)
    lib = ctypes.CDLL(a.lib)
    lines = ["# %s (%s, Python %d.%d)" % (os.path.abspath(a.lib), gcnative.target(), *sys.version_info[:2])]
    inputs = corpus()
    for codec, setting, fn in codecs(L, lib):
        if codec in a.skip:
            continue
        for name, data in inputs:
            try:
                r = fn(data)
            except Exception as e:  # noqa: BLE001 - record and go on; an error is a result too
                r = "error %s: %s" % (type(e).__name__, str(e)[:60])
            if isinstance(r, bytes):
                lines.append("%-14s %-6s %-13s %9d %s" % (codec, setting, name, len(r), hashlib.sha256(r).hexdigest()[:16]))
            else:
                lines.append("%-14s %-6s %-13s %9s %s" % (codec, setting, name, "-", r))
            print(lines[-1], flush=True)
    if a.out:
        with open(a.out, "w") as f:
            f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
