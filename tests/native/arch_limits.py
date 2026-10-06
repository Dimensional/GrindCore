"""Architecture limitations, measured: run with the library of each RID (and that RID's Python) and diff the outputs.
Every line is "key: value" without timings, so the same line on two RIDs means the same behaviour. Not part of the
test suite (gctest/test_arch_limits.py pins the cheap facts); the audit's architecture-limitations.md has the results.

  python arch_limits.py --lib <GrindCore library> [--official <lib7zref from ref/build_7zip_ref.py>] [--big]

  --official  the LZMA checks through official 7-Zip 25.01 too (same process, same bitness)
  --big       the large-input cases: LZMA level 7 with its default dictionary on 82 MiB, and 174 MB whose second copy
              of an 8 MiB block is ~158 MiB back (LZMA with 128 and 192 MiB dictionaries, Fast-LZMA2 high level 9).
              About 1.5 GB of memory; a 32-bit process may report SZ_ERROR_MEM (on Windows, see "large-address-aware").
Python 3.6+, stdlib only."""
import argparse, ctypes, hashlib, lzma, os, random, struct, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gcnative  # noqa: E402
import determinism  # noqa: E402  (its fixed corpus)
from gctest import fl2_util as F, lz4_util  # noqa: E402

MIB = 1 << 20


def sha(b):
    return hashlib.sha256(b).hexdigest()[:16]


def laa():
    """Windows: is this interpreter large-address-aware (4 GB of address space as a 32-bit process, else 2 GB)?"""
    with open(sys.executable, "rb") as f:
        b = f.read(4096)
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    return bool(struct.unpack_from("<H", b, pe + 22)[0] & 0x20)


class Official(object):
    def __init__(self, path):
        r = ctypes.CDLL(path)
        vp, sz = ctypes.c_void_p, ctypes.c_size_t
        for name, res, args in [("LzmaEncProps_Init", None, [vp]),
                                ("LzmaEncode", ctypes.c_int, [vp, vp, vp, sz, vp, vp, vp, ctypes.c_int, vp, vp, vp]),
                                ("LzmaEnc_Create", vp, [vp]), ("LzmaEnc_Destroy", None, [vp, vp, vp]),
                                ("LzmaEnc_SetProps", ctypes.c_int, [vp, vp])]:
            fn = getattr(r, name)
            fn.restype, fn.argtypes = res, args
            setattr(self, name, fn)
        self.alloc = ctypes.addressof(ctypes.c_byte.in_dll(r, "g_Alloc"))
        try:
            self.big = ctypes.addressof(ctypes.c_byte.in_dll(r, "g_BigAlloc"))
        except ValueError:  # off Windows g_BigAlloc is a macro for g_AlignedAlloc (Alloc.h)
            self.big = ctypes.addressof(ctypes.c_byte.in_dll(r, "g_AlignedAlloc"))


def lzma_side(L, O):
    """(init, set_props, encode) for GrindCore (O None) or official 7-Zip."""
    if O is None:
        def set_props(p):
            e = L.SZ_Lzma_v25_01_Enc_Create()
            try:
                return L.SZ_Lzma_v25_01_Enc_SetProps(e, ctypes.byref(p))
            finally:
                L.SZ_Lzma_v25_01_Enc_Destroy(e)

        def encode(dst, dlen, data, p, pe, plen):
            return L.SZ_Lzma_v25_01_Enc_LzmaEncode(dst, dlen, data, len(data), ctypes.byref(p), pe, plen, 0, None)
        return L.SZ_Lzma_v25_01_EncProps_Init, set_props, encode

    def set_props(p):
        e = O.LzmaEnc_Create(O.alloc)
        try:
            return O.LzmaEnc_SetProps(e, ctypes.byref(p))
        finally:
            O.LzmaEnc_Destroy(e, O.alloc, O.big)

    def encode(dst, dlen, data, p, pe, plen):
        return O.LzmaEncode(dst, dlen, data, len(data), ctypes.byref(p), pe, plen, 0, None, O.alloc, O.big)
    return O.LzmaEncProps_Init, set_props, encode


def lzma_encode(L, side, data, level, dict_bytes):
    init, _, encode = side
    p = L.struct.CLzmaEncProps()   # official LzmaEnc.h; GrindCore's is the same file
    init(ctypes.byref(p))
    p.level, p.dictSize, p.numThreads = level, dict_bytes, 1
    cap = len(data) // 4 + (1 << 20)
    dst, dlen = ctypes.create_string_buffer(cap), ctypes.c_size_t(cap)
    pe, plen = ctypes.create_string_buffer(5), ctypes.c_size_t(5)
    rc = encode(dst, ctypes.byref(dlen), data, p, pe, ctypes.byref(plen))
    if rc:
        return "rc %d" % rc
    props, out = pe.raw[:5], dst.raw[:dlen.value]
    ok = lzma.decompress(props + struct.pack("<Q", len(data)) + out, format=lzma.FORMAT_ALONE) == data
    return "%d bytes, dictionary %d MiB, sha256 %s, %s" % (len(out), struct.unpack("<I", props[1:5])[0] >> 20, sha(out),
                                                          "decodes" if ok else "DOES NOT DECODE")


def long_distance():
    r8 = random.Random(7).getrandbits(8 * (8 << 20)).to_bytes(8 << 20, "little")
    return r8 + bytes(150 << 20) + r8


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True)
    ap.add_argument("--official")
    ap.add_argument("--big", action="store_true")
    a = ap.parse_args()
    L = gcnative.load(a.lib)
    bits = 8 * ctypes.sizeof(ctypes.c_void_p)
    print("target: %s, %d-bit%s" % (gcnative.target(), bits,
                                     ", large-address-aware: %s" % laa() if os.name == "nt" and bits == 32 else ""))

    sides = [("GrindCore", lzma_side(L, None))]
    if a.official:
        sides.append(("official", lzma_side(L, Official(a.official))))
    tiny = random.Random(1).getrandbits(8 * 4096).to_bytes(4096, "little")
    for name, side in sides:
        defaults = []
        for level in range(10):   # the property bytes of a tiny one-shot encode: Normalize's default, unshrunk
            init, _, encode = side
            p = L.struct.CLzmaEncProps()
            init(ctypes.byref(p))
            p.level, p.numThreads = level, 1
            dst, dlen = ctypes.create_string_buffer(1 << 16), ctypes.c_size_t(1 << 16)
            pe, plen = ctypes.create_string_buffer(5), ctypes.c_size_t(5)
            rc = encode(dst, ctypes.byref(dlen), tiny, p, pe, ctypes.byref(plen))
            d = struct.unpack("<I", pe.raw[1:5])[0]
            defaults.append("L%d %s" % (level, "rc %d" % rc if rc else "%d MiB" % (d >> 20) if d >= MIB else "%d KiB" % (d >> 10)))
        print("lzma %s default dictionary: %s" % (name, ", ".join(defaults)))
        accepted = []
        for mib in (128, 129, 160, 192, 256):
            p = L.struct.CLzmaEncProps()
            side[0](ctypes.byref(p))
            p.level, p.dictSize = 9, mib * MIB
            accepted.append("%d MiB rc %d" % (mib, side[1](p)))
        print("lzma %s SetProps with an explicit dictionary: %s" % (name, ", ".join(accepted)))

    c = L.FL2_createCCtx()
    for high, label in ((0, "normal"), (1, "high")):
        row = []
        for level in range(1, 11):
            L.FL2_CCtx_setParameter(c, F.HIGH_COMPRESSION, high)
            L.FL2_CCtx_setParameter(c, F.LEVEL, level)
            row.append("%d: %d MiB" % (level, L.FL2_CCtx_getParameter(c, F.DICTIONARY_SIZE) >> 20))
        print("fl2 %s levels, dictionary: %s" % (label, ", ".join(row)))
    for mib in (128, 129, 256):
        r = L.FL2_CCtx_setParameter(c, F.DICTIONARY_SIZE, mib * MIB)
        print("fl2 explicit dictionarySize %d MiB: %s" % (mib, "error %d" % (F.SIZE_MAX + 1 - r) if r > F.SIZE_MAX - F.MAX_CODE else "ok"))
    L.FL2_freeCCtx(c)

    lz = lz4_util.Lz4(L)
    for name, data in determinism.corpus():
        if name not in ("text-1M", "mixed-2.5M"):
            continue
        row = ["frame L%d %s" % (lv, sha(lz.frame_encoder(lz4_util.prefs(lz.Prefs, level=lv)).encode(data, 1 << 16)))
               for lv in (-1, 0, 1, 2, 9)]
        row.append("block fast %s" % sha(lz.compress_fast(data)[1]))   # (result, block)
        row.append("block HC9 %s" % sha(lz.compress_hc(data, 9)[1]))
        print("lz4 %s: %s" % (name, ", ".join(row)))

    if a.big:
        r8 = random.Random(7).getrandbits(8 * (8 << 20)).to_bytes(8 << 20, "little")
        data = r8 + bytes(66 << 20) + r8
        for name, side in sides:
            print("lzma %s 82 MiB, level 7 default dictionary: %s" % (name, lzma_encode(L, side, data, 7, 0)))
        data = long_distance()
        for name, side in sides:
            for mib in (128, 192):
                print("lzma %s 174 MB long distance, %d MiB dictionary: %s" % (name, mib, lzma_encode(L, side, data, 7, mib * MIB)))
        c = L.FL2_createCCtx()
        L.FL2_CCtx_setParameter(c, F.HIGH_COMPRESSION, 1)
        L.FL2_CCtx_setParameter(c, F.LEVEL, 9)
        cap = L.FL2_compressBound(len(data))
        dst = ctypes.create_string_buffer(cap)
        n = L.FL2_compressCCtx(c, dst, cap, data, len(data), 0)
        L.FL2_freeCCtx(c)
        if n > F.SIZE_MAX - F.MAX_CODE:
            print("fl2 174 MB long distance, high level 9: error %d" % (F.SIZE_MAX + 1 - n))
        else:
            out = dst.raw[:n]
            print("fl2 174 MB long distance, high level 9: %d bytes, dictionary property %d (%d MiB), sha256 %s" % (
                n, out[0] & 0x3F, F.dict_size_from_prop(out[0]) >> 20, sha(out)))


if __name__ == "__main__":
    main()
