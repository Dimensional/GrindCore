"""The LZMA/LZMA2 PAL's argument checks (pal_sevenzip_lzma_v25_01.c; audit/lzma.md 3.6), with the zstd and Brotli PALs'
conventions: a NULL decoder, encoder, length, status or properties pointer is SZ_ERROR_PARAM (5) with nothing touched;
Free/FreeProbs/Destroy/Init/Construct of NULL do nothing; a NULL buffer is only bad with a nonzero size, so .NET's empty
arrays (pinned as NULL) still work; the decode calls refuse a decoder that was never allocated or was freed, and a
dicLimit past the dictionary. The shipped builds and nb17 pass everything to 7-Zip, which dereferences it: known defect
lzma-null-args, found with a harmless probe in a child process."""
import ctypes
import json
import textwrap
import unittest

import gctest
from gctest import lzmadec_util as D
from gctest.test_fl2 import faulted
from gctest.test_hashes import child, known

PARAM = 5

# Every bad-argument case, run in one child process: (label, Python expression, expected result or None for "returns
# nothing"). `L` is the library, `d`/`d2` constructed and allocated LZMA/LZMA2 decoders, `e`/`e2` encoders, `s` a
# valid circular input stream; n(x) is a c_size_t, P the 5 LZMA property bytes.
CASES = """
B = ctypes.byref
def n(x): return ctypes.c_size_t(x)
P = bytes([0x5D, 0, 0, 1, 0])
st = ctypes.c_int(0)
out = ctypes.create_string_buffer(64)
d = L.struct.CLzmaDec(); L.SZ_Lzma_v25_01_Dec_Construct(B(d)); L.SZ_Lzma_v25_01_Dec_Allocate(B(d), P, 5); L.SZ_Lzma_v25_01_Dec_Init(B(d))
d2 = L.struct.CLzma2Dec(); L.SZ_Lzma2_v25_01_Dec_Construct(B(d2)); L.SZ_Lzma2_v25_01_Dec_Allocate(B(d2), 16); L.SZ_Lzma2_v25_01_Dec_Init(B(d2))
freed = L.struct.CLzmaDec(); L.SZ_Lzma_v25_01_Dec_Construct(B(freed)); L.SZ_Lzma_v25_01_Dec_Allocate(B(freed), P, 5); L.SZ_Lzma_v25_01_Dec_Free(B(freed))
freed2 = L.struct.CLzma2Dec(); L.SZ_Lzma2_v25_01_Dec_Construct(B(freed2)); L.SZ_Lzma2_v25_01_Dec_Allocate(B(freed2), 16); L.SZ_Lzma2_v25_01_Dec_Free(B(freed2))
e = L.SZ_Lzma_v25_01_Enc_Create(); e2 = L.SZ_Lzma2_v25_01_Enc_Create()
lp = L.struct.CLzmaEncProps(); L.SZ_Lzma_v25_01_EncProps_Init(B(lp))
lp2 = L.struct.CLzma2EncProps(); L.SZ_Lzma2_v25_01_Enc_Construct(B(lp2))
ring = ctypes.create_string_buffer(1024)
s = L.struct.CBufferInStream(); s.buffer, s.size = ctypes.addressof(ring), 1024
bad_s = L.struct.CBufferInStream(); bad_s.buffer, bad_s.size, bad_s.remaining = ctypes.addressof(ring), 1024, 4096
null_s = L.struct.CBufferInStream(); null_s.size = 1024
u32 = ctypes.c_uint32(0)
cases = [
 ("Lzma2 Dec_Construct(NULL)", "L.SZ_Lzma2_v25_01_Dec_Construct(None)", None),
 ("Lzma2 Dec_FreeProbs(NULL)", "L.SZ_Lzma2_v25_01_Dec_FreeProbs(None)", None),
 ("Lzma2 Dec_Free(NULL)", "L.SZ_Lzma2_v25_01_Dec_Free(None)", None),
 ("Lzma2 Dec_Init(NULL)", "L.SZ_Lzma2_v25_01_Dec_Init(None)", None),
 ("Lzma2 Dec_AllocateProbs(NULL)", "L.SZ_Lzma2_v25_01_Dec_AllocateProbs(None, 16)", 5),
 ("Lzma2 Dec_Allocate(NULL)", "L.SZ_Lzma2_v25_01_Dec_Allocate(None, 16)", 5),
 ("Lzma2 Dec_DecodeToDic(NULL dec)", "L.SZ_Lzma2_v25_01_Dec_DecodeToDic(None, 0, b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToDic(NULL srcLen)", "L.SZ_Lzma2_v25_01_Dec_DecodeToDic(B(d2), 0, b'x', None, 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToDic(NULL status)", "L.SZ_Lzma2_v25_01_Dec_DecodeToDic(B(d2), 0, b'x', B(n(1)), 0, None)", 5),
 ("Lzma2 Dec_DecodeToDic(NULL src, size 1)", "L.SZ_Lzma2_v25_01_Dec_DecodeToDic(B(d2), 0, None, B(n(1)), 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToDic(dicLimit past the dictionary)", "L.SZ_Lzma2_v25_01_Dec_DecodeToDic(B(d2), d2.decoder.dicBufSize + 1, b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToDic(freed decoder)", "L.SZ_Lzma2_v25_01_Dec_DecodeToDic(B(freed2), 0, b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToBuf(NULL dec)", "L.SZ_Lzma2_v25_01_Dec_DecodeToBuf(None, out, B(n(64)), b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToBuf(NULL destLen)", "L.SZ_Lzma2_v25_01_Dec_DecodeToBuf(B(d2), out, None, b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToBuf(NULL dest, size 64)", "L.SZ_Lzma2_v25_01_Dec_DecodeToBuf(B(d2), None, B(n(64)), b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToBuf(NULL srcLen)", "L.SZ_Lzma2_v25_01_Dec_DecodeToBuf(B(d2), out, B(n(64)), b'x', None, 0, B(st))", 5),
 ("Lzma2 Dec_DecodeToBuf(NULL status)", "L.SZ_Lzma2_v25_01_Dec_DecodeToBuf(B(d2), out, B(n(64)), b'x', B(n(1)), 0, None)", 5),
 ("Lzma2 Dec_DecodeToBuf(freed decoder)", "L.SZ_Lzma2_v25_01_Dec_DecodeToBuf(B(freed2), out, B(n(64)), b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma2 Dec_Parse(NULL dec)", "L.SZ_Lzma2_v25_01_Dec_Parse(None, 64, b'x', B(n(1)), 0)", 0),
 ("Lzma2 Dec_Parse(NULL srcLen)", "L.SZ_Lzma2_v25_01_Dec_Parse(B(d2), 64, b'x', None, 0)", 0),
 ("Lzma2 Decode(NULL destLen)", "L.SZ_Lzma2_v25_01_Decode(out, None, b'x', B(n(1)), 16, 0, B(st))", 5),
 ("Lzma2 Decode(NULL srcLen)", "L.SZ_Lzma2_v25_01_Decode(out, B(n(64)), b'x', None, 16, 0, B(st))", 5),
 ("Lzma2 Decode(NULL status)", "L.SZ_Lzma2_v25_01_Decode(out, B(n(64)), b'x', B(n(1)), 16, 0, None)", 5),
 ("Lzma2 Decode(NULL dest, size 64)", "L.SZ_Lzma2_v25_01_Decode(None, B(n(64)), b'x', B(n(1)), 16, 0, B(st))", 5),
 ("Lzma2 Decode(NULL src, size 1)", "L.SZ_Lzma2_v25_01_Decode(out, B(n(64)), None, B(n(1)), 16, 0, B(st))", 5),
 ("Lzma2 Enc_Construct(NULL)", "L.SZ_Lzma2_v25_01_Enc_Construct(None)", None),
 ("Lzma2 Enc_Normalize(NULL)", "L.SZ_Lzma2_v25_01_Enc_Normalize(None)", None),
 ("Lzma2 Enc_Destroy(NULL)", "L.SZ_Lzma2_v25_01_Enc_Destroy(None)", None),
 ("Lzma2 Enc_SetProps(NULL enc)", "L.SZ_Lzma2_v25_01_Enc_SetProps(None, B(lp2))", 5),
 ("Lzma2 Enc_SetProps(NULL props)", "L.SZ_Lzma2_v25_01_Enc_SetProps(e2, None)", 5),
 ("Lzma2 Enc_SetDataSize(NULL)", "L.SZ_Lzma2_v25_01_Enc_SetDataSize(None, 1)", None),
 ("Lzma2 Enc_WriteProperties(NULL)", "L.SZ_Lzma2_v25_01_Enc_WriteProperties(None)", 0xFF),
 ("Lzma2 Enc_Encode2(NULL enc)", "L.SZ_Lzma2_v25_01_Enc_Encode2(None, out, B(n(64)), b'x', 1, None)", 5),
 ("Lzma2 Enc_Encode2(NULL outBufSize)", "L.SZ_Lzma2_v25_01_Enc_Encode2(e2, out, None, b'x', 1, None)", 5),
 ("Lzma2 Enc_Encode2(NULL outBuf, size 64)", "L.SZ_Lzma2_v25_01_Enc_Encode2(e2, None, B(n(64)), b'x', 1, None)", 5),
 ("Lzma2 Enc_Encode2(NULL inData, size 1)", "L.SZ_Lzma2_v25_01_Enc_Encode2(e2, out, B(n(64)), None, 1, None)", 5),
 ("Lzma2 Enc_EncodeMultiCallPrepare(NULL)", "L.SZ_Lzma2_v25_01_Enc_EncodeMultiCallPrepare(None)", 5),
 ("Lzma2 Enc_EncodeMultiCall(NULL enc)", "L.SZ_Lzma2_v25_01_Enc_EncodeMultiCall(None, out, B(n(64)), B(s), 0)", 5),
 ("Lzma2 Enc_EncodeMultiCall(NULL outBufSize)", "L.SZ_Lzma2_v25_01_Enc_EncodeMultiCall(e2, out, None, B(s), 0)", 5),
 ("Lzma2 Enc_EncodeMultiCall(NULL stream)", "L.SZ_Lzma2_v25_01_Enc_EncodeMultiCall(e2, out, B(n(64)), None, 0)", 5),
 ("Lzma2 Enc_EncodeMultiCall(stream, remaining > size)", "L.SZ_Lzma2_v25_01_Enc_EncodeMultiCall(e2, out, B(n(64)), B(bad_s), 0)", 5),
 ("Lzma2 Enc_EncodeMultiCall(stream, NULL buffer)", "L.SZ_Lzma2_v25_01_Enc_EncodeMultiCall(e2, out, B(n(64)), B(null_s), 0)", 5),
 ("Lzma Dec_Construct(NULL)", "L.SZ_Lzma_v25_01_Dec_Construct(None)", None),
 ("Lzma Dec_Init(NULL)", "L.SZ_Lzma_v25_01_Dec_Init(None)", None),
 ("Lzma Dec_FreeProbs(NULL)", "L.SZ_Lzma_v25_01_Dec_FreeProbs(None)", None),
 ("Lzma Dec_Free(NULL)", "L.SZ_Lzma_v25_01_Dec_Free(None)", None),
 ("Lzma Dec_AllocateProbs(NULL dec)", "L.SZ_Lzma_v25_01_Dec_AllocateProbs(None, P, 5)", 5),
 ("Lzma Dec_AllocateProbs(NULL props, size 5)", "L.SZ_Lzma_v25_01_Dec_AllocateProbs(B(d), None, 5)", 5),
 ("Lzma Dec_Allocate(NULL dec)", "L.SZ_Lzma_v25_01_Dec_Allocate(None, P, 5)", 5),
 ("Lzma Dec_Allocate(NULL props, size 5)", "L.SZ_Lzma_v25_01_Dec_Allocate(B(d), None, 5)", 5),
 ("Lzma Dec_DecodeToDic(NULL dec)", "L.SZ_Lzma_v25_01_Dec_DecodeToDic(None, 0, b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma Dec_DecodeToDic(NULL srcLen)", "L.SZ_Lzma_v25_01_Dec_DecodeToDic(B(d), 0, b'x', None, 0, B(st))", 5),
 ("Lzma Dec_DecodeToDic(NULL status)", "L.SZ_Lzma_v25_01_Dec_DecodeToDic(B(d), 0, b'x', B(n(1)), 0, None)", 5),
 ("Lzma Dec_DecodeToDic(dicLimit past the dictionary)", "L.SZ_Lzma_v25_01_Dec_DecodeToDic(B(d), d.dicBufSize + 1, b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma Dec_DecodeToDic(freed decoder)", "L.SZ_Lzma_v25_01_Dec_DecodeToDic(B(freed), 0, b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma Dec_DecodeToBuf(NULL dec)", "L.SZ_Lzma_v25_01_Dec_DecodeToBuf(None, out, B(n(64)), b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma Dec_DecodeToBuf(NULL destLen)", "L.SZ_Lzma_v25_01_Dec_DecodeToBuf(B(d), out, None, b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma Dec_DecodeToBuf(NULL dest, size 64)", "L.SZ_Lzma_v25_01_Dec_DecodeToBuf(B(d), None, B(n(64)), b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma Dec_DecodeToBuf(NULL srcLen)", "L.SZ_Lzma_v25_01_Dec_DecodeToBuf(B(d), out, B(n(64)), b'x', None, 0, B(st))", 5),
 ("Lzma Dec_DecodeToBuf(NULL status)", "L.SZ_Lzma_v25_01_Dec_DecodeToBuf(B(d), out, B(n(64)), b'x', B(n(1)), 0, None)", 5),
 ("Lzma Dec_DecodeToBuf(freed decoder)", "L.SZ_Lzma_v25_01_Dec_DecodeToBuf(B(freed), out, B(n(64)), b'x', B(n(1)), 0, B(st))", 5),
 ("Lzma Dec_LzmaDecode(NULL destLen)", "L.SZ_Lzma_v25_01_Dec_LzmaDecode(out, None, P * 2, B(n(10)), P, 5, 0, B(st))", 5),
 ("Lzma Dec_LzmaDecode(NULL srcLen)", "L.SZ_Lzma_v25_01_Dec_LzmaDecode(out, B(n(64)), P * 2, None, P, 5, 0, B(st))", 5),
 ("Lzma Dec_LzmaDecode(NULL status)", "L.SZ_Lzma_v25_01_Dec_LzmaDecode(out, B(n(64)), P * 2, B(n(10)), P, 5, 0, None)", 5),
 ("Lzma Dec_LzmaDecode(NULL props, size 5)", "L.SZ_Lzma_v25_01_Dec_LzmaDecode(out, B(n(64)), P * 2, B(n(10)), None, 5, 0, B(st))", 5),
 ("Lzma Dec_LzmaDecode(NULL src, size 10)", "L.SZ_Lzma_v25_01_Dec_LzmaDecode(out, B(n(64)), None, B(n(10)), P, 5, 0, B(st))", 5),
 ("Lzma EncProps_Init(NULL)", "L.SZ_Lzma_v25_01_EncProps_Init(None)", None),
 ("Lzma EncProps_Normalize(NULL)", "L.SZ_Lzma_v25_01_EncProps_Normalize(None)", None),
 ("Lzma EncProps_GetDictSize(NULL)", "L.SZ_Lzma_v25_01_EncProps_GetDictSize(None)", 0),
 ("Lzma Enc_Destroy(NULL)", "L.SZ_Lzma_v25_01_Enc_Destroy(None)", None),
 ("Lzma Enc_SetProps(NULL enc)", "L.SZ_Lzma_v25_01_Enc_SetProps(None, B(lp))", 5),
 ("Lzma Enc_SetProps(NULL props)", "L.SZ_Lzma_v25_01_Enc_SetProps(e, None)", 5),
 ("Lzma Enc_SetDataSize(NULL)", "L.SZ_Lzma_v25_01_Enc_SetDataSize(None, 1)", None),
 ("Lzma Enc_WriteProperties(NULL enc)", "L.SZ_Lzma_v25_01_Enc_WriteProperties(None, out, B(n(5)))", 5),
 ("Lzma Enc_WriteProperties(NULL size)", "L.SZ_Lzma_v25_01_Enc_WriteProperties(e, out, None)", 5),
 ("Lzma Enc_WriteProperties(NULL buffer, size 5)", "L.SZ_Lzma_v25_01_Enc_WriteProperties(e, None, B(n(5)))", 5),
 ("Lzma Enc_IsWriteEndMark(NULL)", "L.SZ_Lzma_v25_01_Enc_IsWriteEndMark(None)", 0),
 ("Lzma Enc_Encode(NULL enc)", "L.SZ_Lzma_v25_01_Enc_Encode(None, None, None, None)", 5),
 ("Lzma Enc_Encode(NULL streams)", "L.SZ_Lzma_v25_01_Enc_Encode(e, None, None, None)", 5),
 ("Lzma Enc_MemEncode(NULL enc)", "L.SZ_Lzma_v25_01_Enc_MemEncode(None, out, B(n(64)), b'x', 1, 1, None)", 5),
 ("Lzma Enc_MemEncode(NULL destLen)", "L.SZ_Lzma_v25_01_Enc_MemEncode(e, out, None, b'x', 1, 1, None)", 5),
 ("Lzma Enc_MemEncode(NULL dest, size 64)", "L.SZ_Lzma_v25_01_Enc_MemEncode(e, None, B(n(64)), b'x', 1, 1, None)", 5),
 ("Lzma Enc_MemEncode(NULL src, size 1)", "L.SZ_Lzma_v25_01_Enc_MemEncode(e, out, B(n(64)), None, 1, 1, None)", 5),
 ("Lzma Enc_LzmaEncode(NULL destLen)", "L.SZ_Lzma_v25_01_Enc_LzmaEncode(out, None, b'x', 1, B(lp), out, B(n(5)), 1, None)", 5),
 ("Lzma Enc_LzmaEncode(NULL props)", "L.SZ_Lzma_v25_01_Enc_LzmaEncode(out, B(n(64)), b'x', 1, None, out, B(n(5)), 1, None)", 5),
 ("Lzma Enc_LzmaEncode(NULL propsSize)", "L.SZ_Lzma_v25_01_Enc_LzmaEncode(out, B(n(64)), b'x', 1, B(lp), out, None, 1, None)", 5),
 ("Lzma Enc_LzmaEncode(NULL dest, size 64)", "L.SZ_Lzma_v25_01_Enc_LzmaEncode(None, B(n(64)), b'x', 1, B(lp), out, B(n(5)), 1, None)", 5),
 ("Lzma Enc_LzmaCodeMultiCallPrepare(NULL enc)", "L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCallPrepare(None, B(u32), B(u32), 0)", 5),
 ("Lzma Enc_LzmaCodeMultiCallPrepare(NULL sizes)", "L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCallPrepare(e, None, None, 0)", 5),
 ("Lzma Enc_LzmaCodeMultiCall(NULL enc)", "L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCall(None, out, B(n(64)), B(s), 0, B(u32), 0)", 5),
 ("Lzma Enc_LzmaCodeMultiCall(NULL stream)", "L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCall(e, out, B(n(64)), None, 0, B(u32), 0)", 5),
 ("Lzma Enc_LzmaCodeMultiCall(NULL availableBytes)", "L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCall(e, out, B(n(64)), B(s), 0, None, 0)", 5),
 ("Lzma Enc_LzmaCodeMultiCall(stream, remaining > size)", "L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCall(e, out, B(n(64)), B(bad_s), 0, B(u32), 0)", 5),
]
"""


class LzmaArgsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = gctest.LIB
        rc, _, err = child("L.SZ_Lzma_v25_01_Dec_Free(None)\nprint('ok')\n", timeout=60)
        cls.unfixed = faulted(rc, err)

    def test_null_and_bad_arguments(self):
        """Every bad-argument case for the 43 LZMA/LZMA2 exports (CASES), in one child process: each returns its
        documented failure value (SZ_ERROR_PARAM; 0xFF from Lzma2 Enc_WriteProperties; 0 from the getters; Parse's
        NOT_SPECIFIED status) or does nothing, and nothing crashes."""
        if self.unfixed:
            known(self, "lzma-null-args")
        code = textwrap.dedent(CASES) + textwrap.dedent("""
            import json
            got = []
            for label, expr, want in cases:
                print("CASE", label, flush=True)
                r = eval(expr)
                got.append((label, r, want))
            L.SZ_Lzma_v25_01_Dec_Free(B(d)); L.SZ_Lzma2_v25_01_Dec_Free(B(d2))
            L.SZ_Lzma_v25_01_Enc_Destroy(e); L.SZ_Lzma2_v25_01_Enc_Destroy(e2)
            print("RESULT " + json.dumps(got))
        """)
        rc, out, err = child(code, timeout=120)
        last = [l for l in out.splitlines() if l.startswith("CASE ")]
        self.assertFalse(faulted(rc, err), "crashed at %s: %s" % (last[-1] if last else "setup", err[-1500:]))
        self.assertEqual(rc, 0, err[-1500:])
        results = json.loads([l for l in out.splitlines() if l.startswith("RESULT ")][-1][7:])
        self.assertGreater(len(results), 80)
        for label, r, want in results:
            with self.subTest(case=label):
                self.assertEqual(r, want)

    def test_null_buffer_with_size_zero_is_an_empty_buffer(self):
        """NULL with size 0 must give exactly what a real zero-length buffer gives (an empty .NET array is pinned as
        NULL), for every function that takes a buffer and a size."""
        L, B = self.L, ctypes.byref
        A = D.Api(L)
        P = bytes([0x5D, 0, 0, 1, 0])
        empty = ctypes.create_string_buffer(1)

        def both(f):
            return [f(None), f(empty)]

        def lzma_decode(buf):
            dl, sl, st = ctypes.c_size_t(0), ctypes.c_size_t(0), ctypes.c_int(-1)
            return L.SZ_Lzma_v25_01_Dec_LzmaDecode(buf, B(dl), buf, B(sl), P, 5, 0, B(st)), dl.value, sl.value, st.value

        def lzma2_decode(buf):
            dl, sl, st = ctypes.c_size_t(0), ctypes.c_size_t(0), ctypes.c_int(-1)
            return L.SZ_Lzma2_v25_01_Decode(buf, B(dl), buf, B(sl), 16, 0, B(st)), dl.value, sl.value, st.value

        def to_buf(kind):
            def f(buf):
                d = A.new(kind)
                A.allocate(kind, d, P if kind == "lzma" else 16)
                A.init(kind, d)
                r = A.to_buf(kind, d, buf, 0, buf, 0, D.FINISH_ANY)
                A.free(kind, d)
                return r
            return f

        def mem_encode(buf):
            p = L.struct.CLzmaEncProps()
            L.SZ_Lzma_v25_01_EncProps_Init(B(p))
            enc = L.SZ_Lzma_v25_01_Enc_Create()
            L.SZ_Lzma_v25_01_Enc_SetProps(enc, B(p))
            dst = ctypes.create_string_buffer(64)
            dl = ctypes.c_size_t(64)
            rc = L.SZ_Lzma_v25_01_Enc_MemEncode(enc, dst, B(dl), buf, 0, 1, None)
            L.SZ_Lzma_v25_01_Enc_Destroy(enc)
            return rc, dst.raw[:dl.value]

        def encode2(buf):
            p = L.struct.CLzma2EncProps()
            L.SZ_Lzma2_v25_01_Enc_Construct(B(p))
            enc = L.SZ_Lzma2_v25_01_Enc_Create()
            L.SZ_Lzma2_v25_01_Enc_SetProps(enc, B(p))
            dst = ctypes.create_string_buffer(64)
            dl = ctypes.c_size_t(64)
            rc = L.SZ_Lzma2_v25_01_Enc_Encode2(enc, dst, B(dl), buf, 0, None)
            L.SZ_Lzma2_v25_01_Enc_Destroy(enc)
            return rc, dst.raw[:dl.value]

        for name, f in (("LzmaDecode", lzma_decode), ("Lzma2Decode", lzma2_decode), ("Lzma DecodeToBuf", to_buf("lzma")),
                        ("Lzma2 DecodeToBuf", to_buf("lzma2")), ("MemEncode", mem_encode), ("Encode2", encode2)):
            with self.subTest(function=name):
                a, b = both(f)
                self.assertEqual(a, b, "NULL with size 0 differs from an empty buffer")
                self.assertNotEqual(a[0], PARAM, "an empty buffer was refused")
