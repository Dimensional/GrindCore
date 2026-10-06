"""Behaviour that depends on the pointer width or the CPU architecture by upstream design, not defects. Each is
documented in the audit's architecture-limitations.md; these tests pin it, so a change shows up (a different build
option, an updated vendored library), on every RID.

  - 7-Zip 25.01's LZMA/LZMA2 default dictionary at levels 7-9 depends on sizeof(size_t) (LzmaEnc.c:81-86):
    64-bit 128/256/256 MiB, 32-bit 64 MiB.
  - 7-Zip's encoder refuses a dictionary over 128 MiB on 32-bit x86 (LzmaEnc.c:557-562, documented in LzmaEnc.h:16).
    Its position-slot table (kNumLogBits, LzmaEnc.c:214) is too small for larger distances there. ARM builds compute
    the slot with a bit-scan instruction instead (LZMA_LOG_BSR, LzmaEnc.c:144-153) and have no such check.
  - Fast-LZMA2 caps every dictionary at 128 MiB on 32-bit (FL2_DICTLOG_MAX_32, fast-lzma2.h:454-456): its high-
    compression levels 9 and 10 get 128 MiB there (fl2_compress.c:128), and a larger explicit size is refused.
Only parameters are set here, so nothing allocates a dictionary. The memory side of 32-bit is measured by
arch_limits.py --big."""
import ctypes
import unittest

import gcnative
import gctest
from gctest import fl2_util as F

MIB = 1 << 20
SZ_ERROR_PARAM = 5
BITS = 8 * ctypes.sizeof(ctypes.c_void_p)
X86_32 = gcnative.target().endswith("-x86")


class ArchLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = gctest.LIB

    def lzma_props(self, level, dict_bytes=0):
        p = self.L.struct.CLzmaEncProps()
        self.L.SZ_Lzma_v25_01_EncProps_Init(ctypes.byref(p))
        p.level, p.dictSize = level, dict_bytes
        return p

    def test_lzma_default_dictionary_follows_pointer_width(self):
        """LzmaEncProps_Normalize's defaults, with the input size unknown (so not shrunk to it)."""
        want = [64 << 10, 256 << 10, 1 * MIB, 4 * MIB, 16 * MIB, 32 * MIB, 64 * MIB] + (
            [128 * MIB, 256 * MIB, 256 * MIB] if BITS == 64 else [64 * MIB] * 3)
        for level in range(10):
            p = self.lzma_props(level)
            got = self.L.SZ_Lzma_v25_01_EncProps_GetDictSize(ctypes.byref(p))
            self.L.SZ_Lzma_v25_01_EncProps_Normalize(ctypes.byref(p))
            self.assertEqual((got, p.dictSize), (want[level], want[level]), "level %d, %d-bit" % (level, BITS))

    def test_lzma_encoder_dictionary_ceiling(self):
        """128 MiB is accepted everywhere; 129 MiB only where the slot table allows it (not 32-bit x86)."""
        L = self.L
        enc = L.SZ_Lzma_v25_01_Enc_Create()
        try:
            self.assertEqual(L.SZ_Lzma_v25_01_Enc_SetProps(enc, ctypes.byref(self.lzma_props(9, 128 * MIB))), 0)
            rc = L.SZ_Lzma_v25_01_Enc_SetProps(enc, ctypes.byref(self.lzma_props(9, 129 * MIB)))
            self.assertEqual(rc, SZ_ERROR_PARAM if X86_32 else 0, gcnative.target())
        finally:
            L.SZ_Lzma_v25_01_Enc_Destroy(enc)

    def test_fl2_high_level_dictionary_follows_pointer_width(self):
        """FL2_highCParameters (fl2_compress.c:90-101), each capped at FL2_DICTSIZE_MAX; the normal levels fit 32-bit."""
        L = self.L
        c = L.FL2_createCCtx()
        try:
            for high, table in ((0, F.LEVEL_DICT), (1, [None] + [MIB << i for i in range(10)])):
                for level in range(1, 11):
                    L.FL2_CCtx_setParameter(c, F.HIGH_COMPRESSION, high)
                    L.FL2_CCtx_setParameter(c, F.LEVEL, level)
                    want = min(table[level], 128 * MIB) if BITS == 32 else table[level]
                    self.assertEqual(L.FL2_CCtx_getParameter(c, F.DICTIONARY_SIZE), want,
                                     "%s level %d, %d-bit" % ("high" if high else "normal", level, BITS))
        finally:
            L.FL2_freeCCtx(c)

    def test_fl2_dictionary_ceiling(self):
        L = self.L
        c = L.FL2_createCCtx()
        try:
            # the setter returns the value it set, or (size_t)-error
            self.assertEqual(L.FL2_CCtx_setParameter(c, F.DICTIONARY_SIZE, 128 * MIB), 128 * MIB)
            r = L.FL2_CCtx_setParameter(c, F.DICTIONARY_SIZE, 129 * MIB)
            self.assertEqual(r, (F.SIZE_MAX + 1 - F.PARAMETER_OUT_OF_BOUND) if BITS == 32 else 129 * MIB, "%d-bit" % BITS)
        finally:
            L.FL2_freeCCtx(c)


if __name__ == "__main__":
    unittest.main()
