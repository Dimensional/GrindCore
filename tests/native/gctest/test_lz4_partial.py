"""SZ_Lz4_v1_10_0_CompressPartial: LZ4 "destSize" mode (fill a fixed-size output block, report the input consumed).
Implemented on GrindCore's audit/native-fixes branch (other-codecs.md 4.1); absent from the shipped binaries, where
these tests skip. Every block is decoded by an independent LZ4 block decoder (oracle_lz4) and by GrindCore's own."""
import ctypes
import random
import unittest

import gctest
from gctest.oracle_lz4 import decompress_block

OK, ERROR, COMPRESSFAIL = 0, -1, -3
FN = "SZ_Lz4_v1_10_0_CompressPartial"


def data_text(n, seed=1):
    """Compressible: words from a small vocabulary with some noise."""
    r = random.Random(seed)
    words = [b"alpha", b"beta", b"gamma", b"delta", b"grindcore", b"lz4", b"block", b"stream", b"\n"]
    out = bytearray()
    while len(out) < n:
        out += r.choice(words) + (b" " if r.random() < 0.9 else bytes([r.randrange(256)]))
    return bytes(out[:n])


def data_random(n, seed=2):
    return random.Random(seed).getrandbits(8 * n).to_bytes(n, "little") if n else b""


class CompressPartial(unittest.TestCase):
    def setUp(self):
        self.L = gctest.LIB
        if not self.L.has(FN):
            self.skipTest("%s not exported by this library (known gap in the shipped binaries)" % FN)
        self.stream = self.L.struct.SZ_Lz4_v1_10_0_Stream()
        self.assertEqual(self.L.SZ_Lz4_v1_10_0_Init(ctypes.byref(self.stream)), OK)

    def tearDown(self):
        if hasattr(self, "stream"):
            self.L.SZ_Lz4_v1_10_0_End(ctypes.byref(self.stream))

    def partial(self, src, target, acceleration=1, stream=None):
        n = ctypes.c_int(len(src))
        dst = ctypes.create_string_buffer(max(target, 1))
        r = getattr(self.L, FN)(ctypes.byref(stream or self.stream), src, dst, ctypes.byref(n), target, acceleration)
        return r, n.value, dst.raw[:max(r, 0)]

    def grindcore_decode(self, block, capacity):
        """GrindCore's own decoder (DecompressSafeContinue on a fresh stream) as a second opinion."""
        s = self.L.struct.SZ_Lz4_v1_10_0_Stream()
        self.assertEqual(self.L.SZ_Lz4_v1_10_0_Init(ctypes.byref(s)), OK)
        try:
            out = ctypes.create_string_buffer(max(capacity, 1))
            r = self.L.SZ_Lz4_v1_10_0_DecompressSafeContinue(ctypes.byref(s), block, out, len(block), capacity)
            self.assertGreaterEqual(r, 0, "GrindCore's decoder rejected the block (%d)" % r)
            return out.raw[:r]
        finally:
            self.L.SZ_Lz4_v1_10_0_End(ctypes.byref(s))

    def check_block(self, block, expected):
        self.assertEqual(decompress_block(block), expected, "independent decoder disagrees")
        self.assertEqual(self.grindcore_decode(block, len(expected) + 64), expected, "GrindCore decoder disagrees")

    def test_fills_target_and_reports_consumed(self):
        src = data_text(200000)
        r, consumed, block = self.partial(src, 4096)
        self.assertGreater(r, 0)
        self.assertLessEqual(r, 4096)
        self.assertGreater(r, 4096 - 64, "should nearly fill the target when input remains")
        self.assertGreater(consumed, 4096, "compressible input: more than target bytes consumed")
        self.assertLess(consumed, len(src))
        self.check_block(block, src[:consumed])

    def test_fixed_size_blocks_reassemble(self):
        src = data_text(120000, seed=3) + data_random(20000) + data_text(60000, seed=4)
        pos, blocks, out = 0, 0, bytearray()
        while pos < len(src):
            r, consumed, block = self.partial(src[pos:], 1500)
            self.assertGreater(r, 0)
            self.assertLessEqual(r, 1500)
            self.assertGreater(consumed, 0, "no progress at offset %d" % pos)
            out += decompress_block(block)
            pos += consumed
            blocks += 1
        self.assertEqual(bytes(out), src)
        self.assertGreater(blocks, 10)

    def test_incompressible_input_nearly_fills_target(self):
        src = data_random(100000)
        r, consumed, block = self.partial(src, 4096)
        self.assertLessEqual(r, 4096)
        self.assertGreater(consumed, 4096 - 4096 // 100 - 32, "literal overhead should be ~0.4%")
        self.assertLessEqual(consumed, 4096)
        self.check_block(block, src[:consumed])

    def test_target_large_enough_takes_everything(self):
        src = data_text(50000)
        r, consumed, block = self.partial(src, 60000)
        self.assertEqual(consumed, len(src))
        self.check_block(block, src)

    def test_empty_input(self):
        r, consumed, block = self.partial(b"", 64)
        self.assertGreater(r, 0)
        self.assertEqual(consumed, 0)
        self.assertEqual(decompress_block(block), b"")

    def test_block_is_independent_even_after_a_dictionary(self):
        dictionary = data_text(8192, seed=9)
        self.assertEqual(self.L.SZ_Lz4_v1_10_0_LoadDict(ctypes.byref(self.stream), dictionary, len(dictionary)), OK)
        src = dictionary[:4000] + data_text(4000, seed=10)
        r, consumed, block = self.partial(src, 16384)
        self.assertEqual(consumed, len(src))
        # decodable with no dictionary at all: the block never references the loaded dictionary
        self.check_block(block, src)

    def test_stream_is_usable_afterwards(self):
        self.partial(data_text(10000), 2048)
        src = data_text(5000, seed=5)
        dst = ctypes.create_string_buffer(8192)
        r = self.L.SZ_Lz4_v1_10_0_CompressFastContinue(ctypes.byref(self.stream), src, dst, len(src), len(dst), 1)
        self.assertGreater(r, 0)
        self.assertEqual(decompress_block(dst.raw[:r]), src, "stream was reset, so this block is self-contained")

    def test_acceleration(self):
        src = data_text(100000, seed=6)
        for acc in (1, 2, 8, 64):
            with self.subTest(acceleration=acc):
                r, consumed, block = self.partial(src, 4096, acceleration=acc)
                self.assertGreater(r, 0)
                self.check_block(block, src[:consumed])

    def test_invalid_arguments(self):
        f = getattr(self.L, FN)
        n = ctypes.c_int(10)
        dst = ctypes.create_string_buffer(64)
        self.assertEqual(f(None, b"0123456789", dst, ctypes.byref(n), 64, 1), ERROR, "NULL stream")
        self.assertEqual(f(ctypes.byref(self.stream), None, dst, ctypes.byref(n), 64, 1), ERROR, "NULL src")
        self.assertEqual(f(ctypes.byref(self.stream), b"0123456789", None, ctypes.byref(n), 64, 1), ERROR, "NULL dst")
        self.assertEqual(f(ctypes.byref(self.stream), b"0123456789", dst, None, 64, 1), ERROR, "NULL srcSize")
        self.assertEqual(f(ctypes.byref(self.stream), b"0123456789", dst, ctypes.byref(n), 0, 1), ERROR, "target 0")
        neg = ctypes.c_int(-1)
        self.assertEqual(f(ctypes.byref(self.stream), b"0123456789", dst, ctypes.byref(neg), 64, 1), ERROR, "srcSize < 0")
        empty = self.L.struct.SZ_Lz4_v1_10_0_Stream()  # never initialised: internalState NULL
        self.assertEqual(f(ctypes.byref(empty), b"0123456789", dst, ctypes.byref(n), 64, 1), ERROR, "uninitialised stream")
