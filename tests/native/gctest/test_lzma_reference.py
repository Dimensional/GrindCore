"""GrindCore's LZMA/LZMA2 against official 7-Zip: a reference library built unmodified from the upstream tag by
ref/build_7zip_ref.py. Set GC_REF_7ZIP to its path; without it these tests skip.

GrindCore vendors 7-Zip 25.01 with two files changed, LzmaEnc.c and Lzma2Enc.c, which add the multi-call streaming API
(Nanook's hook). Everything else, every decoder included, is the official source. These tests check that:
  - the existing encode paths (one-shot LzmaEncode, LzmaBlock's MemEncode, Lzma2Enc_Encode2 single- and
    multi-threaded) give output byte-identical to official 7-Zip for the same input and settings;
  - the multi-call streams, the hook's own output, decode with official 7-Zip's decoders and with Python's lzma;
  - official 7-Zip's output decodes with GrindCore's decoders."""
import ctypes
import os
import random
import unittest

import gctest
from gctest import lzma_util as U

vp, sz = ctypes.c_void_p, ctypes.c_size_t
LEVELS = (0, 1, 3, 5, 7, 9)


def corpus():
    """(name, bytes): the edges and the content types that take different encoder paths."""
    r = random.Random(11)
    mixed = U.data(900 << 10) + r.getrandbits(8 * (300 << 10)).to_bytes(300 << 10, "little") + bytes(600 << 10) + \
        U.data(900 << 10, seed=3)
    return [("empty", b""), ("1 byte", b"x"), ("100 B text", U.data(100)), ("64 KiB text", U.data(64 << 10)),
            ("300 KiB random", r.getrandbits(8 * (300 << 10)).to_bytes(300 << 10, "little")),
            ("256 KiB zeros", bytes(256 << 10)), ("2.6 MiB mixed", mixed)]


class Ref(object):
    """Official 7-Zip's functions, by their own names."""

    def __init__(self, path):
        r = ctypes.CDLL(path)
        self.alloc = ctypes.addressof(ctypes.c_byte.in_dll(r, "g_Alloc"))
        try:  # off Windows, Alloc.h:56 makes g_BigAlloc a macro for g_AlignedAlloc, so there's no such symbol
            self.big = ctypes.addressof(ctypes.c_byte.in_dll(r, "g_BigAlloc"))
        except ValueError:
            self.big = ctypes.addressof(ctypes.c_byte.in_dll(r, "g_AlignedAlloc"))
        for name, res, args in [
                ("LzmaEncProps_Init", None, [vp]), ("LzmaEncode", ctypes.c_int, [vp, vp, vp, sz, vp, vp, vp, ctypes.c_int, vp, vp, vp]),
                ("LzmaEnc_Create", vp, [vp]), ("LzmaEnc_Destroy", None, [vp, vp, vp]), ("LzmaEnc_SetProps", ctypes.c_int, [vp, vp]),
                ("LzmaEnc_SetDataSize", None, [vp, ctypes.c_uint64]), ("LzmaEnc_WriteProperties", ctypes.c_int, [vp, vp, vp]),
                ("LzmaEnc_MemEncode", ctypes.c_int, [vp, vp, vp, vp, sz, ctypes.c_int, vp, vp, vp]),
                ("Lzma2EncProps_Init", None, [vp]), ("Lzma2EncProps_Normalize", None, [vp]),
                ("Lzma2Enc_Create", vp, [vp, vp]), ("Lzma2Enc_Destroy", None, [vp]), ("Lzma2Enc_SetProps", ctypes.c_int, [vp, vp]),
                ("Lzma2Enc_WriteProperties", ctypes.c_ubyte, [vp]), ("Lzma2Enc_Encode2", ctypes.c_int, [vp, vp, vp, vp, vp, vp, sz, vp]),
                ("LzmaDecode", ctypes.c_int, [vp, vp, vp, vp, vp, ctypes.c_uint, ctypes.c_int, vp, vp]),
                ("Lzma2Decode", ctypes.c_int, [vp, vp, vp, vp, ctypes.c_ubyte, ctypes.c_int, vp, vp])]:
            fn = getattr(r, name)
            fn.restype, fn.argtypes = res, args
            setattr(self, name, fn)


def out_buffer(n):
    return ctypes.create_string_buffer(n + n // 2 + (1 << 16))


class Reference(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("GC_REF_7ZIP")
        if not path:
            raise unittest.SkipTest("GC_REF_7ZIP not set (build the reference with ref/build_7zip_ref.py)")
        cls.R, cls.L, cls.C = Ref(path), gctest.LIB, corpus()

    # ---- the encode paths, both sides, same settings ----

    def lzma_props(self, lib_init, level, threads):
        p = self.L.struct.CLzmaEncProps()
        lib_init(ctypes.byref(p))
        p.level, p.numThreads = level, threads
        return p

    def one_shot(self, data, level, threads, wem):
        res = []
        for side in ("gc", "ref"):
            props = self.lzma_props(self.L.SZ_Lzma_v25_01_EncProps_Init if side == "gc" else self.R.LzmaEncProps_Init,
                                    level, threads)
            dst, dlen = out_buffer(len(data)), None
            dlen = sz(len(dst))
            pe, pn = ctypes.create_string_buffer(5), sz(5)
            if side == "gc":
                rc = self.L.SZ_Lzma_v25_01_Enc_LzmaEncode(dst, ctypes.byref(dlen), data, len(data), ctypes.byref(props),
                                                         pe, ctypes.byref(pn), wem, None)
            else:
                rc = self.R.LzmaEncode(dst, ctypes.byref(dlen), data, len(data), ctypes.byref(props), pe,
                                       ctypes.byref(pn), wem, None, self.R.alloc, self.R.big)
            res.append((rc, pe.raw[:pn.value], dst.raw[:dlen.value]))
        return res

    def mem_encode(self, data, level, threads, wem):
        res = []
        for side in ("gc", "ref"):
            if side == "gc":
                L = self.L
                props = self.lzma_props(L.SZ_Lzma_v25_01_EncProps_Init, level, threads)
                enc = L.SZ_Lzma_v25_01_Enc_Create()
                L.SZ_Lzma_v25_01_Enc_SetProps(enc, ctypes.byref(props))
                L.SZ_Lzma_v25_01_Enc_SetDataSize(enc, len(data))
                pe, pn = ctypes.create_string_buffer(5), sz(5)
                L.SZ_Lzma_v25_01_Enc_WriteProperties(enc, pe, ctypes.byref(pn))
                dst = out_buffer(len(data))
                dlen = sz(len(dst))
                rc = L.SZ_Lzma_v25_01_Enc_MemEncode(enc, dst, ctypes.byref(dlen), data, len(data), wem, None)
                L.SZ_Lzma_v25_01_Enc_Destroy(enc)
            else:
                R = self.R
                props = self.lzma_props(R.LzmaEncProps_Init, level, threads)
                enc = R.LzmaEnc_Create(R.alloc)
                R.LzmaEnc_SetProps(enc, ctypes.byref(props))
                R.LzmaEnc_SetDataSize(enc, len(data))
                pe, pn = ctypes.create_string_buffer(5), sz(5)
                R.LzmaEnc_WriteProperties(enc, pe, ctypes.byref(pn))
                dst = out_buffer(len(data))
                dlen = sz(len(dst))
                rc = R.LzmaEnc_MemEncode(enc, dst, ctypes.byref(dlen), data, len(data), wem, None, R.alloc, R.big)
                R.LzmaEnc_Destroy(enc, R.alloc, R.big)
            res.append((rc, pe.raw[:pn.value], dst.raw[:dlen.value]))
        return res

    def lzma2_encode2(self, data, level, threads, block):
        res = []
        for side in ("gc", "ref"):
            p = self.L.struct.CLzma2EncProps()
            (self.L.SZ_Lzma2_v25_01_Enc_Construct if side == "gc" else self.R.Lzma2EncProps_Init)(ctypes.byref(p))
            p.lzmaProps.level = level
            p.lzmaProps.numThreads = 1
            p.numBlockThreads_Max, p.numTotalThreads, p.blockSize = threads, threads, block
            (self.L.SZ_Lzma2_v25_01_Enc_Normalize if side == "gc" else self.R.Lzma2EncProps_Normalize)(ctypes.byref(p))
            dst = out_buffer(len(data))
            dlen = sz(len(dst))
            if side == "gc":
                enc = self.L.SZ_Lzma2_v25_01_Enc_Create()
                self.L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(p))
                prop = self.L.SZ_Lzma2_v25_01_Enc_WriteProperties(enc)
                rc = self.L.SZ_Lzma2_v25_01_Enc_Encode2(enc, dst, ctypes.byref(dlen), data, len(data), None)
                self.L.SZ_Lzma2_v25_01_Enc_Destroy(enc)
            else:
                enc = self.R.Lzma2Enc_Create(self.R.alloc, self.R.big)
                self.R.Lzma2Enc_SetProps(enc, ctypes.byref(p))
                prop = self.R.Lzma2Enc_WriteProperties(enc)
                rc = self.R.Lzma2Enc_Encode2(enc, None, dst, ctypes.byref(dlen), None, data, len(data), None)
                self.R.Lzma2Enc_Destroy(enc)
            res.append((rc, bytes([prop]), dst.raw[:dlen.value]))
        return res

    def compare(self, what, cases, run):
        checked = 0
        for name, data in self.C:
            for args in cases:
                (grc, gp, gout), (rrc, rp, rout) = run(data, *args)
                with self.subTest(api=what, data=name, settings=args):
                    self.assertEqual((grc, rrc), (0, 0))
                    self.assertEqual(gp, rp, "properties differ")
                    self.assertEqual(len(gout), len(rout), "output sizes differ")
                    self.assertTrue(gout == rout, "output bytes differ")
                checked += 1
        print("  %s: %d encodes byte-identical to official 7-Zip" % (what, checked))

    def test_lzma_one_shot_is_identical(self):
        self.compare("LzmaEncode (one-shot)", [(lv, t, wem) for lv in LEVELS for t in (1, 2) for wem in (0, 1)],
                     self.one_shot)

    def test_lzma_block_memencode_is_identical(self):
        self.compare("LzmaEnc_MemEncode (LzmaBlock)", [(lv, 1, wem) for lv in LEVELS for wem in (0, 1)], self.mem_encode)

    def test_lzma2_encode2_is_identical(self):
        self.compare("Lzma2Enc_Encode2", [(lv, 1, 0) for lv in LEVELS] + [(lv, 2, 1 << 20) for lv in (1, 5, 9)],
                     self.lzma2_encode2)

    def test_randomized_cases_are_identical(self):
        """Semi-random differential: GC_REF_CASES cases (default 60), seeded by GC_REF_SEED (default: new each run,
        printed so a failure can be replayed). Each case draws a size (0 to 4 MiB, log-scale), a mix of text, random,
        zero and repeated runs, and random settings for one of the three encode paths, and must be byte-identical to
        official 7-Zip and decode back with both decoders."""
        seed = int(os.environ.get("GC_REF_SEED") or random.SystemRandom().randrange(1 << 31))
        cases = int(os.environ.get("GC_REF_CASES", "60"))
        r = random.Random(seed)
        print("  seed %d (replay: GC_REF_SEED=%d)" % (seed, seed))
        kinds = {"one-shot": 0, "MemEncode": 0, "Encode2": 0}
        for i in range(cases):
            size = 0 if r.random() < 0.05 else int(2 ** r.uniform(0, 22))
            parts, total = [], 0
            while total < size:
                n = min(size - total, int(2 ** r.uniform(4, 18)))
                kind = r.random()
                parts.append(U.data(n, seed=r.randrange(1 << 30)) if kind < 0.5 else
                             r.getrandbits(8 * n).to_bytes(n, "little") if kind < 0.7 else
                             bytes(n) if kind < 0.85 else (bytes([r.randrange(256)]) * r.randrange(1, 9)) * (n // 8 + 1))
                total += len(parts[-1])
            data = b"".join(parts)[:size]
            api = r.choice(sorted(kinds))
            level = r.randrange(10)
            if api == "one-shot":
                args = (level, r.choice((1, 2)), r.choice((0, 1)))
                (g, ref) = self.one_shot(data, *args)
            elif api == "MemEncode":
                args = (level, 1, r.choice((0, 1)))
                (g, ref) = self.mem_encode(data, *args)
            else:
                threads = r.choice((1, 2))
                args = (level, threads, 0 if threads == 1 else r.choice((1 << 18, 1 << 20)))
                (g, ref) = self.lzma2_encode2(data, *args)
            with self.subTest(case=i, api=api, size=size, settings=args, seed=seed):
                self.assertEqual((g[0], ref[0]), (0, 0))
                self.assertTrue(g[1:] == ref[1:], "output differs from official 7-Zip")
                if api == "Encode2":
                    rc, out = self.ref_lzma2_decode(g[1][0], g[2], len(data))
                else:
                    rc, out = self.ref_lzma_decode(g[1], g[2], len(data))
                self.assertEqual(rc, 0)
                self.assertTrue(out == data, "didn't decode back")
            kinds[api] += 1
        print("  %d random cases (%s): all byte-identical to official 7-Zip and decoded back" % (
            cases, ", ".join("%s %d" % kv for kv in sorted(kinds.items()))))

    # ---- decoding across the two ----

    def ref_lzma_decode(self, props, stream, n):
        dst, dlen, slen, st = ctypes.create_string_buffer(max(n, 1)), sz(n), sz(len(stream)), ctypes.c_int(0)
        rc = self.R.LzmaDecode(dst, ctypes.byref(dlen), stream, ctypes.byref(slen), props, len(props), 1,
                               ctypes.byref(st), self.R.alloc)
        return rc, dst.raw[:dlen.value]

    def ref_lzma2_decode(self, prop, stream, n):
        dst, dlen, slen, st = ctypes.create_string_buffer(max(n, 1)), sz(n), sz(len(stream)), ctypes.c_int(0)
        rc = self.R.Lzma2Decode(dst, ctypes.byref(dlen), stream, ctypes.byref(slen), prop, 1, ctypes.byref(st),
                                self.R.alloc)
        return rc, dst.raw[:dlen.value]

    def test_lzma2_multicall_stream_decodes_with_official_7zip(self):
        """The hook's LZMA2 stream (as Lzma2Stream writes it) decoded by official 7-Zip."""
        for name, data in self.C:
            for level in (1, 5, 9):
                with self.subTest(data=name, level=level):
                    r = U.encode(self.L, data, level=level)
                    if r["rc"] == 2:
                        # A stream has no size to shrink the dictionary with: level 9 asks for 256 MiB (64-bit) plus its
                        # match finder, about 2.7 GB of address space, more than a capped test process may have
                        # (ulimit -v, used where Docker's -m isn't enforced)
                        self.skipTest("level %d: SZ_ERROR_MEM, the encoder's dictionary didn't fit this process's "
                                      "address-space limit" % level)
                    self.assertEqual(r["rc"], 0)
                    rc, out = self.ref_lzma2_decode(r["prop"], r["stream"], len(data))
                    self.assertEqual(rc, 0)
                    self.assertTrue(out == data)
                    solid = self.lzma2_encode2(data, level, 1, 0)[1][2]
                    if name == "2.6 MiB mixed":
                        print("  LZMA2 multi-call stream, level %d: %d bytes; official one-shot Encode2 %d bytes (%s)" % (
                            level, len(r["stream"]), len(solid),
                            "identical" if solid == r["stream"] else "different chunking, both standard"))
        print("  LZMA2 multi-call streams: all decoded by official 7-Zip")

    def test_lzma_multicall_stream_decodes_with_official_7zip(self):
        """The hook's LZMA stream, driven as LzmaEncoder drives it, decoded by official 7-Zip and Python's lzma."""
        for name, data in self.C:
            with self.subTest(data=name):
                props, stream, end_mark = U.lzma_stream_encode(self.L, data)
                rc, out = self.ref_lzma_decode(props, stream, len(data))
                self.assertEqual(rc, 0)
                self.assertTrue(out == data, "official 7-Zip decoded %d of %d bytes correctly" % (len(out), len(data)))
                if U.lzma is not None:
                    size = (1 << 64) - 1 if end_mark else len(data)
                    py, err = U.py_decode_alone(props + size.to_bytes(8, "little") + stream)
                    self.assertIsNone(err)
                    self.assertTrue(py == data)
        print("  LZMA multi-call streams: all decoded by official 7-Zip%s" % (" and Python's lzma" if U.lzma else ""))

    def test_official_output_decodes_with_grindcore(self):
        for name, data in self.C:
            with self.subTest(data=name):
                (_, _, _), (rc, props, stream) = self.one_shot(data, 5, 1, 0)
                dst, dlen, slen, st = ctypes.create_string_buffer(max(len(data), 1)), sz(len(data)), sz(len(stream)), ctypes.c_int(0)
                rc = self.L.SZ_Lzma_v25_01_Dec_LzmaDecode(dst, ctypes.byref(dlen), stream, ctypes.byref(slen), props,
                                                          len(props), 1, ctypes.byref(st))
                self.assertEqual(rc, 0)
                self.assertTrue(dst.raw[:dlen.value] == data)
                (_, _, _), (rc, prop, stream) = self.lzma2_encode2(data, 5, 1, 0)
                dst, dlen, slen = ctypes.create_string_buffer(max(len(data), 1)), sz(len(data)), sz(len(stream))
                rc = self.L.SZ_Lzma2_v25_01_Decode(dst, ctypes.byref(dlen), stream, ctypes.byref(slen), prop[0], 1,
                                                   ctypes.byref(st))
                self.assertEqual(rc, 0)
                self.assertTrue(dst.raw[:dlen.value] == data)
        print("  official 7-Zip's LZMA and LZMA2 output: all decoded by GrindCore")
