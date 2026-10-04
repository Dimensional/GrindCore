"""7-Zip 25.01's multithreaded LZMA/LZMA2 encoding through GrindCore's exports: the properties the ThreadCount design
relies on (audit/lzma.md 3.7). No new export is involved; these are the existing Lzma*/Lzma2* encoder exports.
  - The two-thread match finder (lzmaProps.numThreads 2) gives byte-identical output to one thread, for LZMA
    (MemEncode) and LZMA2 (Encode2, solid).
  - Block threads (Encode2 with numBlockThreads > 1, MtCoder) give output that depends on the block size only, never on
    the thread count, and equals official 7-Zip's ($GC_REF_7ZIP, ref/build_7zip_ref.py).
  - A stream encoded as batches of whole blocks, one Encode2 per batch with its 0x00 end byte stripped, is byte-identical
    to one Encode2 over the whole input; a flush (a batch cut short) leaves a stream whose prefix decodes.
Python's lzma decodes everything where it's available; GrindCore's decoder always."""
import ctypes
import random
import unittest

import gctest
from gctest import sample
from gctest import lzmadec_util as D
from gctest import lzma_util as U

SOLID = (1 << 64) - 1
BLOCK = 256 << 10          # small blocks keep the runs short (the Pi): reduceSize = blockSize also shrinks the dictionary


def lzma2_props(L, level, block_threads, lzma_threads, block, init=None, normalize=None):
    p = L.struct.CLzma2EncProps()
    (init or L.SZ_Lzma2_v25_01_Enc_Construct)(ctypes.byref(p))
    p.lzmaProps.level, p.lzmaProps.numThreads = level, lzma_threads
    p.numBlockThreads_Max, p.numTotalThreads, p.blockSize = block_threads, block_threads * lzma_threads, block
    (normalize or L.SZ_Lzma2_v25_01_Enc_Normalize)(ctypes.byref(p))
    return p


def out_buffer(n):
    return ctypes.create_string_buffer(n + n // 256 + (1 << 16))


class Lzma2Batches(object):
    """The design's threaded LZMA2 stream: input collected into batches of block_threads x block bytes, each batch one
    Lzma2Enc_Encode2 call on one long-lived encoder, its 0x00 end byte stripped; flush() encodes the partial batch."""

    def __init__(self, L, level, block_threads, lzma_threads, block):
        self.L, self.batch = L, block * block_threads
        self.props = lzma2_props(L, level, block_threads, lzma_threads, block)
        self.enc = L.SZ_Lzma2_v25_01_Enc_Create()
        rc = L.SZ_Lzma2_v25_01_Enc_SetProps(self.enc, ctypes.byref(self.props))
        assert rc == 0, rc
        self.prop = L.SZ_Lzma2_v25_01_Enc_WriteProperties(self.enc)
        self.pending, self.out, self.calls = bytearray(), bytearray(), 0

    def _encode(self, data):
        if not data:
            return
        dst = out_buffer(len(data))
        n = ctypes.c_size_t(len(dst))
        rc = self.L.SZ_Lzma2_v25_01_Enc_Encode2(self.enc, dst, ctypes.byref(n), bytes(data), len(data), None)
        if rc or n.value == 0 or dst.raw[n.value - 1] != 0:
            raise AssertionError("Encode2 rc %d, %d bytes, last %r" % (rc, n.value, dst.raw[n.value - 1:n.value]))
        self.out += dst.raw[:n.value - 1]
        self.calls += 1

    def write(self, data):
        self.pending += data
        while len(self.pending) >= self.batch:
            self._encode(self.pending[:self.batch])
            del self.pending[:self.batch]

    def flush(self):
        self._encode(self.pending)
        self.pending = bytearray()

    def finish(self):
        self.flush()
        self.L.SZ_Lzma2_v25_01_Enc_Destroy(self.enc)
        self.enc = None
        return bytes(self.out) + b"\x00"


class LzmaMtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = gctest.LIB
        cls.A = D.Api(cls.L)
        refs, _ = D.references(cls.L)
        cls.ref = None
        import os
        if refs:
            from gctest.test_lzma_reference import Ref
            cls.ref = Ref(os.environ["GC_REF_7ZIP"])

    def decodes(self, prop, stream, data, label):
        r = D.one_shot(self.A, "lzma2", prop, stream, len(data), D.FINISH_END)
        self.assertEqual((r.rc, r.status), (0, D.FINISHED_WITH_MARK), label)
        self.assertTrue(r.out == data, label + ": GrindCore decoded other data")
        if U.lzma is not None:
            out, err = U.py_decode(stream, prop)
            self.assertIsNone(err, label)
            self.assertTrue(out == data, label + ": liblzma decoded other data")

    def encode2(self, data, level, block_threads, lzma_threads, block, side="gc"):
        if side == "gc":
            L = self.L
            p = lzma2_props(L, level, block_threads, lzma_threads, block)
            enc = L.SZ_Lzma2_v25_01_Enc_Create()
            L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(p))
            prop = L.SZ_Lzma2_v25_01_Enc_WriteProperties(enc)
            dst = out_buffer(len(data))
            n = ctypes.c_size_t(len(dst))
            rc = L.SZ_Lzma2_v25_01_Enc_Encode2(enc, dst, ctypes.byref(n), data, len(data), None)
            L.SZ_Lzma2_v25_01_Enc_Destroy(enc)
        else:
            R = self.ref
            p = lzma2_props(self.L, level, block_threads, lzma_threads, block, R.Lzma2EncProps_Init, R.Lzma2EncProps_Normalize)
            enc = R.Lzma2Enc_Create(R.alloc, R.big)
            R.Lzma2Enc_SetProps(enc, ctypes.byref(p))
            prop = R.Lzma2Enc_WriteProperties(enc)
            dst = out_buffer(len(data))
            n = ctypes.c_size_t(len(dst))
            rc = R.Lzma2Enc_Encode2(enc, None, dst, ctypes.byref(n), None, data, len(data), None)
            R.Lzma2Enc_Destroy(enc)
        self.assertEqual(rc, 0)
        return prop, dst.raw[:n.value]

    def lzma1(self, data, level, threads):
        L = self.L
        p = L.struct.CLzmaEncProps()
        L.SZ_Lzma_v25_01_EncProps_Init(ctypes.byref(p))
        p.level, p.numThreads, p.dictSize = level, threads, 1 << 20
        enc = L.SZ_Lzma_v25_01_Enc_Create()
        try:
            L.SZ_Lzma_v25_01_Enc_SetProps(enc, ctypes.byref(p))
            pb, pn = ctypes.create_string_buffer(5), ctypes.c_size_t(5)
            L.SZ_Lzma_v25_01_Enc_WriteProperties(enc, pb, ctypes.byref(pn))
            dst = out_buffer(len(data))
            n = ctypes.c_size_t(len(dst))
            rc = L.SZ_Lzma_v25_01_Enc_MemEncode(enc, dst, ctypes.byref(n), data, len(data), 1, None)
            self.assertEqual(rc, 0)
            return pb.raw[:5], dst.raw[:n.value]
        finally:
            L.SZ_Lzma_v25_01_Enc_Destroy(enc)

    @staticmethod
    def corpus():
        return [("empty", b""), ("1 byte", b"x"), ("text 100000", sample.text(100000, seed=2)),
                ("mixed 1.5 MiB", sample.mixed(1536 << 10, seed=3)), ("runs 1 MiB", sample.runs(1 << 20, seed=4))]

    def test_match_finder_thread_gives_identical_output(self):
        """lzmaProps.numThreads 2 (LzFindMt, the binary-tree match finders of levels 5-9) against 1: the same bytes,
        LZMA one-shot (MemEncode, as LzmaBlock calls it) and LZMA2 solid (Encode2, as Lzma2Block calls it)."""
        for name, data in self.corpus():
            for level in (5, 7, 9):
                with self.subTest(data=name, level=level):
                    p1, s1 = self.lzma1(data, level, 1)
                    p2, s2 = self.lzma1(data, level, 2)
                    self.assertEqual(p1, p2)
                    self.assertTrue(s1 == s2, "LZMA: the match-finder thread changed the output")
                    r = D.one_shot(self.A, "lzma", p2, s2, len(data), D.FINISH_END)
                    self.assertTrue(r.rc == 0 and r.out == data)
                    q1, t1 = self.encode2(data, level, 1, 1, SOLID)
                    q2, t2 = self.encode2(data, level, 1, 2, SOLID)
                    self.assertEqual(q1, q2)
                    self.assertTrue(t1 == t2, "LZMA2: the match-finder thread changed the output")
                    self.decodes(q2, t2, data, "LZMA2 solid, 2 match-finder threads")

    def test_block_threads_output_depends_on_block_size_only(self):
        """Encode2 with 256 KiB blocks at 1, 2, 3, 4 and 8 block threads (and with 2 match-finder threads each): one
        output, equal to official 7-Zip's for the same settings, with a dictionary reset at every block start."""
        data = sample.mixed(3 << 20, seed=5)
        for level in (3, 5, 9):
            with self.subTest(level=level):
                prop, first = self.encode2(data, level, 1, 1, BLOCK)
                for bt, lt in ((2, 1), (3, 1), (4, 1), (8, 1), (4, 2), (8, 2)):
                    p, s = self.encode2(data, level, bt, lt, BLOCK)
                    self.assertEqual(p, prop)
                    self.assertTrue(s == first, "%d block threads x %d changed the output" % (bt, lt))
                resets = [c for c in D.lzma2_chunks(first) if c[1] == 1 or c[1] >= 0xE0]
                self.assertEqual(len(resets), (len(data) + BLOCK - 1) // BLOCK, "one dictionary reset per block")
                self.decodes(prop, first, data, "blocks")
                if self.ref:
                    self.assertTrue(self.encode2(data, level, 4, 1, BLOCK, side="ref") == (prop, first),
                                    "differs from official 7-Zip")

    def test_batched_stream_equals_one_encode2(self):
        """The design's stream: writes of random sizes collected into batches of whole blocks, one Encode2 per batch,
        end bytes stripped. Byte-identical to one Encode2 over the whole input, at every thread count, for inputs that
        end mid-block, on a block boundary, inside the first block, and empty."""
        r = random.Random(6)
        cases = [("mixed, ends mid-block", sample.mixed(2 << 20, seed=7) + b"tail"),
                 ("text, ends on a block boundary", sample.text(8 * BLOCK, seed=8)),
                 ("shorter than a block", sample.text(BLOCK // 3, seed=9)),
                 ("empty", b"")]
        for name, data in cases:
            for bt, lt in ((1, 1), (2, 1), (4, 1), (3, 2)):
                with self.subTest(data=name, block_threads=bt, match_finder_threads=lt):
                    prop, whole = self.encode2(data, 5, bt, lt, BLOCK)
                    st = Lzma2Batches(self.L, 5, bt, lt, BLOCK)
                    pos = 0
                    while pos < len(data):
                        k = r.randrange(1, 3 * BLOCK)
                        st.write(data[pos:pos + k])
                        pos += k
                    s = st.finish()
                    self.assertEqual(st.prop, prop)
                    self.assertTrue(s == whole, "batched stream differs from one Encode2 (%d vs %d bytes)" % (len(s), len(whole)))
                    self.decodes(prop, s, data, name)

    def test_flushed_prefixes_decode(self):
        """A flush encodes the partial batch at once (the last block ends early): after every flush, the stream so far
        plus an end byte decodes to everything written so far; the finished stream decodes to all of it."""
        data = sample.mixed(3 << 20, seed=10)
        r = random.Random(11)
        st = Lzma2Batches(self.L, 5, 4, 1, BLOCK)
        pos = flushes = 0
        while pos < len(data):
            k = r.randrange(1, BLOCK)
            st.write(data[pos:pos + k])
            pos += k
            if r.random() < 0.3:
                st.flush()
                flushes += 1
                self.decodes(st.prop, bytes(st.out) + b"\x00", data[:pos], "after flush %d" % flushes)
        st.flush()
        st.flush()                                   # a flush with nothing pending writes nothing
        s = st.finish()
        self.assertGreater(flushes, 3)
        self.decodes(st.prop, s, data, "flushed stream")
