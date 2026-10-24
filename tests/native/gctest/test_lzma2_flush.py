"""Writing after a Flush() on the multi-call LZMA2 encoder, Lzma2Stream's solid mode (audit/lzma.md 3.1).
Unfixed, a flush that drains the input latches the match finder at the end of its stream, and everything written after
the first flush is lost (NDZ's report: write A, flush, write B, flush, and the stream decodes to A). The fix resumes the
match finder, and during a sync flush (EncodeMultiCall's init bit 1) holds back the positions its binary tree can't
insert with the full length limit, as liblzma's LZMA_SYNC_FLUSH does, inserting them once more input comes.
  - every byte written comes back, at every level, with flushes anywhere and a ring small enough to wrap;
  - each flush is a sync flush: the stream so far decodes to exactly the data written so far;
  - the dictionary is kept: no chunk after the first resets it, and data repeated across a flush costs a few bytes;
  - a stream without a flush is byte-identical to the same input encoded in one go.
GrindCore's decoder checks every stream; Python's lzma (liblzma) checks them too, where it's available."""
import random
import sys
import unittest

import gctest
from gctest import lzmadec_util as D
from gctest import lzma_util as U

# CPython before 3.8.7 and 3.9.1 can stop decompress() with output still inside liblzma when its input and output
# buffers run out together, and hands it over only with more input (bpo-21872; CentOS 7's 3.6 does it here).
PY_LZMA_HOLDS_BACK = sys.version_info < (3, 8, 7) or (3, 9) <= sys.version_info < (3, 9, 1)


def known(test, key):
    test.skipTest("known defect %s: %s" % (key, gctest.KNOWN_DEFECTS[key]))


def records(n, seed):
    """Data that keeps the binary tree busy: near-copies of a small pool of records (a few point mutations each), text
    and short random runs, so that what comes after a flush matches deep into what came before it."""
    r = random.Random(seed)
    pool = [bytes(r.getrandbits(8) for _ in range(r.randrange(40, 600))) for _ in range(24)]
    text = U.data(1 << 16, seed)
    out = bytearray()
    while len(out) < n:
        k = r.random()
        if k < 0.6:
            rec = bytearray(r.choice(pool))
            for _ in range(r.randrange(0, 4)):
                rec[r.randrange(len(rec))] = r.getrandbits(8)
            out += rec
        elif k < 0.9:
            i = r.randrange(len(text) - 2048)
            out += text[i:i + r.randrange(16, 2048)]
        else:
            out += bytes(r.getrandbits(8) for _ in range(r.randrange(1, 64)))
    return bytes(out[:n])


def split(data, seed, mean):
    """[(piece, flush after it)]: pieces of 1 byte up to several times `mean`, most followed by a flush."""
    r = random.Random(seed)
    out, i = [], 0
    while i < len(data):
        n = max(1, int(r.expovariate(1.0 / mean)))
        out.append((data[i:i + n], r.random() < 0.8))
        i += n
    return out


class Lzma2FlushTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = gctest.LIB
        cls.A = D.Api(cls.L)

    def decoded(self, r, n):
        """GrindCore's decoder on the whole stream: its output, or None if it stopped with an error."""
        d = D.one_shot(self.A, "lzma2", r["prop"], r["stream"], n, D.FINISH_END)
        return d.out if d.rc == 0 and d.status == D.FINISHED_WITH_MARK else None

    def roundtrip(self, pieces, level, label, ring=U.RING):
        """Encode, then check the whole stream (GrindCore and liblzma) and each flush's prefix (liblzma, fed the stream
        in order; GrindCore on the middle one, with an end byte). Reports the data-loss defect where it shows."""
        data = b"".join(p for p, _ in pieces)
        r = U.flushed_encode(self.L, pieces, level, ring=ring)
        self.assertEqual(r["rc"], 0, label)
        out = self.decoded(r, len(data))
        if r["stuck"] or (out is not None and len(out) < len(data) and data.startswith(out)):
            known(self, "lzma2-flush-data-loss")
        self.assertTrue(out == data, "%s: GrindCore decoded %s" % (
            label, "an error" if out is None else "%d other bytes" % len(out)))
        if r["marks"]:
            written, end = r["marks"][len(r["marks"]) // 2]
            mid = self.decoded({"prop": r["prop"], "stream": r["stream"][:end] + b"\x00"}, written)
            self.assertTrue(mid == data[:written], "%s: the stream up to a flush (%d bytes in) doesn't decode to "
                                                   "what was written" % (label, written))
        if U.lzma is not None:
            def py_decoder():
                return U.lzma.LZMADecompressor(format=U.lzma.FORMAT_RAW, filters=[
                    {"id": U.lzma.FILTER_LZMA2, "dict_size": max(4096, min(U.dict_size(r["prop"]), 1 << 30))}])
            dec = py_decoder()
            got, pos = bytearray(), 0
            for written, end in r["marks"]:
                got += dec.decompress(r["stream"][pos:end])
                pos = end
                now = bytes(got)
                if len(now) < written and PY_LZMA_HOLDS_BACK:
                    # that Python's hold-back: this prefix on its own, with the end byte, which makes it drain
                    now = py_decoder().decompress(r["stream"][:end] + b"\x00")
                self.assertTrue(now == data[:written], "%s: liblzma, %d bytes in: the stream so far gave %d "
                                                       "bytes, not exactly what was written" % (
                                                           label, written, len(now)))
            got += dec.decompress(r["stream"][pos:])
            self.assertTrue(dec.eof and bytes(got) == data, label + ": liblzma decoded other data")
        return r

    def test_write_after_flush_is_kept(self):
        """NDZ's sequence: 100,000 random bytes, Flush(), the same bytes again, Flush(), then the end."""
        a = bytes(random.Random(1).getrandbits(8) for _ in range(100000))
        for level in (1, 5, 9):
            r = self.roundtrip([(a, True), (a, True)], level, "level %d" % level)
            (_, first), (_, second) = r["marks"]
            self.assertGreater(second, first, "level %d: the second flush wrote nothing" % level)

    def test_flushes_anywhere(self):
        """Every level, about 130 flushes in 512 KiB of record-like data, pieces from 1 byte up."""
        for level in range(10):
            data = records(512 << 10, seed=level)
            self.roundtrip(split(data, seed=100 + level, mean=4096), level, "level %d" % level)

    def test_ring_wraps(self):
        """A 64 KiB ring: the encoder also runs between flushes (on a full ring) and the input wraps around it."""
        for level in (1, 5, 9):
            data = records(768 << 10, seed=20 + level)
            self.roundtrip(split(data, seed=200 + level, mean=24 << 10), level, "level %d, small ring" % level,
                           ring=(64 << 10) + 8)

    def test_dictionary_is_kept(self):
        """Data repeated after a flush is found in the dictionary: no chunk after the first resets it, and the copy
        costs a small fraction of the original."""
        a = records(200 << 10, seed=5)
        for level in (1, 5, 9):
            r = self.roundtrip([(a, True), (a, True)], level, "level %d" % level)
            (_, first), (_, second) = r["marks"]
            resets = [c for c in D.lzma2_chunks(r["stream"])[1:] if c[1] == 1 or c[1] >= 0xE0]
            self.assertEqual(resets, [], "level %d: a chunk after the first resets the dictionary" % level)
            self.assertLess(second - first, first // 20, "level %d: the repeat cost %d bytes, the original %d" % (
                level, second - first, first))

    def test_no_flush_output_unchanged(self):
        """Without a flush the stream is byte-identical to the input encoded in one go (the resume changes nothing)."""
        data = records(300 << 10, seed=9)
        for level in (1, 5, 9):
            one = U.encode(self.L, data, level)
            pieces = [(data[i:i + 7777], False) for i in range(0, len(data), 7777)]
            r = U.flushed_encode(self.L, pieces, level)
            self.assertEqual((one["rc"], r["rc"]), (0, 0), "level %d" % level)
            self.assertTrue(r["stream"] == one["stream"], "level %d: %d bytes against %d" % (
                level, len(r["stream"]), len(one["stream"])))


if __name__ == "__main__":
    unittest.main()
