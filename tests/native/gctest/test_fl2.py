"""Fast-LZMA2 1.0.1 (FL2_*): the one-shot and streaming encoder and decoder, which GrindCore exports unchanged.

GrindCore vendors fast-lzma2 through mcmilk's 7-Zip-zstd; every file it keeps is byte-identical to the official
v1.0.1 release apart from line endings (other-codecs.md 4.4.1). There is no PAL: the 61 exports are the library's own
functions. The references, from $GC_REF_FL2 (ref/build_fl2_ref.py):
  - official 1.0.1, the same C sources: GrindCore's output must match it byte for byte for the same calls;
  - official master (967306d3), 1.0.1 plus upstream's two later encoder fixes.
The oracle everywhere, Windows included, is Python's lzma module (liblzma): an FL2 frame is a property byte, a
standard LZMA2 stream and an XXH32, so liblzma must decode what FL2 writes, and FL2 must decode what liblzma writes.
Crash probes and corrupt-input runs run in child processes."""
import ctypes
import hashlib
import lzma
import random
import sys
import unittest

import gctest
from gctest import sample
from gctest import fl2_util as F
from gctest.test_hashes import child, known

IS_32 = ctypes.sizeof(ctypes.c_void_p) == 4


def describe(a, b):
    """Where two results differ, briefly (unittest's diff of large byte strings is far too slow)."""
    if isinstance(a, bytes) and isinstance(b, bytes):
        first = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
        return "%d vs %d bytes (sha256 %s vs %s), first difference at offset %d" % (
            len(a), len(b), hashlib.sha256(a).hexdigest()[:12], hashlib.sha256(b).hexdigest()[:12], first)
    return "%.300r vs %.300r" % (a, b)


def corpus(big=True):
    out = [("empty", b""), ("1 byte", b"x")] + [("%s %d" % (k, n), f(n, seed=n)) for k, f in sample.KINDS
                                                 for n in (1000, 20000)]
    return out + ([("mixed 300000", sample.mixed(300000))] if big else [])


def repeat_tail(period, n, seed=5):
    """Data ending in a run with a short period: what makes 1.0.1's RMF_handleRepeat read past the end."""
    r = random.Random(seed + period)
    unit = bytes(r.randrange(256) for _ in range(period))
    return (unit * (n // period + 1))[:n]


def crashed(rc, err):
    return rc not in (0, 1) or "Traceback" in err


def faulted(rc, err):
    """A memory fault in a child: a signal on Unix; on Windows ctypes turns an access violation into an OSError."""
    return rc not in (0, 1) or "exception: access violation" in err


class Fl2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = gctest.LIB
        cls.z = F.grindcore(cls.L)
        cls.ref = F.reference("1.0.1")
        cls.master = F.reference("master")

    def same(self, got, want, msg=""):
        if got != want:
            self.fail(describe(got, want) + (" (%s)" % msg if msg else ""))

    def need_ref(self, which="ref"):
        if not getattr(self, which):
            self.skipTest("no official fast-lzma2 %s: " % ("1.0.1" if which == "ref" else which) +
                          ("; ".join(F.REF_ERROR) or "set GC_REF_FL2 (ref/build_fl2_ref.py)"))

    def stream(self, data, level=6, threads=1, dual=0, chunk=1 << 16, flush_every=False, api=None, params=()):
        s = (api or self.z).cstream(threads, dual)
        try:
            for p, v in params:
                self.assertFalse(F.is_error(s.set(p, v)), "setParameter(%d, %d)" % (p, v))
            s.init(level)
            return s.compress(data, chunk, flush_every)
        finally:
            s.close()

    def dstream(self, frame, threads=1, in_step=1 << 16, out_step=1 << 16, api=None):
        d = (api or self.z).dstream(threads)
        try:
            return d.decode(frame, in_step, out_step)
        finally:
            d.close()

    # ------------------------------------------------------------------ format and interoperability

    def test_round_trip(self):
        """Every level, one-shot and streamed (1 thread, 2 threads, 2 threads double-buffered), decodes back through
        FL2_decompress, FL2_decompressMt and the streaming decoder (1 and 2 threads, odd input and output steps)."""
        for name, data in corpus():
            frames = [("one-shot L%d" % lv, self.z.compress(data, lv)) for lv in (1, 3, 4, 6, 10)]
            frames += [("mt L6", self.z.compress(data, 6, threads=2))]
            frames += [("stream %d/%d" % (t, d), self.stream(data, 6, t, d, chunk=7777)) for t, d in ((1, 0), (2, 0), (2, 1))]
            for how, f in frames:
                with self.subTest(data=name, frame=how):
                    self.same(self.z.decompress(f, len(data)), data)
                    self.same(self.z.decompress(f, len(data), threads=2), data)
                    for threads in (1, 2):
                        got, used = self.dstream(f, threads, in_step=777, out_step=1000)
                        self.same(got, data)
                        self.assertEqual(used, len(f))

    def test_output_is_lzma2(self):
        """liblzma decodes every frame: after the property byte a standard LZMA2 stream, then the big-endian XXH32 of
        the data when bit 7 of the property byte says so. With FL2_p_omitProperties the output is a bare LZMA2
        stream, no property byte and no hash: the form an .xz writer needs (other-codecs.md 4.4, xz.md 5)."""
        for name, data in corpus():
            frames = [("one-shot", self.z.compress(data, 6)), ("high 3", self.high(data, 3)),
                      ("stream", self.stream(data, 6)), ("stream mt", self.stream(data, 6, 2, 1, flush_every=True))]
            for how, f in frames:
                with self.subTest(data=name, frame=how):
                    out, rest = F.liblzma_decode(f)
                    self.same(out, data)
                    self.assertTrue(f[0] & 0x80, "the hash flag is on by default")
                    self.assertEqual(len(rest), 4)
                    if len(data) <= 20000:
                        self.assertEqual(int.from_bytes(rest, "big"), F.xxh32(data))
            with self.subTest(data=name, frame="omitProperties"):
                c = self.z.cctx()
                c.set(F.LEVEL, 6)
                c.set(F.OMIT_PROPERTIES, 1)
                bare = c.compress(data)
                c.close()
                if not data:
                    # compressCCtx writes a property byte for empty input even with omitProperties (upstream:
                    # fl2_compress.c:575 checks cSize == 0, not omitProp). Noted in other-codecs.md 4.4.1.
                    self.same(bare[1:], b"\x00")
                    continue
                out, rest = F.liblzma_decode(bare, props=False)
                self.same(out, data)
                self.same(rest, b"")

    def high(self, data, level, threads=1):
        c = self.z.cctx(threads)
        try:
            self.assertFalse(F.is_error(c.set(F.HIGH_COMPRESSION, 1)))
            self.assertFalse(F.is_error(c.set(F.LEVEL, level)))
            return c.compress(data)
        finally:
            c.close()

    def test_decodes_liblzma(self):
        """FL2's decoders read LZMA2 written by liblzma, every preset, given a property byte for its dictionary."""
        for name, data in corpus(big=False) + [("mixed 300000", sample.mixed(300000))]:
            for preset in list(range(10)) + [6 | lzma.PRESET_EXTREME]:
                raw, frame = F.liblzma_encode(data, preset)
                with self.subTest(data=name, preset=preset):
                    self.same(self.z.decompress(frame, len(data)), data)
                    self.same(self.z.decompress(frame, len(data), threads=2), data)
                    self.same(self.dstream(frame, 1, in_step=4096)[0], data)
                    self.same(self.dstream(frame, 2, in_step=4096)[0], data)

    def test_high_compression_levels(self):
        for name, data in corpus():
            for level in range(1, F.MAX_HIGH_CLEVEL + 1):
                with self.subTest(data=name, level=level):
                    f = self.high(data, level)
                    self.same(self.z.decompress(f, len(data)), data)
                    self.same(F.liblzma_decode(f)[0], data)

    def test_empty_input(self):
        for how, f in (("one-shot", self.z.compress(b"")), ("stream", self.stream(b"")),
                       ("stream mt", self.stream(b"", 6, 2, 1))):
            with self.subTest(frame=how):
                self.same(self.z.decompress(f, 0), b"")
                self.same(self.dstream(f)[0], b"")
                self.same(F.liblzma_decode(f)[0], b"")
                self.assertEqual(self.z.find_size(f), 0)

    # ------------------------------------------------------------------ official fast-lzma2

    def test_one_shot_matches_official(self):
        """GrindCore compiles official 1.0.1's sources, so its output must be official 1.0.1's, byte for byte, at every
        level (normal and high) and thread count."""
        self.need_ref()
        for name, data in corpus():
            for level in range(1, F.MAX_CLEVEL + 1):
                for threads in (1, 2, 4):
                    with self.subTest(data=name, level=level, threads=threads):
                        self.same(self.z.compress(data, level, threads), self.ref.compress(data, level, threads))
            for level in (1, 5, 10):
                with self.subTest(data=name, high=level):
                    c = self.ref.cctx()
                    c.set(F.HIGH_COMPRESSION, 1)
                    c.set(F.LEVEL, level)
                    want = c.compress(data)
                    c.close()
                    self.same(self.high(data, level), want)

    def test_stream_matches_official(self):
        """Streams match official 1.0.1 byte for byte, except a double-buffered stream that is flushed often: its
        output depends on the background thread's timing (measured under load on linux-x86: 3 to 6 different
        outputs in 60 runs, of GrindCore and official alike, every one of them correct). Those are checked by
        decoding them instead. GrindCore.net double-buffers whenever ThreadCount > 1 (other-codecs.md 4.4.1)."""
        self.need_ref()
        for name, data in corpus():
            for threads, dual in ((1, 0), (2, 0), (2, 1)):
                for chunk, flush in ((1 << 20, False), (4096, False), (4096, True)):
                    with self.subTest(data=name, threads=threads, dual=dual, chunk=chunk, flush=flush):
                        got = self.stream(data, 6, threads, dual, chunk, flush)
                        if dual and flush:
                            self.same(self.z.decompress(got, len(data)), data)
                            self.same(F.liblzma_decode(got)[0], data)
                            continue
                        want = self.stream(data, 6, threads, dual, chunk, flush, api=self.ref)
                        self.same(got, want)

    def test_upstream_fixes_keep_output(self):
        """Upstream's two fixes after 1.0.1 (b44b79b9, a793db99) change no output: master's frames are 1.0.1's for the
        same calls, so taking them changes nothing a caller can see except the out-of-bounds read."""
        self.need_ref("master")
        for name, data in corpus() + [("rep%d" % p, repeat_tail(p, 65536)) for p in (3, 4, 8, 16)]:
            for level in (1, 4, 6, 10):
                with self.subTest(data=name, level=level):
                    self.same(self.z.compress(data, level), self.master.compress(data, level))
                    self.same(self.stream(data, min(level, 6)), self.stream(data, min(level, 6), api=self.master))

    # ------------------------------------------------------------------ upstream defects

    def test_source_not_read_past_end(self):
        """FL2_compressCCtx reads only its source. 1.0.1's radix match finder (RMF_handleRepeat, radix_mf.c:303)
        extends a repeat without checking the block's end, so a source ending in a short-period run is read past its
        last byte: with a no-access page right after it, levels 4 and 6 crash (measured on linux-x64: 112 of 616
        cases, periods 3-16). Fixed upstream in a793db99, after 1.0.1. Each case in a child, source against a guard."""
        code = """
            from gctest import fl2_util as F
            from gctest.test_fl2 import repeat_tail
            import random
            z = F.grindcore(L)
            for period, n, level in %r:
                data = repeat_tail(period, n)
                if n > 1000:
                    data = random.Random(n).getrandbits(8 * (n - 600)).to_bytes(n - 600, "little") + data[:600]
                g = F.Guarded(data)
                c = z.cctx()
                c.set(F.LEVEL, level)
                f = c.compress(data, src=g.addr)
                c.close()
                assert z.decompress(f, len(data)) == data
                print("ok", period, n, level, flush=True)
        """
        cases = [(8, 300, 6), (4, 4096, 4), (16, 65536, 6), (3, 1 << 20, 4)]
        for case in cases:
            with self.subTest(period=case[0], size=case[1], level=case[2]):
                rc, out, err = child(code % ([case],), timeout=120)
                if rc != 0 and "ok" not in out:
                    if faulted(rc, err):
                        known(self, "fl2-handlerepeat-overread")
                    self.fail("rc %s: %s" % (rc, err[-800:]))

    # ------------------------------------------------------------------ API semantics GrindCore.net relies on

    def test_level_resets_parameters(self):
        """Setting the level (FL2_p_compressionLevel, FL2_initCStream(level > 0), FL2_compressCCtx(level > 0))
        reloads the whole level table: dictionary, strategy, depth, fast length, lc, pb (FL2_fillParameters). So
        parameters must be set after the level, and the stream initialised with level 0. GrindCore.net's encoder and
        block set them first (other-codecs.md 4.4.1, W1/W2)."""
        want = {F.DICTIONARY_SIZE: 1 << 20, F.FAST_LENGTH: 100, F.SEARCH_DEPTH: 20, F.STRATEGY: F.FAST,
                F.LITERAL_CTX_BITS: 1, F.POS_BITS: 0}
        s = self.z.cstream()
        for p, v in want.items():
            self.assertFalse(F.is_error(s.set(p, v)))
        s.init(6)
        self.assertEqual(s.get(F.DICTIONARY_SIZE), F.LEVEL_DICT[6])
        self.assertEqual(s.get(F.STRATEGY), F.LEVEL_STRATEGY[6])
        self.assertEqual((s.get(F.LITERAL_CTX_BITS), s.get(F.POS_BITS)), (3, 2))
        s.close()
        s = self.z.cstream()
        s.set(F.LEVEL, 6)
        for p, v in want.items():
            s.set(p, v)
        s.init(0)
        self.assertEqual({p: s.get(p) for p in want}, want)
        s.close()
        c = self.z.cctx()
        for p, v in want.items():
            c.set(p, v)
        data = sample.text(300000)
        c.compress(data, level=0)
        self.assertEqual({p: c.get(p) for p in want}, want, "compressCCtx(level 0) keeps them")
        c.compress(data, level=6)
        self.assertEqual(c.get(F.DICTIONARY_SIZE), F.LEVEL_DICT[6], "compressCCtx(level 6) reloads the table")
        c.close()

    def test_strategy_values(self):
        """FL2_strategy is fast 0, opt 1, ultra 2. GrindCore.net documents 1..3 and maps "normal" to 3 (W3)."""
        c = self.z.cctx()
        for v in (F.FAST, F.OPT, F.ULTRA):
            self.assertEqual(c.set(F.STRATEGY, v), v)
        self.assertEqual(F.error_of(c.set(F.STRATEGY, 3)), F.PARAMETER_OUT_OF_BOUND)
        c.close()

    def test_parameters_locked_after_init(self):
        s = self.z.cstream()
        s.init(6)
        self.assertEqual(F.error_of(s.set(F.DICTIONARY_SIZE, 1 << 20)), F.STAGE_WRONG)
        self.assertFalse(F.is_error(s.set(F.LITERAL_CTX_BITS, 1)), "lc, lp and pb may change between chunks")
        s.close()

    def test_out_of_range_parameters(self):
        """Every parameter's bounds (fast-lzma2.h). The dictionary's maximum is 128 MiB in a 32-bit build, 1 GiB in a
        64-bit one."""
        dmax = 1 << (27 if IS_32 else 30)
        bounds = [(F.LEVEL, 1, 10), (F.DICTIONARY_LOG, 20, 27 if IS_32 else 30), (F.DICTIONARY_SIZE, 1 << 20, dmax),
                  (F.OVERLAP_FRACTION, 0, 14), (F.BUFFER_RESIZE, 0, 4), (F.HYBRID_CHAIN_LOG, 4, 14),
                  (F.HYBRID_CYCLES, 1, 64), (F.SEARCH_DEPTH, 6, 254), (F.FAST_LENGTH, 6, 273), (F.STRATEGY, 0, 2),
                  (F.LITERAL_CTX_BITS, 0, 4), (F.LITERAL_POS_BITS, 0, 4), (F.POS_BITS, 0, 4)]
        for p, lo, hi in bounds:
            with self.subTest(param=p):
                c = self.z.cctx()
                if p == F.LITERAL_POS_BITS:
                    c.set(F.LITERAL_CTX_BITS, 0)
                for v in (lo, hi):
                    r = c.set(p, v)
                    self.assertFalse(F.is_error(r), "value %d: error %d" % (v, F.error_of(r)))
                if lo > 0:
                    self.assertEqual(F.error_of(c.set(p, lo - 1)), F.PARAMETER_OUT_OF_BOUND)
                self.assertEqual(F.error_of(c.set(p, hi + 1)), F.PARAMETER_OUT_OF_BOUND)
                c.close()
        c = self.z.cctx()
        self.assertEqual(F.error_of(c.set(F.USE_REFERENCE_MF, 1)), F.PARAMETER_UNSUPPORTED,
                         "built without RMF_REFERENCE: GrindCore.net's UseReferenceMF always fails")
        self.assertEqual(F.error_of(c.set(99, 1)), F.PARAMETER_UNSUPPORTED)
        c.close()

    def test_empty_source(self):
        """FL2_decompress with no source bytes at all is an error, and reads nothing. 1.0.1's FL2_decompressDCtx
        (fl2_decompress.c:322-326) reads the property byte without checking srcSize, then decrements srcSize to
        SIZE_MAX and decodes whatever memory follows as if it were input. GrindCore.net's FastLzma2Block reaches this
        with srcCount 0 on 64-bit (other-codecs.md 4.4.1). A 1-byte source (a property byte, nothing else) must fail
        too. Each in a child, the source against a guard page."""
        code = """
            from gctest import fl2_util as F
            import ctypes
            z = F.grindcore(L)
            g = F.Guarded(%r)
            out = ctypes.create_string_buffer(1 << 16)
            for threads in (1, 2):
                r = z.call("FL2_decompressMt", out, len(out), g.addr, %d, threads)
                print("result", threads, F.is_error(r), F.error_of(r), r if not F.is_error(r) else "", flush=True)
        """
        for src, n in ((b"", 0), (b"\x98", 1)):
            with self.subTest(size=n):
                rc, out, err = child(code % (src, n), timeout=60)
                if rc != 0:
                    if n == 0 and faulted(rc, err):
                        known(self, "fl2-empty-source-overread")
                    self.fail("rc %s: %s %s" % (rc, out, err[-800:]))
                for line in out.splitlines():
                    if line.startswith("result"):
                        self.assertEqual(line.split()[2], "True", "decoded %d source bytes as success: %s" % (n, line))

    def test_flush_makes_everything_decodable(self):
        """FL2_flushStream ends the current LZMA2 chunk, and everything written so far decodes (liblzma, reading as a
        stream), while the dictionary carries on: data repeated after a flush still compresses to almost nothing.
        That is the sync flush GrindCore.net's LZMA2 stream lacks (lzma.md 3.1, alternative i)."""
        a, b = sample.text(200000, seed=1), sample.mixed(100000, seed=2)
        for threads, dual in ((1, 0), (2, 0), (2, 1)):
            with self.subTest(threads=threads, dual=dual):
                s = self.z.cstream(threads, dual)
                s.init(6)
                head = s.write(a) + s.flush()
                d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2,
                                                                     "dict_size": F.dict_size_from_prop(head[0])}])
                self.same(d.decompress(head[1:]), a)
                again = s.write(a) + s.flush()
                self.assertLess(len(again), len(head) // 20, "the repeat refers back past the flush")
                self.same(d.decompress(again), a)
                tail = s.write(b) + s.end()
                s.close()
                self.same(d.decompress(tail), b)
                self.assertTrue(d.eof)
                self.assertEqual(len(d.unused_data), 4)

    def test_end_then_new_frame(self):
        """After FL2_endStream, FL2_initCStream(0) starts a new frame with the same parameters. The streaming decoder
        stops at the end of the first and consumes nothing more; a fresh decoder is needed for the second."""
        a, b = sample.text(50000, seed=3), sample.text(50000, seed=4)
        s = self.z.cstream()
        s.init(6)
        f1 = s.write(a) + s.end()
        s.init(0)
        f2 = s.write(b) + s.end()
        s.close()
        got, used = self.dstream(f1 + f2)
        self.same(got, a)
        self.assertEqual(used, len(f1))
        self.same(self.dstream(f2)[0], b)

    def test_decoder_after_end(self):
        """Once a frame is done, FL2_decompressStream returns 0 and consumes nothing, however much input follows. A
        caller that loops until its input is used up never finishes: GrindCore.net's FastLzma2Decoder hangs on any
        trailing byte (W4)."""
        data = sample.text(20000)
        f = self.z.compress(data)
        d = self.z.dstream()
        src, out = F._In(f + b"\x00" * 16), ctypes.create_string_buffer(1 << 16)
        r, used, wrote = d.call(src, 0, len(f) + 16, out)
        self.assertEqual((r, used, wrote), (0, len(f), len(data)))
        for _ in range(5):
            self.assertEqual(d.call(src, used, 16, out), (0, 0, 0))
        d.close()

    def test_truncated_input(self):
        """A frame cut short: FL2_decompressStream returns 1 (more input needed) while input arrives, then with none,
        1 twice more and FL2_error_buffer on the third call without progress. GrindCore.net's decoder ignores that error,
        so a truncated stream just ends early (W6)."""
        data = sample.mixed(100000)
        f = self.z.compress(data)
        cut = f[:len(f) // 2]
        d = self.z.dstream()
        src, out = F._In(cut), ctypes.create_string_buffer(1 << 20)
        r, used, wrote = d.call(src, 0, len(cut), out)
        self.assertEqual((r, used), (1, len(cut)))
        self.assertGreater(wrote, 0)
        results = [d.call(src, len(cut), 0, out)[0] for _ in range(3)]
        d.close()
        self.assertEqual(results[:2], [1, 1])
        self.assertEqual(F.error_of(results[2]), F.BUFFER)
        with self.assertRaises(F.Fl2Error, msg="the one-shot decoder reports it"):
            self.z.decompress(cut, len(data))

    def test_find_decompressed_size(self):
        """FL2_findDecompressedSize adds up the LZMA2 chunk headers; FL2_CONTENTSIZE_ERROR for a frame that is cut
        short or corrupt. That is (size_t)-1 in a 64-bit return: all ones on 64-bit, 0xFFFFFFFF on 32-bit. So
        GrindCore.net's check (== uint.MaxValue) is right on 32-bit and never matches on 64-bit (other-codecs.md 4.4)."""
        for name, data in corpus():
            for f in (self.z.compress(data), self.z.compress(data, 6, threads=2), self.stream(data, 6, chunk=4096, flush_every=True)):
                with self.subTest(data=name):
                    self.assertEqual(self.z.find_size(f), len(data))
        f = self.z.compress(sample.mixed(100000))
        self.assertEqual(self.z.find_size(f[:len(f) // 2]), F.CONTENTSIZE_ERROR)
        self.assertEqual(self.z.find_size(b""), F.CONTENTSIZE_ERROR)
        self.assertEqual(self.z.find_size(f[:1] + b"\xff" * 64), F.CONTENTSIZE_ERROR)

    # ------------------------------------------------------------------ robustness

    def test_corrupt_input(self):
        """Every single-bit flip of a small frame, every truncation, and 200 random bodies behind a valid property
        byte, through FL2_decompress, FL2_decompressMt (2 threads) and both streaming decoders: nothing crashes or
        hangs, nothing writes past its buffer, and with the hash on, nothing wrong is accepted as success."""
        code = """
            from gctest import fl2_util as F, sample
            import random, ctypes
            z = F.grindcore(L)
            data = sample.text(3000, seed=9)
            f = z.compress(data, 6)
            cases = []
            for i in range(len(f) * 8):
                g = bytearray(f); g[i // 8] ^= 1 << (i % 8); cases.append(bytes(g))
            cases += [f[:n] for n in range(1, len(f))]    # (0 bytes: test_empty_source)
            r = random.Random(1)
            cases += [f[:1] + bytes(r.randrange(256) for _ in range(r.randrange(1, 400))) for _ in range(200)]
            wrong = errors = ok = 0
            for g in cases:
                for how in ("one", "mt", "s1", "s2"):
                    try:
                        if how == "one":
                            got = z.decompress(g, len(data) + 100)
                        elif how == "mt":
                            got = z.decompress(g, len(data) + 100, threads=2)
                        else:
                            d = z.dstream(1 if how == "s1" else 2)
                            try:
                                got = d.decode(g, 997, 1500, max_calls=20000)[0]
                            finally:
                                d.close()
                    except (F.Fl2Error, EOFError):
                        errors += 1
                        continue
                    if got == data:
                        ok += 1
                    elif g[0] & 0x80:
                        wrong += 1
            print("cases", len(cases), "ok", ok, "errors", errors, "wrong", wrong)
        """
        rc, out, err = child(code, timeout=900)
        self.assertEqual(rc, 0, err[-1500:])
        self.assertIn("wrong 0", out, out)

    def test_decompress_capacity(self):
        """A destination smaller than the data: an error, and nothing written past it (the guard bytes in
        Api.decompress)."""
        data = sample.mixed(50000)
        f = self.z.compress(data)
        for cap in (0, 1, 1000, len(data) - 1):
            for threads in (1, 2):
                with self.subTest(capacity=cap, threads=threads):
                    with self.assertRaises(F.Fl2Error) as e:
                        self.z.decompress(f, cap, threads)
                    self.assertIn(e.exception.code, (F.DST_SIZE_TOO_SMALL, F.CORRUPTION_DETECTED))
        self.same(self.z.decompress(f, len(data)), data)

    def test_compress_bound(self):
        """FL2_compressBound holds for incompressible data at every level and thread count, and a smaller buffer is
        an error, not an overrun."""
        for n in (0, 1, 100, 70000, 1 << 20):
            data = sample.noise(n, seed=n)
            bound = self.z.call("FL2_compressBound", n)
            for level in (1, 6, 10):
                for threads in (1, 4):
                    with self.subTest(n=n, level=level, threads=threads):
                        f = self.z.compress(data, level, threads, capacity=bound)
                        self.assertLessEqual(len(f), bound)
                        if len(f) > 1:
                            with self.assertRaises(F.Fl2Error) as e:
                                self.z.compress(data, level, threads, capacity=len(f) - 1)
                            self.assertEqual(e.exception.code, F.DST_SIZE_TOO_SMALL)

    def test_threads(self):
        """Any thread count works (0 = one per core), the output for a given count is always the same, and the
        count the context reports is the one asked for."""
        data = sample.mixed(2 << 20, seed=7)
        for threads in (0, 1, 2, 3, 4, 8):
            with self.subTest(threads=threads):
                c = self.z.cctx(threads)
                n = self.z.call("FL2_getCCtxThreadCount", c.c)
                if threads:
                    self.assertEqual(n, threads)
                c.set(F.LEVEL, 6)
                a = c.compress(data)
                b = c.compress(data)
                c.close()
                self.same(a, b)
                self.same(self.z.decompress(a, len(data)), data)

    def test_large_dictionary_limits(self):
        """The biggest settings either work or fail with FL2_error_memory_allocation, and never crash (a child with
        a memory cap from the caller: run with docker -m, or ulimit -v where -m isn't enforced). On 32-bit the dictionary is
        capped at 128 MiB, so the high levels 9 and 10 (256 and 512 MiB) are clamped."""
        code = """
            from gctest import fl2_util as F, sample
            z = F.grindcore(L)
            data = sample.mixed(3 << 20)
            for threads in (1, 4):
                for high, level in ((0, 10), (1, 9), (1, 10)):
                    s = z.cstream(threads, 1)
                    s.set(F.HIGH_COMPRESSION, high)
                    s.set(F.LEVEL, level)
                    try:
                        s.init(0)
                        f = s.compress(data)
                        res = "ok" if z.decompress(f, len(data)) == data else "WRONG"
                    except F.Fl2Error as e:
                        res = "error %d" % e.code
                    print(threads, high, level, s.get(F.DICTIONARY_SIZE), res, flush=True)
                    s.close()
        """
        rc, out, err = child(code, timeout=900)
        self.assertEqual(rc, 0, err[-1500:] + out)
        self.assertNotIn("WRONG", out)
        for line in (l.strip() for l in out.splitlines()):   # a Windows child writes \r\n
            if line and "error" in line:
                self.assertTrue(line.endswith("error %d" % F.MEMORY_ALLOCATION), line)
            if line and IS_32:
                self.assertLessEqual(int(line.split()[3]), 1 << 27, line)

    # ------------------------------------------------------------------ the rest of the API

    def test_level_tables(self):
        """FL2_maxCLevel/FL2_maxHighCLevel and FL2_getLevelParameters give the generic tables GrindCore builds with
        (fl2_compress.c:73-101). Level 0 returns the all-zero row as success (upstream quirk)."""
        self.assertEqual((self.z.call("FL2_maxCLevel"), self.z.call("FL2_maxHighCLevel")), (10, 10))
        p = self.L.struct.FL2_compressionParameters()
        for level in range(1, 11):
            self.assertFalse(F.is_error(self.z.call("FL2_getLevelParameters", level, 0, ctypes.addressof(p))))
            self.assertEqual((p.dictionarySize, p.strategy), (F.LEVEL_DICT[level], F.LEVEL_STRATEGY[level]))
            self.assertFalse(F.is_error(self.z.call("FL2_getLevelParameters", level, 1, ctypes.addressof(p))))
            self.assertEqual((p.dictionarySize, p.strategy), (F.MB << (level - 1), F.ULTRA))
        for high in (0, 1):
            r = self.z.call("FL2_getLevelParameters", 11, high, ctypes.addressof(p))
            self.assertEqual(F.error_of(r), F.PARAMETER_OUT_OF_BOUND)
        self.assertFalse(F.is_error(self.z.call("FL2_getLevelParameters", 0, 0, ctypes.addressof(p))))
        self.assertEqual(p.dictionarySize, 0)

    def test_dict_size_from_prop(self):
        """FL2_getDictSizeFromProp: LZMA2's dictionary sizes for properties 0-39; 40 is SIZE_MAX (which is also
        FL2_error_GENERIC's code); anything above is an error."""
        for p in range(40):
            self.assertEqual(self.z.call("FL2_getDictSizeFromProp", p), F.dict_size_from_prop(p))
        self.assertEqual(self.z.call("FL2_getDictSizeFromProp", 40), F.SIZE_MAX)
        for p in (41, 63, 255):
            self.assertEqual(F.error_of(self.z.call("FL2_getDictSizeFromProp", p)), F.CORRUPTION_DETECTED)

    def test_memory_estimates(self):
        """The estimates are consistent: a CStream is its CCtx plus the dictionary (twice when double-buffered);
        by level, by parameters and from a configured context agree once the stream is initialised (buffers are
        allocated then); more threads and higher levels cost more. Out of range, FL2_estimateCStreamSize indexes the
        level table without a check (fl2_compress.c:1296) and adds what it finds there to FL2_estimateCCtxSize's
        error code: levels below 0 or above 11 return garbage, and level 0 leaves the dictionary out."""
        est = self.z.call
        p = self.L.struct.FL2_compressionParameters()
        for level in (1, 6, 10):
            est("FL2_getLevelParameters", level, 0, ctypes.addressof(p))
            with self.subTest(level=level):
                cctx = est("FL2_estimateCCtxSize", level, 1)
                self.assertEqual(est("FL2_estimateCCtxSize_byParams", ctypes.addressof(p), 1), cctx)
                for dual in (0, 1):
                    self.assertEqual(est("FL2_estimateCStreamSize", level, 1, dual), cctx + (p.dictionarySize << dual))
                    self.assertEqual(est("FL2_estimateCStreamSize_byParams", ctypes.addressof(p), 1, dual),
                                     cctx + (p.dictionarySize << dual))
                self.assertGreater(est("FL2_estimateCCtxSize", level, 4), cctx)
                c = self.z.cctx()
                c.set(F.LEVEL, level)
                self.assertEqual(est("FL2_estimateCCtxSize_usingCCtx", c.c), cctx)
                c.close()
                s = self.z.cstream()
                s.init(level)
                self.assertEqual(est("FL2_estimateCStreamSize_usingCStream", s.s), cctx + p.dictionarySize)
                s.close()
        self.assertLess(est("FL2_estimateCCtxSize", 1, 1), est("FL2_estimateCCtxSize", 6, 1))
        self.assertLess(est("FL2_estimateCCtxSize", 6, 1), est("FL2_estimateCCtxSize", 10, 1))
        self.assertLess(est("FL2_estimateDCtxSize", 1), est("FL2_estimateDCtxSize", 4))
        self.assertGreaterEqual(est("FL2_estimateDStreamSize", 16 << 20, 1), 16 << 20)
        self.assertGreater(est("FL2_estimateDStreamSize", 16 << 20, 4), est("FL2_estimateDStreamSize", 16 << 20, 1))
        self.assertEqual(F.error_of(est("FL2_estimateCCtxSize", 11, 1)), F.PARAMETER_OUT_OF_BOUND)
        level6 = est("FL2_estimateCCtxSize", 6, 1) + F.LEVEL_DICT[6]
        bad = [lv for lv in (-1, 0, 12, 13)
               if F.error_of(est("FL2_estimateCStreamSize", lv, 1, 0)) != F.PARAMETER_OUT_OF_BOUND
               and est("FL2_estimateCStreamSize", lv, 1, 0) != level6]
        if bad:
            known(self, "fl2-estimate-level-unchecked")

    def test_bare_stream_with_stored_property(self):
        """A stream written with FL2_p_omitProperties (no property byte, no hash: 7-Zip's and xz's LZMA2) decodes
        once the decoder is given the property: FL2_initDCtx + FL2_decompressDCtx, and FL2_initDStream_withProp.
        FL2_getCCtxDictProp gives the configured dictionary's property, before and after compressing. That can be
        larger than what a small input needed (the frame's own byte), which is still valid, just generous."""
        data = sample.mixed(300000)
        c = self.z.cctx()
        c.set(F.LEVEL, 6)
        c.set(F.OMIT_PROPERTIES, 1)
        before = self.z.call("FL2_getCCtxDictProp", c.c)
        bare = c.compress(data)
        after = self.z.call("FL2_getCCtxDictProp", c.c)
        c.close()
        self.assertEqual(before, F.dict_prop(F.LEVEL_DICT[6]))
        self.assertEqual(after, before)
        frame_prop = self.z.compress(data, 6)[0] & 0x3F
        self.assertLessEqual(frame_prop, after)
        self.same(F.liblzma_decode(bare, props=False)[0], data)
        for prop in (after, frame_prop):
            for threads in (1, 2):
                with self.subTest(prop=prop, threads=threads):
                    d = self.z.dctx(threads)
                    d.init(prop)
                    self.same(d.decompress(bare, len(data)), data)
                    d.close()
                    s = self.z.dstream(threads)
                    s.init(prop)
                    got, used = s.decode(bare, 4096, 5000)
                    s.close()
                    self.same(got, data)
                    self.assertEqual(used, len(bare))

    def test_dctx_reuse(self):
        """One FL2_DCtx (single- and multithreaded) decodes frame after frame of every size, FL2's and liblzma's,
        and reports the thread count it was given. FL2_createCCtx is a one-thread context. FL2_decompress is
        FL2_decompressMt with one thread."""
        frames = [(d, self.z.compress(d, lv)) for _, d in corpus() for lv in (1, 6)]
        frames += [(d, F.liblzma_encode(d, 6)[1]) for _, d in corpus(big=False)]
        for threads in (1, 4):
            with self.subTest(threads=threads):
                d = self.z.dctx(threads)
                self.assertEqual(self.z.call("FL2_getDCtxThreadCount", d.d), threads)
                for data, f in frames:
                    self.same(d.decompress(f, len(data)), data)
                d.close()
        c = self.z.cctx(1)
        c.close()
        c.c = self.z.call("FL2_createCCtx")
        self.assertEqual(self.z.call("FL2_getCCtxThreadCount", c.c), 1)
        data = sample.text(50000)
        f = c.compress(data, level=6)
        c.close()
        src, out = F._In(f), ctypes.create_string_buffer(len(data))
        self.assertEqual(self.z.call("FL2_decompress", out, len(data), src.addr, src.n), len(data))
        self.same(out.raw, data)

    def test_output_without_a_buffer(self):
        """The radix match finder keeps compressed data in its match table, so a stream can run with output NULL:
        FL2_compressStream(..., NULL, ...) returns 1 when there's output, FL2_remainingOutputSize says how much,
        and FL2_getNextCompressedBuffer hands out the slices (at most one per thread), or FL2_copyCStreamOutput
        copies them. FL2_getDictionaryBuffer/FL2_updateDictionary let the caller write input straight into the
        dictionary. Every path gives the same bytes as FL2_compressStream with an output buffer, given the same
        fill pattern (level 1: a 1 MiB dictionary, so 3 MiB compresses in several blocks)."""
        data = sample.mixed(3 << 20, seed=3)
        for threads in (1, 2):
            with self.subTest(threads=threads):
                want = self.stream(data, 1, threads, chunk=len(data))
                self.same(self.null_output(data, threads, copy=False), want, "getNextCompressedBuffer")
                self.same(self.null_output(data, threads, copy=True), want, "copyCStreamOutput")
                self.same(self.dictionary_buffer(data, threads), want, "getDictionaryBuffer")

    def _slices(self, s, threads, remaining=None):
        got, cb, n = bytearray(), F.CBuffer(), 0
        while self.z.call("FL2_getNextCompressedBuffer", s.s, ctypes.addressof(cb)):
            got += ctypes.string_at(cb.src, cb.size)
            n += 1
        self.assertLessEqual(n, threads)
        if remaining is not None:
            self.assertEqual(len(got), remaining)
        return bytes(got)

    def _copy(self, s):
        got, buf, ob = bytearray(), ctypes.create_string_buffer(1 << 16), self.L.struct.FL2_outBuffer()
        while True:
            ob.dst, ob.size, ob.pos = ctypes.addressof(buf), len(buf), 0
            r = self.z.call("FL2_copyCStreamOutput", s.s, ctypes.addressof(ob))
            got += buf.raw[:ob.pos]
            if r == 0:
                return bytes(got)

    def null_output(self, data, threads, copy):
        s = self.z.cstream(threads)
        s.init(1)
        src, ib, out, blocks = F._In(data), self.L.struct.FL2_inBuffer(), bytearray(), 0
        ib.src, ib.size, ib.pos = src.addr, src.n, 0
        while ib.pos < ib.size:
            r = self.z.check("FL2_compressStream", s.s, None, ctypes.addressof(ib))
            if r:
                blocks += 1
                pending = self.z.call("FL2_remainingOutputSize", s.s)
                out += self._copy(s) if copy else self._slices(s, threads, pending)
        while True:
            r = self.z.check("FL2_endStream", s.s, None)
            out += self._copy(s) if copy else self._slices(s, threads)
            if r == 0:
                break
        s.close()
        self.assertGreater(blocks, 0, "the dictionary filled at least once")
        return bytes(out)

    def dictionary_buffer(self, data, threads):
        s = self.z.cstream(threads)
        s.init(1)
        pos, out, db = 0, bytearray(), F.DictBuffer()
        while pos < len(data):
            self.z.check("FL2_getDictionaryBuffer", s.s, ctypes.addressof(db))
            self.assertGreater(db.size, 0)
            n = min(db.size, len(data) - pos)
            ctypes.memmove(db.dst, data[pos:pos + n], n)
            pos += n
            if self.z.check("FL2_updateDictionary", s.s, n):
                out += self._slices(s, threads)
        while True:
            r = self.z.check("FL2_endStream", s.s, None)
            out += self._slices(s, threads)
            if r == 0:
                break
        s.close()
        return bytes(out)

    def test_progress(self):
        """FL2_getCStreamProgress ends at the input size, and its outputSize at the output less the frame's last
        5 bytes (the end marker and the XXH32 aren't counted; upstream quirk). A NULL outputSize is allowed.
        FL2_getDStreamProgress ends at the decoded size. GrindCore.net declares the first one's pointer as a value
        (abi-verification.md), and uses neither."""
        data = sample.mixed(3 << 20, seed=4)
        for threads in (1, 2):
            with self.subTest(threads=threads):
                s = self.z.cstream(threads)
                s.init(6)
                f = s.compress(data, 1 << 20)
                osz = ctypes.c_ulonglong(0)
                self.assertEqual(self.z.call("FL2_getCStreamProgress", s.s, ctypes.addressof(osz)), len(data))
                self.assertEqual(osz.value, len(f) - 5)
                self.assertEqual(self.z.call("FL2_getCStreamProgress", s.s, None), len(data))
                s.close()
                d = self.z.dstream(threads)
                got, _ = d.decode(f)
                self.assertEqual(self.z.call("FL2_getDStreamProgress", d.s), len(data))
                d.close()
                self.same(got, data)

    def test_cstream_timeout_and_cancel(self):
        """With FL2_setCStreamTimeout, compression runs on a background thread and the stream calls return
        FL2_error_timedOut until it's done; calling again waits on. The output is the same as without a timeout.
        FL2_cancelCStream stops a compression underway and leaves the stream reusable after FL2_initCStream."""
        data = sample.mixed(3 << 20, seed=6)
        for threads, dual in ((1, 0), (2, 1)):
            with self.subTest(threads=threads, dual=dual):
                want = self.stream(data, 6, threads, dual, chunk=len(data))
                s = self.z.cstream(threads, dual)
                s.init(6)
                self.assertEqual(self.z.call("FL2_setCStreamTimeout", s.s, 1), 0)
                src, ib = F._In(data), self.L.struct.FL2_inBuffer()
                ib.src, ib.size, ib.pos = src.addr, src.n, 0
                got, failed = bytearray(), None
                for name, args in (("FL2_compressStream", (ctypes.addressof(ib),)), ("FL2_endStream", ())):
                    while not failed:
                        s._out()
                        r = self.z.call(name, s.s, ctypes.addressof(s.ob), *args)
                        got += s.out.raw[:s.ob.pos]
                        if F.error_of(r) == F.TIMED_OUT:
                            continue
                        if F.is_error(r):
                            failed = "%s: error %d" % (name, F.error_of(r))
                        elif r == 0 and (name == "FL2_endStream" or ib.pos == ib.size):
                            break
                if failed or bytes(got) != want:
                    # FL2POOL_waitAll's timed wait says "done" while the block is still queued (finding 9); the
                    # block then runs on the stream's state after the caller has moved on. Cancel (which waits for
                    # it) before anything is freed.
                    self.z.call("FL2_cancelCStream", s.s)
                    s.close()
                    known(self, "fl2-timeout-wait-race")
                s.init(6)
                ib.pos = 0
                s._out()
                self.z.call("FL2_compressStream", s.s, ctypes.addressof(s.ob), ctypes.addressof(ib))
                self.z.call("FL2_cancelCStream", s.s)
                self.assertEqual(self.z.call("FL2_setCStreamTimeout", s.s, 0), 0)
                s.init(6)
                again = s.compress(data[:200000], 1 << 16)
                s.close()
                self.same(self.z.decompress(again, 200000), data[:200000])

    def test_dstream_timeout_cancel_and_memory_limit(self):
        """The multithreaded streaming decoder, on a stream with a dictionary reset per block (FL2_p_resetInterval
        1, so it can use its threads): plain; with FL2_setDStreamTimeout, where a timed-out call's buffers stay in
        use by the background decoder until FL2_waitDStream says it's over (a caller must keep them pinned: that
        matters to GrindCore.net only if it ever sets a timeout); with FL2_setDStreamMemoryLimitMt too small, where
        it falls back to one thread. Each decodes correctly, and FL2_cancelDStream plus FL2_initDStream reuses it."""
        data = sample.mixed(24 << 20, seed=5)
        cs = self.z.cstream(4)
        cs.set(F.LEVEL, 3)
        cs.set(F.RESET_INTERVAL, 1)
        cs.init(0)
        f = cs.compress(data, 1 << 20)
        cs.close()
        for label, limit, timeout in (("plain", None, 0), ("timeout", None, 1), ("memory limit", 1 << 20, 0)):
            with self.subTest(mode=label):
                d = self.z.dstream(4)
                if limit:
                    self.z.call("FL2_setDStreamMemoryLimitMt", d.s, limit)
                if timeout:
                    self.assertEqual(self.z.call("FL2_setDStreamTimeout", d.s, timeout), 0)
                src, ib, ob = F._In(f), self.L.struct.FL2_inBuffer(), self.L.struct.FL2_outBuffer()
                ib.src, ib.size, ib.pos = src.addr, src.n, 0
                obuf, got, done, failed = ctypes.create_string_buffer(1 << 20), bytearray(), False, None
                while not done and not failed:
                    ob.dst, ob.size, ob.pos = ctypes.addressof(obuf), len(obuf), 0
                    r = self.z.call("FL2_decompressStream", d.s, ctypes.addressof(ob), ctypes.addressof(ib))
                    if F.error_of(r) == F.TIMED_OUT:
                        while True:
                            w = self.z.call("FL2_waitDStream", d.s)
                            if F.error_of(w) != F.TIMED_OUT:
                                break
                        if F.is_error(w):
                            failed = "FL2_waitDStream: error %d" % F.error_of(w)
                        done = w == 0
                    elif F.is_error(r):
                        failed = "FL2_decompressStream: error %d" % F.error_of(r)
                    else:
                        done = r == 0
                    got += obuf.raw[:ob.pos]
                if timeout and (failed or bytes(got) != data):
                    # finding 9: FL2_waitDStream said "done" while the job was still queued, so the caller moved on
                    # (FL2_error_stage_wrong next, or output decoded into a reused buffer). Cancel, which waits for
                    # the job, before the buffers go.
                    self.z.call("FL2_cancelDStream", d.s)
                    d.close()
                    known(self, "fl2-timeout-wait-race")
                self.assertIsNone(failed)
                self.same(bytes(got), data)
                self.assertEqual(self.z.call("FL2_getDStreamProgress", d.s), len(data))
                self.z.call("FL2_cancelDStream", d.s)
                self.z.call("FL2_setDStreamTimeout", d.s, 0)
                d.init()
                self.same(d.decode(f, 1 << 20, 1 << 20)[0], data)
                d.close()
