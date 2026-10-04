"""BZip2 1.0.8 (SZ_BZip2_v1_0_8_*): GrindCore's PAL over libbzip2, which is vendored unmodified (the library sources
are byte-identical to the official 1.0.8 release). Python's bz2 is the independent codec: GrindCore's output must
be what it produces byte for byte (bzip2's output is fully determined by the input and block size), and GrindCore
must decode what it makes. The PAL's bz_internal_error calls abort(), so corrupt-input runs happen in a child
process: an abort there is a finding, not a dead test run."""
import ctypes
import json
import unittest

import gctest
from gctest import sample
from gctest.test_hashes import child

try:
    import bz2
except ImportError:          # some minimal Python builds leave it out
    bz2 = None

BZ_RUN, BZ_FLUSH, BZ_FINISH = 0, 1, 2
BZ_OK, BZ_RUN_OK, BZ_FLUSH_OK, BZ_FINISH_OK, BZ_STREAM_END = 0, 1, 2, 3, 4
BZ_SEQUENCE_ERROR, BZ_PARAM_ERROR, BZ_DATA_ERROR, BZ_DATA_ERROR_MAGIC = -1, -2, -4, -5
BZ_UNEXPECTED_EOF, BZ_OUTBUFF_FULL = -7, -8
P = "SZ_BZip2_v1_0_8_"


class BzError(Exception):
    pass


class BZip2(object):
    def __init__(self, L):
        self.L = L

    def fn(self, n):
        return getattr(self.L, P + n)

    # --- one-shot ---------------------------------------------------------------------------------------------------

    def compress_block(self, data, level=9, work=0, capacity=None):
        cap = len(data) + len(data) // 100 + 600 if capacity is None else capacity
        dst = ctypes.create_string_buffer(max(cap, 1))
        n = ctypes.c_size_t(cap)
        rc = self.fn("CompressBlock")(dst, ctypes.byref(n), data, len(data), level, work)
        return rc, dst.raw[:min(n.value, cap)], n.value

    def decompress_block(self, stream, capacity, small=0):
        dst = ctypes.create_string_buffer(max(capacity, 1))
        n = ctypes.c_size_t(capacity)
        rc = self.fn("DecompressBlock")(dst, ctypes.byref(n), stream, len(stream), small)
        return rc, dst.raw[:min(n.value, capacity)] if rc == BZ_OK else b"", n.value

    # --- streaming --------------------------------------------------------------------------------------------------

    def compress_stream(self, data, level=9, work=0, in_step=0, out_step=0, flushes=(), last_with_finish=False):
        """BZ_RUN in in_step pieces; each position in `flushes` gets a BZ_FLUSH, the end a BZ_FINISH, both driven with
        no input as GrindCore.net does (or, with last_with_finish, the last piece handed in with BZ_FINISH).
        Returns (output, {flush position: output length})."""
        ctx = self.L.struct.SZ_BZip2_v1_0_8_CompressionContext()
        rc = self.fn("CreateCompressionContext")(ctypes.byref(ctx), level, work)
        if rc != BZ_OK:
            raise BzError("CreateCompressionContext returned %d" % rc)
        try:
            src, addr = sample.placed(data, 0)
            in_step = in_step or max(len(data), 1)
            out_step = out_step or len(data) + len(data) // 50 + 1024
            out = ctypes.create_string_buffer(out_step)
            got_in, got_out = ctypes.c_int64(), ctypes.c_int64()
            res, marks, pos = bytearray(), {}, 0
            f = self.fn("CompressStream")

            def call(ptr, n, action):
                rc = f(ctypes.byref(ctx), out, out_step, ptr, n, action, ctypes.byref(got_in), ctypes.byref(got_out))
                if not 0 <= got_in.value <= n or not 0 <= got_out.value <= out_step:
                    raise BzError("sizes out of range: in %d of %d, out %d of %d" % (got_in.value, n, got_out.value, out_step))
                res.extend(out.raw[:got_out.value])
                return rc, got_in.value

            for target, action in [(p, BZ_FLUSH) for p in sorted(flushes)] + [(len(data), BZ_FINISH)]:
                held = 0
                while pos < target:
                    n = min(in_step, target - pos)
                    if last_with_finish and action == BZ_FINISH and pos + n == target:
                        held = n                     # goes in with BZ_FINISH below
                        break
                    rc, used = call(addr + pos, n, BZ_RUN)
                    if rc != BZ_RUN_OK:
                        raise BzError("BZ_RUN returned %d" % rc)
                    pos += used
                done = BZ_STREAM_END if action == BZ_FINISH else BZ_RUN_OK
                busy = BZ_FINISH_OK if action == BZ_FINISH else BZ_FLUSH_OK
                for _ in range(100000):
                    rc, used = call(addr + pos if held else None, held, action)
                    pos, held = pos + used, held - used
                    if rc == done and not held:
                        break
                    if rc not in (busy, done):
                        raise BzError("action %d returned %d" % (action, rc))
                else:
                    raise BzError("action %d never completed" % action)
                marks[target] = len(res)
            return bytes(res), marks
        finally:
            self.fn("FreeCompressionContext")(ctypes.byref(ctx))

    def decompress_stream(self, stream, small=0, in_step=0, out_step=0):
        """Returns (last return code, output, input bytes left over)."""
        ctx = self.L.struct.SZ_BZip2_v1_0_8_DecompressionContext()
        rc = self.fn("CreateDecompressionContext")(ctypes.byref(ctx), small)
        if rc != BZ_OK:
            raise BzError("CreateDecompressionContext returned %d" % rc)
        try:
            src, addr = sample.placed(stream, 0)
            in_step = in_step or max(len(stream), 1)
            out_step = out_step or 1 << 20
            out = ctypes.create_string_buffer(out_step)
            got_in, got_out = ctypes.c_int64(), ctypes.c_int64()
            res, pos = bytearray(), 0
            f = self.fn("DecompressStream")
            while True:
                n = min(in_step, len(stream) - pos)
                rc = f(ctypes.byref(ctx), out, out_step, addr + pos if n else None, n, ctypes.byref(got_in), ctypes.byref(got_out))
                if not 0 <= got_in.value <= n or not 0 <= got_out.value <= out_step:
                    raise BzError("sizes out of range")
                pos += got_in.value
                res.extend(out.raw[:got_out.value])
                if rc != BZ_OK:
                    break
                if got_in.value == 0 and got_out.value == 0 and pos == len(stream):
                    break            # needs more input than there is
            return rc, bytes(res), len(stream) - pos
        finally:
            self.fn("FreeDecompressionContext")(ctypes.byref(ctx))


class BZip2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b = BZip2(gctest.LIB)

    def setUp(self):
        if bz2 is None:
            self.skipTest("this Python has no bz2 module")

    def test_block_matches_python_byte_for_byte(self):
        for kind, gen in sample.KINDS:
            for n in (0, 1, 1000, 250000):
                data = gen(n, seed=51)
                for level in range(1, 10):
                    rc, out, size = self.b.compress_block(data, level)
                    self.assertEqual((rc, size), (BZ_OK, len(out)), "%s %d bytes, level %d" % (kind, n, level))
                    self.assertEqual(out, bz2.compress(data, level), "%s %d bytes, level %d" % (kind, n, level))

    def test_work_factor_does_not_change_the_output(self):
        """workFactor only chooses when the block sort falls back to its slower algorithm; the sorted block, and so
        the stream, is the same. The long-run input is what triggers the fallback."""
        for gen in (sample.runs, sample.text):
            data = gen(400000, seed=52)
            want = bz2.compress(data, 9)
            for work in (0, 1, 30, 100, 250):
                self.assertEqual(self.b.compress_block(data, 9, work)[1], want, "workFactor %d" % work)

    def test_block_decompress(self):
        data = sample.mixed(700000, seed=53)
        for level in (1, 9):
            stream = bz2.compress(data, level)
            for small in (0, 1):
                what = "(level %d, small %d)" % (level, small)
                self.assertEqual(self.b.decompress_block(stream, len(data), small)[:2], (BZ_OK, data), what)
                self.assertEqual(self.b.decompress_block(stream, len(data) + 5, small), (BZ_OK, data, len(data)), what)
                rc, _, n = self.b.decompress_block(stream, len(data) - 1, small)
                self.assertEqual((rc, n), (BZ_OUTBUFF_FULL, len(data) - 1), "one byte short: error, size unchanged %s" % what)
                self.assertEqual(self.b.decompress_block(stream[:-1], len(data) + 1, small)[0], BZ_UNEXPECTED_EOF, what)
                self.assertEqual(self.b.decompress_block(b"BZh" + stream[3:4] + b"x" * 64, len(data), small)[0],
                                 BZ_DATA_ERROR, what)
        self.assertEqual(self.b.decompress_block(b"PK\x03\x04" + b"\x00" * 40, 100)[0], BZ_DATA_ERROR_MAGIC)
        empty = bz2.compress(b"")
        self.assertEqual(self.b.decompress_block(empty, 0)[:2], (BZ_OK, b""), "empty stream into 0 bytes")

    def test_block_decompress_reads_only_the_first_stream(self):
        a, b = sample.text(5000, seed=54), sample.text(7000, seed=55)
        both = bz2.compress(a) + bz2.compress(b)
        self.assertEqual(bz2.decompress(both), a + b, "Python joins concatenated streams")
        self.assertEqual(self.b.decompress_block(both, 20000)[:2], (BZ_OK, a),
                         "BZ2_bzBuffToBuffDecompress stops at the first stream's end")

    def test_stream_compress_in_any_steps_is_the_block_stream(self):
        """Without BZ_FLUSH, the stream is the one-shot stream whatever the piece sizes: blocks are cut by size."""
        small, big = sample.text(3000, seed=56), sample.mixed(1100000, seed=57)
        for data, level, steps in ((small, 1, ((1, 1), (1, 7), (3000, 1))),
                                   (big, 1, ((4093, 13), (99999, 65536), (1 << 20, 777))),
                                   (big, 9, ((65537, 4096),))):
            want = bz2.compress(data, level)
            for in_step, out_step in steps:
                for last in (False, True):
                    what = "(level %d, %d bytes, steps %d/%d, last piece with BZ_FINISH %s)" % (level, len(data), in_step, out_step, last)
                    out, _ = self.b.compress_stream(data, level, in_step=in_step, out_step=out_step, last_with_finish=last)
                    self.assertEqual(out, want, what)

    def test_stream_flush_ends_a_block(self):
        """BZ_FLUSH ends the current block (bzip2's manual: "terminate the current compression block"), but unlike
        zlib's Z_SYNC_FLUSH it doesn't make the block decodable yet: blocks are bit-packed with no padding, and the
        bit writer only emits whole bytes when it next writes, so the block's last 1-4 bytes (its end-of-block code
        at least) come out with the next block or the stream end. Measured on 120 inputs: 1, 2, 3 or 4 bytes, never
        0. Upstream behaviour (the library is unmodified); what GrindCore.net's BZip2Stream.Flush() gives a reader."""
        a, b = sample.text(60000, seed=58), sample.mixed(250000, seed=59)
        for out_step in (0, 101):
            out, marks = self.b.compress_stream(a + b, 5, in_step=8191, out_step=out_step, flushes=(len(a),))
            self.assertEqual(bz2.decompress(out), a + b, "output step %d" % out_step)
            m = marks[len(a)]
            self.assertLess(len(bz2.BZ2Decompressor().decompress(out[:m])), len(a),
                            "the flushed block's end is still held back (step %d)" % out_step)
            self.assertEqual(bz2.BZ2Decompressor().decompress(out[:m + 4]), a,
                             "4 more bytes complete the flushed block (step %d)" % out_step)
        out, marks = self.b.compress_stream(a, 5, flushes=(0, len(a) // 2, len(a) // 2))
        self.assertEqual(bz2.decompress(out), a, "flush with nothing pending, and twice in a row")

    def test_stream_decompress_in_any_steps(self):
        data = sample.mixed(900000, seed=60)
        stream = bz2.compress(data, 3)
        for small in (0, 1):
            for in_step, out_step in ((0, 0), (1, 65536), (4093, 13), (65536, 1 << 20)):
                rc, got, left = self.b.decompress_stream(stream, small, in_step, out_step)
                self.assertEqual((rc, left), (BZ_STREAM_END, 0), "small %d, steps %d/%d" % (small, in_step, out_step))
                self.assertEqual(got, data, "small %d, steps %d/%d" % (small, in_step, out_step))
        tiny = sample.text(2000, seed=61)
        self.assertEqual(self.b.decompress_stream(bz2.compress(tiny), 0, 1, 1), (BZ_STREAM_END, tiny, 0), "1-byte steps")

    def test_stream_decompress_stops_after_one_stream(self):
        a, b = sample.text(40000, seed=62), sample.text(30000, seed=63)
        sa, sb = bz2.compress(a), bz2.compress(b)
        rc, got, left = self.b.decompress_stream(sa + sb, in_step=1000)
        self.assertEqual((rc, got, left), (BZ_STREAM_END, a, len(sb)), "the second stream is left for a new context")
        self.assertEqual(self.b.decompress_stream((sa + sb)[len(sa):])[:2], (BZ_STREAM_END, b), "the rest decodes on its own")

    def test_stream_decompress_truncated_never_ends(self):
        data = sample.mixed(120000, seed=64)
        stream = bz2.compress(data, 1)
        for n in list(range(0, 64)) + list(range(64, len(stream), 211)) + [len(stream) - 1]:
            rc, got, left = self.b.decompress_stream(stream[:n], in_step=512)
            self.assertIn(rc, (BZ_OK, BZ_DATA_ERROR_MAGIC), "%d of %d bytes: %d" % (n, len(stream), rc))
            self.assertEqual(got, data[:len(got)], "output is a prefix (%d bytes)" % n)

    def test_corrupt_input_is_an_error_not_an_abort(self):
        """Every single-bit flip of a small stream, random bodies behind valid headers, and every truncation, through
        the one-shot and streaming decoders (small 0 and 1), in a child process. Nothing may abort (bz_internal_error)
        or crash, and nothing may be accepted with wrong data (each block and the stream carry a CRC)."""
        rc, out, err = child("""
            import bz2, json, random
            from gctest import sample
            from gctest.test_bzip2 import BZip2, BZ_OK, BZ_STREAM_END
            b = BZip2(L)
            data = sample.text(2500, seed=65)
            stream = bytearray(bz2.compress(data, 1))
            cases, errors, accepted_wrong, codes = 0, 0, [], {}
            def check(what, bad):
                global cases, errors
                for small in (0, 1):
                    # success is BZ_OK from the one-shot decoder, BZ_STREAM_END from the streaming one (whose BZ_OK
                    # means "needs more input")
                    for rc, got, ok in (b.decompress_block(bytes(bad), len(data) + 64, small)[:2] + (BZ_OK,),
                                        b.decompress_stream(bytes(bad), small, 97, 4096)[:2] + (BZ_STREAM_END,)):
                        cases += 1
                        codes[rc] = codes.get(rc, 0) + 1
                        if rc == ok and got != data and len(accepted_wrong) < 10:
                            accepted_wrong.append("%s (small %d): %d" % (what, small, rc))
                        elif rc < 0:
                            errors += 1
            for bit in range(len(stream) * 8):
                bad = bytearray(stream); bad[bit // 8] ^= 1 << (bit % 8)
                print("bit", bit, flush=True)
                check("bit %d" % bit, bad)
            r = random.Random(66)
            for i in range(300):
                body = r.getrandbits(8 * 1500).to_bytes(1500, "little")
                check("random body %d" % i, stream[:4] + (b"1AY&SY" if i % 2 else b"") + body)
            for n in range(len(stream)):
                check("truncated to %d" % n, stream[:n])
            print("RESULT " + json.dumps({"cases": cases, "errors": errors, "accepted_wrong": accepted_wrong,
                                          "codes": codes}))
        """, timeout=600)
        if rc != 0 or "RESULT " not in out:
            last = [l for l in out.splitlines() if l.startswith("bit ")][-1:] or ["(before the first case)"]
            self.fail("decoder process died (rc %r) at %s\n%s" % (rc, last[0], err[-2000:]))
        res = json.loads(out.split("RESULT ", 1)[1])
        self.assertEqual(res["accepted_wrong"], [], "corrupt input decoded as valid")
        self.assertGreater(res["errors"], res["cases"] // 2, "most cases must be errors: %r" % res["codes"])

    def test_invalid_parameters(self):
        f = self.b.fn
        c = self.L_struct("SZ_BZip2_v1_0_8_CompressionContext")
        for level, work in ((0, 0), (10, 0), (-1, 0), (9, -1), (9, 251)):
            self.assertEqual(f("CreateCompressionContext")(ctypes.byref(c), level, work), BZ_PARAM_ERROR, (level, work))
            self.assertEqual(f("FreeCompressionContext")(ctypes.byref(c)), BZ_PARAM_ERROR, "free after a failed create")
        d = self.L_struct("SZ_BZip2_v1_0_8_DecompressionContext")
        for small in (-1, 2):
            self.assertEqual(f("CreateDecompressionContext")(ctypes.byref(d), small), BZ_PARAM_ERROR, "small %d" % small)
            self.assertEqual(f("FreeDecompressionContext")(ctypes.byref(d)), BZ_PARAM_ERROR)
        for name, args in (("CreateCompressionContext", (None, 9, 0)), ("CreateDecompressionContext", (None, 0)),
                           ("FreeCompressionContext", (None,)), ("FreeDecompressionContext", (None,))):
            self.assertEqual(f(name)(*args), BZ_PARAM_ERROR, "%s(NULL)" % name)
        n, buf = ctypes.c_size_t(100), ctypes.create_string_buffer(100)
        self.assertEqual(f("CompressBlock")(None, ctypes.byref(n), b"x", 1, 9, 0), BZ_PARAM_ERROR, "NULL dst")
        self.assertEqual(f("CompressBlock")(buf, None, b"x", 1, 9, 0), BZ_PARAM_ERROR, "NULL capacity")
        self.assertEqual(f("CompressBlock")(buf, ctypes.byref(n), None, 1, 9, 0), BZ_PARAM_ERROR, "NULL src")
        self.assertEqual(f("CompressBlock")(buf, ctypes.byref(n), b"x", 1, 0, 0), BZ_PARAM_ERROR, "level 0")
        self.assertEqual(f("DecompressBlock")(buf, ctypes.byref(n), None, 1, 0), BZ_PARAM_ERROR, "NULL src")
        self.assertEqual(f("DecompressBlock")(buf, ctypes.byref(n), b"BZh9", 4, 2), BZ_PARAM_ERROR, "small 2")
        if ctypes.sizeof(ctypes.c_size_t) == 8:
            # the PAL's guard: bzip2's lengths are 32-bit, and BZ2_bzBuffToBuff* would silently truncate
            self.assertEqual(f("CompressBlock")(buf, ctypes.byref(n), b"x", 1 << 32, 9, 0), BZ_PARAM_ERROR, "src >= 4 GiB")
            self.assertEqual(f("DecompressBlock")(buf, ctypes.byref(n), b"x", 1 << 32, 0), BZ_PARAM_ERROR, "src >= 4 GiB")
            big = ctypes.c_size_t(1 << 32)
            self.assertEqual(f("CompressBlock")(buf, ctypes.byref(big), b"x", 1, 9, 0), BZ_PARAM_ERROR, "dst >= 4 GiB")
            self.assertEqual(f("DecompressBlock")(buf, ctypes.byref(big), b"x", 1, 0), BZ_PARAM_ERROR, "dst >= 4 GiB")

    def test_stream_call_errors(self):
        f = self.b.fn
        c = self.L_struct("SZ_BZip2_v1_0_8_CompressionContext")
        self.assertEqual(f("CreateCompressionContext")(ctypes.byref(c), 9, 0), BZ_OK)
        i, o = ctypes.c_int64(), ctypes.c_int64()
        out = ctypes.create_string_buffer(4096)
        try:
            cs = f("CompressStream")
            self.assertEqual(cs(ctypes.byref(c), out, 4096, b"abc", 3, 7, ctypes.byref(i), ctypes.byref(o)), BZ_PARAM_ERROR, "action 7")
            self.assertEqual(cs(ctypes.byref(c), None, 4096, b"abc", 3, 0, ctypes.byref(i), ctypes.byref(o)), BZ_PARAM_ERROR, "NULL dst")
            self.assertEqual(cs(ctypes.byref(c), out, 4096, None, 3, 0, ctypes.byref(i), ctypes.byref(o)), BZ_PARAM_ERROR, "NULL src, 3 bytes")
            self.assertEqual(cs(ctypes.byref(c), out, 4096, b"abc", 3, 0, None, ctypes.byref(o)), BZ_PARAM_ERROR, "NULL inSize")
            self.assertEqual(cs(ctypes.byref(c), out, 4096, b"abc", 3, BZ_RUN, ctypes.byref(i), ctypes.byref(o)), BZ_RUN_OK)
            self.assertEqual(i.value, 3)
            rc = BZ_FINISH_OK
            while rc == BZ_FINISH_OK:
                rc = cs(ctypes.byref(c), out, 4096, None, 0, BZ_FINISH, ctypes.byref(i), ctypes.byref(o))
            self.assertEqual(rc, BZ_STREAM_END)
            self.assertEqual(bz2.decompress(out.raw[:o.value]), b"abc")
            self.assertEqual(cs(ctypes.byref(c), out, 4096, b"more", 4, BZ_RUN, ctypes.byref(i), ctypes.byref(o)),
                             BZ_SEQUENCE_ERROR, "input after the stream end")
        finally:
            self.assertEqual(f("FreeCompressionContext")(ctypes.byref(c)), BZ_OK)

    def test_context_is_bound_to_its_address(self):
        """libbzip2 keeps a pointer back to the bz_stream and rejects calls through a copy (BZ_PARAM_ERROR, no
        crash): the reason GrindCore.net keeps its context in unmovable memory (AllocHGlobal)."""
        f = self.b.fn
        c = self.L_struct("SZ_BZip2_v1_0_8_CompressionContext")
        self.assertEqual(f("CreateCompressionContext")(ctypes.byref(c), 9, 0), BZ_OK)
        try:
            copy = self.L_struct("SZ_BZip2_v1_0_8_CompressionContext")
            ctypes.memmove(ctypes.byref(copy), ctypes.byref(c), ctypes.sizeof(c))
            i, o = ctypes.c_int64(), ctypes.c_int64()
            out = ctypes.create_string_buffer(4096)
            self.assertEqual(f("CompressStream")(ctypes.byref(copy), out, 4096, b"abc", 3, 0, ctypes.byref(i), ctypes.byref(o)),
                             BZ_PARAM_ERROR, "a moved context is refused")
            self.assertEqual(f("FreeCompressionContext")(ctypes.byref(copy)), BZ_PARAM_ERROR, "and can't free the original's state")
        finally:
            self.assertEqual(f("FreeCompressionContext")(ctypes.byref(c)), BZ_OK)

    def L_struct(self, name):
        return getattr(self.b.L.struct, name)()
