"""Brotli 1.1.0 (DN9_BRT_v1_1_0_*): the one-shot and streaming encoder and decoder.

GrindCore vendors official Brotli 1.1.0 with one upstream patch (.NET's google/brotli@85d88cbf, casts for an MSVC
warning): c/common, c/dec, c/enc and c/include are byte-identical to tag v1.1.0 plus that patch (other-codecs.md
4.3.1). The PAL is twelve pass-throughs. The references, from $GC_REF_BROTLI (ref/build_brotli_ref.py):
  - Brotli's own test fixtures (tests/testdata at the tag, each checked against its git blob hash): streams made by
    upstream, decoded here on every platform, Windows included;
  - official Brotli built unmodified from the tag's archive. GrindCore's output must match it byte for byte for the
    same calls, since Brotli's output is fully determined by the version, the parameters and the call sequence.
Crash probes, corrupt-input runs and allocation failures run in child processes."""
import ctypes
import hashlib
import json
import sys
import textwrap
import unittest

import gctest
from gctest import sample
from gctest import brotli_util as B
from gctest.test_hashes import child, known

SIZE_MAX = (1 << (8 * ctypes.sizeof(ctypes.c_size_t))) - 1
_STDCALL = {}
_EXITS = {}


def callback_convention():
    """True when the library's brotli_alloc_func/brotli_free_func are __stdcall (GrindCore's win-x86 build, /Gz; hub
    row 17). Only 32-bit Windows has two conventions. Probed in child processes, since the wrong one corrupts the
    stack; cached per library."""
    if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 4:
        return False
    if gctest.LIB.path not in _STDCALL:
        code = """
            from gctest import sample, brotli_util as B
            z = B.pal(L)
            data = sample.text(20000)
            al = B.Allocator(stdcall=%r)
            e = z.encoder({B.QUALITY: 5}, al)
            ok, out = e.compress(data)
            e.close()
            print("ok" if ok and z.decompress(out, len(data))[1] == data and not al.live else "wrong")
        """
        works = [conv for conv in (True, False) if child(code % conv, timeout=60)[1].strip().endswith("ok")]
        _STDCALL[gctest.LIB.path] = works == [True]
    return _STDCALL[gctest.LIB.path]


def describe(a, b):
    """Where two results differ, briefly: unittest's assertEqual builds a text diff of large byte strings before
    truncating it, which took over 20 minutes on the Pi for two 130 KB streams."""
    if isinstance(a, (tuple, list)) and isinstance(b, (tuple, list)) and len(a) == len(b):
        i = next(i for i in range(len(a)) if a[i] != b[i])
        return "element %d: %s" % (i, describe(a[i], b[i]))
    if isinstance(a, bytes) and isinstance(b, bytes):
        first = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
        return "%d vs %d bytes (sha256 %s vs %s), first difference at offset %d" % (
            len(a), len(b), hashlib.sha256(a).hexdigest()[:12], hashlib.sha256(b).hexdigest()[:12], first)
    return "%.300r vs %.300r" % (a, b)


def bchild(code, timeout=30):
    """child() with brotli_util's callback convention set as in this process."""
    return child("from gctest import brotli_util as B\nB.CALLBACK_STDCALL = %r\n" % B.CALLBACK_STDCALL +
                 textwrap.dedent(code), timeout)


def corpus(big=True):
    out = [("empty", b""), ("1 byte", b"x")] + [("%s %d" % (k, n), f(n, seed=n)) for k, f in sample.KINDS
                                                 for n in (1000, 20000)]
    return out + ([("mixed 300000", sample.mixed(300000))] if big else [])


def crashed(rc, err):
    return rc not in (0, 1) or "Traceback" in err


class BrotliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = gctest.LIB
        cls.z = B.pal(cls.L)
        cls.ref = B.reference()
        cls.fix = B.fixtures()
        B.CALLBACK_STDCALL = callback_convention()

    def same(self, got, want, msg=""):
        """assertEqual for results holding large byte strings (see describe)."""
        if got != want:
            self.fail(describe(got, want) + (" (%s)" % msg if msg else ""))

    def need_ref(self):
        if not self.ref:
            self.skipTest("no official Brotli 1.1.0: " + ("; ".join(B.REF_ERROR) or
                                                          "set GC_REF_BROTLI (ref/build_brotli_ref.py)"))

    def need_fixtures(self):
        if not self.fix:
            self.skipTest("no Brotli test fixtures: set GC_REF_BROTLI (ref/build_brotli_ref.py --fixtures-only)")

    # ------------------------------------------------------------------ decoding upstream's streams

    def test_official_fixtures(self):
        """Every *.compressed* file in Brotli's tests/testdata decodes to its original: one-shot, and streamed with
        1-byte and odd-sized input and output steps. The empty.compressed.NN variants are 19 different encodings of
        the empty stream; x.compressed.NN are 4 of one byte."""
        self.need_fixtures()
        pairs = sorted((n, n.split(".compressed")[0]) for n in self.fix if ".compressed" in n)
        self.same(len(pairs), 44)
        for name, orig in pairs:
            data, want = self.fix[name], self.fix[orig]
            with self.subTest(fixture=name):
                self.same(self.z.decompress(data, len(want) + 1), (B.SUCCESS, want, len(want)))
                steps = ((1 << 20, 1 << 16), (7, 13)) + (((1, 1),) if len(data) <= 20000 else ())
                for in_step, out_step in steps:
                    d = self.z.decoder()
                    try:
                        r, out, used = d.decode(data, in_step, out_step)
                        self.same((r, out, used), (B.SUCCESS, want, len(data)), (in_step, out_step))
                        self.assertTrue(d.finished())
                    finally:
                        d.close()

    # ------------------------------------------------------------------ encoding

    def test_round_trip_every_quality_window_and_mode(self):
        for name, data in corpus():
            for q in range(0, 12):
                for lgwin in (10, 16, 22, 24):
                    for mode in (B.GENERIC, B.TEXT, B.FONT):
                        if len(data) > 20000 and not ((lgwin, mode) == (22, B.GENERIC) or
                                                      ((lgwin, mode) == (24, B.TEXT) and q in (0, 1, 11))):
                            continue
                        with self.subTest(data=name, q=q, lgwin=lgwin, mode=mode):
                            ok, out, _ = self.z.compress(data, q, lgwin, mode)
                            self.assertTrue(ok)
                            self.same(self.z.decompress(out, len(data)), (B.SUCCESS, data, len(data)))

    def test_one_shot_matches_official(self):
        self.need_ref()
        for name, data in corpus():
            for q in range(0, 12):
                for lgwin, mode in ((10, B.GENERIC), (22, B.GENERIC), (24, B.TEXT), (18, B.FONT)):
                    if len(data) > 20000 and lgwin != 22:
                        continue
                    with self.subTest(data=name, q=q, lgwin=lgwin, mode=mode):
                        self.same(self.z.compress(data, q, lgwin, mode), self.ref.compress(data, q, lgwin, mode))

    def test_high_quality_output_fingerprint(self):
        """Informational: GrindCore's own one-shot output for one fixed 300 KB input, so runs on different RIDs can be
        compared. For some inputs, qualities 10 and 11 give compiler-dependent output (all valid; other-codecs.md
        4.3.1), and the RIDs are built with different compilers (clang 7, 14, 15 and 19, Apple clang, MSVC)."""
        data = sample.mixed(300000)
        fp = {}
        for q in (5, 9, 10, 11):
            ok, out, n = self.z.compress(data, q, 22)
            self.assertTrue(ok)
            self.same(self.z.decompress(out, len(data))[1], data)
            fp["q%d" % q] = "%d %s" % (n, hashlib.sha256(out).hexdigest()[:12])
        print("  fingerprint, mixed 300000, window 22: %s" % json.dumps(fp, sort_keys=True))

    def test_stream_matches_official(self):
        """The same parameters and the same calls: PROCESS in chunks, FLUSHes, FINISH, and little output room.
        Afterwards official Brotli reports the stream finished, which checks the run loop's completion test (the
        same test GrindCore.net uses: input consumed and no more output)."""
        self.need_ref()
        data = sample.mixed(200000, seed=9)
        cases = [({B.QUALITY: q}, 65536, 65536, ()) for q in (0, 1, 2, 5, 9, 10, 11)]
        cases += [
            ({B.QUALITY: 5, B.LGWIN: 16}, 1000, 17, (5000, 5001, 100000)),
            ({B.QUALITY: 1, B.LGWIN: 10}, 777, 64, (1, 2, 3, 150000)),
            ({B.QUALITY: 0, B.LGWIN: 24}, 13, 1 << 16, ()),
            ({B.QUALITY: 9, B.LGBLOCK: 16, B.MODE: B.TEXT}, 4096, 1 << 16, (60000,)),
            ({B.QUALITY: 11, B.LGBLOCK: 24, B.SIZE_HINT: len(data)}, 1 << 16, 1 << 16, ()),
            ({B.QUALITY: 7, B.DISABLE_LITERAL_CONTEXT_MODELING: 1}, 1 << 16, 1 << 16, ()),
            ({B.QUALITY: 11, B.NPOSTFIX: 2, B.NDIRECT: 12}, 1 << 16, 1 << 16, ()),
            ({B.QUALITY: 4, B.MODE: B.FONT, B.SIZE_HINT: 1 << 20}, 3000, 1000, (20000,)),
        ]
        for params, chunk, out_step, flush_at in cases:
            with self.subTest(params=params, chunk=chunk, out_step=out_step, flush_at=flush_at):
                results = []
                for api in (self.z, self.ref):
                    e = api.encoder(params)
                    try:
                        results.append(e.compress(data, chunk, out_step, flush_at))
                        if api is self.ref:
                            self.assertTrue(self.ref.dll.BrotliEncoderIsFinished(e.state), "run() stopped early")
                    finally:
                        e.close()
                self.assertTrue(results[0][0])
                self.same(results[0], results[1])
                self.same(self.z.decompress(results[0][1], len(data))[1], data)

    def test_out_of_range_parameters(self):
        """What SetParameter accepts and what the encoder then does with it, as official Brotli: 1.1.0 stores any
        value and clamps quality, window and block size when encoding starts (encode.c SanitizeParams)."""
        data = sample.text(30000, seed=3)
        cases = [({B.QUALITY: 12}, "above 11"), ({B.QUALITY: 0xFFFFFFFF}, "(uint32)-1"), ({B.LGWIN: 9}, "below 10"),
                 ({B.LGWIN: 25}, "25 without LARGE_WINDOW"), ({B.LGWIN: 31, B.LARGE_WINDOW: 1}, "31 large"),
                 ({B.LGBLOCK: 15}, "block below 16"), ({B.LGBLOCK: 25}, "block above 24"),
                 ({B.MODE: 3}, "mode 3"), ({B.NPOSTFIX: 4}, "npostfix 4"), ({B.NDIRECT: 121}, "ndirect 121"),
                 ({B.NPOSTFIX: 1, B.NDIRECT: 3}, "ndirect not a multiple"), ({99: 1}, "unknown parameter")]
        seen = {}
        for params, label in cases:
            with self.subTest(case=label):
                got = []
                for api in (self.z, self.ref) if self.ref else (self.z,):
                    e = api.encoder()
                    try:
                        accepted = [e.set(p, v) for p, v in sorted(params.items())]
                        ok, out = e.compress(data)
                    finally:
                        e.close()
                    decodes = ok and self.z.decompress(out, len(data))[1] == data
                    got.append((accepted, ok, out if ok else None, decodes))
                if self.ref:
                    self.same(got[0], got[1])
                self.assertTrue(not got[0][1] or got[0][3] or params.get(B.LARGE_WINDOW),
                                "a stream the encoder accepted doesn't decode")
                seen[label] = (got[0][0], got[0][1], len(got[0][2] or b""))
        print("  parameters (SetParameter results, encoded, size): %s" % json.dumps(seen, sort_keys=True))

    def test_large_window(self):
        """LARGE_WINDOW streams (window up to 2^30) need BrotliDecoderSetParameter(LARGE_WINDOW), which GrindCore
        doesn't export (other-codecs.md 4.3), so GrindCore's decoders must reject them cleanly: ERROR, no crash.
        Official Brotli with the parameter decodes them, and GrindCore's output must be official Brotli's. The one-shot
        BrotliEncoderCompress turns LARGE_WINDOW on by itself for lgwin > 24 (encode.c:1283).

        The encoder's ring buffer is 2^(lgwin+1) bytes plus a block (encode.c RingBufferSetup): 2 GiB at lgwin 30,
        which a 32-bit process usually can't get. GrindCore's build then fails the compression (BROTLI_ENCODER_CLEANUP_
        ON_OOM and the encode.c checks, other-codecs.md 4.3.1), so BrotliEncoderCompress falls back to storing the data
        uncompressed: valid output any decoder reads. Official Brotli, built with its default, exits the process there
        instead, and so did GrindCore's shipped builds (known defect brotli-exit-on-oom). Unfixed CLEANUP_ON_OOM
        builds wrote an empty stream and reported success. Each window runs in a child, which reports GrindCore's
        results before the reference's, so an exiting reference doesn't hide them. GrindCore.net caps the window at 24
        (BrotliBlock.cs:15, BrotliEncoder.cs:15)."""
        self.need_ref()
        seen, exited = {}, False
        for lgwin in (25, 30):
            code = """
                import json
                from gctest import sample
                z, ref = B.pal(L), B.reference()
                data = sample.mixed(400000, seed=5) * 3
                print("compressing", flush=True)
                ok, out, _ = z.compress(data, 5, %d)
                d = z.decoder()
                r, back, _ = d.decode(out)
                d.close()
                print("grindcore " + json.dumps({"ok": ok, "large-window header": out[:1] == b"\\x11",
                                                 "one-shot": z.decompress(out, len(data))[0], "stream": r,
                                                 "stream output right": back == data}, sort_keys=True), flush=True)
                rok, rout, _ = ref.compress(data, 5, %d)
                d = ref.decoder()
                ref.dll.BrotliDecoderSetParameter(d.state, B.DEC_LARGE_WINDOW, 1)
                right = d.decode(out)[:2] == (B.SUCCESS, data)
                d.close()
                print("official " + json.dumps({"same output": (rok, rout) == (ok, out),
                                                "official decoder, LARGE_WINDOW on": right}, sort_keys=True))
            """ % (lgwin, lgwin)
            rc, out, err = bchild(code, timeout=300)
            lines = out.strip().splitlines()
            gc = next((json.loads(x[len("grindcore "):]) for x in lines if x.startswith("grindcore ")), None)
            off = next((json.loads(x[len("official "):]) for x in lines if x.startswith("official ")), None)
            with self.subTest(lgwin=lgwin):
                self.assertFalse(crashed(rc, err), "rc %s %s" % (rc, err[-400:]))
                if gc is None:
                    seen[lgwin] = "GrindCore's encoder allocation failed and the process exited"
                    self.same((rc, lines[-1:], lgwin), (1, ["compressing"], 30), err[-300:])
                    exited = True
                    continue
                if gc["large-window header"]:
                    seen[lgwin] = "compressed with a large window"
                    self.same(gc, {"ok": 1, "large-window header": True, "one-shot": B.ERROR, "stream": B.ERROR,
                                   "stream output right": False})
                    self.same(off, {"same output": True, "official decoder, LARGE_WINDOW on": True}, err[-300:])
                else:
                    seen[lgwin] = "the ring buffer allocation failed; stored uncompressed"
                    self.same(lgwin, 30, "a 64 MiB ring buffer should always be available")
                    self.same(gc, {"ok": 1, "large-window header": False, "one-shot": B.SUCCESS, "stream": B.SUCCESS,
                                   "stream output right": True})
                    if off is None:
                        seen[lgwin] += "; official Brotli exited the process there (its default)"
                    else:
                        self.same(off["official decoder, LARGE_WINDOW on"], True)
        print("  large windows: %s" % json.dumps(seen, sort_keys=True))
        if exited:
            known(self, "brotli-exit-on-oom")

    def test_max_compressed_size(self):
        """BrotliEncoderMaxCompressedSize is 1.1.0's bound (4 bytes per 16 KiB), 0 on overflow; incompressible input
        fits in exactly that much at every quality, and one byte less than the output fails cleanly. GrindCore.net's
        managed GetMaxCompressedLength keeps Brotli 1.0's formula (4 bytes per 16 MiB), which is smaller from 16 KiB
        on; it has no caller (other-codecs.md 4.3.1)."""
        for n in (0, 1, 2, 16383, 16384, 16385, 1 << 20, (1 << 24) + 1, 1 << 30, SIZE_MAX - 100, SIZE_MAX):
            with self.subTest(n=n):
                self.same(self.z.max_compressed_size(n), B.max_compressed_size(n))
                if self.ref:
                    self.same(self.z.max_compressed_size(n), self.ref.max_compressed_size(n))
        noise = sample.noise(70000, seed=4)
        bound = B.max_compressed_size(len(noise))
        for q in range(0, 12):
            with self.subTest(q=q):
                ok, out, _ = self.z.compress(noise, q, 22, capacity=bound)
                self.assertTrue(ok)
                self.same(self.z.decompress(out, len(noise))[1], noise)
                ok2, _, _ = self.z.compress(noise, q, 22, capacity=len(out) - 1)
                self.assertFalse(ok2, "one byte less than the output it made")
        managed = B.managed_max_compressed_length(len(noise))
        short = [q for q in range(0, 12) if not self.z.compress(noise, q, 22, capacity=managed)[0]]
        print("  70000 noise bytes: bound %d, managed GetMaxCompressedLength %d; qualities that don't fit in the "
              "managed size: %s" % (bound, managed, short or "none"))

    def test_empty_input(self):
        """Empty input compresses to the 1-byte stream 0x06 (one-shot, encode.c:1261) or a short stream (FINISH with
        no input). An empty compressed input is not a stream: the one-shot decoder says ERROR, the streaming one
        NEEDS_MORE_INPUT."""
        for q in (0, 1, 5, 11):
            with self.subTest(q=q):
                self.same(self.z.compress(b"", q), (1, b"\x06", 1))
                e = self.z.encoder({B.QUALITY: q})
                try:
                    ok, out = e.compress(b"")
                finally:
                    e.close()
                self.assertTrue(ok)
                self.same(self.z.decompress(out, 10), (B.SUCCESS, b"", 0))
                if self.ref:
                    r = self.ref.encoder({B.QUALITY: q})
                    try:
                        self.same(r.compress(b""), (ok, out))
                    finally:
                        r.close()
        self.same(self.z.compress(b"", 5, capacity=0)[0], 0, "no output room at all")
        self.same(self.z.decompress(b"", 10)[0], B.ERROR)
        d = self.z.decoder()
        try:
            self.same(d.decode(b"")[0], B.NEEDS_MORE_INPUT)
        finally:
            d.close()

    # ------------------------------------------------------------------ decoding

    def test_decoder_never_writes_past_capacity(self):
        """Guard bytes after the capacity survive the one-shot and the streaming decoder at every capacity, and a
        stream that doesn't fit is ERROR (one-shot) or NEEDS_MORE_OUTPUT (streaming)."""
        data = sample.mixed(30000, seed=8)
        stream = self.z.compress(data, 9)[1]
        guard = b"\xA5" * 64
        for cap in (0, 1, 100, 29999, 30000, 30001):
            with self.subTest(capacity=cap):
                src = B._Buf(stream)
                dst, n = ctypes.create_string_buffer(cap + 64), ctypes.c_size_t(cap)
                ctypes.memmove(ctypes.addressof(dst) + cap, guard, 64)
                r = self.L.DN9_BRT_v1_1_0_BrotliDecoderDecompress(len(stream), src.addr, ctypes.byref(n), dst)
                self.same(dst.raw[cap:cap + 64], guard, "one-shot wrote past the end")
                self.same(r, B.SUCCESS if cap >= 30000 else B.ERROR)
                d = self.z.decoder()
                try:
                    a_in, a_out = ctypes.c_size_t(len(stream)), ctypes.c_size_t(cap)
                    n_in, n_out = ctypes.c_void_p(src.addr), ctypes.c_void_p(ctypes.addressof(dst))
                    r = self.L.DN9_BRT_v1_1_0_BrotliDecoderDecompressStream(
                        d.state, ctypes.byref(a_in), ctypes.byref(n_in), ctypes.byref(a_out), ctypes.byref(n_out),
                        None)
                finally:
                    d.close()
                self.same(dst.raw[cap:cap + 64], guard, "stream decoder wrote past the end")
                self.same(r, B.SUCCESS if cap >= 30000 else B.NEEDS_MORE_OUTPUT)

    def test_trailing_data_and_finished_state(self):
        """Upstream semantics GrindCore.net inherits: the one-shot decoder ignores bytes after the end of the stream
        (SUCCESS), so BrotliBlock accepts a block with trailing garbage; the streaming decoder stops at the end with
        the rest unconsumed, and IsFinished turns true only there. A truncated stream is ERROR one-shot and
        NEEDS_MORE_INPUT streamed."""
        data = sample.text(5000, seed=12)
        stream = self.z.compress(data, 6)[1]
        self.same(self.z.decompress(stream + b"garbage", len(data)), (B.SUCCESS, data, len(data)))
        d = self.z.decoder()
        try:
            self.assertFalse(d.finished())
            r, out, used = d.decode(stream + b"garbage")
            self.same((r, out, used), (B.SUCCESS, data, len(stream)))
            self.assertTrue(d.finished())
            again = d.call(b"more", 100)
        finally:
            d.close()
        self.same(self.z.decompress(stream[:-1], len(data))[0], B.ERROR)
        d = self.z.decoder()
        try:
            r, out, used = d.decode(stream[:-1])
        finally:
            d.close()
        self.same(r, B.NEEDS_MORE_INPUT)
        self.same(out, data[:len(out)])
        if self.ref:
            d = self.ref.decoder()
            try:
                d.decode(stream)
                self.same(d.call(b"more", 100)[:3], again[:3])
            finally:
                d.close()
        print("  DecompressStream after the end, with more input: result %d, consumed %d" % (again[0], again[2]))

    def test_corrupt_input(self):
        """Bit flips in every position of the first 600 bytes and 400 random ones further on, every truncation of a
        small stream, and 200 random inputs, through the one-shot and the streaming decoder (13-byte steps). No
        crash, guard bytes intact, and with the reference: the same result and output as official Brotli."""
        code = """
            import ctypes, json, random
            from gctest import sample, brotli_util as B
            z, ref = B.pal(L), B.reference()
            r = random.Random(4321)
            streams = [z.compress(sample.mixed(20000, seed=21), q)[1] for q in (1, 5, 11)]
            streams.append(z.compress(sample.text(3000, seed=22), 9, 16, B.TEXT)[1])
            inputs = []
            for s in streams:
                pos = list(range(min(len(s), 600))) + [r.randrange(len(s)) for _ in range(400)]
                for p in pos:
                    b = bytearray(s)
                    b[p] ^= 1 << r.randrange(8)
                    inputs.append(bytes(b))
            small = streams[3]
            inputs += [small[:n] for n in range(len(small))]
            inputs += [bytes(r.randrange(256) for _ in range(r.randrange(1, 300))) for _ in range(200)]
            guard = b"\\x5A" * 32
            bad, mismatch, tally = [], [], {}
            def one_shot(api, data):
                src = B._Buf(data)
                dst, n = ctypes.create_string_buffer(25000 + 32), ctypes.c_size_t(25000)
                ctypes.memmove(ctypes.addressof(dst) + 25000, guard, 32)
                res = api.fn("BrotliDecoderDecompress")(len(data), src.addr, ctypes.byref(n), dst)
                return res, dst.raw[:min(n.value, 25000)], dst.raw[25000:25032] == guard
            for i, data in enumerate(inputs):
                res, out, intact = one_shot(z, data)
                d = z.decoder()
                sres, sout, used = d.decode(data, 13, 997)
                d.close()
                if not intact:
                    bad.append(i)
                tally["%d/%d" % (res, sres)] = tally.get("%d/%d" % (res, sres), 0) + 1
                if ref:
                    rres, rout, _ = one_shot(ref, data)
                    d = ref.decoder()
                    got = d.decode(data, 13, 997)
                    d.close()
                    if (res, out, sres, sout, used) != (rres, rout) + got:
                        mismatch.append(i)
            print(json.dumps({"n": len(inputs), "bad": bad, "mismatch": mismatch[:20], "tally": tally}))
        """
        rc, out, err = child(code, timeout=900)
        self.same(rc, 0, "a decoder crashed on corrupt input: %s" % err[-600:])
        got = json.loads(out.strip().splitlines()[-1])
        print("  %d corrupt inputs, one-shot/stream results: %s" % (got["n"], got["tally"]))
        self.same(got["bad"], [], "a decoder wrote past its capacity")
        self.same(got["mismatch"], [], "different from official Brotli")

    # ------------------------------------------------------------------ stream semantics

    def test_flush_makes_everything_decodable(self):
        """After each FLUSH, the output so far decodes to all the input so far (the decoder then wants more input).
        Brotli's FLUSH is a real sync point, unlike bzip2's (other-codecs.md 4.4)."""
        data = sample.mixed(120000, seed=13)
        for q in (0, 1, 5, 11):
            with self.subTest(q=q):
                e = self.z.encoder({B.QUALITY: q})
                try:
                    out, fed = b"", 0
                    for cut in (1, 1000, 1001, 70000, 120000):
                        ok, chunk = e.run([(B.PROCESS, data[fed:cut]), (B.FLUSH, b"")])
                        self.assertTrue(ok)
                        out, fed = out + chunk, cut
                        d = self.z.decoder()
                        try:
                            r, got, used = d.decode(out)
                        finally:
                            d.close()
                        self.same((r, got, used), (B.NEEDS_MORE_INPUT, data[:fed], len(out)), cut)
                finally:
                    e.close()

    def test_finish_is_final(self):
        """After FINISH the encoder accepts no more input: PROCESS with data returns BROTLI_FALSE. GrindCore.net's
        BrotliStream.OnFlush always writes with FINISH (BrotliStream.cs:209), so a Write after Flush() fails there
        (other-codecs.md 4.3.1). FLUSH and FINISH with no input after the end are harmless."""
        e = self.z.encoder({B.QUALITY: 5})
        try:
            ok, out = e.run([(B.PROCESS, b"hello " * 100), (B.FINISH, b"")])
            self.assertTrue(ok)
            self.same(self.z.decompress(out, 600)[1], b"hello " * 100)
            after = {"PROCESS with data": e.call(B.PROCESS, b"more", 100)[0],
                     "PROCESS, no data": e.call(B.PROCESS, b"", 100)[0],
                     "FLUSH, no data": e.call(B.FLUSH, b"", 100)[0],
                     "FINISH, no data": e.call(B.FINISH, b"", 100)[0]}
        finally:
            e.close()
        print("  CompressStream after FINISH: %s" % json.dumps(after, sort_keys=True))
        self.same(after["PROCESS with data"], 0)

    def test_emit_metadata(self):
        """EMIT_METADATA blocks (up to 16 MiB) are skipped by the decoder; output matches official Brotli."""
        data, meta = sample.text(10000, seed=14), b"metadata \x00\xff" * 30
        steps = [(B.PROCESS, data[:4000]), (B.EMIT_METADATA, meta), (B.PROCESS, data[4000:]),
                 (B.EMIT_METADATA, b""), (B.FINISH, b"")]
        outs = []
        for api in (self.z, self.ref) if self.ref else (self.z,):
            e = api.encoder({B.QUALITY: 6})
            try:
                outs.append(e.run(steps, out_step=100))
            finally:
                e.close()
        self.assertTrue(outs[0][0])
        self.assertIn(meta, outs[0][1])
        self.same(self.z.decompress(outs[0][1], len(data)), (B.SUCCESS, data, len(data)))
        if self.ref:
            self.same(outs[0], outs[1])

    def test_interleaved_states_are_independent(self):
        a, b = sample.text(50000, seed=15), sample.noise(50000, seed=16)
        ea, eb = self.z.encoder({B.QUALITY: 7}), self.z.encoder({B.QUALITY: 3, B.LGWIN: 12})
        try:
            oa, ob = [], []
            for i in range(0, 50000, 5000):
                oa.append(ea.run([(B.PROCESS, a[i:i + 5000])])[1])
                ob.append(eb.run([(B.PROCESS, b[i:i + 5000])])[1])
            oa.append(ea.run([(B.FINISH, b"")])[1])
            ob.append(eb.run([(B.FINISH, b"")])[1])
        finally:
            ea.close()
            eb.close()
        ca, cb = b"".join(oa), b"".join(ob)
        for stream, data, params in ((ca, a, {B.QUALITY: 7}), (cb, b, {B.QUALITY: 3, B.LGWIN: 12})):
            e = self.z.encoder(params)
            try:
                alone = e.run([(B.PROCESS, data[i:i + 5000]) for i in range(0, 50000, 5000)] + [(B.FINISH, b"")])
            finally:
                e.close()
            self.same(alone, (True, stream))
        sides = [[self.z.decoder(), ca, 0, [], None], [self.z.decoder(), cb, 0, [], None]]
        try:
            for _ in range(100000):
                for side in sides:
                    d, stream, pos, out, r = side
                    if r in (B.SUCCESS, B.ERROR):
                        continue
                    r, o, used, _ = d.call(stream[pos:pos + 999], 4096)
                    out.append(o)
                    side[2], side[4] = pos + used, r
                if all(side[4] in (B.SUCCESS, B.ERROR) for side in sides):
                    break
        finally:
            for side in sides:
                side[0].close()
        self.same([(s[4], b"".join(s[3])) for s in sides], [(B.SUCCESS, a), (B.SUCCESS, b)])

    # ------------------------------------------------------------------ memory

    def test_allocator_callback_convention(self):
        """Informational: the calling convention a C caller's brotli_alloc_func/brotli_free_func must have. It's the
        build's default, since types.h names none: __stdcall on GrindCore's win-x86 build (/Gz), while a C program
        including Brotli's headers with MSVC's default (/Gd) passes __cdecl ones, which corrupt the stack there. No
        GrindCore.net code passes allocators (they're NULL)."""
        print("  allocator callbacks: %s" % ("__stdcall (win-x86 /Gz)" if B.CALLBACK_STDCALL else
                                            "the platform's only convention" if sys.platform != "win32" or
                                            ctypes.sizeof(ctypes.c_void_p) == 8 else "__cdecl"))

    def test_custom_allocators(self):
        """The PAL passes alloc_func/free_func/opaque through: every block the encoder and decoder allocate goes
        through them with the caller's opaque, and all are freed by DestroyInstance."""
        data = sample.mixed(100000, seed=17)
        for kind in ("encoder", "decoder"):
            with self.subTest(kind=kind):
                al = B.Allocator()
                if kind == "encoder":
                    e = self.z.encoder({B.QUALITY: 11}, al)
                    ok, out = e.compress(data)
                    e.close()
                    self.assertTrue(ok)
                    self.same(self.z.decompress(out, len(data))[1], data)
                else:
                    stream = self.z.compress(data, 11)[1]
                    d = self.z.decoder(al)
                    r, out, _ = d.decode(stream, 1000, 5000)
                    d.close()
                    self.same((r, out), (B.SUCCESS, data))
                self.assertGreater(al.requests, 1)
                self.same((len(al.live), al.bad_opaque, al.unknown_frees), (0, 0, 0))

    def exits_on_oom(self):
        """Whether this library's encoder calls exit() when an allocation fails (Brotli's default; GrindCore's
        shipped builds). Probed once in a child; cached per library."""
        if gctest.LIB.path not in _EXITS:
            probe = """
                from gctest import sample
                z = B.pal(L)
                al = B.Allocator(fail_at=2)
                e = B.Encoder.__new__(B.Encoder)
                e.api, e.allocator = z, al
                e.state = L.DN9_BRT_v1_1_0_BrotliEncoderCreateInstance(*al.args())
                e.set(B.QUALITY, 5)
                print("compressing", flush=True)
                ok, out = e.compress(sample.mixed(20000, seed=18))
                e.close()
                print("returned %d, %d live" % (ok, len(al.live)), flush=True)
            """
            rc, out, err = bchild(probe, timeout=120)
            last = out.strip().splitlines()[-1] if out.strip() else ""
            self.assertFalse(crashed(rc, err), "rc %s %s" % (rc, err[-400:]))
            _EXITS[gctest.LIB.path] = rc == 1 and last == "compressing"
            if not _EXITS[gctest.LIB.path]:
                self.same(last, "returned 0, 0 live")
        return _EXITS[gctest.LIB.path]

    def failure_outcome(self, al, data, q, lgwin, pattern):
        """Compress `data` with allocator `al`: "NULL state", "BROTLI_FALSE", "coped" (Brotli managed, and the output
        is right), or "WRONG OUTPUT" (reported success with output that doesn't decode to the input: silent
        corruption). Anything left allocated, or freed that wasn't, is appended."""
        state = self.L.DN9_BRT_v1_1_0_BrotliEncoderCreateInstance(*al.args())
        if not state:
            key = "NULL state"
        else:
            e = B.Encoder.__new__(B.Encoder)
            e.api, e.allocator, e.state = self.z, al, state
            try:
                e.set(B.QUALITY, q)
                e.set(B.LGWIN, lgwin)
                if pattern == "one FINISH":     # the call BrotliEncoderCompress makes
                    e.set(B.SIZE_HINT, len(data))
                    ok, got, _, _ = e.call(B.FINISH, data, B.max_compressed_size(len(data)))
                    ok = ok and not e.has_more_output()
                else:
                    ok, got = e.compress(data, 1 << 15)
            finally:
                e.close()
            key = "BROTLI_FALSE" if not ok else (
                "coped" if self.z.decompress(got, len(data))[1] == data else "WRONG OUTPUT")
        if al.live or al.bad_opaque or al.unknown_frees:
            key += " (leaked %d, bad opaque %d, unknown frees %d)" % (len(al.live), al.bad_opaque, al.unknown_frees)
        return key

    def test_encoder_allocation_failure(self):
        """A failed encoder allocation must be an error the caller sees: not the end of the process, and never a
        reported success with wrong output. A program that compresses many files has to be able to report the one
        that failed and go on with the next.

        Brotli 1.1.0 defaults to BROTLI_ENCODER_EXIT_ON_OOM (memory.h:22-25), where BrotliAllocate calls
        exit(EXIT_FAILURE) (memory.c:53-56). GrindCore builds it with BROTLI_ENCODER_CLEANUP_ON_OOM
        (brotli_v1_1_0.cmake) and adds the encode.c checks that mode lacked (other-codecs.md 4.3.1). There the call
        returns BROTLI_FALSE, and DestroyInstance frees everything the encoder allocated (BrotliWipeOutMemoryManager).

        In this process, so the leak checker sees it, every allocation of a compression fails in turn:
          - from that request on, at seven quality and window settings (30 KB, in 32 KB PROCESS calls then FINISH);
          - just that one request, at four settings, on 100 KB, both in pieces and in the one FINISH call
            BrotliEncoderCompress makes. A one-off failure is the case a missing check hides behind.
        Each must give a NULL state or BROTLI_FALSE with every block freed, or correct output. Afterwards the same
        process must compress normally."""
        if self.exits_on_oom():
            known(self, "brotli-exit-on-oom")
        runs = [("from n on", 30000, q, w, "pieces") for q, w in
                ((0, 16), (1, 22), (2, 22), (5, 22), (9, 24), (10, 22), (11, 24))]
        runs += [("only n", 100000, q, w, pattern) for q, w in ((1, 22), (2, 22), (5, 22), (11, 22))
                 for pattern in ("pieces", "one FINISH")]
        outcomes, attempts = {}, 0
        for mode, size, q, lgwin, pattern in runs:
            data = sample.mixed(size, seed=18)
            full = B.Allocator()
            self.same(self.failure_outcome(full, data, q, lgwin, pattern), "coped", "no failures injected")
            for n in range(1, full.requests + 1):
                key = self.failure_outcome(B.Allocator(fail_at=n, only=mode == "only n"), data, q, lgwin, pattern)
                outcomes.setdefault(mode, {})
                outcomes[mode][key] = outcomes[mode].get(key, 0) + 1
                attempts += 1
                if key.startswith("WRONG"):
                    print("  q%d w%d %s, %s %d: %s" % (q, lgwin, pattern, mode, n, key))
        print("  encoder allocation failure, %d attempts: %s" % (attempts, json.dumps(outcomes, sort_keys=True)))
        self.same(sorted(set(k for m in outcomes.values() for k in m) - {"NULL state", "BROTLI_FALSE", "coped"}), [])
        # The process carries on: the next "file" compresses normally, one-shot and streamed.
        data = sample.mixed(30000, seed=18)
        ok, out, _ = self.z.compress(data, 11, 22)
        self.same((ok, self.z.decompress(out, len(data))[1]), (1, data), "one-shot after the failures")
        e = self.z.encoder({B.QUALITY: 9})
        try:
            ok, out = e.compress(data)
        finally:
            e.close()
        self.same((ok, self.z.decompress(out, len(data))[1]), (True, data), "streamed after the failures")

    def test_failed_ring_buffer_allocation_is_reported(self):
        """The case that went unreported (other-codecs.md 4.3.1): with CLEANUP_ON_OOM and no check after the ring
        buffer copy (encode.c CopyInputToRingBuffer), a refused ring buffer allocation left the input uncopied but
        counted as consumed. A FINISH call then wrote an empty stream and reported success, which is what
        BrotliEncoderCompress (and so BrotliBlock) sees. Here an allocator refuses every request of 4 MiB or more, so
        only the ring buffer (2^23 bytes plus a block at window 22) fails, on 300 KB, one FINISH call and in pieces."""
        if self.exits_on_oom():
            known(self, "brotli-exit-on-oom")
        data = sample.mixed(300000, seed=7)
        seen = {}
        for q in (2, 4, 5, 9, 11):
            for pattern in ("one FINISH", "pieces"):
                al = B.Allocator(limit=4 << 20)
                key = self.failure_outcome(al, data, q, 22, pattern)
                seen["q%d %s" % (q, pattern)] = "%s (%d refused)" % (key, al.refused)
                self.assertGreater(al.refused, 0, "the ring buffer allocation must have been attempted")
        print("  refused ring buffer: %s" % json.dumps(seen, sort_keys=True))
        self.same(sorted(set(v.split(" (")[0] for v in seen.values()) - {"BROTLI_FALSE"}), [])

    def test_decoder_allocation_failure(self):
        """The decoder has no exit-on-OOM mode: a failed allocation is an ERROR result (or a NULL state), never a
        crash or wrong output. Every request number up to the last one a full decode makes, in a child."""
        code = """
            import json
            from gctest import sample, brotli_util as B
            z = B.pal(L)
            data = sample.mixed(150000, seed=19)
            stream = z.compress(data, 11, 24)[1]
            full = B.Allocator()
            d = z.decoder(full)
            assert d.decode(stream, 5000, 3000)[:2] == (B.SUCCESS, data)
            d.close()
            outcomes = {}
            for n in range(1, full.requests + 2):
                al = B.Allocator(fail_at=n)
                state = L.DN9_BRT_v1_1_0_BrotliDecoderCreateInstance(*al.args())
                if not state:
                    outcomes["null state"] = outcomes.get("null state", 0) + 1
                    continue
                d = B.Decoder.__new__(B.Decoder)
                d.api, d.allocator, d.state = z, al, state
                r, out, _ = d.decode(stream, 5000, 3000)
                d.close()
                key = {B.SUCCESS: "success", B.ERROR: "error"}.get(r, "result %d" % r)
                if r == B.SUCCESS and out != data:
                    key = "WRONG OUTPUT"
                if al.live:
                    key += " (leaked %d)" % len(al.live)
                outcomes[key] = outcomes.get(key, 0) + 1
            print(json.dumps({"requests": full.requests, "outcomes": outcomes}))
        """
        rc, out, err = bchild(code, timeout=300)
        self.same(rc, 0, err[-600:])
        got = json.loads(out.strip().splitlines()[-1])
        print("  decoder allocation failure over %d request numbers: %s" % (got["requests"], got["outcomes"]))
        self.assertNotIn("WRONG OUTPUT", got["outcomes"])
        self.assertFalse([k for k in got["outcomes"] if "leaked" in k], got["outcomes"])

    def test_encoder_live_allocations(self):
        """BROTLI_ENCODER_CLEANUP_ON_OOM, which GrindCore builds with, tracks the encoder's allocations in a fixed
        table: 256 slots, at most 128 of them live (memory.c:23-25). Going over is checked only by BROTLI_DCHECK, so
        in a release build it would write past the table. The most blocks the encoder has live at once must stay
        well under that, per quality and window, and on a larger input with a flush."""
        data = sample.mixed(300000, seed=20)
        peak = {}
        cases = [({B.QUALITY: q, B.LGWIN: lgwin}, data) for q in (0, 1, 2, 4, 5, 9, 10, 11) for lgwin in (16, 22, 24)]
        cases.append(({B.QUALITY: 11, B.LGWIN: 24, B.LGBLOCK: 24, B.SIZE_HINT: 1 << 20}, sample.mixed(1 << 20, seed=21)))
        for params, d in cases:
            al = B.Allocator()
            e = self.z.encoder(params, al)
            try:
                self.assertTrue(e.compress(d, 1 << 16, 1 << 16, (100000,))[0])
            finally:
                e.close()
            peak[" ".join("%s=%d" % ({B.QUALITY: "q", B.LGWIN: "w", B.LGBLOCK: "b", B.SIZE_HINT: "hint"}[k], v)
                          for k, v in sorted(params.items()))] = al.max_live
            self.same(len(al.live), 0)
        most = max(peak.values())
        print("  most live encoder blocks: %d of 128 (%s)" % (most, json.dumps(peak, sort_keys=True)))
        self.assertLess(most, 64, "too close to CLEANUP_ON_OOM's 128-slot table")

    # ------------------------------------------------------------------ arguments

    def test_null_arguments(self):
        """Brotli dereferences its state, size and cursor pointers without checking them. The PAL checks them
        (other-codecs.md 4.3.1, with the zstd PAL's conventions): a bad argument gets Brotli's own failure value, 0
        (BROTLI_FALSE or BROTLI_DECODER_RESULT_ERROR), and nothing is touched. The Destroy functions accept NULL, as
        Brotli documents. Each probe runs in a child; libraries whose PAL has no checks crash on some of them (a
        known defect)."""
        prelude = """
            B = ctypes.create_string_buffer(64)
            A = ctypes.addressof(B)
            ctypes.memmove(A, b"\\x06", 1)   # the 1-byte empty stream
            def call(fn, state, n_in, in_cursor, n_out, out_cursor, null=()):
                a_in, a_out = ctypes.c_size_t(n_in), ctypes.c_size_t(n_out)
                i, o = ctypes.c_void_p(in_cursor), ctypes.c_void_p(out_cursor)
                args = [None if "available_in" in null else ctypes.byref(a_in),
                        None if "next_in" in null else ctypes.byref(i),
                        None if "available_out" in null else ctypes.byref(a_out),
                        None if "next_out" in null else ctypes.byref(o), None]
                return fn(state, *args)
            E = lambda *a, **k: call(lambda s, *r: L.DN9_BRT_v1_1_0_BrotliEncoderCompressStream(s, 0, *r), *a, **k)
            D = lambda *a, **k: call(L.DN9_BRT_v1_1_0_BrotliDecoderDecompressStream, *a, **k)
            enc = L.DN9_BRT_v1_1_0_BrotliEncoderCreateInstance(None, None, None)
            dec = L.DN9_BRT_v1_1_0_BrotliDecoderCreateInstance(None, None, None)
            n = ctypes.c_size_t(64)
            f = lambda name: getattr(L, "DN9_BRT_v1_1_0_" + name)
        """
        probes = {  # name: (code, what a checking PAL gives)
            "EncoderCompress: encoded_size NULL": ("print(f('BrotliEncoderCompress')(5, 22, 0, 3, A, None, A))", "0"),
            "EncoderCompress: input NULL, size 3": (
                "print(f('BrotliEncoderCompress')(5, 22, 0, 3, None, ctypes.byref(n), A + 8), n.value)", "0 64"),
            "EncoderCompress: output NULL, room 64": (
                "print(f('BrotliEncoderCompress')(5, 22, 0, 3, A, ctypes.byref(n), None), n.value)", "0 64"),
            "DecoderDecompress: decoded_size NULL": ("print(f('BrotliDecoderDecompress')(1, A, None, A + 8))", "0"),
            "DecoderDecompress: input NULL, size 5": (
                "print(f('BrotliDecoderDecompress')(5, None, ctypes.byref(n), A + 8), n.value)", "0 64"),
            "DecoderDecompress: output NULL, room 64": (
                "print(f('BrotliDecoderDecompress')(1, A, ctypes.byref(n), None), n.value)", "0 64"),
            "DecoderDecompressStream: state NULL": ("print(D(None, 1, A, 8, A + 8))", "0"),
            "DecoderDecompressStream: available_in NULL": (
                "print(D(dec, 1, A, 8, A + 8, null=('available_in',)))", "0"),
            "DecoderDecompressStream: next_in NULL": ("print(D(dec, 1, A, 8, A + 8, null=('next_in',)))", "0"),
            "DecoderDecompressStream: input cursor NULL, 5 bytes": ("print(D(dec, 5, None, 8, A + 8))", "0"),
            "DecoderDecompressStream: available_out NULL": (
                "print(D(dec, 1, A, 8, A + 8, null=('available_out',)))", "0"),
            # Brotli itself rejects this one, but records the error in the state, so every later call fails too.
            "DecoderDecompressStream: output cursor NULL, room 8; then a good call": (
                "print(D(dec, 1, A, 8, None), D(dec, 1, A, 8, A + 8))", "0 1"),
            "EncoderCompressStream: state NULL": ("print(E(None, 0, A, 8, A + 8))", "0"),
            "EncoderCompressStream: available_in NULL": (
                "print(E(enc, 0, A, 8, A + 8, null=('available_in',)))", "0"),
            "EncoderCompressStream: next_in NULL": ("print(E(enc, 1, A, 8, A + 8, null=('next_in',)))", "0"),
            "EncoderCompressStream: input cursor NULL, 5 bytes": ("print(E(enc, 5, None, 8, A + 8))", "0"),
            "EncoderCompressStream: available_out NULL": (
                "print(E(enc, 1, A, 8, A + 8, null=('available_out',)))", "0"),
            "EncoderCompressStream: output cursor NULL, room 8": ("print(E(enc, 0, A, 8, None))", "0"),
            "EncoderSetParameter: state NULL": ("print(f('BrotliEncoderSetParameter')(None, 1, 5))", "0"),
            "EncoderHasMoreOutput: state NULL": ("print(f('BrotliEncoderHasMoreOutput')(None))", "0"),
            "DecoderIsFinished: state NULL": ("print(f('BrotliDecoderIsFinished')(None))", "0"),
            "EncoderDestroyInstance: NULL": ("f('BrotliEncoderDestroyInstance')(None); print('returned')", "returned"),
            "DecoderDestroyInstance: NULL": ("f('BrotliDecoderDestroyInstance')(None); print('returned')", "returned"),
            "EncoderCreateInstance: alloc set, free NULL": (
                "from gctest import brotli_util as BU; al = BU.Allocator(); "
                "print(f('BrotliEncoderCreateInstance')(al.args()[0], None, None))", "None"),
        }
        seen, crashed_on = {}, []
        for name, (line, _) in sorted(probes.items()):
            rc, out, err = child(textwrap.dedent(prelude) + line, timeout=60)
            # On Windows, ctypes turns an access violation into OSError, so the child exits 1 with a traceback.
            if rc == 0:
                seen[name] = out.strip().splitlines()[-1] if out.strip() else ""
            else:
                seen[name] = "access violation" if "access violation" in err else "crash (rc %s)" % rc
                crashed_on.append(name)
        width = max(len(k) for k in seen)
        print("  NULL arguments:\n" + "\n".join("    %-*s  %s" % (width, k, v) for k, v in sorted(seen.items())))
        if crashed_on:
            known(self, "brotli-null-args")
        self.same(seen, dict((k, v[1]) for k, v in probes.items()))

    def test_null_buffer_with_size_zero_is_an_empty_buffer(self):
        """.NET pins an empty array as NULL, so a NULL buffer with size 0 must behave as any empty buffer: Brotli's API
        allows it, and the PAL's checks mustn't reject it. On every library."""
        L, P = self.L, "DN9_BRT_v1_1_0_"
        out, n = ctypes.create_string_buffer(64), ctypes.c_size_t(64)
        self.same((getattr(L, P + "BrotliEncoderCompress")(5, 22, 0, 0, None, ctypes.byref(n), out), n.value,
                   out.raw[:1]), (1, 1, b"\x06"), "one-shot compress of NULL, 0")
        src, n = B._Buf(b"\x06"), ctypes.c_size_t(0)
        self.same((getattr(L, P + "BrotliDecoderDecompress")(1, src.addr, ctypes.byref(n), None), n.value),
                  (B.SUCCESS, 0), "one-shot decompress of the empty stream into NULL, 0")
        e = self.z.encoder({B.QUALITY: 5})
        try:
            a_in, a_out = ctypes.c_size_t(0), ctypes.c_size_t(64)
            n_in, n_out = ctypes.c_void_p(None), ctypes.c_void_p(ctypes.addressof(out))
            ok = getattr(L, P + "BrotliEncoderCompressStream")(e.state, B.FINISH, ctypes.byref(a_in),
                                                                ctypes.byref(n_in), ctypes.byref(a_out),
                                                                ctypes.byref(n_out), None)
            got = (bool(ok), out.raw[:64 - a_out.value])
        finally:
            e.close()
        e = self.z.encoder({B.QUALITY: 5})
        try:
            want = e.compress(b"")
        finally:
            e.close()
        self.same(got, want, "stream compress of NULL, 0 then FINISH")
        d = self.z.decoder()
        try:
            a_in, a_out = ctypes.c_size_t(0), ctypes.c_size_t(64)
            n_in, n_out = ctypes.c_void_p(None), ctypes.c_void_p(ctypes.addressof(out))
            r1 = getattr(L, P + "BrotliDecoderDecompressStream")(d.state, ctypes.byref(a_in), ctypes.byref(n_in),
                                                                  ctypes.byref(a_out), ctypes.byref(n_out), None)
            a_in, a_out = ctypes.c_size_t(1), ctypes.c_size_t(0)
            n_in = ctypes.c_void_p(src.addr)
            r2 = getattr(L, P + "BrotliDecoderDecompressStream")(d.state, ctypes.byref(a_in), ctypes.byref(n_in),
                                                                  ctypes.byref(a_out), None, None)
            self.same((r1, r2, a_in.value, d.finished()), (B.NEEDS_MORE_INPUT, B.SUCCESS, 0, 1),
                      "stream decode: NULL input with 0 bytes, then the empty stream with no output room")
        finally:
            d.close()
