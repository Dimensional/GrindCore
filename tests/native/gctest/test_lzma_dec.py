"""7-Zip 25.01's LZMA and LZMA2 decoders: GrindCore's 19 decoder exports (SZ_Lzma_v25_01_Dec_*, SZ_Lzma2_v25_01_Dec_*,
SZ_Lzma2_v25_01_Decode), which pass straight through to 7-Zip (audit/lzma.md 3.6).

The decoder sources are official. win-x64 links 7-Zip's assembler decoder (LzmaDecOpt.asm) and every other RID the C
decoder, so the same tests check both. Oracles:
  - Python's lzma (liblzma) encodes the interoperability streams (.lzma and raw LZMA2, all lc/lp/pb it allows);
  - GrindCore's own encoders, byte-identical to official 7-Zip's (lzma.md 3.4), make what liblzma can't: no end mark,
    lc + lp > 4, LZMA2 blocks;
  - official 7-Zip, from $GC_REF_7ZIP (ref/build_7zip_ref.py): the C decoder, and the assembler decoder where it was
    built (lib7zref-asm). GrindCore must give the same result code, status, output and input consumed for every
    corrupt input.
Corrupt-input and guard-page runs are in child processes, so a crash is a reported finding."""
import ctypes
import json
import os
import struct
import sys
import textwrap
import unittest

import gctest
from gctest import sample
from gctest import lzmadec_util as D
from gctest.test_fl2 import faulted
from gctest.test_hashes import child

PROPS = [(3, 0, 2, 1 << 20), (0, 0, 0, 4096), (4, 0, 4, 1 << 16), (0, 4, 0, 1 << 16), (1, 3, 1, 65536), (2, 2, 3, 1 << 23)]


def corpus():
    return [("empty", b""), ("1 byte", b"x"), ("text 1000", sample.text(1000)), ("text 50000", sample.text(50000)),
            ("noise 20000", sample.noise(20000)), ("runs 50000", sample.runs(50000)), ("mixed 200000", sample.mixed(200000))]


def short(r):
    return "%s %s, %d bytes out, %d consumed%s" % (D.RC.get(r.rc, r.rc), D.STATUS.get(r.status, r.status), len(r.out),
                                                  r.used, ", OVERRUN" if r.overrun else "")


class LzmaDecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = gctest.LIB
        cls.A = D.Api(cls.L)
        cls.refs, cls.ref_errors = D.references(cls.L)

    def need_lzma(self):
        if D.lzma is None:
            self.skipTest("this Python has no lzma module")

    def decode_everywhere(self, kind, props, stream, data, end_mark=True, label=""):
        """Every entry point, several step sizes: the output must be `data` and all of `stream` consumed."""
        n = len(data)
        want = D.FINISHED_WITH_MARK if end_mark else D.MAYBE_FINISHED_WITHOUT_MARK
        r = D.one_shot(self.A, kind, props, stream, n, D.FINISH_END)
        self.assertEqual((r.rc, r.status, r.used, r.overrun), (0, want, len(stream), False), label + " one-shot: " + short(r))
        self.assertTrue(r.out == data, label + " one-shot output")
        if end_mark:
            r = D.one_shot(self.A, kind, props, stream, n + 100, D.FINISH_ANY)
            self.assertEqual((r.rc, r.status, r.used), (0, want, len(stream)), label + " one-shot, room to spare: " + short(r))
            self.assertTrue(r.out == data)
        steps = [(1 << 20, 1 << 20), (333, 777)] + ([(7, 13)] if n <= 60000 else []) + ([(1, 1)] if n <= 1000 else [])
        for in_step, out_step in steps:
            for mode in ("buf", "dic"):
                r = D.stream(self.A, kind, props, stream, in_step, out_step, D.FINISH_ANY, mode,
                             size=None if end_mark else n)
                self.assertEqual((r.rc, r.used, r.overrun), (0, len(stream), False),
                                 "%s %s %d/%d: %s" % (label, mode, in_step, out_step, short(r)))
                self.assertTrue(r.out == data, "%s %s %d/%d output" % (label, mode, in_step, out_step))
                self.assertEqual(r.status, want, "%s %s %d/%d: %s" % (label, mode, in_step, out_step, short(r)))

    # ------------------------------------------------------------------ interoperability

    def test_lzma_from_liblzma(self):
        """liblzma's .lzma streams (with an end mark), every lc/lp/pb combination liblzma allows (lc + lp <= 4) and
        several dictionaries, decoded by every LZMA entry point: LzmaDecode, DecodeToBuf, DecodeToDic."""
        self.need_lzma()
        for name, data in corpus():
            for lc, lp, pb, dic in PROPS:
                props, stream = D.xz_lzma(data, lc, lp, pb, dic)
                with self.subTest(data=name, lc=lc, lp=lp, pb=pb, dict=dic):
                    self.decode_everywhere("lzma", props, stream, data, label="%s lc%d lp%d pb%d" % (name, lc, lp, pb))

    def test_lzma_without_end_mark_and_wide_contexts(self):
        """What liblzma can't write: no end mark (decoded with its known size: MAYBE_FINISHED_WITHOUT_MARK), and
        lc + lp > 4 up to lc 8, lp 4, pb 4 (7-Zip's LZMA allows them; LZMA2 doesn't)."""
        for name, data in corpus()[:6]:
            for lc, lp, pb in ((3, 0, 2), (8, 4, 4), (8, 0, 0), (0, 4, 4), (5, 3, 1)):
                for end_mark in (0, 1):
                    props, stream = D.gc_lzma(self.L, data, lc, lp, pb, 1 << 16, end_mark=end_mark)
                    with self.subTest(data=name, lc=lc, lp=lp, pb=pb, end_mark=end_mark):
                        self.decode_everywhere("lzma", props, stream, data, bool(end_mark),
                                               "%s lc%d lp%d pb%d em%d" % (name, lc, lp, pb, end_mark))

    def test_lzma2_from_liblzma(self):
        """liblzma's raw LZMA2 (lc + lp <= 4), presets 0, 6 and 9, several dictionaries: compressed chunks, and
        uncompressed ones for the noise."""
        self.need_lzma()
        for name, data in corpus():
            for lc, lp, pb, dic in PROPS[:5]:
                for preset in (0, 6, 9):
                    prop, stream = D.xz_lzma2(data, lc, lp, pb, dic, preset)
                    with self.subTest(data=name, lc=lc, lp=lp, pb=pb, dict=dic, preset=preset):
                        self.decode_everywhere("lzma2", prop, stream, data, label="%s p%d" % (name, preset))

    def test_lzma2_blocks_resets_and_uncompressed_chunks(self):
        """Dictionary resets inside a stream (7-Zip's block encoder, and two liblzma streams joined), and streams of
        uncompressed chunks only."""
        data = sample.mixed(400000, seed=8)
        prop, stream = D.gc_lzma2_blocks(self.L, data, level=3, block=65536, threads=2)
        resets = [c for c in D.lzma2_chunks(stream) if c[1] >= 0xE0 or c[1] == 1]
        self.assertGreater(len(resets), 4, "the block encoder wrote no dictionary resets")
        self.decode_everywhere("lzma2", prop, stream, data, label="blocks")
        noise = sample.noise(150000, seed=9)
        self.decode_everywhere("lzma2", 0, D.uncompressed_lzma2(noise), noise, label="uncompressed")
        if D.lzma is not None:
            a, b = sample.text(70000, seed=1), sample.runs(90000, seed=2)
            pa, sa = D.xz_lzma2(a, dict_bytes=1 << 16)
            pb_, sb = D.xz_lzma2(b, dict_bytes=1 << 18)
            self.decode_everywhere("lzma2", max(pa, pb_), sa[:-1] + sb, a + b, label="joined")

    # ------------------------------------------------------------------ the parser

    def test_lzma2_parse_finds_every_block_and_chunk(self):
        """Lzma2Dec_Parse (the multithreaded decoder's chunk walker, exported but unused by GrindCore.net) against an
        independent chunk parser: NEW_BLOCK after the control byte of each chunk that resets the dictionary, NEW_CHUNK
        after each chunk header, FINISHED_WITH_MARK at the end byte."""
        streams = [("blocks",) + D.gc_lzma2_blocks(self.L, sample.mixed(300000, seed=3), level=3, block=50000, threads=2),
                   ("uncompressed", 0, D.uncompressed_lzma2(sample.noise(100000, seed=4)))]
        apis = [("GrindCore", self.A)] + self.refs
        for name, prop, stream in streams:
            want = []
            for off, c, unpack, pack, p in D.lzma2_chunks(stream):
                if c == 0:
                    want.append((D.FINISHED_WITH_MARK, off + 1))
                    break
                if c == 1 or c >= 0xE0:
                    want.append((D.PARSE_NEW_BLOCK, off + 1))
                want.append((D.PARSE_NEW_CHUNK, off + (3 if c < 0x80 else 6 if c >= 0xC0 else 5)))
            for an, a in apis:
                with self.subTest(stream=name, decoder=an):
                    d = a.new("lzma2")
                    self.assertEqual(a.allocate("lzma2", d, prop, probs_only=True), 0)
                    a.init("lzma2", d)
                    pos, got = 0, []
                    for _ in range(len(want) + 10):
                        st, used = a.parse(d, 1 << 30, stream[pos:], len(stream) - pos, 0)
                        pos += used
                        got.append((st, pos))
                        if st in (D.FINISHED_WITH_MARK, D.NOT_SPECIFIED):
                            break
                    a.free("lzma2", d)
                    self.assertEqual(got, want)

    # ------------------------------------------------------------------ status, finish modes, trailing data

    def status_cases(self):
        data = sample.text(30000, seed=5)
        pe, se = D.gc_lzma(self.L, data, end_mark=1)
        pn, sn = D.gc_lzma(self.L, data, end_mark=0)
        p2, s2 = D.gc_lzma2_blocks(self.L, data, level=5, block=1 << 30, threads=1)
        n = len(data)
        E, A_ = D.FINISH_END, D.FINISH_ANY
        # (label, kind, props, input, capacity, finish, expected (rc, status, output length, consumed))
        return data, [
            ("LZMA end mark, exact size, END", "lzma", pe, se, n, E, (0, D.FINISHED_WITH_MARK, n, len(se))),
            ("LZMA end mark, room, ANY", "lzma", pe, se, n + 50, A_, (0, D.FINISHED_WITH_MARK, n, len(se))),
            ("LZMA end mark, short output, ANY", "lzma", pe, se, n - 1, A_, (0, D.NOT_FINISHED, n - 1, None)),
            ("LZMA end mark, short output, END", "lzma", pe, se, n - 1, E, (1, D.NOT_FINISHED, n - 1, None)),
            ("LZMA end mark, truncated", "lzma", pe, se[:-3], n + 50, A_, (6, D.NEEDS_MORE_INPUT, None, len(se) - 3)),
            ("LZMA no end mark, exact size, END", "lzma", pn, sn, n, E, (0, D.MAYBE_FINISHED_WITHOUT_MARK, n, len(sn))),
            ("LZMA no end mark, exact size, ANY", "lzma", pn, sn, n, A_, (0, D.MAYBE_FINISHED_WITHOUT_MARK, n, len(sn))),
            ("LZMA, 4 bytes of input", "lzma", pe, se[:4], n, A_, (6, D.NOT_SPECIFIED, 0, 0)),
            ("LZMA2, exact size, END", "lzma2", p2, s2, n, E, (0, D.FINISHED_WITH_MARK, n, len(s2))),
            ("LZMA2, room, ANY", "lzma2", p2, s2, n + 50, A_, (0, D.FINISHED_WITH_MARK, n, len(s2))),
            ("LZMA2, short output, ANY", "lzma2", p2, s2, n - 1, A_, (0, D.NOT_FINISHED, n - 1, None)),
            ("LZMA2, short output, END", "lzma2", p2, s2, n - 1, E, (1, D.NOT_SPECIFIED, n - 1, None)),
            ("LZMA2, end byte missing", "lzma2", p2, s2[:-1], n + 50, A_, (6, D.NEEDS_MORE_INPUT, n, len(s2) - 1)),
            ("LZMA2, empty input", "lzma2", p2, b"", n, A_, (6, D.NEEDS_MORE_INPUT, 0, 0)),
            ("LZMA end mark + trailing data, ANY", "lzma", pe, se + b"\xEE" * 999, n + 50, A_, (0, D.FINISHED_WITH_MARK, n, len(se))),
            ("LZMA2 + trailing data, ANY", "lzma2", p2, s2 + b"\x00\xEE" * 99, n + 50, A_, (0, D.FINISHED_WITH_MARK, n, len(s2))),
        ]

    def test_status_finish_modes_and_trailing_data(self):
        """The documented results of LzmaDecode/Lzma2Decode (LzmaDec.h:170-237): output limits with FINISH_ANY and
        FINISH_END (strict mode: SZ_ERROR_DATA), truncation (SZ_ERROR_INPUT_EOF), streams without an end mark, and
        trailing data, which must be left unread so a container can carry on after the stream. Also the same calls
        on official 7-Zip, where present."""
        data, cases = self.status_cases()
        for label, kind, props, src, cap, fin, want in cases:
            with self.subTest(case=label):
                r = D.one_shot(self.A, kind, props, src, cap, fin)
                got = (r.rc, r.status, len(r.out), r.used)
                self.assertEqual(tuple(g if w is not None else None for g, w in zip(got, want)), want, short(r))
                self.assertTrue(r.out == data[:len(r.out)], "output isn't a prefix of the data")
                self.assertFalse(r.overrun)
                for an, ref in self.refs:
                    self.assertEqual(r[:5], D.one_shot(ref, kind, props, src, cap, fin)[:5], "differs from " + an)

    def test_streaming_stops_at_the_end(self):
        """DecodeToBuf in steps: after FINISHED_WITH_MARK nothing more is consumed, so trailing data stays unread."""
        data = sample.text(30000, seed=5)
        for kind, (props, s) in (("lzma", D.gc_lzma(self.L, data, end_mark=1)),
                                 ("lzma2", D.gc_lzma2_blocks(self.L, data, level=5, block=1 << 30, threads=1))):
            for in_step in (1, 100, 1 << 20):
                with self.subTest(kind=kind, in_step=in_step):
                    r = D.stream(self.A, kind, props, s + b"\xEE" * 5000, in_step, 4096)
                    self.assertEqual((r.rc, r.status, r.used), (0, D.FINISHED_WITH_MARK, len(s)), short(r))
                    self.assertTrue(r.out == data)

    # ------------------------------------------------------------------ properties and allocation

    def test_lzma_properties(self):
        """LzmaProps_Decode: fewer than 5 bytes and a first byte >= 225 are SZ_ERROR_UNSUPPORTED for Allocate,
        AllocateProbs and LzmaDecode; a dictionary below 4 KiB counts as 4 KiB; the dictionary buffer is rounded
        as LzmaDec_Allocate rounds it (LzmaDec.c:1316-1323)."""
        stream = D.gc_lzma(self.L, b"abc", end_mark=1)[1]
        for props in [b"", b"\x5d", b"\x5d\0\0\x01", bytes([225, 0, 0, 1, 0]), bytes([255, 0, 0, 1, 0])]:
            with self.subTest(props=props.hex()):
                d = self.A.new("lzma")
                self.assertEqual(self.A.allocate("lzma", d, props), D.SZ_ERROR_UNSUPPORTED)
                self.assertEqual(self.A.allocate("lzma", d, props, probs_only=True), D.SZ_ERROR_UNSUPPORTED)
                self.A.free("lzma", d)
                self.assertEqual(D.one_shot(self.A, "lzma", props, stream, 10).rc, D.SZ_ERROR_UNSUPPORTED)
        for dic in (0, 1, 4095, 4096, 4097, (1 << 22) - 1, 1 << 22, (1 << 22) + 1, (1 << 30) + 1):
            with self.subTest(dict=dic):
                d = self.A.new("lzma")
                rc = self.A.allocate("lzma", d, D.lzma_props_bytes(3, 0, 2, dic))
                eff = max(dic, 4096)
                mask = (1 << 22) - 1 if eff >= 1 << 30 else (1 << 20) - 1 if eff >= 1 << 22 else (1 << 12) - 1
                want = (eff + mask) & ~mask
                got = (rc, d.dicBufSize, d.prop.dicSize) if rc == 0 else (rc,)
                self.A.free("lzma", d)
                if dic >= 1 << 30:   # a 1 GiB+ dictionary: either allocated as rounded, or SZ_ERROR_MEM, cleanly
                    self.assertIn(got[0], (0, D.SZ_ERROR_MEM))
                    if got[0] == 0:
                        self.assertEqual(got[1:], (want, eff))
                    continue
                self.assertEqual(got, (0, want, eff))

    def test_lzma2_properties(self):
        """LZMA2's dictionary byte: 0-40 accepted (40 = 4 GiB - 1), 41-255 SZ_ERROR_UNSUPPORTED. Allocate sizes the
        dictionary from it; AllocateProbs allocates none (and Lzma2Decode uses the caller's buffer)."""
        for prop in (41, 42, 100, 255):
            d = self.A.new("lzma2")
            self.assertEqual(self.A.allocate("lzma2", d, prop), D.SZ_ERROR_UNSUPPORTED)
            self.assertEqual(self.A.allocate("lzma2", d, prop, probs_only=True), D.SZ_ERROR_UNSUPPORTED)
            self.A.free("lzma2", d)
            self.assertEqual(D.one_shot(self.A, "lzma2", prop, b"\x00", 10).rc, D.SZ_ERROR_UNSUPPORTED)
        for prop in range(0, 41):
            d = self.A.new("lzma2")
            rc = self.A.allocate("lzma2", d, prop, probs_only=True)
            self.assertEqual((rc, d.decoder.prop.dicSize, d.decoder.prop.lc, d.decoder.dic), (0, D.dict_size(prop), 4, None))
            self.A.free("lzma2", d)
            if D.dict_size(prop) <= 1 << 26:
                d = self.A.new("lzma2")
                self.assertEqual(self.A.allocate("lzma2", d, prop), 0)
                self.assertGreaterEqual(d.decoder.dicBufSize, D.dict_size(prop))
                self.A.free("lzma2", d)
        self.assertEqual(D.one_shot(self.A, "lzma2", 40, b"\x00", 10)[:2], (0, D.FINISHED_WITH_MARK))

    def test_lzma2_chunk_rules(self):
        """Lzma2Dec_UpdateState: the first chunk must reset the dictionary (control 1 or >= 0xE0); after an
        uncompressed reset an LZMA chunk must set new properties (>= 0xC0); control bytes 3-0x7F are invalid; a
        chunk's properties byte must be < 225 with lc + lp <= 4. Every rejected case is SZ_ERROR_DATA, on official
        7-Zip too."""
        data = sample.text(3000, seed=6)
        prop, good = D.gc_lzma2_blocks(self.L, data, level=5, block=1 << 30, threads=1)
        (o, c, unpack, pack, p), end = D.lzma2_chunks(good)[:2]
        body = good[6:6 + pack]
        hdr = lambda ctl, props=None: bytes([ctl | ((unpack - 1) >> 16)]) + struct.pack(">HH", (unpack - 1) & 0xFFFF, pack - 1) + \
            (bytes([props]) if props is not None else b"")
        u = lambda ctl, raw: bytes([ctl]) + struct.pack(">H", len(raw) - 1) + raw
        cases = [
            ("valid", good, 0),
            ("first chunk uncompressed without reset (2)", u(2, data[:100]) + b"\x00", 1),
            ("first chunk LZMA without reset (0x80)", hdr(0x80) + body + b"\x00", 1),
            ("first chunk LZMA state reset only (0xA0)", hdr(0xA0) + body + b"\x00", 1),
            ("first chunk LZMA new props, no dict reset (0xC0)", hdr(0xC0, p) + body + b"\x00", 1),
            ("uncompressed reset, then LZMA without new props (0xA0)", u(1, data[:100]) + hdr(0xA0) + body + b"\x00", 1),
            ("uncompressed reset, then LZMA with new props (0xC0)", u(1, data[:100]) + hdr(0xC0, p) + body + b"\x00", None),
            ("control byte 3", bytes([3]) + good[1:], 1),
            ("control byte 0x7F", bytes([0x7F]) + good[1:], 1),
            ("chunk props byte 225", hdr(0xE0, 225) + body + b"\x00", 1),
            ("chunk props lc 4 lp 1", hdr(0xE0, (2 * 5 + 1) * 9 + 4) + body + b"\x00", 1),
            ("chunk props lc 0 lp 4", hdr(0xE0, (2 * 5 + 4) * 9 + 0) + body + b"\x00", None),
        ]
        for label, s, want_rc in cases:
            with self.subTest(case=label):
                r = D.one_shot(self.A, "lzma2", prop, s, len(data) + 200, D.FINISH_ANY)
                if want_rc is not None:
                    self.assertEqual(r.rc, want_rc, short(r))
                    if want_rc == 0:
                        self.assertTrue(r.out == data)
                for an, ref in self.refs:
                    self.assertEqual(r[:5], D.one_shot(ref, "lzma2", prop, s, len(data) + 200, D.FINISH_ANY)[:5], an)

    def test_decoder_reuse_and_free(self):
        """One decoder for several streams (Init between them); Allocate again with other properties (the buffers are
        reallocated) and with the same ones (kept); FreeProbs then Free; Free twice; Free of a decoder never
        allocated."""
        a, b = sample.text(40000, seed=1), sample.runs(60000, seed=2)
        pa, sa = D.gc_lzma(self.L, a, dict_bytes=1 << 16, end_mark=1)
        pb_, sb = D.gc_lzma(self.L, b, lc=0, lp=2, pb=0, dict_bytes=1 << 20, end_mark=1)
        d = self.A.new("lzma")
        out = ctypes.create_string_buffer(1 << 17)
        for props, s, want in ((pa, sa, a), (pa, sa, a), (pb_, sb, b), (pa, sa, a)):
            before = (d.dic, d.dicBufSize, d.probs, d.numProbs)
            self.assertEqual(self.A.allocate("lzma", d, props), 0)
            if props == pa and before[1] == d.dicBufSize:
                self.assertEqual(before[0], d.dic, "same dictionary size, but the buffer was reallocated")
            self.A.init("lzma", d)
            rc, w, u, st = self.A.to_buf("lzma", d, out, len(out), s, len(s), D.FINISH_ANY)
            self.assertEqual((rc, st, u), (0, D.FINISHED_WITH_MARK, len(s)))
            self.assertTrue(out.raw[:w] == want)
        self.A.free("lzma", d, probs_only=True)
        self.assertIsNone(d.probs)
        self.A.free("lzma", d)
        self.A.free("lzma", d)
        self.assertEqual((d.dic, d.probs), (None, None))
        for kind in ("lzma", "lzma2"):
            self.A.free(kind, self.A.new(kind))
        d2 = self.A.new("lzma2")
        p2, s2 = D.gc_lzma2_blocks(self.L, a, level=5, block=1 << 30, threads=1)
        for _ in range(3):
            self.assertEqual(self.A.allocate("lzma2", d2, p2), 0)
            self.A.init("lzma2", d2)
            rc, w, u, st = self.A.to_buf("lzma2", d2, out, len(out), s2, len(s2), D.FINISH_ANY)
            self.assertEqual((rc, st, out.raw[:w] == a), (0, D.FINISHED_WITH_MARK, True))
        self.A.free("lzma2", d2)

    def test_allocation_failure(self):
        """A dictionary that can't be allocated is SZ_ERROR_MEM, with nothing left allocated (LzmaDec_Allocate frees
        the probabilities too). On 32-bit, 4 GiB - 1 can't be; on 64-bit Linux and macOS it runs in a child with a 1 GiB
        address-space limit (RLIMIT_AS); elsewhere it's skipped, so as not to commit 4 GiB."""
        code = textwrap.dedent("""
            from gctest import lzmadec_util as D
            A = D.Api(L)
            for kind, props in (("lzma", D.lzma_props_bytes(3, 0, 2, 0xFFFFFFFF)), ("lzma2", 40)):
                d = A.new(kind)
                rc = A.allocate(kind, d, props)
                inner = d if kind == "lzma" else d.decoder
                print(kind, rc, inner.dic is None, inner.probs is None)
                A.free(kind, d)
        """)
        if D.IS_32:
            prefix = ""
        elif sys.platform.startswith("linux"):
            prefix = "import resource\nresource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))\n"
        else:
            self.skipTest("64-bit %s: no address-space limit to make a 4 GiB allocation fail" % sys.platform)
        rc, out, err = child(prefix + code, timeout=120)
        self.assertEqual(rc, 0, err[-2000:])
        self.assertEqual(out.split(), ["lzma", "2", "True", "True", "lzma2", "2", "True", "True"])

    # ------------------------------------------------------------------ corrupt input, in children

    def test_corrupt_input_matches_official(self):
        """The corrupt-input differential (lzmadec_util.sweep): every single-bit flip, every truncation and random
        bodies of six streams, one-shot with FINISH_ANY and FINISH_END and partly streamed, through GrindCore and
        official 7-Zip's decoders. Same result code, status, output and input consumed everywhere, and nothing
        written past the output. On win-x64 GrindCore's assembler decoder is compared with official 7-Zip's
        assembler decoder and with its C decoder."""
        if not self.refs:
            self.skipTest("no official 7-Zip: " + "; ".join(self.ref_errors))
        code = """
            import json
            from gctest import lzmadec_util as D
            refs, _ = D.references(L)
            print(json.dumps(D.sweep(L, [("GrindCore", D.Api(L))] + refs)))
        """
        rc, out, err = child(code, timeout=3600)
        self.assertFalse(faulted(rc, err), "crashed: rc %s %s" % (rc, err[-2000:]))
        self.assertEqual(rc, 0, err[-2000:])
        rep = json.loads(out.strip().splitlines()[-1])
        for name, r in sorted(rep.items()):
            print("  %-28s %5d mutations, %6d decodes, differences %s, overruns %d, SZ_ERROR_FAIL %d; %s" % (
                name, r["mutations"], r["decodes"], r["differences"] or "none", r["overruns"], r["sz_error_fail"],
                ", ".join("%s: %d" % kv for kv in sorted(r["outcomes"].items()))))
            with self.subTest(stream=name):
                self.assertEqual(r["differences"], {}, r["examples"])
                self.assertEqual(r["overruns"], 0)

    def test_no_reads_or_writes_past_the_buffers(self):
        """Guard pages (lzmadec_util.guard_sweep): every truncation and 150 random flips of each sweep stream, with
        the input ending at a no-access page (one-shot, and every streamed call's input), and with the output ending
        at one (the exact size and half of it). Any read past the input or write past the output faults."""
        code = """
            from gctest import lzmadec_util as D
            print(D.guard_sweep(L, D.Api(L), flips=150))
        """
        rc, out, err = child(code, timeout=3600)
        self.assertFalse(faulted(rc, err), "a guard page was touched: rc %s %s" % (rc, err[-2000:]))
        self.assertEqual(rc, 0, err[-2000:])
        print("  %s guarded decodes, no fault" % out.strip().splitlines()[-1])


if __name__ == "__main__":
    unittest.main()
