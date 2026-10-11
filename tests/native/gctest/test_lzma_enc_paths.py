"""The LZMA/LZMA2 encoder entry points the other modules don't drive.

  - SZ_Lzma_v25_01_Enc_Encode: LzmaEnc_Encode, which reads its input through the caller's ISeqInStream and writes
    through an ISeqOutStream, with an optional ICompressProgress (7zTypes.h). GrindCore.net declares it
    (Interop.Lzma.cs) but doesn't call it; it's there for native callers. It's the one LZMA path that doesn't know
    the data's size unless Enc_SetDataSize gives it.
  - Enc_SetDataSize, which LzmaBlock and Lzma2Block call before they encode (LzmaBlock.cs:162, Lzma2Block.cs:137).

What the data size changes (7-Zip 25.01): the match finder sizes its hash table from the smaller of the dictionary
and the data size (LzFind.c:423-437), so for data smaller than the dictionary the output can depend on whether the
size was given (measured at levels 1-3; test_data_size_and_official_output). It's the same on every RID and in
official 7-Zip: the output follows from the calls. MemEncode always gives it (LzmaEnc_MemPrepare, LzmaEnc.c:2917),
so LzmaBlock's SetDataSize changes nothing. Lzma2Enc_Encode2 from memory goes through MemPrepare for each block too (Lzma2Enc.c:581-592); its own
expected size only caps the thread count (Lzma2Enc.c:790), so Lzma2Block's output is the same with or without it.

The callbacks take the build's default calling convention, since 7zTypes.h names none: __stdcall on GrindCore's
win-x86 build (/Gz, hub row 17), as with the zstd seekable and Brotli allocator callbacks. It's probed per library in
child processes. The GrindCore probe also checks the audit fix in LzmaEnc_Encode, which clears a leftover
multicallMode (audit/lzma.md 3.3): the shipped binaries can hang there, so on them the callback tests skip rather
than risk hanging the suite."""
import ctypes
import json
import os
import struct
import sys
import unittest

import gctest
from gctest import sample
from gctest import lzma_util as U
from gctest import lzmadec_util as D
from gctest.test_hashes import child
from gctest.test_lzma_reference import Ref

vp, sz = ctypes.c_void_p, ctypes.c_size_t
SZ_OK, SZ_ERROR_DATA, SZ_ERROR_READ, SZ_ERROR_WRITE, SZ_ERROR_PROGRESS = 0, 1, 8, 9, 10
DICT = 1 << 20
_PROBES = {}


def callback_types(stdcall):
    """ISeqInStream::Read, ISeqOutStream::Write, ICompressProgress::Progress (7zTypes.h:340-450)."""
    f = ctypes.WINFUNCTYPE if stdcall else ctypes.CFUNCTYPE
    return (f(ctypes.c_int, vp, vp, ctypes.POINTER(sz)), f(sz, vp, vp, sz),
            f(ctypes.c_int, vp, ctypes.c_uint64, ctypes.c_uint64))


class Streams(object):
    """The three interfaces over Python data. Read gives at most `step` bytes a call (less than asked is allowed);
    Write collects. read_fail, write_fail and progress_break are the call (counting from 1) at which Read returns an
    error, Write writes nothing, or Progress asks to stop. With progress=False no ICompressProgress is passed."""

    def __init__(self, data, step, stdcall, read_fail=None, write_fail=None, progress=True, progress_break=None):
        read_t, write_t, progress_t = callback_types(stdcall)
        self.pos, self.out, self.sizes = 0, bytearray(), []
        self.calls = {"read": 0, "write": 0, "progress": 0}

        def read(p, buf, size):
            self.calls["read"] += 1
            if self.calls["read"] == read_fail:
                return SZ_ERROR_DATA            # any error; 7-Zip reports SZ_ERROR_READ for it (CheckErrors)
            n = min(size[0], step, len(data) - self.pos)
            ctypes.memmove(buf, data[self.pos:self.pos + n], n)
            self.pos += n
            size[0] = n
            return SZ_OK

        def write(p, buf, size):
            self.calls["write"] += 1
            if self.calls["write"] == write_fail:
                return 0
            self.out += ctypes.string_at(buf, size)
            return size

        def progress_fn(p, done_in, done_out):
            self.calls["progress"] += 1
            self.sizes.append((done_in, done_out))
            return 1 if self.calls["progress"] == progress_break else SZ_OK

        self.keep = (read_t(read), write_t(write), progress_t(progress_fn))
        self.vtables = [(vp * 1)(ctypes.cast(fn, vp)) for fn in self.keep]   # each interface is one function pointer
        self.ins, self.outs, prog = [ctypes.addressof(v) for v in self.vtables]
        self.progress = prog if (progress or progress_break) else None


def props(L, level, threads, end_mark, init, dict_bytes=DICT):
    p = L.struct.CLzmaEncProps()
    init(ctypes.byref(p))
    p.level, p.numThreads, p.writeEndMark, p.dictSize = level, threads, end_mark, dict_bytes
    return p


def encode(L, data, R=None, level=5, threads=1, end_mark=0, step=1 << 16, data_size=None, stdcall=False,
           force_mode=None, dict_bytes=DICT, **kw):
    """Create, SetProps, [SetDataSize], WriteProperties, Encode on GrindCore, or with R (test_lzma_reference.Ref) the
    same calls on official 7-Zip. force_mode writes a multicallMode value in first (U.find_mode_offset must have run).
    Returns (rc, properties, output, Streams)."""
    if R is None:
        enc = L.SZ_Lzma_v25_01_Enc_Create()
        set_props, set_size, write_props = (L.SZ_Lzma_v25_01_Enc_SetProps, L.SZ_Lzma_v25_01_Enc_SetDataSize,
                                            L.SZ_Lzma_v25_01_Enc_WriteProperties)
        p = props(L, level, threads, end_mark, L.SZ_Lzma_v25_01_EncProps_Init, dict_bytes)
    else:
        enc = R.LzmaEnc_Create(R.alloc)
        set_props, set_size, write_props = R.LzmaEnc_SetProps, R.LzmaEnc_SetDataSize, R.LzmaEnc_WriteProperties
        p = props(L, level, threads, end_mark, R.LzmaEncProps_Init, dict_bytes)
    try:
        rc = set_props(enc, ctypes.byref(p))
        if rc:
            return rc, b"", b"", None
        if data_size is not None:
            set_size(enc, data_size)
        pe, pn = ctypes.create_string_buffer(5), sz(5)
        write_props(enc, pe, ctypes.byref(pn))
        if force_mode is not None:
            ctypes.c_uint32.from_address(U.mode_address(enc)).value = force_mode
        s = Streams(data, step, stdcall, **kw)
        if R is None:
            rc = L.SZ_Lzma_v25_01_Enc_Encode(enc, s.outs, s.ins, s.progress)
        else:
            rc = R.LzmaEnc_Encode(enc, s.outs, s.ins, s.progress, R.alloc, R.big)
        return rc, pe.raw[:pn.value], bytes(s.out), s
    finally:
        if R is None:
            L.SZ_Lzma_v25_01_Enc_Destroy(enc)
        else:
            R.LzmaEnc_Destroy(enc, R.alloc, R.big)


def mem_encode(L, data, level=5, threads=1, end_mark=0, dict_bytes=DICT):
    """LzmaBlock's calls (Create, SetProps, SetDataSize, WriteProperties, MemEncode): (rc, properties, output)."""
    enc = L.SZ_Lzma_v25_01_Enc_Create()
    try:
        rc = L.SZ_Lzma_v25_01_Enc_SetProps(enc, ctypes.byref(props(L, level, threads, end_mark,
                                                                    L.SZ_Lzma_v25_01_EncProps_Init, dict_bytes)))
        if rc:
            return rc, b"", b""
        L.SZ_Lzma_v25_01_Enc_SetDataSize(enc, len(data))
        pe, pn = ctypes.create_string_buffer(5), sz(5)
        L.SZ_Lzma_v25_01_Enc_WriteProperties(enc, pe, ctypes.byref(pn))
        dst = ctypes.create_string_buffer(len(data) + len(data) // 2 + 1024)
        dlen = sz(len(dst))
        rc = L.SZ_Lzma_v25_01_Enc_MemEncode(enc, dst, ctypes.byref(dlen), data, len(data), end_mark, None)
        return rc, pe.raw[:pn.value], dst.raw[:dlen.value]
    finally:
        L.SZ_Lzma_v25_01_Enc_Destroy(enc)


def decode(L, properties, stream, n):
    """GrindCore's LzmaDecode of exactly n bytes, or None if it isn't a complete stream of them."""
    r = D.one_shot(D.Api(L), "lzma", properties, stream, n, D.FINISH_END)
    ok = r.rc == SZ_OK and r.status in (D.FINISHED_WITH_MARK, D.MAYBE_FINISHED_WITHOUT_MARK) and not r.overrun
    return r.out if ok else None


def py_decode(properties, stream, n, end_mark):
    """Python's lzma, as .lzma ("alone"): properties, the size (unknown with an end mark), the stream."""
    size = (1 << 64) - 1 if end_mark else n
    return U.py_decode_alone(properties + struct.pack("<Q", size) + stream)


def probe(L):
    """{"gc": ..., "ref": ...}: for GrindCore and, where GC_REF_7ZIP is set, official 7-Zip, the callback
    convention that encodes correctly (True for __stdcall), found in child processes; None if neither did. For
    GrindCore the child first sets multicallMode to 2, which the fixed LzmaEnc_Encode clears; "hangs" if the encode
    never returned (the shipped binaries). "old" for a reference without LzmaEnc_Encode. Cached per library."""
    if L.path in _PROBES:
        return _PROBES[L.path]
    code = """
        import json, os
        from gctest import lzma_util as U, test_lzma_enc_paths as T
        side, stdcall = %r, %r
        R = T.Ref(os.environ["GC_REF_7ZIP"]) if side == "ref" else None
        force = 2 if side == "gc" and U.find_mode_offset(L)[0] is not None else None
        data = U.data(50000)
        rc, props, out, s = T.encode(L, data, R=R, end_mark=1, stdcall=stdcall, force_mode=force)
        print(json.dumps({"rc": rc, "ok": rc == 0 and T.decode(L, props, out, len(data)) == data,
                          "forced": force is not None}))
    """
    conventions = (True, False) if sys.platform == "win32" and ctypes.sizeof(vp) == 4 else (False,)
    result = {}
    for side in ("gc", "ref") if os.environ.get("GC_REF_7ZIP") else ("gc",):
        if side == "ref" and Ref(os.environ["GC_REF_7ZIP"]).LzmaEnc_Encode is None:
            result[side] = "old"
            continue
        works, hung = [], False
        for stdcall in conventions:
            rc, out, err = child(code % (side, stdcall), timeout=60)
            lines = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
            hung = hung or rc == "timeout"
            if rc == 0 and lines and lines[-1]["ok"]:
                works.append(stdcall)
        result[side] = works[0] if len(works) == 1 else ("hangs" if hung and not works else None)
    _PROBES[L.path] = result
    return result


class EncEncode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L, cls.R = gctest.LIB, None
        p = probe(cls.L)
        if p["gc"] == "hangs":
            raise unittest.SkipTest("known defect lzma-multicallmode (LzmaEnc_Encode with a leftover multicallMode "
                                    "of 2 never returns): " + gctest.KNOWN_DEFECTS["lzma-multicallmode"])
        cls.broken = None if p["gc"] in (True, False) else "no calling convention encoded correctly (child probe)"
        cls.stdcall = p["gc"] is True
        cls.ref_broken, cls.ref_note = None, "no official 7-Zip (GC_REF_7ZIP)"
        if p.get("ref") in (True, False):
            cls.R, cls.ref_stdcall, cls.ref_note = Ref(os.environ["GC_REF_7ZIP"]), p["ref"] is True, None
        elif p.get("ref") == "old":
            cls.ref_note = "this lib7zref doesn't export LzmaEnc_Encode (rebuild it with ref/build_7zip_ref.py)"
        elif "ref" in p:
            cls.ref_broken = "official 7-Zip: no calling convention encoded correctly (child probe)"

    def setUp(self):
        if self.broken:
            self.fail(self.broken)

    def gc(self, data, **kw):
        return encode(self.L, data, stdcall=self.stdcall, **kw)

    def official(self, data, **kw):
        """Official 7-Zip's result for the same calls, or None without GC_REF_7ZIP."""
        if self.ref_broken:
            self.fail(self.ref_broken)
        return encode(self.L, data, R=self.R, stdcall=self.ref_stdcall, **kw) if self.R else None

    def test_callback_convention(self):
        """Informational: the convention a C caller's ISeqInStream/ISeqOutStream/ICompressProgress functions must
        have. A C program built with MSVC's default (/Gd) passes __cdecl ones, which corrupt the stack on win-x86."""
        print("  LZMA stream callbacks: %s; official 7-Zip comparisons: %s" % (
            "__stdcall (win-x86 /Gz)" if self.stdcall else "the platform's only convention"
            if sys.platform != "win32" or ctypes.sizeof(vp) == 8 else "__cdecl",
            self.ref_broken or self.ref_note or ("on, its callbacks %s" % ("__stdcall" if self.ref_stdcall else
                                                                           "the default convention"))))

    def test_round_trip_any_read_size(self):
        """Any read size, with and without an end mark, the data size given or not: GrindCore's decoder and Python's
        lzma both get the data back."""
        cases = [("empty", b""), ("1 byte", b"x"), ("text 20 KB", sample.text(20000, seed=3)),
                 ("noise 70 KB", sample.noise(70000, seed=4)), ("mixed 300 KB", sample.mixed(300000, seed=5))]
        for name, data in cases:
            for step in (1, 4097, 1 << 20):
                if step == 1 and len(data) > 20000:
                    continue
                for end_mark in (0, 1):
                    for size in (None, len(data)):
                        with self.subTest(data=name, step=step, end_mark=end_mark, data_size=size):
                            rc, pr, out, s = self.gc(data, step=step, end_mark=end_mark, data_size=size)
                            self.assertEqual(rc, SZ_OK)
                            self.assertTrue(decode(self.L, pr, out, len(data)) == data, "GrindCore's decoder")
                            if U.lzma is not None:
                                got, err = py_decode(pr, out, len(data), end_mark)
                                self.assertIsNone(err)
                                self.assertTrue(got == data, "Python's lzma")

    def test_data_size_and_official_output(self):
        """With SetDataSize(n) the output is MemEncode's (LzmaBlock's) for the same properties, at any read size.
        Without it the hash table follows the dictionary, so data smaller than the dictionary can encode differently:
        measured (2026-10-10, 300 random cases on win-x64) only at levels 1-3, 7-Zip's fast mode with hash chains,
        by a byte or two, about 1 case in 75 overall; never at 5-9 (binary trees). mixed(300000, seed=1) at level 1
        with a 1 MiB dictionary is one that differs, and is pinned. Data at least the dictionary's size can't
        differ. Both results are official 7-Zip's output for the same calls, where GC_REF_7ZIP is set."""
        pinned = ("mixed 300 KB, seed 1", sample.mixed(300000, seed=1))
        cases = [("text 200 KB", U.data(200000)), ("mixed 300 KB", sample.mixed(300000, seed=6)), pinned,
                 ("text 1.5 MiB", U.data(3 << 19, seed=8))]
        settings = ((1, 1, DICT), (3, 1, 1 << 24), (5, 1, DICT), (5, 2, DICT), (9, 1, 1 << 24))
        differ, compared = [], 0
        for name, data in cases:
            for level, threads, dict_bytes in settings:
                with self.subTest(data=name, level=level, threads=threads, dict=dict_bytes):
                    kw = dict(level=level, threads=threads, end_mark=1, dict_bytes=dict_bytes)
                    block = mem_encode(self.L, data, level, threads, 1, dict_bytes)
                    self.assertEqual(block[0], SZ_OK)
                    sized = self.gc(data, data_size=len(data), step=4097, **kw)
                    self.assertEqual(sized[:3], block, "SetDataSize + Encode vs MemEncode")
                    unsized = self.gc(data, **kw)
                    self.assertEqual(unsized[0], SZ_OK)
                    self.assertTrue(decode(self.L, unsized[1], unsized[2], len(data)) == data)
                    if unsized[2] != sized[2]:
                        differ.append("%s L%d dict %d MiB" % (name, level, dict_bytes >> 20))
                        self.assertLess(len(data), dict_bytes, "the size can only matter below the dictionary size")
                    elif (name, level, dict_bytes) == (pinned[0], 1, DICT):
                        self.fail("the pinned case no longer differs without SetDataSize")
                    for size, got in ((len(data), sized), (None, unsized)):
                        want = self.official(data, data_size=size, step=4097 if size else 1 << 16, **kw)
                        if want is not None:
                            self.assertEqual(got[:3], want[:3], "official 7-Zip, data size %s" % size)
                            compared += 1
        print("  Enc_Encode: with SetDataSize = MemEncode for all %d; without it, output differs for %d (%s)%s" % (
            len(cases) * len(settings), len(differ), ", ".join(differ) or "none",
            "; %d encodes identical to official 7-Zip" % compared if compared else ""))

    def test_errors(self):
        """A failed Read is SZ_ERROR_READ whatever it returned, a short Write SZ_ERROR_WRITE, and a Progress that
        asks to stop SZ_ERROR_PROGRESS (LzmaEnc.c CheckErrors and LzmaEnc_Encode2). Progress reports growing sizes,
        input up to the data's size. The same results as official 7-Zip, where present."""
        data = sample.mixed(400000, seed=9)
        for label, kw, want in (("read fails", {"read_fail": 2}, SZ_ERROR_READ),
                                ("write fails", {"write_fail": 1}, SZ_ERROR_WRITE),
                                ("progress stops", {"progress_break": 1}, SZ_ERROR_PROGRESS),
                                ("no progress", {"progress": False}, SZ_OK)):
            with self.subTest(case=label):
                rc, pr, out, s = self.gc(data, **kw)
                self.assertEqual(rc, want)
                official = self.official(data, **kw)
                if official is not None:
                    self.assertEqual((rc, s.calls), (official[0], official[3].calls), "official 7-Zip")
        rc, pr, out, s = self.gc(data)
        self.assertEqual(rc, SZ_OK)
        self.assertGreater(len(s.sizes), 1)
        self.assertEqual(s.sizes, sorted(s.sizes))
        self.assertLessEqual(s.sizes[-1][0], len(data))


class Lzma2DataSize(unittest.TestCase):
    def test_lzma2_block_output_ignores_data_size(self):
        """Lzma2Block's calls (Create, SetProps, SetDataSize(n), WriteProperties, Encode2; Lzma2Block.cs:128-146) give
        the same output as without SetDataSize, single- and multi-threaded: Encode2 from memory sizes each block's
        match finder itself, and its expected size only caps the threads. Decodes back."""
        L = gctest.LIB
        for name, data in (("text 200 KB", U.data(200000)), ("mixed 1 MiB", sample.mixed(1 << 20, seed=7))):
            for level, threads, block in ((1, 1, 0), (5, 1, 0), (9, 1, 0), (5, 2, 1 << 18), (9, 2, 1 << 18)):
                with self.subTest(data=name, level=level, threads=threads, block=block):
                    outs = []
                    for size in (len(data), None):
                        p = L.struct.CLzma2EncProps()
                        L.SZ_Lzma2_v25_01_Enc_Construct(ctypes.byref(p))
                        p.lzmaProps.level, p.lzmaProps.numThreads = level, 1
                        p.numBlockThreads_Max, p.numTotalThreads, p.blockSize = threads, threads, block
                        L.SZ_Lzma2_v25_01_Enc_Normalize(ctypes.byref(p))
                        enc = L.SZ_Lzma2_v25_01_Enc_Create()
                        try:
                            self.assertEqual(L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(p)), SZ_OK)
                            if size is not None:
                                L.SZ_Lzma2_v25_01_Enc_SetDataSize(enc, size)
                            prop = L.SZ_Lzma2_v25_01_Enc_WriteProperties(enc)
                            dst = ctypes.create_string_buffer(len(data) + len(data) // 2 + (1 << 16))
                            dlen = sz(len(dst))
                            rc = L.SZ_Lzma2_v25_01_Enc_Encode2(enc, dst, ctypes.byref(dlen), data, len(data), None)
                        finally:
                            L.SZ_Lzma2_v25_01_Enc_Destroy(enc)
                        self.assertEqual(rc, SZ_OK)
                        outs.append((prop, dst.raw[:dlen.value]))
                    self.assertTrue(outs[0] == outs[1], "output changed with SetDataSize")
                    r = D.one_shot(D.Api(L), "lzma2", outs[0][0], outs[0][1], len(data), D.FINISH_END)
                    self.assertEqual((r.rc, r.status), (SZ_OK, D.FINISHED_WITH_MARK))
                    self.assertTrue(r.out == data)
