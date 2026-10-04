"""Shared by test_lzma_dec.py and the child processes it starts: 7-Zip 25.01's LZMA and LZMA2 decoders, driven through
GrindCore's exports or through official 7-Zip's own functions with exactly the same calls, plus the streams to decode.

GrindCore's 19 decoder exports pass straight through to 7-Zip with g_AlignedAlloc as the allocator
(pal_sevenzip_lzma_v25_01.c). The decoder sources are official (audit/lzma.md 3.4). Which decoder runs depends on the
build: win-x64 links 7-Zip's assembler decoder (Asm/x86/LzmaDecOpt.asm, -DZ7_LZMA_DEC_OPT, through shared_asm.cmake),
and every other RID compiles the C one.

The references are official 7-Zip built unmodified by ref/build_7zip_ref.py. GC_REF_7ZIP names lib7zref (the C
decoder); lib7zref-asm next to it, where it was built, is the assembler decoder (win-x64: the same LzmaDecOpt.asm
GrindCore links; arm64: Asm/arm64/LzmaDecOpt.S, which GrindCore doesn't build).

Python 3.6 compatible, stdlib only."""
import collections
import ctypes
import mmap
import os
import random
import struct
import sys

import gcnative

try:
    import lzma
except ImportError:  # some minimal Pythons are built without it
    lzma = None

vp, sz, c_int, c_uint, c_ubyte = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint, ctypes.c_ubyte

SZ_OK, SZ_ERROR_DATA, SZ_ERROR_MEM, SZ_ERROR_UNSUPPORTED, SZ_ERROR_INPUT_EOF, SZ_ERROR_FAIL = 0, 1, 2, 4, 6, 11
FINISH_ANY, FINISH_END = 0, 1
NOT_SPECIFIED, FINISHED_WITH_MARK, NOT_FINISHED, NEEDS_MORE_INPUT, MAYBE_FINISHED_WITHOUT_MARK = range(5)
PARSE_NEW_BLOCK, PARSE_NEW_CHUNK = 5, 6
STATUS = {0: "NOT_SPECIFIED", 1: "FINISHED_WITH_MARK", 2: "NOT_FINISHED", 3: "NEEDS_MORE_INPUT",
          4: "MAYBE_FINISHED_WITHOUT_MARK", 5: "PARSE_NEW_BLOCK", 6: "PARSE_NEW_CHUNK"}
RC = {0: "SZ_OK", 1: "SZ_ERROR_DATA", 2: "SZ_ERROR_MEM", 4: "SZ_ERROR_UNSUPPORTED", 6: "SZ_ERROR_INPUT_EOF",
      11: "SZ_ERROR_FAIL"}
GUARD = 64                     # sentinel bytes after every output buffer
SENTINEL = 0xA5
IS_32 = ctypes.sizeof(ctypes.c_void_p) == 4


def asm_decoder_expected():
    """Whether this RID's GrindCore build links the assembler decoder: sevenzip-lzma_v25_01.cmake needs USE_ASM, which
    GrindCore.build's configuretools.cmake sets for win-x64 and win-x86 only, and IS_X64."""
    return gcnative.target() == "win-x64"


# ------------------------------------------------------------------------------------------ the two APIs

class Api(object):
    """One decoder library: GrindCore (SZ_* exports) or official 7-Zip (its own function names, allocator passed
    explicitly). The decoder state structs are the caller's, laid out from the same headers for both."""

    def __init__(self, L, ref_path=None, name=None):
        self.S = L.struct
        self.ref = ref_path is not None
        if self.ref:
            self.name = name or os.path.basename(ref_path)
            self._bind_ref(ctypes.CDLL(ref_path))
        else:
            self.name = name or "GrindCore"
            self.L = L
        self.dec_off = self.S.CLzma2Dec.decoder.offset

    def _bind_ref(self, r):
        self.dll = r
        self.alloc = ctypes.addressof(ctypes.c_byte.in_dll(r, "g_AlignedAlloc"))
        self.f = {}
        for name, res, args in [
                ("LzmaDec_Init", None, [vp]), ("LzmaDec_AllocateProbs", c_int, [vp, vp, c_uint, vp]),
                ("LzmaDec_FreeProbs", None, [vp, vp]), ("LzmaDec_Allocate", c_int, [vp, vp, c_uint, vp]),
                ("LzmaDec_Free", None, [vp, vp]),
                ("LzmaDec_DecodeToDic", c_int, [vp, sz, vp, vp, c_int, vp]),
                ("LzmaDec_DecodeToBuf", c_int, [vp, vp, vp, vp, vp, c_int, vp]),
                ("LzmaDecode", c_int, [vp, vp, vp, vp, vp, c_uint, c_int, vp, vp]),
                ("Lzma2Dec_AllocateProbs", c_int, [vp, c_ubyte, vp]), ("Lzma2Dec_Allocate", c_int, [vp, c_ubyte, vp]),
                ("Lzma2Dec_Init", None, [vp]), ("Lzma2Dec_DecodeToDic", c_int, [vp, sz, vp, vp, c_int, vp]),
                ("Lzma2Dec_DecodeToBuf", c_int, [vp, vp, vp, vp, vp, c_int, vp]),
                ("Lzma2Dec_Parse", c_int, [vp, sz, vp, vp, c_int]),
                ("Lzma2Decode", c_int, [vp, vp, vp, vp, c_ubyte, c_int, vp, vp])]:
            fn = getattr(r, name)
            fn.restype, fn.argtypes = res, args
            self.f[name] = fn

    def new(self, kind):
        """A constructed decoder state (CLzmaDec for "lzma", CLzma2Dec for "lzma2")."""
        d = (self.S.CLzmaDec if kind == "lzma" else self.S.CLzma2Dec)()
        if not self.ref:
            (self.L.SZ_Lzma_v25_01_Dec_Construct if kind == "lzma" else self.L.SZ_Lzma2_v25_01_Dec_Construct)(ctypes.byref(d))
        else:
            inner = d if kind == "lzma" else d.decoder
            inner.dic, inner.probs = None, None          # LzmaDec_CONSTRUCT
        return d

    def _inner(self, d):
        return ctypes.addressof(d) + (self.dec_off if isinstance(d, self.S.CLzma2Dec) else 0)

    def allocate(self, kind, d, props, probs_only=False):
        if not self.ref:
            L = self.L
            if kind == "lzma":
                fn = L.SZ_Lzma_v25_01_Dec_AllocateProbs if probs_only else L.SZ_Lzma_v25_01_Dec_Allocate
                return fn(ctypes.byref(d), props, len(props))
            fn = L.SZ_Lzma2_v25_01_Dec_AllocateProbs if probs_only else L.SZ_Lzma2_v25_01_Dec_Allocate
            return fn(ctypes.byref(d), props)
        if kind == "lzma":
            fn = self.f["LzmaDec_AllocateProbs" if probs_only else "LzmaDec_Allocate"]
            return fn(ctypes.byref(d), props, len(props), self.alloc)
        return self.f["Lzma2Dec_AllocateProbs" if probs_only else "Lzma2Dec_Allocate"](ctypes.byref(d), props, self.alloc)

    def init(self, kind, d):
        if not self.ref:
            (self.L.SZ_Lzma_v25_01_Dec_Init if kind == "lzma" else self.L.SZ_Lzma2_v25_01_Dec_Init)(ctypes.byref(d))
        else:
            self.f["LzmaDec_Init" if kind == "lzma" else "Lzma2Dec_Init"](ctypes.byref(d))

    def free(self, kind, d, probs_only=False):
        if not self.ref:
            L = self.L
            if kind == "lzma":
                (L.SZ_Lzma_v25_01_Dec_FreeProbs if probs_only else L.SZ_Lzma_v25_01_Dec_Free)(ctypes.byref(d))
            else:
                (L.SZ_Lzma2_v25_01_Dec_FreeProbs if probs_only else L.SZ_Lzma2_v25_01_Dec_Free)(ctypes.byref(d))
        else:  # Lzma2Dec_Free/FreeProbs are macros over the inner CLzmaDec
            self.f["LzmaDec_FreeProbs" if probs_only else "LzmaDec_Free"](self._inner(d), self.alloc)

    def to_dic(self, kind, d, dic_limit, src, n, finish):
        """DecodeToDic -> (rc, consumed, status)."""
        sl, st = sz(n), c_int(-1)
        if not self.ref:
            fn = self.L.SZ_Lzma_v25_01_Dec_DecodeToDic if kind == "lzma" else self.L.SZ_Lzma2_v25_01_Dec_DecodeToDic
        else:
            fn = self.f["LzmaDec_DecodeToDic" if kind == "lzma" else "Lzma2Dec_DecodeToDic"]
        rc = fn(ctypes.byref(d), dic_limit, src, ctypes.byref(sl), finish, ctypes.byref(st))
        return rc, sl.value, st.value

    def to_buf(self, kind, d, dst, cap, src, n, finish):
        """DecodeToBuf -> (rc, written, consumed, status)."""
        dl, sl, st = sz(cap), sz(n), c_int(-1)
        if not self.ref:
            fn = self.L.SZ_Lzma_v25_01_Dec_DecodeToBuf if kind == "lzma" else self.L.SZ_Lzma2_v25_01_Dec_DecodeToBuf
        else:
            fn = self.f["LzmaDec_DecodeToBuf" if kind == "lzma" else "Lzma2Dec_DecodeToBuf"]
        rc = fn(ctypes.byref(d), dst, ctypes.byref(dl), src, ctypes.byref(sl), finish, ctypes.byref(st))
        return rc, dl.value, sl.value, st.value

    def one_shot_raw(self, kind, dst, cap, src, n, props, finish):
        """LzmaDecode / Lzma2Decode -> (rc, written, consumed, status)."""
        dl, sl, st = sz(cap), sz(n), c_int(-1)
        if not self.ref:
            if kind == "lzma":
                rc = self.L.SZ_Lzma_v25_01_Dec_LzmaDecode(dst, ctypes.byref(dl), src, ctypes.byref(sl), props, len(props),
                                                          finish, ctypes.byref(st))
            else:
                rc = self.L.SZ_Lzma2_v25_01_Decode(dst, ctypes.byref(dl), src, ctypes.byref(sl), props, finish,
                                                   ctypes.byref(st))
        elif kind == "lzma":
            rc = self.f["LzmaDecode"](dst, ctypes.byref(dl), src, ctypes.byref(sl), props, len(props), finish,
                                      ctypes.byref(st), self.alloc)
        else:
            rc = self.f["Lzma2Decode"](dst, ctypes.byref(dl), src, ctypes.byref(sl), props, finish, ctypes.byref(st),
                                       self.alloc)
        return rc, dl.value, sl.value, st.value

    def parse(self, d, out_size, src, n, check_finish):
        """Lzma2Dec_Parse -> (status, consumed)."""
        sl = sz(n)
        if not self.ref:
            r = self.L.SZ_Lzma2_v25_01_Dec_Parse(ctypes.byref(d), out_size, src, ctypes.byref(sl), check_finish)
        else:
            r = self.f["Lzma2Dec_Parse"](ctypes.byref(d), out_size, src, ctypes.byref(sl), check_finish)
        return r, sl.value


def references(L):
    """[(label, Api)] for the official builds found from $GC_REF_7ZIP, plus the reasons for any that wouldn't load."""
    path = os.environ.get("GC_REF_7ZIP")
    out, errors = [], []
    if not path:
        return out, ["GC_REF_7ZIP not set (ref/build_7zip_ref.py)"]
    base, ext = os.path.splitext(path)
    for label, p in (("official C", path), ("official asm", base + "-asm" + ext)):
        if not os.path.exists(p):
            if label == "official C":
                errors.append("%s: missing" % p)
            continue
        try:
            out.append((label, Api(L, p, label)))
        except (OSError, AttributeError) as e:
            errors.append("%s: %s" % (p, e))
    return out, errors


# ------------------------------------------------------------------------------------------ results

Result = collections.namedtuple("Result", "rc status out used overrun calls")


def _out_buffer(cap):
    buf = ctypes.create_string_buffer(cap + GUARD)
    ctypes.memset(buf, SENTINEL, cap + GUARD)
    return buf


def _overrun(buf, cap):
    tail = buf.raw[cap:cap + GUARD]
    return tail != bytes([SENTINEL]) * GUARD


def one_shot(api, kind, props, src, cap, finish=FINISH_END, src_addr=None, dst_addr=None):
    """LzmaDecode / Lzma2Decode of `src` into `cap` bytes. src_addr/dst_addr place input or output elsewhere (guard
    pages); otherwise the output gets GUARD sentinel bytes after it, checked for writes past `cap`."""
    if dst_addr is None:
        buf = _out_buffer(cap)
        dst = buf
    else:
        buf, dst = None, dst_addr
    rc, w, u, st = api.one_shot_raw(kind, dst, cap, src if src_addr is None else src_addr, len(src), props, finish)
    out = (buf.raw[:w] if buf is not None else ctypes.string_at(dst_addr, w))
    return Result(rc, st, out, u, _overrun(buf, cap) if buf is not None else False, 1)


def stream(api, kind, props, src, in_step, out_step, finish=FINISH_ANY, mode="buf", size=None, max_calls=200000,
           src_slot=None):
    """Streaming decode as an application would: Allocate, Init, then DecodeToBuf (mode "buf") or DecodeToDic on the
    decoder's own dictionary (mode "dic") with at most in_step new input bytes and out_step output bytes per call.
    With `size` (known output size), output calls are capped at what's left and the call that reaches it uses
    FINISH_END; otherwise every call uses `finish`. Stops on an error, on FINISHED_WITH_MARK, on reaching `size`, or
    when a call makes no progress. src_slot: a Guarded slot each call's input is copied into, so a read past that
    call's input faults. Returns a Result (used = input consumed; rc = 2 (SZ_ERROR_MEM) etc. if Allocate failed)."""
    d = api.new(kind)
    rc = api.allocate(kind, d, props)
    if rc:
        api.free(kind, d)
        return Result(rc, None, b"", 0, False, 0)
    api.init(kind, d)
    data = ctypes.create_string_buffer(src, max(len(src), 1))
    base = ctypes.addressof(data)
    inner = d if kind == "lzma" else d.decoder
    out, pos, status, calls, overrun = bytearray(), 0, None, 0, False
    obuf = _out_buffer(out_step) if mode == "buf" else None
    try:
        while calls < max_calls:
            n = min(in_step, len(src) - pos)
            addr = base + pos if src_slot is None else src_slot.put(src[pos:pos + n])
            cap, fin = out_step, finish
            if size is not None:
                left = size - len(out)
                if left <= cap:
                    cap, fin = left, FINISH_END
            if mode == "buf":
                rc, w, u, status = api.to_buf(kind, d, obuf, cap, addr, n, fin)
                out += obuf.raw[:w]
                overrun = overrun or _overrun(obuf, out_step)
            else:
                if inner.dicPos == inner.dicBufSize:
                    inner.dicPos = 0
                start = inner.dicPos
                limit = min(start + cap, inner.dicBufSize)
                if limit - start < cap:
                    fin = FINISH_ANY
                rc, u, status = api.to_dic(kind, d, limit, addr, n, fin)
                w = inner.dicPos - start
                out += ctypes.string_at(inner.dic + start, w)
            calls += 1
            pos += u
            if rc or status == FINISHED_WITH_MARK:
                break
            if size is not None and len(out) >= size and status != NEEDS_MORE_INPUT:
                break
            if u == 0 and w == 0:
                break
        return Result(rc, status, bytes(out), pos, overrun, calls)
    finally:
        api.free(kind, d)


# ------------------------------------------------------------------------------------------ guard pages

PAGE = mmap.PAGESIZE


class Guarded(object):
    """A writable region of `size` bytes that ends exactly where a no-access page begins. put(data) copies data so it
    ends at the guard and returns its address; a read past it faults."""

    def __init__(self, size):
        n = (max(size, 1) + PAGE - 1) // PAGE
        if sys.platform == "win32":
            k = ctypes.windll.kernel32
            k.VirtualAlloc.restype = ctypes.c_void_p
            k.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32]
            k.VirtualProtect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_void_p]
            base = k.VirtualAlloc(None, (n + 1) * PAGE, 0x3000, 0x04)          # MEM_COMMIT|RESERVE, READWRITE
            old = ctypes.c_uint32()
            if not base or not k.VirtualProtect(base + n * PAGE, PAGE, 0x01, ctypes.byref(old)):   # NOACCESS
                raise OSError("VirtualAlloc/VirtualProtect")
        else:
            self.map = mmap.mmap(-1, (n + 1) * PAGE)
            base = ctypes.addressof(ctypes.c_char.from_buffer(self.map))
            libc = ctypes.CDLL(None)
            libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            if libc.mprotect(base + n * PAGE, PAGE, 0) != 0:                   # PROT_NONE
                raise OSError("mprotect")
        self.end = base + n * PAGE
        self.size = n * PAGE

    def put(self, data):
        addr = self.end - len(data)
        ctypes.memmove(addr, bytes(data), len(data))
        return addr

    def room(self, n):
        """The address of n writable bytes that end at the guard (an output buffer)."""
        return self.end - n


# ------------------------------------------------------------------------------------------ streams to decode

def lzma2_prop(dict_bytes):
    """The smallest LZMA2 dictionary property that covers dict_bytes."""
    for p in range(41):
        if dict_size(p) >= dict_bytes:
            return p
    return 40


def dict_size(prop):
    return 0xFFFFFFFF if prop == 40 else (2 | (prop & 1)) << (prop // 2 + 11)


def lzma_props_bytes(lc, lp, pb, dict_bytes):
    return bytes([(pb * 5 + lp) * 9 + lc]) + struct.pack("<I", dict_bytes)


def xz_lzma(data, lc=3, lp=0, pb=2, dict_bytes=1 << 20, preset=6):
    """liblzma's .lzma ("alone") encoder: (5 property bytes, raw stream with an end mark). lc + lp <= 4 (liblzma)."""
    f = {"id": lzma.FILTER_LZMA1, "preset": preset, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_bytes}
    alone = lzma.compress(data, format=lzma.FORMAT_ALONE, filters=[f])
    return alone[:5], alone[13:]


def xz_lzma2(data, lc=3, lp=0, pb=2, dict_bytes=1 << 20, preset=6):
    """liblzma's raw LZMA2 encoder: (property byte, stream ending in the 0x00 end byte)."""
    f = {"id": lzma.FILTER_LZMA2, "preset": preset, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_bytes}
    return lzma2_prop(dict_bytes), lzma.compress(data, format=lzma.FORMAT_RAW, filters=[f])


def gc_lzma(L, data, lc=3, lp=0, pb=2, dict_bytes=1 << 20, level=5, end_mark=0):
    """GrindCore's one-shot LZMA encoder (byte-identical to official 7-Zip's, lzma.md 3.4), for what liblzma can't
    make: lc + lp > 4, and streams without an end mark. Returns (5 property bytes, raw stream)."""
    p = L.struct.CLzmaEncProps()
    L.SZ_Lzma_v25_01_EncProps_Init(ctypes.byref(p))
    p.level, p.dictSize, p.lc, p.lp, p.pb, p.numThreads = level, dict_bytes, lc, lp, pb, 1
    dst = ctypes.create_string_buffer(len(data) + len(data) // 2 + 1024)
    dl, pe, pn = sz(len(dst)), ctypes.create_string_buffer(5), sz(5)
    rc = L.SZ_Lzma_v25_01_Enc_LzmaEncode(dst, ctypes.byref(dl), data, len(data), ctypes.byref(p), pe, ctypes.byref(pn),
                                         end_mark, None)
    if rc:
        raise RuntimeError("LzmaEncode returned %d" % rc)
    return pe.raw[:pn.value], dst.raw[:dl.value]


def gc_lzma2_blocks(L, data, level=5, block=1 << 18, threads=2):
    """GrindCore's Lzma2Enc_Encode2 with blocks (each starts with a dictionary reset, as 7-Zip's multithreaded
    encoder writes): (property byte, stream)."""
    p = L.struct.CLzma2EncProps()
    L.SZ_Lzma2_v25_01_Enc_Construct(ctypes.byref(p))
    p.lzmaProps.level, p.lzmaProps.numThreads = level, 1
    p.numBlockThreads_Max, p.numTotalThreads, p.blockSize = threads, threads, block
    L.SZ_Lzma2_v25_01_Enc_Normalize(ctypes.byref(p))
    enc = L.SZ_Lzma2_v25_01_Enc_Create()
    try:
        L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(p))
        prop = L.SZ_Lzma2_v25_01_Enc_WriteProperties(enc)
        dst = ctypes.create_string_buffer(len(data) + len(data) // 2 + (1 << 16))
        dl = sz(len(dst))
        rc = L.SZ_Lzma2_v25_01_Enc_Encode2(enc, dst, ctypes.byref(dl), data, len(data), None)
        if rc:
            raise RuntimeError("Lzma2Enc_Encode2 returned %d" % rc)
        return prop, dst.raw[:dl.value]
    finally:
        L.SZ_Lzma2_v25_01_Enc_Destroy(enc)


def lzma2_chunks(stream):
    """An independent LZMA2 chunk parser (the format in Lzma2Dec.c:16-27): [(offset, control, unpack, pack, props or
    None)] up to and including the end byte. Raises ValueError on a malformed header."""
    out, i = [], 0
    while True:
        if i >= len(stream):
            raise ValueError("no end byte")
        c = stream[i]
        if c == 0:
            out.append((i, 0, 0, 0, None))
            return out
        if c < 0x80:
            if c > 2:
                raise ValueError("control %#x at %d" % (c, i))
            unpack = (stream[i + 1] << 8 | stream[i + 2]) + 1
            out.append((i, c, unpack, 0, None))
            i += 3 + unpack
        else:
            unpack = ((c & 0x1F) << 16 | stream[i + 1] << 8 | stream[i + 2]) + 1
            pack = (stream[i + 3] << 8 | stream[i + 4]) + 1
            has_props = c >= 0xC0
            out.append((i, c, unpack, pack, stream[i + 5] if has_props else None))
            i += 5 + (1 if has_props else 0) + pack


def uncompressed_lzma2(data, first_reset=True, piece=40000):
    """An LZMA2 stream of uncompressed chunks only (control 1, then 2), as an encoder writes for incompressible data."""
    out, first = bytearray(), True
    for i in range(0, len(data), piece):
        part = data[i:i + piece]
        out += bytes([1 if (first and first_reset) else 2]) + struct.pack(">H", len(part) - 1) + part
        first = False
    return bytes(out + b"\x00")


def sweep_streams(L):
    """(name, kind, props, stream, data): the streams the corrupt-input sweeps mutate. Made with GrindCore's own
    encoders (byte-identical to official 7-Zip's, lzma.md 3.4), so no lzma module is needed."""
    from gctest import sample
    text, mixed, noise = sample.text(2500, seed=21), sample.mixed(6000, seed=22), sample.noise(1200, seed=23)
    out = []
    p, s = gc_lzma(L, text, end_mark=1)
    out.append(("LZMA, end mark", "lzma", p, s, text))
    p, s = gc_lzma(L, text, end_mark=0)
    out.append(("LZMA, no end mark", "lzma", p, s, text))
    p, s = gc_lzma(L, mixed[:3000], lc=8, lp=4, pb=4, end_mark=1)
    out.append(("LZMA lc8 lp4 pb4", "lzma", p, s, mixed[:3000]))
    p, s = gc_lzma2_blocks(L, text, level=5, block=1 << 30, threads=1)
    out.append(("LZMA2, one block", "lzma2", p, s, text))
    p, s = gc_lzma2_blocks(L, mixed, level=3, block=2000, threads=2)
    out.append(("LZMA2, 2000-byte blocks", "lzma2", p, s, mixed))
    out.append(("LZMA2, uncompressed chunks", "lzma2", 0, uncompressed_lzma2(noise, piece=500), noise))
    return out


def _outcome(r):
    return (r.rc, r.status, r.out, r.used, r.overrun)


def sweep(L, apis, seed=1, stream_every=16, randoms=40):
    """The corrupt-input differential: every mutation of every sweep stream, through every Api, one-shot with
    FINISH_ANY (room to spare) and FINISH_END (the exact size), and every stream_every-th one also streamed (61 bytes in,
    97 out per call). Returns {stream: summary}; apis[0] is the library under test, compared with each of the others."""
    r = random.Random(seed)
    report = {}
    for name, kind, props, s, data in sweep_streams(L):
        size = len(data)
        rep = {"bytes": len(s), "mutations": 0, "decodes": 0, "differences": {}, "examples": [], "overruns": 0,
               "sz_error_fail": 0, "outcomes": collections.Counter()}
        for i, (label, m) in enumerate(mutations(s, r, flips=None if len(s) <= 600 else 3000, randoms=randoms)):
            rep["mutations"] += 1
            res = {}
            for an, a in apis:
                got = [_outcome(one_shot(a, kind, props, m, size + 64, FINISH_ANY)),
                       _outcome(one_shot(a, kind, props, m, size, FINISH_END))]
                if i % stream_every == 0:
                    got.append(_outcome(stream(a, kind, props, m, 61, 97, FINISH_ANY)))
                res[an] = got
                rep["decodes"] += len(got)
                rep["overruns"] += sum(1 for g in got if g[4])
                rep["sz_error_fail"] += sum(1 for g in got if g[0] == SZ_ERROR_FAIL)
            base = res[apis[0][0]]
            for an, _ in apis[1:]:
                if res[an] != base:
                    rep["differences"][an] = rep["differences"].get(an, 0) + 1
                    if len(rep["examples"]) < 5:
                        rep["examples"].append([label, an, [(g[0], g[1], len(g[2]), g[3]) for g in base],
                                                [(g[0], g[1], len(g[2]), g[3]) for g in res[an]]])
            o = base[1]   # FINISH_END at the exact size: what a caller that knows the size sees
            rep["outcomes"]["%s %s %s" % (RC.get(o[0], o[0]), STATUS.get(o[1], o[1]),
                                          "original data" if o[2] == data else "other data")] += 1
        rep["outcomes"] = dict(rep["outcomes"])
        report[name] = rep
    return report


def guard_sweep(L, api, steps=(1, 7, 64), flips=300, seed=3):
    """Reads past the input and writes past the output, caught by guard pages: every truncation and `flips` random
    bit flips of every sweep stream. One-shot with the input ending at a guard page (FINISH_ANY and FINISH_END) and
    with the output ending at one (the exact size, and half of it); streamed with every call's input ending at a guard
    page. A fault ends the process, so run this in a child. Returns the number of decodes."""
    r = random.Random(seed)
    slot, n = Guarded(1 << 16), 0
    outs = {}
    for name, kind, props, s, data in sweep_streams(L):
        size = len(data)
        for cap in (size, size // 2):
            if cap not in outs:
                outs[cap] = Guarded(max(cap, 1))
        cases = [s[:t] for t in range(len(s) + 1)]
        for _ in range(flips):
            b = r.randrange(len(s) * 8)
            m = bytearray(s)
            m[b // 8] ^= 1 << (b % 8)
            cases.append(bytes(m))
        for m in cases:
            for fin in (FINISH_ANY, FINISH_END):
                addr = slot.put(m)
                api.one_shot_raw(kind, ctypes.create_string_buffer(size + 64), size + 64, addr, len(m), props, fin)
                for cap in (size, size // 2):
                    api.one_shot_raw(kind, outs[cap].room(cap), cap, m, len(m), props, fin)
                n += 3
            for step in steps:
                stream(api, kind, props, m, step, 97, FINISH_ANY, src_slot=slot)
                n += 1
    return n


def mutations(stream, r, flips=None, randoms=50):
    """(label, mutated stream): every single-bit flip (or `flips` random ones), every truncation, and random bodies of
    the same length."""
    n = len(stream)
    positions = range(n * 8) if flips is None else [r.randrange(n * 8) for _ in range(flips)]
    for b in positions:
        m = bytearray(stream)
        m[b // 8] ^= 1 << (b % 8)
        yield "flip %d.%d" % (b // 8, b % 8), bytes(m)
    for t in range(n):
        yield "truncated %d" % t, stream[:t]
    for k in range(randoms):
        yield "random %d" % k, r.getrandbits(8 * n).to_bytes(n, "little")
