"""Helpers for test_lz4.py: GrindCore's LZ4 PAL (SZ_Lz4_v1_10_0_* / SZ_Lz4F_v1_10_0_*) and official LZ4 driven through
the same call sequences, so their outputs can be compared byte for byte.

Block output depends on the exact entry point, not only on the data: LZ4_compress_fast picks a 16-bit hash table for
inputs under 64 KB, while LZ4_compress_fast_continue always uses the 32-bit one. The references therefore make the
calls the PAL makes (a fresh LZ4_stream_t and LZ4_compress_fast_continue, LZ4_compress_HC, LZ4F_*)."""
import ctypes
import os
import sys

OK, ERROR, MEMERROR, COMPRESSFAIL, DECOMPRESSFAIL = 0, -1, -2, -3, -4
STREAMHC_SIZE = 262200          # LZ4_STREAMHC_MINSIZE (lz4hc.h), the extState size LZ4 guarantees
LZ4F_VERSION = 100
LZ4F_ERROR_MAXCODE = 23         # lz4frame.h: ERROR_maxCode is the 24th item of the LZ4F error list, counting OK_NoError
FRAME_MAGIC, SKIPPABLE_START = 0x184D2204, 0x184D2A50
SIZE_T_BITS = 8 * ctypes.sizeof(ctypes.c_size_t)

# LZ4F_blockSizeID_t / LZ4F_blockMode_t / flags (lz4frame.h)
BLOCK_64K, BLOCK_256K, BLOCK_1M, BLOCK_4M = 4, 5, 6, 7
LINKED, INDEPENDENT = 0, 1


def lz4f_is_error(code):
    """LZ4F_isError: codes are (size_t)-n for n in 1..maxCode-1."""
    return code > (1 << SIZE_T_BITS) - LZ4F_ERROR_MAXCODE


def lz4f_error_code(code):
    return (1 << SIZE_T_BITS) - code


def bound(n):
    """LZ4_compressBound."""
    return n + n // 255 + 16 if 0 <= n <= 0x7E000000 else 0


class _Buf(object):
    """Bytes at a fixed address (a ctypes buffer kept alive with its address)."""

    def __init__(self, data, size=None):
        self.keep = ctypes.create_string_buffer(bytes(data), max(size or len(data), 1))
        self.addr, self.n = ctypes.addressof(self.keep), len(data)


def prefs(struct_cls, level=0, block_size=BLOCK_64K, block_mode=LINKED, content_checksum=0, block_checksum=0,
          content_size=0, auto_flush=0, favor_dec_speed=0, dict_id=0):
    p = struct_cls()
    fi = p.frameInfo
    fi.blockSizeID, fi.blockMode, fi.contentChecksumFlag = block_size, block_mode, content_checksum
    fi.frameType, fi.contentSize, fi.dictID, fi.blockChecksumFlag = 0, content_size, dict_id, block_checksum
    p.compressionLevel, p.autoFlush, p.favorDecSpeed = level, auto_flush, favor_dec_speed
    return p


# ------------------------------------------------------------------------------------------------ GrindCore's PAL


class Lz4(object):
    """GrindCore's LZ4 PAL, 1.10.0."""

    def __init__(self, L):
        self.L = L
        self.Prefs = L.struct.LZ4F_preferences_t
        self.FrameInfo = L.struct.LZ4F_frameInfo_t

    def f(self, name):
        return getattr(self.L, name)

    # --- block ---

    def stream(self):
        s = self.L.struct.SZ_Lz4_v1_10_0_Stream()
        if self.f("SZ_Lz4_v1_10_0_Init")(ctypes.byref(s)) != OK:
            raise MemoryError("SZ_Lz4_v1_10_0_Init")
        return s

    def end(self, s):
        self.f("SZ_Lz4_v1_10_0_End")(ctypes.byref(s))

    def compress_fast(self, data, accel=1, capacity=None):
        """GrindCore.net's block path: a fresh stream per call. (result, block or None)"""
        s = self.stream()
        try:
            cap = bound(len(data)) if capacity is None else capacity
            src, dst = _Buf(data), ctypes.create_string_buffer(max(cap, 1))
            r = self.f("SZ_Lz4_v1_10_0_CompressFastContinue")(ctypes.byref(s), src.addr, dst, len(data), cap, accel)
            return r, (dst.raw[:r] if r > 0 else None)
        finally:
            self.end(s)

    def compress_hc(self, data, level, capacity=None):
        cap = bound(len(data)) if capacity is None else capacity
        src, dst = _Buf(data), ctypes.create_string_buffer(max(cap, 1))
        r = self.f("SZ_Lz4_v1_10_0_CompressHC")(src.addr, dst, len(data), cap, level)
        return r, (dst.raw[:r] if r > 0 else None)

    def compress_hc_ext(self, data, level, capacity=None):
        cap = bound(len(data)) if capacity is None else capacity
        state = (ctypes.c_uint64 * (STREAMHC_SIZE // 8 + 1))()
        src, dst = _Buf(data), ctypes.create_string_buffer(max(cap, 1))
        r = self.f("SZ_Lz4_v1_10_0_CompressHC_ExtState")(state, src.addr, dst, len(data), cap, level)
        return r, (dst.raw[:r] if r > 0 else None)

    def compress_hc_destsize(self, data, target, level):
        state = (ctypes.c_uint64 * (STREAMHC_SIZE // 8 + 1))()
        src, dst, n = _Buf(data), ctypes.create_string_buffer(max(target, 1)), ctypes.c_int(len(data))
        r = self.f("SZ_Lz4_v1_10_0_CompressHC_DestSize")(state, src.addr, dst, ctypes.byref(n), target, level)
        return r, n.value, (dst.raw[:r] if r > 0 else None)

    def decompress(self, block, capacity):
        """GrindCore.net's block path: DecompressSafeContinue on a fresh stream. (result, output or None)"""
        s = self.stream()
        try:
            src, dst = _Buf(block), ctypes.create_string_buffer(max(capacity, 1))
            r = self.f("SZ_Lz4_v1_10_0_DecompressSafeContinue")(ctypes.byref(s), src.addr, dst, len(block), capacity)
            return r, (dst.raw[:r] if r >= 0 else None)
        finally:
            self.end(s)

    def decompress_using_dict(self, block, capacity, dictionary):
        s = self.stream()
        try:
            src, dst, dct = _Buf(block), ctypes.create_string_buffer(max(capacity, 1)), _Buf(dictionary)
            r = self.f("SZ_Lz4_v1_10_0_DecompressUsingDict")(ctypes.byref(s), src.addr, dst, len(block), capacity,
                                                             dct.addr, len(dictionary))
            return r, (dst.raw[:r] if r >= 0 else None)
        finally:
            self.end(s)

    def linked_encoder(self, accel=1, dictionary=None):
        return _LinkedEncoder(self.f("SZ_Lz4_v1_10_0_CompressFastContinue"), self.stream, self.end,
                              lambda s, addr, n: self.f("SZ_Lz4_v1_10_0_LoadDict")(ctypes.byref(s), addr, n),
                              accel, dictionary, byref=True)

    def linked_decoder(self):
        return _LinkedDecoder(self)

    # --- frame ---

    def frame_encoder(self, p):
        return _FrameEncoder(self.L, "SZ_Lz4F_v1_10_0_", p, pal=True)

    def frame_decoder(self):
        return _FrameDecoder(self.L, "SZ_Lz4F_v1_10_0_", pal=True)

    def frame_bound(self, n, p=None):
        return self.f("SZ_Lz4F_v1_10_0_CompressFrameBound")(n, ctypes.byref(p) if p is not None else None)


class _LinkedEncoder(object):
    """Blocks compressed one after another on one stream (linked: later blocks refer back to earlier ones).

    LZ4's output depends on where the blocks sit in memory: a block that starts where the previous one ended continues
    it (prefix mode, up to 64 KB of history), any other block sees only the previous block as an external dictionary.
    With a separate allocation per block, which mode applies depends on the allocator (macOS sometimes places two
    4 KB buffers back to back, glibc never does). So all blocks go into one buffer, back to back, always prefix mode;
    a dictionary goes at its start with a gap after it, so it is always an external dictionary."""

    GAP = 64

    def __init__(self, fn, new, end, load, accel, dictionary, byref, capacity=1 << 22):
        self.fn, self.end_fn, self.accel, self.byref = fn, end, accel, byref
        self.s = new()
        self.buf = ctypes.create_string_buffer(capacity + (len(dictionary) + self.GAP if dictionary else 0))
        self.base, self.pos = ctypes.addressof(self.buf), 0
        if dictionary is not None:
            ctypes.memmove(self.base, dictionary, len(dictionary))
            load(self.s, self.base, len(dictionary))
            self.pos = len(dictionary) + self.GAP

    def compress(self, data, capacity=None):
        src = self.base + self.pos
        if len(data) > len(self.buf) - self.pos:
            raise ValueError("linked encoder buffer full")
        ctypes.memmove(src, data, len(data))
        self.pos += len(data)
        cap = bound(len(data)) if capacity is None else capacity
        dst = ctypes.create_string_buffer(max(cap, 1))
        s = ctypes.byref(self.s) if self.byref else self.s
        r = self.fn(s, src, dst, len(data), cap, self.accel)
        return r, (dst.raw[:r] if r > 0 else None)

    def close(self):
        self.end_fn(self.s)


class _LinkedDecoder(object):
    """DecompressSafeContinue on one stream, each block decoded right after the previous block's output."""

    def __init__(self, z, total=1 << 22):
        self.z, self.s = z, z.stream()
        self.out = ctypes.create_string_buffer(total)
        self.pos = 0

    def decompress(self, block, capacity):
        src = _Buf(block)
        dst = ctypes.addressof(self.out) + self.pos
        r = self.z.f("SZ_Lz4_v1_10_0_DecompressSafeContinue")(ctypes.byref(self.s), src.addr, dst, len(block),
                                                              capacity)
        if r > 0:
            got = ctypes.string_at(dst, r)
            self.pos += r
            return r, got
        return r, (b"" if r == 0 else None)

    def close(self):
        self.z.end(self.s)


class _FrameEncoder(object):
    """LZ4F: begin, updates (with optional flushes), end. Returns the frame; raises on an LZ4F error."""

    def __init__(self, L, prefix, p, pal):
        self.L, self.P, self.p, self.pal = L, prefix, p, pal
        if pal:
            self.ctx = L.struct.SZ_Lz4F_v1_10_0_CompressionContext()
            rc = getattr(L, prefix + "CreateCompressionContext")(ctypes.byref(self.ctx))
        else:
            self.ctx = ctypes.c_void_p()
            rc = getattr(L, prefix + "createCompressionContext")(ctypes.byref(self.ctx), LZ4F_VERSION)
        if rc != 0:
            raise MemoryError("create compression context: %d" % rc)
        self.handle = ctypes.byref(self.ctx) if pal else self.ctx

    def call(self, name, *args):
        r = getattr(self.L, self.P + name)(self.handle, *args)
        if lz4f_is_error(r):
            raise ValueError("%s: LZ4F error %d" % (name, lz4f_error_code(r)))
        return r

    def encode(self, data, step, flush_at=()):
        bound_fn = getattr(self.L, self.P + ("CompressBound" if self.pal else "compressBound"))
        out = []
        cap = 64 + 19
        dst = ctypes.create_string_buffer(cap)
        n = self.call("CompressBegin" if self.pal else "compressBegin", dst, cap, ctypes.byref(self.p))
        out.append(dst.raw[:n])
        src, pos = _Buf(data), 0
        cuts = sorted(set(list(range(step, len(data), step)) + [c for c in flush_at if 0 < c < len(data)] +
                      [len(data)])) if data else []
        for cut in cuts:
            size = cut - pos
            cap = bound_fn(size, ctypes.byref(self.p))
            dst = ctypes.create_string_buffer(max(cap, 1))
            n = self.call("CompressUpdate" if self.pal else "compressUpdate", dst, cap, src.addr + pos, size, None)
            out.append(dst.raw[:n])
            pos = cut
            if cut in flush_at:
                cap = bound_fn(0, ctypes.byref(self.p))
                dst = ctypes.create_string_buffer(max(cap, 1))
                n = self.call("Flush" if self.pal else "flush", dst, cap, None)
                out.append(dst.raw[:n])
        cap = bound_fn(0, ctypes.byref(self.p))
        dst = ctypes.create_string_buffer(max(cap, 1))
        n = self.call("CompressEnd" if self.pal else "compressEnd", dst, cap, None)
        out.append(dst.raw[:n])
        return b"".join(out)

    def close(self):
        if self.pal:
            getattr(self.L, self.P + "FreeCompressionContext")(ctypes.byref(self.ctx))
        else:
            getattr(self.L, self.P + "freeCompressionContext")(self.ctx)


class _FrameDecoder(object):
    """LZ4F decompression in steps: in_step bytes of input and out_cap bytes of room per call."""

    def __init__(self, L, prefix, pal):
        self.L, self.P, self.pal = L, prefix, pal
        self.ctx = L.struct.SZ_Lz4F_v1_10_0_DecompressionContext()
        if getattr(L, prefix + "CreateDecompressionContext")(ctypes.byref(self.ctx)) != 0:
            raise MemoryError("CreateDecompressionContext")

    def decode(self, frame, in_step=1 << 20, out_cap=1 << 16, max_calls=1 << 20):
        """(output, last hint, error code or 0). The hint is 0 once a frame is complete."""
        fn = getattr(self.L, self.P + "Decompress")
        src, pos, out, hint = _Buf(frame), 0, [], None
        dst = ctypes.create_string_buffer(out_cap)
        for _ in range(max_calls):
            n_in = ctypes.c_size_t(min(in_step, len(frame) - pos))
            n_out = ctypes.c_size_t(out_cap)
            hint = fn(ctypes.byref(self.ctx), dst, ctypes.byref(n_out), src.addr + pos, ctypes.byref(n_in), None)
            if lz4f_is_error(hint):
                return b"".join(out), hint, lz4f_error_code(hint)
            out.append(dst.raw[:n_out.value])
            pos += n_in.value
            if hint == 0 or (pos >= len(frame) and n_out.value == 0 and n_in.value == 0):
                break
        return b"".join(out), hint, 0

    def reset(self):
        getattr(self.L, self.P + "ResetDecompressionContext")(ctypes.byref(self.ctx))

    def close(self):
        getattr(self.L, self.P + "FreeDecompressionContext")(ctypes.byref(self.ctx))


# ------------------------------------------------------------------------------------------------ official LZ4


def reference(version="1.10.0"):
    """The official library for this version from $GC_REF_LZ4, or None."""
    folder = os.environ.get("GC_REF_LZ4")
    if not folder:
        return None
    ext = ".dylib" if sys.platform == "darwin" else ".dll" if sys.platform == "win32" else ".so"
    path = os.path.join(folder, "liblz4ref-%s%s" % (version, ext))
    return Ref(path, version) if os.path.exists(path) else None


class Ref(object):
    """Official LZ4 by its own names, with the same call sequences as the PAL."""

    def __init__(self, path, version):
        d = self.dll = ctypes.CDLL(path)
        self.version, self.path = version, path
        vp, sz, i, ci = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_char_p
        for name, res, args in (
                ("LZ4_createStream", vp, []), ("LZ4_freeStream", i, [vp]),
                ("LZ4_compress_fast_continue", i, [vp, vp, vp, i, i, i]),
                ("LZ4_loadDict", i, [vp, vp, i]), ("LZ4_saveDict", i, [vp, vp, i]),
                ("LZ4_attach_dictionary", None, [vp, vp]),
                ("LZ4_compress_HC", i, [vp, vp, i, i, i]),
                ("LZ4_compress_HC_extStateHC", i, [vp, vp, vp, i, i, i]),
                ("LZ4_compress_HC_destSize", i, [vp, vp, vp, vp, i, i]),
                ("LZ4_compress_destSize", i, [vp, vp, vp, i]),
                ("LZ4_decompress_safe", i, [vp, vp, i, i]),
                ("LZ4F_createCompressionContext", sz, [vp, ctypes.c_uint]), ("LZ4F_freeCompressionContext", sz, [vp]),
                ("LZ4F_compressBegin", sz, [vp, vp, sz, vp]), ("LZ4F_compressUpdate", sz, [vp, vp, sz, vp, sz, vp]),
                ("LZ4F_flush", sz, [vp, vp, sz, vp]), ("LZ4F_compressEnd", sz, [vp, vp, sz, vp]),
                ("LZ4F_compressBound", sz, [sz, vp]), ("LZ4F_compressFrameBound", sz, [sz, vp]),
                ("LZ4F_getErrorName", ci, [sz])):
            fn = getattr(d, name)
            fn.restype, fn.argtypes = res, args

    def compress_fast(self, data, accel=1, capacity=None):
        s = self.dll.LZ4_createStream()
        try:
            cap = bound(len(data)) if capacity is None else capacity
            src, dst = _Buf(data), ctypes.create_string_buffer(max(cap, 1))
            r = self.dll.LZ4_compress_fast_continue(s, src.addr, dst, len(data), cap, accel)
            return r, (dst.raw[:r] if r > 0 else None)
        finally:
            self.dll.LZ4_freeStream(s)

    def compress_hc(self, data, level, capacity=None):
        cap = bound(len(data)) if capacity is None else capacity
        src, dst = _Buf(data), ctypes.create_string_buffer(max(cap, 1))
        r = self.dll.LZ4_compress_HC(src.addr, dst, len(data), cap, level)
        return r, (dst.raw[:r] if r > 0 else None)

    def compress_hc_destsize(self, data, target, level):
        state = (ctypes.c_uint64 * (STREAMHC_SIZE // 8 + 1))()
        src, dst, n = _Buf(data), ctypes.create_string_buffer(max(target, 1)), ctypes.c_int(len(data))
        r = self.dll.LZ4_compress_HC_destSize(state, src.addr, dst, ctypes.byref(n), target, level)
        return r, n.value, (dst.raw[:r] if r > 0 else None)

    def linked_encoder(self, accel=1, dictionary=None):
        return _LinkedEncoder(self.dll.LZ4_compress_fast_continue, self.dll.LZ4_createStream, self.dll.LZ4_freeStream,
                              lambda s, addr, n: self.dll.LZ4_loadDict(s, addr, n), accel, dictionary, byref=False)

    def frame_encoder(self, p):
        return _FrameEncoder(self.dll, "LZ4F_", p, pal=False)
