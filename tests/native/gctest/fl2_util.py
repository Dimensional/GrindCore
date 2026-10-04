"""Helpers for test_fl2.py: fast-lzma2 1.0.1's own API, which GrindCore exports unchanged (61 FL2_* functions, no PAL),
and the same calls on official builds from ref/build_fl2_ref.py, so the two compare byte for byte. Both load through
gcnative, which gives them the same prototypes.

An FL2 frame is a property byte (bits 0-5 the LZMA2 dictionary property; bit 7 set when an XXH32 follows), LZMA2
chunks, the LZMA2 end marker (0), then the XXH32 of the uncompressed data, big-endian (fl2_compress.c FL2_writeEnd)."""
import ctypes
import lzma
import mmap
import os
import struct
import sys

import gcnative

# FL2_ErrorCode (fl2_errors.h)
(NO_ERROR, GENERIC, INTERNAL, CORRUPTION_DETECTED, CHECKSUM_WRONG, PARAMETER_UNSUPPORTED, PARAMETER_OUT_OF_BOUND,
 LCLP_MAX_EXCEEDED, STAGE_WRONG, INIT_MISSING, MEMORY_ALLOCATION, DST_SIZE_TOO_SMALL, SRC_SIZE_WRONG, CANCELED,
 BUFFER, TIMED_OUT) = range(16)
MAX_CODE = 20
# FL2_cParameter (fast-lzma2.h)
(LEVEL, HIGH_COMPRESSION, DICTIONARY_LOG, DICTIONARY_SIZE, OVERLAP_FRACTION, RESET_INTERVAL, BUFFER_RESIZE,
 HYBRID_CHAIN_LOG, HYBRID_CYCLES, SEARCH_DEPTH, FAST_LENGTH, DIVIDE_AND_CONQUER, STRATEGY, LITERAL_CTX_BITS,
 LITERAL_POS_BITS, POS_BITS, OMIT_PROPERTIES, DO_XXHASH, USE_REFERENCE_MF) = range(19)
FAST, OPT, ULTRA = range(3)                  # FL2_strategy
MAX_CLEVEL = MAX_HIGH_CLEVEL = 10            # the generic table (neither FL2_XZ_BUILD nor FL2_7ZIP_BUILD)
# FL2_CONTENTSIZE_ERROR is (size_t)-1 (fast-lzma2.h:122), though FL2_findDecompressedSize returns 64 bits: all ones
# on a 64-bit build, 0xFFFFFFFF on a 32-bit one (where it can't be told from a real size of 4 GiB - 1).
CONTENTSIZE_ERROR = (1 << (8 * ctypes.sizeof(ctypes.c_size_t))) - 1
SIZE_MAX = (1 << (8 * ctypes.sizeof(ctypes.c_size_t))) - 1
MB = 1 << 20
# FL2_defaultCParameters (fl2_compress.c:73-85): dictionary size, and the strategy, for levels 1..10
LEVEL_DICT = [None, 1 * MB, 2 * MB, 2 * MB, 4 * MB, 8 * MB, 16 * MB, 32 * MB, 64 * MB, 64 * MB, 128 * MB]
LEVEL_STRATEGY = [None, FAST, FAST, OPT, OPT, OPT, ULTRA, ULTRA, ULTRA, ULTRA, ULTRA]


def is_error(r):
    """FL2_isError: code > (size_t)-FL2_error_maxCode."""
    return r > SIZE_MAX + 1 - MAX_CODE


def error_of(r):
    return SIZE_MAX + 1 - r if is_error(r) else NO_ERROR


class Fl2Error(Exception):
    def __init__(self, fn, code):
        Exception.__init__(self, "%s: FL2 error %d" % (fn, code))
        self.code = code


def dict_size_from_prop(p):
    """lzma2_dec.c LZMA2_getDictSizeFromProp, for the low six bits of a frame's first byte."""
    p &= 0x3F
    return 0xFFFFFFFF if p >= 40 else (2 | (p & 1)) << (p // 2 + 11)


def dict_prop(size):
    """lzma2_enc.c LZMA2_getDictSizeProp: the smallest property whose dictionary holds size."""
    for bit in range(11, 32):
        if 2 << bit >= size:
            return (bit - 11) << 1
        if 3 << bit >= size:
            return ((bit - 11) << 1) | 1
    return 40


_P1, _P2, _P3, _P4, _P5 = 2654435761, 2246822519, 3266489917, 668265263, 374761393
_M = 0xFFFFFFFF


def _rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & _M


def xxh32(data, seed=0):
    """XXH32, pure Python (slow: keep it to small inputs)."""
    n, i = len(data), 0
    if n >= 16:
        v = [(seed + _P1 + _P2) & _M, (seed + _P2) & _M, seed & _M, (seed - _P1) & _M]
        while i <= n - 16:
            lanes = struct.unpack_from("<4I", data, i)
            v = [_rotl((v[k] + lanes[k] * _P2) & _M, 13) * _P1 & _M for k in range(4)]
            i += 16
        h = (_rotl(v[0], 1) + _rotl(v[1], 7) + _rotl(v[2], 12) + _rotl(v[3], 18)) & _M
    else:
        h = (seed + _P5) & _M
    h = (h + n) & _M
    while i + 4 <= n:
        h = _rotl((h + struct.unpack_from("<I", data, i)[0] * _P3) & _M, 17) * _P4 & _M
        i += 4
    while i < n:
        h = _rotl((h + data[i] * _P5) & _M, 11) * _P1 & _M
        i += 1
    h ^= h >> 15
    h = h * _P2 & _M
    h ^= h >> 13
    h = h * _P3 & _M
    h ^= h >> 16
    return h


def liblzma_decode(frame, props=True):
    """liblzma's reading of a frame (props=False: a bare LZMA2 stream, as FL2_p_omitProperties writes): the data and
    whatever follows the LZMA2 end marker. Raises lzma.LZMAError if liblzma rejects it, EOFError if it's cut short."""
    dsize = dict_size_from_prop(frame[0]) if props else 1 << 30
    d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2,
                                                         "dict_size": max(4096, min(dsize, 1 << 30))}])
    out = d.decompress(frame[1:] if props else frame)
    if not d.eof:
        raise EOFError("no LZMA2 end marker")
    return out, d.unused_data


def liblzma_encode(data, preset=6):
    """A bare LZMA2 stream from liblzma, and the frame FL2's decoder reads it as (a property byte, no hash)."""
    raw = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "preset": preset}])
    # xz's preset dictionary sizes (liblzma lzma_lzma_preset)
    dsize = [256 << 10, 1 << 20, 2 << 20, 4 << 20, 4 << 20, 8 << 20, 8 << 20, 16 << 20, 32 << 20, 64 << 20][preset & 15]
    return raw, bytes([dict_prop(dsize)]) + raw


class _In(object):
    """Bytes at a fixed address."""

    def __init__(self, data):
        self.keep = ctypes.create_string_buffer(bytes(data), max(1, len(data)))
        self.addr, self.n = ctypes.addressof(self.keep), len(data)


class Api(object):
    """fast-lzma2's API on one library (GrindCore, or an official build)."""

    def __init__(self, L, label):
        self.L, self.label = L, label

    def call(self, name, *args):
        return getattr(self.L, name)(*args)

    def check(self, name, *args):
        r = self.call(name, *args)
        if is_error(r):
            raise Fl2Error(name, error_of(r))
        return r

    def compress(self, data, level=6, threads=1, capacity=None):
        """FL2_compressMt (FL2_compress when threads == 1)."""
        src = _In(data)
        cap = self.call("FL2_compressBound", len(data)) if capacity is None else capacity
        dst = ctypes.create_string_buffer(max(1, cap))
        if threads == 1:
            n = self.check("FL2_compress", dst, cap, src.addr, src.n, level)
        else:
            n = self.check("FL2_compressMt", dst, cap, src.addr, src.n, level, threads)
        return dst.raw[:n]

    def cctx(self, threads=1):
        return CCtx(self, threads)

    def decompress(self, frame, capacity, threads=1):
        """FL2_decompressMt into a buffer of exactly `capacity` (plus a guard that must stay untouched)."""
        src = _In(frame)
        guard = b"\xa5" * 64
        dst = ctypes.create_string_buffer(capacity + len(guard))
        ctypes.memmove(ctypes.addressof(dst) + capacity, guard, len(guard))
        r = self.call("FL2_decompressMt", dst, capacity, src.addr, src.n, threads)
        if dst.raw[capacity:] != guard:
            raise AssertionError("%s: FL2_decompressMt wrote past its capacity" % self.label)
        if is_error(r):
            raise Fl2Error("FL2_decompressMt", error_of(r))
        return dst.raw[:r]

    def find_size(self, frame):
        src = _In(frame)
        return self.call("FL2_findDecompressedSize", src.addr, src.n)

    def cstream(self, threads=1, dual=0):
        return CStream(self, threads, dual)

    def dstream(self, threads=1):
        return DStream(self, threads)

    def dctx(self, threads=1):
        return DCtx(self, threads)


class CCtx(object):
    def __init__(self, api, threads=1):
        self.api = api
        self.c = api.call("FL2_createCCtxMt", threads)
        if not self.c:
            raise MemoryError("FL2_createCCtxMt")

    def set(self, param, value):
        return self.api.call("FL2_CCtx_setParameter", self.c, param, value)

    def get(self, param):
        return self.api.call("FL2_CCtx_getParameter", self.c, param)

    def compress(self, data, level=0, capacity=None, src=None):
        """FL2_compressCCtx; level 0 keeps the parameters already set. `src`: an address to use instead of a copy."""
        keep = None if src is not None else _In(data)
        addr = src if src is not None else keep.addr
        cap = self.api.call("FL2_compressBound", len(data)) if capacity is None else capacity
        dst = ctypes.create_string_buffer(max(1, cap))
        n = self.api.check("FL2_compressCCtx", self.c, dst, cap, addr, len(data), level)
        return dst.raw[:n]

    def close(self):
        if self.c:
            self.api.call("FL2_freeCCtx", self.c)
            self.c = None


class CStream(object):
    """FL2_CStream driven the way the API documents: every call gets an output buffer, and flush/end repeat until
    they return 0 (nothing left to write)."""

    def __init__(self, api, threads=1, dual=0, out_step=1 << 16):
        self.api, self.L = api, api.L
        self.s = (api.call("FL2_createCStream") if threads == 1 and not dual
                  else api.call("FL2_createCStreamMt", threads, dual))
        if not self.s:
            raise MemoryError("FL2_createCStream")
        self.out = ctypes.create_string_buffer(out_step)
        self.ob = self.L.struct.FL2_outBuffer()
        self.ib = self.L.struct.FL2_inBuffer()
        self.calls = 0

    def set(self, param, value):
        return self.api.call("FL2_CStream_setParameter", self.s, param, value)

    def get(self, param):
        return self.api.call("FL2_CStream_getParameter", self.s, param)

    def init(self, level=0):
        return self.api.check("FL2_initCStream", self.s, level)

    def _out(self):
        self.ob.dst, self.ob.size, self.ob.pos = ctypes.addressof(self.out), len(self.out), 0

    def write(self, data, max_calls=1 << 20):
        src = _In(data)
        self.ib.src, self.ib.size, self.ib.pos = src.addr, src.n, 0
        got = bytearray()
        while True:
            self._out()
            r = self.api.check("FL2_compressStream", self.s, ctypes.addressof(self.ob), ctypes.addressof(self.ib))
            self.calls += 1
            got += self.out.raw[:self.ob.pos]
            if self.ib.pos == self.ib.size and r == 0:
                return bytes(got)
            if self.calls > max_calls:
                raise AssertionError("FL2_compressStream: no end after %d calls" % max_calls)

    def _drain(self, name, max_calls=1 << 20):
        got = bytearray()
        for _ in range(max_calls):
            self._out()
            r = self.api.check(name, self.s, ctypes.addressof(self.ob))
            self.calls += 1
            got += self.out.raw[:self.ob.pos]
            if r == 0:
                return bytes(got)
        raise AssertionError("%s: still not done after %d calls" % (name, max_calls))

    def flush(self):
        """FL2_flushStream until it returns 0, then, while FL2_waitCStream says output is pending, again. A
        double-buffered stream needs the second step: its flush hands the block to the background thread and returns
        0 before any of the block's output exists (FL2_compressCurBlock resets threadCount to 0; the header promises
        1 while output remains). Single-buffered streams never take it."""
        got = bytearray()
        while True:
            got += self._drain("FL2_flushStream")
            if self.api.check("FL2_waitCStream", self.s) == 0:
                return bytes(got)

    def end(self):
        return self._drain("FL2_endStream")

    def compress(self, data, chunk=1 << 20, flush_every=False):
        out = bytearray()
        for i in range(0, len(data), chunk):
            out += self.write(data[i:i + chunk])
            if flush_every:
                out += self.flush()
        return bytes(out + self.end())

    def close(self):
        if self.s:
            self.api.call("FL2_freeCStream", self.s)
            self.s = None


class DStream(object):
    """FL2_DStream, fed `in_step` bytes at a time into an `out_step` buffer."""

    def __init__(self, api, threads=1):
        self.api, self.L = api, api.L
        self.s = api.call("FL2_createDStream") if threads == 1 else api.call("FL2_createDStreamMt", threads)
        if not self.s:
            raise MemoryError("FL2_createDStream")
        api.check("FL2_initDStream", self.s)
        self.ob = self.L.struct.FL2_outBuffer()
        self.ib = self.L.struct.FL2_inBuffer()

    def init(self, prop=None):
        """FL2_initDStream, or FL2_initDStream_withProp for a stream written with FL2_p_omitProperties."""
        if prop is None:
            return self.api.check("FL2_initDStream", self.s)
        return self.api.check("FL2_initDStream_withProp", self.s, prop)

    def call(self, src, pos, n, out):
        """One FL2_decompressStream over src[pos:pos+n] into `out`: (raw result, bytes consumed, bytes written)."""
        self.ib.src, self.ib.size, self.ib.pos = src.addr + pos, n, 0
        self.ob.dst, self.ob.size, self.ob.pos = ctypes.addressof(out), len(out), 0
        r = self.api.call("FL2_decompressStream", self.s, ctypes.addressof(self.ob), ctypes.addressof(self.ib))
        return r, self.ib.pos, self.ob.pos

    def decode(self, frame, in_step=1 << 16, out_step=1 << 16, max_calls=1 << 22):
        """Decode until FL2_decompressStream returns 0 (frame done): (data, bytes of the frame consumed). An error
        raises Fl2Error; running out of input before the end raises EOFError."""
        src, out, got, pos = _In(frame), ctypes.create_string_buffer(out_step), bytearray(), 0
        for _ in range(max_calls):
            n = min(in_step, len(frame) - pos)
            r, used, wrote = self.call(src, pos, n, out)
            pos += used
            got += out.raw[:wrote]
            if is_error(r):
                raise Fl2Error("FL2_decompressStream", error_of(r))
            if r == 0:
                return bytes(got), pos
            if pos == len(frame) and used == 0 and wrote == 0:
                raise EOFError("input ended before the frame did")
        raise AssertionError("FL2_decompressStream: no end after %d calls" % max_calls)

    def close(self):
        if self.s:
            self.api.call("FL2_freeDStream", self.s)
            self.s = None


class DictBuffer(ctypes.Structure):
    """FL2_dictBuffer: its size is `unsigned long` (fast-lzma2.h:218), 4 bytes on Windows and 8 on Linux and macOS.
    The generated spec, parsed on Windows, has 32 bits, so this is declared here with c_ulong. (GrindCore.net's
    FL2DictBuffer uses nuint, which is wrong on Windows; it's unused.)"""
    _fields_ = [("dst", ctypes.c_void_p), ("size", ctypes.c_ulong)]


class CBuffer(ctypes.Structure):
    _fields_ = [("src", ctypes.c_void_p), ("size", ctypes.c_size_t)]


class DCtx(object):
    """FL2_DCtx for the one-shot decoder, reusable across frames."""

    def __init__(self, api, threads=1):
        self.api = api
        self.d = api.call("FL2_createDCtx") if threads == 1 else api.call("FL2_createDCtxMt", threads)
        if not self.d:
            raise MemoryError("FL2_createDCtx")

    def init(self, prop):
        return self.api.check("FL2_initDCtx", self.d, prop)

    def decompress(self, frame, capacity):
        src = _In(frame)
        guard = b"\x5a" * 64
        dst = ctypes.create_string_buffer(capacity + len(guard))
        ctypes.memmove(ctypes.addressof(dst) + capacity, guard, len(guard))
        r = self.api.call("FL2_decompressDCtx", self.d, dst, capacity, src.addr, src.n)
        if dst.raw[capacity:] != guard:
            raise AssertionError("FL2_decompressDCtx wrote past its capacity")
        if is_error(r):
            raise Fl2Error("FL2_decompressDCtx", error_of(r))
        return dst.raw[:r]

    def close(self):
        if self.d:
            self.api.call("FL2_freeDCtx", self.d)
            self.d = None


def grindcore(L):
    return Api(L, "GrindCore")


# ------------------------------------------------------------------------------------------ official fast-lzma2

REF_ERROR = []


def reference(version="1.0.1"):
    """Official fast-lzma2 from $GC_REF_FL2 (libfl2ref-<version>), or None. One that is there but won't load (built for
    a newer glibc, say) is None too, with the reason in REF_ERROR."""
    d = os.environ.get("GC_REF_FL2")
    if not d:
        return None
    ext = ".dylib" if sys.platform == "darwin" else ".dll" if sys.platform == "win32" else ".so"
    path = os.path.join(d, "libfl2ref-%s%s" % (version, ext))
    if not os.path.exists(path):
        return None
    try:
        return Api(gcnative.load(path), "official %s" % version)
    except OSError as e:
        REF_ERROR.append("%s: %s" % (path, e))
        return None


# ------------------------------------------------------------------------------------------ guard pages

PAGE = mmap.PAGESIZE


class Guarded(object):
    """`data` placed to end exactly where a no-access page begins, so a read past its end faults."""

    def __init__(self, data):
        n = (len(data) + PAGE - 1) // PAGE + 1
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
        self.addr = base + n * PAGE - len(data)
        ctypes.memmove(self.addr, bytes(data), len(data))
