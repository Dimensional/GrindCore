"""Helpers for test_brotli.py: GrindCore's Brotli PAL (DN9_BRT_v1_1_0_*, twelve pass-throughs) and official Brotli
1.1.0 driven through the same calls, so their results can be compared byte for byte.

The two sides share one wrapper (Api): the PAL by its DN9_BRT_v1_1_0_ names, the reference by Brotli's own. Brotli's
output depends on the call sequence as well as the data (quality 0 and 1 compress each input chunk as it arrives), so
comparisons always make the same calls with the same chunk sizes on both sides."""
import ctypes
import ctypes.util
import os
import sys

# BrotliDecoderResult (decode.h)
ERROR, SUCCESS, NEEDS_MORE_INPUT, NEEDS_MORE_OUTPUT = 0, 1, 2, 3
# BrotliEncoderOperation, BrotliEncoderMode, BrotliEncoderParameter (encode.h)
PROCESS, FLUSH, FINISH, EMIT_METADATA = 0, 1, 2, 3
GENERIC, TEXT, FONT = 0, 1, 2
(MODE, QUALITY, LGWIN, LGBLOCK, DISABLE_LITERAL_CONTEXT_MODELING, SIZE_HINT, LARGE_WINDOW, NPOSTFIX, NDIRECT,
 STREAM_OFFSET) = range(10)
# BrotliDecoderParameter: the reference only (GrindCore exports no BrotliDecoderSetParameter; other-codecs.md 4.3)
DEC_DISABLE_RING_BUFFER_REALLOCATION, DEC_LARGE_WINDOW = 0, 1
MIN_WINDOW, MAX_WINDOW, LARGE_MAX_WINDOW, MIN_QUALITY, MAX_QUALITY = 10, 24, 30, 0, 11

PAL = "DN9_BRT_v1_1_0_"
FUNCTIONS = ("BrotliDecoderCreateInstance", "BrotliDecoderDecompress", "BrotliDecoderDecompressStream",
             "BrotliDecoderDestroyInstance", "BrotliDecoderIsFinished", "BrotliEncoderCompress",
             "BrotliEncoderCompressStream", "BrotliEncoderCreateInstance", "BrotliEncoderDestroyInstance",
             "BrotliEncoderHasMoreOutput", "BrotliEncoderMaxCompressedSize", "BrotliEncoderSetParameter")

# brotli_alloc_func and brotli_free_func (types.h) name no calling convention, so they take the build's default:
# GrindCore's win-x86 build compiles C with /Gz, which makes them __stdcall there (as the seekable zstd callbacks,
# hub row 17). test_brotli probes which one a library uses and sets this.
CALLBACK_STDCALL = False


def callback_types(stdcall=None):
    f = ctypes.WINFUNCTYPE if (CALLBACK_STDCALL if stdcall is None else stdcall) else ctypes.CFUNCTYPE
    return f(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t), f(None, ctypes.c_void_p, ctypes.c_void_p)


def max_compressed_size(n):
    """BrotliEncoderMaxCompressedSize in 1.1.0 (encode.c:1202): 2 + 4 bytes per 16 KiB + 4, and 2 for empty input."""
    if n == 0:
        return 2
    r = n + 2 + 4 * (n >> 14) + 3 + 1
    return r if r < 1 << (8 * ctypes.sizeof(ctypes.c_size_t)) else 0


def managed_max_compressed_length(n):
    """GrindCore.net's BrotliEncoder.GetMaxCompressedLength (BrotliEncoder.cs:164-180): Brotli 1.0's formula, 4 bytes
    per 16 MiB."""
    if n == 0:
        return 1
    tail = n & 0xFFFFFF
    return n + 2 + 4 * (n >> 24) + (4 if tail > 1 << 20 else 3) + 1


class _Buf(object):
    """Bytes at a fixed address (a ctypes buffer kept alive with its address)."""

    def __init__(self, data, size=None):
        self.keep = ctypes.create_string_buffer(bytes(data), max(size or len(data), 1))
        self.addr, self.n = ctypes.addressof(self.keep), len(data)


class Allocator(object):
    """A brotli_alloc_func/brotli_free_func pair over the C runtime's malloc/free that counts live blocks and can
    fail requests: the n-th (fail_at, 1-based) and every one after it, or with only=True just the n-th, or any of at
    least `limit` bytes. `opaque` must come back unchanged.

    A one-off failure matters: when every later request fails too, a later allocation's check reports it even if the
    failing site's own check is missing (as the encoder's ring buffer copy was, other-codecs.md 4.3.1)."""

    OPAQUE = 0x5EED

    def __init__(self, fail_at=None, stdcall=None, only=False, limit=None):
        crt = ctypes.cdll.msvcrt if sys.platform == "win32" else ctypes.CDLL(ctypes.util.find_library("c"))
        self.malloc, self.free = crt.malloc, crt.free
        self.malloc.restype, self.malloc.argtypes = ctypes.c_void_p, [ctypes.c_size_t]
        self.free.restype, self.free.argtypes = None, [ctypes.c_void_p]
        self.fail_at, self.requests, self.live, self.max_live, self.bad_opaque = fail_at, 0, set(), 0, 0
        self.only, self.limit, self.refused, self.unknown_frees = only, limit, 0, 0
        alloc_type, free_type = callback_types(stdcall)
        self.alloc_cb, self.free_cb = alloc_type(self._alloc), free_type(self._free)

    def _alloc(self, opaque, size):
        self.requests += 1
        if opaque != self.OPAQUE:
            self.bad_opaque += 1
        if ((self.fail_at is not None and (self.requests == self.fail_at if self.only else self.requests >= self.fail_at))
                or (self.limit is not None and size >= self.limit)):
            self.refused += 1
            return None
        p = self.malloc(size or 1)
        if p:
            self.live.add(p)
            self.max_live = max(self.max_live, len(self.live))
        return p

    def _free(self, opaque, p):
        if opaque != self.OPAQUE:
            self.bad_opaque += 1
        if p:
            if p in self.live:
                self.live.discard(p)
            else:
                self.unknown_frees += 1
            self.free(p)

    def args(self):
        return (ctypes.cast(self.alloc_cb, ctypes.c_void_p), ctypes.cast(self.free_cb, ctypes.c_void_p),
                ctypes.c_void_p(self.OPAQUE))


class Api(object):
    """Brotli's twelve functions, as GrindCore exports them or by the reference's own names."""

    def __init__(self, fn, label):
        self.fn, self.label = fn, label

    def compress(self, data, quality=11, lgwin=22, mode=GENERIC, capacity=None):
        """BrotliEncoderCompress: (ok, output or None, the encoded_size it reported)."""
        cap = max_compressed_size(len(data)) if capacity is None else capacity
        src, dst, n = _Buf(data), ctypes.create_string_buffer(max(cap, 1)), ctypes.c_size_t(cap)
        ok = self.fn("BrotliEncoderCompress")(quality, lgwin, mode, len(data), src.addr, ctypes.byref(n), dst)
        return ok, (dst.raw[:n.value] if ok else None), n.value

    def decompress(self, data, capacity):
        """BrotliDecoderDecompress: (result, output, the decoded_size it reported)."""
        src, dst, n = _Buf(data), ctypes.create_string_buffer(max(capacity, 1)), ctypes.c_size_t(capacity)
        r = self.fn("BrotliDecoderDecompress")(len(data), src.addr, ctypes.byref(n), dst)
        return r, dst.raw[:min(n.value, capacity)], n.value

    def max_compressed_size(self, n):
        return self.fn("BrotliEncoderMaxCompressedSize")(n)

    def encoder(self, params=None, allocator=None):
        return Encoder(self, params, allocator)

    def decoder(self, allocator=None):
        return Decoder(self, allocator)

    def round_trip(self, data, **kw):
        ok, out, _ = self.compress(data, **kw)
        return ok and self.decompress(out, len(data)) == (SUCCESS, data, len(data))


class Encoder(object):
    """A BrotliEncoderState. run() feeds (operation, data) steps, each until its input is consumed and, for FLUSH,
    FINISH and EMIT_METADATA, until nothing is left to output, with at most out_step bytes of room per call."""

    def __init__(self, api, params=None, allocator=None):
        self.api, self.allocator = api, allocator
        self.state = api.fn("BrotliEncoderCreateInstance")(*(allocator.args() if allocator else (None, None, None)))
        if not self.state:
            raise MemoryError("BrotliEncoderCreateInstance")
        for param, value in sorted((params or {}).items()):
            self.set(param, value)

    def set(self, param, value):
        return self.api.fn("BrotliEncoderSetParameter")(self.state, param, value)

    def has_more_output(self):
        return self.api.fn("BrotliEncoderHasMoreOutput")(self.state)

    def call(self, op, data, out_step):
        """One BrotliEncoderCompressStream call: (ok, output, bytes consumed, total_out)."""
        src, dst = _Buf(data), ctypes.create_string_buffer(max(out_step, 1))
        a_in, a_out = ctypes.c_size_t(len(data)), ctypes.c_size_t(out_step)
        n_in, n_out, total = ctypes.c_void_p(src.addr), ctypes.c_void_p(ctypes.addressof(dst)), ctypes.c_size_t(0)
        ok = self.api.fn("BrotliEncoderCompressStream")(self.state, op, ctypes.byref(a_in), ctypes.byref(n_in),
                                                        ctypes.byref(a_out), ctypes.byref(n_out), ctypes.byref(total))
        return ok, dst.raw[:out_step - a_out.value], len(data) - a_in.value, total.value

    def run(self, steps, out_step=1 << 16, max_calls=1 << 20):
        """(ok, output). Stops at the first call that returns BROTLI_FALSE."""
        out = []
        for op, data in steps:
            pos, calls = 0, 0
            while True:
                ok, chunk, used, _ = self.call(op, data[pos:], out_step)
                out.append(chunk)
                if not ok:
                    return False, b"".join(out)
                pos += used
                calls += 1
                if calls > max_calls:
                    raise RuntimeError("encoder made no progress")
                if pos >= len(data) and (op == PROCESS or not self.has_more_output()):
                    break
        return True, b"".join(out)

    def compress(self, data, chunk=1 << 16, out_step=1 << 16, flush_at=()):
        """PROCESS in chunks (with a FLUSH at each offset in flush_at), then FINISH."""
        cuts = sorted(set([c for c in range(chunk, len(data), chunk)] + [c for c in flush_at if 0 < c < len(data)]))
        steps, pos = [], 0
        for cut in cuts + [len(data)]:
            steps.append((PROCESS, data[pos:cut]))
            if cut in flush_at:
                steps.append((FLUSH, b""))
            pos = cut
        steps.append((FINISH, b""))
        return self.run(steps, out_step)

    def close(self):
        if self.state:
            self.api.fn("BrotliEncoderDestroyInstance")(self.state)
            self.state = None


class Decoder(object):
    """A BrotliDecoderState fed in_step bytes of input and out_step bytes of room per call."""

    def __init__(self, api, allocator=None):
        self.api, self.allocator = api, allocator
        self.state = api.fn("BrotliDecoderCreateInstance")(*(allocator.args() if allocator else (None, None, None)))
        if not self.state:
            raise MemoryError("BrotliDecoderCreateInstance")

    def finished(self):
        return self.api.fn("BrotliDecoderIsFinished")(self.state)

    def call(self, data, out_step):
        """One BrotliDecoderDecompressStream call: (result, output, bytes consumed, total_out)."""
        src, dst = _Buf(data), ctypes.create_string_buffer(max(out_step, 1))
        a_in, a_out = ctypes.c_size_t(len(data)), ctypes.c_size_t(out_step)
        n_in, n_out, total = ctypes.c_void_p(src.addr), ctypes.c_void_p(ctypes.addressof(dst)), ctypes.c_size_t(0)
        r = self.api.fn("BrotliDecoderDecompressStream")(self.state, ctypes.byref(a_in), ctypes.byref(n_in),
                                                         ctypes.byref(a_out), ctypes.byref(n_out), ctypes.byref(total))
        return r, dst.raw[:out_step - a_out.value], len(data) - a_in.value, total.value

    def decode(self, data, in_step=1 << 20, out_step=1 << 16, max_calls=1 << 22):
        """(last result, output, bytes of input consumed).

        NEEDS_MORE_INPUT doesn't mean all decoded output has been delivered: the decoder pushes what it has into the
        room given and returns NEEDS_MORE_INPUT even when that room ran out (decode.c, "pro-actively push output"),
        and BrotliDecoderHasMoreOutput, which would say so, isn't exported. So a call that filled the output is
        repeated with no new input until one returns less than a full buffer."""
        out, pos, r = [], 0, NEEDS_MORE_INPUT
        for _ in range(max_calls):
            r, chunk, used, _ = self.call(data[pos:pos + in_step], out_step)
            out.append(chunk)
            pos += used
            if r in (SUCCESS, ERROR) or (r == NEEDS_MORE_INPUT and pos >= len(data) and len(chunk) < out_step):
                break
        else:
            raise RuntimeError("decoder made no progress")
        return r, b"".join(out), pos

    def close(self):
        if self.state:
            self.api.fn("BrotliDecoderDestroyInstance")(self.state)
            self.state = None


def pal(L):
    return Api(lambda name: getattr(L, PAL + name), "GrindCore")


# ------------------------------------------------------------------------------------------------ official Brotli


def folder():
    return os.environ.get("GC_REF_BROTLI")


def fixtures():
    """{name: bytes} of Brotli's own test fixtures from $GC_REF_BROTLI/brotli-1.1.0-testdata, or None."""
    d = folder()
    d = d and os.path.join(d, "brotli-1.1.0-testdata")
    if not d or not os.path.isdir(d):
        return None
    out = {}
    for name in sorted(os.listdir(d)):
        with open(os.path.join(d, name), "rb") as f:
            out[name] = f.read()
    return out


REF_ERROR = []


def reference(version="1.1.0"):
    """Official Brotli from $GC_REF_BROTLI, or None. A library that is there but won't load (built for a newer glibc,
    say) is None too, with the reason in REF_ERROR."""
    d = folder()
    if not d:
        return None
    ext = ".dylib" if sys.platform == "darwin" else ".dll" if sys.platform == "win32" else ".so"
    path = os.path.join(d, "libbrotliref-%s%s" % (version, ext))
    if not os.path.exists(path):
        return None
    try:
        return Ref(path)
    except OSError as e:
        REF_ERROR.append("%s: %s" % (path, e))
        return None


class Ref(Api):
    """Official Brotli by its own names, plus the decoder functions GrindCore doesn't export."""

    def __init__(self, path):
        d = self.dll = ctypes.CDLL(path)
        self.path = path
        vp, sz, i, u32 = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_uint32
        for name, res, args in (
                ("BrotliDecoderCreateInstance", vp, [vp, vp, vp]),
                ("BrotliDecoderDecompress", i, [sz, vp, vp, vp]),
                ("BrotliDecoderDecompressStream", i, [vp, vp, vp, vp, vp, vp]),
                ("BrotliDecoderDestroyInstance", None, [vp]),
                ("BrotliDecoderIsFinished", i, [vp]),
                ("BrotliEncoderCompress", i, [i, i, i, sz, vp, vp, vp]),
                ("BrotliEncoderCompressStream", i, [vp, i, vp, vp, vp, vp, vp]),
                ("BrotliEncoderCreateInstance", vp, [vp, vp, vp]),
                ("BrotliEncoderDestroyInstance", None, [vp]),
                ("BrotliEncoderHasMoreOutput", i, [vp]),
                ("BrotliEncoderMaxCompressedSize", sz, [sz]),
                ("BrotliEncoderSetParameter", i, [vp, i, u32]),
                ("BrotliDecoderSetParameter", i, [vp, i, u32]),
                ("BrotliDecoderGetErrorCode", i, [vp]),
                ("BrotliDecoderErrorString", ctypes.c_char_p, [i]),
                ("BrotliEncoderIsFinished", i, [vp]),
                ("BrotliDecoderVersion", u32, []),
                ("BrotliEncoderVersion", u32, [])):
            fn = getattr(d, name)
            fn.restype, fn.argtypes = res, args
        Api.__init__(self, lambda name: getattr(d, name), "official")
