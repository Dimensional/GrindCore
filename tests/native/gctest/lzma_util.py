"""Shared by the LZMA/LZMA2 encoder tests and the child processes they start. GrindCore's encoders are driven the way
GrindCore.net drives them; Python's own lzma module is the independent decoder.

  LZMA2 stream: Lzma2Encoder in solid mode (Lzma2Encoder.cs:45-170, 247-325), 0x00 end marker from Lzma2Stream.
  LZMA stream:  LzmaEncoder's multi-call API (LzmaEncoder.cs:106-141, 205), the only code that sets multicallMode.
  LZMA block:   LzmaBlock (LzmaBlock.cs:151-190): Create, SetProps, SetDataSize, WriteProperties, MemEncode.

multicallMode (audit/lzma.md 3.3) is a field of 7-Zip's CLzmaEnc, which isn't in any header. Nothing here depends on a
build's debug info or on recorded offsets, so the tests run on any RID and any build configuration:
  - offsetof(CLzmaEnc, multicallMode) differs by OS (the struct embeds the OS's thread and sync objects: 0x1C4A8 on
    win-arm64 up to 0x208A8 on osx-x64). find_mode_offset finds it by behaviour, reading only inside the encoder's
    heap block (alloc_end).
  - offsetof(CLzma2Enc, coders) comes from the struct's definition (Lzma2Enc.c:357-368), laid out by ctypes with this
    platform's C rules, and is checked by asking the encoder found there for its properties (verify_offsets)."""
import ctypes
import random
import struct
import sys

try:
    import lzma
except ImportError:  # some minimal Pythons are built without it
    lzma = None

RING = 0x400000 + 8          # Lzma2Encoder's solid-mode input buffer: 4 MiB + 8
OUT_CHUNK = 1 << 20
MODE_START = 0x10000         # where the multicallMode search starts; it's the last field of a ~115 KiB struct
ALLOC_ALIGN = 1 << 7         # Alloc.c:414 ALLOC_ALIGN_SIZE
_mode_offset = None


# ---------- memory: heap block bounds, struct offsets ----------

def _usable_size(block):
    """The C runtime's size for a heap block it returned (the block may be larger than asked for), or None."""
    if sys.platform.startswith("win"):  # UCRT's malloc allocates from the process heap
        k = ctypes.WinDLL("kernel32")
        k.GetProcessHeap.restype = ctypes.c_void_p
        k.HeapSize.restype, k.HeapSize.argtypes = ctypes.c_size_t, [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        n = k.HeapSize(k.GetProcessHeap(), 0, block)
        return None if n == ctypes.c_size_t(-1).value else n
    libc = ctypes.CDLL("libSystem.B.dylib" if sys.platform == "darwin" else None)
    fn = getattr(libc, "malloc_size" if sys.platform == "darwin" else "malloc_usable_size")
    fn.restype, fn.argtypes = ctypes.c_size_t, [ctypes.c_void_p]
    return fn(block) or None


def alloc_end(aligned):
    """End of the heap block behind a g_AlignedAlloc pointer. Alloc.c:416-459: either malloc with the real block
    pointer stored just below the aligned one (always on Windows), or posix_memalign (the pointer is the block).
    Off Windows the posix_memalign case is tried first: reading below a posix_memalign block would read heap
    metadata (harmless, but Valgrind rightly flags it). macOS's malloc_size returns 0 for a pointer that isn't a
    block, so trying it there is safe either way."""
    if not sys.platform.startswith("win"):
        n = _usable_size(aligned)
        if n and MODE_START < n < (1 << 26):
            return aligned + n
    real = ctypes.c_void_p.from_address(aligned - ctypes.sizeof(ctypes.c_void_p)).value
    if real and 0 < aligned - real <= ALLOC_ALIGN + ctypes.sizeof(ctypes.c_void_p):
        n = _usable_size(real)
        if n:
            return real + n
    if sys.platform.startswith("win"):
        return None
    n = _usable_size(aligned)
    return aligned + n if n else None


class _Lzma2EncInt(ctypes.Structure):  # Lzma2Enc.c:81-89
    _fields_ = [("enc", ctypes.c_void_p), ("propsAreSet", ctypes.c_ubyte), ("propsByte", ctypes.c_ubyte),
                ("needInitState", ctypes.c_ubyte), ("needInitProp", ctypes.c_ubyte), ("srcPos", ctypes.c_uint64)]


def coders_offset(L):
    """offsetof(CLzma2Enc, coders): the fields in front of it (Lzma2Enc.c:357-368), laid out by ctypes."""
    class Head(ctypes.Structure):
        _fields_ = [("propEncoded", ctypes.c_ubyte), ("props", L.struct.CLzma2EncProps),
                    ("expectedDataSize", ctypes.c_uint64), ("tempBufLzma", ctypes.c_void_p),
                    ("alloc", ctypes.c_void_p), ("allocBig", ctypes.c_void_p), ("coders0", _Lzma2EncInt)]
    return Head.coders0.offset


def inner_encoder(L, enc):
    """The LZMA2 stream encoder's one CLzmaEnc (coders[0].enc), after EncodeMultiCallPrepare."""
    return ctypes.c_void_p.from_address(enc + coders_offset(L)).value


def mode_address(lzma_enc):
    return lzma_enc + _mode_offset


# ---------- data and the independent decoder ----------

def data(n, seed=7):
    """Text-like data, mostly compressible (LZMA chunks, which end with the range coder flush the defect skips), with
    an occasional short random stretch."""
    r = random.Random(seed)
    words = [b"grindcore", b"lzma2", b"stream", b"chunk", b"range", b"coder", b"flush", b"\n", b"multicall"]
    out = bytearray()
    while len(out) < n:
        if r.random() < 0.0005:
            out += bytes(r.getrandbits(8) for _ in range(r.randrange(16, 256)))
        else:
            out += r.choice(words) + b" "
    return bytes(out[:n])


def dict_size(prop):
    """LZMA2's one-byte dictionary property -> bytes (the xz/7-Zip definition)."""
    return 0xFFFFFFFF if prop == 40 else (2 | (prop & 1)) << (prop // 2 + 11)


def py_decode(stream, prop):
    """Raw LZMA2 -> (decoded bytes or None, error text or None) with Python's own decoder."""
    d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                              filters=[{"id": lzma.FILTER_LZMA2, "dict_size": max(4096, min(dict_size(prop), 1 << 30))}])
    try:
        out = d.decompress(stream)
    except lzma.LZMAError as e:
        return None, str(e)
    return out, (None if d.eof else "no end of stream")


def py_decode_alone(stream):
    """.lzma ("alone": 5 property bytes, 8-byte size, data) -> (decoded bytes or None, error text or None)."""
    try:
        return lzma.decompress(stream, format=lzma.FORMAT_ALONE), None
    except lzma.LZMAError as e:
        return None, str(e)


# ---------- the encoders, as GrindCore.net uses them ----------

def props_for(L, level):
    """CLzma2EncProps as Lzma2Encoder builds it for one thread, solid."""
    p = L.struct.CLzma2EncProps()
    L.SZ_Lzma2_v25_01_Enc_Construct(ctypes.byref(p))
    p.lzmaProps.level = level
    p.lzmaProps.numThreads = -1
    p.numBlockThreads_Max = 1
    p.numBlockThreads_Reduced = -1
    p.numTotalThreads = 1
    p.blockSize = (1 << 64) - 1
    L.SZ_Lzma2_v25_01_Enc_Normalize(ctypes.byref(p))
    return p


def encode(L, payload, level=1, force=None):
    """One LZMA2 stream, solid, the whole payload buffered then drained, 0x00 end marker appended as Lzma2Stream does
    (Lzma2Stream.cs:228). force = a multicallMode value written into the inner encoder right after Prepare.
    Returns dict(rc, prop, stream, inner)."""
    enc = L.SZ_Lzma2_v25_01_Enc_Create()
    try:
        props = props_for(L, level)
        rc = L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(props))
        if rc:
            return {"rc": rc, "prop": None, "stream": b"", "inner": None}
        prop = L.SZ_Lzma2_v25_01_Enc_WriteProperties(enc)
        rc = L.SZ_Lzma2_v25_01_Enc_EncodeMultiCallPrepare(enc)
        if rc:
            return {"rc": rc, "prop": prop, "stream": b"", "inner": None}
        inner = inner_encoder(L, enc)
        if force is not None:
            ctypes.c_uint32.from_address(mode_address(inner)).value = force
        ring = ctypes.create_string_buffer(RING)
        ctypes.memmove(ring, payload, len(payload))
        s = L.struct.CBufferInStream()
        s.buffer, s.size, s.pos, s.remaining = ctypes.addressof(ring), RING, 0, len(payload)
        out, ob = bytearray(), ctypes.create_string_buffer(OUT_CHUNK)
        for _ in range(100000):  # Lzma2Encoder's final drain: until a call produces nothing
            n = ctypes.c_size_t(OUT_CHUNK)
            rc = L.SZ_Lzma2_v25_01_Enc_EncodeMultiCall(enc, ob, ctypes.byref(n), ctypes.byref(s), 0)
            out += ob.raw[:n.value]
            if rc or n.value == 0:
                break
        return {"rc": rc, "prop": prop, "stream": bytes(out) + b"\x00", "inner": inner}
    finally:
        L.SZ_Lzma2_v25_01_Enc_Destroy(enc)


def lzma_props(L, level=5, dict_bytes=1 << 16):
    p = L.struct.CLzmaEncProps()
    L.SZ_Lzma_v25_01_EncProps_Init(ctypes.byref(p))
    p.level, p.dictSize, p.numThreads = level, dict_bytes, 1
    return p


def block_encode(L, payload, level=5, force=None, before=None):
    """One LZMA block as LzmaBlock encodes it, with an end mark, returned as .lzma ("alone", unknown size) for
    py_decode_alone. force = a multicallMode value written in before MemEncode; before(enc) runs just before it, so a
    caller can log the encoder's address ahead of a call that may never return. Returns dict(rc, stream, address)."""
    props = lzma_props(L, level, 1 << 20)
    enc = L.SZ_Lzma_v25_01_Enc_Create()
    try:
        rc = L.SZ_Lzma_v25_01_Enc_SetProps(enc, ctypes.byref(props))
        if rc:
            return {"rc": rc, "stream": b"", "address": enc}
        L.SZ_Lzma_v25_01_Enc_SetDataSize(enc, len(payload))
        pb, pn = ctypes.create_string_buffer(8), ctypes.c_size_t(5)
        L.SZ_Lzma_v25_01_Enc_WriteProperties(enc, pb, ctypes.byref(pn))
        if force is not None:
            ctypes.c_uint32.from_address(mode_address(enc)).value = force
        if before:
            before(enc)
        dst = ctypes.create_string_buffer(len(payload) + len(payload) // 2 + 1024)
        dlen = ctypes.c_size_t(len(dst))
        rc = L.SZ_Lzma_v25_01_Enc_MemEncode(enc, dst, ctypes.byref(dlen), payload, len(payload), 1, None)
        header = pb.raw[:pn.value] + struct.pack("<Q", (1 << 64) - 1)
        return {"rc": rc, "stream": header + dst.raw[:dlen.value], "address": enc}
    finally:
        L.SZ_Lzma_v25_01_Enc_Destroy(enc)


class _LzmaStream(object):
    """An LZMA stream encoder on the multi-call API, which sets multicallMode (1 prepare, 2 mid-stream, 3 final)."""

    def __init__(self, L, seed=3):
        self.L = L
        props = lzma_props(L)
        self.enc = L.SZ_Lzma_v25_01_Enc_Create()
        L.SZ_Lzma_v25_01_Enc_SetProps(self.enc, ctypes.byref(props))
        bs, self.ds = ctypes.c_uint32(0), ctypes.c_uint32(0)
        L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCallPrepare(self.enc, ctypes.byref(bs), ctypes.byref(self.ds), 0)
        size, n = bs.value + 8, self.ds.value
        self.buf = ctypes.create_string_buffer(size)
        ctypes.memmove(self.buf, data(n, seed), n)
        self.s = L.struct.CBufferInStream()
        self.s.buffer, self.s.size, self.s.pos, self.s.remaining = ctypes.addressof(self.buf), size, 0, n
        self.out = ctypes.create_string_buffer(2 * n + 1024)

    def call(self, final):
        olen, avail = ctypes.c_size_t(len(self.out)), ctypes.c_uint32(0)
        return self.L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCall(self.enc, self.out, ctypes.byref(olen), ctypes.byref(self.s),
                                                           self.ds.value, ctypes.byref(avail), 1 if final else 0)

    def destroy(self):
        self.L.SZ_Lzma_v25_01_Enc_Destroy(self.enc)


class TooManyCalls(Exception):
    pass


class LzmaStreamEncoder(object):
    """A port of GrindCore.net's LzmaEncoder (LzmaEncoder.cs:100-245): the multi-call API fed through its circular
    input buffer, one BlockSize (= the dictionary size) per call, then drained with final calls. `calls` counts the
    native calls; past max_calls, TooManyCalls is raised (audit/lzma.md 3.5: a stalled encoder takes one call per
    symbol)."""

    def __init__(self, L, level=5, dict_bytes=1 << 20, max_calls=None):
        self.L = L
        self.calls, self.max_calls = 0, max_calls
        props = lzma_props(L, level, dict_bytes)
        self.enc = L.SZ_Lzma_v25_01_Enc_Create()
        L.SZ_Lzma_v25_01_Enc_SetProps(self.enc, ctypes.byref(props))
        pb, pn = ctypes.create_string_buffer(8), ctypes.c_size_t(5)
        L.SZ_Lzma_v25_01_Enc_WriteProperties(self.enc, pb, ctypes.byref(pn))
        self.props = pb.raw[:pn.value]
        self.end_mark = bool(L.SZ_Lzma_v25_01_Enc_IsWriteEndMark(self.enc))
        bs, ds = ctypes.c_uint32(0), ctypes.c_uint32(0)
        L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCallPrepare(self.enc, ctypes.byref(bs), ctypes.byref(ds), 0)
        self.block = ds.value
        self.ring = ctypes.create_string_buffer(bs.value + 8)
        self.s = L.struct.CBufferInStream()
        self.s.buffer, self.s.size = ctypes.addressof(self.ring), bs.value + 8
        self.out = ctypes.create_string_buffer(2 * (bs.value + 8) + (1 << 16))
        self.to_flush = 0

    def encode_data(self, data, final):
        """LzmaEncoder.EncodeData: data is everything the caller has now; returns the compressed bytes produced."""
        s, pos, produced, n_last = self.s, 0, bytearray(), 0
        while len(data) - pos != 0 or final:
            if s.pos == s.size:
                s.pos = 0
            p = (s.pos + s.remaining) % s.size
            size = min(len(data) - pos, s.size - s.remaining)
            end = s.size - p
            first = min(size, end)
            ctypes.memmove(ctypes.addressof(self.ring) + p, data[pos:pos + first], first)
            if size > end:
                ctypes.memmove(self.ring, data[pos + first:pos + size], size - end)
            pos += size
            s.remaining += size
            remaining = s.remaining + self.to_flush
            if not final and remaining < self.block:
                break
            finalfinal = final and remaining == 0
            while True:
                n, avail = ctypes.c_size_t(len(self.out)), ctypes.c_uint32(0)
                rc = self.L.SZ_Lzma_v25_01_Enc_LzmaCodeMultiCall(self.enc, self.out, ctypes.byref(n), ctypes.byref(s),
                                                                 0 if final else self.block, ctypes.byref(avail),
                                                                 1 if finalfinal else 0)
                if rc:
                    raise RuntimeError("LzmaCodeMultiCall returned %d" % rc)
                self.calls += 1
                if self.max_calls and self.calls > self.max_calls:
                    raise TooManyCalls(self.calls)
                produced += ctypes.string_at(self.out, n.value)
                self.to_flush, n_last = avail.value, n.value
                if n.value == 0 or (not final and s.remaining + self.to_flush < self.block):
                    break
            if final and (n_last != 0 or self.to_flush == 0):
                break
        return bytes(produced)

    def destroy(self):
        self.L.SZ_Lzma_v25_01_Enc_Destroy(self.enc)


def lzma_stream_encode(L, payload, write_size=64 << 10):
    """A whole LZMA stream as LzmaStream would produce it: the payload written in write_size pieces, then final calls
    until one produces nothing. Returns (5 property bytes, raw LZMA stream, whether it ends with an end mark)."""
    e = LzmaStreamEncoder(L)
    try:
        out = bytearray()
        for i in range(0, len(payload), write_size):
            out += e.encode_data(payload[i:i + write_size], final=False)
        for _ in range(64):
            chunk = e.encode_data(b"", final=True)
            out += chunk
            if not chunk:
                break
        return e.props, bytes(out), e.end_mark
    finally:
        e.destroy()


def lzma_stream_abandoned(L, seed=3):
    """An LZMA stream encoder destroyed after one mid-stream call: the real-API way a CLzmaEnc gets freed with
    multicallMode == 2 (lzma.md 3.3, evidence 3). Returns (address it had, multicallMode it was freed with or None)."""
    st = _LzmaStream(L, seed)
    st.call(final=False)
    mode = ctypes.c_uint32.from_address(mode_address(st.enc)).value if _mode_offset is not None else None
    st.destroy()
    return st.enc, mode


# ---------- finding and checking the offsets ----------

def find_mode_offset(L):
    """offsetof(CLzmaEnc, multicallMode), found by behaviour: the only 32-bit field that reads 1 after the multi-call
    Prepare, 2 after a mid-stream call and 3 after the final call, searched from MODE_START to the end of the
    encoder's heap block. Returns (offset or None, why)."""
    global _mode_offset
    st = _LzmaStream(L)
    try:
        end = alloc_end(st.enc)
        if end is None:
            return None, "multicallMode: the encoder's heap block size couldn't be determined"
        size = (end - st.enc - MODE_START) // 4 * 4
        snap = lambda: struct.unpack("<%dI" % (size // 4), ctypes.string_at(st.enc + MODE_START, size))
        after_prepare = snap()
        st.call(final=False)
        mid = snap()
        st.call(final=True)
        final = snap()
    finally:
        st.destroy()
    hits = [MODE_START + 4 * i for i in range(size // 4) if (after_prepare[i], mid[i], final[i]) == (1, 2, 3)]
    if len(hits) != 1:
        return None, "multicallMode: %d fields in %#x-%#x read 1, 2, 3 across the calls" % (
            len(hits), MODE_START, MODE_START + size)
    _mode_offset = hits[0]
    return _mode_offset, None


def verify_offsets(L, lzma2=True):
    """None if the offsets the tests need are known for this library, else why not. multicallMode: find_mode_offset.
    With lzma2, coders[0].enc must also be an encoder whose LZMA properties byte is the LZMA2 default
    (lc=3 lp=0 pb=2 -> 0x5D)."""
    off, why = find_mode_offset(L)
    if why or not lzma2:
        return why
    enc = L.SZ_Lzma2_v25_01_Enc_Create()
    try:
        L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(props_for(L, 1)))
        L.SZ_Lzma2_v25_01_Enc_EncodeMultiCallPrepare(enc)
        inner = inner_encoder(L, enc)
        pb, pn = ctypes.create_string_buffer(8), ctypes.c_size_t(5)
        rc = L.SZ_Lzma_v25_01_Enc_WriteProperties(inner, pb, ctypes.byref(pn)) if inner else -1
    finally:
        L.SZ_Lzma2_v25_01_Enc_Destroy(enc)
    if rc != 0 or pn.value != 5 or pb.raw[0] != 0x5D:
        return "coders offset %#x: WriteProperties on it gave rc=%s, %d bytes, first %#x" % (
            coders_offset(L), rc, pn.value, pb.raw[0])
    return None
