"""Deterministic test inputs for the codec tests, and buffers placed at a chosen alignment. Python 3.6 compatible."""
import ctypes
import random

WORDS = [b"grindcore", b"deflate", b"inflate", b"bzip2", b"window", b"block", b"stream", b"huffman", b"\n", b"zlib"]


def text(n, seed=1):
    """Compressible, text-like: words from a small vocabulary with an occasional random byte."""
    r = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        out += r.choice(WORDS) + (b" " if r.random() < 0.95 else bytes([r.randrange(256)]))
    return bytes(out[:n])


def noise(n, seed=2):
    """Incompressible."""
    return random.Random(seed).getrandbits(8 * n).to_bytes(n, "little") if n else b""


def runs(n, seed=3):
    """Long runs of a few byte values: the worst case for bzip2's block sort, and RLE-friendly for deflate."""
    r = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        out += bytes([r.choice(b"aab\x00")]) * r.randrange(1, 5000)
    return bytes(out[:n])


def mixed(n, seed=4):
    """Stretches of text, noise and runs, so one input exercises several block types."""
    r = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        k = r.randrange(1, 40000)
        out += r.choice((text, text, noise, runs))(k, r.randrange(1 << 30))
    return bytes(out[:n])


KINDS = (("text", text), ("noise", noise), ("runs", runs), ("mixed", mixed))


def placed(data, offset, align=32, extra=0):
    """Copy data to an address that is `offset` bytes past an `align`-byte boundary. Returns (buffer, address): keep
    the buffer alive while the address is in use. `extra` bytes of writable space follow the data."""
    buf = ctypes.create_string_buffer(len(data) + align + offset + extra + 1)
    addr = ((ctypes.addressof(buf) + align - 1) & ~(align - 1)) + offset
    ctypes.memmove(addr, data, len(data))
    return buf, addr
