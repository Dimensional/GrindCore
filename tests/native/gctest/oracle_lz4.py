"""Independent LZ4 decoders, written from the LZ4 Block Format Description (lz4/doc/lz4_Block_format.md) and the LZ4
Frame Format Description (lz4_Frame_format.md), used as oracles: GrindCore's LZ4 output is checked against the formats,
not only against GrindCore's own decoder. Python 3.6+, no dependencies. Speed is irrelevant here; correctness and
strictness are the point."""
import struct

from gctest.oracle_hashes import xxh32

WINDOW = 65536          # LZ4 match offsets are 16-bit: a block can refer back at most 64 KB


class LZ4FormatError(ValueError):
    pass


def decompress_block(src, max_output=1 << 30, prefix=b""):
    """Decode one raw LZ4 block (no frame header). Matches may refer back into `prefix` (the previous blocks' output
    or a dictionary: its last 64 KB). Raises LZ4FormatError on anything malformed."""
    src = bytes(src)
    prefix = bytes(prefix[-WINDOW:])
    out = bytearray(prefix)
    base = len(prefix)
    max_output += base
    i, n = 0, len(src)
    if n == 0:
        raise LZ4FormatError("empty block (a valid block has at least a token)")
    while True:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            lit += _read_length(src, i)
            i = _after_length(src, i)
        if i + lit > n:
            raise LZ4FormatError("literals run past the end of the block")
        out += src[i:i + lit]
        i += lit
        if i == n:  # the last sequence has literals only
            break
        if i + 2 > n:
            raise LZ4FormatError("truncated offset")
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0:
            raise LZ4FormatError("offset 0 is invalid")
        ml = token & 15
        if ml == 15:
            ml += _read_length(src, i)
            i = _after_length(src, i)
        ml += 4  # minmatch
        start = len(out) - off
        if start < 0:
            raise LZ4FormatError("offset %d points before the start of the output" % off)
        if off >= ml:
            out += out[start:start + ml]
        else:  # overlapping copy (run-length style), byte by byte
            for k in range(ml):
                out.append(out[start + k])
        if len(out) > max_output:
            raise LZ4FormatError("output exceeds %d bytes" % (max_output - base))
    if len(out) > max_output:
        raise LZ4FormatError("output exceeds %d bytes" % (max_output - base))
    return bytes(out[base:])


BLOCK_MAX = {4: 64 << 10, 5: 256 << 10, 6: 1 << 20, 7: 4 << 20}


def decompress_frames(data, dictionary=b""):
    """Decode a sequence of LZ4 frames (and skippable frames). Returns (output, [frame info dicts]). Every field and
    checksum the format defines is checked; anything else raises LZ4FormatError."""
    data, pos, out, infos = bytes(data), 0, bytearray(), []
    if not data:
        raise LZ4FormatError("no frame")
    while pos < len(data):
        if pos + 4 > len(data):
            raise LZ4FormatError("truncated magic number")
        magic = struct.unpack_from("<I", data, pos)[0]
        if magic & 0xFFFFFFF0 == 0x184D2A50:
            if pos + 8 > len(data):
                raise LZ4FormatError("truncated skippable frame")
            size = struct.unpack_from("<I", data, pos + 4)[0]
            if pos + 8 + size > len(data):
                raise LZ4FormatError("skippable frame runs past the end")
            infos.append({"skippable": magic & 15, "size": size})
            pos += 8 + size
            continue
        if magic != 0x184D2204:
            raise LZ4FormatError("bad magic number 0x%08X" % magic)
        frame, pos, info = _frame(data, pos + 4, dictionary)
        out += frame
        infos.append(info)
    return bytes(out), infos


def _frame(data, pos, dictionary):
    start = pos
    if pos + 3 > len(data):
        raise LZ4FormatError("truncated frame descriptor")
    flg, bd = data[pos], data[pos + 1]
    version, indep, bsum, csize, csum, reserved, dictid = (flg >> 6, (flg >> 5) & 1, (flg >> 4) & 1, (flg >> 3) & 1,
                                                           (flg >> 2) & 1, (flg >> 1) & 1, flg & 1)
    if version != 1:
        raise LZ4FormatError("frame version %d" % version)
    if reserved or bd & 0x8F:
        raise LZ4FormatError("reserved bits set")
    bid = (bd >> 4) & 7
    if bid not in BLOCK_MAX:
        raise LZ4FormatError("block maximum size id %d" % bid)
    pos += 2
    content_size = dict_id = None
    if csize:
        if pos + 8 > len(data):
            raise LZ4FormatError("truncated content size")
        content_size = struct.unpack_from("<Q", data, pos)[0]
        pos += 8
    if dictid:
        if pos + 4 > len(data):
            raise LZ4FormatError("truncated dictionary id")
        dict_id = struct.unpack_from("<I", data, pos)[0]
        pos += 4
    if pos >= len(data):
        raise LZ4FormatError("truncated header checksum")
    if data[pos] != (xxh32(data[start:pos]) >> 8) & 0xFF:
        raise LZ4FormatError("header checksum mismatch")
    pos += 1
    out = bytearray()
    history = bytes(dictionary[-WINDOW:])
    blocks = []
    while True:
        if pos + 4 > len(data):
            raise LZ4FormatError("truncated block size")
        word = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if word == 0:
            break
        size, raw = word & 0x7FFFFFFF, word >> 31
        if size > BLOCK_MAX[bid]:
            raise LZ4FormatError("block of %d bytes exceeds the frame's maximum %d" % (size, BLOCK_MAX[bid]))
        if pos + size + 4 * bsum > len(data):
            raise LZ4FormatError("block runs past the end")
        block = data[pos:pos + size]
        pos += size
        if bsum:
            if struct.unpack_from("<I", data, pos)[0] != xxh32(block):
                raise LZ4FormatError("block checksum mismatch")
            pos += 4
        prefix = history if indep else (history + bytes(out))[-WINDOW:]
        decoded = block if raw else decompress_block(block, BLOCK_MAX[bid], prefix=prefix)
        if len(decoded) > BLOCK_MAX[bid]:
            raise LZ4FormatError("block decodes to more than the frame's maximum")
        out += decoded
        blocks.append((size, bool(raw), len(decoded)))
    if csum:
        if pos + 4 > len(data):
            raise LZ4FormatError("truncated content checksum")
        if struct.unpack_from("<I", data, pos)[0] != xxh32(bytes(out)):
            raise LZ4FormatError("content checksum mismatch")
        pos += 4
    if content_size is not None and content_size != len(out):
        raise LZ4FormatError("content size says %d, frame decodes to %d" % (content_size, len(out)))
    info = {"independent": bool(indep), "block_checksum": bool(bsum), "content_checksum": bool(csum),
            "content_size": content_size, "dict_id": dict_id, "block_max": BLOCK_MAX[bid], "blocks": blocks}
    return bytes(out), pos, info


def _read_length(src, i):
    total = 0
    while True:
        if i >= len(src):
            raise LZ4FormatError("truncated length")
        b = src[i]
        i += 1
        total += b
        if b != 255:
            return total


def _after_length(src, i):
    while src[i] == 255:
        i += 1
    return i + 1
