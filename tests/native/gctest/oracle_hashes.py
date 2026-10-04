"""Independent reference implementations for the hashes Python's hashlib lacks (or may lack): MD2 (RFC 1319),
MD4 (RFC 1320), XXH32/XXH64 (xxHash spec), BLAKE3 (the BLAKE3 spec / reference_impl), and BLAKE2sp built from
hashlib.blake2s's tree-hashing parameters. Each is checked against published test vectors by KNOWN_ANSWERS before
it's trusted as an oracle. Pure Python 3.6+, slow but only used on test-sized inputs."""
import hashlib
import struct

M32, M64 = 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF


# ---------------------------------------------------------------- MD2 (RFC 1319)
# S-table from RFC 1319 section 3.2 (the digits-of-pi permutation). A single wrong entry breaks the RFC vectors below.
_MD2_S = bytes([
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199, 115, 140, 152, 147,
    43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18, 190, 78, 196,
    214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16,
    137, 11, 34, 95, 33, 128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72,
    165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156,
    116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27, 96, 37, 173, 174, 176,
    185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234,
    38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250,
    36, 225, 123, 8, 12, 189, 177, 74, 120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57, 242,
    239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26, 219, 153,
    141, 51, 159, 17, 131, 20])


def md2(data):
    pad = 16 - len(data) % 16
    msg = bytearray(data) + bytes([pad]) * pad
    checksum, last = bytearray(16), 0
    for i in range(0, len(msg), 16):
        for j in range(16):
            checksum[j] ^= _MD2_S[msg[i + j] ^ last]
            last = checksum[j]
    msg += checksum
    x = bytearray(48)
    for i in range(0, len(msg), 16):
        for j in range(16):
            x[16 + j] = msg[i + j]
            x[32 + j] = x[16 + j] ^ x[j]
        t = 0
        for j in range(18):
            for k in range(48):
                x[k] ^= _MD2_S[t]
                t = x[k]
            t = (t + j) & 0xFF
    return bytes(x[:16])


# ---------------------------------------------------------------- MD4 (RFC 1320)
def _rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def md4(data):
    msg = bytearray(data) + b"\x80"
    msg += b"\0" * ((56 - len(msg) % 64) % 64) + struct.pack("<Q", (len(data) * 8) & M64)
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        aa, bb, cc, dd = a, b, c, d
        f = lambda x_, y, z: (x_ & y) | (~x_ & z)
        g = lambda x_, y, z: (x_ & y) | (x_ & z) | (y & z)
        h = lambda x_, y, z: x_ ^ y ^ z
        for i in range(16):
            k, s = i, (3, 7, 11, 19)[i % 4]
            a = _rotl32((a + f(b, c, d) + x[k]) & M32, s)
            a, b, c, d = d, a, b, c
        for i in range(16):
            k, s = (i % 4) * 4 + i // 4, (3, 5, 9, 13)[i % 4]
            a = _rotl32((a + g(b, c, d) + x[k] + 0x5A827999) & M32, s)
            a, b, c, d = d, a, b, c
        for i in range(16):
            k, s = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i], (3, 9, 11, 15)[i % 4]
            a = _rotl32((a + h(b, c, d) + x[k] + 0x6ED9EBA1) & M32, s)
            a, b, c, d = d, a, b, c
        a, b, c, d = (a + aa) & M32, (b + bb) & M32, (c + cc) & M32, (d + dd) & M32
    return struct.pack("<4I", a, b, c, d)


# ---------------------------------------------------------------- xxHash 32 / 64
P32 = (0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D, 0x27D4EB2F, 0x165667B1)
P64 = (0x9E3779B185EBCA87, 0xC2B2AE3D27D4EB4F, 0x165667B19E3779F9, 0x85EBCA77C2B2AE63, 0x27D4EB2F165667C5)


def xxh32(data, seed=0):
    n, i = len(data), 0
    if n >= 16:
        v = [(seed + P32[0] + P32[1]) & M32, (seed + P32[1]) & M32, seed & M32, (seed - P32[0]) & M32]
        while i <= n - 16:
            for j in range(4):
                v[j] = (_rotl32((v[j] + struct.unpack_from("<I", data, i + 4 * j)[0] * P32[1]) & M32, 13) * P32[0]) & M32
            i += 16
        h = (_rotl32(v[0], 1) + _rotl32(v[1], 7) + _rotl32(v[2], 12) + _rotl32(v[3], 18)) & M32
    else:
        h = (seed + P32[4]) & M32
    h = (h + n) & M32
    while i <= n - 4:
        h = (_rotl32((h + struct.unpack_from("<I", data, i)[0] * P32[2]) & M32, 17) * P32[3]) & M32
        i += 4
    while i < n:
        h = (_rotl32((h + data[i] * P32[4]) & M32, 11) * P32[0]) & M32
        i += 1
    h ^= h >> 15
    h = (h * P32[1]) & M32
    h ^= h >> 13
    h = (h * P32[2]) & M32
    h ^= h >> 16
    return h


def _rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & M64


def _xxh64_round(acc, lane):
    return (_rotl64((acc + lane * P64[1]) & M64, 31) * P64[0]) & M64


def xxh64(data, seed=0):
    n, i = len(data), 0
    if n >= 32:
        v = [(seed + P64[0] + P64[1]) & M64, (seed + P64[1]) & M64, seed & M64, (seed - P64[0]) & M64]
        while i <= n - 32:
            for j in range(4):
                v[j] = _xxh64_round(v[j], struct.unpack_from("<Q", data, i + 8 * j)[0])
            i += 32
        h = (_rotl64(v[0], 1) + _rotl64(v[1], 7) + _rotl64(v[2], 12) + _rotl64(v[3], 18)) & M64
        for j in range(4):
            h = ((h ^ _xxh64_round(0, v[j])) * P64[0] + P64[3]) & M64
    else:
        h = (seed + P64[4]) & M64
    h = (h + n) & M64
    while i <= n - 8:
        h = (_rotl64(h ^ _xxh64_round(0, struct.unpack_from("<Q", data, i)[0]), 27) * P64[0] + P64[3]) & M64
        i += 8
    if i <= n - 4:
        h = (_rotl64(h ^ ((struct.unpack_from("<I", data, i)[0] * P64[0]) & M64), 23) * P64[1] + P64[2]) & M64
        i += 4
    while i < n:
        h = (_rotl64(h ^ ((data[i] * P64[4]) & M64), 11) * P64[0]) & M64
        i += 1
    h ^= h >> 33
    h = (h * P64[1]) & M64
    h ^= h >> 29
    h = (h * P64[2]) & M64
    h ^= h >> 32
    return h


# ---------------------------------------------------------------- BLAKE2sp from hashlib.blake2s tree mode
def blake2sp(data, key=b""):
    """BLAKE2sp = 8 BLAKE2s leaves (fanout 8, depth 2, inner length 32, node_offset i; leaf 7 is the last node)
    taking 64-byte blocks round-robin, then a root (node_depth 1, last node) over the 8 leaf digests."""
    leaves = []
    for i in range(8):
        part = b"".join(data[j:j + 64] for j in range(64 * i, len(data), 512))
        leaves.append(hashlib.blake2s(part, digest_size=32, key=key, fanout=8, depth=2, leaf_size=0, node_offset=i,
                                      node_depth=0, inner_size=32, last_node=(i == 7)).digest())
    return hashlib.blake2s(b"".join(leaves), digest_size=32, key=key, fanout=8, depth=2, leaf_size=0, node_offset=0,
                           node_depth=1, inner_size=32, last_node=True).digest()


# ---------------------------------------------------------------- BLAKE3 (port of the spec's reference_impl.py)
_B3_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
_B3_PERM = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START, CHUNK_END, PARENT, ROOT, KEYED_HASH, DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL = 1, 2, 4, 8, 16, 32, 64


def _rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _b3_g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & M32
    s[d] = _rotr32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & M32
    s[d] = _rotr32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32
    s[b] = _rotr32(s[b] ^ s[c], 7)


def _b3_compress(cv, m, counter, block_len, flags):
    s = list(cv) + list(_B3_IV[:4]) + [counter & M32, (counter >> 32) & M32, block_len, flags]
    m = list(m)
    for r in range(7):
        _b3_g(s, 0, 4, 8, 12, m[0], m[1]); _b3_g(s, 1, 5, 9, 13, m[2], m[3])
        _b3_g(s, 2, 6, 10, 14, m[4], m[5]); _b3_g(s, 3, 7, 11, 15, m[6], m[7])
        _b3_g(s, 0, 5, 10, 15, m[8], m[9]); _b3_g(s, 1, 6, 11, 12, m[10], m[11])
        _b3_g(s, 2, 7, 8, 13, m[12], m[13]); _b3_g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in _B3_PERM]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(b):
    return struct.unpack("<16I", bytes(b).ljust(64, b"\0"))


class _Output(object):
    def __init__(self, cv, m, counter, block_len, flags):
        self.cv, self.m, self.counter, self.block_len, self.flags = cv, m, counter, block_len, flags

    def chaining_value(self):
        return _b3_compress(self.cv, self.m, self.counter, self.block_len, self.flags)[:8]

    def root_bytes(self, n, seek=0):
        out, counter, skip = bytearray(), seek // 64, seek % 64
        while len(out) < n + skip:
            out += struct.pack("<16I", *_b3_compress(self.cv, self.m, counter, self.block_len, self.flags | ROOT))
            counter += 1
        return bytes(out[skip:skip + n])


class _Chunk(object):
    def __init__(self, key, counter, flags):
        self.cv, self.counter, self.flags, self.block, self.blocks = list(key), counter, flags, bytearray(), 0

    def __len__(self):
        return 64 * self.blocks + len(self.block)

    def _start(self):
        return CHUNK_START if self.blocks == 0 else 0

    def update(self, data):
        while data:
            if len(self.block) == 64:
                self.cv = _b3_compress(self.cv, _words(self.block), self.counter, 64, self.flags | self._start())[:8]
                self.blocks += 1
                self.block = bytearray()
            take = min(64 - len(self.block), len(data))
            self.block += data[:take]
            data = data[take:]

    def output(self):
        return _Output(self.cv, _words(self.block), self.counter, len(self.block), self.flags | self._start() | CHUNK_END)


class Blake3(object):
    def __init__(self, key=_B3_IV, flags=0):
        self.key, self.flags, self.stack = tuple(key), flags, []
        self.chunk = _Chunk(self.key, 0, flags)

    @classmethod
    def keyed(cls, key32):
        return cls(struct.unpack("<8I", key32), KEYED_HASH)

    @classmethod
    def derive_key(cls, context):
        ctx = cls(_B3_IV, DERIVE_KEY_CONTEXT)
        ctx.update(context)
        return cls(struct.unpack("<8I", ctx.digest(32)), DERIVE_KEY_MATERIAL)

    def _parent(self, left, right):
        return _Output(self.key, list(left) + list(right), 0, 64, PARENT | self.flags)

    def update(self, data):
        data = bytes(data)
        while data:
            if len(self.chunk) == 1024:
                cv, total = self.chunk.output().chaining_value(), self.chunk.counter + 1
                while total & 1 == 0:
                    cv = self._parent(self.stack.pop(), cv).chaining_value()
                    total >>= 1
                self.stack.append(cv)
                self.chunk = _Chunk(self.key, self.chunk.counter + 1, self.flags)
            take = min(1024 - len(self.chunk), len(data))
            self.chunk.update(data[:take])
            data = data[take:]
        return self

    def digest(self, n=32, seek=0):
        out = self.chunk.output()
        for cv in reversed(self.stack):
            out = self._parent(cv, out.chaining_value())
        return out.root_bytes(n, seek)


# ---------------------------------------------------------------- self-check against published vectors
_ALPHA = b"abcdefghijklmnopqrstuvwxyz"
_ALNUM = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_DIGITS = b"1234567890" * 8
B3_KEY = b"whats the Elvish word for friend"          # BLAKE3 test_vectors.json key
B3_CONTEXT = b"BLAKE3 2019-12-27 16:29:52 test vectors context"

KNOWN_ANSWERS = [  # (name, function, input, expected hex) -- RFC 1319/1320, xxHash sanity, BLAKE3 test_vectors.json
    ("md2", md2, b"", "8350e5a3e24c153df2275c9f80692773"),
    ("md2", md2, b"abc", "da853b0d3f88d99b30283a69e6ded6bb"),
    ("md2", md2, b"message digest", "ab4f496bfb2a530b219ff33031fe06b0"),
    ("md2", md2, _ALPHA, "4e8ddff3650292ab5a4108c3aa47940b"),
    ("md2", md2, _ALNUM, "da33def2a42df13975352846c30338cd"),
    ("md2", md2, _DIGITS, "d5976f79d83d3a0dc9806c3c66f3efd8"),
    ("md4", md4, b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    ("md4", md4, b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
    ("md4", md4, b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    ("md4", md4, b"message digest", "d9130a8164549fe818874806e1c7014b"),
    ("md4", md4, _ALPHA, "d79e1c308aa5bbcdeea8ed63df412da9"),
    ("md4", md4, _ALNUM, "043f8582f241db351ce627e153e7f0e4"),
    ("md4", md4, _DIGITS, "e33b4ddc9c38f2199c3e7b164fcc0536"),
    ("xxh32", lambda d: struct.pack(">I", xxh32(d)), b"", "02cc5d05"),
    ("xxh64", lambda d: struct.pack(">Q", xxh64(d)), b"", "ef46db3751d8e999"),
    ("blake3", lambda d: Blake3().update(d).digest(32), b"",
     "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"),
    ("blake3", lambda d: Blake3().update(d).digest(32), b"abc",
     "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"),
    ("blake3-keyed", lambda d: Blake3.keyed(B3_KEY).update(d).digest(32), b"",
     "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26"),
    ("blake3-derive", lambda d: Blake3.derive_key(B3_CONTEXT).update(d).digest(32), b"",
     "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d"),
]


def self_check():
    bad = [(n, x, f(x).hex(), want) for n, f, x, want in KNOWN_ANSWERS if f(x).hex() != want]
    return bad


if __name__ == "__main__":
    problems = self_check()
    print("oracle self-check:", "OK (%d vectors)" % len(KNOWN_ANSWERS) if not problems else problems)
