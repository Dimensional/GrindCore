"""Phase 2, hashes: every hash export against an independent oracle (hashlib, or gctest/oracle_hashes.py, which is
itself checked against published vectors first). Probes that may crash or hang run in a child process."""
import ctypes
import hashlib
import os
import random
import struct
import subprocess
import sys
import textwrap
import unittest

import gcnative
import gctest
from gctest import oracle_hashes as O

LENGTHS = [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 55, 56, 57, 63, 64, 65, 111, 112, 113, 119, 120, 127, 128, 129, 135,
           136, 137, 143, 144, 191, 192, 255, 256, 257, 511, 512, 513, 1000, 1023, 1024, 1025, 2047, 2048, 2049, 4095,
           4096, 4097, 8192, 16385, 65536 + 13, 262144 + 31]


def rnd(n, seed=1):
    return random.Random(seed).getrandbits(8 * n).to_bytes(n, "little") if n else b""


def placed(data, misalign=0, align=64):
    """(keepalive, address): data copied to an address that is `misalign` bytes past an `align` boundary."""
    buf = ctypes.create_string_buffer(len(data) + align + misalign + 1)
    base = ctypes.addressof(buf)
    addr = base + (-base) % align + misalign
    ctypes.memmove(addr, data, len(data))
    return buf, addr


def raw_state(size=512, align=64):
    buf = ctypes.create_string_buffer(size + align)
    addr = ctypes.addressof(buf) + (-ctypes.addressof(buf)) % align
    return buf, addr


class Adapter(object):
    """One hash behind a uniform interface: new() -> ctx, update(ctx, data, misalign), final(ctx) -> bytes."""

    def __init__(self, name, oracle, new, update, final, max_len=None, block=64):
        self.name, self.oracle, self._new, self._update, self._final = name, oracle, new, update, final
        self.max_len, self.block = max_len, block

    def new(self):
        return self._new()

    def update(self, ctx, data, misalign=0):
        keep, addr = placed(data, misalign)
        self._update(ctx, addr, len(data))

    def final(self, ctx):
        return self._final(ctx)

    def digest(self, data, misalign=0):
        ctx = self.new()
        self.update(ctx, data, misalign)
        return self.final(ctx)


def adapters(L):
    A = []

    def struct_hash(name, oracle, sname, init, update, final_res_first, size, max_len=None, block=64, init_args=()):
        def new():
            ctx = L.alloc(sname)
            getattr(L, init)(ctypes.byref(ctx), *init_args)
            return ctx

        def upd(ctx, addr, n):
            getattr(L, update)(ctypes.byref(ctx), addr, n)

        def fin(ctx):
            out = ctypes.create_string_buffer(size)
            if final_res_first:
                getattr(L, final_res_first)(out, ctypes.byref(ctx))
            return out.raw
        return Adapter(name, oracle, new, upd, fin, max_len, block)

    def struct_hash_ctx_first(name, oracle, sname, prefix, size, block=64):
        def new():
            ctx = L.alloc(sname)
            getattr(L, prefix + "_Init")(ctypes.byref(ctx))
            return ctx

        def upd(ctx, addr, n):
            getattr(L, prefix + "_Update")(ctypes.byref(ctx), addr, n)

        def fin(ctx):
            out = ctypes.create_string_buffer(size)
            getattr(L, prefix + "_Final")(ctypes.byref(ctx), out)
            return out.raw
        return Adapter(name, oracle, new, upd, fin, None, block)

    # mcmilk hashes: Final(result, ctx)
    A.append(struct_hash("MD2", O.md2, "md2", "SZ_MD2_Init", "SZ_MD2_Update", "SZ_MD2_Final", 16, max_len=20000, block=16))
    A.append(struct_hash("MD4", O.md4, "md4", "SZ_MD4_Init", "SZ_MD4_Update", "SZ_MD4_Final", 16, max_len=300000))
    A.append(struct_hash("MD5", lambda d: hashlib.md5(d).digest(), "md5", "SZ_MD5_Init", "SZ_MD5_Update", "SZ_MD5_Final", 16))
    A.append(struct_hash("SHA-384", lambda d: hashlib.sha384(d).digest(), "hc_sha512state", "SZ_SHA384_Init",
                         "SZ_SHA384_Update", "SZ_SHA384_Final", 48, block=128))
    A.append(struct_hash("SHA-512", lambda d: hashlib.sha512(d).digest(), "hc_sha512state", "SZ_SHA512_Init",
                         "SZ_SHA512_Update", "SZ_SHA512_Final", 64, block=128))
    for bits, rate in ((224, 144), (256, 136), (384, 104), (512, 72)):
        A.append(struct_hash("SHA3-%d" % bits, getattr(hashlib, "sha3_%d" % bits) and
                             (lambda d, b=bits: getattr(hashlib, "sha3_%d" % b)(d).digest()),
                             "sha3_context_", "SZ_SHA3_Init", "SZ_SHA3_Update", "SZ_SHA3_Final", bits // 8,
                             block=rate, init_args=(bits,)))
    # 7-Zip hashes: Final(ctx, digest)
    A.append(struct_hash_ctx_first("SHA-1", lambda d: hashlib.sha1(d).digest(), "CSha1", "SZ_Sha1", 20))
    A.append(struct_hash_ctx_first("SHA-256", lambda d: hashlib.sha256(d).digest(), "CSha256", "SZ_Sha256", 32))
    A.append(struct_hash_ctx_first("BLAKE2sp", O.blake2sp, "CBlake2sp", "SZ_Blake2sp", 32, block=512))
    # BLAKE3
    b3 = Adapter("BLAKE3", lambda d: O.Blake3().update(d).digest(32),
                 lambda: _b3_new(L, "SZ_blake3_hasher_init"),
                 lambda ctx, addr, n: L.SZ_blake3_hasher_update(ctypes.byref(ctx), addr, n),
                 lambda ctx: _b3_out(L, ctx, 32), max_len=300000, block=1024)
    A.append(b3)
    # xxHash: opaque state, 48/88 bytes in xxHash; a 512-byte aligned buffer is ample
    for bits, oracle in ((32, O.xxh32), (64, O.xxh64)):
        pre = "SZ_XXH%d" % bits

        def new(pre=pre):
            keep, addr = raw_state()
            getattr(L, pre + "_Reset")(addr)
            return (keep, addr)

        def upd(ctx, addr, n, pre=pre):
            getattr(L, pre + "_Update")(ctx[1], addr, n)

        def fin(ctx, pre=pre, bits=bits):
            v = getattr(L, pre + "_Digest")(ctx[1])
            return struct.pack(">I" if bits == 32 else ">Q", v)
        A.append(Adapter("XXH%d" % bits, lambda d, o=oracle, b=bits: struct.pack(">I" if b == 32 else ">Q", o(d)),
                         new, upd, fin, max_len=300000, block=16 if bits == 32 else 32))
    return A


def _b3_new(L, init, *args):
    ctx = L.alloc("blake3_hasher")
    getattr(L, init)(ctypes.byref(ctx), *args)
    return ctx


def _b3_out(L, ctx, n, seek=None):
    out = ctypes.create_string_buffer(max(n, 1))
    if seek is None:
        L.SZ_blake3_hasher_finalize(ctypes.byref(ctx), out, n)
    else:
        L.SZ_blake3_hasher_finalize_seek(ctypes.byref(ctx), seek, out, n)
    return out.raw[:n]


def child(code, timeout=30):
    """Run code in a fresh interpreter with gcnative loaded on the same library as LIB. Returns (rc, stdout, stderr)."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prog = "import sys, ctypes; sys.path.insert(0, %r)\nimport gcnative\nL = gcnative.load(%r)\n" % (here, gctest.LIB.path)
    try:
        r = subprocess.run([sys.executable, "-c", prog + textwrap.dedent(code)], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
        return r.returncode, r.stdout.decode(errors="replace"), r.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return "timeout", "", ""


def known(test, key):
    test.skipTest("known defect %s: %s" % (key, gctest.KNOWN_DEFECTS[key]))


class AllHashes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.A = adapters(gctest.LIB)

    def check_streamed(self, a, got, want):
        """Multi-call results: MD2's are wrong on libraries with the md2-streaming defect."""
        if got != want and a.name == "MD2":
            known(self, "md2-streaming")
        self.assertEqual(got, want)

    def test_lengths_around_block_boundaries(self):
        for a in self.A:
            for n in LENGTHS:
                if a.max_len and n > a.max_len:
                    continue
                data = rnd(n, seed=n + 7)
                with self.subTest(hash=a.name, length=n):
                    self.assertEqual(a.digest(data).hex(), a.oracle(data).hex())

    def test_streaming_random_chunks(self):
        for a in self.A:
            n = min(a.max_len or 200000, 200000)
            data = rnd(n, seed=11)
            r = random.Random(a.name)
            ctx, pos = a.new(), 0
            while pos < n:
                step = r.choice([0, 1, 3, a.block - 1, a.block, a.block + 1, r.randrange(0, 5 * a.block)])
                a.update(ctx, data[pos:pos + step], misalign=r.randrange(8))
                pos += step
            with self.subTest(hash=a.name):
                self.check_streamed(a, a.final(ctx).hex(), a.oracle(data).hex())

    def test_md2_streaming_minimal(self):
        """The smallest trigger: 5 bytes pending, then a call that crosses the block boundary."""
        a = next(x for x in self.A if x.name == "MD2")
        data = rnd(45, seed=5)
        ctx = a.new()
        a.update(ctx, data[:5])
        a.update(ctx, data[5:])
        self.check_streamed(a, a.final(ctx).hex(), a.oracle(data).hex())

    def test_misaligned_input(self):
        for a in self.A:
            for n in (1, a.block - 1, a.block * 3 + 5, 5000):
                data = rnd(n, seed=n)
                want = a.oracle(data)
                for mis in range(1, 8):
                    with self.subTest(hash=a.name, length=n, misalign=mis):
                        self.assertEqual(a.digest(data, misalign=mis).hex(), want.hex())

    def test_interleaved_contexts_are_independent(self):
        for a in self.A:
            d1, d2 = rnd(3000, seed=21), rnd(3000, seed=22)
            c1, c2 = a.new(), a.new()
            for i in range(0, 3000, 250):
                a.update(c1, d1[i:i + 250])
                a.update(c2, d2[i:i + 250])
            with self.subTest(hash=a.name):
                self.check_streamed(a, a.final(c1).hex(), a.oracle(d1).hex())
                self.check_streamed(a, a.final(c2).hex(), a.oracle(d2).hex())

    def test_large_input(self):
        data = rnd(4 * 1024 * 1024 + 17, seed=31)
        for a in self.A:
            if a.max_len:
                continue  # pure-Python oracle: too slow for 4 MiB
            with self.subTest(hash=a.name):
                self.assertEqual(a.digest(data).hex(), a.oracle(data).hex())


class SevenZipFunctions(unittest.TestCase):
    """SHA-1/SHA-256/BLAKE2sp choose an implementation per context (SetFunction); the *Prepare switches detect the
    CPU's instructions. GrindCore.net never calls the Prepare functions (hashes.md 6.3)."""

    def run_algos(self, prefix, sname, size, oracle, algos):
        L = gctest.LIB
        data = rnd(200003, seed=41)
        supported = []
        for algo in algos:
            ctx = L.alloc(sname)
            getattr(L, prefix + "_Init")(ctypes.byref(ctx))
            if not getattr(L, prefix + "_SetFunction")(ctypes.byref(ctx), algo):
                continue
            # SetFunction only swaps the function pointers. For BLAKE2sp each vector implementation keeps the state in
            # its own layout, so the state must be rebuilt after choosing (as 7-Zip does: SetFunction, then InitState).
            getattr(L, prefix + "_InitState")(ctypes.byref(ctx))
            supported.append(algo)
            keep, addr = placed(data, 3)
            getattr(L, prefix + "_Update")(ctypes.byref(ctx), addr, len(data))
            out = ctypes.create_string_buffer(size)
            getattr(L, prefix + "_Final")(ctypes.byref(ctx), out)
            with self.subTest(hash=prefix, algo=algo):
                self.assertEqual(out.raw.hex(), oracle(data).hex())
        return supported

    def test_every_available_sha1_sha256_function(self):
        gctest.LIB.SZ_Sha1Prepare()
        gctest.LIB.SZ_Sha256Prepare()
        s1 = self.run_algos("SZ_Sha1", "CSha1", 20, lambda d: hashlib.sha1(d).digest(), (0, 1, 2, 3))
        s2 = self.run_algos("SZ_Sha256", "CSha256", 32, lambda d: hashlib.sha256(d).digest(), (0, 1, 2, 3))
        print("  SHA-1 functions available: %s; SHA-256: %s  (0 default, 1 software, 2 hardware)" % (s1, s2))
        self.assertIn(1, s1)
        self.assertIn(1, s2)
        self.assertNotIn(3, s1 + s2, "unknown algorithm codes must be refused")

    def test_every_available_blake2sp_function(self):
        gctest.LIB.SZ_Black2sp_Prepare()
        s = self.run_algos("SZ_Blake2sp", "CBlake2sp", 32, O.blake2sp, range(0, 9))
        print("  BLAKE2sp functions available: %s  (0 default, 1 scalar, 2 V128 fast, 3 AVX2 fast, 4 V128 way1, "
              "5 V128 way2, 6 AVX2 way2, 7 AVX2 way4)" % s)
        self.assertIn(1, s)
        self.assertNotIn(8, s, "unknown algorithm codes must be refused")

    def test_blake2sp_vector_paths_with_a_misaligned_state(self):
        """hashes.md 6.3: the SSE/AVX2 BLAKE2sp code uses aligned loads on the state (Z7_BLAKE2SP_STRUCT_IS_NOT_ALIGNED
        is not defined), and GrindCore.net's managed state is typically only 8-byte aligned. Observed per algorithm in
        a child process, with the state 8 bytes past a 64-byte boundary. Informational: records what each path does."""
        rc0, out0, _ = child("""
            L.SZ_Black2sp_Prepare()
            ok = []
            for a in range(2, 8):
                c = L.alloc("CBlake2sp"); L.SZ_Blake2sp_Init(ctypes.byref(c))
                if L.SZ_Blake2sp_SetFunction(ctypes.byref(c), a): ok.append(a)
            print(ok)
        """)
        algos = eval(out0.strip().splitlines()[-1]) if rc0 == 0 else []
        results = {}
        for algo in algos:
            rc, out, err = child("""
                L.SZ_Black2sp_Prepare()
                size = ctypes.sizeof(L.struct.CBlake2sp)
                arena = ctypes.create_string_buffer(size + 128)
                addr = ctypes.addressof(arena) + (-ctypes.addressof(arena)) %% 64 + 8
                try:
                    L.SZ_Blake2sp_Init(addr); L.SZ_Blake2sp_SetFunction(addr, %d); L.SZ_Blake2sp_InitState(addr)
                    data = bytes(range(256)) * 400
                    L.SZ_Blake2sp_Update(addr, data, len(data))
                    out = ctypes.create_string_buffer(32); L.SZ_Blake2sp_Final(addr, out)
                    print(out.raw.hex())
                except OSError as e:  # Windows: ctypes turns a native access violation into OSError
                    print("CRASH " + str(e))
            """ % algo)
            want = O.blake2sp(bytes(range(256)) * 400).hex()
            text = out.strip().splitlines()[-1] if out.strip() else ""
            results[algo] = ("correct" if text == want else "native crash: " + text[6:] if text.startswith("CRASH")
                             else "wrong digest" if rc == 0 else "process died (%s)" % rc)
        print("  BLAKE2sp with the state 8 bytes past a 64-byte boundary: %s" % (results or "no vector paths here"))

    def test_hardware_paths_exist_only_after_prepare(self):
        """In a fresh process: which hardware functions exist before and after the Prepare calls."""
        rc, out, err = child("""
            def avail(pre, sname, algo):
                ctx = L.alloc(sname); getattr(L, pre + "_Init")(ctypes.byref(ctx))
                return bool(getattr(L, pre + "_SetFunction")(ctypes.byref(ctx), algo))
            before = [avail("SZ_Sha1", "CSha1", 2), avail("SZ_Sha256", "CSha256", 2),
                      [a for a in range(2, 8) if avail("SZ_Blake2sp", "CBlake2sp", a)]]
            L.SZ_Sha1Prepare(); L.SZ_Sha256Prepare(); L.SZ_Black2sp_Prepare()
            after = [avail("SZ_Sha1", "CSha1", 2), avail("SZ_Sha256", "CSha256", 2),
                     [a for a in range(2, 8) if avail("SZ_Blake2sp", "CBlake2sp", a)]]
            print(before); print(after)
        """)
        self.assertEqual(rc, 0, err[-500:])
        before, after = out.strip().splitlines()[-2:]
        print("  before Prepare: SHA-1 hw, SHA-256 hw, BLAKE2sp vector algos = %s" % before)
        print("  after  Prepare: SHA-1 hw, SHA-256 hw, BLAKE2sp vector algos = %s" % after)

    def test_sha1_prepare_block_and_block_digest(self):
        """7-Zip's single-block helpers, within their contract: the current count must be a whole number of blocks,
        and size a multiple of 4 no larger than 52 (Sha1.c:385-398)."""
        L = gctest.LIB
        prefix = rnd(128, seed=51)
        for size in range(0, 53, 4):
            msg = rnd(size, seed=size)
            ctx = L.alloc("CSha1")
            L.SZ_Sha1_Init(ctypes.byref(ctx))
            L.SZ_Sha1_Update(ctypes.byref(ctx), prefix, len(prefix))
            block = ctypes.create_string_buffer(64)
            ctypes.memmove(block, msg, size)
            L.SZ_Sha1_PrepareBlock(ctypes.byref(ctx), block, size)
            out = ctypes.create_string_buffer(20)
            L.SZ_Sha1_GetBlockDigest(ctypes.byref(ctx), block, out)
            with self.subTest(size=size):
                self.assertEqual(out.raw.hex(), hashlib.sha1(prefix + msg).hexdigest())

    def test_sha1_prepare_block_rejects_out_of_contract_size(self):
        """size 5 is not a multiple of 4: the vendored padding loop steps over 56 and never stops (Sha1.c:393-397).
        A fixed PAL returns -1 and leaves memory alone. Probed in a child process: the defect corrupts the heap."""
        results = {}
        for size in (5, 54, 56, 60):
            rc, out, err = child("""
                ctx = L.alloc("CSha1"); L.SZ_Sha1_Init(ctypes.byref(ctx))
                arena = ctypes.create_string_buffer(64 + 65536)   # the block, then 64 KiB of guard
                r = L.SZ_Sha1_PrepareBlock(ctypes.byref(ctx), arena, %d)
                print(r, arena.raw[64:] == bytes(65536))
            """ % size, timeout=15)
            results[size] = (rc, out.strip())
        print("  PrepareBlock out-of-contract sizes -> (exit code, 'return guard-intact'): %s" % results)
        if any(rc != 0 for rc, _ in results.values()):
            known(self, "sha1-prepareblock-size")
        for size, (rc, out) in results.items():
            with self.subTest(size=size):
                self.assertEqual(out, "-1 True")


class Blake3Modes(unittest.TestCase):
    def test_keyed_derive_and_xof(self):
        L = gctest.LIB
        data = rnd(70001, seed=61)
        key = O.B3_KEY
        ctx_str = O.B3_CONTEXT
        cases = [
            ("plain", lambda: _b3_new(L, "SZ_blake3_hasher_init"), O.Blake3()),
            ("keyed", lambda: _b3_new(L, "SZ_blake3_hasher_init_keyed", key), O.Blake3.keyed(key)),
            ("derive_key", lambda: _b3_new(L, "SZ_blake3_hasher_init_derive_key", ctx_str), O.Blake3.derive_key(ctx_str)),
            ("derive_key_raw", lambda: _b3_new(L, "SZ_blake3_hasher_init_derive_key_raw", ctx_str + b"\0x", len(ctx_str) + 2),
             O.Blake3.derive_key(ctx_str + b"\0x")),
        ]
        for name, make, ref in cases:
            ctx = make()
            L.SZ_blake3_hasher_update(ctypes.byref(ctx), data, len(data))
            ref.update(data)
            for n in (1, 31, 32, 33, 64, 65, 1000):
                with self.subTest(mode=name, out_len=n):
                    self.assertEqual(_b3_out(L, ctx, n).hex(), ref.digest(n).hex())
            for seek in (1, 63, 64, 1000, (1 << 32) + 5):
                with self.subTest(mode=name, seek=seek):
                    self.assertEqual(_b3_out(L, ctx, 100, seek).hex(), ref.digest(100, seek).hex())


class Sha3BitSize(unittest.TestCase):
    def test_out_of_range_bit_size_is_contained(self):
        """bitSize > 800 makes capacityWords > 25, so the rate check in SHA3_Update never matches and the sponge index
        runs past the 25-word state. Measured inside a guarded buffer: Update first, and Final only once Update is
        known to have stayed inside the context (on a defective library Final would write wild)."""
        L = gctest.LIB
        size = ctypes.sizeof(L.struct.sha3_context_)
        data = rnd(2000, seed=71)
        for bits in (0, 100, 801, 1024, 4096, 0xFFFFFFFF):
            arena = ctypes.create_string_buffer(size + 8192)
            r = L.SZ_SHA3_Init(arena, bits)
            L.SZ_SHA3_Update(arena, data, len(data))
            damaged = arena.raw[size:] != bytes(8192)
            if damaged:
                print("  SHA3_Init(%d) + 2000 bytes: guard after the %d-byte context OVERWRITTEN" % (bits, size))
                known(self, "sha3-bitsize")
            if r != -1:  # no refusal: a library without the check (its void return leaves a register value here)
                print("  SHA3_Init(%d) was not refused" % bits)
                known(self, "sha3-bitsize")
            out = ctypes.create_string_buffer(64 + 4096)
            L.SZ_SHA3_Final(out, arena)
            with self.subTest(bitSize=bits):
                self.assertEqual(r, -1, "an unsupported size must be refused")
                self.assertEqual(arena.raw[size:], bytes(8192), "Final wrote past the context")
                self.assertEqual(out.raw, bytes(64 + 4096), "a refused context must produce no output")
        for bits in (224, 256, 384, 512):
            arena = ctypes.create_string_buffer(size)
            with self.subTest(bitSize=bits):
                self.assertEqual(L.SZ_SHA3_Init(arena, bits), 0)
