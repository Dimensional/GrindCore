"""Phase 1: what the library exports, how its structs are laid out, and the calls that need no codec setup."""
import ctypes
import unittest

import gcnative
import gctest
from gcnative import _spec


class Symbols(unittest.TestCase):
    def test_exports_match_expectation(self):
        """Linux/macOS export exactly entrypoints.c; Windows also every dllexport. Documented gaps are allowed,
        anything else (a new gap, or a documented one that changed) fails."""
        problems, known, closed = [], [], []
        for name, tags, expected, present in gctest.LIB.symbol_report():
            if expected and not present:
                problems.append("%s: expected here (%s) but not exported" % (name, ",".join(tags)))
            elif present and not expected:
                if "dllexport" in tags or "pinvoke" in tags:
                    # a library built from a newer entrypoints.c than the code map was made from
                    closed.append("%s: exported here now (spec: %s)" % (name, ",".join(tags)))
                else:
                    problems.append("%s: exported but not expected (%s)" % (name, ",".join(tags)))
            elif "pinvoke" in tags and not present:
                (known if name in gctest.KNOWN_SYMBOL_GAPS else problems).append(
                    "%s: GrindCore.net P/Invokes it, not exported here -- %s" % (name, gctest.KNOWN_SYMBOL_GAPS.get(name, "NEW")))
        for k in known:
            print("  known gap: " + k)
        for c in closed:
            print("  gap closed: " + c)
        self.assertEqual(problems, [])

    def test_known_gaps_report(self):
        """Which documented gaps this library still has (baseline) or no longer has (a fixed build). Informational:
        the audit's status of each gap is tracked in the audit, not by failing here."""
        win = gcnative.target().startswith("win")
        for name, why in sorted(gctest.KNOWN_SYMBOL_GAPS.items()):
            windows_only = win and "dllexport" in _spec.SYMBOLS.get(name, [])
            state = "exported" if gctest.LIB.has(name) else "missing"
            print("  %-45s %-8s%s  (%s)" % (name, state, " (Windows dllexport)" if windows_only else "", why.split(";")[0]))


class Layouts(unittest.TestCase):
    def test_struct_layouts_match_clang(self):
        rows = gctest.LIB.layout_report()
        compared = [r for r in rows if r[2] is not None]
        if not compared:
            for name, got, _ in rows:
                print("  %-40s size %5d offsets %s" % (name, got[0], got[1]))
            self.skipTest("the code map has no clang layouts for %s (only win-x64/win-x86); sizes printed" % gcnative.target())
        bad = ["%s: ctypes %s vs clang %s" % (n, g, w) for n, g, w in compared if (g[0], g[1]) != (w[0], w[1])]
        self.assertEqual(bad, [])

    def test_over_aligned_structs_get_their_alignment(self):
        for name in gctest.LIB.struct.names():
            if gctest.LIB.alignment(name) > 16:
                obj = gctest.LIB.alloc(name)
                self.assertEqual(ctypes.addressof(obj) % gctest.LIB.alignment(name), 0, name)


class NoSetupCalls(unittest.TestCase):
    """Exports that take no arguments: versions, limits, the hardware-dispatch 'Prepare' switches, and constructors
    paired with their destructors."""

    def test_versions_and_limits(self):
        L = gctest.LIB
        self.assertRegex(L.SZ_blake3_version().decode(), r"^\d+\.\d+\.\d+$")
        self.assertGreaterEqual(L.FL2_maxCLevel(), 1)
        self.assertGreaterEqual(L.FL2_maxHighCLevel(), 1)
        for v in ("1_5_2", "1_5_7"):
            self.assertGreater(getattr(L, "SZ_ZStd_v%s_CStreamInSize" % v)(), 0)
            self.assertGreater(getattr(L, "SZ_ZStd_v%s_CStreamOutSize" % v)(), 0)

    def test_prepare_switches_are_callable_twice(self):
        # hashes.md 6.3: never called by GrindCore.net; calling them must be harmless and idempotent
        for fn in ("SZ_Sha1Prepare", "SZ_Sha256Prepare", "SZ_Black2sp_Prepare"):
            getattr(gctest.LIB, fn)()
            getattr(gctest.LIB, fn)()

    def test_create_destroy_pairs(self):
        L = gctest.LIB
        pairs = [("FL2_createCCtx", "FL2_freeCCtx"), ("FL2_createCStream", "FL2_freeCStream"),
                 ("FL2_createDCtx", "FL2_freeDCtx"), ("FL2_createDStream", "FL2_freeDStream"),
                 ("SZ_Lzma_v25_01_Enc_Create", "SZ_Lzma_v25_01_Enc_Destroy"),
                 ("SZ_Lzma2_v25_01_Enc_Create", "SZ_Lzma2_v25_01_Enc_Destroy")]
        for make, free in pairs:
            with self.subTest(make):
                p = getattr(L, make)()
                self.assertTrue(p, "%s returned NULL" % make)
                getattr(L, free)(p)
