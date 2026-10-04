"""LZMA2 stream encoder (the multi-call API behind GrindCore.net's Lzma2Stream), checked by Python's own LZMA2 decoder.

Also the multicallMode defect (audit/lzma.md 3.3): LzmaEnc_Construct never initialises the field, and a leftover 2
makes LzmaEnc_CodeOneBlock take the hook's flush-only branch (LzmaEnc.c:2694). In the LZMA2 path, CodeOneMemBlock
(Lzma2Enc.c:146) then returns a chunk without the range coder's final bytes, i.e. a stream that doesn't decode. The
forced and real-API cases run in child processes."""
import json
import unittest

import gctest
from gctest import lzma_util as U
from gctest.test_hashes import child, known

PAYLOAD = 3 << 20   # several LZMA2 chunks (each at most 2 MiB unpacked, 64 KiB packed)


def forced_case(value, level=1):
    """Child program: encode with multicallMode forced to value, decode with Python, print a JSON result."""
    return """
        import json, zlib
        from gctest import lzma_util as U
        why = U.verify_offsets(L)
        if why:
            print(json.dumps({"unverified": why}))
        else:
            payload = U.data(%d)
            r = U.encode(L, payload, level=%d, force=%d)
            out, err = U.py_decode(r["stream"], r["prop"]) if r["rc"] == 0 else (None, "encode rc=%%d" %% r["rc"])
            print(json.dumps({"rc": r["rc"], "bytes": len(r["stream"]), "error": err, "offset": U._mode_offset,
                              "decoded": None if out is None else len(out), "match": out == payload}))
    """ % (PAYLOAD, level, value)


def chain_case(rounds):
    """Child program, real API only: an LZMA stream encoder abandoned mid-stream, then an LZMA2 stream encode, repeated."""
    return """
        import json
        from gctest import lzma_util as U
        offsets = U.verify_offsets(L) is None
        payload = U.data(1 << 20)
        results = []
        for i in range(%d):
            freed_at, freed_mode = U.lzma_stream_abandoned(L, seed=i)
            r = U.encode(L, payload, level=1)
            out, err = U.py_decode(r["stream"], r["prop"]) if r["rc"] == 0 else (None, "encode rc=%%d" %% r["rc"])
            results.append({"reused": (r["inner"] == freed_at) if offsets else None,
                            "freed_mode": freed_mode if offsets else None, "ok": out == payload, "error": err})
        print(json.dumps(results))
    """ % rounds


def run_child(test, code, timeout=300):
    rc, out, err = child(code, timeout=timeout)
    test.assertEqual(rc, 0, "child failed (%s): %s" % (rc, err[-800:]))
    return json.loads(out.strip().splitlines()[-1])


class Lzma2Stream(unittest.TestCase):
    def setUp(self):
        if U.lzma is None:
            self.skipTest("this Python has no lzma module (the independent decoder)")
        self.L = gctest.LIB

    def test_stream_round_trip(self):
        """Unforced, as GrindCore.net uses it: level 1 (Fastest) and 5 (default), decoded by Python's lzma."""
        payload = U.data(PAYLOAD)
        for level in (1, 5):
            with self.subTest(level=level):
                r = U.encode(self.L, payload, level=level)
                self.assertEqual(r["rc"], 0)
                out, err = U.py_decode(r["stream"], r["prop"])
                self.assertIsNone(err)
                self.assertEqual(out, payload)
                print("  LZMA2 stream, level %d: %d -> %d bytes, decoded by Python's lzma" % (
                    level, len(payload), len(r["stream"])))

    def test_leftover_multicall_mode_is_contained(self):
        """multicallMode forced to each value the multi-call API leaves behind. Unfixed: 2 gives a stream that
        doesn't decode. Fixed: CodeOneMemBlock resets the field, so every value encodes correctly."""
        results = {}
        for value in (0, 1, 2, 3):
            res = run_child(self, forced_case(value))
            if "unverified" in res:
                self.skipTest("struct offsets not verified for this library: " + res["unverified"])
            results[value] = res
            print("  multicallMode (at %#x) forced to %d: rc=%s, %s bytes, %s" % (
                res["offset"], value, res["rc"], res["bytes"], "decodes correctly" if res["match"] else
                "DOES NOT DECODE (%s; %s of %d bytes recovered)" % (res["error"], res["decoded"], PAYLOAD)))
        bad = [v for v, r in results.items() if not r["match"]]
        if bad == [2]:
            known(self, "lzma-multicallmode")
        self.assertEqual(bad, [], "values that broke the stream: %s" % bad)

    def test_abandoned_lzma_stream_then_lzma2_stream(self):
        """Real API only, the way the .NET failure could arise: an LZMA stream encoder freed mid-stream (it holds
        multicallMode == 2), then an LZMA2 stream whose new inner encoder may get the same memory."""
        rounds = 20
        res = run_child(self, chain_case(rounds))
        reused = sum(1 for r in res if r["reused"])
        broken = [r for r in res if not r["ok"]]
        print("  %d rounds: freed with multicallMode=%s; the LZMA2 encoder reused that memory in %s; "
              "%d streams don't decode%s" % (
                  rounds, sorted(set(r["freed_mode"] for r in res)), reused if res[0]["reused"] is not None else "?",
                  len(broken), " (%s)" % broken[0]["error"] if broken else ""))
        if broken:
            known(self, "lzma-multicallmode")
