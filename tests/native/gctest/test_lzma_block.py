"""LZMA block encoder (MemEncode, what GrindCore.net's LzmaBlock uses), checked by Python's lzma (.lzma "alone").

Also the hang side of the multicallMode defect (audit/lzma.md 3.3): with a leftover 2, LzmaEnc_CodeOneBlock takes the
flush-only branch and never sets `finished`, so LzmaEnc_Encode2's loop (LzmaEnc.c:3022) never ends and MemEncode
never returns. Those cases run in child processes that are killed after a time limit."""
import json
import os
import subprocess
import sys
import textwrap
import unittest

import gctest
from gctest import lzma_util as U
from gctest.test_hashes import known

BLOCK = 256 << 10
HANG_LIMIT = 20      # seconds; a normal encode here takes well under 1 s, even emulated
ROUNDS = 20


def spawn(code, timeout):
    """Run code in a fresh interpreter with gcnative loaded on the library under test (as L). Unlike test_hashes.child,
    a child that is still running at the limit is killed and its output so far is kept: the last line it printed says
    where it stopped. Returns (returncode or "timeout", stdout, stderr)."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    prog = "import sys, ctypes; sys.path.insert(0, %r)\nimport gcnative\nL = gcnative.load(%r)\n" % (here, gctest.LIB.path)
    p = subprocess.Popen([sys.executable, "-c", prog + textwrap.dedent(code)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    try:
        out, err = p.communicate(timeout=timeout)
        status = p.returncode
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        status = "timeout"
    return status, out.decode(errors="replace"), err.decode(errors="replace")


def lines(out):
    return [json.loads(l) for l in out.splitlines() if l.startswith("{")]


class LzmaBlock(unittest.TestCase):
    def setUp(self):
        if U.lzma is None:
            self.skipTest("this Python has no lzma module (the independent decoder)")
        self.L = gctest.LIB

    def test_block_round_trip(self):
        """Unforced, as GrindCore.net uses it: levels 1, 5 and 9, decoded by Python's lzma."""
        payload = U.data(BLOCK)
        for level in (1, 5, 9):
            with self.subTest(level=level):
                r = U.block_encode(self.L, payload, level=level)
                self.assertEqual(r["rc"], 0)
                out, err = U.py_decode_alone(r["stream"])
                self.assertIsNone(err)
                self.assertEqual(out, payload)
        print("  LZMA block, levels 1/5/9: %d bytes each way, decoded by Python's lzma" % BLOCK)

    def test_leftover_multicall_mode_is_contained(self):
        """multicallMode forced to each value the multi-call API leaves behind, then MemEncode. Unfixed: 2 never
        returns. Fixed: MemEncode resets the field, so every value encodes correctly."""
        results = {}
        for value in (0, 1, 2, 3):
            status, out, err = spawn("""
                import json
                from gctest import lzma_util as U
                off, why = U.find_mode_offset(L)
                if why:
                    print(json.dumps({"unverified": why}))
                else:
                    payload = U.data(%d)
                    print(json.dumps({"offset": off}), flush=True)
                    r = U.block_encode(L, payload, force=%d)
                    out, err = U.py_decode_alone(r["stream"]) if r["rc"] == 0 else (None, "rc=%%d" %% r["rc"])
                    print(json.dumps({"rc": r["rc"], "match": out == payload, "error": err}), flush=True)
            """ % (BLOCK, value), HANG_LIMIT)
            got = lines(out)
            if got and "unverified" in got[0]:
                self.skipTest("multicallMode offset not found for this library: " + got[0]["unverified"])
            self.assertTrue(got, "child failed (%s): %s" % (status, err[-800:]))
            if status == "timeout":
                results[value] = "HANGS (no return in %d s)" % HANG_LIMIT
            else:
                self.assertEqual(status, 0, err[-800:])
                results[value] = "decodes correctly" if got[-1]["match"] else "WRONG OUTPUT (%s)" % got[-1]["error"]
            print("  multicallMode (at %#x) forced to %d: MemEncode %s" % (got[0]["offset"], value, results[value]))
        bad = sorted(v for v, r in results.items() if r != "decodes correctly")
        if bad == [2] and results[2].startswith("HANGS"):
            known(self, "lzma-multicallmode")
        self.assertEqual(bad, [], "values that broke MemEncode: %s" % bad)

    def test_abandoned_lzma_stream_then_block(self):
        """Real API only: an LZMA stream encoder freed mid-stream (holding multicallMode == 2), then a block encode as
        LzmaBlock does it, repeated. On an unfixed library a block encoder that inherits the 2 never returns."""
        status, out, err = spawn("""
            import json
            from gctest import lzma_util as U
            U.find_mode_offset(L)
            payload = U.data(%d)
            for i in range(%d):
                freed_at, freed_mode = U.lzma_stream_abandoned(L, seed=i)
                log = lambda enc: print(json.dumps({"round": i, "start": True, "reused": enc == freed_at,
                                                    "freed_mode": freed_mode}), flush=True)
                r = U.block_encode(L, payload, before=log)
                out, err = U.py_decode_alone(r["stream"]) if r["rc"] == 0 else (None, "rc=%%d" %% r["rc"])
                print(json.dumps({"round": i, "ok": out == payload, "error": err}), flush=True)
        """ % (BLOCK, ROUNDS), HANG_LIMIT + 10)
        got = lines(out)
        self.assertTrue(got, "child failed (%s): %s" % (status, err[-800:]))
        starts = [g for g in got if g.get("start")]
        done = [g for g in got if "ok" in g]
        broken = [g for g in done if not g["ok"]]
        reused = sum(1 for g in starts if g["reused"])
        if status == "timeout":
            hung = starts[-1]
            print("  round %d of %d HANGS in MemEncode (block encoder %s the abandoned stream encoder's memory, freed "
                  "with multicallMode=%s); %d earlier rounds finished" % (
                      hung["round"] + 1, ROUNDS, "reused" if hung["reused"] else "did not reuse", hung["freed_mode"],
                      len(done)))
            known(self, "lzma-multicallmode")
        self.assertEqual(status, 0, err[-800:])
        print("  %d rounds: block encoder reused the abandoned stream encoder's memory in %d; %d wrong outputs" % (
            ROUNDS, reused, len(broken)))
        self.assertEqual(broken, [])
