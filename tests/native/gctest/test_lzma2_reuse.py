"""LZMA2 encoder handles reused across modes: a multithreaded Encode2, then the multi-call Prepare (audit/lzma.md 3.3).

Unfixed, Lzma2Enc_EncodeMultiCallPrepare sets coders[1..].enc, outBufs[] and the MtCoder to NULL/False without
freeing them: every cycle leaks a worker's LZMA encoder (2.5-4.5 MB), two 1 MiB output buffers and the MtCoder's
threads. This needs no leak checker: a child process repeats the cycle and watches its own memory (and on Linux its
thread count), so it runs on every RID. leakcheck.py shows the same leak by allocation site."""
import json
import unittest

import gctest
from gctest.test_hashes import child, known

CYCLES = 12


class Lzma2HandleReuse(unittest.TestCase):
    def test_prepare_after_multithreaded_encode_frees_everything(self):
        rc, out, err = child("""
            import ctypes, json, os, sys
            from gctest import lzma_util as U

            def memory():
                # this process's memory, by each OS's own counter: resident (Linux), peak resident (macOS),
                # private bytes (Windows). Peak or current both rise with a leak and stay flat without one.
                if sys.platform.startswith("linux"):
                    with open("/proc/self/statm") as f:
                        return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
                if sys.platform == "darwin":
                    import resource
                    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                class PMC(ctypes.Structure):
                    _fields_ = [("cb", ctypes.c_uint32), ("PageFaultCount", ctypes.c_uint32)] + \\
                               [(n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize",
                                "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]
                c = PMC(); c.cb = ctypes.sizeof(c)
                k = ctypes.WinDLL("kernel32"); k.GetCurrentProcess.restype = ctypes.c_void_p
                ctypes.WinDLL("psapi").GetProcessMemoryInfo(ctypes.c_void_p(k.GetCurrentProcess()), ctypes.byref(c), c.cb)
                return c.PrivateUsage

            def threads():
                try:
                    with open("/proc/self/status") as f:
                        return int([l for l in f if l.startswith("Threads:")][0].split()[1])
                except (IOError, OSError):
                    return None

            data = U.data(3 << 20)
            out = ctypes.create_string_buffer(len(data) + (1 << 16))
            def cycle():
                enc = L.SZ_Lzma2_v25_01_Enc_Create()
                p = L.struct.CLzma2EncProps()
                L.SZ_Lzma2_v25_01_Enc_Construct(ctypes.byref(p))
                p.lzmaProps.level, p.lzmaProps.numThreads = 1, 1
                p.numBlockThreads_Max, p.numTotalThreads, p.blockSize = 2, 2, 1 << 20
                L.SZ_Lzma2_v25_01_Enc_Normalize(ctypes.byref(p))
                L.SZ_Lzma2_v25_01_Enc_SetProps(enc, ctypes.byref(p))
                n = ctypes.c_size_t(len(out))
                assert L.SZ_Lzma2_v25_01_Enc_Encode2(enc, out, ctypes.byref(n), data, len(data), None) == 0
                assert L.SZ_Lzma2_v25_01_Enc_EncodeMultiCallPrepare(enc) == 0
                L.SZ_Lzma2_v25_01_Enc_Destroy(enc)

            for _ in range(2):        # warm-up: allocator pools, the thread-pool shape
                cycle()
            m0, t0 = memory(), threads()
            for _ in range(%d):
                cycle()
            m1, t1 = memory(), threads()
            print(json.dumps({"growth": m1 - m0, "threads": None if t0 is None else t1 - t0}))
        """ % (CYCLES - 2), timeout=300)
        self.assertEqual(rc, 0, err[-800:])
        r = json.loads(out.strip().splitlines()[-1])
        mb = r["growth"] / float(1 << 20)
        print("  %d cycles of 2-thread Encode2 -> Prepare -> Destroy: memory grew %.1f MiB%s" % (
            CYCLES - 2, mb, "" if r["threads"] is None else ", threads %+d" % r["threads"]))
        leaked = mb > 20 or (r["threads"] or 0) > 2
        if leaked:
            known(self, "lzma2-prepare-leak")
