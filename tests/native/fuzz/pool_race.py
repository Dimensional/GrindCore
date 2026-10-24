"""A deterministic check of Fast-LZMA2's thread-pool wait (the workspace's audit/other-codecs.md 4.4.1, finding 12).
  python3 fuzz/pool_race.py [--cc clang-15] [--out fuzz/out]
FL2POOL_waitAll used to check the pool without its lock, so a multithreaded encode or decode could go on while a worker
was just starting its job: wrong output, crashes, a decoder freed under its worker. The window is two memory loads wide,
so this holds it open. It builds fl2_pool_race.c with AddressSanitizer against GrindCore's own Fast-LZMA2 sources
(fuzz.py's list), with a copy of fl2_pool.c whose worker sleeps 200 ms between taking a job (++queueIndex) and counting
itself busy (++numThreadsBusy). The delay is in that copy only; the vendored file isn't touched. Then it decodes valid
multi-block data with 2 threads ("dec") and compresses with 2 threads ("enc"). A pool with the bug crashes or gives
wrong data in both; a fixed one passes both (2026-10-24: both crash before the fix, both pass after). Needs Linux and
a clang or gcc with AddressSanitizer, as fuzz.py does. Plain Python 3.6+, standard library only.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fuzz  # noqa: E402  (fuzz.py: the Fast-LZMA2 sources and include paths, the default compiler)

DELAY = "        usleep(200000); /* pool_race.py: holds the window between taking a job and counting it busy */\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--cc", default=fuzz.default_cc())
    ap.add_argument("--out", default=os.path.join(HERE, "out"))
    a = ap.parse_args()
    sources, includes, _ = fuzz.TARGETS["fl2"]
    os.makedirs(a.out, exist_ok=True)
    pool = next(s for s in sources if s.endswith("fl2_pool.c"))
    with open(pool, encoding="utf-8", errors="replace") as f:
        text = f.read().replace("\r\n", "\n")
    take = "        ++ctx->queueIndex;\n"
    if text.count(take) != 1:
        sys.exit("pool_race: fl2_pool.c no longer has the line the delay goes after (%r)" % take.strip())
    delayed = os.path.join(a.out, "fl2_pool_delayed.c")
    with open(delayed, "w", encoding="utf-8", newline="\n") as f:
        f.write("#include <unistd.h>\n" + text.replace(take, take + DELAY))
    exe = os.path.join(a.out, "fl2_pool_race")
    cmd = ([a.cc, "-g", "-O1", "-fsanitize=address", "-pthread"] + ["-I" + i for i in includes]
           + ["-o", exe, os.path.join(HERE, "fl2_pool_race.c"), delayed] + [s for s in sources if s != pool])
    print("$ " + " ".join(cmd), flush=True)
    subprocess.check_call(cmd)
    prefix = []
    arch = os.uname().machine
    if subprocess.call(["setarch", arch, "-R", "true"], stderr=subprocess.DEVNULL) == 0:
        prefix = ["setarch", arch, "-R"]  # as fuzz.py: clang 15's ASan can crash at start with full randomisation
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=0")
    failed = 0
    for mode in ("dec", "enc"):
        r = subprocess.run(prefix + [exe, mode], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           universal_newlines=True, errors="replace", env=env)
        lines = r.stdout.splitlines()
        said = next((l for l in lines if l.startswith(("ok:", "decode ", "enc:", "compress:"))), None)
        asan = next((l for l in lines if l.startswith("SUMMARY: AddressSanitizer")), None)
        ok = r.returncode == 0 and said and said.startswith("ok:")
        failed += not ok
        print("%s: %s" % (mode, said if ok else "FAILED (exit %d): %s" % (r.returncode, asan or said or lines[-1:])),
              flush=True)
    print("pool_race: %s" % ("the pool waits correctly" if not failed else "the pool's wait lets jobs run on"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
