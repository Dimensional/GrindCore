"""python -m gctest --lib <libGrindCore.so | GrindCore.dll | libGrindCore.dylib> [--json out.json] [-k pattern]..."""
import argparse
import json
import os
import platform
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import gcnative  # noqa: E402
import gctest  # noqa: E402
from gcnative import _spec  # noqa: E402


def main():
    ap = argparse.ArgumentParser(prog="gctest")
    ap.add_argument("--lib", required=True)
    ap.add_argument("--json")
    ap.add_argument("-k", dest="pattern", action="append", help="only tests whose id contains this (repeatable: any)")
    ap.add_argument("-v", dest="verbose", action="store_true")
    a = ap.parse_args()

    gctest.LIB = gcnative.load(a.lib)
    print("GrindCore native tests: %s (%s, Python %s %d-bit, %s)" % (
        a.lib, gcnative.target(), platform.python_version(), 64 if sys.maxsize > 2 ** 32 else 32, platform.platform()))
    suite = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py", top_level_dir=os.path.dirname(HERE))
    if a.pattern:
        suite = unittest.TestSuite(t for t in _flatten(suite) if any(p in t.id() for p in a.pattern))
    t0 = time.time()
    result = unittest.TextTestRunner(verbosity=2 if a.verbose else 1, stream=sys.stdout).run(suite)

    lib = gctest.LIB
    present = sorted(n for n in gcnative.EXPORTS if lib.has(n))
    uncalled = [n for n in present if n not in lib.called]
    print("export coverage: %d of %d exports present here were called; %d not yet" % (
        len(present) - len(uncalled), len(present), len(uncalled)))
    if a.json:
        with open(a.json, "w") as f:
            json.dump({
                "target": gcnative.target(), "library": os.path.abspath(a.lib), "python": platform.python_version(),
                "platform": platform.platform(), "seconds": round(time.time() - t0, 1),
                "tests": result.testsRun, "failures": [t.id() for t, _ in result.failures],
                "errors": [t.id() for t, _ in result.errors], "skipped": [t.id() for t, _ in result.skipped],
                "exports_present": len(present), "exports_called": sorted(lib.called), "exports_uncalled": uncalled,
            }, f, indent=1)
    return 0 if result.wasSuccessful() else 1


def _flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            for u in _flatten(t):
                yield u
        else:
            yield t


if __name__ == "__main__":
    sys.exit(main())
