"""python -m gctest --lib <libGrindCore.so | GrindCore.dll | libGrindCore.dylib> [--refs DIR] [--rid RID]
       [-k pattern,...] [--without input,...] [--json out.json] [-v]

-k and --without take comma-separated lists, and can be repeated. A run fails if a test went without an input it
needed (a reference, Brotli's test streams, a Python module; gctest.INPUTS), unless that input can't be had for the
RID or --without accepts its absence ("all": any). The end of the run lists every skip by kind."""
import argparse
import json
import os
import platform
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import gcnative  # noqa: E402
import gctest  # noqa: E402
from gcnative import _spec  # noqa: E402


# --refs DIR, laid out as tools/native-test/ref: out-<rid>/ holds the RID's references (ref/build_*_ref.py --out), and
# tb/ the release tarballs and Brotli's test streams (ref/build_brotli_ref.py --fixtures-only, for RIDs without an
# official Brotli). The older per-host folder names are still found.
OLD_REF_DIRS = {"linux-x64": "out", "linux-x86": "out-x86", "linux-x64-legacy": "out-legacy", "linux-arm": "out-arm",
                "linux-arm64": "out-arm64", "osx-arm64": "out-arm64", "osx-x64": "out-x64", "win-x64": "out-win64",
                "win-arm64": "out-arm64"}


def set_refs(root, rid):
    """Point each GC_REF_* that isn't set already at root's references for `rid`: (folder or None, [what was set])."""
    names = ["out-" + rid] + ([OLD_REF_DIRS[rid]] if rid in OLD_REF_DIRS else [])
    d = next((os.path.join(root, n) for n in names if os.path.isdir(os.path.join(root, n))), None)
    ext = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
    env = {"GC_REF_BROTLI": os.pathsep.join(x for x in (d, os.path.join(root, "tb")) if x)}
    if d:
        env.update(GC_REF_ZLIB=d, GC_REF_ZSTD=d, GC_REF_LZ4=d, GC_REF_FL2=d,
                   GC_REF_7ZIP=os.path.join(d, "lib7zref" + ext))
    done = []
    for k in sorted(env):
        if not os.environ.get(k):
            os.environ[k] = env[k]
            done.append(k)
    return d, done


def comma_list(values):
    return [x.strip() for v in values or [] for x in v.split(",") if x.strip()]


def main():
    ap = argparse.ArgumentParser(prog="gctest")
    ap.add_argument("--lib", required=True)
    ap.add_argument("--json")
    ap.add_argument("-k", dest="pattern", action="append",
                    help="only tests whose id contains one of these (comma-separated, repeatable)")
    ap.add_argument("--refs", help="a folder of references: out-<rid>/ and tb/, as tools/native-test/ref")
    ap.add_argument("--rid", help="the library's RID, where the process can't tell (linux-x64-legacy, "
                                  "linux-arm64-legacy); default: this process's, %s" % gcnative.target())
    ap.add_argument("--without", action="append", help="inputs whose absence is accepted (comma-separated, "
                                                       "repeatable; all: any): " + ", ".join(sorted(gctest.INPUTS)))
    ap.add_argument("-v", dest="verbose", action="store_true")
    a = ap.parse_args()
    patterns, without = comma_list(a.pattern), set(comma_list(a.without))
    unknown = without - set(gctest.INPUTS) - {"all"}
    if unknown:
        ap.error("--without: no input called %s (the inputs: %s)" % (", ".join(sorted(unknown)),
                                                                    ", ".join(sorted(gctest.INPUTS))))
    gctest.RID = a.rid or gcnative.target()
    if gctest.RID != gcnative.target() and not gctest.RID.startswith(gcnative.target() + "-"):
        ap.error("--rid %s doesn't match this process (%s)" % (gctest.RID, gcnative.target()))

    gctest.LIB = gcnative.load(a.lib)
    print("GrindCore native tests: %s (%s, Python %s %d-bit, %s)" % (
        a.lib, gctest.RID, platform.python_version(), 64 if sys.maxsize > 2 ** 32 else 32, platform.platform()))
    if a.refs:
        d, done = set_refs(a.refs, gctest.RID)
        print("references: %s%s" % (d or "no folder for %s in %s" % (gctest.RID, a.refs),
                                    " (set %s)" % ", ".join(done) if done else ""))
    suite = unittest.defaultTestLoader.discover(HERE, pattern="test_*.py", top_level_dir=os.path.dirname(HERE))
    if patterns:
        suite = unittest.TestSuite(t for t in _flatten(suite) if any(p in t.id() for p in patterns))
    # the child processes' calls count too: they record them in this file (gcnative.Library)
    fd, calls_log = tempfile.mkstemp(prefix="gctest-calls-", suffix=".txt")
    os.close(fd)
    os.environ[gcnative.CALLS_ENV] = calls_log
    t0 = time.time()
    try:
        result = unittest.TextTestRunner(verbosity=2 if a.verbose else 1, stream=sys.stdout).run(suite)
        in_children = gcnative.read_calls(calls_log, gctest.LIB.path) - gctest.LIB.called
    finally:
        del os.environ[gcnative.CALLS_ENV]
        os.remove(calls_log)

    lib = gctest.LIB
    called = lib.called | in_children
    present = sorted(n for n in gcnative.EXPORTS if lib.has(n))
    uncalled = [n for n in present if n not in called]
    print("export coverage: %d of %d exports present here were called (%d only in child processes); %d not yet%s" % (
        len(present) - len(uncalled), len(present), len(in_children & set(present)), len(uncalled),
        (": " + ", ".join(uncalled)) if 0 < len(uncalled) <= 20 else ""))
    unaccepted = report_skips(result, without)
    if a.json:
        with open(a.json, "w") as f:
            json.dump({
                "target": gctest.RID, "library": os.path.abspath(a.lib), "python": platform.python_version(),
                "platform": platform.platform(), "seconds": round(time.time() - t0, 1),
                "tests": result.testsRun, "failures": [t.id() for t, _ in result.failures],
                "errors": [t.id() for t, _ in result.errors], "skipped": {t.id(): r for t, r in result.skipped},
                "missing_inputs": {k: sorted(v) for k, v in sorted(gctest.MISSING.items())},
                "missing_inputs_unaccepted": unaccepted,
                "exports_present": len(present), "exports_called": sorted(called),
                "exports_called_only_in_children": sorted(in_children), "exports_uncalled": uncalled,
            }, f, indent=1)
    return 0 if result.wasSuccessful() and not unaccepted else 1


def report_skips(result, without):
    """Print every skip by kind, and the inputs tests went without. Returns those the run doesn't accept."""
    known = sorted(r.split(":")[0][len("known defect "):] for _, r in result.skipped if r.startswith("known defect "))
    other = {}
    for t, r in result.skipped:
        if not r.startswith("known defect ") and not r.startswith("missing "):
            other.setdefault(r, []).append(t.id())
    print("skips: %d known defect(s)%s; %d for missing inputs; %d other(s)" % (
        len(known), " (%s)" % ", ".join(known) if known else "",
        sum(1 for _, r in result.skipped if r.startswith("missing ")), sum(len(v) for v in other.values())))
    for r, ids in sorted(other.items()):
        print("  other: %s -- %s" % (r[:150], ", ".join(i.replace("gctest.", "") for i in ids)))
    unaccepted = []
    for name, ids in sorted(gctest.MISSING.items()):
        why = gctest.unavailable(name, gctest.RID)
        state = ("can't be had for %s: %s" % (gctest.RID, why) if why else
                 "accepted (--without)" if name in without or "all" in without else "NOT ACCEPTED")
        print("  missing input %s: %d test(s) went without it, %s" % (name, len(ids), state))
        if not why and name not in without and "all" not in without:
            unaccepted.append(name)
    if unaccepted:
        print("FAILED (missing inputs): %s. Set them up (--refs DIR, or %s), or accept their absence with "
              "--without %s" % (", ".join(unaccepted), "; ".join(gctest.INPUTS[n] for n in unaccepted),
                                ",".join(unaccepted)))
    return unaccepted


def _flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            for u in _flatten(t):
                yield u
        else:
            yield t


if __name__ == "__main__":
    sys.exit(main())
