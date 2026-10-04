"""The vendored libraries' own test suites, built from GrindCore's vendored sources with the compiler and flags of a
GrindCore build (audit/build-exam.md, part 5).

Each library's release tree supplies its tests. GrindCore's copy of the library is laid over the release's sources,
so the tests exercise the exact code GrindCore ships, compiled the way GrindCore compiles it: the compiler and the
flags come from that build's compile_commands.json (optimisation, hardening, -fwrapv/-fsigned-char/-ffp-contract,
the architecture flags, and each library's own defines).

Run it in the RID's build image with the build tree mounted where it was built, so the paths in compile_commands.json
hold; the audit workspace's tools/native-build/hosts/upstream-tests.sh does that:
  python3 upstream_tests.py --src <tree>/src/native --cc-json <tree>/artifacts/obj/native/<rid>/compile_commands.json
                            --rid <rid> --work <dir> [--tarballs ref/tb] [--time 60] [--only zstd-1.5.7,lz4,...]
Release archives come from --tarballs, or are downloaded; each is checked against a pinned or published SHA-256.
Prints one line per suite (OK, FAIL or SKIP with the reason); each suite's full output is in <work>/<suite>.log.
Python 3.6+, stdlib only.
"""
import argparse, glob, hashlib, json, os, re, shlex, shutil, subprocess, sys, tarfile, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_brotli_ref, build_fl2_ref, build_lz4_ref, build_zstd_ref  # noqa: E402  (their fetch() checks the archives)

# Archives the reference builders don't fetch: name -> (URL, SHA-256). zlib's and bzip2's are the published values;
# zlib-ng's and BLAKE3's are GitHub tag archives, recorded at the first fetch (2026-10-04).
PINNED = {
    "zlib-ng-2.2.1.tar.gz": ("https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.2.1.tar.gz",
                             "ec6a76169d4214e2e8b737e0850ba4acb806c69eeace6240ed4481b9f5c57cdf"),
    "zlib-1.3.1.tar.gz": ("https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz",
                          "9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23"),
    "bzip2-1.0.8.tar.gz": ("https://sourceware.org/pub/bzip2/bzip2-1.0.8.tar.gz",
                           "ab5a03176ee106d3f0fa90e381da478ddae405918153cca248e682cd0c4a2269"),
    "blake3-0.3.7.tar.gz": ("https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/0.3.7.tar.gz",
                            "304b3608770cc91a151c7c4af5541dd6dd29716bad449ae5a418643ef15bcc5b"),
}

# compile_commands defines that belong to GrindCore's own build, not to a library
INTERNAL = ("-DHOST_", "-DTARGET_", "-DDISABLE_CONTRACTS", "-DURTBLDENV", "-DCOMPILER_SUPPORTS", "-DMY_ZCALLOC",
            "-DGrindCore_EXPORTS", "-DPALEXPORT")
KEEP = ("-O", "-g", "-f", "-m", "--target", "-D_FORTIFY_SOURCE", "-D_FILE_OFFSET_BITS", "-D_TIME_BITS", "-DNDEBUG")
DROP = ("-ferror-limit", "-fvisibility", "-fdiagnostics", "-fcolor")


class Ctx(object):
    def __init__(self, a):
        self.a = a
        self.src = os.path.abspath(a.src)
        self.work = os.path.abspath(a.work)
        os.makedirs(self.work, exist_ok=True)
        self.jobs = str(os.cpu_count() or 2)
        cmds = json.load(open(a.cc_json))
        self.cmds = [(e["file"].replace("\\", "/"), shlex.split(e["command"]) if "command" in e else e["arguments"])
                     for e in cmds]
        self.cc = self.cmds[0][1][0]
        common = None
        for _, args in self.cmds:
            s = set(args[1:])
            common = s if common is None else common & s
        self.common = common
        first, self.flags, i = self.cmds[0][1], [], 1
        while i < len(first):
            x = first[i]
            if x in ("-arch", "-isysroot", "-target") and i + 1 < len(first):   # two-word flags (macOS, cross)
                self.flags += [x, first[i + 1]]
                i += 1
            elif x in common and x.startswith(KEEP) and not x.startswith(DROP):
                self.flags.append(x)
            i += 1
        self.cxx = self.cc.replace("clang-", "clang++-") if "clang-" in self.cc else \
            self.cc.replace("clang", "clang++") if self.cc.endswith("clang") else "c++"
        self.arch = ("arm64" if a.rid.endswith(("arm64", "arm64-legacy")) else "arm" if a.rid == "linux-arm" else "x86")

    def lib_flags(self, path_part):
        """A library's own defines (and -include) from GrindCore's compile command for one of its files."""
        for f, args in self.cmds:
            if f.endswith(path_part):
                out, i = [], 1
                while i < len(args):
                    x = args[i]
                    if x == "-include":
                        out += [x, args[i + 1]]
                        i += 1
                    elif x.startswith("-D") and x not in self.common and not x.startswith(INTERNAL):
                        out.append(x)
                    i += 1
                return out
        raise RuntimeError("no compile command for %s" % path_part)

    def log(self, suite):
        return os.path.join(self.work, suite + ".log")

    def run(self, suite, cmd, cwd, timeout=3600, env=None):
        with open(self.log(suite), "a") as f:
            f.write("\n$ (cd %s) %s\n" % (cwd, " ".join(cmd)))
            f.flush()
            try:
                r = subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT, timeout=timeout,
                                   env=dict(os.environ, **(env or {})))
                f.write("[exit %d]\n" % r.returncode)
                return r.returncode
            except subprocess.TimeoutExpired:
                f.write("[timeout after %d s]\n" % timeout)
                return "timeout"

    def archive(self, name):
        """A release archive: from --tarballs if present, else downloaded; checked against PINNED."""
        url, sha = PINNED[name]
        path = os.path.join(self.a.tarballs, name) if self.a.tarballs else None
        if not path or not os.path.exists(path):
            path = os.path.join(self.work, name)
            if not os.path.exists(path):
                with urllib.request.urlopen(url, timeout=120) as r, open(path, "wb") as f:
                    f.write(r.read())
        with open(path, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got != sha:
            raise RuntimeError("%s: SHA-256 %s, expected %s" % (path, got, sha))
        return path

    def release(self, suite, archive):
        """A fresh copy of the release tree for one suite."""
        dest = os.path.join(self.work, suite)
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        os.makedirs(dest)
        with tarfile.open(archive) as t:
            top = t.getnames()[0].split("/")[0]
            if hasattr(tarfile, "data_filter"):
                t.extractall(dest, filter="data")
            else:
                t.extractall(dest)
        return os.path.join(dest, top)


def overlay(src, dst, skip=()):
    """Copy GrindCore's vendored files over the release tree's. Returns (replaced and different, added)."""
    changed = added = 0
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        if rel.split(os.sep)[0] in skip:
            continue
        for n in files:
            s, d = os.path.join(root, n), os.path.join(dst, rel, n)
            if os.path.exists(d):
                if open(s, "rb").read().replace(b"\r\n", b"\n") != open(d, "rb").read().replace(b"\r\n", b"\n"):
                    changed += 1
            else:
                added += 1
            os.makedirs(os.path.dirname(d), exist_ok=True)
            shutil.copyfile(s, d)
    return changed, added


# ---- the suites: each returns a short detail string, or raises Fail / Skip -----------------------------------------

class Fail(Exception):
    pass


class Skip(Exception):
    pass


def need(rc, what):
    if rc != 0:
        raise Fail("%s: %s" % (what, rc))


def zstd(c, version):
    suite = "zstd-" + version
    tree = c.release(suite, build_zstd_ref.fetch(version, c.work, c.a.tarballs))
    if version == "1.5.7":
        changed, added = overlay(os.path.join(c.src, "external/facebook/zstd_v1_5_7"), os.path.join(tree, "lib"),
                                 skip=("seekable",))
        extras = c.lib_flags("zstd_v1_5_7/compress/zstd_compress.c")
        source = "GrindCore's lib/ (%d files differ from the release, %d added)" % (changed, added)
    else:
        # GrindCore's 1.5.2 is renamed ZSTD_v1_5_2_*, which upstream's tests can't link with: the release's own
        # sources (the same code, audit/zstd.md 9.3) with GrindCore's 1.5.2 defines under their upstream names
        extras = [x.replace("ZSTD_v1_5_2_", "ZSTD_") for x in c.lib_flags("zstd_v1_5_2/compress/zstd_compress.c")
                  if not x.startswith("-DZSTD_NAMESPACE")]
        source = "the release's lib/ (GrindCore's copy is renamed)"
    flags = " ".join(c.flags + extras)
    need(c.run(suite, ["make", "-j", c.jobs, "fuzzer", "zstreamtest", "CC=" + c.cc, "CFLAGS=" + flags,
                       "ZSTD_LEGACY_SUPPORT=0"], os.path.join(tree, "tests")), "build")
    t = "-T%ds" % c.a.time
    need(c.run(suite, ["./fuzzer", t], os.path.join(tree, "tests"), timeout=c.a.time * 4 + 300), "fuzzer")
    need(c.run(suite, ["./zstreamtest", t], os.path.join(tree, "tests"), timeout=c.a.time * 4 + 300), "zstreamtest")
    return "fuzzer and zstreamtest, %d s each; %s; flags %s" % (c.a.time, source, " ".join(extras))


def zstd_seekable(c):
    suite = "zstd-1.5.7-seekable"
    tree = c.release(suite, build_zstd_ref.fetch("1.5.7", c.work, c.a.tarballs))
    overlay(os.path.join(c.src, "external/facebook/zstd_v1_5_7"), os.path.join(tree, "lib"), skip=("seekable",))
    changed, _ = overlay(os.path.join(c.src, "external/facebook/zstd_v1_5_7/seekable"),
                         os.path.join(tree, "contrib/seekable_format"))
    extras = c.lib_flags("zstd_v1_5_7/seekable/zstdseek_decompress.c")
    # GrindCore renamed the seekable API ZSTD_v1_5_7_seekable_* (so it can't clash with 1.5.2's); upstream's test uses
    # the plain names, so a generated header maps them for the build
    sf = os.path.join(tree, "contrib/seekable_format")
    names = sorted(set(re.findall(r"\bZSTD_v1_5_7_(\w+)", open(os.path.join(sf, "zstd_seekable.h")).read())))
    mapping = os.path.join(sf, "tests", "plain_names.h")
    with open(mapping, "w") as m:
        m.write("".join("#define ZSTD_%s ZSTD_v1_5_7_%s\n" % (n, n) for n in names))
    extras += ["-include", mapping]
    # Test 4 expects an empty input to start with a zstd frame. GrindCore's 1.5.7 keeps 1.5.2's end-of-stream rule
    # (the user's decision, audit/other-codecs.md 4.8.1), so it writes just the seek table. That test reports the known
    # difference instead of ending the run, so test 5 still runs.
    test_c = os.path.join(sf, "tests", "seekable_tests.c")
    src = open(test_c).read()
    old = r'''            goto _test_error;
        }

        free(inBuffer);
        free(outBuffer);
        ZSTD_seekable_freeCStream(s);
    }
    printf("Success!\n");'''
    new = r'''            printf("known difference, by decision: GrindCore keeps 1.5.2's end-of-stream rule\n");
        } else {
            free(inBuffer);
            free(outBuffer);
            ZSTD_seekable_freeCStream(s);
            printf("Success!\n");
        }
    }'''
    if src.count(old) != 1:
        raise Fail("seekable_tests.c: test 4's text isn't as expected")
    open(test_c, "w").write(src.replace(old, new))
    srcs = sorted(f for d in ("common", "compress", "decompress") for f in glob.glob(os.path.join(tree, "lib", d, "*.c")))
    need(c.run(suite, [c.cc] + c.flags + extras + ["-I", os.path.join(tree, "lib"), "-I", os.path.join(tree, "lib/common"),
                                                    "-I", sf, os.path.join(sf, "tests/seekable_tests.c"),
                                                    os.path.join(sf, "zstdseek_compress.c"), os.path.join(sf, "zstdseek_decompress.c")]
               + srcs + ["-pthread", "-o", "seekable_tests"], os.path.join(sf, "tests")), "build")
    need(c.run(suite, ["./seekable_tests"], os.path.join(sf, "tests"), timeout=600), "seekable_tests")
    return ("seekable_tests; GrindCore's seekable code (%d files differ from the release: the renamed API and the audit's "
            "fixes), with %d plain names mapped for the test; test 4 is the known end-of-stream difference" %
            (changed, len(names)))


def lz4(c):
    suite = "lz4-1.10.0"
    tree = c.release(suite, build_lz4_ref.fetch("1.10.0", c.work, c.a.tarballs))
    changed, added = overlay(os.path.join(c.src, "external/lz4/lz4"), os.path.join(tree, "lib"))
    flags = " ".join(c.flags + c.lib_flags("lz4/lz4/lz4.c"))
    tests = os.path.join(tree, "tests")
    need(c.run(suite, ["make", "-j", c.jobs, "fuzzer", "frametest", "CC=" + c.cc, "CFLAGS=" + flags], tests), "build")
    t = "-T%d" % c.a.time
    need(c.run(suite, ["./fuzzer", t], tests, timeout=c.a.time * 4 + 300), "fuzzer")
    need(c.run(suite, ["./frametest", t], tests, timeout=c.a.time * 4 + 300), "frametest")
    return "fuzzer and frametest, %d s each; GrindCore's lib/ (%d files differ from the release)" % (c.a.time, changed)


def brotli(c):
    suite = "brotli-1.1.0"
    tree = c.release(suite, build_brotli_ref.fetch_tarball(c.work, c.a.tarballs))
    changed, added = overlay(os.path.join(c.src, "external/dotnet9_0/brotli_v1_1_0"), os.path.join(tree, "c"))
    extras = c.lib_flags("brotli_v1_1_0/enc/encode.c")
    srcs = [f for d in ("common", "dec", "enc") for f in sorted(glob.glob(os.path.join(tree, "c", d, "*.c")))]
    os.makedirs(os.path.join(tree, "bin", "tmp"), exist_ok=True)
    need(c.run(suite, [c.cc] + c.flags + extras + ["-I", os.path.join(tree, "c/include")] + srcs +
               [os.path.join(tree, "c/tools/brotli.c"), "-lm", "-o", "bin/brotli"], tree), "build")
    need(c.run(suite, ["bash", "tests/roundtrip_test.sh"], tree, timeout=3600), "roundtrip_test.sh")
    need(c.run(suite, ["bash", "tests/compatibility_test.sh"], tree, timeout=3600), "compatibility_test.sh")
    return "roundtrip and compatibility tests; GrindCore's c/ (%d files differ from the release: .NET's casts and the " \
           "audit's encode.c checks); %s" % (changed, " ".join(extras))


def zlib_ng(c):
    suite = "zlib-ng-2.2.1"
    tree = c.release(suite, c.archive("zlib-ng-2.2.1.tar.gz"))
    changed, added = overlay(os.path.join(c.src, "external/dotnet9_0/zlib-ng_v2_2_1"), tree)
    extras = [x for x in c.lib_flags("zlib-ng_v2_2_1/deflate.c") if x == "-include" or x.startswith(("/", "-DARM_"))]
    # GrindCore's wrapper (external/dotnet9_0/zlib-ng_v2_2_1.cmake): compat mode, no ARMv6/RVV; zlib-ng's own probes
    # then decide the same features as in GrindCore's build (same CMake, same compiler)
    base = ["cmake", "-S", tree, "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_C_COMPILER=" + c.cc,
            "-DCMAKE_CXX_COMPILER=" + c.cxx, "-DCMAKE_C_FLAGS=" + " ".join(c.flags + extras),
            "-DZLIB_COMPAT=ON", "-DWITH_ARMV6=OFF", "-DWITH_RVV=OFF", "-DZLIB_ENABLE_TESTS=ON", "-DZLIBNG_ENABLE_TESTS=ON"]
    if c.a.rid.startswith("osx-"):
        # as GrindCore's macOS build does (CMAKE_OSX_ARCHITECTURES): left empty, CMake adds the host's -arch as well,
        # and Apple's clang then compiles every file for both (osx-x64's x86 code fails for arm64)
        base.append("-DCMAKE_OSX_ARCHITECTURES=" + ("x86_64" if c.a.rid == "osx-x64" else "arm64"))
    gtest = "with gtest"
    b = os.path.join(tree, "build")
    if c.run(suite, base + ["-B", b, "-DWITH_GTEST=ON"], tree) != 0 or \
            c.run(suite, ["cmake", "--build", b, "-j", c.jobs], tree) != 0:
        gtest = "without gtest (it didn't configure or build here: see the log)"
        shutil.rmtree(b, ignore_errors=True)
        need(c.run(suite, base + ["-B", b, "-DWITH_GTEST=OFF"], tree), "configure")
        need(c.run(suite, ["cmake", "--build", b, "-j", c.jobs], tree), "build")
    known = ""
    if c.run(suite, ["ctest", "--output-on-failure", "-j", c.jobs], b, timeout=7200) != 0:
        # Upstream zlib-ng 2.2.1's gz file functions mis-seek on 32-bit builds with -D_FILE_OFFSET_BITS=64, which
        # GrindCore's build sets: gzip.readwrite fails, official zlib-ng too (audit/build-exam.md part 5). GrindCore
        # exports none of the gz functions. Accept exactly that: gtest_zlib is ctest's only failure, and in it only
        # gzip.readwrite fails. Anything else is reported by name (ctest lists the failures in LastTestsFailed.log).
        try:
            with open(os.path.join(b, "Testing", "Temporary", "LastTestsFailed.log")) as f:
                failed = [ln.strip().split(":", 1)[-1] for ln in f if ln.strip()]
        except OSError:
            failed = []
        others = [t for t in failed if t != "gtest_zlib"]
        gt = os.path.join(b, "gtest_zlib")
        if others or not failed or not os.path.exists(gt):
            raise Fail("ctest: %s" % (", ".join(others) or "failed"))
        need(c.run(suite, [gt, "--gtest_filter=-gzip.readwrite"], b, timeout=3600), "gtest_zlib without gzip.readwrite")
        if c.run(suite, [gt, "--gtest_filter=gzip.readwrite"], b, timeout=600) == 0:
            raise Fail("ctest: gtest_zlib, but gzip.readwrite passes alone")
        known = "; gzip.readwrite fails as in official zlib-ng (gz file API, not exported by GrindCore, with " \
                "_FILE_OFFSET_BITS=64)"
    return "ctest %s; GrindCore's tree (%d files differ from the release, %d added); %s%s" % (
        gtest, changed, added, " ".join(extras) or "no extra flags", known)


def zlib(c):
    suite = "zlib-1.3.1"
    tree = c.release(suite, c.archive("zlib-1.3.1.tar.gz"))
    changed, added = overlay(os.path.join(c.src, "external/dotnet8_0/zlib_v1_3_1"), tree)
    lib = [os.path.join(tree, n + ".c") for n in ("adler32", "compress", "crc32", "deflate", "gzclose", "gzlib", "gzread",
                                                  "gzwrite", "infback", "inffast", "inflate", "inftrees", "trees",
                                                  "uncompr", "zutil")]
    flags = c.flags + c.lib_flags("zlib_v1_3_1/deflate.c") + ["-I", tree, "-D_LARGEFILE64_SOURCE=1"]
    for prog in ("example", "minigzip"):
        need(c.run(suite, [c.cc] + flags + [os.path.join(tree, "test", prog + ".c")] + lib + ["-o", prog], tree), "build")
    need(c.run(suite, ["./example"], tree, timeout=600), "example")
    data = os.path.join(tree, "ChangeLog")
    shutil.copyfile(data, os.path.join(tree, "sample"))
    need(c.run(suite, ["sh", "-c", "./minigzip < sample > sample.gz && ./minigzip -d < sample.gz | cmp - sample"], tree),
         "minigzip round trip")
    return "example and a minigzip round trip; GrindCore's sources (%d files differ from the release; the gz* files " \
           "are the release's, which GrindCore doesn't build)" % changed


def bzip2(c):
    suite = "bzip2-1.0.8"
    tree = c.release(suite, c.archive("bzip2-1.0.8.tar.gz"))
    changed, added = overlay(os.path.join(c.src, "external/bzip2/bzip2"), tree)
    # GrindCore builds with BZ_NO_STDIO, which removes the file API that bzip2's command-line tool needs
    extras = [x for x in c.lib_flags("bzip2/bzip2/compress.c") if x != "-DBZ_NO_STDIO"]
    need(c.run(suite, ["make", "CC=" + c.cc, "CFLAGS=" + " ".join(c.flags + extras), "test"], tree), "make test")
    return "make test (the 6 sample files); GrindCore's sources (%d files differ from the release); without " \
           "BZ_NO_STDIO, for the command-line tool" % changed


def fl2(c):
    suite = "fast-lzma2-1.0.1"
    archive = build_fl2_ref.fetch(c.work, c.a.tarballs, "1.0.1")
    tree = c.release(suite, archive)
    changed, added = overlay(os.path.join(c.src, "external/mcmilk/C/fast-lzma2"), tree)
    # The fuzzer's custom-allocator tests (fuzzer.c:99-244) compile only on macOS, and use FL2_customMem and
    # FL2_createCCtx_advanced, which 1.0.1 doesn't have: upstream's test code doesn't build there. Use its own stub,
    # the branch every other platform compiles.
    fz = os.path.join(tree, "fuzzer", "fuzzer.c")
    text = open(fz).read()
    guard = "#if defined(__APPLE__) && defined(__MACH__)"
    if text.count(guard) != 1:
        raise Fail("fuzzer.c: the macOS-only block isn't as expected")
    open(fz, "w").write(text.replace(guard, "#if 0  /* upstream's macOS-only block uses an API 1.0.1 lacks */"))
    srcs = sorted(glob.glob(os.path.join(tree, "*.c"))) + [os.path.join(tree, "fuzzer/datagen.c"),
                                                            os.path.join(tree, "fuzzer/fuzzer.c")]
    need(c.run(suite, [c.cc] + c.flags + c.lib_flags("fast-lzma2/fl2_compress.c") + ["-I", tree] + srcs +
               ["-pthread", "-o", "fuzzer/fuzzer"], tree), "build")
    # -m: threads. Its default, 0 ("automatic"), makes the fuzzer itself divide by zero in its streaming test
    # (fuzzer.c:1123, `% (dictSize * 4U * nbThreads)`): a bug in upstream's test program, not in the library
    threads = min(4, os.cpu_count() or 2)
    need(c.run(suite, ["./fuzzer", "-T%ds" % c.a.time, "-m%d" % threads], os.path.join(tree, "fuzzer"),
               timeout=c.a.time * 4 + 300), "fuzzer")
    return ("fuzzer, %d s, %d threads; GrindCore's sources (%d files differ from 1.0.1: master's encoder fixes "
            "and the audit's)" % (c.a.time, threads, changed))


def blake3(c):
    suite = "blake3-0.3.7"
    tree = c.release(suite, c.archive("blake3-0.3.7.tar.gz"))
    cdir = os.path.join(tree, "c")
    changed, added = overlay(os.path.join(c.src, "external/blake3/blake3_v0_3_7"), cdir)
    if changed:
        raise Fail("%d vendored files differ from official 0.3.7" % changed)
    core = ["blake3.c", "blake3_dispatch.c", "blake3_portable.c"]
    no = ["-DBLAKE3_NO_AVX512"]
    if c.arch == "x86":
        simd = [("blake3_sse2.c", "-msse2"), ("blake3_sse41.c", "-msse4.1"), ("blake3_avx2.c", "-mavx2")]
        variants = [("dispatch", no, simd), ("max SSE4.1", no + ["-DBLAKE3_NO_AVX2"], simd[:2]),
                    ("max SSE2", no + ["-DBLAKE3_NO_AVX2", "-DBLAKE3_NO_SSE41"], simd[:1]),
                    ("portable", no + ["-DBLAKE3_NO_AVX2", "-DBLAKE3_NO_SSE41", "-DBLAKE3_NO_SSE2"], [])]
    elif c.arch == "arm64":
        variants = [("NEON", ["-DBLAKE3_USE_NEON=1"], [("blake3_neon.c", None)]), ("portable", [], [])]
    else:
        variants = [("portable", [], [])]
    done = []
    for name, defines, files in variants:
        objs = []
        for f, flag in [(n, None) for n in core + ["main.c"]] + files:
            o = os.path.join(cdir, f[:-2] + ".o")
            # BLAKE3_TESTING: upstream's test build (Makefile.testing); main.c needs its CPU-feature hooks
            need(c.run(suite, [c.cc] + c.flags + defines + ["-DBLAKE3_TESTING"] + ([flag] if flag else []) +
                       ["-c", f, "-o", o], cdir),
                 "compile %s (%s)" % (f, name))
            objs.append(o)
        need(c.run(suite, [c.cc] + c.flags + objs + ["-o", "blake3"], cdir), "link (%s)" % name)
        # by its absolute path: Python 3.6 (CentOS 7) gives test.py a relative __file__, and its "./blake3" becomes "blake3"
        need(c.run(suite, [sys.executable, os.path.join(cdir, "test.py")], cdir, timeout=1200), "test.py (%s)" % name)
        done.append(name)
    return ("test.py with the official vectors, built %s (with BLAKE3_TESTING, as upstream tests); the vendored files "
            "equal official 0.3.7" % ", ".join(done))


SUITES = [("zstd-1.5.7", lambda c: zstd(c, "1.5.7")), ("zstd-1.5.7-seekable", zstd_seekable),
          ("zstd-1.5.2", lambda c: zstd(c, "1.5.2")), ("lz4-1.10.0", lz4), ("brotli-1.1.0", brotli),
          ("zlib-ng-2.2.1", zlib_ng), ("zlib-1.3.1", zlib), ("bzip2-1.0.8", bzip2), ("fast-lzma2-1.0.1", fl2),
          ("blake3-0.3.7", blake3)]
# 7-Zip's C sources ship no test suite; the native suite compares GrindCore with official 7-Zip instead.


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--src", required=True, help="the build tree's src/native (GrindCore merged into GrindCore.build)")
    ap.add_argument("--cc-json", required=True, help="that build's compile_commands.json for the RID")
    ap.add_argument("--rid", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--tarballs", help="a folder that may already hold the release archives (ref/tb)")
    ap.add_argument("--time", type=int, default=60, help="seconds for each fuzzer (default 60)")
    ap.add_argument("--only", help="comma-separated suite names")
    a = ap.parse_args()
    c = Ctx(a)
    print("%s: %s %s" % (a.rid, c.cc, " ".join(c.flags)), flush=True)
    failed = 0
    for name, fn in SUITES:
        if a.only and name not in a.only.split(","):
            continue
        t0 = time.time()
        if os.path.exists(c.log(name)):
            os.remove(c.log(name))
        try:
            detail, status = fn(c), "OK"
        except Skip as e:
            detail, status = str(e), "SKIP"
        except Exception as e:  # noqa: BLE001 - a failing suite is a result; the next one still runs
            detail, status = "%s: %s (log: %s)" % (type(e).__name__, e, c.log(name)), "FAIL"
            failed += 1
        print("%-20s %-4s %5.0f s  %s" % (name, status, time.time() - t0, detail), flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
