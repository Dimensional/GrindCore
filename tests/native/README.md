# Native test suite (ctypes, no .NET)

Tests GrindCore's C library directly: all 329 exports, every codec, on all 11 RIDs. It was written for the 2026 audit.
The plan, the results and the findings are in the audit's notes, the `grindcore-workspace` repo (the
`audit/<topic>.md` references in the code are to that repo). They aren't needed to run anything here.

```
python -m gctest --lib <libGrindCore.so | GrindCore.dll | libGrindCore.dylib> [-v] [-k pattern]... [--json out.json]
```

Run it from this folder, or run `gctest/__main__.py` by its path from anywhere. `-k` can be repeated, and tests
matching any of the patterns run (e.g. `-k zstd` while working on zstd). Without references (below), the
comparisons against official libraries skip, each giving its reason.

## Design rules

- **Standard library only, Python 3.6+** (CentOS 7 and Ubuntu 18.04 ship 3.6). The Python must have the library's
  bitness. Nothing needs installing: Linux RIDs can run in their build images, and on Windows an unpacked
  embeddable Python will do (`.python/` here is git-ignored for that).
- **Portable by design:** every test runs on every RID and against any build configuration of the library.
  - Internal layouts are worked out at run time: a field is found by how it behaves, or a struct definition is
    laid out with ctypes.
  - Debug info, PDBs and disassembly may confirm an answer but are never an input.
  - When something can't be determined, the test skips with a stated reason.
- **Independent oracles:**
  - Python's `zlib`, `bz2`, `lzma` and `hashlib`;
  - official libraries built from pinned sources (below);
  - pure-Python decoders written from the format specs (`oracle_lz4.py`, `oracle_hashes.py`).

  Self-consistency alone isn't trusted. A golden-value test would have missed the BZip2 `FLUSH`/`FINISH` bug, which
  showed up as an error, not wrong bytes.
- **Known defects:** `gctest.KNOWN_DEFECTS` plus `known()`.
  - A library that still has a documented defect (e.g. a release built before the fix) reports it as a skip; a
    fixed library must pass.
  - Probes that crash or hang run in `child()` / `spawn()` subprocesses.
  - `gctest/KNOWN_SYMBOL_GAPS` lists the export-table gaps. If one disappears or a new one appears, the test fails.

## Layout

- `gcnative/` loads the library:
  - prototypes for every export, and `ctypes.Structure` classes for the structs callers allocate;
  - call recording (export coverage), `symbol_report()` and `layout_report()`;
  - `alloc()` for structs that need more alignment than ctypes gives (`CBlake2sp`: 64).
- `gcnative/_spec.py` is **generated**; don't edit it. `python gen_bindings.py [--db codemap.db]` writes it from the
  code map (the workspace's `tools/codemap`; by default its `out/codemap.db`, with GrindCore checked out as the
  workspace's submodule). `gcnative.OVERRIDES` carries prototypes that changed on the audit branch.
  - Symbols = `entrypoints.c` ∪ dllexport ∪ GrindCore.net's P/Invokes, each tagged with its source.
  - Types come from the win-x64 and win-x86 maps: whatever differs in width is `size_t`. There's no C `long` in the API.
  - Anonymous unions have no record in the code map; `gen_bindings.py` lists them (`ANONYMOUS`), and the layout
    check verifies them.
- `gctest/test_*.py` are the tests, and `gctest/*_util.py` drive each codec identically through GrindCore or a
  reference (`zstd_util.drive()`, `brotli_util.Api`, `lzmadec_util.Api`).
- `loadso.c` loads `libGrindCore.so` as a plain C program would (no `-lm`, no `-lpthread`, `RTLD_NOW`):
  `cc -o loadso loadso.c -ldl && ./loadso libGrindCore.so`.
- Other tools:
  - `leakcheck.py`: Valgrind, or `leaks` on macOS;
  - `determinism.py`: hashes compressed output to compare builds and RIDs;
  - `bench_*.py`, speed;
  - `fl2_timeout_stress.py`;
  - `ref/`: the reference builders and `upstream_tests.py` (below).

## Running it per RID

The audit ran it with the workspace's `tools/native-build` scripts (`hosts/native-tests.sh`), which do the steps
below, keep the references, and run each Linux RID in the image GrindCore.build builds it in.

| RID | Where | How |
|---|---|---|
| linux-* (all 6) | the RID's build environment (GrindCore.build's Dockerfile, or the CI runner) on a host of that architecture | `python3 -B -m gctest -v --lib <tree>/artifacts/bin/<rid>/native/libGrindCore.so`, after `loadso.c` |
| osx-arm64, osx-x64 | a Mac | osx-arm64: `/usr/bin/python3`. osx-x64: an x86_64 Python ([python-build-standalone](https://github.com/astral-sh/python-build-standalone)) under `arch -x86_64`, so Rosetta |
| win-x64 | Windows x64 | `python -B -m gctest -v --lib …\win-x64\native\GrindCore.dll` |
| win-x86 | Windows x64 | python.org's 32-bit *embeddable* zip, unpacked: `<python>\python.exe -B gctest\__main__.py -v --lib …` |
| win-arm64 | Windows on ARM | the ARM64 embeddable zip, as for win-x86. win-x64 also runs there under Prism with an ordinary x64 Python |

- **Embeddable Pythons:** `-m gctest` fails with "No module named gctest", because their `._pth` file drops the
  working directory. Run `gctest\__main__.py` instead.
- **Memory caps:** some corruption sweeps allocate a lot when a defect is present. Run Linux containers with `-m 4g`
  (`-m 2560m --memory-swap 2560m` on a 4 GB Raspberry Pi). Never flip seek-table bits in ad-hoc sweeps: on unfixed
  zstd seekable loaders, one bit makes them allocate about 26 GB.

## References (official libraries, built from pinned sources)

| Variable | Builder | What |
|---|---|---|
| `GC_REF_ZSTD` (folder) | `ref/build_zstd_ref.py` | zstd 1.5.2 and 1.5.7 plus `contrib/seekable_format`, from the SHA-256-checked tarballs |
| `GC_REF_LZ4` (folder) | `ref/build_lz4_ref.py` | LZ4 1.10.0 |
| `GC_REF_BROTLI` (folder) | `ref/build_brotli_ref.py` | Brotli 1.1.0 and its 44 test streams. `--fixtures-only` gives the streams without a library |
| `GC_REF_FL2` (folder) | `ref/build_fl2_ref.py` | Fast-LZMA2 1.0.1 and master `967306d3`; `--asm` adds the x86-64 assembler decoder |
| `GC_REF_7ZIP` (file) | `ref/build_7zip_ref.py` | 7-Zip 25.01's LZMA/LZMA2; `--asm` adds the assembler decoder (win-x64, arm64) |

- Each builder writes to `--out ref/out-<rid>` (git-ignored) and downloads its archive, checking the SHA-256.
  `--tarballs <folder>` (and `--src <folder>/7zip-25.01`) use archives already on disk, for hosts without network.
- **Build the references for each architecture, in the RID's own build environment.** Brotli's Q10/Q11 output
  depends on the compiler for some inputs, so its builder (and Fast-LZMA2's, to match) picks the compiler as
  GrindCore.build's `init-compiler.sh` does: the newest `clang-N`.
- **linux-x86:** build the references with `--cflags="-msse2 -mfpmath=sse"`, as GrindCore.build builds linux-x86.
  x87 references differ in Brotli Q10/11 and zstd 1.5.2 L5/L9.
- **Legacy (CentOS 7):** only 7-Zip's reference builds there. On the arm64 one, pass
  `--cc /opt/rh/devtoolset-8/root/usr/bin/gcc`: CentOS's gcc 4.8.5 can't compile `CpuArch.c`, and devtoolset-11 is empty.
- **Windows:** `build_7zip_ref.py` uses MSVC through vswhere (`--arch x86/arm64`). zstd's comparisons use Python
  3.14's `compression.zstd` (1.5.7) there.

## The vendored libraries' own test suites (`ref/upstream_tests.py`)

Each library's release tree supplies its tests, and GrindCore's vendored copy is laid over the release's sources, so
the tests run against the code GrindCore ships, compiled with the compiler and flags of a real GrindCore build (read
from that build's `compile_commands.json`). Run it in the RID's build environment, with the build tree where it was
built (the paths in `compile_commands.json` are absolute):

```
python3 ref/upstream_tests.py --src <tree>/src/native --rid <rid> --work <dir>
        --cc-json <tree>/artifacts/obj/native/<rid>/compile_commands.json [--tarballs <folder>] [--time 60]
```

The workspace's `hosts/upstream-tests.sh` does that for each Linux RID in its build image, and natively on a Mac.

| Suite | What runs | Notes |
|---|---|---|
| zstd 1.5.7 | `fuzzer`, `zstreamtest` (`--time` seconds each) | GrindCore's `lib/` |
| zstd 1.5.7 seekable | `seekable_tests` | GrindCore's renamed API is mapped to the plain names for the test. Test 4 reports the known end-of-stream difference (other-codecs.md §4.8.1) |
| zstd 1.5.2 | `fuzzer`, `zstreamtest` | the release's own `lib/` with GrindCore's 1.5.2 defines: GrindCore's copy is renamed `ZSTD_v1_5_2_*` |
| LZ4 1.10.0 | `fuzzer`, `frametest` | |
| Brotli 1.1.0 | the round-trip and compatibility scripts | with `BROTLI_ENCODER_CLEANUP_ON_OOM` |
| zlib-ng 2.2.1 | `ctest`, with googletest when it builds | zlib-ng's own CMake, with GrindCore's options, so its probes decide as in GrindCore's build. On 32-bit, `gzip.readwrite` fails as it does in official zlib-ng with `-D_FILE_OFFSET_BITS=64` (the gz file API, which GrindCore doesn't export) |
| zlib 1.3.1 | `example`, a `minigzip` round trip | the release's `gz*` files, which GrindCore doesn't build |
| BZip2 1.0.8 | `make test` | without `BZ_NO_STDIO`, which removes the file API the command-line tool needs |
| Fast-LZMA2 1.0.1 | `fuzzer -m<threads>` | upstream's fuzzer divides by zero with its default thread count of 0 |
| BLAKE3 0.3.7 | `test.py` with the official vectors | built once per SIMD level (dispatch, SSE4.1, SSE2, portable on x86; NEON and portable on ARM64) |

7-Zip's C sources ship no test suite; the native suite compares GrindCore with official 7-Zip instead. Windows isn't
covered (the suites are make- and shell-based); the native suite covers Windows.

## Memory checking

- **Linux:** `leakcheck.py` runs the suite plus leak scenarios under Valgrind memcheck and reports only findings with a
  GrindCore frame (`--save` keeps Valgrind's full output).
  - Use Valgrind 3.22+, which means `ubuntu:24.04`: 3.18 can't read the clang-15 builds' DWARF 5.
  - On ARM32, use Debian 12; Python 3.13 (Debian 13) segfaults under Valgrind at startup.
  - `-k <codec>` limits it to that codec's tests.
  - Valgrind doesn't follow child processes, so the corrupt-input sweeps have `--scenario` equivalents, e.g.
    `--scenario lzma_decoders`.
- **macOS:** `leaks`, run on the framework's real Python binary, because the Command Line Tools' `python3` is a
  launcher and `leaks` would see nothing.
- **When:** the codec being changed before each commit; the whole suite once per codec or phase.

## Harness lessons (each one cost a debugging session)

- **ctypes:** a closure must hold the buffer *object*, not just its address, or Python frees it and the library reads
  freed memory. That access violation looks like a decoder bug. On Windows, ctypes turns a native access violation into
  `OSError: exception: access violation`, so crash probes check for that as well as a signal.
- **Calling conventions:** on win-x86, callbacks the vendored code declares without a convention are `__stdcall`
  (`/Gz`): zstd seekable's read/seek and Brotli's allocator. Probe per library (`WINFUNCTYPE` vs `CFUNCTYPE`).
- **zstd:**
  - `DecompressStream` holds back a frame's last input byte until the output is flushed, then returns 1 for it, so
    a drain loop must re-supply the unconsumed tail;
  - the setters return the value actually set (level 0 reports 3);
  - a destination exactly the compressed size can fail.
- **LZ4:** block output depends on memory layout: a block contiguous with the previous one continues it. Keep linked
  blocks in one buffer, or output differs from official.
- **Brotli:**
  - the decoder can return `NEEDS_MORE_INPUT` with output still pending, so repeat while the output buffer comes
    back full;
  - the encoder `exit()`s on a failed allocation in Brotli's default mode;
  - allocation-failure sweeps need one-off failures as well as "fail from here on". The latter let a later check
    hide the missing one.
- **Fast-LZMA2:**
  - a double-buffered stream's `FL2_flushStream` returns 0 before the output exists, so wait (`FL2_waitCStream`)
    and drain again;
  - that mode's output varies with timing, so compare it by decoding, not byte for byte;
  - `FL2_CONTENTSIZE_ERROR` is `(size_t)-1`, which is `0xFFFFFFFF` on 32-bit.
- **LZMA:** with a known size, a streaming decoder must keep being called while the status is `NEEDS_MORE_INPUT`, even
  at size 0, because the range coder needs its 5 start bytes.
- **unittest:** never `assertEqual` large `bytes`. unittest builds the full text diff before truncating it, which took
  20+ minutes on the Pi and looked like a hang. Use `self.same` / `describe`.
- **ThreadSanitizer** on a ctypes-loaded library: gcc `-fsanitize=thread`, `LD_PRELOAD` of `libtsan.so`, and
  `setarch x86_64 -R`. In Docker it also needs `--security-opt seccomp=unconfined`.
