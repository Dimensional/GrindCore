# BLAKE3 0.3.7, the official C implementation with its run-time SIMD dispatch (audit/build-exam.md F3). It replaces
# the portable-only copy merged into external/mcmilk/C/hashes/blake3.c, which is no longer built. Same version, so the
# same digests and the same blake3_hasher layout.
#
# The SIMD sources are chosen from the compiler's own architecture macros, not CMake's processor variables, which say
# x86_64 inside the linux-x86 build container (build-exam.md B3). Each SIMD file gets only its own instruction-set flag,
# as BLAKE3's own build does, and blake3_dispatch.c picks one at run time from CPUID, so every x86 RID runs on any CPU.
#   x86 (32- and 64-bit): SSE2, SSE4.1 and AVX2. AVX-512 is left out (BLAKE3_NO_AVX512) until a host can test it.
#   ARM64: NEON, which every ARM64 CPU has.
#   32-bit ARM: portable only. ARMv7 doesn't guarantee NEON, and 0.3.7 can't detect it at run time.
include(CheckCSourceCompiles)

set(BLAKE3_V0_3_7_DIR ${CMAKE_CURRENT_LIST_DIR}/blake3_v0_3_7)

check_c_source_compiles("
#if !(defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86))
#error not x86
#endif
int main(void) { return 0; }" GRINDCORE_BLAKE3_X86)
check_c_source_compiles("
#if !(defined(__aarch64__) || defined(_M_ARM64))
#error not ARM64
#endif
int main(void) { return 0; }" GRINDCORE_BLAKE3_ARM64)

set(BLAKE3_V0_3_7_SOURCES
    ${BLAKE3_V0_3_7_DIR}/blake3.c
    ${BLAKE3_V0_3_7_DIR}/blake3_dispatch.c
    ${BLAKE3_V0_3_7_DIR}/blake3_portable.c
)
set(BLAKE3_V0_3_7_DEFINES)

if (GRINDCORE_BLAKE3_X86)
    list(APPEND BLAKE3_V0_3_7_SOURCES
        ${BLAKE3_V0_3_7_DIR}/blake3_sse2.c
        ${BLAKE3_V0_3_7_DIR}/blake3_sse41.c
        ${BLAKE3_V0_3_7_DIR}/blake3_avx2.c
    )
    list(APPEND BLAKE3_V0_3_7_DEFINES BLAKE3_NO_AVX512)
    if (MSVC)
        set_source_files_properties(${BLAKE3_V0_3_7_DIR}/blake3_avx2.c PROPERTIES COMPILE_OPTIONS "/arch:AVX2")
    else()
        set_source_files_properties(${BLAKE3_V0_3_7_DIR}/blake3_sse2.c PROPERTIES COMPILE_OPTIONS "-msse2")
        set_source_files_properties(${BLAKE3_V0_3_7_DIR}/blake3_sse41.c PROPERTIES COMPILE_OPTIONS "-msse4.1")
        set_source_files_properties(${BLAKE3_V0_3_7_DIR}/blake3_avx2.c PROPERTIES COMPILE_OPTIONS "-mavx2")
    endif()
elseif (GRINDCORE_BLAKE3_ARM64)
    list(APPEND BLAKE3_V0_3_7_SOURCES ${BLAKE3_V0_3_7_DIR}/blake3_neon.c)
    list(APPEND BLAKE3_V0_3_7_DEFINES BLAKE3_USE_NEON=1)
endif()

add_library(blake3_v0_3_7 STATIC ${BLAKE3_V0_3_7_SOURCES})
target_include_directories(blake3_v0_3_7 PRIVATE ${BLAKE3_V0_3_7_DIR})
target_compile_definitions(blake3_v0_3_7 PRIVATE ${BLAKE3_V0_3_7_DEFINES})
if (MSVC)
    # Upstream's code under /W4 /WX: integer narrowing (C4242, C4244; the merged copy silenced these two with pragmas),
    # and the SIMD files' _mm_prefetch calls pass a const uint8_t* where MSVC declares const char* (C4057).
    target_compile_options(blake3_v0_3_7 PRIVATE /wd4242 /wd4244 /wd4057)
endif()
