# IMPORTANT: do not use add_compile_options(), add_definitions() or similar functions here since it will leak to the including projects 

include(FetchContent)

FetchContent_Declare(
    fetchzlibng
    SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/zlib-ng_v2_2_1")

set(ZLIB_COMPAT ON)
set(ZLIB_ENABLE_TESTS OFF)
set(ZLIBNG_ENABLE_TESTS OFF)
set(Z_PREFIX ON)

# TODO: Turn back on when Linux kernels with proper RISC-V extension detection (>= 6.5) are more commonplace
set(WITH_RVV OFF)
# We don't support ARMv6 and the check works incorrectly when compiling for ARMv7 w/ Thumb instruction set
set(WITH_ARMV6 OFF)

# 'aligned_alloc' is not available in browser/wasi, yet it is set by zlib-ng/CMakeLists.txt.
if (CLR_CMAKE_TARGET_BROWSER OR CLR_CMAKE_TARGET_WASI)
  set(HAVE_ALIGNED_ALLOC FALSE CACHE BOOL "have aligned_alloc" FORCE)
endif()

set(BUILD_SHARED_LIBS OFF) # Shared libraries aren't supported in wasm
set(SKIP_INSTALL_ALL ON)
FetchContent_MakeAvailable(fetchzlibng)
set(SKIP_INSTALL_ALL OFF)

set_property(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/zlib-ng_v2_2_1 PROPERTY MSVC_WARNING_LEVEL 3)
target_compile_options(zlib PRIVATE $<$<COMPILE_LANG_AND_ID:C,Clang,AppleClang>:-Wno-unused-command-line-argument>)
target_compile_options(zlib PRIVATE $<$<COMPILE_LANG_AND_ID:C,Clang,AppleClang>:-Wno-logical-op-parentheses>)
target_compile_options(zlib PRIVATE $<$<COMPILE_LANG_AND_ID:C,Clang,AppleClang>:-Wno-ignored-target-attributes>)
target_compile_options(zlib PRIVATE $<$<COMPILE_LANG_AND_ID:C,MSVC>:/wd4127>)
target_compile_options(zlib PRIVATE $<$<COMPILE_LANG_AND_ID:C,MSVC>:/guard:cf>)

# [audit fix, audit/platforms.md 10.7] clang <= 16 emits 32-byte-aligned (:256) loads/stores for the vld1q_*_x4 /
# vst1q_u16_x4 intrinsics on 32-bit ARM, but zlib-ng only aligns its data to 16 -> SIGBUS in the NEON Adler-32.
# zlib-ng's own workaround (arch/arm/neon_intrins.h:28-34) is Android-only; this header applies it here.
if (CLR_CMAKE_TARGET_ARCH_ARM AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(zlib PRIVATE "SHELL:-include ${CMAKE_CURRENT_LIST_DIR}/zlib-ng_arm32_neon_ld4.h")
endif()

set_target_properties(zlib PROPERTIES DEBUG_POSTFIX "")

add_library(zlibng_v2_2_1 ALIAS zlib)