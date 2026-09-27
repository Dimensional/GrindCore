/* GrindCore-owned; force-included into zlib-ng on 32-bit ARM (audit/platforms.md 10.7).
 * clang <= 16 gives vld1q_u8_x4/vld1q_u16_x4/vst1q_u16_x4 a 32-byte (:256) alignment hint on 32-bit ARM, but zlib-ng
 * only aligns its data to 16, so the NEON Adler-32 raises SIGBUS. zlib-ng's own workaround (arch/arm/neon_intrins.h
 * lines 28-34) does exactly these #undefs, but only for __ANDROID__; this applies it on Linux too, so neon_intrins.h
 * uses its separate-load fallback (lines 36-61). arm_neon.h's include guard keeps the macros from coming back. */
#if defined(__arm__) && defined(__ARM_NEON) && defined(__clang__)
#  include <arm_neon.h>
#  undef ARM_NEON_HASLD4
#  undef vld1q_u16_x4
#  undef vld1q_u8_x4
#  undef vst1q_u16_x4
#endif
