/* libFuzzer harness: 7-Zip 25.01's LZMA and LZMA2 decoders on arbitrary input (the workspace's audit/native-tests.md,
 * "Fuzzing"). fuzz.py builds it with GrindCore's vendored LzmaDec.c and Lzma2Dec.c (the C decoder every RID but win-x64
 * uses) and AddressSanitizer, reads and writes both checked. Each input is decoded as both formats:
 *   - LZMA: the first 5 bytes are the properties (lc/lp/pb, then the dictionary size), the rest the stream;
 *   - LZMA2: the first byte is the dictionary property, the rest the stream;
 * each one-shot (LzmaDecode, Lzma2Decode: GrindCore.net's blocks) and streamed 13 bytes in and 4 KiB out at a time
 * (LzmaDec_DecodeToBuf, Lzma2Dec_DecodeToBuf: its streams). What counts is any ASan report, a leak or a hang.
 * The streamed dictionary is capped at 16 MiB: a stream may declare up to 4 GiB, which the decoder then allocates.
 * That is the format, not a defect. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "LzmaDec.h"
#include "Lzma2Dec.h"

#define OUT_CAP (1 << 20)
#define MAX_DICT (16u << 20)
#define MAX_PROP2 24  /* LZMA2's property for 16 MiB */

static void *SzAlloc(ISzAllocPtr p, size_t size) { (void)p; return malloc(size); }
static void SzFree(ISzAllocPtr p, void *address) { (void)p; free(address); }
static const ISzAlloc g_Alloc = { SzAlloc, SzFree };

/* One decoder over src[0..len): 13 bytes in and 4 KiB out per call, the output discarded. */
#define STREAM(call, dec, out, src, len)                                                                  \
    do {                                                                                                  \
        SizeT pos_ = 0;                                                                                   \
        int calls_;                                                                                       \
        for (calls_ = 0; calls_ < 100000; calls_++) {                                                     \
            SizeT in_ = (len) - pos_ < 13 ? (len) - pos_ : 13, out_ = 4096;                               \
            ELzmaStatus status_;                                                                          \
            SRes r_ = call(dec, out, &out_, (src) + pos_, &in_, LZMA_FINISH_ANY, &status_);               \
            pos_ += in_;                                                                                  \
            if (r_ != SZ_OK || status_ == LZMA_STATUS_FINISHED_WITH_MARK)                                 \
                break;                                                                                    \
            if (in_ == 0 && out_ == 0)                                                                    \
                break; /* no progress: the input is used up, or the stream ends short */                  \
        }                                                                                                 \
    } while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t *out;
    ELzmaStatus status;
    SizeT n, outLen;

    if (size < LZMA_PROPS_SIZE || size > OUT_CAP)
        return 0;
    if (!out && !(out = malloc(OUT_CAP)))
        return 0;

    { /* LZMA */
        const uint8_t *src = data + LZMA_PROPS_SIZE;
        size_t len = size - LZMA_PROPS_SIZE;
        uint8_t props[LZMA_PROPS_SIZE];
        uint32_t dict = (uint32_t)data[1] | (uint32_t)data[2] << 8 | (uint32_t)data[3] << 16 | (uint32_t)data[4] << 24;
        CLzmaDec dec;

        n = len, outLen = OUT_CAP;
        LzmaDecode(out, &outLen, src, &n, data, LZMA_PROPS_SIZE, LZMA_FINISH_END, &status, &g_Alloc);

        memcpy(props, data, LZMA_PROPS_SIZE);
        if (dict > MAX_DICT) {
            props[1] = 0; props[2] = 0; props[3] = (uint8_t)(MAX_DICT >> 16); props[4] = 0;
        }
        LzmaDec_Construct(&dec);
        if (LzmaDec_Allocate(&dec, props, LZMA_PROPS_SIZE, &g_Alloc) == SZ_OK) {
            LzmaDec_Init(&dec);
            STREAM(LzmaDec_DecodeToBuf, &dec, out, src, len);
            LzmaDec_Free(&dec, &g_Alloc);
        }
    }

    { /* LZMA2 */
        const uint8_t *src = data + 1;
        size_t len = size - 1;
        CLzma2Dec dec;

        n = len, outLen = OUT_CAP;
        Lzma2Decode(out, &outLen, src, &n, data[0], LZMA_FINISH_END, &status, &g_Alloc);

        Lzma2Dec_Construct(&dec);
        if (Lzma2Dec_Allocate(&dec, data[0] > MAX_PROP2 ? MAX_PROP2 : data[0], &g_Alloc) == SZ_OK) {
            Lzma2Dec_Init(&dec);
            STREAM(Lzma2Dec_DecodeToBuf, &dec, out, src, len);
            Lzma2Dec_Free(&dec, &g_Alloc);
        }
    }
    return 0;
}
