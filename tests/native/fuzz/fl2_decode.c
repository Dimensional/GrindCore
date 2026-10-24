/* libFuzzer harness: Fast-LZMA2's decoders on arbitrary input (the workspace's audit/native-tests.md, "Fuzzing").
 * fuzz.py builds it with GrindCore's vendored sources and AddressSanitizer. Each input is decoded three ways, as
 * GrindCore.net's callers do it:
 *   - FL2_decompress, one-shot (FastLzma2Block with one thread);
 *   - FL2_decompressMt with 2 threads (FastLzma2Block with ThreadCount 2);
 *   - FL2_decompressStream on one thread, fed 13 bytes and drained 4 KiB at a time (FastLzma2Decoder).
 * What counts is a crash, a read or write past a buffer, a use after free, a leak or a hang. Each input sits in an
 * allocation of exactly its size, so reading one byte past it is a finding.
 *   - Before 2026-10-24 reads were unchecked (fuzz.py --writes-only) and 32 bytes of slack followed each input: the
 *     decoder read up to 19 bytes past corrupt input (other-codecs.md 4.4.1 finding 10, since fixed), and with reads
 *     checked every run stopped on it within seconds.
 *   - Excluded on purpose: the dictionary property is capped at 24 (16 MiB). A frame may declare up to 1.5 GiB, which
 *     the stream decoder then allocates. That is the format, not a defect. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fast-lzma2.h"

#define SLACK 0  /* bytes after each input; 32 while reads were unchecked */
#define OUT_CAP (1 << 20)
#define MAX_PROP 24

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static uint8_t *out;
    uint8_t *in;

    if (size == 0 || size > OUT_CAP)
        return 0;
    if (!out && !(out = malloc(OUT_CAP)))
        return 0;
    if (!(in = malloc(size + SLACK)))
        return 0;
    memcpy(in, data, size);
    memset(in + size, 0, SLACK);
    if ((in[0] & 0x3F) > MAX_PROP)
        in[0] = (uint8_t)((in[0] & 0xC0) | MAX_PROP);

    FL2_decompress(out, OUT_CAP, in, size);
    FL2_decompressMt(out, OUT_CAP, in, size, 2);

    {
        FL2_DStream *ds = FL2_createDStream();
        if (ds && !FL2_isError(FL2_initDStream(ds))) {
            FL2_inBuffer ib = { in, 0, 0 };
            FL2_outBuffer ob = { out, 0, 0 };
            int calls;
            for (calls = 0; calls < 100000; calls++) {
                size_t before = ib.pos, r;
                ib.size = ib.size + 13 < size ? ib.size + 13 : size;
                ob.pos = 0;  /* the output isn't checked, so each call gets the whole buffer again */
                ob.size = 4096;
                r = FL2_decompressStream(ds, &ob, &ib);
                if (FL2_isError(r) || r == 0)
                    break;
                if (ib.size == size && ib.pos == before && ob.pos == 0)
                    break;  /* all input given, nothing consumed or written: the frame is cut short */
            }
        }
        FL2_freeDStream(ds);
    }
    free(in);
    return 0;
}
