/* LZMA encoder dictionary limits, measured without Python (whose 32-bit Windows build isn't large-address-aware, so
   it gets 2 GB of address space). Official 7-Zip's LzmaEncode/LzmaDecode, linked in directly; the audit's
   architecture-limitations.md has the results.
     lzma_dict_harness <level> <dictionary MiB> <small|bigdist|file:PATH>
   small   = 512 KiB pseudo-random, twice (1 MiB).
   bigdist = 8 MiB pseudo-random, 150 MiB zeros, the same 8 MiB again: the repeat is ~158 MiB back.
   file:PATH = that file (for speed: the encode's time is printed, one thread).
   Prints rc (0, 2 SZ_ERROR_MEM, 5 SZ_ERROR_PARAM), the sizes, an FNV-1a 64 of the compressed bytes (to compare builds)
   and whether LzmaDecode gives the input back.

   Build against the pinned official sources (ref/build_7zip_ref.py --fetch-only DIR, or the workspace's
   tools/native-test/ref/tb/7zip-25.01), C=<that folder>/C:
     MSVC x86, 4 GB of address space (in "vcvarsall x86"):
       cl /O2 /MT /DNDEBUG /I%C% lzma_dict_harness.c %C%\Alloc.c %C%\CpuArch.c %C%\LzFind.c %C%\LzFindMt.c
          %C%\LzFindOpt.c %C%\LzmaDec.c %C%\LzmaEnc.c %C%\Threads.c /link /LARGEADDRESSAWARE
     the same with /DLZMA_LOG_BSR: the position slot from a bit-scan instruction, as upstream builds ARM
     cc (any RID): cc -O2 -DNDEBUG -I$C lzma_dict_harness.c $C/{Alloc,CpuArch,LzFind,LzFindMt,LzFindOpt,LzmaDec,LzmaEnc,Threads}.c -lpthread */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "LzmaEnc.h"
#include "LzmaDec.h"
#include "Alloc.h"

static unsigned long long fnv(const unsigned char *p, size_t n)
{
    unsigned long long h = 1469598103934665603ULL;
    while (n--) { h ^= *p++; h *= 1099511628211ULL; }
    return h;
}

int main(int argc, char **argv)
{
    int level = atoi(argv[1]);
    unsigned dict_mib = (unsigned)atoi(argv[2]);
    int bigdist = strcmp(argv[3], "bigdist") == 0;
    size_t rnd = bigdist ? ((size_t)8 << 20) : ((size_t)512 << 10);
    size_t zeros = bigdist ? ((size_t)150 << 20) : 0;
    size_t n = rnd * 2 + zeros, i, cap, dlen, plen = LZMA_PROPS_SIZE, blen, slen;
    unsigned long long x = 88172645463325252ULL;
    unsigned char *src, *dst, *back;
    Byte props_enc[LZMA_PROPS_SIZE];
    CLzmaEncProps props;
    ELzmaStatus st;
    SRes rc;
    clock_t t0;
    if (strncmp(argv[3], "file:", 5) == 0) {
        FILE *f = fopen(argv[3] + 5, "rb");
        if (!f) { printf("can't open %s\n", argv[3] + 5); return 1; }
        fseek(f, 0, SEEK_END); n = (size_t)ftell(f); fseek(f, 0, SEEK_SET);
        src = (unsigned char *)malloc(n);
        if (!src || fread(src, 1, n, f) != n) { printf("can't read %s\n", argv[3] + 5); return 1; }
        fclose(f);
    } else {
        src = (unsigned char *)malloc(n);
        if (!src) { printf("%d-bit: no memory for the input\n", (int)(sizeof(void *) * 8)); return 1; }
        for (i = 0; i < rnd; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; src[i] = (unsigned char)(x >> 32); }
        memset(src + rnd, 0, zeros);
        memcpy(src + rnd + zeros, src, rnd);
    }
    cap = n / 2 + (1 << 20); dlen = cap; blen = n;
    dst = (unsigned char *)malloc(cap);
    LzmaEncProps_Init(&props);
    props.level = level;
    props.dictSize = dict_mib << 20;
    props.numThreads = 1;
    t0 = clock();
    rc = LzmaEncode(dst, &dlen, src, n, &props, props_enc, &plen, 0, NULL, &g_Alloc, &g_BigAlloc);
    printf("%d-bit L%d dict %u MiB %s: encode rc %d", (int)(sizeof(void *) * 8), level, dict_mib, argv[3], rc);
    if (rc != SZ_OK) { printf("\n"); return 0; }
    printf(", %zu -> %zu bytes, props %02x%02x%02x%02x%02x, fnv %016llx, %.2f s", n, dlen, props_enc[0], props_enc[1],
           props_enc[2], props_enc[3], props_enc[4], fnv(dst, dlen), (double)(clock() - t0) / CLOCKS_PER_SEC);
    back = (unsigned char *)malloc(n);
    slen = dlen;
    rc = LzmaDecode(back, &blen, dst, &slen, props_enc, LZMA_PROPS_SIZE, LZMA_FINISH_END, &st, &g_Alloc);
    printf(", decode rc %d, round trip %s\n", rc, (rc == SZ_OK && blen == n && memcmp(back, src, n) == 0) ? "IDENTICAL" : "DIFFERS");
    return 0;
}
