/* pool_race.py's test program: Fast-LZMA2's thread-pool wait (the workspace's audit/other-codecs.md 4.4.1 finding 12).
 * Valid data, compressed with a dictionary reset per block so FL2_decompressMt splits the work across its 2 threads,
 * then decoded 20 times ("dec"); or compressed with 2 threads and decoded once to check ("enc"). pool_race.py
 * builds it with a copy of fl2_pool.c whose worker sleeps between taking a job and counting itself busy, which holds
 * the race window open; the delay is in that copy only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fast-lzma2.h"

int main(int argc, char **argv)
{
    int const enc = argc > 1 && !strcmp(argv[1], "enc");
    size_t const n = 4 << 20;
    unsigned char *src = malloc(n), *z = malloc(n + 4096), *out = malloc(n);
    unsigned x = 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    for (size_t i = 0; i < n; i++) { x = x * 1103515245u + 12345u; src[i] = (unsigned char)('a' + (x >> 24) % 16); }
    FL2_CCtx *c = enc ? FL2_createCCtxMt(2) : FL2_createCCtx();
    FL2_CCtx_setParameter(c, FL2_p_compressionLevel, 1);
    FL2_CCtx_setParameter(c, FL2_p_dictionarySize, 1 << 20);
    FL2_CCtx_setParameter(c, FL2_p_resetInterval, 1);
    size_t const zs = FL2_compressCCtx(c, z, n + 4096, src, n, 0);
    FL2_freeCCtx(c);
    if (FL2_isError(zs)) { printf("compress: %s\n", FL2_getErrorName(zs)); return 2; }
    if (enc) {
        size_t const r = FL2_decompress(out, n, z, zs);
        if (FL2_isError(r) || r != n || memcmp(out, src, n)) { printf("enc: the frame decodes wrong\n"); return 1; }
        printf("ok: compressed with 2 threads into %zu bytes, which decode correctly\n", zs);
    } else {
        for (int i = 0; i < 20; i++) {
            size_t const r = FL2_decompressMt(out, n, z, zs, 2);
            if (FL2_isError(r) || r != n || memcmp(out, src, n)) {
                printf("decode %d: wrong result (%s, %zu bytes)\n", i, FL2_isError(r) ? FL2_getErrorName(r) : "no error", r);
                return 1;
            }
        }
        printf("ok: a %zu-byte frame decoded 20 times with 2 threads\n", zs);
    }
    free(src); free(z); free(out);
    return 0;
}
