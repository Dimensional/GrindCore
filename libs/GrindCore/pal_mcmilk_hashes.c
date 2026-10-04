#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "pal_mcmilk_hashes.h"

/////////////////////////////////////////
// XXH32
FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_XXH32_Reset(XXH32_state_t *ctx) {
    XXH32_reset(ctx, 0);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_XXH32_Update(XXH32_state_t *ctx, const void *data, size_t len) {
    XXH32_update(ctx, data, len);
}

FUNCTIONEXPORT UInt32 FUNCTIONCALLINGCONVENCTION SZ_XXH32_Digest(XXH32_state_t *ctx) {
    return XXH32_digest(ctx);
}

/////////////////////////////////////////
// XXH64
FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_XXH64_Reset(XXH64_state_t *ctx) {
    XXH64_reset(ctx, 0);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_XXH64_Update(XXH64_state_t *ctx, const void *data, size_t len) {
    XXH64_update(ctx, data, len);
}

FUNCTIONEXPORT UInt64 FUNCTIONCALLINGCONVENCTION SZ_XXH64_Digest(XXH64_state_t *ctx) {
    return XXH64_digest(ctx);
}

/////////////////////////////////////////
// Blake2
FUNCTIONEXPORT BoolInt FUNCTIONCALLINGCONVENCTION SZ_Blake2sp_SetFunction(CBlake2sp *p, unsigned algo) {
    return Blake2sp_SetFunction(p, algo);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Blake2sp_Init(CBlake2sp *p) {
    Blake2sp_Init(p);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Blake2sp_InitState(CBlake2sp *p) {
    Blake2sp_InitState(p);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Blake2sp_Update(CBlake2sp *p, const Byte *data, size_t size) {
    Blake2sp_Update(p, data, size);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Blake2sp_Final(CBlake2sp *p, Byte *digest) {
    Blake2sp_Final(p, digest);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Black2sp_Prepare(void) {
    z7_Black2sp_Prepare();
}

/////////////////////////////////////////
// Blake3
FUNCTIONEXPORT const char* FUNCTIONCALLINGCONVENCTION SZ_blake3_version(void) {
    return "0.3.7"; /* official 0.3.7 has no blake3_version(); the merged copy defined it */
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_blake3_hasher_init(blake3_hasher *self) {
    blake3_hasher_init(self);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_blake3_hasher_init_keyed(blake3_hasher *self, const uint8_t key[BLAKE3_KEY_LEN]) {
    blake3_hasher_init_keyed(self, key);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_blake3_hasher_init_derive_key(blake3_hasher *self, const char *context) {
    blake3_hasher_init_derive_key(self, context);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_blake3_hasher_init_derive_key_raw(blake3_hasher *self, const void *context, size_t context_len) {
    blake3_hasher_init_derive_key_raw(self, context, context_len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_blake3_hasher_update(blake3_hasher *self, const void *input, size_t input_len) {
    blake3_hasher_update(self, input, input_len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out, size_t out_len) {
    blake3_hasher_finalize(self, out, out_len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek, uint8_t *out, size_t out_len) {
    blake3_hasher_finalize_seek(self, seek, out, out_len);
}

/////////////////////////////////////////
// MD2
FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD2_Init(struct md2 *m) {
    MD2_Init(m);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD2_Update(struct md2 *m, const void *v, size_t len) {
    // The vendored MD2_Update completes a pending partial block with 16-idx bytes but then advances the input by 16
    // (md2.c:106), skipping idx bytes and reading up to 15 bytes past the caller's buffer (audit/hashes.md 6.5).
    // That branch is never entered here: a pending block is completed in a local buffer and handed in as a whole block
    // (after taking the pending bytes back out of the count), and whole-block input is handled correctly.
    const unsigned char *p = (const unsigned char *)v;
    size_t idx = m->len & 0xf;
    if (idx != 0 && len > 0) {
        unsigned char block[16];
        size_t take = 16 - idx;
        if (len < take) {           // still short of a block: MD2_Update only appends (idx + len < 16)
            MD2_Update(m, p, len);
            return;
        }
        memcpy(block, m->data, idx);
        memcpy(block + idx, p, take);
        m->len -= idx;              // the pending bytes go back in as the start of the whole block
        MD2_Update(m, block, 16);
        p += take;
        len -= take;
    }
    if (len > 0)
        MD2_Update(m, p, len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD2_Final(void *res, struct md2 *m) {
    MD2_Final(res, m);
}

/////////////////////////////////////////
// MD4
FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD4_Init(struct md4 *m) {
    MD4_Init(m);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD4_Update(struct md4 *m, const void *v, size_t len) {
    MD4_Update(m, v, len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD4_Final(void *res, struct md4 *m) {
    MD4_Final(res, m);
}

/////////////////////////////////////////
// MD5
FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD5_Init(struct md5 *m) {
    MD5_Init(m);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD5_Update(struct md5 *m, const void *v, size_t len) {
    MD5_Update(m, v, len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_MD5_Final(void *res, struct md5 *m) {
    MD5_Final(res, m);
}

/////////////////////////////////////////
// SHA1
FUNCTIONEXPORT BoolInt FUNCTIONCALLINGCONVENCTION SZ_Sha1_SetFunction(CSha1 *p, unsigned algo) {
    return Sha1_SetFunction(p, algo);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha1_InitState(CSha1 *p) {
    Sha1_InitState(p);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha1_Init(CSha1 *p) {
    Sha1_Init(p);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha1_Update(CSha1 *p, const Byte *data, size_t size) {
    Sha1_Update(p, data, size);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha1_Final(CSha1 *p, Byte *digest) {
    Sha1_Final(p, digest);
}

FUNCTIONEXPORT int32_t FUNCTIONCALLINGCONVENCTION SZ_Sha1_PrepareBlock(const CSha1 *p, Byte *block, unsigned size) {
    // Sha1.c:385-398 pads in 4-byte steps until size == 56: any other size never matches and the loop runs away.
    if (p == NULL || block == NULL || (size & 3) != 0 || size > 52)
        return -1;
    Sha1_PrepareBlock(p, block, size);
    return 0;
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha1_GetBlockDigest(const CSha1 *p, const Byte *data, Byte *destDigest) {
    Sha1_GetBlockDigest(p, data, destDigest);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha1Prepare(void) {
    Sha1Prepare();
}

/////////////////////////////////////////
// SHA2 256
FUNCTIONEXPORT BoolInt FUNCTIONCALLINGCONVENCTION SZ_Sha256_SetFunction(CSha256 *p, unsigned algo) {
    return Sha256_SetFunction(p, algo);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha256_InitState(CSha256 *p) {
    Sha256_InitState(p);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha256_Init(CSha256 *m) {
    Sha256_Init(m);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha256_Update(CSha256 *m, const Byte *data, size_t size) {
    Sha256_Update(m, data, size);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha256_Final(CSha256 *m, Byte *digest) {
    Sha256_Final(m, digest);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_Sha256Prepare(void) {
    Sha256Prepare();    
}

/////////////////////////////////////////
// SHA2 384
FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_SHA384_Init(SHA384_CTX *m) {
    SHA384_Init(m);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_SHA384_Update(SHA384_CTX *m, const void *v, size_t len) {
    SHA384_Update(m, v, len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_SHA384_Final(void *res, SHA384_CTX *m) {
    SHA384_Final(res, m);
}

/////////////////////////////////////////
// SHA2 512
FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_SHA512_Init(SHA512_CTX *m) {
    SHA512_Init(m);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_SHA512_Update(SHA512_CTX *m, const void *v, size_t len) {
    SHA512_Update(m, v, len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_SHA512_Final(void *res, SHA512_CTX *m) {
    SHA512_Final(res, m);
}

/////////////////////////////////////////
// SHA3
FUNCTIONEXPORT int32_t FUNCTIONCALLINGCONVENCTION SZ_SHA3_Init(SHA3_CTX *m, unsigned bitSize) {
    if (m == NULL)
        return -1;
    if (bitSize != 224 && bitSize != 256 && bitSize != 384 && bitSize != 512) {
        // sha3.c:108-113 takes any size; > 800 bits makes the rate negative and the sponge index runs past the state.
        // A 0-bit context keeps later Update/Final in bounds (full-width rate, nothing copied out).
        SHA3_Init(m, 0);
        return -1;
    }
    SHA3_Init(m, bitSize);
    return 0;
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_SHA3_Update(SHA3_CTX *m, const void *v, size_t len) {
    SHA3_Update(m, v, len);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION SZ_SHA3_Final(void *res, SHA3_CTX *m) {
    SHA3_Final(res, m);
}
