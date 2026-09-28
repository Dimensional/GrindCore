#include <pal_brotli_v1_1_0.h>

// Argument checks (audit/other-codecs.md 4.3.1), with the zstd PAL's conventions (audit/zstd.md 2.2). Brotli
// dereferences its state, size and cursor pointers without checking them. A bad argument gets Brotli's own failure
// value, BROTLI_FALSE or BROTLI_DECODER_RESULT_ERROR, and nothing is touched. A NULL buffer is only bad with a nonzero
// size, so an empty array (which .NET pins as NULL) is still an empty buffer. As Brotli documents, the output cursor
// may be NULL when there's no room, and total_out may always be NULL.
#define SZ_BRT_NULL_BUF(p, n) (!(p) && (n) != 0)
#define SZ_BRT_BAD_CURSORS(available_in, next_in, available_out, next_out) \
    (!(available_in) || !(next_in) || !(available_out) || SZ_BRT_NULL_BUF(*(next_in), *(available_in)) || \
     (*(available_out) != 0 && (!(next_out) || !*(next_out))))

FUNCTIONEXPORT BrotliDecoderState* FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliDecoderCreateInstance(
    brotli_alloc_func alloc_func, brotli_free_func free_func, void* opaque) {
    return BrotliDecoderCreateInstance(alloc_func, free_func, opaque);
}

FUNCTIONEXPORT BrotliDecoderResult FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliDecoderDecompress(
    size_t encoded_size, const uint8_t* encoded_buffer,
    size_t* decoded_size, uint8_t* decoded_buffer) {
    if (!decoded_size || SZ_BRT_NULL_BUF(encoded_buffer, encoded_size) || SZ_BRT_NULL_BUF(decoded_buffer, *decoded_size))
        return BROTLI_DECODER_RESULT_ERROR;
    return BrotliDecoderDecompress(encoded_size, encoded_buffer, decoded_size, decoded_buffer);
}

FUNCTIONEXPORT BrotliDecoderResult FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliDecoderDecompressStream(
    BrotliDecoderState* state, size_t* available_in, const uint8_t** next_in,
    size_t* available_out, uint8_t** next_out, size_t* total_out) {
    if (!state || SZ_BRT_BAD_CURSORS(available_in, next_in, available_out, next_out))
        return BROTLI_DECODER_RESULT_ERROR;
    return BrotliDecoderDecompressStream(state, available_in, next_in, available_out, next_out, total_out);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliDecoderDestroyInstance(BrotliDecoderState* state) {
    BrotliDecoderDestroyInstance(state); // accepts NULL
}

FUNCTIONEXPORT BROTLI_BOOL FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliDecoderIsFinished(const BrotliDecoderState* state) {
    if (!state) return BROTLI_FALSE;
    return BrotliDecoderIsFinished(state);
}

FUNCTIONEXPORT BROTLI_BOOL FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliEncoderCompress(
    int quality, int lgwin, BrotliEncoderMode mode, size_t input_size, const uint8_t* input_buffer,
    size_t* encoded_size, uint8_t* encoded_buffer) {
    if (!encoded_size || SZ_BRT_NULL_BUF(input_buffer, input_size) || SZ_BRT_NULL_BUF(encoded_buffer, *encoded_size))
        return BROTLI_FALSE;
    return BrotliEncoderCompress(quality, lgwin, mode, input_size, input_buffer, encoded_size, encoded_buffer);
}

FUNCTIONEXPORT BROTLI_BOOL FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliEncoderCompressStream(
    BrotliEncoderState* state, BrotliEncoderOperation op,
    size_t* available_in, const uint8_t** next_in,
    size_t* available_out, uint8_t** next_out, size_t* total_out) {
    if (!state || SZ_BRT_BAD_CURSORS(available_in, next_in, available_out, next_out))
        return BROTLI_FALSE;
    return BrotliEncoderCompressStream(state, op, available_in, next_in, available_out, next_out, total_out);
}

FUNCTIONEXPORT BrotliEncoderState* FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliEncoderCreateInstance(
    brotli_alloc_func alloc_func, brotli_free_func free_func, void* opaque) {
    return BrotliEncoderCreateInstance(alloc_func, free_func, opaque);
}

FUNCTIONEXPORT void FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliEncoderDestroyInstance(BrotliEncoderState* state) {
    BrotliEncoderDestroyInstance(state); // accepts NULL
}

FUNCTIONEXPORT BROTLI_BOOL FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliEncoderHasMoreOutput(BrotliEncoderState* state) {
    if (!state) return BROTLI_FALSE;
    return BrotliEncoderHasMoreOutput(state);
}

FUNCTIONEXPORT size_t FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliEncoderMaxCompressedSize(size_t input_size) {
    return BrotliEncoderMaxCompressedSize(input_size);
}

FUNCTIONEXPORT BROTLI_BOOL FUNCTIONCALLINGCONVENCTION DN9_BRT_v1_1_0_BrotliEncoderSetParameter(
    BrotliEncoderState* state, BrotliEncoderParameter param, uint32_t value) {
    if (!state) return BROTLI_FALSE;
    return BrotliEncoderSetParameter(state, param, value);
}
