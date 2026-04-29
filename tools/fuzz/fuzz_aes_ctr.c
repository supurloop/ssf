/* libFuzzer harness: differential test SSF AES-CTR against OpenSSL EVP_aes_*_ctr.
 *
 * Input layout (mutated by the fuzzer):
 *   byte 0          — keysize selector (0/1/2 → 16/24/32)
 *   bytes 1..N      — key
 *   bytes N+1..N+16 — IV / initial counter (16 bytes)
 *   bytes N+17..end — plaintext (variable length, 0..1024 bytes)
 *
 * We run SSFAESCTR on the buffer, run OpenSSL EVP_aes_*_ctr's encrypt path on the
 * same buffer, and abort if the outputs disagree. ASan/UBSan also instrument both
 * sides, so any memory or UB that fires on either side aborts here.
 *
 * Run:
 *   ./fuzz_aes_ctr -max_total_time=300 corpus_dir
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/evp.h>

#include "ssfport.h"
#include "ssfassert.h"
#include "ssfaesctr.h"

#define MAX_PT_LEN 1024u

static void ossl_aes_ctr(const uint8_t *key, size_t keyLen,
                         const uint8_t *iv,
                         const uint8_t *in, size_t inLen,
                         uint8_t *out)
{
    const EVP_CIPHER *cipher;
    switch (keyLen) {
        case 16: cipher = EVP_aes_128_ctr(); break;
        case 24: cipher = EVP_aes_192_ctr(); break;
        case 32: cipher = EVP_aes_256_ctr(); break;
        default: abort();
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) abort();
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) abort();
    int outLen = 0;
    if (EVP_EncryptUpdate(ctx, out, &outLen, in, (int)inLen) != 1) abort();
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, out + outLen, &finalLen) != 1) abort();
    EVP_CIPHER_CTX_free(ctx);
    if ((size_t)(outLen + finalLen) != inLen) abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Need at least selector + 16-byte key + 16-byte IV. */
    if (size < 1u + 16u + 16u) return 0;

    uint8_t sel = data[0] % 3u;
    size_t keyLen = (sel == 0u) ? 16u : (sel == 1u) ? 24u : 32u;

    if (size < 1u + keyLen + 16u) return 0;

    const uint8_t *key = data + 1u;
    const uint8_t *iv  = key + keyLen;
    const uint8_t *pt  = iv + 16u;
    size_t ptLen = size - 1u - keyLen - 16u;

    if (ptLen > MAX_PT_LEN) ptLen = MAX_PT_LEN;
    if (ptLen == 0u) return 0;  /* CTR with 0-length input is a no-op; skip. */

    uint8_t ssf_out[MAX_PT_LEN];
    uint8_t ossl_out[MAX_PT_LEN];

    SSFAESCTR(key, keyLen, iv, pt, ssf_out, ptLen);
    ossl_aes_ctr(key, keyLen, iv, pt, ptLen, ossl_out);

    if (memcmp(ssf_out, ossl_out, ptLen) != 0) {
        fprintf(stderr, "DIVERGENCE: keyLen=%zu ptLen=%zu\n", keyLen, ptLen);
        for (size_t i = 0; i < ptLen; i++) {
            if (ssf_out[i] != ossl_out[i]) {
                fprintf(stderr, "  [%zu] ssf=%02x ossl=%02x\n",
                        i, ssf_out[i], ossl_out[i]);
                break;
            }
        }
        abort();
    }

    /* Also check round-trip: decrypt(encrypt(pt)) == pt for both. */
    uint8_t ssf_back[MAX_PT_LEN];
    SSFAESCTR(key, keyLen, iv, ssf_out, ssf_back, ptLen);
    if (memcmp(ssf_back, pt, ptLen) != 0) abort();

    return 0;
}
