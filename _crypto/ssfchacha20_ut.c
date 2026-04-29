/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfchacha20_ut.c                                                                              */
/* Provides ChaCha20 stream cipher unit test (RFC 7539).                                         */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2024 Supurloop Software LLC                                                         */
/*                                                                                               */
/* Redistribution and use in source and binary forms, with or without modification, are          */
/* permitted provided that the following conditions are met:                                     */
/*                                                                                               */
/* 1. Redistributions of source code must retain the above copyright notice, this list of        */
/* conditions and the following disclaimer.                                                      */
/* 2. Redistributions in binary form must reproduce the above copyright notice, this list of     */
/* conditions and the following disclaimer in the documentation and/or other materials provided  */
/* with the distribution.                                                                        */
/* 3. Neither the name of the copyright holder nor the names of its contributors may be used to  */
/* endorse or promote products derived from this software without specific prior written         */
/* permission.                                                                                   */
/*                                                                                               */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS   */
/* OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF               */
/* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE    */
/* COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL      */
/* EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE */
/* GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED    */
/* AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING     */
/* NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED  */
/* OF THE POSSIBILITY OF SUCH DAMAGE.                                                            */
/* --------------------------------------------------------------------------------------------- */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ssfport.h"
#include "ssfassert.h"
#include "ssfchacha20.h"

/* Cross-validate ChaCha20 against OpenSSL on host builds where libcrypto is linked. Same    */
/* gating pattern as ssfaesctr_ut.c. When disabled (cross builds with                         */
/* -DSSF_CONFIG_HAVE_OPENSSL=0) the RFC 8439 test vectors above are the load-bearing          */
/* correctness coverage.                                                                      */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_CHACHA20_UNIT_TEST == 1)
#define SSF_CHACHA20_OSSL_VERIFY 1
#else
#define SSF_CHACHA20_OSSL_VERIFY 0
#endif

#if SSF_CHACHA20_OSSL_VERIFY == 1
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#if SSF_CONFIG_CHACHA20_UNIT_TEST == 1

#if SSF_CHACHA20_OSSL_VERIFY == 1

/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers.                                                                  */
/* --------------------------------------------------------------------------------------------- */

/* Compute ChaCha20 via OpenSSL's EVP_chacha20. OpenSSL takes a 16-byte IV laid out as          */
/* [counter (4 bytes little-endian) | nonce (12 bytes)] per RFC 8439.                            */
static void _OSSLChaCha20(const uint8_t *key, const uint8_t *nonce, uint32_t counter,
                          const uint8_t *in, uint8_t *out, size_t len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t iv[16];
    int outL = 0;
    int outL2 = 0;

    iv[0] = (uint8_t)(counter & 0xFFu);
    iv[1] = (uint8_t)((counter >> 8) & 0xFFu);
    iv[2] = (uint8_t)((counter >> 16) & 0xFFu);
    iv[3] = (uint8_t)((counter >> 24) & 0xFFu);
    memcpy(&iv[4], nonce, 12u);

    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv) == 1);
    if (len > 0u) SSF_ASSERT(EVP_EncryptUpdate(ctx, out, &outL, in, (int)len) == 1);
    SSF_ASSERT(EVP_EncryptFinal_ex(ctx, out + outL, &outL2) == 1);
    SSF_ASSERT((size_t)(outL + outL2) == len);
    EVP_CIPHER_CTX_free(ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz across (counter × len) including the block-boundary cutoffs (64-byte) and       */
/* the counter values that test the high-bit / wrap-adjacent paths.                              */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyChaCha20AgainstOpenSSLRandom(void)
{
    static const size_t lens[]        = {0u, 1u, 31u, 63u, 64u, 65u, 127u, 128u, 129u,
                                          255u, 256u, 257u, 1023u, 1024u, 1025u, 4096u};
    /* Keep counters far enough below 2^32 that 4096 bytes (64 blocks) cannot wrap. RFC 8439   */
    /* doesn't define IETF ChaCha20 behavior past the 32-bit counter, and OpenSSL/SSF need not */
    /* agree there.                                                                             */
    static const uint32_t counters[]  = {0u, 1u, 0x12345678u, 0x7FFFFFFFu, 0xFFFFFFA0u};
    uint8_t key[SSF_CHACHA20_KEY_SIZE];
    uint8_t nonce[SSF_CHACHA20_NONCE_SIZE];
    uint8_t in[4096];
    uint8_t outSSF[4096];
    uint8_t outOSSL[4096];
    size_t lIdx;
    size_t cIdx;
    int iter;

    for (lIdx = 0; lIdx < (sizeof(lens) / sizeof(lens[0])); lIdx++)
    {
        for (cIdx = 0; cIdx < (sizeof(counters) / sizeof(counters[0])); cIdx++)
        {
            for (iter = 0; iter < 5; iter++)
            {
                size_t len = lens[lIdx];
                uint32_t counter = counters[cIdx];

                SSF_ASSERT(RAND_bytes(key, sizeof(key)) == 1);
                SSF_ASSERT(RAND_bytes(nonce, sizeof(nonce)) == 1);
                if (len > 0u) SSF_ASSERT(RAND_bytes(in, (int)len) == 1);

                SSFChaCha20Encrypt(in, len, key, sizeof(key), nonce, sizeof(nonce),
                                   counter, outSSF, sizeof(outSSF));
                _OSSLChaCha20(key, nonce, counter, in, outOSSL, len);
                if (len > 0u) SSF_ASSERT(memcmp(outSSF, outOSSL, len) == 0);

                /* In-place encrypt must produce the same output: catches a bug where the impl */
                /* reads from out[i] before writing the keystream-XOR result.                  */
                if (len > 0u)
                {
                    uint8_t buf[4096];
                    memcpy(buf, in, len);
                    SSFChaCha20Encrypt(buf, len, key, sizeof(key), nonce, sizeof(nonce),
                                       counter, buf, sizeof(buf));
                    SSF_ASSERT(memcmp(buf, outSSF, len) == 0);
                }
            }
        }
    }
}
#endif /* SSF_CHACHA20_OSSL_VERIFY */

/* --------------------------------------------------------------------------------------------- */
/* RFC 7539 Section 2.4.2 test vector                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFChaCha20UnitTest(void)
{
    /* RFC 7539 Section 2.4.2 - ChaCha20 encryption test vector */
    static const uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t nonce[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t pt[] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
        0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
        0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
        0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
        0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
        0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
        0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };
    static const uint8_t expected_ct[] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
        0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
        0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
        0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
        0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
        0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
        0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
        0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d
    };

    uint8_t ct[sizeof(pt)];
    uint8_t dec[sizeof(pt)];

    /* Test encryption (counter = 1 per RFC 7539 Section 2.4.2) */
    SSFChaCha20Encrypt(pt, sizeof(pt), key, sizeof(key), nonce, sizeof(nonce), 1, ct, sizeof(ct));
    SSF_ASSERT(memcmp(ct, expected_ct, sizeof(expected_ct)) == 0);

    /* Test decryption (ChaCha20 is symmetric) */
    SSFChaCha20Decrypt(ct, sizeof(ct), key, sizeof(key), nonce, sizeof(nonce), 1, dec, sizeof(dec));
    SSF_ASSERT(memcmp(dec, pt, sizeof(pt)) == 0);

    /* Test zero-length input */
    SSFChaCha20Encrypt(NULL, 0, key, sizeof(key), nonce, sizeof(nonce), 0, NULL, 0);

    /* Test single-byte encrypt/decrypt round-trip */
    {
        uint8_t one_pt = 0x42;
        uint8_t one_ct;
        uint8_t one_dec;

        SSFChaCha20Encrypt(&one_pt, 1, key, sizeof(key), nonce, sizeof(nonce), 0,
                           &one_ct, sizeof(one_ct));
        SSFChaCha20Decrypt(&one_ct, 1, key, sizeof(key), nonce, sizeof(nonce), 0,
                           &one_dec, sizeof(one_dec));
        SSF_ASSERT(one_dec == one_pt);
    }

    /* Test multi-block crossing 64-byte boundary */
    {
        uint8_t big_pt[128];
        uint8_t big_ct[128];
        uint8_t big_dec[128];
        uint32_t i;

        for (i = 0; i < sizeof(big_pt); i++) big_pt[i] = (uint8_t)i;

        SSFChaCha20Encrypt(big_pt, sizeof(big_pt), key, sizeof(key), nonce, sizeof(nonce), 0,
                           big_ct, sizeof(big_ct));
        SSFChaCha20Decrypt(big_ct, sizeof(big_ct), key, sizeof(key), nonce, sizeof(nonce), 0,
                           big_dec, sizeof(big_dec));
        SSF_ASSERT(memcmp(big_dec, big_pt, sizeof(big_pt)) == 0);
    }

    /* SSFChaCha20Encrypt: DBC coverage. The contract surface is large — key / keyLen / nonce
     * / nonceLen / ptLen <= ctSize / ptLen < 512 MiB / pt / ct. Every SSF_REQUIRE is exercised
     * with at least one boundary or NULL-pointer violation. The 512 MiB ptLen test passes
     * matching ctSize so that check fires last — nothing dereferences the pt/ct pointers so
     * the absurd ptLen value never causes a real allocation. */
    {
        static const uint8_t scratchKey[32] = {0};
        static const uint8_t scratchNonce[12] = {0};
        static const uint8_t scratchPt[16] = {0};
        uint8_t scratchCt[16];

        /* key NULL */
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           NULL, sizeof(scratchKey),
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, scratchCt, sizeof(scratchCt)));

        /* keyLen wrong (0, just below, just above, double-size) */
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, 0u,
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, 31u,
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, 33u,
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, 64u,
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, scratchCt, sizeof(scratchCt)));

        /* nonce NULL */
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, sizeof(scratchKey),
                                           NULL, sizeof(scratchNonce),
                                           0u, scratchCt, sizeof(scratchCt)));

        /* nonceLen wrong (0, just below, just above, double-size) */
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, sizeof(scratchKey),
                                           scratchNonce, 0u,
                                           0u, scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, sizeof(scratchKey),
                                           scratchNonce, 11u,
                                           0u, scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, sizeof(scratchKey),
                                           scratchNonce, 13u,
                                           0u, scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, sizeof(scratchKey),
                                           scratchNonce, 24u,
                                           0u, scratchCt, sizeof(scratchCt)));

        /* ptLen > ctSize */
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, sizeof(scratchKey),
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, scratchCt, sizeof(scratchPt) - 1u));

        /* ptLen ≥ 512 MiB. ctSize matches so the size-bound assert fires; nothing derefs pt
         * or ct, so the absurd length never causes any actual allocation or access. */
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, 512u * 1024u * 1024u,
                                           scratchKey, sizeof(scratchKey),
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, scratchCt, 512u * 1024u * 1024u));

        /* pt NULL with ptLen > 0 */
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(NULL, sizeof(scratchCt),
                                           scratchKey, sizeof(scratchKey),
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, scratchCt, sizeof(scratchCt)));

        /* ct NULL with ptLen > 0 */
        SSF_ASSERT_TEST(SSFChaCha20Encrypt(scratchPt, sizeof(scratchPt),
                                           scratchKey, sizeof(scratchKey),
                                           scratchNonce, sizeof(scratchNonce),
                                           0u, NULL, sizeof(scratchCt)));

        /* Permitted edge: ptLen == 0 with pt and ct both NULL must NOT assert. */
        SSFChaCha20Encrypt(NULL, 0u,
                           scratchKey, sizeof(scratchKey),
                           scratchNonce, sizeof(scratchNonce),
                           0u, NULL, 0u);
    }

#if SSF_CHACHA20_OSSL_VERIFY == 1
    _VerifyChaCha20AgainstOpenSSLRandom();
#endif
}

#endif /* SSF_CONFIG_CHACHA20_UNIT_TEST */
