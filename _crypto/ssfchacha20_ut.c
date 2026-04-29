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

    /* RFC 8439 §A.1 ChaCha20 block-function vectors. Encrypt-of-zero exposes the raw 64-byte
     * keystream block. These KATs isolate the QR macro / round routing / state init from the
     * encryption layer — a self-consistent-but-wrong implementation would still round-trip for
     * arbitrary plaintexts but produce keystream values that diverge from the RFC. */

    /* RFC 8439 §A.1 TV1: key=0, counter=0, nonce=0. */
    {
        static const uint8_t zeroKey[32] = {0};
        static const uint8_t zeroNonce[12] = {0};
        static const uint8_t zeroPt[64] = {0};
        static const uint8_t expectedKs[] = {
            0x76u, 0xB8u, 0xE0u, 0xADu, 0xA0u, 0xF1u, 0x3Du, 0x90u,
            0x40u, 0x5Du, 0x6Au, 0xE5u, 0x53u, 0x86u, 0xBDu, 0x28u,
            0xBDu, 0xD2u, 0x19u, 0xB8u, 0xA0u, 0x8Du, 0xEDu, 0x1Au,
            0xA8u, 0x36u, 0xEFu, 0xCCu, 0x8Bu, 0x77u, 0x0Du, 0xC7u,
            0xDAu, 0x41u, 0x59u, 0x7Cu, 0x51u, 0x57u, 0x48u, 0x8Du,
            0x77u, 0x24u, 0xE0u, 0x3Fu, 0xB8u, 0xD8u, 0x4Au, 0x37u,
            0x6Au, 0x43u, 0xB8u, 0xF4u, 0x15u, 0x18u, 0xA1u, 0x1Cu,
            0xC3u, 0x87u, 0xB6u, 0x69u, 0xB2u, 0xEEu, 0x65u, 0x86u
        };
        uint8_t ct[64];

        SSFChaCha20Encrypt(zeroPt, sizeof(zeroPt), zeroKey, sizeof(zeroKey),
                           zeroNonce, sizeof(zeroNonce), 0u, ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedKs, sizeof(expectedKs)) == 0);
    }

    /* RFC 8439 §A.1 TV2: key=0, counter=1, nonce=0 — same key/nonce as TV1 with a different
     * counter. Confirms counter is correctly mixed into state[12]. */
    {
        static const uint8_t zeroKey[32] = {0};
        static const uint8_t zeroNonce[12] = {0};
        static const uint8_t zeroPt[64] = {0};
        static const uint8_t expectedKs[] = {
            0x9Fu, 0x07u, 0xE7u, 0xBEu, 0x55u, 0x51u, 0x38u, 0x7Au,
            0x98u, 0xBAu, 0x97u, 0x7Cu, 0x73u, 0x2Du, 0x08u, 0x0Du,
            0xCBu, 0x0Fu, 0x29u, 0xA0u, 0x48u, 0xE3u, 0x65u, 0x69u,
            0x12u, 0xC6u, 0x53u, 0x3Eu, 0x32u, 0xEEu, 0x7Au, 0xEDu,
            0x29u, 0xB7u, 0x21u, 0x76u, 0x9Cu, 0xE6u, 0x4Eu, 0x43u,
            0xD5u, 0x71u, 0x33u, 0xB0u, 0x74u, 0xD8u, 0x39u, 0xD5u,
            0x31u, 0xEDu, 0x1Fu, 0x28u, 0x51u, 0x0Au, 0xFBu, 0x45u,
            0xACu, 0xE1u, 0x0Au, 0x1Fu, 0x4Bu, 0x79u, 0x4Du, 0x6Fu
        };
        uint8_t ct[64];

        SSFChaCha20Encrypt(zeroPt, sizeof(zeroPt), zeroKey, sizeof(zeroKey),
                           zeroNonce, sizeof(zeroNonce), 1u, ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedKs, sizeof(expectedKs)) == 0);
    }

    /* RFC 8439 §A.1 TV3: key=00..01, counter=1, nonce=0 — confirms key bytes mix correctly. */
    {
        static const uint8_t key1[] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
        };
        static const uint8_t zeroNonce[12] = {0};
        static const uint8_t zeroPt[64] = {0};
        static const uint8_t expectedKs[] = {
            0x3Au, 0xEBu, 0x52u, 0x24u, 0xECu, 0xF8u, 0x49u, 0x92u,
            0x9Bu, 0x9Du, 0x82u, 0x8Du, 0xB1u, 0xCEu, 0xD4u, 0xDDu,
            0x83u, 0x20u, 0x25u, 0xE8u, 0x01u, 0x8Bu, 0x81u, 0x60u,
            0xB8u, 0x22u, 0x84u, 0xF3u, 0xC9u, 0x49u, 0xAAu, 0x5Au,
            0x8Eu, 0xCAu, 0x00u, 0xBBu, 0xB4u, 0xA7u, 0x3Bu, 0xDAu,
            0xD1u, 0x92u, 0xB5u, 0xC4u, 0x2Fu, 0x73u, 0xF2u, 0xFDu,
            0x4Eu, 0x27u, 0x36u, 0x44u, 0xC8u, 0xB3u, 0x61u, 0x25u,
            0xA6u, 0x4Au, 0xDDu, 0xEBu, 0x00u, 0x6Cu, 0x13u, 0xA0u
        };
        uint8_t ct[64];

        SSFChaCha20Encrypt(zeroPt, sizeof(zeroPt), key1, sizeof(key1),
                           zeroNonce, sizeof(zeroNonce), 1u, ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedKs, sizeof(expectedKs)) == 0);
    }

    /* RFC 8439 §A.1 TV4: key=00 FF 00.., counter=2, nonce=0 — non-zero high bit in second key
     * byte exercises the LE byte-loading at state[4]. */
    {
        static const uint8_t key00ff[] = {
            0x00u, 0xFFu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
        };
        static const uint8_t zeroNonce[12] = {0};
        static const uint8_t zeroPt[64] = {0};
        static const uint8_t expectedKs[] = {
            0x72u, 0xD5u, 0x4Du, 0xFBu, 0xF1u, 0x2Eu, 0xC4u, 0x4Bu,
            0x36u, 0x26u, 0x92u, 0xDFu, 0x94u, 0x13u, 0x7Fu, 0x32u,
            0x8Fu, 0xEAu, 0x8Du, 0xA7u, 0x39u, 0x90u, 0x26u, 0x5Eu,
            0xC1u, 0xBBu, 0xBEu, 0xA1u, 0xAEu, 0x9Au, 0xF0u, 0xCAu,
            0x13u, 0xB2u, 0x5Au, 0xA2u, 0x6Cu, 0xB4u, 0xA6u, 0x48u,
            0xCBu, 0x9Bu, 0x9Du, 0x1Bu, 0xE6u, 0x5Bu, 0x2Cu, 0x09u,
            0x24u, 0xA6u, 0x6Cu, 0x54u, 0xD5u, 0x45u, 0xECu, 0x1Bu,
            0x73u, 0x74u, 0xF4u, 0x87u, 0x2Eu, 0x99u, 0xF0u, 0x96u
        };
        uint8_t ct[64];

        SSFChaCha20Encrypt(zeroPt, sizeof(zeroPt), key00ff, sizeof(key00ff),
                           zeroNonce, sizeof(zeroNonce), 2u, ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedKs, sizeof(expectedKs)) == 0);
    }

    /* RFC 8439 §A.1 TV5: key=0, counter=0, nonce=00..02 — non-zero nonce confirms it is
     * correctly placed in state[13..15]. */
    {
        static const uint8_t zeroKey[32] = {0};
        static const uint8_t nonce2[] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x02u
        };
        static const uint8_t zeroPt[64] = {0};
        static const uint8_t expectedKs[] = {
            0xC2u, 0xC6u, 0x4Du, 0x37u, 0x8Cu, 0xD5u, 0x36u, 0x37u,
            0x4Au, 0xE2u, 0x04u, 0xB9u, 0xEFu, 0x93u, 0x3Fu, 0xCDu,
            0x1Au, 0x8Bu, 0x22u, 0x88u, 0xB3u, 0xDFu, 0xA4u, 0x96u,
            0x72u, 0xABu, 0x76u, 0x5Bu, 0x54u, 0xEEu, 0x27u, 0xC7u,
            0x8Au, 0x97u, 0x0Eu, 0x0Eu, 0x95u, 0x5Cu, 0x14u, 0xF3u,
            0xA8u, 0x8Eu, 0x74u, 0x1Bu, 0x97u, 0xC2u, 0x86u, 0xF7u,
            0x5Fu, 0x8Fu, 0xC2u, 0x99u, 0xE8u, 0x14u, 0x83u, 0x62u,
            0xFAu, 0x19u, 0x8Au, 0x39u, 0x53u, 0x1Bu, 0xEDu, 0x6Du
        };
        uint8_t ct[64];

        SSFChaCha20Encrypt(zeroPt, sizeof(zeroPt), zeroKey, sizeof(zeroKey),
                           nonce2, sizeof(nonce2), 0u, ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedKs, sizeof(expectedKs)) == 0);
    }

    /* RFC 8439 §A.2 TV2: 375-byte IETF-text encryption with key=00..01, counter=1, nonce=00..02.
     * Multi-block (5 full + 1 partial = 6 blocks); confirms counter advances correctly across
     * blocks and partial-final-block keystream truncation works. (§A.2 TV1 is redundant with
     * §A.1 TV1 above — same key/nonce/counter on a 64-byte zero plaintext — so it is omitted.) */
    {
        static const uint8_t key1[] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x01u
        };
        static const uint8_t nonce2[] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x02u
        };
        static const uint8_t plaintext[] = {
            0x41u, 0x6Eu, 0x79u, 0x20u, 0x73u, 0x75u, 0x62u, 0x6Du,
            0x69u, 0x73u, 0x73u, 0x69u, 0x6Fu, 0x6Eu, 0x20u, 0x74u,
            0x6Fu, 0x20u, 0x74u, 0x68u, 0x65u, 0x20u, 0x49u, 0x45u,
            0x54u, 0x46u, 0x20u, 0x69u, 0x6Eu, 0x74u, 0x65u, 0x6Eu,
            0x64u, 0x65u, 0x64u, 0x20u, 0x62u, 0x79u, 0x20u, 0x74u,
            0x68u, 0x65u, 0x20u, 0x43u, 0x6Fu, 0x6Eu, 0x74u, 0x72u,
            0x69u, 0x62u, 0x75u, 0x74u, 0x6Fu, 0x72u, 0x20u, 0x66u,
            0x6Fu, 0x72u, 0x20u, 0x70u, 0x75u, 0x62u, 0x6Cu, 0x69u,
            0x63u, 0x61u, 0x74u, 0x69u, 0x6Fu, 0x6Eu, 0x20u, 0x61u,
            0x73u, 0x20u, 0x61u, 0x6Cu, 0x6Cu, 0x20u, 0x6Fu, 0x72u,
            0x20u, 0x70u, 0x61u, 0x72u, 0x74u, 0x20u, 0x6Fu, 0x66u,
            0x20u, 0x61u, 0x6Eu, 0x20u, 0x49u, 0x45u, 0x54u, 0x46u,
            0x20u, 0x49u, 0x6Eu, 0x74u, 0x65u, 0x72u, 0x6Eu, 0x65u,
            0x74u, 0x2Du, 0x44u, 0x72u, 0x61u, 0x66u, 0x74u, 0x20u,
            0x6Fu, 0x72u, 0x20u, 0x52u, 0x46u, 0x43u, 0x20u, 0x61u,
            0x6Eu, 0x64u, 0x20u, 0x61u, 0x6Eu, 0x79u, 0x20u, 0x73u,
            0x74u, 0x61u, 0x74u, 0x65u, 0x6Du, 0x65u, 0x6Eu, 0x74u,
            0x20u, 0x6Du, 0x61u, 0x64u, 0x65u, 0x20u, 0x77u, 0x69u,
            0x74u, 0x68u, 0x69u, 0x6Eu, 0x20u, 0x74u, 0x68u, 0x65u,
            0x20u, 0x63u, 0x6Fu, 0x6Eu, 0x74u, 0x65u, 0x78u, 0x74u,
            0x20u, 0x6Fu, 0x66u, 0x20u, 0x61u, 0x6Eu, 0x20u, 0x49u,
            0x45u, 0x54u, 0x46u, 0x20u, 0x61u, 0x63u, 0x74u, 0x69u,
            0x76u, 0x69u, 0x74u, 0x79u, 0x20u, 0x69u, 0x73u, 0x20u,
            0x63u, 0x6Fu, 0x6Eu, 0x73u, 0x69u, 0x64u, 0x65u, 0x72u,
            0x65u, 0x64u, 0x20u, 0x61u, 0x6Eu, 0x20u, 0x22u, 0x49u,
            0x45u, 0x54u, 0x46u, 0x20u, 0x43u, 0x6Fu, 0x6Eu, 0x74u,
            0x72u, 0x69u, 0x62u, 0x75u, 0x74u, 0x69u, 0x6Fu, 0x6Eu,
            0x22u, 0x2Eu, 0x20u, 0x53u, 0x75u, 0x63u, 0x68u, 0x20u,
            0x73u, 0x74u, 0x61u, 0x74u, 0x65u, 0x6Du, 0x65u, 0x6Eu,
            0x74u, 0x73u, 0x20u, 0x69u, 0x6Eu, 0x63u, 0x6Cu, 0x75u,
            0x64u, 0x65u, 0x20u, 0x6Fu, 0x72u, 0x61u, 0x6Cu, 0x20u,
            0x73u, 0x74u, 0x61u, 0x74u, 0x65u, 0x6Du, 0x65u, 0x6Eu,
            0x74u, 0x73u, 0x20u, 0x69u, 0x6Eu, 0x20u, 0x49u, 0x45u,
            0x54u, 0x46u, 0x20u, 0x73u, 0x65u, 0x73u, 0x73u, 0x69u,
            0x6Fu, 0x6Eu, 0x73u, 0x2Cu, 0x20u, 0x61u, 0x73u, 0x20u,
            0x77u, 0x65u, 0x6Cu, 0x6Cu, 0x20u, 0x61u, 0x73u, 0x20u,
            0x77u, 0x72u, 0x69u, 0x74u, 0x74u, 0x65u, 0x6Eu, 0x20u,
            0x61u, 0x6Eu, 0x64u, 0x20u, 0x65u, 0x6Cu, 0x65u, 0x63u,
            0x74u, 0x72u, 0x6Fu, 0x6Eu, 0x69u, 0x63u, 0x20u, 0x63u,
            0x6Fu, 0x6Du, 0x6Du, 0x75u, 0x6Eu, 0x69u, 0x63u, 0x61u,
            0x74u, 0x69u, 0x6Fu, 0x6Eu, 0x73u, 0x20u, 0x6Du, 0x61u,
            0x64u, 0x65u, 0x20u, 0x61u, 0x74u, 0x20u, 0x61u, 0x6Eu,
            0x79u, 0x20u, 0x74u, 0x69u, 0x6Du, 0x65u, 0x20u, 0x6Fu,
            0x72u, 0x20u, 0x70u, 0x6Cu, 0x61u, 0x63u, 0x65u, 0x2Cu,
            0x20u, 0x77u, 0x68u, 0x69u, 0x63u, 0x68u, 0x20u, 0x61u,
            0x72u, 0x65u, 0x20u, 0x61u, 0x64u, 0x64u, 0x72u, 0x65u,
            0x73u, 0x73u, 0x65u, 0x64u, 0x20u, 0x74u, 0x6Fu
        };
        static const uint8_t expectedCt[] = {
            0xA3u, 0xFBu, 0xF0u, 0x7Du, 0xF3u, 0xFAu, 0x2Fu, 0xDEu,
            0x4Fu, 0x37u, 0x6Cu, 0xA2u, 0x3Eu, 0x82u, 0x73u, 0x70u,
            0x41u, 0x60u, 0x5Du, 0x9Fu, 0x4Fu, 0x4Fu, 0x57u, 0xBDu,
            0x8Cu, 0xFFu, 0x2Cu, 0x1Du, 0x4Bu, 0x79u, 0x55u, 0xECu,
            0x2Au, 0x97u, 0x94u, 0x8Bu, 0xD3u, 0x72u, 0x29u, 0x15u,
            0xC8u, 0xF3u, 0xD3u, 0x37u, 0xF7u, 0xD3u, 0x70u, 0x05u,
            0x0Eu, 0x9Eu, 0x96u, 0xD6u, 0x47u, 0xB7u, 0xC3u, 0x9Fu,
            0x56u, 0xE0u, 0x31u, 0xCAu, 0x5Eu, 0xB6u, 0x25u, 0x0Du,
            0x40u, 0x42u, 0xE0u, 0x27u, 0x85u, 0xECu, 0xECu, 0xFAu,
            0x4Bu, 0x4Bu, 0xB5u, 0xE8u, 0xEAu, 0xD0u, 0x44u, 0x0Eu,
            0x20u, 0xB6u, 0xE8u, 0xDBu, 0x09u, 0xD8u, 0x81u, 0xA7u,
            0xC6u, 0x13u, 0x2Fu, 0x42u, 0x0Eu, 0x52u, 0x79u, 0x50u,
            0x42u, 0xBDu, 0xFAu, 0x77u, 0x73u, 0xD8u, 0xA9u, 0x05u,
            0x14u, 0x47u, 0xB3u, 0x29u, 0x1Cu, 0xE1u, 0x41u, 0x1Cu,
            0x68u, 0x04u, 0x65u, 0x55u, 0x2Au, 0xA6u, 0xC4u, 0x05u,
            0xB7u, 0x76u, 0x4Du, 0x5Eu, 0x87u, 0xBEu, 0xA8u, 0x5Au,
            0xD0u, 0x0Fu, 0x84u, 0x49u, 0xEDu, 0x8Fu, 0x72u, 0xD0u,
            0xD6u, 0x62u, 0xABu, 0x05u, 0x26u, 0x91u, 0xCAu, 0x66u,
            0x42u, 0x4Bu, 0xC8u, 0x6Du, 0x2Du, 0xF8u, 0x0Eu, 0xA4u,
            0x1Fu, 0x43u, 0xABu, 0xF9u, 0x37u, 0xD3u, 0x25u, 0x9Du,
            0xC4u, 0xB2u, 0xD0u, 0xDFu, 0xB4u, 0x8Au, 0x6Cu, 0x91u,
            0x39u, 0xDDu, 0xD7u, 0xF7u, 0x69u, 0x66u, 0xE9u, 0x28u,
            0xE6u, 0x35u, 0x55u, 0x3Bu, 0xA7u, 0x6Cu, 0x5Cu, 0x87u,
            0x9Du, 0x7Bu, 0x35u, 0xD4u, 0x9Eu, 0xB2u, 0xE6u, 0x2Bu,
            0x08u, 0x71u, 0xCDu, 0xACu, 0x63u, 0x89u, 0x39u, 0xE2u,
            0x5Eu, 0x8Au, 0x1Eu, 0x0Eu, 0xF9u, 0xD5u, 0x28u, 0x0Fu,
            0xA8u, 0xCAu, 0x32u, 0x8Bu, 0x35u, 0x1Cu, 0x3Cu, 0x76u,
            0x59u, 0x89u, 0xCBu, 0xCFu, 0x3Du, 0xAAu, 0x8Bu, 0x6Cu,
            0xCCu, 0x3Au, 0xAFu, 0x9Fu, 0x39u, 0x79u, 0xC9u, 0x2Bu,
            0x37u, 0x20u, 0xFCu, 0x88u, 0xDCu, 0x95u, 0xEDu, 0x84u,
            0xA1u, 0xBEu, 0x05u, 0x9Cu, 0x64u, 0x99u, 0xB9u, 0xFDu,
            0xA2u, 0x36u, 0xE7u, 0xE8u, 0x18u, 0xB0u, 0x4Bu, 0x0Bu,
            0xC3u, 0x9Cu, 0x1Eu, 0x87u, 0x6Bu, 0x19u, 0x3Bu, 0xFEu,
            0x55u, 0x69u, 0x75u, 0x3Fu, 0x88u, 0x12u, 0x8Cu, 0xC0u,
            0x8Au, 0xAAu, 0x9Bu, 0x63u, 0xD1u, 0xA1u, 0x6Fu, 0x80u,
            0xEFu, 0x25u, 0x54u, 0xD7u, 0x18u, 0x9Cu, 0x41u, 0x1Fu,
            0x58u, 0x69u, 0xCAu, 0x52u, 0xC5u, 0xB8u, 0x3Fu, 0xA3u,
            0x6Fu, 0xF2u, 0x16u, 0xB9u, 0xC1u, 0xD3u, 0x00u, 0x62u,
            0xBEu, 0xBCu, 0xFDu, 0x2Du, 0xC5u, 0xBCu, 0xE0u, 0x91u,
            0x19u, 0x34u, 0xFDu, 0xA7u, 0x9Au, 0x86u, 0xF6u, 0xE6u,
            0x98u, 0xCEu, 0xD7u, 0x59u, 0xC3u, 0xFFu, 0x9Bu, 0x64u,
            0x77u, 0x33u, 0x8Fu, 0x3Du, 0xA4u, 0xF9u, 0xCDu, 0x85u,
            0x14u, 0xEAu, 0x99u, 0x82u, 0xCCu, 0xAFu, 0xB3u, 0x41u,
            0xB2u, 0x38u, 0x4Du, 0xD9u, 0x02u, 0xF3u, 0xD1u, 0xABu,
            0x7Au, 0xC6u, 0x1Du, 0xD2u, 0x9Cu, 0x6Fu, 0x21u, 0xBAu,
            0x5Bu, 0x86u, 0x2Fu, 0x37u, 0x30u, 0xE3u, 0x7Cu, 0xFDu,
            0xC4u, 0xFDu, 0x80u, 0x6Cu, 0x22u, 0xF2u, 0x21u
        };
        uint8_t ct[sizeof(plaintext)];

        SSFChaCha20Encrypt(plaintext, sizeof(plaintext), key1, sizeof(key1),
                           nonce2, sizeof(nonce2), 1u, ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedCt, sizeof(expectedCt)) == 0);
    }

    /* RFC 8439 §A.2 TV3: 127-byte Jabberwocky excerpt with a non-zero key, an unusual high
     * starting counter (42), and the §A.1 TV5 nonce. Tests counter values that are neither 0
     * nor 1 — the typical (key, nonce, counter ≠ 0/1) combination not exercised elsewhere. */
    {
        static const uint8_t keyJ[] = {
            0x1Cu, 0x92u, 0x40u, 0xA5u, 0xEBu, 0x55u, 0xD3u, 0x8Au,
            0xF3u, 0x33u, 0x88u, 0x86u, 0x04u, 0xF6u, 0xB5u, 0xF0u,
            0x47u, 0x39u, 0x17u, 0xC1u, 0x40u, 0x2Bu, 0x80u, 0x09u,
            0x9Du, 0xCAu, 0x5Cu, 0xBCu, 0x20u, 0x70u, 0x75u, 0xC0u
        };
        static const uint8_t nonce2[] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x00u, 0x02u
        };
        static const uint8_t plaintext[] = {
            0x27u, 0x54u, 0x77u, 0x61u, 0x73u, 0x20u, 0x62u, 0x72u,
            0x69u, 0x6Cu, 0x6Cu, 0x69u, 0x67u, 0x2Cu, 0x20u, 0x61u,
            0x6Eu, 0x64u, 0x20u, 0x74u, 0x68u, 0x65u, 0x20u, 0x73u,
            0x6Cu, 0x69u, 0x74u, 0x68u, 0x79u, 0x20u, 0x74u, 0x6Fu,
            0x76u, 0x65u, 0x73u, 0x0Au, 0x44u, 0x69u, 0x64u, 0x20u,
            0x67u, 0x79u, 0x72u, 0x65u, 0x20u, 0x61u, 0x6Eu, 0x64u,
            0x20u, 0x67u, 0x69u, 0x6Du, 0x62u, 0x6Cu, 0x65u, 0x20u,
            0x69u, 0x6Eu, 0x20u, 0x74u, 0x68u, 0x65u, 0x20u, 0x77u,
            0x61u, 0x62u, 0x65u, 0x3Au, 0x0Au, 0x41u, 0x6Cu, 0x6Cu,
            0x20u, 0x6Du, 0x69u, 0x6Du, 0x73u, 0x79u, 0x20u, 0x77u,
            0x65u, 0x72u, 0x65u, 0x20u, 0x74u, 0x68u, 0x65u, 0x20u,
            0x62u, 0x6Fu, 0x72u, 0x6Fu, 0x67u, 0x6Fu, 0x76u, 0x65u,
            0x73u, 0x2Cu, 0x0Au, 0x41u, 0x6Eu, 0x64u, 0x20u, 0x74u,
            0x68u, 0x65u, 0x20u, 0x6Du, 0x6Fu, 0x6Du, 0x65u, 0x20u,
            0x72u, 0x61u, 0x74u, 0x68u, 0x73u, 0x20u, 0x6Fu, 0x75u,
            0x74u, 0x67u, 0x72u, 0x61u, 0x62u, 0x65u, 0x2Eu
        };
        static const uint8_t expectedCt[] = {
            0x62u, 0xE6u, 0x34u, 0x7Fu, 0x95u, 0xEDu, 0x87u, 0xA4u,
            0x5Fu, 0xFAu, 0xE7u, 0x42u, 0x6Fu, 0x27u, 0xA1u, 0xDFu,
            0x5Fu, 0xB6u, 0x91u, 0x10u, 0x04u, 0x4Cu, 0x0Du, 0x73u,
            0x11u, 0x8Eu, 0xFFu, 0xA9u, 0x5Bu, 0x01u, 0xE5u, 0xCFu,
            0x16u, 0x6Du, 0x3Du, 0xF2u, 0xD7u, 0x21u, 0xCAu, 0xF9u,
            0xB2u, 0x1Eu, 0x5Fu, 0xB1u, 0x4Cu, 0x61u, 0x68u, 0x71u,
            0xFDu, 0x84u, 0xC5u, 0x4Fu, 0x9Du, 0x65u, 0xB2u, 0x83u,
            0x19u, 0x6Cu, 0x7Fu, 0xE4u, 0xF6u, 0x05u, 0x53u, 0xEBu,
            0xF3u, 0x9Cu, 0x64u, 0x02u, 0xC4u, 0x22u, 0x34u, 0xE3u,
            0x2Au, 0x35u, 0x6Bu, 0x3Eu, 0x76u, 0x43u, 0x12u, 0xA6u,
            0x1Au, 0x55u, 0x32u, 0x05u, 0x57u, 0x16u, 0xEAu, 0xD6u,
            0x96u, 0x25u, 0x68u, 0xF8u, 0x7Du, 0x3Fu, 0x3Fu, 0x77u,
            0x04u, 0xC6u, 0xA8u, 0xD1u, 0xBCu, 0xD1u, 0xBFu, 0x4Du,
            0x50u, 0xD6u, 0x15u, 0x4Bu, 0x6Du, 0xA7u, 0x31u, 0xB1u,
            0x87u, 0xB5u, 0x8Du, 0xFDu, 0x72u, 0x8Au, 0xFAu, 0x36u,
            0x75u, 0x7Au, 0x79u, 0x7Au, 0xC1u, 0x88u, 0xD1u
        };
        uint8_t ct[sizeof(plaintext)];

        SSFChaCha20Encrypt(plaintext, sizeof(plaintext), keyJ, sizeof(keyJ),
                           nonce2, sizeof(nonce2), 42u, ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedCt, sizeof(expectedCt)) == 0);
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

        /* Counter wrap forbidden. RFC 8439 leaves behavior past 2^32 blocks undefined and
         * SSF diverges from OpenSSL there; the contract forbids any (counter, ptLen) where
         * the last block index would exceed 2^32 - 1. Use larger pt/ct buffers since the
         * earlier ptLen <= ctSize check would otherwise fire first. */
        {
            uint8_t bigPt[129] = {0};
            uint8_t bigCt[129];

            /* Just past the boundary: counter=UINT32_MAX with ptLen=65 needs 2 blocks, and
             * the second one would be at the wrap. Must assert. */
            SSF_ASSERT_TEST(SSFChaCha20Encrypt(bigPt, 65u,
                                               scratchKey, sizeof(scratchKey),
                                               scratchNonce, sizeof(scratchNonce),
                                               0xFFFFFFFFu, bigCt, sizeof(bigCt)));
            /* Past boundary by one: counter=0xFFFFFFFE with ptLen=129 needs 3 blocks; the
             * third one is at the wrap. Must assert. */
            SSF_ASSERT_TEST(SSFChaCha20Encrypt(bigPt, 129u,
                                               scratchKey, sizeof(scratchKey),
                                               scratchNonce, sizeof(scratchNonce),
                                               0xFFFFFFFEu, bigCt, sizeof(bigCt)));

            /* Boundary OK: last block at counter == UINT32_MAX, no wrap. Must NOT assert. */
            SSFChaCha20Encrypt(bigPt, 64u,
                               scratchKey, sizeof(scratchKey),
                               scratchNonce, sizeof(scratchNonce),
                               0xFFFFFFFFu, bigCt, sizeof(bigCt));
            /* Boundary OK: 2 blocks ending at counter == UINT32_MAX. Must NOT assert. */
            SSFChaCha20Encrypt(bigPt, 128u,
                               scratchKey, sizeof(scratchKey),
                               scratchNonce, sizeof(scratchNonce),
                               0xFFFFFFFEu, bigCt, sizeof(bigCt));
        }
    }

#if SSF_CHACHA20_OSSL_VERIFY == 1
    _VerifyChaCha20AgainstOpenSSLRandom();
#endif
}

#endif /* SSF_CONFIG_CHACHA20_UNIT_TEST */
