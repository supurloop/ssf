/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfchacha20poly1305_ut.c                                                                      */
/* Provides ChaCha20-Poly1305 AEAD unit test (RFC 7539).                                         */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2026 Supurloop Software LLC                                                         */
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
#include "ssfchacha20poly1305.h"

/* Cross-validate ChaCha20-Poly1305 AEAD against OpenSSL on host builds where libcrypto is */
/* linked. Same gating pattern as ssfaesctr_ut.c. When disabled (cross builds with         */
/* -DSSF_CONFIG_HAVE_OPENSSL=0) the RFC 8439 KAT plus internal corner cases are the load-  */
/* bearing correctness coverage.                                                             */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_CCP_UNIT_TEST == 1)
#define SSF_CCP_OSSL_VERIFY 1
#else
#define SSF_CCP_OSSL_VERIFY 0
#endif

#if SSF_CCP_OSSL_VERIFY == 1
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#if SSF_CONFIG_CCP_UNIT_TEST == 1

#if SSF_CCP_OSSL_VERIFY == 1

/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers.                                                                  */
/* --------------------------------------------------------------------------------------------- */

/* Encrypt + tag via OpenSSL EVP_chacha20_poly1305. */
static void _OSSLCCPEncrypt(const uint8_t *pt, size_t ptLen,
                            const uint8_t *iv, size_t ivLen,
                            const uint8_t *aad, size_t aadLen,
                            const uint8_t *key, uint8_t *tag, uint8_t *ct)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outL = 0;
    int outL2 = 0;

    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1);
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)ivLen, NULL) == 1);
    SSF_ASSERT(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) == 1);
    if (aadLen > 0u)
    {
        SSF_ASSERT(EVP_EncryptUpdate(ctx, NULL, &outL, aad, (int)aadLen) == 1);
    }
    if (ptLen > 0u)
    {
        SSF_ASSERT(EVP_EncryptUpdate(ctx, ct, &outL, pt, (int)ptLen) == 1);
        SSF_ASSERT((size_t)outL == ptLen);
    }
    SSF_ASSERT(EVP_EncryptFinal_ex(ctx, (ptLen > 0u) ? (ct + outL) : NULL, &outL2) == 1);
    SSF_ASSERT(outL2 == 0);
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, SSF_CCP_TAG_SIZE, tag) == 1);
    EVP_CIPHER_CTX_free(ctx);
}

/* Decrypt + verify via OpenSSL. */
static bool _OSSLCCPDecrypt(const uint8_t *ct, size_t ctLen,
                            const uint8_t *iv, size_t ivLen,
                            const uint8_t *aad, size_t aadLen,
                            const uint8_t *key, const uint8_t *tag, uint8_t *pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outL = 0;
    int rc;
    bool ok;

    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1);
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)ivLen, NULL) == 1);
    SSF_ASSERT(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1);
    if (aadLen > 0u)
    {
        SSF_ASSERT(EVP_DecryptUpdate(ctx, NULL, &outL, aad, (int)aadLen) == 1);
    }
    if (ctLen > 0u)
    {
        SSF_ASSERT(EVP_DecryptUpdate(ctx, pt, &outL, ct, (int)ctLen) == 1);
        SSF_ASSERT((size_t)outL == ctLen);
    }
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, SSF_CCP_TAG_SIZE, (void *)tag) == 1);
    rc = EVP_DecryptFinal_ex(ctx, (ctLen > 0u) ? (pt + outL) : NULL, &outL);
    ok = (rc == 1);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz across (ptLen × aadLen). Each cell:                                               */
/*   - draws fresh random key/nonce/aad/pt                                                       */
/*   - SSF and OpenSSL encrypt; assert ct AND tag agree byte-for-byte                            */
/*   - decrypt SSF ct via OpenSSL and OpenSSL ct via SSF; both must succeed and recover pt       */
/*   - tamper ct[0] / aad[0] / tag[0]; both libs must reject                                     */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyCCPAgainstOpenSSLRandom(void)
{
    static const size_t ptLens[]  = {0u, 1u, 15u, 16u, 17u, 31u, 32u, 33u, 63u, 64u, 65u, 100u,
                                      256u, 1024u};
    static const size_t aadLens[] = {0u, 1u, 15u, 16u, 17u, 64u, 100u};
    uint8_t key[SSF_CCP_KEY_SIZE];
    uint8_t nonce[SSF_CCP_NONCE_SIZE];
    uint8_t aad[100];
    uint8_t pt[1024];
    uint8_t ctSSF[1024];
    uint8_t ctOSSL[1024];
    uint8_t tagSSF[SSF_CCP_TAG_SIZE];
    uint8_t tagOSSL[SSF_CCP_TAG_SIZE];
    uint8_t back[1024];
    size_t pIdx;
    size_t aIdx;
    int iter;

    for (pIdx = 0; pIdx < (sizeof(ptLens) / sizeof(ptLens[0])); pIdx++)
    {
        for (aIdx = 0; aIdx < (sizeof(aadLens) / sizeof(aadLens[0])); aIdx++)
        {
            for (iter = 0; iter < 3; iter++)
            {
                size_t ptLen  = ptLens[pIdx];
                size_t aadLen = aadLens[aIdx];

                SSF_ASSERT(RAND_bytes(key, sizeof(key)) == 1);
                SSF_ASSERT(RAND_bytes(nonce, sizeof(nonce)) == 1);
                if (aadLen > 0u) SSF_ASSERT(RAND_bytes(aad, (int)aadLen) == 1);
                if (ptLen > 0u)  SSF_ASSERT(RAND_bytes(pt, (int)ptLen) == 1);

                SSFChaCha20Poly1305Encrypt(ptLen ? pt : NULL, ptLen, nonce, sizeof(nonce),
                                           aadLen ? aad : NULL, aadLen, key, sizeof(key),
                                           tagSSF, sizeof(tagSSF), ctSSF, ptLen);
                _OSSLCCPEncrypt(ptLen ? pt : NULL, ptLen, nonce, sizeof(nonce),
                                aadLen ? aad : NULL, aadLen, key, tagOSSL, ctOSSL);
                if (ptLen > 0u) SSF_ASSERT(memcmp(ctSSF, ctOSSL, ptLen) == 0);
                SSF_ASSERT(memcmp(tagSSF, tagOSSL, SSF_CCP_TAG_SIZE) == 0);

                /* SSF decrypts OpenSSL's ciphertext. */
                SSF_ASSERT(SSFChaCha20Poly1305Decrypt(ctOSSL, ptLen, nonce, sizeof(nonce),
                                                     aadLen ? aad : NULL, aadLen,
                                                     key, sizeof(key),
                                                     tagOSSL, sizeof(tagOSSL),
                                                     back, ptLen) == true);
                if (ptLen > 0u) SSF_ASSERT(memcmp(back, pt, ptLen) == 0);

                /* OpenSSL decrypts SSF's ciphertext. */
                memset(back, 0, sizeof(back));
                SSF_ASSERT(_OSSLCCPDecrypt(ctSSF, ptLen, nonce, sizeof(nonce),
                                           aadLen ? aad : NULL, aadLen, key, tagSSF, back) == true);
                if (ptLen > 0u) SSF_ASSERT(memcmp(back, pt, ptLen) == 0);

                /* Tamper ct: both libs must reject. */
                if (ptLen > 0u)
                {
                    ctSSF[0] ^= 0x01u;
                    SSF_ASSERT(SSFChaCha20Poly1305Decrypt(ctSSF, ptLen, nonce, sizeof(nonce),
                                                         aadLen ? aad : NULL, aadLen,
                                                         key, sizeof(key),
                                                         tagSSF, sizeof(tagSSF),
                                                         back, ptLen) == false);
                    SSF_ASSERT(_OSSLCCPDecrypt(ctSSF, ptLen, nonce, sizeof(nonce),
                                               aadLen ? aad : NULL, aadLen,
                                               key, tagSSF, back) == false);
                    ctSSF[0] ^= 0x01u;
                }

                /* Tamper aad: both libs must reject. */
                if (aadLen > 0u)
                {
                    aad[0] ^= 0x01u;
                    SSF_ASSERT(SSFChaCha20Poly1305Decrypt(ctSSF, ptLen, nonce, sizeof(nonce),
                                                         aad, aadLen, key, sizeof(key),
                                                         tagSSF, sizeof(tagSSF),
                                                         back, ptLen) == false);
                    SSF_ASSERT(_OSSLCCPDecrypt(ctSSF, ptLen, nonce, sizeof(nonce),
                                               aad, aadLen, key, tagSSF, back) == false);
                    aad[0] ^= 0x01u;
                }

                /* Tamper tag: both libs must reject. */
                tagSSF[0] ^= 0x01u;
                SSF_ASSERT(SSFChaCha20Poly1305Decrypt(ctSSF, ptLen, nonce, sizeof(nonce),
                                                     aadLen ? aad : NULL, aadLen,
                                                     key, sizeof(key),
                                                     tagSSF, sizeof(tagSSF),
                                                     back, ptLen) == false);
                SSF_ASSERT(_OSSLCCPDecrypt(ctSSF, ptLen, nonce, sizeof(nonce),
                                           aadLen ? aad : NULL, aadLen,
                                           key, tagSSF, back) == false);
                tagSSF[0] ^= 0x01u;
            }
        }
    }
}
#endif /* SSF_CCP_OSSL_VERIFY */

/* --------------------------------------------------------------------------------------------- */
/* RFC 7539 Section 2.8.2 AEAD test vector                                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFChaCha20Poly1305UnitTest(void)
{
    /* RFC 7539 Section 2.8.2 */
    static const uint8_t key[] = {
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
        0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
    };
    static const uint8_t nonce[] = {
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };
    static const uint8_t aad[] = {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
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
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    static const uint8_t expected_tag[] = {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };

    uint8_t ct[sizeof(pt)];
    uint8_t tag[16];
    uint8_t dec[sizeof(pt)];
    bool ok;

    /* Test RFC 7539 Section 2.8.2 AEAD encrypt */
    SSFChaCha20Poly1305Encrypt(pt, sizeof(pt), nonce, sizeof(nonce),
                               aad, sizeof(aad), key, sizeof(key),
                               tag, sizeof(tag), ct, sizeof(ct));
    SSF_ASSERT(memcmp(ct, expected_ct, sizeof(expected_ct)) == 0);
    SSF_ASSERT(memcmp(tag, expected_tag, sizeof(expected_tag)) == 0);

    /* Test RFC 7539 Section 2.8.2 AEAD decrypt */
    ok = SSFChaCha20Poly1305Decrypt(ct, sizeof(ct), nonce, sizeof(nonce),
                                    aad, sizeof(aad), key, sizeof(key),
                                    tag, sizeof(tag), dec, sizeof(dec));
    SSF_ASSERT(ok);
    SSF_ASSERT(memcmp(dec, pt, sizeof(pt)) == 0);

    /* RFC 8439 §A.5 AEAD test vector. Distinct (key, nonce, AAD) from §2.8.2 with a 265-byte
     * plaintext crossing 4 full blocks plus a partial. Bidirectional: encrypt-of-pt must
     * produce expected ct + tag; decrypt-of-ct + tag must verify and recover pt. */
    {
        static const uint8_t a5Key[] = {
            0x1Cu, 0x92u, 0x40u, 0xA5u, 0xEBu, 0x55u, 0xD3u, 0x8Au,
            0xF3u, 0x33u, 0x88u, 0x86u, 0x04u, 0xF6u, 0xB5u, 0xF0u,
            0x47u, 0x39u, 0x17u, 0xC1u, 0x40u, 0x2Bu, 0x80u, 0x09u,
            0x9Du, 0xCAu, 0x5Cu, 0xBCu, 0x20u, 0x70u, 0x75u, 0xC0u
        };
        static const uint8_t a5Nonce[] = {
            0x00u, 0x00u, 0x00u, 0x00u, 0x01u, 0x02u, 0x03u, 0x04u,
            0x05u, 0x06u, 0x07u, 0x08u
        };
        static const uint8_t a5Aad[] = {
            0xF3u, 0x33u, 0x88u, 0x86u, 0x00u, 0x00u, 0x00u, 0x00u,
            0x00u, 0x00u, 0x4Eu, 0x91u
        };
        static const uint8_t a5Pt[] = {
            0x49u, 0x6Eu, 0x74u, 0x65u, 0x72u, 0x6Eu, 0x65u, 0x74u,
            0x2Du, 0x44u, 0x72u, 0x61u, 0x66u, 0x74u, 0x73u, 0x20u,
            0x61u, 0x72u, 0x65u, 0x20u, 0x64u, 0x72u, 0x61u, 0x66u,
            0x74u, 0x20u, 0x64u, 0x6Fu, 0x63u, 0x75u, 0x6Du, 0x65u,
            0x6Eu, 0x74u, 0x73u, 0x20u, 0x76u, 0x61u, 0x6Cu, 0x69u,
            0x64u, 0x20u, 0x66u, 0x6Fu, 0x72u, 0x20u, 0x61u, 0x20u,
            0x6Du, 0x61u, 0x78u, 0x69u, 0x6Du, 0x75u, 0x6Du, 0x20u,
            0x6Fu, 0x66u, 0x20u, 0x73u, 0x69u, 0x78u, 0x20u, 0x6Du,
            0x6Fu, 0x6Eu, 0x74u, 0x68u, 0x73u, 0x20u, 0x61u, 0x6Eu,
            0x64u, 0x20u, 0x6Du, 0x61u, 0x79u, 0x20u, 0x62u, 0x65u,
            0x20u, 0x75u, 0x70u, 0x64u, 0x61u, 0x74u, 0x65u, 0x64u,
            0x2Cu, 0x20u, 0x72u, 0x65u, 0x70u, 0x6Cu, 0x61u, 0x63u,
            0x65u, 0x64u, 0x2Cu, 0x20u, 0x6Fu, 0x72u, 0x20u, 0x6Fu,
            0x62u, 0x73u, 0x6Fu, 0x6Cu, 0x65u, 0x74u, 0x65u, 0x64u,
            0x20u, 0x62u, 0x79u, 0x20u, 0x6Fu, 0x74u, 0x68u, 0x65u,
            0x72u, 0x20u, 0x64u, 0x6Fu, 0x63u, 0x75u, 0x6Du, 0x65u,
            0x6Eu, 0x74u, 0x73u, 0x20u, 0x61u, 0x74u, 0x20u, 0x61u,
            0x6Eu, 0x79u, 0x20u, 0x74u, 0x69u, 0x6Du, 0x65u, 0x2Eu,
            0x20u, 0x49u, 0x74u, 0x20u, 0x69u, 0x73u, 0x20u, 0x69u,
            0x6Eu, 0x61u, 0x70u, 0x70u, 0x72u, 0x6Fu, 0x70u, 0x72u,
            0x69u, 0x61u, 0x74u, 0x65u, 0x20u, 0x74u, 0x6Fu, 0x20u,
            0x75u, 0x73u, 0x65u, 0x20u, 0x49u, 0x6Eu, 0x74u, 0x65u,
            0x72u, 0x6Eu, 0x65u, 0x74u, 0x2Du, 0x44u, 0x72u, 0x61u,
            0x66u, 0x74u, 0x73u, 0x20u, 0x61u, 0x73u, 0x20u, 0x72u,
            0x65u, 0x66u, 0x65u, 0x72u, 0x65u, 0x6Eu, 0x63u, 0x65u,
            0x20u, 0x6Du, 0x61u, 0x74u, 0x65u, 0x72u, 0x69u, 0x61u,
            0x6Cu, 0x20u, 0x6Fu, 0x72u, 0x20u, 0x74u, 0x6Fu, 0x20u,
            0x63u, 0x69u, 0x74u, 0x65u, 0x20u, 0x74u, 0x68u, 0x65u,
            0x6Du, 0x20u, 0x6Fu, 0x74u, 0x68u, 0x65u, 0x72u, 0x20u,
            0x74u, 0x68u, 0x61u, 0x6Eu, 0x20u, 0x61u, 0x73u, 0x20u,
            0x2Fu, 0xE2u, 0x80u, 0x9Cu, 0x77u, 0x6Fu, 0x72u, 0x6Bu,
            0x20u, 0x69u, 0x6Eu, 0x20u, 0x70u, 0x72u, 0x6Fu, 0x67u,
            0x72u, 0x65u, 0x73u, 0x73u, 0x2Eu, 0x2Fu, 0xE2u, 0x80u,
            0x9Du
        };
        static const uint8_t a5ExpectedCt[] = {
            0x64u, 0xA0u, 0x86u, 0x15u, 0x75u, 0x86u, 0x1Au, 0xF4u,
            0x60u, 0xF0u, 0x62u, 0xC7u, 0x9Bu, 0xE6u, 0x43u, 0xBDu,
            0x5Eu, 0x80u, 0x5Cu, 0xFDu, 0x34u, 0x5Cu, 0xF3u, 0x89u,
            0xF1u, 0x08u, 0x67u, 0x0Au, 0xC7u, 0x6Cu, 0x8Cu, 0xB2u,
            0x4Cu, 0x6Cu, 0xFCu, 0x18u, 0x75u, 0x5Du, 0x43u, 0xEEu,
            0xA0u, 0x9Eu, 0xE9u, 0x4Eu, 0x38u, 0x2Du, 0x26u, 0xB0u,
            0xBDu, 0xB7u, 0xB7u, 0x3Cu, 0x32u, 0x1Bu, 0x01u, 0x00u,
            0xD4u, 0xF0u, 0x3Bu, 0x7Fu, 0x35u, 0x58u, 0x94u, 0xCFu,
            0x33u, 0x2Fu, 0x83u, 0x0Eu, 0x71u, 0x0Bu, 0x97u, 0xCEu,
            0x98u, 0xC8u, 0xA8u, 0x4Au, 0xBDu, 0x0Bu, 0x94u, 0x81u,
            0x14u, 0xADu, 0x17u, 0x6Eu, 0x00u, 0x8Du, 0x33u, 0xBDu,
            0x60u, 0xF9u, 0x82u, 0xB1u, 0xFFu, 0x37u, 0xC8u, 0x55u,
            0x97u, 0x97u, 0xA0u, 0x6Eu, 0xF4u, 0xF0u, 0xEFu, 0x61u,
            0xC1u, 0x86u, 0x32u, 0x4Eu, 0x2Bu, 0x35u, 0x06u, 0x38u,
            0x36u, 0x06u, 0x90u, 0x7Bu, 0x6Au, 0x7Cu, 0x02u, 0xB0u,
            0xF9u, 0xF6u, 0x15u, 0x7Bu, 0x53u, 0xC8u, 0x67u, 0xE4u,
            0xB9u, 0x16u, 0x6Cu, 0x76u, 0x7Bu, 0x80u, 0x4Du, 0x46u,
            0xA5u, 0x9Bu, 0x52u, 0x16u, 0xCDu, 0xE7u, 0xA4u, 0xE9u,
            0x90u, 0x40u, 0xC5u, 0xA4u, 0x04u, 0x33u, 0x22u, 0x5Eu,
            0xE2u, 0x82u, 0xA1u, 0xB0u, 0xA0u, 0x6Cu, 0x52u, 0x3Eu,
            0xAFu, 0x45u, 0x34u, 0xD7u, 0xF8u, 0x3Fu, 0xA1u, 0x15u,
            0x5Bu, 0x00u, 0x47u, 0x71u, 0x8Cu, 0xBCu, 0x54u, 0x6Au,
            0x0Du, 0x07u, 0x2Bu, 0x04u, 0xB3u, 0x56u, 0x4Eu, 0xEAu,
            0x1Bu, 0x42u, 0x22u, 0x73u, 0xF5u, 0x48u, 0x27u, 0x1Au,
            0x0Bu, 0xB2u, 0x31u, 0x60u, 0x53u, 0xFAu, 0x76u, 0x99u,
            0x19u, 0x55u, 0xEBu, 0xD6u, 0x31u, 0x59u, 0x43u, 0x4Eu,
            0xCEu, 0xBBu, 0x4Eu, 0x46u, 0x6Du, 0xAEu, 0x5Au, 0x10u,
            0x73u, 0xA6u, 0x72u, 0x76u, 0x27u, 0x09u, 0x7Au, 0x10u,
            0x49u, 0xE6u, 0x17u, 0xD9u, 0x1Du, 0x36u, 0x10u, 0x94u,
            0xFAu, 0x68u, 0xF0u, 0xFFu, 0x77u, 0x98u, 0x71u, 0x30u,
            0x30u, 0x5Bu, 0xEAu, 0xBAu, 0x2Eu, 0xDAu, 0x04u, 0xDFu,
            0x99u, 0x7Bu, 0x71u, 0x4Du, 0x6Cu, 0x6Fu, 0x2Cu, 0x29u,
            0xA6u, 0xADu, 0x5Cu, 0xB4u, 0x02u, 0x2Bu, 0x02u, 0x70u,
            0x9Bu
        };
        static const uint8_t a5ExpectedTag[] = {
            0xEEu, 0xADu, 0x9Du, 0x67u, 0x89u, 0x0Cu, 0xBBu, 0x22u,
            0x39u, 0x23u, 0x36u, 0xFEu, 0xA1u, 0x85u, 0x1Fu, 0x38u
        };
        uint8_t a5Ct[265];
        uint8_t a5Tag[16];
        uint8_t a5Pt2[265];
        bool a5Ok;

        SSFChaCha20Poly1305Encrypt(a5Pt, sizeof(a5Pt), a5Nonce, sizeof(a5Nonce),
                                   a5Aad, sizeof(a5Aad), a5Key, sizeof(a5Key),
                                   a5Tag, sizeof(a5Tag), a5Ct, sizeof(a5Ct));
        SSF_ASSERT(memcmp(a5Ct, a5ExpectedCt, sizeof(a5ExpectedCt)) == 0);
        SSF_ASSERT(memcmp(a5Tag, a5ExpectedTag, sizeof(a5ExpectedTag)) == 0);

        a5Ok = SSFChaCha20Poly1305Decrypt(a5ExpectedCt, sizeof(a5ExpectedCt),
                                          a5Nonce, sizeof(a5Nonce),
                                          a5Aad, sizeof(a5Aad),
                                          a5Key, sizeof(a5Key),
                                          a5ExpectedTag, sizeof(a5ExpectedTag),
                                          a5Pt2, sizeof(a5Pt2));
        SSF_ASSERT(a5Ok == true);
        SSF_ASSERT(memcmp(a5Pt2, a5Pt, sizeof(a5Pt)) == 0);
    }

    /* Wycheproof v1 chacha20_poly1305_test.json — selected representative vectors. The 300-
     * vector set is too large to embed wholesale (and the OpenSSL fuzz on host already covers
     * the bulk of the valid-input combinatorics); these four vectors specifically pin down
     * patterns the fuzz won't generate by chance. */

    /* Wycheproof tcId 5 (valid): 1-byte msg, 8-byte AAD. Single-byte body exercises the
     * partial-block keystream truncation in the AEAD wrapper. */
    {
        static const uint8_t wpKey[] = {
            0x46u, 0xF0u, 0x25u, 0x49u, 0x65u, 0xF7u, 0x69u, 0xD5u,
            0x2Bu, 0xDBu, 0x4Au, 0x70u, 0xB4u, 0x43u, 0x19u, 0x9Fu,
            0x8Eu, 0xF2u, 0x07u, 0x52u, 0x0Du, 0x12u, 0x20u, 0xC5u,
            0x5Eu, 0x4Bu, 0x70u, 0xF0u, 0xFDu, 0xA6u, 0x20u, 0xEEu
        };
        static const uint8_t wpIv[] = {
            0xABu, 0x0Du, 0xCAu, 0x71u, 0x6Eu, 0xE0u, 0x51u, 0xD2u,
            0x78u, 0x2Fu, 0x44u, 0x03u
        };
        static const uint8_t wpAad[] = {
            0x91u, 0xCAu, 0x6Cu, 0x59u, 0x2Cu, 0xBCu, 0xCAu, 0x53u
        };
        static const uint8_t wpMsg[]      = { 0x51u };
        static const uint8_t wpExpectCt[] = { 0xC4u };
        static const uint8_t wpExpectTag[] = {
            0x16u, 0x83u, 0x10u, 0xCAu, 0x45u, 0xB1u, 0xF7u, 0xC6u,
            0x6Cu, 0xADu, 0x4Eu, 0x99u, 0xE4u, 0x3Fu, 0x72u, 0xB9u
        };
        uint8_t wpCt[1];
        uint8_t wpTag[16];
        uint8_t wpDec[1];

        SSFChaCha20Poly1305Encrypt(wpMsg, sizeof(wpMsg), wpIv, sizeof(wpIv),
                                   wpAad, sizeof(wpAad), wpKey, sizeof(wpKey),
                                   wpTag, sizeof(wpTag), wpCt, sizeof(wpCt));
        SSF_ASSERT(memcmp(wpCt, wpExpectCt, sizeof(wpExpectCt)) == 0);
        SSF_ASSERT(memcmp(wpTag, wpExpectTag, sizeof(wpExpectTag)) == 0);
        SSF_ASSERT(SSFChaCha20Poly1305Decrypt(wpExpectCt, sizeof(wpExpectCt),
                                              wpIv, sizeof(wpIv),
                                              wpAad, sizeof(wpAad),
                                              wpKey, sizeof(wpKey),
                                              wpExpectTag, sizeof(wpExpectTag),
                                              wpDec, sizeof(wpDec)) == true);
        SSF_ASSERT(memcmp(wpDec, wpMsg, sizeof(wpMsg)) == 0);
    }

    /* Wycheproof tcId 4 (valid): 1-byte msg, ZERO-length AAD. Auth-only path with empty AAD
     * pad16 — should produce an entirely-empty padded-AAD region in the Poly1305 tag input. */
    {
        static const uint8_t wpKey[] = {
            0xCCu, 0x56u, 0xB6u, 0x80u, 0x55u, 0x2Eu, 0xB7u, 0x50u,
            0x08u, 0xF5u, 0x48u, 0x4Bu, 0x4Cu, 0xB8u, 0x03u, 0xFAu,
            0x50u, 0x63u, 0xEBu, 0xD6u, 0xEAu, 0xB9u, 0x1Fu, 0x6Au,
            0xB6u, 0xAEu, 0xF4u, 0x91u, 0x6Au, 0x76u, 0x62u, 0x73u
        };
        static const uint8_t wpIv[] = {
            0x99u, 0xE2u, 0x3Eu, 0xC4u, 0x89u, 0x85u, 0xBCu, 0xCDu,
            0xEEu, 0xABu, 0x60u, 0xF1u
        };
        static const uint8_t wpMsg[]      = { 0x2Au };
        static const uint8_t wpExpectCt[] = { 0x3Au };
        static const uint8_t wpExpectTag[] = {
            0xCAu, 0xC2u, 0x7Du, 0xECu, 0x09u, 0x68u, 0x80u, 0x1Eu,
            0x9Fu, 0x6Eu, 0xDEu, 0xD6u, 0x9Du, 0x80u, 0x75u, 0x22u
        };
        uint8_t wpCt[1];
        uint8_t wpTag[16];

        SSFChaCha20Poly1305Encrypt(wpMsg, sizeof(wpMsg), wpIv, sizeof(wpIv),
                                   NULL, 0u, wpKey, sizeof(wpKey),
                                   wpTag, sizeof(wpTag), wpCt, sizeof(wpCt));
        SSF_ASSERT(memcmp(wpCt, wpExpectCt, sizeof(wpExpectCt)) == 0);
        SSF_ASSERT(memcmp(wpTag, wpExpectTag, sizeof(wpExpectTag)) == 0);
    }

    /* Wycheproof tcId 72 (valid): 64-byte msg (one full block), zero-length AAD, distinct
     * key/nonce. Multi-block-boundary case beyond what RFC §2.8.2 (114B) and §A.5 (265B)
     * exercise — specifically tests the exactly-one-full-block boundary. */
    {
        static const uint8_t wpKey[] = {
            0x5Bu, 0x1Du, 0x10u, 0x35u, 0xC0u, 0xB1u, 0x7Eu, 0xE0u,
            0xB0u, 0x44u, 0x47u, 0x67u, 0xF8u, 0x0Au, 0x25u, 0xB8u,
            0xC1u, 0xB7u, 0x41u, 0xF4u, 0xB5u, 0x0Au, 0x4Du, 0x30u,
            0x52u, 0x22u, 0x6Bu, 0xAAu, 0x1Cu, 0x6Fu, 0xB7u, 0x01u
        };
        static const uint8_t wpIv[] = {
            0xD6u, 0x10u, 0x40u, 0xA3u, 0x13u, 0xEDu, 0x49u, 0x28u,
            0x23u, 0xCCu, 0x06u, 0x5Bu
        };
        static const uint8_t wpMsg[] = {
            0xD0u, 0x96u, 0x80u, 0x31u, 0x81u, 0xBEu, 0xEFu, 0x9Eu,
            0x00u, 0x8Fu, 0xF8u, 0x5Du, 0x5Du, 0xDCu, 0x38u, 0xDDu,
            0xACu, 0xF0u, 0xF0u, 0x9Eu, 0xE5u, 0xF7u, 0xE0u, 0x7Fu,
            0x1Eu, 0x40u, 0x79u, 0xCBu, 0x64u, 0xD0u, 0xDCu, 0x8Fu,
            0x5Eu, 0x67u, 0x11u, 0xCDu, 0x49u, 0x21u, 0xA7u, 0x88u,
            0x7Du, 0xE7u, 0x6Eu, 0x26u, 0x78u, 0xFDu, 0xC6u, 0x76u,
            0x18u, 0xF1u, 0x18u, 0x55u, 0x86u, 0xBFu, 0xEAu, 0x9Du,
            0x4Cu, 0x68u, 0x5Du, 0x50u, 0xE4u, 0xBBu, 0x9Au, 0x82u
        };
        static const uint8_t wpExpectCt[] = {
            0x9Au, 0x4Eu, 0xF2u, 0x2Bu, 0x18u, 0x16u, 0x77u, 0xB5u,
            0x75u, 0x5Cu, 0x08u, 0xF7u, 0x47u, 0xC0u, 0xF8u, 0xD8u,
            0xE8u, 0xD4u, 0xC1u, 0x8Au, 0x9Cu, 0xC2u, 0x40u, 0x5Cu,
            0x12u, 0xBBu, 0x51u, 0xBBu, 0x18u, 0x72u, 0xC8u, 0xE8u,
            0xB8u, 0x77u, 0x67u, 0x8Bu, 0xECu, 0x44u, 0x2Cu, 0xFCu,
            0xBBu, 0x0Fu, 0xF4u, 0x64u, 0xA6u, 0x4Bu, 0x74u, 0x33u,
            0x2Cu, 0xF0u, 0x72u, 0x89u, 0x8Cu, 0x7Eu, 0x0Eu, 0xDDu,
            0xF6u, 0x23u, 0x2Eu, 0xA6u, 0xE2u, 0x7Eu, 0xFEu, 0x50u
        };
        static const uint8_t wpExpectTag[] = {
            0x9Fu, 0xF3u, 0x42u, 0x7Au, 0x0Fu, 0x32u, 0xFAu, 0x56u,
            0x6Du, 0x9Cu, 0xA0u, 0xA7u, 0x8Au, 0xEFu, 0xC0u, 0x13u
        };
        uint8_t wpCt[64];
        uint8_t wpTag[16];

        SSFChaCha20Poly1305Encrypt(wpMsg, sizeof(wpMsg), wpIv, sizeof(wpIv),
                                   NULL, 0u, wpKey, sizeof(wpKey),
                                   wpTag, sizeof(wpTag), wpCt, sizeof(wpCt));
        SSF_ASSERT(memcmp(wpCt, wpExpectCt, sizeof(wpExpectCt)) == 0);
        SSF_ASSERT(memcmp(wpTag, wpExpectTag, sizeof(wpExpectTag)) == 0);
    }

    /* Wycheproof tcId 146 (invalid): empty msg, 3-byte AAD, single-bit flip in tag. Auth-only
     * mode with a tampered tag — Decrypt MUST return false. The original valid tag would have
     * been f4..., the supplied tampered tag is f5... (low bit of byte 0 flipped). */
    {
        static const uint8_t wpKey[] = {
            0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
            0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu,
            0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u,
            0x38u, 0x39u, 0x3Au, 0x3Bu, 0x3Cu, 0x3Du, 0x3Eu, 0x3Fu
        };
        static const uint8_t wpIv[] = {
            0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu
        };
        static const uint8_t wpAad[]        = { 0x00u, 0x01u, 0x02u };
        static const uint8_t wpTamperedTag[] = {
            0xF5u, 0x40u, 0x9Bu, 0xB7u, 0x29u, 0x03u, 0x9Du, 0x08u,
            0x14u, 0xACu, 0x51u, 0x40u, 0x54u, 0x32u, 0x3Fu, 0x44u
        };

        /* Empty ct — pass NULL with ctLen = 0. Tampered tag must reject. */
        SSF_ASSERT(SSFChaCha20Poly1305Decrypt(NULL, 0u,
                                              wpIv, sizeof(wpIv),
                                              wpAad, sizeof(wpAad),
                                              wpKey, sizeof(wpKey),
                                              wpTamperedTag, sizeof(wpTamperedTag),
                                              NULL, 0u) == false);
    }

    /* Tag-buffer write boundary: oversized tag buffer must leave bytes 16..N-1 untouched.
     * Pins down the .md guarantee "exactly 16 bytes are written". */
    {
        static const uint8_t boundaryKey[SSF_CCP_KEY_SIZE] = {0};
        static const uint8_t boundaryNonce[SSF_CCP_NONCE_SIZE] = {0};
        static const uint8_t boundaryPt[16] = {0};
        uint8_t boundaryCt[16];
        uint8_t oversizedTag[32];
        size_t i;

        memset(oversizedTag, 0xCCu, sizeof(oversizedTag));
        SSFChaCha20Poly1305Encrypt(boundaryPt, sizeof(boundaryPt),
                                   boundaryNonce, sizeof(boundaryNonce),
                                   NULL, 0u,
                                   boundaryKey, sizeof(boundaryKey),
                                   oversizedTag, sizeof(oversizedTag),
                                   boundaryCt, sizeof(boundaryCt));
        for (i = 16u; i < sizeof(oversizedTag); i++) SSF_ASSERT(oversizedTag[i] == 0xCCu);
    }

    /* Test wrong tag returns false */
    {
        uint8_t badTag[16];
        memcpy(badTag, tag, sizeof(badTag));
        badTag[0] ^= 0x01;
        ok = SSFChaCha20Poly1305Decrypt(ct, sizeof(ct), nonce, sizeof(nonce),
                                        aad, sizeof(aad), key, sizeof(key),
                                        badTag, sizeof(badTag), dec, sizeof(dec));
        SSF_ASSERT(!ok);
    }

    /* Test encrypt/decrypt round-trip with no AAD */
    {
        uint8_t rtCt[sizeof(pt)];
        uint8_t rtTag[16];
        uint8_t rtDec[sizeof(pt)];

        SSFChaCha20Poly1305Encrypt(pt, sizeof(pt), nonce, sizeof(nonce),
                                   NULL, 0, key, sizeof(key),
                                   rtTag, sizeof(rtTag), rtCt, sizeof(rtCt));
        ok = SSFChaCha20Poly1305Decrypt(rtCt, sizeof(rtCt), nonce, sizeof(nonce),
                                        NULL, 0, key, sizeof(key),
                                        rtTag, sizeof(rtTag), rtDec, sizeof(rtDec));
        SSF_ASSERT(ok);
        SSF_ASSERT(memcmp(rtDec, pt, sizeof(pt)) == 0);
    }

    /* Test empty plaintext (auth-only mode) */
    {
        uint8_t authOnlyTag[16];
        uint8_t authOnlyTag2[16];

        SSFChaCha20Poly1305Encrypt(NULL, 0, nonce, sizeof(nonce),
                                   aad, sizeof(aad), key, sizeof(key),
                                   authOnlyTag, sizeof(authOnlyTag), NULL, 0);
        ok = SSFChaCha20Poly1305Decrypt(NULL, 0, nonce, sizeof(nonce),
                                        aad, sizeof(aad), key, sizeof(key),
                                        authOnlyTag, sizeof(authOnlyTag), NULL, 0);
        SSF_ASSERT(ok);

        /* Verify wrong tag fails for auth-only mode too */
        memset(authOnlyTag2, 0, sizeof(authOnlyTag2));
        ok = SSFChaCha20Poly1305Decrypt(NULL, 0, nonce, sizeof(nonce),
                                        aad, sizeof(aad), key, sizeof(key),
                                        authOnlyTag2, sizeof(authOnlyTag2), NULL, 0);
        SSF_ASSERT(!ok);
    }

    /* Defense-in-depth regression: the failure-then-success sequence below confirms that a
     * Decrypt that returns false on a wrong tag does not leave the operation in a state that
     * breaks subsequent calls. The internal computedTag scrub on the failure path is not
     * directly observable from C, but this round-trip pattern would catch any state-leak
     * regression that affects the next decrypt. */
    {
        uint8_t scratchKey[SSF_CCP_KEY_SIZE];
        uint8_t scratchNonce[SSF_CCP_NONCE_SIZE];
        uint8_t scratchPt[64];
        uint8_t scratchCt[64];
        uint8_t scratchTag[SSF_CCP_TAG_SIZE];
        uint8_t scratchBadTag[SSF_CCP_TAG_SIZE];
        uint8_t recovered[64];
        size_t i;

        for (i = 0; i < sizeof(scratchKey);   i++) scratchKey[i]   = (uint8_t)(i ^ 0x33u);
        for (i = 0; i < sizeof(scratchNonce); i++) scratchNonce[i] = (uint8_t)(i ^ 0x77u);
        for (i = 0; i < sizeof(scratchPt);    i++) scratchPt[i]    = (uint8_t)(i ^ 0xA5u);

        SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                   scratchNonce, sizeof(scratchNonce),
                                   NULL, 0u,
                                   scratchKey, sizeof(scratchKey),
                                   scratchTag, sizeof(scratchTag),
                                   scratchCt, sizeof(scratchCt));

        memcpy(scratchBadTag, scratchTag, sizeof(scratchBadTag));
        scratchBadTag[0] ^= 0x01u;
        ok = SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                        scratchNonce, sizeof(scratchNonce),
                                        NULL, 0u,
                                        scratchKey, sizeof(scratchKey),
                                        scratchBadTag, sizeof(scratchBadTag),
                                        recovered, sizeof(recovered));
        SSF_ASSERT(ok == false);

        /* Same buffers, correct tag — must succeed with the original plaintext. */
        ok = SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                        scratchNonce, sizeof(scratchNonce),
                                        NULL, 0u,
                                        scratchKey, sizeof(scratchKey),
                                        scratchTag, sizeof(scratchTag),
                                        recovered, sizeof(recovered));
        SSF_ASSERT(ok == true);
        SSF_ASSERT(memcmp(recovered, scratchPt, sizeof(scratchPt)) == 0);
    }

    /* SSFChaCha20Poly1305Encrypt: DBC coverage. Every SSF_REQUIRE at the AEAD entry is
     * exercised with at least one boundary or NULL-pointer violation. The 512 MiB ptLen test
     * passes a matching ctSize so the size-bound check fires last; nothing dereferences pt or
     * ct so the absurd length never causes any actual allocation. */
    {
        static const uint8_t scratchKey[SSF_CCP_KEY_SIZE] = {0};
        static const uint8_t scratchNonce[SSF_CCP_NONCE_SIZE] = {0};
        static const uint8_t scratchPt[16] = {0};
        uint8_t scratchTag[SSF_CCP_TAG_SIZE];
        uint8_t scratchCt[16];

        /* iv NULL */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   NULL, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        /* key NULL */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   NULL, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        /* tag NULL */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   NULL, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        /* keyLen wrong */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, 0u,
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, 31u,
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, 33u,
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        /* ivLen wrong */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, 0u,
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, 11u,
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, 13u,
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        /* tagSize too small */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, 0u,
                                                   scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, 15u,
                                                   scratchCt, sizeof(scratchCt)));
        /* ptLen > ctSize */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchPt) - 1u));
        /* ptLen ≥ 512 MiB */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, 512u * 1024u * 1024u,
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, 512u * 1024u * 1024u));
        /* pt NULL with ptLen > 0 */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(NULL, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));
        /* ct NULL with ptLen > 0 */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   NULL, sizeof(scratchCt)));
        /* AAD NULL with authLen > 0 (already covered above; repeated here for completeness
         * within this DBC block). */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 5u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchCt, sizeof(scratchCt)));

        /* Permitted edge: ptLen == 0 with NULL pt and ct must NOT assert. */
        SSFChaCha20Poly1305Encrypt(NULL, 0u,
                                   scratchNonce, sizeof(scratchNonce),
                                   NULL, 0u,
                                   scratchKey, sizeof(scratchKey),
                                   scratchTag, sizeof(scratchTag),
                                   NULL, 0u);
    }

    /* SSFChaCha20Poly1305Decrypt: DBC coverage. Mirror of the encrypt block, plus the
     * tagLen-must-equal-16 check (decrypt rejects truncated tags rather than verifying a
     * shorter prefix). The pt/ct NULL-with-len>0 cases assert via Poly1305Update inside
     * tag computation since pt/ct's explicit AEAD-level check is gated on a successful
     * tag verify which never happens on these all-zero-key inputs. */
    {
        static const uint8_t scratchKey[SSF_CCP_KEY_SIZE] = {0};
        static const uint8_t scratchNonce[SSF_CCP_NONCE_SIZE] = {0};
        static const uint8_t scratchTag[SSF_CCP_TAG_SIZE] = {0};
        static const uint8_t scratchCt[16] = {0};
        uint8_t scratchPt[16];

        /* iv NULL */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   NULL, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        /* key NULL */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   NULL, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        /* tag NULL */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   NULL, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        /* keyLen wrong */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, 0u,
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, 31u,
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, 33u,
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        /* ivLen wrong */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, 0u,
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, 11u,
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, 13u,
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));
        /* tagLen wrong (decrypt rejects anything other than exactly 16) */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, 0u,
                                                   scratchPt, sizeof(scratchPt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, 15u,
                                                   scratchPt, sizeof(scratchPt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, 17u,
                                                   scratchPt, sizeof(scratchPt)));
        /* ctLen > ptSize */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchCt) - 1u));
        /* ctLen ≥ 512 MiB */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, 512u * 1024u * 1024u,
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 0u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, 512u * 1024u * 1024u));
        /* AAD NULL with authLen > 0 */
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 5u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchPt, sizeof(scratchPt)));

        /* Permitted edge: ctLen == 0 with NULL ct and pt — auth-only mode with NULL buffers
         * and a zero-AAD construction. The all-zero tag matches the all-zero-key auth-only
         * computation only by accident, so we don't assert on the return value. The point
         * is that the call must not assert. */
        (void)SSFChaCha20Poly1305Decrypt(NULL, 0u,
                                         scratchNonce, sizeof(scratchNonce),
                                         NULL, 0u,
                                         scratchKey, sizeof(scratchKey),
                                         scratchTag, sizeof(scratchTag),
                                         NULL, 0u);
    }

#if SSF_CCP_OSSL_VERIFY == 1
    _VerifyCCPAgainstOpenSSLRandom();
#endif
}

#endif /* SSF_CONFIG_CCP_UNIT_TEST */
