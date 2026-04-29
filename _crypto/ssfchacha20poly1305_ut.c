/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfchacha20poly1305_ut.c                                                                      */
/* Provides ChaCha20-Poly1305 AEAD unit test (RFC 7539).                                         */
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
        bool ok;

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

    /* AAD-pointer contract regression. NULL `auth` with `authLen > 0` must assert at the
     * AEAD entry, both for encrypt and for decrypt. The test passes regardless of which
     * SSF_REQUIRE catches it (the AEAD-level check or the deeper Poly1305Update), so it
     * serves as documentation + regression protection if either layer is later refactored. */
    {
        static const uint8_t scratchKey[SSF_CCP_KEY_SIZE] = {0};
        static const uint8_t scratchNonce[SSF_CCP_NONCE_SIZE] = {0};
        static const uint8_t scratchTag[SSF_CCP_TAG_SIZE] = {0};
        static const uint8_t scratchPt[16] = {0};
        uint8_t scratchCt[16];
        uint8_t scratchOutTag[SSF_CCP_TAG_SIZE];
        uint8_t scratchOutPt[16];

        SSF_ASSERT_TEST(SSFChaCha20Poly1305Encrypt(scratchPt, sizeof(scratchPt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 5u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchOutTag, sizeof(scratchOutTag),
                                                   scratchCt, sizeof(scratchCt)));
        SSF_ASSERT_TEST(SSFChaCha20Poly1305Decrypt(scratchCt, sizeof(scratchCt),
                                                   scratchNonce, sizeof(scratchNonce),
                                                   NULL, 5u,
                                                   scratchKey, sizeof(scratchKey),
                                                   scratchTag, sizeof(scratchTag),
                                                   scratchOutPt, sizeof(scratchOutPt)));
    }

#if SSF_CCP_OSSL_VERIFY == 1
    _VerifyCCPAgainstOpenSSLRandom();
#endif
}

#endif /* SSF_CONFIG_CCP_UNIT_TEST */
