/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfaesccm_ut.c                                                                                */
/* Provides unit tests for the ssfaesccm AES-CCM module.                                         */
/* Test vectors from RFC 3610 and NIST SP 800-38C.                                               */
/*                                                                                               */
/* BSD-3-Clause License                                                                          */
/* Copyright 2020 Supurloop Software LLC                                                         */
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
#include "ssfassert.h"
#include "ssfaesccm.h"

/* Cross-validate AES-CCM against OpenSSL on host builds where libcrypto is linked. Same gating */
/* pattern as ssfaesctr_ut.c. When disabled (cross builds with -DSSF_CONFIG_HAVE_OPENSSL=0) the  */
/* NIST SP 800-38C KATs above are the load-bearing correctness coverage.                         */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_AESCCM_UNIT_TEST == 1)
#define SSF_AESCCM_OSSL_VERIFY 1
#else
#define SSF_AESCCM_OSSL_VERIFY 0
#endif

#if SSF_AESCCM_OSSL_VERIFY == 1
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#endif

#if SSF_CONFIG_AESCCM_UNIT_TEST == 1

#if SSF_AESCCM_OSSL_VERIFY == 1

/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers.                                                                  */
/* --------------------------------------------------------------------------------------------- */

/* Map keyLen to the OpenSSL AES-CCM EVP_CIPHER. */
static const EVP_CIPHER *_OSSLAESCCMCipher(size_t keyLen)
{
    switch (keyLen)
    {
        case 16u: return EVP_aes_128_ccm();
        case 24u: return EVP_aes_192_ccm();
        case 32u: return EVP_aes_256_ccm();
        default: SSF_ASSERT(0); return NULL;
    }
}

/* Compute AES-CCM via OpenSSL's EVP path. CCM requires the total plaintext length to be set */
/* before AAD is fed in (NULL-update with len = ptLen) and produces both ciphertext and tag. */
static void _OSSLAESCCMEncrypt(const uint8_t *pt, size_t ptLen,
                               const uint8_t *nonce, size_t nonceLen,
                               const uint8_t *aad, size_t aadLen,
                               const uint8_t *key, size_t keyLen,
                               uint8_t *tag, size_t tagLen,
                               uint8_t *ct)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outL = 0;
    int outL2 = 0;

    uint8_t dummy = 0u;
    const uint8_t *ptIn = (ptLen > 0u) ? pt : &dummy;
    uint8_t *ctOut = (ptLen > 0u) ? ct : &dummy;

    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(EVP_EncryptInit_ex(ctx, _OSSLAESCCMCipher(keyLen), NULL, NULL, NULL) == 1);
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonceLen, NULL) == 1);
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tagLen, NULL) == 1);
    SSF_ASSERT(EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1);
    /* CCM requires the total plaintext length to be set up-front so B0 is formatted with the */
    /* correct length encoding. The "only when AAD is used" wording in OpenSSL docs is        */
    /* misleading; the data-feed update below depends on the announce having happened.        */
    SSF_ASSERT(EVP_EncryptUpdate(ctx, NULL, &outL, NULL, (int)ptLen) == 1);
    if (aadLen > 0u)
    {
        SSF_ASSERT(EVP_EncryptUpdate(ctx, NULL, &outL, aad, (int)aadLen) == 1);
    }
    /* Always call the data-feed update — even at ptLen == 0 — so the CBC-MAC tag is         */
    /* finalized. NULL pointers would be re-interpreted as another AAD update; use a dummy.  */
    SSF_ASSERT(EVP_EncryptUpdate(ctx, ctOut, &outL, ptIn, (int)ptLen) == 1);
    SSF_ASSERT((size_t)outL == ptLen);
    SSF_ASSERT(EVP_EncryptFinal_ex(ctx, ctOut + outL, &outL2) == 1);
    SSF_ASSERT(outL2 == 0);
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, (int)tagLen, tag) == 1);
    EVP_CIPHER_CTX_free(ctx);
}

/* Decrypt + verify via OpenSSL. Returns true iff the tag verified. CCM verifies the tag inside */
/* DecryptUpdate (not Final), so its return value is the auth result.                            */
static bool _OSSLAESCCMDecrypt(const uint8_t *ct, size_t ctLen,
                               const uint8_t *nonce, size_t nonceLen,
                               const uint8_t *aad, size_t aadLen,
                               const uint8_t *key, size_t keyLen,
                               const uint8_t *tag, size_t tagLen,
                               uint8_t *pt)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outL = 0;
    int rc = 0;
    bool ok;

    uint8_t dummy = 0u;
    const uint8_t *ctIn = (ctLen > 0u) ? ct : &dummy;
    uint8_t *ptOut = (ctLen > 0u) ? pt : &dummy;

    SSF_ASSERT(ctx != NULL);
    SSF_ASSERT(EVP_DecryptInit_ex(ctx, _OSSLAESCCMCipher(keyLen), NULL, NULL, NULL) == 1);
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonceLen, NULL) == 1);
    SSF_ASSERT(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)tagLen, (void *)tag) == 1);
    SSF_ASSERT(EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1);
    /* Mirror the encrypt path: always announce length, conditional AAD, always feed data. */
    SSF_ASSERT(EVP_DecryptUpdate(ctx, NULL, &outL, NULL, (int)ctLen) == 1);
    if (aadLen > 0u)
    {
        SSF_ASSERT(EVP_DecryptUpdate(ctx, NULL, &outL, aad, (int)aadLen) == 1);
    }
    /* CCM verifies the tag inside DecryptUpdate, so its return value is the auth result. */
    rc = EVP_DecryptUpdate(ctx, ptOut, &outL, ctIn, (int)ctLen);
    ok = (rc == 1);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz across (keyLen × nonceLen × tagLen × ptLen × aadLen). Each cell:                  */
/*   - draws fresh random key/nonce/aad/pt                                                       */
/*   - encrypts via SSF, encrypts via OpenSSL, asserts byte-equal ct AND tag                     */
/*   - decrypts SSF ciphertext via OpenSSL and OpenSSL ciphertext via SSF, both must succeed     */
/*   - tampers ct[0] / aad[0] / tag[0] (when each is non-empty) and asserts BOTH SSF and OpenSSL */
/*     reject the tampered input                                                                  */
/* This catches divergence in CBC-MAC tag formation, CTR keystream, B0/A_i formatting, AAD       */
/* length encoding, and partial-block padding that wouldn't surface in the fixed NIST KATs.       */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyAESCCMAgainstOpenSSLRandom(void)
{
    static const size_t keyLens[]   = {16u, 24u, 32u};
    static const size_t nonceLens[] = {7u, 8u, 11u, 12u, 13u};
    static const size_t tagLens[]   = {4u, 6u, 8u, 10u, 12u, 14u, 16u};
    static const size_t ptLens[]    = {0u, 1u, 15u, 16u, 17u, 31u, 32u, 33u, 64u, 100u, 256u};
    static const size_t aadLens[]   = {0u, 1u, 15u, 16u, 17u, 64u, 100u};
    uint8_t key[32];
    uint8_t nonce[13];
    uint8_t aad[100];
    uint8_t pt[256];
    uint8_t ctSSF[256];
    uint8_t ctOSSL[256];
    uint8_t tagSSF[16];
    uint8_t tagOSSL[16];
    uint8_t back[256];
    size_t kIdx;
    size_t nIdx;
    size_t tIdx;
    size_t pIdx;
    size_t aIdx;

    for (kIdx = 0; kIdx < (sizeof(keyLens) / sizeof(keyLens[0])); kIdx++)
    {
        for (nIdx = 0; nIdx < (sizeof(nonceLens) / sizeof(nonceLens[0])); nIdx++)
        {
            for (tIdx = 0; tIdx < (sizeof(tagLens) / sizeof(tagLens[0])); tIdx++)
            {
                for (pIdx = 0; pIdx < (sizeof(ptLens) / sizeof(ptLens[0])); pIdx++)
                {
                    for (aIdx = 0; aIdx < (sizeof(aadLens) / sizeof(aadLens[0])); aIdx++)
                    {
                        size_t keyLen   = keyLens[kIdx];
                        size_t nonceLen = nonceLens[nIdx];
                        size_t tagLen   = tagLens[tIdx];
                        size_t ptLen    = ptLens[pIdx];
                        size_t aadLen   = aadLens[aIdx];

                        SSF_ASSERT(RAND_bytes(key, (int)keyLen) == 1);
                        SSF_ASSERT(RAND_bytes(nonce, (int)nonceLen) == 1);
                        if (aadLen > 0u) SSF_ASSERT(RAND_bytes(aad, (int)aadLen) == 1);
                        if (ptLen > 0u)  SSF_ASSERT(RAND_bytes(pt, (int)ptLen) == 1);

                        /* Encrypt: SSF and OpenSSL must produce identical ciphertext + tag. */
                        SSFAESCCMEncrypt(ptLen ? pt : NULL, ptLen, nonce, nonceLen,
                                         aadLen ? aad : NULL, aadLen, key, keyLen,
                                         tagSSF, tagLen, ctSSF, ptLen);
                        _OSSLAESCCMEncrypt(ptLen ? pt : NULL, ptLen, nonce, nonceLen,
                                           aadLen ? aad : NULL, aadLen, key, keyLen,
                                           tagOSSL, tagLen, ctOSSL);
                        if (ptLen > 0u) SSF_ASSERT(memcmp(ctSSF, ctOSSL, ptLen) == 0);
                        SSF_ASSERT(memcmp(tagSSF, tagOSSL, tagLen) == 0);

                        /* SSF decrypts OpenSSL's ciphertext successfully. */
                        SSF_ASSERT(SSFAESCCMDecrypt(ctOSSL, ptLen, nonce, nonceLen,
                                                    aadLen ? aad : NULL, aadLen, key, keyLen,
                                                    tagOSSL, tagLen, back, ptLen) == true);
                        if (ptLen > 0u) SSF_ASSERT(memcmp(back, pt, ptLen) == 0);

                        /* OpenSSL decrypts SSF's ciphertext successfully. */
                        memset(back, 0, sizeof(back));
                        SSF_ASSERT(_OSSLAESCCMDecrypt(ctSSF, ptLen, nonce, nonceLen,
                                                      aadLen ? aad : NULL, aadLen, key, keyLen,
                                                      tagSSF, tagLen, back) == true);
                        if (ptLen > 0u) SSF_ASSERT(memcmp(back, pt, ptLen) == 0);

                        /* Tamper ct: both must reject. (Skip when ptLen == 0.) */
                        if (ptLen > 0u)
                        {
                            ctSSF[0] ^= 0x01u;
                            SSF_ASSERT(SSFAESCCMDecrypt(ctSSF, ptLen, nonce, nonceLen,
                                                        aadLen ? aad : NULL, aadLen, key, keyLen,
                                                        tagSSF, tagLen, back, ptLen) == false);
                            SSF_ASSERT(_OSSLAESCCMDecrypt(ctSSF, ptLen, nonce, nonceLen,
                                                          aadLen ? aad : NULL, aadLen, key, keyLen,
                                                          tagSSF, tagLen, back) == false);
                            ctSSF[0] ^= 0x01u;
                        }

                        /* Tamper aad: both must reject. (Skip when aadLen == 0.) */
                        if (aadLen > 0u)
                        {
                            aad[0] ^= 0x01u;
                            SSF_ASSERT(SSFAESCCMDecrypt(ctSSF, ptLen, nonce, nonceLen,
                                                        aad, aadLen, key, keyLen,
                                                        tagSSF, tagLen, back, ptLen) == false);
                            SSF_ASSERT(_OSSLAESCCMDecrypt(ctSSF, ptLen, nonce, nonceLen,
                                                          aad, aadLen, key, keyLen,
                                                          tagSSF, tagLen, back) == false);
                            aad[0] ^= 0x01u;
                        }

                        /* Tamper tag: both must reject. */
                        tagSSF[0] ^= 0x01u;
                        SSF_ASSERT(SSFAESCCMDecrypt(ctSSF, ptLen, nonce, nonceLen,
                                                    aadLen ? aad : NULL, aadLen, key, keyLen,
                                                    tagSSF, tagLen, back, ptLen) == false);
                        SSF_ASSERT(_OSSLAESCCMDecrypt(ctSSF, ptLen, nonce, nonceLen,
                                                      aadLen ? aad : NULL, aadLen, key, keyLen,
                                                      tagSSF, tagLen, back) == false);
                        tagSSF[0] ^= 0x01u;
                    }
                }
            }
        }
    }
}
#endif /* SSF_AESCCM_OSSL_VERIFY */

void SSFAESCCMUnitTest(void)
{
    /* ---- NIST SP 800-38C Example 1: AES-128, Nonce=7, Tag=4 ---- */
    /* Key: 40414243 44454647 48494a4b 4c4d4e4f */
    /* Nonce: 10111213 141516 */
    /* AAD: 00010203 04050607 */
    /* Plaintext: 20212223 */
    /* Expected CT: 7162015b */
    /* Expected Tag: 4dac255d */
    {
        static const uint8_t key[] = {
            0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
            0x48u, 0x49u, 0x4Au, 0x4Bu, 0x4Cu, 0x4Du, 0x4Eu, 0x4Fu
        };
        static const uint8_t nonce[] = { 0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u };
        static const uint8_t aad[] = { 0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u };
        static const uint8_t pt[] = { 0x20u, 0x21u, 0x22u, 0x23u };
        static const uint8_t expectedCt[] = { 0x71u, 0x62u, 0x01u, 0x5Bu };
        static const uint8_t expectedTag[] = { 0x4Du, 0xACu, 0x25u, 0x5Du };
        uint8_t ct[4];
        uint8_t tag[4];
        uint8_t dec[4];

        SSFAESCCMEncrypt(pt, sizeof(pt), nonce, sizeof(nonce), aad, sizeof(aad),
                         key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedCt, sizeof(expectedCt)) == 0);
        SSF_ASSERT(memcmp(tag, expectedTag, sizeof(expectedTag)) == 0);

        SSF_ASSERT(SSFAESCCMDecrypt(ct, sizeof(ct), nonce, sizeof(nonce), aad, sizeof(aad),
                   key, sizeof(key), tag, sizeof(tag), dec, sizeof(dec)) == true);
        SSF_ASSERT(memcmp(dec, pt, sizeof(pt)) == 0);
    }

    /* ---- NIST SP 800-38C Example 2: AES-128, Nonce=8, Tag=6 ---- */
    /* Key: 40414243 44454647 48494a4b 4c4d4e4f */
    /* Nonce: 10111213 14151617 */
    /* AAD: 00010203 04050607 08090a0b 0c0d0e0f */
    /* Plaintext: 20212223 24252627 28292a2b 2c2d2e2f */
    /* Expected CT: d2a1f0e0 51ea5f62 081a7792 073d593d */
    /* Expected Tag: 1fc64fbf accd */
    {
        static const uint8_t key[] = {
            0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
            0x48u, 0x49u, 0x4Au, 0x4Bu, 0x4Cu, 0x4Du, 0x4Eu, 0x4Fu
        };
        static const uint8_t nonce[] = {
            0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u
        };
        static const uint8_t aad[] = {
            0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu
        };
        static const uint8_t pt[] = {
            0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
            0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu
        };
        static const uint8_t expectedCt[] = {
            0xD2u, 0xA1u, 0xF0u, 0xE0u, 0x51u, 0xEAu, 0x5Fu, 0x62u,
            0x08u, 0x1Au, 0x77u, 0x92u, 0x07u, 0x3Du, 0x59u, 0x3Du
        };
        static const uint8_t expectedTag[] = { 0x1Fu, 0xC6u, 0x4Fu, 0xBFu, 0xACu, 0xCDu };
        uint8_t ct[16];
        uint8_t tag[6];
        uint8_t dec[16];

        SSFAESCCMEncrypt(pt, sizeof(pt), nonce, sizeof(nonce), aad, sizeof(aad),
                         key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedCt, sizeof(expectedCt)) == 0);
        SSF_ASSERT(memcmp(tag, expectedTag, sizeof(expectedTag)) == 0);

        SSF_ASSERT(SSFAESCCMDecrypt(ct, sizeof(ct), nonce, sizeof(nonce), aad, sizeof(aad),
                   key, sizeof(key), tag, sizeof(tag), dec, sizeof(dec)) == true);
        SSF_ASSERT(memcmp(dec, pt, sizeof(pt)) == 0);
    }

    /* ---- NIST SP 800-38C Example 3: AES-128, Nonce=12, Tag=8 ---- */
    /* Key: 40414243 44454647 48494a4b 4c4d4e4f */
    /* Nonce: 10111213 14151617 18191a1b */
    /* AAD: 00010203 04050607 08090a0b 0c0d0e0f 10111213 */
    /* Plaintext: 20212223 24252627 28292a2b 2c2d2e2f 30313233 34353637 */
    /* Expected CT: e3b201a9 f5b71a7a 9b1ceaec cd97e70b 6176aad9 a4428aa5 */
    /* Expected Tag: 484392fb c1b09951 */
    {
        static const uint8_t key[] = {
            0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
            0x48u, 0x49u, 0x4Au, 0x4Bu, 0x4Cu, 0x4Du, 0x4Eu, 0x4Fu
        };
        static const uint8_t nonce[] = {
            0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
            0x18u, 0x19u, 0x1Au, 0x1Bu
        };
        static const uint8_t aad[] = {
            0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
            0x10u, 0x11u, 0x12u, 0x13u
        };
        static const uint8_t pt[] = {
            0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
            0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu,
            0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u
        };
        static const uint8_t expectedCt[] = {
            0xE3u, 0xB2u, 0x01u, 0xA9u, 0xF5u, 0xB7u, 0x1Au, 0x7Au,
            0x9Bu, 0x1Cu, 0xEAu, 0xECu, 0xCDu, 0x97u, 0xE7u, 0x0Bu,
            0x61u, 0x76u, 0xAAu, 0xD9u, 0xA4u, 0x42u, 0x8Au, 0xA5u
        };
        static const uint8_t expectedTag[] = {
            0x48u, 0x43u, 0x92u, 0xFBu, 0xC1u, 0xB0u, 0x99u, 0x51u
        };
        uint8_t ct[24];
        uint8_t tag[8];
        uint8_t dec[24];

        SSFAESCCMEncrypt(pt, sizeof(pt), nonce, sizeof(nonce), aad, sizeof(aad),
                         key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));
        SSF_ASSERT(memcmp(ct, expectedCt, sizeof(expectedCt)) == 0);
        SSF_ASSERT(memcmp(tag, expectedTag, sizeof(expectedTag)) == 0);

        SSF_ASSERT(SSFAESCCMDecrypt(ct, sizeof(ct), nonce, sizeof(nonce), aad, sizeof(aad),
                   key, sizeof(key), tag, sizeof(tag), dec, sizeof(dec)) == true);
        SSF_ASSERT(memcmp(dec, pt, sizeof(pt)) == 0);
    }

    /* ---- Tag tamper detection ---- */
    {
        static const uint8_t key[] = {
            0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
            0x48u, 0x49u, 0x4Au, 0x4Bu, 0x4Cu, 0x4Du, 0x4Eu, 0x4Fu
        };
        static const uint8_t nonce[] = { 0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u };
        static const uint8_t aad[] = { 0x00u, 0x01u, 0x02u, 0x03u };
        static const uint8_t pt[] = { 0xAAu, 0xBBu, 0xCCu, 0xDDu };
        uint8_t ct[4];
        uint8_t tag[8];
        uint8_t dec[4];
        uint8_t badTag[8];

        SSFAESCCMEncrypt(pt, sizeof(pt), nonce, sizeof(nonce), aad, sizeof(aad),
                         key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));

        /* Tamper with the tag */
        memcpy(badTag, tag, sizeof(tag));
        badTag[0] ^= 0x01u;
        SSF_ASSERT(SSFAESCCMDecrypt(ct, sizeof(ct), nonce, sizeof(nonce), aad, sizeof(aad),
                   key, sizeof(key), badTag, sizeof(badTag), dec, sizeof(dec)) == false);
        /* Plaintext should be zeroed on failure */
        SSF_ASSERT(dec[0] == 0 && dec[1] == 0 && dec[2] == 0 && dec[3] == 0);
    }

    /* ---- Ciphertext tamper detection ---- */
    {
        static const uint8_t key[] = {
            0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
            0x48u, 0x49u, 0x4Au, 0x4Bu, 0x4Cu, 0x4Du, 0x4Eu, 0x4Fu
        };
        static const uint8_t nonce[] = { 0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u };
        static const uint8_t pt[] = { 0x11u, 0x22u, 0x33u, 0x44u };
        uint8_t ct[4];
        uint8_t tag[8];
        uint8_t dec[4];

        SSFAESCCMEncrypt(pt, sizeof(pt), nonce, sizeof(nonce), NULL, 0,
                         key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));

        /* Tamper with ciphertext */
        ct[0] ^= 0xFFu;
        SSF_ASSERT(SSFAESCCMDecrypt(ct, sizeof(ct), nonce, sizeof(nonce), NULL, 0,
                   key, sizeof(key), tag, sizeof(tag), dec, sizeof(dec)) == false);
    }

    /* ---- No AAD (plaintext only) ---- */
    {
        static const uint8_t key[16] = { 0 };
        static const uint8_t nonce[12] = { 0 };
        static const uint8_t pt[] = { 0x01u, 0x02u, 0x03u, 0x04u };
        uint8_t ct[4];
        uint8_t tag[16];
        uint8_t dec[4];

        SSFAESCCMEncrypt(pt, sizeof(pt), nonce, sizeof(nonce), NULL, 0,
                         key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));
        SSF_ASSERT(SSFAESCCMDecrypt(ct, sizeof(ct), nonce, sizeof(nonce), NULL, 0,
                   key, sizeof(key), tag, sizeof(tag), dec, sizeof(dec)) == true);
        SSF_ASSERT(memcmp(dec, pt, sizeof(pt)) == 0);
    }

    /* ---- AAD only (no plaintext) ---- */
    {
        static const uint8_t key[16] = { 0 };
        static const uint8_t nonce[12] = { 0 };
        static const uint8_t aad[] = { 0xABu, 0xCDu };
        uint8_t tag[8];

        SSFAESCCMEncrypt(NULL, 0, nonce, sizeof(nonce), aad, sizeof(aad),
                         key, sizeof(key), tag, sizeof(tag), NULL, 0);
        /* Verify the tag is non-zero */
        {
            uint32_t i;
            bool allZero = true;
            for (i = 0; i < sizeof(tag); i++) { if (tag[i] != 0) allZero = false; }
            SSF_ASSERT(allZero == false);
        }
        SSF_ASSERT(SSFAESCCMDecrypt(NULL, 0, nonce, sizeof(nonce), aad, sizeof(aad),
                   key, sizeof(key), tag, sizeof(tag), NULL, 0) == true);
    }

    /* ---- 16-byte tag (TLS 1.3 CCM) ---- */
    {
        static const uint8_t key[16] = {
            0xC0u, 0xC1u, 0xC2u, 0xC3u, 0xC4u, 0xC5u, 0xC6u, 0xC7u,
            0xC8u, 0xC9u, 0xCAu, 0xCBu, 0xCCu, 0xCDu, 0xCEu, 0xCFu
        };
        static const uint8_t nonce[12] = {
            0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u, 0xA6u, 0xA7u,
            0xA8u, 0xA9u, 0xAAu, 0xABu
        };
        static const uint8_t pt[] = { 'H', 'e', 'l', 'l', 'o' };
        uint8_t ct[5];
        uint8_t tag[16];
        uint8_t dec[5];

        SSFAESCCMEncrypt(pt, sizeof(pt), nonce, sizeof(nonce), NULL, 0,
                         key, sizeof(key), tag, sizeof(tag), ct, sizeof(ct));
        SSF_ASSERT(SSFAESCCMDecrypt(ct, sizeof(ct), nonce, sizeof(nonce), NULL, 0,
                   key, sizeof(key), tag, sizeof(tag), dec, sizeof(dec)) == true);
        SSF_ASSERT(memcmp(dec, pt, sizeof(pt)) == 0);
    }

#if SSF_AESCCM_OSSL_VERIFY == 1
    _VerifyAESCCMAgainstOpenSSLRandom();
#endif
}
#endif /* SSF_CONFIG_AESCCM_UNIT_TEST */
