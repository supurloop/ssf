/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhkdf_ut.c                                                                                  */
/* Provides unit tests for the ssfhkdf HKDF module.                                              */
/* Test vectors from RFC 5869 appendix A.                                                        */
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
#include <string.h>
#include "ssfassert.h"
#include "ssfhkdf.h"
#include "ssfhmac.h"

/* Cross-validate HKDF against OpenSSL on host builds where libcrypto is linked. Same gating */
/* pattern as ssfaesctr_ut.c. When disabled (cross builds with -DSSF_CONFIG_HAVE_OPENSSL=0)  */
/* the RFC 5869 KATs above are the load-bearing correctness coverage.                         */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_HKDF_UNIT_TEST == 1)
#define SSF_HKDF_OSSL_VERIFY 1
#else
#define SSF_HKDF_OSSL_VERIFY 0
#endif

#if SSF_HKDF_OSSL_VERIFY == 1
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#endif

#if SSF_CONFIG_HKDF_UNIT_TEST == 1

#if SSF_HKDF_OSSL_VERIFY == 1

/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers.                                                                  */
/* --------------------------------------------------------------------------------------------- */

/* Map SSFHMACHash_t to the OpenSSL digest name. */
static const char *_OSSLHKDFDigestName(SSFHMACHash_t h)
{
    switch (h)
    {
        case SSF_HMAC_HASH_SHA1:   return "SHA1";
        case SSF_HMAC_HASH_SHA256: return "SHA256";
        case SSF_HMAC_HASH_SHA384: return "SHA384";
        case SSF_HMAC_HASH_SHA512: return "SHA512";
        default: SSF_ASSERT(0); return NULL;
    }
}

/* Drive OpenSSL's EVP_KDF("HKDF") in one of three modes. okmLen is the requested output length. */
static void _OSSLHKDF(const char *mode, SSFHMACHash_t h,
                      const uint8_t *salt, size_t saltLen,
                      const uint8_t *key, size_t keyLen,
                      const uint8_t *info, size_t infoLen,
                      uint8_t *okm, size_t okmLen)
{
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *ctx;
    OSSL_PARAM params[6];
    size_t pIdx = 0;
    char digestName[16];

    SSF_ASSERT(kdf != NULL);
    ctx = EVP_KDF_CTX_new(kdf);
    SSF_ASSERT(ctx != NULL);

    /* OSSL_PARAM_construct_utf8_string takes a writable char* in OpenSSL 3.0; copy to a local. */
    {
        const char *src = _OSSLHKDFDigestName(h);
        size_t srcLen = strlen(src);
        SSF_ASSERT(srcLen < sizeof(digestName));
        memcpy(digestName, src, srcLen);
        digestName[srcLen] = '\0';
    }

    params[pIdx++] = OSSL_PARAM_construct_utf8_string("mode", (char *)mode, 0);
    params[pIdx++] = OSSL_PARAM_construct_utf8_string("digest", digestName, 0);
    params[pIdx++] = OSSL_PARAM_construct_octet_string("key", (void *)key, keyLen);
    if (saltLen > 0u)
    {
        params[pIdx++] = OSSL_PARAM_construct_octet_string("salt", (void *)salt, saltLen);
    }
    if (infoLen > 0u)
    {
        params[pIdx++] = OSSL_PARAM_construct_octet_string("info", (void *)info, infoLen);
    }
    params[pIdx++] = OSSL_PARAM_construct_end();

    SSF_ASSERT(EVP_KDF_derive(ctx, okm, okmLen, params) == 1);

    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz across (hash × saltLen × ikmLen × infoLen × okmLen). Each cell drives:           */
/*   - SSFHKDFExtract  vs OpenSSL "EXTRACT_ONLY"                                                 */
/*   - SSFHKDFExpand   vs OpenSSL "EXPAND_ONLY" (using the SSF-derived PRK as the "key")         */
/*   - SSFHKDF         vs OpenSSL "EXTRACT_AND_EXPAND"                                           */
/* okmLens span the 1-, multi-block, and last-partial-block paths plus the per-hash maximum     */
/* (255 * hashSize) edge cases via large requests.                                              */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyHKDFAgainstOpenSSLRandom(void)
{
    static const SSFHMACHash_t hashes[] = {
        SSF_HMAC_HASH_SHA1, SSF_HMAC_HASH_SHA256,
        SSF_HMAC_HASH_SHA384, SSF_HMAC_HASH_SHA512
    };
    static const size_t saltLens[] = {0u, 1u, 16u, 32u, 100u};
    static const size_t ikmLens[]  = {1u, 16u, 32u, 100u};
    static const size_t infoLens[] = {0u, 1u, 16u, 100u};
    static const size_t okmLens[]  = {1u, 16u, 32u, 33u, 64u, 65u, 100u, 1024u};
    uint8_t salt[100];
    uint8_t ikm[100];
    uint8_t info[100];
    uint8_t prkSSF[64];
    uint8_t prkOSSL[64];
    uint8_t okmSSF[1024];
    uint8_t okmOSSL[1024];
    size_t hIdx;
    size_t sIdx;
    size_t iIdx;
    size_t fIdx;
    size_t oIdx;

    for (hIdx = 0; hIdx < (sizeof(hashes) / sizeof(hashes[0])); hIdx++)
    {
        size_t hashSize = SSFHMACGetHashSize(hashes[hIdx]);

        for (sIdx = 0; sIdx < (sizeof(saltLens) / sizeof(saltLens[0])); sIdx++)
        {
            for (iIdx = 0; iIdx < (sizeof(ikmLens) / sizeof(ikmLens[0])); iIdx++)
            {
                for (fIdx = 0; fIdx < (sizeof(infoLens) / sizeof(infoLens[0])); fIdx++)
                {
                    for (oIdx = 0; oIdx < (sizeof(okmLens) / sizeof(okmLens[0])); oIdx++)
                    {
                        size_t saltLen = saltLens[sIdx];
                        size_t ikmLen  = ikmLens[iIdx];
                        size_t infoLen = infoLens[fIdx];
                        size_t okmLen  = okmLens[oIdx];

                        if (saltLen > 0u) SSF_ASSERT(RAND_bytes(salt, (int)saltLen) == 1);
                        SSF_ASSERT(RAND_bytes(ikm, (int)ikmLen) == 1);
                        if (infoLen > 0u) SSF_ASSERT(RAND_bytes(info, (int)infoLen) == 1);

                        /* Extract: SSF vs OpenSSL EXTRACT_ONLY. */
                        SSF_ASSERT(SSFHKDFExtract(hashes[hIdx],
                                                  saltLen ? salt : NULL, saltLen,
                                                  ikm, ikmLen, prkSSF, hashSize) == true);
                        _OSSLHKDF("EXTRACT_ONLY", hashes[hIdx],
                                  saltLen ? salt : NULL, saltLen,
                                  ikm, ikmLen, NULL, 0u, prkOSSL, hashSize);
                        SSF_ASSERT(memcmp(prkSSF, prkOSSL, hashSize) == 0);

                        /* Expand: SSF vs OpenSSL EXPAND_ONLY (use SSF's PRK as the "key"). */
                        SSF_ASSERT(SSFHKDFExpand(hashes[hIdx], prkSSF, hashSize,
                                                 infoLen ? info : NULL, infoLen,
                                                 okmSSF, okmLen) == true);
                        _OSSLHKDF("EXPAND_ONLY", hashes[hIdx],
                                  NULL, 0u, prkSSF, hashSize,
                                  infoLen ? info : NULL, infoLen, okmOSSL, okmLen);
                        SSF_ASSERT(memcmp(okmSSF, okmOSSL, okmLen) == 0);

                        /* Full HKDF: SSF vs OpenSSL EXTRACT_AND_EXPAND. */
                        SSF_ASSERT(SSFHKDF(hashes[hIdx],
                                           saltLen ? salt : NULL, saltLen,
                                           ikm, ikmLen,
                                           infoLen ? info : NULL, infoLen,
                                           okmSSF, okmLen) == true);
                        _OSSLHKDF("EXTRACT_AND_EXPAND", hashes[hIdx],
                                  saltLen ? salt : NULL, saltLen,
                                  ikm, ikmLen,
                                  infoLen ? info : NULL, infoLen, okmOSSL, okmLen);
                        SSF_ASSERT(memcmp(okmSSF, okmOSSL, okmLen) == 0);
                    }
                }
            }
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Verify SSFHKDFExpand with prkLen > hashSize against OpenSSL. The standard fuzz above only     */
/* exercises prkLen == hashSize (the Extract output size); this covers the two HMAC long-key     */
/* regimes from RFC 2104: zero-pad when prkLen <= blockSize, pre-hash when prkLen > blockSize.   */
/* SHA-1/256 blockSize = 64, SHA-384/512 blockSize = 128, so prkLens 65/129/200 hit both paths.  */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyHKDFExpandLongPRK(void)
{
    static const SSFHMACHash_t hashes[] = {
        SSF_HMAC_HASH_SHA1, SSF_HMAC_HASH_SHA256,
        SSF_HMAC_HASH_SHA384, SSF_HMAC_HASH_SHA512
    };
    static const size_t prkLens[] = {65u, 129u, 200u};
    uint8_t prk[200];
    uint8_t info[32];
    uint8_t okmSSF[128];
    uint8_t okmOSSL[128];
    size_t hIdx;
    size_t pIdx;

    SSF_ASSERT(RAND_bytes(info, sizeof(info)) == 1);

    for (hIdx = 0; hIdx < (sizeof(hashes) / sizeof(hashes[0])); hIdx++)
    {
        for (pIdx = 0; pIdx < (sizeof(prkLens) / sizeof(prkLens[0])); pIdx++)
        {
            size_t prkLen = prkLens[pIdx];

            SSF_ASSERT(RAND_bytes(prk, (int)prkLen) == 1);

            SSF_ASSERT(SSFHKDFExpand(hashes[hIdx], prk, prkLen, info, sizeof(info),
                                     okmSSF, sizeof(okmSSF)) == true);
            _OSSLHKDF("EXPAND_ONLY", hashes[hIdx], NULL, 0u, prk, prkLen,
                      info, sizeof(info), okmOSSL, sizeof(okmOSSL));
            SSF_ASSERT(memcmp(okmSSF, okmOSSL, sizeof(okmOSSL)) == 0);
        }
    }
}
#endif /* SSF_HKDF_OSSL_VERIFY */

void SSFHKDFUnitTest(void)
{
    /* ---- RFC 5869 Test Case 1: HKDF-SHA-256, basic ---- */
    {
        static const uint8_t ikm[] = {
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu
        };
        static const uint8_t salt[] = {
            0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu
        };
        static const uint8_t info[] = {
            0xF0u, 0xF1u, 0xF2u, 0xF3u, 0xF4u, 0xF5u, 0xF6u, 0xF7u,
            0xF8u, 0xF9u
        };
        static const uint8_t expectedPRK[] = {
            0x07u, 0x77u, 0x09u, 0x36u, 0x2Cu, 0x2Eu, 0x32u, 0xDFu,
            0x0Du, 0xDCu, 0x3Fu, 0x0Du, 0xC4u, 0x7Bu, 0xBAu, 0x63u,
            0x90u, 0xB6u, 0xC7u, 0x3Bu, 0xB5u, 0x0Fu, 0x9Cu, 0x31u,
            0x22u, 0xECu, 0x84u, 0x4Au, 0xD7u, 0xC2u, 0xB3u, 0xE5u
        };
        static const uint8_t expectedOKM[] = {
            0x3Cu, 0xB2u, 0x5Fu, 0x25u, 0xFAu, 0xACu, 0xD5u, 0x7Au,
            0x90u, 0x43u, 0x4Fu, 0x64u, 0xD0u, 0x36u, 0x2Fu, 0x2Au,
            0x2Du, 0x2Du, 0x0Au, 0x90u, 0xCFu, 0x1Au, 0x5Au, 0x4Cu,
            0x5Du, 0xB0u, 0x2Du, 0x56u, 0xECu, 0xC4u, 0xC5u, 0xBFu,
            0x34u, 0x00u, 0x72u, 0x08u, 0xD5u, 0xB8u, 0x87u, 0x18u,
            0x58u, 0x65u
        };
        uint8_t prk[32];
        uint8_t okm[42];

        /* Test Extract separately */
        SSF_ASSERT(SSFHKDFExtract(SSF_HMAC_HASH_SHA256, salt, sizeof(salt), ikm, sizeof(ikm),
                   prk, sizeof(prk)) == true);
        SSF_ASSERT(memcmp(prk, expectedPRK, sizeof(expectedPRK)) == 0);

        /* Test Expand separately */
        SSF_ASSERT(SSFHKDFExpand(SSF_HMAC_HASH_SHA256, prk, sizeof(prk), info, sizeof(info),
                   okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);

        /* Test combined */
        memset(okm, 0, sizeof(okm));
        SSF_ASSERT(SSFHKDF(SSF_HMAC_HASH_SHA256, salt, sizeof(salt), ikm, sizeof(ikm),
                   info, sizeof(info), okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- RFC 5869 Test Case 2: HKDF-SHA-256, longer inputs/outputs ---- */
    {
        static const uint8_t ikm[] = {
            0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
            0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu,
            0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
            0x18u, 0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu,
            0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
            0x28u, 0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu,
            0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u,
            0x38u, 0x39u, 0x3Au, 0x3Bu, 0x3Cu, 0x3Du, 0x3Eu, 0x3Fu,
            0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
            0x48u, 0x49u, 0x4Au, 0x4Bu, 0x4Cu, 0x4Du, 0x4Eu, 0x4Fu
        };
        static const uint8_t salt[] = {
            0x60u, 0x61u, 0x62u, 0x63u, 0x64u, 0x65u, 0x66u, 0x67u,
            0x68u, 0x69u, 0x6Au, 0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu,
            0x70u, 0x71u, 0x72u, 0x73u, 0x74u, 0x75u, 0x76u, 0x77u,
            0x78u, 0x79u, 0x7Au, 0x7Bu, 0x7Cu, 0x7Du, 0x7Eu, 0x7Fu,
            0x80u, 0x81u, 0x82u, 0x83u, 0x84u, 0x85u, 0x86u, 0x87u,
            0x88u, 0x89u, 0x8Au, 0x8Bu, 0x8Cu, 0x8Du, 0x8Eu, 0x8Fu,
            0x90u, 0x91u, 0x92u, 0x93u, 0x94u, 0x95u, 0x96u, 0x97u,
            0x98u, 0x99u, 0x9Au, 0x9Bu, 0x9Cu, 0x9Du, 0x9Eu, 0x9Fu,
            0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u, 0xA6u, 0xA7u,
            0xA8u, 0xA9u, 0xAAu, 0xABu, 0xACu, 0xADu, 0xAEu, 0xAFu
        };
        static const uint8_t info[] = {
            0xB0u, 0xB1u, 0xB2u, 0xB3u, 0xB4u, 0xB5u, 0xB6u, 0xB7u,
            0xB8u, 0xB9u, 0xBAu, 0xBBu, 0xBCu, 0xBDu, 0xBEu, 0xBFu,
            0xC0u, 0xC1u, 0xC2u, 0xC3u, 0xC4u, 0xC5u, 0xC6u, 0xC7u,
            0xC8u, 0xC9u, 0xCAu, 0xCBu, 0xCCu, 0xCDu, 0xCEu, 0xCFu,
            0xD0u, 0xD1u, 0xD2u, 0xD3u, 0xD4u, 0xD5u, 0xD6u, 0xD7u,
            0xD8u, 0xD9u, 0xDAu, 0xDBu, 0xDCu, 0xDDu, 0xDEu, 0xDFu,
            0xE0u, 0xE1u, 0xE2u, 0xE3u, 0xE4u, 0xE5u, 0xE6u, 0xE7u,
            0xE8u, 0xE9u, 0xEAu, 0xEBu, 0xECu, 0xEDu, 0xEEu, 0xEFu,
            0xF0u, 0xF1u, 0xF2u, 0xF3u, 0xF4u, 0xF5u, 0xF6u, 0xF7u,
            0xF8u, 0xF9u, 0xFAu, 0xFBu, 0xFCu, 0xFDu, 0xFEu, 0xFFu
        };
        static const uint8_t expectedOKM[] = {
            0xB1u, 0x1Eu, 0x39u, 0x8Du, 0xC8u, 0x03u, 0x27u, 0xA1u,
            0xC8u, 0xE7u, 0xF7u, 0x8Cu, 0x59u, 0x6Au, 0x49u, 0x34u,
            0x4Fu, 0x01u, 0x2Eu, 0xDAu, 0x2Du, 0x4Eu, 0xFAu, 0xD8u,
            0xA0u, 0x50u, 0xCCu, 0x4Cu, 0x19u, 0xAFu, 0xA9u, 0x7Cu,
            0x59u, 0x04u, 0x5Au, 0x99u, 0xCAu, 0xC7u, 0x82u, 0x72u,
            0x71u, 0xCBu, 0x41u, 0xC6u, 0x5Eu, 0x59u, 0x0Eu, 0x09u,
            0xDAu, 0x32u, 0x75u, 0x60u, 0x0Cu, 0x2Fu, 0x09u, 0xB8u,
            0x36u, 0x77u, 0x93u, 0xA9u, 0xACu, 0xA3u, 0xDBu, 0x71u,
            0xCCu, 0x30u, 0xC5u, 0x81u, 0x79u, 0xECu, 0x3Eu, 0x87u,
            0xC1u, 0x4Cu, 0x01u, 0xD5u, 0xC1u, 0xF3u, 0x43u, 0x4Fu,
            0x1Du, 0x87u
        };
        uint8_t okm[82];

        SSF_ASSERT(SSFHKDF(SSF_HMAC_HASH_SHA256, salt, sizeof(salt), ikm, sizeof(ikm),
                   info, sizeof(info), okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- RFC 5869 Test Case 3: HKDF-SHA-256, zero-length salt and info ---- */
    {
        static const uint8_t ikm[] = {
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu
        };
        static const uint8_t expectedPRK[] = {
            0x19u, 0xEFu, 0x24u, 0xA3u, 0x2Cu, 0x71u, 0x7Bu, 0x16u,
            0x7Fu, 0x33u, 0xA9u, 0x1Du, 0x6Fu, 0x64u, 0x8Bu, 0xDFu,
            0x96u, 0x59u, 0x67u, 0x76u, 0xAFu, 0xDBu, 0x63u, 0x77u,
            0xACu, 0x43u, 0x4Cu, 0x1Cu, 0x29u, 0x3Cu, 0xCBu, 0x04u
        };
        static const uint8_t expectedOKM[] = {
            0x8Du, 0xA4u, 0xE7u, 0x75u, 0xA5u, 0x63u, 0xC1u, 0x8Fu,
            0x71u, 0x5Fu, 0x80u, 0x2Au, 0x06u, 0x3Cu, 0x5Au, 0x31u,
            0xB8u, 0xA1u, 0x1Fu, 0x5Cu, 0x5Eu, 0xE1u, 0x87u, 0x9Eu,
            0xC3u, 0x45u, 0x4Eu, 0x5Fu, 0x3Cu, 0x73u, 0x8Du, 0x2Du,
            0x9Du, 0x20u, 0x13u, 0x95u, 0xFAu, 0xA4u, 0xB6u, 0x1Au,
            0x96u, 0xC8u
        };
        uint8_t prk[32];
        uint8_t okm[42];

        /* Extract with NULL salt */
        SSF_ASSERT(SSFHKDFExtract(SSF_HMAC_HASH_SHA256, NULL, 0, ikm, sizeof(ikm),
                   prk, sizeof(prk)) == true);
        SSF_ASSERT(memcmp(prk, expectedPRK, sizeof(expectedPRK)) == 0);

        /* Expand with empty info */
        SSF_ASSERT(SSFHKDFExpand(SSF_HMAC_HASH_SHA256, prk, sizeof(prk), NULL, 0,
                   okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- RFC 5869 Test Case 4: HKDF-SHA-1, basic ---- */
    {
        static const uint8_t ikm[] = { 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
                                        0x0Bu, 0x0Bu, 0x0Bu };
        static const uint8_t salt[] = { 0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
                                         0x08u, 0x09u, 0x0Au, 0x0Bu, 0x0Cu };
        static const uint8_t info[] = { 0xF0u, 0xF1u, 0xF2u, 0xF3u, 0xF4u, 0xF5u, 0xF6u, 0xF7u,
                                         0xF8u, 0xF9u };
        static const uint8_t expectedPRK[] = {
            0x9Bu, 0x6Cu, 0x18u, 0xC4u, 0x32u, 0xA7u, 0xBFu, 0x8Fu,
            0x0Eu, 0x71u, 0xC8u, 0xEBu, 0x88u, 0xF4u, 0xB3u, 0x0Bu,
            0xAAu, 0x2Bu, 0xA2u, 0x43u
        };
        static const uint8_t expectedOKM[] = {
            0x08u, 0x5Au, 0x01u, 0xEAu, 0x1Bu, 0x10u, 0xF3u, 0x69u,
            0x33u, 0x06u, 0x8Bu, 0x56u, 0xEFu, 0xA5u, 0xADu, 0x81u,
            0xA4u, 0xF1u, 0x4Bu, 0x82u, 0x2Fu, 0x5Bu, 0x09u, 0x15u,
            0x68u, 0xA9u, 0xCDu, 0xD4u, 0xF1u, 0x55u, 0xFDu, 0xA2u,
            0xC2u, 0x2Eu, 0x42u, 0x24u, 0x78u, 0xD3u, 0x05u, 0xF3u,
            0xF8u, 0x96u
        };
        uint8_t prk[20];
        uint8_t okm[42];

        SSF_ASSERT(SSFHKDFExtract(SSF_HMAC_HASH_SHA1, salt, sizeof(salt), ikm, sizeof(ikm),
                   prk, sizeof(prk)) == true);
        SSF_ASSERT(memcmp(prk, expectedPRK, sizeof(expectedPRK)) == 0);

        SSF_ASSERT(SSFHKDFExpand(SSF_HMAC_HASH_SHA1, prk, sizeof(prk), info, sizeof(info),
                   okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- RFC 5869 Test Case 7: HKDF-SHA-1, salt absent (NULL) ---- */
    {
        static const uint8_t ikm[] = {
            0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu,
            0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu,
            0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu, 0x0Cu
        };
        static const uint8_t expectedPRK[] = {
            0x2Au, 0xDCu, 0xCAu, 0xDAu, 0x18u, 0x77u, 0x9Eu, 0x7Cu,
            0x20u, 0x77u, 0xADu, 0x2Eu, 0xB1u, 0x9Du, 0x3Fu, 0x3Eu,
            0x73u, 0x13u, 0x85u, 0xDDu
        };
        static const uint8_t expectedOKM[] = {
            0x2Cu, 0x91u, 0x11u, 0x72u, 0x04u, 0xD7u, 0x45u, 0xF3u,
            0x50u, 0x0Du, 0x63u, 0x6Au, 0x62u, 0xF6u, 0x4Fu, 0x0Au,
            0xB3u, 0xBAu, 0xE5u, 0x48u, 0xAAu, 0x53u, 0xD4u, 0x23u,
            0xB0u, 0xD1u, 0xF2u, 0x7Eu, 0xBBu, 0xA6u, 0xF5u, 0xE5u,
            0x67u, 0x3Au, 0x08u, 0x1Du, 0x70u, 0xCCu, 0xE7u, 0xACu,
            0xFCu, 0x48u
        };
        uint8_t prk[20];
        uint8_t okm[42];

        /* Salt absent for SHA-1 — exercises the salt==NULL substitution branch that TC4 does */
        /* not reach (TC3 covers it for SHA-256 only).                                         */
        SSF_ASSERT(SSFHKDFExtract(SSF_HMAC_HASH_SHA1, NULL, 0, ikm, sizeof(ikm),
                   prk, sizeof(prk)) == true);
        SSF_ASSERT(memcmp(prk, expectedPRK, sizeof(expectedPRK)) == 0);

        SSF_ASSERT(SSFHKDFExpand(SSF_HMAC_HASH_SHA1, prk, sizeof(prk), NULL, 0,
                   okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- HKDF-SHA-384, single-block (Wycheproof v1 hkdf_sha384_test.json tcId 10) ---- */
    {
        static const uint8_t ikm[] = {
            0xC3u, 0x60u, 0xE1u, 0x60u, 0x84u, 0xCFu, 0xD1u, 0x3Cu,
            0xB4u, 0x4Bu, 0x0Du, 0xC0u, 0x2Du, 0x86u, 0x65u, 0xDEu
        };
        static const uint8_t salt[] = {
            0x68u, 0x5Au, 0xC7u, 0xDFu, 0x93u, 0x70u, 0x1Du, 0x6Cu,
            0x78u, 0xBAu, 0xBDu, 0x84u, 0x78u, 0x61u, 0xBBu, 0x3Cu
        };
        static const uint8_t info[] = {
            0xE0u, 0xDDu, 0xFAu, 0xAAu, 0xA7u, 0xAFu, 0xB5u, 0x3Fu,
            0x59u, 0xA0u, 0x07u, 0xA2u, 0x05u, 0xC7u, 0x14u, 0x9Bu,
            0x5Bu, 0x5Au, 0x72u, 0xBEu
        };
        static const uint8_t expectedOKM[] = {
            0x00u, 0xAAu, 0x14u, 0x03u, 0x87u, 0xA3u, 0xD4u, 0x3Au,
            0xAEu, 0x91u, 0x5Cu, 0x35u, 0xB3u, 0x06u, 0x53u, 0x31u,
            0x79u, 0x01u, 0x9Bu, 0xABu
        };
        uint8_t okm[20];

        SSF_ASSERT(SSFHKDF(SSF_HMAC_HASH_SHA384, salt, sizeof(salt), ikm, sizeof(ikm),
                   info, sizeof(info), okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- HKDF-SHA-384, multi-block (Wycheproof v1 hkdf_sha384_test.json tcId 12) ---- */
    {
        static const uint8_t ikm[] = {
            0x7Au, 0x00u, 0x81u, 0x76u, 0x89u, 0xA3u, 0xD7u, 0x90u,
            0x01u, 0x82u, 0x5Au, 0x86u, 0x4Cu, 0x69u, 0xC1u, 0x20u
        };
        static const uint8_t salt[] = {
            0x08u, 0xBCu, 0x01u, 0xC0u, 0x53u, 0xA6u, 0x40u, 0x6Cu,
            0x7Cu, 0x4Au, 0x66u, 0x7Cu, 0x9Bu, 0x9Bu, 0x38u, 0x94u
        };
        static const uint8_t info[] = {
            0x96u, 0x7Cu, 0xCDu, 0x75u, 0x39u, 0x5Bu, 0xE6u, 0xE9u,
            0x6Au, 0x67u, 0x75u, 0x9Fu, 0x07u, 0x04u, 0x87u, 0xC9u,
            0xE2u, 0x10u, 0x77u, 0x91u
        };
        static const uint8_t expectedOKM[] = {
            0xBDu, 0x02u, 0xE1u, 0x6Bu, 0x60u, 0x24u, 0xF2u, 0xC3u,
            0xB7u, 0x52u, 0xD1u, 0xC1u, 0xD3u, 0x04u, 0x75u, 0x83u,
            0x69u, 0x77u, 0x31u, 0x91u, 0x5Fu, 0xBBu, 0xB3u, 0x44u,
            0x18u, 0xF4u, 0x79u, 0xB0u, 0xC9u, 0xBFu, 0x84u, 0xA8u,
            0x6Bu, 0xD8u, 0xE7u, 0x15u, 0xECu, 0xA1u, 0x98u, 0xDAu,
            0x8Fu, 0x9Bu, 0x39u, 0xB2u, 0x5Au, 0x12u, 0x29u, 0xC3u,
            0x11u, 0x85u, 0x3Fu, 0x86u, 0x23u, 0x40u, 0xCDu, 0xEFu,
            0xE4u, 0x6Du, 0xDFu, 0x41u, 0xDCu, 0xF2u, 0x56u, 0xD9u
        };
        uint8_t okm[64];

        /* 64B output > 48B SHA-384 hashSize → exercises multi-block Expand iteration. */
        SSF_ASSERT(SSFHKDF(SSF_HMAC_HASH_SHA384, salt, sizeof(salt), ikm, sizeof(ikm),
                   info, sizeof(info), okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- HKDF-SHA-512, single-block (Wycheproof v1 hkdf_sha512_test.json tcId 10) ---- */
    {
        static const uint8_t ikm[] = {
            0xC3u, 0x60u, 0xE1u, 0x60u, 0x84u, 0xCFu, 0xD1u, 0x3Cu,
            0xB4u, 0x4Bu, 0x0Du, 0xC0u, 0x2Du, 0x86u, 0x65u, 0xDEu
        };
        static const uint8_t salt[] = {
            0x68u, 0x5Au, 0xC7u, 0xDFu, 0x93u, 0x70u, 0x1Du, 0x6Cu,
            0x78u, 0xBAu, 0xBDu, 0x84u, 0x78u, 0x61u, 0xBBu, 0x3Cu
        };
        static const uint8_t info[] = {
            0xE0u, 0xDDu, 0xFAu, 0xAAu, 0xA7u, 0xAFu, 0xB5u, 0x3Fu,
            0x59u, 0xA0u, 0x07u, 0xA2u, 0x05u, 0xC7u, 0x14u, 0x9Bu,
            0x5Bu, 0x5Au, 0x72u, 0xBEu
        };
        static const uint8_t expectedOKM[] = {
            0x17u, 0x40u, 0x8Cu, 0x6Fu, 0x8Du, 0xD7u, 0xEBu, 0x84u,
            0x23u, 0x75u, 0x8Cu, 0xE3u, 0x9Au, 0x91u, 0xB5u, 0x90u,
            0x20u, 0xF7u, 0xDEu, 0xBEu
        };
        uint8_t okm[20];

        SSF_ASSERT(SSFHKDF(SSF_HMAC_HASH_SHA512, salt, sizeof(salt), ikm, sizeof(ikm),
                   info, sizeof(info), okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- HKDF-SHA-512, multi-block (Wycheproof v1 hkdf_sha512_test.json tcId 71) ---- */
    {
        static const uint8_t ikm[] = {
            0xC1u, 0x32u, 0xACu, 0x86u, 0x1Du, 0x00u, 0xE8u, 0xAAu,
            0x82u, 0x47u, 0x0Bu, 0xAFu, 0x3Bu, 0xE3u, 0x85u, 0x1Cu,
            0x9Fu, 0x77u, 0xF9u, 0x6Bu, 0x19u, 0xCCu, 0x2Cu, 0x3Eu,
            0xB5u, 0x55u, 0x8Cu, 0x20u, 0x91u, 0x5Au, 0xD1u, 0x6Cu,
            0xB4u, 0x5Cu, 0x50u, 0xDBu, 0x9Bu, 0x23u, 0x0Cu, 0x52u,
            0x79u, 0xBFu, 0x7Bu, 0x38u, 0xFBu, 0xF5u, 0x0Cu, 0xE6u,
            0x8Bu, 0x60u, 0xD7u, 0xB2u, 0x30u, 0x53u, 0x0Fu, 0x3Au,
            0x5Fu, 0x40u, 0x16u, 0x88u, 0x3Fu, 0x21u, 0x71u, 0x68u
        };
        static const uint8_t salt[] = {
            0x4Cu, 0x35u, 0x82u, 0xC8u, 0x67u, 0xFAu, 0xB8u, 0x4Cu,
            0xA0u, 0x75u, 0xDAu, 0x5Au, 0xEFu, 0x6Bu, 0x78u, 0xB8u,
            0xDBu, 0x98u, 0x2Eu, 0xE4u, 0xFEu, 0x33u, 0xFBu, 0x45u,
            0x00u, 0x29u, 0x46u, 0x59u, 0xAAu, 0xD6u, 0x3Du, 0xD7u,
            0x67u, 0x7Fu, 0x2Fu, 0x25u, 0x6Bu, 0xF7u, 0x19u, 0xC6u,
            0x79u, 0x6Eu, 0xA8u, 0xFDu, 0xF1u, 0x2Cu, 0x46u, 0x86u,
            0x30u, 0x64u, 0x87u, 0x5Au, 0x52u, 0x9Au, 0xEEu, 0xF9u,
            0x31u, 0x8Fu, 0x34u, 0x43u, 0x35u, 0x61u, 0x0Fu, 0x82u
        };
        static const uint8_t info[] = {
            0x75u, 0x73u, 0xB9u, 0x5Fu, 0x1Du, 0x8Eu, 0xE5u, 0xD0u
        };
        static const uint8_t expectedOKM[] = {
            0xD9u, 0x36u, 0x63u, 0x82u, 0x59u, 0x63u, 0xA4u, 0xA2u,
            0x32u, 0x8Au, 0x6Eu, 0x56u, 0xEEu, 0x7Du, 0x10u, 0x8Du,
            0xE9u, 0x5Bu, 0x7Cu, 0x98u, 0x1Cu, 0x3Eu, 0x62u, 0xDCu,
            0x8Du, 0xF4u, 0x01u, 0x05u, 0xE4u, 0x99u, 0x51u, 0x37u,
            0xCAu, 0x8Cu, 0xFAu, 0x91u, 0xCBu, 0xFFu, 0xB4u, 0x47u,
            0xFFu, 0xD8u, 0x0Bu, 0x0Bu, 0x90u, 0x15u, 0x78u, 0xAAu,
            0xABu, 0xC6u, 0xC5u, 0x6Bu, 0x3Au, 0xA6u, 0x67u, 0x34u,
            0xFBu, 0xE9u, 0x8Bu, 0x95u, 0xC1u, 0x12u, 0x59u, 0x90u,
            0xE1u, 0x45u, 0x33u, 0xE1u, 0x3Du, 0x04u, 0x9Fu, 0x02u,
            0x58u, 0x80u, 0xFBu, 0x28u, 0x34u, 0xC8u, 0xE5u, 0xE2u,
            0xBBu, 0xC8u, 0x71u, 0x9Du, 0xEBu, 0x3Bu, 0x20u, 0x74u,
            0x29u, 0x39u, 0x7Cu, 0x19u, 0xBEu, 0xB0u, 0x16u, 0x0Fu,
            0x46u, 0x44u, 0x1Fu, 0x95u, 0xF8u, 0xB1u, 0x1Au, 0xB2u,
            0xEAu, 0xD3u, 0x2Cu, 0x64u, 0xC1u, 0x2Du, 0x9Fu, 0x46u,
            0xD6u, 0xAAu, 0xA5u, 0x8Fu, 0x9Eu, 0x68u, 0x57u, 0x71u
        };
        uint8_t okm[120];

        /* 120B output > 64B SHA-512 hashSize → exercises multi-block Expand iteration. */
        SSF_ASSERT(SSFHKDF(SSF_HMAC_HASH_SHA512, salt, sizeof(salt), ikm, sizeof(ikm),
                   info, sizeof(info), okm, sizeof(okm)) == true);
        SSF_ASSERT(memcmp(okm, expectedOKM, sizeof(expectedOKM)) == 0);
    }

    /* ---- Expand: output length exactly one hash block ---- */
    {
        uint8_t prk[32];
        uint8_t okm[32];
        static const uint8_t ikm[] = { 0x01u };

        SSF_ASSERT(SSFHKDFExtract(SSF_HMAC_HASH_SHA256, NULL, 0, ikm, 1, prk, sizeof(prk)) == true);
        SSF_ASSERT(SSFHKDFExpand(SSF_HMAC_HASH_SHA256, prk, sizeof(prk), NULL, 0,
                   okm, 32) == true);
        {
            uint32_t j;
            bool nonZero = false;
            for (j = 0; j < 32u; j++) { if (okm[j] != 0) nonZero = true; }
            SSF_ASSERT(nonZero == true);
        }
    }

    /* ---- Expand: zero output length ---- */
    {
        uint8_t prk[32] = { 0 };
        SSF_ASSERT(SSFHKDFExpand(SSF_HMAC_HASH_SHA256, prk, sizeof(prk), NULL, 0,
                   prk, 0) == true);
    }

#if SSF_HKDF_OSSL_VERIFY == 1
    _VerifyHKDFAgainstOpenSSLRandom();
    _VerifyHKDFExpandLongPRK();
#endif
}
#endif /* SSF_CONFIG_HKDF_UNIT_TEST */
