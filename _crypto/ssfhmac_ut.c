/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhmac_ut.c                                                                                  */
/* Provides unit tests for the ssfhmac HMAC module.                                              */
/* Test vectors from RFC 4231 (HMAC-SHA-256/384/512) and RFC 2202 (HMAC-SHA-1).                  */
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
#include "ssfhmac.h"

/* Cross-check against OpenSSL HMAC when libcrypto is linked, else RFC 4231/2202 KATs cover it.  */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_HMAC_UNIT_TEST == 1)
#define SSF_HMAC_OSSL_VERIFY 1
#else
#define SSF_HMAC_OSSL_VERIFY 0
#endif

#if SSF_HMAC_OSSL_VERIFY == 1
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#if SSF_CONFIG_HMAC_UNIT_TEST == 1

#if SSF_HMAC_OSSL_VERIFY == 1

/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers.                                                                  */
/* --------------------------------------------------------------------------------------------- */

/* Map SSF hash enum to OpenSSL's EVP_MD*. */
static const EVP_MD *_OSSLMd(SSFHMACHash_t h)
{
    switch (h)
    {
        case SSF_HMAC_HASH_SHA1:   return EVP_sha1();
        case SSF_HMAC_HASH_SHA256: return EVP_sha256();
        case SSF_HMAC_HASH_SHA384: return EVP_sha384();
        case SSF_HMAC_HASH_SHA512: return EVP_sha512();
        default: SSF_ASSERT(0); return NULL;
    }
}

/* Compute HMAC via OpenSSL's single-call API. The output buffer must be exactly hashSize bytes. */
static void _OSSLHMAC(SSFHMACHash_t h, const uint8_t *key, size_t keyLen,
                      const uint8_t *msg, size_t msgLen,
                      uint8_t *out, size_t outLen)
{
    unsigned int outU = (unsigned int)outLen;

    SSF_ASSERT(HMAC(_OSSLMd(h), key, (int)keyLen, msg, msgLen, out, &outU) != NULL);
    SSF_ASSERT((size_t)outU == outLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz (hash x keyLen x msgLen): one-shot and split incremental vs OpenSSL HMAC.         */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyHMACAgainstOpenSSLRandom(void)
{
    static const SSFHMACHash_t hashes[] = {
        SSF_HMAC_HASH_SHA1, SSF_HMAC_HASH_SHA256,
        SSF_HMAC_HASH_SHA384, SSF_HMAC_HASH_SHA512
    };
    /* keyLens span < block, == block and > block for both block sizes (64 and 128). */
    static const size_t keyLens[] = {1u, 16u, 32u, 63u, 64u, 65u, 100u, 127u, 128u, 131u, 200u};
    /* msgLens span SHA's partial-block buffer transitions and a couple of multi-block cases.   */
    static const size_t msgLens[] = {0u, 1u, 7u, 31u, 63u, 64u, 65u, 127u,
                                     128u, 129u, 255u, 256u, 511u, 1024u};
    uint8_t key[256];
    uint8_t msg[1024];
    uint8_t macSSF[64];
    uint8_t macOSSL[64];
        size_t hIdx;
        size_t kIdx;
        size_t mIdx;
    int iter;

    for (hIdx = 0; hIdx < sizeof(hashes) / sizeof(hashes[0]); hIdx++)
    {
        size_t hashSize = SSFHMACGetHashSize(hashes[hIdx]);

        for (kIdx = 0; kIdx < sizeof(keyLens) / sizeof(keyLens[0]); kIdx++)
        {
            size_t kLen = keyLens[kIdx];

            for (mIdx = 0; mIdx < sizeof(msgLens) / sizeof(msgLens[0]); mIdx++)
            {
                size_t mLen = msgLens[mIdx];

                for (iter = 0; iter < 5; iter++)
                {
                    SSFHMACContext_t ctx = {0};

                    SSF_ASSERT(RAND_bytes(key, (int)kLen) == 1);
                    if (mLen > 0u) SSF_ASSERT(RAND_bytes(msg, (int)mLen) == 1);

                    SSF_ASSERT(SSFHMAC(hashes[hIdx], key, kLen,
                                       (mLen == 0u) ? NULL : msg, mLen,
                                       macSSF, hashSize) == true);
                    _OSSLHMAC(hashes[hIdx], key, kLen, msg, mLen, macOSSL, hashSize);
                    SSF_ASSERT(memcmp(macSSF, macOSSL, hashSize) == 0);

                    SSFHMACBegin(&ctx, hashes[hIdx], key, kLen);
                    if (mLen >= 4u)
                    {
                        SSFHMACUpdate(&ctx, msg, mLen / 2u);
                        SSFHMACUpdate(&ctx, &msg[mLen / 2u], mLen - (mLen / 2u));
                    }
                    else if (mLen > 0u)
                    {
                        SSFHMACUpdate(&ctx, msg, mLen);
                    }
                    SSFHMACEnd(&ctx, macSSF, hashSize);
                    SSFHMACDeInit(&ctx);
                    SSF_ASSERT(memcmp(macSSF, macOSSL, hashSize) == 0);
                }
            }
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Corner cases vs OpenSSL: all-zero/all-0xFF keys, empty message, byte-at-a-time.               */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyHMACCornerCasesAgainstOpenSSL(void)
{
    static const SSFHMACHash_t hashes[] = {
        SSF_HMAC_HASH_SHA1, SSF_HMAC_HASH_SHA256,
        SSF_HMAC_HASH_SHA384, SSF_HMAC_HASH_SHA512
    };
    uint8_t macSSF[64];
    uint8_t macOSSL[64];
    size_t hIdx;

    for (hIdx = 0; hIdx < sizeof(hashes) / sizeof(hashes[0]); hIdx++)
    {
        SSFHMACHash_t h = hashes[hIdx];
        size_t hashSize = SSFHMACGetHashSize(h);
        size_t blockSize = (h == SSF_HMAC_HASH_SHA384 || h == SSF_HMAC_HASH_SHA512) ? 128u : 64u;

        /* All-zero key (32 B), nominal message. */
        {
            uint8_t key[32] = {0};
            static const uint8_t msg[] = "the quick brown fox";
            SSF_ASSERT(SSFHMAC(h, key, sizeof(key), msg, sizeof(msg) - 1u,
                               macSSF, hashSize) == true);
            _OSSLHMAC(h, key, sizeof(key), msg, sizeof(msg) - 1u, macOSSL, hashSize);
            SSF_ASSERT(memcmp(macSSF, macOSSL, hashSize) == 0);
        }

        /* All-0xFF key (32 B), nominal message. */
        {
            uint8_t key[32];
            static const uint8_t msg[] = "the quick brown fox";
            memset(key, 0xFFu, sizeof(key));
            SSF_ASSERT(SSFHMAC(h, key, sizeof(key), msg, sizeof(msg) - 1u,
                               macSSF, hashSize) == true);
            _OSSLHMAC(h, key, sizeof(key), msg, sizeof(msg) - 1u, macOSSL, hashSize);
            SSF_ASSERT(memcmp(macSSF, macOSSL, hashSize) == 0);
        }

        /* All-zero message of exactly the hash's block size. */
        {
            static const uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
            uint8_t msg[128] = {0};
            SSF_ASSERT(SSFHMAC(h, key, sizeof(key), msg, blockSize,
                               macSSF, hashSize) == true);
            _OSSLHMAC(h, key, sizeof(key), msg, blockSize, macOSSL, hashSize);
            SSF_ASSERT(memcmp(macSSF, macOSSL, hashSize) == 0);
        }

        /* Key length exactly == block size -- bypasses the long-key hash-the-key path. */
        {
            uint8_t key[128];
            static const uint8_t msg[] = "boundary";
            size_t i;
            for (i = 0; i < blockSize; i++) key[i] = (uint8_t)(i ^ 0x77u);
            SSF_ASSERT(SSFHMAC(h, key, blockSize, msg, sizeof(msg) - 1u,
                               macSSF, hashSize) == true);
            _OSSLHMAC(h, key, blockSize, msg, sizeof(msg) - 1u, macOSSL, hashSize);
            SSF_ASSERT(memcmp(macSSF, macOSSL, hashSize) == 0);
        }

        /* Incremental Update with one-byte chunks across multiple SHA blocks. */
        {
            uint8_t key[24];
            uint8_t msg[300];
            SSFHMACContext_t ctx = {0};
            size_t i;
            for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i + 0x88u);
            for (i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)((i * 7u) ^ 0xA5u);

            SSFHMACBegin(&ctx, h, key, sizeof(key));
            for (i = 0; i < sizeof(msg); i++) SSFHMACUpdate(&ctx, &msg[i], 1u);
            SSFHMACEnd(&ctx, macSSF, hashSize);
            SSFHMACDeInit(&ctx);

            _OSSLHMAC(h, key, sizeof(key), msg, sizeof(msg), macOSSL, hashSize);
            SSF_ASSERT(memcmp(macSSF, macOSSL, hashSize) == 0);
        }
    }
}

#endif /* SSF_HMAC_OSSL_VERIFY */

void SSFHMACUnitTest(void)
{
    uint8_t mac[64];

    /* ---- RFC 4231 Test Case 1: HMAC-SHA-256 ---- */
    {
        static const uint8_t key[20] = {
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu
        };
        static const uint8_t expected[32] = {
            0xB0u, 0x34u, 0x4Cu, 0x61u, 0xD8u, 0xDBu, 0x38u, 0x53u,
            0x5Cu, 0xA8u, 0xAFu, 0xCEu, 0xAFu, 0x0Bu, 0xF1u, 0x2Bu,
            0x88u, 0x1Du, 0xC2u, 0x00u, 0xC9u, 0x83u, 0x3Du, 0xA7u,
            0x26u, 0xE9u, 0x37u, 0x6Cu, 0x2Eu, 0x32u, 0xCFu, 0xF7u
        };

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key),
                   (const uint8_t *)"Hi There", 8, mac, 32u) == true);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- RFC 4231 Test Case 2: HMAC-SHA-256 ---- */
    {
        static const uint8_t expected[32] = {
            0x5Bu, 0xDCu, 0xC1u, 0x46u, 0xBFu, 0x60u, 0x75u, 0x4Eu,
            0x6Au, 0x04u, 0x24u, 0x26u, 0x08u, 0x95u, 0x75u, 0xC7u,
            0x5Au, 0x00u, 0x3Fu, 0x08u, 0x9Du, 0x27u, 0x39u, 0x83u,
            0x9Du, 0xECu, 0x58u, 0xB9u, 0x64u, 0xECu, 0x38u, 0x43u
        };

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256,
                   (const uint8_t *)"Jefe", 4,
                   (const uint8_t *)"what do ya want for nothing?", 28,
                   mac, 32u) == true);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- RFC 4231 Test Case 3: HMAC-SHA-256 ---- */
    {
        uint8_t key[20];
        uint8_t data[50];
        static const uint8_t expected[32] = {
            0x77u, 0x3Eu, 0xA9u, 0x1Eu, 0x36u, 0x80u, 0x0Eu, 0x46u,
            0x85u, 0x4Du, 0xB8u, 0xEBu, 0xD0u, 0x91u, 0x81u, 0xA7u,
            0x29u, 0x59u, 0x09u, 0x8Bu, 0x3Eu, 0xF8u, 0xC1u, 0x22u,
            0xD9u, 0x63u, 0x55u, 0x14u, 0xCEu, 0xD5u, 0x65u, 0xFEu
        };

        memset(key, 0xAAu, sizeof(key));
        memset(data, 0xDDu, sizeof(data));
        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key), data, sizeof(data),
                   mac, 32u) == true);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- RFC 2202 Test Case 1: HMAC-SHA-1 ---- */
    {
        static const uint8_t key[20] = {
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu
        };
        static const uint8_t expected[20] = {
            0xB6u, 0x17u, 0x31u, 0x86u, 0x55u, 0x05u, 0x72u, 0x64u,
            0xE2u, 0x8Bu, 0xC0u, 0xB6u, 0xFBu, 0x37u, 0x8Cu, 0x8Eu,
            0xF1u, 0x46u, 0xBEu, 0x00u
        };

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA1, key, sizeof(key),
                   (const uint8_t *)"Hi There", 8, mac, 20u) == true);
        SSF_ASSERT(memcmp(mac, expected, 20) == 0);
    }

    /* ---- RFC 2202 Test Case 2: HMAC-SHA-1 ---- */
    {
        static const uint8_t expected[20] = {
            0xEFu, 0xFCu, 0xDFu, 0x6Au, 0xE5u, 0xEBu, 0x2Fu, 0xA2u,
            0xD2u, 0x74u, 0x16u, 0xD5u, 0xF1u, 0x84u, 0xDFu, 0x9Cu,
            0x25u, 0x9Au, 0x7Cu, 0x79u
        };

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA1,
                   (const uint8_t *)"Jefe", 4,
                   (const uint8_t *)"what do ya want for nothing?", 28,
                   mac, 20u) == true);
        SSF_ASSERT(memcmp(mac, expected, 20) == 0);
    }

    /* ---- RFC 4231 Test Case 4: HMAC-SHA-256 with long key (131 bytes) ---- */
    {
        uint8_t longKey[131];
        static const uint8_t expected[32] = {
            0x60u, 0xE4u, 0x31u, 0x59u, 0x1Eu, 0xE0u, 0xB6u, 0x7Fu,
            0x0Du, 0x8Au, 0x26u, 0xAAu, 0xCBu, 0xF5u, 0xB7u, 0x7Fu,
            0x8Eu, 0x0Bu, 0xC6u, 0x21u, 0x37u, 0x28u, 0xC5u, 0x14u,
            0x05u, 0x46u, 0x04u, 0x0Fu, 0x0Eu, 0xE3u, 0x7Fu, 0x54u
        };

        memset(longKey, 0xAAu, sizeof(longKey));
        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, longKey, sizeof(longKey),
                   (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54,
                   mac, 32u) == true);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- HMAC-SHA-512 Test Case (RFC 4231 TC1) ---- */
    {
        static const uint8_t key[20] = {
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu
        };
        static const uint8_t expected[64] = {
            0x87u, 0xAAu, 0x7Cu, 0xDEu, 0xA5u, 0xEFu, 0x61u, 0x9Du,
            0x4Fu, 0xF0u, 0xB4u, 0x24u, 0x1Au, 0x1Du, 0x6Cu, 0xB0u,
            0x23u, 0x79u, 0xF4u, 0xE2u, 0xCEu, 0x4Eu, 0xC2u, 0x78u,
            0x7Au, 0xD0u, 0xB3u, 0x05u, 0x45u, 0xE1u, 0x7Cu, 0xDEu,
            0xDAu, 0xA8u, 0x33u, 0xB7u, 0xD6u, 0xB8u, 0xA7u, 0x02u,
            0x03u, 0x8Bu, 0x27u, 0x4Eu, 0xAEu, 0xA3u, 0xF4u, 0xE4u,
            0xBEu, 0x9Du, 0x91u, 0x4Eu, 0xEBu, 0x61u, 0xF1u, 0x70u,
            0x2Eu, 0x69u, 0x6Cu, 0x20u, 0x3Au, 0x12u, 0x68u, 0x54u
        };

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA512, key, sizeof(key),
                   (const uint8_t *)"Hi There", 8, mac, 64u) == true);
        SSF_ASSERT(memcmp(mac, expected, 64) == 0);
    }

    /* ---- Incremental: same as Test Case 1 but fed in chunks ---- */
    {
        static const uint8_t key[20] = {
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu
        };
        static const uint8_t expected[32] = {
            0xB0u, 0x34u, 0x4Cu, 0x61u, 0xD8u, 0xDBu, 0x38u, 0x53u,
            0x5Cu, 0xA8u, 0xAFu, 0xCEu, 0xAFu, 0x0Bu, 0xF1u, 0x2Bu,
            0x88u, 0x1Du, 0xC2u, 0x00u, 0xC9u, 0x83u, 0x3Du, 0xA7u,
            0x26u, 0xE9u, 0x37u, 0x6Cu, 0x2Eu, 0x32u, 0xCFu, 0xF7u
        };
        SSFHMACContext_t ctx = {0};

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSFHMACUpdate(&ctx, (const uint8_t *)"Hi ", 3);
        SSFHMACUpdate(&ctx, (const uint8_t *)"There", 5);
        SSFHMACEnd(&ctx, mac, 32u);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- Empty message ---- */
    {
        static const uint8_t key[] = { 0x01u, 0x02u, 0x03u, 0x04u };
        uint8_t mac1[32];
        bool nonZero = false;
        uint32_t i;

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key), NULL, 0,
                   mac1, sizeof(mac1)) == true);
        for (i = 0; i < 32u; i++) { if (mac1[i] != 0) nonZero = true; }
        SSF_ASSERT(nonZero == true);
    }

    /* ---- RFC 4231 Test Case 1: HMAC-SHA-384 ---- */
    {
        static const uint8_t key[20] = {
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu,
            0x0Bu, 0x0Bu, 0x0Bu, 0x0Bu
        };
        static const uint8_t expected[48] = {
            0xAFu, 0xD0u, 0x39u, 0x44u, 0xD8u, 0x48u, 0x95u, 0x62u,
            0x6Bu, 0x08u, 0x25u, 0xF4u, 0xABu, 0x46u, 0x90u, 0x7Fu,
            0x15u, 0xF9u, 0xDAu, 0xDBu, 0xE4u, 0x10u, 0x1Eu, 0xC6u,
            0x82u, 0xAAu, 0x03u, 0x4Cu, 0x7Cu, 0xEBu, 0xC5u, 0x9Cu,
            0xFAu, 0xEAu, 0x9Eu, 0xA9u, 0x07u, 0x6Eu, 0xDEu, 0x7Fu,
            0x4Au, 0xF1u, 0x52u, 0xE8u, 0xB2u, 0xFAu, 0x9Cu, 0xB6u
        };
        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA384, key, sizeof(key),
                   (const uint8_t *)"Hi There", 8, mac, 48u) == true);
        SSF_ASSERT(memcmp(mac, expected, 48) == 0);
    }

    /* ---- RFC 4231 Test Case 6: HMAC-SHA-384, 131-byte key (hashed first) ---- */
    {
        uint8_t longKey[131];
        static const uint8_t expected[48] = {
            0x4Eu, 0xCEu, 0x08u, 0x44u, 0x85u, 0x81u, 0x3Eu, 0x90u,
            0x88u, 0xD2u, 0xC6u, 0x3Au, 0x04u, 0x1Bu, 0xC5u, 0xB4u,
            0x4Fu, 0x9Eu, 0xF1u, 0x01u, 0x2Au, 0x2Bu, 0x58u, 0x8Fu,
            0x3Cu, 0xD1u, 0x1Fu, 0x05u, 0x03u, 0x3Au, 0xC4u, 0xC6u,
            0x0Cu, 0x2Eu, 0xF6u, 0xABu, 0x40u, 0x30u, 0xFEu, 0x82u,
            0x96u, 0x24u, 0x8Du, 0xF1u, 0x63u, 0xF4u, 0x49u, 0x52u
        };
        memset(longKey, 0xAAu, sizeof(longKey));
        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA384, longKey, sizeof(longKey),
                   (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54,
                   mac, 48u) == true);
        SSF_ASSERT(memcmp(mac, expected, 48) == 0);
    }

    /* ---- RFC 4231 Test Case 7: 131-byte key + 152-byte message, all SHA-2 variants ---- */
    {
        uint8_t longKey[131];
        static const char tc7Msg[] =
            "This is a test using a larger than block-size key and "
            "a larger than block-size data. The key needs to be hashed "
            "before being used by the HMAC algorithm.";
        /* sizeof includes the trailing NUL; the message itself is 152 bytes. */

        memset(longKey, 0xAAu, sizeof(longKey));

        /* HMAC-SHA-256 */
        {
            static const uint8_t expected[32] = {
                0x9Bu, 0x09u, 0xFFu, 0xA7u, 0x1Bu, 0x94u, 0x2Fu, 0xCBu,
                0x27u, 0x63u, 0x5Fu, 0xBCu, 0xD5u, 0xB0u, 0xE9u, 0x44u,
                0xBFu, 0xDCu, 0x63u, 0x64u, 0x4Fu, 0x07u, 0x13u, 0x93u,
                0x8Au, 0x7Fu, 0x51u, 0x53u, 0x5Cu, 0x3Au, 0x35u, 0xE2u
            };
            SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, longKey, sizeof(longKey),
                       (const uint8_t *)tc7Msg, sizeof(tc7Msg) - 1u,
                       mac, 32u) == true);
            SSF_ASSERT(memcmp(mac, expected, 32) == 0);
        }

        /* HMAC-SHA-384 */
        {
            static const uint8_t expected[48] = {
                0x66u, 0x17u, 0x17u, 0x8Eu, 0x94u, 0x1Fu, 0x02u, 0x0Du,
                0x35u, 0x1Eu, 0x2Fu, 0x25u, 0x4Eu, 0x8Fu, 0xD3u, 0x2Cu,
                0x60u, 0x24u, 0x20u, 0xFEu, 0xB0u, 0xB8u, 0xFBu, 0x9Au,
                0xDCu, 0xCEu, 0xBBu, 0x82u, 0x46u, 0x1Eu, 0x99u, 0xC5u,
                0xA6u, 0x78u, 0xCCu, 0x31u, 0xE7u, 0x99u, 0x17u, 0x6Du,
                0x38u, 0x60u, 0xE6u, 0x11u, 0x0Cu, 0x46u, 0x52u, 0x3Eu
            };
            SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA384, longKey, sizeof(longKey),
                       (const uint8_t *)tc7Msg, sizeof(tc7Msg) - 1u,
                       mac, 48u) == true);
            SSF_ASSERT(memcmp(mac, expected, 48) == 0);
        }

        /* HMAC-SHA-512 */
        {
            static const uint8_t expected[64] = {
                0xE3u, 0x7Bu, 0x6Au, 0x77u, 0x5Du, 0xC8u, 0x7Du, 0xBAu,
                0xA4u, 0xDFu, 0xA9u, 0xF9u, 0x6Eu, 0x5Eu, 0x3Fu, 0xFDu,
                0xDEu, 0xBDu, 0x71u, 0xF8u, 0x86u, 0x72u, 0x89u, 0x86u,
                0x5Du, 0xF5u, 0xA3u, 0x2Du, 0x20u, 0xCDu, 0xC9u, 0x44u,
                0xB6u, 0x02u, 0x2Cu, 0xACu, 0x3Cu, 0x49u, 0x82u, 0xB1u,
                0x0Du, 0x5Eu, 0xEBu, 0x55u, 0xC3u, 0xE4u, 0xDEu, 0x15u,
                0x13u, 0x46u, 0x76u, 0xFBu, 0x6Du, 0xE0u, 0x44u, 0x60u,
                0x65u, 0xC9u, 0x74u, 0x40u, 0xFAu, 0x8Cu, 0x6Au, 0x58u
            };
            SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA512, longKey, sizeof(longKey),
                       (const uint8_t *)tc7Msg, sizeof(tc7Msg) - 1u,
                       mac, 64u) == true);
            SSF_ASSERT(memcmp(mac, expected, 64) == 0);
        }
    }

    /* ---- SSFHMACGetHashSize ---- */
    SSF_ASSERT(SSFHMACGetHashSize(SSF_HMAC_HASH_SHA1) == 20u);
    SSF_ASSERT(SSFHMACGetHashSize(SSF_HMAC_HASH_SHA256) == 32u);
    SSF_ASSERT(SSFHMACGetHashSize(SSF_HMAC_HASH_SHA384) == 48u);
    SSF_ASSERT(SSFHMACGetHashSize(SSF_HMAC_HASH_SHA512) == 64u);

    /* Block-boundary message lengths under HMAC-SHA-256: incremental equals one-shot. */
    {
        static const size_t lens[] = {0u, 1u, 63u, 64u, 65u, 127u, 128u, 129u, 1024u};
        static uint8_t msg[1024];
        uint8_t key[16];
        uint8_t ref[32];
        uint8_t inc[32];
        size_t i;
        size_t k;

        for (i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;
        for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i + 0x10u);

        for (k = 0; k < (sizeof(lens) / sizeof(lens[0])); k++)
        {
            SSFHMACContext_t ctx = {0};
            size_t L = lens[k];

            SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key),
                       (L == 0u) ? NULL : msg, L, ref, 32u) == true);

            SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
            if (L > 0u) SSFHMACUpdate(&ctx, msg, L);
            SSFHMACEnd(&ctx, inc, 32u);
            SSFHMACDeInit(&ctx);
            SSF_ASSERT(memcmp(ref, inc, 32u) == 0);
        }
    }

    /* Incremental Begin / Update / End must match one-shot SSFHMAC for every hash variant. */
    {
        static const SSFHMACHash_t hashes[] = {
            SSF_HMAC_HASH_SHA1,
            SSF_HMAC_HASH_SHA256,
            SSF_HMAC_HASH_SHA384,
            SSF_HMAC_HASH_SHA512
        };
        uint8_t key[20];
        uint8_t msg[80];
        uint8_t ref[64];
        uint8_t inc[64];
        size_t i;
        size_t h;

        memset(key, 0xAAu, sizeof(key));
        for (i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i ^ 0x55u);

        for (h = 0; h < (sizeof(hashes) / sizeof(hashes[0])); h++)
        {
            SSFHMACContext_t ctx = {0};
            size_t hashSize = SSFHMACGetHashSize(hashes[h]);

            SSF_ASSERT(SSFHMAC(hashes[h], key, sizeof(key), msg, sizeof(msg),
                       ref, hashSize) == true);

            SSFHMACBegin(&ctx, hashes[h], key, sizeof(key));
            SSFHMACUpdate(&ctx, &msg[0],  10u);
            SSFHMACUpdate(&ctx, &msg[10], 20u);
            SSFHMACUpdate(&ctx, &msg[30], sizeof(msg) - 30u);
            SSFHMACEnd(&ctx, inc, hashSize);
            SSFHMACDeInit(&ctx);
            SSF_ASSERT(memcmp(ref, inc, hashSize) == 0);
        }
    }

    /* Zero-length Update (data NULL or not) is a no-op and must not affect the MAC. */
    {
        SSFHMACContext_t ctx = {0};
        uint8_t key[16];
        uint8_t msg[20];
        uint8_t ref[32];
        uint8_t inc[32];
        size_t i;

        memset(key, 0xBBu, sizeof(key));
        for (i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key), msg, sizeof(msg),
                   ref, 32u) == true);

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSFHMACUpdate(&ctx, msg,        0u); /* leading no-op, non-NULL data */
        SSFHMACUpdate(&ctx, NULL,       0u); /* leading no-op, NULL data */
        SSFHMACUpdate(&ctx, &msg[0],    5u);
        SSFHMACUpdate(&ctx, NULL,       0u); /* mid no-op */
        SSFHMACUpdate(&ctx, &msg[5],    15u);
        SSFHMACUpdate(&ctx, msg,        0u); /* trailing no-op */
        SSFHMACEnd(&ctx, inc, 32u);
        SSFHMACDeInit(&ctx);
        SSF_ASSERT(memcmp(ref, inc, 32u) == 0);
    }

    /* DeInit must zero every byte of the context, including a Begun-but-not-Ended one. */
    {
        SSFHMACContext_t ctx = {0};
        uint8_t key[16];
        const uint8_t *p;
        size_t i;

        memset(key, 0xCCu, sizeof(key));

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSFHMACUpdate(&ctx, (const uint8_t *)"abc", 3u);
        SSFHMACDeInit(&ctx);

        p = (const uint8_t *)&ctx;
        for (i = 0; i < sizeof(ctx); i++) SSF_ASSERT(p[i] == 0u);
    }

    /* Reuse one stack context across two hash + key combinations with DeInit between. */
    {
        SSFHMACContext_t ctx = {0};
        static const uint8_t key1[16] = {
            0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u, 0x18u,
            0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu, 0x20u
        };
        static const uint8_t key2[20] = {
            0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u, 0x28u,
            0x29u, 0x2Au, 0x2Bu, 0x2Cu, 0x2Du, 0x2Eu, 0x2Fu, 0x30u,
            0x31u, 0x32u, 0x33u, 0x34u
        };
        uint8_t mac1Ref[32];
        uint8_t mac1Inc[32];
        uint8_t mac2Ref[20];
        uint8_t mac2Inc[20];

        /* HMAC-SHA-256 under key1. */
        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key1, sizeof(key1),
                   (const uint8_t *)"hello", 5u, mac1Ref, 32u) == true);
        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key1, sizeof(key1));
        SSFHMACUpdate(&ctx, (const uint8_t *)"hello", 5u);
        SSFHMACEnd(&ctx, mac1Inc, 32u);
        SSFHMACDeInit(&ctx);
        SSF_ASSERT(memcmp(mac1Ref, mac1Inc, 32u) == 0);

        /* Reuse the same ctx for HMAC-SHA-1 under key2. */
        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA1, key2, sizeof(key2),
                   (const uint8_t *)"world", 5u, mac2Ref, 20u) == true);
        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA1, key2, sizeof(key2));
        SSFHMACUpdate(&ctx, (const uint8_t *)"world", 5u);
        SSFHMACEnd(&ctx, mac2Inc, 20u);
        SSFHMACDeInit(&ctx);
        SSF_ASSERT(memcmp(mac2Ref, mac2Inc, 20u) == 0);
    }

    /* An all-zero key (keyLen > 0) still produces a deterministic MAC. */
    {
        static const uint8_t zeroKey[32] = {0};
        bool nonZero = false;
        size_t i;

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, zeroKey, sizeof(zeroKey),
                   (const uint8_t *)"data", 4u, mac, 32u) == true);
        for (i = 0; i < 32u; i++) { if (mac[i] != 0u) nonZero = true; }
        SSF_ASSERT(nonZero == true);
    }

    /* Key length sweep under HMAC-SHA-256 (1..131 around block size): one-shot == incremental. */
    {
        static const size_t keyLens[] = {1u, 16u, 32u, 63u, 64u, 65u, 100u, 131u};
        uint8_t key[131];
        uint8_t msg[16];
        uint8_t ref[32];
        uint8_t inc[32];
        size_t i;
        size_t k;

        for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i ^ 0x33u);
        for (i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)i;

        for (k = 0; k < (sizeof(keyLens) / sizeof(keyLens[0])); k++)
        {
            SSFHMACContext_t ctx = {0};
            size_t L = keyLens[k];

            SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key, L, msg, sizeof(msg),
                       ref, 32u) == true);

            SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, L);
            SSFHMACUpdate(&ctx, msg, sizeof(msg));
            SSFHMACEnd(&ctx, inc, 32u);
            SSFHMACDeInit(&ctx);
            SSF_ASSERT(memcmp(ref, inc, 32u) == 0);
        }
    }

    /* size_t -> uint32_t truncation regression: small chunkMax via the test hook must match. */
    {
        uint8_t data[1024];
        uint8_t key[32];
        uint8_t macRef[32];
        uint8_t macChunked[32];
        SSFHMACContext_t ctx = {0};
        size_t i;
        size_t cs;
        static const uint32_t chunkSizes[] =
            {1u, 7u, 13u, 31u, 63u, 64u, 65u, 127u, 1023u, 1024u, 2048u};

        for (i = 0; i < sizeof(data); i++) data[i] = (uint8_t)((i * 0x9Eu) + 0xA5u);
        for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i + 0x55u);

        /* Reference: single-call MAC. */
        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key), data, sizeof(data),
                   macRef, sizeof(macRef)) == true);

        for (cs = 0; cs < (sizeof(chunkSizes) / sizeof(chunkSizes[0])); cs++)
        {
            SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
            _SSFHMACTestHookUpdateChunked(&ctx, data, sizeof(data), chunkSizes[cs]);
            SSFHMACEnd(&ctx, macChunked, sizeof(macChunked));
            SSF_ASSERT(memcmp(macRef, macChunked, 32u) == 0);
            SSFHMACDeInit(&ctx);
        }
    }

    /* Chunked Update across all hash dispatches. */
    {
        static const SSFHMACHash_t hashes[] = {
            SSF_HMAC_HASH_SHA1,
            SSF_HMAC_HASH_SHA256,
            SSF_HMAC_HASH_SHA384,
            SSF_HMAC_HASH_SHA512
        };
        uint8_t data[256];
        uint8_t key[16];
        uint8_t macRef[64];
        uint8_t macChunked[64];
        SSFHMACContext_t ctx = {0};
        size_t i;
        size_t h;

        for (i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(i ^ 0x33u);
        for (i = 0; i < sizeof(key); i++) key[i] = (uint8_t)i;

        for (h = 0; h < (sizeof(hashes) / sizeof(hashes[0])); h++)
        {
            size_t hashSize = SSFHMACGetHashSize(hashes[h]);
            SSF_ASSERT(SSFHMAC(hashes[h], key, sizeof(key), data, sizeof(data),
                       macRef, hashSize) == true);

            SSFHMACBegin(&ctx, hashes[h], key, sizeof(key));
            _SSFHMACTestHookUpdateChunked(&ctx, data, sizeof(data), 13u);
            SSFHMACEnd(&ctx, macChunked, hashSize);
            SSF_ASSERT(memcmp(macRef, macChunked, hashSize) == 0);
            SSFHMACDeInit(&ctx);
        }
    }

    /* Chunked Update with dataLen == 0 must be a no-op: the MAC equals the empty-message MAC. */
    {
        static const uint8_t key[16] = {0};
        uint8_t macRef[32];
        uint8_t macChunked[32];
        SSFHMACContext_t ctx = {0};

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key), NULL, 0,
                   macRef, sizeof(macRef)) == true);

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        _SSFHMACTestHookUpdateChunked(&ctx, NULL, 0u, 7u);
        SSFHMACEnd(&ctx, macChunked, sizeof(macChunked));
        SSF_ASSERT(memcmp(macRef, macChunked, 32u) == 0);
        SSFHMACDeInit(&ctx);
    }

    /* chunkMax == 0 must trip SSF_REQUIRE (would otherwise infinite-loop). */
    {
        uint8_t key[16] = {0};
        uint8_t data[4] = {0};
        SSFHMACContext_t ctx = {0};
        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSF_ASSERT_TEST(_SSFHMACTestHookUpdateChunked(&ctx, data, sizeof(data), 0u));
        SSFHMACDeInit(&ctx);
    }

    /* M3: an uninitialized context must trip a contract check on Update / End / DeInit. */
    {
        SSFHMACContext_t ctx = {0};
        uint8_t data[4] = {0};

        memset(&ctx, 0, sizeof(ctx));
        SSF_ASSERT_TEST(SSFHMACUpdate(&ctx, data, sizeof(data)));
        SSF_ASSERT_TEST(SSFHMACEnd(&ctx, mac, 32u));
        SSF_ASSERT_TEST(SSFHMACDeInit(&ctx));
    }

    /* M3: a DeInit'd context must trip on any later operation (incl. double DeInit). */
    {
        SSFHMACContext_t ctx = {0};
        uint8_t key[16] = {0};
        uint8_t data[4] = {0};

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSFHMACDeInit(&ctx);
        SSF_ASSERT_TEST(SSFHMACUpdate(&ctx, data, sizeof(data)));
        SSF_ASSERT_TEST(SSFHMACEnd(&ctx, mac, 32u));
        SSF_ASSERT_TEST(SSFHMACDeInit(&ctx));
    }

    /* Begin requires magic == 0 on entry: non-zero garbage is rejected. */
    {
        SSFHMACContext_t ctx;
        uint8_t key[16] = {0};

        /* Zeroed prior contents -- Begin succeeds. */
        memset(&ctx, 0, sizeof(ctx));
        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSFHMACUpdate(&ctx, (const uint8_t *)"abc", 3);
        SSFHMACEnd(&ctx, mac, 32u);
        SSFHMACDeInit(&ctx);

        /* Non-zero garbage -- Begin must reject. */
        memset(&ctx, 0xC3u, sizeof(ctx));
        SSF_ASSERT_TEST(SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key)));
    }

    /* Begin must refuse to re-init an already-initialized context. */
    {
        SSFHMACContext_t ctx = {0};
        uint8_t key[16] = {0};

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSF_ASSERT_TEST(SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA1, key, sizeof(key)));
        SSFHMACDeInit(&ctx);
    }

    /* Regression for M2: macOutSize must equal hashSize exactly. */
    {
        static const uint8_t key[16] = {0};
        uint8_t macOversize[64];
        uint8_t macUndersize[16];
        uint8_t macExact[32];
        SSFHMACContext_t ctx = {0};

        /* Exact match must succeed (positive control). */
        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSFHMACUpdate(&ctx, (const uint8_t *)"abc", 3);
        SSFHMACEnd(&ctx, macExact, 32u);
        SSFHMACDeInit(&ctx);

        /* macOutSize > hashSize must trip SSF_REQUIRE. */
        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSF_ASSERT_TEST(SSFHMACEnd(&ctx, macOversize, sizeof(macOversize)));
        SSFHMACDeInit(&ctx);

        /* macOutSize < hashSize must trip SSF_REQUIRE (was already caught; keep regression). */
        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSF_ASSERT_TEST(SSFHMACEnd(&ctx, macUndersize, sizeof(macUndersize)));
        SSFHMACDeInit(&ctx);

        /* Same checks via the single-call SSFHMAC entry point. */
        SSF_ASSERT_TEST(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key),
                                (const uint8_t *)"abc", 3, macOversize, sizeof(macOversize)));
        SSF_ASSERT_TEST(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key),
                                (const uint8_t *)"abc", 3, macUndersize, sizeof(macUndersize)));
    }

    /* DBC: SSFHMACGetHashSize must reject hash values outside (MIN, MAX). */
    {
        SSF_ASSERT_TEST(SSFHMACGetHashSize(SSF_HMAC_HASH_MIN));
        SSF_ASSERT_TEST(SSFHMACGetHashSize(SSF_HMAC_HASH_MAX));
        SSF_ASSERT_TEST(SSFHMACGetHashSize((SSFHMACHash_t)999));
        SSF_ASSERT_TEST(SSFHMACGetHashSize((SSFHMACHash_t)-42));
    }

    /* DBC: SSFHMACBegin rejects NULL ctx, NULL key, out-of-range hash and zero keyLen. */
    {
        SSFHMACContext_t ctx = {0};
        uint8_t key[16] = {0};

        SSF_ASSERT_TEST(SSFHMACBegin(NULL, SSF_HMAC_HASH_SHA256, key, sizeof(key)));
        SSF_ASSERT_TEST(SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, NULL, sizeof(key)));
        SSF_ASSERT_TEST(SSFHMACBegin(&ctx, SSF_HMAC_HASH_MIN, key, sizeof(key)));
        SSF_ASSERT_TEST(SSFHMACBegin(&ctx, SSF_HMAC_HASH_MAX, key, sizeof(key)));
        SSF_ASSERT_TEST(SSFHMACBegin(&ctx, (SSFHMACHash_t)999, key, sizeof(key)));
        SSF_ASSERT_TEST(SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, 0u));
    }

    /* DBC: SSFHMACUpdate rejects NULL ctx and NULL data with non-zero length. */
    {
        SSFHMACContext_t ctx = {0};
        uint8_t key[16] = {0};
        uint8_t data[4] = {0};

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSF_ASSERT_TEST(SSFHMACUpdate(NULL, data, sizeof(data)));
        SSF_ASSERT_TEST(SSFHMACUpdate(&ctx, NULL, sizeof(data)));
        SSFHMACDeInit(&ctx);
    }

    /* DBC: SSFHMACEnd rejects NULL ctx and NULL macOut (size mismatch covered by M2). */
    {
        SSFHMACContext_t ctx = {0};
        uint8_t key[16] = {0};

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSF_ASSERT_TEST(SSFHMACEnd(NULL, mac, 32u));
        SSF_ASSERT_TEST(SSFHMACEnd(&ctx, NULL, 32u));
        SSFHMACDeInit(&ctx);
    }

    /* DBC: SSFHMACDeInit rejects NULL ctx (magic mismatch covered by M3). */
    {
        SSF_ASSERT_TEST(SSFHMACDeInit(NULL));
    }

    /* DBC: single-call SSFHMAC parameter validation -- every required argument tested. */
    {
        uint8_t key[16] = {0};

        SSF_ASSERT_TEST(SSFHMAC(SSF_HMAC_HASH_SHA256, NULL, sizeof(key),
                                (const uint8_t *)"abc", 3, mac, 32u));
        SSF_ASSERT_TEST(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key),
                                NULL, 3, mac, 32u));
        SSF_ASSERT_TEST(SSFHMAC(SSF_HMAC_HASH_SHA256, key, sizeof(key),
                                (const uint8_t *)"abc", 3, NULL, 32u));
        SSF_ASSERT_TEST(SSFHMAC(SSF_HMAC_HASH_MIN, key, sizeof(key),
                                (const uint8_t *)"abc", 3, mac, 32u));
        SSF_ASSERT_TEST(SSFHMAC(SSF_HMAC_HASH_MAX, key, sizeof(key),
                                (const uint8_t *)"abc", 3, mac, 32u));
        SSF_ASSERT_TEST(SSFHMAC((SSFHMACHash_t)999, key, sizeof(key),
                                (const uint8_t *)"abc", 3, mac, 32u));
        SSF_ASSERT_TEST(SSFHMAC(SSF_HMAC_HASH_SHA256, key, 0u,
                                (const uint8_t *)"abc", 3, mac, 32u));
    }

#if SSF_HMAC_OSSL_VERIFY == 1
    /* Comprehensive cross-validation against OpenSSL: random fuzz plus corner cases. */
    _VerifyHMACAgainstOpenSSLRandom();
    _VerifyHMACCornerCasesAgainstOpenSSL();
#endif
}
#endif /* SSF_CONFIG_HMAC_UNIT_TEST */
