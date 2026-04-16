/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhmac_ut.c                                                                                  */
/* Provides unit tests for the ssfhmac HMAC module.                                              */
/* Test vectors from RFC 4231 (HMAC-SHA-256) and RFC 2202 (HMAC-SHA-1).                          */
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
#include "ssfhmac.h"

#if SSF_CONFIG_HMAC_UNIT_TEST == 1

void SSFHMACUnitTest(void)
{
    uint8_t mac[64];

    /* ---- RFC 4231 Test Case 1: HMAC-SHA-256 ---- */
    /* Key:  0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes) */
    /* Data: "Hi There" */
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
                   (const uint8_t *)"Hi There", 8, mac, sizeof(mac)) == true);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- RFC 4231 Test Case 2: HMAC-SHA-256 ---- */
    /* Key:  "Jefe" */
    /* Data: "what do ya want for nothing?" */
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
                   mac, sizeof(mac)) == true);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- RFC 4231 Test Case 3: HMAC-SHA-256 ---- */
    /* Key:  aaaa...aa (20 bytes of 0xaa) */
    /* Data: dddd...dd (50 bytes of 0xdd) */
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
                   mac, sizeof(mac)) == true);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- RFC 2202 Test Case 1: HMAC-SHA-1 ---- */
    /* Key:  0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes) */
    /* Data: "Hi There" */
    /* Expected: b617318655057264e28bc0b6fb378c8ef146be00 */
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
                   (const uint8_t *)"Hi There", 8, mac, sizeof(mac)) == true);
        SSF_ASSERT(memcmp(mac, expected, 20) == 0);
    }

    /* ---- RFC 2202 Test Case 2: HMAC-SHA-1 ---- */
    /* Key: "Jefe" */
    /* Data: "what do ya want for nothing?" */
    /* Expected: effcdf6ae5eb2fa2d27416d5f184df9c259a7c79 */
    {
        static const uint8_t expected[20] = {
            0xEFu, 0xFCu, 0xDFu, 0x6Au, 0xE5u, 0xEBu, 0x2Fu, 0xA2u,
            0xD2u, 0x74u, 0x16u, 0xD5u, 0xF1u, 0x84u, 0xDFu, 0x9Cu,
            0x25u, 0x9Au, 0x7Cu, 0x79u
        };

        SSF_ASSERT(SSFHMAC(SSF_HMAC_HASH_SHA1,
                   (const uint8_t *)"Jefe", 4,
                   (const uint8_t *)"what do ya want for nothing?", 28,
                   mac, sizeof(mac)) == true);
        SSF_ASSERT(memcmp(mac, expected, 20) == 0);
    }

    /* ---- RFC 4231 Test Case 4: HMAC-SHA-256 with long key (131 bytes) ---- */
    /* Key: aa repeated 131 times (key > block size, so it gets hashed) */
    /* Data: "Test Using Larger Than Block-Size Key - Hash Key First" */
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
                   mac, sizeof(mac)) == true);
        SSF_ASSERT(memcmp(mac, expected, 32) == 0);
    }

    /* ---- HMAC-SHA-512 Test Case (RFC 4231 TC1) ---- */
    /* Key:  0b * 20 */
    /* Data: "Hi There" */
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
                   (const uint8_t *)"Hi There", 8, mac, sizeof(mac)) == true);
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
        SSFHMACContext_t ctx;

        SSFHMACBegin(&ctx, SSF_HMAC_HASH_SHA256, key, sizeof(key));
        SSFHMACUpdate(&ctx, (const uint8_t *)"Hi ", 3);
        SSFHMACUpdate(&ctx, (const uint8_t *)"There", 5);
        SSFHMACEnd(&ctx, mac, sizeof(mac));
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

    /* ---- SSFHMACGetHashSize ---- */
    SSF_ASSERT(SSFHMACGetHashSize(SSF_HMAC_HASH_SHA1) == 20u);
    SSF_ASSERT(SSFHMACGetHashSize(SSF_HMAC_HASH_SHA256) == 32u);
    SSF_ASSERT(SSFHMACGetHashSize(SSF_HMAC_HASH_SHA384) == 48u);
    SSF_ASSERT(SSFHMACGetHashSize(SSF_HMAC_HASH_SHA512) == 64u);
}
#endif /* SSF_CONFIG_HMAC_UNIT_TEST */
