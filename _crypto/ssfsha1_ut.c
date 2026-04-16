/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfsha1_ut.c                                                                                  */
/* Provides unit tests for the ssfsha1 SHA-1 hash module.                                        */
/* Test vectors from RFC 3174 appendix A and FIPS 180-1.                                         */
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
#include "ssfsha1.h"

#if SSF_CONFIG_SHA1_UNIT_TEST == 1

void SSFSHA1UnitTest(void)
{
    uint8_t hash[SSF_SHA1_HASH_SIZE];

    /* ---- Test vector 1: "abc" (RFC 3174) ---- */
    /* SHA1("abc") = A9993E36 4706816A BA3E2571 7850C26C 9CD0D89D */
    {
        static const uint8_t expected[SSF_SHA1_HASH_SIZE] = {
            0xA9u, 0x99u, 0x3Eu, 0x36u, 0x47u, 0x06u, 0x81u, 0x6Au,
            0xBAu, 0x3Eu, 0x25u, 0x71u, 0x78u, 0x50u, 0xC2u, 0x6Cu,
            0x9Cu, 0xD0u, 0xD8u, 0x9Du
        };

        SSFSHA1((const uint8_t *)"abc", 3, hash);
        SSF_ASSERT(memcmp(hash, expected, SSF_SHA1_HASH_SIZE) == 0);
    }

    /* ---- Test vector 2: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" ---- */
    /* SHA1 = 84983E44 1C3BD26E BAAE4AA1 F95129E5 E54670F1 */
    {
        static const char *input =
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        static const uint8_t expected[SSF_SHA1_HASH_SIZE] = {
            0x84u, 0x98u, 0x3Eu, 0x44u, 0x1Cu, 0x3Bu, 0xD2u, 0x6Eu,
            0xBAu, 0xAEu, 0x4Au, 0xA1u, 0xF9u, 0x51u, 0x29u, 0xE5u,
            0xE5u, 0x46u, 0x70u, 0xF1u
        };

        SSFSHA1((const uint8_t *)input, 56, hash);
        SSF_ASSERT(memcmp(hash, expected, SSF_SHA1_HASH_SIZE) == 0);
    }

    /* ---- Test vector 3: empty string ---- */
    /* SHA1("") = DA39A3EE 5E6B4B0D 3255BFEF 95601890 AFD80709 */
    {
        static const uint8_t expected[SSF_SHA1_HASH_SIZE] = {
            0xDAu, 0x39u, 0xA3u, 0xEEu, 0x5Eu, 0x6Bu, 0x4Bu, 0x0Du,
            0x32u, 0x55u, 0xBFu, 0xEFu, 0x95u, 0x60u, 0x18u, 0x90u,
            0xAFu, 0xD8u, 0x07u, 0x09u
        };

        SSFSHA1(NULL, 0, hash);
        SSF_ASSERT(memcmp(hash, expected, SSF_SHA1_HASH_SIZE) == 0);
    }

    /* ---- Test vector 4: "a" repeated 1,000,000 times ---- */
    /* SHA1 = 34AA973C D4C4DAA4 F61EEB2B DBAD2731 6534016F */
    {
        static const uint8_t expected[SSF_SHA1_HASH_SIZE] = {
            0x34u, 0xAAu, 0x97u, 0x3Cu, 0xD4u, 0xC4u, 0xDAu, 0xA4u,
            0xF6u, 0x1Eu, 0xEBu, 0x2Bu, 0xDBu, 0xADu, 0x27u, 0x31u,
            0x65u, 0x34u, 0x01u, 0x6Fu
        };
        SSFSHA1Context_t ctx;
        uint32_t i;
        uint8_t chunk[100];

        memset(chunk, 'a', sizeof(chunk));
        SSFSHA1Begin(&ctx);
        for (i = 0; i < 10000u; i++)
        {
            SSFSHA1Update(&ctx, chunk, 100);
        }
        SSFSHA1End(&ctx, hash);
        SSF_ASSERT(memcmp(hash, expected, SSF_SHA1_HASH_SIZE) == 0);
    }

    /* ---- Test vector 5: WebSocket accept key computation (RFC 6455 section 4.2.2) ---- */
    /* Key: "dGhlIHNhbXBsZSBub25jZQ==" + GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"       */
    /* SHA1 = B3 7A 4F 2C C0 62 4F 16 90 F6 46 06 CF 38 59 45 B2 BE C4 EA               */
    {
        static const char *wsInput =
            "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        static const uint8_t expected[SSF_SHA1_HASH_SIZE] = {
            0xB3u, 0x7Au, 0x4Fu, 0x2Cu, 0xC0u, 0x62u, 0x4Fu, 0x16u,
            0x90u, 0xF6u, 0x46u, 0x06u, 0xCFu, 0x38u, 0x59u, 0x45u,
            0xB2u, 0xBEu, 0xC4u, 0xEAu
        };
        uint32_t len = 0;
        while (wsInput[len] != '\0') len++;

        SSFSHA1((const uint8_t *)wsInput, len, hash);
        SSF_ASSERT(memcmp(hash, expected, SSF_SHA1_HASH_SIZE) == 0);
    }

    /* ---- Incremental update: same as test vector 1 but fed byte-by-byte ---- */
    {
        static const uint8_t expected[SSF_SHA1_HASH_SIZE] = {
            0xA9u, 0x99u, 0x3Eu, 0x36u, 0x47u, 0x06u, 0x81u, 0x6Au,
            0xBAu, 0x3Eu, 0x25u, 0x71u, 0x78u, 0x50u, 0xC2u, 0x6Cu,
            0x9Cu, 0xD0u, 0xD8u, 0x9Du
        };
        SSFSHA1Context_t ctx;

        SSFSHA1Begin(&ctx);
        SSFSHA1Update(&ctx, (const uint8_t *)"a", 1);
        SSFSHA1Update(&ctx, (const uint8_t *)"b", 1);
        SSFSHA1Update(&ctx, (const uint8_t *)"c", 1);
        SSFSHA1End(&ctx, hash);
        SSF_ASSERT(memcmp(hash, expected, SSF_SHA1_HASH_SIZE) == 0);
    }

    /* ---- Exactly 64 bytes (one full block, no padding block) ---- */
    {
        SSFSHA1Context_t ctx;
        uint8_t input64[64];
        uint32_t i;

        for (i = 0; i < 64u; i++) input64[i] = (uint8_t)i;

        /* Just verify it completes without assertion failure */
        SSFSHA1Begin(&ctx);
        SSFSHA1Update(&ctx, input64, 64);
        SSFSHA1End(&ctx, hash);
        /* Hash should be non-zero */
        {
            bool allZero = true;
            for (i = 0; i < SSF_SHA1_HASH_SIZE; i++)
            {
                if (hash[i] != 0) { allZero = false; break; }
            }
            SSF_ASSERT(allZero == false);
        }
    }

    /* ---- Exactly 55 bytes (padding fits in same block) ---- */
    {
        uint8_t input55[55];
        memset(input55, 0x41u, 55); /* 55 'A's */

        SSFSHA1(input55, 55, hash);
        {
            bool allZero = true;
            uint32_t i;
            for (i = 0; i < SSF_SHA1_HASH_SIZE; i++)
            {
                if (hash[i] != 0) { allZero = false; break; }
            }
            SSF_ASSERT(allZero == false);
        }
    }

    /* ---- Exactly 56 bytes (padding requires an extra block) ---- */
    {
        uint8_t input56[56];
        memset(input56, 0x42u, 56);

        SSFSHA1(input56, 56, hash);
        {
            bool allZero = true;
            uint32_t i;
            for (i = 0; i < SSF_SHA1_HASH_SIZE; i++)
            {
                if (hash[i] != 0) { allZero = false; break; }
            }
            SSF_ASSERT(allZero == false);
        }
    }
}
#endif /* SSF_CONFIG_SHA1_UNIT_TEST */
