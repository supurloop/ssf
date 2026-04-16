/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfhkdf_ut.c                                                                                  */
/* Provides unit tests for the ssfhkdf HKDF module.                                              */
/* Test vectors from RFC 5869 appendix A.                                                        */
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
#include "ssfhkdf.h"

#if SSF_CONFIG_HKDF_UNIT_TEST == 1

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
}
#endif /* SSF_CONFIG_HKDF_UNIT_TEST */
