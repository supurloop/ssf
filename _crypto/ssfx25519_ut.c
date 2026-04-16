/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfx25519_ut.c                                                                                */
/* Provides unit tests for the ssfx25519 X25519 module.                                          */
/* Test vectors from RFC 7748 Section 6.1.                                                       */
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
#include "ssfassert.h"
#include "ssfx25519.h"

#if SSF_CONFIG_X25519_UNIT_TEST == 1

void SSFX25519UnitTest(void)
{
    /* ---- RFC 7748 Section 6.1: Test Vector 1 ---- */
    {
        /* Alice's private key */
        static const uint8_t privA[] = {
            0x77u, 0x07u, 0x6Du, 0x0Au, 0x73u, 0x18u, 0xA5u, 0x7Du,
            0x3Cu, 0x16u, 0xC1u, 0x72u, 0x51u, 0xB2u, 0x66u, 0x45u,
            0xDFu, 0x4Cu, 0x2Fu, 0x87u, 0xEBu, 0xC0u, 0x99u, 0x2Au,
            0xB1u, 0x77u, 0xFBu, 0xA5u, 0x1Du, 0xB9u, 0x2Cu, 0x2Au
        };
        /* Alice's public key = privA * basepoint */
        static const uint8_t expectedPubA[] = {
            0x85u, 0x20u, 0xF0u, 0x09u, 0x89u, 0x30u, 0xA7u, 0x54u,
            0x74u, 0x8Bu, 0x7Du, 0xDCu, 0xB4u, 0x3Eu, 0xF7u, 0x5Au,
            0x0Du, 0xBFu, 0x3Au, 0x0Du, 0x26u, 0x38u, 0x1Au, 0xF4u,
            0xEBu, 0xA4u, 0xA9u, 0x8Eu, 0xAAu, 0x9Bu, 0x4Eu, 0x6Au
        };
        /* Bob's private key */
        static const uint8_t privB[] = {
            0x5Du, 0xABu, 0x08u, 0x7Eu, 0x62u, 0x4Au, 0x8Au, 0x4Bu,
            0x79u, 0xE1u, 0x7Fu, 0x8Bu, 0x83u, 0x80u, 0x0Eu, 0xE6u,
            0x6Fu, 0x3Bu, 0xB1u, 0x29u, 0x26u, 0x18u, 0xB6u, 0xFDu,
            0x1Cu, 0x2Fu, 0x8Bu, 0x27u, 0xFFu, 0x88u, 0xE0u, 0xEBu
        };
        /* Bob's public key = privB * basepoint */
        static const uint8_t expectedPubB[] = {
            0xDEu, 0x9Eu, 0xDBu, 0x7Du, 0x7Bu, 0x7Du, 0xC1u, 0xB4u,
            0xD3u, 0x5Bu, 0x61u, 0xC2u, 0xECu, 0xE4u, 0x35u, 0x37u,
            0x3Fu, 0x83u, 0x43u, 0xC8u, 0x5Bu, 0x78u, 0x67u, 0x4Du,
            0xADu, 0xFCu, 0x7Eu, 0x14u, 0x6Fu, 0x88u, 0x2Bu, 0x4Fu
        };
        /* Shared secret = privA * pubB = privB * pubA */
        static const uint8_t expectedSecret[] = {
            0x4Au, 0x5Du, 0x9Du, 0x5Bu, 0xA4u, 0xCEu, 0x2Du, 0xE1u,
            0x72u, 0x8Eu, 0x3Bu, 0xF4u, 0x80u, 0x35u, 0x0Fu, 0x25u,
            0xE0u, 0x7Eu, 0x21u, 0xC9u, 0x47u, 0xD1u, 0x9Eu, 0x33u,
            0x76u, 0xF0u, 0x9Bu, 0x3Cu, 0x1Eu, 0x16u, 0x17u, 0x42u
        };
        uint8_t pubA[32], pubB[32], secretA[32], secretB[32];

        /* Compute public keys */
        SSFX25519PubKeyFromPrivKey(privA, pubA);
        SSF_ASSERT(memcmp(pubA, expectedPubA, 32) == 0);

        SSFX25519PubKeyFromPrivKey(privB, pubB);
        SSF_ASSERT(memcmp(pubB, expectedPubB, 32) == 0);

        /* Compute shared secrets from both sides */
        SSF_ASSERT(SSFX25519ComputeSecret(privA, pubB, secretA) == true);
        SSF_ASSERT(SSFX25519ComputeSecret(privB, pubA, secretB) == true);

        SSF_ASSERT(memcmp(secretA, expectedSecret, 32) == 0);
        SSF_ASSERT(memcmp(secretB, expectedSecret, 32) == 0);
    }

    /* ---- RFC 7748 Section 5.2: Iterated test (1 iteration as sanity check) ---- */
    {
        /* Start: k = u = 9 (basepoint) */
        uint8_t k[32] = { 9 };
        uint8_t u[32] = { 9 };
        uint8_t out[32];

        /* After 1 iteration: k = X25519(9, 9) */
        static const uint8_t expected1[] = {
            0x42u, 0x2Cu, 0x8Eu, 0x7Au, 0x62u, 0x27u, 0xD7u, 0xBCu,
            0xA1u, 0x35u, 0x0Bu, 0x3Eu, 0x2Bu, 0xB7u, 0x27u, 0x9Fu,
            0x78u, 0x97u, 0xB8u, 0x7Bu, 0xB6u, 0x85u, 0x4Bu, 0x78u,
            0x3Cu, 0x60u, 0xE8u, 0x03u, 0x11u, 0xAEu, 0x30u, 0x79u
        };

        SSFX25519PubKeyFromPrivKey(k, out);
        /* out = X25519(k=9, u_basepoint=9) */
        SSF_ASSERT(memcmp(out, expected1, 32) == 0);
    }

    /* ---- Key generation + ECDHE roundtrip ---- */
    {
        uint8_t privA[32], pubA[32];
        uint8_t privB[32], pubB[32];
        uint8_t secretA[32], secretB[32];

        SSF_ASSERT(SSFX25519KeyGen(privA, pubA) == true);
        SSF_ASSERT(SSFX25519KeyGen(privB, pubB) == true);

        /* Shared secrets must match */
        SSF_ASSERT(SSFX25519ComputeSecret(privA, pubB, secretA) == true);
        SSF_ASSERT(SSFX25519ComputeSecret(privB, pubA, secretB) == true);
        SSF_ASSERT(memcmp(secretA, secretB, 32) == 0);
    }

    /* ---- All-zero peer key rejection ---- */
    {
        uint8_t priv[32], pub[32], secret[32];
        uint8_t zeroPub[32];

        SSF_ASSERT(SSFX25519KeyGen(priv, pub) == true);
        memset(zeroPub, 0, 32);
        SSF_ASSERT(SSFX25519ComputeSecret(priv, zeroPub, secret) == false);
    }

    /* ---- Pub key derivation consistency ---- */
    {
        uint8_t priv[32], pub1[32], pub2[32];

        SSF_ASSERT(SSFX25519KeyGen(priv, pub1) == true);
        SSFX25519PubKeyFromPrivKey(priv, pub2);
        SSF_ASSERT(memcmp(pub1, pub2, 32) == 0);
    }
}
#endif /* SSF_CONFIG_X25519_UNIT_TEST */
