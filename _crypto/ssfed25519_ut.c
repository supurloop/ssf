/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfed25519_ut.c                                                                               */
/* Provides unit tests for the ssfed25519 Ed25519 module.                                        */
/* Test vectors from RFC 8032 Section 7.1.                                                       */
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
#include <string.h>
#include "ssfassert.h"
#include "ssfed25519.h"

#if SSF_CONFIG_ED25519_UNIT_TEST == 1

/* --------------------------------------------------------------------------------------------- */
/* Helper: convert hex string to bytes.                                                          */
/* --------------------------------------------------------------------------------------------- */
static void _HexToBytes(const char *hex, uint8_t *out, size_t outLen)
{
    size_t i;
    for (i = 0; i < outLen; i++)
    {
        uint8_t hi = (hex[i * 2] >= 'a') ? (uint8_t)(hex[i * 2] - 'a' + 10) :
                     (hex[i * 2] >= 'A') ? (uint8_t)(hex[i * 2] - 'A' + 10) :
                     (uint8_t)(hex[i * 2] - '0');
        uint8_t lo = (hex[i * 2 + 1] >= 'a') ? (uint8_t)(hex[i * 2 + 1] - 'a' + 10) :
                     (hex[i * 2 + 1] >= 'A') ? (uint8_t)(hex[i * 2 + 1] - 'A' + 10) :
                     (uint8_t)(hex[i * 2 + 1] - '0');
        out[i] = (uint8_t)((hi << 4) | lo);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* SSFEd25519UnitTest                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFEd25519UnitTest(void)
{
    /* ---- RFC 8032 Test Vector 1: empty message ---- */
    {
        uint8_t seed[32], expectedPub[32], expectedSig[64];
        uint8_t pubKey[32], sig[64];

        _HexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                     seed, 32);
        _HexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                     expectedPub, 32);
        _HexToBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                     "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                     expectedSig, 64);

        /* Derive public key */
        SSFEd25519PubKeyFromSeed(seed, pubKey);
        SSF_ASSERT(memcmp(pubKey, expectedPub, 32) == 0);

        /* Sign empty message */
        SSFEd25519Sign(seed, pubKey, NULL, 0, sig);
        SSF_ASSERT(memcmp(sig, expectedSig, 64) == 0);

        /* Verify */
        SSF_ASSERT(SSFEd25519Verify(pubKey, NULL, 0, sig) == true);

        /* Verify fails with wrong pubkey */
        pubKey[0] ^= 0x01u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, NULL, 0, sig) == false);
    }

    /* ---- RFC 8032 Test Vector 2: 1-byte message ---- */
    {
        uint8_t seed[32], expectedPub[32], expectedSig[64];
        uint8_t pubKey[32], sig[64];
        uint8_t msg[] = { 0x72u };

        _HexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                     seed, 32);
        _HexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                     expectedPub, 32);
        _HexToBytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                     expectedSig, 64);

        SSFEd25519PubKeyFromSeed(seed, pubKey);
        SSF_ASSERT(memcmp(pubKey, expectedPub, 32) == 0);

        SSFEd25519Sign(seed, pubKey, msg, sizeof(msg), sig);
        SSF_ASSERT(memcmp(sig, expectedSig, 64) == 0);

        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg), sig) == true);

        /* Verify fails with wrong message */
        msg[0] = 0x73u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg), sig) == false);
    }

    /* ---- RFC 8032 Test Vector 3: 2-byte message ---- */
    {
        uint8_t seed[32], expectedPub[32], expectedSig[64];
        uint8_t pubKey[32], sig[64];
        uint8_t msg[] = { 0xAFu, 0x82u };

        _HexToBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                     seed, 32);
        _HexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                     expectedPub, 32);
        _HexToBytes("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                     "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                     expectedSig, 64);

        SSFEd25519PubKeyFromSeed(seed, pubKey);
        SSF_ASSERT(memcmp(pubKey, expectedPub, 32) == 0);

        SSFEd25519Sign(seed, pubKey, msg, sizeof(msg), sig);
        SSF_ASSERT(memcmp(sig, expectedSig, 64) == 0);

        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg), sig) == true);
    }

    /* ---- KeyGen round-trip ---- */
    {
        uint8_t seed[32], pubKey[32], pubKey2[32], sig[64];
        const uint8_t msg[] = "Hello Ed25519";

        SSF_ASSERT(SSFEd25519KeyGen(seed, pubKey) == true);

        /* Derive again should match */
        SSFEd25519PubKeyFromSeed(seed, pubKey2);
        SSF_ASSERT(memcmp(pubKey, pubKey2, 32) == 0);

        /* Sign and verify */
        SSFEd25519Sign(seed, pubKey, msg, sizeof(msg) - 1u, sig);
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg) - 1u, sig) == true);

        /* Corrupted signature fails */
        sig[0] ^= 0x01u;
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg) - 1u, sig) == false);

        /* All-zero signature fails */
        memset(sig, 0, 64);
        SSF_ASSERT(SSFEd25519Verify(pubKey, msg, sizeof(msg) - 1u, sig) == false);
    }
}
#endif /* SSF_CONFIG_ED25519_UNIT_TEST */
