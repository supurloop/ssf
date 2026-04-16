/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfecdsa_ut.c                                                                                 */
/* Provides unit tests for the ssfecdsa ECDSA/ECDH module.                                      */
/* Test vectors from RFC 6979 appendix A.2.5 (P-256/SHA-256).                                   */
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
#include "ssfecdsa.h"
#include "ssfsha2.h"

#if SSF_CONFIG_ECDSA_UNIT_TEST == 1

void SSFECDSAUnitTest(void)
{
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* ---- RFC 6979 A.2.5: P-256/SHA-256 sign and verify ---- */
    {
        /* Private key from RFC 6979 A.2.5 */
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };

        /* Corresponding public key (SEC 1 uncompressed) */
        static const uint8_t pubKey[] = {
            0x04u,
            0x60u, 0xFEu, 0xD4u, 0xBAu, 0x25u, 0x5Au, 0x9Du, 0x31u,
            0xC9u, 0x61u, 0xEBu, 0x74u, 0xC6u, 0x35u, 0x6Du, 0x68u,
            0xC0u, 0x49u, 0xB8u, 0x92u, 0x3Bu, 0x61u, 0xFAu, 0x6Cu,
            0xE6u, 0x69u, 0x62u, 0x2Eu, 0x60u, 0xF2u, 0x9Fu, 0xB6u,
            0x79u, 0x03u, 0xFEu, 0x10u, 0x08u, 0xB8u, 0xBCu, 0x99u,
            0xA4u, 0x1Au, 0xE9u, 0xE9u, 0x56u, 0x28u, 0xBCu, 0x64u,
            0xF2u, 0xF1u, 0xB2u, 0x0Cu, 0x2Du, 0x7Eu, 0x9Fu, 0x51u,
            0x77u, 0xA3u, 0xC2u, 0x94u, 0xD4u, 0x46u, 0x22u, 0x99u
        };

        uint8_t hash[32];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        /* Hash "sample" with SHA-256 */
        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));

        /* Sign */
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(sigLen > 0u);
        SSF_ASSERT(sigLen <= SSF_ECDSA_MAX_SIG_SIZE);

        /* Verify the signature we just created */
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey),
                   hash, sizeof(hash), sig, sigLen) == true);

        /* Verify with wrong hash fails */
        {
            uint8_t badHash[32];
            memcpy(badHash, hash, sizeof(hash));
            badHash[0] ^= 0x01u;
            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey),
                       badHash, sizeof(badHash), sig, sigLen) == false);
        }

        /* Verify with wrong public key fails */
        {
            uint8_t badPub[65];
            memcpy(badPub, pubKey, sizeof(pubKey));
            badPub[1] ^= 0x01u; /* corrupt x-coordinate */
            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, badPub, sizeof(badPub),
                       hash, sizeof(hash), sig, sigLen) == false);
        }
    }

    /* ---- P-256: public key derivation from private key ---- */
    {
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
        static const uint8_t expectedPub[] = {
            0x04u,
            0x60u, 0xFEu, 0xD4u, 0xBAu, 0x25u, 0x5Au, 0x9Du, 0x31u,
            0xC9u, 0x61u, 0xEBu, 0x74u, 0xC6u, 0x35u, 0x6Du, 0x68u,
            0xC0u, 0x49u, 0xB8u, 0x92u, 0x3Bu, 0x61u, 0xFAu, 0x6Cu,
            0xE6u, 0x69u, 0x62u, 0x2Eu, 0x60u, 0xF2u, 0x9Fu, 0xB6u,
            0x79u, 0x03u, 0xFEu, 0x10u, 0x08u, 0xB8u, 0xBCu, 0x99u,
            0xA4u, 0x1Au, 0xE9u, 0xE9u, 0x56u, 0x28u, 0xBCu, 0x64u,
            0xF2u, 0xF1u, 0xB2u, 0x0Cu, 0x2Du, 0x7Eu, 0x9Fu, 0x51u,
            0x77u, 0xA3u, 0xC2u, 0x94u, 0xD4u, 0x46u, 0x22u, 0x99u
        };
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;

        SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P256,
                   privKey, sizeof(privKey),
                   pubKey, sizeof(pubKey), &pubKeyLen) == true);
        SSF_ASSERT(pubKeyLen == 65u);
        SSF_ASSERT(memcmp(pubKey, expectedPub, 65) == 0);
    }

    /* ---- P-256: public key validation ---- */
    {
        static const uint8_t goodPub[] = {
            0x04u,
            0x60u, 0xFEu, 0xD4u, 0xBAu, 0x25u, 0x5Au, 0x9Du, 0x31u,
            0xC9u, 0x61u, 0xEBu, 0x74u, 0xC6u, 0x35u, 0x6Du, 0x68u,
            0xC0u, 0x49u, 0xB8u, 0x92u, 0x3Bu, 0x61u, 0xFAu, 0x6Cu,
            0xE6u, 0x69u, 0x62u, 0x2Eu, 0x60u, 0xF2u, 0x9Fu, 0xB6u,
            0x79u, 0x03u, 0xFEu, 0x10u, 0x08u, 0xB8u, 0xBCu, 0x99u,
            0xA4u, 0x1Au, 0xE9u, 0xE9u, 0x56u, 0x28u, 0xBCu, 0x64u,
            0xF2u, 0xF1u, 0xB2u, 0x0Cu, 0x2Du, 0x7Eu, 0x9Fu, 0x51u,
            0x77u, 0xA3u, 0xC2u, 0x94u, 0xD4u, 0x46u, 0x22u, 0x99u
        };
        uint8_t badPub[65];

        SSF_ASSERT(SSFECDSAPubKeyIsValid(SSF_EC_CURVE_P256, goodPub, sizeof(goodPub)) == true);

        /* Invalid: all zeros */
        memset(badPub, 0, sizeof(badPub));
        badPub[0] = 0x04u;
        SSF_ASSERT(SSFECDSAPubKeyIsValid(SSF_EC_CURVE_P256, badPub, sizeof(badPub)) == false);
    }

    /* ---- P-256: key generation + sign + verify roundtrip ---- */
    {
        uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t hash[32];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        /* Generate key pair */
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privKey, sizeof(privKey),
                   pubKey, sizeof(pubKey), &pubKeyLen) == true);
        SSF_ASSERT(pubKeyLen == 65u);

        /* Validate generated public key */
        SSF_ASSERT(SSFECDSAPubKeyIsValid(SSF_EC_CURVE_P256, pubKey, pubKeyLen) == true);

        /* Hash a test message */
        SSFSHA256((const uint8_t *)"test message", 12, hash, sizeof(hash));

        /* Sign */
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, 32,
                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);

        /* Verify */
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, pubKeyLen,
                   hash, sizeof(hash), sig, sigLen) == true);
    }

    /* ---- P-256: ECDH key agreement ---- */
    {
        uint8_t privA[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubA[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubALen;
        uint8_t privB[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubB[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubBLen;
        uint8_t secretA[SSF_ECDH_MAX_SECRET_SIZE];
        size_t secretALen;
        uint8_t secretB[SSF_ECDH_MAX_SECRET_SIZE];
        size_t secretBLen;

        /* Generate two key pairs */
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privA, sizeof(privA), pubA, sizeof(pubA), &pubALen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privB, sizeof(privB), pubB, sizeof(pubB), &pubBLen) == true);

        /* Compute shared secrets */
        SSF_ASSERT(SSFECDHComputeSecret(SSF_EC_CURVE_P256,
                   privA, 32, pubB, pubBLen,
                   secretA, sizeof(secretA), &secretALen) == true);
        SSF_ASSERT(SSFECDHComputeSecret(SSF_EC_CURVE_P256,
                   privB, 32, pubA, pubALen,
                   secretB, sizeof(secretB), &secretBLen) == true);

        /* Shared secrets must match */
        SSF_ASSERT(secretALen == 32u);
        SSF_ASSERT(secretBLen == 32u);
        SSF_ASSERT(memcmp(secretA, secretB, 32) == 0);
    }

    /* ---- P-256: ECDH rejects invalid peer public key ---- */
    {
        uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t badPub[65];
        uint8_t secret[SSF_ECDH_MAX_SECRET_SIZE];
        size_t secretLen;

        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privKey, sizeof(privKey), pubKey, sizeof(pubKey), &pubKeyLen) == true);

        /* Invalid peer key: all zeros */
        memset(badPub, 0, sizeof(badPub));
        badPub[0] = 0x04u;
        SSF_ASSERT(SSFECDHComputeSecret(SSF_EC_CURVE_P256,
                   privKey, 32, badPub, sizeof(badPub),
                   secret, sizeof(secret), &secretLen) == false);
    }

    /* ---- P-256: deterministic signing (same input = same signature) ---- */
    {
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
        uint8_t hash[32];
        uint8_t sig1[SSF_ECDSA_MAX_SIG_SIZE], sig2[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sig1Len, sig2Len;

        SSFSHA256((const uint8_t *)"deterministic", 13, hash, sizeof(hash));

        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig1, sizeof(sig1), &sig1Len) == true);
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig2, sizeof(sig2), &sig2Len) == true);

        /* RFC 6979 deterministic: same key + same hash = same signature */
        SSF_ASSERT(sig1Len == sig2Len);
        SSF_ASSERT(memcmp(sig1, sig2, sig1Len) == 0);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
}
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */
