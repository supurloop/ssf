/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfrsa_ut.c                                                                                   */
/* Provides unit tests for the ssfrsa RSA module.                                                */
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
#include "ssfrsa.h"
#include "ssfsha2.h"

#if SSF_CONFIG_RSA_UNIT_TEST == 1

void SSFRSAUnitTest(void)
{
    /* ---- ssfbn enhancement: GCD ---- */
    {
        SSFBN_t a, b, r;

        /* gcd(12, 8) = 4 */
        SSFBNSetUint32(&a, 12u, 4);
        SSFBNSetUint32(&b, 8u, 4);
        SSFBNGcd(&r, &a, &b);
        SSF_ASSERT(r.limbs[0] == 4u);

        /* gcd(17, 13) = 1 (both prime) */
        SSFBNSetUint32(&a, 17u, 4);
        SSFBNSetUint32(&b, 13u, 4);
        SSFBNGcd(&r, &a, &b);
        SSF_ASSERT(r.limbs[0] == 1u);

        /* gcd(0, 5) = 5 */
        SSFBNSetUint32(&a, 0u, 4);
        SSFBNSetUint32(&b, 5u, 4);
        SSFBNGcd(&r, &a, &b);
        SSF_ASSERT(r.limbs[0] == 5u);
    }

    /* ---- ssfbn enhancement: ModInvExt (composite modulus) ---- */
    {
        SSFBN_t a, m, r, check;

        /* 3^(-1) mod 10 = 7 (since 3*7 = 21 = 1 mod 10) */
        /* 10 is composite, so Fermat's won't work but ExtGCD will */
        SSFBNSetUint32(&a, 3u, 4);
        SSFBNSetUint32(&m, 10u, 4);
        SSF_ASSERT(SSFBNModInvExt(&r, &a, &m) == true);
        SSFBNModMul(&check, &a, &r, &m);
        SSF_ASSERT(SSFBNIsOne(&check));

        /* 65537^(-1) mod 100 -- e inverse mod a composite */
        SSFBNSetUint32(&a, 65537u, 4);
        SSFBNSetUint32(&m, 100u, 4);
        /* gcd(65537, 100) = 1 since 65537 is prime and doesn't divide 100 */
        SSF_ASSERT(SSFBNModInvExt(&r, &a, &m) == true);
        SSFBNModMul(&check, &a, &r, &m);
        SSF_ASSERT(SSFBNIsOne(&check));

        /* No inverse: gcd(4, 10) = 2 != 1 */
        SSFBNSetUint32(&a, 4u, 4);
        SSFBNSetUint32(&m, 10u, 4);
        SSF_ASSERT(SSFBNModInvExt(&r, &a, &m) == false);
    }

    /* ---- RSA public key validation ---- */
    {
        /* A valid-looking but minimal public key won't validate with real RSA */
        /* but we can test that malformed DER is rejected */
        uint8_t badDer[] = { 0x30, 0x00 }; /* empty SEQUENCE */
        SSF_ASSERT(SSFRSAPubKeyIsValid(badDer, sizeof(badDer)) == false);
    }

#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
    /* ---- RSA-2048 key generation + PKCS#1 v1.5 sign + verify roundtrip ---- */
    {
        uint8_t privKeyDer[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        size_t privKeyDerLen;
        uint8_t pubKeyDer[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t pubKeyDerLen;

        /* Generate 2048-bit key pair */
        SSF_ASSERT(SSFRSAKeyGen(2048,
                   privKeyDer, sizeof(privKeyDer), &privKeyDerLen,
                   pubKeyDer, sizeof(pubKeyDer), &pubKeyDerLen) == true);
        SSF_ASSERT(privKeyDerLen > 0u);
        SSF_ASSERT(pubKeyDerLen > 0u);

        /* Validate generated public key */
        SSF_ASSERT(SSFRSAPubKeyIsValid(pubKeyDer, pubKeyDerLen) == true);

#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        /* PKCS#1 v1.5 sign + verify */
        {
            uint8_t hashVal[32];
            uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSFSHA256((const uint8_t *)"test message", 12, hashVal, sizeof(hashVal));

            SSF_ASSERT(SSFRSASignPKCS1(privKeyDer, privKeyDerLen,
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                       sig, sizeof(sig), &sigLen) == true);
            SSF_ASSERT(sigLen == 256u); /* 2048 bits = 256 bytes */

            /* Verify */
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubKeyDerLen,
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                       sig, sigLen) == true);

            /* Wrong hash fails */
            hashVal[0] ^= 0x01u;
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubKeyDerLen,
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                       sig, sigLen) == false);
            hashVal[0] ^= 0x01u;

            /* Corrupted signature fails */
            sig[0] ^= 0x01u;
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubKeyDerLen,
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                       sig, sigLen) == false);
            sig[0] ^= 0x01u;

            /* Deterministic: same input = same signature (PKCS#1 v1.5 is deterministic) */
            {
                uint8_t sig2[SSF_RSA_MAX_SIG_SIZE];
                size_t sig2Len;
                SSF_ASSERT(SSFRSASignPKCS1(privKeyDer, privKeyDerLen,
                           SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                           sig2, sizeof(sig2), &sig2Len) == true);
                SSF_ASSERT(sigLen == sig2Len);
                SSF_ASSERT(memcmp(sig, sig2, sigLen) == 0);
            }
        }
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */

#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        /* RSA-PSS sign + verify */
        {
            uint8_t hashVal[32];
            uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
            size_t sigLen;

            SSFSHA256((const uint8_t *)"pss test", 8, hashVal, sizeof(hashVal));

            SSF_ASSERT(SSFRSASignPSS(privKeyDer, privKeyDerLen,
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                       sig, sizeof(sig), &sigLen) == true);
            SSF_ASSERT(sigLen == 256u);

            /* Verify */
            SSF_ASSERT(SSFRSAVerifyPSS(pubKeyDer, pubKeyDerLen,
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                       sig, sigLen) == true);

            /* Wrong hash fails */
            hashVal[0] ^= 0x01u;
            SSF_ASSERT(SSFRSAVerifyPSS(pubKeyDer, pubKeyDerLen,
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                       sig, sigLen) == false);
            hashVal[0] ^= 0x01u;

            /* PSS is randomized: two signatures of the same hash should differ */
            {
                uint8_t sig2[SSF_RSA_MAX_SIG_SIZE];
                size_t sig2Len;
                SSF_ASSERT(SSFRSASignPSS(privKeyDer, privKeyDerLen,
                           SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                           sig2, sizeof(sig2), &sig2Len) == true);
                /* Both should verify */
                SSF_ASSERT(SSFRSAVerifyPSS(pubKeyDer, pubKeyDerLen,
                           SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                           sig2, sig2Len) == true);
                /* But should be different (with overwhelming probability) */
                SSF_ASSERT(memcmp(sig, sig2, sigLen) != 0);
            }
        }
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
    }
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */
}
#endif /* SSF_CONFIG_RSA_UNIT_TEST */
