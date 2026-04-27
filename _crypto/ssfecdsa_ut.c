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

/* Cross-validate ECDSA sign/verify with OpenSSL on host platforms where libcrypto is linked.    */
#if (defined(__APPLE__) || defined(__linux__)) && (SSF_CONFIG_ECDSA_UNIT_TEST == 1)
#define SSF_ECDSA_OSSL_VERIFY 1
#else
#define SSF_ECDSA_OSSL_VERIFY 0
#endif

#if SSF_ECDSA_OSSL_VERIFY == 1
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
#endif

#if SSF_CONFIG_ECDSA_UNIT_TEST == 1

#if SSF_ECDSA_OSSL_VERIFY == 1
/* --------------------------------------------------------------------------------------------- */
/* ECDSA sign/verify interop helpers — bridge SSF privKey/pubKey/sig bytes to OpenSSL EC_KEY     */
/* and ECDSA_SIG, and back. Used to catch DER encoding / signature serialization bugs that       */
/* self-consistency tests miss.                                                                   */
/* --------------------------------------------------------------------------------------------- */

/* Build an OpenSSL EC_KEY for the given curve, with the SSF-format pubKey loaded. */
static EC_KEY *_ECDSAOSSLKeyFromPub(SSFECCurve_t curve,
                                    const uint8_t *pubKey, size_t pubKeyLen)
{
    int nid = (curve == SSF_EC_CURVE_P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
    EC_KEY *eckey = EC_KEY_new_by_curve_name(nid);
    EC_POINT *pt = NULL;
    SSF_ASSERT(eckey != NULL);
    pt = EC_POINT_new(EC_KEY_get0_group(eckey));
    SSF_ASSERT(pt != NULL);
    SSF_ASSERT(EC_POINT_oct2point(EC_KEY_get0_group(eckey), pt, pubKey, pubKeyLen, NULL) == 1);
    SSF_ASSERT(EC_KEY_set_public_key(eckey, pt) == 1);
    EC_POINT_free(pt);
    return eckey;
}

/* Set the private-key BIGNUM on an EC_KEY from SSF privKey bytes. */
static void _ECDSAOSSLSetPriv(EC_KEY *eckey, const uint8_t *privKey, size_t privKeyLen)
{
    BIGNUM *bnD = BN_bin2bn(privKey, (int)privKeyLen, NULL);
    SSF_ASSERT(bnD != NULL);
    SSF_ASSERT(EC_KEY_set_private_key(eckey, bnD) == 1);
    BN_free(bnD);
}
#endif /* SSF_ECDSA_OSSL_VERIFY */

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

    /* ---- P-256: projective verify check accepts a Jacobian R with non-1 Z ---- */
    /* Builds R = [k]G with k > 1 (so Z != 1 in Jacobian form) and confirms the new projective    */
    /* _SSFECDSAVerifyCheckR accepts the matching r and rejects a tampered r.                      */
    {
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rOk, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rBad, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);

        /* k = 12345 — any value > 1 produces a Jacobian R with Z != 1 after the doublings/adds. */
        SSFBNSetUint32(&k, 12345u, c->limbs);
        SSFECScalarMulBaseP256(&R, &k);

        /* Reference: convert R to affine and reduce x mod n to compute the expected r. */
        SSF_ASSERT(SSFECPointToAffine(&rx, &ry, &R, SSF_EC_CURVE_P256) == true);
        SSFBNCopy(&rOk, &rx);
        if (SSFBNCmp(&rOk, &c->n) >= 0) SSFBNSub(&rOk, &rOk, &c->n);

        /* Projective check should accept the canonical r and reject a tampered one. */
        SSF_ASSERT(_SSFECDSAVerifyCheckRForTest(SSF_EC_CURVE_P256, &R, &rOk) == true);
        SSFBNCopy(&rBad, &rOk);
        (void)SSFBNAddUint32(&rBad, &rBad, 1u);
        SSF_ASSERT(_SSFECDSAVerifyCheckRForTest(SSF_EC_CURVE_P256, &R, &rBad) == false);
    }

    /* ---- P-256: projective verify check exercises the wraparound branch ---- */
    /* Builds a synthetic R with Z=1 and X = n (smallest value triggering wraparound), then sets  */
    /* r = X - n = 0... no, r=0 is rejected upstream. Use X = n + 1 so r = 1 is a valid scalar.   */
    /* _SSFECDSAVerifyCheckR doesn't validate curve membership; it only does the projective       */
    /* comparison. r < p - n must hold for the wraparound branch to fire.                          */
    {
        SSFBN_DEFINE(rWrap, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rNotMatch, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(pMinusN, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);

        /* Sanity-check that r=1 sits below p-n on this curve so the wraparound branch will run. */
        SSFBNSub(&pMinusN, &c->p, &c->n);
        SSFBNSetUint32(&rWrap, 1u, c->limbs);
        SSF_ASSERT(SSFBNCmp(&rWrap, &pMinusN) < 0);

        /* Synthetic R: affine (Z=1), X = n + 1, Y arbitrary. (X - n) mod n = 1 = r. */
        SSFBNSetZero(&R.y, c->limbs);
        SSFBNSetOne(&R.z, c->limbs);
        (void)SSFBNAdd(&R.x, &c->n, &rWrap);  /* R.x = n + 1, < p since 1 < p - n */

        /* Wraparound branch: accepts r=1 because (1 + n) * 1² == n + 1 == R.x (mod p). */
        SSF_ASSERT(_SSFECDSAVerifyCheckRForTest(SSF_EC_CURVE_P256, &R, &rWrap) == true);

        /* Negative: r=2 should NOT match. (2 + n) * 1² = n + 2 != n + 1, and 2 * 1² = 2 != n+1. */
        SSFBNSetUint32(&rNotMatch, 2u, c->limbs);
        SSF_ASSERT(_SSFECDSAVerifyCheckRForTest(SSF_EC_CURVE_P256, &R, &rNotMatch) == false);
    }

    /* ---- (Gap 6) RFC 5903 §8.1 ECDH P-256 known-answer test ---- */
    /* Verifies SSFECDHComputeSecret produces the documented shared secret for a known privKey  */
    /* + peerPubKey pair from RFC 5903 §8.1. The existing Alice/Bob roundtrip test only verifies */
    /* self-consistency — this catches arithmetic bugs that would silently produce mutually-     */
    /* matching but incorrect shared secrets.                                                    */
    {
        /* RFC 5903 §8.1: i (initiator's privKey) */
        static const uint8_t privKey[] = {
            0xC8u, 0x8Fu, 0x01u, 0xF5u, 0x10u, 0xD9u, 0xACu, 0x3Fu,
            0x70u, 0xA2u, 0x92u, 0xDAu, 0xA2u, 0x31u, 0x6Du, 0xE5u,
            0x44u, 0xE9u, 0xAAu, 0xB8u, 0xAFu, 0xE8u, 0x40u, 0x49u,
            0xC6u, 0x2Au, 0x9Cu, 0x57u, 0x86u, 0x2Du, 0x14u, 0x33u
        };
        /* RFC 5903 §8.1: gr (responder's pubKey) in SEC1 uncompressed form */
        static const uint8_t peerPubKey[65] = {
            0x04u,
            /* grx */
            0xD1u, 0x2Du, 0xFBu, 0x52u, 0x89u, 0xC8u, 0xD4u, 0xF8u,
            0x12u, 0x08u, 0xB7u, 0x02u, 0x70u, 0x39u, 0x8Cu, 0x34u,
            0x22u, 0x96u, 0x97u, 0x0Au, 0x0Bu, 0xCCu, 0xB7u, 0x4Cu,
            0x73u, 0x6Fu, 0xC7u, 0x55u, 0x44u, 0x94u, 0xBFu, 0x63u,
            /* gry */
            0x56u, 0xFBu, 0xF3u, 0xCAu, 0x36u, 0x6Cu, 0xC2u, 0x3Eu,
            0x81u, 0x57u, 0x85u, 0x4Cu, 0x13u, 0xC5u, 0x8Du, 0x6Au,
            0xACu, 0x23u, 0xF0u, 0x46u, 0xADu, 0xA3u, 0x0Fu, 0x83u,
            0x53u, 0xE7u, 0x4Fu, 0x33u, 0x03u, 0x98u, 0x72u, 0xABu
        };
        /* RFC 5903 §8.1: zx (shared secret = x-coord of [i]gr = [r]gi) */
        static const uint8_t expectedZ[] = {
            0xD6u, 0x84u, 0x0Fu, 0x6Bu, 0x42u, 0xF6u, 0xEDu, 0xAFu,
            0xD1u, 0x31u, 0x16u, 0xE0u, 0xE1u, 0x25u, 0x65u, 0x20u,
            0x2Fu, 0xEFu, 0x8Eu, 0x9Eu, 0xCEu, 0x7Du, 0xCEu, 0x03u,
            0x81u, 0x24u, 0x64u, 0xD0u, 0x4Bu, 0x94u, 0x42u, 0xDEu
        };
        uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
        size_t sharedLen;

        SSF_ASSERT(SSFECDHComputeSecret(SSF_EC_CURVE_P256,
                   privKey, sizeof(privKey),
                   peerPubKey, sizeof(peerPubKey),
                   shared, sizeof(shared), &sharedLen) == true);
        SSF_ASSERT(sharedLen == sizeof(expectedZ));
        SSF_ASSERT(memcmp(shared, expectedZ, sizeof(expectedZ)) == 0);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* ---- RFC 5903 §8.2 ECDH P-384 known-answer test (using the symmetric (r, gi) → z form) ---- */
    /* ECDH is symmetric: [i]gr = [r]gi = z. We use (r, gi) here (responder's privKey + initiator's */
    /* pubKey) which gives the same expected zx.                                                     */
    {
        /* RFC 5903 §8.2: r (responder's privKey, 48 bytes) */
        static const uint8_t privKey[] = {
            0x41u, 0xCBu, 0x07u, 0x79u, 0xB4u, 0xBDu, 0xB8u, 0x5Du,
            0x47u, 0x84u, 0x67u, 0x25u, 0xFBu, 0xECu, 0x3Cu, 0x94u,
            0x30u, 0xFAu, 0xB4u, 0x6Cu, 0xC8u, 0xDCu, 0x50u, 0x60u,
            0x85u, 0x5Cu, 0xC9u, 0xBDu, 0xA0u, 0xAAu, 0x29u, 0x42u,
            0xE0u, 0x30u, 0x83u, 0x12u, 0x91u, 0x6Bu, 0x8Eu, 0xD2u,
            0x96u, 0x0Eu, 0x4Bu, 0xD5u, 0x5Au, 0x74u, 0x48u, 0xFCu
        };
        /* RFC 5903 §8.2: gi (initiator's pubKey) in SEC1 uncompressed form */
        static const uint8_t peerPubKey[97] = {
            0x04u,
            /* gix */
            0x66u, 0x78u, 0x42u, 0xD7u, 0xD1u, 0x80u, 0xACu, 0x2Cu,
            0xDEu, 0x6Fu, 0x74u, 0xF3u, 0x75u, 0x51u, 0xF5u, 0x57u,
            0x55u, 0xC7u, 0x64u, 0x5Cu, 0x20u, 0xEFu, 0x73u, 0xE3u,
            0x16u, 0x34u, 0xFEu, 0x72u, 0xB4u, 0xC5u, 0x5Eu, 0xE6u,
            0xDEu, 0x3Au, 0xC8u, 0x08u, 0xACu, 0xB4u, 0xBDu, 0xB4u,
            0xC8u, 0x87u, 0x32u, 0xAEu, 0xE9u, 0x5Fu, 0x41u, 0xAAu,
            /* giy */
            0x94u, 0x82u, 0xEDu, 0x1Fu, 0xC0u, 0xEEu, 0xB9u, 0xCAu,
            0xFCu, 0x49u, 0x84u, 0x62u, 0x5Cu, 0xCFu, 0xC2u, 0x3Fu,
            0x65u, 0x03u, 0x21u, 0x49u, 0xE0u, 0xE1u, 0x44u, 0xADu,
            0xA0u, 0x24u, 0x18u, 0x15u, 0x35u, 0xA0u, 0xF3u, 0x8Eu,
            0xEBu, 0x9Fu, 0xCFu, 0xF3u, 0xC2u, 0xC9u, 0x47u, 0xDAu,
            0xE6u, 0x9Bu, 0x4Cu, 0x63u, 0x45u, 0x73u, 0xA8u, 0x1Cu
        };
        /* RFC 5903 §8.2: zx (shared secret) */
        static const uint8_t expectedZ[] = {
            0x11u, 0x18u, 0x73u, 0x31u, 0xC2u, 0x79u, 0x96u, 0x2Du,
            0x93u, 0xD6u, 0x04u, 0x24u, 0x3Fu, 0xD5u, 0x92u, 0xCBu,
            0x9Du, 0x0Au, 0x92u, 0x6Fu, 0x42u, 0x2Eu, 0x47u, 0x18u,
            0x75u, 0x21u, 0x28u, 0x7Eu, 0x71u, 0x56u, 0xC5u, 0xC4u,
            0xD6u, 0x03u, 0x13u, 0x55u, 0x69u, 0xB9u, 0xE9u, 0xD0u,
            0x9Cu, 0xF5u, 0xD4u, 0xA2u, 0x70u, 0xF5u, 0x97u, 0x46u
        };
        uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
        size_t sharedLen;

        SSF_ASSERT(SSFECDHComputeSecret(SSF_EC_CURVE_P384,
                   privKey, sizeof(privKey),
                   peerPubKey, sizeof(peerPubKey),
                   shared, sizeof(shared), &sharedLen) == true);
        SSF_ASSERT(sharedLen == sizeof(expectedZ));
        SSF_ASSERT(memcmp(shared, expectedZ, sizeof(expectedZ)) == 0);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

#if SSF_ECDSA_OSSL_VERIFY == 1
    /* ====================================================================================== */
    /* === Sign-with-SSF / verify-with-OpenSSL (and reverse) interop ========================  */
    /* ====================================================================================== */
    /* Catches DER signature encoding bugs (length fields, ASN.1 INTEGER tag/leading-zero      */
    /* handling) and end-to-end serialization mismatches that the per-primitive KATs miss.     */
    /* Run for both directions on each enabled curve.                                           */
    printf("--- ssfecdsa OpenSSL sign/verify interop ---\n");

#if SSF_EC_CONFIG_ENABLE_P256 == 1
    {
        uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t hash[32];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;
        const char *messages[] = {
            "interop-msg-0", "interop-msg-1", "interop-msg-2",
            "interop-msg-3", "interop-msg-4"
        };
        size_t mi;

        /* === SSF signs → OpenSSL verifies (P-256/SHA-256) === */
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privKey, sizeof(privKey),
                   pubKey,  sizeof(pubKey), &pubKeyLen) == true);

        for (mi = 0; mi < sizeof(messages) / sizeof(messages[0]); mi++)
        {
            EC_KEY *eckey;
            const uint8_t *p;
            ECDSA_SIG *osslSig;
            int verifyResult;

            SSFSHA256((const uint8_t *)messages[mi], (uint32_t)strlen(messages[mi]),
                      hash, sizeof(hash));
            SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, 32u,
                       hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);

            /* Hand SSF's pubKey + DER sig to OpenSSL for verification. */
            eckey = _ECDSAOSSLKeyFromPub(SSF_EC_CURVE_P256, pubKey, pubKeyLen);
            p = sig;
            osslSig = d2i_ECDSA_SIG(NULL, &p, (long)sigLen);
            SSF_ASSERT(osslSig != NULL);  /* DER must parse */
            verifyResult = ECDSA_do_verify(hash, sizeof(hash), osslSig, eckey);
            SSF_ASSERT(verifyResult == 1);
            ECDSA_SIG_free(osslSig);
            EC_KEY_free(eckey);
        }

        /* === OpenSSL signs → SSF verifies (P-256/SHA-256) === */
        for (mi = 0; mi < sizeof(messages) / sizeof(messages[0]); mi++)
        {
            EC_KEY *eckey;
            ECDSA_SIG *osslSig;
            uint8_t osslDer[SSF_ECDSA_MAX_SIG_SIZE];
            uint8_t *derP = osslDer;
            int derLen;

            eckey = _ECDSAOSSLKeyFromPub(SSF_EC_CURVE_P256, pubKey, pubKeyLen);
            _ECDSAOSSLSetPriv(eckey, privKey, 32u);

            SSFSHA256((const uint8_t *)messages[mi], (uint32_t)strlen(messages[mi]),
                      hash, sizeof(hash));
            osslSig = ECDSA_do_sign(hash, sizeof(hash), eckey);
            SSF_ASSERT(osslSig != NULL);

            derLen = i2d_ECDSA_SIG(osslSig, &derP);
            SSF_ASSERT(derLen > 0 && derLen <= (int)sizeof(osslDer));
            ECDSA_SIG_free(osslSig);

            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256,
                       pubKey, pubKeyLen, hash, sizeof(hash),
                       osslDer, (size_t)derLen) == true);
            EC_KEY_free(eckey);
        }
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    {
        uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t hash[48];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;
        const char *messages[] = {
            "interop-msg-0", "interop-msg-1", "interop-msg-2",
            "interop-msg-3", "interop-msg-4"
        };
        size_t mi;

        /* === SSF signs → OpenSSL verifies (P-384/SHA-384) === */
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P384,
                   privKey, sizeof(privKey),
                   pubKey,  sizeof(pubKey), &pubKeyLen) == true);

        for (mi = 0; mi < sizeof(messages) / sizeof(messages[0]); mi++)
        {
            EC_KEY *eckey;
            const uint8_t *p;
            ECDSA_SIG *osslSig;

            SSFSHA384((const uint8_t *)messages[mi], (uint32_t)strlen(messages[mi]),
                      hash, sizeof(hash));
            SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P384, privKey, 48u,
                       hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);

            eckey = _ECDSAOSSLKeyFromPub(SSF_EC_CURVE_P384, pubKey, pubKeyLen);
            p = sig;
            osslSig = d2i_ECDSA_SIG(NULL, &p, (long)sigLen);
            SSF_ASSERT(osslSig != NULL);
            SSF_ASSERT(ECDSA_do_verify(hash, sizeof(hash), osslSig, eckey) == 1);
            ECDSA_SIG_free(osslSig);
            EC_KEY_free(eckey);
        }

        /* === OpenSSL signs → SSF verifies (P-384/SHA-384) === */
        for (mi = 0; mi < sizeof(messages) / sizeof(messages[0]); mi++)
        {
            EC_KEY *eckey;
            ECDSA_SIG *osslSig;
            uint8_t osslDer[SSF_ECDSA_MAX_SIG_SIZE];
            uint8_t *derP = osslDer;
            int derLen;

            eckey = _ECDSAOSSLKeyFromPub(SSF_EC_CURVE_P384, pubKey, pubKeyLen);
            _ECDSAOSSLSetPriv(eckey, privKey, 48u);

            SSFSHA384((const uint8_t *)messages[mi], (uint32_t)strlen(messages[mi]),
                      hash, sizeof(hash));
            osslSig = ECDSA_do_sign(hash, sizeof(hash), eckey);
            SSF_ASSERT(osslSig != NULL);

            derLen = i2d_ECDSA_SIG(osslSig, &derP);
            SSF_ASSERT(derLen > 0 && derLen <= (int)sizeof(osslDer));
            ECDSA_SIG_free(osslSig);

            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P384,
                       pubKey, pubKeyLen, hash, sizeof(hash),
                       osslDer, (size_t)derLen) == true);
            EC_KEY_free(eckey);
        }
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

    printf("--- end ssfecdsa OpenSSL interop ---\n");
#endif /* SSF_ECDSA_OSSL_VERIFY */

#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* ====================================================================================== */
    /* === Wycheproof ECDSA P-256/SHA-256 verify vectors (Google adversarial test suite) ====  */
    /* ====================================================================================== */
    /* 482 vectors covering edge cases that random KAT can't reach: malformed DER, integer    */
    /* overflow patterns, edge-case public keys, Shamir multiplication corner cases, BER vs   */
    /* DER encodings, invalid r/s ranges, etc. Counts mismatches without aborting on the      */
    /* first failure so we can survey the entire vector set in one run.                        */
    {
        #include "wycheproof_ecdsa_p256.h"
        uint8_t hash[32];
        uint16_t i;
        uint16_t pass = 0, mismatches = 0;

        printf("--- Wycheproof ECDSA P-256 verify (%u tests) ---\n",
               (unsigned)SSF_WYCHEPROOF_ECDSA_P256_NTESTS);
        for (i = 0; i < (uint16_t)SSF_WYCHEPROOF_ECDSA_P256_NTESTS; i++)
        {
            const _SSFWycheproofEcdsaP256Test_t *t = &_wp_P256_tests[i];
            bool got;

            SSFSHA256(t->msg, (uint32_t)t->msgLen, hash, sizeof(hash));
            got = SSFECDSAVerify(SSF_EC_CURVE_P256,
                                 t->pubKey, t->pubKeyLen,
                                 hash, sizeof(hash),
                                 t->sig, t->sigLen);

            if (got == t->expectedValid)
            {
                pass++;
            }
            else
            {
                mismatches++;
                printf("  tcId %4u: expected %s, got %s (sig %u bytes)\n",
                       (unsigned)t->tcId,
                       t->expectedValid ? "valid  " : "invalid",
                       got               ? "valid  " : "invalid",
                       (unsigned)t->sigLen);
            }
        }
        printf("--- Wycheproof ECDSA P-256: %u/%u pass, %u mismatches ---\n",
               (unsigned)pass, (unsigned)SSF_WYCHEPROOF_ECDSA_P256_NTESTS,
               (unsigned)mismatches);
        SSF_ASSERT(mismatches == 0u);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */
}
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */
