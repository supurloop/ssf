/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfecdsa_ut.c                                                                                 */
/* Provides unit tests for the ssfecdsa ECDSA/ECDH module.                                       */
/* Test vectors from RFC 6979 appendix A.2.5 (P-256/SHA-256).                                    */
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
#include "ssfassert.h"
#include "ssfecdsa.h"
#include "ssfsha2.h"
#include "ssfsha1.h"

/* Cross-validate ECDSA sign/verify with OpenSSL when SSF_CONFIG_HAVE_OPENSSL is 1. */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_ECDSA_UNIT_TEST == 1)
#define SSF_ECDSA_OSSL_VERIFY 1
#else
#define SSF_ECDSA_OSSL_VERIFY 0
#endif

#if SSF_ECDSA_OSSL_VERIFY == 1
/* Pin OpenSSL to the 1.1.1 API so the legacy EC_KEY/ECDSA/ECDH oracle has no deprecations. */
#define OPENSSL_API_COMPAT 10101
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <stdio.h>
#endif

#if SSF_CONFIG_ECDSA_UNIT_TEST == 1

#if SSF_ECDSA_OSSL_VERIFY == 1
/* --------------------------------------------------------------------------------------------- */
/* Interop helpers bridging SSF key/sig bytes to OpenSSL EC_KEY and ECDSA_SIG, and back. */
/* --------------------------------------------------------------------------------------------- */

/* Build an OpenSSL EC_KEY for the given curve, with the SSF-format pubKey loaded. */
static EC_KEY *_ECDSAOSSLKeyFromPub(SSFECCurve_t curve,
                                    const uint8_t *pubKey, size_t pubKeyLen)
{
    int nid;
    EC_KEY *eckey;
    EC_POINT *pt = NULL;

    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(pubKeyLen > 0u);

    nid = (curve == SSF_EC_CURVE_P256) ? NID_X9_62_prime256v1 : NID_secp384r1;
    eckey = EC_KEY_new_by_curve_name(nid);
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
    BIGNUM *bnD;

    SSF_REQUIRE(eckey != NULL);
    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(privKeyLen > 0u);

    bnD = BN_bin2bn(privKey, (int)privKeyLen, NULL);
    SSF_ASSERT(bnD != NULL);
    SSF_ASSERT(EC_KEY_set_private_key(eckey, bnD) == 1);
    BN_free(bnD);
}

/* Curve metadata bundle: byte sizes and OpenSSL NID. */
typedef struct
{
    int      nid; /* OpenSSL NID for the curve. */
    size_t   privBytes; /* Private-key serialized size. */
    size_t   pubBytes; /* Public-key uncompressed size (1 + 2 * field). */
    size_t   hashBytes; /* Recommended hash size (matches the curve's bit size). */
    size_t   secretBytes;/* ECDH shared-secret size (== field size). */
} _ECDSAOSSLCurveInfo_t;

/* Fill info with the byte sizes and OpenSSL NID of curve. */
static void _ECDSAOSSLCurveInfo(SSFECCurve_t curve, _ECDSAOSSLCurveInfo_t *info)
{
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(info != NULL);

    /* Is the curve P-256? */
    if (curve == SSF_EC_CURVE_P256)
    {
        /* Yes, use the 32-byte sizes */
        info->nid = NID_X9_62_prime256v1;
        info->privBytes = 32u;
        info->pubBytes = 65u;
        info->hashBytes = 32u;
        info->secretBytes = 32u;
    }
    else
    {
        /* No, it must be P-384 with 48-byte sizes */
        SSF_ASSERT(curve == SSF_EC_CURVE_P384);
        info->nid = NID_secp384r1;
        info->privBytes = 48u;
        info->pubBytes = 97u;
        info->hashBytes = 48u;
        info->secretBytes = 48u;
    }
}

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
/* --------------------------------------------------------------------------------------------- */
/* Random fuzz: every SSF<->OpenSSL direction on random keys and hashes per curve. */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyECDSARandomAgainstOpenSSL(SSFECCurve_t curve, uint16_t iters)
{
    _ECDSAOSSLCurveInfo_t info;
    uint16_t i;

    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(iters > 0u);

    _ECDSAOSSLCurveInfo(curve, &info);

    for (i = 0; i < iters; i++)
    {
        uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t  pubKeyLen = 0u;
        uint8_t hash[SSF_ECDSA_MAX_PRIV_KEY_SIZE]; /* hash size == priv size for these curves. */
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t  sigLen;

        /* === SSF generates the key, OpenSSL must accept it === */
        SSF_ASSERT(SSFECDSAKeyGen(curve,
                                  privKey, sizeof(privKey),
                                  pubKey,  sizeof(pubKey), &pubKeyLen) == true);
        SSF_ASSERT(pubKeyLen == info.pubBytes);
        {
            EC_KEY *eckey = _ECDSAOSSLKeyFromPub(curve, pubKey, pubKeyLen);
            _ECDSAOSSLSetPriv(eckey, privKey, info.privBytes);
            /* EC_KEY_check_key: priv in [1, n-1], pub on curve, priv * G == pub. */
            SSF_ASSERT(EC_KEY_check_key(eckey) == 1);
            EC_KEY_free(eckey);
        }

        /* === Random hash (simulates a digest of arbitrary content) === */
        SSF_ASSERT(RAND_bytes(hash, (int)info.hashBytes) == 1);

        /* === SSF signs -> OpenSSL verifies === */
        SSF_ASSERT(SSFECDSASign(curve, privKey, info.privBytes,
                                hash, info.hashBytes,
                                sig, sizeof(sig), &sigLen) == true);
        {
            EC_KEY *eckey = _ECDSAOSSLKeyFromPub(curve, pubKey, pubKeyLen);
            const uint8_t *p = sig;
            ECDSA_SIG *osslSig = d2i_ECDSA_SIG(NULL, &p, (long)sigLen);
            SSF_ASSERT(osslSig != NULL);
            SSF_ASSERT(ECDSA_do_verify(hash, (int)info.hashBytes, osslSig, eckey) == 1);
            ECDSA_SIG_free(osslSig);
            EC_KEY_free(eckey);
        }

        /* === OpenSSL signs (with the same SSF-generated key) -> SSF verifies === */
        {
            EC_KEY *eckey = _ECDSAOSSLKeyFromPub(curve, pubKey, pubKeyLen);
            ECDSA_SIG *osslSig;
            uint8_t osslDer[SSF_ECDSA_MAX_SIG_SIZE];
            uint8_t *derP = osslDer;
            int derLen;

            _ECDSAOSSLSetPriv(eckey, privKey, info.privBytes);
            osslSig = ECDSA_do_sign(hash, (int)info.hashBytes, eckey);
            SSF_ASSERT(osslSig != NULL);
            derLen = i2d_ECDSA_SIG(osslSig, &derP);
            SSF_ASSERT((derLen > 0) && (derLen <= (int)sizeof(osslDer)));
            ECDSA_SIG_free(osslSig);

            SSF_ASSERT(SSFECDSAVerify(curve, pubKey, pubKeyLen,
                                      hash, info.hashBytes,
                                      osslDer, (size_t)derLen) == true);
            EC_KEY_free(eckey);
        }

        /* === OpenSSL generates the key, SSF verifies a sig OpenSSL produced === */
        {
            EC_KEY *osslKey = EC_KEY_new_by_curve_name(info.nid);
            const EC_GROUP *grp;
            const EC_POINT *pub;
            size_t osslPubLen;
            uint8_t osslPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            ECDSA_SIG *osslSig;
            uint8_t osslDer[SSF_ECDSA_MAX_SIG_SIZE];
            uint8_t *derP = osslDer;
            int derLen;

            SSF_ASSERT(osslKey != NULL);
            SSF_ASSERT(EC_KEY_generate_key(osslKey) == 1);
            grp = EC_KEY_get0_group(osslKey);
            pub = EC_KEY_get0_public_key(osslKey);
            osslPubLen = EC_POINT_point2oct(grp, pub, POINT_CONVERSION_UNCOMPRESSED,
                                            osslPub, sizeof(osslPub), NULL);
            SSF_ASSERT(osslPubLen == info.pubBytes);

            osslSig = ECDSA_do_sign(hash, (int)info.hashBytes, osslKey);
            SSF_ASSERT(osslSig != NULL);
            derLen = i2d_ECDSA_SIG(osslSig, &derP);
            SSF_ASSERT(derLen > 0);
            ECDSA_SIG_free(osslSig);

            SSF_ASSERT(SSFECDSAVerify(curve, osslPub, osslPubLen,
                                      hash, info.hashBytes,
                                      osslDer, (size_t)derLen) == true);

            /* SSFECDSAPubKeyIsValid must agree with EC_KEY_check_key on the OpenSSL key. */
            SSF_ASSERT(SSFECDSAPubKeyIsValid(curve, osslPub, osslPubLen) == true);

            EC_KEY_free(osslKey);
        }
    }
}
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */

/* --------------------------------------------------------------------------------------------- */
/* ECDH cross-check: SSF and OpenSSL derive the same secret for mixed-origin keys. */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyECDHAgainstOpenSSL(SSFECCurve_t curve, uint16_t iters)
{
    _ECDSAOSSLCurveInfo_t info;
    uint16_t i;

    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(iters > 0u);

    _ECDSAOSSLCurveInfo(curve, &info);

    for (i = 0; i < iters; i++)
    {
        /* Two keypairs A and B. Both generated by SSF this iteration. */
        uint8_t privA[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubA [SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t  pubALen = 0u;
        uint8_t privB[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubB [SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t  pubBLen = 0u;
        uint8_t ssfSecret [SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t osslSecret[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        size_t  ssfSecretLen = 0u;
        EC_KEY *keyA;
        EC_KEY *keyB;
        const EC_POINT *pubBPoint;
        int      n;

        SSF_ASSERT(SSFECDSAKeyGen(curve, privA, sizeof(privA),
                                  pubA, sizeof(pubA), &pubALen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(curve, privB, sizeof(privB),
                                  pubB, sizeof(pubB), &pubBLen) == true);

        /* === SSF: compute A<->B via SSFECDH === */
        SSF_ASSERT(SSFECDHComputeSecret(curve, privA, info.privBytes, pubB, pubBLen,
                                        ssfSecret, sizeof(ssfSecret),
                                        &ssfSecretLen) == true);
        SSF_ASSERT(ssfSecretLen == info.secretBytes);

        /* === OpenSSL: same operation, same inputs (priv from A, pub from B) === */
        keyA = _ECDSAOSSLKeyFromPub(curve, pubA, pubALen);
        _ECDSAOSSLSetPriv(keyA, privA, info.privBytes);
        keyB = _ECDSAOSSLKeyFromPub(curve, pubB, pubBLen);
        pubBPoint = EC_KEY_get0_public_key(keyB);

        n = ECDH_compute_key(osslSecret, sizeof(osslSecret), pubBPoint, keyA, NULL);
        SSF_ASSERT(n == (int)info.secretBytes);
        SSF_ASSERT(memcmp(ssfSecret, osslSecret, info.secretBytes) == 0);

        EC_KEY_free(keyA);
        EC_KEY_free(keyB);

        /* === Mixed origin: priv from SSF, peer pub from a fresh OpenSSL keypair === */
        {
            EC_KEY *osslPeer = EC_KEY_new_by_curve_name(info.nid);
            const EC_GROUP *grp;
            uint8_t osslPub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t  osslPubLen;
            EC_KEY *keyAself;
            uint8_t ssfSecret2[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            uint8_t osslSecret2[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
            size_t  ssfSecret2Len = 0u;

            SSF_ASSERT(osslPeer != NULL);
            SSF_ASSERT(EC_KEY_generate_key(osslPeer) == 1);
            grp = EC_KEY_get0_group(osslPeer);
            osslPubLen = EC_POINT_point2oct(grp, EC_KEY_get0_public_key(osslPeer),
                                            POINT_CONVERSION_UNCOMPRESSED,
                                            osslPub, sizeof(osslPub), NULL);
            SSF_ASSERT(osslPubLen == info.pubBytes);

            SSF_ASSERT(SSFECDHComputeSecret(curve, privA, info.privBytes,
                                            osslPub, osslPubLen,
                                            ssfSecret2, sizeof(ssfSecret2),
                                            &ssfSecret2Len) == true);

            keyAself = _ECDSAOSSLKeyFromPub(curve, pubA, pubALen);
            _ECDSAOSSLSetPriv(keyAself, privA, info.privBytes);
            n = ECDH_compute_key(osslSecret2, sizeof(osslSecret2),
                                 EC_KEY_get0_public_key(osslPeer), keyAself, NULL);
            SSF_ASSERT(n == (int)info.secretBytes);
            SSF_ASSERT(memcmp(ssfSecret2, osslSecret2, info.secretBytes) == 0);

            EC_KEY_free(keyAself);
            EC_KEY_free(osslPeer);
        }
    }
}

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
/* --------------------------------------------------------------------------------------------- */
/* Corner cases vs OpenSSL: all-zero hash, all-0xFF hash, and the DER round-trip property. */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyECDSACornerCasesAgainstOpenSSL(SSFECCurve_t curve)
{
    _ECDSAOSSLCurveInfo_t info;
    uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
    uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
    size_t  pubKeyLen = 0u;
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t  sigLen;
    static const uint8_t zeroHash[SSF_ECDSA_MAX_PRIV_KEY_SIZE] = {0};
    uint8_t ffHash[SSF_ECDSA_MAX_PRIV_KEY_SIZE];

    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));

    _ECDSAOSSLCurveInfo(curve, &info);
    memset(ffHash, 0xFFu, sizeof(ffHash));

    SSF_ASSERT(SSFECDSAKeyGen(curve, privKey, sizeof(privKey),
                              pubKey, sizeof(pubKey), &pubKeyLen) == true);

    /* All-zero hash. Valid input to ECDSA (e == 0 mod n). Sign with SSF, verify with OpenSSL. */
    SSF_ASSERT(SSFECDSASign(curve, privKey, info.privBytes,
                            zeroHash, info.hashBytes,
                            sig, sizeof(sig), &sigLen) == true);
    {
        EC_KEY *eckey = _ECDSAOSSLKeyFromPub(curve, pubKey, pubKeyLen);
        const uint8_t *p = sig;
        ECDSA_SIG *osslSig = d2i_ECDSA_SIG(NULL, &p, (long)sigLen);
        SSF_ASSERT(osslSig != NULL);
        SSF_ASSERT(ECDSA_do_verify(zeroHash, (int)info.hashBytes, osslSig, eckey) == 1);
        ECDSA_SIG_free(osslSig);
        EC_KEY_free(eckey);
    }

    /* All-0xFF hash. Tests reduction-mod-n on a hash bigger than the curve order. */
    SSF_ASSERT(SSFECDSASign(curve, privKey, info.privBytes,
                            ffHash, info.hashBytes,
                            sig, sizeof(sig), &sigLen) == true);
    {
        EC_KEY *eckey = _ECDSAOSSLKeyFromPub(curve, pubKey, pubKeyLen);
        const uint8_t *p = sig;
        ECDSA_SIG *osslSig = d2i_ECDSA_SIG(NULL, &p, (long)sigLen);
        SSF_ASSERT(osslSig != NULL);
        SSF_ASSERT(ECDSA_do_verify(ffHash, (int)info.hashBytes, osslSig, eckey) == 1);
        ECDSA_SIG_free(osslSig);
        EC_KEY_free(eckey);
    }

    /* DER round-trip: OpenSSL must re-encode SSF's signature byte-identically. */
    SSF_ASSERT(SSFECDSASign(curve, privKey, info.privBytes,
                            zeroHash, info.hashBytes,
                            sig, sizeof(sig), &sigLen) == true);
    {
        const uint8_t *p = sig;
        ECDSA_SIG *osslSig = d2i_ECDSA_SIG(NULL, &p, (long)sigLen);
        uint8_t roundtrip[SSF_ECDSA_MAX_SIG_SIZE];
        uint8_t *rp = roundtrip;
        int rLen;
        SSF_ASSERT(osslSig != NULL);
        rLen = i2d_ECDSA_SIG(osslSig, &rp);
        SSF_ASSERT(rLen == (int)sigLen);
        SSF_ASSERT(memcmp(roundtrip, sig, sigLen) == 0);
        ECDSA_SIG_free(osslSig);
    }

    /* Public-key derivation cross-check: OpenSSL derives priv * G, must match SSF's pubKey. */
    {
        EC_KEY *osslKey = EC_KEY_new_by_curve_name(info.nid);
        BIGNUM *bnD = BN_bin2bn(privKey, (int)info.privBytes, NULL);
        const EC_GROUP *grp;
        EC_POINT *derived;
        uint8_t derivedBytes[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t  derivedLen;

        SSF_ASSERT(osslKey != NULL);
        SSF_ASSERT(bnD != NULL);
        SSF_ASSERT(EC_KEY_set_private_key(osslKey, bnD) == 1);
        grp = EC_KEY_get0_group(osslKey);
        derived = EC_POINT_new(grp);
        SSF_ASSERT(EC_POINT_mul(grp, derived, bnD, NULL, NULL, NULL) == 1);
        derivedLen = EC_POINT_point2oct(grp, derived, POINT_CONVERSION_UNCOMPRESSED,
                                        derivedBytes, sizeof(derivedBytes), NULL);
        SSF_ASSERT(derivedLen == pubKeyLen);
        SSF_ASSERT(memcmp(derivedBytes, pubKey, pubKeyLen) == 0);

        EC_POINT_free(derived);
        BN_free(bnD);
        EC_KEY_free(osslKey);
    }
}
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */
#endif /* SSF_ECDSA_OSSL_VERIFY */

/* The audit tests that install these hooks use P-256 vectors and need signing */
#if (SSF_ECDSA_CONFIG_ENABLE_SIGN == 1) && (SSF_EC_CONFIG_ENABLE_P256 == 1)
/* --------------------------------------------------------------------------------------------- */
/* Zeroization audit hooks                                                                       */
/* --------------------------------------------------------------------------------------------- */
/* Exit hooks check every secret-derived stack local was wiped by the cleanup label. */
typedef struct
{
    bool sawHook;
    bool nonZero;
    const char *firstNonZero;
} _SSFECDSAZeroAudit_t;

/* Return true if bn is absent or every limb up to its capacity is zero. */
static bool _ECDSAUTLimbsAllZero(const SSFBN_t *bn)
{
    uint16_t i;

    /* Is there no limb storage to inspect? */
    if ((bn == NULL) || (bn->limbs == NULL))
    {
        /* Yes, nothing to leak. */
        return true;
    }
    for (i = 0; i < bn->cap; i++)
    {
        if (bn->limbs[i] != 0u) return false;
    }
    return true;
}

/* Record name as the first leak if bn is non-zero and no leak was recorded yet. */
static void _ECDSAUTRecordBN(_SSFECDSAZeroAudit_t *a, const SSFBN_t *bn, const char *name)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(name != NULL);

    if (a->nonZero) return;
    if (!_ECDSAUTLimbsAllZero(bn))
    {
        a->nonZero = true;
        a->firstNonZero = name;
    }
}

/* Sign exit hook: audit every secret-derived local for residue. */
static void _ECDSAUTSignHook(void *ctx,
                             const SSFBN_t *d, const SSFBN_t *k, const SSFBN_t *e,
                             const SSFBN_t *kInv, const SSFBN_t *tmp,
                             const SSFECPoint_t *R,
                             const SSFBN_t *Rx, const SSFBN_t *Ry)
{
    _SSFECDSAZeroAudit_t *a;

    SSF_REQUIRE(ctx != NULL);

    a = (_SSFECDSAZeroAudit_t *)ctx;
    a->sawHook = true;
    _ECDSAUTRecordBN(a, d,    "d");
    _ECDSAUTRecordBN(a, k,    "k");
    _ECDSAUTRecordBN(a, e,    "e");
    _ECDSAUTRecordBN(a, kInv, "kInv");
    _ECDSAUTRecordBN(a, tmp,  "tmp");
    if (R != NULL)
    {
        _ECDSAUTRecordBN(a, &R->x, "R.x");
        _ECDSAUTRecordBN(a, &R->y, "R.y");
        _ECDSAUTRecordBN(a, &R->z, "R.z");
    }
    _ECDSAUTRecordBN(a, Rx, "Rx");
    _ECDSAUTRecordBN(a, Ry, "Ry");
}

/* ECDH exit hook: audit d and the shared point for residue. */
static void _ECDSAUTECDHHook(void *ctx,
                             const SSFBN_t *d,
                             const SSFECPoint_t *S,
                             const SSFBN_t *Sx, const SSFBN_t *Sy)
{
    _SSFECDSAZeroAudit_t *a;

    SSF_REQUIRE(ctx != NULL);

    a = (_SSFECDSAZeroAudit_t *)ctx;
    a->sawHook = true;
    _ECDSAUTRecordBN(a, d, "d");
    if (S != NULL)
    {
        _ECDSAUTRecordBN(a, &S->x, "S.x");
        _ECDSAUTRecordBN(a, &S->y, "S.y");
        _ECDSAUTRecordBN(a, &S->z, "S.z");
    }
    _ECDSAUTRecordBN(a, Sx, "Sx");
    _ECDSAUTRecordBN(a, Sy, "Sy");
}

/* Record the first leak among the projective coordinates of pt, named prefix.x/y/z. */
static void _ECDSAUTRecordPoint(_SSFECDSAZeroAudit_t *a, const SSFECPoint_t *pt,
                                const char *xName, const char *yName, const char *zName)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(pt != NULL);

    _ECDSAUTRecordBN(a, &pt->x, xName);
    _ECDSAUTRecordBN(a, &pt->y, yName);
    _ECDSAUTRecordBN(a, &pt->z, zName);
}

/* KeyGen exit hook: audit d, the projective Q and the entropy seed buffer for residue. */
static void _ECDSAUTKeyGenHook(void *ctx,
                               const SSFBN_t *d,
                               const SSFECPoint_t *Q,
                               const uint8_t *entropy, size_t entropyLen)
{
    _SSFECDSAZeroAudit_t *a;
    size_t i;

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(Q != NULL);

    a = (_SSFECDSAZeroAudit_t *)ctx;
    a->sawHook = true;
    _ECDSAUTRecordBN(a, d, "d");
    _ECDSAUTRecordPoint(a, Q, "Q.x", "Q.y", "Q.z");

    /* Is there entropy to scan and no leak recorded yet? */
    if ((entropy != NULL) && (!a->nonZero))
    {
        /* Yes, record the first non-zero entropy byte. */
        for (i = 0; i < entropyLen; i++)
        {
            if (entropy[i] != 0u)
            {
                a->nonZero = true;
                a->firstNonZero = "entropy";
                break;
            }
        }
    }
}

/* PubKeyFromPrivKey exit hook: audit d and the projective Q for residue. */
static void _ECDSAUTPubKeyHook(void *ctx, const SSFBN_t *d, const SSFECPoint_t *Q)
{
    _SSFECDSAZeroAudit_t *a;

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(d != NULL);
    SSF_REQUIRE(Q != NULL);

    a = (_SSFECDSAZeroAudit_t *)ctx;
    a->sawHook = true;
    _ECDSAUTRecordBN(a, d, "d");
    _ECDSAUTRecordPoint(a, Q, "Q.x", "Q.y", "Q.z");
}

/* Assert PubKeyFromPrivKey's result for privKey, and that d and Q are wiped on return. */
static void _ECDSAUTPubKeyAudit(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                                bool expectOk, const char *caseStr)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
    size_t pubKeyLen = 0xA5u;
    size_t i;
    _SSFECDSAZeroAudit_t audit = { false, false, NULL };

    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(caseStr != NULL);

    memset(pubKey, 0xEE, sizeof(pubKey));
    _SSFECDSAPubKeyTestExitHookCtx = &audit;
    _SSFECDSAPubKeyTestExitHook = _ECDSAUTPubKeyHook;
    SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(curve, privKey, privKeyLen, pubKey, sizeof(pubKey),
                                         &pubKeyLen) == expectOk);
    _SSFECDSAPubKeyTestExitHook = NULL;
    _SSFECDSAPubKeyTestExitHookCtx = NULL;

    SSF_ASSERT(audit.sawHook == true);
    if (audit.nonZero)
    {
        SSF_UT_PRINTF("PubKeyFromPrivKey (%s) zeroization audit FAILED: %s left non-zero\n",
                      caseStr, audit.firstNonZero);
    }
    SSF_ASSERT(audit.nonZero == false);

    /* Was the scalar expected to be accepted? */
    if (expectOk)
    {
        /* Yes, an uncompressed SEC 1 point was written */
        SSF_ASSERT(pubKeyLen == (1u + (2u * (size_t)c->bytes)));
        SSF_ASSERT(pubKey[0] == 0x04u);
    }
    else
    {
        /* No, neither output was written */
        SSF_ASSERT(pubKeyLen == 0xA5u);
        for (i = 0u; i < sizeof(pubKey); i++)
        {
            SSF_ASSERT(pubKey[i] == 0xEEu);
        }
    }
}

/* Run the PubKeyFromPrivKey audit on 1, n - 1, 0, n, n + 1 and all 0xFF for curve. */
static void _ECDSAUTPubKeyAuditCurve(SSFECCurve_t curve)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    uint8_t priv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
    size_t i;

    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(c->bytes <= sizeof(priv));

    /* d = 1, the smallest valid scalar */
    memset(priv, 0, sizeof(priv));
    priv[c->bytes - 1u] = 1u;
    _ECDSAUTPubKeyAudit(curve, priv, c->bytes, true, "d = 1");

    /* d = n - 1, the largest valid scalar (n is odd, so no borrow) */
    SSF_ASSERT(SSFBNToBytes(&c->n, priv, c->bytes));
    priv[c->bytes - 1u]--;
    _ECDSAUTPubKeyAudit(curve, priv, c->bytes, true, "d = n - 1");

    /* d = 0 */
    memset(priv, 0, sizeof(priv));
    _ECDSAUTPubKeyAudit(curve, priv, c->bytes, false, "d = 0");

    /* d = n */
    SSF_ASSERT(SSFBNToBytes(&c->n, priv, c->bytes));
    _ECDSAUTPubKeyAudit(curve, priv, c->bytes, false, "d = n");

    /* d = n + 1 (big-endian increment with carry) */
    for (i = c->bytes; i > 0u; i--)
    {
        priv[i - 1u]++;
        /* Did this byte absorb the carry? */
        if (priv[i - 1u] != 0u)
        {
            /* Yes, done */
            break;
        }
        /* No, carry into the next byte up */
    }
    _ECDSAUTPubKeyAudit(curve, priv, c->bytes, false, "d = n + 1");

    /* d = all 0xFF */
    memset(priv, 0xFF, c->bytes);
    _ECDSAUTPubKeyAudit(curve, priv, c->bytes, false, "d = all 0xFF");
}
#endif /* (SSF_ECDSA_CONFIG_ENABLE_SIGN == 1) && (SSF_EC_CONFIG_ENABLE_P256 == 1) */

void SSFECDSAUnitTest(void)
{
    /* ---- (Hardening) _SSFECDSABits2Int: (1) long hashLen truncates; (2) bitlen(n) assert ---- */
    {
#if SSF_EC_CONFIG_ENABLE_P256 == 1
        const SSFECCurveParams_t *cReal = SSFECGetCurveParams(SSF_EC_CURVE_P256);
#else
        const SSFECCurveParams_t *cReal = SSFECGetCurveParams(SSF_EC_CURVE_P384);
#endif
        uint8_t hash[SSF_EC_MAX_COORD_BYTES + 1u] = {0};
        SSFECCurveParams_t cBad;

        /* (1) hashLen one byte past the coordinate width is truncated, not asserted (ECDSA-3). */
        _SSFECDSABits2IntForTest(cReal, hash, (size_t)cReal->bytes + 1u);

        /* A matched-width hashLen must NOT assert (the normal path still works). */
        _SSFECDSABits2IntForTest(cReal, hash, cReal->bytes);

        /* (2) bytes*8 != bitlen(n) on a shallow params copy must fire the assert. */
        cBad = *cReal;
        cBad.bytes = (uint16_t)(cReal->bytes - 1u);
        SSF_ASSERT_TEST(_SSFECDSABits2IntForTest(&cBad, hash, 1u));
    }

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* ---- COV-8 (P-384): 28-byte digest uses HMAC-SHA-384; A.2.6 key, independent KAT ---- */
    {
        static const uint8_t privKey[] = {
            0x6Bu, 0x9Du, 0x3Du, 0xADu, 0x2Eu, 0x1Bu, 0x8Cu, 0x1Cu,
            0x05u, 0xB1u, 0x98u, 0x75u, 0xB6u, 0x65u, 0x9Fu, 0x4Du,
            0xE2u, 0x3Cu, 0x3Bu, 0x66u, 0x7Bu, 0xF2u, 0x97u, 0xBAu,
            0x9Au, 0xA4u, 0x77u, 0x40u, 0x78u, 0x71u, 0x37u, 0xD8u,
            0x96u, 0xD5u, 0x72u, 0x4Eu, 0x4Cu, 0x70u, 0xA8u, 0x25u,
            0xF8u, 0x72u, 0xC9u, 0xEAu, 0x60u, 0xD2u, 0xEDu, 0xF5u
        };
        static const uint8_t expSig[] = {
            0x30u, 0x65u, 0x02u, 0x31u, 0x00u, 0x95u, 0x3Eu, 0xE1u,
            0xF5u, 0xA1u, 0xF3u, 0x52u, 0x3Fu, 0x62u, 0x40u, 0x42u,
            0xAAu, 0x4Cu, 0x95u, 0xF1u, 0x73u, 0x0Cu, 0xA1u, 0xAFu,
            0x7Fu, 0x4Cu, 0x62u, 0x3Cu, 0x98u, 0xCAu, 0x73u, 0x3Cu,
            0x8Du, 0x94u, 0x28u, 0x06u, 0xDAu, 0xFAu, 0x2Bu, 0x8Eu,
            0xC2u, 0x96u, 0x51u, 0xCEu, 0x21u, 0x27u, 0x44u, 0x0Fu,
            0x17u, 0xD3u, 0xCBu, 0x85u, 0x41u, 0x02u, 0x30u, 0x29u,
            0x13u, 0xFAu, 0x54u, 0xA3u, 0x2Eu, 0xB1u, 0x00u, 0x94u,
            0x83u, 0xB5u, 0x30u, 0x0Fu, 0x8Au, 0xD6u, 0xFDu, 0x3Cu,
            0x75u, 0xE7u, 0x39u, 0xC1u, 0xD7u, 0x1Au, 0x99u, 0xAAu,
            0x4Bu, 0xE7u, 0xBAu, 0x24u, 0x6Au, 0xCAu, 0x94u, 0xD4u,
            0x0Du, 0xE0u, 0xBBu, 0x29u, 0x0Eu, 0x8Du, 0x9Au, 0x8Cu,
            0x56u, 0x47u, 0x66u, 0xABu, 0x04u, 0x2Eu, 0x7Bu
        };
        uint8_t hash[48];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        SSFSHA384((const uint8_t *)"sample", 6, hash, sizeof(hash));
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P384, privKey, sizeof(privKey), hash, 28u, sig,
                                sizeof(sig), &sigLen) == true);
        SSF_ASSERT((sigLen == sizeof(expSig)) && (memcmp(sig, expSig, sigLen) == 0));
        SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P384, privKey, sizeof(privKey), pubKey,
                                             sizeof(pubKey), &pubKeyLen) == true);
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P384, pubKey, pubKeyLen, hash, 28u, sig,
                                  sigLen) == true);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* ---- COV-8: 28-byte digest uses the curve hash (HMAC-SHA-256); A.2.5 key, independent KAT */
    {
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
        static const uint8_t expSig[] = {
            0x30u, 0x45u, 0x02u, 0x20u,
            0x59u, 0x16u, 0x23u, 0x57u, 0x0Au, 0xCDu, 0xC4u, 0x8Fu,
            0xE3u, 0xE7u, 0xF7u, 0xA6u, 0x79u, 0xBFu, 0x86u, 0x92u,
            0xBFu, 0x48u, 0x24u, 0x80u, 0x1Bu, 0x61u, 0xD3u, 0x0Cu,
            0x1Bu, 0x48u, 0xEBu, 0x77u, 0xECu, 0x19u, 0x57u, 0x2Cu,
            0x02u, 0x21u, 0x00u,
            0x94u, 0xA3u, 0xBCu, 0xA4u, 0xAFu, 0x99u, 0x58u, 0x8Bu,
            0x07u, 0xFAu, 0x5Eu, 0x9Bu, 0x8Fu, 0xC0u, 0x37u, 0x59u,
            0x1Cu, 0xBEu, 0xDBu, 0xEDu, 0xEAu, 0x1Eu, 0x81u, 0x91u,
            0x6Bu, 0xD9u, 0x5Au, 0x82u, 0xC5u, 0x21u, 0x07u, 0x27u
        };
        uint8_t hash[32];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey), hash, 28u, sig,
                                sizeof(sig), &sigLen) == true);
        SSF_ASSERT((sigLen == sizeof(expSig)) && (memcmp(sig, expSig, sigLen) == 0));
        SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P256, privKey, sizeof(privKey), pubKey,
                                             sizeof(pubKey), &pubKeyLen) == true);
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, pubKeyLen, hash, 28u, sig,
                                  sigLen) == true);
    }

    /* ---- Zeroization audit: Sign success path leaves no secret-derived limbs on stack ---- */
    {
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
        uint8_t hash[32];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;
        _SSFECDSAZeroAudit_t audit = { false, false, NULL };

        SSFSHA256((const uint8_t *)"audit-sign-success", 18, hash, sizeof(hash));

        _SSFECDSASignTestExitHookCtx = &audit;
        _SSFECDSASignTestExitHook = _ECDSAUTSignHook;
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);
        _SSFECDSASignTestExitHook = NULL;
        _SSFECDSASignTestExitHookCtx = NULL;

        SSF_ASSERT(audit.sawHook == true);
        if (audit.nonZero)
        {
            SSF_UT_PRINTF("ECDSA Sign zeroization audit FAILED: %s left non-zero on stack\n",
                   audit.firstNonZero);
        }
        SSF_ASSERT(audit.nonZero == false);
    }

    /* ---- Zeroization audit: Sign failure path (invalid privKey) also wipes secrets ---- */
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);
        uint8_t badPrivKey[32];
        uint8_t hash[32];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;
        _SSFECDSAZeroAudit_t audit = { false, false, NULL };

        /* d = n exactly: SSFBNFromBytes succeeds but _SSFECDSAPrivKeyIsValid rejects (d >= n). */
        SSFBNToBytes(&c->n, badPrivKey, sizeof(badPrivKey));
        SSFSHA256((const uint8_t *)"audit-sign-fail", 15, hash, sizeof(hash));

        _SSFECDSASignTestExitHookCtx = &audit;
        _SSFECDSASignTestExitHook = _ECDSAUTSignHook;
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, badPrivKey, sizeof(badPrivKey),
                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == false);
        _SSFECDSASignTestExitHook = NULL;
        _SSFECDSASignTestExitHookCtx = NULL;

        SSF_ASSERT(audit.sawHook == true);
        if (audit.nonZero)
        {
            SSF_UT_PRINTF("ECDSA Sign (fail path) zeroization audit FAILED: %s left non-zero\n",
                   audit.firstNonZero);
        }
        SSF_ASSERT(audit.nonZero == false);
    }

    /* ---- Zeroization audit: ECDH success path leaves no d, S, Sx or Sy limbs on stack ---- */
    {
        uint8_t privA[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubA[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubALen;
        uint8_t privB[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubB[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubBLen;
        uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
        size_t sharedLen;
        _SSFECDSAZeroAudit_t audit = { false, false, NULL };

        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privA, sizeof(privA), pubA, sizeof(pubA), &pubALen) == true);
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privB, sizeof(privB), pubB, sizeof(pubB), &pubBLen) == true);

        _SSFECDSAECDHTestExitHookCtx = &audit;
        _SSFECDSAECDHTestExitHook = _ECDSAUTECDHHook;
        SSF_ASSERT(SSFECDHComputeSecret(SSF_EC_CURVE_P256, privA, 32u, pubB, pubBLen,
                   shared, sizeof(shared), &sharedLen) == true);
        _SSFECDSAECDHTestExitHook = NULL;
        _SSFECDSAECDHTestExitHookCtx = NULL;

        SSF_ASSERT(audit.sawHook == true);
        if (audit.nonZero)
        {
            SSF_UT_PRINTF("ECDH zeroization audit FAILED: %s left non-zero on stack\n",
                   audit.firstNonZero);
        }
        SSF_ASSERT(audit.nonZero == false);
    }

    /* ---- Zeroization audit: ECDH failure path (invalid peer pubKey) wipes secrets ---- */
    {
        uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t badPub[65];
        uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
        size_t sharedLen;
        _SSFECDSAZeroAudit_t audit = { false, false, NULL };

        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privKey, sizeof(privKey), pubKey, sizeof(pubKey), &pubKeyLen) == true);

        memset(badPub, 0, sizeof(badPub));
        badPub[0] = 0x04u; /* Identity-shaped -- rejected by SSFECPointDecode */

        _SSFECDSAECDHTestExitHookCtx = &audit;
        _SSFECDSAECDHTestExitHook = _ECDSAUTECDHHook;
        SSF_ASSERT(SSFECDHComputeSecret(SSF_EC_CURVE_P256, privKey, 32u, badPub, sizeof(badPub),
                   shared, sizeof(shared), &sharedLen) == false);
        _SSFECDSAECDHTestExitHook = NULL;
        _SSFECDSAECDHTestExitHookCtx = NULL;

        SSF_ASSERT(audit.sawHook == true);
        if (audit.nonZero)
        {
            SSF_UT_PRINTF("ECDH (fail path) zeroization audit FAILED: %s left non-zero\n",
                   audit.firstNonZero);
        }
        SSF_ASSERT(audit.nonZero == false);
    }

    /* ---- Zeroization audit: KeyGen wipes d, the projective Q and the entropy seed buffer ---- */
    {
        uint8_t privKey[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        _SSFECDSAZeroAudit_t audit = { false, false, NULL };

        _SSFECDSAKeyGenTestExitHookCtx = &audit;
        _SSFECDSAKeyGenTestExitHook = _ECDSAUTKeyGenHook;
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privKey, sizeof(privKey),
                   pubKey,  sizeof(pubKey), &pubKeyLen) == true);
        _SSFECDSAKeyGenTestExitHook = NULL;
        _SSFECDSAKeyGenTestExitHookCtx = NULL;

        SSF_ASSERT(audit.sawHook == true);
        if (audit.nonZero)
        {
            SSF_UT_PRINTF("KeyGen zeroization audit FAILED: %s left non-zero on stack\n",
                   audit.firstNonZero);
        }
        SSF_ASSERT(audit.nonZero == false);
    }

    /* ---- Zeroization audit: PubKeyFromPrivKey wipes d and Q on every return ---- */
    _ECDSAUTPubKeyAuditCurve(SSF_EC_CURVE_P256);
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    _ECDSAUTPubKeyAuditCurve(SSF_EC_CURVE_P384);
#endif

    /* ---- RFC 6979 A.2.5: canonical (r, s) and DER KAT for P-256/SHA-256 "sample" ---- */
    {
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
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
        /* RFC 6979 A.2.5 expected r, s for SHA-256 / "sample" (32 bytes each) */
        static const uint8_t expR[32] = {
            0xEFu, 0xD4u, 0x8Bu, 0x2Au, 0xACu, 0xB6u, 0xA8u, 0xFDu,
            0x11u, 0x40u, 0xDDu, 0x9Cu, 0xD4u, 0x5Eu, 0x81u, 0xD6u,
            0x9Du, 0x2Cu, 0x87u, 0x7Bu, 0x56u, 0xAAu, 0xF9u, 0x91u,
            0xC3u, 0x4Du, 0x0Eu, 0xA8u, 0x4Eu, 0xAFu, 0x37u, 0x16u
        };
        static const uint8_t expS[32] = {
            0xF7u, 0xCBu, 0x1Cu, 0x94u, 0x2Du, 0x65u, 0x7Cu, 0x41u,
            0xD4u, 0x36u, 0xC7u, 0xA1u, 0xB6u, 0xE2u, 0x9Fu, 0x65u,
            0xF3u, 0xE9u, 0x00u, 0xDBu, 0xB9u, 0xAFu, 0xF4u, 0x06u,
            0x4Du, 0xC4u, 0xABu, 0x2Fu, 0x84u, 0x3Au, 0xCDu, 0xA8u
        };
        uint8_t hash[32];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);

        /* DER: r and s have MSB set, so each INTEGER is 33 bytes and the total is 72 bytes. */
        SSF_ASSERT(sigLen == 72u);
        SSF_ASSERT(sig[0] == 0x30u);
        SSF_ASSERT(sig[2] == 0x02u);
        SSF_ASSERT(sig[3] == 0x21u);
        SSF_ASSERT(sig[4] == 0x00u);
        SSF_ASSERT(memcmp(&sig[5], expR, 32) == 0);
        SSF_ASSERT(sig[37] == 0x02u);
        SSF_ASSERT(sig[38] == 0x21u);
        SSF_ASSERT(sig[39] == 0x00u);
        SSF_ASSERT(memcmp(&sig[40], expS, 32) == 0);

        /* Round-trip verify of the canonical signature. */
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey),
                   hash, sizeof(hash), sig, sigLen) == true);

        /* Negative: flipping a bit in the last byte of s must reject. */
        {
            uint8_t bad[SSF_ECDSA_MAX_SIG_SIZE];
            memcpy(bad, sig, sigLen);
            bad[sigLen - 1u] ^= 0x01u;
            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey),
                       hash, sizeof(hash), bad, sigLen) == false);
        }
    }

    /* ---- AUDIT ECDSA-1: forced r == 0 continues the RFC 6979 generator (Python model KAT) ---- */
    {
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
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
        static const uint8_t sigK2[71] = {
            0x30u, 0x45u, 0x02u, 0x21u, 0x00u, 0xFEu, 0x96u, 0x83u, 0x88u, 0x6Au, 0x9Du, 0x10u,
            0xF4u, 0x09u, 0x82u, 0xF0u, 0x01u, 0xE9u, 0xCAu, 0xF5u, 0x6Fu, 0x43u, 0x64u, 0xB1u,
            0xECu, 0x18u, 0x42u, 0x2Cu, 0xAEu, 0xE5u, 0xB5u, 0xF3u, 0xFBu, 0x31u, 0x2Cu, 0x4Du,
            0x6Bu, 0x02u, 0x20u, 0x1Du, 0x9Du, 0x98u, 0x11u, 0x93u, 0x18u, 0x8Cu, 0x31u, 0x5Cu,
            0x46u, 0x2Du, 0x09u, 0xFFu, 0xACu, 0xEFu, 0x90u, 0x8Cu, 0x76u, 0x80u, 0x48u, 0xACu,
            0x02u, 0xC5u, 0x2Du, 0xB0u, 0xE6u, 0x4Au, 0x5Bu, 0xAFu, 0x41u, 0x04u, 0xEAu
        };
        static const uint8_t sigK3[70] = {
            0x30u, 0x44u, 0x02u, 0x20u, 0x57u, 0xD2u, 0xBBu, 0xEBu, 0x6Bu, 0x5Fu, 0x3Du, 0xBEu,
            0xA8u, 0x9Eu, 0x3Du, 0x3Du, 0x7Cu, 0xB0u, 0xDFu, 0xE5u, 0xCDu, 0xB9u, 0x1Cu, 0xCDu,
            0x3Bu, 0xE3u, 0x20u, 0xEFu, 0x31u, 0x92u, 0xA3u, 0xD5u, 0xBDu, 0x88u, 0xD4u, 0x17u,
            0x02u, 0x20u, 0x24u, 0xD1u, 0x8Fu, 0xCBu, 0xCCu, 0xBEu, 0xE8u, 0x50u, 0x55u, 0xBDu,
            0x25u, 0xACu, 0x78u, 0xC9u, 0x59u, 0xF4u, 0x7Du, 0xE8u, 0x32u, 0xA2u, 0x12u, 0xAAu,
            0x6Eu, 0x25u, 0x90u, 0x11u, 0xEBu, 0xAEu, 0xA0u, 0x5Du, 0xB3u, 0x0Fu
        };
        uint8_t hash[32];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));

        /* One forced rejection: the second RFC 6979 candidate signs. */
        _SSFECDSASignTestForcedRetries = 1u;
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey), hash, sizeof(hash),
                                sig, sizeof(sig), &sigLen) == true);
        _SSFECDSASignTestForcedRetries = 0u;
        SSF_ASSERT((sigLen == sizeof(sigK2)) && (memcmp(sig, sigK2, sizeof(sigK2)) == 0));
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey), hash, sizeof(hash),
                                  sig, sigLen) == true);

        /* Two forced rejections: the third candidate signs. */
        _SSFECDSASignTestForcedRetries = 2u;
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey), hash, sizeof(hash),
                                sig, sizeof(sig), &sigLen) == true);
        _SSFECDSASignTestForcedRetries = 0u;
        SSF_ASSERT((sigLen == sizeof(sigK3)) && (memcmp(sig, sigK3, sizeof(sigK3)) == 0));
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey), hash, sizeof(hash),
                                  sig, sigLen) == true);

        /* Every attempt rejected: Sign gives up after its bounded attempt count (8). */
        _SSFECDSASignTestForcedRetries = 8u;
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey), hash, sizeof(hash),
                                sig, sizeof(sig), &sigLen) == false);
        _SSFECDSASignTestForcedRetries = 7u;
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey), hash, sizeof(hash),
                                sig, sizeof(sig), &sigLen) == true);
        _SSFECDSASignTestForcedRetries = 0u;
    }

    /* ---- AUDIT ECDSA-5: a faulted signature is never released (verify-after-sign) ---- */
#if SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN == 1
    {
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
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
        size_t i;
        uint8_t mode;

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));

        /* Fault in r, d, then e: each must be caught. */
        for (mode = 1u; mode <= 3u; mode++)
        {
            memset(sig, 0xA5, sizeof(sig));
            sigLen = 0x5A5Au;
            _SSFECDSASignTestFault = mode;
            SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey), hash,
                                    sizeof(hash), sig, sizeof(sig), &sigLen) == false);
            _SSFECDSASignTestFault = 0u;
            SSF_ASSERT(sigLen == 0x5A5Au);
            for (i = 0; i < sizeof(sig); i++) SSF_ASSERT(sig[i] == 0xA5u);
        }

        /* No fault: the same call signs and the signature verifies. */
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey), hash, sizeof(hash),
                                sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey), hash, sizeof(hash),
                                  sig, sigLen) == true);
    }
#endif /* SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN */

    /* ---- AUDIT ECDSA-2: the RFC 6979 nonce HMAC follows the digest's hash, not the curve ---- */
    {
        static const uint8_t privKey256[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
        static const uint8_t sigP256Sha1[70] = {
            0x30u, 0x44u, 0x02u, 0x20u, 0x61u, 0x34u, 0x0Cu, 0x88u, 0xC3u, 0xAAu, 0xEBu, 0xEBu,
            0x4Fu, 0x6Du, 0x66u, 0x7Fu, 0x67u, 0x2Cu, 0xA9u, 0x75u, 0x9Au, 0x6Cu, 0xCAu, 0xA9u,
            0xFAu, 0x88u, 0x11u, 0x31u, 0x30u, 0x39u, 0xEEu, 0x4Au, 0x35u, 0x47u, 0x1Du, 0x32u,
            0x02u, 0x20u, 0x6Du, 0x7Fu, 0x14u, 0x7Du, 0xACu, 0x08u, 0x94u, 0x41u, 0xBBu, 0x2Eu,
            0x2Fu, 0xE8u, 0xF7u, 0xA3u, 0xFAu, 0x26u, 0x4Bu, 0x9Cu, 0x47u, 0x50u, 0x98u, 0xFDu,
            0xCFu, 0x6Eu, 0x00u, 0xD7u, 0xC9u, 0x96u, 0xE1u, 0xB8u, 0xB7u, 0xEBu
        };
        uint8_t sha1Hash[SSF_SHA1_HASH_SIZE];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        /* P-256 signing a 20-byte SHA-1 digest: nonce via HMAC-SHA-1. */
        SSFSHA1((const uint8_t *)"sample", 6u, sha1Hash);
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey256, sizeof(privKey256), sha1Hash,
                                sizeof(sha1Hash), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT((sigLen == sizeof(sigP256Sha1)) &&
                   (memcmp(sig, sigP256Sha1, sizeof(sigP256Sha1)) == 0));

#if SSF_EC_CONFIG_ENABLE_P384 == 1
        {
            static const uint8_t privKey384[] = {
                0x6Bu, 0x9Du, 0x3Du, 0xADu, 0x2Eu, 0x1Bu, 0x8Cu, 0x1Cu,
                0x05u, 0xB1u, 0x98u, 0x75u, 0xB6u, 0x65u, 0x9Fu, 0x4Du,
                0xE2u, 0x3Cu, 0x3Bu, 0x66u, 0x7Bu, 0xF2u, 0x97u, 0xBAu,
                0x9Au, 0xA4u, 0x77u, 0x40u, 0x78u, 0x71u, 0x37u, 0xD8u,
                0x96u, 0xD5u, 0x72u, 0x4Eu, 0x4Cu, 0x70u, 0xA8u, 0x25u,
                0xF8u, 0x72u, 0xC9u, 0xEAu, 0x60u, 0xD2u, 0xEDu, 0xF5u
            };
            static const uint8_t sigP384Sha256[103] = {
                0x30u, 0x65u, 0x02u, 0x30u, 0x21u, 0xB1u, 0x3Du, 0x1Eu, 0x01u, 0x3Cu, 0x7Fu, 0xA1u,
                0x39u, 0x2Du, 0x03u, 0xC5u, 0xF9u, 0x9Au, 0xF8u, 0xB3u, 0x0Cu, 0x57u, 0x0Cu, 0x6Fu,
                0x98u, 0xD4u, 0xEAu, 0x8Eu, 0x35u, 0x4Bu, 0x63u, 0xA2u, 0x1Du, 0x3Du, 0xAAu, 0x33u,
                0xBDu, 0xE1u, 0xE8u, 0x88u, 0xE6u, 0x33u, 0x55u, 0xD9u, 0x2Fu, 0xA2u, 0xB3u, 0xC3u,
                0x6Du, 0x8Fu, 0xB2u, 0xCDu, 0x02u, 0x31u, 0x00u, 0xF3u, 0xAAu, 0x44u, 0x3Fu, 0xB1u,
                0x07u, 0x74u, 0x5Bu, 0xF4u, 0xBDu, 0x77u, 0xCBu, 0x38u, 0x91u, 0x67u, 0x46u, 0x32u,
                0x06u, 0x8Au, 0x10u, 0xCAu, 0x67u, 0xE3u, 0xD4u, 0x5Du, 0xB2u, 0x26u, 0x6Fu, 0xA7u,
                0xD1u, 0xFEu, 0xEBu, 0xEFu, 0xDCu, 0x63u, 0xECu, 0xCDu, 0x1Au, 0xC4u, 0x2Eu, 0xC0u,
                0xCBu, 0x86u, 0x68u, 0xA4u, 0xFAu, 0x0Au, 0xB0u
            };
            uint8_t sha256Hash[32];

            /* P-384 signing a 32-byte SHA-256 digest: nonce via HMAC-SHA-256. */
            SSFSHA256((const uint8_t *)"sample", 6, sha256Hash, sizeof(sha256Hash));
            SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P384, privKey384, sizeof(privKey384), sha256Hash,
                                    sizeof(sha256Hash), sig, sizeof(sig), &sigLen) == true);
            SSF_ASSERT((sigLen == sizeof(sigP384Sha256)) &&
                       (memcmp(sig, sigP384Sha256, sizeof(sigP384Sha256)) == 0));
        }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */
    }

    /* ---- AUDIT ECDSA-3: digests longer than the curve are truncated (FIPS 186-4 6.4) ---- */
    {
        static const uint8_t privKey256[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
        static const uint8_t pubKey256[] = {
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
        static const uint8_t sigP256Sha384[70] = {
            0x30u, 0x44u, 0x02u, 0x20u, 0x0Eu, 0xAFu, 0xEAu, 0x03u, 0x9Bu, 0x20u, 0xE9u, 0xB4u,
            0x23u, 0x09u, 0xFBu, 0x1Du, 0x89u, 0xE2u, 0x13u, 0x05u, 0x7Cu, 0xBFu, 0x97u, 0x3Du,
            0xC0u, 0xCFu, 0xC8u, 0xF1u, 0x29u, 0xEDu, 0xDDu, 0xC8u, 0x00u, 0xEFu, 0x77u, 0x19u,
            0x02u, 0x20u, 0x48u, 0x61u, 0xF0u, 0x49u, 0x1Eu, 0x69u, 0x98u, 0xB9u, 0x45u, 0x51u,
            0x93u, 0xE3u, 0x4Eu, 0x7Bu, 0x0Du, 0x28u, 0x4Du, 0xDDu, 0x71u, 0x49u, 0xA7u, 0x4Bu,
            0x95u, 0xB9u, 0x26u, 0x1Fu, 0x13u, 0xABu, 0xDEu, 0x94u, 0x09u, 0x54u
        };
        static const uint8_t sigP256Sha512[71] = {
            0x30u, 0x45u, 0x02u, 0x21u, 0x00u, 0x84u, 0x96u, 0xA6u, 0x0Bu, 0x5Eu, 0x9Bu, 0x47u,
            0xC8u, 0x25u, 0x48u, 0x88u, 0x27u, 0xE0u, 0x49u, 0x5Bu, 0x0Eu, 0x3Fu, 0xA1u, 0x09u,
            0xECu, 0x45u, 0x68u, 0xFDu, 0x3Fu, 0x8Du, 0x10u, 0x97u, 0x67u, 0x8Eu, 0xB9u, 0x7Fu,
            0x00u, 0x02u, 0x20u, 0x23u, 0x62u, 0xABu, 0x1Au, 0xDBu, 0xE2u, 0xB8u, 0xADu, 0xF9u,
            0xCBu, 0x9Eu, 0xDAu, 0xB7u, 0x40u, 0xEAu, 0x60u, 0x49u, 0xC0u, 0x28u, 0x11u, 0x4Fu,
            0x24u, 0x60u, 0xF9u, 0x65u, 0x54u, 0xF6u, 0x1Fu, 0xAEu, 0x33u, 0x02u, 0xFEu
        };
        uint8_t h384[48];
        uint8_t h512[64];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        SSFSHA384((const uint8_t *)"sample", 6, h384, sizeof(h384));
        SSFSHA512((const uint8_t *)"sample", 6, h512, sizeof(h512));

        /* P-256 + SHA-384 (48-byte digest, truncated to 32). */
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey256, sizeof(privKey256), h384,
                                sizeof(h384), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT((sigLen == sizeof(sigP256Sha384)) &&
                   (memcmp(sig, sigP256Sha384, sizeof(sigP256Sha384)) == 0));
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey256, sizeof(pubKey256), h384,
                                  sizeof(h384), sig, sigLen) == true);

        /* P-256 + SHA-512 (64-byte digest, truncated to 32). */
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey256, sizeof(privKey256), h512,
                                sizeof(h512), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT((sigLen == sizeof(sigP256Sha512)) &&
                   (memcmp(sig, sigP256Sha512, sizeof(sigP256Sha512)) == 0));
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey256, sizeof(pubKey256), h512,
                                  sizeof(h512), sig, sigLen) == true);

        /* Longer than any supported digest still traps. */
        SSF_ASSERT_TEST(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey256, sizeof(pubKey256), h512,
                                       sizeof(h512) + 1u, sig, sigLen));

#if SSF_EC_CONFIG_ENABLE_P384 == 1
        {
            static const uint8_t privKey384[] = {
                0x6Bu, 0x9Du, 0x3Du, 0xADu, 0x2Eu, 0x1Bu, 0x8Cu, 0x1Cu,
                0x05u, 0xB1u, 0x98u, 0x75u, 0xB6u, 0x65u, 0x9Fu, 0x4Du,
                0xE2u, 0x3Cu, 0x3Bu, 0x66u, 0x7Bu, 0xF2u, 0x97u, 0xBAu,
                0x9Au, 0xA4u, 0x77u, 0x40u, 0x78u, 0x71u, 0x37u, 0xD8u,
                0x96u, 0xD5u, 0x72u, 0x4Eu, 0x4Cu, 0x70u, 0xA8u, 0x25u,
                0xF8u, 0x72u, 0xC9u, 0xEAu, 0x60u, 0xD2u, 0xEDu, 0xF5u
            };
            static const uint8_t sigP384Sha512[103] = {
                0x30u, 0x65u, 0x02u, 0x31u, 0x00u, 0xEDu, 0x09u, 0x59u, 0xD5u, 0x88u, 0x0Au, 0xB2u,
                0xD8u, 0x69u, 0xAEu, 0x7Fu, 0x6Cu, 0x29u, 0x15u, 0xC6u, 0xD6u, 0x0Fu, 0x96u, 0x50u,
                0x7Fu, 0x9Cu, 0xB3u, 0xE0u, 0x47u, 0xC0u, 0x04u, 0x68u, 0x61u, 0xDAu, 0x4Au, 0x79u,
                0x9Cu, 0xFEu, 0x30u, 0xF3u, 0x5Cu, 0xC9u, 0x00u, 0x05u, 0x6Du, 0x7Cu, 0x99u, 0xCDu,
                0x78u, 0x82u, 0x43u, 0x37u, 0x09u, 0x02u, 0x30u, 0x51u, 0x2Cu, 0x8Cu, 0xCEu, 0xEEu,
                0x38u, 0x90u, 0xA8u, 0x40u, 0x58u, 0xCEu, 0x1Eu, 0x22u, 0xDBu, 0xC2u, 0x19u, 0x8Fu,
                0x42u, 0x32u, 0x3Cu, 0xE8u, 0xACu, 0xA9u, 0x13u, 0x53u, 0x29u, 0xF0u, 0x3Cu, 0x06u,
                0x8Eu, 0x51u, 0x12u, 0xDCu, 0x7Cu, 0xC3u, 0xEFu, 0x34u, 0x46u, 0xDEu, 0xFCu, 0xEBu,
                0x01u, 0xA4u, 0x5Cu, 0x26u, 0x67u, 0xFDu, 0xD5u
            };
            uint8_t pubKey384[SSF_ECDSA_MAX_PUB_KEY_SIZE];
            size_t pubKey384Len;

            /* P-384 + SHA-512 (64-byte digest, truncated to 48). */
            SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P384, privKey384, sizeof(privKey384),
                                                 pubKey384, sizeof(pubKey384),
                                                 &pubKey384Len) == true);
            SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P384, privKey384, sizeof(privKey384), h512,
                                    sizeof(h512), sig, sizeof(sig), &sigLen) == true);
            SSF_ASSERT((sigLen == sizeof(sigP384Sha512)) &&
                       (memcmp(sig, sigP384Sha512, sizeof(sigP384Sha512)) == 0));
            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P384, pubKey384, pubKey384Len, h512,
                                      sizeof(h512), sig, sigLen) == true);
        }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */
    }

    /* ---- Sign rejects a 1-byte-short sig buffer without writing past it ---- */
    {
        static const uint8_t privKey[] = {
            0xC9u, 0xAFu, 0xA9u, 0xD8u, 0x45u, 0xBAu, 0x75u, 0x16u,
            0x6Bu, 0x5Cu, 0x21u, 0x57u, 0x67u, 0xB1u, 0xD6u, 0x93u,
            0x4Eu, 0x50u, 0xC3u, 0xDBu, 0x36u, 0xE8u, 0x9Bu, 0x12u,
            0x7Bu, 0x8Au, 0x62u, 0x2Bu, 0x12u, 0x0Fu, 0x67u, 0x21u
        };
        uint8_t hash[32];
        uint8_t sigFull[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigFullLen;

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));

        /* First produce the canonical signature (sigFullLen = 72 for this RFC vector). */
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                   hash, sizeof(hash), sigFull, sizeof(sigFull), &sigFullLen) == true);
        SSF_ASSERT(sigFullLen == 72u);

        /* Sign into a buffer one byte too small, bracketed by head/tail sentinel bytes. */
        {
            uint8_t guarded[(1u + (72u - 1u)) + 1u]; /* head sentinel | sig | tail sentinel */
            uint8_t *sigSmall = &guarded[1];
            size_t sigSmallSize = 71u;
            size_t sigOutLen = 999u;

            memset(guarded, 0xA5u, sizeof(guarded));
            SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                       hash, sizeof(hash), sigSmall, sigSmallSize, &sigOutLen) == false);

            SSF_ASSERT(guarded[0] == 0xA5u);
            SSF_ASSERT(guarded[sizeof(guarded) - 1u] == 0xA5u);
            /* The head may hold the SEQUENCE header; the tail sentinel must be intact. */
        }

        /* Sign into an exactly-sized buffer succeeds and produces the same DER bytes. */
        {
            uint8_t sigExact[72];
            size_t sigExactLen;
            SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                       hash, sizeof(hash), sigExact, sizeof(sigExact), &sigExactLen) == true);
            SSF_ASSERT(sigExactLen == sigFullLen);
            SSF_ASSERT(memcmp(sigExact, sigFull, sigFullLen) == 0);
        }
    }

    /* ---- Verify rejects sig lengths 0..7 (below the strict-DER minimum) without overflow ---- */
    {
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
        uint8_t shortSig[7] = { 0x30u, 0x05u, 0x02u, 0x01u, 0x01u, 0x02u, 0x01u };
        size_t i;

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));

        for (i = 0; i <= 7u; i++)
        {
            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey),
                       hash, sizeof(hash), shortSig, i) == false);
        }
    }

    /* ---- Verify rejects an INTEGER with an extra leading 0x00 before a byte < 0x80 ---- */
    {
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
        /* SEQUENCE(0x47=71) { INT(0x21=33){00 01 ..32 bytes..}, INT(0x20=32){5A ..32 bytes..} } */
        uint8_t badSig[73] = {
            0x30u, 0x47u,
            0x02u, 0x21u,
            0x00u, /* extra leading zero */
            0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u, /* next byte 0x01 < 0x80 */
            0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u,
            0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u, 0x18u,
            0x19u, 0x1Au, 0x1Bu, 0x1Cu, 0x1Du, 0x1Eu, 0x1Fu, 0x20u,
            0x02u, 0x20u,
            0x5Au, 0x5Bu, 0x5Cu, 0x5Du, 0x5Eu, 0x5Fu, 0x60u, 0x61u,
            0x62u, 0x63u, 0x64u, 0x65u, 0x66u, 0x67u, 0x68u, 0x69u,
            0x6Au, 0x6Bu, 0x6Cu, 0x6Du, 0x6Eu, 0x6Fu, 0x70u, 0x71u,
            0x72u, 0x73u, 0x74u, 0x75u, 0x76u, 0x77u, 0x78u, 0x79u
        };

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey),
                                  hash, sizeof(hash), badSig, sizeof(badSig)) == false);
    }

    /* ---- Sign / PubKeyFromPrivKey reject the all-zero (d == 0) private key ---- */
    {
        uint8_t zeroPriv[32] = {0};
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t hash[32];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));
        SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P256, zeroPriv, sizeof(zeroPriv),
                                             pubKey, sizeof(pubKey), &pubKeyLen) == false);
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, zeroPriv, sizeof(zeroPriv),
                                hash, sizeof(hash), sig, sizeof(sig), &sigLen) == false);
#else
        (void)sig;
        (void)sigLen;
#endif
    }

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
        uint8_t sig1[SSF_ECDSA_MAX_SIG_SIZE];
        uint8_t sig2[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sig1Len;
        size_t sig2Len;

        SSFSHA256((const uint8_t *)"deterministic", 13, hash, sizeof(hash));

        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig1, sizeof(sig1), &sig1Len) == true);
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig2, sizeof(sig2), &sig2Len) == true);

        /* RFC 6979 deterministic: same key + same hash = same signature */
        SSF_ASSERT(sig1Len == sig2Len);
        SSF_ASSERT(memcmp(sig1, sig2, sig1Len) == 0);
    }

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
    /* ---- P-256: projective verify check accepts a Jacobian R with Z != 1 ---- */
    {
        SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rx, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(ry, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rOk, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(rBad, SSF_EC_MAX_LIMBS);
        SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P256);

        /* k = 12345 -- any value > 1 produces a Jacobian R with Z != 1 after the doublings/adds. */
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
#endif /* SSF_EC_CONFIG_FIXED_BASE_P256 */

    /* ---- P-256: projective verify wraparound branch: synthetic R with X = n + 1, r = 1 ---- */
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
        (void)SSFBNAdd(&R.x, &c->n, &rWrap); /* R.x = n + 1, < p since 1 < p - n */

        /* Wraparound branch: accepts r=1 because (1 + n) * 1^2 == n + 1 == R.x (mod p). */
        SSF_ASSERT(_SSFECDSAVerifyCheckRForTest(SSF_EC_CURVE_P256, &R, &rWrap) == true);

        /* Negative: r=2 should NOT match. (2+n)*1^2 = n+2 != n+1, and 2*1^2 = 2 != n+1. */
        SSFBNSetUint32(&rNotMatch, 2u, c->limbs);
        SSF_ASSERT(_SSFECDSAVerifyCheckRForTest(SSF_EC_CURVE_P256, &R, &rNotMatch) == false);
    }

    /* ---- (Gap 6) RFC 5903 Sec. 8.1 ECDH P-256 known-answer test ---- */
    {
        /* RFC 5903 Sec. 8.1: i (initiator's privKey) */
        static const uint8_t privKey[] = {
            0xC8u, 0x8Fu, 0x01u, 0xF5u, 0x10u, 0xD9u, 0xACu, 0x3Fu,
            0x70u, 0xA2u, 0x92u, 0xDAu, 0xA2u, 0x31u, 0x6Du, 0xE5u,
            0x44u, 0xE9u, 0xAAu, 0xB8u, 0xAFu, 0xE8u, 0x40u, 0x49u,
            0xC6u, 0x2Au, 0x9Cu, 0x57u, 0x86u, 0x2Du, 0x14u, 0x33u
        };
        /* RFC 5903 Sec. 8.1: gr (responder's pubKey) in SEC1 uncompressed form */
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
        /* RFC 5903 Sec. 8.1: zx (shared secret = x-coord of [i]gr = [r]gi) */
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
    /* ---- RFC 6979 Sec. A.2.6: P-384/SHA-384 sign and verify KAT for "sample" ---- */
    {
        /* RFC 6979 Sec. A.2.6: x (privKey, 48 bytes) */
        static const uint8_t privKey[] = {
            0x6Bu, 0x9Du, 0x3Du, 0xADu, 0x2Eu, 0x1Bu, 0x8Cu, 0x1Cu,
            0x05u, 0xB1u, 0x98u, 0x75u, 0xB6u, 0x65u, 0x9Fu, 0x4Du,
            0xE2u, 0x3Cu, 0x3Bu, 0x66u, 0x7Bu, 0xF2u, 0x97u, 0xBAu,
            0x9Au, 0xA4u, 0x77u, 0x40u, 0x78u, 0x71u, 0x37u, 0xD8u,
            0x96u, 0xD5u, 0x72u, 0x4Eu, 0x4Cu, 0x70u, 0xA8u, 0x25u,
            0xF8u, 0x72u, 0xC9u, 0xEAu, 0x60u, 0xD2u, 0xEDu, 0xF5u
        };
        /* Expected pubKey U = x*G in SEC 1 uncompressed (1 + 2*48 = 97 bytes) */
        static const uint8_t expPub[97] = {
            0x04u,
            /* Ux */
            0xECu, 0x3Au, 0x4Eu, 0x41u, 0x5Bu, 0x4Eu, 0x19u, 0xA4u,
            0x56u, 0x86u, 0x18u, 0x02u, 0x9Fu, 0x42u, 0x7Fu, 0xA5u,
            0xDAu, 0x9Au, 0x8Bu, 0xC4u, 0xAEu, 0x92u, 0xE0u, 0x2Eu,
            0x06u, 0xAAu, 0xE5u, 0x28u, 0x6Bu, 0x30u, 0x0Cu, 0x64u,
            0xDEu, 0xF8u, 0xF0u, 0xEAu, 0x90u, 0x55u, 0x86u, 0x60u,
            0x64u, 0xA2u, 0x54u, 0x51u, 0x54u, 0x80u, 0xBCu, 0x13u,
            /* Uy */
            0x80u, 0x15u, 0xD9u, 0xB7u, 0x2Du, 0x7Du, 0x57u, 0x24u,
            0x4Eu, 0xA8u, 0xEFu, 0x9Au, 0xC0u, 0xC6u, 0x21u, 0x89u,
            0x67u, 0x08u, 0xA5u, 0x93u, 0x67u, 0xF9u, 0xDFu, 0xB9u,
            0xF5u, 0x4Cu, 0xA8u, 0x4Bu, 0x3Fu, 0x1Cu, 0x9Du, 0xB1u,
            0x28u, 0x8Bu, 0x23u, 0x1Cu, 0x3Au, 0xE0u, 0xD4u, 0xFEu,
            0x73u, 0x44u, 0xFDu, 0x25u, 0x33u, 0x26u, 0x47u, 0x20u
        };
        /* RFC 6979 A.2.6 expected r, s for SHA-384 / "sample" (48 bytes each) */
        static const uint8_t expR[48] = {
            0x94u, 0xEDu, 0xBBu, 0x92u, 0xA5u, 0xECu, 0xB8u, 0xAAu,
            0xD4u, 0x73u, 0x6Eu, 0x56u, 0xC6u, 0x91u, 0x91u, 0x6Bu,
            0x3Fu, 0x88u, 0x14u, 0x06u, 0x66u, 0xCEu, 0x9Fu, 0xA7u,
            0x3Du, 0x64u, 0xC4u, 0xEAu, 0x95u, 0xADu, 0x13u, 0x3Cu,
            0x81u, 0xA6u, 0x48u, 0x15u, 0x2Eu, 0x44u, 0xACu, 0xF9u,
            0x6Eu, 0x36u, 0xDDu, 0x1Eu, 0x80u, 0xFAu, 0xBEu, 0x46u
        };
        static const uint8_t expS[48] = {
            0x99u, 0xEFu, 0x4Au, 0xEBu, 0x15u, 0xF1u, 0x78u, 0xCEu,
            0xA1u, 0xFEu, 0x40u, 0xDBu, 0x26u, 0x03u, 0x13u, 0x8Fu,
            0x13u, 0x0Eu, 0x74u, 0x0Au, 0x19u, 0x62u, 0x45u, 0x26u,
            0x20u, 0x3Bu, 0x63u, 0x51u, 0xD0u, 0xA3u, 0xA9u, 0x4Fu,
            0xA3u, 0x29u, 0xC1u, 0x45u, 0x78u, 0x6Eu, 0x67u, 0x9Eu,
            0x7Bu, 0x82u, 0xC7u, 0x1Au, 0x38u, 0x62u, 0x8Au, 0xC8u
        };
        uint8_t pubKey[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        size_t pubKeyLen;
        uint8_t hash[48];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        size_t sigLen;

        /* Derive pubKey from privKey, then check it matches RFC 6979 A.2.6's documented U. */
        SSF_ASSERT(SSFECDSAPubKeyFromPrivKey(SSF_EC_CURVE_P384,
                   privKey, sizeof(privKey),
                   pubKey, sizeof(pubKey), &pubKeyLen) == true);
        SSF_ASSERT(pubKeyLen == sizeof(expPub));
        SSF_ASSERT(memcmp(pubKey, expPub, sizeof(expPub)) == 0);

        /* r and s have MSB set: each INTEGER is 49 bytes and the total is 104 bytes (max). */
        SSFSHA384((const uint8_t *)"sample", 6, hash, sizeof(hash));
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P384, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(sigLen == 104u);
        SSF_ASSERT(sig[0] == 0x30u);
        SSF_ASSERT(sig[1] == 0x66u);
        SSF_ASSERT(sig[2] == 0x02u);
        SSF_ASSERT(sig[3] == 0x31u);
        SSF_ASSERT(sig[4] == 0x00u);
        SSF_ASSERT(memcmp(&sig[5], expR, 48) == 0);
        SSF_ASSERT(sig[53] == 0x02u);
        SSF_ASSERT(sig[54] == 0x31u);
        SSF_ASSERT(sig[55] == 0x00u);
        SSF_ASSERT(memcmp(&sig[56], expS, 48) == 0);

        /* Round-trip verify confirms the produced signature parses and validates. */
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P384, pubKey, pubKeyLen,
                   hash, sizeof(hash), sig, sigLen) == true);

        /* Negative: tampering s rejects (exercises the P-384 verify path on a corrupted s). */
        {
            uint8_t bad[SSF_ECDSA_MAX_SIG_SIZE];
            memcpy(bad, sig, sigLen);
            bad[sigLen - 1u] ^= 0x01u;
            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P384, pubKey, pubKeyLen,
                       hash, sizeof(hash), bad, sigLen) == false);
        }
    }

    /* ---- RFC 5903 Sec. 8.2 ECDH P-384 KAT using the symmetric (r, gi) -> z form ---- */
    {
        /* RFC 5903 Sec. 8.2: r (responder's privKey, 48 bytes) */
        static const uint8_t privKey[] = {
            0x41u, 0xCBu, 0x07u, 0x79u, 0xB4u, 0xBDu, 0xB8u, 0x5Du,
            0x47u, 0x84u, 0x67u, 0x25u, 0xFBu, 0xECu, 0x3Cu, 0x94u,
            0x30u, 0xFAu, 0xB4u, 0x6Cu, 0xC8u, 0xDCu, 0x50u, 0x60u,
            0x85u, 0x5Cu, 0xC9u, 0xBDu, 0xA0u, 0xAAu, 0x29u, 0x42u,
            0xE0u, 0x30u, 0x83u, 0x12u, 0x91u, 0x6Bu, 0x8Eu, 0xD2u,
            0x96u, 0x0Eu, 0x4Bu, 0xD5u, 0x5Au, 0x74u, 0x48u, 0xFCu
        };
        /* RFC 5903 Sec. 8.2: gi (initiator's pubKey) in SEC1 uncompressed form */
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
        /* RFC 5903 Sec. 8.2: zx (shared secret) */
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

    /* ---- P-384: _SSFBNReduceP384 borrow/carry regression via (p-1) * (p-1) mod p ---- */
    {
        SSFBN_DEFINE(a, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(result, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(expected, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(one, SSF_EC_MAX_LIMBS);
        const SSFECCurveParams_t *c = SSFECGetCurveParams(SSF_EC_CURVE_P384);

        SSFBNSetOne(&one, c->limbs);

        /* Create a = p - 1 (large value near the modulus) */
        SSFBNSub(&a, &c->p, &one);
        a.len = c->limbs;

        /* Create b = p - 1 (another large value) */
        SSFBNCopy(&b, &a);
        b.len = c->limbs;

        /* (p-1) * (p-1) mod p = 1; the large product needs multiple correction iterations. */
        SSFBNCopy(&expected, &one);
        expected.len = c->limbs;

        /* Perform the modular multiplication that triggers _SSFBNReduceP384. */
        SSFBNModMulNIST(&result, &a, &b, &c->p);

        /* Verify the result matches the expected value. */
        SSF_ASSERT(SSFBNCmp(&result, &expected) == 0);

        /* Additional verification: result should be < p */
        SSF_ASSERT(SSFBNCmp(&result, &c->p) < 0);

        /* Test another edge case: (p-2) * 2 mod p should equal p-4 */
        SSFBN_DEFINE(two, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(pMinus2, SSF_EC_MAX_LIMBS);
        SSFBN_DEFINE(pMinus4, SSF_EC_MAX_LIMBS);

        SSFBNSetUint32(&two, 2u, c->limbs);
        SSFBNSub(&pMinus2, &c->p, &two);
        pMinus2.len = c->limbs;

        /* Expected: (p-2) * 2 = 2p - 4 == -4 == p-4 (mod p) */
        SSFBNSetUint32(&pMinus4, 4u, c->limbs);
        SSFBNSub(&pMinus4, &c->p, &pMinus4);
        pMinus4.len = c->limbs;

        SSFBNModMulNIST(&result, &pMinus2, &two, &c->p);
        SSF_ASSERT(SSFBNCmp(&result, &pMinus4) == 0);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

#if SSF_ECDSA_OSSL_VERIFY == 1
    /* === Sign-with-SSF / verify-with-OpenSSL (and reverse) interop ======================= */
    SSF_UT_PRINTF("--- ssfecdsa OpenSSL sign/verify interop ---\n");

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

        /* === SSF signs -> OpenSSL verifies (P-256/SHA-256) === */
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P256,
                   privKey, sizeof(privKey),
                   pubKey,  sizeof(pubKey), &pubKeyLen) == true);

        for (mi = 0; mi < (sizeof(messages) / sizeof(messages[0])); mi++)
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
            SSF_ASSERT(osslSig != NULL);
            verifyResult = ECDSA_do_verify(hash, sizeof(hash), osslSig, eckey);
            SSF_ASSERT(verifyResult == 1);
            ECDSA_SIG_free(osslSig);
            EC_KEY_free(eckey);
        }

        /* === OpenSSL signs -> SSF verifies (P-256/SHA-256) === */
        for (mi = 0; mi < (sizeof(messages) / sizeof(messages[0])); mi++)
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
            SSF_ASSERT((derLen > 0) && (derLen <= (int)sizeof(osslDer)));
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

        /* === SSF signs -> OpenSSL verifies (P-384/SHA-384) === */
        SSF_ASSERT(SSFECDSAKeyGen(SSF_EC_CURVE_P384,
                   privKey, sizeof(privKey),
                   pubKey,  sizeof(pubKey), &pubKeyLen) == true);

        for (mi = 0; mi < (sizeof(messages) / sizeof(messages[0])); mi++)
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

        /* === OpenSSL signs -> SSF verifies (P-384/SHA-384) === */
        for (mi = 0; mi < (sizeof(messages) / sizeof(messages[0])); mi++)
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
            SSF_ASSERT((derLen > 0) && (derLen <= (int)sizeof(osslDer)));
            ECDSA_SIG_free(osslSig);

            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P384,
                       pubKey, pubKeyLen, hash, sizeof(hash),
                       osslDer, (size_t)derLen) == true);
            EC_KEY_free(eckey);
        }
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

    SSF_UT_PRINTF("--- end ssfecdsa OpenSSL interop ---\n");

    /* OpenSSL cross-validation: random fuzz, ECDH cross-check and corner cases per curve. */
    SSF_UT_PRINTF("--- ssfecdsa OpenSSL random fuzz + ECDH + corner cases ---\n");
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    _VerifyECDSARandomAgainstOpenSSL(SSF_EC_CURVE_P256, 25u);
    _VerifyECDHAgainstOpenSSL(SSF_EC_CURVE_P256, 25u);
    _VerifyECDSACornerCasesAgainstOpenSSL(SSF_EC_CURVE_P256);
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    _VerifyECDSARandomAgainstOpenSSL(SSF_EC_CURVE_P384, 15u);
    _VerifyECDHAgainstOpenSSL(SSF_EC_CURVE_P384, 15u);
    _VerifyECDSACornerCasesAgainstOpenSSL(SSF_EC_CURVE_P384);
#endif
    SSF_UT_PRINTF("--- end ssfecdsa OpenSSL random fuzz + ECDH + corner cases ---\n");
#endif /* SSF_ECDSA_OSSL_VERIFY */

#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN; the Wycheproof verify and ECDH vectors below always run */

#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* ---- P-256: SSFECDSAPubKeyIsValid oracle (runs in verify-only builds too) ---- */
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

    /* === Wycheproof ECDSA P-256/SHA-256 verify vectors (counts mismatches, no early abort) === */
    {
        #include "wycheproof_ecdsa_p256.h"
        uint8_t hash[32];
        uint16_t i;
        uint16_t pass = 0;
        uint16_t mismatches = 0;

        SSF_UT_PRINTF("--- Wycheproof ECDSA P-256 verify (%u tests) ---\n",
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

            /* Did verify match the expected result? */
            if (got == t->expectedValid)
            {
                /* Yes, count a pass */
                pass++;
            }
            else
            {
                /* No, count and report the mismatch */
                mismatches++;
                SSF_UT_PRINTF("  tcId %4u: expected %s, got %s (sig %u bytes)\n",
                       (unsigned)t->tcId,
                       t->expectedValid ? "valid  " : "invalid",
                       got               ? "valid  " : "invalid",
                       (unsigned)t->sigLen);
            }
        }
        SSF_UT_PRINTF("--- Wycheproof ECDSA P-256: %u/%u pass, %u mismatches ---\n",
               (unsigned)pass, (unsigned)SSF_WYCHEPROOF_ECDSA_P256_NTESTS,
               (unsigned)mismatches);
        SSF_ASSERT(mismatches == 0u);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* === Wycheproof ECDSA P-384/SHA-384 verify vectors === */
    {
        #include "wycheproof_ecdsa_p384.h"
        uint8_t hash[48];
        uint16_t i;
        uint16_t pass = 0;
        uint16_t mismatches = 0;

        SSF_UT_PRINTF("--- Wycheproof ECDSA P-384 verify (%u tests) ---\n",
               (unsigned)SSF_WYCHEPROOF_ECDSA_P384_NTESTS);
        for (i = 0; i < (uint16_t)SSF_WYCHEPROOF_ECDSA_P384_NTESTS; i++)
        {
            const _SSFWycheproofEcdsaP384Test_t *t = &_wp_P384_tests[i];
            bool got;

            SSFSHA384(t->msg, (uint32_t)t->msgLen, hash, sizeof(hash));
            got = SSFECDSAVerify(SSF_EC_CURVE_P384,
                                 t->pubKey, t->pubKeyLen,
                                 hash, sizeof(hash),
                                 t->sig, t->sigLen);

            /* Did verify match the expected result? */
            if (got == t->expectedValid)
            {
                /* Yes, count a pass */
                pass++;
            }
            else
            {
                /* No, count and report the mismatch */
                mismatches++;
                SSF_UT_PRINTF("  tcId %4u: expected %s, got %s (sig %u bytes)\n",
                       (unsigned)t->tcId,
                       t->expectedValid ? "valid  " : "invalid",
                       got               ? "valid  " : "invalid",
                       (unsigned)t->sigLen);
            }
        }
        SSF_UT_PRINTF("--- Wycheproof ECDSA P-384: %u/%u pass, %u mismatches ---\n",
               (unsigned)pass, (unsigned)SSF_WYCHEPROOF_ECDSA_P384_NTESTS,
               (unsigned)mismatches);
        SSF_ASSERT(mismatches == 0u);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* === Wycheproof ECDH P-256 vectors ("acceptable" results never count as mismatches) === */
    {
        #include "wycheproof_ecdh_p256.h"
        /* Known mismatches: malformed SPKI curve params, not applicable to raw SEC1 input. */
        static const uint16_t knownEcdhP256Mismatches[] = {
            352u, 353u, 358u, 359u, 363u
        };
        uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
        size_t sharedLen;
        uint16_t i;
        uint16_t pass = 0;
        uint16_t mismatches = 0;
        uint16_t acceptableSkipped = 0;
        uint16_t knownIssue = 0;

        SSF_UT_PRINTF("--- Wycheproof ECDH P-256 (%u tests) ---\n",
               (unsigned)SSF_WYCHEPROOF_ECDH_P256_NTESTS);
        for (i = 0; i < (uint16_t)SSF_WYCHEPROOF_ECDH_P256_NTESTS; i++)
        {
            const _SSFWycheproofEcdhP256Test_t *t = &_wp_P256_ecdh_tests[i];
            bool got;
            bool sharedOk = false;
            bool isKnown = false;
            uint16_t ki;

            for (ki = 0;
                 ki < (sizeof(knownEcdhP256Mismatches) / sizeof(knownEcdhP256Mismatches[0]));
                 ki++)
            {
                if (knownEcdhP256Mismatches[ki] == t->tcId) { isKnown = true; break; }
            }

            got = SSFECDHComputeSecret(SSF_EC_CURVE_P256,
                                       t->privKey, t->privKeyLen,
                                       t->pubKey,  t->pubKeyLen,
                                       shared, sizeof(shared), &sharedLen);
            if (got)
            {
                sharedOk = ((sharedLen == t->sharedLen) &&
                            (memcmp(shared, t->shared, t->sharedLen) == 0));
            }

            if (t->acceptable) { acceptableSkipped++; continue; }

            bool expectedOk = (t->expectedValid ? (got && sharedOk) : ((!got) || (!sharedOk)));

            /* Did the result match the expectation? */
            if (expectedOk)
            {
                /* Yes, count a pass */
                pass++;
            }
            /* No, is it a known mismatch? */
            else if (isKnown)
            {
                /* Yes, count a known issue */
                knownIssue++;
            }
            else
            {
                /* No, count and report the new mismatch */
                mismatches++;
                SSF_UT_PRINTF("  tcId %4u: expected %s, got %s\n",
                       (unsigned)t->tcId,
                       t->expectedValid ? "valid" : "invalid",
                       got ? (sharedOk ? "valid" : "wrong-shared") : "rejected");
            }
        }
        SSF_UT_PRINTF("--- Wycheproof ECDH P-256: %u pass, %u acceptable, %u known-issue, "
                      "%u new-mismatches ---\n",
                      (unsigned)pass, (unsigned)acceptableSkipped, (unsigned)knownIssue,
                      (unsigned)mismatches);
        SSF_ASSERT(mismatches == 0u);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* === Wycheproof ECDH P-384 vectors === */
    {
        #include "wycheproof_ecdh_p384.h"
        /* P-384 known-issue allowlist (empty; populate from a first run as for P-256). */
        uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
        size_t sharedLen;
        uint16_t i;
        uint16_t pass = 0;
        uint16_t mismatches = 0;
        uint16_t acceptableSkipped = 0;
        uint16_t knownIssue = 0;
        uint16_t firstFails[16];
        uint16_t nFirstFails = 0;

        SSF_UT_PRINTF("--- Wycheproof ECDH P-384 (%u tests) ---\n",
               (unsigned)SSF_WYCHEPROOF_ECDH_P384_NTESTS);
        for (i = 0; i < (uint16_t)SSF_WYCHEPROOF_ECDH_P384_NTESTS; i++)
        {
            const _SSFWycheproofEcdhP384Test_t *t = &_wp_P384_ecdh_tests[i];
            bool got;
            bool sharedOk = false;

            got = SSFECDHComputeSecret(SSF_EC_CURVE_P384,
                                       t->privKey, t->privKeyLen,
                                       t->pubKey,  t->pubKeyLen,
                                       shared, sizeof(shared), &sharedLen);
            if (got)
            {
                sharedOk = ((sharedLen == t->sharedLen) &&
                            (memcmp(shared, t->shared, t->sharedLen) == 0));
            }

            if (t->acceptable) { acceptableSkipped++; continue; }

            bool expectedOk = (t->expectedValid ? (got && sharedOk) : ((!got) || (!sharedOk)));

            /* Did the result match the expectation? */
            if (expectedOk)
            {
                /* Yes, count a pass */
                pass++;
            }
            else
            {
                /* No, count the mismatch and remember its tcId */
                mismatches++;
                if (nFirstFails < 16u) firstFails[nFirstFails++] = t->tcId;
            }
            (void)knownIssue;
        }
        SSF_UT_PRINTF("--- Wycheproof ECDH P-384: %u pass, %u acceptable, %u mismatches",
               (unsigned)pass, (unsigned)acceptableSkipped, (unsigned)mismatches);
        if (mismatches > 0u)
        {
            uint16_t k;
            SSF_UT_PRINTF(" (first fails:");
            for (k = 0; (k < nFirstFails) && (k < 8u); k++)
            {
                SSF_UT_PRINTF(" %u", (unsigned)firstFails[k]);
            }
            SSF_UT_PRINTF(")");
        }
        SSF_UT_PRINTF(" ---\n");
        SSF_ASSERT(mismatches == 0u);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */

#if SSF_CONFIG_BN_UNIT_TEST == 1
    /* ---- OPTIMIZE EC-O3: keygen/sign/verify/ECDH use only curve-width ModInv/ModMul ---- */
    {
        static const SSFECCurve_t curves[] = {
#if SSF_EC_CONFIG_ENABLE_P256 == 1
            SSF_EC_CURVE_P256,
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
            SSF_EC_CURVE_P384,
#endif
        };
        uint8_t priv[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t pub[SSF_ECDSA_MAX_PUB_KEY_SIZE];
        uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
        uint8_t secret[SSF_ECDSA_MAX_PRIV_KEY_SIZE];
        uint8_t hash[48];
        size_t pubLen;
        size_t sigLen;
        size_t secretLen;
        size_t privLen;
        uint16_t ci;

        memset(hash, 0x5A, sizeof(hash));
        for (ci = 0u; ci < (uint16_t)(sizeof(curves) / sizeof(curves[0])); ci++)
        {
            privLen = (curves[ci] == SSF_EC_CURVE_P256) ? 32u : 48u;
            _SSFBNFullWidthCalls = 0u;
            SSF_ASSERT(SSFECDSAKeyGen(curves[ci], priv, privLen, pub, sizeof(pub), &pubLen));
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
            SSF_ASSERT(SSFECDSASign(curves[ci], priv, privLen, hash, privLen, sig, sizeof(sig),
                                    &sigLen));
            SSF_ASSERT(SSFECDSAVerify(curves[ci], pub, pubLen, hash, privLen, sig, sigLen));
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */
            SSF_ASSERT(SSFECDHComputeSecret(curves[ci], priv, privLen, pub, pubLen, secret,
                                            sizeof(secret), &secretLen));
            SSF_ASSERT(_SSFBNFullWidthCalls == 0u);
        }
    }
#endif /* SSF_CONFIG_BN_UNIT_TEST */
}
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */
