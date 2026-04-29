/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfecdsa_ut.c                                                                                 */
/* Provides unit tests for the ssfecdsa ECDSA/ECDH module.                                      */
/* Test vectors from RFC 6979 appendix A.2.5 (P-256/SHA-256).                                   */
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

/* Cross-validate ECDSA sign/verify with OpenSSL on host builds where libcrypto is linked. Gated */
/* on SSF_CONFIG_HAVE_OPENSSL (1 on native macOS/Linux, 0 on cross builds -- see ssfport.h).     */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_ECDSA_UNIT_TEST == 1)
#define SSF_ECDSA_OSSL_VERIFY 1
#else
#define SSF_ECDSA_OSSL_VERIFY 0
#endif

#if SSF_ECDSA_OSSL_VERIFY == 1
/* This test file uses the legacy EC_KEY / ECDSA_do_* / ECDH_compute_key API as an interop oracle. */
/* Pin the exposed API to OpenSSL 1.1.1 so the 3.0+ deprecation markers don't fire here. Scoped to */
/* this translation unit; production code keeps -Wdeprecated-declarations active.                  */
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
/* ECDSA sign/verify interop helpers -- bridge SSF privKey/pubKey/sig bytes to OpenSSL EC_KEY    */
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

/* Curve metadata bundle: byte sizes and OpenSSL NID. Avoids scattering the curve->{nid,sizes}    */
/* mapping across each cross-check function.                                                       */
typedef struct
{
    int      nid;        /* OpenSSL NID for the curve. */
    size_t   privBytes;  /* Private-key serialized size. */
    size_t   pubBytes;   /* Public-key uncompressed size (1 + 2 * field). */
    size_t   hashBytes;  /* Recommended hash size (matches the curve's bit size). */
    size_t   secretBytes;/* ECDH shared-secret size (== field size). */
} _ECDSAOSSLCurveInfo_t;

static void _ECDSAOSSLCurveInfo(SSFECCurve_t curve, _ECDSAOSSLCurveInfo_t *info)
{
    if (curve == SSF_EC_CURVE_P256)
    {
        info->nid = NID_X9_62_prime256v1;
        info->privBytes = 32u; info->pubBytes = 65u;
        info->hashBytes = 32u; info->secretBytes = 32u;
    }
    else
    {
        SSF_ASSERT(curve == SSF_EC_CURVE_P384);
        info->nid = NID_secp384r1;
        info->privBytes = 48u; info->pubBytes = 97u;
        info->hashBytes = 48u; info->secretBytes = 48u;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Random fuzz: per curve x iters, exercise every cross-direction (SSF<->OpenSSL) on randomly    */
/* generated keys and randomly generated hashes. Catches DER edge cases, leftmost-bits truncation */
/* off-by-ones, and any state-corruption between operations that the fixed-message interop misses */
/* by reusing one keypair.                                                                         */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyECDSARandomAgainstOpenSSL(SSFECCurve_t curve, uint16_t iters)
{
    _ECDSAOSSLCurveInfo_t info;
    uint16_t i;

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
            /* OpenSSL's EC_KEY_check_key validates: priv in [1, n-1], pub on curve, and         */
            /* priv * G == pub. A failure here means SSF's KeyGen produced an inconsistent pair.  */
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
            SSF_ASSERT(derLen > 0 && derLen <= (int)sizeof(osslDer));
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

            /* Validity oracle: SSFECDSAPubKeyIsValid must agree with EC_KEY_check_key on the     */
            /* OpenSSL-generated public key (which is on-curve by construction).                  */
            SSF_ASSERT(SSFECDSAPubKeyIsValid(curve, osslPub, osslPubLen) == true);

            EC_KEY_free(osslKey);
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* ECDH cross-check: SSF and OpenSSL must derive the same shared secret given the same           */
/* (private, peer-public) inputs. Run with mixed origins -- keys from SSF, keys from OpenSSL,    */
/* and one of each -- to catch any corner where an SSF-imported pubkey and an OpenSSL-imported   */
/* pubkey diverge.                                                                                */
/* --------------------------------------------------------------------------------------------- */
static void _VerifyECDHAgainstOpenSSL(SSFECCurve_t curve, uint16_t iters)
{
    _ECDSAOSSLCurveInfo_t info;
    uint16_t i;

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
        EC_KEY *keyA, *keyB;
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

/* --------------------------------------------------------------------------------------------- */
/* Corner-case verification against OpenSSL.                                                      */
/*                                                                                                */
/* Random fuzz can miss identity-shaped inputs (all-zero hash, all-0xFF hash) and the DER         */
/* round-trip property. This routine drives those explicitly per curve.                           */
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

    /* DER round-trip property: parse SSF's signature with OpenSSL, re-encode, expect byte-      */
    /* identical output. Catches superfluous-leading-byte and length-encoding deviations from    */
    /* canonical DER (which OpenSSL would re-canonicalize on the way out).                       */
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

        SSF_ASSERT(osslKey != NULL); SSF_ASSERT(bnD != NULL);
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
#endif /* SSF_ECDSA_OSSL_VERIFY */

/* --------------------------------------------------------------------------------------------- */
/* Zeroization audit hooks                                                                       */
/* --------------------------------------------------------------------------------------------- */
/* The hardening invariant we want to enforce: by the time SSFECDSASign / SSFECDHComputeSecret / */
/* SSFECDSAKeyGen returns, every stack-local that ever held secret-derived material must have    */
/* been wiped. The hook fires from each function's unified cleanup label after the explicit       */
/* SSFBNZeroize calls -- a non-zero limb here means a code path slipped past zeroization.         */
typedef struct
{
    bool sawHook;
    bool nonZero;
    const char *firstNonZero;
} _SSFECDSAZeroAudit_t;

static bool _ECDSAUTLimbsAllZero(const SSFBN_t *bn)
{
    uint16_t i;
    if (bn == NULL || bn->limbs == NULL) return true;
    for (i = 0; i < bn->cap; i++)
    {
        if (bn->limbs[i] != 0u) return false;
    }
    return true;
}

static void _ECDSAUTRecordBN(_SSFECDSAZeroAudit_t *a, const SSFBN_t *bn, const char *name)
{
    if (a->nonZero) return;
    if (!_ECDSAUTLimbsAllZero(bn))
    {
        a->nonZero = true;
        a->firstNonZero = name;
    }
}

static void _ECDSAUTSignHook(void *ctx,
                             const SSFBN_t *d, const SSFBN_t *k, const SSFBN_t *e,
                             const SSFBN_t *kInv, const SSFBN_t *tmp,
                             const SSFECPoint_t *R,
                             const SSFBN_t *Rx, const SSFBN_t *Ry)
{
    _SSFECDSAZeroAudit_t *a = (_SSFECDSAZeroAudit_t *)ctx;
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

static void _ECDSAUTECDHHook(void *ctx,
                             const SSFBN_t *d,
                             const SSFECPoint_t *S,
                             const SSFBN_t *Sx, const SSFBN_t *Sy)
{
    _SSFECDSAZeroAudit_t *a = (_SSFECDSAZeroAudit_t *)ctx;
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

static void _ECDSAUTKeyGenHook(void *ctx,
                               const SSFBN_t *d,
                               const uint8_t *entropy, size_t entropyLen)
{
    _SSFECDSAZeroAudit_t *a = (_SSFECDSAZeroAudit_t *)ctx;
    size_t i;
    a->sawHook = true;
    _ECDSAUTRecordBN(a, d, "d");
    if (entropy != NULL && !a->nonZero)
    {
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

void SSFECDSAUnitTest(void)
{
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    /* ---- Zeroization audit: Sign success path leaves no secret-derived limbs on stack ---- */
    /* The hook fires from Sign's unified cleanup label after explicit SSFBNZeroize. Any non-zero */
    /* limb is a slot that the implementation forgot to wipe. d, k, kInv are the obvious privacy- */
    /* sensitive ones; Rx/Ry/R.{x,y,z}/tmp/e are computed from k or d and must also be wiped.     */
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

        /* d = n exactly: SSFBNFromBytes succeeds but _SSFECDSAPrivKeyIsValid rejects (d >= n).   */
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

    /* ---- Zeroization audit: ECDH success path leaves no shared-secret limbs on stack ---- */
    /* d (local privKey) and S/Sx/Sy (the shared point and its affine coords -- i.e., the raw   */
    /* ECDH output) all need to be wiped at exit. Sy is wiped both as defense-in-depth and to   */
    /* prevent any future code change that exposes y from leaking it through stack memory.       */
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
        badPub[0] = 0x04u;  /* Identity-shaped -- rejected by SSFECPointDecode */

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

    /* ---- Zeroization audit: KeyGen wipes both d and the entropy seed buffer ---- */
    /* The entropy[] buffer is what feeds SSFPRNGInitContext, which produces d. Leaving entropy */
    /* on the stack defeats the privacy of d as effectively as leaving d itself.                 */
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

    /* ---- RFC 6979 A.2.5: canonical (r, s) KAT for P-256/SHA-256 "sample" ---- */
    /* Pins the deterministic nonce derivation, the (r, s) computation, and the DER wrapping     */
    /* against the RFC. Also exercises the non-CT s^-1 path in Verify on a known-good s -- if   */
    /* SSFBNModInvExt ever regressed for canonical-spec inputs this test would catch it.         */
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

        /* DER layout: 30 LL 02 RL r... 02 SL s... For RFC 6979 A.2.5 / "sample": both r and s  */
        /* have their MSB set (0xEF, 0xF7), so each INTEGER is 33 bytes (0x00 sign-pad + 32),   */
        /* yielding a 70-byte SEQUENCE content and a 72-byte total signature.                    */
        SSF_ASSERT(sigLen == 72u);
        SSF_ASSERT(sig[0] == 0x30u);
        SSF_ASSERT(sig[2] == 0x02u);
        SSF_ASSERT(sig[3] == 0x21u);  /* 33 = 0x21 */
        SSF_ASSERT(sig[4] == 0x00u);
        SSF_ASSERT(memcmp(&sig[5], expR, 32) == 0);
        SSF_ASSERT(sig[37] == 0x02u);
        SSF_ASSERT(sig[38] == 0x21u);
        SSF_ASSERT(sig[39] == 0x00u);
        SSF_ASSERT(memcmp(&sig[40], expS, 32) == 0);

        /* Round-trip verify: confirms the non-CT s^-1 path reaches the right answer for the    */
        /* canonical s. */
        SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey),
                   hash, sizeof(hash), sig, sigLen) == true);

        /* Negative: tampering s by one bit must reject. Targets the last byte of s, well past  */
        /* the DER header. */
        {
            uint8_t bad[SSF_ECDSA_MAX_SIG_SIZE];
            memcpy(bad, sig, sigLen);
            bad[sigLen - 1u] ^= 0x01u;
            SSF_ASSERT(SSFECDSAVerify(SSF_EC_CURVE_P256, pubKey, sizeof(pubKey),
                       hash, sizeof(hash), bad, sigLen) == false);
        }
    }

    /* ---- Sign rejects undersized sig buffer without overflowing it ---- */
    /* The DER encoder's "totalLen > sigSize" guard is the last line of defense before any byte */
    /* lands in the caller's buffer. Bracket it: a 1-byte-short buffer must reject; an exactly- */
    /* sized buffer must accept; the 1-byte-short buffer's tail must remain unwritten.           */
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

        /* Sign into a buffer one byte too small. The DER encoder must reject (return false)    */
        /* without writing a byte. Detect any spurious write by surrounding the small buffer    */
        /* with sentinel bytes and confirming all bytes (including the head/tail sentinels) are */
        /* untouched.                                                                            */
        {
            uint8_t guarded[1u + (72u - 1u) + 1u];   /* head sentinel | sig buffer | tail sentinel */
            uint8_t *sigSmall = &guarded[1];
            size_t sigSmallSize = 71u;
            size_t sigOutLen = 999u;

            memset(guarded, 0xA5u, sizeof(guarded));
            SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P256, privKey, sizeof(privKey),
                       hash, sizeof(hash), sigSmall, sigSmallSize, &sigOutLen) == false);

            SSF_ASSERT(guarded[0] == 0xA5u);                      /* head sentinel intact */
            SSF_ASSERT(guarded[sizeof(guarded) - 1u] == 0xA5u);   /* tail sentinel intact */
            /* The DER encoder is allowed to scribble the SEQUENCE header into the buffer head  */
            /* before the totalLen check fires (current implementation in fact does so via the  */
            /* pass-2 EncTagLen call), but it must not write past sigSmallSize. Verify the head */
            /* sentinel above already covers the lower-OOB direction; the assertion that the    */
            /* tail sentinel is intact covers the upper-OOB direction.                           */
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

    /* ---- Verify rejects sig buffers below the strict-DER minimum without overflow ---- */
    /* Strict DER validator's first check is `sigLen < 8u`, well before any sig-byte read past  */
    /* the first. Hand it lengths 0..7 and confirm rejection without crash.                      */
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

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
    /* ---- P-256: projective verify check accepts a Jacobian R with non-1 Z ---- */
    /* Builds R = [k]G with k > 1 (so Z != 1 in Jacobian form) and confirms the new projective    */
    /* _SSFECDSAVerifyCheckR accepts the matching r and rejects a tampered r. Gated on            */
    /* FIXED_BASE_P256 because SSFECScalarMulBaseP256 is only compiled when the comb table is in. */
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

        /* Wraparound branch: accepts r=1 because (1 + n) * 1^2 == n + 1 == R.x (mod p). */
        SSF_ASSERT(_SSFECDSAVerifyCheckRForTest(SSF_EC_CURVE_P256, &R, &rWrap) == true);

        /* Negative: r=2 should NOT match. (2+n)*1^2 = n+2 != n+1, and 2*1^2 = 2 != n+1.          */
        SSFBNSetUint32(&rNotMatch, 2u, c->limbs);
        SSF_ASSERT(_SSFECDSAVerifyCheckRForTest(SSF_EC_CURVE_P256, &R, &rNotMatch) == false);
    }

    /* ---- (Gap 6) RFC 5903 Sec. 8.1 ECDH P-256 known-answer test ---- */
    /* Verifies SSFECDHComputeSecret produces the documented shared secret for a known privKey  */
    /* + peerPubKey pair from RFC 5903 Sec. 8.1. The Alice/Bob roundtrip test only verifies     */
    /* self-consistency -- this catches arithmetic bugs that would silently produce mutually-    */
    /* matching but incorrect shared secrets.                                                    */
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
    /* Pins the deterministic-nonce derivation, (r, s) computation, and DER wrapping for the    */
    /* P-384 curve. Until this test, P-384 was covered only by ECDH-KAT and Wycheproof verify;  */
    /* this is the first P-384 *sign* known-answer test in the suite.                            */
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

        /* Sign and check the canonical (r, s). r=0x94..., s=0x99... -- both have MSB set, so  */
        /* each INTEGER is 49 bytes (0x00 sign-pad + 48), giving a 102-byte SEQUENCE content    */
        /* and a 104-byte total signature (the P-384 max).                                       */
        SSFSHA384((const uint8_t *)"sample", 6, hash, sizeof(hash));
        SSF_ASSERT(SSFECDSASign(SSF_EC_CURVE_P384, privKey, sizeof(privKey),
                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(sigLen == 104u);
        SSF_ASSERT(sig[0] == 0x30u);
        SSF_ASSERT(sig[1] == 0x66u);  /* 102 = 0x66 */
        SSF_ASSERT(sig[2] == 0x02u);
        SSF_ASSERT(sig[3] == 0x31u);  /* 49 = 0x31 */
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

    /* ---- RFC 5903 Sec. 8.2 ECDH P-384 known-answer test (using the symmetric (r, gi) -> z form) ---- */
    /* ECDH is symmetric: [i]gr = [r]gi = z. We use (r, gi) here (responder's privKey + initiator's */
    /* pubKey) which gives the same expected zx.                                                     */
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

    /* ---- P-384: modular reduction edge case (sparse coordinate bug regression test) ---- */
    /* Tests the fix for unconditional borrow/carry decrements in _SSFBNReduceP384.         */
    /* Uses SSFBNModMulNIST to trigger the internal _SSFBNReduceP384 with inputs that would */
    /* expose the bug where borrow/carry counters were unconditionally decremented instead  */
    /* of only when add/sub operations actually overflow/underflow.                          */
    {
        /* This test exercises the specific bug pattern by using multiplication that        */
        /* creates large intermediate values requiring multiple correction iterations where  */
        /* some iterations don't cross the 2^384 boundary. The old code would incorrectly  */
        /* decrement borrow/carry on every iteration; the fixed code only decrements on     */
        /* actual overflow/underflow.                                                        */

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

        /* Computing (p-1) * (p-1) mod p = (p^2 - 2p + 1) mod p = 1 mod p */
        /* But the intermediate product p^2 - 2p + 1 is much larger than p and will       */
        /* trigger the reduction bug pattern with multiple correction iterations.          */
        /* The expected result should be 1.                                                */
        SSFBNCopy(&expected, &one);
        expected.len = c->limbs;

        /* Perform the modular multiplication that will trigger _SSFBNReduceP384 */
        /* This creates the large intermediate product that exercises the correction loops */
        SSFBNModMulNIST(&result, &a, &b, &c->p);

        /* Verify the result matches expected value */
        /* With the old buggy code, this would fail due to incorrect counter management */
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
    /* ====================================================================================== */
    /* === Sign-with-SSF / verify-with-OpenSSL (and reverse) interop ========================  */
    /* ====================================================================================== */
    /* Catches DER signature encoding bugs (length fields, ASN.1 INTEGER tag/leading-zero      */
    /* handling) and end-to-end serialization mismatches that the per-primitive KATs miss.     */
    /* Run for both directions on each enabled curve.                                           */
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

        /* === OpenSSL signs -> SSF verifies (P-256/SHA-256) === */
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

        /* === SSF signs -> OpenSSL verifies (P-384/SHA-384) === */
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

        /* === OpenSSL signs -> SSF verifies (P-384/SHA-384) === */
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

    SSF_UT_PRINTF("--- end ssfecdsa OpenSSL interop ---\n");

    /* Comprehensive OpenSSL cross-validation, mirroring the ssfbn pattern: random fuzz across   */
    /* both curves (catches DER-edge / leftmost-bits / state-corruption bugs the fixed-message   */
    /* interop above can miss with one keypair), ECDH cross-check (no prior coverage), and       */
    /* corner cases (zero hash, all-0xFF hash, DER round-trip, pubkey derivation).               */
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

#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN -- Sign-using blocks above; Wycheproof verify vectors */
       /* and ECDH below run regardless because they do not use SSFECDSASign.                 */

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

            if (got == t->expectedValid)
            {
                pass++;
            }
            else
            {
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
        uint16_t pass = 0, mismatches = 0;

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

            if (got == t->expectedValid)
            {
                pass++;
            }
            else
            {
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
    /* === Wycheproof ECDH P-256 vectors ===                                                */
    /* Each test case: privKey + peer pubKey -> expected shared secret. SSF accepts only     */
    /* uncompressed SEC1 pubkeys; SPKI-wrapped ones were stripped at codegen and tests where */
    /* SPKI was malformed are marked with the original bytes (SSF must reject them).         */
    /* "acceptable" Wycheproof results don't increment mismatches either way.                */
    {
        #include "wycheproof_ecdh_p256.h"
        /* Remaining known-mismatch tcIds (now only category B): Wycheproof tests with malformed */
        /* curve parameters embedded in SubjectPublicKeyInfo DER. SSF's API takes raw SEC1 bytes  */
        /* and the codegen strips the SPKI wrapper, so these specific Wycheproof failure modes   */
        /* are not applicable to SSF's design.                                                   */
        static const uint16_t knownEcdhP256Mismatches[] = {
            352u, 353u, 358u, 359u, 363u
        };
        uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
        size_t sharedLen;
        uint16_t i;
        uint16_t pass = 0, mismatches = 0, acceptableSkipped = 0, knownIssue = 0;

        SSF_UT_PRINTF("--- Wycheproof ECDH P-256 (%u tests) ---\n",
               (unsigned)SSF_WYCHEPROOF_ECDH_P256_NTESTS);
        for (i = 0; i < (uint16_t)SSF_WYCHEPROOF_ECDH_P256_NTESTS; i++)
        {
            const _SSFWycheproofEcdhP256Test_t *t = &_wp_P256_ecdh_tests[i];
            bool got, sharedOk = false, isKnown = false;
            uint16_t ki;

            for (ki = 0; ki < sizeof(knownEcdhP256Mismatches) / sizeof(knownEcdhP256Mismatches[0]); ki++)
            {
                if (knownEcdhP256Mismatches[ki] == t->tcId) { isKnown = true; break; }
            }

            got = SSFECDHComputeSecret(SSF_EC_CURVE_P256,
                                       t->privKey, t->privKeyLen,
                                       t->pubKey,  t->pubKeyLen,
                                       shared, sizeof(shared), &sharedLen);
            if (got)
            {
                sharedOk = (sharedLen == t->sharedLen) &&
                           (memcmp(shared, t->shared, t->sharedLen) == 0);
            }

            if (t->acceptable) { acceptableSkipped++; continue; }

            bool expectedOk = t->expectedValid ? (got && sharedOk) : (!got || !sharedOk);

            if (expectedOk) pass++;
            else if (isKnown) knownIssue++;
            else
            {
                mismatches++;
                SSF_UT_PRINTF("  tcId %4u: expected %s, got %s\n",
                       (unsigned)t->tcId,
                       t->expectedValid ? "valid" : "invalid",
                       got ? (sharedOk ? "valid" : "wrong-shared") : "rejected");
            }
        }
        SSF_UT_PRINTF("--- Wycheproof ECDH P-256: %u pass, %u acceptable, %u known-issue, %u new-mismatches ---\n",
               (unsigned)pass, (unsigned)acceptableSkipped, (unsigned)knownIssue, (unsigned)mismatches);
        SSF_ASSERT(mismatches == 0u);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P256 */

#if SSF_EC_CONFIG_ENABLE_P384 == 1
    /* === Wycheproof ECDH P-384 vectors === */
    {
        #include "wycheproof_ecdh_p384.h"
        /* P-384 known-issue allowlist will be populated based on first run. Built up the same  */
        /* way as P-256: empty initial list, run, populate from output, re-run.                  */
        uint8_t shared[SSF_ECDH_MAX_SECRET_SIZE];
        size_t sharedLen;
        uint16_t i;
        uint16_t pass = 0, mismatches = 0, acceptableSkipped = 0, knownIssue = 0;
        uint16_t firstFails[16];
        uint16_t nFirstFails = 0;

        SSF_UT_PRINTF("--- Wycheproof ECDH P-384 (%u tests) ---\n",
               (unsigned)SSF_WYCHEPROOF_ECDH_P384_NTESTS);
        for (i = 0; i < (uint16_t)SSF_WYCHEPROOF_ECDH_P384_NTESTS; i++)
        {
            const _SSFWycheproofEcdhP384Test_t *t = &_wp_P384_ecdh_tests[i];
            bool got, sharedOk = false;

            got = SSFECDHComputeSecret(SSF_EC_CURVE_P384,
                                       t->privKey, t->privKeyLen,
                                       t->pubKey,  t->pubKeyLen,
                                       shared, sizeof(shared), &sharedLen);
            if (got)
            {
                sharedOk = (sharedLen == t->sharedLen) &&
                           (memcmp(shared, t->shared, t->sharedLen) == 0);
            }

            if (t->acceptable) { acceptableSkipped++; continue; }

            bool expectedOk = t->expectedValid ? (got && sharedOk) : (!got || !sharedOk);

            if (expectedOk) pass++;
            else
            {
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
            for (k = 0; k < nFirstFails && k < 8u; k++) SSF_UT_PRINTF(" %u", (unsigned)firstFails[k]);
            SSF_UT_PRINTF(")");
        }
        SSF_UT_PRINTF(" ---\n");
        SSF_ASSERT(mismatches == 0u);
    }
#endif /* SSF_EC_CONFIG_ENABLE_P384 */
}
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */
