/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfrsa_ut.c                                                                                   */
/* Provides unit tests for the ssfrsa RSA module.                                                */
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
#include "ssfrsa.h"
#include "ssfsha2.h"

/* Cross-check against OpenSSL when SSF_CONFIG_HAVE_OPENSSL is 1 (host builds link -lcrypto). */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_RSA_UNIT_TEST == 1)
#define SSF_RSA_OSSL_VERIFY 1
#else
#define SSF_RSA_OSSL_VERIFY 0
#endif

#if SSF_RSA_OSSL_VERIFY == 1
/* d2i_RSA*Key are deprecated in OpenSSL 3.x but still work; silence the warning here only. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#endif

#if SSF_CONFIG_RSA_UNIT_TEST == 1

/* The helpers below serve the RSA tests only, which need at least one key size */
#if SSF_RSA_ANY_ENABLED == 1

/* --------------------------------------------------------------------------------------------- */
/* Hygiene test scaffolding: noinline 16 KiB pollute/scan frames that overlay a freed frame.     */
/* --------------------------------------------------------------------------------------------- */
#define _SSFRSA_UT_HYGIENE_PROBE_BYTES (16u * 1024u)

/* Suppress C6262 (large stack frame): the probe buffer intentionally overlays a freed frame. */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6262)
#endif
SSF_NOINLINE
static void _SSFRSAUTPolluteStack(uint8_t v)
{
    volatile uint8_t buf[_SSFRSA_UT_HYGIENE_PROBE_BYTES];
    size_t i;
    for (i = 0u; i < sizeof(buf); i++) buf[i] = v;
}
#ifdef _WIN32
#pragma warning(pop)
#endif

/* Reading uninitialized stack is the test: silence -Wuninitialized and MSVC C6001 here. */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#if !defined(__clang__)
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#endif
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 6001)
#pragma warning(disable: 6262)
#endif
SSF_NOINLINE
static int _SSFRSAUTScanStack(const uint8_t *needle, size_t needleLen)
{
    volatile uint8_t buf[_SSFRSA_UT_HYGIENE_PROBE_BYTES];
    int found = 0;
    size_t i;
    size_t j;

    /* Read residue without writing first -- buf was just allocated atop the freed callee frame. */
    for (i = 0u; (i + needleLen) <= sizeof(buf); i++)
    {
        bool match = true;
        for (j = 0u; j < needleLen; j++)
        {
            if (buf[i + j] != needle[j]) { match = false; break; }
        }
        if (match) found++;
    }
    /* Force the array to be allocated even with aggressive optimisation. */
    buf[0] = (uint8_t)found;
    return found;
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

/* Returns a pointer to p's magnitude in an emitted 2048-bit PKCS#1 RSAPrivateKey, else NULL. */
static const uint8_t *_SSFRSAUTLocatePMag(const uint8_t *priv, size_t privLen)
{
    const uint8_t *cur;
    size_t dHeader;
    size_t dMag;

    if (privLen < 268u) return NULL;
    cur = priv + 273u; /* d INTEGER tag */
    if (cur[0] != 0x02u) return NULL;
    if (cur[1] == 0x82u)      { dHeader = 4u; dMag = ((size_t)cur[2] << 8) | cur[3]; }
    else if (cur[1] == 0x81u) { dHeader = 3u; dMag = cur[2]; }
    else                      { dHeader = 2u; dMag = cur[1]; }
    cur += dHeader + dMag; /* now at p INTEGER */
    if (cur[0] != 0x02u) return NULL;
    if (cur[1] == 0x81u) cur += 3u;
    else                 cur += 2u;
    if (cur[0] == 0x00u) cur++; /* skip strict-DER sign byte */
    return cur;
}

#if SSF_RSA_OSSL_VERIFY == 1
/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers and driver (keygen DER, PKCS#1 v1.5 and PSS interop).             */
/* --------------------------------------------------------------------------------------------- */

/* Decode an SSF-emitted PKCS#1 RSAPrivateKey DER into an EVP_PKEY suitable for OpenSSL ops. */
static EVP_PKEY *_OSSLLoadPrivKey(const uint8_t *der, size_t derLen)
{
    const uint8_t *p = der;
    RSA *rsa = d2i_RSAPrivateKey(NULL, &p, (long)derLen);
    EVP_PKEY *pkey = NULL;
    if (rsa == NULL) return NULL;
    pkey = EVP_PKEY_new();
    if (pkey == NULL) { RSA_free(rsa); return NULL; }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
    {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    /* assign_RSA takes ownership of rsa on success -- don't free rsa here. */
    return pkey;
}

/* BN-07: d of an SSF-generated key is exactly 65537^(-1) mod lambda(n) = lcm(p - 1, q - 1), */
/* computed independently with OpenSSL's BN (loading the key does not check d is minimal).   */
static void _OSSLCheckDIsInvModLambda(const uint8_t *der, size_t derLen)
{
    const uint8_t *p = der;
    RSA *rsa = d2i_RSAPrivateKey(NULL, &p, (long)derLen);
    const BIGNUM *n = NULL, *e = NULL, *d = NULL, *bp = NULL, *bq = NULL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *pm1 = BN_new(), *qm1 = BN_new(), *g = BN_new(), *lam = BN_new(), *want = BN_new();

    SSF_ASSERT((rsa != NULL) && (ctx != NULL) && (pm1 != NULL) && (qm1 != NULL) && (g != NULL) &&
               (lam != NULL) && (want != NULL));
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &bp, &bq);
    SSF_ASSERT(BN_is_word(e, 65537u) == 1);
    SSF_ASSERT((BN_sub(pm1, bp, BN_value_one()) == 1) && (BN_sub(qm1, bq, BN_value_one()) == 1));
    SSF_ASSERT(BN_gcd(g, pm1, qm1, ctx) == 1);
    SSF_ASSERT(BN_mul(lam, pm1, qm1, ctx) == 1);
    SSF_ASSERT(BN_div(lam, NULL, lam, g, ctx) == 1);
    SSF_ASSERT(BN_mod_inverse(want, e, lam, ctx) != NULL);
    SSF_ASSERT(BN_cmp(d, want) == 0);
    BN_free(want); BN_free(lam); BN_free(g); BN_free(qm1); BN_free(pm1);
    BN_CTX_free(ctx);
    RSA_free(rsa);
}

static EVP_PKEY *_OSSLLoadPubKey(const uint8_t *der, size_t derLen)
{
    const uint8_t *p = der;
    RSA *rsa = d2i_RSAPublicKey(NULL, &p, (long)derLen);
    EVP_PKEY *pkey = NULL;
    if (rsa == NULL) return NULL;
    pkey = EVP_PKEY_new();
    if (pkey == NULL) { RSA_free(rsa); return NULL; }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
    {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }
    return pkey;
}

static bool _OSSLVerifyPKCS1(EVP_PKEY *pkey, const EVP_MD *md,
                             const uint8_t *msg, size_t msgLen,
                             const uint8_t *sig, size_t sigLen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx == NULL) return false;
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) == 1)
    {
        if (EVP_DigestVerify(ctx, sig, sigLen, msg, msgLen) == 1) ok = true;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool _OSSLSignPKCS1(EVP_PKEY *pkey, const EVP_MD *md,
                           const uint8_t *msg, size_t msgLen,
                           uint8_t *sig, size_t *sigLen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx == NULL) return false;
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) == 1)
    {
        if (EVP_DigestSign(ctx, sig, sigLen, msg, msgLen) == 1) ok = true;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool _OSSLVerifyPSS(EVP_PKEY *pkey, const EVP_MD *md, int saltLen,
                           const uint8_t *msg, size_t msgLen,
                           const uint8_t *sig, size_t sigLen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    bool ok = false;
    if (ctx == NULL) return false;
    /* Is the PSS verify context set up? */
    if ((EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pkey) == 1) &&
        (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0) &&
        (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLen) > 0) &&
        (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0))
    {
        /* Yes, verify the signature */
        if (EVP_DigestVerify(ctx, sig, sigLen, msg, msgLen) == 1) ok = true;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool _OSSLSignPSS(EVP_PKEY *pkey, const EVP_MD *md, int saltLen,
                         const uint8_t *msg, size_t msgLen,
                         uint8_t *sig, size_t *sigLen)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    bool ok = false;
    if (ctx == NULL) return false;
    /* Is the PSS sign context set up? */
    if ((EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey) == 1) &&
        (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0) &&
        (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLen) > 0) &&
        (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0))
    {
        /* Yes, make the signature */
        if (EVP_DigestSign(ctx, sig, sigLen, msg, msgLen) == 1) ok = true;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
/* Run all five PKCS#1 v1.5 / PSS round-trips for one (key, hash) pair. */
static void _SSFRSAVerifyHashAtKey(const uint8_t *priv, size_t privLen,
                                   const uint8_t *pub,  size_t pubLen,
                                   EVP_PKEY *pkey,      EVP_PKEY *pkeyPub,
                                   SSFRSAHash_t ssfHash, const EVP_MD *md, size_t hLen,
                                   const uint8_t *msg, size_t msgLen)
{
    uint8_t hashVal[64];
    uint8_t sigSSF[SSF_RSA_MAX_SIG_SIZE];
    uint8_t sigOSSL[SSF_RSA_MAX_SIG_SIZE];
    size_t sigSSFLen;
    size_t sigOSSLLen;

    SSF_ASSERT(hLen <= sizeof(hashVal));

    /* Compute the message hash with SSF -- fed to SSFRSA's hashed-input API. */
    switch (ssfHash)
    {
    case SSF_RSA_HASH_SHA256: SSFSHA256(msg, (uint32_t)msgLen, hashVal, (uint32_t)hLen); break;
    case SSF_RSA_HASH_SHA384: SSFSHA384(msg, (uint32_t)msgLen, hashVal, (uint32_t)hLen); break;
    case SSF_RSA_HASH_SHA512: SSFSHA512(msg, (uint32_t)msgLen, hashVal, (uint32_t)hLen); break;
    default: SSF_ASSERT(false); return;
    }

#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
    /* ---- PKCS#1 v1.5 round-trip: SSF sign, OpenSSL verify ---- */
    SSF_ASSERT(SSFRSASignPKCS1(priv, privLen, ssfHash, hashVal, hLen,
                               sigSSF, sizeof(sigSSF), &sigSSFLen) == true);
    SSF_ASSERT(_OSSLVerifyPKCS1(pkeyPub, md, msg, msgLen, sigSSF, sigSSFLen));

    /* OpenSSL sign, SSF verify, plus byte-exact match (PKCS#1 v1.5 is deterministic). */
    sigOSSLLen = sizeof(sigOSSL);
    SSF_ASSERT(_OSSLSignPKCS1(pkey, md, msg, msgLen, sigOSSL, &sigOSSLLen));
    SSF_ASSERT(sigOSSLLen == sigSSFLen);
    SSF_ASSERT(memcmp(sigSSF, sigOSSL, sigSSFLen) == 0);
    SSF_ASSERT(SSFRSAVerifyPKCS1(pub, pubLen, ssfHash, hashVal, hLen,
                                 sigOSSL, sigOSSLLen) == true);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */

#if SSF_RSA_CONFIG_ENABLE_PSS == 1
    /* ---- PSS round-trip: randomized, so only cross-verify both directions ---- */
    SSF_ASSERT(SSFRSASignPSS(priv, privLen, ssfHash, hashVal, hLen,
                             sigSSF, sizeof(sigSSF), &sigSSFLen) == true);
    SSF_ASSERT(_OSSLVerifyPSS(pkeyPub, md, (int)hLen, msg, msgLen, sigSSF, sigSSFLen));

    sigOSSLLen = sizeof(sigOSSL);
    SSF_ASSERT(_OSSLSignPSS(pkey, md, (int)hLen, msg, msgLen, sigOSSL, &sigOSSLLen));
    SSF_ASSERT(SSFRSAVerifyPSS(pub, pubLen, ssfHash, hashVal, hLen, hLen,
                               sigOSSL, sigOSSLLen) == true);

    /* Tampered-signature negative: flip a byte; both verifiers must reject. */
    sigOSSL[sigOSSLLen / 2u] ^= 0x01u;
    SSF_ASSERT(_OSSLVerifyPSS(pkeyPub, md, (int)hLen, msg, msgLen,
                              sigOSSL, sigOSSLLen) == false);
    SSF_ASSERT(SSFRSAVerifyPSS(pub, pubLen, ssfHash, hashVal, hLen, hLen,
                               sigOSSL, sigOSSLLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
}

/* Drive cross-checks at one key size with the supplied hash menu. */
static void _SSFRSACrossCheckAtSize(uint16_t bits,
                                    const SSFRSAHash_t *hashes,
                                    const size_t *hLens,
                                    const EVP_MD *(*const mdFns[])(void),
                                    size_t nHashes)
{
    static const uint8_t msg[] = "ssfrsa OpenSSL cross-check message";
    uint8_t priv[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
    uint8_t pub[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
    size_t privLen;
    size_t pubLen;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkeyPub = NULL;
    size_t i;

    /* Generate with SSF; OpenSSL loading the DER checks strict DER and the n=p*q / CRT values. */
    SSF_ASSERT(SSFRSAKeyGen(bits, priv, sizeof(priv), &privLen,
                             pub, sizeof(pub), &pubLen) == true);

    /* Both validators accept a fresh key at every size (the only 3072 / 4096 coverage). */
    SSF_ASSERT(SSFRSAPubKeyIsValid(pub, pubLen) == true);
    SSF_ASSERT(SSFRSAPrivKeyIsValid(priv, privLen) == true);

    pkey = _OSSLLoadPrivKey(priv, privLen);
    SSF_ASSERT(pkey != NULL);
    pkeyPub = _OSSLLoadPubKey(pub, pubLen);
    SSF_ASSERT(pkeyPub != NULL);
    SSF_ASSERT((uint16_t)EVP_PKEY_bits(pkey) == bits);
    _OSSLCheckDIsInvModLambda(priv, privLen);
    SSF_ASSERT((uint16_t)EVP_PKEY_bits(pkeyPub) == bits);

    for (i = 0; i < nHashes; i++)
    {
        _SSFRSAVerifyHashAtKey(priv, privLen, pub, pubLen, pkey, pkeyPub,
                               hashes[i], mdFns[i](), hLens[i],
                               msg, sizeof(msg) - 1u);
    }

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyPub);
}

#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

#if SSF_RSA_CONFIG_ENABLE_PSS == 1
/* PSS sign with OpenSSL on the foreign key fixtures, verify with SSF. */
static void _SSFRSACrossCheckForeignPSS(const uint8_t *foreignPriv, size_t foreignPrivLen,
                                        const uint8_t *foreignPub,  size_t foreignPubLen)
{
    static const uint8_t msg[] = "PSS interop on foreign key";
    EVP_PKEY *pkey    = _OSSLLoadPrivKey(foreignPriv, foreignPrivLen);
    EVP_PKEY *pkeyPub = _OSSLLoadPubKey(foreignPub,  foreignPubLen);
    uint8_t hashVal[32];
    uint8_t sigOSSL[SSF_RSA_MAX_SIG_SIZE];
    size_t sigOSSLLen = sizeof(sigOSSL);

    SSF_ASSERT(pkey != NULL);
    SSF_ASSERT(pkeyPub != NULL);

    SSFSHA256(msg, sizeof(msg) - 1u, hashVal, sizeof(hashVal));

    /* OpenSSL signs PSS-SHA256 with sLen=32, MGF1=SHA256 -- same profile SSF emits. */
    SSF_ASSERT(_OSSLSignPSS(pkey, EVP_sha256(), 32, msg, sizeof(msg) - 1u,
                            sigOSSL, &sigOSSLLen));
    SSF_ASSERT(SSFRSAVerifyPSS(foreignPub, foreignPubLen, SSF_RSA_HASH_SHA256,
                               hashVal, sizeof(hashVal), sizeof(hashVal),
                               sigOSSL, sigOSSLLen) == true);

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyPub);
}
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */

/* Accessor wrappers so the EVP_MD_get_*() functions can be passed by pointer. */
static const EVP_MD *_OSSLSha256(void) { return EVP_sha256(); }
static const EVP_MD *_OSSLSha384(void) { return EVP_sha384(); }
static const EVP_MD *_OSSLSha512(void) { return EVP_sha512(); }

static void _SSFRSAVerifyAgainstOpenSSL(const uint8_t *foreignPriv, size_t foreignPrivLen,
                                        const uint8_t *foreignPub,  size_t foreignPubLen)
{
    /* Hash menus per NIST SP 800-57 Sec. 5.6.2 (security strength matched to key size). */
#if SSF_RSA_CONFIG_ENABLE_2048 == 1
    static const SSFRSAHash_t h2048[] = { SSF_RSA_HASH_SHA256 };
    static const size_t       l2048[] = { 32u };
    static const EVP_MD *(*const m2048[])(void) = { _OSSLSha256 };
#endif

#if SSF_RSA_CONFIG_ENABLE_3072 == 1
    static const SSFRSAHash_t h3072[] = { SSF_RSA_HASH_SHA256, SSF_RSA_HASH_SHA384 };
    static const size_t       l3072[] = { 32u, 48u };
    static const EVP_MD *(*const m3072[])(void) = { _OSSLSha256, _OSSLSha384 };
#endif

#if SSF_RSA_CONFIG_ENABLE_4096 == 1
    static const SSFRSAHash_t h4096[] = { SSF_RSA_HASH_SHA256, SSF_RSA_HASH_SHA384,
                                          SSF_RSA_HASH_SHA512 };
    static const size_t       l4096[] = { 32u, 48u, 64u };
    static const EVP_MD *(*const m4096[])(void) = { _OSSLSha256, _OSSLSha384, _OSSLSha512 };
#endif

    SSF_UT_PRINTF("\n--- ssfrsa OpenSSL cross-check ---\n");

#if SSF_RSA_CONFIG_ENABLE_PSS == 1
    SSF_UT_PRINTF("  foreign-key PSS round-trip (sign-OSSL / verify-SSF)... ");
    fflush(stdout);
    _SSFRSACrossCheckForeignPSS(foreignPriv, foreignPrivLen, foreignPub, foreignPubLen);
    SSF_UT_PRINTF("OK\n");
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */

#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1

#if SSF_RSA_CONFIG_ENABLE_2048 == 1
    SSF_UT_PRINTF("  RSA-2048 keygen + PKCS1v15(byte-match) + PSS(round-trip) @ SHA-256... ");
    fflush(stdout);
    _SSFRSACrossCheckAtSize(2048u, h2048, l2048, m2048, sizeof(h2048) / sizeof(h2048[0]));
    SSF_UT_PRINTF("OK\n");
#endif

#if SSF_RSA_CONFIG_ENABLE_3072 == 1
    SSF_UT_PRINTF("  RSA-3072 keygen + PKCS1v15(byte-match) + PSS(round-trip) @ SHA-256/384... ");
    fflush(stdout);
    _SSFRSACrossCheckAtSize(3072u, h3072, l3072, m3072, sizeof(h3072) / sizeof(h3072[0]));
    SSF_UT_PRINTF("OK\n");
#endif

#if SSF_RSA_CONFIG_ENABLE_4096 == 1
    SSF_UT_PRINTF("  RSA-4096 keygen + PKCS1v15(byte-match) + PSS(round-trip) @ "
                  "SHA-256/384/512... ");
    fflush(stdout);
    _SSFRSACrossCheckAtSize(4096u, h4096, l4096, m4096, sizeof(h4096) / sizeof(h4096[0]));
    SSF_UT_PRINTF("OK\n");
#endif
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

    SSF_UT_PRINTF("--- end OpenSSL cross-check ---\n");
}

#pragma GCC diagnostic pop /* -Wdeprecated-declarations restored */
#endif /* SSF_RSA_OSSL_VERIFY */

/* Suppress C6262 (large stack frame): the test entry point holds many RSA-sized buffers. */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6262)
#endif
#if (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1) && \
    (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1)
/* State captured by the RSA private-op blinding hook (see the blinding test below). */
typedef struct
{
    bool fired;
    bool rInRange;    /* message blind r in [1, n-1] */
    bool rInvOk;      /* r * rInv == 1 mod n */
    bool baseBlinded; /* cBlind != cIn */
    bool expBlindsNZ; /* both exponent blinds non-zero */
} _SSFRSABlindAudit_t;

static void _SSFRSABlindHook(void *ctx, const SSFBN_t *r, const SSFBN_t *rInv,
                             const SSFBN_t *expBlindP, const SSFBN_t *expBlindQ,
                             const SSFBN_t *cIn, const SSFBN_t *cBlind, const SSFBN_t *n)
{
    _SSFRSABlindAudit_t *a = (_SSFRSABlindAudit_t *)ctx;
    SSFBN_DEFINE(chk, SSF_BN_MAX_LIMBS);

    a->fired = true;
    a->rInRange = (SSFBNIsZero(r) == false) && (SSFBNCmp(r, n) < 0);
    SSFBNModMul(&chk, r, rInv, n); /* r * rInv mod n must be 1 */
    a->rInvOk = (SSFBNCmpUint32(&chk, 1u) == 0);
    a->baseBlinded = (SSFBNCmp(cBlind, cIn) != 0); /* the base was actually blinded */
    a->expBlindsNZ = (SSFBNIsZero(expBlindP) == false) && (SSFBNIsZero(expBlindQ) == false);
    SSFBNZeroize(&chk);
}
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN && SSF_RSA_CONFIG_ENABLE_2048 && PKCS1_V15 */

#if (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1) && \
    (SSF_RSA_CONFIG_ENABLE_PSS == 1)
/* RSA-2048 RSAPublicKey (270 bytes) for an OpenSSL PSS SHA-256 saltLength 20 signature. */
static const uint8_t _pssSalt20Pub[] = {
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xcd, 0x6a, 0xff,
    0x4d, 0x7c, 0xba, 0xe3, 0x6e, 0xb0, 0xf1, 0xb0, 0x40, 0xc2, 0xfa, 0xcb,
    0xc8, 0x5a, 0xdb, 0xe0, 0xa3, 0x35, 0xea, 0x27, 0xa9, 0xc9, 0x1d, 0x57,
    0xed, 0x6c, 0x6d, 0x0a, 0xfa, 0xff, 0x7d, 0xe3, 0x72, 0x72, 0xeb, 0x85,
    0xa5, 0x21, 0xa0, 0xea, 0xc1, 0x13, 0x33, 0x84, 0x23, 0xda, 0xd0, 0x9e,
    0xb2, 0x1b, 0x46, 0x13, 0xd8, 0x84, 0x26, 0xab, 0x0d, 0x5b, 0xa4, 0x4b,
    0x4f, 0x8d, 0xc9, 0x02, 0x51, 0x6c, 0x0b, 0xf9, 0xad, 0x46, 0x97, 0x22,
    0x1e, 0x61, 0x14, 0x03, 0x3a, 0x3d, 0xb9, 0x54, 0x61, 0xe4, 0x8f, 0xff,
    0x47, 0x1d, 0x84, 0x5d, 0x90, 0xe1, 0x45, 0xa9, 0x58, 0xea, 0xcf, 0xbe,
    0x2c, 0x67, 0x91, 0x33, 0x10, 0x56, 0xa0, 0xd3, 0x89, 0x0d, 0x69, 0x95,
    0xff, 0xe3, 0x40, 0x61, 0x6d, 0xf5, 0xd8, 0x59, 0xcb, 0x6f, 0xd6, 0xbe,
    0xd6, 0x41, 0x35, 0xf1, 0x0e, 0x52, 0x97, 0xc4, 0x4d, 0x8f, 0xa0, 0x0c,
    0xcd, 0xdf, 0xd8, 0x09, 0x08, 0x32, 0xdb, 0xfc, 0xfd, 0xfa, 0x52, 0x49,
    0x70, 0xf0, 0xc3, 0xdc, 0xe5, 0xf0, 0x98, 0x95, 0x4f, 0x66, 0x64, 0xa8,
    0x10, 0xcc, 0xb4, 0xf1, 0xae, 0x13, 0x31, 0x8e, 0x13, 0xd6, 0x15, 0xe3,
    0x33, 0x18, 0xc4, 0xb5, 0x85, 0x1d, 0x51, 0x00, 0xe0, 0x5a, 0xc8, 0xfb,
    0x5c, 0xf9, 0xfb, 0x6f, 0x60, 0x19, 0xa0, 0x23, 0xc7, 0x68, 0xbf, 0x7b,
    0xe9, 0x7a, 0xdf, 0xb1, 0x6d, 0x27, 0x29, 0xa0, 0xfa, 0x4b, 0x91, 0x1f,
    0x55, 0x90, 0xb8, 0x03, 0x1d, 0x3a, 0x62, 0xaa, 0x3d, 0xac, 0x60, 0x38,
    0x6d, 0xa0, 0x61, 0x03, 0xc2, 0x4d, 0x17, 0x5e, 0x34, 0x45, 0xaa, 0xc1,
    0x49, 0x21, 0x50, 0x53, 0x81, 0x8d, 0xf1, 0x94, 0x58, 0xcf, 0x2c, 0xb6,
    0x64, 0x34, 0xd8, 0x1d, 0x79, 0x27, 0x2a, 0x90, 0x6d, 0xfd, 0xf6, 0x08,
    0x97, 0x02, 0x03, 0x01, 0x00, 0x01
};

/* SHA-256 of the signed message */
static const uint8_t _pssSalt20Hash[] = {
    0x0e, 0xba, 0x02, 0xdb, 0x5d, 0x99, 0xfa, 0xe8, 0xf9, 0x73, 0xd1, 0x53,
    0xd0, 0x26, 0xce, 0x89, 0xcf, 0x2a, 0x67, 0x00, 0xce, 0xd8, 0x36, 0x81,
    0xb8, 0x00, 0xaf, 0x72, 0xf9, 0x79, 0xc7, 0xdc
};

/* RSASSA-PSS signature, saltLength 20, 256 bytes */
static const uint8_t _pssSalt20Sig[] = {
    0x87, 0xdf, 0x9e, 0x18, 0xcc, 0x8f, 0x69, 0x2f, 0x97, 0x14, 0x99, 0xb2,
    0x28, 0xd6, 0x81, 0xe3, 0x3e, 0xce, 0xf4, 0x1c, 0x98, 0x79, 0x2a, 0xa6,
    0x9e, 0x02, 0xd1, 0x56, 0xcd, 0x3f, 0x4e, 0x61, 0x94, 0xfb, 0x7b, 0x57,
    0xc4, 0x2b, 0x17, 0xc8, 0xda, 0xf2, 0x9e, 0x2a, 0x83, 0xff, 0x61, 0x16,
    0xe9, 0xfc, 0x85, 0x88, 0xc1, 0x35, 0x29, 0x83, 0x6f, 0xe0, 0xfd, 0xf8,
    0x80, 0x5d, 0x33, 0xdf, 0xd8, 0x91, 0x70, 0xb2, 0x89, 0x62, 0x5a, 0xfb,
    0x8e, 0x13, 0x2c, 0xb6, 0xee, 0x2a, 0x8c, 0x1a, 0xc7, 0xf3, 0x91, 0xf8,
    0x7c, 0x92, 0x8f, 0x14, 0x6f, 0x9b, 0x6d, 0x64, 0xa8, 0xcd, 0x0c, 0x44,
    0xba, 0x52, 0x85, 0x51, 0xb6, 0x83, 0xa3, 0x71, 0x89, 0x9a, 0x7b, 0xdb,
    0x93, 0x12, 0xd1, 0x93, 0xbc, 0x44, 0xe3, 0x37, 0xeb, 0xde, 0xee, 0xb7,
    0x9a, 0x43, 0x7b, 0x3c, 0x4e, 0xc3, 0x30, 0x34, 0xc3, 0xb6, 0x27, 0xd1,
    0xa9, 0x56, 0xa3, 0xa1, 0xe3, 0x7f, 0x28, 0x1c, 0xcc, 0x86, 0x08, 0x85,
    0x55, 0xbc, 0x83, 0x13, 0x8a, 0x18, 0x6d, 0x43, 0xbf, 0x3b, 0x0d, 0xd0,
    0x2c, 0x3e, 0xa3, 0x1c, 0x6e, 0x07, 0x98, 0x35, 0xed, 0xa9, 0x5f, 0xba,
    0x75, 0x23, 0xbd, 0xc9, 0x0d, 0xd8, 0xc6, 0x10, 0x1d, 0xb5, 0x44, 0x98,
    0x20, 0xf7, 0x30, 0x13, 0x7b, 0x46, 0xee, 0x49, 0xc7, 0xc4, 0x7b, 0xcb,
    0x2a, 0x83, 0x6e, 0x3d, 0x9b, 0xe0, 0xa3, 0x67, 0xb0, 0xef, 0x94, 0x7c,
    0xdf, 0x98, 0x15, 0x5c, 0x6b, 0xc1, 0x29, 0x67, 0xb4, 0x79, 0x2d, 0xb9,
    0xfc, 0xe2, 0x74, 0xdf, 0x70, 0x22, 0x7e, 0x8d, 0x71, 0xcf, 0xa4, 0xdb,
    0xb7, 0xdc, 0xff, 0xee, 0x66, 0x78, 0x85, 0x39, 0x2c, 0xfe, 0x4c, 0x46,
    0xef, 0x32, 0x85, 0x55, 0x6d, 0x26, 0x2b, 0xa3, 0xfc, 0xab, 0xd2, 0xef,
    0x0e, 0x89, 0xd0, 0x7e
};
#endif /* PKCS1_V15 && 2048 && PSS */

/* --------------------------------------------------------------------------------------------- */
/* UT helper: emit a DER INTEGER of mag magnitude bytes (msb, 0xFF fill, lsb) at der[*pos].      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFRSAUTPutIntTLV(uint8_t *der, uint32_t *pos, uint32_t mag, uint8_t msb,
                               uint8_t lsb)
{
    uint32_t i;
    uint32_t len = mag;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE(mag >= 2u);

    /* Is the magnitude's top bit set? */
    if ((msb & 0x80u) != 0u)
    {
        /* Yes, DER needs a leading 0x00 so the INTEGER stays positive. */
        len++;
    }
    der[(*pos)++] = 0x02u;
    der[(*pos)++] = 0x82u;
    der[(*pos)++] = (uint8_t)(len >> 8);
    der[(*pos)++] = (uint8_t)(len & 0xFFu);
    if ((msb & 0x80u) != 0u) { der[(*pos)++] = 0x00u; }
    der[(*pos)++] = msb;
    for (i = 1u; i < (mag - 1u); i++) { der[(*pos)++] = 0xFFu; }
    der[(*pos)++] = lsb;
}

/* --------------------------------------------------------------------------------------------- */
/* UT helper: close a hand-built SEQUENCE whose 0x30 0x82 hi lo header starts at der[0].         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFRSAUTCloseSeq(uint8_t *der, uint32_t pos)
{
    uint32_t content;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(pos >= 4u);

    content = pos - 4u;
    der[0] = 0x30u;
    der[1] = 0x82u;
    der[2] = (uint8_t)(content >> 8);
    der[3] = (uint8_t)(content & 0xFFu);
}

#if (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1)
/* --------------------------------------------------------------------------------------------- */
/* UT helper: add 1 to the last byte of INTEGER number idx in a DER SEQUENCE (AUDIT RSA-12).     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFRSAUTBumpInt(uint8_t *der, size_t derLen, uint8_t idx)
{
    size_t pos;
    size_t len;
    uint8_t i;
    uint8_t k;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(derLen > 4u);
    SSF_REQUIRE(der[0] == 0x30u);

    pos = ((der[1] & 0x80u) != 0u) ? (2u + (size_t)(der[1] & 0x7Fu)) : 2u;
    for (i = 0; ; i++)
    {
        SSF_REQUIRE((pos + 2u) < derLen);
        SSF_REQUIRE(der[pos] == 0x02u);
        pos++;
        /* Is the length in long form? */
        if ((der[pos] & 0x80u) != 0u)
        {
            /* Yes, read the k length bytes */
            k = (uint8_t)(der[pos] & 0x7Fu);
            pos++;
            len = 0u;
            while (k > 0u) { len = (len << 8) | der[pos]; pos++; k--; }
        }
        else
        {
            /* No, the byte is the length */
            len = der[pos];
            pos++;
        }
        SSF_REQUIRE((pos + len) <= derLen);
        /* Is this the INTEGER to bump? */
        if (i == idx)
        {
            /* Yes, increment its last byte (never 0xFF, so the length is unchanged) */
            SSF_REQUIRE(der[(pos + len) - 1u] != 0xFFu);
            der[(pos + len) - 1u]++;
            return;
        }
        pos += len;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* UT helper: copy a 30 82 LL LL DER SEQUENCE with INTEGER number idx replaced by 0 (SAFE-06).   */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFRSAUTZeroInt(const uint8_t *der, size_t derLen, uint8_t idx, uint8_t *out,
                               size_t outSize)
{
    size_t pos = 4u;
    size_t start;
    size_t len;
    uint32_t outPos = 4u;
    uint8_t i;
    uint8_t k;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(derLen > 4u);
    SSF_REQUIRE(outSize >= derLen);
    SSF_REQUIRE((der[0] == 0x30u) && (der[1] == 0x82u));

    for (i = 0; pos < derLen; i++)
    {
        start = pos;
        SSF_REQUIRE(der[pos] == 0x02u);
        pos++;
        /* Is the length in long form? */
        if ((der[pos] & 0x80u) != 0u)
        {
            /* Yes, read the k length bytes */
            k = (uint8_t)(der[pos] & 0x7Fu);
            pos++;
            len = 0u;
            while (k > 0u) { len = (len << 8) | der[pos]; pos++; k--; }
        }
        else
        {
            /* No, the byte is the length */
            len = der[pos];
            pos++;
        }
        pos += len;
        SSF_REQUIRE(pos <= derLen);
        /* Is this the INTEGER to replace? */
        if (i == idx)
        {
            /* Yes, write INTEGER 0 */
            out[outPos++] = 0x02u;
            out[outPos++] = 0x01u;
            out[outPos++] = 0x00u;
        }
        else
        {
            /* No, copy it unchanged */
            memcpy(&out[outPos], &der[start], pos - start);
            outPos += (uint32_t)(pos - start);
        }
    }
    SSF_REQUIRE(i > idx);
    _SSFRSAUTCloseSeq(out, outPos);
    return outPos;
}
#endif /* PKCS1_V15 && 2048 */

/* --------------------------------------------------------------------------------------------- */
/* UT helper: append INTEGER of mag (< 127) bytes msb, 0xFF.., lsb in short-form DER (RSA-11).   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFRSAUTPutShortIntTLV(uint8_t *der, uint32_t *pos, uint32_t mag, uint8_t msb,
                                    uint8_t lsb)
{
    uint32_t i;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE(mag >= 2u);
    SSF_REQUIRE(mag < 127u);
    SSF_REQUIRE((msb & 0x80u) == 0u);

    der[(*pos)++] = 0x02u;
    der[(*pos)++] = (uint8_t)mag;
    der[(*pos)++] = msb;
    for (i = 1u; i < (mag - 1u); i++) { der[(*pos)++] = 0xFFu; }
    der[(*pos)++] = lsb;
}

/* --------------------------------------------------------------------------------------------- */
/* UT helper: emit a DER INTEGER of 128..255 magnitude bytes (minimal 0x81 length form).         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFRSAUTPutMidIntTLV(uint8_t *der, uint32_t *pos, uint32_t mag, uint8_t msb,
                                  uint8_t lsb)
{
    uint32_t i;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(pos != NULL);
    SSF_REQUIRE((mag >= 128u) && (mag <= 255u));
    SSF_REQUIRE((msb & 0x80u) == 0u);

    der[(*pos)++] = 0x02u;
    der[(*pos)++] = 0x81u;
    der[(*pos)++] = (uint8_t)mag;
    der[(*pos)++] = msb;
    for (i = 1u; i < (mag - 1u); i++) { der[(*pos)++] = 0xFFu; }
    der[(*pos)++] = lsb;
}

/* --------------------------------------------------------------------------------------------- */
/* AUDIT RSA-12: scrub-hook callback; counts calls and any buffer that is not all zero.          */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _scrubCalls;
static uint32_t _scrubDirty;
static void _ScrubCheck(const void *buf, size_t len)
{
    const uint8_t *b = (const uint8_t *)buf;
    size_t i;

    SSF_ASSERT(buf != NULL);
    _scrubCalls++;
    for (i = 0; i < len; i++)
    {
        if (b[i] != 0u)
        {
            _scrubDirty++;
            break;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* SAFE-05: stack-scrub hook callback; counts calls, keeps the size, counts non-zero buffers.    */
/* --------------------------------------------------------------------------------------------- */
static uint32_t _stackScrubCalls;
static size_t _stackScrubLen;
static uint32_t _stackScrubSizes;
static uint32_t _stackScrubDirty;
static void _StackScrubCheck(const void *buf, size_t len)
{
    const uint8_t *b = (const uint8_t *)buf;
    size_t i;

    SSF_ASSERT(buf != NULL);
    if ((_stackScrubCalls == 0u) || (len != _stackScrubLen)) _stackScrubSizes++;
    _stackScrubCalls++;
    _stackScrubLen = len;
    for (i = 0; i < len; i++)
    {
        if (b[i] != 0u)
        {
            _stackScrubDirty++;
            break;
        }
    }
}

/* Fills the stack below the caller with a non-zero pattern, deeper than any scrub reaches, so */
/* a scrub that leaves part of its buffer unwritten shows up as a dirty buffer.                 */
SSF_NOINLINE
static void _StackScrubPaint(void)
{
    volatile uint8_t paint[(2u * SSF_RSA_SIGN_STACK_SCRUB_BYTES) + 16384u];
    size_t i;

    for (i = 0; i < sizeof(paint); i++) paint[i] = 0xA5u;
}

static void _StackScrubReset(void)
{
    _stackScrubCalls = 0u;
    _stackScrubLen = 0u;
    _stackScrubSizes = 0u;
    _stackScrubDirty = 0u;
}
#endif /* SSF_RSA_ANY_ENABLED == 1 */

void SSFRSAUnitTest(void)
{
#if SSF_RSA_ANY_ENABLED == 0
    /* No RSA size is enabled: print "skipped" so main.c stays linkable for pure-ECC builds. */
    SSF_UT_PRINTF("(skipped: no SSF_RSA_CONFIG_ENABLE_2048 / 3072 / 4096 enabled)\n");
    return;
#else

    /* ---- SAFE-05: stack-scrub sizes, measured (Cortex-M4 GCC -Os) for k = 4, no margin ---- */
    /* The depth the ssfbn calls below a sign / keygen entry point reach, from the static call  */
    /* graph at each RSA cap; the derived sizes must match it (re-measure if a frame changes).  */
#if (SSF_BN_MODEXP_WIN_K == 4u) && (SSF_RSA_CONFIG_STACK_SCRUB_MARGIN == 0u)
#if SSF_BN_MAX_MOD_LIMBS == 128u
    SSF_ASSERT(SSF_RSA_SIGN_STACK_SCRUB_BYTES == 14792u);
#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
    SSF_ASSERT(SSF_RSA_KEYGEN_STACK_SCRUB_BYTES == 14352u);
#endif
#elif SSF_BN_MAX_MOD_LIMBS == 96u
    SSF_ASSERT(SSF_RSA_SIGN_STACK_SCRUB_BYTES == 11272u);
#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
    SSF_ASSERT(SSF_RSA_KEYGEN_STACK_SCRUB_BYTES == 10896u);
#endif
#elif SSF_BN_MAX_MOD_LIMBS == 64u
    SSF_ASSERT(SSF_RSA_SIGN_STACK_SCRUB_BYTES == 7752u);
#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
    SSF_ASSERT(SSF_RSA_KEYGEN_STACK_SCRUB_BYTES == 7440u);
#endif
#endif /* SSF_BN_MAX_MOD_LIMBS */
#endif /* k = 4, no margin */

    /* ---- SAFE-05: a failed sign still scrubs, once, at the sign size ---- */
    {
        static const uint8_t badDer[] = { 0x30u, 0x00u };
        uint8_t hash[32];
        uint8_t sig[SSF_RSA_MAX_KEY_BYTES];
        size_t sigLen;

        memset(hash, 0x5Au, sizeof(hash));
        _SSFRSAStackScrubTestHook = _StackScrubCheck;
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        _StackScrubReset();
        _StackScrubPaint();
        SSF_ASSERT(SSFRSASignPKCS1(badDer, sizeof(badDer), SSF_RSA_HASH_SHA256,
                                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == false);
        SSF_ASSERT(_stackScrubCalls == 1u);
        SSF_ASSERT(_stackScrubLen == SSF_RSA_SIGN_STACK_SCRUB_BYTES);
        SSF_ASSERT(_stackScrubDirty == 0u);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        _StackScrubReset();
        _StackScrubPaint();
        SSF_ASSERT(SSFRSASignPSS(badDer, sizeof(badDer), SSF_RSA_HASH_SHA256,
                                 hash, sizeof(hash), sig, sizeof(sig), &sigLen) == false);
        SSF_ASSERT(_stackScrubCalls == 1u);
        SSF_ASSERT(_stackScrubLen == SSF_RSA_SIGN_STACK_SCRUB_BYTES);
        SSF_ASSERT(_stackScrubDirty == 0u);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS == 1 */
        _SSFRSAStackScrubTestHook = NULL;
    }

    /* ---- (Hardening) DER pubkey with n wider than SSF_BN_MAX_BYTES returns false ---- */
    {
        static uint8_t der[SSF_BN_MAX_BYTES + 32u];
        const uint32_t nMag = (uint32_t)SSF_BN_MAX_BYTES + 8u; /* exceeds the max BN byte width */
        const uint32_t content = (4u + nMag) + 5u;             /* INTEGER n TLV + INTEGER e TLV */
        uint32_t p = 0u;
        uint32_t i;

        der[p++] = 0x30u; /* SEQUENCE */
        der[p++] = 0x82u; /* 2-byte long-form length */
        der[p++] = (uint8_t)(content >> 8);
        der[p++] = (uint8_t)(content & 0xFFu);
        der[p++] = 0x02u; /* INTEGER n */
        der[p++] = 0x82u;
        der[p++] = (uint8_t)(nMag >> 8);
        der[p++] = (uint8_t)(nMag & 0xFFu);
        der[p++] = 0x7Fu; /* MSB: nonzero + positive (no leading-zero trim) */
        for (i = 1u; i < nMag; i++) { der[p++] = 0xFFu; }
        der[p++] = 0x02u; /* INTEGER e = 65537 */
        der[p++] = 0x03u;
        der[p++] = 0x01u; der[p++] = 0x00u; der[p++] = 0x01u;

        SSF_ASSERT((size_t)p <= sizeof(der));
        SSF_ASSERT(SSFRSAPubKeyIsValid(der, (size_t)p) == false);
    }

    /* ---- BN-07: keygen's d = 65537^(-1) mod lambda equals SSFBNModInvExt, rare carries too ---- */
#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
    {
        SSFBN_DEFINE(lam, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(dRef, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(d, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(t, SSF_BN_MAX_LIMBS);
        uint32_t x = 0x85EBCA6Bu;
        uint32_t r;
        uint32_t it;
        uint16_t n;
        uint16_t k;

        for (it = 0u; it < 600u; it++)
        {
            /* Widths 2..8 and the largest modulus; shapes: random, tiny top limb (the exact  */
            /* division then borrows often), and lambda == -1 mod 65537 (Fermat meets 2^32)  */
            n = (uint16_t)((it < 540u) ? (2u + (it % 7u)) : SSF_BN_MAX_MOD_LIMBS);
            for (k = 0u; k < n; k++)
            {
                x ^= x << 13; x ^= x >> 17; x ^= x << 5;
                lam.limbs[k] = x;
            }
            lam.len = n;
            lam.limbs[0] &= ~1u;
            if ((it % 3u) == 1u) lam.limbs[n - 1u] = 1u + (x & 3u);
            if (lam.limbs[n - 1u] == 0u) lam.limbs[n - 1u] = 1u;
            r = SSFBNModUint32(&lam, 65537u);
            if ((it % 3u) == 2u)
            {
                /* Raise lambda to the next value == 65536 mod 65537, keeping it even */
                (void)SSFBNAddUint32(&lam, &lam, (65536u + 65537u - r) % 65537u);
                if ((lam.limbs[0] & 1u) != 0u) (void)SSFBNAddUint32(&lam, &lam, 65537u);
                SSF_ASSERT(SSFBNModUint32(&lam, 65537u) == 65536u);
            }
            if (SSFBNModUint32(&lam, 65537u) == 0u) continue; /* keygen's FIPS check excludes it */
            SSFBNSetUint32(&e, 65537u, n);
            SSF_ASSERT(SSFBNModInvExt(&dRef, &e, &lam) == true);
            _SSFRSAInvE65537Test(&d, &lam, &t, n);
            SSF_ASSERT((d.len == n) && (SSFBNCmp(&d, &dRef) == 0));
        }

        /* lambda = d * 65537 - 1 for d whose exact division by 65537 borrows below the top limb */
        /* (about 1 in 50,000 random lambdas); lambda == -1 mod 65537, so k = 1                 */
        {
            static const uint32_t borrowLam[4][5] = {
                { 0x96CD407Au, 0x00003DB8u, 0x19CF53C1u, 0xF2797383u, 0x24F48292u },
                { 0x050F28C0u, 0x00009804u, 0x0A6A4EB5u, 0u, 0u },
                { 0x9AFFB9E1u, 0x000058E8u, 0x8CA7389Fu, 0x69F3B6C7u, 0x5B50EABAu },
                { 0xFB3001B9u, 0x8D16EEC8u, 0x2E370F5Eu, 0x0000B59Du, 0x66666766u } };
            static const uint16_t borrowLen[4] = { 5u, 3u, 5u, 5u };

            for (it = 0u; it < 4u; it++)
            {
                n = borrowLen[it];
                for (k = 0u; k < n; k++) lam.limbs[k] = borrowLam[it][k];
                lam.len = n;
                SSF_ASSERT(SSFBNModUint32(&lam, 65537u) == 65536u);
                SSFBNSetUint32(&e, 65537u, n);
                SSF_ASSERT(SSFBNModInvExt(&dRef, &e, &lam) == true);
                _SSFRSAInvE65537Test(&d, &lam, &t, n);
                SSF_ASSERT((d.len == n) && (SSFBNCmp(&d, &dRef) == 0));
            }
        }
    }
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

    /* ---- AUDIT RSA-12: KeyGen wipes the private-key DER scratch buffer ---- */
#if (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1)
    {
        static uint8_t privDer[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t pubDer[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t privLen;
        size_t pubLen;

        _scrubCalls = 0u;
        _scrubDirty = 0u;
        _SSFRSAScrubTestHook = _ScrubCheck;
        _StackScrubReset();
        _SSFRSAStackScrubTestHook = _StackScrubCheck;
        SSF_ASSERT(SSFRSAKeyGen(2048u, privDer, sizeof(privDer), &privLen, pubDer, sizeof(pubDer),
                                &pubLen) == true);
        _SSFRSAScrubTestHook = NULL;
        _SSFRSAStackScrubTestHook = NULL;
        SSF_ASSERT(_scrubCalls == 1u);
        SSF_ASSERT(_scrubDirty == 0u);
        /* SAFE-05: the derive step and KeyGen each scrub, at the keygen size */
        SSF_ASSERT(_stackScrubCalls == 2u);
        SSF_ASSERT(_stackScrubSizes == 1u);
        SSF_ASSERT(_stackScrubLen == SSF_RSA_KEYGEN_STACK_SCRUB_BYTES);
        SSF_ASSERT(_stackScrubDirty == 0u);
        SSF_ASSERT(SSFRSAPrivKeyIsValid(privDer, privLen) == true);
    }
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN && SSF_RSA_CONFIG_ENABLE_2048 */

    /* ---- AUDIT RSA-11: CRT primes narrower than half the modulus are refused, not trapped ---- */
#if SSF_RSA_CONFIG_ENABLE_2048 == 1
    {
        static uint8_t der[4u + 3u + (3u * 260u) + (5u * 20u)];
        static uint8_t sig[SSF_RSA_MAX_KEY_BYTES];
        uint8_t hash[32];
        size_t sigLen = 0u;
        uint32_t p = 4u;
        uint32_t i;

        memset(hash, 0x5A, sizeof(hash));
        der[p++] = 0x02u; der[p++] = 0x01u; der[p++] = 0x00u;
        _SSFRSAUTPutIntTLV(der, &p, 256u, 0xC5u, 0x01u);
        _SSFRSAUTPutShortIntTLV(der, &p, 3u, 0x01u, 0x01u);
        _SSFRSAUTPutIntTLV(der, &p, 256u, 0x41u, 0x01u);
        for (i = 0; i < 5u; i++) { _SSFRSAUTPutShortIntTLV(der, &p, 16u, 0x41u, 0x03u); }
        _SSFRSAUTCloseSeq(der, p);
        SSF_ASSERT((size_t)p <= sizeof(der));

        SSF_ASSERT(SSFRSAPrivKeyIsValid(der, (size_t)p) == false);
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSASignPKCS1(der, (size_t)p, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                                   sig, sizeof(sig), &sigLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSASignPSS(der, (size_t)p, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                                 sig, sizeof(sig), &sigLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
    }
#endif /* SSF_RSA_CONFIG_ENABLE_2048 */

    /* ---- COV-1: PrivKeyIsValid refuses d = 0, d = 1 and q = 1 (each odd/width-legal) ---- */
    /* p = 1 cannot reach the check: the decoder pins p to half the modulus width, and        */
    /* _SSFRSAValidatePubFields then rejects any modulus narrow enough for a one-limb p.      */
#if SSF_RSA_CONFIG_ENABLE_2048 == 1
    {
        static uint8_t der[1400u];
        uint32_t p;
        uint32_t i;
        uint8_t which;

        for (which = 0u; which < 3u; which++)
        {
            p = 4u;
            der[p++] = 0x02u; der[p++] = 0x01u; der[p++] = 0x00u;  /* version 0 */
            _SSFRSAUTPutIntTLV(der, &p, 256u, 0xC5u, 0x01u);       /* n: 2048 bits, odd */
            _SSFRSAUTPutShortIntTLV(der, &p, 3u, 0x01u, 0x01u);    /* e = 0x01FF01 */
            if (which < 2u)
            {
                /* d = 0 or d = 1 */
                der[p++] = 0x02u; der[p++] = 0x01u; der[p++] = which;
            }
            else { _SSFRSAUTPutIntTLV(der, &p, 256u, 0x41u, 0x01u); } /* d: wide, odd */
            _SSFRSAUTPutMidIntTLV(der, &p, 128u, 0x45u, 0x01u);    /* p: half width, odd */
            if (which == 2u)
            {
                /* q = 1 */
                der[p++] = 0x02u; der[p++] = 0x01u; der[p++] = 0x01u;
            }
            else { _SSFRSAUTPutMidIntTLV(der, &p, 128u, 0x43u, 0x01u); } /* q: half, odd */
            for (i = 0; i < 3u; i++) { _SSFRSAUTPutMidIntTLV(der, &p, 128u, 0x41u, 0x03u); }
            _SSFRSAUTCloseSeq(der, p);
            SSF_ASSERT((size_t)p <= sizeof(der));

            SSF_ASSERT(SSFRSAPrivKeyIsValid(der, (size_t)p) == false);
        }
    }
#endif /* SSF_RSA_CONFIG_ENABLE_2048 */

    /* ---- AUDIT RSA-6: PSS verify checks the byte dropped when bitLen(n) = 1 mod 8 ---- */
#if (SSF_RSA_CONFIG_ENABLE_PSS == 1) && (SSF_RSA_MAX_KEY_BYTES >= 257u)
    {
        static const uint8_t rsa6Pub[270] = {
            0x30u, 0x82u, 0x01u, 0x0Au, 0x02u, 0x82u, 0x01u, 0x01u, 0x01u, 0x31u, 0xEBu, 0x6Eu,
            0x93u, 0xE4u, 0x64u, 0xC0u, 0x9Du, 0x3Bu, 0xE0u, 0x23u, 0xBCu, 0x17u, 0x58u, 0xD0u,
            0xCAu, 0xF7u, 0x7Fu, 0x5Eu, 0xFBu, 0x24u, 0x04u, 0xD8u, 0x41u, 0x7Cu, 0xF3u, 0xD1u,
            0x84u, 0x12u, 0x39u, 0x45u, 0x20u, 0x52u, 0x3Du, 0xAFu, 0x3Au, 0x3Eu, 0xD1u, 0xDDu,
            0xD0u, 0x37u, 0xA2u, 0xE2u, 0x84u, 0x85u, 0x49u, 0x51u, 0x94u, 0xEAu, 0x0Eu, 0x41u,
            0xDFu, 0xA3u, 0xE5u, 0x83u, 0x5Au, 0x14u, 0xD1u, 0xF8u, 0xA9u, 0x10u, 0x5Du, 0xB6u,
            0x98u, 0xAAu, 0x05u, 0xD8u, 0xC0u, 0xDDu, 0x0Au, 0x0Eu, 0x5Au, 0x9Eu, 0xE9u, 0x77u,
            0x78u, 0x8Bu, 0x12u, 0x6Au, 0xE4u, 0x36u, 0x6Bu, 0xC9u, 0x20u, 0x70u, 0x0Cu, 0x71u,
            0x00u, 0x97u, 0x22u, 0xDCu, 0x75u, 0x7Cu, 0x3Bu, 0x93u, 0x93u, 0xB4u, 0x47u, 0xD1u,
            0x1Cu, 0xFDu, 0x88u, 0x55u, 0x74u, 0x24u, 0xA7u, 0x8Bu, 0xEDu, 0xDCu, 0xB7u, 0xF2u,
            0xCBu, 0xF4u, 0xE3u, 0xA7u, 0x6Au, 0x7Eu, 0x64u, 0x58u, 0x8Fu, 0x8Eu, 0x14u, 0x20u,
            0xFEu, 0xAFu, 0x0Du, 0xA2u, 0xC7u, 0x8Bu, 0xBEu, 0x5Bu, 0xE9u, 0x45u, 0xA8u, 0xBEu,
            0x61u, 0xABu, 0x2Fu, 0x27u, 0xB6u, 0xD0u, 0xEEu, 0xEDu, 0xE6u, 0x4Eu, 0x70u, 0x4Eu,
            0xDCu, 0x4Eu, 0x85u, 0x76u, 0xBDu, 0xC9u, 0x53u, 0x40u, 0x28u, 0xF8u, 0x9Eu, 0x8Cu,
            0x33u, 0x36u, 0x0Du, 0x16u, 0xA6u, 0x31u, 0x29u, 0x3Cu, 0x30u, 0xB0u, 0xDDu, 0x93u,
            0xB4u, 0xD6u, 0xC4u, 0xB2u, 0x7Fu, 0x69u, 0x47u, 0x6Eu, 0x83u, 0x80u, 0xCFu, 0xDCu,
            0x84u, 0xC7u, 0x50u, 0x27u, 0xD1u, 0x0Fu, 0xD2u, 0x32u, 0x1Du, 0xC2u, 0x5Au, 0xE4u,
            0xACu, 0x29u, 0x48u, 0xC7u, 0x0Du, 0xD5u, 0x49u, 0x59u, 0x9Cu, 0x5Bu, 0x3Eu, 0x15u,
            0xC6u, 0xC9u, 0x23u, 0x0Eu, 0xC6u, 0x80u, 0x98u, 0xEFu, 0x84u, 0x29u, 0xEFu, 0x68u,
            0xE2u, 0x3Bu, 0xC7u, 0x3Eu, 0x00u, 0x2Eu, 0xD5u, 0x27u, 0x22u, 0x6Bu, 0xE5u, 0xAFu,
            0xC1u, 0xD8u, 0x11u, 0xC7u, 0x79u, 0x50u, 0x39u, 0x45u, 0x08u, 0xDAu, 0xF6u, 0x0Du,
            0xD9u, 0x4Du, 0x5Du, 0x1Du, 0x7Cu, 0x0Du, 0xACu, 0xE4u, 0x78u, 0x57u, 0xF7u, 0xB0u,
            0xB9u, 0x02u, 0x03u, 0x01u, 0x00u, 0x01u
        };
        static const uint8_t rsa6Hash[32] = {
            0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u, 0xA6u, 0xA7u, 0xA8u, 0xA9u, 0xAAu, 0xABu,
            0xACu, 0xADu, 0xAEu, 0xAFu, 0xB0u, 0xB1u, 0xB2u, 0xB3u, 0xB4u, 0xB5u, 0xB6u, 0xB7u,
            0xB8u, 0xB9u, 0xBAu, 0xBBu, 0xBCu, 0xBDu, 0xBEu, 0xBFu
        };
        /* Vectors from a Python RSA/PSS model; OpenSSL verifies SigGood and rejects SigHigh */
        static const uint8_t rsa6SigGood[257] = {
            0x00u, 0xA4u, 0x8Eu, 0xA9u, 0xABu, 0x6Eu, 0xAEu, 0xF3u, 0x15u, 0x38u, 0xE4u, 0x51u,
            0xADu, 0xB0u, 0x7Cu, 0x64u, 0xD2u, 0x4Bu, 0x68u, 0xFBu, 0xDCu, 0x09u, 0xE3u, 0x00u,
            0x74u, 0xC8u, 0x39u, 0xF0u, 0x92u, 0x17u, 0x06u, 0xA1u, 0x2Eu, 0xD7u, 0xACu, 0x25u,
            0xB4u, 0xEEu, 0xDDu, 0x7Eu, 0x56u, 0xB2u, 0x05u, 0x45u, 0x08u, 0xD9u, 0x73u, 0xFEu,
            0xF9u, 0x7Du, 0x22u, 0x4Du, 0xB7u, 0x7Eu, 0xE4u, 0x4Bu, 0x30u, 0x81u, 0x43u, 0xC8u,
            0xD8u, 0xF7u, 0x69u, 0x53u, 0xBFu, 0xF0u, 0x3Du, 0x66u, 0x34u, 0x1Cu, 0x5Cu, 0x0Bu,
            0x32u, 0xD9u, 0xBDu, 0x7Au, 0xB1u, 0x7Du, 0x12u, 0x99u, 0xECu, 0xEDu, 0x88u, 0x8Du,
            0x33u, 0x09u, 0x0Cu, 0x86u, 0x46u, 0xD0u, 0x09u, 0x79u, 0x3Bu, 0x12u, 0xFDu, 0x65u,
            0x24u, 0x10u, 0x60u, 0x8Au, 0xDAu, 0x4Au, 0x9Fu, 0xB2u, 0xD2u, 0xDDu, 0x50u, 0x38u,
            0xB4u, 0xF3u, 0xFDu, 0x09u, 0xE3u, 0xECu, 0x58u, 0xE0u, 0xFEu, 0x28u, 0x2Fu, 0xDFu,
            0x37u, 0xB9u, 0x9Bu, 0xF8u, 0xD0u, 0xDAu, 0x40u, 0x28u, 0xC9u, 0x70u, 0xD6u, 0xB1u,
            0x44u, 0x68u, 0x0Cu, 0xD3u, 0xB3u, 0xFFu, 0x42u, 0x79u, 0x1Fu, 0x5Au, 0xA9u, 0x5Au,
            0x40u, 0x65u, 0xBBu, 0x9Cu, 0xB2u, 0x56u, 0x30u, 0xB2u, 0xF1u, 0x42u, 0x9Bu, 0xF7u,
            0xDFu, 0x9Eu, 0x8Eu, 0xC1u, 0xB8u, 0xE0u, 0x13u, 0x35u, 0x42u, 0xBDu, 0xE1u, 0x43u,
            0x54u, 0xF2u, 0x6Fu, 0x5Du, 0x49u, 0x7Cu, 0x31u, 0x49u, 0x19u, 0xFFu, 0x48u, 0x46u,
            0xA6u, 0x2Fu, 0x33u, 0xFFu, 0xABu, 0x2Bu, 0x38u, 0xB5u, 0xF8u, 0xABu, 0x81u, 0x5Bu,
            0x3Bu, 0xBCu, 0x5Du, 0x14u, 0xFDu, 0xAEu, 0x16u, 0xC6u, 0x5Fu, 0x48u, 0xBFu, 0xFFu,
            0x38u, 0x78u, 0xB3u, 0x74u, 0x46u, 0xADu, 0x8Cu, 0x01u, 0x1Fu, 0xD4u, 0x51u, 0xDBu,
            0xEDu, 0x92u, 0x5Fu, 0xC0u, 0xEEu, 0xFAu, 0x42u, 0x10u, 0x6Eu, 0x3Eu, 0xCAu, 0xD4u,
            0x9Eu, 0x43u, 0x2Bu, 0x8Fu, 0xBAu, 0xB0u, 0x3Au, 0x4Au, 0x1Cu, 0xEAu, 0x9Eu, 0x5Eu,
            0x40u, 0x16u, 0x15u, 0xD6u, 0xBBu, 0x88u, 0x00u, 0xBEu, 0xC5u, 0x11u, 0xCCu, 0xA1u,
            0x0Fu, 0x88u, 0x70u, 0x5Eu, 0x40u
        };
        static const uint8_t rsa6SigHigh[257] = {
            0x00u, 0x56u, 0xB5u, 0xB1u, 0x34u, 0x77u, 0x81u, 0xEEu, 0x76u, 0x51u, 0x68u, 0x99u,
            0x3Au, 0xEDu, 0x0Cu, 0x8Bu, 0x5Fu, 0x7Eu, 0x37u, 0xC4u, 0x8Fu, 0x05u, 0xA1u, 0xF6u,
            0xCBu, 0x99u, 0x35u, 0x1Eu, 0x52u, 0xCFu, 0xE6u, 0xC5u, 0x39u, 0x75u, 0x64u, 0x6Fu,
            0xDFu, 0x77u, 0x69u, 0x9Cu, 0x8Bu, 0x70u, 0x6Bu, 0x1Eu, 0x6Bu, 0x40u, 0xD0u, 0x12u,
            0x6Bu, 0xEDu, 0x3Eu, 0xD8u, 0x51u, 0xA5u, 0x75u, 0x63u, 0x28u, 0x0Cu, 0xBBu, 0x58u,
            0x94u, 0x8Du, 0x07u, 0x67u, 0xADu, 0xCAu, 0x4Fu, 0xB9u, 0x1Bu, 0xFDu, 0x09u, 0xB7u,
            0xC4u, 0x35u, 0x6Au, 0x4Fu, 0x86u, 0x3Du, 0x5Du, 0xDCu, 0xDAu, 0x25u, 0xF9u, 0xA1u,
            0x03u, 0xCBu, 0xD1u, 0x00u, 0x87u, 0xFFu, 0x8Eu, 0x43u, 0x52u, 0x95u, 0xFFu, 0x5Bu,
            0x1Cu, 0x72u, 0x7Eu, 0xF7u, 0xF4u, 0x91u, 0x29u, 0x92u, 0x95u, 0x2Du, 0x47u, 0x5Fu,
            0x86u, 0x3Cu, 0x1Fu, 0x86u, 0x53u, 0x5Au, 0x5Cu, 0x11u, 0x19u, 0x73u, 0xBCu, 0x38u,
            0x59u, 0x44u, 0x02u, 0x8Bu, 0xDDu, 0x7Bu, 0x5Fu, 0xAAu, 0x4Bu, 0xB4u, 0x02u, 0xDFu,
            0x6Bu, 0x6Fu, 0xA0u, 0x5Cu, 0x58u, 0x81u, 0xB4u, 0xDCu, 0x84u, 0x4Au, 0xC6u, 0xA2u,
            0x92u, 0xD2u, 0xB0u, 0xE8u, 0x8Bu, 0x3Du, 0x70u, 0xA9u, 0xE7u, 0x1Au, 0xF1u, 0x87u,
            0x7Eu, 0xDDu, 0x13u, 0x47u, 0xD6u, 0xFDu, 0xC5u, 0x3Fu, 0xB9u, 0x71u, 0x60u, 0x1Du,
            0x19u, 0x14u, 0x7Fu, 0xE6u, 0x3Du, 0x0Du, 0xFAu, 0xCBu, 0x22u, 0x04u, 0xE4u, 0x80u,
            0x83u, 0x23u, 0xB0u, 0xCDu, 0x6Eu, 0x98u, 0x39u, 0xAEu, 0x33u, 0x45u, 0xBFu, 0x53u,
            0x14u, 0x27u, 0x23u, 0xCAu, 0xCDu, 0xBBu, 0x55u, 0x60u, 0xD6u, 0xC1u, 0xB5u, 0x34u,
            0xA2u, 0xD0u, 0x2Du, 0xB2u, 0x01u, 0x46u, 0x49u, 0xF2u, 0x7Bu, 0xD2u, 0x48u, 0xD9u,
            0xB5u, 0x99u, 0xFEu, 0x51u, 0xB0u, 0x28u, 0x26u, 0xF0u, 0x93u, 0xA9u, 0x74u, 0xC7u,
            0x03u, 0xADu, 0x13u, 0x21u, 0x36u, 0xFCu, 0xEDu, 0xEAu, 0x24u, 0x08u, 0xEDu, 0x9Bu,
            0x41u, 0x0Eu, 0x6Fu, 0x1Bu, 0xB2u, 0x81u, 0x75u, 0x4Bu, 0x40u, 0xCDu, 0x79u, 0x21u,
            0xD5u, 0x72u, 0x53u, 0x9Bu, 0x0Bu
        };

        SSF_ASSERT(SSFRSAVerifyPSS(rsa6Pub, sizeof(rsa6Pub), SSF_RSA_HASH_SHA256, rsa6Hash,
                                   sizeof(rsa6Hash), 32u, rsa6SigGood,
                                   sizeof(rsa6SigGood)) == true);
        SSF_ASSERT(SSFRSAVerifyPSS(rsa6Pub, sizeof(rsa6Pub), SSF_RSA_HASH_SHA256, rsa6Hash,
                                   sizeof(rsa6Hash), 32u, rsa6SigHigh,
                                   sizeof(rsa6SigHigh)) == false);
    }
#endif /* SSF_RSA_CONFIG_ENABLE_PSS && SSF_RSA_MAX_KEY_BYTES >= 257 */

    /* ---- COV-7: PSS sign when bitLen(n) = 1 mod 8 (emLen = keyBytes - 1, EM left-padded) ---- */
    /* 2049-bit key (p 1025 bits, q 1024 bits) built offline, checked with openssl rsa -check.    */
#if (SSF_RSA_CONFIG_ENABLE_PSS == 1) && (SSF_RSA_MAX_KEY_BYTES >= 257u)
    {
        static const uint8_t rsa2049Priv[1192] = {
            0x30u, 0x82u, 0x04u, 0xA4u, 0x02u, 0x01u, 0x00u, 0x02u, 0x82u, 0x01u, 0x01u, 0x01u,
            0xBBu, 0xFCu, 0x8Fu, 0xE3u, 0x49u, 0x35u, 0x3Au, 0x3Du, 0xF9u, 0x7Cu, 0x05u, 0x37u,
            0x9Bu, 0x8Bu, 0x98u, 0x48u, 0xB2u, 0x4Au, 0x3Bu, 0x5Fu, 0x01u, 0xA2u, 0x90u, 0x10u,
            0x7Fu, 0x35u, 0x3Au, 0x3Bu, 0x8Cu, 0xB7u, 0x14u, 0x84u, 0x99u, 0xE8u, 0x73u, 0x02u,
            0x53u, 0x81u, 0xC4u, 0xC6u, 0xBFu, 0x73u, 0x51u, 0x09u, 0x64u, 0x9Du, 0x81u, 0xA5u,
            0x79u, 0x97u, 0xA5u, 0x90u, 0x6Eu, 0x88u, 0x6Cu, 0x3Cu, 0x31u, 0xCAu, 0x42u, 0xE5u,
            0xDCu, 0xE3u, 0x8Fu, 0xD0u, 0x04u, 0x82u, 0xF1u, 0x6Bu, 0x25u, 0xEEu, 0x62u, 0x23u,
            0x06u, 0x8Eu, 0x08u, 0xEDu, 0x9Bu, 0xEAu, 0xF4u, 0x3Bu, 0x5Fu, 0x29u, 0x83u, 0x93u,
            0x33u, 0x2Du, 0x65u, 0x3Du, 0x48u, 0xC1u, 0x37u, 0x29u, 0x2Au, 0x0Bu, 0xE6u, 0x3Fu,
            0x3Cu, 0x1Au, 0x34u, 0x3Cu, 0x35u, 0x76u, 0x1Eu, 0x96u, 0x8Fu, 0x4Au, 0x12u, 0x5Du,
            0xE5u, 0x9Du, 0xF2u, 0x9Du, 0x04u, 0xD5u, 0x0Bu, 0xD8u, 0x86u, 0x89u, 0xA6u, 0xBBu,
            0x51u, 0x81u, 0x9Eu, 0xEDu, 0xA6u, 0xE6u, 0x80u, 0x9Fu, 0x02u, 0x0Eu, 0x60u, 0x50u,
            0xF2u, 0x7Au, 0xC1u, 0x84u, 0x3Cu, 0xD5u, 0x0Au, 0x4Au, 0x82u, 0x9Au, 0x15u, 0xD1u,
            0x67u, 0x1Bu, 0xE8u, 0x4Du, 0xB9u, 0xCFu, 0x05u, 0x62u, 0x6Du, 0x44u, 0x54u, 0x3Au,
            0xB6u, 0x95u, 0xFBu, 0xCAu, 0x2Cu, 0xE0u, 0xDAu, 0x9Cu, 0x76u, 0x1Cu, 0x78u, 0x22u,
            0xF8u, 0x6Bu, 0xC9u, 0x86u, 0x18u, 0xF0u, 0xD2u, 0xABu, 0xB0u, 0xAAu, 0xFDu, 0x69u,
            0xB9u, 0x49u, 0xDFu, 0x40u, 0x6Bu, 0x30u, 0x37u, 0x9Au, 0x84u, 0x2Au, 0xF9u, 0x10u,
            0xF7u, 0x8Fu, 0xBFu, 0x03u, 0xE5u, 0x33u, 0x3Bu, 0xB3u, 0xA8u, 0xA8u, 0xBDu, 0x68u,
            0x30u, 0x79u, 0xCAu, 0x1Au, 0xB3u, 0x1Du, 0x28u, 0x4Au, 0x98u, 0xA7u, 0xD1u, 0x26u,
            0x37u, 0x84u, 0x7Cu, 0x8Au, 0x0Bu, 0x1Au, 0x6Cu, 0x61u, 0xE7u, 0xEEu, 0x06u, 0xAEu,
            0xE8u, 0x14u, 0x12u, 0x33u, 0x46u, 0x10u, 0x7Cu, 0x82u, 0x84u, 0xAEu, 0xA7u, 0xE9u,
            0x33u, 0x2Bu, 0xE8u, 0xA8u, 0x68u, 0xC8u, 0x48u, 0x10u, 0xD4u, 0x5Bu, 0xCBu, 0xF1u,
            0xA7u, 0x8Au, 0x5Bu, 0x53u, 0x02u, 0x03u, 0x01u, 0x00u, 0x01u, 0x02u, 0x82u, 0x01u,
            0x01u, 0x00u, 0xC8u, 0xFEu, 0xD4u, 0x90u, 0xFBu, 0xA2u, 0x6Au, 0x24u, 0x86u, 0x5Eu,
            0x5Bu, 0xEAu, 0x49u, 0xB3u, 0x8Fu, 0x94u, 0x51u, 0x8Au, 0x83u, 0x88u, 0x46u, 0x30u,
            0x36u, 0xF2u, 0x10u, 0xF4u, 0xA2u, 0xD1u, 0x34u, 0xA9u, 0xE9u, 0x53u, 0x02u, 0x6Eu,
            0x16u, 0x2Au, 0xD6u, 0x6Du, 0x28u, 0x0Du, 0x25u, 0xBCu, 0xE9u, 0xD1u, 0xCBu, 0xC7u,
            0xF6u, 0x5Au, 0x58u, 0x4Au, 0x8Bu, 0xBCu, 0x70u, 0x1Du, 0xB8u, 0x8Au, 0x23u, 0xACu,
            0x42u, 0x4Eu, 0xD7u, 0x89u, 0xF9u, 0xA0u, 0x1Du, 0x7Au, 0xBEu, 0x1Au, 0x58u, 0xC8u,
            0xABu, 0x8Au, 0xD9u, 0xBBu, 0xD1u, 0x54u, 0xE8u, 0x42u, 0x1Cu, 0xA1u, 0x08u, 0x3Au,
            0xBEu, 0x03u, 0x14u, 0xA7u, 0x17u, 0x6Fu, 0x00u, 0x11u, 0xE0u, 0x8Bu, 0xF5u, 0x29u,
            0xFFu, 0xE9u, 0x5Eu, 0xA7u, 0x2Au, 0x40u, 0x9Bu, 0x9Fu, 0x46u, 0xC7u, 0xB8u, 0x44u,
            0xBBu, 0x3Du, 0xE0u, 0xE6u, 0x79u, 0x60u, 0x16u, 0x40u, 0xF0u, 0xA4u, 0xECu, 0x7Bu,
            0x42u, 0x8Du, 0x08u, 0xA0u, 0x1Au, 0xB7u, 0xD1u, 0xD8u, 0x06u, 0x1Fu, 0x34u, 0x28u,
            0x90u, 0x09u, 0xEBu, 0x8Eu, 0xE5u, 0x3Fu, 0xFCu, 0xDFu, 0x17u, 0x7Eu, 0xD7u, 0xCEu,
            0x4Fu, 0x1Fu, 0xBDu, 0x32u, 0x53u, 0x8Au, 0x3Cu, 0x28u, 0xC7u, 0x5Du, 0x66u, 0x88u,
            0x81u, 0x31u, 0x19u, 0x52u, 0xA1u, 0xD5u, 0xB5u, 0x9Fu, 0xC5u, 0xB8u, 0x5Du, 0x23u,
            0xA2u, 0xE3u, 0x64u, 0x5Bu, 0x17u, 0xB6u, 0x71u, 0x3Bu, 0xBFu, 0xD9u, 0x65u, 0xA6u,
            0x39u, 0x16u, 0xAEu, 0xD4u, 0xCDu, 0x15u, 0x17u, 0x98u, 0xE7u, 0x18u, 0x69u, 0x69u,
            0x5Du, 0x6Au, 0x27u, 0x3Eu, 0xCCu, 0x33u, 0xAEu, 0x27u, 0x23u, 0x97u, 0x52u, 0x81u,
            0x6Du, 0xDAu, 0x15u, 0x43u, 0x4Bu, 0xC4u, 0x10u, 0x43u, 0xF0u, 0x35u, 0x65u, 0xABu,
            0x64u, 0xE7u, 0x44u, 0x2Cu, 0x63u, 0x84u, 0xF6u, 0x57u, 0x01u, 0xBDu, 0xB4u, 0x9Au,
            0x7Eu, 0x12u, 0xD0u, 0x6Bu, 0x25u, 0x81u, 0x46u, 0x72u, 0xD8u, 0xE1u, 0xAEu, 0x12u,
            0xE1u, 0x50u, 0xDEu, 0xB1u, 0x66u, 0xAEu, 0x31u, 0x44u, 0x6Cu, 0xA3u, 0xAEu, 0x85u,
            0x6Eu, 0xF3u, 0x15u, 0x8Du, 0x3Au, 0x31u, 0x02u, 0x81u, 0x81u, 0x01u, 0xD4u, 0x4Au,
            0x78u, 0x1Eu, 0xBBu, 0x11u, 0x61u, 0x24u, 0x8Au, 0x0Bu, 0xBCu, 0x74u, 0x69u, 0x37u,
            0x0Du, 0x92u, 0x62u, 0x06u, 0xEEu, 0x23u, 0xAAu, 0x87u, 0x14u, 0x45u, 0x2Fu, 0x97u,
            0x66u, 0x50u, 0xD0u, 0xFFu, 0xB6u, 0x31u, 0x2Fu, 0x70u, 0xEEu, 0xBAu, 0xF8u, 0x09u,
            0x74u, 0x80u, 0xD0u, 0x9Cu, 0x93u, 0xF1u, 0xF6u, 0x2Au, 0x4Bu, 0xD0u, 0xF5u, 0x7Cu,
            0xB9u, 0xD4u, 0xB4u, 0x15u, 0x57u, 0x55u, 0xCDu, 0x3Bu, 0x0Cu, 0xC4u, 0xD8u, 0x61u,
            0xB8u, 0x1Cu, 0x15u, 0x64u, 0x5Bu, 0x26u, 0x09u, 0xF1u, 0x94u, 0x54u, 0x7Cu, 0x28u,
            0xEEu, 0xB8u, 0x98u, 0x03u, 0xF7u, 0x88u, 0x41u, 0x7Au, 0x60u, 0xDEu, 0x21u, 0x19u,
            0x03u, 0xD6u, 0x9Du, 0xD9u, 0x10u, 0x33u, 0x75u, 0xE8u, 0x9Cu, 0xE9u, 0x6Cu, 0x1Eu,
            0xC2u, 0xDDu, 0x2Fu, 0xE0u, 0x11u, 0xBFu, 0x81u, 0x9Au, 0xF6u, 0x6Fu, 0x28u, 0x44u,
            0x1Cu, 0x6Eu, 0xCBu, 0x0Cu, 0xF8u, 0xB1u, 0xF9u, 0x7Cu, 0xFEu, 0x2Cu, 0x09u, 0xBDu,
            0x63u, 0x16u, 0x3Eu, 0xD2u, 0x6Bu, 0xD9u, 0x02u, 0x81u, 0x81u, 0x00u, 0xF2u, 0xB6u,
            0xADu, 0x82u, 0x63u, 0x3Cu, 0xCFu, 0xCDu, 0xC1u, 0x19u, 0xB3u, 0x9Au, 0x11u, 0x5Eu,
            0x9Fu, 0xA6u, 0x91u, 0x71u, 0x16u, 0xCEu, 0x62u, 0x54u, 0x9Fu, 0x0Bu, 0xF3u, 0x41u,
            0x55u, 0x7Au, 0x0Cu, 0x9Fu, 0xF3u, 0xA4u, 0x0Eu, 0x72u, 0xD1u, 0x4Fu, 0xF9u, 0x34u,
            0x16u, 0x4Eu, 0x29u, 0xCAu, 0x2Fu, 0xD8u, 0x3Du, 0xC7u, 0xF9u, 0xC4u, 0x9Au, 0x72u,
            0x84u, 0x99u, 0x53u, 0xA0u, 0x32u, 0xD2u, 0xA1u, 0xE8u, 0xDBu, 0x68u, 0x01u, 0xB1u,
            0x9Au, 0xBBu, 0x64u, 0xFCu, 0xB4u, 0xB4u, 0x07u, 0xE9u, 0x22u, 0xC8u, 0x1Fu, 0x32u,
            0x39u, 0xA1u, 0xD7u, 0x36u, 0x59u, 0xCDu, 0xD1u, 0x0Au, 0xA2u, 0xF7u, 0x1Au, 0x4Du,
            0x6Bu, 0x2Cu, 0x44u, 0x08u, 0xCDu, 0xC9u, 0x2Du, 0xF8u, 0xBFu, 0xCDu, 0xBFu, 0x72u,
            0x6Eu, 0xECu, 0xBBu, 0x32u, 0x94u, 0x26u, 0xDEu, 0xCDu, 0x0Au, 0x44u, 0xD4u, 0x2Au,
            0xB2u, 0xEEu, 0x12u, 0x78u, 0xBFu, 0xA1u, 0x0Cu, 0x16u, 0x25u, 0x74u, 0x5Au, 0x06u,
            0x27u, 0xB0u, 0x9Du, 0xA6u, 0xE1u, 0x0Bu, 0x02u, 0x81u, 0x81u, 0x00u, 0xFFu, 0xC1u,
            0xC0u, 0x43u, 0x00u, 0x66u, 0x28u, 0x88u, 0xFDu, 0x40u, 0x15u, 0xA7u, 0xFAu, 0x82u,
            0xCFu, 0xCDu, 0xBFu, 0xEEu, 0x0Bu, 0x07u, 0xBDu, 0xADu, 0xD2u, 0x9Bu, 0x4Au, 0xB7u,
            0xC4u, 0x70u, 0xA5u, 0x04u, 0xD3u, 0xABu, 0x9Fu, 0x3Eu, 0x6Du, 0x93u, 0xFDu, 0xBDu,
            0xA4u, 0x3Cu, 0x6Au, 0x32u, 0xE9u, 0xF6u, 0x3Fu, 0x3Cu, 0xB0u, 0x75u, 0xAAu, 0x6Du,
            0x79u, 0x4Cu, 0xBBu, 0x21u, 0xE0u, 0xB6u, 0x02u, 0xC5u, 0x9Au, 0x5Eu, 0xB3u, 0xD3u,
            0x02u, 0xEBu, 0x8Bu, 0x9Fu, 0x68u, 0xCCu, 0xA8u, 0xA7u, 0xA1u, 0x1Cu, 0x57u, 0x47u,
            0x3Fu, 0xC1u, 0xDFu, 0x7Cu, 0x63u, 0x27u, 0xAEu, 0xA3u, 0x38u, 0xDEu, 0x78u, 0x73u,
            0x22u, 0x0Eu, 0x87u, 0xDDu, 0x32u, 0x24u, 0xF8u, 0xE3u, 0x97u, 0x37u, 0x41u, 0x0Eu,
            0xB7u, 0xDCu, 0x77u, 0xB6u, 0x47u, 0xDBu, 0x30u, 0xDCu, 0xC2u, 0x74u, 0xC9u, 0x28u,
            0x11u, 0xE3u, 0x4Cu, 0xD0u, 0x83u, 0xCFu, 0x27u, 0xF4u, 0x65u, 0x19u, 0x06u, 0x24u,
            0xC2u, 0x46u, 0x36u, 0xFFu, 0x53u, 0x59u, 0x02u, 0x81u, 0x80u, 0x54u, 0x4Eu, 0x37u,
            0xBEu, 0x8Eu, 0x91u, 0xD4u, 0xECu, 0x77u, 0x22u, 0x62u, 0x4Cu, 0x25u, 0xB4u, 0x64u,
            0x68u, 0x0Bu, 0x24u, 0xE8u, 0xF3u, 0x0Fu, 0x1Cu, 0xADu, 0x92u, 0x0Du, 0x10u, 0xA8u,
            0x8Cu, 0x18u, 0x4Eu, 0x86u, 0xE6u, 0x79u, 0x4Eu, 0x50u, 0x7Eu, 0x22u, 0xE5u, 0x80u,
            0xC9u, 0xEDu, 0xA2u, 0x19u, 0x34u, 0x57u, 0x61u, 0x5Au, 0xD4u, 0x7Bu, 0x81u, 0x43u,
            0xA5u, 0xAEu, 0x72u, 0x7Au, 0xB4u, 0xC7u, 0x20u, 0x86u, 0xF5u, 0x7Du, 0x81u, 0x1Fu,
            0x69u, 0xF0u, 0x0Eu, 0x07u, 0x06u, 0x71u, 0xA8u, 0xFDu, 0x37u, 0xDDu, 0xFEu, 0x28u,
            0x1Eu, 0x9Bu, 0x0Eu, 0x79u, 0xEBu, 0x0Fu, 0xADu, 0x4Eu, 0x25u, 0xDEu, 0xB0u, 0xFDu,
            0x85u, 0x06u, 0xACu, 0xB8u, 0x2Eu, 0x25u, 0x15u, 0xBEu, 0x29u, 0xCDu, 0x52u, 0x06u,
            0x4Du, 0x9Cu, 0x48u, 0x59u, 0x45u, 0x97u, 0x26u, 0x49u, 0x66u, 0xD6u, 0xFBu, 0x6Du,
            0xE3u, 0x5Bu, 0xEFu, 0x2Du, 0x40u, 0xD7u, 0x5Du, 0xE9u, 0xECu, 0x9Cu, 0x48u, 0x7Fu,
            0x08u, 0xCDu, 0xF9u, 0xE5u, 0x39u, 0x02u, 0x81u, 0x80u, 0x67u, 0x02u, 0xBFu, 0xC6u,
            0xDCu, 0xA8u, 0x37u, 0x01u, 0x44u, 0xC8u, 0x8Au, 0xD5u, 0xE5u, 0xFCu, 0xD8u, 0x26u,
            0xC1u, 0xDBu, 0x60u, 0x65u, 0x28u, 0x1Au, 0x01u, 0x0Au, 0x26u, 0x90u, 0xCFu, 0x2Bu,
            0xBBu, 0xA5u, 0x53u, 0xEAu, 0xFDu, 0xC9u, 0x79u, 0x21u, 0x10u, 0xA8u, 0x7Fu, 0xB3u,
            0x84u, 0xF1u, 0x92u, 0xC2u, 0x72u, 0xCEu, 0x18u, 0x01u, 0xB0u, 0x1Du, 0x39u, 0x92u,
            0x4Bu, 0xB6u, 0x2Au, 0xCBu, 0x3Cu, 0xDBu, 0x5Au, 0xA2u, 0x3Bu, 0x4Eu, 0x4Du, 0xAEu,
            0x25u, 0x30u, 0x9Du, 0x9Du, 0xDAu, 0x4Cu, 0xA1u, 0xAEu, 0x30u, 0x0Bu, 0xDFu, 0xD6u,
            0xADu, 0xA9u, 0x87u, 0x0Bu, 0x0Du, 0x91u, 0xB8u, 0x39u, 0x0Eu, 0xDFu, 0xE0u, 0xFCu,
            0x2Au, 0xA6u, 0xE3u, 0xA7u, 0x48u, 0x49u, 0xB4u, 0xD5u, 0x5Au, 0x6Du, 0x64u, 0x76u,
            0x19u, 0x59u, 0x76u, 0xECu, 0x2Du, 0x55u, 0x71u, 0x7Bu, 0x6Cu, 0xA7u, 0xB9u, 0x3Du,
            0xD5u, 0x97u, 0x1Bu, 0xBFu, 0x45u, 0x8Fu, 0x16u, 0xF3u, 0x06u, 0x26u, 0xB4u, 0xFAu,
            0x72u, 0x4Au, 0xD0u, 0x63u
        };
        static const uint8_t rsa2049Pub[270] = {
            0x30u, 0x82u, 0x01u, 0x0Au, 0x02u, 0x82u, 0x01u, 0x01u, 0x01u, 0xBBu, 0xFCu, 0x8Fu,
            0xE3u, 0x49u, 0x35u, 0x3Au, 0x3Du, 0xF9u, 0x7Cu, 0x05u, 0x37u, 0x9Bu, 0x8Bu, 0x98u,
            0x48u, 0xB2u, 0x4Au, 0x3Bu, 0x5Fu, 0x01u, 0xA2u, 0x90u, 0x10u, 0x7Fu, 0x35u, 0x3Au,
            0x3Bu, 0x8Cu, 0xB7u, 0x14u, 0x84u, 0x99u, 0xE8u, 0x73u, 0x02u, 0x53u, 0x81u, 0xC4u,
            0xC6u, 0xBFu, 0x73u, 0x51u, 0x09u, 0x64u, 0x9Du, 0x81u, 0xA5u, 0x79u, 0x97u, 0xA5u,
            0x90u, 0x6Eu, 0x88u, 0x6Cu, 0x3Cu, 0x31u, 0xCAu, 0x42u, 0xE5u, 0xDCu, 0xE3u, 0x8Fu,
            0xD0u, 0x04u, 0x82u, 0xF1u, 0x6Bu, 0x25u, 0xEEu, 0x62u, 0x23u, 0x06u, 0x8Eu, 0x08u,
            0xEDu, 0x9Bu, 0xEAu, 0xF4u, 0x3Bu, 0x5Fu, 0x29u, 0x83u, 0x93u, 0x33u, 0x2Du, 0x65u,
            0x3Du, 0x48u, 0xC1u, 0x37u, 0x29u, 0x2Au, 0x0Bu, 0xE6u, 0x3Fu, 0x3Cu, 0x1Au, 0x34u,
            0x3Cu, 0x35u, 0x76u, 0x1Eu, 0x96u, 0x8Fu, 0x4Au, 0x12u, 0x5Du, 0xE5u, 0x9Du, 0xF2u,
            0x9Du, 0x04u, 0xD5u, 0x0Bu, 0xD8u, 0x86u, 0x89u, 0xA6u, 0xBBu, 0x51u, 0x81u, 0x9Eu,
            0xEDu, 0xA6u, 0xE6u, 0x80u, 0x9Fu, 0x02u, 0x0Eu, 0x60u, 0x50u, 0xF2u, 0x7Au, 0xC1u,
            0x84u, 0x3Cu, 0xD5u, 0x0Au, 0x4Au, 0x82u, 0x9Au, 0x15u, 0xD1u, 0x67u, 0x1Bu, 0xE8u,
            0x4Du, 0xB9u, 0xCFu, 0x05u, 0x62u, 0x6Du, 0x44u, 0x54u, 0x3Au, 0xB6u, 0x95u, 0xFBu,
            0xCAu, 0x2Cu, 0xE0u, 0xDAu, 0x9Cu, 0x76u, 0x1Cu, 0x78u, 0x22u, 0xF8u, 0x6Bu, 0xC9u,
            0x86u, 0x18u, 0xF0u, 0xD2u, 0xABu, 0xB0u, 0xAAu, 0xFDu, 0x69u, 0xB9u, 0x49u, 0xDFu,
            0x40u, 0x6Bu, 0x30u, 0x37u, 0x9Au, 0x84u, 0x2Au, 0xF9u, 0x10u, 0xF7u, 0x8Fu, 0xBFu,
            0x03u, 0xE5u, 0x33u, 0x3Bu, 0xB3u, 0xA8u, 0xA8u, 0xBDu, 0x68u, 0x30u, 0x79u, 0xCAu,
            0x1Au, 0xB3u, 0x1Du, 0x28u, 0x4Au, 0x98u, 0xA7u, 0xD1u, 0x26u, 0x37u, 0x84u, 0x7Cu,
            0x8Au, 0x0Bu, 0x1Au, 0x6Cu, 0x61u, 0xE7u, 0xEEu, 0x06u, 0xAEu, 0xE8u, 0x14u, 0x12u,
            0x33u, 0x46u, 0x10u, 0x7Cu, 0x82u, 0x84u, 0xAEu, 0xA7u, 0xE9u, 0x33u, 0x2Bu, 0xE8u,
            0xA8u, 0x68u, 0xC8u, 0x48u, 0x10u, 0xD4u, 0x5Bu, 0xCBu, 0xF1u, 0xA7u, 0x8Au, 0x5Bu,
            0x53u, 0x02u, 0x03u, 0x01u, 0x00u, 0x01u
        };
        uint8_t hash[32];
        static uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
        size_t sigLen = 0u;

        SSFSHA256((const uint8_t *)"COV-7 2049-bit PSS", 18u, hash, sizeof(hash));
        SSF_ASSERT(SSFRSASignPSS(rsa2049Priv, sizeof(rsa2049Priv), SSF_RSA_HASH_SHA256, hash,
                                 sizeof(hash), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(sigLen == 257u);
        SSF_ASSERT(SSFRSAVerifyPSS(rsa2049Pub, sizeof(rsa2049Pub), SSF_RSA_HASH_SHA256, hash,
                                   sizeof(hash), sizeof(hash), sig, sigLen) == true);
        sig[100] ^= 0x01u;
        SSF_ASSERT(SSFRSAVerifyPSS(rsa2049Pub, sizeof(rsa2049Pub), SSF_RSA_HASH_SHA256, hash,
                                   sizeof(hash), sizeof(hash), sig, sigLen) == false);
    }
#endif /* SSF_RSA_CONFIG_ENABLE_PSS && SSF_RSA_MAX_KEY_BYTES >= 257 */

    /* ---- (Hardening, AUDIT RSA-1/RSA-2/RSA-3/RSA-4) decoders bound every RSA integer ---- */
#if (SSF_RSA_MAX_KEY_BYTES + 16u) <= SSF_BN_MAX_BYTES
    {
        static uint8_t der[SSF_RSA_MAX_KEY_BYTES + 64u];
        static uint8_t sig[SSF_RSA_MAX_KEY_BYTES + 16u];
        uint8_t hash[32];
        const uint32_t nMag = (uint32_t)SSF_RSA_MAX_KEY_BYTES + 16u;
        uint32_t p = 4u;

        memset(hash, 0xA5, sizeof(hash));
        memset(sig, 0x01, sizeof(sig));
        sig[0] = 0x00u; /* s < n */

        /* Odd modulus 16 bytes above the configured maximum; e = 65537. */
        _SSFRSAUTPutIntTLV(der, &p, nMag, 0x7Fu, 0xFFu);
        _SSFRSAUTPutIntTLV(der, &p, 3u, 0x01u, 0x01u);
        _SSFRSAUTCloseSeq(der, p);
        SSF_ASSERT((size_t)p <= sizeof(der));

        SSF_ASSERT(SSFRSAPubKeyIsValid(der, (size_t)p) == false);
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSAVerifyPKCS1(der, (size_t)p, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                                     sig, (size_t)nMag) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSAVerifyPSS(der, (size_t)p, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                                   sizeof(hash), sig, (size_t)nMag) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
    }

    {
        static uint8_t der[SSF_RSA_MAX_KEY_BYTES + 64u];
        static uint8_t sig[SSF_RSA_MAX_KEY_BYTES];
        uint8_t hash[32];
        const uint32_t nMag = (uint32_t)SSF_RSA_MAX_KEY_BYTES;
        uint32_t p = 4u;

        memset(hash, 0xA5, sizeof(hash));
        memset(sig, 0x01, sizeof(sig));
        sig[0] = 0x00u; /* s < n */

        /* Even modulus of exactly the maximum size; e = 65537. */
        _SSFRSAUTPutIntTLV(der, &p, nMag, 0xFFu, 0xFEu);
        _SSFRSAUTPutIntTLV(der, &p, 3u, 0x01u, 0x01u);
        _SSFRSAUTCloseSeq(der, p);
        SSF_ASSERT((size_t)p <= sizeof(der));

        SSF_ASSERT(SSFRSAPubKeyIsValid(der, (size_t)p) == false);
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSAVerifyPKCS1(der, (size_t)p, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                                     sig, (size_t)nMag) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSAVerifyPSS(der, (size_t)p, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                                   sizeof(hash), sig, (size_t)nMag) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
    }

    {
        /* Private key whose modulus is 16 bytes above the configured maximum (RSA-4). */
        static uint8_t der[(3u * (SSF_RSA_MAX_KEY_BYTES + 32u)) + (5u * (SSF_RSA_MAX_KEY_BYTES)) +
                           64u];
        static uint8_t sig[SSF_RSA_MAX_KEY_BYTES + 16u];
        uint8_t hash[32];
        const uint32_t nMag = (uint32_t)SSF_RSA_MAX_KEY_BYTES + 16u;
        const uint32_t hMag = nMag / 2u;
        size_t sigLen = 0u;
        uint32_t p = 4u;
        uint32_t i;

        memset(hash, 0xA5, sizeof(hash));

        der[p++] = 0x02u; der[p++] = 0x01u; der[p++] = 0x00u; /* version 0 */
        _SSFRSAUTPutIntTLV(der, &p, nMag, 0x7Fu, 0xFFu);     /* n (odd) */
        _SSFRSAUTPutIntTLV(der, &p, 3u, 0x01u, 0x01u);       /* e = 65537 */
        _SSFRSAUTPutIntTLV(der, &p, nMag, 0x01u, 0xFFu);     /* d (odd) */
        for (i = 0; i < 5u; i++) { _SSFRSAUTPutIntTLV(der, &p, hMag, 0x7Fu, 0xFFu); }
        _SSFRSAUTCloseSeq(der, p);
        SSF_ASSERT((size_t)p <= sizeof(der));

        SSF_ASSERT(SSFRSAPrivKeyIsValid(der, (size_t)p) == false);
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSASignPKCS1(der, (size_t)p, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                                   sig, sizeof(sig), &sigLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSASignPSS(der, (size_t)p, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                                 sig, sizeof(sig), &sigLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
    }
#endif /* (SSF_RSA_MAX_KEY_BYTES + 16u) <= SSF_BN_MAX_BYTES */

#if SSF_RSA_CONFIG_ENABLE_2048 == 1
    {
        /* Valid-looking 2048-bit n and e with p and q each a full 1024 bytes wide (RSA-3). */
        static uint8_t der[(3u * 300u) + (5u * 1040u) + 64u];
        uint32_t p = 4u;
        uint32_t i;

        der[p++] = 0x02u; der[p++] = 0x01u; der[p++] = 0x00u; /* version 0 */
        _SSFRSAUTPutIntTLV(der, &p, 256u, 0x80u, 0xFFu);     /* n: exactly 2048 bits, odd */
        _SSFRSAUTPutIntTLV(der, &p, 3u, 0x01u, 0x01u);       /* e = 65537 */
        _SSFRSAUTPutIntTLV(der, &p, 256u, 0x01u, 0xFFu);     /* d (odd) */
        for (i = 0; i < 5u; i++) { _SSFRSAUTPutIntTLV(der, &p, 1024u, 0x7Fu, 0xFFu); }
        _SSFRSAUTCloseSeq(der, p);
        SSF_ASSERT((size_t)p <= sizeof(der));

        SSF_ASSERT(SSFRSAPrivKeyIsValid(der, (size_t)p) == false);
    }
#endif /* SSF_RSA_CONFIG_ENABLE_2048 */

    /* ---- ssfbn enhancement: GCD ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

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
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);

        /* 3^(-1) mod 10 = 7: composite modulus, so ExtGCD rather than Fermat */
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
        /* Malformed DER is rejected */
        uint8_t badDer[] = { 0x30, 0x00 }; /* empty SEQUENCE */
        SSF_ASSERT(SSFRSAPubKeyIsValid(badDer, sizeof(badDer)) == false);

        /* Reject: well-formed DER but n is tiny (8-bit), far below any supported key size. */
        {
            static const uint8_t pubTinyN[] = {
                0x30u, 0x08u,
                0x02u, 0x01u, 0x03u,                      /* n = 3 */
                0x02u, 0x03u, 0x01u, 0x00u, 0x01u         /* e = 65537 */
            };
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubTinyN, sizeof(pubTinyN)) == false);
        }
    }

    /* ---- All key-consuming public APIs reject malformed DER on the decode boundary ---- */
    {
        static const uint8_t badDer[] = { 0x30u, 0x00u }; /* empty SEQUENCE -- parser bails */
        uint8_t hash[32];
        uint8_t sig[SSF_RSA_MAX_KEY_BYTES];
        size_t sigLen;

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));

        SSF_ASSERT(SSFRSAPrivKeyIsValid(badDer, sizeof(badDer)) == false);
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSASignPKCS1(badDer, sizeof(badDer), SSF_RSA_HASH_SHA256,
                                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSASignPSS(badDer, sizeof(badDer), SSF_RSA_HASH_SHA256,
                                 hash, sizeof(hash), sig, sizeof(sig), &sigLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS == 1 */
        /* Verify-side: decode bails before any sig byte is read, so sig contents don't matter */
        memset(sig, 0, 256);
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSAVerifyPKCS1(badDer, sizeof(badDer), SSF_RSA_HASH_SHA256,
                                     hash, sizeof(hash), sig, 256) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSAVerifyPSS(badDer, sizeof(badDer), SSF_RSA_HASH_SHA256,
                                   hash, sizeof(hash), sizeof(hash), sig, 256) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS == 1 */
    }

#if (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1)
    /* ---- Sign / Verify reject signature-length and buffer-size mismatches ---- */
    {
        uint8_t hash[32];
        uint8_t pubKeyDer[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        uint8_t privKeyDer[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        size_t pubKeyDerLen;
        size_t privKeyDerLen;
        uint8_t sig[SSF_RSA_MAX_KEY_BYTES];
        uint8_t sigFF[256];
        size_t sigLen;
        uint8_t tinyBuf[8];

        SSFSHA256((const uint8_t *)"sample", 6, hash, sizeof(hash));
        SSF_ASSERT(SSFRSAKeyGen(2048u,
                                privKeyDer, sizeof(privKeyDer), &privKeyDerLen,
                                pubKeyDer,  sizeof(pubKeyDer),  &pubKeyDerLen) == true);

        /* SignPKCS1 / SignPSS reject when the output buffer cannot hold a keyBytes-sized sig. */
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSASignPKCS1(privKeyDer, privKeyDerLen, SSF_RSA_HASH_SHA256,
                                   hash, sizeof(hash), tinyBuf, sizeof(tinyBuf), &sigLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSASignPSS(privKeyDer, privKeyDerLen, SSF_RSA_HASH_SHA256,
                                 hash, sizeof(hash), tinyBuf, sizeof(tinyBuf), &sigLen) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS == 1 */

        /* Produce one valid sig so we can mangle its length on the verify side. */
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSASignPKCS1(privKeyDer, privKeyDerLen, SSF_RSA_HASH_SHA256,
                                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);
#else
        SSF_ASSERT(SSFRSASignPSS(privKeyDer, privKeyDerLen, SSF_RSA_HASH_SHA256,
                                 hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1 */

        /* VerifyPKCS1 / VerifyPSS reject when sigLen != keyBytes (256 for RSA-2048). */
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256,
                                     hash, sizeof(hash), sig, sigLen - 1u) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSAVerifyPSS(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256,
                                   hash, sizeof(hash), sizeof(hash), sig, sigLen - 1u) == false);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS == 1 */

        /* An all-0xFF 256-byte sig exceeds any 2048-bit n, so _SSFRSAPublicOp rejects m >= n */
        memset(sigFF, 0xFFu, sizeof(sigFF));
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256,
                                     hash, sizeof(hash), sigFF, sizeof(sigFF)) == false);
#else
        SSF_ASSERT(SSFRSAVerifyPSS(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256,
                                   hash, sizeof(hash), sizeof(hash), sigFF, sizeof(sigFF)) ==
                   false);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1 */
    }
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN && SSF_RSA_CONFIG_ENABLE_2048 */

#if (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1) && \
    (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1)
    /* ---- (Hardening) RSA private op applies message + exponent blinding ---- */
    {
        _SSFRSABlindAudit_t audit;
        uint8_t hash[32];
        uint8_t privKeyDer[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        uint8_t pubKeyDer[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t privLen;
        size_t pubLen;
        uint8_t sig[SSF_RSA_MAX_KEY_BYTES];
        uint8_t sig2[SSF_RSA_MAX_KEY_BYTES];
        size_t sigLen;
        size_t sig2Len;
        int iter;

        SSFSHA256((const uint8_t *)"blind-me", 8, hash, sizeof(hash));
        SSF_ASSERT(SSFRSAKeyGen(2048u, privKeyDer, sizeof(privKeyDer), &privLen,
                                pubKeyDer, sizeof(pubKeyDer), &pubLen) == true);

        memset(&audit, 0, sizeof(audit));
        _SSFRSASignBlindTestHookCtx = &audit;
        _SSFRSASignBlindTestHook = _SSFRSABlindHook;
        SSF_ASSERT(SSFRSASignPKCS1(privKeyDer, privLen, SSF_RSA_HASH_SHA256,
                                   hash, sizeof(hash), sig, sizeof(sig), &sigLen) == true);
        _SSFRSASignBlindTestHook = NULL;
        _SSFRSASignBlindTestHookCtx = NULL;

        /* Blinding was engaged and internally consistent. */
        SSF_ASSERT(audit.fired == true);
        SSF_ASSERT(audit.rInRange == true);
        SSF_ASSERT(audit.rInvOk == true);
        SSF_ASSERT(audit.baseBlinded == true);
        SSF_ASSERT(audit.expBlindsNZ == true);

        /* Signature is valid, and repeated signing (fresh blinds each call) is correct + stable. */
        SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubLen, SSF_RSA_HASH_SHA256,
                                     hash, sizeof(hash), sig, sigLen) == true);
        for (iter = 0; iter < 8; iter++)
        {
            SSF_ASSERT(SSFRSASignPKCS1(privKeyDer, privLen, SSF_RSA_HASH_SHA256,
                                       hash, sizeof(hash), sig2, sizeof(sig2), &sig2Len) == true);
            SSF_ASSERT(sig2Len == sigLen);
            SSF_ASSERT(memcmp(sig, sig2, sigLen) == 0);
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubLen, SSF_RSA_HASH_SHA256,
                                         hash, sizeof(hash), sig2, sig2Len) == true);
        }
    }
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN && SSF_RSA_CONFIG_ENABLE_2048 && PKCS1_V15 */

    /* ---- FIPS 186-4 Sec. B.3.3 step 5.4: |p - q| > 2^(halfBits - 100) (anti-Fermat) ---- */
    {
        SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(q, SSF_BN_MAX_LIMBS);

        /* Reject: p and q identical except for low bits -- |p-q| < 2^(1024-100)=2^924. */
        SSFBNSetZero(&p, SSF_BN_MAX_LIMBS);
        SSFBNSetBit(&p, 1023u);
        SSFBNCopy(&q, &p);
        (void)SSFBNAddUint32(&q, &q, 5u);
        SSF_ASSERT(SSFRSAFipsPrimeDistanceOK(&p, &q, 1024u) == false);

        /* Accept: p and q differ by 2^925 -- well above the 2^924 threshold. */
        SSFBNSetZero(&p, SSF_BN_MAX_LIMBS);
        SSFBNSetBit(&p, 1023u);
        SSFBNCopy(&q, &p);
        SSFBNSetBit(&q, 925u);
        SSF_ASSERT(SSFRSAFipsPrimeDistanceOK(&p, &q, 1024u) == true);

        /* Accept regardless of argument order (symmetric in |p - q|). */
        SSF_ASSERT(SSFRSAFipsPrimeDistanceOK(&q, &p, 1024u) == true);
    }

    /* ---- FIPS 186-4 Sec. B.3.1: d > 2^(nlen/2) (anti-Wiener) ---- */
    {
        SSFBN_DEFINE(d, SSF_BN_MAX_LIMBS);

        /* Reject: d = 2^1023 has bitLen 1024 -- equal to halfBits, not strictly greater. */
        SSFBNSetZero(&d, SSF_BN_MAX_LIMBS);
        SSFBNSetBit(&d, 1023u);
        SSF_ASSERT(SSFRSAFipsDLowerBoundOK(&d, 1024u) == false);

        /* Reject: d = 1 -- bitLen 1, far below halfBits=1024. */
        SSFBNSetUint32(&d, 1u, SSF_BN_MAX_LIMBS);
        SSF_ASSERT(SSFRSAFipsDLowerBoundOK(&d, 1024u) == false);

        /* Accept: d = 2^1024 has bitLen 1025 -- strictly greater than halfBits. */
        SSFBNSetZero(&d, SSF_BN_MAX_LIMBS);
        SSFBNSetBit(&d, 1024u);
        SSF_ASSERT(SSFRSAFipsDLowerBoundOK(&d, 1024u) == true);

        /* Accept: typical CRT-derived d at near full key width. */
        SSFBNSetZero(&d, SSF_BN_MAX_LIMBS);
        SSFBNSetBit(&d, 2047u);
        SSF_ASSERT(SSFRSAFipsDLowerBoundOK(&d, 1024u) == true);
    }

    /* ---- gcd(e, p-1) == 1 && gcd(e, q-1) == 1 (d = e^(-1) mod lambda(n) exists) ---- */
    {
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(pm1, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(qm1, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&e, 65537u, SSF_BN_MAX_LIMBS);

        /* Accept: pm1=4, qm1=4 -- gcd with 65537 (prime) is 1. */
        SSFBNSetUint32(&pm1, 4u, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&qm1, 4u, SSF_BN_MAX_LIMBS);
        SSF_ASSERT(SSFRSAFipsECoprimeOK(&e, &pm1, &qm1) == true);

        /* Reject: pm1 = 65537 -- gcd(65537, 65537) = 65537. */
        SSFBNSetUint32(&pm1, 65537u, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&qm1, 4u, SSF_BN_MAX_LIMBS);
        SSF_ASSERT(SSFRSAFipsECoprimeOK(&e, &pm1, &qm1) == false);

        /* Reject: qm1 = 2*65537 -- qm1-side gcd is 65537. */
        SSFBNSetUint32(&pm1, 4u, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&qm1, 131074u, SSF_BN_MAX_LIMBS);
        SSF_ASSERT(SSFRSAFipsECoprimeOK(&e, &pm1, &qm1) == false);
    }

#if (SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1)
    /* ---- DER interop: openssl genrsa -traditional 2048 key, dgst -sha256 sig of msg ---- */
    {
        static const uint8_t foreignPriv[] = {
            0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00,
            0xdd, 0xf3, 0xf8, 0x95, 0x64, 0x87, 0x4f, 0x11, 0x92, 0x71, 0x64, 0x08,
            0x9d, 0x39, 0x54, 0x76, 0x00, 0x58, 0x64, 0x40, 0xe1, 0x02, 0x23, 0x88,
            0xa3, 0x30, 0x0b, 0xf9, 0x7f, 0x34, 0xe5, 0xf8, 0x31, 0x33, 0x05, 0xb6,
            0x88, 0x6d, 0x8d, 0x14, 0x2d, 0x77, 0x5a, 0x95, 0xd5, 0x67, 0x38, 0x85,
            0x3b, 0xaf, 0x46, 0x13, 0x96, 0x98, 0x58, 0x19, 0xf4, 0x27, 0xfb, 0x7a,
            0xf5, 0xb7, 0x5c, 0xec, 0x32, 0xae, 0xd7, 0x7c, 0x71, 0xe7, 0x86, 0x9e,
            0x1e, 0x00, 0xd4, 0x7c, 0xa8, 0xed, 0x6b, 0x3b, 0x3d, 0x59, 0x0f, 0xaf,
            0x44, 0xed, 0x82, 0x13, 0xd2, 0xd0, 0x5d, 0x68, 0x02, 0xea, 0x25, 0xc8,
            0xfe, 0xa2, 0x90, 0x38, 0x3e, 0x1e, 0xa5, 0x30, 0x6d, 0x9d, 0x81, 0x21,
            0xf2, 0x64, 0xf9, 0xe6, 0xe8, 0x9d, 0x24, 0x90, 0x1e, 0x56, 0x41, 0x5a,
            0xd2, 0x82, 0x35, 0xb4, 0xab, 0x53, 0x12, 0x08, 0x76, 0xcc, 0xe0, 0xc7,
            0xd5, 0xa0, 0x1a, 0xda, 0x81, 0x8f, 0x76, 0x7f, 0x51, 0x53, 0x24, 0x13,
            0x21, 0x82, 0x0b, 0xca, 0xa3, 0x79, 0x26, 0x43, 0x60, 0xb9, 0x55, 0xba,
            0xe1, 0xd6, 0x64, 0x92, 0x2c, 0xb4, 0x3e, 0xa7, 0x9d, 0x89, 0xaf, 0xc4,
            0xfa, 0x33, 0x87, 0xc0, 0xf0, 0x58, 0x26, 0x8d, 0x40, 0xab, 0x8d, 0xc5,
            0x52, 0xb0, 0xd5, 0x17, 0x14, 0x76, 0xaa, 0x10, 0x26, 0xb7, 0xca, 0x09,
            0x18, 0x2b, 0x4b, 0x4c, 0xfe, 0x52, 0xa3, 0x45, 0xcb, 0xde, 0x6a, 0x2e,
            0x21, 0x14, 0x44, 0x57, 0xfc, 0x7c, 0x30, 0x1f, 0x46, 0x08, 0x4e, 0x43,
            0xde, 0xa6, 0x89, 0x00, 0x02, 0xec, 0x80, 0xad, 0xff, 0x79, 0xf5, 0xf1,
            0x0f, 0xd2, 0x77, 0xe5, 0xbe, 0x7e, 0x71, 0xfd, 0xcc, 0x5c, 0x37, 0x9a,
            0xf0, 0xf5, 0xa1, 0x8e, 0x63, 0x5a, 0x60, 0x2e, 0x26, 0xf7, 0x5d, 0xd0,
            0x0a, 0xe2, 0xcc, 0x6f, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x82, 0x01,
            0x00, 0x34, 0x7d, 0x7d, 0x3d, 0x7f, 0x6f, 0xcc, 0x90, 0x40, 0x4c, 0xd6,
            0xb6, 0x7e, 0xd0, 0x4f, 0x1c, 0x35, 0x0a, 0xb2, 0x72, 0xf1, 0x83, 0xba,
            0xf9, 0x96, 0x76, 0x47, 0x6e, 0xb2, 0xd9, 0xc4, 0xc5, 0x44, 0x85, 0x67,
            0x85, 0x7a, 0x90, 0x45, 0xfc, 0x0e, 0xa0, 0x9a, 0x68, 0xb2, 0xf6, 0x5d,
            0x54, 0x8c, 0xff, 0xef, 0x97, 0xb4, 0x56, 0xc5, 0x07, 0x26, 0x49, 0xca,
            0x5c, 0x92, 0xfd, 0xd1, 0x58, 0xfe, 0xc7, 0x80, 0xa8, 0xaa, 0x9b, 0x71,
            0xa7, 0xb5, 0x3a, 0xc7, 0x05, 0xd0, 0x41, 0x8d, 0xc9, 0x8d, 0xc1, 0xa1,
            0x46, 0xf7, 0x0b, 0x20, 0x67, 0x25, 0xc5, 0x27, 0x41, 0xf0, 0xe6, 0x85,
            0x17, 0x1a, 0xb9, 0x41, 0x58, 0x3b, 0xc0, 0xad, 0x9a, 0x5d, 0x62, 0x11,
            0x67, 0x00, 0xd7, 0x46, 0x8e, 0x88, 0x56, 0x99, 0x8e, 0x07, 0xce, 0xa8,
            0x58, 0x1d, 0x4e, 0xb3, 0xfa, 0xcd, 0x45, 0xb1, 0x0e, 0xa4, 0x8c, 0x1c,
            0xb2, 0xc6, 0xe5, 0xa2, 0x55, 0xf7, 0x06, 0xa2, 0x81, 0xc5, 0x1a, 0x2d,
            0x05, 0xfb, 0x2a, 0x4f, 0x62, 0xa8, 0xef, 0xac, 0x4e, 0xf9, 0x53, 0x6c,
            0x98, 0x04, 0x34, 0xb8, 0x2c, 0xb2, 0x4b, 0xc9, 0xb1, 0x82, 0x33, 0xab,
            0xdf, 0xf4, 0xa3, 0xd2, 0x9c, 0xf7, 0x7c, 0x31, 0x88, 0x62, 0xb0, 0x39,
            0x90, 0x30, 0x1f, 0xe6, 0x3d, 0x08, 0xaa, 0x4b, 0x44, 0x23, 0xbf, 0x9d,
            0x06, 0xd3, 0xb7, 0x11, 0x52, 0xe8, 0x5f, 0x7e, 0xb1, 0xc8, 0x72, 0x01,
            0xbb, 0x83, 0x0f, 0xc8, 0x4b, 0x79, 0xf1, 0xe2, 0x4d, 0xc1, 0xd4, 0xad,
            0x54, 0x41, 0x14, 0x25, 0x01, 0x2f, 0x6b, 0xb3, 0xb6, 0xf9, 0x82, 0xb1,
            0x97, 0x53, 0x76, 0x7b, 0x92, 0xe7, 0xeb, 0x47, 0x4e, 0xac, 0x08, 0x61,
            0x0f, 0x66, 0x8d, 0x4d, 0xb4, 0x78, 0x99, 0x09, 0x5b, 0x54, 0x5f, 0x6c,
            0xfc, 0x7b, 0x76, 0x04, 0x51, 0x02, 0x81, 0x81, 0x00, 0xf7, 0xfc, 0xe0,
            0x30, 0x12, 0xf9, 0x9a, 0xd3, 0xa0, 0xfa, 0x53, 0xed, 0x6f, 0x0a, 0x70,
            0x3c, 0x21, 0x12, 0xaa, 0xa1, 0x9a, 0xc3, 0xc8, 0x5e, 0x6f, 0x66, 0x2d,
            0xdb, 0xe4, 0x9d, 0x3a, 0x5a, 0xa6, 0x33, 0x20, 0x7c, 0xbc, 0x10, 0x81,
            0xfc, 0xc5, 0x95, 0xa5, 0xaa, 0x25, 0xcd, 0x53, 0xff, 0x74, 0xaf, 0x3f,
            0x1d, 0x14, 0xd5, 0xaf, 0x7f, 0x3c, 0x2e, 0xec, 0x94, 0x78, 0x4a, 0x4c,
            0x6f, 0x66, 0x46, 0x47, 0xb9, 0x78, 0x64, 0x10, 0x24, 0x1d, 0x44, 0xeb,
            0x62, 0x53, 0x9f, 0x18, 0xde, 0x2d, 0x58, 0x16, 0xee, 0x7d, 0xcb, 0xf7,
            0x8a, 0x6b, 0x30, 0xb7, 0xc8, 0xa1, 0xad, 0x95, 0xa0, 0x82, 0x83, 0xc7,
            0xfc, 0xdb, 0x9a, 0x44, 0x92, 0x74, 0x01, 0xcb, 0xfe, 0x7c, 0xb2, 0xa0,
            0x51, 0xf4, 0xaa, 0x4b, 0x21, 0xb8, 0x5d, 0x24, 0x67, 0x3a, 0x2b, 0x5c,
            0x3b, 0xbc, 0xcb, 0xfd, 0x69, 0x02, 0x81, 0x81, 0x00, 0xe5, 0x1f, 0xc2,
            0x81, 0xaa, 0xc2, 0x7e, 0x2e, 0xfd, 0xd7, 0x53, 0xc0, 0x5a, 0x6e, 0x53,
            0x9b, 0xab, 0x37, 0xd2, 0xb7, 0x6c, 0x66, 0x97, 0x9c, 0x78, 0xa4, 0xc4,
            0xbe, 0x7c, 0x93, 0x42, 0x8a, 0x33, 0xe4, 0xd5, 0x12, 0xf2, 0xf6, 0x4b,
            0x9a, 0x0c, 0x49, 0x10, 0x2c, 0xec, 0x2f, 0x66, 0x46, 0x2c, 0xb3, 0x3f,
            0x5f, 0x39, 0x69, 0x56, 0x5e, 0x99, 0x0c, 0x08, 0x19, 0xc4, 0x66, 0x4f,
            0x32, 0x40, 0x81, 0x7b, 0x0f, 0xe2, 0xd9, 0xdc, 0x6e, 0x27, 0x82, 0x49,
            0x23, 0xc2, 0x91, 0x68, 0x89, 0x1d, 0xdb, 0x23, 0x49, 0xda, 0x61, 0x84,
            0x2e, 0x4d, 0xad, 0xc6, 0xb0, 0x7e, 0x51, 0x61, 0xd5, 0x4a, 0xfc, 0x70,
            0x16, 0xa4, 0x35, 0x92, 0xda, 0xb9, 0x4c, 0x37, 0x5d, 0xaf, 0x50, 0x0c,
            0xb9, 0xda, 0x9a, 0xa6, 0x1f, 0xa8, 0xe6, 0x4e, 0xf2, 0x8d, 0x26, 0x5d,
            0xa5, 0xce, 0x4d, 0xc8, 0x17, 0x02, 0x81, 0x81, 0x00, 0xc8, 0x5f, 0xe1,
            0x5d, 0xb6, 0xd7, 0x4c, 0x4c, 0xd7, 0x73, 0xad, 0x40, 0xda, 0x4a, 0x1a,
            0xe9, 0xda, 0xe7, 0x54, 0x4c, 0x03, 0xdb, 0x52, 0x19, 0x4b, 0xf5, 0xc9,
            0xf4, 0x35, 0x42, 0xfd, 0x95, 0xa5, 0x59, 0x06, 0x55, 0x03, 0x38, 0x6b,
            0x6f, 0xac, 0xce, 0xff, 0xee, 0xfd, 0x60, 0x6d, 0x10, 0xaa, 0x5d, 0xb7,
            0xa7, 0x6d, 0xe0, 0x43, 0x4f, 0x91, 0x77, 0x70, 0xdd, 0x7e, 0x5c, 0xba,
            0x6a, 0x00, 0xbf, 0xa4, 0xd0, 0xae, 0x00, 0x5c, 0x32, 0x72, 0x1b, 0xef,
            0xfd, 0xa1, 0x07, 0x9a, 0x76, 0x5b, 0x39, 0x24, 0x3e, 0x4c, 0x12, 0xf4,
            0xcf, 0x39, 0x51, 0x42, 0x0e, 0xb0, 0xe4, 0xab, 0x53, 0xe8, 0x61, 0x46,
            0xc4, 0x7f, 0x44, 0xa5, 0x47, 0x98, 0xc8, 0xa2, 0xe5, 0xdc, 0x28, 0x10,
            0xf6, 0x67, 0xb4, 0xf9, 0xc4, 0x23, 0x4d, 0xcf, 0x4e, 0x41, 0x68, 0x2b,
            0xbc, 0x71, 0x0e, 0x7a, 0x91, 0x02, 0x81, 0x80, 0x2a, 0xfa, 0x43, 0x1c,
            0xd9, 0x6f, 0xf4, 0x05, 0x52, 0x7e, 0x02, 0x6a, 0xb1, 0x4b, 0xc2, 0x89,
            0x0f, 0x9b, 0xbf, 0xfd, 0xc1, 0xea, 0x98, 0x83, 0xb4, 0x29, 0x8b, 0xf2,
            0x03, 0x22, 0x08, 0x38, 0x2e, 0x35, 0xbd, 0x35, 0xf9, 0xb6, 0xf3, 0x45,
            0x69, 0x0a, 0x87, 0x6b, 0x35, 0xbe, 0x4a, 0x5b, 0xdd, 0x64, 0x9d, 0xfd,
            0x79, 0xa2, 0x65, 0x9e, 0x06, 0xed, 0x37, 0xd3, 0xc5, 0x80, 0x3f, 0x58,
            0xb8, 0xba, 0xd0, 0xdf, 0x90, 0xf8, 0xb6, 0x9d, 0x3e, 0xf1, 0xf4, 0x50,
            0x2d, 0xdd, 0xe2, 0x92, 0xdd, 0xb3, 0xce, 0x31, 0xbb, 0x31, 0xd1, 0x7e,
            0x71, 0xf9, 0xa7, 0xac, 0x51, 0x75, 0x68, 0x79, 0x7e, 0xc0, 0x4d, 0x32,
            0x22, 0x09, 0x1e, 0x8b, 0xc2, 0x78, 0x26, 0x66, 0x7f, 0x4c, 0xef, 0xa6,
            0x28, 0xf8, 0x1b, 0x33, 0x13, 0x16, 0x68, 0x36, 0x9c, 0xfd, 0x56, 0x51,
            0x94, 0x9a, 0x08, 0x6f, 0x02, 0x81, 0x81, 0x00, 0xe6, 0x71, 0x1e, 0x34,
            0xa6, 0xda, 0x93, 0x04, 0x44, 0x4c, 0x09, 0xac, 0x03, 0x8c, 0xba, 0xe5,
            0x68, 0x3e, 0xf2, 0xca, 0xd1, 0xe5, 0x2c, 0xd9, 0x4d, 0xe5, 0x08, 0x43,
            0x33, 0x4b, 0x72, 0xcb, 0x21, 0x0d, 0xf0, 0x42, 0x1c, 0xd9, 0x92, 0x0e,
            0x72, 0x73, 0x26, 0x5c, 0x7c, 0x83, 0x81, 0x0b, 0xfc, 0x58, 0xa4, 0xaa,
            0x21, 0x4e, 0x80, 0xcc, 0x2f, 0x11, 0x65, 0x62, 0x46, 0xc6, 0x6c, 0x71,
            0x15, 0x3c, 0x82, 0x40, 0x90, 0xda, 0x85, 0x32, 0xbe, 0xb6, 0xc6, 0x3b,
            0x5f, 0x4b, 0x66, 0xd5, 0x7a, 0x38, 0x9a, 0x8e, 0xcd, 0xb3, 0x81, 0xf2,
            0x44, 0x62, 0x97, 0x2c, 0x2b, 0x83, 0x1c, 0xcb, 0x00, 0x99, 0x81, 0xf3,
            0x3d, 0x9b, 0xfe, 0xa8, 0xfc, 0x23, 0xb3, 0x87, 0x82, 0x5a, 0xb8, 0x6d,
            0xcd, 0x49, 0xb1, 0x5d, 0x12, 0x0e, 0x0b, 0xe1, 0xf0, 0x10, 0x9c, 0x2e,
            0x84, 0x9b, 0x7c, 0x8b
        };
        static const uint8_t foreignPub[] = {
            0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdd, 0xf3, 0xf8,
            0x95, 0x64, 0x87, 0x4f, 0x11, 0x92, 0x71, 0x64, 0x08, 0x9d, 0x39, 0x54,
            0x76, 0x00, 0x58, 0x64, 0x40, 0xe1, 0x02, 0x23, 0x88, 0xa3, 0x30, 0x0b,
            0xf9, 0x7f, 0x34, 0xe5, 0xf8, 0x31, 0x33, 0x05, 0xb6, 0x88, 0x6d, 0x8d,
            0x14, 0x2d, 0x77, 0x5a, 0x95, 0xd5, 0x67, 0x38, 0x85, 0x3b, 0xaf, 0x46,
            0x13, 0x96, 0x98, 0x58, 0x19, 0xf4, 0x27, 0xfb, 0x7a, 0xf5, 0xb7, 0x5c,
            0xec, 0x32, 0xae, 0xd7, 0x7c, 0x71, 0xe7, 0x86, 0x9e, 0x1e, 0x00, 0xd4,
            0x7c, 0xa8, 0xed, 0x6b, 0x3b, 0x3d, 0x59, 0x0f, 0xaf, 0x44, 0xed, 0x82,
            0x13, 0xd2, 0xd0, 0x5d, 0x68, 0x02, 0xea, 0x25, 0xc8, 0xfe, 0xa2, 0x90,
            0x38, 0x3e, 0x1e, 0xa5, 0x30, 0x6d, 0x9d, 0x81, 0x21, 0xf2, 0x64, 0xf9,
            0xe6, 0xe8, 0x9d, 0x24, 0x90, 0x1e, 0x56, 0x41, 0x5a, 0xd2, 0x82, 0x35,
            0xb4, 0xab, 0x53, 0x12, 0x08, 0x76, 0xcc, 0xe0, 0xc7, 0xd5, 0xa0, 0x1a,
            0xda, 0x81, 0x8f, 0x76, 0x7f, 0x51, 0x53, 0x24, 0x13, 0x21, 0x82, 0x0b,
            0xca, 0xa3, 0x79, 0x26, 0x43, 0x60, 0xb9, 0x55, 0xba, 0xe1, 0xd6, 0x64,
            0x92, 0x2c, 0xb4, 0x3e, 0xa7, 0x9d, 0x89, 0xaf, 0xc4, 0xfa, 0x33, 0x87,
            0xc0, 0xf0, 0x58, 0x26, 0x8d, 0x40, 0xab, 0x8d, 0xc5, 0x52, 0xb0, 0xd5,
            0x17, 0x14, 0x76, 0xaa, 0x10, 0x26, 0xb7, 0xca, 0x09, 0x18, 0x2b, 0x4b,
            0x4c, 0xfe, 0x52, 0xa3, 0x45, 0xcb, 0xde, 0x6a, 0x2e, 0x21, 0x14, 0x44,
            0x57, 0xfc, 0x7c, 0x30, 0x1f, 0x46, 0x08, 0x4e, 0x43, 0xde, 0xa6, 0x89,
            0x00, 0x02, 0xec, 0x80, 0xad, 0xff, 0x79, 0xf5, 0xf1, 0x0f, 0xd2, 0x77,
            0xe5, 0xbe, 0x7e, 0x71, 0xfd, 0xcc, 0x5c, 0x37, 0x9a, 0xf0, 0xf5, 0xa1,
            0x8e, 0x63, 0x5a, 0x60, 0x2e, 0x26, 0xf7, 0x5d, 0xd0, 0x0a, 0xe2, 0xcc,
            0x6f, 0x02, 0x03, 0x01, 0x00, 0x01
        };
        static const uint8_t foreignSig[] = {
            0x02, 0xae, 0x60, 0x29, 0xd3, 0x28, 0x7f, 0x79, 0xa9, 0xc0, 0xa8, 0x22,
            0x2c, 0x0c, 0x24, 0xaa, 0x04, 0x37, 0x59, 0xec, 0x7b, 0x5f, 0x01, 0x34,
            0xf3, 0xca, 0xd7, 0x1e, 0xf4, 0x9c, 0x67, 0x89, 0x6c, 0xff, 0x05, 0x41,
            0x4d, 0x30, 0xbe, 0x02, 0x77, 0xd1, 0x8a, 0xf1, 0x14, 0x35, 0x07, 0xdc,
            0xdb, 0x31, 0x7a, 0x88, 0xf5, 0x90, 0x54, 0x4a, 0x09, 0x84, 0x66, 0x50,
            0x82, 0x1c, 0x99, 0xd7, 0x92, 0x5e, 0x0d, 0x4d, 0x55, 0x27, 0x08, 0x7a,
            0x4b, 0x25, 0x36, 0xdc, 0x90, 0x07, 0x0e, 0xb6, 0x91, 0x1b, 0x27, 0x1e,
            0xe6, 0x3d, 0xe5, 0xcd, 0x39, 0x6a, 0x63, 0xa6, 0x32, 0x1a, 0x93, 0xc0,
            0x93, 0x4b, 0xfb, 0x69, 0xb6, 0xae, 0x23, 0xd3, 0xfb, 0x96, 0xb7, 0xd7,
            0xda, 0x63, 0x98, 0x65, 0x26, 0x0e, 0x04, 0x23, 0x1c, 0x5a, 0xd7, 0x28,
            0xe3, 0xb5, 0x64, 0x6e, 0x99, 0x22, 0x9e, 0x9f, 0xf9, 0x5a, 0x21, 0x1c,
            0x13, 0x5e, 0x78, 0x3b, 0x7d, 0x03, 0xd0, 0xb7, 0xba, 0x69, 0x86, 0x14,
            0x8c, 0xbd, 0x84, 0x5b, 0xcc, 0x61, 0x7e, 0xe4, 0xf4, 0x11, 0x47, 0xc5,
            0x7e, 0x70, 0x42, 0x24, 0xec, 0xf5, 0xc1, 0xbf, 0x76, 0x01, 0xec, 0x35,
            0x17, 0xf0, 0x68, 0x15, 0xcd, 0xf6, 0x76, 0xcd, 0xbc, 0xed, 0xf6, 0xf9,
            0xcb, 0x75, 0xd4, 0x98, 0x74, 0x19, 0x69, 0x7c, 0x99, 0xcc, 0x51, 0xb7,
            0x35, 0x66, 0x2d, 0x63, 0xf8, 0xe8, 0xa6, 0x47, 0x83, 0xa3, 0x81, 0xc3,
            0x3b, 0x05, 0xa3, 0xc2, 0xca, 0x6c, 0xf1, 0x9f, 0x4c, 0xca, 0x04, 0xd7,
            0x7f, 0x65, 0x57, 0xf1, 0x0f, 0x99, 0x1c, 0x7f, 0xcc, 0x0a, 0x9c, 0x57,
            0x35, 0x70, 0xf0, 0xec, 0xa3, 0x49, 0xd8, 0x02, 0xfb, 0x29, 0x4b, 0x38,
            0x60, 0xf0, 0x6e, 0x8f, 0x9d, 0x8d, 0x0b, 0x91, 0x23, 0xc7, 0x49, 0xce,
            0xd1, 0x40, 0x6f, 0x2f
        };
        uint8_t hashVal[32];
        uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
        size_t sigLen;

        /* Public-key validity check on a foreign-format DER must succeed. */
        SSF_ASSERT(SSFRSAPubKeyIsValid(foreignPub, sizeof(foreignPub)) == true);

        /* Verify the openssl PKCS#1 v1.5 signature with the foreign-format public key. */
        SSFSHA256((const uint8_t *)"interop test", 12, hashVal, sizeof(hashVal));
        SSF_ASSERT(SSFRSAVerifyPKCS1(foreignPub, sizeof(foreignPub),
                   SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                   foreignSig, sizeof(foreignSig)) == true);

        /* Sign with the foreign private key: deterministic, so it must match openssl's sig. */
        /* SAFE-05: a successful sign scrubs once, at the sign size.                          */
        _StackScrubReset();
        _SSFRSAStackScrubTestHook = _StackScrubCheck;
        SSF_ASSERT(SSFRSASignPKCS1(foreignPriv, sizeof(foreignPriv),
                   SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                   sig, sizeof(sig), &sigLen) == true);
        _SSFRSAStackScrubTestHook = NULL;
        SSF_ASSERT(_stackScrubCalls == 1u);
        SSF_ASSERT(_stackScrubLen == SSF_RSA_SIGN_STACK_SCRUB_BYTES);
        SSF_ASSERT(_stackScrubDirty == 0u);
        SSF_ASSERT(sigLen == sizeof(foreignSig));
        SSF_ASSERT(memcmp(sig, foreignSig, sigLen) == 0);
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        _StackScrubReset();
        _SSFRSAStackScrubTestHook = _StackScrubCheck;
        SSF_ASSERT(SSFRSASignPSS(foreignPriv, sizeof(foreignPriv),
                   SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                   sig, sizeof(sig), &sigLen) == true);
        _SSFRSAStackScrubTestHook = NULL;
        SSF_ASSERT(_stackScrubCalls == 1u);
        SSF_ASSERT(_stackScrubLen == SSF_RSA_SIGN_STACK_SCRUB_BYTES);
        SSF_ASSERT(_stackScrubDirty == 0u);
        SSF_ASSERT(SSFRSAVerifyPSS(foreignPub, sizeof(foreignPub), SSF_RSA_HASH_SHA256,
                   hashVal, sizeof(hashVal), sizeof(hashVal), sig, sigLen) == true);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS == 1 */

        /* ---- SAFE-06: an even p or q (or q = 0) makes signing return false, not assert ---- */
        {
            static uint8_t bad[sizeof(foreignPriv)];
            size_t badLen;
            uint8_t c;

            /* Cases: 0 = p + 1 (even), 1 = q + 1 (even), 2 = p and q + 1, 3 = q = 0 */
            for (c = 0u; c < 4u; c++)
            {
                if (c < 3u)
                {
                    memcpy(bad, foreignPriv, sizeof(bad));
                    badLen = sizeof(bad);
                    if (c != 1u) _SSFRSAUTBumpInt(bad, badLen, 4u);
                    if (c != 0u) _SSFRSAUTBumpInt(bad, badLen, 5u);
                }
                else
                {
                    badLen = _SSFRSAUTZeroInt(foreignPriv, sizeof(foreignPriv), 5u, bad,
                                              sizeof(bad));
                    SSF_ASSERT(badLen < sizeof(foreignPriv));
                }
                sigLen = 0u;
                SSF_ASSERT(SSFRSASignPKCS1(bad, badLen, SSF_RSA_HASH_SHA256, hashVal,
                           sizeof(hashVal), sig, sizeof(sig), &sigLen) == false);
                SSF_ASSERT(sigLen == 0u);
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
                SSF_ASSERT(SSFRSASignPSS(bad, badLen, SSF_RSA_HASH_SHA256, hashVal,
                           sizeof(hashVal), sig, sizeof(sig), &sigLen) == false);
                SSF_ASSERT(sigLen == 0u);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS == 1 */
                SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, badLen) == false);
            }

            /* The rebuilt-DER helper is a faithful copy when it replaces an INTEGER already 0 */
            badLen = _SSFRSAUTZeroInt(foreignPriv, sizeof(foreignPriv), 0u, bad, sizeof(bad));
            SSF_ASSERT(badLen == sizeof(foreignPriv));
            SSF_ASSERT(memcmp(bad, foreignPriv, badLen) == 0);
            SSF_ASSERT(SSFRSASignPKCS1(bad, badLen, SSF_RSA_HASH_SHA256, hashVal,
                       sizeof(hashVal), sig, sizeof(sig), &sigLen) == true);
        }

        /* ---- Stricter SSFRSAPubKeyIsValid: small public exponent (e = 3) ---- */
        {
            uint8_t pubE3[sizeof(foreignPub) - 2u];
            memcpy(pubE3, foreignPub, sizeof(foreignPub) - 5u);
            SSF_ASSERT(pubE3[1] == 0x82u);
            SSF_ASSERT(pubE3[2] == 0x01u);
            SSF_ASSERT(pubE3[3] == 0x0au);
            pubE3[3] = 0x08u; /* new length 264 = 266 - 2 */
            pubE3[(sizeof(foreignPub) - 5u) + 0u] = 0x02u; /* INTEGER tag */
            pubE3[(sizeof(foreignPub) - 5u) + 1u] = 0x01u; /* length 1 */
            pubE3[(sizeof(foreignPub) - 5u) + 2u] = 0x03u; /* e = 3 */
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubE3, sizeof(pubE3)) == false);
        }

        /* ---- SSFRSAPrivKeyIsValid: positive case (foreign-format key) ---- */
        SSF_ASSERT(SSFRSAPrivKeyIsValid(foreignPriv, sizeof(foreignPriv)) == true);

        /* ---- AUDIT RSA-12: IsValid wipes private fields and checks e * dp, e * dq == 1 ---- */
        {
            uint8_t bad[sizeof(foreignPriv)];

            _scrubCalls = 0u;
            _scrubDirty = 0u;
            _SSFRSAScrubTestHook = _ScrubCheck;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(foreignPriv, sizeof(foreignPriv)) == true);
            SSF_ASSERT(_scrubCalls == 11u);
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[100] ^= 0x01u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, sizeof(bad)) == false);
            SSF_ASSERT(_scrubCalls == 22u);
            _SSFRSAScrubTestHook = NULL;
            SSF_ASSERT(_scrubDirty == 0u);

            memcpy(bad, foreignPriv, sizeof(bad));
            _SSFRSAUTBumpInt(bad, sizeof(bad), 3u);
            _SSFRSAUTBumpInt(bad, sizeof(bad), 6u);
            _SSFRSAUTBumpInt(bad, sizeof(bad), 7u);
            SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, sizeof(bad)) == false);
        }

        /* ---- SSFRSAPrivKeyIsValid: tampered components must reject ---- */
        {
            /* Flip a byte inside n's magnitude (offsets 12..267); afterwards n != p*q. */
            uint8_t bad[sizeof(foreignPriv)];
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[100] ^= 0x01u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, sizeof(bad)) == false);
        }
        {
            /* Flip a byte inside dp's magnitude (~801..928); afterwards dp != d mod (p-1). */
            uint8_t bad[sizeof(foreignPriv)];
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[805] ^= 0x01u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, sizeof(bad)) == false);
        }
        {
            /* Flip the trailing byte (last byte of qInv). After tampering, qInv*q mod p != 1. */
            uint8_t bad[sizeof(foreignPriv)];
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[sizeof(bad) - 1u] ^= 0x01u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, sizeof(bad)) == false);
        }

        /* ---- Sign-time fault detection: verify-after-sign ---- */
        {
            uint8_t bad[sizeof(foreignPriv)];
            uint8_t hashFault[32];
            uint8_t sigFault[SSF_RSA_MAX_SIG_SIZE];
            size_t sigFaultLen;
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[805] ^= 0x01u; /* corrupt dp */
            SSFSHA256((const uint8_t *)"fault test", 10, hashFault, sizeof(hashFault));
            SSF_ASSERT(SSFRSASignPKCS1(bad, sizeof(bad),
                       SSF_RSA_HASH_SHA256, hashFault, sizeof(hashFault),
                       sigFault, sizeof(sigFault), &sigFaultLen) == false);
        }

#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        /* ---- PSS saltLength is caller-specified: OpenSSL vector signed with saltLength 20 ---- */
        {
            SSF_ASSERT(SSFRSAVerifyPSS(_pssSalt20Pub, sizeof(_pssSalt20Pub), SSF_RSA_HASH_SHA256,
                                       _pssSalt20Hash, sizeof(_pssSalt20Hash), 20u,
                                       _pssSalt20Sig, sizeof(_pssSalt20Sig)) == true);
            /* The hash-length salt SSF itself emits is not this signature's salt */
            SSF_ASSERT(SSFRSAVerifyPSS(_pssSalt20Pub, sizeof(_pssSalt20Pub), SSF_RSA_HASH_SHA256,
                                       _pssSalt20Hash, sizeof(_pssSalt20Hash), 32u,
                                       _pssSalt20Sig, sizeof(_pssSalt20Sig)) == false);
            SSF_ASSERT(SSFRSAVerifyPSS(_pssSalt20Pub, sizeof(_pssSalt20Pub), SSF_RSA_HASH_SHA256,
                                       _pssSalt20Hash, sizeof(_pssSalt20Hash), 19u,
                                       _pssSalt20Sig, sizeof(_pssSalt20Sig)) == false);
            SSF_ASSERT(SSFRSAVerifyPSS(_pssSalt20Pub, sizeof(_pssSalt20Pub), SSF_RSA_HASH_SHA256,
                                       _pssSalt20Hash, sizeof(_pssSalt20Hash), 0u,
                                       _pssSalt20Sig, sizeof(_pssSalt20Sig)) == false);
        }
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */

#if SSF_RSA_OSSL_VERIFY == 1
        /* OpenSSL cross-check (PKCS#1 v1.5 byte match, PSS both ways, all hash sizes). */
        _SSFRSAVerifyAgainstOpenSSL(foreignPriv, sizeof(foreignPriv),
                                    foreignPub,  sizeof(foreignPub));
#endif

        /* ---- AUDIT RSA-7: key decoders reject bytes after e / qInv and after the SEQUENCE ---- */
        {
            static uint8_t pubX[sizeof(foreignPub) + 3u];
            static uint8_t privX[sizeof(foreignPriv) + 3u];
            uint16_t seqLen;

            /* Trailing byte after the public-key SEQUENCE. */
            memcpy(pubX, foreignPub, sizeof(foreignPub));
            pubX[sizeof(foreignPub)] = 0x00u;
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubX, sizeof(foreignPub) + 1u) == false);
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubX, sizeof(foreignPub) + 1u, SSF_RSA_HASH_SHA256,
                                         hashVal, sizeof(hashVal), foreignSig,
                                         sizeof(foreignSig)) == false);

            /* Extra INTEGER inside the public-key SEQUENCE after e. */
            seqLen = (uint16_t)(((uint16_t)foreignPub[2] << 8) | foreignPub[3]);
            seqLen = (uint16_t)(seqLen + 3u);
            pubX[2] = (uint8_t)(seqLen >> 8);
            pubX[3] = (uint8_t)(seqLen & 0xFFu);
            pubX[sizeof(foreignPub)] = 0x02u;
            pubX[sizeof(foreignPub) + 1u] = 0x01u;
            pubX[sizeof(foreignPub) + 2u] = 0x00u;
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubX, sizeof(pubX)) == false);
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubX, sizeof(pubX), SSF_RSA_HASH_SHA256, hashVal,
                                         sizeof(hashVal), foreignSig,
                                         sizeof(foreignSig)) == false);

            /* Trailing byte after the private-key SEQUENCE. */
            memcpy(privX, foreignPriv, sizeof(foreignPriv));
            privX[sizeof(foreignPriv)] = 0x00u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(privX, sizeof(foreignPriv) + 1u) == false);
            SSF_ASSERT(SSFRSASignPKCS1(privX, sizeof(foreignPriv) + 1u, SSF_RSA_HASH_SHA256,
                                       hashVal, sizeof(hashVal), sig, sizeof(sig),
                                       &sigLen) == false);

            /* Extra INTEGER inside the private-key SEQUENCE after qInv. */
            seqLen = (uint16_t)(((uint16_t)foreignPriv[2] << 8) | foreignPriv[3]);
            seqLen = (uint16_t)(seqLen + 3u);
            privX[2] = (uint8_t)(seqLen >> 8);
            privX[3] = (uint8_t)(seqLen & 0xFFu);
            privX[sizeof(foreignPriv)] = 0x02u;
            privX[sizeof(foreignPriv) + 1u] = 0x01u;
            privX[sizeof(foreignPriv) + 2u] = 0x00u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(privX, sizeof(privX)) == false);
            SSF_ASSERT(SSFRSASignPKCS1(privX, sizeof(privX), SSF_RSA_HASH_SHA256, hashVal,
                                       sizeof(hashVal), sig, sizeof(sig), &sigLen) == false);
        }

        /* ---- AUDIT ASN1-3: negative or padded modulus is refused, not read as magnitude ---- */
        {
            static uint8_t pubNeg[sizeof(foreignPub) - 1u];
            static uint8_t pubPad[sizeof(foreignPub) + 1u];
            const uint32_t eAt = 9u + 256u;

            SSF_ASSERT((foreignPub[4] == 0x02u) && (foreignPub[5] == 0x82u));
            SSF_ASSERT((foreignPub[6] == 0x01u) && (foreignPub[7] == 0x01u));
            SSF_ASSERT((foreignPub[8] == 0x00u) && ((foreignPub[9] & 0x80u) != 0u));

            /* foreignPub is 30 82 01 0A 02 82 01 01 00 <n> <e>; drop the 0x00 sign byte */
            memcpy(pubNeg, foreignPub, 8u);
            pubNeg[3] = (uint8_t)(foreignPub[3] - 1u);
            pubNeg[7] = 0x00u;
            memcpy(&pubNeg[8], &foreignPub[9], sizeof(foreignPub) - 9u);
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubNeg, sizeof(pubNeg)) == false);

            /* Add a second 0x00 before n (padded INTEGER) */
            memcpy(pubPad, foreignPub, 9u);
            pubPad[3] = (uint8_t)(foreignPub[3] + 1u);
            pubPad[7] = 0x02u;
            pubPad[9] = 0x00u;
            memcpy(&pubPad[10], &foreignPub[9], sizeof(foreignPub) - 9u);
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubPad, sizeof(pubPad)) == false);
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubPad, sizeof(pubPad), SSF_RSA_HASH_SHA256, hashVal,
                                         sizeof(hashVal), foreignSig,
                                         sizeof(foreignSig)) == false);
            SSF_ASSERT(foreignPub[eAt] == 0x02u);
        }
    }
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 && SSF_RSA_CONFIG_ENABLE_2048 */

#if (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1)
    /* ---- RSA-2048 key generation + PKCS#1 v1.5 sign + verify roundtrip ---- */
    {
        uint8_t privKeyDer[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        size_t privKeyDerLen;
        uint8_t pubKeyDer[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t pubKeyDerLen;

        /* Pre-fill the stack with a sentinel so secrets left in keygen's frame can be found. */
        _SSFRSAUTPolluteStack(0xCCu);

        /* Generate 2048-bit key pair */
        SSF_ASSERT(SSFRSAKeyGen(2048,
                   privKeyDer, sizeof(privKeyDer), &privKeyDerLen,
                   pubKeyDer, sizeof(pubKeyDer), &pubKeyDerLen) == true);
        SSF_ASSERT(privKeyDerLen > 0u);
        SSF_ASSERT(pubKeyDerLen > 0u);

        /* Hygiene: top 16 bytes of p (= top of pm1), byte-reversed as in limbs, must be gone. */
        {
            const uint8_t *pTop = _SSFRSAUTLocatePMag(privKeyDer, privKeyDerLen);
            uint8_t needle[16];
            size_t i;
            SSF_ASSERT(pTop != NULL);
            for (i = 0u; i < sizeof(needle); i++) needle[i] = pTop[15u - i];
            SSF_ASSERT(_SSFRSAUTScanStack(needle, sizeof(needle)) == 0);
        }

        /* Validate the generated keys (FIPS post-conditions and CRT consistency). */
        SSF_ASSERT(SSFRSAPubKeyIsValid(pubKeyDer, pubKeyDerLen) == true);
        SSF_ASSERT(SSFRSAPrivKeyIsValid(privKeyDer, privKeyDerLen) == true);

        /* RSAPublicKey n must lead with a 0x00 sign byte (bit 2047 set; X.690 Sec. 8.3.2). */
        {
            /* Outer SEQUENCE: tag 0x30, long-form length (0x82, 2 length bytes). */
            SSF_ASSERT(pubKeyDer[0] == 0x30u);
            SSF_ASSERT(pubKeyDer[1] == 0x82u);
            /* INTEGER n at offset 4: tag 0x02, long-form length 0x82 0x01 0x01 (= 257). */
            SSF_ASSERT(pubKeyDer[4] == 0x02u);
            SSF_ASSERT(pubKeyDer[5] == 0x82u);
            SSF_ASSERT(pubKeyDer[6] == 0x01u);
            SSF_ASSERT(pubKeyDer[7] == 0x01u);
            /* The leading sign byte is 0x00; the next byte (start of magnitude) has bit 7 set. */
            SSF_ASSERT(pubKeyDer[8] == 0x00u);
            SSF_ASSERT((pubKeyDer[9] & 0x80u) != 0u);
        }

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
            SSF_ASSERT(sigLen == 256u);

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
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal), sizeof(hashVal),
                       sig, sigLen) == true);

            /* Wrong hash fails */
            hashVal[0] ^= 0x01u;
            SSF_ASSERT(SSFRSAVerifyPSS(pubKeyDer, pubKeyDerLen,
                       SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal), sizeof(hashVal),
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
                           SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal), sizeof(hashVal),
                           sig2, sig2Len) == true);
                /* But should be different (with overwhelming probability) */
                SSF_ASSERT(memcmp(sig, sig2, sigLen) != 0);
            }
        }
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
    }
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN && SSF_RSA_CONFIG_ENABLE_2048 */

    /* ---- Design-by-Contract: precondition violations must trigger SSFPortAssert ---- */
    {
        /* Reusable valid SSFBN. Length 64 limbs (2048 bits) is a representative working width.*/
        SSFBN_DEFINE(bn, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&bn, 5u, 64u);

        /* SSFBN_t with NULL limbs: only the explicit ->limbs != NULL REQUIRE should trip. */
        SSFBN_t bnNullLimbs;
        bnNullLimbs.limbs = NULL;
        bnNullLimbs.len = 64u;
        bnNullLimbs.cap = 0u;

        static uint8_t dbcDerBuf[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t dbcPubBuf[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        static uint8_t dbcSigBuf[SSF_RSA_MAX_SIG_SIZE];
        uint8_t dbcHashBuf[64];
        size_t dbcLenA;
        size_t dbcLenB;
        memset(dbcHashBuf, 0, sizeof(dbcHashBuf));

        /* ---- SSFRSAFipsPrimeDistanceOK ---- */
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(NULL, &bn, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bn, NULL, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bnNullLimbs, &bn, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bn, &bnNullLimbs, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bn, &bn, 100u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bn, &bn, 0u));

        /* ---- SSFRSAFipsDLowerBoundOK ---- */
        SSF_ASSERT_TEST(SSFRSAFipsDLowerBoundOK(NULL, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsDLowerBoundOK(&bnNullLimbs, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsDLowerBoundOK(&bn, 0u));

        /* ---- SSFRSAFipsECoprimeOK ---- */
        SSF_ASSERT_TEST(SSFRSAFipsECoprimeOK(NULL, &bn, &bn));
        SSF_ASSERT_TEST(SSFRSAFipsECoprimeOK(&bn, NULL, &bn));
        SSF_ASSERT_TEST(SSFRSAFipsECoprimeOK(&bn, &bn, NULL));
        SSF_ASSERT_TEST(SSFRSAFipsECoprimeOK(&bnNullLimbs, &bn, &bn));
        SSF_ASSERT_TEST(SSFRSAFipsECoprimeOK(&bn, &bnNullLimbs, &bn));
        SSF_ASSERT_TEST(SSFRSAFipsECoprimeOK(&bn, &bn, &bnNullLimbs));

        /* ---- SSFRSAPubKeyIsValid ---- */
        SSF_ASSERT_TEST(SSFRSAPubKeyIsValid(NULL, 16u));
        SSF_ASSERT_TEST(SSFRSAPubKeyIsValid(dbcPubBuf, 0u));

        /* ---- SSFRSAPrivKeyIsValid ---- */
        SSF_ASSERT_TEST(SSFRSAPrivKeyIsValid(NULL, 16u));
        SSF_ASSERT_TEST(SSFRSAPrivKeyIsValid(dbcDerBuf, 0u));

#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
        /* Use the smallest enabled size so the bits check does not mask the tested REQUIRE. */
#if SSF_RSA_CONFIG_ENABLE_2048 == 1
#define _SSFRSA_UT_DBC_BITS 2048u
#elif SSF_RSA_CONFIG_ENABLE_3072 == 1
#define _SSFRSA_UT_DBC_BITS 3072u
#else
#define _SSFRSA_UT_DBC_BITS 4096u
#endif
        /* ---- SSFRSAKeyGen ---- */
        SSF_ASSERT_TEST(SSFRSAKeyGen(_SSFRSA_UT_DBC_BITS, NULL, sizeof(dbcDerBuf), &dbcLenA,
                                     dbcPubBuf, sizeof(dbcPubBuf), &dbcLenB));
        SSF_ASSERT_TEST(SSFRSAKeyGen(_SSFRSA_UT_DBC_BITS, dbcDerBuf, sizeof(dbcDerBuf), NULL,
                                     dbcPubBuf, sizeof(dbcPubBuf), &dbcLenB));
        SSF_ASSERT_TEST(SSFRSAKeyGen(_SSFRSA_UT_DBC_BITS, dbcDerBuf, sizeof(dbcDerBuf), &dbcLenA,
                                     NULL, sizeof(dbcPubBuf), &dbcLenB));
        SSF_ASSERT_TEST(SSFRSAKeyGen(_SSFRSA_UT_DBC_BITS, dbcDerBuf, sizeof(dbcDerBuf), &dbcLenA,
                                     dbcPubBuf, sizeof(dbcPubBuf), NULL));
        SSF_ASSERT_TEST(SSFRSAKeyGen(1024u, dbcDerBuf, sizeof(dbcDerBuf), &dbcLenA,
                                     dbcPubBuf, sizeof(dbcPubBuf), &dbcLenB));
        SSF_ASSERT_TEST(SSFRSAKeyGen(5120u, dbcDerBuf, sizeof(dbcDerBuf), &dbcLenA,
                                     dbcPubBuf, sizeof(dbcPubBuf), &dbcLenB));
        /* Output-buffer size is documented as >= SSF_RSA_MAX_*_DER_SIZE; must be a precondition.*/
        SSF_ASSERT_TEST(SSFRSAKeyGen(_SSFRSA_UT_DBC_BITS, dbcDerBuf,
                                     SSF_RSA_MAX_PRIV_KEY_DER_SIZE - 1u,
                                     &dbcLenA, dbcPubBuf, sizeof(dbcPubBuf), &dbcLenB));
        SSF_ASSERT_TEST(SSFRSAKeyGen(_SSFRSA_UT_DBC_BITS, dbcDerBuf, sizeof(dbcDerBuf), &dbcLenA,
                                     dbcPubBuf, SSF_RSA_MAX_PUB_KEY_DER_SIZE - 1u, &dbcLenB));
#undef _SSFRSA_UT_DBC_BITS
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        /* ---- SSFRSASignPKCS1 ---- */
        SSF_ASSERT_TEST(SSFRSASignPKCS1(NULL, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                        dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPKCS1(dbcDerBuf, 16u, SSF_RSA_HASH_SHA256, NULL, 32u,
                                        dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPKCS1(dbcDerBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                        NULL, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPKCS1(dbcDerBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                        dbcSigBuf, sizeof(dbcSigBuf), NULL));
        SSF_ASSERT_TEST(SSFRSASignPKCS1(dbcDerBuf, 0u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                        dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPKCS1(dbcDerBuf, 16u, SSF_RSA_HASH_MIN, dbcHashBuf, 32u,
                                        dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPKCS1(dbcDerBuf, 16u, SSF_RSA_HASH_MAX, dbcHashBuf, 32u,
                                        dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPKCS1(dbcDerBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 31u,
                                        dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));

        /* ---- SSFRSAVerifyPKCS1 ---- */
        SSF_ASSERT_TEST(SSFRSAVerifyPKCS1(NULL, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                          dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPKCS1(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, NULL, 32u,
                                          dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPKCS1(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                          NULL, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPKCS1(dbcPubBuf, 0u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                          dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPKCS1(dbcPubBuf, 16u, SSF_RSA_HASH_MIN, dbcHashBuf, 32u,
                                          dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPKCS1(dbcPubBuf, 16u, SSF_RSA_HASH_MAX, dbcHashBuf, 32u,
                                          dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPKCS1(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 31u,
                                          dbcSigBuf, 256u));
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */

#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        /* ---- SSFRSASignPSS ---- */
        SSF_ASSERT_TEST(SSFRSASignPSS(NULL, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                      dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPSS(dbcDerBuf, 16u, SSF_RSA_HASH_SHA256, NULL, 32u,
                                      dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPSS(dbcDerBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                      NULL, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPSS(dbcDerBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                      dbcSigBuf, sizeof(dbcSigBuf), NULL));
        SSF_ASSERT_TEST(SSFRSASignPSS(dbcDerBuf, 0u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                      dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPSS(dbcDerBuf, 16u, SSF_RSA_HASH_MIN, dbcHashBuf, 32u,
                                      dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPSS(dbcDerBuf, 16u, SSF_RSA_HASH_MAX, dbcHashBuf, 32u,
                                      dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));
        SSF_ASSERT_TEST(SSFRSASignPSS(dbcDerBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 31u,
                                      dbcSigBuf, sizeof(dbcSigBuf), &dbcLenA));

        /* ---- SSFRSAVerifyPSS ---- */
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(NULL, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, NULL, 32u, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u, 32u,
                                        NULL, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 0u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_MIN, dbcHashBuf, 32u, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_MAX, dbcHashBuf, 32u, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 31u, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u, 33u,
                                        dbcSigBuf, 256u));
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
    }

#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
    /* ---- OPTIMIZE RSA-STK: every enabled key size runs end to end without OpenSSL ---- */
    {
        static const uint16_t sizes[] = {
#if SSF_RSA_CONFIG_ENABLE_2048 == 1
            2048u,
#endif
#if SSF_RSA_CONFIG_ENABLE_3072 == 1
            3072u,
#endif
#if SSF_RSA_CONFIG_ENABLE_4096 == 1
            4096u,
#endif
        };
        static uint8_t privKeyDer[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t pubKeyDer[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        uint8_t hash[32];
        uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
        size_t privKeyDerLen;
        size_t pubKeyDerLen;
        size_t sigLen;
        uint16_t si;

        SSFSHA256((const uint8_t *)"every size", 10, hash, sizeof(hash));
        for (si = 0u; si < (uint16_t)(sizeof(sizes) / sizeof(sizes[0])); si++)
        {
            SSF_ASSERT(SSFRSAKeyGen(sizes[si], privKeyDer, sizeof(privKeyDer), &privKeyDerLen,
                                    pubKeyDer, sizeof(pubKeyDer), &pubKeyDerLen) == true);
            SSF_ASSERT(SSFRSAPrivKeyIsValid(privKeyDer, privKeyDerLen) == true);
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubKeyDer, pubKeyDerLen) == true);
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
            SSF_ASSERT(SSFRSASignPKCS1(privKeyDer, privKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                       sizeof(hash), sig, sizeof(sig), &sigLen) == true);
            SSF_ASSERT(sigLen == ((size_t)sizes[si] / 8u));
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                         sizeof(hash), sig, sigLen) == true);
            hash[0] ^= 1u;
            SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                         sizeof(hash), sig, sigLen) == false);
            hash[0] ^= 1u;
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
            SSF_ASSERT(SSFRSASignPSS(privKeyDer, privKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                     sizeof(hash), sig, sizeof(sig), &sigLen) == true);
            SSF_ASSERT(SSFRSAVerifyPSS(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                       sizeof(hash), sizeof(hash), sig, sigLen) == true);
            hash[0] ^= 1u;
            SSF_ASSERT(SSFRSAVerifyPSS(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                       sizeof(hash), sizeof(hash), sig, sigLen) == false);
            hash[0] ^= 1u;
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
        }
    }
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

#if (SSF_CONFIG_BN_UNIT_TEST == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1) && \
    (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1)
    /* ---- OPTIMIZE BN-O4 / BN-O5: RSA signing never takes the slow ModMulCT / ModInvExt ---- */
    {
        static uint8_t privKeyDer[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t pubKeyDer[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        uint8_t hash[32];
        uint8_t sig[SSF_RSA_MAX_KEY_BYTES];
        size_t privKeyDerLen;
        size_t pubKeyDerLen;
        size_t sigLen;

        SSFSHA256((const uint8_t *)"slow path", 9, hash, sizeof(hash));
        SSF_ASSERT(SSFRSAKeyGen(2048u, privKeyDer, sizeof(privKeyDer), &privKeyDerLen,
                                pubKeyDer, sizeof(pubKeyDer), &pubKeyDerLen) == true);
        _SSFBNSlowPathCalls = 0u;
        _SSFBNModShiftCalls = 0u;
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
        SSF_ASSERT(SSFRSASignPKCS1(privKeyDer, privKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                   sizeof(hash), sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(SSFRSAVerifyPKCS1(pubKeyDer, pubKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                     sizeof(hash), sig, sigLen) == true);
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1 */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
        SSF_ASSERT(SSFRSASignPSS(privKeyDer, privKeyDerLen, SSF_RSA_HASH_SHA256, hash,
                                 sizeof(hash), sig, sizeof(sig), &sigLen) == true);
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
        SSF_ASSERT(_SSFBNSlowPathCalls == 0u);

        /* The CRT split cB mod p, cB mod q is constant-time Montgomery, not shift-subtract */
        SSF_ASSERT(_SSFBNModShiftCalls == 0u);
    }
#endif /* SSF_CONFIG_BN_UNIT_TEST && SSF_RSA_CONFIG_ENABLE_2048 && KEYGEN */
#endif /* SSF_RSA_ANY_ENABLED */
}
#ifdef _WIN32
#pragma warning(pop)
#endif
#endif /* SSF_CONFIG_RSA_UNIT_TEST */
