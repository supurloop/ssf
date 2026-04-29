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

/* Cross-check the SSFRSA implementation against OpenSSL. Same gating pattern as every other   */
/* _ut.c file: SSF_CONFIG_HAVE_OPENSSL drives whether the libcrypto path is compiled in. The   */
/* host ninja files default it to 1 and link -lcrypto; cross-test envs (e.g. tools/cross-test/ */
/* targets/mipsel.env) pass -DSSF_CONFIG_HAVE_OPENSSL=0 so the headers aren't required.        */
#if (SSF_CONFIG_HAVE_OPENSSL == 1) && (SSF_CONFIG_RSA_UNIT_TEST == 1)
#define SSF_RSA_OSSL_VERIFY 1
#else
#define SSF_RSA_OSSL_VERIFY 0
#endif

#if SSF_RSA_OSSL_VERIFY == 1
/* d2i_RSAPrivateKey / d2i_RSAPublicKey are the natural decoders for our PKCS#1 RSAPrivateKey / */
/* RSAPublicKey output. They are flagged "low-level" (deprecated) in OpenSSL 3.x but still ship */
/* and still return a usable RSA pointer -- we silence the warning only inside this test file.  */
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

/* --------------------------------------------------------------------------------------------- */
/* Hygiene test scaffolding: stack-residue scan.                                                 */
/*                                                                                               */
/* The pollute / scan / target helpers all run with `noinline` so each gets its own stack frame  */
/* allocated below their common parent. A frame size of 16 KiB exceeds the worst-case stack      */
/* footprint of SSFRSAKeyGen and the sign paths, so a sentinel laid down by the polluter and     */
/* then partially overwritten by a target call is fully visible to the scanner -- the scanner's  */
/* uninitialised local sits at the same stack region the previous callee just freed.             */
/*                                                                                               */
/* The scan looks for an exact byte-pattern needle. We use the top bytes of `p` extracted from   */
/* the just-emitted private-key DER: those bytes equal the top bytes of `pm1 = p - 1` (which     */
/* differs from p only in the lowest limb), so a 16-byte scan catches a non-zeroized pm1 sitting */
/* in `_SSFRSAKeyGenDerive`'s freed frame. Pre-hygiene-fix the scan finds 1+ hits; post-fix 0.   */
/* --------------------------------------------------------------------------------------------- */
#define _SSFRSA_UT_HYGIENE_PROBE_BYTES (16u * 1024u)

/* Suppress C6262 (large stack frame). The pollute/scan probe pair intentionally allocates a   */
/* 16 KiB stack buffer to overlay the freed callee frame from the function under test.         */
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

/* Reading uninitialized stack is the test -- silence GCC/clang's -Wuninitialized and MSVC      */
/* /analyze's C6001 for this body.                                                              */
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
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
    size_t i, j;

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

/* Locate the start of p's magnitude bytes inside an emitted PKCS#1 RSAPrivateKey for a 2048-bit */
/* key. Layout:                                                                                  */
/*   [0..3]   outer SEQUENCE header                                                              */
/*   [4..6]   version (3 bytes)                                                                  */
/*   [7..267] n INTEGER (tag + 0x82 long-form len + 0x00 sign + 256 magnitude)                   */
/*   [268..]  e INTEGER (5 bytes for e=65537)                                                    */
/*   [273..]  d INTEGER (variable length)                                                        */
/*   then     p INTEGER (tag 0x02, len 0x81 LL, optional 0x00 sign, magnitude)                   */
static const uint8_t *_SSFRSAUTLocatePMag(const uint8_t *priv, size_t privLen)
{
    const uint8_t *cur;
    size_t dHeader, dMag;

    if (privLen < 268u) return NULL;
    cur = priv + 273u;                          /* d INTEGER tag */
    if (cur[0] != 0x02u) return NULL;
    if (cur[1] == 0x82u)      { dHeader = 4u; dMag = ((size_t)cur[2] << 8) | cur[3]; }
    else if (cur[1] == 0x81u) { dHeader = 3u; dMag = cur[2]; }
    else                      { dHeader = 2u; dMag = cur[1]; }
    cur += dHeader + dMag;                      /* now at p INTEGER */
    if (cur[0] != 0x02u) return NULL;
    if (cur[1] == 0x81u) cur += 3u;
    else                 cur += 2u;
    if (cur[0] == 0x00u) cur++;                 /* skip strict-DER sign byte */
    return cur;
}

#if SSF_RSA_OSSL_VERIFY == 1
/* --------------------------------------------------------------------------------------------- */
/* OpenSSL cross-check helpers and driver.                                                       */
/*                                                                                               */
/* Coverage:                                                                                     */
/*   1. SSFRSAKeyGen DER must be parseable by OpenSSL (validates strict-DER compliance and the   */
/*      n=p*q / dp / dq / qInv consistency that OpenSSL itself checks during EVP_PKEY load).     */
/*   2. PKCS#1 v1.5: SSF-sign vs. OpenSSL-sign must produce the same byte-exact signature for    */
/*      the same (key, hash, message) -- PKCS#1 v1.5 is deterministic.                           */
/*   3. PKCS#1 v1.5: SSFRSAVerifyPKCS1 accepts an OpenSSL-produced signature.                    */
/*   4. PSS: SSFRSAVerifyPSS accepts an OpenSSL-produced signature with sLen=hLen MGF1=H.        */
/*   5. PSS: OpenSSL accepts an SSF-produced signature.                                          */
/*   6. Above runs across hash sizes (SHA-256/384/512) appropriate to each modulus size.         */
/* --------------------------------------------------------------------------------------------- */

/* Decode an SSF-emitted PKCS#1 RSAPrivateKey DER into an EVP_PKEY suitable for OpenSSL ops.    */
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
    if (EVP_DigestVerifyInit(ctx, &pctx, md, NULL, pkey) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLen) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0)
    {
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
    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, pkey) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, saltLen) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0)
    {
        if (EVP_DigestSign(ctx, sig, sigLen, msg, msgLen) == 1) ok = true;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

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
    size_t sigSSFLen, sigOSSLLen;

    SSF_ASSERT(hLen <= sizeof(hashVal));

    /* Compute the message hash with SSF -- fed to SSFRSA's hashed-input API. */
    switch (ssfHash)
    {
    case SSF_RSA_HASH_SHA256: SSFSHA256(msg, (uint32_t)msgLen, hashVal, (uint32_t)hLen); break;
    case SSF_RSA_HASH_SHA384: SSFSHA384(msg, (uint32_t)msgLen, hashVal, (uint32_t)hLen); break;
    case SSF_RSA_HASH_SHA512: SSFSHA512(msg, (uint32_t)msgLen, hashVal, (uint32_t)hLen); break;
    default: SSF_ASSERT(false); return;
    }

    /* ---- PKCS#1 v1.5 round-trip ------------------------------------------------------ */
    /* SSF sign, OpenSSL verify. */
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

    /* ---- PSS round-trip --------------------------------------------------------------- */
    /* PSS is randomized, so byte match is impossible -- only cross-verify both directions. */
    SSF_ASSERT(SSFRSASignPSS(priv, privLen, ssfHash, hashVal, hLen,
                             sigSSF, sizeof(sigSSF), &sigSSFLen) == true);
    SSF_ASSERT(_OSSLVerifyPSS(pkeyPub, md, (int)hLen, msg, msgLen, sigSSF, sigSSFLen));

    sigOSSLLen = sizeof(sigOSSL);
    SSF_ASSERT(_OSSLSignPSS(pkey, md, (int)hLen, msg, msgLen, sigOSSL, &sigOSSLLen));
    SSF_ASSERT(SSFRSAVerifyPSS(pub, pubLen, ssfHash, hashVal, hLen,
                               sigOSSL, sigOSSLLen) == true);

    /* Tampered-signature negative: flip a byte in the OpenSSL signature; both verifiers   */
    /* must reject. Catches accidental bypasses on either side.                             */
    sigOSSL[sigOSSLLen / 2u] ^= 0x01u;
    SSF_ASSERT(_OSSLVerifyPSS(pkeyPub, md, (int)hLen, msg, msgLen,
                              sigOSSL, sigOSSLLen) == false);
    SSF_ASSERT(SSFRSAVerifyPSS(pub, pubLen, ssfHash, hashVal, hLen,
                               sigOSSL, sigOSSLLen) == false);
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
    size_t privLen, pubLen;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pkeyPub = NULL;
    size_t i;

    /* Generate a fresh key with SSF. The DER bytes are then handed to OpenSSL -- if OpenSSL   */
    /* can decode the PKCS#1 RSAPrivateKey blob, our strict-DER encoding plus n=p*q / CRT       */
    /* consistency is correct (OpenSSL re-derives and checks these on load).                    */
    SSF_ASSERT(SSFRSAKeyGen(bits, priv, sizeof(priv), &privLen,
                             pub, sizeof(pub), &pubLen) == true);
    pkey = _OSSLLoadPrivKey(priv, privLen);
    SSF_ASSERT(pkey != NULL);
    pkeyPub = _OSSLLoadPubKey(pub, pubLen);
    SSF_ASSERT(pkeyPub != NULL);
    SSF_ASSERT((uint16_t)EVP_PKEY_bits(pkey) == bits);
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

/* Additional cross-check using the openssl-generated foreignPriv / foreignPub fixtures        */
/* embedded earlier in this file: PSS sign with OpenSSL on the foreign key, verify with SSF.   */
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

    /* OpenSSL signs PSS-SHA256 with sLen=32, MGF1=SHA256 -- same profile SSF emits.           */
    SSF_ASSERT(_OSSLSignPSS(pkey, EVP_sha256(), 32, msg, sizeof(msg) - 1u,
                            sigOSSL, &sigOSSLLen));
    SSF_ASSERT(SSFRSAVerifyPSS(foreignPub, foreignPubLen, SSF_RSA_HASH_SHA256,
                               hashVal, sizeof(hashVal), sigOSSL, sigOSSLLen) == true);

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pkeyPub);
}

/* Accessor wrappers so the EVP_MD_get_*() functions can be passed by pointer. */
static const EVP_MD *_OSSLSha256(void) { return EVP_sha256(); }
static const EVP_MD *_OSSLSha384(void) { return EVP_sha384(); }
static const EVP_MD *_OSSLSha512(void) { return EVP_sha512(); }

static void _SSFRSAVerifyAgainstOpenSSL(const uint8_t *foreignPriv, size_t foreignPrivLen,
                                        const uint8_t *foreignPub,  size_t foreignPubLen)
{
    /* Hash menus per NIST SP 800-57 Sec. 5.6.2 (security-strength matching with key size). Each */
    /* enabled size runs end-to-end provided SSF_BN_CONFIG_MAX_BITS is at least twice the       */
    /* largest enabled modulus (the CRT recombine and ModInvExt over lambda(n) feed a full nxn  */
    /* product into SSFBNMul -- see ssfrsa.h compile-time gates).                                */
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
    static const SSFRSAHash_t h4096[] = { SSF_RSA_HASH_SHA256, SSF_RSA_HASH_SHA384, SSF_RSA_HASH_SHA512 };
    static const size_t       l4096[] = { 32u, 48u, 64u };
    static const EVP_MD *(*const m4096[])(void) = { _OSSLSha256, _OSSLSha384, _OSSLSha512 };
#endif

    SSF_UT_PRINTF("\n--- ssfrsa OpenSSL cross-check ---\n");

    SSF_UT_PRINTF("  foreign-key PSS round-trip (sign-OSSL / verify-SSF)... ");
    fflush(stdout);
    _SSFRSACrossCheckForeignPSS(foreignPriv, foreignPrivLen, foreignPub, foreignPubLen);
    SSF_UT_PRINTF("OK\n");

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
    SSF_UT_PRINTF("  RSA-4096 keygen + PKCS1v15(byte-match) + PSS(round-trip) @ SHA-256/384/512... ");
    fflush(stdout);
    _SSFRSACrossCheckAtSize(4096u, h4096, l4096, m4096, sizeof(h4096) / sizeof(h4096[0]));
    SSF_UT_PRINTF("OK\n");
#endif

    SSF_UT_PRINTF("--- end OpenSSL cross-check ---\n");
}

#pragma GCC diagnostic pop  /* -Wdeprecated-declarations restored */
#endif /* SSF_RSA_OSSL_VERIFY */

/* Suppress C6262 (large stack frame). This unit-test entry point intentionally allocates many */
/* RSA-sized buffers across its sub-test blocks; the host test environment has ample stack.    */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6262)
#endif
void SSFRSAUnitTest(void)
{
#if SSF_RSA_ANY_ENABLED == 0
    /* No RSA size is enabled -- the rest of the body references SSFRSAKeyGen / SSFRSASignPKCS1 / */
    /* etc., none of which are compiled. Print a clear "skipped" line and return so main.c's     */
    /* test runner stays linkable for pure-ECC builds.                                            */
    SSF_UT_PRINTF("(skipped: no SSF_RSA_CONFIG_ENABLE_2048 / 3072 / 4096 enabled)\n");
    return;
#else

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

        /* Reject: well-formed DER but n is tiny (8-bit). bitLen(n) << 2048, the floor for any  */
        /* supported key size. The pre-fix validator only checked odd/>1 and accepted this.     */
        {
            static const uint8_t pubTinyN[] = {
                0x30u, 0x08u,
                0x02u, 0x01u, 0x03u,                      /* n = 3 */
                0x02u, 0x03u, 0x01u, 0x00u, 0x01u         /* e = 65537 */
            };
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubTinyN, sizeof(pubTinyN)) == false);
        }
    }

    /* ---- FIPS 186-4 Sec. B.3.3 step 5.4: |p - q| > 2^(halfBits - 100) ---- */
    /* Defends against Fermat-style factorization of n when p and q happen to be very    */
    /* close. The threshold is statistically irrelevant for random primes (failure is    */
    /* ~2^-100), but the spec mandates the explicit guard.                                */
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

    /* ---- FIPS 186-4 Sec. B.3.1: d > 2^(nlen/2) ---- */
    /* Defends against Wiener's continued-fraction attack on small d. With random         */
    /* primes d is overwhelmingly large, but unlucky lambda(n) values can produce a small d.*/
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

    /* ---- gcd(e, p-1) == 1 && gcd(e, q-1) == 1 ---- */
    /* Required for d = e^(-1) mod lambda(n) to exist. Implicitly ensured by SSFBNModInvExt*/
    /* failure today, but FIPS prefers an explicit pre-check on (p-1, q-1) so failures    */
    /* abort early before the lcm/divide work, and so an imported key can be validated.   */
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
    /* ---- DER interop with foreign-format PKCS#1 keys ----                                       */
    /* Real RSA-2048 PKCS#1 RSAPrivateKey/RSAPublicKey/signature triple, generated by:             */
    /*   printf 'interop test' > msg.bin                                                           */
    /*   openssl genrsa -traditional 2048 | openssl rsa -traditional -outform DER > priv.der       */
    /*   openssl rsa -in priv.der -inform DER -RSAPublicKey_out -outform DER > pub.der             */
    /*   openssl dgst -sha256 -sign priv.der -keyform DER -out sig.bin msg.bin                     */
    /* Each INTEGER field carries its standard 0x00 sign byte when the magnitude high bit is set,  */
    /* the form every conforming PKCS#1 producer emits. The pre-fix decoder cannot read these.     */
    /*                                                                                              */
    /* Block requires ENABLE_2048: the fixture is a 2048-bit key, and SSFRSAPubKeyIsValid will     */
    /* reject 2048-bit keys when ENABLE_2048 is off.                                                */
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

        /* Verify the openssl-produced PKCS#1 v1.5 signature with our verifier and
         * the foreign-format public key. Exercises the public-key DER decoder against
         * a real-world layout (with the standard 0x00 sign byte on n). */
        SSFSHA256((const uint8_t *)"interop test", 12, hashVal, sizeof(hashVal));
        SSF_ASSERT(SSFRSAVerifyPKCS1(foreignPub, sizeof(foreignPub),
                   SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                   foreignSig, sizeof(foreignSig)) == true);

        /* Sign with the foreign-format private key, verify with the foreign-format
         * public key. PKCS#1 v1.5 is deterministic, so the signature must match what
         * openssl produced byte-for-byte -- pinning both the decoder *and* the math. */
        SSF_ASSERT(SSFRSASignPKCS1(foreignPriv, sizeof(foreignPriv),
                   SSF_RSA_HASH_SHA256, hashVal, sizeof(hashVal),
                   sig, sizeof(sig), &sigLen) == true);
        SSF_ASSERT(sigLen == sizeof(foreignSig));
        SSF_ASSERT(memcmp(sig, foreignSig, sigLen) == 0);

        /* ---- Stricter SSFRSAPubKeyIsValid: small public exponent ---- */
        /* Synthesize a 2048-bit-modulus pubkey with e=3 by patching foreignPub: drop the last  */
        /* 5-byte e=65537 field, append a 3-byte e=3, and shrink the outer SEQUENCE length by 2.*/
        {
            uint8_t pubE3[sizeof(foreignPub) - 2u];
            memcpy(pubE3, foreignPub, sizeof(foreignPub) - 5u);
            SSF_ASSERT(pubE3[1] == 0x82u);       /* long-form 2-byte length follows */
            SSF_ASSERT(pubE3[2] == 0x01u);       /* original length high byte */
            SSF_ASSERT(pubE3[3] == 0x0au);       /* original length low byte (266) */
            pubE3[3] = 0x08u;                    /* new length 264 = 266 - 2 */
            pubE3[sizeof(foreignPub) - 5u + 0u] = 0x02u;  /* INTEGER tag */
            pubE3[sizeof(foreignPub) - 5u + 1u] = 0x01u;  /* length 1 */
            pubE3[sizeof(foreignPub) - 5u + 2u] = 0x03u;  /* e = 3 */
            SSF_ASSERT(SSFRSAPubKeyIsValid(pubE3, sizeof(pubE3)) == false);
        }

        /* ---- SSFRSAPrivKeyIsValid: positive case (foreign-format key) ---- */
        SSF_ASSERT(SSFRSAPrivKeyIsValid(foreignPriv, sizeof(foreignPriv)) == true);

        /* ---- SSFRSAPrivKeyIsValid: tampered components must reject ---- */
        /* Each test copies foreignPriv into a mutable buffer and flips a single byte at an     */
        /* offset known to land inside one of the algebraic components. The DER framing is      */
        /* untouched so decode succeeds; the consistency check then catches the breakage.       */
        {
            /* Flip a byte inside n's magnitude (offset 100 is well inside the 256-byte modulus */
            /* that runs from offset 12 to 267). After tampering, n != p*q.                     */
            uint8_t bad[sizeof(foreignPriv)];
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[100] ^= 0x01u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, sizeof(bad)) == false);
        }
        {
            /* Flip a byte inside dp (offset 805 is in dp's magnitude, which runs ~801..928).   */
            /* After tampering, dp != d mod (p-1).                                              */
            uint8_t bad[sizeof(foreignPriv)];
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[805] ^= 0x01u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, sizeof(bad)) == false);
        }
        {
            /* Flip the trailing byte (last byte of qInv). After tampering, qInv*q mod p != 1.  */
            uint8_t bad[sizeof(foreignPriv)];
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[sizeof(bad) - 1u] ^= 0x01u;
            SSF_ASSERT(SSFRSAPrivKeyIsValid(bad, sizeof(bad)) == false);
        }

        /* ---- Sign-time fault detection: verify-after-sign ---- */
        /* The Boneh-DeMillo-Lipton fault attack recovers p from a single bad CRT signature.    */
        /* As a defense-in-depth, the signer recomputes m' = sig^e mod n and rejects unless     */
        /* m' equals the original encoded message m. A privkey with a tampered dp passes DER    */
        /* decode but produces a faulty CRT signature; verify-after-sign must catch this.        */
        {
            uint8_t bad[sizeof(foreignPriv)];
            uint8_t hashFault[32];
            uint8_t sigFault[SSF_RSA_MAX_SIG_SIZE];
            size_t sigFaultLen;
            memcpy(bad, foreignPriv, sizeof(bad));
            bad[805] ^= 0x01u;            /* corrupt dp */
            SSFSHA256((const uint8_t *)"fault test", 10, hashFault, sizeof(hashFault));
            SSF_ASSERT(SSFRSASignPKCS1(bad, sizeof(bad),
                       SSF_RSA_HASH_SHA256, hashFault, sizeof(hashFault),
                       sigFault, sizeof(sigFault), &sigFaultLen) == false);
        }

#if SSF_RSA_OSSL_VERIFY == 1
        /* Comprehensive OpenSSL cross-check: PKCS#1-v1.5 (deterministic byte match), PSS in     */
        /* both directions, multiple hash sizes per key size. The foreignPriv / foreignPub       */
        /* arrays are passed in so the inner helper can run a PSS round-trip on them too.        */
        _SSFRSAVerifyAgainstOpenSSL(foreignPriv, sizeof(foreignPriv),
                                    foreignPub,  sizeof(foreignPub));
#endif
    }
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 && SSF_RSA_CONFIG_ENABLE_2048 */

#if (SSF_RSA_CONFIG_ENABLE_KEYGEN == 1) && (SSF_RSA_CONFIG_ENABLE_2048 == 1)
    /* ---- RSA-2048 key generation + PKCS#1 v1.5 sign + verify roundtrip ---- */
    /* Gated on ENABLE_2048: this block is hard-coded to the 2048-bit canonical example         */
    /* (sigLen == 256 etc. assertions). 3072 / 4096 keygen + sign + verify is exercised by the  */
    /* OpenSSL cross-check above when those sizes are enabled.                                  */
    {
        uint8_t privKeyDer[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        size_t privKeyDerLen;
        uint8_t pubKeyDer[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        size_t pubKeyDerLen;

        /* Pre-fill the lower stack with a recognisable sentinel so we can later detect any       */
        /* secret bytes left behind in keygen's frame. SSFRSAKeyGen's frame allocates atop the    */
        /* same region the polluter just freed, so any region keygen does not write retains the  */
        /* sentinel; any region keygen writes and fails to zeroize retains the secret.            */
        _SSFRSAUTPolluteStack(0xCCu);

        /* Generate 2048-bit key pair */
        SSF_ASSERT(SSFRSAKeyGen(2048,
                   privKeyDer, sizeof(privKeyDer), &privKeyDerLen,
                   pubKeyDer, sizeof(pubKeyDer), &pubKeyDerLen) == true);
        SSF_ASSERT(privKeyDerLen > 0u);
        SSF_ASSERT(pubKeyDerLen > 0u);

        /* Hygiene: scan the just-freed keygen frame for the top 16 bytes of p. Those bytes      */
        /* equal the top bytes of pm1 = p - 1 (only the lowest limb differs), and pm1 lives in   */
        /* _SSFRSAKeyGenDerive's stack frame. Pre-fix the scanner finds 1+ matches; post-fix     */
        /* Derive zeroizes its intermediates so the scanner finds 0.                              */
        /*                                                                                       */
        /* SSFBN stores 32-bit limbs little-endian-byte within each limb, with limb[0] = lowest. */
        /* p's DER magnitude is big-endian, so its top 16 bytes appear in the in-memory limb     */
        /* array as those 16 bytes byte-reversed (limbs[28..31] -> bytes byte[15]..byte[0]).      */
        {
            const uint8_t *pTop = _SSFRSAUTLocatePMag(privKeyDer, privKeyDerLen);
            uint8_t needle[16];
            size_t i;
            SSF_ASSERT(pTop != NULL);
            for (i = 0u; i < sizeof(needle); i++) needle[i] = pTop[15u - i];
            SSF_ASSERT(_SSFRSAUTScanStack(needle, sizeof(needle)) == 0);
        }

        /* Validate generated public and private keys (FIPS post-conditions plus n=p*q,           */
        /* dp == d mod (p-1), dq == d mod (q-1), qInv*q == 1 mod p -- all hold by construction).  */
        SSF_ASSERT(SSFRSAPubKeyIsValid(pubKeyDer, pubKeyDerLen) == true);
        SSF_ASSERT(SSFRSAPrivKeyIsValid(privKeyDer, privKeyDerLen) == true);

        /* The emitted public DER must be strict-DER compliant. RSAPublicKey is                    */
        /*   SEQUENCE { INTEGER n, INTEGER e }                                                     */
        /* and the keygen forces the top two bits of p and q so n always has bit 2047 set. ASN.1   */
        /* INTEGER is signed (X.690 Sec. 8.3.2), so n's encoded body must lead with a 0x00 padding */
        /* byte. Without that byte, strict DER parsers (OpenSSL, mbedTLS) read n as negative.      */
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
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN && SSF_RSA_CONFIG_ENABLE_2048 */

    /* ---- Design-by-Contract: precondition violations must trigger SSFPortAssert ---- */
    /* Every public ssfrsa entry point declares preconditions through SSF_REQUIRE; this block  */
    /* drives each one with a deliberately-violating call and uses SSF_ASSERT_TEST to confirm  */
    /* the assertion fires. Some violations were already caught at the entry point, others    */
    /* trickled into ssfbn / ssfasn1 deep inside the call (where the assertion is correct but */
    /* harder to attribute) or -- worst -- slipped through to a graceful `return false`. After */
    /* the DBC pass every violation lands at the entry point of the function the caller       */
    /* invoked, so a misuse is identified at its source.                                       */
    {
        /* Reusable valid SSFBN. Length 64 limbs (2048 bits) is a representative working width.*/
        SSFBN_DEFINE(bn, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&bn, 5u, 64u);

        /* Synthetic SSFBN_t with NULL limbs to test the per-arg limbs-pointer guard. The      */
        /* struct itself is valid (non-NULL), so the only thing that should trip is the        */
        /* explicit ->limbs != NULL REQUIRE.                                                    */
        SSFBN_t bnNullLimbs;
        bnNullLimbs.limbs = NULL;
        bnNullLimbs.len = 64u;
        bnNullLimbs.cap = 0u;

        static uint8_t dbcDerBuf[SSF_RSA_MAX_PRIV_KEY_DER_SIZE];
        static uint8_t dbcPubBuf[SSF_RSA_MAX_PUB_KEY_DER_SIZE];
        static uint8_t dbcSigBuf[SSF_RSA_MAX_SIG_SIZE];
        uint8_t dbcHashBuf[64];
        size_t dbcLenA, dbcLenB;
        memset(dbcHashBuf, 0, sizeof(dbcHashBuf));

        /* ---- SSFRSAFipsPrimeDistanceOK ---- */
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(NULL, &bn, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bn, NULL, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bnNullLimbs, &bn, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bn, &bnNullLimbs, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bn, &bn, 100u));   /* halfBits == 100 */
        SSF_ASSERT_TEST(SSFRSAFipsPrimeDistanceOK(&bn, &bn, 0u));     /* halfBits == 0 */

        /* ---- SSFRSAFipsDLowerBoundOK ---- */
        SSF_ASSERT_TEST(SSFRSAFipsDLowerBoundOK(NULL, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsDLowerBoundOK(&bnNullLimbs, 1024u));
        SSF_ASSERT_TEST(SSFRSAFipsDLowerBoundOK(&bn, 0u));            /* halfBits == 0 */

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
        /* Pick the smallest enabled key size for DBC arg-validation tests so the bits check    */
        /* doesn't fire first and mask the NULL / size precondition we're actually testing.    */
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
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(NULL, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, NULL, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                        NULL, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 0u, SSF_RSA_HASH_SHA256, dbcHashBuf, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_MIN, dbcHashBuf, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_MAX, dbcHashBuf, 32u,
                                        dbcSigBuf, 256u));
        SSF_ASSERT_TEST(SSFRSAVerifyPSS(dbcPubBuf, 16u, SSF_RSA_HASH_SHA256, dbcHashBuf, 31u,
                                        dbcSigBuf, 256u));
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
    }
#endif /* SSF_RSA_ANY_ENABLED */
}
#ifdef _WIN32
#pragma warning(pop)
#endif
#endif /* SSF_CONFIG_RSA_UNIT_TEST */
