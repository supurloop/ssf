/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpkey_ut.c                                                                                  */
/* Provides unit tests for private key decoding.                                                 */
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
#include <stdio.h>
#include <string.h>
#include "ssfpkey.h"
#include "ssfpem.h"
#include "ssfbase64.h"
#include "ssfecdsa.h"
#include "ssfed25519.h"
#include "ssfrsa.h"
#include "ssfsha2.h"
#include "ssfport.h"

#if SSF_CONFIG_PKEY_UNIT_TEST == 1
#include "ssfpkey_ut_fix.h"

/* OIDs, value bytes only */
static const uint8_t _utOidRSA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const uint8_t _utOidEC[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t _utOidP256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t _utOidP384[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t _utOidEd25519[] = { 0x2B, 0x65, 0x70 };
static const uint8_t _utOidX25519[] = { 0x2B, 0x65, 0x6E };

/* P-256 group order n */
static const uint8_t _utP256N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};

/* ---- A tiny DER writer for building test inputs ---- */
typedef struct { uint8_t b[2048]; size_t len; } _UTDer_t;

static void _UTPut(_UTDer_t *d, const uint8_t *p, size_t n)
{
    SSF_ASSERT((d->len + n) <= sizeof(d->b));
    if (n == 0u) return;                    /* p may be NULL for an empty value */
    memcpy(&d->b[d->len], p, n);
    d->len += n;
}

static void _UTByte(_UTDer_t *d, uint8_t x) { _UTPut(d, &x, 1u); }

/* Appends tag, length and value. */
static void _UTTLV(_UTDer_t *d, uint8_t tag, const uint8_t *v, size_t n)
{
    _UTByte(d, tag);
    if (n < 0x80u) _UTByte(d, (uint8_t)n);
    else if (n < 0x100u) { _UTByte(d, 0x81u); _UTByte(d, (uint8_t)n); }
    else { _UTByte(d, 0x82u); _UTByte(d, (uint8_t)(n >> 8)); _UTByte(d, (uint8_t)n); }
    _UTPut(d, v, n);
}

/* Appends tag + length + the contents of inner. */
static void _UTWrap(_UTDer_t *d, uint8_t tag, const _UTDer_t *inner)
{
    _UTTLV(d, tag, inner->b, inner->len);
}

static void _UTInt(_UTDer_t *d, uint8_t v) { _UTTLV(d, 0x02u, &v, 1u); }

/* SEC 1 ECPrivateKey: version, scalar, optional [0] curve OID, optional [1] public key. */
static void _UTSEC1(_UTDer_t *out, uint8_t version, const uint8_t *scalar, size_t scalarLen,
                    const uint8_t *curveOid, size_t curveOidLen, const uint8_t *pub, size_t pubLen)
{
    _UTDer_t seq, ctx, bits;
    memset(&seq, 0, sizeof(seq));
    _UTInt(&seq, version);
    _UTTLV(&seq, 0x04u, scalar, scalarLen);
    if (curveOid != NULL)
    {
        memset(&ctx, 0, sizeof(ctx));
        _UTTLV(&ctx, 0x06u, curveOid, curveOidLen);
        _UTWrap(&seq, 0xA0u, &ctx);
    }
    if (pub != NULL)
    {
        memset(&bits, 0, sizeof(bits));
        _UTByte(&bits, 0x00u);
        _UTPut(&bits, pub, pubLen);
        memset(&ctx, 0, sizeof(ctx));
        _UTWrap(&ctx, 0x03u, &bits);
        _UTWrap(&seq, 0xA1u, &ctx);
    }
    memset(out, 0, sizeof(*out));
    _UTWrap(out, 0x30u, &seq);
}

/* PKCS#8: version, AlgorithmIdentifier { oid, params }, OCTET STRING inner, then extra bytes  */
/* (attributes / [1] public key) appended raw. paramsTag 0 means no parameters.               */
static void _UTPKCS8(_UTDer_t *out, uint8_t version, const uint8_t *oid, size_t oidLen,
                     uint8_t paramsTag, const uint8_t *params, size_t paramsLen,
                     const uint8_t *inner, size_t innerLen, const uint8_t *extra, size_t extraLen)
{
    _UTDer_t seq, alg;
    memset(&seq, 0, sizeof(seq));
    memset(&alg, 0, sizeof(alg));
    _UTInt(&seq, version);
    _UTTLV(&alg, 0x06u, oid, oidLen);
    if (paramsTag != 0u) _UTTLV(&alg, paramsTag, params, paramsLen);
    _UTWrap(&seq, 0x30u, &alg);
    _UTTLV(&seq, 0x04u, inner, innerLen);
    if (extra != NULL) _UTPut(&seq, extra, extraLen);
    memset(out, 0, sizeof(*out));
    _UTWrap(out, 0x30u, &seq);
}

/* Ed25519 PKCS#8 with the given seed length and optional [1] public key. */
static void _UTEd25519(_UTDer_t *out, uint8_t version, size_t seedLen, const uint8_t *pub,
                       uint8_t paramsTag)
{
    _UTDer_t inner, extra, bits;
    uint8_t seed[40];
    SSF_ASSERT(seedLen <= sizeof(seed));
    memset(seed, 0x11, sizeof(seed));
    memcpy(seed, _pkEd25519Seed, (seedLen < 32u) ? seedLen : 32u);
    memset(&inner, 0, sizeof(inner));
    _UTTLV(&inner, 0x04u, seed, seedLen);
    memset(&extra, 0, sizeof(extra));
    if (pub != NULL)
    {
        memset(&bits, 0, sizeof(bits));
        _UTByte(&bits, 0x00u);
        _UTPut(&bits, pub, 32u);
        _UTWrap(&extra, 0x81u, &bits);
    }
    _UTPKCS8(out, version, _utOidEd25519, sizeof(_utOidEd25519), paramsTag, NULL, 0,
             inner.b, inner.len, (pub != NULL) ? extra.b : NULL, extra.len);
}

/* Wraps der as a PEM block with the given label. */
static size_t _UTPem(char *out, size_t outSize, const char *label, const uint8_t *der,
                     size_t derLen)
{
    size_t n;
    size_t b64Len;
    n = (size_t)snprintf(out, outSize, "-----BEGIN %s-----\n", label);
    SSF_ASSERT(SSFBase64Encode(der, derLen, &out[n], outSize - n, &b64Len));
    n += b64Len;
    n += (size_t)snprintf(&out[n], outSize - n, "\n-----END %s-----\n", label);
    SSF_ASSERT(n < outSize);
    return n;
}

static bool _UTAllZero(const void *p, size_t len)
{
    const uint8_t *b = (const uint8_t *)p;
    size_t i;
    for (i = 0; i < len; i++) { if (b[i] != 0u) return false; }
    return true;
}

/* Expects der to be refused, with the key wiped. */
static void _UTRefuseDER(const uint8_t *der, size_t derLen)
{
    SSFPKey_t key;
    memset(&key, 0xAA, sizeof(key));
    SSF_ASSERT(SSFPKeyDecodeDER(der, derLen, &key) == false);
    SSF_ASSERT(_UTAllZero(&key, sizeof(key)));
    SSF_ASSERT(key.type == SSF_PKEY_TYPE_NONE);                 /* a wiped key is no key */
}

/* Expects pem to be refused, with the key and the whole DER buffer wiped. */
static void _UTRefusePEM(const char *pem, size_t pemLen)
{
    static uint8_t buf[2048];
    SSFPKey_t key;
    memset(&key, 0xAA, sizeof(key));
    memset(buf, 0xAA, sizeof(buf));
    SSF_ASSERT(SSFPKeyDecodePEM(pem, pemLen, buf, sizeof(buf), &key) == false);
    SSF_ASSERT(_UTAllZero(&key, sizeof(key)) && (key.type == SSF_PKEY_TYPE_NONE));
    SSF_ASSERT(_UTAllZero(buf, sizeof(buf)));
}

/* Checks an EC key decoded to the expected values and that it signs. */
static void _UTCheckEC(const SSFPKey_t *key, SSFPKeyType_t type, const uint8_t *priv,
                       size_t privLen, const uint8_t *pub, size_t pubLen)
{
    uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
    uint8_t sig[SSF_ECDSA_MAX_SIG_SIZE];
    size_t sigLen;
    SSFECCurve_t curve = (type == SSF_PKEY_TYPE_P256) ? SSF_EC_CURVE_P256 : SSF_EC_CURVE_P384;

    SSF_ASSERT(key->type == type);
    SSF_ASSERT((key->privLen == privLen) && (memcmp(key->priv, priv, privLen) == 0));
    SSF_ASSERT((key->pubLen == pubLen) && (memcmp(key->pub, pub, pubLen) == 0));
    SSF_ASSERT((key->rsaDer == NULL) && (key->rsaDerLen == 0u));
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
    SSFSHA256((const uint8_t *)"pkey", 4u, hash, sizeof(hash));
    SSF_ASSERT(SSFECDSASign(curve, key->priv, key->privLen, hash, sizeof(hash), sig, sizeof(sig),
                            &sigLen));
    SSF_ASSERT(SSFECDSAVerify(curve, pub, pubLen, hash, sizeof(hash), sig, sigLen));
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */
}

static void _UTCheckEd25519(const SSFPKey_t *key)
{
    uint8_t sig[SSF_ED25519_SIG_SIZE];
    SSF_ASSERT(key->type == SSF_PKEY_TYPE_ED25519);
    SSF_ASSERT((key->privLen == 32u) && (memcmp(key->priv, _pkEd25519Seed, 32u) == 0));
    SSF_ASSERT((key->pubLen == 32u) && (memcmp(key->pub, _pkEd25519Pub, 32u) == 0));
    SSF_ASSERT(SSFEd25519Sign(key->priv, key->pub, (const uint8_t *)"pkey", 4u, sig));
    SSF_ASSERT(SSFEd25519Verify(_pkEd25519Pub, (const uint8_t *)"pkey", 4u, sig));
}

static void _UTCheckRSA(const SSFPKey_t *key)
{
    uint8_t hash[SSF_SHA2_256_BYTE_SIZE];
    static uint8_t sig[SSF_RSA_MAX_SIG_SIZE];
    size_t sigLen;
    SSF_ASSERT(key->type == SSF_PKEY_TYPE_RSA);
    SSF_ASSERT(key->rsaDerLen == sizeof(_pkRSAPKCS1Der));
    SSF_ASSERT(memcmp(key->rsaDer, _pkRSAPKCS1Der, sizeof(_pkRSAPKCS1Der)) == 0);
    SSF_ASSERT((key->privLen == 0u) && (key->pubLen == 0u));
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
    SSFSHA256((const uint8_t *)"pkey", 4u, hash, sizeof(hash));
    SSF_ASSERT(SSFRSASignPSS(key->rsaDer, key->rsaDerLen, SSF_RSA_HASH_SHA256, hash, sizeof(hash),
                             sig, sizeof(sig), &sigLen));
    SSF_ASSERT(SSFRSAVerifyPSS(_pkRSAPubDer, sizeof(_pkRSAPubDer), SSF_RSA_HASH_SHA256, hash,
                               sizeof(hash), sizeof(hash), sig, sigLen));
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
}

/* Curve availability: a key for a curve compiled out must be refused, not decoded */
#define _UT_P256 (SSF_EC_CONFIG_ENABLE_P256 == 1)
#define _UT_P384 (SSF_EC_CONFIG_ENABLE_P384 == 1)
#define _UT_EC_GOOD(_built, _decode, ...) do { \
    if (_built) { SSF_ASSERT(_decode); _UTCheckEC(&key, __VA_ARGS__); } \
    else { SSF_ASSERT(!(_decode)); } } while (0)
#define _UT_PEM(_pem) SSFPKeyDecodePEM((_pem), strlen(_pem), buf, sizeof(buf), &key)
#define _UT_DER(_der) SSFPKeyDecodeDER((_der), sizeof(_der), &key)
#define _UT_K256 SSF_PKEY_TYPE_P256, _pkP256Priv, 32u, _pkP256Pub, 65u
#define _UT_K384 SSF_PKEY_TYPE_P384, _pkP384Priv, 48u, _pkP384Pub, 97u

void SSFPKeyUnitTest(void)
{
    static uint8_t buf[2048];
    static char pem[4096];
    static _UTDer_t d;
    static _UTDer_t inner;
    SSFPKey_t key;
    size_t n;

    /* ======== Good keys, PEM (every format OpenSSL writes) ======== */
    SSF_ASSERT(SSFPKeyDecodePEM(_pkRSAPKCS1Pem, strlen(_pkRSAPKCS1Pem), buf, sizeof(buf), &key));
    _UTCheckRSA(&key);
    SSF_ASSERT(SSFPKeyDecodePEM(_pkRSAPKCS8Pem, strlen(_pkRSAPKCS8Pem), buf, sizeof(buf), &key));
    _UTCheckRSA(&key);
    SSF_ASSERT((key.rsaDer >= buf) && (key.rsaDer < (buf + sizeof(buf)))); /* points into buf */

    _UT_EC_GOOD(_UT_P256, _UT_PEM(_pkP256SEC1Pem), _UT_K256);
    _UT_EC_GOOD(_UT_P256, _UT_PEM(_pkP256SEC1NoPubPem), _UT_K256); /* pub derived */
    _UT_EC_GOOD(_UT_P256, _UT_PEM(_pkP256ParamsSEC1Pem), _UT_K256); /* EC PARAMETERS skipped */
    _UT_EC_GOOD(_UT_P256, _UT_PEM(_pkP256PKCS8Pem), _UT_K256);
    _UT_EC_GOOD(_UT_P384, _UT_PEM(_pkP384SEC1Pem), _UT_K384);
    _UT_EC_GOOD(_UT_P384, _UT_PEM(_pkP384PKCS8Pem), _UT_K384);
    SSF_ASSERT(SSFPKeyDecodePEM(_pkEd25519PKCS8Pem, strlen(_pkEd25519PKCS8Pem), buf, sizeof(buf),
                                &key));
    _UTCheckEd25519(&key);

    /* ======== Good keys, DER ======== */
    SSF_ASSERT(SSFPKeyDecodeDER(_pkRSAPKCS1Der, sizeof(_pkRSAPKCS1Der), &key));
    _UTCheckRSA(&key);
    SSF_ASSERT(key.rsaDer == _pkRSAPKCS1Der);                              /* zero copy */
    _UT_EC_GOOD(_UT_P256, _UT_DER(_pkP256SEC1Der), _UT_K256);
    _UT_EC_GOOD(_UT_P256, _UT_DER(_pkP256PKCS8Der), _UT_K256);
    _UT_EC_GOOD(_UT_P384, _UT_DER(_pkP384SEC1Der), _UT_K384);
    SSF_ASSERT(SSFPKeyDecodeDER(_pkEd25519PKCS8Der, sizeof(_pkEd25519PKCS8Der), &key));
    _UTCheckEd25519(&key);

    /* ======== SSFPKeyWipe ======== */
    SSFPKeyWipe(&key);
    SSF_ASSERT(_UTAllZero(&key, sizeof(key)) && (key.type == SSF_PKEY_TYPE_NONE));
    SSF_ASSERT((int)SSF_PKEY_TYPE_NONE == 0);

    /* ======== Ed25519 v2 (OneAsymmetricKey with public key) ======== */
    _UTEd25519(&d, 1u, 32u, _pkEd25519Pub, 0u);
    SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));
    _UTCheckEd25519(&key);
    {
        uint8_t bad[32];
        memcpy(bad, _pkEd25519Pub, 32u);
        bad[31] ^= 0x01u;
        _UTEd25519(&d, 1u, 32u, bad, 0u);                      /* public key does not match */
        _UTRefuseDER(d.b, d.len);
    }
    _UTEd25519(&d, 0u, 32u, _pkEd25519Pub, 0u);                /* v1 must not carry one */
    _UTRefuseDER(d.b, d.len);
    _UTEd25519(&d, 2u, 32u, NULL, 0u);                         /* unknown version */
    _UTRefuseDER(d.b, d.len);
    _UTEd25519(&d, 0u, 31u, NULL, 0u);                         /* seed length */
    _UTRefuseDER(d.b, d.len);
    _UTEd25519(&d, 0u, 33u, NULL, 0u);
    _UTRefuseDER(d.b, d.len);
    _UTEd25519(&d, 0u, 32u, NULL, 0x05u);                      /* parameters must be absent */
    _UTRefuseDER(d.b, d.len);
    _UTEd25519(&d, 0u, 32u, NULL, 0u);                         /* control: built form decodes */
    SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));
    _UTCheckEd25519(&key);

    /* ======== PKCS#8 attributes [0] are skipped ======== */
    {
        static const uint8_t attrs[] = { 0xA0, 0x00 };
        memset(&inner, 0, sizeof(inner));
        _UTTLV(&inner, 0x04u, _pkEd25519Seed, 32u);
        _UTPKCS8(&d, 0u, _utOidEd25519, sizeof(_utOidEd25519), 0u, NULL, 0, inner.b, inner.len,
                 attrs, sizeof(attrs));
        SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));
        _UTCheckEd25519(&key);
    }

    /* ======== Unknown algorithm (X25519 is a key-agreement key) ======== */
    memset(&inner, 0, sizeof(inner));
    _UTTLV(&inner, 0x04u, _pkEd25519Seed, 32u);
    _UTPKCS8(&d, 0u, _utOidX25519, sizeof(_utOidX25519), 0u, NULL, 0, inner.b, inner.len, NULL, 0);
    _UTRefuseDER(d.b, d.len);

#if SSF_EC_CONFIG_ENABLE_P256 == 1 /* The built forms below use P-256 key material */
    /* ======== SEC 1 built forms ======== */
    _UTSEC1(&d, 1u, _pkP256Priv, 32u, _utOidP256, sizeof(_utOidP256), NULL, 0);
    SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));                       /* control */
    _UTCheckEC(&key, SSF_PKEY_TYPE_P256, _pkP256Priv, 32u, _pkP256Pub, 65u);
    _UTSEC1(&d, 0u, _pkP256Priv, 32u, _utOidP256, sizeof(_utOidP256), NULL, 0);
    _UTRefuseDER(d.b, d.len);                                              /* version 0 */
    _UTSEC1(&d, 2u, _pkP256Priv, 32u, _utOidP256, sizeof(_utOidP256), NULL, 0);
    _UTRefuseDER(d.b, d.len);                                              /* version 2 */
    _UTSEC1(&d, 1u, _pkP256Priv, 32u, NULL, 0, _pkP256Pub, 65u);
    _UTRefuseDER(d.b, d.len);                          /* standalone SEC 1 needs the curve */
    {
        static const uint8_t unk[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x08 };
        _UTSEC1(&d, 1u, _pkP256Priv, 32u, unk, sizeof(unk), NULL, 0);
        _UTRefuseDER(d.b, d.len);                      /* unknown curve */
    }
    {
        /* Explicit curve parameters ([0] holding a SEQUENCE) are refused */
        static const uint8_t explicitParams[] = {
            0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01,
            0xA0, 0x0A, 0x30, 0x08, 0x02, 0x01, 0x01, 0x30, 0x03, 0x06, 0x01, 0x00 };
        _UTRefuseDER(explicitParams, sizeof(explicitParams));
    }
    {
        uint8_t s[33];
        memset(s, 0, sizeof(s));
        _UTSEC1(&d, 1u, s, 32u, _utOidP256, sizeof(_utOidP256), NULL, 0);
        _UTRefuseDER(d.b, d.len);                      /* scalar 0 */
        _UTSEC1(&d, 1u, _utP256N, 32u, _utOidP256, sizeof(_utOidP256), NULL, 0);
        _UTRefuseDER(d.b, d.len);                      /* scalar n */
        memcpy(s, _utP256N, 32u);
        s[31]--;
        _UTSEC1(&d, 1u, s, 32u, _utOidP256, sizeof(_utOidP256), NULL, 0);
        SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));  /* n - 1 is the largest valid scalar */
        SSF_ASSERT((key.privLen == 32u) && (memcmp(key.priv, s, 32u) == 0) && (key.pubLen == 65u));
        /* A scalar with its leading zero byte dropped is left-padded */
        memset(s, 0, sizeof(s));
        memcpy(&s[1], &_pkP256Priv[1], 31u);
        s[0] = 0;
        _UTSEC1(&d, 1u, &s[1], 31u, _utOidP256, sizeof(_utOidP256), NULL, 0);
        SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));
        SSF_ASSERT((key.privLen == 32u) && (key.priv[0] == 0u) &&
                   (memcmp(&key.priv[1], &_pkP256Priv[1], 31u) == 0));
        /* Longer than the curve is refused, even with a leading zero */
        s[0] = 0;
        memcpy(&s[1], _pkP256Priv, 32u);
        _UTSEC1(&d, 1u, s, 33u, _utOidP256, sizeof(_utOidP256), NULL, 0);
        _UTRefuseDER(d.b, d.len);
    }
    {
        /* Public key must match the private key, uncompressed */
        uint8_t pub[65];
        memcpy(pub, _pkP256Pub, 65u);
        pub[64] ^= 0x01u;
        _UTSEC1(&d, 1u, _pkP256Priv, 32u, _utOidP256, sizeof(_utOidP256), pub, 65u);
        _UTRefuseDER(d.b, d.len);
        _UTSEC1(&d, 1u, _pkP256Priv, 32u, _utOidP256, sizeof(_utOidP256), _pkP384Pub, 97u);
        _UTRefuseDER(d.b, d.len);
        pub[0] = (uint8_t)(0x02u | (_pkP256Pub[64] & 1u));            /* compressed form */
        memcpy(&pub[1], &_pkP256Pub[1], 32u);
        _UTSEC1(&d, 1u, _pkP256Priv, 32u, _utOidP256, sizeof(_utOidP256), pub, 33u);
        _UTRefuseDER(d.b, d.len);
        _UTSEC1(&d, 1u, _pkP256Priv, 32u, _utOidP256, sizeof(_utOidP256), _pkP256Pub, 65u);
        SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));                 /* control */
    }

    /* ======== PKCS#8 EC wrapper ======== */
    {
        _UTDer_t sec1;
        _UTSEC1(&sec1, 1u, _pkP256Priv, 32u, NULL, 0, NULL, 0);
        _UTPKCS8(&d, 0u, _utOidEC, sizeof(_utOidEC), 0x06u, _utOidP256, sizeof(_utOidP256),
                 sec1.b, sec1.len, NULL, 0);
        SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));                 /* curve from wrapper */
        _UTCheckEC(&key, SSF_PKEY_TYPE_P256, _pkP256Priv, 32u, _pkP256Pub, 65u);
        _UTPKCS8(&d, 0u, _utOidEC, sizeof(_utOidEC), 0u, NULL, 0, sec1.b, sec1.len, NULL, 0);
        _UTRefuseDER(d.b, d.len);                                       /* no curve at all */
        _UTPKCS8(&d, 0u, _utOidEC, sizeof(_utOidEC), 0x05u, NULL, 0, sec1.b, sec1.len, NULL, 0);
        _UTRefuseDER(d.b, d.len);                                       /* NULL params */
        _UTSEC1(&sec1, 1u, _pkP256Priv, 32u, _utOidP256, sizeof(_utOidP256), NULL, 0);
        _UTPKCS8(&d, 0u, _utOidEC, sizeof(_utOidEC), 0x06u, _utOidP256, sizeof(_utOidP256),
                 sec1.b, sec1.len, NULL, 0);
        SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));                 /* both agree */
        _UTPKCS8(&d, 0u, _utOidEC, sizeof(_utOidEC), 0x06u, _utOidP384, sizeof(_utOidP384),
                 sec1.b, sec1.len, NULL, 0);
        _UTRefuseDER(d.b, d.len);                                       /* they disagree */
        _UTPKCS8(&d, 0u, _utOidEC, sizeof(_utOidEC), 0x06u, _utOidP256, sizeof(_utOidP256),
                 sec1.b, sec1.len - 1u, NULL, 0);
        _UTRefuseDER(d.b, d.len);                                       /* inner truncated */
    }

#endif /* SSF_EC_CONFIG_ENABLE_P256 */

    /* ======== PKCS#8 RSA wrapper ======== */
    _UTPKCS8(&d, 0u, _utOidRSA, sizeof(_utOidRSA), 0x05u, NULL, 0, _pkRSAPKCS1Der,
             sizeof(_pkRSAPKCS1Der), NULL, 0);
    SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));                     /* control */
    _UTCheckRSA(&key);
    _UTPKCS8(&d, 0u, _utOidRSA, sizeof(_utOidRSA), 0u, NULL, 0, _pkRSAPKCS1Der,
             sizeof(_pkRSAPKCS1Der), NULL, 0);
    _UTRefuseDER(d.b, d.len);                                           /* params must be NULL */
    {
        /* v2 RSA key carrying a public key: refused (it cannot be checked) */
        static const uint8_t rsaPub[] = { 0x81, 0x03, 0x00, 0x01, 0x02 };
        _UTPKCS8(&d, 1u, _utOidRSA, sizeof(_utOidRSA), 0x05u, NULL, 0, _pkRSAPKCS1Der,
                 sizeof(_pkRSAPKCS1Der), rsaPub, sizeof(rsaPub));
        _UTRefuseDER(d.b, d.len);
        _UTPKCS8(&d, 1u, _utOidRSA, sizeof(_utOidRSA), 0x05u, NULL, 0, _pkRSAPKCS1Der,
                 sizeof(_pkRSAPKCS1Der), NULL, 0);
        SSF_ASSERT(SSFPKeyDecodeDER(d.b, d.len, &key));                 /* v2 without it is fine */
    }
    _UTPKCS8(&d, 0u, _utOidRSA, sizeof(_utOidRSA), 0x05u, NULL, 0, _pkP256SEC1Der,
             sizeof(_pkP256SEC1Der), NULL, 0);
    _UTRefuseDER(d.b, d.len);                                           /* EC key under RSA OID */
    _UTPKCS8(&d, 0u, _utOidEC, sizeof(_utOidEC), 0x06u, _utOidP256, sizeof(_utOidP256),
             _pkRSAPKCS1Der, sizeof(_pkRSAPKCS1Der), NULL, 0);
    _UTRefuseDER(d.b, d.len);                                           /* RSA key under EC OID */

    /* ======== PKCS#1 damage ======== */
    memcpy(d.b, _pkRSAPKCS1Der, sizeof(_pkRSAPKCS1Der));
    d.b[40] ^= 0x01u;                                                   /* inside the modulus */
    _UTRefuseDER(d.b, sizeof(_pkRSAPKCS1Der));

    /* ======== Framing: truncated, trailing bytes, garbage ======== */
    _UTRefuseDER(_pkP256SEC1Der, sizeof(_pkP256SEC1Der) - 1u);
    _UTRefuseDER(_pkP256PKCS8Der, sizeof(_pkP256PKCS8Der) - 1u);
    _UTRefuseDER(_pkRSAPKCS1Der, sizeof(_pkRSAPKCS1Der) - 1u);
    memcpy(d.b, _pkP256SEC1Der, sizeof(_pkP256SEC1Der));
    d.b[sizeof(_pkP256SEC1Der)] = 0x00u;
    _UTRefuseDER(d.b, sizeof(_pkP256SEC1Der) + 1u);
    memcpy(d.b, _pkEd25519PKCS8Der, sizeof(_pkEd25519PKCS8Der));
    d.b[sizeof(_pkEd25519PKCS8Der)] = 0x00u;
    _UTRefuseDER(d.b, sizeof(_pkEd25519PKCS8Der) + 1u);
    {
        static const uint8_t junk1[] = { 0x30, 0x00 };
        static const uint8_t junk2[] = { 0x30, 0x03, 0x02, 0x01, 0x00 };
        static const uint8_t junk3[] = { 0x04, 0x02, 0x00, 0x00 };
        _UTRefuseDER(junk1, sizeof(junk1));
        _UTRefuseDER(junk2, sizeof(junk2));
        _UTRefuseDER(junk3, sizeof(junk3));
    }

    /* ======== PEM refusals (key and the whole DER buffer wiped) ======== */
    _UTRefusePEM(_pkP256EncPem, strlen(_pkP256EncPem));                 /* encrypted PKCS#8 */
    n = (size_t)snprintf(pem, sizeof(pem), "%s%s", _pkP256SEC1Pem, _pkP256PKCS8Pem);
    _UTRefusePEM(pem, n);                                               /* two key blocks */
    n = (size_t)snprintf(pem, sizeof(pem), "%s%s", _pkP256PKCS8Pem, _pkP256EncPem);
    _UTRefusePEM(pem, n);                                               /* key + encrypted key */
    n = (size_t)snprintf(pem, sizeof(pem), "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n"
                         "-----END EC PARAMETERS-----\n");
    _UTRefusePEM(pem, n);                                               /* no key block */
    _UTRefusePEM("", 0);
    n = (size_t)snprintf(pem, sizeof(pem), "%s-----BEGIN X-----\nA*==\n-----END X-----\n",
                         _pkP256SEC1Pem);
    _UTRefusePEM(pem, n);                                               /* later block malformed */
    n = _UTPem(pem, sizeof(pem), "EC PRIVATE KEY", _pkP256PKCS8Der, sizeof(_pkP256PKCS8Der));
    _UTRefusePEM(pem, n);                                               /* label says SEC 1 */
    n = _UTPem(pem, sizeof(pem), "PRIVATE KEY", _pkP256SEC1Der, sizeof(_pkP256SEC1Der));
    _UTRefusePEM(pem, n);                                               /* label says PKCS#8 */
    n = _UTPem(pem, sizeof(pem), "RSA PRIVATE KEY", _pkP256SEC1Der, sizeof(_pkP256SEC1Der));
    _UTRefusePEM(pem, n);                                               /* label says PKCS#1 */
    n = _UTPem(pem, sizeof(pem), "PRIVATE KEY", _pkP256PKCS8Der, sizeof(_pkP256PKCS8Der));
    SSF_ASSERT(SSFPKeyDecodePEM(pem, n, buf, sizeof(buf), &key) == _UT_P256); /* control */
    {
        /* DER buffer too small: refused, buffer wiped */
        uint8_t small[64];
        memset(small, 0xAA, sizeof(small));
        memset(&key, 0xAA, sizeof(key));
        SSF_ASSERT(SSFPKeyDecodePEM(_pkP256PKCS8Pem, strlen(_pkP256PKCS8Pem), small, sizeof(small),
                                    &key) == false);
        SSF_ASSERT(_UTAllZero(small, sizeof(small)) && _UTAllZero(&key, sizeof(key)));
    }
    {
        /* A key block's DER that fails validation also wipes the buffer */
        uint8_t bad[sizeof(_pkP256SEC1Der)];
        memcpy(bad, _pkP256SEC1Der, sizeof(bad));
        bad[4] = 0x02u;                                                 /* SEC 1 version 2 */
        n = _UTPem(pem, sizeof(pem), "EC PRIVATE KEY", bad, sizeof(bad));
        _UTRefusePEM(pem, n);
    }
}
#endif /* SSF_CONFIG_PKEY_UNIT_TEST */
