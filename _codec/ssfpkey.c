/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfpkey.c                                                                                     */
/* Provides private key decoding: PKCS#8, SEC 1 and PKCS#1, in DER or PEM.                       */
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
#include <string.h>
#include "ssfassert.h"
#include "ssfpkey.h"
#include "ssfpem.h"
#include "ssfasn1.h"
#include "ssfcrypt.h"
#include "ssfecdsa.h"
#include "ssfed25519.h"
#include "ssfrsa.h"

/* --------------------------------------------------------------------------------------------- */
/* Local defines                                                                                 */
/* --------------------------------------------------------------------------------------------- */
#define SSF_PKEY_TAG_ATTRS   ((uint16_t)0xA0u) /* PKCS#8 attributes [0] IMPLICIT SET             */
#define SSF_PKEY_TAG_PKCS8PUB ((uint16_t)0x81u) /* OneAsymmetricKey publicKey [1] IMPLICIT BITS  */
#define SSF_PKEY_TAG_EC_CURVE ((uint16_t)0xA0u) /* ECPrivateKey parameters [0] EXPLICIT          */
#define SSF_PKEY_TAG_EC_PUB   ((uint16_t)0xA1u) /* ECPrivateKey publicKey [1] EXPLICIT           */

/* OID value bytes */
static const uint8_t _ssfPKeyOidRSA[] = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };
static const uint8_t _ssfPKeyOidEC[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t _ssfPKeyOidEd25519[] = { 0x2B, 0x65, 0x70 };
#if SSF_EC_CONFIG_ENABLE_P256 == 1
static const uint8_t _ssfPKeyOidP256[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
static const uint8_t _ssfPKeyOidP384[] = { 0x2B, 0x81, 0x04, 0x00, 0x22 };
#endif

/* --------------------------------------------------------------------------------------------- */
/* Returns true if the OID value oid[0..len) equals ref.                                         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFPKeyOidIs(const uint8_t *oid, uint32_t len, const uint8_t *ref, size_t refLen)
{
    return (len == refLen) && (memcmp(oid, ref, refLen) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Maps a named-curve OID to a key type; SSF_PKEY_TYPE_NONE if not an enabled curve.             */
/* --------------------------------------------------------------------------------------------- */
static SSFPKeyType_t _SSFPKeyCurveType(const uint8_t *oid, uint32_t len)
{
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    if (_SSFPKeyOidIs(oid, len, _ssfPKeyOidP256, sizeof(_ssfPKeyOidP256)))
    {
        return SSF_PKEY_TYPE_P256;
    }
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    if (_SSFPKeyOidIs(oid, len, _ssfPKeyOidP384, sizeof(_ssfPKeyOidP384)))
    {
        return SSF_PKEY_TYPE_P384;
    }
#endif
    (void)oid;
    (void)len;
    return SSF_PKEY_TYPE_NONE;
}

/* --------------------------------------------------------------------------------------------- */
/* Decodes a SEC 1 ECPrivateKey (RFC 5915). wrapperType is the curve named by an enclosing      */
/* PKCS#8 AlgorithmIdentifier, or SSF_PKEY_TYPE_NONE for a standalone key, which must name its    */
/* curve. Sets priv (left-padded to the curve size) and pub (derived; a public key in the file */
/* must equal it).                                                                               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFPKeyDecodeSEC1(const uint8_t *der, size_t derLen, SSFPKeyType_t wrapperType,
                               SSFPKey_t *key)
{
    SSFASN1Cursor_t cur = { der, (uint32_t)derLen };
    SSFASN1Cursor_t seq;
    SSFASN1Cursor_t ctx;
    SSFASN1Cursor_t next;
    uint64_t version;
    const uint8_t *scalar;
    uint32_t scalarLen;
    const uint8_t *oid;
    uint32_t oidLen;
    const uint8_t *pub = NULL;
    uint32_t pubLen = 0;
    uint8_t unused;
    uint16_t tag;
    SSFPKeyType_t type = wrapperType;
    SSFECCurve_t curve;
    size_t size;

    if (derLen > 0xFFFFFFFFu) return false;
    if (!SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &seq, &next)) return false;
    if (!SSFASN1DecIsEmpty(&next)) return false;
    if (!SSFASN1DecGetIntU64(&seq, &version, &seq) || (version != 1u)) return false;
    if (!SSFASN1DecGetOctetString(&seq, &scalar, &scalarLen, &seq)) return false;

    /* parameters [0] EXPLICIT: a named curve only */
    if (SSFASN1DecPeekTag(&seq, &tag) && (tag == SSF_PKEY_TAG_EC_CURVE))
    {
        if (!SSFASN1DecOpenConstructed(&seq, SSF_PKEY_TAG_EC_CURVE, &ctx, &seq)) return false;
        if (!SSFASN1DecGetOIDRaw(&ctx, &oid, &oidLen, &ctx) || !SSFASN1DecIsEmpty(&ctx))
        {
            return false;
        }
        type = _SSFPKeyCurveType(oid, oidLen);
        if ((type == SSF_PKEY_TYPE_NONE) ||
            ((wrapperType != SSF_PKEY_TYPE_NONE) && (type != wrapperType))) return false;
    }
    if (type == SSF_PKEY_TYPE_NONE) return false;

    /* publicKey [1] EXPLICIT BIT STRING */
    if (SSFASN1DecPeekTag(&seq, &tag) && (tag == SSF_PKEY_TAG_EC_PUB))
    {
        if (!SSFASN1DecOpenConstructed(&seq, SSF_PKEY_TAG_EC_PUB, &ctx, &seq)) return false;
        if (!SSFASN1DecGetBitString(&ctx, &pub, &pubLen, &unused, &ctx) || (unused != 0u) ||
            !SSFASN1DecIsEmpty(&ctx)) return false;
    }
    if (!SSFASN1DecIsEmpty(&seq)) return false;

    /* Scalar: at most the curve size; a short one (leading zeros dropped) is left-padded */
    curve = (type == SSF_PKEY_TYPE_P256) ? SSF_EC_CURVE_P256 : SSF_EC_CURVE_P384;
    size = (type == SSF_PKEY_TYPE_P256) ? 32u : 48u;
    if ((scalarLen == 0u) || (scalarLen > size)) return false;
    memcpy(&key->priv[size - scalarLen], scalar, scalarLen);
    key->privLen = size;

    /* Derive the public key (also checks 1 <= d <= n - 1); one in the file must match */
    if (!SSFECDSAPubKeyFromPrivKey(curve, key->priv, size, key->pub, sizeof(key->pub),
                                   &key->pubLen)) return false;
    if ((pub != NULL) && ((pubLen != key->pubLen) || (memcmp(pub, key->pub, pubLen) != 0)))
    {
        return false;
    }
    key->type = type;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Accepts a PKCS#1 RSAPrivateKey after full validation; the key points at der (zero copy).     */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFPKeyDecodePKCS1(const uint8_t *der, size_t derLen, SSFPKey_t *key)
{
    if (!SSFRSAPrivKeyIsValid(der, derLen)) return false;
    key->type = SSF_PKEY_TYPE_RSA;
    key->rsaDer = der;
    key->rsaDerLen = derLen;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Decodes PKCS#8 PrivateKeyInfo (v1) / OneAsymmetricKey (v2), RFC 5208 / RFC 5958.             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFPKeyDecodePKCS8(const uint8_t *der, size_t derLen, SSFPKey_t *key)
{
    SSFASN1Cursor_t cur = { der, (uint32_t)derLen };
    SSFASN1Cursor_t seq;
    SSFASN1Cursor_t alg;
    SSFASN1Cursor_t next;
    uint64_t version;
    const uint8_t *oid;
    uint32_t oidLen;
    const uint8_t *curveOid = NULL;
    uint32_t curveOidLen = 0;
    const uint8_t *inner;
    uint32_t innerLen;
    const uint8_t *pub = NULL;
    uint32_t pubLen = 0;
    uint16_t tag;
    bool isRSA;
    bool isEC;
    bool isEd;

    if (derLen > 0xFFFFFFFFu) return false;
    if (!SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &seq, &next)) return false;
    if (!SSFASN1DecIsEmpty(&next)) return false;
    if (!SSFASN1DecGetIntU64(&seq, &version, &seq) || (version > 1u)) return false;

    /* AlgorithmIdentifier: RSA with NULL, EC with a named curve, Ed25519 with nothing */
    if (!SSFASN1DecOpenConstructed(&seq, SSF_ASN1_TAG_SEQUENCE, &alg, &seq)) return false;
    if (!SSFASN1DecGetOIDRaw(&alg, &oid, &oidLen, &alg)) return false;
    isRSA = _SSFPKeyOidIs(oid, oidLen, _ssfPKeyOidRSA, sizeof(_ssfPKeyOidRSA));
    isEC = _SSFPKeyOidIs(oid, oidLen, _ssfPKeyOidEC, sizeof(_ssfPKeyOidEC));
    isEd = _SSFPKeyOidIs(oid, oidLen, _ssfPKeyOidEd25519, sizeof(_ssfPKeyOidEd25519));
    if (isRSA && !SSFASN1DecGetNull(&alg, &alg)) return false;
    if (isEC && !SSFASN1DecGetOIDRaw(&alg, &curveOid, &curveOidLen, &alg)) return false;
    if (!(isRSA || isEC || isEd) || !SSFASN1DecIsEmpty(&alg)) return false;

    if (!SSFASN1DecGetOctetString(&seq, &inner, &innerLen, &seq)) return false;

    /* attributes [0] are skipped; publicKey [1] only in v2 */
    if (SSFASN1DecPeekTag(&seq, &tag) && (tag == SSF_PKEY_TAG_ATTRS))
    {
        if (!SSFASN1DecSkip(&seq, &seq)) return false;
    }
    if (SSFASN1DecPeekTag(&seq, &tag) && (tag == SSF_PKEY_TAG_PKCS8PUB))
    {
        if ((version != 1u) ||
            !SSFASN1DecGetTLV(&seq, &tag, &pub, &pubLen, &seq) ||
            (pubLen < 1u) || (pub[0] != 0u)) return false;
        pub++;
        pubLen--;
    }
    if (!SSFASN1DecIsEmpty(&seq)) return false;

    if (isRSA)
    {
        /* A public key here cannot be checked without re-encoding it: refuse rather than ignore */
        if (pub != NULL) return false;
        return _SSFPKeyDecodePKCS1(inner, innerLen, key);
    }
    if (isEC)
    {
        SSFPKeyType_t type = _SSFPKeyCurveType(curveOid, curveOidLen);
        if (type == SSF_PKEY_TYPE_NONE) return false;
        if (!_SSFPKeyDecodeSEC1(inner, innerLen, type, key)) return false;
    }
    else
    {
        /* Ed25519: CurvePrivateKey ::= OCTET STRING (the 32-byte seed), RFC 8410 */
        SSFASN1Cursor_t c = { inner, innerLen };
        const uint8_t *seed;
        uint32_t seedLen;
        if (!SSFASN1DecGetOctetString(&c, &seed, &seedLen, &c) || !SSFASN1DecIsEmpty(&c) ||
            (seedLen != SSF_ED25519_SEED_SIZE)) return false;
        memcpy(key->priv, seed, SSF_ED25519_SEED_SIZE);
        key->privLen = SSF_ED25519_SEED_SIZE;
        SSFEd25519PubKeyFromSeed(key->priv, key->pub);
        key->pubLen = SSF_ED25519_PUB_KEY_SIZE;
        key->type = SSF_PKEY_TYPE_ED25519;
    }
    if ((pub != NULL) && ((pubLen != key->pubLen) || (memcmp(pub, key->pub, pubLen) != 0)))
    {
        return false;
    }
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Decodes an unencrypted private key in DER; see ssfpkey.h.                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFPKeyDecodeDER(const uint8_t *der, size_t derLen, SSFPKey_t *keyOut)
{
    SSFASN1Cursor_t cur;
    SSFASN1Cursor_t seq;
    SSFASN1Cursor_t next;
    uint64_t version;
    uint16_t tag;
    bool ok = false;

    SSF_REQUIRE(der != NULL);
    SSF_REQUIRE(keyOut != NULL);

    SSFPKeyWipe(keyOut);
    if (derLen > 0xFFFFFFFFu) return false;

    /* The element after the version tells the formats apart: AlgorithmIdentifier SEQUENCE   */
    /* (PKCS#8), privateKey OCTET STRING (SEC 1) or modulus INTEGER (PKCS#1).                  */
    cur.buf = der;
    cur.bufLen = (uint32_t)derLen;
    if (SSFASN1DecOpenConstructed(&cur, SSF_ASN1_TAG_SEQUENCE, &seq, &next) &&
        SSFASN1DecGetIntU64(&seq, &version, &seq) && SSFASN1DecPeekTag(&seq, &tag))
    {
        if (tag == SSF_ASN1_TAG_SEQUENCE) ok = _SSFPKeyDecodePKCS8(der, derLen, keyOut);
        else if (tag == SSF_ASN1_TAG_OCTET_STRING)
        {
            ok = _SSFPKeyDecodeSEC1(der, derLen, SSF_PKEY_TYPE_NONE, keyOut);
        }
        else if (tag == SSF_ASN1_TAG_INTEGER) ok = _SSFPKeyDecodePKCS1(der, derLen, keyOut);
    }
    if (!ok) SSFPKeyWipe(keyOut);
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Decodes the one private key block of a PEM buffer; see ssfpkey.h.                             */
/* --------------------------------------------------------------------------------------------- */
bool SSFPKeyDecodePEM(const char *pem, size_t pemLen, uint8_t *derBuf, size_t derBufSize,
                      SSFPKey_t *keyOut)
{
    size_t pos = 0;
    size_t keyPos = 0;
    size_t start;
    const char *label;
    size_t labelLen;
    size_t derLen;
    uint8_t format = 0;     /* 1 PKCS#8, 2 SEC 1, 3 PKCS#1 */
    uint8_t keyBlocks = 0;
    SSFPEMResult_t r;
    bool ok = false;

    SSF_REQUIRE(pem != NULL);
    SSF_REQUIRE(derBuf != NULL);
    SSF_REQUIRE(keyOut != NULL);

    SSFPKeyWipe(keyOut);

    /* Check every block and find the one key block without decoding the others */
    for (;;)
    {
        start = pos;
        r = SSFPEMDecodeNext(pem, pemLen, &pos, &label, &labelLen, NULL, 0, &derLen);
        if (r == SSF_PEM_END) break;
        if (r != SSF_PEM_BLOCK) goto done;
        if (SSFPEMLabelIs(label, labelLen, "ENCRYPTED PRIVATE KEY")) goto done;
        if (SSFPEMLabelIs(label, labelLen, "PRIVATE KEY")) format = 1;
        else if (SSFPEMLabelIs(label, labelLen, "EC PRIVATE KEY")) format = 2;
        else if (SSFPEMLabelIs(label, labelLen, "RSA PRIVATE KEY")) format = 3;
        else continue;
        keyPos = start;
        if (++keyBlocks > 1u) goto done;
    }
    if (keyBlocks != 1u) goto done;

    /* Decode the key block and parse it as its label says */
    pos = keyPos;
    if (SSFPEMDecodeNext(pem, pemLen, &pos, &label, &labelLen, derBuf, derBufSize, &derLen) !=
        SSF_PEM_BLOCK) goto done;
    if (format == 1u) ok = _SSFPKeyDecodePKCS8(derBuf, derLen, keyOut);
    else if (format == 2u) ok = _SSFPKeyDecodeSEC1(derBuf, derLen, SSF_PKEY_TYPE_NONE, keyOut);
    else ok = _SSFPKeyDecodePKCS1(derBuf, derLen, keyOut);

done:
    if (!ok)
    {
        SSFPKeyWipe(keyOut);
        if (derBufSize > 0u) SSFCryptSecureZero(derBuf, derBufSize);
    }
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Zeroes the whole key structure.                                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFPKeyWipe(SSFPKey_t *key)
{
    SSF_REQUIRE(key != NULL);

    SSFCryptSecureZero(key, sizeof(*key));
}
