/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfrsa.c                                                                                      */
/* Provides RSA digital signature (PKCS#1 v1.5, PSS) and key generation implementation.          */
/*                                                                                               */
/* RFC 8017: PKCS #1: RSA Cryptography Specifications Version 2.2                               */
/* FIPS 186-4: Digital Signature Standard (DSS)                                                  */
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
#include "ssfasn1.h"
#include "ssfsha2.h"
#include "ssfprng.h"
#include "ssfcrypt.h"

/* --------------------------------------------------------------------------------------------- */
/* Prime-candidate screening (small-prime trial division, Miller-Rabin, and the random-prime     */
/* generator) now lives in ssfbn. See SSFBNModUint32, SSFBNIsProbablePrime, SSFBNGenPrime.       */
/* --------------------------------------------------------------------------------------------- */

/* --------------------------------------------------------------------------------------------- */
/* DigestInfo DER prefixes for PKCS#1 v1.5 (RFC 8017 Section 9.2, Note 1).                      */
/* Each is SEQUENCE { SEQUENCE { OID hashAlg, NULL }, OCTET STRING length } without hash bytes.  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
static const uint8_t _ssfRSADigestInfoSHA256[] = {
    0x30u, 0x31u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
    0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x01u, 0x05u,
    0x00u, 0x04u, 0x20u
};
static const uint8_t _ssfRSADigestInfoSHA384[] = {
    0x30u, 0x41u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
    0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x02u, 0x05u,
    0x00u, 0x04u, 0x30u
};
static const uint8_t _ssfRSADigestInfoSHA512[] = {
    0x30u, 0x51u, 0x30u, 0x0Du, 0x06u, 0x09u, 0x60u, 0x86u,
    0x48u, 0x01u, 0x65u, 0x03u, 0x04u, 0x02u, 0x03u, 0x05u,
    0x00u, 0x04u, 0x40u
};
#define SSF_RSA_DIGEST_INFO_PREFIX_LEN (19u)
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */

/* --------------------------------------------------------------------------------------------- */
/* Internal: zero a byte buffer through a volatile pointer so the compiler cannot elide the      */
/* writes. Mirrors the pattern in SSFBNZeroize for non-SSFBN scratch (entropy buffers, byte      */
/* arrays).                                                                                       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFRSASecureWipe(void *buf, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len > 0u) { *p++ = 0u; len--; }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: scrub the deeper-stack region used by ssfbn primitives that ssfrsa just called.     */
/* SSFBNGcd, SSFBNDivMod, SSFBNModInv, SSFBNModInvExt, SSFBNModExp etc. all leave their internal */
/* SSFBN locals in their freed frames, and ssfrsa cannot reach into those frames to wipe them.   */
/* Calling this helper from sign / keygen cleanup allocates a fresh frame at the same depth      */
/* those primitives just vacated and overwrites it with zeros. The size is generous enough to    */
/* cover the deepest in-tree BN call chain (SSFBNModInvExt + helpers).                            */
/* --------------------------------------------------------------------------------------------- */
SSF_NOINLINE
static void _SSFRSAStackScrub(void)
{
    volatile uint8_t scratch[8192];
    size_t i;
    for (i = 0u; i < sizeof(scratch); i++) scratch[i] = 0u;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: convert an SSFBN-serialized magnitude into a strict-DER INTEGER body, in place.     */
/* ASN.1 INTEGER is signed two's-complement (X.690 §8.3.2): a positive magnitude whose leading   */
/* byte has bit 7 set must carry a single 0x00 padding byte. Strips leading zeros first so the   */
/* output is canonical regardless of how zero-padded the SSFBNToBytes output was. Caller must    */
/* size intBuf for at least magLen + 1 bytes to accommodate the optional padding byte.           */
/* All-zero magnitudes collapse to a single 0x00 byte (DER's canonical zero).                    */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFRSANormalizeMag(uint8_t *intBuf, size_t magLen)
{
    size_t i;

    for (i = 0; i < magLen && intBuf[i] == 0u; i++) {}
    if (i == magLen)
    {
        intBuf[0] = 0x00u;
        return 1u;
    }
    if (i > 0u)
    {
        memmove(intBuf, &intBuf[i], magLen - i);
        magLen -= i;
    }
    if ((intBuf[0] & 0x80u) != 0u)
    {
        memmove(&intBuf[1], intBuf, magLen);
        intBuf[0] = 0x00u;
        magLen += 1u;
    }
    return magLen;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: read the next ASN.1 INTEGER under cursor and import it into bn at the requested    */
/* limb width, stripping the leading 0x00 sign byte (or any spurious leading zeros) so that      */
/* magnitudes that are exactly limbs*4 bytes long round-trip even when the producer emitted the  */
/* canonical positive-INTEGER 0x00 prefix. Returns false on any structural or sizing error.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSADecIntToBN(const SSFASN1Cursor_t *cursor, SSFBN_t *bn, uint16_t limbs,
                              SSFASN1Cursor_t *next)
{
    const uint8_t *buf;
    uint32_t bufLen;

    if (!SSFASN1DecGetInt(cursor, &buf, &bufLen, next)) return false;
    while (bufLen > 0u && *buf == 0u) { buf++; bufLen--; }
    return SSFBNFromBytes(bn, buf, bufLen, limbs);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: hash output size for the given hash algorithm.                                      */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFRSAGetHashSize(SSFRSAHash_t hash)
{
    switch (hash)
    {
    case SSF_RSA_HASH_SHA256: return 32u;
    case SSF_RSA_HASH_SHA384: return 48u;
    case SSF_RSA_HASH_SHA512: return 64u;
    default: SSF_ASSERT(false); return 0;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: compute hash using incremental API (for MGF1 and PSS).                              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFRSAHashBeginUpdateEnd(SSFRSAHash_t hash,
                                      const uint8_t *d1, size_t d1Len,
                                      const uint8_t *d2, size_t d2Len,
                                      uint8_t *out, size_t outSize)
{
    switch (hash)
    {
    case SSF_RSA_HASH_SHA256:
    {
        SSFSHA2_32Context_t ctx;
        SSFSHA256Begin(&ctx);
        if (d1 != NULL) SSFSHA256Update(&ctx, d1, (uint32_t)d1Len);
        if (d2 != NULL) SSFSHA256Update(&ctx, d2, (uint32_t)d2Len);
        SSFSHA256End(&ctx, out, (uint32_t)outSize);
        break;
    }
    case SSF_RSA_HASH_SHA384:
    {
        SSFSHA2_64Context_t ctx;
        SSFSHA384Begin(&ctx);
        if (d1 != NULL) SSFSHA384Update(&ctx, d1, (uint32_t)d1Len);
        if (d2 != NULL) SSFSHA384Update(&ctx, d2, (uint32_t)d2Len);
        SSFSHA384End(&ctx, out, (uint32_t)outSize);
        break;
    }
    case SSF_RSA_HASH_SHA512:
    {
        SSFSHA2_64Context_t ctx;
        SSFSHA512Begin(&ctx);
        if (d1 != NULL) SSFSHA512Update(&ctx, d1, (uint32_t)d1Len);
        if (d2 != NULL) SSFSHA512Update(&ctx, d2, (uint32_t)d2Len);
        SSFSHA512End(&ctx, out, (uint32_t)outSize);
        break;
    }
    default: SSF_ASSERT(false); break;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-encode an RSA public key: SEQUENCE { INTEGER n, INTEGER e }.                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAPubKeyEncode(const SSFBN_t *n, const SSFBN_t *e,
                                uint8_t *der, size_t derSize, size_t *derLen)
{
    size_t nBytes = (size_t)n->len * sizeof(SSFBNLimb_t);
    size_t eBytes = (size_t)e->len * sizeof(SSFBNLimb_t);
    uint8_t nBuf[SSF_BN_MAX_BYTES + 1u];
    uint8_t eBuf[SSF_BN_MAX_BYTES + 1u];
    uint32_t nEncLen, eEncLen, contentLen, seqHdrLen, offset;

    if (!SSFBNToBytes(n, nBuf, nBytes)) return false;
    if (!SSFBNToBytes(e, eBuf, eBytes)) return false;

    nBytes = _SSFRSANormalizeMag(nBuf, nBytes);
    eBytes = _SSFRSANormalizeMag(eBuf, eBytes);

    if (!SSFASN1EncInt(NULL, 0, nBuf, (uint32_t)nBytes, &nEncLen)) return false;
    if (!SSFASN1EncInt(NULL, 0, eBuf, (uint32_t)eBytes, &eEncLen)) return false;

    contentLen = nEncLen + eEncLen;
    if (!SSFASN1EncTagLen(NULL, 0, SSF_ASN1_TAG_SEQUENCE, contentLen, &seqHdrLen)) return false;

    if ((size_t)(seqHdrLen + contentLen) > derSize) return false;

    {
        uint32_t wrLen;
        if (!SSFASN1EncTagLen(der, (uint32_t)derSize, SSF_ASN1_TAG_SEQUENCE, contentLen, &wrLen))
        {
            return false;
        }
        offset = wrLen;
        if (!SSFASN1EncInt(&der[offset], (uint32_t)(derSize - offset), nBuf,
                           (uint32_t)nBytes, &wrLen))
        {
            return false;
        }
        offset += wrLen;
        if (!SSFASN1EncInt(&der[offset], (uint32_t)(derSize - offset), eBuf,
                           (uint32_t)eBytes, &wrLen))
        {
            return false;
        }
        offset += wrLen;
    }

    *derLen = (size_t)offset;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-decode an RSA public key.                                                       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAPubKeyDecode(const uint8_t *der, size_t derLen,
                                SSFBN_t *n, SSFBN_t *e, uint16_t *keyLimbs)
{
    SSFASN1Cursor_t cursor, inner, next;
    const uint8_t *nBuf, *eBuf;
    uint32_t nLen, eLen;
    uint16_t limbs;

    cursor.buf = der;
    cursor.bufLen = (uint32_t)derLen;

    if (!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &inner, &next)) return false;
    if (!SSFASN1DecGetInt(&inner, &nBuf, &nLen, &next)) return false;
    if (!SSFASN1DecGetInt(&next, &eBuf, &eLen, &next)) return false;

    /* Determine limb count from n's byte length (skip leading zeros) */
    {
        const uint8_t *nb = nBuf;
        uint32_t nl = nLen;
        while (nl > 0u && *nb == 0u) { nb++; nl--; }
        limbs = (uint16_t)SSF_BN_BITS_TO_LIMBS(nl * 8u);
    }

    /* Strip leading zeros before importing (ASN.1 INTEGER may have a leading 0x00 for
       positive sign, which makes nLen one byte larger than the limb capacity) */
    {
        const uint8_t *nb = nBuf;
        uint32_t nl = nLen;
        while (nl > 0u && *nb == 0u) { nb++; nl--; }
        if (!SSFBNFromBytes(n, nb, nl, limbs)) return false;
    }
    {
        const uint8_t *eb = eBuf;
        uint32_t el = eLen;
        while (el > 0u && *eb == 0u) { eb++; el--; }
        if (!SSFBNFromBytes(e, eb, el, limbs)) return false;
    }

    *keyLimbs = limbs;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-encode an RSA private key (PKCS#1 RSAPrivateKey, 9 INTEGERs).                  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
static bool _SSFRSAPrivKeyEncode(const SSFBN_t *n, const SSFBN_t *e, const SSFBN_t *d,
                                 const SSFBN_t *p, const SSFBN_t *q,
                                 const SSFBN_t *dp, const SSFBN_t *dq, const SSFBN_t *qInv,
                                 uint8_t *der, size_t derSize, size_t *derLen)
{
    uint8_t buf[SSF_BN_MAX_BYTES + 1u];
    uint32_t encLens[9];
    uint32_t contentLen = 0;
    uint32_t seqHdrLen;
    uint32_t offset;
    uint32_t i;

    /* Fields: version=0, n, e, d, p, q, dp, dq, qInv */
    const SSFBN_t *fields[] = { NULL, n, e, d, p, q, dp, dq, qInv };
    size_t fieldBytes[9];

    /* Version = 0 */
    if (!SSFASN1EncIntU64(NULL, 0, 0, &encLens[0])) return false;
    contentLen += encLens[0];

    for (i = 1; i < 9u; i++)
    {
        size_t magLen = (size_t)fields[i]->len * sizeof(SSFBNLimb_t);
        if (!SSFBNToBytes(fields[i], buf, magLen)) return false;
        fieldBytes[i] = _SSFRSANormalizeMag(buf, magLen);
        if (!SSFASN1EncInt(NULL, 0, buf, (uint32_t)fieldBytes[i], &encLens[i])) return false;
        contentLen += encLens[i];
    }

    if (!SSFASN1EncTagLen(NULL, 0, SSF_ASN1_TAG_SEQUENCE, contentLen, &seqHdrLen)) return false;
    if ((size_t)(seqHdrLen + contentLen) > derSize) return false;

    /* Encode */
    {
        uint32_t wrLen;
        if (!SSFASN1EncTagLen(der, (uint32_t)derSize, SSF_ASN1_TAG_SEQUENCE, contentLen, &wrLen))
        {
            return false;
        }
        offset = wrLen;
        if (!SSFASN1EncIntU64(&der[offset], (uint32_t)(derSize - offset), 0, &wrLen)) return false;
        offset += wrLen;

        for (i = 1; i < 9u; i++)
        {
            size_t magLen = (size_t)fields[i]->len * sizeof(SSFBNLimb_t);
            (void)SSFBNToBytes(fields[i], buf, magLen);
            (void)_SSFRSANormalizeMag(buf, magLen); /* fieldBytes[i] computed in pass 1 */
            if (!SSFASN1EncInt(&der[offset], (uint32_t)(derSize - offset),
                               buf, (uint32_t)fieldBytes[i], &wrLen))
            {
                return false;
            }
            offset += wrLen;
        }
    }

    *derLen = (size_t)offset;
    return true;
}
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-decode an RSA private key (PKCS#1 RSAPrivateKey).                               */
/* Extracts n, d, p, q, dp, dq, qInv for CRT operations.                                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAPrivKeyDecode(const uint8_t *der, size_t derLen,
                                 SSFBN_t *n, SSFBN_t *e, SSFBN_t *d,
                                 SSFBN_t *p, SSFBN_t *q,
                                 SSFBN_t *dp, SSFBN_t *dq, SSFBN_t *qInv,
                                 uint16_t *nLimbs)
{
    SSFASN1Cursor_t cursor, inner, next, peek;
    const uint8_t *buf;
    uint32_t bufLen;
    uint64_t version;
    uint16_t nl, hl;

    cursor.buf = der;
    cursor.bufLen = (uint32_t)derLen;

    if (!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &inner, &next)) return false;

    /* version */
    if (!SSFASN1DecGetIntU64(&inner, &version, &next)) return false;
    if (version != 0u) return false;

    /* n: peek to derive nl from the magnitude length, then import via the helper. */
    peek = next;
    if (!SSFASN1DecGetInt(&peek, &buf, &bufLen, &peek)) return false;
    while (bufLen > 0u && *buf == 0u) { buf++; bufLen--; }
    nl = (uint16_t)SSF_BN_BITS_TO_LIMBS(bufLen * 8u);
    if (!_SSFRSADecIntToBN(&next, n, nl, &next)) return false;

    /* e, d are loaded at full key width. */
    if (!_SSFRSADecIntToBN(&next, e, nl, &next)) return false;
    if (!_SSFRSADecIntToBN(&next, d, nl, &next)) return false;

    /* p: peek to derive hl from the magnitude length. */
    peek = next;
    if (!SSFASN1DecGetInt(&peek, &buf, &bufLen, &peek)) return false;
    while (bufLen > 0u && *buf == 0u) { buf++; bufLen--; }
    hl = (uint16_t)SSF_BN_BITS_TO_LIMBS(bufLen * 8u);
    if (!_SSFRSADecIntToBN(&next, p, hl, &next)) return false;

    /* q, dp, dq, qInv are loaded at half-key width. */
    if (!_SSFRSADecIntToBN(&next, q, hl, &next)) return false;
    if (!_SSFRSADecIntToBN(&next, dp, hl, &next)) return false;
    if (!_SSFRSADecIntToBN(&next, dq, hl, &next)) return false;
    if (!_SSFRSADecIntToBN(&next, qInv, hl, &next)) return false;

    *nLimbs = nl;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: RSA public-key operation: result = m^e mod n.                                       */
/* All three operands (m, e, n) are public: m is the signature/ciphertext, e and n form the      */
/* public key. Variable-time ModExp is side-channel-safe here and 2-3x faster than the constant- */
/* time ladder for the typical low-Hamming-weight public exponents (3, 17, 65537).               */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAPublicOp(const SSFBN_t *m, const SSFBN_t *e, const SSFBN_t *n,
                            SSFBN_t *result)
{
    if (SSFBNCmp(m, n) >= 0) return false;
    SSFBNModExpPub(result, m, e, n);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: RSA private-key operation using CRT.                                                */
/* m1 = c^dp mod p, m2 = c^dq mod q, h = qInv*(m1-m2) mod p, result = m2 + h*q                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAPrivateOpCRT(const SSFBN_t *c, uint16_t nLimbs,
                                const SSFBN_t *p, const SSFBN_t *q,
                                const SSFBN_t *dp, const SSFBN_t *dq,
                                const SSFBN_t *qInv,
                                SSFBN_t *result)
{
    /* Flat declarations (vs. nested scopes) so the cleanup section can wipe every local on the */
    /* return path. Each of these carries information about the secret factors p, q or the      */
    /* secret CRT exponents dp, dq, so leaving them in the freed frame would be a hygiene leak. */
    SSFBN_DEFINE(cp, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(cq, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m2, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(h, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m2Full, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(hFull, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(qFull, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
    uint16_t hl = p->len;

    /* cp = c mod p, cq = c mod q */
    SSFBNMod(&cp, c, p);
    SSFBNMod(&cq, c, q);

    /* m1 = cp^dp mod p */
    SSFBNModExp(&m1, &cp, dp, p);

    /* m2 = cq^dq mod q */
    SSFBNModExp(&m2, &cq, dq, q);

    /* h = qInv * (m1 - m2) mod p */
    if (SSFBNCmp(&m1, &m2) >= 0)
    {
        SSFBNSub(&h, &m1, &m2);
    }
    else
    {
        /* m1 < m2: compute (m1 + p - m2) to avoid underflow */
        SSFBNSub(&h, &m2, &m1);
        SSFBNSub(&h, p, &h);
    }
    SSFBNModMul(&h, qInv, &h, p);

    /* Expand half-width values to full n-width. */
    SSFBNSetZero(&m2Full, nLimbs);
    memcpy(m2Full.limbs, m2.limbs, (size_t)hl * sizeof(SSFBNLimb_t));
    SSFBNSetZero(&hFull, nLimbs);
    memcpy(hFull.limbs, h.limbs, (size_t)hl * sizeof(SSFBNLimb_t));
    SSFBNSetZero(&qFull, nLimbs);
    memcpy(qFull.limbs, q->limbs, (size_t)hl * sizeof(SSFBNLimb_t));

    /* result = (h * q) + m2 (in full n-width). */
    SSFBNMul(&prod, &hFull, &qFull);
    result->len = nLimbs;
    memcpy(result->limbs, prod.limbs, (size_t)nLimbs * sizeof(SSFBNLimb_t));
    SSFBNAdd(result, result, &m2Full);

    SSFBNZeroize(&cp);
    SSFBNZeroize(&cq);
    SSFBNZeroize(&m1);
    SSFBNZeroize(&m2);
    SSFBNZeroize(&h);
    SSFBNZeroize(&m2Full);
    SSFBNZeroize(&hFull);
    SSFBNZeroize(&qFull);
    SSFBNZeroize(&prod);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* FIPS 186-4 §B.3 keygen post-condition checks.                                                 */
/* --------------------------------------------------------------------------------------------- */
bool SSFRSAFipsPrimeDistanceOK(const SSFBN_t *p, const SSFBN_t *q, uint16_t halfBits)
{
    SSFBN_DEFINE(diff, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->limbs != NULL);
    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(q->limbs != NULL);
    SSF_REQUIRE(halfBits > 100u);

    if (SSFBNCmp(p, q) >= 0)
    {
        (void)SSFBNSub(&diff, p, q);
    }
    else
    {
        (void)SSFBNSub(&diff, q, p);
    }
    /* bitLen(diff) > halfBits - 100 ⇔ diff >= 2^(halfBits - 100). Random primes clear this by  */
    /* a wide margin; the explicit guard is for defense in depth and FIPS conformance.          */
    return SSFBNBitLen(&diff) > (uint32_t)(halfBits - 100u);
}

bool SSFRSAFipsDLowerBoundOK(const SSFBN_t *d, uint16_t halfBits)
{
    SSF_REQUIRE(d != NULL);
    SSF_REQUIRE(d->limbs != NULL);
    SSF_REQUIRE(halfBits > 0u);
    /* bitLen(d) > halfBits ⇔ d >= 2^halfBits. Strict-> per spec; matters only at the boundary  */
    /* which random d never hits.                                                               */
    return SSFBNBitLen(d) > (uint32_t)halfBits;
}

bool SSFRSAFipsECoprimeOK(const SSFBN_t *e, const SSFBN_t *pMinus1, const SSFBN_t *qMinus1)
{
    SSFBN_DEFINE(eW, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(xW, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(g, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(e->limbs != NULL);
    SSF_REQUIRE(pMinus1 != NULL);
    SSF_REQUIRE(pMinus1->limbs != NULL);
    SSF_REQUIRE(qMinus1 != NULL);
    SSF_REQUIRE(qMinus1->limbs != NULL);

    /* SSFBNGcd requires equal-len operands. Keygen passes e at full key width and (p-1)/(q-1)  */
    /* at half-key width, so widen each pair into a shared SSF_BN_MAX_LIMBS scratch first.       */
    SSFBNSetZero(&eW, SSF_BN_MAX_LIMBS);
    memcpy(eW.limbs, e->limbs, (size_t)e->len * sizeof(SSFBNLimb_t));

    SSFBNSetZero(&xW, SSF_BN_MAX_LIMBS);
    memcpy(xW.limbs, pMinus1->limbs, (size_t)pMinus1->len * sizeof(SSFBNLimb_t));
    SSFBNGcd(&g, &eW, &xW);
    if (!SSFBNIsOne(&g)) return false;

    SSFBNSetZero(&xW, SSF_BN_MAX_LIMBS);
    memcpy(xW.limbs, qMinus1->limbs, (size_t)qMinus1->len * sizeof(SSFBNLimb_t));
    SSFBNGcd(&g, &eW, &xW);
    if (!SSFBNIsOne(&g)) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: validate decoded (n, e). Used by both SSFRSAPubKeyIsValid and SSFRSAPrivKeyIsValid  */
/* so the public-side rules stay in one place.                                                    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAValidatePubFields(const SSFBN_t *n, const SSFBN_t *e)
{
    uint32_t nBits;

    /* n: odd, > 1, and at one of the supported bit lengths. The exact-set check also implies   */
    /* the high bit of the leading byte is set (for 2048/3072/4096 which are byte-aligned), so  */
    /* a degenerate modulus with leading zero bits is rejected here.                             */
    if (SSFBNIsEven(n)) return false;
    if (SSFBNIsOne(n)) return false;
    nBits = SSFBNBitLen(n);
    if ((nBits != 2048u) && (nBits != 3072u) && (nBits != 4096u)) return false;
    if (nBits > SSF_BN_CONFIG_MAX_BITS) return false;

    /* e: odd, ≥ 65537 (rejects e=3, e=17 small-exponent classes per FIPS 186-4 §B.3.1), < n.   */
    if (SSFBNIsEven(e)) return false;
    if (SSFBNBitLen(e) < 17u) return false;          /* 65537 has bitLen 17, anything smaller fails */
    if (SSFBNCmp(e, n) >= 0) return false;

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Validate a DER-encoded RSA public key.                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFRSAPubKeyIsValid(const uint8_t *pubKeyDer, size_t pubKeyDerLen)
{
    SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
    uint16_t keyLimbs;

    SSF_REQUIRE(pubKeyDer != NULL);
    SSF_REQUIRE(pubKeyDerLen > 0u);

    if (!_SSFRSAPubKeyDecode(pubKeyDer, pubKeyDerLen, &n, &e, &keyLimbs)) return false;
    return _SSFRSAValidatePubFields(&n, &e);
}

/* --------------------------------------------------------------------------------------------- */
/* Validate a DER-encoded RSA private key.                                                       */
/* --------------------------------------------------------------------------------------------- */
bool SSFRSAPrivKeyIsValid(const uint8_t *privKeyDer, size_t privKeyDerLen)
{
    SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(d, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(q, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(dp, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(dq, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(qInv, SSF_BN_MAX_LIMBS);
    uint16_t nLimbs;

    SSF_REQUIRE(privKeyDer != NULL);
    SSF_REQUIRE(privKeyDerLen > 0u);

    if (!_SSFRSAPrivKeyDecode(privKeyDer, privKeyDerLen, &n, &e, &d,
                              &p, &q, &dp, &dq, &qInv, &nLimbs)) return false;

    /* Public-side rules (n size, e bounds, e < n). */
    if (!_SSFRSAValidatePubFields(&n, &e)) return false;

    /* d, p, q must be odd and > 1. */
    if (SSFBNIsZero(&d) || SSFBNIsOne(&d)) return false;
    if (SSFBNIsEven(&p) || SSFBNIsOne(&p)) return false;
    if (SSFBNIsEven(&q) || SSFBNIsOne(&q)) return false;

    /* n == p * q. Both p and q have len = nLimbs/2, so p*q has len = nLimbs and matches n.     */
    {
        SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
        SSFBNMul(&prod, &p, &q);
        if (prod.len != n.len) return false;
        if (SSFBNCmp(&prod, &n) != 0) return false;
    }

    /* dp == d mod (p - 1). */
    {
        SSFBN_DEFINE(pm1, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);
        (void)SSFBNSubUint32(&pm1, &p, 1u);
        SSFBNMod(&check, &d, &pm1);
        if (SSFBNCmp(&check, &dp) != 0) return false;
    }

    /* dq == d mod (q - 1). */
    {
        SSFBN_DEFINE(qm1, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);
        (void)SSFBNSubUint32(&qm1, &q, 1u);
        SSFBNMod(&check, &d, &qm1);
        if (SSFBNCmp(&check, &dq) != 0) return false;
    }

    /* qInv * q ≡ 1 (mod p). qInv, q, p all have len = nLimbs/2 — SSFBNModMul-compatible.       */
    {
        SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
        SSFBNModMul(&prod, &qInv, &q, &p);
        if (!SSFBNIsOne(&prod)) return false;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* RSA key generation.                                                                           */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_KEYGEN == 1
/* --------------------------------------------------------------------------------------------- */
/* KeyGen stage 1: seed PRNG from platform entropy, generate two distinct primes p and q (with    */
/* p > q so CRT works as expected), and compute n = p * q. The PRNG context, entropy buffer, the  */
/* swap temp and the n-product temp all live in this helper's frame and are released on return,  */
/* so they don't coexist with the lambda / ModInv working state in stage 2.                       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAKeyGenPrimes(uint16_t bits,
                                SSFBN_t *p, SSFBN_t *q, SSFBN_t *n,
                                uint16_t *nLimbsOut)
{
    SSFPRNGContext_t prng;
    uint8_t entropy[SSF_PRNG_ENTROPY_SIZE];
    uint16_t halfBits;
    uint16_t nLimbs;
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
    bool ok = false;

    halfBits = bits / 2u;
    nLimbs = (uint16_t)SSF_BN_BITS_TO_LIMBS(bits);
    *nLimbsOut = nLimbs;

    if (!SSFPortGetEntropy(entropy, (uint16_t)sizeof(entropy))) goto cleanup;
    SSFPRNGInitContext(&prng, entropy, sizeof(entropy));

    if (!SSFBNGenPrime(p, halfBits, SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS, &prng)) goto cleanup_prng;
    if (!SSFBNGenPrime(q, halfBits, SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS, &prng)) goto cleanup_prng;

    /* Ensure p != q */
    if (SSFBNCmp(p, q) == 0) goto cleanup_prng;

    /* Ensure p > q (for CRT). tmp briefly holds the original p — secret-adjacent state. */
    if (SSFBNCmp(p, q) < 0)
    {
        SSFBNCopy(&tmp, p);
        SSFBNCopy(p, q);
        SSFBNCopy(q, &tmp);
    }

    /* n = p * q */
    SSFBNMul(&prod, p, q);
    n->len = nLimbs;
    memcpy(n->limbs, prod.limbs, (size_t)nLimbs * sizeof(SSFBNLimb_t));

    ok = true;

cleanup_prng:
    SSFPRNGDeInitContext(&prng);
cleanup:
    /* Wipe the raw entropy buffer (PRNG context's copy is wiped by DeInit; this is the source  */
    /* copy on the stack) and the tmp/prod scratch BNs that briefly held p, q, or p·q.          */
    _SSFRSASecureWipe(entropy, sizeof(entropy));
    SSFBNZeroize(&tmp);
    SSFBNZeroize(&prod);
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* KeyGen stage 2: given p, q, derive d (private exponent), dp, dq, qInv (CRT parameters).        */
/* Local pm1, qm1, g, lambda and the division-loop working state live here and are released on    */
/* return, so they don't overlap with the MillerRabin chain of stage 1 or the DER-encoding of     */
/* stage 3. Any secret intermediates (lambda is derived from p, q) are zeroised before return.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAKeyGenDerive(uint16_t nLimbs,
                                const SSFBN_t *p, const SSFBN_t *q,
                                SSFBN_t *d, SSFBN_t *dp, SSFBN_t *dq, SSFBN_t *qInv)
{
    SSFBN_DEFINE(pm1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(qm1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(g, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(lambda, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(eFull, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(pm1_div, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(rem, SSF_BN_MAX_LIMBS);
    bool ok = false;

    /* pm1 = p - 1, qm1 = q - 1 */
    (void)SSFBNSubUint32(&pm1, p, 1u);
    (void)SSFBNSubUint32(&qm1, q, 1u);

    /* Explicit FIPS check: e ⊥ (p-1) and e ⊥ (q-1). Fails fast before λ compute on the rare    */
    /* case where 65537 divides p-1 or q-1 (caller retries with fresh primes).                   */
    SSFBNSetUint32(&eFull, 65537u, nLimbs);
    if (!SSFRSAFipsECoprimeOK(&eFull, &pm1, &qm1)) goto cleanup;

    /* g = gcd(pm1, qm1) */
    SSFBNGcd(&g, &pm1, &qm1);

    /* lambda = lcm(pm1, qm1) = (pm1 / gcd) * qm1 — the division-by-large-numbers form avoids   */
    /* needing to divide pm1 * qm1 by g, which wouldn't fit in our fixed-width SSFBN_t.          */
    if (SSFBNIsOne(&g))
    {
        /* Common case: skip the divide — lambda = pm1 * qm1 directly. */
        SSFBNCopy(&pm1_div, &pm1);
    }
    else
    {
        SSFBNDivMod(&pm1_div, &rem, &pm1, &g);
    }
    SSFBNMul(&prod, &pm1_div, &qm1);
    lambda.len = nLimbs;
    memcpy(lambda.limbs, prod.limbs, (size_t)nLimbs * sizeof(SSFBNLimb_t));

    /* d = 65537^(-1) mod lambda. */
    if (!SSFBNModInvExt(d, &eFull, &lambda)) goto cleanup;

    /* CRT parameters. */
    SSFBNMod(dp, d, &pm1);
    SSFBNMod(dq, d, &qm1);

    /* qInv = q^(-1) mod p (p is prime, so Fermat works). */
    if (!SSFBNModInv(qInv, q, p)) goto cleanup;

    ok = true;

cleanup:
    /* All locals are derived from the secret primes (pm1, qm1, lambda, pm1_div, prod, rem) or  */
    /* are arithmetic temporaries that touched the secret λ(n) (g, eFull). Wipe every one so    */
    /* the freed frame is clean regardless of which return path we took, then scrub the deeper- */
    /* stack region used by SSFBNGcd / SSFBNDivMod / SSFBNModInvExt / SSFBNModInv internals.    */
    SSFBNZeroize(&pm1);
    SSFBNZeroize(&qm1);
    SSFBNZeroize(&g);
    SSFBNZeroize(&lambda);
    SSFBNZeroize(&eFull);
    SSFBNZeroize(&pm1_div);
    SSFBNZeroize(&prod);
    SSFBNZeroize(&rem);
    _SSFRSAStackScrub();
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* KeyGen stage 3: encode (n, e) and (n, e, d, p, q, dp, dq, qInv) as PKCS#1 DER. Local e lives   */
/* only here; everything else is caller-owned and passed by const pointer.                        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAKeyGenEncode(const SSFBN_t *n, const SSFBN_t *d,
                                const SSFBN_t *p, const SSFBN_t *q,
                                const SSFBN_t *dp, const SSFBN_t *dq, const SSFBN_t *qInv,
                                uint16_t nLimbs,
                                uint8_t *privKeyDer, size_t privKeyDerSize, size_t *privKeyDerLen,
                                uint8_t *pubKeyDer,  size_t pubKeyDerSize,  size_t *pubKeyDerLen)
{
    SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);

    SSFBNSetUint32(&e, 65537u, nLimbs);

    if (!_SSFRSAPubKeyEncode(n, &e, pubKeyDer, pubKeyDerSize, pubKeyDerLen)) return false;
    if (!_SSFRSAPrivKeyEncode(n, &e, d, p, q, dp, dq, qInv,
                              privKeyDer, privKeyDerSize, privKeyDerLen)) return false;
    return true;
}

/* Cap the prime+derive retry budget. The FIPS post-conditions (|p-q|, d-lower-bound, e-coprime) */
/* almost never reject random candidates — a healthy run completes in attempts == 1. The cap is  */
/* purely a guard against pathological loops if entropy or the BN layer goes sideways.           */
#define SSF_RSA_KEYGEN_FIPS_MAX_ATTEMPTS (8u)

bool SSFRSAKeyGen(uint16_t bits,
                  uint8_t *privKeyDer, size_t privKeyDerSize, size_t *privKeyDerLen,
                  uint8_t *pubKeyDer, size_t pubKeyDerSize, size_t *pubKeyDerLen)
{
    SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(q, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(d, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(dp, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(dq, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(qInv, SSF_BN_MAX_LIMBS);
    uint16_t nLimbs;
    uint16_t halfBits;
    uint32_t attempts;
    bool ok = false;

    SSF_REQUIRE(privKeyDer != NULL);
    SSF_REQUIRE(pubKeyDer != NULL);
    SSF_REQUIRE(privKeyDerLen != NULL);
    SSF_REQUIRE(pubKeyDerLen != NULL);
    SSF_REQUIRE(bits == 2048u || bits == 3072u || bits == 4096u);
    SSF_REQUIRE(bits <= SSF_BN_CONFIG_MAX_BITS);
    SSF_REQUIRE(privKeyDerSize >= SSF_RSA_MAX_PRIV_KEY_DER_SIZE);
    SSF_REQUIRE(pubKeyDerSize >= SSF_RSA_MAX_PUB_KEY_DER_SIZE);

    halfBits = bits / 2u;
    ok = false;

    /* FIPS 186-4 §B.3.3 step 5: if a candidate fails any post-condition, regenerate the prime  */
    /* pair and retry. Each retry is a full prime-pair regeneration (the most defensive option  */
    /* — finer-grained retry of just q on |p-q| failure is the pure-spec form, but the win is   */
    /* irrelevant when the rejection rate is ~2^-100 per check).                                 */
    for (attempts = 0u; attempts < SSF_RSA_KEYGEN_FIPS_MAX_ATTEMPTS; attempts++)
    {
        /* Hard failure (no entropy, etc.) — don't retry. */
        if (!_SSFRSAKeyGenPrimes(bits, &p, &q, &n, &nLimbs)) goto cleanup;

        /* §B.3.3 step 5.4: |p - q| > 2^(halfBits - 100). */
        if (!SSFRSAFipsPrimeDistanceOK(&p, &q, halfBits)) continue;

        /* Soft failure inside Derive (e ⊥ λ(n) violated, or modular-inverse instability).      */
        /* Both are retriable per FIPS — fresh primes give a fresh λ(n).                         */
        if (!_SSFRSAKeyGenDerive(nLimbs, &p, &q, &d, &dp, &dq, &qInv)) continue;

        /* §B.3.1: d > 2^halfBits, defending against Wiener. */
        if (!SSFRSAFipsDLowerBoundOK(&d, halfBits)) continue;

        ok = true;
        break;
    }
    if (!ok) goto cleanup;

    if (!_SSFRSAKeyGenEncode(&n, &d, &p, &q, &dp, &dq, &qInv, nLimbs,
                             privKeyDer, privKeyDerSize, privKeyDerLen,
                             pubKeyDer,  pubKeyDerSize,  pubKeyDerLen))
    {
        ok = false;
        goto cleanup;
    }

cleanup:
    /* Wipe every secret-bearing local on every return path (success or any failure). n is the */
    /* public modulus so it isn't in the wipe list, but everything else carries information     */
    /* about the secret factors and must be cleared. The stack scrub then overwrites the deeper */
    /* frames left behind by Primes / Derive / Encode so BN-internal scratch doesn't survive.   */
    SSFBNZeroize(&d);
    SSFBNZeroize(&p);
    SSFBNZeroize(&q);
    SSFBNZeroize(&dp);
    SSFBNZeroize(&dq);
    SSFBNZeroize(&qInv);
    _SSFRSAStackScrub();
    return ok;
}
#endif /* SSF_RSA_CONFIG_ENABLE_KEYGEN */

/* --------------------------------------------------------------------------------------------- */
/* PKCS#1 v1.5 signature.                                                                        */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_PKCS1_V15 == 1
bool SSFRSASignPKCS1(const uint8_t *privKeyDer, size_t privKeyDerLen,
                     SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                     uint8_t *sig, size_t sigSize, size_t *sigLen)
{
    SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(d, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(q, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(dp, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(dq, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(qInv, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(mCheck, SSF_BN_MAX_LIMBS);
    uint16_t nLimbs;
    size_t keyBytes;
    size_t hLen;
    const uint8_t *diPrefix;
    uint8_t em[SSF_RSA_MAX_KEY_BYTES];
    size_t tLen;
    size_t psLen;
    bool ok = false;

    SSF_REQUIRE(privKeyDer != NULL);
    SSF_REQUIRE(privKeyDerLen > 0u);
    SSF_REQUIRE(hashVal != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);
    SSF_REQUIRE((hash > SSF_RSA_HASH_MIN) && (hash < SSF_RSA_HASH_MAX));

    hLen = _SSFRSAGetHashSize(hash);
    SSF_REQUIRE(hashLen == hLen);

    if (!_SSFRSAPrivKeyDecode(privKeyDer, privKeyDerLen, &n, &e, &d,
                              &p, &q, &dp, &dq, &qInv, &nLimbs)) goto cleanup;

    keyBytes = (SSFBNBitLen(&n) + 7u) / 8u;
    if (sigSize < keyBytes) goto cleanup;

    switch (hash)
    {
    case SSF_RSA_HASH_SHA256: diPrefix = _ssfRSADigestInfoSHA256; break;
    case SSF_RSA_HASH_SHA384: diPrefix = _ssfRSADigestInfoSHA384; break;
    case SSF_RSA_HASH_SHA512: diPrefix = _ssfRSADigestInfoSHA512; break;
    default: goto cleanup;
    }

    tLen = SSF_RSA_DIGEST_INFO_PREFIX_LEN + hLen;
    if (keyBytes < tLen + 11u) goto cleanup;
    psLen = keyBytes - tLen - 3u;

    /* EM = 0x00 || 0x01 || PS(0xFF…) || 0x00 || T. */
    em[0] = 0x00u;
    em[1] = 0x01u;
    memset(&em[2], 0xFF, psLen);
    em[2u + psLen] = 0x00u;
    memcpy(&em[3u + psLen], diPrefix, SSF_RSA_DIGEST_INFO_PREFIX_LEN);
    memcpy(&em[3u + psLen + SSF_RSA_DIGEST_INFO_PREFIX_LEN], hashVal, hLen);

    /* Convert EM to integer and perform private-key operation. */
    SSFBNFromBytes(&m, em, keyBytes, nLimbs);
    if (!_SSFRSAPrivateOpCRT(&m, nLimbs, &p, &q, &dp, &dq, &qInv, &s)) goto cleanup;

    /* Verify-after-sign: recompute m' = s^e mod n and require m' == m before releasing the     */
    /* signature. Defense against the Boneh-DeMillo-Lipton CRT fault attack and against simple  */
    /* private-key tampering (mismatched dp / dq / qInv). The cost is one extra public-exponent */
    /* modular exponentiation per sign — small relative to the CRT private op.                   */
    if (!_SSFRSAPublicOp(&s, &e, &n, &mCheck)) goto cleanup;
    if (SSFBNCmp(&mCheck, &m) != 0) goto cleanup;

    if (!SSFBNToBytes(&s, sig, keyBytes)) goto cleanup;
    *sigLen = keyBytes;
    ok = true;

cleanup:
    /* Wipe every BN local that touched the private key, plus the EM (carries the message hash) */
    /* and the BN-form message m / signature s / verify-after-sign reconstructed mCheck. Then   */
    /* scrub the deeper-stack region used by the CRT primitive's internal SSFBN locals.          */
    SSFBNZeroize(&d);
    SSFBNZeroize(&p);
    SSFBNZeroize(&q);
    SSFBNZeroize(&dp);
    SSFBNZeroize(&dq);
    SSFBNZeroize(&qInv);
    SSFBNZeroize(&m);
    SSFBNZeroize(&s);
    SSFBNZeroize(&mCheck);
    _SSFRSASecureWipe(em, sizeof(em));
    _SSFRSAStackScrub();
    return ok;
}

bool SSFRSAVerifyPKCS1(const uint8_t *pubKeyDer, size_t pubKeyDerLen,
                       SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                       const uint8_t *sig, size_t sigLen)
{
    SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
    uint16_t keyLimbs;
    size_t keyBytes;
    size_t hLen;
    const uint8_t *diPrefix;
    uint8_t em[SSF_RSA_MAX_KEY_BYTES];
    uint8_t emExpected[SSF_RSA_MAX_KEY_BYTES];
    size_t tLen, psLen;
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(pubKeyDer != NULL);
    SSF_REQUIRE(pubKeyDerLen > 0u);
    SSF_REQUIRE(hashVal != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE((hash > SSF_RSA_HASH_MIN) && (hash < SSF_RSA_HASH_MAX));

    hLen = _SSFRSAGetHashSize(hash);
    SSF_REQUIRE(hashLen == hLen);

    if (!_SSFRSAPubKeyDecode(pubKeyDer, pubKeyDerLen, &n, &e, &keyLimbs)) return false;

    keyBytes = (SSFBNBitLen(&n) + 7u) / 8u;
    if (sigLen != keyBytes) return false;

    /* Import signature and perform public-key operation */
    SSFBNFromBytes(&s, sig, sigLen, keyLimbs);
    if (!_SSFRSAPublicOp(&s, &e, &n, &m)) return false;

    /* Export recovered EM */
    if (!SSFBNToBytes(&m, em, keyBytes)) return false;

    /* Build expected EM */
    switch (hash)
    {
    case SSF_RSA_HASH_SHA256: diPrefix = _ssfRSADigestInfoSHA256; break;
    case SSF_RSA_HASH_SHA384: diPrefix = _ssfRSADigestInfoSHA384; break;
    case SSF_RSA_HASH_SHA512: diPrefix = _ssfRSADigestInfoSHA512; break;
    default: return false;
    }

    tLen = SSF_RSA_DIGEST_INFO_PREFIX_LEN + hLen;
    if (keyBytes < tLen + 11u) return false;
    psLen = keyBytes - tLen - 3u;

    emExpected[0] = 0x00u;
    emExpected[1] = 0x01u;
    memset(&emExpected[2], 0xFF, psLen);
    emExpected[2u + psLen] = 0x00u;
    memcpy(&emExpected[3u + psLen], diPrefix, SSF_RSA_DIGEST_INFO_PREFIX_LEN);
    memcpy(&emExpected[3u + psLen + SSF_RSA_DIGEST_INFO_PREFIX_LEN], hashVal, hLen);

    /* Compare recovered EM against expected EM in constant time. */
    return SSFCryptCTMemEq(em, emExpected, keyBytes);
}
#endif /* SSF_RSA_CONFIG_ENABLE_PKCS1_V15 */

/* --------------------------------------------------------------------------------------------- */
/* MGF1 mask generation function (RFC 8017 Appendix B.2.1).                                     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_RSA_CONFIG_ENABLE_PSS == 1
static void _SSFRSAM_GF1(SSFRSAHash_t hash, const uint8_t *seed, size_t seedLen,
                         uint8_t *mask, size_t maskLen)
{
    uint32_t counter = 0;
    size_t generated = 0;
    size_t hLen = _SSFRSAGetHashSize(hash);

    while (generated < maskLen)
    {
        uint8_t hashOut[64]; /* max hash size */
        uint8_t cBuf[4];
        size_t toCopy;

        cBuf[0] = (uint8_t)((counter >> 24) & 0xFFu);
        cBuf[1] = (uint8_t)((counter >> 16) & 0xFFu);
        cBuf[2] = (uint8_t)((counter >> 8) & 0xFFu);
        cBuf[3] = (uint8_t)(counter & 0xFFu);

        /* Hash(seed || counter) */
        _SSFRSAHashBeginUpdateEnd(hash, seed, seedLen, cBuf, 4, hashOut, sizeof(hashOut));

        toCopy = maskLen - generated;
        if (toCopy > hLen) toCopy = hLen;
        memcpy(&mask[generated], hashOut, toCopy);
        generated += toCopy;
        counter++;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* RSA-PSS signature (RFC 8017 Section 8.1.1, 9.1.1).                                           */
/* Salt length = hash length (per TLS 1.3 requirement).                                          */
/* --------------------------------------------------------------------------------------------- */
bool SSFRSASignPSS(const uint8_t *privKeyDer, size_t privKeyDerLen,
                   SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                   uint8_t *sig, size_t sigSize, size_t *sigLen)
{
    SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(d, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(q, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(dp, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(dq, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(qInv, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(mCheck, SSF_BN_MAX_LIMBS);
    uint16_t nLimbs;
    size_t keyBytes, emBits, emLen;
    size_t hLen, sLen, dbLen;
    uint8_t salt[64];                /* max hash size */
    uint8_t mPrime[8 + 64 + 64];     /* 8 zero + hash + salt */
    uint8_t H[64];
    uint8_t em[SSF_RSA_MAX_KEY_BYTES];
    uint8_t dbMask[SSF_RSA_MAX_KEY_BYTES];
    size_t i;
    bool ok = false;

    SSF_REQUIRE(privKeyDer != NULL);
    SSF_REQUIRE(privKeyDerLen > 0u);
    SSF_REQUIRE(hashVal != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);
    SSF_REQUIRE((hash > SSF_RSA_HASH_MIN) && (hash < SSF_RSA_HASH_MAX));

    hLen = _SSFRSAGetHashSize(hash);
    sLen = hLen; /* salt length = hash length */
    SSF_REQUIRE(hashLen == hLen);

    if (!_SSFRSAPrivKeyDecode(privKeyDer, privKeyDerLen, &n, &e, &d,
                              &p, &q, &dp, &dq, &qInv, &nLimbs)) goto cleanup;

    emBits = SSFBNBitLen(&n) - 1u;
    emLen = (emBits + 7u) / 8u;
    keyBytes = (SSFBNBitLen(&n) + 7u) / 8u;

    if (emLen < hLen + sLen + 2u) goto cleanup;
    if (sigSize < keyBytes) goto cleanup;

    dbLen = emLen - hLen - 1u;

    /* Generate random salt. sLen is bounded by the hash output size (<= 64 bytes for SHA-512), */
    /* so the narrowing cast to uint16_t cannot truncate.                                       */
    if (!SSFPortGetEntropy(salt, (uint16_t)sLen)) goto cleanup;

    /* M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
    memset(mPrime, 0, 8);
    memcpy(&mPrime[8], hashVal, hLen);
    memcpy(&mPrime[8u + hLen], salt, sLen);

    /* H = Hash(M') */
    _SSFRSAHashBeginUpdateEnd(hash, mPrime, 8u + hLen + sLen, NULL, 0, H, sizeof(H));

    /* DB = PS || 0x01 || salt, where PS = emLen - hLen - sLen - 2 zero bytes */
    memset(em, 0, dbLen);
    em[dbLen - sLen - 1u] = 0x01u;
    memcpy(&em[dbLen - sLen], salt, sLen);

    /* dbMask = MGF1(H, dbLen) */
    _SSFRSAM_GF1(hash, H, hLen, dbMask, dbLen);

    /* maskedDB = DB XOR dbMask */
    for (i = 0; i < dbLen; i++) em[i] ^= dbMask[i];

    /* Clear top bits: set the leftmost 8*emLen - emBits bits of maskedDB to zero */
    {
        uint8_t topMask = (uint8_t)(0xFFu >> (8u * emLen - emBits));
        em[0] &= topMask;
    }

    /* EM = maskedDB || H || 0xBC */
    memcpy(&em[dbLen], H, hLen);
    em[emLen - 1u] = 0xBCu;

    /* Pad to keyBytes if emLen < keyBytes */
    if (emLen < keyBytes)
    {
        memmove(&em[keyBytes - emLen], em, emLen);
        memset(em, 0, keyBytes - emLen);
    }

    /* Convert EM to integer and perform private-key operation */
    SSFBNFromBytes(&m, em, keyBytes, nLimbs);
    if (!_SSFRSAPrivateOpCRT(&m, nLimbs, &p, &q, &dp, &dq, &qInv, &s)) goto cleanup;

    /* Verify-after-sign: m' = s^e mod n must equal m. See SSFRSASignPKCS1 for rationale. */
    if (!_SSFRSAPublicOp(&s, &e, &n, &mCheck)) goto cleanup;
    if (SSFBNCmp(&mCheck, &m) != 0) goto cleanup;

    if (!SSFBNToBytes(&s, sig, keyBytes)) goto cleanup;
    *sigLen = keyBytes;
    ok = true;

cleanup:
    SSFBNZeroize(&d);
    SSFBNZeroize(&p);
    SSFBNZeroize(&q);
    SSFBNZeroize(&dp);
    SSFBNZeroize(&dq);
    SSFBNZeroize(&qInv);
    SSFBNZeroize(&m);
    SSFBNZeroize(&s);
    SSFBNZeroize(&mCheck);
    /* salt is the random salt fed back into both H computation and DB; mPrime contains hash    */
    /* + salt; em / dbMask hold the encoded message and the MGF1 mask. All must be wiped.        */
    _SSFRSASecureWipe(salt, sizeof(salt));
    _SSFRSASecureWipe(mPrime, sizeof(mPrime));
    _SSFRSASecureWipe(H, sizeof(H));
    _SSFRSASecureWipe(em, sizeof(em));
    _SSFRSASecureWipe(dbMask, sizeof(dbMask));
    _SSFRSAStackScrub();
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* RSA-PSS verification (RFC 8017 Section 8.1.2, 9.1.2).                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFRSAVerifyPSS(const uint8_t *pubKeyDer, size_t pubKeyDerLen,
                     SSFRSAHash_t hash, const uint8_t *hashVal, size_t hashLen,
                     const uint8_t *sig, size_t sigLen)
{
    SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
    uint16_t keyLimbs;
    size_t keyBytes, emBits, emLen;
    size_t hLen, sLen, dbLen;
    uint8_t em[SSF_RSA_MAX_KEY_BYTES];
    uint8_t dbMask[SSF_RSA_MAX_KEY_BYTES];
    uint8_t H[64], HPrime[64];
    uint8_t mPrime[8 + 64 + 64];
    size_t i;
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
    uint8_t topMask;
    uint8_t diff;

    SSF_REQUIRE(pubKeyDer != NULL);
    SSF_REQUIRE(pubKeyDerLen > 0u);
    SSF_REQUIRE(hashVal != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE((hash > SSF_RSA_HASH_MIN) && (hash < SSF_RSA_HASH_MAX));

    hLen = _SSFRSAGetHashSize(hash);
    sLen = hLen;
    SSF_REQUIRE(hashLen == hLen);

    /* Early failures below depend only on public values (pubKey contents, sigLen). */
    if (!_SSFRSAPubKeyDecode(pubKeyDer, pubKeyDerLen, &n, &e, &keyLimbs))
    { return false; }

    emBits = SSFBNBitLen(&n) - 1u;
    emLen = (emBits + 7u) / 8u;
    keyBytes = (SSFBNBitLen(&n) + 7u) / 8u;

    if (sigLen != keyBytes) { return false; }
    if (emLen < hLen + sLen + 2u) { return false; }

    dbLen = emLen - hLen - 1u;

    /* Import signature and perform public-key operation */
    SSFBNFromBytes(&s, sig, sigLen, keyLimbs);
    if (!_SSFRSAPublicOp(&s, &e, &n, &m)) { return false; }

    /* Export recovered EM (right-aligned to emLen within keyBytes) */
    {
        uint8_t emFull[SSF_RSA_MAX_KEY_BYTES];
        if (!SSFBNToBytes(&m, emFull, keyBytes)) { return false; }
        memcpy(em, &emFull[keyBytes - emLen], emLen);
    }

    /* All checks below operate on attacker-influenced bytes of `em` (the output of the RSA
     * public op on `sig`). Fold every structural check into a single-byte accumulator `diff`
     * and run MGF1 + DB unmask + hash recomputation unconditionally, so that the wall-clock
     * time to reach the final `return` is independent of which byte of `em` first diverged
     * from the PSS padding pattern. Without this, an attacker who can time rejected sigs
     * can distinguish "em trailer wrong" from "em trailer ok but PS[k] nonzero" from
     * "structure ok but H mismatched" — a defense-in-depth signal PSS was designed to
     * avoid exposing. */
    diff = 0u;
    topMask = (uint8_t)(0xFFu >> (8u * emLen - emBits));

    /* Trailer byte must be 0xBC. */
    diff |= (uint8_t)(em[emLen - 1u] ^ 0xBCu);

    /* Top (emBits-aligned) bits of em[0] must be zero. */
    diff |= (uint8_t)(em[0] & ~topMask);

    /* Extract H, derive the MGF1 mask, unmask DB — all unconditional. */
    memcpy(H, &em[dbLen], hLen);
    _SSFRSAM_GF1(hash, H, hLen, dbMask, dbLen);
    for (i = 0; i < dbLen; i++) em[i] ^= dbMask[i];
    em[0] &= topMask;

    /* DB = PS(zeros) || 0x01 || salt. Accumulate every PS byte into diff; compare the
     * separator byte by XOR-into-diff rather than a branch. */
    for (i = 0; i < dbLen - sLen - 1u; i++) diff |= em[i];
    diff |= (uint8_t)(em[dbLen - sLen - 1u] ^ 0x01u);

    /* M' = 00 00 00 00 00 00 00 00 || mHash || salt — unconditional. */
    memset(mPrime, 0, 8);
    memcpy(&mPrime[8], hashVal, hLen);
    memcpy(&mPrime[8u + hLen], &em[dbLen - sLen], sLen);

    /* H' = Hash(M'). */
    _SSFRSAHashBeginUpdateEnd(hash, mPrime, 8u + hLen + sLen, NULL, 0, HPrime, sizeof(HPrime));

    /* Fold H vs H' comparison into the same accumulator. */
    for (i = 0; i < hLen; i++) diff |= (uint8_t)(H[i] ^ HPrime[i]);

    return (diff == 0u);
}
#endif /* SSF_RSA_CONFIG_ENABLE_PSS */
