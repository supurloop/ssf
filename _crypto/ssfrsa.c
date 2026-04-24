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
#include "ssfct.h"

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
    uint8_t nBuf[SSF_BN_MAX_BYTES];
    uint8_t eBuf[SSF_BN_MAX_BYTES];
    uint32_t nEncLen, eEncLen, contentLen, seqHdrLen, offset;

    if (!SSFBNToBytes(n, nBuf, nBytes)) return false;
    if (!SSFBNToBytes(e, eBuf, eBytes)) return false;

    /* Find actual byte length of e (strip leading zeros) */
    {
        size_t i;
        for (i = 0; i < eBytes - 1u; i++) { if (eBuf[i] != 0u) break; }
        memmove(eBuf, &eBuf[i], eBytes - i);
        eBytes -= i;
    }

    if (!SSFASN1EncInt(NULL, 0, nBuf, (uint32_t)nBytes, &nEncLen)) return false;
    if (!SSFASN1EncInt(NULL, 0, eBuf, (uint32_t)eBytes, &eEncLen)) return false;

    contentLen = nEncLen + eEncLen;
    if (!SSFASN1EncTagLen(NULL, 0, SSF_ASN1_TAG_SEQUENCE, contentLen, &seqHdrLen)) return false;

    if ((size_t)(seqHdrLen + contentLen) > derSize) return false;

    {
        uint32_t n;
        if (!SSFASN1EncTagLen(der, (uint32_t)derSize, SSF_ASN1_TAG_SEQUENCE, contentLen, &n))
        {
            return false;
        }
        offset = n;
        if (!SSFASN1EncInt(&der[offset], (uint32_t)(derSize - offset), nBuf,
                           (uint32_t)nBytes, &n))
        {
            return false;
        }
        offset += n;
        if (!SSFASN1EncInt(&der[offset], (uint32_t)(derSize - offset), eBuf,
                           (uint32_t)eBytes, &n))
        {
            return false;
        }
        offset += n;
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
        limbs = SSF_BN_BITS_TO_LIMBS(nl * 8u);
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
    uint8_t buf[SSF_BN_MAX_BYTES];
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
        fieldBytes[i] = (size_t)fields[i]->len * sizeof(SSFBNLimb_t);
        if (!SSFBNToBytes(fields[i], buf, fieldBytes[i])) return false;
        if (!SSFASN1EncInt(NULL, 0, buf, (uint32_t)fieldBytes[i], &encLens[i])) return false;
        contentLen += encLens[i];
    }

    if (!SSFASN1EncTagLen(NULL, 0, SSF_ASN1_TAG_SEQUENCE, contentLen, &seqHdrLen)) return false;
    if ((size_t)(seqHdrLen + contentLen) > derSize) return false;

    /* Encode */
    {
        uint32_t n;
        if (!SSFASN1EncTagLen(der, (uint32_t)derSize, SSF_ASN1_TAG_SEQUENCE, contentLen, &n))
        {
            return false;
        }
        offset = n;
        if (!SSFASN1EncIntU64(&der[offset], (uint32_t)(derSize - offset), 0, &n)) return false;
        offset += n;

        for (i = 1; i < 9u; i++)
        {
            SSFBNToBytes(fields[i], buf, fieldBytes[i]);
            if (!SSFASN1EncInt(&der[offset], (uint32_t)(derSize - offset),
                               buf, (uint32_t)fieldBytes[i], &n))
            {
                return false;
            }
            offset += n;
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
                                 uint16_t *nLimbs, uint16_t *halfLimbs)
{
    SSFASN1Cursor_t cursor, inner, next;
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

    /* n */
    if (!SSFASN1DecGetInt(&next, &buf, &bufLen, &next)) return false;
    {
        const uint8_t *nb = buf;
        uint32_t nbLen = bufLen;
        while (nbLen > 0u && *nb == 0u) { nb++; nbLen--; }
        nl = SSF_BN_BITS_TO_LIMBS(nbLen * 8u);
    }
    if (!SSFBNFromBytes(n, buf, bufLen, nl)) return false;

    /* e */
    if (!SSFASN1DecGetInt(&next, &buf, &bufLen, &next)) return false;
    if (!SSFBNFromBytes(e, buf, bufLen, nl)) return false;

    /* d */
    if (!SSFASN1DecGetInt(&next, &buf, &bufLen, &next)) return false;
    if (!SSFBNFromBytes(d, buf, bufLen, nl)) return false;

    /* p */
    if (!SSFASN1DecGetInt(&next, &buf, &bufLen, &next)) return false;
    {
        const uint8_t *pb = buf;
        uint32_t pbLen = bufLen;
        while (pbLen > 0u && *pb == 0u) { pb++; pbLen--; }
        hl = SSF_BN_BITS_TO_LIMBS(pbLen * 8u);
    }
    if (!SSFBNFromBytes(p, buf, bufLen, hl)) return false;

    /* q */
    if (!SSFASN1DecGetInt(&next, &buf, &bufLen, &next)) return false;
    if (!SSFBNFromBytes(q, buf, bufLen, hl)) return false;

    /* dp */
    if (!SSFASN1DecGetInt(&next, &buf, &bufLen, &next)) return false;
    if (!SSFBNFromBytes(dp, buf, bufLen, hl)) return false;

    /* dq */
    if (!SSFASN1DecGetInt(&next, &buf, &bufLen, &next)) return false;
    if (!SSFBNFromBytes(dq, buf, bufLen, hl)) return false;

    /* qInv */
    if (!SSFASN1DecGetInt(&next, &buf, &bufLen, &next)) return false;
    if (!SSFBNFromBytes(qInv, buf, bufLen, hl)) return false;

    *nLimbs = nl;
    *halfLimbs = hl;
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
    SSFBN_DEFINE(cp, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(cq, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(m2, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(h, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(hq, SSF_BN_MAX_LIMBS);
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

    /* result = m2 + h * q (in full n-width) */
    {
        SSFBN_DEFINE(m2Full, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(hFull, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(qFull, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(hqFull, SSF_BN_MAX_LIMBS);

        /* Expand half-width values to full n-width */
        SSFBNSetZero(&m2Full, nLimbs);
        memcpy(m2Full.limbs, m2.limbs, (size_t)hl * sizeof(SSFBNLimb_t));

        SSFBNSetZero(&hFull, nLimbs);
        memcpy(hFull.limbs, h.limbs, (size_t)hl * sizeof(SSFBNLimb_t));

        SSFBNSetZero(&qFull, nLimbs);
        memcpy(qFull.limbs, q->limbs, (size_t)hl * sizeof(SSFBNLimb_t));

        /* hq = h * q (result fits in nLimbs since h < p and q < n/p) */
        {
            SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
            SSFBNMul(&prod, &hFull, &qFull);
            /* prod.len = 2*nLimbs; take lower nLimbs */
            result->len = nLimbs;
            memcpy(result->limbs, prod.limbs, (size_t)nLimbs * sizeof(SSFBNLimb_t));
        }

        SSFBNAdd(result, result, &m2Full);
    }

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

    if (!_SSFRSAPubKeyDecode(pubKeyDer, pubKeyDerLen, &n, &e, &keyLimbs)) return false;

    /* n must be odd and > 1 */
    if (SSFBNIsEven(&n)) return false;
    if (SSFBNIsOne(&n)) return false;

    /* e must be odd and > 1 */
    if (SSFBNIsEven(&e)) return false;
    if (SSFBNIsOne(&e)) return false;

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
                                uint16_t *nLimbsOut, uint16_t *halfLimbsOut)
{
    SSFPRNGContext_t prng;
    uint8_t entropy[SSF_PRNG_ENTROPY_SIZE];
    uint16_t halfBits;
    uint16_t nLimbs;

    halfBits = bits / 2u;
    nLimbs = SSF_BN_BITS_TO_LIMBS(bits);
    *nLimbsOut = nLimbs;
    *halfLimbsOut = SSF_BN_BITS_TO_LIMBS(halfBits);

    if (!SSFPortGetEntropy(entropy, (uint16_t)sizeof(entropy))) return false;
    SSFPRNGInitContext(&prng, entropy, sizeof(entropy));

    if (!SSFBNGenPrime(p, halfBits, SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS, &prng))
    {
        SSFPRNGDeInitContext(&prng);
        return false;
    }
    if (!SSFBNGenPrime(q, halfBits, SSF_RSA_CONFIG_MILLER_RABIN_ROUNDS, &prng))
    {
        SSFPRNGDeInitContext(&prng);
        return false;
    }

    /* Ensure p != q */
    if (SSFBNCmp(p, q) == 0) { SSFPRNGDeInitContext(&prng); return false; }

    /* Ensure p > q (for CRT) */
    if (SSFBNCmp(p, q) < 0)
    {
        SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);
        SSFBNCopy(&tmp, p);
        SSFBNCopy(p, q);
        SSFBNCopy(q, &tmp);
    }

    SSFPRNGDeInitContext(&prng);

    /* n = p * q */
    {
        SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
        SSFBNMul(&prod, p, q);
        n->len = nLimbs;
        memcpy(n->limbs, prod.limbs, (size_t)nLimbs * sizeof(SSFBNLimb_t));
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* KeyGen stage 2: given p, q, derive d (private exponent), dp, dq, qInv (CRT parameters).        */
/* Local pm1, qm1, g, lambda and the division-loop working state live here and are released on    */
/* return, so they don't overlap with the MillerRabin chain of stage 1 or the DER-encoding of     */
/* stage 3. Any secret intermediates (lambda is derived from p, q) are zeroised before return.    */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFRSAKeyGenDerive(uint16_t nLimbs, uint16_t halfLimbs,
                                const SSFBN_t *p, const SSFBN_t *q,
                                SSFBN_t *d, SSFBN_t *dp, SSFBN_t *dq, SSFBN_t *qInv)
{
    SSFBN_DEFINE(pm1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(qm1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(g, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(lambda, SSF_BN_MAX_LIMBS);

    /* pm1 = p - 1, qm1 = q - 1 */
    (void)SSFBNSubUint32(&pm1, p, 1u);
    (void)SSFBNSubUint32(&qm1, q, 1u);

    /* g = gcd(pm1, qm1) */
    SSFBNGcd(&g, &pm1, &qm1);

    /* lambda = lcm(pm1, qm1) = (pm1 / gcd) * qm1 — the division-by-large-numbers form avoids
     * needing to divide pm1 * qm1 by g, which wouldn't fit in our fixed-width SSFBN_t. */
    {
        SSFBN_DEFINE(pm1_div, SSF_BN_MAX_LIMBS);

        /* Is gcd(pm1, qm1) == 1 (the common case for well-chosen primes)? */
        if (SSFBNIsOne(&g))
        {
            /* Yes, skip the divide — lambda = pm1 * qm1 directly. */
            SSFBNCopy(&pm1_div, &pm1);
        }
        else
        {
            /* No, compute pm1 / g via SSFBNDivMod. The remainder is discarded. */
            SSFBN_DEFINE(rem, SSF_BN_MAX_LIMBS);
            SSFBNDivMod(&pm1_div, &rem, &pm1, &g);
            (void)rem;
        }

        /* lambda = pm1_div * qm1 */
        {
            SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
            SSFBNMul(&prod, &pm1_div, &qm1);
            lambda.len = nLimbs;
            memcpy(lambda.limbs, prod.limbs, (size_t)nLimbs * sizeof(SSFBNLimb_t));
        }
    }

    /* d = 65537^(-1) mod lambda */
    {
        SSFBN_DEFINE(eFull, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&eFull, 65537u, nLimbs);
        if (!SSFBNModInvExt(d, &eFull, &lambda)) { SSFBNZeroize(&lambda); return false; }
    }

    /* CRT parameters */
    SSFBNMod(dp, d, &pm1);
    SSFBNMod(dq, d, &qm1);

    /* qInv = q^(-1) mod p (p is prime, so Fermat works) */
    if (!SSFBNModInv(qInv, q, p)) { SSFBNZeroize(&lambda); return false; }

    /* lambda was derived from (p-1)(q-1) — treat as secret adjacent state. */
    SSFBNZeroize(&lambda);
    return true;
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
    uint16_t nLimbs, halfLimbs;

    SSF_REQUIRE(privKeyDer != NULL);
    SSF_REQUIRE(pubKeyDer != NULL);
    SSF_REQUIRE(privKeyDerLen != NULL);
    SSF_REQUIRE(pubKeyDerLen != NULL);
    SSF_REQUIRE(bits == 2048u || bits == 3072u || bits == 4096u);
    SSF_REQUIRE(bits <= SSF_BN_CONFIG_MAX_BITS);

    if (!_SSFRSAKeyGenPrimes(bits, &p, &q, &n, &nLimbs, &halfLimbs)) return false;
    if (!_SSFRSAKeyGenDerive(nLimbs, halfLimbs, &p, &q, &d, &dp, &dq, &qInv)) return false;
    if (!_SSFRSAKeyGenEncode(&n, &d, &p, &q, &dp, &dq, &qInv, nLimbs,
                             privKeyDer, privKeyDerSize, privKeyDerLen,
                             pubKeyDer,  pubKeyDerSize,  pubKeyDerLen)) return false;

    /* Zeroize secrets on success. Failure paths return before secrets are fully derived or
     * before encode completes; per the existing convention those do not zeroise (the stack
     * bytes go out of scope on return anyway). */
    SSFBNZeroize(&d);
    SSFBNZeroize(&p);
    SSFBNZeroize(&q);
    SSFBNZeroize(&dp);
    SSFBNZeroize(&dq);
    SSFBNZeroize(&qInv);

    return true;
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
    uint16_t nLimbs, halfLimbs;
    size_t keyBytes;
    size_t hLen;
    const uint8_t *diPrefix;
    uint8_t em[SSF_RSA_MAX_KEY_BYTES];
    size_t tLen;
    size_t psLen;
    SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(privKeyDer != NULL);
    SSF_REQUIRE(hashVal != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);
    SSF_REQUIRE((hash > SSF_RSA_HASH_MIN) && (hash < SSF_RSA_HASH_MAX));

    hLen = _SSFRSAGetHashSize(hash);
    SSF_REQUIRE(hashLen == hLen);

    if (!_SSFRSAPrivKeyDecode(privKeyDer, privKeyDerLen, &n, &e, &d,
                              &p, &q, &dp, &dq, &qInv, &nLimbs, &halfLimbs)) return false;

    keyBytes = (SSFBNBitLen(&n) + 7u) / 8u;
    if (sigSize < keyBytes) return false;

    /* Select DigestInfo prefix */
    switch (hash)
    {
    case SSF_RSA_HASH_SHA256: diPrefix = _ssfRSADigestInfoSHA256; break;
    case SSF_RSA_HASH_SHA384: diPrefix = _ssfRSADigestInfoSHA384; break;
    case SSF_RSA_HASH_SHA512: diPrefix = _ssfRSADigestInfoSHA512; break;
    default: return false;
    }

    /* T = DigestInfo prefix || hash */
    tLen = SSF_RSA_DIGEST_INFO_PREFIX_LEN + hLen;

    /* EM must be at least tLen + 11 bytes */
    if (keyBytes < tLen + 11u) return false;

    psLen = keyBytes - tLen - 3u;

    /* Build EM: 0x00 || 0x01 || PS || 0x00 || T */
    em[0] = 0x00u;
    em[1] = 0x01u;
    memset(&em[2], 0xFF, psLen);
    em[2u + psLen] = 0x00u;
    memcpy(&em[3u + psLen], diPrefix, SSF_RSA_DIGEST_INFO_PREFIX_LEN);
    memcpy(&em[3u + psLen + SSF_RSA_DIGEST_INFO_PREFIX_LEN], hashVal, hLen);

    /* Convert EM to integer and perform private-key operation */
    SSFBNFromBytes(&m, em, keyBytes, nLimbs);
    if (!_SSFRSAPrivateOpCRT(&m, nLimbs, &p, &q, &dp, &dq, &qInv, &s)) return false;

    /* Export signature */
    if (!SSFBNToBytes(&s, sig, keyBytes)) return false;
    *sigLen = keyBytes;

    SSFBNZeroize(&d);
    SSFBNZeroize(&p);
    SSFBNZeroize(&q);
    SSFBNZeroize(&dp);
    SSFBNZeroize(&dq);
    SSFBNZeroize(&qInv);

    return true;
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
    return SSFCTMemEq(em, emExpected, keyBytes);
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
    uint16_t nLimbs, halfLimbs;
    size_t keyBytes, emBits, emLen;
    size_t hLen, sLen, dbLen;
    uint8_t salt[64]; /* max hash size */
    uint8_t mPrime[8 + 64 + 64]; /* 8 zero + hash + salt */
    uint8_t H[64];
    uint8_t em[SSF_RSA_MAX_KEY_BYTES];
    uint8_t dbMask[SSF_RSA_MAX_KEY_BYTES];
    size_t i;
    SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(privKeyDer != NULL);
    SSF_REQUIRE(hashVal != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);
    SSF_REQUIRE((hash > SSF_RSA_HASH_MIN) && (hash < SSF_RSA_HASH_MAX));

    hLen = _SSFRSAGetHashSize(hash);
    sLen = hLen; /* salt length = hash length */
    SSF_REQUIRE(hashLen == hLen);

    if (!_SSFRSAPrivKeyDecode(privKeyDer, privKeyDerLen, &n, &e, &d,
                              &p, &q, &dp, &dq, &qInv, &nLimbs, &halfLimbs)) return false;

    emBits = SSFBNBitLen(&n) - 1u;
    emLen = (emBits + 7u) / 8u;
    keyBytes = (SSFBNBitLen(&n) + 7u) / 8u;

    if (emLen < hLen + sLen + 2u) return false;
    if (sigSize < keyBytes) return false;

    dbLen = emLen - hLen - 1u;

    /* Generate random salt. sLen is bounded by the hash output size (<= 64 bytes for SHA-512), */
    /* so the narrowing cast to uint16_t cannot truncate.                                       */
    if (!SSFPortGetEntropy(salt, (uint16_t)sLen)) return false;

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
    if (!_SSFRSAPrivateOpCRT(&m, nLimbs, &p, &q, &dp, &dq, &qInv, &s)) return false;

    if (!SSFBNToBytes(&s, sig, keyBytes)) return false;
    *sigLen = keyBytes;

    SSFBNZeroize(&d);
    SSFBNZeroize(&p);
    SSFBNZeroize(&q);
    SSFBNZeroize(&dp);
    SSFBNZeroize(&dq);
    SSFBNZeroize(&qInv);

    return true;
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
