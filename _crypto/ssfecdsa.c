/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfecdsa.c                                                                                    */
/* Provides ECDSA digital signature and ECDH key agreement implementation.                       */
/*                                                                                               */
/* FIPS 186-4: Digital Signature Standard (DSS)                                                  */
/* RFC 6979: Deterministic Usage of the DSA and ECDSA                                            */
/* NIST SP 800-56A Rev. 3: Pair-Wise Key-Establishment Using Discrete Logarithm Cryptography     */
/* SEC 1 v2: Elliptic Curve Cryptography                                                         */
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
#include "ssfhmac.h"
#include "ssfsha1.h"
#include "ssfsha2.h"
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
#include "ssfasn1.h"
#endif
#include "ssfprng.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* Maximum RFC 6979 candidates Sign tries when r or s is zero. */
#define SSF_ECDSA_SIGN_MAX_ATTEMPTS (8u)

#if (SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN != 0u) && (SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN != 1u)
#error SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN must be 0 or 1.
#endif

#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
/* Test-only exit hooks fired AFTER zeroization, BEFORE return; NULL in production. */
void (*_SSFECDSASignTestExitHook)(void *ctx,
                                  const SSFBN_t *d, const SSFBN_t *k, const SSFBN_t *e,
                                  const SSFBN_t *kInv, const SSFBN_t *tmp,
                                  const SSFECPoint_t *R,
                                  const SSFBN_t *Rx, const SSFBN_t *Ry) = NULL;
void *_SSFECDSASignTestExitHookCtx = NULL;

void (*_SSFECDSAECDHTestExitHook)(void *ctx,
                                  const SSFBN_t *d,
                                  const SSFECPoint_t *S,
                                  const SSFBN_t *Sx, const SSFBN_t *Sy) = NULL;
void *_SSFECDSAECDHTestExitHookCtx = NULL;

void (*_SSFECDSAKeyGenTestExitHook)(void *ctx,
                                    const SSFBN_t *d,
                                    const SSFECPoint_t *Q,
                                    const uint8_t *entropy, size_t entropyLen) = NULL;
void *_SSFECDSAKeyGenTestExitHookCtx = NULL;

void (*_SSFECDSAPubKeyTestExitHook)(void *ctx,
                                    const SSFBN_t *d,
                                    const SSFECPoint_t *Q) = NULL;
void *_SSFECDSAPubKeyTestExitHookCtx = NULL;

/* Test-only fault injection: Sign treats its first N attempts as r == 0. */
uint8_t _SSFECDSASignTestForcedRetries = 0u;

/* Test-only fault injection: 1 flips r, 2 flips d, 3 flips e before s. */
uint8_t _SSFECDSASignTestFault = 0u;
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: r = k * G via the fastest configured scalar mul (fixed-base comb when available).   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSAScalarMulBase(SSFECPoint_t *r, const SSFBN_t *k, SSFECCurve_t curve)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(k != NULL);
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));

#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
    if (curve == SSF_EC_CURVE_P256) { SSFECScalarMulBaseP256(r, k); return; }
#endif
#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
    if (curve == SSF_EC_CURVE_P384) { SSFECScalarMulBaseP384(r, k); return; }
#endif
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);

        SSF_REQUIRE(c != NULL);
        SSFECPointFromAffine(&G, &c->gx, &c->gy, curve);
        SSFECScalarMul(r, k, &G, curve);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: select HMAC hash type for the curve.                                                */
/* --------------------------------------------------------------------------------------------- */
static SSFHMACHash_t _SSFECDSAGetHMACHash(SSFECCurve_t curve)
{
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));

    switch (curve)
    {
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    case SSF_EC_CURVE_P256: return SSF_HMAC_HASH_SHA256;
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    case SSF_EC_CURVE_P384: return SSF_HMAC_HASH_SHA384;
#endif
    default: SSF_ASSERT(false); return SSF_HMAC_HASH_SHA256;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: get the expected hash output size for the curve.                                    */
/* --------------------------------------------------------------------------------------------- */
static size_t _SSFECDSAGetHashSize(SSFECCurve_t curve)
{
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));

    switch (curve)
    {
#if SSF_EC_CONFIG_ENABLE_P256 == 1
    case SSF_EC_CURVE_P256: return SSF_SHA2_256_BYTE_SIZE;
#endif
#if SSF_EC_CONFIG_ENABLE_P384 == 1
    case SSF_EC_CURVE_P384: return SSF_SHA2_384_BYTE_SIZE;
#endif
    default: SSF_ASSERT(false); return 0;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: RFC 6979 nonce HMAC = the digest's hash, inferred from hashLen (else the curve's).  */
/* --------------------------------------------------------------------------------------------- */
static SSFHMACHash_t _SSFECDSANonceHMACHash(SSFECCurve_t curve, size_t hashLen, size_t *hlen)
{
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE((hashLen > 0u) && (hashLen <= SSF_SHA2_512_BYTE_SIZE));
    SSF_REQUIRE(hlen != NULL);

    /* RFC 6979 HMAC-DRBG uses the digest's hash, inferred from hashLen */
    switch (hashLen)
    {
    case SSF_SHA1_HASH_SIZE: *hlen = SSF_SHA1_HASH_SIZE; return SSF_HMAC_HASH_SHA1;
    case SSF_SHA2_256_BYTE_SIZE: *hlen = SSF_SHA2_256_BYTE_SIZE; return SSF_HMAC_HASH_SHA256;
    case SSF_SHA2_384_BYTE_SIZE: *hlen = SSF_SHA2_384_BYTE_SIZE; return SSF_HMAC_HASH_SHA384;
    case SSF_SHA2_512_BYTE_SIZE: *hlen = SSF_SHA2_512_BYTE_SIZE; return SSF_HMAC_HASH_SHA512;
    default:
        /* Not a SHA-1 / SHA-2 digest length: fall back to the curve's hash. */
        *hlen = _SSFECDSAGetHashSize(curve);
        return _SSFECDSAGetHMACHash(curve);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: bits2int per RFC 6979 Sec. 2.3.2: the leftmost qlen bits of the hash as an integer. */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSABits2Int(SSFBN_t *out, const uint8_t *hash, size_t hashLen,
                              const SSFECCurveParams_t *c)
{
    size_t useLen;

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(((uint32_t)c->bytes * 8u) == SSFBNBitLen(&c->n));
    useLen = hashLen;

    /* Is the digest longer than the curve order? */
    if (useLen > c->bytes)
    {
        /* Yes, keep its leftmost c->bytes bytes. */
        useLen = c->bytes;
    }
    SSF_ASSERT(SSFBNFromBytes(out, hash, useLen, c->limbs));
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: bits2octets per RFC 6979 2.3.4 (hash to integer mod n, then BE bytes coordBytes).   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSABits2Octets(uint8_t *out, size_t outSize, const uint8_t *hash, size_t hashLen,
                                 const SSFECCurveParams_t *c)
{
    SSFBN_DEFINE(z, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(out != NULL);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(c != NULL);

    _SSFECDSABits2Int(&z, hash, hashLen, c);

    /* Is z >= n? */
    if (SSFBNCmp(&z, &c->n) >= 0)
    {
        /* Yes, reduce it mod n. */
        SSFBNSub(&z, &z, &c->n);
    }

    SSFBNToBytes(&z, out, outSize);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: RFC 6979 nonce generation (HMAC-DRBG); k = the (skip+1)-th candidate in [1, n-1].   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAGenK(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                          const uint8_t *hash, size_t hashLen, const SSFECCurveParams_t *c,
                          uint8_t skip, SSFBN_t *k)
{
    size_t hlen;
    SSFHMACHash_t hmacHash = _SSFECDSANonceHMACHash(curve, hashLen, &hlen);
    uint8_t V[SSF_HMAC_MAX_HASH_SIZE];
    uint8_t K[SSF_HMAC_MAX_HASH_SIZE];
    uint8_t h1Octets[SSF_EC_MAX_COORD_BYTES];
    SSFHMACContext_t ctx = {0};
    uint8_t sep;
    uint8_t T[SSF_EC_MAX_COORD_BYTES];
    uint16_t attempts;

    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(k != NULL);

    /* Step a: h1 = H(m) -- already provided by caller as hash */

    /* Step b: V = 0x01 0x01 ... 0x01 (hlen octets) */
    memset(V, 0x01, hlen);

    /* Step c: K = 0x00 0x00 ... 0x00 (hlen octets) */
    memset(K, 0x00, hlen);

    /* bits2octets(h1) for use in steps d and f */
    _SSFECDSABits2Octets(h1Octets, c->bytes, hash, hashLen, c);

    /* Step d: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)) */
    sep = 0x00u;
    SSFHMACBegin(&ctx, hmacHash, K, hlen);
    SSFHMACUpdate(&ctx, V, hlen);
    SSFHMACUpdate(&ctx, &sep, 1);
    SSFHMACUpdate(&ctx, privKey, privKeyLen);
    SSFHMACUpdate(&ctx, h1Octets, c->bytes);
    SSFHMACEnd(&ctx, K, hlen);

    /* Step e: V = HMAC_K(V) */
    SSFHMAC(hmacHash, K, hlen, V, hlen, V, hlen);

    /* Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) */
    sep = 0x01u;
    SSFHMACDeInit(&ctx);
    SSFHMACBegin(&ctx, hmacHash, K, hlen);
    SSFHMACUpdate(&ctx, V, hlen);
    SSFHMACUpdate(&ctx, &sep, 1);
    SSFHMACUpdate(&ctx, privKey, privKeyLen);
    SSFHMACUpdate(&ctx, h1Octets, c->bytes);
    SSFHMACEnd(&ctx, K, hlen);

    /* Step g: V = HMAC_K(V) */
    SSFHMAC(hmacHash, K, hlen, V, hlen, V, hlen);

    /* Step h: Loop until a valid k is found */
    for (attempts = 0; attempts < 100u; attempts++)
    {
        size_t tLen = 0;

        /* Step h.2: Generate T of coordBytes length */
        while (tLen < c->bytes)
        {
            /* V = HMAC_K(V) */
            SSFHMAC(hmacHash, K, hlen, V, hlen, V, hlen);

            /* T = T || V */
            {
                size_t copyLen = c->bytes - tLen;
                if (copyLen > hlen) { copyLen = hlen; }
                memcpy(&T[tLen], V, copyLen);
                tLen += copyLen;
            }
        }

        /* Step h.3: k = bits2int(T) */
        _SSFECDSABits2Int(k, T, c->bytes, c);

        /* Is k in [1, n-1]? */
        if ((!SSFBNIsZero(k)) && (SSFBNCmp(k, &c->n) < 0))
        {
            /* Yes. Is it the candidate the caller asked for? */
            if (skip == 0u)
            {
                /* Yes, done. */
                SSFHMACDeInit(&ctx);
                SSFCryptSecureZero(V, sizeof(V));
                SSFCryptSecureZero(K, sizeof(K));
                SSFCryptSecureZero(h1Octets, sizeof(h1Octets));
                SSFCryptSecureZero(T, sizeof(T));
                return true;
            }
            /* No, Sign rejected an earlier k (r or s == 0); continue the generator */
            skip--;
        }

        /* Step h.3 (retry): K = HMAC_K(V || 0x00), V = HMAC_K(V) */
        sep = 0x00u;
        SSFHMACDeInit(&ctx);
        SSFHMACBegin(&ctx, hmacHash, K, hlen);
        SSFHMACUpdate(&ctx, V, hlen);
        SSFHMACUpdate(&ctx, &sep, 1);
        SSFHMACEnd(&ctx, K, hlen);

        SSFHMAC(hmacHash, K, hlen, V, hlen, V, hlen);
    }

    SSFHMACDeInit(&ctx);
    SSFCryptSecureZero(V, sizeof(V));
    SSFCryptSecureZero(K, sizeof(K));
    SSFCryptSecureZero(h1Octets, sizeof(h1Octets));
    SSFCryptSecureZero(T, sizeof(T));
    /* Wipe k so no rejected HMAC-DRBG candidate is left behind. */
    SSFBNZeroize(k);
    return false; /* Should never reach here for valid inputs */
}

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1

/* --------------------------------------------------------------------------------------------- */
/* Internal: canonical DER INTEGER bytes of a BE integer in *outBuf (input or padBuf).           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSACanonicalizeInt(const uint8_t *intBuf, uint32_t intLen, uint8_t *padBuf,
                                     uint32_t padBufSize, const uint8_t **outBuf, uint32_t *outLen)
{
    const uint8_t *p = intBuf;
    uint32_t n = intLen;

    SSF_REQUIRE(intBuf != NULL);
    SSF_REQUIRE(intLen > 0u);
    SSF_REQUIRE(padBuf != NULL);
    SSF_REQUIRE(outBuf != NULL);
    SSF_REQUIRE(outLen != NULL);

    /* Is there a leading zero byte to strip (keeping at least one byte)? */
    while ((n > 1u) && (*p == 0u))
    {
        /* Yes, skip it. */
        p++;
        n--;
    }

    /* Is the high bit set (would read as a negative INTEGER)? */
    if ((*p & 0x80u) != 0u)
    {
        /* Yes, prepend one 0x00 sign-pad byte. */
        SSF_ASSERT(padBufSize >= (n + 1u));
        padBuf[0] = 0u;
        memcpy(&padBuf[1], p, (size_t)n);
        *outBuf = padBuf;
        *outLen = n + 1u;
    }
    else
    {
        /* No, use the stripped bytes in place. */
        *outBuf = p;
        *outLen = n;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-encode an ECDSA signature (r, s) as SEQUENCE { INTEGER, INTEGER }.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSASigEncode(const SSFBN_t *r, const SSFBN_t *s, const SSFECCurveParams_t *c,
                               uint8_t *sig, size_t sigSize, size_t *sigLen)
{
    uint8_t rBytes[SSF_EC_MAX_COORD_BYTES];
    uint8_t sBytes[SSF_EC_MAX_COORD_BYTES];
    uint8_t rPad[SSF_EC_MAX_COORD_BYTES + 1u];
    uint8_t sPad[SSF_EC_MAX_COORD_BYTES + 1u];
    const uint8_t *rCan;
    const uint8_t *sCan;
    uint32_t rCanLen;
    uint32_t sCanLen;
    uint32_t rEncLen;
    uint32_t sEncLen;
    uint32_t contentLen;
    uint32_t seqHdrLen;
    uint32_t totalLen;
    uint32_t offset;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);

    /* Export r, s as BE bytes and canonicalize for ASN.1 INTEGER encoding. */
    if (!SSFBNToBytes(r, rBytes, c->bytes)) return false;
    if (!SSFBNToBytes(s, sBytes, c->bytes)) return false;
    _SSFECDSACanonicalizeInt(rBytes, (uint32_t)c->bytes, rPad, sizeof(rPad), &rCan, &rCanLen);
    _SSFECDSACanonicalizeInt(sBytes, (uint32_t)c->bytes, sPad, sizeof(sPad), &sCan, &sCanLen);

    /* Measure: pass 1 */
    if (!SSFASN1EncInt(NULL, 0, rCan, rCanLen, &rEncLen)) return false;
    if (!SSFASN1EncInt(NULL, 0, sCan, sCanLen, &sEncLen)) return false;

    contentLen = rEncLen + sEncLen;
    if (!SSFASN1EncTagLen(NULL, 0, SSF_ASN1_TAG_SEQUENCE, contentLen, &seqHdrLen)) return false;

    totalLen = seqHdrLen + contentLen;
    if ((size_t)totalLen > sigSize) return false;

    /* Encode: pass 2 */
    {
        uint32_t n;
        if (!SSFASN1EncTagLen(sig, (uint32_t)sigSize, SSF_ASN1_TAG_SEQUENCE, contentLen, &n))
        {
            return false;
        }
        offset = n;
        if (!SSFASN1EncInt(&sig[offset], (uint32_t)(sigSize - offset), rCan, rCanLen, &n))
        {
            return false;
        }
        offset += n;
        if (!SSFASN1EncInt(&sig[offset], (uint32_t)(sigSize - offset), sCan, sCanLen, &n))
        {
            return false;
        }
        offset += n;
    }

    *sigLen = (size_t)offset;
    return true;
}

#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */

/* --------------------------------------------------------------------------------------------- */
/* Internal: strict byte-level DER parse of the signature; outputs r, s INTEGER content spans.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSASigParseStrictDER(const uint8_t *sig, size_t sigLen, uint16_t coordBytes,
                                       size_t *rOff, size_t *rLen, size_t *sOff, size_t *sLen)
{
    size_t pos = 0u;
    size_t seqLen;
    size_t intLen;
    size_t outOff[2];
    size_t outLen[2];
    uint16_t i;

    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(coordBytes > 0u);
    SSF_REQUIRE(rOff != NULL);
    SSF_REQUIRE(rLen != NULL);
    SSF_REQUIRE(sOff != NULL);
    SSF_REQUIRE(sLen != NULL);

    /* Smallest valid sig is 30 06 02 01 rr 02 01 ss = 8 bytes. */
    if (sigLen < 8u) return false;

    /* Outer SEQUENCE tag. */
    if (sig[pos++] != 0x30u) return false;

    /* Is the SEQUENCE length in short form? */
    if (sig[pos] < 0x80u)
    {
        /* Yes, take it directly. */
        seqLen = sig[pos++];
    }
    /* No, is it in the canonical 0x81 XX long form? */
    else if (sig[pos] == 0x81u)
    {
        /* Yes, take the single length byte. */
        pos++;
        if (pos >= sigLen) return false;
        seqLen = sig[pos++];
        if (seqLen < 0x80u) return false; /* must use short form when < 128 */
    }
    else
    {
        /* No, reject 0x82+ since signatures are < 256 bytes. */
        return false;
    }

    /* Total bytes must match exactly: header (pos) + content (seqLen). */
    if (sigLen != (pos + seqLen)) return false;

    /* Two INTEGERs: r then s. Same canonical-form requirements. */
    for (i = 0u; i < 2u; i++)
    {
        if (pos >= sigLen) return false;
        if (sig[pos++] != 0x02u) return false; /* INTEGER tag */
        if (pos >= sigLen) return false;
        if (sig[pos] >= 0x80u) return false; /* INTEGER length must be short form */
        intLen = sig[pos++];
        if (intLen == 0u) return false;
        if ((pos + intLen) > sigLen) return false;
        if (intLen > ((size_t)coordBytes + 1u)) return false; /* exceeds maximum for the curve */

        /* Is the INTEGER longer than one byte? */
        if (intLen > 1u)
        {
            /* Yes, is there a 0x00 prefix not followed by an MSB-set byte (non-canonical)? */
            if ((sig[pos] == 0x00u) && (sig[pos + 1u] < 0x80u))
            {
                /* Yes, reject the non-canonical leading zero. */
                return false;
            }
        }
        /* MSB of first content byte must be 0 (positive INTEGER without canonical 0x00 pad). */
        if (sig[pos] >= 0x80u) return false;

        outOff[i] = pos;
        outLen[i] = intLen;
        pos += intLen;
    }

    /* No trailing data after second INTEGER. */
    if (pos != sigLen) return false;

    *rOff = outOff[0];
    *rLen = outLen[0];
    *sOff = outOff[1];
    *sLen = outLen[1];
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-decode an ECDSA signature from SEQUENCE { INTEGER, INTEGER } to (r, s).         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSASigDecode(const uint8_t *sig, size_t sigLen, const SSFECCurveParams_t *c,
                               SSFBN_t *r, SSFBN_t *s)
{
    size_t rOff;
    size_t rLen;
    size_t sOff;
    size_t sLen;

    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(s != NULL);

    if (!_SSFECDSASigParseStrictDER(sig, sigLen, c->bytes, &rOff, &rLen, &sOff, &sLen))
    {
        return false;
    }

    /* Does r carry the (at most one) canonical 0x00 sign-pad? */
    if ((rLen > 1u) && (sig[rOff] == 0u))
    {
        /* Yes, strip it so SSFBNFromBytes sees the magnitude. */
        rOff++;
        rLen--;
    }
    /* Does s carry the (at most one) canonical 0x00 sign-pad? */
    if ((sLen > 1u) && (sig[sOff] == 0u))
    {
        /* Yes, strip it so SSFBNFromBytes sees the magnitude. */
        sOff++;
        sLen--;
    }
    if (!SSFBNFromBytes(r, &sig[rOff], rLen, c->limbs)) return false;
    if (!SSFBNFromBytes(s, &sig[sOff], sLen, c->limbs)) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: reduces affine x mod n constant-time (one trial subtract + masked commit).          */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSAReduceModN(SSFBN_t *r, const SSFBN_t *x, const SSFECCurveParams_t *c)
{
    SSFBN_DEFINE(tmp, SSF_EC_MAX_LIMBS);
    SSFBNLimb_t borrow;
    SSFBNLimb_t mask;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(x != NULL);
    SSF_REQUIRE(x->limbs != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(x->len == c->n.len);
    SSF_REQUIRE(c->n.len <= r->cap);

    SSFBNCopy(r, x);
    tmp.len = r->len;
    /* tmp = r - n. If r >= n, borrow == 0 and we commit tmp; else keep r. */
    borrow = SSFBNSub(&tmp, r, &c->n);
    mask = (SSFBNLimb_t)(borrow - 1u); /* all-ones if borrow == 0, else 0 */
    SSF_CT_VALUE_BARRIER(mask);
    for (i = 0; i < r->len; i++)
    {
        r->limbs[i] = (tmp.limbs[i] & mask) | (r->limbs[i] & ~mask);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: validate a private key d is in [1, n-1].                                            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAPrivKeyIsValid(const SSFBN_t *d, const SSFECCurveParams_t *c)
{
    SSF_REQUIRE(d != NULL);
    SSF_REQUIRE(c != NULL);

    if (SSFBNIsZero(d)) return false;
    if (SSFBNCmp(d, &c->n) >= 0) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Generate an ECDSA key pair.                                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSAKeyGen(SSFECCurve_t curve, uint8_t *privKey, size_t privKeySize, uint8_t *pubKey,
                    size_t pubKeySize, size_t *pubKeyLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFPRNGContext_t prng;
    uint8_t entropy[SSF_PRNG_ENTROPY_SIZE];
    SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    uint16_t attempts;
    bool prngInited = false;
    bool ok = false;

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(pubKeyLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeySize >= c->bytes);
    SSF_REQUIRE(pubKeySize >= (1u + (2u * (size_t)c->bytes)));

    /* Obtain platform entropy and seed PRNG */
    if (!SSFPortGetEntropy(entropy, (uint16_t)sizeof(entropy))) goto cleanup;
    SSFPRNGInitContext(&prng, entropy, sizeof(entropy));
    prngInited = true;

    /* Generate d in [1, n-1] via rejection sampling (guard against d == 0). */
    for (attempts = 0; attempts < 100u; attempts++)
    {
        /* Did the underlying rejection sampler succeed? */
        if (!SSFBNRandomBelow(&d, &c->n, &prng))
        {
            /* No, retry cap exhausted. */
            continue;
        }
        /* Is the draw non-zero (i.e. d in [1, n-1])? */
        if (!SSFBNIsZero(&d))
        {
            /* Yes, accept. */
            break;
        }
        /* No, re-roll. */
    }
    /* Did we fall out of the loop without finding a valid d? */
    if (attempts >= 100u) goto cleanup;

    /* Export private key */
    if (!SSFBNToBytes(&d, privKey, c->bytes)) goto cleanup;

    /* Compute public key: Q = d * G */
    _SSFECDSAScalarMulBase(&Q, &d, curve);

    /* Encode public key in SEC 1 uncompressed format */
    if (!SSFECPointEncode(&Q, curve, pubKey, pubKeySize, pubKeyLen)) goto cleanup;

    ok = true;

cleanup:
    /* Wipe d, the projective Q, the PRNG state and its entropy seed. */
    SSFBNZeroize(&d);
    SSFBNZeroize(&Q.x);
    SSFBNZeroize(&Q.y);
    SSFBNZeroize(&Q.z);
    if (prngInited) SSFPRNGDeInitContext(&prng);
    SSFCryptSecureZero(entropy, sizeof(entropy));
#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
    if (_SSFECDSAKeyGenTestExitHook != NULL)
    {
        _SSFECDSAKeyGenTestExitHook(_SSFECDSAKeyGenTestExitHookCtx,
                                    &d, &Q, entropy, sizeof(entropy));
    }
#endif
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Compute the public key from a private key.                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSAPubKeyFromPrivKey(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                               uint8_t *pubKey, size_t pubKeySize, size_t *pubKeyLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    bool ok = false;

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(pubKeyLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeyLen == c->bytes);
    SSF_REQUIRE(pubKeySize >= (1u + (2u * (size_t)c->bytes)));

    /* Import and validate private key */
    if (!SSFBNFromBytes(&d, privKey, privKeyLen, c->limbs)) goto cleanup;
    if (!_SSFECDSAPrivKeyIsValid(&d, c)) goto cleanup;

    /* Q = d * G */
    _SSFECDSAScalarMulBase(&Q, &d, curve);

    /* Encode */
    ok = SSFECPointEncode(&Q, curve, pubKey, pubKeySize, pubKeyLen);

cleanup:
    /* Wipe d and the projective Q. */
    SSFBNZeroize(&d);
    SSFBNZeroize(&Q.x);
    SSFBNZeroize(&Q.y);
    SSFBNZeroize(&Q.z);
#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
    if (_SSFECDSAPubKeyTestExitHook != NULL)
    {
        _SSFECDSAPubKeyTestExitHook(_SSFECDSAPubKeyTestExitHookCtx, &d, &Q);
    }
#endif
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* Validate a public key.                                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSAPubKeyIsValid(SSFECCurve_t curve, const uint8_t *pubKey, size_t pubKeyLen)
{
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(pubKey != NULL);

    /* SSFECPointDecode validates format, range, and on-curve */
    return SSFECPointDecode(&Q, curve, pubKey, pubKeyLen);
}

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
#if SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN == 1
static bool _SSFECDSASignSelfCheck(SSFECCurve_t curve, const SSFECCurveParams_t *c,
                                   const uint8_t *privKey, size_t privKeyLen, const uint8_t *hash,
                                   size_t hashLen, const SSFBN_t *r, const SSFBN_t *s);
#endif /* SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN */

/* --------------------------------------------------------------------------------------------- */
/* Signs a message hash using ECDSA with deterministic nonce (RFC 6979 / FIPS 186-4 Sec. 6.4).   */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSASign(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                  const uint8_t *hash, size_t hashLen, uint8_t *sig, size_t sigSize, size_t *sigLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(k, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(r, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(s, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(kInv, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(Rx, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(Ry, SSF_EC_MAX_LIMBS);
    uint8_t attempt;
    bool found = false;
    bool ok = false;

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeyLen == c->bytes);
    SSF_REQUIRE((hashLen > 0u) && (hashLen <= SSF_SHA2_512_BYTE_SIZE));

    /* Import private key */
    if (!SSFBNFromBytes(&d, privKey, privKeyLen, c->limbs)) goto cleanup;
    if (!_SSFECDSAPrivKeyIsValid(&d, c)) goto cleanup;

    /* e = bits2int(hash) */
    _SSFECDSABits2Int(&e, hash, hashLen, c);
    if (SSFBNCmp(&e, &c->n) >= 0) SSFBNSub(&e, &e, &c->n);

    /* On r == 0 or s == 0 take the next RFC 6979 candidate k */
    for (attempt = 0u; attempt < SSF_ECDSA_SIGN_MAX_ATTEMPTS; attempt++)
    {
        /* Generate deterministic k per RFC 6979 */
        if (!_SSFECDSAGenK(curve, privKey, privKeyLen, hash, hashLen, c, attempt, &k)) goto cleanup;

        /* R = k * G */
        _SSFECDSAScalarMulBase(&R, &k, curve);

        /* Convert R to affine and get r = Rx mod n */
        if (!SSFECPointToAffine(&Rx, &Ry, &R, curve)) goto cleanup;
        _SSFECDSAReduceModN(&r, &Rx, c);

#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
        /* Is this attempt forced to fail (test-only fault injection)? */
        if (attempt < _SSFECDSASignTestForcedRetries)
        {
            /* Yes, treat it as r == 0 */
            SSFBNSetZero(&r, c->limbs);
        }
        /* No, keep the computed r */
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */

        /* Is r zero? */
        if (SSFBNIsZero(&r))
        {
            /* Yes, take the next k. */
            continue;
        }

#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
        /* Test-only fault injection into r, d or e before s is computed */
        if (_SSFECDSASignTestFault == 1u) r.limbs[0] ^= 1u;
        if (_SSFECDSASignTestFault == 2u) d.limbs[0] ^= 1u;
        if (_SSFECDSASignTestFault == 3u) e.limbs[0] ^= 1u;
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */

        /* No, s = k^(-1) * (e + r * d) mod n, all at curve width */
        if (!SSFBNModInvSmall(&kInv, &k, &c->n)) goto cleanup;

        /* CT mod-n arithmetic on secret operands (d, kInv): ModMulSmall, ModAdd both CT. */
        SSFBNModMulSmall(&tmp, &r, &d, &c->n); /* r * d mod n */
        SSFBNModAdd(&tmp, &e, &tmp, &c->n); /* e + r*d mod n */
        SSFBNModMulSmall(&s, &kInv, &tmp, &c->n); /* k^(-1) * (e + r*d) mod n */

        /* Is s non-zero? */
        if (!SSFBNIsZero(&s))
        {
            /* Yes, (r, s) is a valid signature. */
            found = true;
            break;
        }
        /* No, take the next k. */
    }
    /* Did every attempt produce r == 0 or s == 0? */
    if (!found) goto cleanup;

#if SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN == 1
    /* Does (r, s) verify under a fresh Q = d * G and e, ruling out a fault? */
    if (!_SSFECDSASignSelfCheck(curve, c, privKey, privKeyLen, hash, hashLen, &r, &s))
    {
        /* No, a fault corrupted the signature; release nothing */
        goto cleanup;
    }
    /* Yes, the signature is consistent with privKey and hash */
#endif /* SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN */

    /* DER-encode the signature. */
    ok = _SSFECDSASigEncode(&r, &s, c, sig, sigSize, sigLen);

cleanup:
    /* Wipe r and s. */
    SSFBNZeroize(&r);
    SSFBNZeroize(&s);
    /* Wipe every secret-derived limb (d, k, kInv, tmp, R/Rx/Ry; e wiped for uniformity). */
    SSFBNZeroize(&d);
    SSFBNZeroize(&k);
    SSFBNZeroize(&e);
    SSFBNZeroize(&kInv);
    SSFBNZeroize(&tmp);
    SSFBNZeroize(&R.x);
    SSFBNZeroize(&R.y);
    SSFBNZeroize(&R.z);
    SSFBNZeroize(&Rx);
    SSFBNZeroize(&Ry);
#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
    if (_SSFECDSASignTestExitHook != NULL)
    {
        _SSFECDSASignTestExitHook(_SSFECDSASignTestExitHookCtx,
                                  &d, &k, &e, &kInv, &tmp, &R, &Rx, &Ry);
    }
#endif
    return ok;
}
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN */

/* --------------------------------------------------------------------------------------------- */
/* Verify stage 1: decode + validate pubKey, decode sig, range-check r/s, compute e, w, u1, u2.  */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAVerifyInit(const SSFECCurveParams_t *c, SSFECCurve_t curve,
                                const uint8_t *pubKey, size_t pubKeyLen, const uint8_t *hash,
                                size_t hashLen, const uint8_t *sig, size_t sigLen, SSFBN_t *rOut,
                                SSFBN_t *u1Out, SSFBN_t *u2Out, SSFECPoint_t *QOut)
{
    SSFBN_DEFINE(s, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(w, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(rOut != NULL);
    SSF_REQUIRE(u1Out != NULL);
    SSF_REQUIRE(u2Out != NULL);
    SSF_REQUIRE(QOut != NULL);

    if (!SSFECPointDecode(QOut, curve, pubKey, pubKeyLen)) return false;
    if (!_SSFECDSASigDecode(sig, sigLen, c, rOut, &s)) return false;

    /* Is r outside [1, n-1]? */
    if ((SSFBNIsZero(rOut)) || (SSFBNCmp(rOut, &c->n) >= 0))
    {
        /* Yes, invalid signature. */
        return false;
    }
    /* Is s outside [1, n-1]? */
    if ((SSFBNIsZero(&s)) || (SSFBNCmp(&s, &c->n) >= 0))
    {
        /* Yes, invalid signature. */
        return false;
    }

    _SSFECDSABits2Int(&e, hash, hashLen, c);
    if (SSFBNCmp(&e, &c->n) >= 0) SSFBNSub(&e, &e, &c->n);

    /* Curve-width inverse and products; constant-time, though s, e and r are public */
    if (!SSFBNModInvSmall(&w, &s, &c->n)) return false;

    SSFBNModMulSmall(u1Out, &e, &w, &c->n);
    SSFBNModMulSmall(u2Out, rOut, &w, &c->n);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Verify stage 2: R = u1 * G + u2 * Q (dispatches to fixed-base dual when configured).          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAVerifyGetR(const SSFECCurveParams_t *c, SSFECCurve_t curve, const SSFBN_t *u1,
                                const SSFBN_t *u2, const SSFECPoint_t *Q, SSFECPoint_t *Rout)
{
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(u1 != NULL);
    SSF_REQUIRE(u2 != NULL);
    SSF_REQUIRE(Q != NULL);
    SSF_REQUIRE(Rout != NULL);

#if (SSF_EC_CONFIG_FIXED_BASE_P256 == 1) || (SSF_EC_CONFIG_FIXED_BASE_P384 == 1)
    (void)c;
    SSFECScalarMulDualBase(Rout, u1, u2, Q, curve);
#else
    {
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPointFromAffine(&G, &c->gx, &c->gy, curve);
        SSFECScalarMulDual(Rout, u1, &G, u2, Q, curve);
    }
#endif
    if (SSFECPointIsIdentity(Rout)) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Verify stage 3: r == affine(R).x (mod n) checked in Jacobian (no inversion of Z).             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAVerifyCheckR(const SSFECCurveParams_t *c, SSFECCurve_t curve,
                                  const SSFECPoint_t *R, const SSFBN_t *r)
{
    SSFBN_DEFINE(z2, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(rPlusN, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(pMinusN, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(R != NULL);
    SSF_REQUIRE(r != NULL);
    (void)curve;

    /* z2 = R.z^2 mod p */
    SSFBNModMulNISTPrime(&z2, &R->z, &R->z, &c->p);

    /* Case A: t = r * z2 mod p; accept if t == R.x */
    SSFBNModMulNISTPrime(&t, r, &z2, &c->p);
    if (SSFBNCmp(&t, &R->x) == 0) return true;

    SSFBNSub(&pMinusN, &c->p, &c->n);

    /* Is r < p - n, so that r + n < p is a possible wrapped x? */
    if (SSFBNCmp(r, &pMinusN) < 0)
    {
        /* Yes, case B: t = (r + n) * z2 mod p; accept if t == R.x */
        (void)SSFBNAdd(&rPlusN, r, &c->n);
        SSFBNModMulNISTPrime(&t, &rPlusN, &z2, &c->p);
        if (SSFBNCmp(&t, &R->x) == 0) return true;
    }
    return false;
}

#if (SSF_ECDSA_CONFIG_ENABLE_SIGN == 1) && (SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN == 1)
/* --------------------------------------------------------------------------------------------- */
/* If (r, s) verifies under freshly derived Q = d * G and e returns true, else false.            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSASignSelfCheck(SSFECCurve_t curve, const SSFECCurveParams_t *c,
                                   const uint8_t *privKey, size_t privKeyLen, const uint8_t *hash,
                                   size_t hashLen, const SSFBN_t *r, const SSFBN_t *s)
{
    SSFBN_DEFINE(dQ, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(w, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(u1, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(u2, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);
    bool ok = false;

    SSF_REQUIRE((curve > SSF_EC_CURVE_MIN) && (curve < SSF_EC_CURVE_MAX));
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(privKeyLen == c->bytes);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE((hashLen > 0u) && (hashLen <= SSF_SHA2_512_BYTE_SIZE));
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(r->len == c->limbs);
    SSF_REQUIRE(s != NULL);
    SSF_REQUIRE(s->limbs != NULL);
    SSF_REQUIRE(s->len == c->limbs);

    /* Q = d * G from a second import of privKey, independent of the d that signed */
    if (!SSFBNFromBytes(&dQ, privKey, privKeyLen, c->limbs)) goto cleanup;
    _SSFECDSAScalarMulBase(&Q, &dQ, curve);

    /* e recomputed from hash, independent of the e that signed */
    _SSFECDSABits2Int(&e, hash, hashLen, c);
    if (SSFBNCmp(&e, &c->n) >= 0) SSFBNSub(&e, &e, &c->n);

    /* Standard verify on the public (r, s): u1 = e / s, u2 = r / s, R = u1 * G + u2 * Q */
    if (!SSFBNModInvSmall(&w, s, &c->n)) goto cleanup;
    SSFBNModMulSmall(&u1, &e, &w, &c->n);
    SSFBNModMulSmall(&u2, r, &w, &c->n);
    if (!_SSFECDSAVerifyGetR(c, curve, &u1, &u2, &Q, &R)) goto cleanup;
    ok = _SSFECDSAVerifyCheckR(c, curve, &R, r);

cleanup:
    SSFBNZeroize(&dQ);
    SSFBNZeroize(&Q.x);
    SSFBNZeroize(&Q.y);
    SSFBNZeroize(&Q.z);
    SSFBNZeroize(&R.x);
    SSFBNZeroize(&R.y);
    SSFBNZeroize(&R.z);
    return ok;
}
#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN && SSF_ECDSA_CONFIG_VERIFY_AFTER_SIGN */

#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Unit test access to _SSFECDSAVerifyCheckR for tests that synthesize R.                        */
/* --------------------------------------------------------------------------------------------- */
bool _SSFECDSAVerifyCheckRForTest(SSFECCurve_t curve, const SSFECPoint_t *R, const SSFBN_t *r)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);

    SSF_REQUIRE(R != NULL);
    SSF_REQUIRE(r != NULL);

    if (c == NULL) return false;
    return _SSFECDSAVerifyCheckR(c, curve, R, r);
}

/* --------------------------------------------------------------------------------------------- */
/* Unit test access to _SSFECDSABits2Int with caller-supplied curve params and hashLen.          */
/* --------------------------------------------------------------------------------------------- */
void _SSFECDSABits2IntForTest(const SSFECCurveParams_t *c, const uint8_t *hash, size_t hashLen)
{
    SSFBN_DEFINE(out, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(hash != NULL);

    _SSFECDSABits2Int(&out, hash, hashLen, c);
    SSFBNZeroize(&out);
}
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Returns true if sig is a valid DER ECDSA signature of hash under pubKey, else false.          */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSAVerify(SSFECCurve_t curve, const uint8_t *pubKey, size_t pubKeyLen,
                    const uint8_t *hash, size_t hashLen, const uint8_t *sig, size_t sigLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(r, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(u1, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(u2, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(R, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE((hashLen > 0u) && (hashLen <= SSF_SHA2_512_BYTE_SIZE));

    if (!_SSFECDSAVerifyInit(c, curve, pubKey, pubKeyLen, hash, hashLen, sig, sigLen,
                             &r, &u1, &u2, &Q))
    {
        return false;
    }
    if (!_SSFECDSAVerifyGetR(c, curve, &u1, &u2, &Q, &R)) return false;
    return _SSFECDSAVerifyCheckR(c, curve, &R, &r);
}

/* --------------------------------------------------------------------------------------------- */
/* Computes an ECDH shared secret S = d * Q (NIST SP 800-56A Rev. 3); returns Sx.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDHComputeSecret(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                          const uint8_t *peerPubKey, size_t peerPubKeyLen, uint8_t *secret,
                          size_t secretSize, size_t *secretLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(S, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(Sx, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(Sy, SSF_EC_MAX_LIMBS);
    bool ok = false;

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(peerPubKey != NULL);
    SSF_REQUIRE(secret != NULL);
    SSF_REQUIRE(secretLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeyLen == c->bytes);
    SSF_REQUIRE(secretSize >= c->bytes);

    /* Import and validate private key */
    if (!SSFBNFromBytes(&d, privKey, privKeyLen, c->limbs)) goto cleanup;
    if (!_SSFECDSAPrivKeyIsValid(&d, c)) goto cleanup;

    /* Decode and validate peer's public key */
    if (!SSFECPointDecode(&Q, curve, peerPubKey, peerPubKeyLen)) goto cleanup;

    /* S = d * Q (the shared point; affine coords wiped in the cleanup block). */
    SSFECScalarMul(&S, &d, &Q, curve);

    /* S must not be identity */
    if (SSFECPointIsIdentity(&S)) goto cleanup;

    /* Export x-coordinate of S as shared secret */
    if (!SSFECPointToAffine(&Sx, &Sy, &S, curve)) goto cleanup;
    if (!SSFBNToBytes(&Sx, secret, c->bytes)) goto cleanup;

    *secretLen = c->bytes;
    ok = true;

cleanup:
    /* Wipe d and the shared-point intermediates (caller's secret buffer keeps Sx). */
    SSFBNZeroize(&d);
    SSFBNZeroize(&S.x);
    SSFBNZeroize(&S.y);
    SSFBNZeroize(&S.z);
    SSFBNZeroize(&Sx);
    SSFBNZeroize(&Sy);
#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
    if (_SSFECDSAECDHTestExitHook != NULL)
    {
        _SSFECDSAECDHTestExitHook(_SSFECDSAECDHTestExitHookCtx, &d, &S, &Sx, &Sy);
    }
#endif
    return ok;
}
