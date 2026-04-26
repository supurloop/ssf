/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfecdsa.c                                                                                    */
/* Provides ECDSA digital signature and ECDH key agreement implementation.                       */
/*                                                                                               */
/* FIPS 186-4: Digital Signature Standard (DSS)                                                  */
/* RFC 6979: Deterministic Usage of the DSA and ECDSA                                            */
/* NIST SP 800-56A Rev. 3: Pair-Wise Key-Establishment Using Discrete Logarithm Cryptography    */
/* SEC 1 v2: Elliptic Curve Cryptography                                                        */
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
#include "ssfhmac.h"
#include "ssfsha2.h"
#include "ssfasn1.h"
#include "ssfprng.h"

/* --------------------------------------------------------------------------------------------- */
/* Internal: r = k * G via the fastest available scalar multiplication. Dispatches to the curve-  */
/* specific fixed-base comb when configured (~4x faster than the generic windowed routine);       */
/* otherwise falls back to SSFECScalarMul through a stack-built G.                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSAScalarMulBase(SSFECPoint_t *r, const SSFBN_t *k, SSFECCurve_t curve)
{
#if SSF_EC_CONFIG_FIXED_BASE_P256 == 1
    if (curve == SSF_EC_CURVE_P256) { SSFECScalarMulBaseP256(r, k); return; }
#endif
#if SSF_EC_CONFIG_FIXED_BASE_P384 == 1
    if (curve == SSF_EC_CURVE_P384) { SSFECScalarMulBaseP384(r, k); return; }
#endif
    {
        const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
        SSFECPOINT_DEFINE(G, SSF_EC_MAX_LIMBS);
        SSFECPointFromAffine(&G, &c->gx, &c->gy, curve);
        SSFECScalarMul(r, k, &G, curve);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: select HMAC hash type for the curve.                                                */
/* --------------------------------------------------------------------------------------------- */
static SSFHMACHash_t _SSFECDSAGetHMACHash(SSFECCurve_t curve)
{
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
/* Internal: bits2int per RFC 6979 section 2.3.2.                                                */
/* Converts a hash byte string to an integer, right-shifting if the hash is longer than the      */
/* curve order's bit length. For our matched hash/curve pairs (SHA-256/P-256, SHA-384/P-384),    */
/* no shifting is needed.                                                                        */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSABits2Int(SSFBN_t *out, const uint8_t *hash, size_t hashLen,
                              const SSFECCurveParams_t *c)
{
    SSFBNFromBytes(out, hash, hashLen, c->limbs);

    /* If hash bit length > order bit length, right-shift. Not needed for matched pairs. */
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: bits2octets per RFC 6979 section 2.3.4.                                             */
/* Converts a hash to an integer mod n, then to a big-endian byte string of coordBytes length.   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSABits2Octets(uint8_t *out, size_t outLen,
                                 const uint8_t *hash, size_t hashLen,
                                 const SSFECCurveParams_t *c)
{
    SSFBN_DEFINE(z, SSF_EC_MAX_LIMBS);

    _SSFECDSABits2Int(&z, hash, hashLen, c);

    /* Reduce mod n if z >= n */
    if (SSFBNCmp(&z, &c->n) >= 0)
    {
        SSFBNSub(&z, &z, &c->n);
    }

    SSFBNToBytes(&z, out, outLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: RFC 6979 deterministic nonce generation.                                            */
/* Generates k in [1, n-1] using HMAC-DRBG seeded with the private key and message hash.        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAGenK(SSFECCurve_t curve,
                          const uint8_t *privKey, size_t privKeyLen,
                          const uint8_t *hash, size_t hashLen,
                          const SSFECCurveParams_t *c,
                          SSFBN_t *k)
{
    SSFHMACHash_t hmacHash = _SSFECDSAGetHMACHash(curve);
    size_t hlen = _SSFECDSAGetHashSize(curve);
    uint8_t V[SSF_HMAC_MAX_HASH_SIZE];
    uint8_t K[SSF_HMAC_MAX_HASH_SIZE];
    uint8_t h1Octets[SSF_EC_MAX_COORD_BYTES];
    SSFHMACContext_t ctx;
    uint8_t sep;
    uint8_t T[SSF_EC_MAX_COORD_BYTES];
    uint16_t attempts;

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
    SSFHMACEnd(&ctx, K, sizeof(K));

    /* Step e: V = HMAC_K(V) */
    SSFHMAC(hmacHash, K, hlen, V, hlen, V, sizeof(V));

    /* Step f: K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1)) */
    sep = 0x01u;
    SSFHMACBegin(&ctx, hmacHash, K, hlen);
    SSFHMACUpdate(&ctx, V, hlen);
    SSFHMACUpdate(&ctx, &sep, 1);
    SSFHMACUpdate(&ctx, privKey, privKeyLen);
    SSFHMACUpdate(&ctx, h1Octets, c->bytes);
    SSFHMACEnd(&ctx, K, sizeof(K));

    /* Step g: V = HMAC_K(V) */
    SSFHMAC(hmacHash, K, hlen, V, hlen, V, sizeof(V));

    /* Step h: Loop until a valid k is found */
    for (attempts = 0; attempts < 100u; attempts++)
    {
        size_t tLen = 0;

        /* Step h.2: Generate T of coordBytes length */
        while (tLen < c->bytes)
        {
            /* V = HMAC_K(V) */
            SSFHMAC(hmacHash, K, hlen, V, hlen, V, sizeof(V));

            /* T = T || V */
            {
                size_t copyLen = c->bytes - tLen;
                if (copyLen > hlen) copyLen = hlen;
                memcpy(&T[tLen], V, copyLen);
                tLen += copyLen;
            }
        }

        /* Step h.3: k = bits2int(T) */
        _SSFECDSABits2Int(k, T, c->bytes, c);

        /* Check k in [1, n-1] */
        if (!SSFBNIsZero(k) && (SSFBNCmp(k, &c->n) < 0))
        {
            SSFHMACDeInit(&ctx);
            SSFSecureZero(V, sizeof(V));
            SSFSecureZero(K, sizeof(K));
            SSFSecureZero(h1Octets, sizeof(h1Octets));
            SSFSecureZero(T, sizeof(T));
            return true;
        }

        /* Step h.3 (retry): K = HMAC_K(V || 0x00), V = HMAC_K(V) */
        sep = 0x00u;
        SSFHMACBegin(&ctx, hmacHash, K, hlen);
        SSFHMACUpdate(&ctx, V, hlen);
        SSFHMACUpdate(&ctx, &sep, 1);
        SSFHMACEnd(&ctx, K, sizeof(K));

        SSFHMAC(hmacHash, K, hlen, V, hlen, V, sizeof(V));
    }

    SSFHMACDeInit(&ctx);
    SSFSecureZero(V, sizeof(V));
    SSFSecureZero(K, sizeof(K));
    SSFSecureZero(h1Octets, sizeof(h1Octets));
    SSFSecureZero(T, sizeof(T));
    return false; /* Should never reach here for valid inputs */
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-encode an ECDSA signature (r, s) as SEQUENCE { INTEGER, INTEGER }.              */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSASigEncode(const SSFBN_t *r, const SSFBN_t *s,
                               const SSFECCurveParams_t *c,
                               uint8_t *sig, size_t sigSize, size_t *sigLen)
{
    uint8_t rBytes[SSF_EC_MAX_COORD_BYTES];
    uint8_t sBytes[SSF_EC_MAX_COORD_BYTES];
    uint32_t rEncLen, sEncLen, contentLen, seqHdrLen, totalLen;
    uint32_t offset;

    /* Export r and s as big-endian bytes */
    if (!SSFBNToBytes(r, rBytes, c->bytes)) return false;
    if (!SSFBNToBytes(s, sBytes, c->bytes)) return false;

    /* Measure: pass 1 */
    if (!SSFASN1EncInt(NULL, 0, rBytes, (uint32_t)c->bytes, &rEncLen)) return false;
    if (!SSFASN1EncInt(NULL, 0, sBytes, (uint32_t)c->bytes, &sEncLen)) return false;

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
        if (!SSFASN1EncInt(&sig[offset], (uint32_t)(sigSize - offset), rBytes,
                           (uint32_t)c->bytes, &n))
        {
            return false;
        }
        offset += n;
        if (!SSFASN1EncInt(&sig[offset], (uint32_t)(sigSize - offset), sBytes,
                           (uint32_t)c->bytes, &n))
        {
            return false;
        }
        offset += n;
    }

    *sigLen = (size_t)offset;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-decode an ECDSA signature from SEQUENCE { INTEGER, INTEGER } to (r, s).         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSASigDecode(const uint8_t *sig, size_t sigLen,
                               const SSFECCurveParams_t *c,
                               SSFBN_t *r, SSFBN_t *s)
{
    SSFASN1Cursor_t cursor, inner, next, next2;
    const uint8_t *rBuf, *sBuf;
    uint32_t rLen, sLen;

    cursor.buf = sig;
    cursor.bufLen = (uint32_t)sigLen;

    /* Open the outer SEQUENCE */
    if (!SSFASN1DecOpenConstructed(&cursor, SSF_ASN1_TAG_SEQUENCE, &inner, &next)) return false;

    /* Decode r INTEGER */
    if (!SSFASN1DecGetInt(&inner, &rBuf, &rLen, &next2)) return false;

    /* Decode s INTEGER */
    if (!SSFASN1DecGetInt(&next2, &sBuf, &sLen, &next2)) return false;

    /* No trailing data allowed */
    if (!SSFASN1DecIsEmpty(&next2)) return false;

    /* Import into SSFBN_t. Strip leading 0x00 bytes from ASN.1 INTEGER (positive sign padding). */
    {
        const uint8_t *rb = rBuf; uint32_t rl = rLen;
        const uint8_t *sb = sBuf; uint32_t sl = sLen;
        while (rl > 0u && *rb == 0u) { rb++; rl--; }
        while (sl > 0u && *sb == 0u) { sb++; sl--; }
        if (!SSFBNFromBytes(r, rb, rl, c->limbs)) return false;
        if (!SSFBNFromBytes(s, sb, sl, c->limbs)) return false;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: reduce an affine x-coordinate modulo n.                                             */
/* For NIST curves, p > n but p < 2n, so at most one subtraction is needed.                      */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSAReduceModN(SSFBN_t *r, const SSFBN_t *x, const SSFECCurveParams_t *c)
{
    SSFBNCopy(r, x);
    if (SSFBNCmp(r, &c->n) >= 0)
    {
        SSFBNSub(r, r, &c->n);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: validate a private key d is in [1, n-1].                                            */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAPrivKeyIsValid(const SSFBN_t *d, const SSFECCurveParams_t *c)
{
    if (SSFBNIsZero(d)) return false;
    if (SSFBNCmp(d, &c->n) >= 0) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Generate an ECDSA key pair.                                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSAKeyGen(SSFECCurve_t curve,
                    uint8_t *privKey, size_t privKeySize,
                    uint8_t *pubKey, size_t pubKeySize, size_t *pubKeyLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFPRNGContext_t prng;
    uint8_t entropy[SSF_PRNG_ENTROPY_SIZE];
    SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    uint16_t attempts;

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(pubKeyLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeySize >= c->bytes);
    SSF_REQUIRE(pubKeySize >= (1u + 2u * (size_t)c->bytes));

    /* Obtain platform entropy and seed PRNG */
    if (!SSFPortGetEntropy(entropy, (uint16_t)sizeof(entropy))) return false;
    SSFPRNGInitContext(&prng, entropy, sizeof(entropy));

    /* Generate d in [1, n-1] via rejection sampling. SSFBNRandomBelow returns a value in        */
    /* [0, n) — the only remaining case we need to guard is d == 0 (probability ~2^-bitLen(n)). */
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
    if (attempts >= 100u)
    {
        SSFPRNGDeInitContext(&prng);
        return false;
    }

    SSFPRNGDeInitContext(&prng);

    /* Export private key */
    if (!SSFBNToBytes(&d, privKey, c->bytes)) return false;

    /* Compute public key: Q = d * G */
    _SSFECDSAScalarMulBase(&Q, &d, curve);

    /* Encode public key in SEC 1 uncompressed format */
    if (!SSFECPointEncode(&Q, curve, pubKey, pubKeySize, pubKeyLen))
    {
        SSFBNZeroize(&d);
        return false;
    }

    SSFBNZeroize(&d);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Compute the public key from a private key.                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSAPubKeyFromPrivKey(SSFECCurve_t curve,
                               const uint8_t *privKey, size_t privKeyLen,
                               uint8_t *pubKey, size_t pubKeySize, size_t *pubKeyLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(pubKey != NULL);
    SSF_REQUIRE(pubKeyLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeyLen == c->bytes);
    SSF_REQUIRE(pubKeySize >= (1u + 2u * (size_t)c->bytes));

    /* Import and validate private key */
    if (!SSFBNFromBytes(&d, privKey, privKeyLen, c->limbs)) return false;
    if (!_SSFECDSAPrivKeyIsValid(&d, c)) return false;

    /* Q = d * G */
    _SSFECDSAScalarMulBase(&Q, &d, curve);

    /* Encode */
    if (!SSFECPointEncode(&Q, curve, pubKey, pubKeySize, pubKeyLen))
    {
        SSFBNZeroize(&d);
        return false;
    }

    SSFBNZeroize(&d);
    return true;
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

/* --------------------------------------------------------------------------------------------- */
/* Sign a message hash using ECDSA with deterministic nonce (RFC 6979).                          */
/*                                                                                               */
/* Algorithm (FIPS 186-4 section 6.4):                                                           */
/* 1. e = bits2int(hash)                                                                         */
/* 2. k = RFC6979_HMAC_DRBG(privKey, hash)                                                      */
/* 3. R = k * G                                                                                  */
/* 4. r = Rx mod n                                                                               */
/* 5. s = k^(-1) * (e + r * d) mod n                                                             */
/* 6. Return DER(SEQUENCE { INTEGER r, INTEGER s })                                              */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSASign(SSFECCurve_t curve,
                  const uint8_t *privKey, size_t privKeyLen,
                  const uint8_t *hash, size_t hashLen,
                  uint8_t *sig, size_t sigSize, size_t *sigLen)
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

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeyLen == c->bytes);
    /* RFC 5758 §3.2 / FIPS 186-4 §6.4: ECDSA may pair any hash with any curve. The current     */
    /* _SSFECDSABits2Int implementation handles hashLen <= c->bytes correctly (no right-shift   */
    /* required); longer hashes would need bit-truncation which is not implemented.             */
    SSF_REQUIRE(hashLen > 0u && hashLen <= c->bytes);

    /* Import private key */
    if (!SSFBNFromBytes(&d, privKey, privKeyLen, c->limbs)) return false;
    if (!_SSFECDSAPrivKeyIsValid(&d, c)) { SSFBNZeroize(&d); return false; }

    /* e = bits2int(hash) */
    _SSFECDSABits2Int(&e, hash, hashLen, c);
    if (SSFBNCmp(&e, &c->n) >= 0) SSFBNSub(&e, &e, &c->n);

    /* Generate deterministic k per RFC 6979 */
    if (!_SSFECDSAGenK(curve, privKey, privKeyLen, hash, hashLen, c, &k))
    {
        SSFBNZeroize(&d);
        return false;
    }

    /* R = k * G */
    _SSFECDSAScalarMulBase(&R, &k, curve);

    /* Convert R to affine and get r = Rx mod n */
    if (!SSFECPointToAffine(&Rx, &Ry, &R, curve))
    {
        SSFBNZeroize(&d);
        SSFBNZeroize(&k);
        return false;
    }
    _SSFECDSAReduceModN(&r, &Rx, c);

    if (SSFBNIsZero(&r))
    {
        SSFBNZeroize(&d);
        SSFBNZeroize(&k);
        return false;
    }

    /* s = k^(-1) * (e + r * d) mod n */
    if (!SSFBNModInv(&kInv, &k, &c->n))
    {
        SSFBNZeroize(&d);
        SSFBNZeroize(&k);
        return false;
    }

    SSFBNModMul(&tmp, &r, &d, &c->n);     /* r * d mod n */
    SSFBNModAdd(&tmp, &e, &tmp, &c->n);   /* e + r*d mod n */
    SSFBNModMul(&s, &kInv, &tmp, &c->n);  /* k^(-1) * (e + r*d) mod n */

    if (SSFBNIsZero(&s))
    {
        SSFBNZeroize(&d);
        SSFBNZeroize(&k);
        SSFBNZeroize(&kInv);
        return false;
    }

    /* Zeroize secret intermediates */
    SSFBNZeroize(&d);
    SSFBNZeroize(&k);
    SSFBNZeroize(&kInv);

    /* DER-encode the signature */
    return _SSFECDSASigEncode(&r, &s, c, sig, sigSize, sigLen);
}

/* --------------------------------------------------------------------------------------------- */
/* Verify an ECDSA signature over a message hash.                                                */
/*                                                                                               */
/* Algorithm (FIPS 186-4 section 6.4):                                                           */
/* 1. Decode DER signature -> (r, s)                                                             */
/* 2. Check r, s in [1, n-1]                                                                     */
/* 3. e = bits2int(hash)                                                                         */
/* 4. w = s^(-1) mod n                                                                           */
/* 5. u1 = e * w mod n                                                                           */
/* 6. u2 = r * w mod n                                                                           */
/* 7. R = u1 * G + u2 * Q                                                                       */
/* 8. v = Rx mod n                                                                               */
/* 9. Accept iff v == r                                                                          */
/* --------------------------------------------------------------------------------------------- */
/* --------------------------------------------------------------------------------------------- */
/* Verify stage 1: decode + validate pubKey, decode signature, range-check r/s, compute           */
/* e = bits2int(hash), w = s^(-1) mod n, u1 = e*w mod n, u2 = r*w mod n. Local s, e, w are        */
/* released when this helper returns, so they don't contribute to peak stack during the later    */
/* scalar multiplication. Outputs go into caller-owned r, u1, u2, Q slots.                       */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAVerifyInit(const SSFECCurveParams_t *c, SSFECCurve_t curve,
                                const uint8_t *pubKey, size_t pubKeyLen,
                                const uint8_t *hash,   size_t hashLen,
                                const uint8_t *sig,    size_t sigLen,
                                SSFBN_t *rOut, SSFBN_t *u1Out, SSFBN_t *u2Out,
                                SSFECPoint_t *QOut)
{
    SSFBN_DEFINE(s, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(e, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(w, SSF_EC_MAX_LIMBS);

    if (!SSFECPointDecode(QOut, curve, pubKey, pubKeyLen)) return false;
    if (!_SSFECDSASigDecode(sig, sigLen, c, rOut, &s)) return false;
    if (SSFBNIsZero(rOut) || (SSFBNCmp(rOut, &c->n) >= 0)) return false;
    if (SSFBNIsZero(&s) || (SSFBNCmp(&s, &c->n) >= 0)) return false;

    _SSFECDSABits2Int(&e, hash, hashLen, c);
    if (SSFBNCmp(&e, &c->n) >= 0) SSFBNSub(&e, &e, &c->n);

    if (!SSFBNModInv(&w, &s, &c->n)) return false;

    SSFBNModMul(u1Out, &e, &w, &c->n);
    SSFBNModMul(u2Out, rOut, &w, &c->n);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Verify stage 2: compute R = u1 * G + u2 * Q. When fixed-base tables are configured for the    */
/* curve, dispatches to SSFECScalarMulDualBase (~10-15% faster than plain Shamir's trick on the  */
/* dual scalar mul); otherwise falls back to SSFECScalarMulDual. Rejects R = O per FIPS 186-4.   */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAVerifyGetR(const SSFECCurveParams_t *c, SSFECCurve_t curve,
                                const SSFBN_t *u1, const SSFBN_t *u2,
                                const SSFECPoint_t *Q,
                                SSFECPoint_t *Rout)
{
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
/* Verify stage 3: check r ≡ affine(R).x (mod n) directly in Jacobian coordinates, without       */
/* inverting Z. Affine x = R.X / R.Z² mod p, and ECDSA verify wants (affine_x mod n) == r.       */
/*                                                                                                */
/*   Case A (always check): affine_x == r              ⇔  r · Z² ≡ R.X  (mod p)                 */
/*   Case B (only if r < p − n): affine_x == r + n     ⇔  (r + n) · Z² ≡ R.X  (mod p)            */
/*                                                                                                */
/* Case B handles the rare wraparound where the original signer's affine x landed in [n, p−1]    */
/* and got reduced mod n during signing. For NIST P-256 / P-384 this fires with probability      */
/* (p − n)/p ≈ 2^−128 / 2^−191 respectively but is mandatory for spec correctness.               */
/*                                                                                                */
/* Saves one full SSFBNModInv per Verify versus the previous PointToAffine path (~150 µs at      */
/* current Fermat-via-ModExp cost), at the cost of one ModSqr + one or two ModMul mod p.         */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAVerifyCheckR(const SSFECCurveParams_t *c, SSFECCurve_t curve,
                                  const SSFECPoint_t *R, const SSFBN_t *r)
{
    SSFBN_DEFINE(z2, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(rPlusN, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(pMinusN, SSF_EC_MAX_LIMBS);

    (void)curve;

    /* z2 = R.z² mod p */
    SSFBNModMulNIST(&z2, &R->z, &R->z, &c->p);

    /* Case A: t = r * z2 mod p; accept if t == R.x */
    SSFBNModMulNIST(&t, r, &z2, &c->p);
    if (SSFBNCmp(&t, &R->x) == 0) return true;

    /* Case B: only if r < p - n (wraparound is possible). r + n is < p in that case so no   */
    /* extra mod-p reduction is needed before the multiply.                                  */
    SSFBNSub(&pMinusN, &c->p, &c->n);
    if (SSFBNCmp(r, &pMinusN) < 0)
    {
        (void)SSFBNAdd(&rPlusN, r, &c->n);
        SSFBNModMulNIST(&t, &rPlusN, &z2, &c->p);
        if (SSFBNCmp(&t, &R->x) == 0) return true;
    }
    return false;
}

/* Test-only wrapper that exposes _SSFECDSAVerifyCheckR for unit tests that synthesize R.        */
bool _SSFECDSAVerifyCheckRForTest(SSFECCurve_t curve, const SSFECPoint_t *R, const SSFBN_t *r)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    if (c == NULL) return false;
    return _SSFECDSAVerifyCheckR(c, curve, R, r);
}

bool SSFECDSAVerify(SSFECCurve_t curve,
                    const uint8_t *pubKey, size_t pubKeyLen,
                    const uint8_t *hash, size_t hashLen,
                    const uint8_t *sig, size_t sigLen)
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
    /* See SSFECDSASign comment: any hash <= curve order length is mathematically valid. */
    SSF_REQUIRE(hashLen > 0u && hashLen <= c->bytes);

    if (!_SSFECDSAVerifyInit(c, curve, pubKey, pubKeyLen, hash, hashLen, sig, sigLen,
                             &r, &u1, &u2, &Q)) return false;
    if (!_SSFECDSAVerifyGetR(c, curve, &u1, &u2, &Q, &R)) return false;
    return _SSFECDSAVerifyCheckR(c, curve, &R, &r);
}

/* --------------------------------------------------------------------------------------------- */
/* Compute an ECDH shared secret.                                                                */
/*                                                                                               */
/* Algorithm (NIST SP 800-56A Rev. 3):                                                           */
/* 1. Validate peer's public key Q                                                               */
/* 2. S = d * Q (scalar multiplication)                                                          */
/* 3. If S is identity, fail                                                                     */
/* 4. Shared secret = Sx (x-coordinate of S)                                                     */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDHComputeSecret(SSFECCurve_t curve,
                          const uint8_t *privKey, size_t privKeyLen,
                          const uint8_t *peerPubKey, size_t peerPubKeyLen,
                          uint8_t *secret, size_t secretSize, size_t *secretLen)
{
    const SSFECCurveParams_t *c = SSFECGetCurveParams(curve);
    SSFBN_DEFINE(d, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(Q, SSF_EC_MAX_LIMBS);
    SSFECPOINT_DEFINE(S, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(Sx, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(Sy, SSF_EC_MAX_LIMBS);

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(peerPubKey != NULL);
    SSF_REQUIRE(secret != NULL);
    SSF_REQUIRE(secretLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeyLen == c->bytes);
    SSF_REQUIRE(secretSize >= c->bytes);

    /* Import and validate private key */
    if (!SSFBNFromBytes(&d, privKey, privKeyLen, c->limbs))
    {
        SSFBNZeroize(&d);
        return false;
    }
    if (!_SSFECDSAPrivKeyIsValid(&d, c))
    {
        SSFBNZeroize(&d);
        return false;
    }

    /* Decode and validate peer's public key */
    if (!SSFECPointDecode(&Q, curve, peerPubKey, peerPubKeyLen))
    {
        SSFBNZeroize(&d);
        return false;
    }

    /* S = d * Q */
    SSFECScalarMul(&S, &d, &Q, curve);

    SSFBNZeroize(&d);

    /* S must not be identity */
    if (SSFECPointIsIdentity(&S)) return false;

    /* Export x-coordinate of S as shared secret */
    if (!SSFECPointToAffine(&Sx, &Sy, &S, curve)) return false;
    if (!SSFBNToBytes(&Sx, secret, c->bytes)) return false;

    *secretLen = c->bytes;
    return true;
}
