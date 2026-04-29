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
#include "ssfsha2.h"
#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
#include "ssfasn1.h"  /* Sign's _SSFECDSASigEncode is the only consumer; verify is byte-level. */
#endif
#include "ssfprng.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

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
                                    const uint8_t *entropy, size_t entropyLen) = NULL;
void *_SSFECDSAKeyGenTestExitHookCtx = NULL;
#endif /* SSF_CONFIG_ECDSA_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Internal: r = k * G via the fastest configured scalar mul (fixed-base comb when available).   */
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
/* Internal: bits2int per RFC 6979 Sec. 2.3.2 (hash bytes to integer, no shift for matched pairs).*/
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSABits2Int(SSFBN_t *out, const uint8_t *hash, size_t hashLen,
                              const SSFECCurveParams_t *c)
{
    SSFBNFromBytes(out, hash, hashLen, c->limbs);

    /* If hash bit length > order bit length, right-shift. Not needed for matched pairs. */
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: bits2octets per RFC 6979 2.3.4 (hash to integer mod n, then BE bytes coordBytes).   */
/* --------------------------------------------------------------------------------------------- */
static void _SSFECDSABits2Octets(uint8_t *out, size_t outLen, const uint8_t *hash, size_t hashLen,
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
/* Internal: RFC 6979 deterministic nonce generation (HMAC-DRBG; k in [1, n-1]).                 */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAGenK(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                          const uint8_t *hash, size_t hashLen, const SSFECCurveParams_t *c,
                          SSFBN_t *k)
{
    SSFHMACHash_t hmacHash = _SSFECDSAGetHMACHash(curve);
    size_t hlen = _SSFECDSAGetHashSize(curve);
    uint8_t V[SSF_HMAC_MAX_HASH_SIZE];
    uint8_t K[SSF_HMAC_MAX_HASH_SIZE];
    uint8_t h1Octets[SSF_EC_MAX_COORD_BYTES];
    SSFHMACContext_t ctx = {0};
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
            SSFCryptSecureZero(V, sizeof(V));
            SSFCryptSecureZero(K, sizeof(K));
            SSFCryptSecureZero(h1Octets, sizeof(h1Octets));
            SSFCryptSecureZero(T, sizeof(T));
            return true;
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
    /* Wipe k (rejected candidates leak HMAC-DRBG output if the caller skips the cleanup path). */
    SSFBNZeroize(k);
    return false; /* Should never reach here for valid inputs */
}

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-encode an ECDSA signature (r, s) as SEQUENCE { INTEGER, INTEGER }.              */
/* --------------------------------------------------------------------------------------------- */
/* Canonicalize a fixed-width big-endian integer for ASN.1 encoding: strip leading zero bytes,  */
/* then prepend ONE 0x00 byte if the high bit of the first byte is set (so the value is read as */
/* a positive INTEGER in two's complement). Writes a pointer to the canonical bytes into *outBuf */
/* (which may point into the input or into the supplied padBuf scratch).                          */
static void _SSFECDSACanonicalizeInt(const uint8_t *intBuf, uint32_t intLen,
                                     uint8_t *padBuf, uint32_t padBufSize,
                                     const uint8_t **outBuf, uint32_t *outLen)
{
    const uint8_t *p = intBuf;
    uint32_t n = intLen;
    /* intLen == 0 would dereference a zero-byte buffer at *p below; assert as a precondition. */
    SSF_REQUIRE(intLen > 0u);
    while (n > 1u && *p == 0u) { p++; n--; }
    if ((*p & 0x80u) != 0u)
    {
        SSF_ASSERT(padBufSize >= n + 1u);
        padBuf[0] = 0u;
        memcpy(&padBuf[1], p, (size_t)n);
        *outBuf = padBuf;
        *outLen = n + 1u;
    }
    else
    {
        *outBuf = p;
        *outLen = n;
    }
}

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
    uint32_t rEncLen, sEncLen, contentLen, seqHdrLen, totalLen;
    uint32_t offset;

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

#endif /* SSF_ECDSA_CONFIG_ENABLE_SIGN -- end of DER-encode helpers */

/* --------------------------------------------------------------------------------------------- */
/* Internal: DER-decode an ECDSA signature from SEQUENCE { INTEGER, INTEGER } to (r, s).         */
/* --------------------------------------------------------------------------------------------- */
/* Strict DER parse for an ECDSA signature SEQUENCE { INTEGER r, INTEGER s }. Validates the   */
/* structure and emits the (r, s) byte offsets+lengths. Pure byte-level -- no ssfasn1 calls,  */
/* so a verify-only build can drop the entire ssfasn1 module. The strict ruleset rejects the  */
/* BER-tolerant forms a generic decoder would accept, which create signature malleability     */
/* (CVE-2020-14966, CVE-2020-13822, CVE-2019-14859, CVE-2016-1000342 class) -- these are the  */
/* same Wycheproof / RFC 5480 strictness rules.                                                */
/*                                                                                             */
/* Validates:                                                                                  */
/*  - Outer SEQUENCE tag (0x30) and canonical-form length                                     */
/*  - Total byte count exactly matches header + SEQUENCE content                              */
/*  - Two INTEGERs back-to-back, each with short-form length                                  */
/*  - INTEGER length in [1, coordBytes+1] (length 1 holds 0x00..0x7F; length coordBytes+1     */
/*    holds the canonical 0x00 sign-pad followed by an MSB-set byte)                          */
/*  - INTEGER content is canonical positive: no extra leading 0x00, and MSB of first byte     */
/*    must be 0 (a value with MSB set requires the canonical 0x00 prefix; any encoding where  */
/*    the first content byte is >= 0x80 is rejected since ECDSA r,s are always positive)      */
/*  - No trailing data after the second INTEGER                                                */
/*                                                                                             */
/* On success: rOff/rLen and sOff/sLen point at the INTEGER content bytes inside `sig` (no    */
/* leading 0x00 stripping yet -- the caller does that to get a canonical magnitude).           */
static bool _SSFECDSASigParseStrictDER(const uint8_t *sig, size_t sigLen, uint16_t coordBytes,
                                       size_t *rOff, size_t *rLen,
                                       size_t *sOff, size_t *sLen)
{
    size_t pos = 0u;
    size_t seqLen;
    size_t intLen;
    size_t outOff[2];
    size_t outLen[2];
    uint16_t i;

    /* Smallest valid sig: 30 06 02 01 rr 02 01 ss = 8 bytes (1-byte r and s). Use 8 as floor. */
    if (sigLen < 8u) return false;

    /* Outer SEQUENCE tag. */
    if (sig[pos++] != 0x30u) return false;

    /* SEQUENCE length: short form or canonical 0x81 XX; reject 0x82+ (sigs < 256 bytes). */
    if (sig[pos] < 0x80u)
    {
        seqLen = sig[pos++];
    }
    else if (sig[pos] == 0x81u)
    {
        pos++;
        if (pos >= sigLen) return false;
        seqLen = sig[pos++];
        if (seqLen < 0x80u) return false;  /* must use short form when < 128 */
    }
    else
    {
        return false;
    }

    /* Total bytes must match exactly: header (pos) + content (seqLen). */
    if (sigLen != pos + seqLen) return false;

    /* Two INTEGERs: r then s. Same canonical-form requirements. */
    for (i = 0u; i < 2u; i++)
    {
        if (pos >= sigLen) return false;
        if (sig[pos++] != 0x02u) return false;             /* INTEGER tag */
        if (pos >= sigLen) return false;
        if (sig[pos] >= 0x80u) return false;               /* INTEGER length must be short form */
        intLen = sig[pos++];
        if (intLen == 0u) return false;
        if (pos + intLen > sigLen) return false;
        if (intLen > (size_t)coordBytes + 1u) return false; /* exceeds maximum for the curve */

        if (intLen > 1u)
        {
            /* Reject extra leading zero: 0x00 prefix only valid when the next byte's MSB is set. */
            if (sig[pos] == 0x00u && sig[pos + 1u] < 0x80u) return false;
        }
        /* MSB of first content byte must be 0 (positive INTEGER without canonical 0x00 pad). */
        if (sig[pos] >= 0x80u) return false;

        outOff[i] = pos;
        outLen[i] = intLen;
        pos += intLen;
    }

    /* No trailing data after second INTEGER. */
    if (pos != sigLen) return false;

    *rOff = outOff[0]; *rLen = outLen[0];
    *sOff = outOff[1]; *sLen = outLen[1];
    return true;
}

static bool _SSFECDSASigDecode(const uint8_t *sig, size_t sigLen, const SSFECCurveParams_t *c,
                               SSFBN_t *r, SSFBN_t *s)
{
    size_t rOff, rLen, sOff, sLen;

    if (!_SSFECDSASigParseStrictDER(sig, sigLen, c->bytes, &rOff, &rLen, &sOff, &sLen))
    {
        return false;
    }

    /* Strip the canonical 0x00 sign-pad (positive ASN.1 INTEGER convention) so SSFBNFromBytes */
    /* sees the raw magnitude bytes. The strict parser already validated length bounds and    */
    /* canonical-form, so at most one 0x00 leading byte can be present.                        */
    if (rLen > 1u && sig[rOff] == 0u) { rOff++; rLen--; }
    if (sLen > 1u && sig[sOff] == 0u) { sOff++; sLen--; }
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
    mask = (SSFBNLimb_t)(borrow - 1u);  /* all-ones if borrow == 0, else 0 */
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
    if (SSFBNIsZero(d)) return false;
    if (SSFBNCmp(d, &c->n) >= 0) return false;
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Generate an ECDSA key pair.                                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDSAKeyGen(SSFECCurve_t curve, uint8_t *privKey, size_t privKeySize,
                    uint8_t *pubKey, size_t pubKeySize, size_t *pubKeyLen)
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
    SSF_REQUIRE(pubKeySize >= (1u + 2u * (size_t)c->bytes));

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
    /* Wipe d and the HMAC-DRBG seed (leaving the seed on the stack is equivalent to leaking d). */
    SSFBNZeroize(&d);
    if (prngInited) SSFPRNGDeInitContext(&prng);
    SSFCryptSecureZero(entropy, sizeof(entropy));
#if SSF_CONFIG_ECDSA_UNIT_TEST == 1
    if (_SSFECDSAKeyGenTestExitHook != NULL)
    {
        _SSFECDSAKeyGenTestExitHook(_SSFECDSAKeyGenTestExitHookCtx,
                                    &d, entropy, sizeof(entropy));
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

#if SSF_ECDSA_CONFIG_ENABLE_SIGN == 1
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
    bool ok = false;

    SSF_REQUIRE(privKey != NULL);
    SSF_REQUIRE(hash != NULL);
    SSF_REQUIRE(sig != NULL);
    SSF_REQUIRE(sigLen != NULL);
    SSF_REQUIRE(c != NULL);
    SSF_REQUIRE(privKeyLen == c->bytes);
    /* hashLen <= c->bytes (longer hashes would need bit-truncation, not implemented). */
    SSF_REQUIRE(hashLen > 0u && hashLen <= c->bytes);

    /* Import private key */
    if (!SSFBNFromBytes(&d, privKey, privKeyLen, c->limbs)) goto cleanup;
    if (!_SSFECDSAPrivKeyIsValid(&d, c)) goto cleanup;

    /* e = bits2int(hash) */
    _SSFECDSABits2Int(&e, hash, hashLen, c);
    if (SSFBNCmp(&e, &c->n) >= 0) SSFBNSub(&e, &e, &c->n);

    /* Generate deterministic k per RFC 6979 */
    if (!_SSFECDSAGenK(curve, privKey, privKeyLen, hash, hashLen, c, &k)) goto cleanup;

    /* R = k * G */
    _SSFECDSAScalarMulBase(&R, &k, curve);

    /* Convert R to affine and get r = Rx mod n */
    if (!SSFECPointToAffine(&Rx, &Ry, &R, curve)) goto cleanup;
    _SSFECDSAReduceModN(&r, &Rx, c);

    if (SSFBNIsZero(&r)) goto cleanup;

    /* s = k^(-1) * (e + r * d) mod n */
    if (!SSFBNModInv(&kInv, &k, &c->n)) goto cleanup;

    /* CT mod-n arithmetic on secret operands (d, kInv): SSFBNModMulCT, SSFBNModAdd both CT. */
    SSFBNModMulCT(&tmp, &r, &d, &c->n);     /* r * d mod n */
    SSFBNModAdd(&tmp, &e, &tmp, &c->n);     /* e + r*d mod n */
    SSFBNModMulCT(&s, &kInv, &tmp, &c->n);  /* k^(-1) * (e + r*d) mod n */

    if (SSFBNIsZero(&s)) goto cleanup;

    /* DER-encode the signature. */
    ok = _SSFECDSASigEncode(&r, &s, c, sig, sigSize, sigLen);

cleanup:
    /* Wipe every secret-derived limb (d, k, kInv, tmp, R/Rx/Ry; e wiped for audit uniformity). */
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
                                const uint8_t *pubKey, size_t pubKeyLen,
                                const uint8_t *hash, size_t hashLen,
                                const uint8_t *sig, size_t sigLen,
                                SSFBN_t *rOut, SSFBN_t *u1Out, SSFBN_t *u2Out, SSFECPoint_t *QOut)
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

    /* s is public, so non-CT SSFBNModInvExt is faster than the CT SSFBNModInv. */
    if (!SSFBNModInvExt(&w, &s, &c->n)) return false;

    SSFBNModMul(u1Out, &e, &w, &c->n);
    SSFBNModMul(u2Out, rOut, &w, &c->n);
    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Verify stage 2: R = u1 * G + u2 * Q (dispatches to fixed-base dual when configured).          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAVerifyGetR(const SSFECCurveParams_t *c, SSFECCurve_t curve,
                                const SSFBN_t *u1, const SSFBN_t *u2, const SSFECPoint_t *Q,
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
/* Verify stage 3: r == affine(R).x (mod n) checked in Jacobian (no inversion of Z).             */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFECDSAVerifyCheckR(const SSFECCurveParams_t *c, SSFECCurve_t curve,
                                  const SSFECPoint_t *R, const SSFBN_t *r)
{
    SSFBN_DEFINE(z2, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(t, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(rPlusN, SSF_EC_MAX_LIMBS);
    SSFBN_DEFINE(pMinusN, SSF_EC_MAX_LIMBS);

    (void)curve;

    /* z2 = R.z^2 mod p */
    SSFBNModMulNIST(&z2, &R->z, &R->z, &c->p);

    /* Case A: t = r * z2 mod p; accept if t == R.x */
    SSFBNModMulNIST(&t, r, &z2, &c->p);
    if (SSFBNCmp(&t, &R->x) == 0) return true;

    /* Case B: only if r < p - n (wraparound; r + n is then < p without further reduction). */
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
    /* See SSFECDSASign comment: any hash <= curve order length is mathematically valid. */
    SSF_REQUIRE(hashLen > 0u && hashLen <= c->bytes);

    if (!_SSFECDSAVerifyInit(c, curve, pubKey, pubKeyLen, hash, hashLen, sig, sigLen,
                             &r, &u1, &u2, &Q)) return false;
    if (!_SSFECDSAVerifyGetR(c, curve, &u1, &u2, &Q, &R)) return false;
    return _SSFECDSAVerifyCheckR(c, curve, &R, &r);
}

/* --------------------------------------------------------------------------------------------- */
/* Computes an ECDH shared secret S = d * Q (NIST SP 800-56A Rev. 3); returns Sx.                */
/* --------------------------------------------------------------------------------------------- */
bool SSFECDHComputeSecret(SSFECCurve_t curve, const uint8_t *privKey, size_t privKeyLen,
                          const uint8_t *peerPubKey, size_t peerPubKeyLen,
                          uint8_t *secret, size_t secretSize, size_t *secretLen)
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

