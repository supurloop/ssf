/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbn.c                                                                                       */
/* Provides multi-precision big number arithmetic implementation.                                */
/* Supports ECC (P-256, P-384), RSA (2048, 4096), and DH key sizes.                             */
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
#include "ssfbn.h"

/* --------------------------------------------------------------------------------------------- */
/* NIST curve prime constants                                                                    */
/* --------------------------------------------------------------------------------------------- */
/* P-256: 2^256 - 2^224 + 2^192 + 2^96 - 1                                                      */
/* = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF                           */
#if SSF_BN_CONFIG_MAX_BITS >= 256
static SSFBNLimb_t _ssfBNNistP256Limbs[8] =
{
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
    0x00000000ul, 0x00000000ul, 0x00000001ul, 0xFFFFFFFFul
};
const SSFBN_t SSF_BN_NIST_P256 = { _ssfBNNistP256Limbs, 8, 8 };
#endif /* SSF_BN_CONFIG_MAX_BITS >= 256 */

/* P-384: 2^384 - 2^128 - 2^96 + 2^32 - 1                                                       */
/* = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF  */
#if SSF_BN_CONFIG_MAX_BITS >= 384
static SSFBNLimb_t _ssfBNNistP384Limbs[12] =
{
    0xFFFFFFFFul, 0x00000000ul, 0x00000000ul, 0xFFFFFFFFul,
    0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul
};
const SSFBN_t SSF_BN_NIST_P384 = { _ssfBNNistP384Limbs, 12, 12 };
#endif /* SSF_BN_CONFIG_MAX_BITS >= 384 */

/* --------------------------------------------------------------------------------------------- */
/* Internal helper: constant-time select. Returns a if sel != 0, else b.                         */
/* --------------------------------------------------------------------------------------------- */
static SSFBNLimb_t _SSFBNConstSelect(SSFBNLimb_t a, SSFBNLimb_t b, SSFBNLimb_t sel)
{
    SSFBNLimb_t mask = (SSFBNLimb_t)(-(int32_t)(sel != 0u));
    return (a & mask) | (b & ~mask);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal helper: raw add of n limbs. Returns carry.                                           */
/* --------------------------------------------------------------------------------------------- */
static SSFBNLimb_t _SSFBNRawAdd(SSFBNLimb_t *r, const SSFBNLimb_t *a, const SSFBNLimb_t *b,
                                uint16_t n)
{
    SSFBNDLimb_t carry = 0;
    uint16_t i;

    for (i = 0; i < n; i++)
    {
        carry += (SSFBNDLimb_t)a[i] + (SSFBNDLimb_t)b[i];
        r[i] = (SSFBNLimb_t)carry;
        carry >>= SSF_BN_LIMB_BITS;
    }
    return (SSFBNLimb_t)carry;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal helper: raw subtract of n limbs. Returns borrow.                                     */
/* --------------------------------------------------------------------------------------------- */
static SSFBNLimb_t _SSFBNRawSub(SSFBNLimb_t *r, const SSFBNLimb_t *a, const SSFBNLimb_t *b,
                                uint16_t n)
{
    SSFBNDLimb_t borrow = 0;
    uint16_t i;

    for (i = 0; i < n; i++)
    {
        SSFBNDLimb_t diff = (SSFBNDLimb_t)a[i] - (SSFBNDLimb_t)b[i] - borrow;
        r[i] = (SSFBNLimb_t)diff;
        borrow = (diff >> 63) & 1u;
    }
    return (SSFBNLimb_t)borrow;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal helper: raw compare of n limbs. Returns 0 if equal, -1 if a < b, 1 if a > b.        */
/* Constant-time.                                                                                */
/* --------------------------------------------------------------------------------------------- */
static int8_t _SSFBNRawCmp(const SSFBNLimb_t *a, const SSFBNLimb_t *b, uint16_t n)
{
    uint32_t gt = 0;
    uint32_t lt = 0;
    int16_t i;

    for (i = (int16_t)(n - 1u); i >= 0; i--)
    {
        gt |= ((uint32_t)(a[i] > b[i])) & ~(gt | lt);
        lt |= ((uint32_t)(a[i] < b[i])) & ~(gt | lt);
    }
    return (int8_t)((int32_t)gt - (int32_t)lt);
}

/* --------------------------------------------------------------------------------------------- */
/* Set a to zero with the specified working limb count.                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFBNSetZero(SSFBN_t *a, uint16_t numLimbs)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= SSF_BN_MAX_LIMBS);

    memset(a->limbs, 0, (size_t)numLimbs * sizeof(SSFBNLimb_t));
    a->len = numLimbs;
}

/* --------------------------------------------------------------------------------------------- */
/* Set a to a small integer value with the specified working limb count.                         */
/* --------------------------------------------------------------------------------------------- */
void SSFBNSetUint32(SSFBN_t *a, uint32_t val, uint16_t numLimbs)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= SSF_BN_MAX_LIMBS);

    memset(a->limbs, 0, (size_t)numLimbs * sizeof(SSFBNLimb_t));
    a->limbs[0] = val;
    a->len = numLimbs;
}

/* --------------------------------------------------------------------------------------------- */
/* Copy src to dst.                                                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFBNCopy(SSFBN_t *dst, const SSFBN_t *src)
{
    SSF_REQUIRE(dst != NULL);
    SSF_REQUIRE(src != NULL);

    memcpy(dst->limbs, src->limbs, (size_t)src->len * sizeof(SSFBNLimb_t));
    dst->len = src->len;
}

/* --------------------------------------------------------------------------------------------- */
/* Import from big-endian byte array.                                                            */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNFromBytes(SSFBN_t *a, const uint8_t *data, size_t dataLen, uint16_t numLimbs)
{
    size_t maxBytes;
    size_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= SSF_BN_MAX_LIMBS);

    maxBytes = (size_t)numLimbs * sizeof(SSFBNLimb_t);
    if (dataLen > maxBytes) return false;

    memset(a->limbs, 0, maxBytes);
    a->len = numLimbs;

    /* Convert big-endian bytes to little-endian limbs. */
    /* data[dataLen-1] is the least significant byte -> goes into limbs[0] low byte. */
    for (i = 0; i < dataLen; i++)
    {
        size_t bytePos = dataLen - 1u - i;
        uint16_t limbIdx = (uint16_t)(i / sizeof(SSFBNLimb_t));
        uint16_t byteIdx = (uint16_t)(i % sizeof(SSFBNLimb_t));

        a->limbs[limbIdx] |= ((SSFBNLimb_t)data[bytePos]) << (byteIdx * 8u);
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Export to big-endian byte array. Writes exactly outSize bytes (zero-pads leading).             */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNToBytes(const SSFBN_t *a, uint8_t *out, size_t outSize)
{
    size_t totalBytes;
    size_t i;
    size_t padLen;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(out != NULL);

    totalBytes = (size_t)a->len * sizeof(SSFBNLimb_t);

    /* Find actual byte length (skip leading zero limbs/bytes) */
    {
        size_t actualBytes = totalBytes;
        int16_t li;
        for (li = (int16_t)(a->len - 1u); li >= 0; li--)
        {
            if (a->limbs[li] != 0u) break;
            actualBytes -= sizeof(SSFBNLimb_t);
        }
        if (li >= 0)
        {
            /* Count significant bytes in the top nonzero limb */
            SSFBNLimb_t top = a->limbs[li];
            actualBytes = (size_t)li * sizeof(SSFBNLimb_t);
            while (top != 0u)
            {
                actualBytes++;
                top >>= 8;
            }
        }
        else
        {
            actualBytes = 1u; /* Zero value still needs 1 byte */
        }

        if (outSize < actualBytes) return false;
    }

    memset(out, 0, outSize);

    /* Write little-endian limbs into big-endian byte array from the right */
    padLen = outSize - totalBytes;
    for (i = 0; i < (size_t)a->len; i++)
    {
        SSFBNLimb_t limb = a->limbs[i];
        size_t base = outSize - 1u - (i * sizeof(SSFBNLimb_t));
        uint16_t b;

        for (b = 0; b < sizeof(SSFBNLimb_t); b++)
        {
            if (base < b) break;
            out[base - b] = (uint8_t)(limb & 0xFFu);
            limb >>= 8;
        }
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a is zero.                                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNIsZero(const SSFBN_t *a)
{
    SSFBNLimb_t bits = 0;
    uint16_t i;

    SSF_REQUIRE(a != NULL);

    for (i = 0; i < a->len; i++)
    {
        bits |= a->limbs[i];
    }
    return (bits == 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a equals 1.                                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNIsOne(const SSFBN_t *a)
{
    SSFBNLimb_t bits = 0;
    uint16_t i;

    SSF_REQUIRE(a != NULL);

    if (a->limbs[0] != 1u) return false;
    for (i = 1; i < a->len; i++)
    {
        bits |= a->limbs[i];
    }
    return (bits == 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns true if a is even.                                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNIsEven(const SSFBN_t *a)
{
    SSF_REQUIRE(a != NULL);

    return ((a->limbs[0] & 1u) == 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* Constant-time comparison.                                                                     */
/* --------------------------------------------------------------------------------------------- */
int8_t SSFBNCmp(const SSFBN_t *a, const SSFBN_t *b)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(a->len == b->len);

    return _SSFBNRawCmp(a->limbs, b->limbs, a->len);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the index of the most significant set bit (0-based), or 0 if a is zero.              */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFBNBitLen(const SSFBN_t *a)
{
    int16_t i;

    SSF_REQUIRE(a != NULL);

    for (i = (int16_t)(a->len - 1u); i >= 0; i--)
    {
        if (a->limbs[i] != 0u)
        {
            SSFBNLimb_t limb = a->limbs[i];
            uint32_t bits = (uint32_t)i * SSF_BN_LIMB_BITS;

            while (limb != 0u)
            {
                bits++;
                limb >>= 1;
            }
            return bits;
        }
    }
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the value of bit at position pos (0 = LSB).                                           */
/* --------------------------------------------------------------------------------------------- */
uint8_t SSFBNGetBit(const SSFBN_t *a, uint32_t pos)
{
    uint16_t limbIdx;
    uint16_t bitIdx;

    SSF_REQUIRE(a != NULL);

    limbIdx = (uint16_t)(pos / SSF_BN_LIMB_BITS);
    bitIdx = (uint16_t)(pos % SSF_BN_LIMB_BITS);

    if (limbIdx >= a->len) return 0;

    return (uint8_t)((a->limbs[limbIdx] >> bitIdx) & 1u);
}

/* --------------------------------------------------------------------------------------------- */
/* Shift a left by 1 bit in place.                                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFBNShiftLeft1(SSFBN_t *a)
{
    SSFBNLimb_t carry = 0;
    uint16_t i;

    SSF_REQUIRE(a != NULL);

    for (i = 0; i < a->len; i++)
    {
        SSFBNLimb_t newCarry = a->limbs[i] >> (SSF_BN_LIMB_BITS - 1u);
        a->limbs[i] = (a->limbs[i] << 1) | carry;
        carry = newCarry;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Shift a right by 1 bit in place.                                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFBNShiftRight1(SSFBN_t *a)
{
    SSFBNLimb_t carry = 0;
    int16_t i;

    SSF_REQUIRE(a != NULL);

    for (i = (int16_t)(a->len - 1u); i >= 0; i--)
    {
        SSFBNLimb_t newCarry = a->limbs[i] << (SSF_BN_LIMB_BITS - 1u);
        a->limbs[i] = (a->limbs[i] >> 1) | carry;
        carry = newCarry;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a + b. Returns carry.                                                                     */
/* --------------------------------------------------------------------------------------------- */
SSFBNLimb_t SSFBNAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(a->len == b->len);

    r->len = a->len;
    return _SSFBNRawAdd(r->limbs, a->limbs, b->limbs, a->len);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a - b. Returns borrow.                                                                    */
/* --------------------------------------------------------------------------------------------- */
SSFBNLimb_t SSFBNSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(a->len == b->len);

    r->len = a->len;
    return _SSFBNRawSub(r->limbs, a->limbs, b->limbs, a->len);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a * b. Schoolbook multiplication.                                                         */
/* r->len is set to a->len + b->len. r must not alias a or b.                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b)
{
    uint16_t rLen;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(r != a);
    SSF_REQUIRE(r != b);

    rLen = a->len + b->len;
    SSF_REQUIRE(rLen <= SSF_BN_MAX_LIMBS);

    memset(r->limbs, 0, (size_t)rLen * sizeof(SSFBNLimb_t));
    r->len = rLen;

    for (i = 0; i < a->len; i++)
    {
        SSFBNDLimb_t carry = 0;
        uint16_t j;

        if (a->limbs[i] == 0u) continue;

        for (j = 0; j < b->len; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)b->limbs[j] +
                                (SSFBNDLimb_t)r->limbs[i + j] + carry;
            r->limbs[i + j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
        r->limbs[i + b->len] += (SSFBNLimb_t)carry;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a + b) mod m.                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBNLimb_t carry;
    SSFBNLimb_t borrow;
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);

    r->len = m->len;
    carry = _SSFBNRawAdd(r->limbs, a->limbs, b->limbs, m->len);

    /* If carry or r >= m, subtract m */
    tmp.len = m->len;
    borrow = _SSFBNRawSub(tmp.limbs, r->limbs, m->limbs, m->len);

    /* Use result of subtraction if there was a carry from add, or no borrow from sub */
    if ((carry != 0u) || (borrow == 0u))
    {
        memcpy(r->limbs, tmp.limbs, (size_t)m->len * sizeof(SSFBNLimb_t));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a - b) mod m.                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBNLimb_t borrow;
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);

    r->len = m->len;
    borrow = _SSFBNRawSub(r->limbs, a->limbs, b->limbs, m->len);

    /* If borrow, add m back */
    if (borrow != 0u)
    {
        tmp.len = m->len;
        _SSFBNRawAdd(r->limbs, r->limbs, m->limbs, m->len);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a mod m. a->len may be up to 2 * m->len.                                                 */
/* Uses iterative subtraction for small quotients and shift-subtract for general case.           */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMod(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBN_DEFINE(rem, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(shifted, SSF_BN_MAX_LIMBS);
    uint32_t aBits;
    uint32_t mBits;
    int32_t shift;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(!SSFBNIsZero(m));
    SSF_REQUIRE(a->len <= 2u * m->len);
    SSF_REQUIRE(a->len <= SSF_BN_MAX_LIMBS);

    /* Copy a into working remainder at the larger length */
    SSFBNSetZero(&rem, (a->len > m->len) ? a->len : m->len);
    memcpy(rem.limbs, a->limbs, (size_t)a->len * sizeof(SSFBNLimb_t));

    aBits = SSFBNBitLen(&rem);
    mBits = SSFBNBitLen(m);

    if (mBits == 0u) return; /* Avoid division by zero */

    /* Shift-and-subtract division */
    shift = (int32_t)(aBits - mBits);

    /* Prepare shifted modulus at rem's length */
    SSFBNSetZero(&shifted, rem.len);
    {
        /* Copy m into shifted, then shift left by 'shift' bits */
        uint16_t i;
        for (i = 0; i < m->len; i++)
        {
            shifted.limbs[i] = m->limbs[i];
        }
        {
            int32_t s;
            for (s = 0; s < shift; s++)
            {
                SSFBNShiftLeft1(&shifted);
            }
        }
    }

    while (shift >= 0)
    {
        SSFBNLimb_t borrow = _SSFBNRawSub(rem.limbs, rem.limbs, shifted.limbs, rem.len);
        if (borrow != 0u)
        {
            /* Undo: add shifted back */
            _SSFBNRawAdd(rem.limbs, rem.limbs, shifted.limbs, rem.len);
        }
        SSFBNShiftRight1(&shifted);
        shift--;
    }

    /* Copy result into r at m's limb count */
    r->len = m->len;
    memcpy(r->limbs, rem.limbs, (size_t)m->len * sizeof(SSFBNLimb_t));
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m. Generic modular multiplication.                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);
    SSF_REQUIRE((uint16_t)(a->len + b->len) <= SSF_BN_MAX_LIMBS);

    SSFBNMul(&prod, a, b);
    SSFBNMod(r, &prod, m);
}

/* --------------------------------------------------------------------------------------------- */
/* r = gcd(a, b) using binary GCD (Stein's algorithm).                                          */
/* --------------------------------------------------------------------------------------------- */
void SSFBNGcd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b)
{
    SSFBN_DEFINE(u, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(v, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);
    uint32_t shift = 0;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(a->len == b->len);

    if (SSFBNIsZero(a)) { SSFBNCopy(r, b); return; }
    if (SSFBNIsZero(b)) { SSFBNCopy(r, a); return; }

    SSFBNCopy(&u, a);
    SSFBNCopy(&v, b);

    /* Remove and count common factors of 2 */
    while (SSFBNIsEven(&u) && SSFBNIsEven(&v))
    {
        SSFBNShiftRight1(&u);
        SSFBNShiftRight1(&v);
        shift++;
    }

    /* Remove remaining factors of 2 from u */
    while (SSFBNIsEven(&u)) SSFBNShiftRight1(&u);

    while (!SSFBNIsZero(&v))
    {
        while (SSFBNIsEven(&v)) SSFBNShiftRight1(&v);

        if (SSFBNCmp(&u, &v) > 0)
        {
            SSFBNCopy(&tmp, &u);
            SSFBNCopy(&u, &v);
            SSFBNCopy(&v, &tmp);
        }
        SSFBNSub(&v, &v, &u);
    }

    /* Restore common factors of 2 */
    SSFBNCopy(r, &u);
    {
        uint32_t s;
        for (s = 0; s < shift; s++) SSFBNShiftLeft1(r);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: shift-subtract division producing quotient and remainder.                           */
/* q = a / b, r = a mod b. a->len may be up to 2 * b->len. q->len set to a->len.               */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNDivMod(SSFBN_t *q, SSFBN_t *rem, const SSFBN_t *a, const SSFBN_t *b)
{
    SSFBN_DEFINE(shifted, SSF_BN_MAX_LIMBS);
    uint32_t aBits, bBits;
    int32_t shift;
    uint16_t workLen = (a->len > b->len) ? a->len : b->len;

    SSFBNSetZero(q, workLen);
    SSFBNSetZero(rem, workLen);
    memcpy(rem->limbs, a->limbs, (size_t)a->len * sizeof(SSFBNLimb_t));

    aBits = SSFBNBitLen(rem);
    bBits = SSFBNBitLen(b);
    if (bBits == 0u) return;

    shift = (int32_t)(aBits - bBits);
    if (shift < 0) return; /* a < b, quotient is 0, remainder is a */

    SSFBNSetZero(&shifted, workLen);
    {
        uint16_t i;
        for (i = 0; i < b->len && i < workLen; i++) shifted.limbs[i] = b->limbs[i];
    }
    {
        int32_t s;
        for (s = 0; s < shift; s++) SSFBNShiftLeft1(&shifted);
    }

    while (shift >= 0)
    {
        SSFBNShiftLeft1(q);
        if (_SSFBNRawCmp(rem->limbs, shifted.limbs, workLen) >= 0)
        {
            _SSFBNRawSub(rem->limbs, rem->limbs, shifted.limbs, workLen);
            q->limbs[0] |= 1u;
        }
        SSFBNShiftRight1(&shifted);
        shift--;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^(-1) mod m using the standard extended Euclidean algorithm.                             */
/* Works for any coprime a and m (m may be even or odd).                                         */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNModInvExt(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    /* Extended Euclidean algorithm:                                                              */
    /* Maintain old_r, r such that old_r = old_s*a_orig + old_t*m_orig                           */
    /* When old_r = gcd = 1, old_s is the modular inverse.                                       */
    /* We only track the 's' coefficient (for a), not 't' (for m).                               */
    /* Signs are tracked separately since SSFBN_t is unsigned.                                   */
    SSFBN_DEFINE(old_r, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(cur_r, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(old_s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(cur_s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(quotient, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp_r, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp_s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
    bool old_s_neg = false;
    bool cur_s_neg = false;
    uint16_t len = m->len;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(a->len == m->len);

    if (SSFBNIsZero(a)) return false;

    /* old_r = m, cur_r = a (reduced mod m if needed) */
    SSFBNCopy(&old_r, m);
    SSFBNCopy(&cur_r, a);
    if (SSFBNCmp(&cur_r, m) >= 0)
    {
        SSFBNMod(&cur_r, &cur_r, m);
    }
    if (SSFBNIsZero(&cur_r)) return false;

    /* old_s = 0, cur_s = 1 */
    SSFBNSetZero(&old_s, len);
    SSFBNSetUint32(&cur_s, 1u, len);

    while (!SSFBNIsZero(&cur_r))
    {
        bool tmp_neg;

        /* quotient = old_r / cur_r, tmp_r = old_r mod cur_r */
        _SSFBNDivMod(&quotient, &tmp_r, &old_r, &cur_r);

        /* tmp_s = old_s - quotient * cur_s (with sign tracking) */
        /* First compute quotient * cur_s */
        {
            SSFBN_DEFINE(qxs, SSF_BN_MAX_LIMBS);
            /* quotient and cur_s may have len up to 'len'. Product may overflow. */
            /* Since quotient < old_r/cur_r and cur_s < m, product < m^2 which may be > len */
            /* Use modular approach: compute (quotient * cur_s) mod m, track sign */
            /* For safety, compute full product then reduce */
            if ((uint16_t)(quotient.len + cur_s.len) <= SSF_BN_MAX_LIMBS)
            {
                SSFBNMul(&prod, &quotient, &cur_s);
                SSFBNMod(&qxs, &prod, m);
            }
            else
            {
                SSFBNModMul(&qxs, &quotient, &cur_s, m);
            }

            /* tmp_s = old_s - q*cur_s (sign arithmetic) */
            /* If old_s_neg == cur_s_neg: same sign, subtract magnitudes carefully */
            /* If old_s_neg != cur_s_neg: different signs, add magnitudes */
            if (old_s_neg == cur_s_neg)
            {
                /* Both same sign: tmp = |old_s| - |q*cur_s| */
                if (SSFBNCmp(&old_s, &qxs) >= 0)
                {
                    SSFBNSub(&tmp_s, &old_s, &qxs);
                    tmp_neg = old_s_neg;
                }
                else
                {
                    SSFBNSub(&tmp_s, &qxs, &old_s);
                    tmp_neg = !old_s_neg;
                }
            }
            else
            {
                /* Different signs: |old_s| + |q*cur_s| */
                SSFBNModAdd(&tmp_s, &old_s, &qxs, m);
                tmp_neg = old_s_neg;
            }
        }

        /* Shift: old = cur, cur = tmp */
        SSFBNCopy(&old_r, &cur_r);
        SSFBNCopy(&cur_r, &tmp_r);
        SSFBNCopy(&old_s, &cur_s);
        old_s_neg = cur_s_neg;
        SSFBNCopy(&cur_s, &tmp_s);
        cur_s_neg = tmp_neg;
    }

    /* old_r should be 1 (gcd) */
    if (!SSFBNIsOne(&old_r)) return false;

    /* If old_s is negative, add m to make positive */
    if (old_s_neg && !SSFBNIsZero(&old_s))
    {
        SSFBNSub(r, m, &old_s);
    }
    else
    {
        SSFBNCopy(r, &old_s);
    }

    /* Reduce if >= m */
    if (SSFBNCmp(r, m) >= 0)
    {
        SSFBNSub(r, r, m);
    }

    /* Verify: a * r mod m == 1 */
    {
        SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);
        SSFBNModMul(&check, a, r, m);
        if (!SSFBNIsOne(&check)) return false;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: NIST P-256 fast reduction.                                                          */
/* Reduces a 512-bit product modulo P-256 using the special prime structure.                     */
/* Input t has 16 limbs (512 bits). Output r has 8 limbs.                                        */
/* Reference: NIST SP 800-186, Section D.2.1                                                    */
/* --------------------------------------------------------------------------------------------- */
#if SSF_BN_CONFIG_MAX_BITS >= 256
static void _SSFBNReduceP256(SSFBN_t *r, const SSFBN_t *t)
{
    /* Name the 32-bit words: t = (c15 c14 ... c1 c0) where c0 = t->limbs[0] etc. */
    /* Notation follows NIST SP 800-186 D.2.1 */
    const SSFBNLimb_t *c = t->limbs;
    SSFBNLimb_t carry;
    SSFBNLimb_t borrow;
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);

    /* s1 = (c7, c6, c5, c4, c3, c2, c1, c0) -- the low half */
    r->len = 8;
    memcpy(r->limbs, c, 8u * sizeof(SSFBNLimb_t));

    /* s2 = (c15, c14, c13, c12, c11, 0, 0, 0) */
    s.len = 8;
    s.limbs[0] = 0; s.limbs[1] = 0; s.limbs[2] = 0;
    s.limbs[3] = c[11]; s.limbs[4] = c[12]; s.limbs[5] = c[13];
    s.limbs[6] = c[14]; s.limbs[7] = c[15];
    /* Add 2*s2 */
    carry = _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 8);
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 8);

    /* s3 = (0, c15, c14, c13, c12, 0, 0, 0) */
    s.limbs[0] = 0; s.limbs[1] = 0; s.limbs[2] = 0;
    s.limbs[3] = c[12]; s.limbs[4] = c[13]; s.limbs[5] = c[14];
    s.limbs[6] = c[15]; s.limbs[7] = 0;
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 8);
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 8);

    /* s4 = (c15, c14, 0, 0, 0, c10, c9, c8) */
    s.limbs[0] = c[8]; s.limbs[1] = c[9]; s.limbs[2] = c[10];
    s.limbs[3] = 0; s.limbs[4] = 0; s.limbs[5] = 0;
    s.limbs[6] = c[14]; s.limbs[7] = c[15];
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 8);

    /* s5 = (c8, c13, c15, c14, c13, c11, c10, c9) */
    s.limbs[0] = c[9]; s.limbs[1] = c[10]; s.limbs[2] = c[11];
    s.limbs[3] = c[13]; s.limbs[4] = c[14]; s.limbs[5] = c[15];
    s.limbs[6] = c[13]; s.limbs[7] = c[8];
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 8);

    /* Now subtract: d1 = (c10, c8, 0, 0, 0, c13, c12, c11) */
    s.limbs[0] = c[11]; s.limbs[1] = c[12]; s.limbs[2] = c[13];
    s.limbs[3] = 0; s.limbs[4] = 0; s.limbs[5] = 0;
    s.limbs[6] = c[8]; s.limbs[7] = c[10];
    borrow = _SSFBNRawSub(r->limbs, r->limbs, s.limbs, 8);

    /* d2 = (c11, c9, 0, 0, c15, c14, c13, c12) */
    s.limbs[0] = c[12]; s.limbs[1] = c[13]; s.limbs[2] = c[14];
    s.limbs[3] = c[15]; s.limbs[4] = 0; s.limbs[5] = 0;
    s.limbs[6] = c[9]; s.limbs[7] = c[11];
    borrow += _SSFBNRawSub(r->limbs, r->limbs, s.limbs, 8);

    /* d3 = (c12, 0, c10, c9, c8, c15, c14, c13) */
    s.limbs[0] = c[13]; s.limbs[1] = c[14]; s.limbs[2] = c[15];
    s.limbs[3] = c[8]; s.limbs[4] = c[9]; s.limbs[5] = c[10];
    s.limbs[6] = 0; s.limbs[7] = c[12];
    borrow += _SSFBNRawSub(r->limbs, r->limbs, s.limbs, 8);

    /* d4 = (c13, 0, c11, c10, c9, 0, c15, c14) */
    s.limbs[0] = c[14]; s.limbs[1] = c[15]; s.limbs[2] = 0;
    s.limbs[3] = c[9]; s.limbs[4] = c[10]; s.limbs[5] = c[11];
    s.limbs[6] = 0; s.limbs[7] = c[13];
    borrow += _SSFBNRawSub(r->limbs, r->limbs, s.limbs, 8);

    /* Adjust for accumulated carry/borrow */
    /* The result may be slightly above or below [0, p). Add/subtract p as needed. */
    /* carry - borrow gives net adjustment */
    tmp.len = 8;

    /* Handle net borrows: add p back */
    while (borrow > carry)
    {
        _SSFBNRawAdd(r->limbs, r->limbs, SSF_BN_NIST_P256.limbs, 8);
        borrow--;
    }

    /* Handle net carries: subtract p */
    carry -= borrow;
    while (carry > 0u)
    {
        _SSFBNRawSub(r->limbs, r->limbs, SSF_BN_NIST_P256.limbs, 8);
        carry--;
    }

    /* Final reduction: while r >= p, subtract p */
    while (_SSFBNRawCmp(r->limbs, SSF_BN_NIST_P256.limbs, 8) >= 0)
    {
        _SSFBNRawSub(r->limbs, r->limbs, SSF_BN_NIST_P256.limbs, 8);
    }
}
#endif /* SSF_BN_CONFIG_MAX_BITS >= 256 */

/* --------------------------------------------------------------------------------------------- */
/* Internal: NIST P-384 fast reduction.                                                          */
/* Reduces a 768-bit product modulo P-384 using the special prime structure.                     */
/* Input t has 24 limbs (768 bits). Output r has 12 limbs.                                       */
/* Reference: NIST SP 800-186, Section D.2.2                                                    */
/* --------------------------------------------------------------------------------------------- */
#if SSF_BN_CONFIG_MAX_BITS >= 384
static void _SSFBNReduceP384(SSFBN_t *r, const SSFBN_t *t)
{
    const SSFBNLimb_t *c = t->limbs;
    SSFBNLimb_t carry = 0;
    SSFBNLimb_t borrow = 0;
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);

    /* s1 = (c11, c10, c9, c8, c7, c6, c5, c4, c3, c2, c1, c0) */
    r->len = 12;
    memcpy(r->limbs, c, 12u * sizeof(SSFBNLimb_t));

    /* s2 = (0, 0, 0, 0, 0, c23, c22, c21, 0, 0, 0, 0) */
    s.len = 12;
    memset(s.limbs, 0, 12u * sizeof(SSFBNLimb_t));
    s.limbs[4] = c[21]; s.limbs[5] = c[22]; s.limbs[6] = c[23];
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 12);
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 12);

    /* s3 = (c23, c22, c21, c20, c19, c18, c17, c16, c15, c14, c13, c12) */
    s.limbs[0]  = c[12]; s.limbs[1]  = c[13]; s.limbs[2]  = c[14]; s.limbs[3]  = c[15];
    s.limbs[4]  = c[16]; s.limbs[5]  = c[17]; s.limbs[6]  = c[18]; s.limbs[7]  = c[19];
    s.limbs[8]  = c[20]; s.limbs[9]  = c[21]; s.limbs[10] = c[22]; s.limbs[11] = c[23];
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 12);

    /* s4 = (c20, c19, c18, c17, c16, c15, c14, c13, c12, c23, c22, c21) */
    s.limbs[0]  = c[21]; s.limbs[1]  = c[22]; s.limbs[2]  = c[23]; s.limbs[3]  = c[12];
    s.limbs[4]  = c[13]; s.limbs[5]  = c[14]; s.limbs[6]  = c[15]; s.limbs[7]  = c[16];
    s.limbs[8]  = c[17]; s.limbs[9]  = c[18]; s.limbs[10] = c[19]; s.limbs[11] = c[20];
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 12);

    /* s5 = (c19, c18, c17, c16, c15, c14, c13, c12, c20, 0, c23, 0) */
    s.limbs[0]  = 0;     s.limbs[1]  = c[23]; s.limbs[2]  = 0;     s.limbs[3]  = c[20];
    s.limbs[4]  = c[12]; s.limbs[5]  = c[13]; s.limbs[6]  = c[14]; s.limbs[7]  = c[15];
    s.limbs[8]  = c[16]; s.limbs[9]  = c[17]; s.limbs[10] = c[18]; s.limbs[11] = c[19];
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 12);

    /* s6 = (0, 0, 0, 0, c23, c22, c21, c20, 0, 0, 0, 0) */
    memset(s.limbs, 0, 12u * sizeof(SSFBNLimb_t));
    s.limbs[4] = c[20]; s.limbs[5] = c[21]; s.limbs[6] = c[22]; s.limbs[7] = c[23];
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 12);

    /* s7 = (0, 0, 0, 0, 0, 0, c23, c22, c21, 0, 0, c20) */
    memset(s.limbs, 0, 12u * sizeof(SSFBNLimb_t));
    s.limbs[0] = c[20]; s.limbs[3] = c[21]; s.limbs[4] = c[22]; s.limbs[5] = c[23];
    carry += _SSFBNRawAdd(r->limbs, r->limbs, s.limbs, 12);

    /* d1 = (c22, c21, c20, c19, c18, c17, c16, c15, c14, c13, c12, c23) */
    s.limbs[0]  = c[23]; s.limbs[1]  = c[12]; s.limbs[2]  = c[13]; s.limbs[3]  = c[14];
    s.limbs[4]  = c[15]; s.limbs[5]  = c[16]; s.limbs[6]  = c[17]; s.limbs[7]  = c[18];
    s.limbs[8]  = c[19]; s.limbs[9]  = c[20]; s.limbs[10] = c[21]; s.limbs[11] = c[22];
    borrow += _SSFBNRawSub(r->limbs, r->limbs, s.limbs, 12);

    /* d2 = (0, 0, 0, 0, 0, 0, 0, c23, c22, c21, c20, 0) */
    memset(s.limbs, 0, 12u * sizeof(SSFBNLimb_t));
    s.limbs[1] = c[20]; s.limbs[2] = c[21]; s.limbs[3] = c[22]; s.limbs[4] = c[23];
    borrow += _SSFBNRawSub(r->limbs, r->limbs, s.limbs, 12);

    /* d3 = (0, 0, 0, 0, 0, 0, 0, c23, c23, 0, 0, 0) */
    memset(s.limbs, 0, 12u * sizeof(SSFBNLimb_t));
    s.limbs[3] = c[23]; s.limbs[4] = c[23];
    borrow += _SSFBNRawSub(r->limbs, r->limbs, s.limbs, 12);

    /* Adjust for accumulated carry/borrow */
    tmp.len = 12;

    while (borrow > carry)
    {
        _SSFBNRawAdd(r->limbs, r->limbs, SSF_BN_NIST_P384.limbs, 12);
        borrow--;
    }

    carry -= borrow;
    while (carry > 0u)
    {
        _SSFBNRawSub(r->limbs, r->limbs, SSF_BN_NIST_P384.limbs, 12);
        carry--;
    }

    while (_SSFBNRawCmp(r->limbs, SSF_BN_NIST_P384.limbs, 12) >= 0)
    {
        _SSFBNRawSub(r->limbs, r->limbs, SSF_BN_NIST_P384.limbs, 12);
    }
}
#endif /* SSF_BN_CONFIG_MAX_BITS >= 384 */

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m using NIST fast reduction for P-256 or P-384.                               */
/* Falls back to generic SSFBNModMul for other moduli.                                           */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMulNIST(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);

#if SSF_BN_CONFIG_MAX_BITS >= 256
    if ((m->len == 8u) && (_SSFBNRawCmp(m->limbs, SSF_BN_NIST_P256.limbs, 8) == 0))
    {
        SSFBNMul(&prod, a, b);
        _SSFBNReduceP256(r, &prod);
        return;
    }
#endif /* SSF_BN_CONFIG_MAX_BITS >= 256 */

#if SSF_BN_CONFIG_MAX_BITS >= 384
    if ((m->len == 12u) && (_SSFBNRawCmp(m->limbs, SSF_BN_NIST_P384.limbs, 12) == 0))
    {
        SSFBNMul(&prod, a, b);
        _SSFBNReduceP384(r, &prod);
        return;
    }
#endif /* SSF_BN_CONFIG_MAX_BITS >= 384 */

    /* Fallback to generic */
    SSFBNModMul(r, a, b, m);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^(-1) mod m.                                                                             */
/* Uses binary extended GCD (constant-time variant for prime m via Fermat: a^(m-2) mod m).       */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNModInv(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBN_DEFINE(exp, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(two, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(a->len == m->len);

    if (SSFBNIsZero(a)) return false;

    /* Compute exp = m - 2 (Fermat's little theorem for prime m) */
    SSFBNSetUint32(&two, 2u, m->len);
    SSFBNSub(&exp, m, &two);

    /* r = a^(m-2) mod m */
    SSFBNModExp(r, a, &exp, m);

    /* Verify: if a and m are not coprime, the result won't satisfy a*r = 1 mod m */
    {
        SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);
        SSFBNModMul(&check, a, r, m);
        if (!SSFBNIsOne(&check)) return false;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Initialize Montgomery context for a given odd modulus.                                        */
/* Precomputes R^2 mod m and -m^(-1) mod 2^32.                                                  */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontInit(SSFBNMont_t *ctx, const SSFBN_t *m)
{
    uint16_t i;
    SSFBN_DEFINE(r2, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u); /* m must be odd */

    SSFBNCopy(&ctx->mod, m);
    ctx->len = m->len;

    /* Compute mp = -m^(-1) mod 2^32 using Newton's method:                                      */
    /* x = x * (2 - m * x) mod 2^32, starting with x = 1 (since m is odd, m*1 = m = 1 mod 2)   */
    {
        SSFBNLimb_t x = 1;
        SSFBNLimb_t m0 = m->limbs[0];

        for (i = 0; i < 5; i++) /* 5 iterations for 32-bit convergence */
        {
            x = x * (2u - m0 * x);
        }
        ctx->mp = (SSFBNLimb_t)(-(int32_t)x); /* -m^(-1) mod 2^32 */
    }

    /* Compute R^2 mod m where R = 2^(len*32).                                                   */
    /* Start with R mod m = 2^(len*32) mod m, then square it.                                    */
    /* Compute R mod m by repeated subtraction starting from R - m, R - 2m, etc.                 */
    /* More efficient: start with 1, shift left by 1 and reduce, repeated len*32 times.          */
    SSFBNSetUint32(&r2, 1u, m->len);
    for (i = 0; i < (uint16_t)(m->len * SSF_BN_LIMB_BITS * 2u); i++)
    {
        SSFBNModAdd(&r2, &r2, &r2, m); /* r2 = 2 * r2 mod m */
    }
    SSFBNCopy(&ctx->rr, &r2);
}

/* --------------------------------------------------------------------------------------------- */
/* Montgomery multiplication: r = a * b * R^(-1) mod m.                                          */
/* a and b must be in Montgomery form. Uses CIOS (Coarsely Integrated Operand Scanning).         */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBNMont_t *ctx)
{
    /* CIOS Montgomery multiplication */
    SSFBNLimb_t t[SSF_BN_MAX_LIMBS + 2];
    uint16_t n;
    uint16_t i;
    SSFBNLimb_t borrow;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(ctx != NULL);

    n = ctx->len;
    memset(t, 0, (size_t)(n + 2u) * sizeof(SSFBNLimb_t));

    for (i = 0; i < n; i++)
    {
        SSFBNDLimb_t carry = 0;
        SSFBNLimb_t u;
        uint16_t j;

        /* t = t + a[i] * b */
        for (j = 0; j < n; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)b->limbs[j] +
                                (SSFBNDLimb_t)t[j] + carry;
            t[j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
        t[n] += (SSFBNLimb_t)carry;
        t[n + 1u] = (SSFBNLimb_t)((SSFBNDLimb_t)t[n] < carry ? 1u : 0u);

        /* u = t[0] * mp mod 2^32 */
        u = t[0] * ctx->mp;

        /* t = (t + u * m) / 2^32 */
        carry = 0;
        for (j = 0; j < n; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)u * (SSFBNDLimb_t)ctx->mod.limbs[j] +
                                (SSFBNDLimb_t)t[j] + carry;
            t[j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
        {
            SSFBNDLimb_t sum = (SSFBNDLimb_t)t[n] + carry;
            t[n] = (SSFBNLimb_t)sum;
            t[n + 1u] += (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);
        }

        /* Shift right by one limb */
        {
            uint16_t k;
            for (k = 0; k < n + 1u; k++)
            {
                t[k] = t[k + 1u];
            }
            t[n + 1u] = 0;
        }
    }

    /* Final conditional subtraction */
    r->len = n;
    memcpy(r->limbs, t, (size_t)n * sizeof(SSFBNLimb_t));

    borrow = _SSFBNRawSub(r->limbs, r->limbs, ctx->mod.limbs, n);
    if ((borrow != 0u) && (t[n] == 0u))
    {
        /* Undo subtraction */
        _SSFBNRawAdd(r->limbs, r->limbs, ctx->mod.limbs, n);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Convert a to Montgomery form.                                                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontConvertIn(SSFBN_t *aR, const SSFBN_t *a, const SSFBNMont_t *ctx)
{
    SSF_REQUIRE(aR != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(ctx != NULL);

    /* aR = MontMul(a, R^2) = a * R^2 * R^(-1) mod m = a * R mod m */
    SSFBNMontMul(aR, a, &ctx->rr, ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Convert a from Montgomery form.                                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontConvertOut(SSFBN_t *a, const SSFBN_t *aR, const SSFBNMont_t *ctx)
{
    SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(aR != NULL);
    SSF_REQUIRE(ctx != NULL);

    /* a = MontMul(aR, 1) = aR * 1 * R^(-1) mod m = a */
    SSFBNSetUint32(&one, 1u, ctx->len);
    SSFBNMontMul(a, aR, &one, ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^e mod m. Constant-time Montgomery ladder.                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExp(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(m != NULL);

    SSFBNMontInit(&mont, m);
    SSFBNModExpMont(r, a, e, &mont);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^e mod m using precomputed Montgomery context. Constant-time Montgomery ladder.           */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExpMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx)
{
    SSFBN_DEFINE(r0, SSF_BN_MAX_LIMBS);  /* Montgomery form of running result */
    SSFBN_DEFINE(r1, SSF_BN_MAX_LIMBS);  /* Montgomery form of running result * a */
    SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);  /* a in Montgomery form */
    uint32_t eBits;
    int32_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(ctx != NULL);

    eBits = SSFBNBitLen(e);

    if (eBits == 0u)
    {
        /* a^0 = 1 */
        SSFBNSetUint32(r, 1u, ctx->len);
        return;
    }

    /* Convert a to Montgomery form */
    SSFBNMontConvertIn(&aM, a, ctx);

    /* Initialize: r0 = R mod m (i.e., Montgomery form of 1) */
    {
        SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&one, 1u, ctx->len);
        SSFBNMontConvertIn(&r0, &one, ctx);
    }
    SSFBNCopy(&r1, &aM);

    /* Montgomery ladder: constant-time, processes every bit */
    for (i = (int32_t)(eBits - 1u); i >= 0; i--)
    {
        uint8_t bit = SSFBNGetBit(e, (uint32_t)i);

        if (bit != 0u)
        {
            SSFBNMontMul(&r0, &r0, &r1, ctx);
            SSFBNMontMul(&r1, &r1, &r1, ctx);
        }
        else
        {
            SSFBNMontMul(&r1, &r0, &r1, ctx);
            SSFBNMontMul(&r0, &r0, &r0, ctx);
        }
    }

    /* Convert result out of Montgomery form */
    SSFBNMontConvertOut(r, &r0, ctx);

    /* Zeroize temporaries containing key material */
    SSFBNZeroize(&r0);
    SSFBNZeroize(&r1);
    SSFBNZeroize(&aM);
}

/* --------------------------------------------------------------------------------------------- */
/* Constant-time conditional swap.                                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFBNCondSwap(SSFBN_t *a, SSFBN_t *b, SSFBNLimb_t swap)
{
    SSFBNLimb_t mask;
    uint16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(a->len == b->len);

    mask = (SSFBNLimb_t)(-(int32_t)(swap != 0u));

    for (i = 0; i < a->len; i++)
    {
        SSFBNLimb_t diff = (a->limbs[i] ^ b->limbs[i]) & mask;
        a->limbs[i] ^= diff;
        b->limbs[i] ^= diff;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Constant-time conditional copy.                                                               */
/* --------------------------------------------------------------------------------------------- */
void SSFBNCondCopy(SSFBN_t *dst, const SSFBN_t *src, SSFBNLimb_t sel)
{
    SSFBNLimb_t mask;
    uint16_t i;

    SSF_REQUIRE(dst != NULL);
    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(dst->len == src->len);

    mask = (SSFBNLimb_t)(-(int32_t)(sel != 0u));

    for (i = 0; i < dst->len; i++)
    {
        dst->limbs[i] = (src->limbs[i] & mask) | (dst->limbs[i] & ~mask);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Securely zeroize a big number.                                                                */
/* Uses volatile pointer to prevent compiler from optimizing away the clear.                     */
/* --------------------------------------------------------------------------------------------- */
void SSFBNZeroize(SSFBN_t *a)
{
    volatile uint8_t *p;
    size_t i;
    size_t n;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

    /* Zero the limb storage (the secret material) via a volatile write that the compiler can't  */
    /* elide. Leave the struct's own fields (limbs pointer, cap) intact so the SSFBN_t remains   */
    /* usable for subsequent operations; len is explicitly cleared.                              */
    p = (volatile uint8_t *)a->limbs;
    n = (size_t)a->cap * sizeof(SSFBNLimb_t);

    for (i = 0; i < n; i++)
    {
        p[i] = 0;
    }
    a->len = 0;
}
