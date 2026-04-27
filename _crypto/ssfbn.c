/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbn.c                                                                                       */
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
/* Module defines.                                                                               */
/* --------------------------------------------------------------------------------------------- */
/* SSF_BN_MAX_LIMBS must fit in int16_t so a->len + b->len can't overflow uint16_t. */
#if (SSF_BN_MAX_LIMBS > 32767u)
#error "SSF_BN_MAX_LIMBS must fit in int16_t to keep uint16_t sums safe in Mul/Square"
#endif

#define SSF_BN_KARATSUBA_THRESHOLD (32u)
#define SSF_BN_MODEXP_WIN_K        (4u)
#define SSF_BN_MODEXP_TBL_N        ((uint32_t)1u << SSF_BN_MODEXP_WIN_K)
#define SSF_BN_NUM_SMALL_PRIMES    (sizeof(_ssfBNSmallPrimes) / sizeof(_ssfBNSmallPrimes[0]))

/* --------------------------------------------------------------------------------------------- */
/* Module data.                                                                                  */
/* --------------------------------------------------------------------------------------------- */
#if SSF_BN_CONFIG_MAX_BITS >= 256
/* P-256: 2^256 - 2^224 + 2^192 + 2^96 - 1 */
static SSFBNLimb_t _ssfBNNistP256Limbs[8] =
{
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
    0x00000000ul, 0x00000000ul, 0x00000001ul, 0xFFFFFFFFul
};
const SSFBN_t SSF_BN_NIST_P256 = { _ssfBNNistP256Limbs, 8, 8 };
#endif /* SSF_BN_CONFIG_MAX_BITS >= 256 */

#if SSF_BN_CONFIG_MAX_BITS >= 384
/* P-384: 2^384 - 2^128 - 2^96 + 2^32 - 1 */
static SSFBNLimb_t _ssfBNNistP384Limbs[12] =
{
    0xFFFFFFFFul, 0x00000000ul, 0x00000000ul, 0xFFFFFFFFul,
    0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul
};
const SSFBN_t SSF_BN_NIST_P384 = { _ssfBNNistP384Limbs, 12, 12 };
#endif /* SSF_BN_CONFIG_MAX_BITS >= 384 */

/* First 256 primes for trial division during prime-candidate screening (up to 1613). */
static const uint16_t _ssfBNSmallPrimes[] = {
       2,    3,    5,    7,   11,   13,   17,   19,   23,   29,   31,   37,   41,   43,   47,
      53,   59,   61,   67,   71,   73,   79,   83,   89,   97,  101,  103,  107,  109,  113,
     127,  131,  137,  139,  149,  151,  157,  163,  167,  173,  179,  181,  191,  193,  197,
     199,  211,  223,  227,  229,  233,  239,  241,  251,  257,  263,  269,  271,  277,  281,
     283,  293,  307,  311,  313,  317,  331,  337,  347,  349,  353,  359,  367,  373,  379,
     383,  389,  397,  401,  409,  419,  421,  431,  433,  439,  443,  449,  457,  461,  463,
     467,  479,  487,  491,  499,  503,  509,  521,  523,  541,  547,  557,  563,  569,  571,
     577,  587,  593,  599,  601,  607,  613,  617,  619,  631,  641,  643,  647,  653,  659,
     661,  673,  677,  683,  691,  701,  709,  719,  727,  733,  739,  743,  751,  757,  761,
     769,  773,  787,  797,  809,  811,  821,  823,  827,  829,  839,  853,  857,  859,  863,
     877,  881,  883,  887,  907,  911,  919,  929,  937,  941,  947,  953,  967,  971,  977,
     983,  991,  997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187,
    1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,
    1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427,
    1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
    1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613
};

/* --------------------------------------------------------------------------------------------- */
/* Returns a if sel != 0, else b; constant-time.                                                 */
/* --------------------------------------------------------------------------------------------- */
static SSFBNLimb_t _SSFBNConstSelect(SSFBNLimb_t a, SSFBNLimb_t b, SSFBNLimb_t sel)
{
    SSFBNLimb_t mask = (SSFBNLimb_t)(-(int32_t)(sel != 0u));
    return ((a & mask) | (b & ~mask));
}

/* --------------------------------------------------------------------------------------------- */
/* Adds n limbs of a + b into r and returns the final carry.                                     */
/* --------------------------------------------------------------------------------------------- */
static SSFBNLimb_t _SSFBNRawAdd(SSFBNLimb_t *r, const SSFBNLimb_t *a, const SSFBNLimb_t *b,
                                uint16_t n)
{
    SSFBNDLimb_t carry = 0;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(n >= 1u);

    for (i = 0; i < n; i++)
    {
        carry += ((SSFBNDLimb_t)a[i] + (SSFBNDLimb_t)b[i]);
        r[i] = (SSFBNLimb_t)carry;
        carry >>= SSF_BN_LIMB_BITS;
    }
    return (SSFBNLimb_t)carry;
}

/* --------------------------------------------------------------------------------------------- */
/* Subtracts n limbs of b from a into r and returns the final borrow.                            */
/* --------------------------------------------------------------------------------------------- */
static SSFBNLimb_t _SSFBNRawSub(SSFBNLimb_t *r, const SSFBNLimb_t *a, const SSFBNLimb_t *b,
                                uint16_t n)
{
    SSFBNDLimb_t borrow = 0;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(n >= 1u);

    for (i = 0; i < n; i++)
    {
        SSFBNDLimb_t diff = ((SSFBNDLimb_t)a[i] - (SSFBNDLimb_t)b[i] - borrow);
        r[i] = (SSFBNLimb_t)diff;
        borrow = ((diff >> 63) & 1u);
    }
    return (SSFBNLimb_t)borrow;
}

/* --------------------------------------------------------------------------------------------- */
/* Constant-time three-way compare of n limbs; returns 0, -1, or +1.                             */
/* --------------------------------------------------------------------------------------------- */
static int8_t _SSFBNRawCmp(const SSFBNLimb_t *a, const SSFBNLimb_t *b, uint16_t n)
{
    uint32_t gt = 0;
    uint32_t lt = 0;
    int16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(n >= 1u);

    for (i = (int16_t)(n - 1u); i >= 0; i--)
    {
        gt |= (((uint32_t)(a[i] > b[i])) & ~(gt | lt));
        lt |= (((uint32_t)(a[i] < b[i])) & ~(gt | lt));
    }
    return (int8_t)((int32_t)gt - (int32_t)lt);
}

/* --------------------------------------------------------------------------------------------- */
/* Sets a to zero with the specified working limb count.                                         */
/* --------------------------------------------------------------------------------------------- */
void SSFBNSetZero(SSFBN_t *a, uint16_t numLimbs)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(numLimbs <= a->cap);

    memset(a->limbs, 0, (size_t)numLimbs * sizeof(SSFBNLimb_t));
    a->len = numLimbs;
}

/* --------------------------------------------------------------------------------------------- */
/* Sets a to a small integer value with the specified working limb count.                        */
/* --------------------------------------------------------------------------------------------- */
void SSFBNSetUint32(SSFBN_t *a, uint32_t val, uint16_t numLimbs)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(numLimbs <= a->cap);

    memset(a->limbs, 0, (size_t)numLimbs * sizeof(SSFBNLimb_t));
    a->limbs[0] = val;
    a->len = numLimbs;
}

/* --------------------------------------------------------------------------------------------- */
/* Sets a to 1 with the specified working limb count.                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNSetOne(SSFBN_t *a, uint16_t numLimbs)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(numLimbs <= a->cap);

    SSFBNSetUint32(a, 1u, numLimbs);
}

/* --------------------------------------------------------------------------------------------- */
/* Copies src to dst.                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNCopy(SSFBN_t *dst, const SSFBN_t *src)
{
    SSF_REQUIRE(dst != NULL);
    SSF_REQUIRE(dst->limbs != NULL);
    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(src->limbs != NULL);
    SSF_REQUIRE(src->len <= dst->cap);

    memcpy(dst->limbs, src->limbs, (size_t)src->len * sizeof(SSFBNLimb_t));
    dst->len = src->len;
}

/* --------------------------------------------------------------------------------------------- */
/* If data fits in numLimbs then writes a, sets a->len = numLimbs, returns true; else false.     */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNFromBytes(SSFBN_t *a, const uint8_t *data, size_t dataLen, uint16_t numLimbs)
{
    size_t maxBytes;
    size_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(numLimbs <= a->cap);

    maxBytes = (size_t)numLimbs * sizeof(SSFBNLimb_t);
    if (dataLen > maxBytes) return false;

    memset(a->limbs, 0, maxBytes);
    a->len = numLimbs;

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
/* If outSize holds a then writes out (BE, zero-padded leading), returns true; else false.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNToBytes(const SSFBN_t *a, uint8_t *out, size_t outSize)
{
    size_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(out != NULL);

    /* Find the minimum byte length needed to represent a. */
    {
        size_t actualBytes;
        int16_t li;
        for (li = (int16_t)(a->len - 1u); li >= 0; li--)
        {
            if (a->limbs[li] != 0u) break;
        }
        /* Does a have any non-zero limbs? */
        if (li >= 0)
        {
            /* Yes, count the significant bytes in the top non-zero limb. */
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
            /* No, represent zero as a single 0x00 byte. */
            actualBytes = 1u;
        }

        /* Is the caller's buffer large enough to hold the significant bytes? */
        if (outSize < actualBytes)
        {
            /* No, report failure so the caller can grow the buffer. */
            return false;
        }
    }

    memset(out, 0, outSize);

    /* Write LE limbs into the tail of the BE buffer; limbs past outSize are already zero. */
    for (i = 0; i < (size_t)a->len; i++)
    {
        SSFBNLimb_t limb = a->limbs[i];
        size_t limbOffset = i * sizeof(SSFBNLimb_t);
        uint16_t b;

        /* Does this limb's byte range reach into out[]? */
        if (limbOffset >= outSize)
        {
            /* No, further limbs are entirely past the buffer — stop. */
            break;
        }

        for (b = 0; b < sizeof(SSFBNLimb_t); b++)
        {
            /* Does byte b of this limb fall inside the output buffer? */
            if ((limbOffset + b) >= outSize)
            {
                /* No, the remaining high bytes of this limb don't fit — stop this limb. */
                break;
            }
            /* Yes, write the byte into its big-endian slot. */
            out[outSize - 1u - limbOffset - b] = (uint8_t)(limb & 0xFFu);
            limb >>= 8;
        }
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* If data fits in numLimbs then writes a (LE), sets a->len = numLimbs, returns true; else       */
/* false.                                                                                        */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNFromBytesLE(SSFBN_t *a, const uint8_t *data, size_t dataLen, uint16_t numLimbs)
{
    size_t maxBytes;
    size_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE((data != NULL) || (dataLen == 0));
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(numLimbs <= a->cap);

    maxBytes = (size_t)numLimbs * sizeof(SSFBNLimb_t);

    /* Does the input fit in numLimbs worth of bytes? */
    if (dataLen > maxBytes)
    {
        /* No, the high bytes would be truncated — reject. */
        return false;
    }

    memset(a->limbs, 0, maxBytes);
    a->len = numLimbs;

    /* Pack each byte into its limb at its byte offset. */
    for (i = 0; i < dataLen; i++)
    {
        uint16_t limbIdx = (uint16_t)(i / sizeof(SSFBNLimb_t));
        uint16_t byteIdx = (uint16_t)(i % sizeof(SSFBNLimb_t));
        a->limbs[limbIdx] |= ((SSFBNLimb_t)data[i]) << (byteIdx * 8u);
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* If outSize holds a then writes out (LE, zero-padded high), returns true; else false.          */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNToBytesLE(const SSFBN_t *a, uint8_t *out, size_t outSize)
{
    size_t actualBytes;
    int16_t li;
    size_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(out != NULL);

    /* Count the minimum bytes needed to represent a (same logic as SSFBNToBytes). */
    for (li = (int16_t)(a->len - 1u); li >= 0; li--)
    {
        if (a->limbs[li] != 0u) break;
    }
    /* Does a have any non-zero limbs? */
    if (li >= 0)
    {
        /* Yes, count significant bytes within the top non-zero limb. */
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
        /* No, the value is zero — represent as a single 0x00 byte. */
        actualBytes = 1u;
    }

    /* Is the caller's buffer large enough for the significant bytes? */
    if (outSize < actualBytes)
    {
        /* No, report failure. */
        return false;
    }

    memset(out, 0, outSize);

    /* Each byte goes to its linear offset: data[i] = limb[i/4] >> (i%4 * 8). */
    for (i = 0; i < actualBytes; i++)
    {
        uint16_t limbIdx = (uint16_t)(i / sizeof(SSFBNLimb_t));
        uint16_t byteIdx = (uint16_t)(i % sizeof(SSFBNLimb_t));
        out[i] = (uint8_t)((a->limbs[limbIdx] >> (byteIdx * 8u)) & 0xFFu);
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* If a is zero then returns true, else false.                                                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNIsZero(const SSFBN_t *a)
{
    SSFBNLimb_t bits = 0;
    uint16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

    for (i = 0; i < a->len; i++)
    {
        bits |= a->limbs[i];
    }
    return (bits == 0u);
}

/* --------------------------------------------------------------------------------------------- */
/* If a is one then returns true, else false.                                                    */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNIsOne(const SSFBN_t *a)
{
    SSFBNLimb_t bits;
    uint16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(a->len >= 1u);

    /* Fold limb[0]^1 into the OR-accumulator so the result is one CT comparison. */
    bits = a->limbs[0] ^ 1u;
    for (i = 1; i < a->len; i++)
    {
        bits |= a->limbs[i];
    }
    return (bits == 0u);
}

/* SSFBNIsEven and SSFBNIsOdd are macros in ssfbn.h to eliminate call overhead. */

/* --------------------------------------------------------------------------------------------- */
/* Returns 0 if a equals b, -1 if a < b, +1 if a > b; constant-time.                             */
/* --------------------------------------------------------------------------------------------- */
int8_t SSFBNCmp(const SSFBN_t *a, const SSFBN_t *b)
{
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(a->len == b->len);
    SSF_REQUIRE(a->len >= 1u);

    return _SSFBNRawCmp(a->limbs, b->limbs, a->len);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns 0 if a equals val, -1 if a < val, +1 if a > val; constant-time over a->len.           */
/* --------------------------------------------------------------------------------------------- */
int8_t SSFBNCmpUint32(const SSFBN_t *a, uint32_t val)
{
    uint16_t i;
    SSFBNLimb_t highBits = 0;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(a->len >= 1u);

    /* OR together all limbs above limb[0]; any set bit means a > val regardless of limb[0]. */
    for (i = 1; i < a->len; i++)
    {
        highBits |= a->limbs[i];
    }

    /* Does a have any content above limb[0]? */
    if (highBits != 0u)
    {
        /* Yes, a > val since val fits entirely in a single limb. */
        return 1;
    }
    /* No, the comparison reduces to limb[0] vs val. */
    if (a->limbs[0] < val) return -1;
    if (a->limbs[0] > val) return 1;
    return 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the index of the most significant set bit (0-based), or 0 if a is zero.               */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFBNBitLen(const SSFBN_t *a)
{
    int16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

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
/* Returns the number of trailing zero bits (index of the lowest set bit).                       */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFBNTrailingZeros(const SSFBN_t *a)
{
    uint16_t i;
    SSFBNLimb_t limb;
    uint32_t pos;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

    /* Scan low-to-high for the first non-zero limb. */
    for (i = 0; i < a->len; i++)
    {
        /* Is this limb non-zero? */
        if (a->limbs[i] != 0u)
        {
            /* Yes, the lowest set bit of a lives in this limb. */
            break;
        }
    }
    /* The caller must guarantee a is non-zero; asserting here catches the bug at its source. */
    SSF_REQUIRE(i < a->len);

    /* Within the limb, shift right until the low bit is set, counting steps. */
    limb = a->limbs[i];
    pos = 0;
    while ((limb & 1u) == 0u)
    {
        limb >>= 1;
        pos++;
    }

    return ((uint32_t)i * SSF_BN_LIMB_BITS) + pos;
}

/* --------------------------------------------------------------------------------------------- */
/* Shifts a left by 1 bit in place.                                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFBNShiftLeft1(SSFBN_t *a)
{
    SSFBNLimb_t carry = 0;
    uint16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

    for (i = 0; i < a->len; i++)
    {
        SSFBNLimb_t newCarry = a->limbs[i] >> (SSF_BN_LIMB_BITS - 1u);
        a->limbs[i] = (a->limbs[i] << 1) | carry;
        carry = newCarry;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Shifts a right by 1 bit in place.                                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFBNShiftRight1(SSFBN_t *a)
{
    SSFBNLimb_t carry = 0;
    int16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

    for (i = (int16_t)(a->len - 1u); i >= 0; i--)
    {
        SSFBNLimb_t newCarry = a->limbs[i] << (SSF_BN_LIMB_BITS - 1u);
        a->limbs[i] = (a->limbs[i] >> 1) | carry;
        carry = newCarry;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Shifts a left by nBits in place.                                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFBNShiftLeft(SSFBN_t *a, uint32_t nBits)
{
    uint16_t limbShift;
    uint32_t bitShift;
    uint16_t n;
    int16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

    n = a->len;

    /* Does the shift zero the entire value? */
    if (nBits >= ((uint32_t)n * SSF_BN_LIMB_BITS))
    {
        /* Yes, clear all limbs. */
        memset(a->limbs, 0, (size_t)n * sizeof(SSFBNLimb_t));
        return;
    }
    /* Is this a no-op? */
    if (nBits == 0u)
    {
        /* Yes, nothing to do. */
        return;
    }

    limbShift = (uint16_t)(nBits / SSF_BN_LIMB_BITS);
    bitShift = nBits % SSF_BN_LIMB_BITS;

    /* Limb-shift pass: move a[i - limbShift] to a[i], top-down to avoid overwriting sources. */
    if (limbShift > 0u)
    {
        for (i = (int16_t)(n - 1u); i >= (int16_t)limbShift; i--)
        {
            a->limbs[i] = a->limbs[i - limbShift];
        }
        /* Zero the freed low limbs. */
        for (i = 0; i < (int16_t)limbShift; i++)
        {
            a->limbs[i] = 0u;
        }
    }

    /* bitShift == 0 skipped to avoid `limb >> 32` UB on 32-bit limbs. */
    if (bitShift != 0u)
    {
        SSFBNLimb_t carry = 0u;
        for (i = (int16_t)limbShift; i < (int16_t)n; i++)
        {
            SSFBNLimb_t limb = a->limbs[i];
            SSFBNLimb_t newCarry = (SSFBNLimb_t)(limb >> (SSF_BN_LIMB_BITS - bitShift));
            a->limbs[i] = (SSFBNLimb_t)((limb << bitShift) | carry);
            carry = newCarry;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Shifts a right by nBits in place. Mirror of SSFBNShiftLeft.                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFBNShiftRight(SSFBN_t *a, uint32_t nBits)
{
    uint16_t limbShift;
    uint32_t bitShift;
    uint16_t n;
    uint16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

    n = a->len;

    /* Does the shift zero the entire value? */
    if (nBits >= ((uint32_t)n * SSF_BN_LIMB_BITS))
    {
        /* Yes, clear all limbs. */
        memset(a->limbs, 0, (size_t)n * sizeof(SSFBNLimb_t));
        return;
    }
    /* Is this a no-op? */
    if (nBits == 0u)
    {
        /* Yes, nothing to do. */
        return;
    }

    limbShift = (uint16_t)(nBits / SSF_BN_LIMB_BITS);
    bitShift = nBits % SSF_BN_LIMB_BITS;

    /* Limb-shift pass: move a[i + limbShift] to a[i], bottom-up to avoid overwriting sources. */
    if (limbShift > 0u)
    {
        for (i = 0; i + limbShift < n; i++)
        {
            a->limbs[i] = a->limbs[i + limbShift];
        }
        /* Zero the freed high limbs. */
        for (i = (uint16_t)(n - limbShift); i < n; i++)
        {
            a->limbs[i] = 0u;
        }
    }

    /* Bit-shift pass (0 < bitShift < 32). */
    if (bitShift != 0u)
    {
        SSFBNLimb_t carry = 0u;
        uint16_t top = (uint16_t)(n - limbShift);
        for (i = top; i > 0u; i--)
        {
            SSFBNLimb_t limb = a->limbs[i - 1u];
            SSFBNLimb_t newCarry = (SSFBNLimb_t)(limb << (SSF_BN_LIMB_BITS - bitShift));
            a->limbs[i - 1u] = (SSFBNLimb_t)((limb >> bitShift) | carry);
            carry = newCarry;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the final carry from r = a + b.                                                       */
/* --------------------------------------------------------------------------------------------- */
SSFBNLimb_t SSFBNAdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(a->len == b->len);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(a->len <= r->cap);

    r->len = a->len;
    return _SSFBNRawAdd(r->limbs, a->limbs, b->limbs, a->len);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the final borrow from r = a - b.                                                      */
/* --------------------------------------------------------------------------------------------- */
SSFBNLimb_t SSFBNSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(a->len == b->len);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(a->len <= r->cap);

    r->len = a->len;
    return _SSFBNRawSub(r->limbs, a->limbs, b->limbs, a->len);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the final carry from r = a + b where b is a single 32-bit value.                      */
/* --------------------------------------------------------------------------------------------- */
SSFBNLimb_t SSFBNAddUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b)
{
    SSFBNDLimb_t carry;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(a->len <= r->cap);

    r->len = a->len;
    /* First iteration adds b; subsequent iterations only propagate the carry. */
    carry = (SSFBNDLimb_t)b;
    for (i = 0; i < a->len; i++)
    {
        carry += (SSFBNDLimb_t)a->limbs[i];
        r->limbs[i] = (SSFBNLimb_t)carry;
        carry >>= SSF_BN_LIMB_BITS;
    }
    return (SSFBNLimb_t)carry;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns the final borrow from r = a - b where b is a single 32-bit value.                     */
/* --------------------------------------------------------------------------------------------- */
SSFBNLimb_t SSFBNSubUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b)
{
    SSFBNLimb_t borrow;
    SSFBNLimb_t sub;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(a->len <= r->cap);

    r->len = a->len;
    /* sub carries b into limb 0 then zeroes; only the borrow propagates through higher limbs. */
    borrow = 0;
    sub = b;
    for (i = 0; i < a->len; i++)
    {
        SSFBNDLimb_t diff = (SSFBNDLimb_t)a->limbs[i] -
                            (SSFBNDLimb_t)sub -
                            (SSFBNDLimb_t)borrow;
        r->limbs[i] = (SSFBNLimb_t)diff;
        borrow = (SSFBNLimb_t)((diff >> SSF_BN_LIMB_BITS) & 1u);
        sub = 0u;
    }
    return borrow;
}

/* --------------------------------------------------------------------------------------------- */
/* Schoolbook multiply on raw limb pointers; r is overwritten with na + nb limbs.                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNSchoolbookMulRaw(SSFBNLimb_t *r,
                                   const SSFBNLimb_t *a, uint16_t na,
                                   const SSFBNLimb_t *b, uint16_t nb)
{
    uint16_t i;
    uint16_t j;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(na >= 1u);
    SSF_REQUIRE(nb >= 1u);
    SSF_REQUIRE((uint32_t)na + (uint32_t)nb <= (uint32_t)SSF_BN_MAX_LIMBS);

    memset(r, 0, (size_t)(na + nb) * sizeof(SSFBNLimb_t));

    for (i = 0; i < na; i++)
    {
        SSFBNDLimb_t carry = 0;
        SSFBNLimb_t ai = a[i];

        /* No zero-limb skip: secret-data paths require timing independent of operand bits. */
        for (j = 0; j < nb; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)ai * (SSFBNDLimb_t)b[j] +
                                (SSFBNDLimb_t)r[i + j] + carry;
            r[i + j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
        r[i + nb] += (SSFBNLimb_t)carry;
#ifdef _WIN32
#pragma warning(pop)
#endif
    }
}

/* --------------------------------------------------------------------------------------------- */
/* One-level Karatsuba mul for same-size even-length operands; r must be 2n limbs, no alias.     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNKaratsubaMul(SSFBNLimb_t *r,
                               const SSFBNLimb_t *a,
                               const SSFBNLimb_t *b, uint16_t n)
{
    /* half+1-limb sum buffers and n+2-limb mid product. Sized for the largest allowed n. */
    SSFBNLimb_t sumA[(SSF_BN_MAX_LIMBS / 2u) + 1u];
    SSFBNLimb_t sumB[(SSF_BN_MAX_LIMBS / 2u) + 1u];
    SSFBNLimb_t mid[SSF_BN_MAX_LIMBS + 2u];
    uint16_t half;
    uint16_t i;
    SSFBNLimb_t borrow;
    SSFBNDLimb_t addCarry;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(n >= 1u);
    SSF_REQUIRE((uint32_t)(n * 2u) <= (uint32_t)SSF_BN_MAX_LIMBS);

    /* Fall back to schoolbook when size below threshold or n is odd. */
    if ((n < SSF_BN_KARATSUBA_THRESHOLD) || ((n & 1u) != 0u))
    {
        _SSFBNSchoolbookMulRaw(r, a, n, b, n);
        return;
    }

    half = (uint16_t)(n / 2u);

    /* Step 1: z0 = aL * bL -> r[0..n-1]. */
    _SSFBNSchoolbookMulRaw(r, a, half, b, half);

    /* Step 2: z2 = aH * bH -> r[n..2n-1]. */
    _SSFBNSchoolbookMulRaw(&r[n], &a[half], half, &b[half], half);

    /* Step 3: sumA = aL + aH, sumB = bL + bH, each (half+1) limbs including the carry bit. */
    sumA[half] = _SSFBNRawAdd(sumA, a, &a[half], half);
    sumB[half] = _SSFBNRawAdd(sumB, b, &b[half], half);

    /* Step 4: mid = sumA * sumB -> up to 2*(half+1) = n+2 limbs. */
    _SSFBNSchoolbookMulRaw(mid, sumA, (uint16_t)(half + 1u), sumB, (uint16_t)(half + 1u));

    /* Step 5: mid -= z0 (occupying r[0..n-1]). */
    borrow = _SSFBNRawSub(mid, mid, r, n);
    for (i = n; (borrow != 0u) && (i < (uint16_t)(n + 2u)); i++)
    {
        SSFBNDLimb_t diff = (SSFBNDLimb_t)mid[i] - (SSFBNDLimb_t)borrow;
        mid[i] = (SSFBNLimb_t)diff;
        borrow = (SSFBNLimb_t)((diff >> SSF_BN_LIMB_BITS) & 1u);
    }

    /* Step 6: mid -= z2 (occupying r[n..2n-1]). */
    borrow = _SSFBNRawSub(mid, mid, &r[n], n);
    for (i = n; (borrow != 0u) && (i < (uint16_t)(n + 2u)); i++)
    {
        SSFBNDLimb_t diff = (SSFBNDLimb_t)mid[i] - (SSFBNDLimb_t)borrow;
        mid[i] = (SSFBNLimb_t)diff;
        borrow = (SSFBNLimb_t)((diff >> SSF_BN_LIMB_BITS) & 1u);
    }

    /* Step 7: r[half .. half+n+1] += mid[0 .. n+1], propagate carry through higher r limbs. */
    addCarry = 0;
    for (i = 0; i < (uint16_t)(n + 2u); i++)
    {
        addCarry += (SSFBNDLimb_t)r[half + i] + (SSFBNDLimb_t)mid[i];
        r[half + i] = (SSFBNLimb_t)addCarry;
        addCarry >>= SSF_BN_LIMB_BITS;
    }
    for (i = (uint16_t)(half + n + 2u); (addCarry != 0u) && (i < (uint16_t)(2u * n)); i++)
    {
        addCarry += (SSFBNDLimb_t)r[i];
        r[i] = (SSFBNLimb_t)addCarry;
        addCarry >>= SSF_BN_LIMB_BITS;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a * b; Karatsuba for same-size even-length operands at threshold, else schoolbook.        */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b)
{
    uint16_t rLen;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(r != a);
    SSF_REQUIRE(r != b);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(b->len >= 1u);

    rLen = a->len + b->len;
    SSF_REQUIRE(rLen <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(rLen <= r->cap);

    /* Is this a same-size, even-length multiply at or above the Karatsuba threshold? */
    if ((a->len == b->len) &&
        (a->len >= SSF_BN_KARATSUBA_THRESHOLD) &&
        ((a->len & 1u) == 0u))
    {
        /* Yes, dispatch to Karatsuba — ~0.75·n² single-limb multiplies vs n² schoolbook. */
        _SSFBNKaratsubaMul(r->limbs, a->limbs, b->limbs, a->len);
        r->len = rLen;
        return;
    }

    /* No, use schoolbook (handles asymmetric-length or small-operand cases). */
    memset(r->limbs, 0, (size_t)rLen * sizeof(SSFBNLimb_t));
    r->len = rLen;

    for (i = 0; i < a->len; i++)
    {
        SSFBNDLimb_t carry = 0;
        uint16_t j;

        /* No zero-limb skip — see _SSFBNSchoolbookMulRaw for rationale. */
        for (j = 0; j < b->len; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)b->limbs[j] +
                                (SSFBNDLimb_t)r->limbs[i + j] + carry;
            r->limbs[i + j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
        r->limbs[i + b->len] += (SSFBNLimb_t)carry;
#ifdef _WIN32
#pragma warning(pop)
#endif
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a * b where b is a single 32-bit value.                                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMulUint32(SSFBN_t *r, const SSFBN_t *a, uint32_t b)
{
    SSFBNDLimb_t carry;
    uint16_t rLen;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(r != a);
    SSF_REQUIRE(a->len >= 1u);

    rLen = (uint16_t)(a->len + 1u);
    SSF_REQUIRE(rLen <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(rLen <= r->cap);

    carry = 0;
    for (i = 0; i < a->len; i++)
    {
        carry += (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)b;
        r->limbs[i] = (SSFBNLimb_t)carry;
        carry >>= SSF_BN_LIMB_BITS;
    }
    r->limbs[a->len] = (SSFBNLimb_t)carry;
    r->len = rLen;
}

/* --------------------------------------------------------------------------------------------- */
/* r = a * a via triangular squaring (strict upper triangle, doubled, then diagonal added).      */
/* --------------------------------------------------------------------------------------------- */
void SSFBNSquare(SSFBN_t *r, const SSFBN_t *a)
{
    uint16_t n;
    uint16_t rLen;
    uint16_t i;
    uint16_t k;
    SSFBNLimb_t shiftCarry;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(r != a);
    SSF_REQUIRE(a->len >= 1u);

    n = a->len;
    rLen = (uint16_t)(n * 2u);
    SSF_REQUIRE(rLen <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(rLen <= r->cap);

    memset(r->limbs, 0, (size_t)rLen * sizeof(SSFBNLimb_t));
    r->len = rLen;

    /* Step 1: accumulate strict upper triangle a[i]*a[j] (i<j); r[2n-1] stays 0 so step 2 fits. */
    for (i = 0; i + 1u < n; i++)
    {
        SSFBNDLimb_t carry = 0;
        uint16_t j;
        SSFBNLimb_t ai = a->limbs[i];

        /* No zero-limb skip — see _SSFBNSchoolbookMulRaw for rationale. */
        for (j = (uint16_t)(i + 1u); j < n; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)ai * (SSFBNDLimb_t)a->limbs[j] +
                                (SSFBNDLimb_t)r->limbs[i + j] + carry;
            r->limbs[i + j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
        r->limbs[i + n] += (SSFBNLimb_t)carry;
    }

    /* Step 2: double the upper triangle via a single shift-left-by-1 across 2n limbs. */
    shiftCarry = 0;
    for (k = 0; k < rLen; k++)
    {
        SSFBNLimb_t newCarry = r->limbs[k] >> (SSF_BN_LIMB_BITS - 1u);
        r->limbs[k] = (SSFBNLimb_t)((r->limbs[k] << 1) | shiftCarry);
        shiftCarry = newCarry;
    }

    /* Step 3: add diagonal a[i]*a[i] terms at offset 2i; propagate any carry forward. */
    for (i = 0; i < n; i++)
    {
        SSFBNDLimb_t sq = (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)a->limbs[i];
        SSFBNDLimb_t sum;
        SSFBNLimb_t carry;
        uint16_t pos;

        /* Low half of the square into r[2i]. */
        sum = (SSFBNDLimb_t)r->limbs[2u * i] + (SSFBNDLimb_t)(SSFBNLimb_t)sq;
        r->limbs[2u * i] = (SSFBNLimb_t)sum;
        carry = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);

        /* High half of the square plus incoming carry into r[2i+1]. */
        sum = (SSFBNDLimb_t)r->limbs[2u * i + 1u] +
              (SSFBNDLimb_t)(SSFBNLimb_t)(sq >> SSF_BN_LIMB_BITS) +
              (SSFBNDLimb_t)carry;
        r->limbs[2u * i + 1u] = (SSFBNLimb_t)sum;
        carry = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);

        /* Propagate any remaining carry through higher limbs. */
        pos = (uint16_t)(2u * i + 2u);
        while ((carry != 0u) && (pos < rLen))
        {
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
            sum = (SSFBNDLimb_t)r->limbs[pos] + (SSFBNDLimb_t)carry;
#ifdef _WIN32
#pragma warning(pop)
#endif
            r->limbs[pos] = (SSFBNLimb_t)sum;
            carry = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);
            pos++;
        }
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
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

    r->len = m->len;
    carry = _SSFBNRawAdd(r->limbs, a->limbs, b->limbs, m->len);

    /* If carry or r >= m, subtract m */
    tmp.len = m->len;
    borrow = _SSFBNRawSub(tmp.limbs, r->limbs, m->limbs, m->len);

    /* CT-pick subtraction result iff carry from add OR no borrow from sub. */
    SSFBNCondCopy(r, &tmp, (SSFBNLimb_t)((carry != 0u) | (borrow == 0u)));
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a - b) mod m.                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModSub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBNLimb_t borrow;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

    r->len = m->len;
    borrow = _SSFBNRawSub(r->limbs, a->limbs, b->limbs, m->len);

    /* If borrow, add m back; CT via value-masked add. */
    {
        SSFBNLimb_t mask = (SSFBNLimb_t)(-(int32_t)(borrow != 0u));
        SSFBNDLimb_t carry = 0;
        uint16_t i;
        for (i = 0; i < m->len; i++)
        {
            carry += (SSFBNDLimb_t)r->limbs[i] + (SSFBNDLimb_t)(m->limbs[i] & mask);
            r->limbs[i] = (SSFBNLimb_t)carry;
            carry >>= SSF_BN_LIMB_BITS;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a mod m via shift-and-subtract. a->len may be up to 2 * m->len.                           */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMod(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBN_DEFINE(rem, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(shifted, SSF_BN_MAX_LIMBS);
    uint32_t aBits;
    uint32_t mBits;
    int32_t shift;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(SSFBNIsZero(m) == false);
    SSF_REQUIRE(a->len <= 2u * m->len);
    SSF_REQUIRE(a->len <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

    /* Copy a into working remainder at the larger length */
    SSFBNSetZero(&rem, (a->len > m->len) ? a->len : m->len);
    memcpy(rem.limbs, a->limbs, (size_t)a->len * sizeof(SSFBNLimb_t));

    aBits = SSFBNBitLen(&rem);
    mBits = SSFBNBitLen(m);

    if (mBits == 0u) return;

    /* Shift-and-subtract division */
    shift = (int32_t)(aBits - mBits);

    /* Prepare shifted modulus: zero-extend m into rem's width, then left-shift by `shift`. */
    SSFBNSetZero(&shifted, rem.len);
    {
        uint16_t i;
        for (i = 0; i < m->len; i++)
        {
            shifted.limbs[i] = m->limbs[i];
        }
    }
    SSFBNShiftLeft(&shifted, (uint32_t)shift);

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
/* r = (a * b) mod m.                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE((uint16_t)(a->len + b->len) <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(m->len <= r->cap);

    SSFBNMul(&prod, a, b);
    SSFBNMod(r, &prod, m);
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m, constant-time. Mathematically equivalent to SSFBNModMul but the iteration  */
/* count and per-iteration work do not depend on the values of a, b, or intermediate state — only */
/* on the limb count of m. Use this when a or b are secret (e.g. ECDSA Sign's k^-1 and d-derived  */
/* operands on mod-n).                                                                            */
/*                                                                                                */
/* Cost: ~2-3x slower than SSFBNModMul for typical inputs because it always does worst-case work. */
/* Algorithm: schoolbook multiply (already CT) followed by fixed-iteration shift-and-subtract     */
/* reduction with branchless mask-conditional commits.                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMulCT(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(shifted, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);
    uint16_t i;
    uint16_t j;
    uint16_t prodLen;
    uint32_t nIters;
    uint32_t k;
    SSFBNLimb_t mask;
    SSFBNLimb_t borrow;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(SSFBNIsZero(m) == false);
    SSF_REQUIRE((uint16_t)(2u * m->len) <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(m->len <= r->cap);

    /* prod = a * b. SSFBNMul has no zero-limb shortcut so it is CT over (a, b). */
    SSFBNMul(&prod, a, b);
    prodLen = (uint16_t)(2u * m->len);
    prod.len = prodLen;

    /* shifted = m << (m->len * 32). Place m in the high half of a 2n-limb buffer; low half is 0. */
    SSFBNSetZero(&shifted, prodLen);
    for (i = 0; i < m->len; i++)
    {
        shifted.limbs[i + m->len] = m->limbs[i];
    }
    shifted.len = prodLen;
    tmp.len = prodLen;

    /* Fixed-iteration shift-and-subtract: nIters = m->len * 32 + 1 covers all possible shifts.   */
    /* Each iteration: compute prod - shifted into tmp; commit prod := tmp via CT mask if the     */
    /* subtract did not underflow; then shift shifted right by 1.                                  */
    nIters = (uint32_t)m->len * SSF_BN_LIMB_BITS + 1u;
    for (k = 0; k < nIters; k++)
    {
        borrow = _SSFBNRawSub(tmp.limbs, prod.limbs, shifted.limbs, prodLen);
        /* mask = all-ones if borrow == 0 (subtract was valid, i.e. prod >= shifted), else 0. */
        mask = (SSFBNLimb_t)(borrow - 1u);
        for (j = 0; j < prodLen; j++)
        {
            prod.limbs[j] = (tmp.limbs[j] & mask) | (prod.limbs[j] & ~mask);
        }
        SSFBNShiftRight1(&shifted);
    }

    /* After the loop, prod < m and the high m->len limbs of prod are zero. Copy the low half. */
    r->len = m->len;
    memcpy(r->limbs, prod.limbs, (size_t)m->len * sizeof(SSFBNLimb_t));
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * a) mod m.                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModSquare(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE((uint16_t)(a->len * 2u) <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(m->len <= r->cap);

    SSFBNSquare(&prod, a);
    SSFBNMod(r, &prod, m);
}

/* --------------------------------------------------------------------------------------------- */
/* r = gcd(a, b) via binary GCD (Stein's algorithm).                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFBNGcd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b)
{
    SSFBN_DEFINE(u, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(v, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);
    uint32_t shift = 0;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(a->len == b->len);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(a->len <= r->cap);

    if (SSFBNIsZero(a)) { SSFBNCopy(r, b); return; }
    if (SSFBNIsZero(b)) { SSFBNCopy(r, a); return; }

    SSFBNCopy(&u, a);
    SSFBNCopy(&v, b);

    /* Strip common 2-factors via min(tz(u), tz(v)); leaves at least one of u, v odd. */
    {
        uint32_t tzU = SSFBNTrailingZeros(&u);
        uint32_t tzV = SSFBNTrailingZeros(&v);
        shift = (tzU < tzV) ? tzU : tzV;
        SSFBNShiftRight(&u, shift);
        SSFBNShiftRight(&v, shift);
    }

    /* Strip any remaining factors of 2 from u so u is odd going into the main loop. */
    SSFBNShiftRight(&u, SSFBNTrailingZeros(&u));

    while (SSFBNIsZero(&v) == false)
    {
        /* Reduce v to its odd part in one shot. */
        SSFBNShiftRight(&v, SSFBNTrailingZeros(&v));

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
    SSFBNShiftLeft(r, shift);
}

/* --------------------------------------------------------------------------------------------- */
/* Computes q = a / b and rem = a mod b via shift-subtract long division.                        */
/* --------------------------------------------------------------------------------------------- */
void SSFBNDivMod(SSFBN_t *q, SSFBN_t *rem, const SSFBN_t *a, const SSFBN_t *b)
{
    SSFBN_DEFINE(shifted, SSF_BN_MAX_LIMBS);
    uint32_t aBits, bBits;
    int32_t shift;
    uint16_t workLen;

    SSF_REQUIRE(q != NULL);
    SSF_REQUIRE(q->limbs != NULL);
    SSF_REQUIRE(rem != NULL);
    SSF_REQUIRE(rem->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(q != rem);
    SSF_REQUIRE(q != a);
    SSF_REQUIRE(q != b);
    SSF_REQUIRE(rem != a);
    SSF_REQUIRE(rem != b);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(b->len >= 1u);
    SSF_REQUIRE(SSFBNIsZero(b) == false);

    workLen = (a->len > b->len) ? a->len : b->len;
    SSF_REQUIRE(workLen <= q->cap);
    SSF_REQUIRE(workLen <= rem->cap);

    SSFBNSetZero(q, workLen);
    SSFBNSetZero(rem, workLen);
    memcpy(rem->limbs, a->limbs, (size_t)a->len * sizeof(SSFBNLimb_t));

    aBits = SSFBNBitLen(rem);
    bBits = SSFBNBitLen(b);

    shift = (int32_t)(aBits - bBits);
    if (shift < 0) return;

    SSFBNSetZero(&shifted, workLen);
    {
        uint16_t i;
        for (i = 0; i < b->len && i < workLen; i++) shifted.limbs[i] = b->limbs[i];
    }
    SSFBNShiftLeft(&shifted, (uint32_t)shift);

    while (shift >= 0)
    {
        SSFBNShiftLeft1(q);
        /* Does the remaining dividend contain another copy of the current shifted divisor? */
        if (_SSFBNRawCmp(rem->limbs, shifted.limbs, workLen) >= 0)
        {
            /* Yes, subtract it and set the new quotient's low bit. */
            _SSFBNRawSub(rem->limbs, rem->limbs, shifted.limbs, workLen);
            SSFBNSetBit(q, 0u);
        }
        SSFBNShiftRight1(&shifted);
        shift--;
    }
}

/* --------------------------------------------------------------------------------------------- */
/* If a^(-1) mod m exists then writes r, returns true; else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNModInvExt(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    /* Track only s (m's coefficient is implicit); signs tracked separately (SSFBN_t unsigned). */
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
    uint16_t len;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

    len = m->len;

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
    SSFBNSetOne(&cur_s, len);

    while (SSFBNIsZero(&cur_r) == false)
    {
        bool tmp_neg;

        SSFBNDivMod(&quotient, &tmp_r, &old_r, &cur_r);

        /* tmp_s = old_s - quotient * cur_s with sign tracking; reduce mod m to bound product. */
        {
            SSFBN_DEFINE(qxs, SSF_BN_MAX_LIMBS);
            /* Does the full product fit within MAX_LIMBS? */
            if ((uint16_t)(quotient.len + cur_s.len) <= SSF_BN_MAX_LIMBS)
            {
                /* Yes, compute it directly then reduce. */
                SSFBNMul(&prod, &quotient, &cur_s);
                SSFBNMod(&qxs, &prod, m);
            }
            else
            {
                /* No, fall back to modular multiply. */
                SSFBNModMul(&qxs, &quotient, &cur_s, m);
            }

            /* Do old_s and qxs share the same sign? */
            if (old_s_neg == cur_s_neg)
            {
                /* Yes, subtract magnitudes. */
                if (SSFBNCmp(&old_s, &qxs) >= 0)
                {
                    SSFBNSub(&tmp_s, &old_s, &qxs);
                    tmp_neg = old_s_neg;
                }
                else
                {
                    SSFBNSub(&tmp_s, &qxs, &old_s);
                    tmp_neg = (old_s_neg == false);
                }
            }
            else
            {
                /* No, add magnitudes. */
                SSFBNModAdd(&tmp_s, &old_s, &qxs, m);
                tmp_neg = old_s_neg;
            }
        }

        /* Shift: old = cur, cur = tmp. */
        SSFBNCopy(&old_r, &cur_r);
        SSFBNCopy(&cur_r, &tmp_r);
        SSFBNCopy(&old_s, &cur_s);
        old_s_neg = cur_s_neg;
        SSFBNCopy(&cur_s, &tmp_s);
        cur_s_neg = tmp_neg;
    }

    /* Did the algorithm converge with gcd == 1? */
    if (SSFBNIsOne(&old_r) == false) return false;

    /* Is old_s negative and non-zero? */
    if ((old_s_neg) && (SSFBNIsZero(&old_s) == false))
    {
        /* Yes, normalize to the positive representative by computing m - old_s. */
        SSFBNSub(r, m, &old_s);
    }
    else
    {
        /* No, old_s is already in [0, m). */
        SSFBNCopy(r, &old_s);
    }

    /* Is r still >= m after the sign normalization? */
    if (SSFBNCmp(r, m) >= 0)
    {
        /* Yes, reduce by one subtraction. */
        SSFBNSub(r, r, m);
    }

    /* Verify a * r mod m == 1; catches a non-coprime case where the algorithm produced garbage. */
    {
        SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);
        SSFBNModMul(&check, a, r, m);
        if (SSFBNIsOne(&check) == false) return false;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Reduces a 512-bit product (16 limbs) modulo NIST P-256 to 8 limbs. NIST SP 800-186 D.2.1.     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_BN_CONFIG_MAX_BITS >= 256
static void _SSFBNReduceP256(SSFBN_t *r, const SSFBN_t *t)
{
    /* Name the 32-bit words: t = (c15 c14 ... c1 c0) where c0 = t->limbs[0] etc. */
    /* Notation follows NIST SP 800-186 D.2.1 */
    const SSFBNLimb_t *c;
    SSFBNLimb_t carry;
    SSFBNLimb_t borrow;
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(r->cap >= 8u);
    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(t->limbs != NULL);
    SSF_REQUIRE(t->len >= 16u);

    c = t->limbs;

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

    /* CT correction loops. Each preserves V mod p where V = r + (carry - borrow) * 2^256.       */
    /* The borrow/carry counters must only be decremented when the underlying add/sub actually   */
    /* crosses the 2^256 boundary — otherwise the bookkeeping breaks the V-mod-p invariant       */
    /* (Wycheproof ECDH P-256 tcId 49 / sparse-coord inputs were a victim of the prior buggy     */
    /* unconditional decrement). Bounds: each successful (overflow-causing) iter is preceded by  */
    /* up to one "spinning" non-overflow iter that pushes r toward 2^256 — so 2× the original    */
    /* worst-case carry/borrow counts cover all cases.                                            */
    tmp.len = 8;
    {
        SSFBNLimb_t mask, lim, addCarry, subBorrow;
        uint16_t k, j;

        /* Loop 1: while (borrow > carry), add p. Decrement borrow ONLY when the add overflows. */
        for (k = 0; k < 8u; k++)
        {
            addCarry = _SSFBNRawAdd(tmp.limbs, r->limbs, SSF_BN_NIST_P256.limbs, 8);
            /* mask = all-ones if (borrow > carry); use unsigned wraparound on (carry - borrow). */
            lim = carry - borrow;
            mask = (SSFBNLimb_t)0u - (SSFBNLimb_t)(lim >> (SSF_BN_LIMB_BITS - 1u));
            for (j = 0; j < 8u; j++)
            {
                r->limbs[j] = (tmp.limbs[j] & mask) | (r->limbs[j] & ~mask);
            }
            borrow -= (mask & 1u) & (addCarry & 1u);
        }

        /* Now borrow <= carry; collapse to a single net carry. */
        carry -= borrow;

        /* Loop 2: while (carry > 0), subtract p. Decrement carry ONLY when the sub underflows. */
        for (k = 0; k < 12u; k++)
        {
            subBorrow = _SSFBNRawSub(tmp.limbs, r->limbs, SSF_BN_NIST_P256.limbs, 8);
            /* mask = all-ones if carry != 0. */
            mask = (SSFBNLimb_t)0u -
                   (SSFBNLimb_t)(((carry | (SSFBNLimb_t)(0u - carry)) >> (SSF_BN_LIMB_BITS - 1u)));
            for (j = 0; j < 8u; j++)
            {
                r->limbs[j] = (tmp.limbs[j] & mask) | (r->limbs[j] & ~mask);
            }
            carry -= (mask & 1u) & (subBorrow & 1u);
        }

        /* Loop 3: final reduce. mask is set when the trial subtract did not underflow. */
        for (k = 0; k < 3u; k++)
        {
            subBorrow = _SSFBNRawSub(tmp.limbs, r->limbs, SSF_BN_NIST_P256.limbs, 8);
            mask = (SSFBNLimb_t)(subBorrow - 1u);
            for (j = 0; j < 8u; j++)
            {
                r->limbs[j] = (tmp.limbs[j] & mask) | (r->limbs[j] & ~mask);
            }
        }
    }
}
#endif /* SSF_BN_CONFIG_MAX_BITS >= 256 */

/* --------------------------------------------------------------------------------------------- */
/* Reduces a 768-bit product (24 limbs) modulo NIST P-384 to 12 limbs. NIST SP 800-186 D.2.2.    */
/* --------------------------------------------------------------------------------------------- */
#if SSF_BN_CONFIG_MAX_BITS >= 384
static void _SSFBNReduceP384(SSFBN_t *r, const SSFBN_t *t)
{
    const SSFBNLimb_t *c;
    SSFBNLimb_t carry = 0;
    SSFBNLimb_t borrow = 0;
    SSFBN_DEFINE(s, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(tmp, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(r->cap >= 12u);
    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(t->limbs != NULL);
    SSF_REQUIRE(t->len >= 24u);

    c = t->limbs;

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

    /* CT correction loops — same algorithm as _SSFBNReduceP256. Bounds doubled to handle the    */
    /* "non-progressing" non-overflow iters that occur for sparse-coord inputs.                   */
    tmp.len = 12;
    {
        SSFBNLimb_t mask, lim, addCarry, subBorrow;
        uint16_t k, j;

        for (k = 0; k < 6u; k++)  /* original max borrow = 3, doubled */
        {
            addCarry = _SSFBNRawAdd(tmp.limbs, r->limbs, SSF_BN_NIST_P384.limbs, 12);
            lim = carry - borrow;
            mask = (SSFBNLimb_t)0u - (SSFBNLimb_t)(lim >> (SSF_BN_LIMB_BITS - 1u));
            for (j = 0; j < 12u; j++)
            {
                r->limbs[j] = (tmp.limbs[j] & mask) | (r->limbs[j] & ~mask);
            }
            borrow -= (mask & 1u) & (addCarry & 1u);
        }

        carry -= borrow;

        for (k = 0; k < 14u; k++)  /* original max carry = 7, doubled */
        {
            subBorrow = _SSFBNRawSub(tmp.limbs, r->limbs, SSF_BN_NIST_P384.limbs, 12);
            mask = (SSFBNLimb_t)0u -
                   (SSFBNLimb_t)(((carry | (SSFBNLimb_t)(0u - carry)) >> (SSF_BN_LIMB_BITS - 1u)));
            for (j = 0; j < 12u; j++)
            {
                r->limbs[j] = (tmp.limbs[j] & mask) | (r->limbs[j] & ~mask);
            }
            carry -= (mask & 1u) & (subBorrow & 1u);
        }

        for (k = 0; k < 3u; k++)
        {
            subBorrow = _SSFBNRawSub(tmp.limbs, r->limbs, SSF_BN_NIST_P384.limbs, 12);
            mask = (SSFBNLimb_t)(subBorrow - 1u);
            for (j = 0; j < 12u; j++)
            {
                r->limbs[j] = (tmp.limbs[j] & mask) | (r->limbs[j] & ~mask);
            }
        }
    }
}
#endif /* SSF_BN_CONFIG_MAX_BITS >= 384 */

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m via NIST fast reduction for P-256/P-384, else falls back to SSFBNModMul.    */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMulNIST(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

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
/* If a^(-1) mod m exists for prime m and is verified then writes r, returns true; else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNModInv(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBN_DEFINE(exp, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

    if (SSFBNIsZero(a)) return false;

    (void)SSFBNSubUint32(&exp, m, 2u);
    SSFBNModExp(r, a, &exp, m);

    /* Verify a * r mod m == 1; if a and m are not coprime the result will fail this check. */
    {
        SSFBN_DEFINE(check, SSF_BN_MAX_LIMBS);
        SSFBNModMul(&check, a, r, m);
        if (SSFBNIsOne(&check) == false) return false;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes Montgomery context for the given odd modulus m.                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontInit(SSFBNMont_t *ctx, const SSFBN_t *m)
{
    uint16_t i;
    SSFBN_DEFINE(r2, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->rr.limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= ctx->mod.cap);
    SSF_REQUIRE(m->len <= ctx->rr.cap);
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u);

    SSFBNCopy(&ctx->mod, m);
    ctx->len = m->len;

    /* mp = -m^(-1) mod 2^32 via Newton iteration; 5 iters reach 32-bit accuracy. */
    {
        SSFBNLimb_t x = 1;
        SSFBNLimb_t m0 = m->limbs[0];

        for (i = 0; i < 5; i++)
        {
            x = x * (2u - m0 * x);
        }
        ctx->mp = (SSFBNLimb_t)(-(int32_t)x);
    }

    /* Compute R^2 mod m where R = 2^(len*32) by doubling 1 modulo m for 2*len*32 iterations. */
    SSFBNSetOne(&r2, m->len);
    for (i = 0; i < (uint16_t)(m->len * SSF_BN_LIMB_BITS * 2u); i++)
    {
        SSFBNModAdd(&r2, &r2, &r2, m);
    }
    SSFBNCopy(&ctx->rr, &r2);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a * b * R^(-1) mod m. a and b must be in Montgomery form. CIOS algorithm.                 */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBNMont_t *ctx)
{
    SSFBNLimb_t t[SSF_BN_MAX_LIMBS + 2];
    uint16_t n;
    uint16_t i;
    SSFBNLimb_t borrow;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->len >= 1u);
    SSF_REQUIRE(ctx->len <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(ctx->len <= r->cap);
    SSF_REQUIRE(ctx->len <= a->cap);
    SSF_REQUIRE(ctx->len <= b->cap);

    n = ctx->len;
    memset(t, 0, (size_t)(n + 2u) * sizeof(SSFBNLimb_t));

    for (i = 0; i < n; i++)
    {
        SSFBNDLimb_t carry = 0;
        SSFBNLimb_t u;
        uint16_t j;

        /* t += a[i] * b */
        for (j = 0; j < n; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)b->limbs[j] +
                                (SSFBNDLimb_t)t[j] + carry;
            t[j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
        t[n] += (SSFBNLimb_t)carry;
        t[n + 1u] = (SSFBNLimb_t)((SSFBNDLimb_t)t[n] < carry ? 1u : 0u);

        /* t = (t + (t[0] * mp mod 2^32) * m) / 2^32 */
        u = t[0] * ctx->mp;

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
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
            t[n + 1u] += (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);
#ifdef _WIN32
#pragma warning(pop)
#endif
        }

        {
            uint16_t k;
            for (k = 0; k < n + 1u; k++)
            {
                t[k] = t[k + 1u];
            }
            t[n + 1u] = 0;
        }
    }

    /* CT cond-sub: unconditional sub puts r in [-m, m); add m back iff (borrow && t[n]==0). */
    r->len = n;
    memcpy(r->limbs, t, (size_t)n * sizeof(SSFBNLimb_t));

    borrow = _SSFBNRawSub(r->limbs, r->limbs, ctx->mod.limbs, n);
    {
        SSFBNLimb_t cond = ((SSFBNLimb_t)(borrow != 0u)) & ((SSFBNLimb_t)(t[n] == 0u));
        SSFBNLimb_t mask = (SSFBNLimb_t)(-(int32_t)cond);
        SSFBNDLimb_t addCarry = 0;
        for (i = 0; i < n; i++)
        {
            addCarry += (SSFBNDLimb_t)r->limbs[i] + (SSFBNDLimb_t)(ctx->mod.limbs[i] & mask);
            r->limbs[i] = (SSFBNLimb_t)addCarry;
            addCarry >>= SSF_BN_LIMB_BITS;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a * a * R^(-1) mod m using SOS squaring; ~25-40% faster than SSFBNMontMul(a, a, ctx).     */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontSquare(SSFBN_t *r, const SSFBN_t *a, const SSFBNMont_t *ctx)
{
    /* Cannot reuse SSFBNSquare: its rLen<=MAX_LIMBS assertion caps n at MAX_LIMBS/2. */
    SSFBNLimb_t t[(2u * SSF_BN_MAX_LIMBS) + 1u];
    uint16_t n;
    uint16_t i;
    SSFBNLimb_t shiftCarry;
    SSFBNLimb_t borrow;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);

    n = ctx->len;
    SSF_REQUIRE(n >= 1u);
    SSF_REQUIRE(n <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(n <= r->cap);
    SSF_REQUIRE(n <= a->cap);

    memset(t, 0, (size_t)(2u * n + 1u) * sizeof(SSFBNLimb_t));

    /* Triangular full square: t = a * a (2n limbs) */

    /* Step 1: accumulate strict upper triangle a[i]*a[j] (i<j) without doubling. */
    for (i = 0; (uint16_t)(i + 1u) < n; i++)
    {
        SSFBNDLimb_t carry = 0;
        uint16_t j;
        SSFBNLimb_t ai = a->limbs[i];

        /* No zero-limb skip — see _SSFBNSchoolbookMulRaw for rationale. */
        for (j = (uint16_t)(i + 1u); j < n; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)ai * (SSFBNDLimb_t)a->limbs[j] +
                                (SSFBNDLimb_t)t[i + j] + carry;
            t[i + j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
        t[i + n] += (SSFBNLimb_t)carry;
    }

    /* Step 2: double via shift-left-by-1 across 2n limbs; t[2n-1]'s top bit is 0 after step 1. */
    shiftCarry = 0;
    for (i = 0; i < (uint16_t)(2u * n); i++)
    {
        SSFBNLimb_t newCarry = t[i] >> (SSF_BN_LIMB_BITS - 1u);
        t[i] = (SSFBNLimb_t)((t[i] << 1) | shiftCarry);
        shiftCarry = newCarry;
    }

    /* Step 3: add diagonal a[i]*a[i] terms at offset 2i, propagating carries forward. */
    for (i = 0; i < n; i++)
    {
        SSFBNDLimb_t sq = (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)a->limbs[i];
        SSFBNDLimb_t sum;
        SSFBNLimb_t carry;
        uint16_t pos;

        sum = (SSFBNDLimb_t)t[2u * i] + (SSFBNDLimb_t)(SSFBNLimb_t)sq;
        t[2u * i] = (SSFBNLimb_t)sum;
        carry = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);

        sum = (SSFBNDLimb_t)t[2u * i + 1u] +
              (SSFBNDLimb_t)(SSFBNLimb_t)(sq >> SSF_BN_LIMB_BITS) +
              (SSFBNDLimb_t)carry;
        t[2u * i + 1u] = (SSFBNLimb_t)sum;
        carry = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);

        pos = (uint16_t)(2u * i + 2u);
        while (carry != 0u)
        {
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
            sum = (SSFBNDLimb_t)t[pos] + (SSFBNDLimb_t)carry;
#ifdef _WIN32
#pragma warning(pop)
#endif
            t[pos] = (SSFBNLimb_t)sum;
            carry = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);
            pos++;
        }
    }

    /* Montgomery reduction (SOS): clear low half, upper half holds a*a*R^-1 mod m (up to one m). */
    for (i = 0; i < n; i++)
    {
        SSFBNLimb_t u = (SSFBNLimb_t)(t[i] * ctx->mp);
        SSFBNDLimb_t carry = 0;
        uint16_t j;
        uint16_t k;

        /* t[i..i+n-1] += u * m (low n limbs of the product). */
        for (j = 0; j < n; j++)
        {
            SSFBNDLimb_t prod = (SSFBNDLimb_t)u * (SSFBNDLimb_t)ctx->mod.limbs[j] +
                                (SSFBNDLimb_t)t[i + j] + carry;
            t[i + j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }

        /* Propagate inner-loop carry forward; bounded ~2^(2n*w+1) so it can't reach past t[2n]. */
        k = (uint16_t)(i + n);
        while (carry != 0u)
        {
            SSFBNDLimb_t sum = (SSFBNDLimb_t)t[k] + carry;
            t[k] = (SSFBNLimb_t)sum;
            carry = sum >> SSF_BN_LIMB_BITS;
            k++;
        }
    }

    /* Final conditional subtraction: result in [0, 2m), want [0, m). */
    r->len = n;
    memcpy(r->limbs, &t[n], (size_t)n * sizeof(SSFBNLimb_t));

    borrow = _SSFBNRawSub(r->limbs, r->limbs, ctx->mod.limbs, n);
    /* Cond-subtract m: needed iff !borrow OR t[2n]==1; constant-time via value-masked add. */
    {
        SSFBNLimb_t cond = ((SSFBNLimb_t)(borrow != 0u)) & ((SSFBNLimb_t)(t[2u * n] == 0u));
        SSFBNLimb_t mask = (SSFBNLimb_t)(-(int32_t)cond);
        SSFBNDLimb_t addCarry = 0;
        for (i = 0; i < n; i++)
        {
            addCarry += (SSFBNDLimb_t)r->limbs[i] + (SSFBNDLimb_t)(ctx->mod.limbs[i] & mask);
            r->limbs[i] = (SSFBNLimb_t)addCarry;
            addCarry >>= SSF_BN_LIMB_BITS;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Converts a to Montgomery form: aR = a * R mod m.                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontConvertIn(SSFBN_t *aR, const SSFBN_t *a, const SSFBNMont_t *ctx)
{
    SSF_REQUIRE(aR != NULL);
    SSF_REQUIRE(aR->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->rr.limbs != NULL);
    SSF_REQUIRE(ctx->len >= 1u);
    SSF_REQUIRE(ctx->len <= aR->cap);

    /* aR = MontMul(a, R^2) = a * R^2 * R^(-1) mod m = a * R mod m */
    SSFBNMontMul(aR, a, &ctx->rr, ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Converts aR from Montgomery form: a = aR * R^(-1) mod m.                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontConvertOut(SSFBN_t *a, const SSFBN_t *aR, const SSFBNMont_t *ctx)
{
    SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(aR != NULL);
    SSF_REQUIRE(aR->limbs != NULL);
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->len >= 1u);
    SSF_REQUIRE(ctx->len <= a->cap);

    /* a = MontMul(aR, 1) = aR * 1 * R^(-1) mod m = a */
    SSFBNSetOne(&one, ctx->len);
    SSFBNMontMul(a, aR, &one, ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^e mod m. Constant-time fixed-window via SSFBNModExpMont.                                */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExp(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(e->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

    SSFBNMontInit(&mont, m);
    SSFBNModExpMont(r, a, e, &mont);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^e mod m using precomputed Montgomery context; constant-time fixed-window (k=4).         */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExpMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx)
{
    SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(result, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(picked, SSF_BN_MAX_LIMBS);
    SSFBNLimb_t tableStorage[SSF_BN_MODEXP_TBL_N][SSF_BN_MAX_LIMBS];
    SSFBN_t table[SSF_BN_MODEXP_TBL_N];
    uint32_t nWindows;
    uint32_t winIdx;
    uint32_t w;
    uint32_t k;
    uint32_t bp;
    uint32_t bitOffset;
    int32_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(e->limbs != NULL);
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->len >= 1u);
    SSF_REQUIRE(ctx->len <= r->cap);

    /* Wire up table descriptors over their stack-resident backing storage. */
    for (w = 0u; w < SSF_BN_MODEXP_TBL_N; w++)
    {
        table[w].limbs = tableStorage[w];
        table[w].len = 0u;
        table[w].cap = SSF_BN_MAX_LIMBS;
    }

    /* Convert a to Montgomery form. */
    SSFBNMontConvertIn(&aM, a, ctx);

    /* table[0] = Mont(1) for zero-windows; table[i] = aM^i for i=1..15. */
    {
        SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
        SSFBNSetOne(&one, ctx->len);
        SSFBNMontConvertIn(&table[0], &one, ctx);
    }
    SSFBNCopy(&table[1], &aM);
    for (w = 2u; w < SSF_BN_MODEXP_TBL_N; w++)
    {
        SSFBNMontMul(&table[w], &table[w - 1u], &aM, ctx);
    }

    /* Init result = Mont(1); seed picked with table[0] so its len matches for CondCopy. */
    SSFBNCopy(&result, &table[0]);
    SSFBNCopy(&picked, &table[0]);

    /* nWindows fixed at max(e->len, ctx->len)*32/k so timing/loop count is e-independent. */
    {
        uint16_t expLen = (e->len > ctx->len) ? e->len : ctx->len;
        nWindows = (uint32_t)expLen * SSF_BN_LIMB_BITS / SSF_BN_MODEXP_WIN_K;
    }
    for (winIdx = 0u; winIdx < nWindows; winIdx++)
    {
        /* Square k times. */
        for (k = 0u; k < SSF_BN_MODEXP_WIN_K; k++)
        {
            SSFBNMontSquare(&result, &result, ctx);
        }

        /* Decode this window's k-bit value (MSB first). */
        bitOffset = (nWindows - 1u - winIdx) * SSF_BN_MODEXP_WIN_K;
        w = 0u;
        for (k = 0u; k < SSF_BN_MODEXP_WIN_K; k++)
        {
            bp = bitOffset + (SSF_BN_MODEXP_WIN_K - 1u - k);
            w = (w << 1) | (uint32_t)SSFBNGetBit(e, bp);
        }

        /* CT table lookup: scan all entries with a masked copy; address/timing independent of w. */
        for (i = 0; i < (int32_t)SSF_BN_MODEXP_TBL_N; i++)
        {
            SSFBNCondCopy(&picked, &table[i], (SSFBNLimb_t)((uint32_t)i == w));
        }

        /* result = result * picked (= aM^w). */
        SSFBNMontMul(&result, &result, &picked, ctx);
    }

    /* Convert result out of Montgomery form. */
    SSFBNMontConvertOut(r, &result, ctx);

    /* Zeroize secret material. */
    SSFBNZeroize(&aM);
    SSFBNZeroize(&result);
    SSFBNZeroize(&picked);
    for (w = 0u; w < SSF_BN_MODEXP_TBL_N; w++)
    {
        SSFBNZeroize(&table[w]);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Variable-time r = a^e mod m; PUBLIC-EXPONENT USE ONLY (see header warning).                   */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExpPub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(e->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

    SSFBNMontInit(&mont, m);
    SSFBNModExpMontPub(r, a, e, &mont);
}

/* --------------------------------------------------------------------------------------------- */
/* Variable-time ModExp with precomputed Montgomery context; left-to-right binary method.        */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExpMontPub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx)
{
    SSFBN_DEFINE(result, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
    uint32_t eBits;
    int32_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(e != NULL);
    SSF_REQUIRE(e->limbs != NULL);
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->len >= 1u);
    SSF_REQUIRE(ctx->len <= r->cap);

    eBits = SSFBNBitLen(e);

    /* Is the exponent zero? */
    if (eBits == 0u)
    {
        /* Yes, a^0 = 1 by convention. */
        SSFBNSetOne(r, ctx->len);
        return;
    }

    /* Convert a to Montgomery form once; every subsequent MontMul keeps result in Mont form. */
    SSFBNMontConvertIn(&aM, a, ctx);

    /* Initialize result = Montgomery(1) = R mod m. */
    {
        SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
        SSFBNSetOne(&one, ctx->len);
        SSFBNMontConvertIn(&result, &one, ctx);
    }

    /* Left-to-right binary square-and-multiply; leaks Hamming weight of e (public-only). */
    for (i = (int32_t)(eBits - 1u); i >= 0; i--)
    {
        SSFBNMontSquare(&result, &result, ctx);
        /* Is bit i of e set? */
        if (SSFBNGetBit(e, (uint32_t)i) != 0u)
        {
            /* Yes, multiply the running result by the base. */
            SSFBNMontMul(&result, &result, &aM, ctx);
        }
    }

    SSFBNMontConvertOut(r, &result, ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Constant-time conditional swap of a and b's limbs when swap != 0.                             */
/* --------------------------------------------------------------------------------------------- */
void SSFBNCondSwap(SSFBN_t *a, SSFBN_t *b, SSFBNLimb_t swap)
{
    SSFBNLimb_t mask;
    uint16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
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
/* Constant-time conditional copy of src into dst when sel != 0.                                 */
/* --------------------------------------------------------------------------------------------- */
void SSFBNCondCopy(SSFBN_t *dst, const SSFBN_t *src, SSFBNLimb_t sel)
{
    SSFBNLimb_t mask;
    uint16_t i;

    SSF_REQUIRE(dst != NULL);
    SSF_REQUIRE(dst->limbs != NULL);
    SSF_REQUIRE(src != NULL);
    SSF_REQUIRE(src->limbs != NULL);
    SSF_REQUIRE(dst->len == src->len);

    mask = (SSFBNLimb_t)(-(int32_t)(sel != 0u));

    for (i = 0; i < dst->len; i++)
    {
        dst->limbs[i] = (src->limbs[i] & mask) | (dst->limbs[i] & ~mask);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* Zeroes a's limb storage (cap limbs) and clears len; volatile defeats dead-store elision.      */
/* --------------------------------------------------------------------------------------------- */
void SSFBNZeroize(SSFBN_t *a)
{
    volatile SSFBNLimb_t *p;
    uint16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);

    /* Volatile write defeats dead-store elimination; struct fields stay so a remains usable. */
    p = (volatile SSFBNLimb_t *)a->limbs;
    for (i = 0; i < a->cap; i++)
    {
        p[i] = 0u;
    }
    a->len = 0;
}

/* --------------------------------------------------------------------------------------------- */
/* Returns a mod d via successive 64-bit modulo across limbs from MSB to LSB.                    */
/* --------------------------------------------------------------------------------------------- */
uint32_t SSFBNModUint32(const SSFBN_t *a, uint32_t d)
{
    uint64_t r = 0;
    int16_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(d != 0u);

    for (i = (int16_t)(a->len - 1u); i >= 0; i--)
    {
        r = ((r << SSF_BN_LIMB_BITS) | (uint64_t)a->limbs[i]) % (uint64_t)d;
    }
    return (uint32_t)r;
}

/* --------------------------------------------------------------------------------------------- */
/* Fills numLimbs of a with random bytes from prng; sets a->len = numLimbs.                      */
/* --------------------------------------------------------------------------------------------- */
void SSFBNRandom(SSFBN_t *a, uint16_t numLimbs, SSFPRNGContext_t *prng)
{
    size_t byteLen;
    size_t generated;
    uint8_t *buf;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(numLimbs >= 1u);
    SSF_REQUIRE(numLimbs <= a->cap);
    SSF_REQUIRE(prng != NULL);

    /* Fill the limb storage as a byte stream, chunked by SSF_PRNG_RANDOM_MAX_SIZE per call. */
    byteLen = (size_t)numLimbs * sizeof(SSFBNLimb_t);
    buf = (uint8_t *)a->limbs;
    generated = 0;
    while (generated < byteLen)
    {
        size_t chunk = byteLen - generated;

        /* Is the remaining request larger than one PRNG call can satisfy? */
        if (chunk > SSF_PRNG_RANDOM_MAX_SIZE)
        {
            /* Yes, clamp to the max. Subsequent iterations cover the rest. */
            chunk = SSF_PRNG_RANDOM_MAX_SIZE;
        }
        SSFPRNGGetRandom(prng, &buf[generated], chunk);
        generated += chunk;
    }
    a->len = numLimbs;
}

/* --------------------------------------------------------------------------------------------- */
/* If a uniform random in [0, bound) is found within the cap then writes a; returns success.     */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNRandomBelow(SSFBN_t *a, const SSFBN_t *bound, SSFPRNGContext_t *prng)
{
    uint32_t bitLen;
    uint16_t topLimb;
    uint16_t topBit;
    SSFBNLimb_t topMask;
    uint16_t attempts;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(bound != NULL);
    SSF_REQUIRE(bound->limbs != NULL);
    SSF_REQUIRE(bound->len >= 1u);
    SSF_REQUIRE(bound->len <= a->cap);
    SSF_REQUIRE(prng != NULL);
    SSF_REQUIRE(SSFBNIsZero(bound) == false);

    bitLen = SSFBNBitLen(bound);
    topLimb = (uint16_t)((bitLen - 1u) / SSF_BN_LIMB_BITS);
    topBit = (uint16_t)((bitLen - 1u) % SSF_BN_LIMB_BITS);

    /* Mask keeps bits [0, topBit] in top limb; guards `1u << 32` UB at limb-aligned bitLen. */
    if (topBit == (SSF_BN_LIMB_BITS - 1u))
    {
        topMask = (SSFBNLimb_t)(~(SSFBNLimb_t)0u);
    }
    else
    {
        topMask = (SSFBNLimb_t)(((SSFBNLimb_t)1u << (topBit + 1u)) - 1u);
    }

    for (attempts = 0; attempts < 100u; attempts++)
    {
        uint16_t i;

        SSFBNRandom(a, bound->len, prng);

        /* Zero limbs above topLimb (SSFBNRandom filled bound->len, so only those need clearing). */
        for (i = (uint16_t)(topLimb + 1u); i < bound->len; i++)
        {
            a->limbs[i] = 0u;
        }
        a->limbs[topLimb] &= topMask;

        /* Is the draw within the target range? */
        if (SSFBNCmp(a, bound) < 0)
        {
            /* Yes, accept. */
            return true;
        }
        /* No, re-draw. */
    }
    return false;
}

/* --------------------------------------------------------------------------------------------- */
/* If n passes all rounds of Miller-Rabin then returns true (n is probably prime), else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNIsProbablePrime(const SSFBN_t *n, uint16_t rounds, SSFPRNGContext_t *prng)
{
    SSFBN_DEFINE(nm1, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(d, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(x, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(nm3, SSF_BN_MAX_LIMBS);
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
    uint32_t s = 0;
    uint16_t round;

    SSF_REQUIRE(n != NULL);
    SSF_REQUIRE(n->limbs != NULL);
    SSF_REQUIRE(prng != NULL);

    /* Small-case fast paths: witness range [2, n-2] is empty for n <= 3;handle 0..3 explicitly. */
    if (SSFBNCmpUint32(n, 1u) <= 0) return false;
    if (SSFBNCmpUint32(n, 3u) <= 0) return true;
    if (SSFBNIsEven(n)) return false;
    /* From here n >= 5 and odd; the witness range [2, n-2] is non-empty. */

    /* nm1 = n - 1. */
    (void)SSFBNSubUint32(&nm1, n, 1u);

    /* Write n-1 = 2^s * d; n-1 is even (n odd, n > 3), so TrailingZeros is defined. */
    SSFBNCopy(&d, &nm1);
    s = SSFBNTrailingZeros(&d);
    SSFBNShiftRight(&d, s);

    /* Precompute Montgomery context for n. */
    SSFBNMontInit(&mont, n);

    /* nm3 = n - 3 for the witness-range rejection check. */
    (void)SSFBNSubUint32(&nm3, n, 3u);

    for (round = 0; round < rounds; round++)
    {
        uint32_t r;
        bool cont = false;

        /* Pick random witness a in [2, n-2]. */
        {
            uint16_t attempts;

            for (attempts = 0; attempts < 100u; attempts++)
            {
                SSFBNRandom(&a, n->len, prng);

                /* Mask candidate to bitLen(n)-1 bits; clear limbs above topLimb so < n-3 holds. */
                {
                    uint32_t nBits = SSFBNBitLen(n);
                    uint16_t topLimb = (uint16_t)((nBits - 1u) / SSF_BN_LIMB_BITS);
                    uint16_t topBit = (uint16_t)((nBits - 1u) % SSF_BN_LIMB_BITS);
                    uint16_t k;
                    a.limbs[topLimb] &= ((SSFBNLimb_t)1u << topBit) - 1u;
                    for (k = (uint16_t)(topLimb + 1u); k < n->len; k++)
                    {
                        a.limbs[k] = 0u;
                    }
                }

                /* Is the candidate already below n-3? */
                if (SSFBNCmp(&a, &nm3) < 0)
                {
                    /* Yes, accept it. */
                    break;
                }
                /* No, re-draw. */
            }

            /* Shift to [2, n-2] by adding 2. */
            (void)SSFBNAddUint32(&a, &a, 2u);
        }

        /* x = a^d mod n. */
        SSFBNModExpMont(&x, &a, &d, &mont);

        /* Does x equal 1 or n-1? */
        if (SSFBNIsOne(&x) || (SSFBNCmp(&x, &nm1) == 0))
        {
            /* Yes, this witness is inconclusive. Try another round. */
            continue;
        }

        /* Inner loop: square x up to s-1 times, looking for x == n-1. */
        cont = false;
        for (r = 1; r < s; r++)
        {
            SSFBNModSquare(&x, &x, n);

            /* Did squaring hit n-1? */
            if (SSFBNCmp(&x, &nm1) == 0)
            {
                /* Yes, witness inconclusive. */
                cont = true;
                break;
            }
            /* Did squaring reach 1 without first passing through n-1? */
            if (SSFBNIsOne(&x))
            {
                /* Yes, definitive composite via non-trivial sqrt(1). */
                return false;
            }
        }

        /* Did we find a pass condition inside the inner loop? */
        if (cont == false)
        {
            /* No, this witness proves n composite. */
            return false;
        }
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* If a random bitLen-bit prime is found within the cap then writes p, returns true; else false. */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNGenPrime(SSFBN_t *p, uint16_t bitLen, uint16_t rounds, SSFPRNGContext_t *prng)
{
    size_t byteLen;
    uint16_t limbs;
    uint8_t buf[SSF_BN_MAX_BYTES];
    uint32_t attempts;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->limbs != NULL);
    SSF_REQUIRE(bitLen >= 8u);
    SSF_REQUIRE(bitLen <= SSF_BN_CONFIG_MAX_BITS);
    SSF_REQUIRE(prng != NULL);

    byteLen = (size_t)(bitLen + 7u) / 8u;
    limbs = SSF_BN_BITS_TO_LIMBS(bitLen);

    for (attempts = 0; attempts < 50000u; attempts++)
    {
        uint16_t i;
        bool trialPass;
        size_t generated = 0;

        /* Draw byteLen random bytes via the PRNG. */
        while (generated < byteLen)
        {
            size_t chunk = byteLen - generated;
            if (chunk > SSF_PRNG_RANDOM_MAX_SIZE) chunk = SSF_PRNG_RANDOM_MAX_SIZE;
            SSFPRNGGetRandom(prng, &buf[generated], chunk);
            generated += chunk;
        }

        /* Force the top two bits so p * q has the full 2*bitLen bit length. */
        buf[0] |= 0xC0u;
        /* Force the low bit so the candidate is odd. */
        buf[byteLen - 1u] |= 0x01u;

        SSFBNFromBytes(p, buf, byteLen, limbs);

        /* Trial-divide against the small-prime table. */
        trialPass = true;
        for (i = 0; i < SSF_BN_NUM_SMALL_PRIMES; i++)
        {
            /* Does this small prime divide p? */
            if (SSFBNModUint32(p, _ssfBNSmallPrimes[i]) == 0u)
            {
                /* Yes, reject (if p equals the small prime it's prime but way too small). */
                trialPass = false;
                break;
            }
        }
        /* Did trial division pass? */
        if (trialPass == false)
        {
            /* No, next candidate. */
            continue;
        }

        /* Yes, confirm with Miller-Rabin. */
        if (SSFBNIsProbablePrime(p, rounds, prng)) return true;
    }

    return false;
}

