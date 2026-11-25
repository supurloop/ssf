/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbn.c                                                                                       */
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
#include "ssfbn.h"
#include "ssfcrypt.h"
#include "ssfusexport.h"

/* --------------------------------------------------------------------------------------------- */
/* Module defines.                                                                               */
/* --------------------------------------------------------------------------------------------- */
/* SSF_BN_MAX_LIMBS must fit in int16_t so a->len + b->len can't overflow uint16_t. */
#if (SSF_BN_MAX_LIMBS > 32767u)
#error "SSF_BN_MAX_LIMBS must fit in int16_t to keep uint16_t sums safe in Mul/Square"
#endif

/* SSF_BN_KARATSUBA_THRESHOLD and SSF_BN_MODEXP_WIN_K come from ssfbn_opt.h or ssfcrypt_opt.h */

/* Karatsuba step 7 stays inside the 2n-limb result only for n >= 4 */
#if SSF_BN_KARATSUBA_THRESHOLD < 4
#error "SSF_BN_KARATSUBA_THRESHOLD must be >= 4 (Karatsuba step 7 overruns r for n < 4)"
#endif
#define SSF_BN_MODEXP_TBL_N        ((uint32_t)1u << SSF_BN_MODEXP_WIN_K)
#if (SSF_BN_MODEXP_WIN_K < 1u) || (SSF_BN_MODEXP_WIN_K > 8u)
#error SSF_BN_MODEXP_WIN_K must be 1 to 8 (a 2^k-entry table on the stack)
#endif
#define SSF_BN_NUM_SMALL_PRIMES    (sizeof(_ssfBNSmallPrimes) / sizeof(_ssfBNSmallPrimes[0]))

#if SSF_CONFIG_BN_UNIT_TEST == 1
/* Test-only count of SSFBNMod calls. */
uint32_t _SSFBNModCallCount = 0u;

/* Test-only hook fired after each secret local is wiped; NULL in production. */
void (*_SSFBNScrubTestHook)(const void *buf, size_t len) = NULL;
#define _SSF_BN_SCRUB_HOOK(p, n) \
    do { if (_SSFBNScrubTestHook != NULL) { _SSFBNScrubTestHook((p), (n)); } } while (0)

/* Test-only counters: Karatsuba propagation iterations, exporter scans. */
uint32_t _SSFBNKaratsubaPropIters = 0u;
uint32_t _SSFBNToBytesScans = 0u;

/* Test-only count of the modular doublings SSFBNMontInit runs. */
uint32_t _SSFBNMontInitDoublings = 0u;

/* Test-only counts: MontMul inner-loop and MontSquare carry-loop iterations. */
uint32_t _SSFBNMontMulIters = 0u;
uint32_t _SSFBNMontSqrCarryIters = 0u;

/* Test-only count of SSFBNSquare's diagonal carry steps, fixed at a->len */
uint32_t _SSFBNSquareCarryIters = 0u;

/* Test-only count of the P-256 / P-384 reductions' correction passes */
uint32_t _SSFBNNistCorrPasses = 0u;

/* Test-only count of full NIST prime comparisons in SSFBNModMulNIST */
uint32_t _SSFBNNistPrimeCmps = 0u;

/* Test-only count of full-width entry points (ModExpMont[Pub], ModMulCT, ModInvExt, ModMul). */
uint32_t _SSFBNFullWidthCalls = 0u;

/* Test-only count of the slow ModMulCT / ModInvExt algorithms (shift-subtract, Euclid) */
uint32_t _SSFBNSlowPathCalls = 0u;

/* Test-only count of SSFBNMod's variable-time shift-and-subtract reductions */
uint32_t _SSFBNModShiftCalls = 0u;
#define _SSF_BN_COUNT(c) do { (c)++; } while (0)
#else
#define _SSF_BN_SCRUB_HOOK(p, n) do { } while (0)
#define _SSF_BN_COUNT(c) do { } while (0)
#endif /* SSF_CONFIG_BN_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* Module data.                                                                                  */
/* --------------------------------------------------------------------------------------------- */
/* NIST primes need a cap that holds the 2N-limb product their fast reductions consume */
#if SSF_BN_CONFIG_MAX_BITS >= 512
/* P-256: 2^256 - 2^224 + 2^192 + 2^96 - 1; in flash, shared with the curve code */
const SSFBNLimb_t SSF_BN_NIST_P256_LIMBS[8] =
{
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0x00000000ul,
    0x00000000ul, 0x00000000ul, 0x00000001ul, 0xFFFFFFFFul
};
const SSFBN_t SSF_BN_NIST_P256 = { (SSFBNLimb_t *)SSF_BN_NIST_P256_LIMBS, 8, 8 };
#endif /* SSF_BN_CONFIG_MAX_BITS >= 512 */

#if SSF_BN_CONFIG_MAX_BITS >= 768
/* P-384: 2^384 - 2^128 - 2^96 + 2^32 - 1; in flash, shared with the curve code */
const SSFBNLimb_t SSF_BN_NIST_P384_LIMBS[12] =
{
    0xFFFFFFFFul, 0x00000000ul, 0x00000000ul, 0xFFFFFFFFul,
    0xFFFFFFFEul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
    0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul
};
const SSFBN_t SSF_BN_NIST_P384 = { (SSFBNLimb_t *)SSF_BN_NIST_P384_LIMBS, 12, 12 };
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */

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
        SSFBNDLimb_t diff = (((SSFBNDLimb_t)a[i] - (SSFBNDLimb_t)b[i]) - borrow);
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
    SSF_ASSUME(src->len <= dst->cap);

    memcpy(dst->limbs, src->limbs, (size_t)src->len * sizeof(SSFBNLimb_t));
    dst->len = src->len;
}

/* --------------------------------------------------------------------------------------------- */
/* If data fits in numLimbs then writes a, sets a->len = numLimbs, returns true, else false.     */
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
        size_t bytePos = (dataLen - 1u) - i;
        uint16_t limbIdx = (uint16_t)(i / sizeof(SSFBNLimb_t));
        uint16_t byteIdx = (uint16_t)(i % sizeof(SSFBNLimb_t));

        a->limbs[limbIdx] |= (((SSFBNLimb_t)data[bytePos]) << (byteIdx * 8u));
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* If outSize holds a then writes out (BE, zero-padded leading), returns true, else false.       */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNToBytes(const SSFBN_t *a, uint8_t *out, size_t outSize)
{
    size_t i;

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(a->len >= 1u);
    SSF_REQUIRE(out != NULL);

    /* Is out narrower than a's limbs, so whether a fits depends on its value? */
    if (outSize < ((size_t)a->len * sizeof(SSFBNLimb_t)))
    {
        /* Yes, find the minimum byte length needed to represent a (variable-time) */
        {
            size_t actualBytes;
            int16_t li;

            _SSF_BN_COUNT(_SSFBNToBytesScans);
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
    }
    /* No, every limb fits, so no value-dependent scan is needed */

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
            /* No, further limbs are entirely past the buffer -- stop. */
            break;
        }

        for (b = 0; b < sizeof(SSFBNLimb_t); b++)
        {
            /* Does byte b of this limb fall inside the output buffer? */
            if ((limbOffset + b) >= outSize)
            {
                /* No, the remaining high bytes of this limb don't fit -- stop this limb. */
                break;
            }
            /* Yes, write the byte into its big-endian slot. */
            out[((outSize - 1u) - limbOffset) - b] = (uint8_t)(limb & 0xFFu);
            limb >>= 8;
        }
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* If data fits in numLimbs writes a (LE), sets a->len = numLimbs, returns true, else false.     */
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
        /* No, the high bytes would be truncated -- reject. */
        return false;
    }

    memset(a->limbs, 0, maxBytes);
    a->len = numLimbs;

    /* Pack each byte into its limb at its byte offset. */
    for (i = 0; i < dataLen; i++)
    {
        uint16_t limbIdx = (uint16_t)(i / sizeof(SSFBNLimb_t));
        uint16_t byteIdx = (uint16_t)(i % sizeof(SSFBNLimb_t));
        a->limbs[limbIdx] |= (((SSFBNLimb_t)data[i]) << (byteIdx * 8u));
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* If outSize holds a then writes out (LE, zero-padded high), returns true, else false.          */
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

    /* Write every limb unless out is narrower than a's limbs */
    actualBytes = (size_t)a->len * sizeof(SSFBNLimb_t);

    /* Is out narrower than a's limbs, so whether a fits depends on its value? */
    if (outSize < actualBytes)
    {
        /* Yes, count the minimum bytes needed to represent a (variable-time) */
        _SSF_BN_COUNT(_SSFBNToBytesScans);
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
            /* No, the value is zero -- represent as a single 0x00 byte. */
            actualBytes = 1u;
        }

        /* Is the caller's buffer large enough for the significant bytes? */
        if (outSize < actualBytes)
        {
            /* No, report failure. */
            return false;
        }
    }
    /* No, every limb fits, so no value-dependent scan is needed */

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

/* SSFBNIsEven and SSFBNIsOdd are macros in ssfbn.h. */

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
/* Returns the bit length of a (most significant set bit index + 1), or 0 if a is zero.          */
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
        for (i = 0; (i + limbShift) < n; i++)
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
        SSFBNDLimb_t diff = ((SSFBNDLimb_t)a->limbs[i] -
                             (SSFBNDLimb_t)sub) -
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
static void _SSFBNSchoolbookMulRaw(SSFBNLimb_t *r, const SSFBNLimb_t *a, uint16_t na,
                                   const SSFBNLimb_t *b, uint16_t nb)
{
    uint16_t i;
    uint16_t j;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(na >= 1u);
    SSF_REQUIRE(nb >= 1u);
    SSF_REQUIRE(((uint32_t)na + (uint32_t)nb) <= (uint32_t)SSF_BN_MAX_LIMBS);

    memset(r, 0, (size_t)(na + nb) * sizeof(SSFBNLimb_t));

    for (i = 0; i < na; i++)
    {
        SSFBNDLimb_t carry = 0;
        SSFBNLimb_t ai = a[i];

        /* No zero-limb skip: secret-data paths require timing independent of operand bits. */
        for (j = 0; j < nb; j++)
        {
            SSFBNDLimb_t prod = (((SSFBNDLimb_t)ai * (SSFBNDLimb_t)b[j]) +
                                 (SSFBNDLimb_t)r[i + j]) + carry;
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
static void _SSFBNKaratsubaMul(SSFBNLimb_t *r, const SSFBNLimb_t *a, const SSFBNLimb_t *b,
                               uint16_t n)
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
    SSF_REQUIRE(n >= SSF_BN_KARATSUBA_THRESHOLD);
    SSF_REQUIRE((n & 1u) == 0u);

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
    /* Fixed two-limb borrow propagation; a zero borrow subtracts nothing */
    for (i = n; i < (uint16_t)(n + 2u); i++)
    {
        _SSF_BN_COUNT(_SSFBNKaratsubaPropIters);
        SSFBNDLimb_t diff = (SSFBNDLimb_t)mid[i] - (SSFBNDLimb_t)borrow;
        mid[i] = (SSFBNLimb_t)diff;
        borrow = (SSFBNLimb_t)((diff >> SSF_BN_LIMB_BITS) & 1u);
    }

    /* Step 6: mid -= z2 (occupying r[n..2n-1]). */
    borrow = _SSFBNRawSub(mid, mid, &r[n], n);
    /* Fixed two-limb borrow propagation; a zero borrow subtracts nothing */
    for (i = n; i < (uint16_t)(n + 2u); i++)
    {
        _SSF_BN_COUNT(_SSFBNKaratsubaPropIters);
        SSFBNDLimb_t diff = (SSFBNDLimb_t)mid[i] - (SSFBNDLimb_t)borrow;
        mid[i] = (SSFBNLimb_t)diff;
        borrow = (SSFBNLimb_t)((diff >> SSF_BN_LIMB_BITS) & 1u);
    }

    /* Step 7: r[half .. half+n+1] += mid[0 .. n+1], propagate carry through higher r limbs. */
    addCarry = 0;
    for (i = 0; i < (uint16_t)(n + 2u); i++)
    {
        addCarry += ((SSFBNDLimb_t)r[half + i] + (SSFBNDLimb_t)mid[i]);
        r[half + i] = (SSFBNLimb_t)addCarry;
        addCarry >>= SSF_BN_LIMB_BITS;
    }
    /* Tail carry propagation to the top of r, fixed length; a zero carry adds nothing */
    for (i = (uint16_t)((half + n) + 2u); i < (uint16_t)(2u * n); i++)
    {
        _SSF_BN_COUNT(_SSFBNKaratsubaPropIters);
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
    SSF_REQUIRE(a->len <= a->cap);
    SSF_REQUIRE(b->len <= b->cap);
    SSF_REQUIRE(((uint32_t)a->len + (uint32_t)b->len) <= (uint32_t)SSF_BN_MAX_LIMBS);

    rLen = (uint16_t)(a->len + b->len);
    SSF_REQUIRE(rLen <= r->cap);

    /* Is this a same-size, even-length multiply at or above the Karatsuba threshold? */
    if ((a->len == b->len) &&
        (a->len >= SSF_BN_KARATSUBA_THRESHOLD) &&
        ((a->len & 1u) == 0u))
    {
        /* Yes, dispatch to Karatsuba -- ~0.75*n^2 single-limb multiplies vs n^2 schoolbook. */
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

        /* No zero-limb skip -- see _SSFBNSchoolbookMulRaw for rationale. */
        for (j = 0; j < b->len; j++)
        {
            SSFBNDLimb_t prod = (((SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)b->limbs[j]) +
                                 (SSFBNDLimb_t)r->limbs[i + j]) + carry;
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
        carry += ((SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)b);
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
    SSF_REQUIRE(a->len <= a->cap);
    SSF_REQUIRE(((uint32_t)a->len * 2u) <= (uint32_t)SSF_BN_MAX_LIMBS);

    n = a->len;
    rLen = (uint16_t)(n * 2u);
    SSF_REQUIRE(rLen <= r->cap);

    memset(r->limbs, 0, (size_t)rLen * sizeof(SSFBNLimb_t));
    r->len = rLen;

    /* Step 1: accumulate strict upper triangle a[i]*a[j] (i<j); r[2n-1] stays 0 so step 2 fits. */
    for (i = 0; (i + 1u) < n; i++)
    {
        SSFBNDLimb_t carry = 0;
        uint16_t j;
        SSFBNLimb_t ai = a->limbs[i];

        /* No zero-limb skip -- see _SSFBNSchoolbookMulRaw for rationale. */
        for (j = (uint16_t)(i + 1u); j < n; j++)
        {
            SSFBNDLimb_t prod = (((SSFBNDLimb_t)ai * (SSFBNDLimb_t)a->limbs[j]) +
                                 (SSFBNDLimb_t)r->limbs[i + j]) + carry;
            r->limbs[i + j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
        }
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
        r->limbs[i + n] += (SSFBNLimb_t)carry;
#ifdef _WIN32
#pragma warning(pop)
#endif
    }

    /* Step 2: double the upper triangle via a single shift-left-by-1 across 2n limbs. */
    shiftCarry = 0;
    for (k = 0; k < rLen; k++)
    {
        SSFBNLimb_t newCarry = r->limbs[k] >> (SSF_BN_LIMB_BITS - 1u);
        r->limbs[k] = (SSFBNLimb_t)((r->limbs[k] << 1) | shiftCarry);
        shiftCarry = newCarry;
    }

    /* Step 3: add diagonal a[i]*a[i] at 2i, one fixed pass with a running carry */
    {
        SSFBNLimb_t carry = 0u;

        for (i = 0; i < n; i++)
        {
            SSFBNDLimb_t sq = (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)a->limbs[i];
            SSFBNDLimb_t sum;

            /* r[2i] += low(sq) + carry; r[2i + 1] += high(sq) + that carry (a^2 < 2^(64n)) */
            sum = ((SSFBNDLimb_t)r->limbs[2u * i] + (SSFBNDLimb_t)(SSFBNLimb_t)sq) +
                  (SSFBNDLimb_t)carry;
            r->limbs[2u * i] = (SSFBNLimb_t)sum;
            sum = ((SSFBNDLimb_t)r->limbs[(2u * i) + 1u] + (sq >> SSF_BN_LIMB_BITS)) +
                  (sum >> SSF_BN_LIMB_BITS);
            r->limbs[(2u * i) + 1u] = (SSFBNLimb_t)sum;
            carry = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);
            _SSF_BN_COUNT(_SSFBNSquareCarryIters);
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
    SSFBNLimb_t mask;
    SSFBNDLimb_t addCarry;
    uint16_t i;

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

    /* Subtract m in place, no temporary */
    borrow = _SSFBNRawSub(r->limbs, r->limbs, m->limbs, m->len);

    /* a + b < m exactly when the add did not carry and the subtract borrowed: add m back, CT */
    mask = (SSFBNLimb_t)(-(int32_t)((SSFBNLimb_t)(carry == 0u) & (SSFBNLimb_t)(borrow != 0u)));
    addCarry = 0u;
    for (i = 0u; i < m->len; i++)
    {
        addCarry += ((SSFBNDLimb_t)r->limbs[i] + (SSFBNDLimb_t)(m->limbs[i] & mask));
        r->limbs[i] = (SSFBNLimb_t)addCarry;
        addCarry >>= SSF_BN_LIMB_BITS;
    }
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
            carry += ((SSFBNDLimb_t)r->limbs[i] + (SSFBNDLimb_t)(m->limbs[i] & mask));
            r->limbs[i] = (SSFBNLimb_t)carry;
            carry >>= SSF_BN_LIMB_BITS;
        }
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a mod m by shift-and-subtract: any nonzero m; branches on each step's borrow.             */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNModShift(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBN_DEFINE(rem, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(shifted, SSF_BN_MAX_LIMBS);
    uint32_t aBits;
    uint32_t mBits;
    int32_t shift;

    _SSF_BN_COUNT(_SSFBNModShiftCalls);

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
/* r = a mod m for odd m, constant-time: a in modulus-width chunks folded in Montgomery form.    */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNModMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(ctx, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(acc, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(c, SSF_BN_MAX_MOD_LIMBS);
    uint16_t n;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);
    SSF_REQUIRE(a->len <= (2u * m->len));
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u);

    n = m->len;
    SSFBNMontInit(&ctx, m);

    /* Is a wider than m? (lengths are public) */
    if (a->len > n)
    {
        /* Yes, a = hi * R + lo: acc = hi * R^2, c = lo * R, so acc + c = a * R (mod m) */
        c.len = (uint16_t)(a->len - n);
        memcpy(c.limbs, &a->limbs[n], (size_t)c.len * sizeof(SSFBNLimb_t));
        SSFBNMontConvertIn(&acc, &c, &ctx);
        SSFBNMontMul(&acc, &acc, &ctx.rr, &ctx);
        c.len = n;
        memcpy(c.limbs, a->limbs, (size_t)n * sizeof(SSFBNLimb_t));
        SSFBNMontConvertIn(&c, &c, &ctx);
        SSFBNModAdd(&acc, &acc, &c, m);
    }
    else
    {
        /* No, acc = a * R (mod m) directly */
        c.len = a->len;
        memcpy(c.limbs, a->limbs, (size_t)a->len * sizeof(SSFBNLimb_t));
        SSFBNMontConvertIn(&acc, &c, &ctx);
    }

    /* Each chunk is < R and R^2 mod m < m, so every product is exact; r = acc * R^-1 = a */
    SSFBNMontConvertOut(r, &acc, &ctx);

    /* Zeroize the intermediates and the context, since m may be a secret prime */
    SSFBNZeroize(&acc);
    _SSF_BN_SCRUB_HOOK(acc.limbs, (size_t)acc.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&c);
    _SSF_BN_SCRUB_HOOK(c.limbs, (size_t)c.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&ctx.mod);
    _SSF_BN_SCRUB_HOOK(ctx.mod.limbs, (size_t)ctx.mod.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&ctx.rr);
    _SSF_BN_SCRUB_HOOK(ctx.rr.limbs, (size_t)ctx.rr.cap * sizeof(SSFBNLimb_t));
}

/* --------------------------------------------------------------------------------------------- */
/* r = a mod m. a->len may be up to 2 * m->len. Constant-time for odd m.                         */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMod(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
#if SSF_CONFIG_BN_UNIT_TEST == 1
    _SSFBNModCallCount++;
#endif /* SSF_CONFIG_BN_UNIT_TEST */

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(SSFBNIsZero(m) == false);
    SSF_REQUIRE(a->len <= (2u * m->len));
    SSF_REQUIRE(a->len <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);

    /* Is m odd and no wider than a Montgomery modulus, as RSA's p, q and n are? */
    if (((m->limbs[0] & 1u) != 0u) && (m->len <= SSF_BN_MAX_MOD_LIMBS))
    {
        /* Yes, constant-time Montgomery reduction; m's parity and length are public */
        _SSFBNModMont(r, a, m);
    }
    else
    {
        /* No, Montgomery needs an odd modulus: shift-and-subtract */
        _SSFBNModShift(r, a, m);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m.                                                                            */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);

    _SSF_BN_COUNT(_SSFBNFullWidthCalls);

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
/* r = (a * b) mod m, constant-time, by fixed-iteration shift-and-subtract (any m).              */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNModMulCTShift(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b,
                                const SSFBN_t *m)
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

    _SSF_BN_COUNT(_SSFBNSlowPathCalls);

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

    /* Fixed-iteration shift-and-subtract: nIters = m->len * 32 + 1 covers all possible shifts. */
    nIters = ((uint32_t)m->len * SSF_BN_LIMB_BITS) + 1u;
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
/* r = (a * b) mod m for odd m, constant-time, by two Montgomery multiplies.                     */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNModMulCTMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(ctx, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(t, SSF_BN_MAX_MOD_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u);

    /* a * b * R^-1, then times R^2 * R^-1: exact when a < m or b < m (the other < R) */
    SSFBNMontInit(&ctx, m);
    SSFBNMontMul(&t, a, b, &ctx);
    SSFBNMontMul(r, &t, &ctx.rr, &ctx);

    /* Zeroize the intermediate, and the context in case m is a secret prime */
    SSFBNZeroize(&t);
    _SSF_BN_SCRUB_HOOK(t.limbs, (size_t)t.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&ctx.mod);
    _SSF_BN_SCRUB_HOOK(ctx.mod.limbs, (size_t)ctx.mod.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&ctx.rr);
    _SSF_BN_SCRUB_HOOK(ctx.rr.limbs, (size_t)ctx.rr.cap * sizeof(SSFBNLimb_t));
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m, constant-time.                                                             */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMulCT(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    uint8_t aLtM;
    uint8_t bLtM;

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

    _SSF_BN_COUNT(_SSFBNFullWidthCalls);

    /* Exact only if a < m or b < m; compares combined branch-free */
    aLtM = (uint8_t)(SSFBNCmp(a, m) < 0);
    bLtM = (uint8_t)(SSFBNCmp(b, m) < 0);
    SSF_REQUIRE((aLtM | bLtM) != 0u);

    /* Is m odd, as every in-tree caller's (RSA n, p, q; prime moduli) is? */
    if ((m->limbs[0] & 1u) != 0u)
    {
        /* Yes, use the faster Montgomery reduction; m is public */
        _SSFBNModMulCTMont(r, a, b, m);
    }
    else
    {
        /* No, Montgomery needs an odd modulus */
        _SSFBNModMulCTShift(r, a, b, m);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m for odd m, constant-time: SSFBNModMulCT without its even-modulus path, so    */
/* callers whose moduli are always odd do not link the shift-and-subtract (OPTIMIZE BN-15).      */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMulCTOdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    uint8_t aLtM;
    uint8_t bLtM;

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
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u);
    SSF_REQUIRE((uint16_t)(2u * m->len) <= SSF_BN_MAX_LIMBS);
    SSF_REQUIRE(m->len <= r->cap);

    _SSF_BN_COUNT(_SSFBNFullWidthCalls);

    /* Exact only if a < m or b < m; compares combined branch-free */
    aLtM = (uint8_t)(SSFBNCmp(a, m) < 0);
    bLtM = (uint8_t)(SSFBNCmp(b, m) < 0);
    SSF_REQUIRE((aLtM | bLtM) != 0u);

    _SSFBNModMulCTMont(r, a, b, m);
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
    SSFBN_DEFINE(ub, SSF_BN_MAX_LIMBS);
    SSFBN_DEFINE(vb, SSF_BN_MAX_LIMBS);
    SSFBN_t *u = &ub;
    SSFBN_t *v = &vb;
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

    SSFBNCopy(u, a);
    SSFBNCopy(v, b);

    /* Strip common 2-factors via min(tz(u), tz(v)); leaves at least one of u, v odd. */
    {
        uint32_t tzU = SSFBNTrailingZeros(u);
        uint32_t tzV = SSFBNTrailingZeros(v);
        shift = (tzU < tzV) ? tzU : tzV;
        SSFBNShiftRight(u, shift);
        SSFBNShiftRight(v, shift);
    }

    /* Strip any remaining factors of 2 from u so u is odd going into the main loop. */
    SSFBNShiftRight(u, SSFBNTrailingZeros(u));

    while (SSFBNIsZero(v) == false)
    {
        /* Reduce v to its odd part in one shot. */
        SSFBNShiftRight(v, SSFBNTrailingZeros(v));

        if (SSFBNCmp(u, v) > 0)
        {
            /* Swap the roles, not the limbs */
            SSFBN_t *t = u;
            u = v;
            v = t;
        }
        SSFBNSub(v, v, u);
    }

    /* Restore common factors of 2 */
    SSFBNCopy(r, u);
    SSFBNShiftLeft(r, shift);
}

/* --------------------------------------------------------------------------------------------- */
/* Computes q = a / b and rem = a mod b via shift-subtract long division.                        */
/* --------------------------------------------------------------------------------------------- */
void SSFBNDivMod(SSFBN_t *q, SSFBN_t *rem, const SSFBN_t *a, const SSFBN_t *b)
{
    SSFBN_DEFINE(shifted, SSF_BN_MAX_LIMBS);
    uint32_t aBits;
    uint32_t bBits;
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
        for (i = 0; (i < b->len) && (i < workLen); i++) shifted.limbs[i] = b->limbs[i];
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
/* If gcd(a, m) == 1 writes r = a^(-1) mod m by extended Euclid and returns true (any m).        */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFBNModInvExtEuclid(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    /* Track only s (m's coefficient is implicit); signs tracked separately (SSFBN_t unsigned). */
    /* Every value is reduced below m, so only the product needs 2N limbs (BN-05). */
    SSFBN_DEFINE(old_r, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(cur_r, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(old_s, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(cur_s, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(quotient, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(tmp_r, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(tmp_s, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(prod, SSF_BN_MAX_LIMBS);       /* quotient * cur_s: the only 2N-wide local */
    bool old_s_neg = false;
    bool cur_s_neg = false;
    uint16_t len;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);

    _SSF_BN_COUNT(_SSFBNSlowPathCalls);

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
            SSFBN_DEFINE(qxs, SSF_BN_MAX_MOD_LIMBS);
            SSF_ENSURE((uint16_t)(quotient.len + cur_s.len) <= SSF_BN_MAX_LIMBS);
            SSFBNMul(&prod, &quotient, &cur_s);
            SSFBNMod(&qxs, &prod, m);

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

    SSF_ENSURE(SSFBNCmp(r, m) < 0);

    /* Verify a * r mod m == 1; catches a non-coprime case where the algorithm produced garbage. */
    {
        SSFBN_DEFINE(check, SSF_BN_MAX_MOD_LIMBS);
        SSFBNModMul(&check, a, r, m);
        if (SSFBNIsOne(&check) == false) return false;
    }

    return true;
}

/* --------------------------------------------------------------------------------------------- */
/* x = x / 2 mod m for odd m and x < m: adds m first when x is odd, keeping its carry bit.       */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNHalveMod(SSFBN_t *x, const SSFBN_t *m)
{
    SSFBNLimb_t carry = 0u;
    uint16_t i;

    SSF_REQUIRE(x != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(x->len == m->len);

    /* Is x odd? */
    if ((x->limbs[0] & 1u) != 0u)
    {
        /* Yes, x + m is even (m is odd) and below 2m: one carry bit above the top limb */
        carry = _SSFBNRawAdd(x->limbs, x->limbs, m->limbs, m->len);
    }
    /* No */
    for (i = 0u; i < x->len; i++)
    {
        SSFBNLimb_t hi = ((uint16_t)(i + 1u) < x->len) ? x->limbs[i + 1u] : carry;

        x->limbs[i] = (SSFBNLimb_t)((x->limbs[i] >> 1) | (hi << (SSF_BN_LIMB_BITS - 1u)));
    }
}

/* --------------------------------------------------------------------------------------------- */
/* If gcd(a, m) == 1 writes r = a^(-1) mod m by binary extended GCD (odd m, 0 < a < m).          */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFBNModInvBinary(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBN_DEFINE(u, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(v, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(x1, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(x2, SSF_BN_MAX_MOD_LIMBS);
    uint32_t passes = 0u;
    bool ok;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u);

    /* Invariants: x1 * a == u and x2 * a == v (mod m); u + v shrinks every pass, v stays odd */
    SSFBNCopy(&u, a);
    SSFBNCopy(&v, m);
    SSFBNSetOne(&x1, m->len);
    SSFBNSetZero(&x2, m->len);
    while (!SSFBNIsZero(&u))
    {
        /* Each pass halves at least once after it, and u + v has at most 64 * len bits to lose */
        passes++;
        SSF_ASSERT(passes <= (((2u * (uint32_t)m->len) * SSF_BN_LIMB_BITS) + 1u));

        while ((u.limbs[0] & 1u) == 0u)
        {
            SSFBNShiftRight1(&u);
            _SSFBNHalveMod(&x1, m);
        }
        while ((v.limbs[0] & 1u) == 0u)
        {
            SSFBNShiftRight1(&v);
            _SSFBNHalveMod(&x2, m);
        }

        /* Is u >= v? */
        if (_SSFBNRawCmp(u.limbs, v.limbs, m->len) >= 0)
        {
            /* Yes, u -= v keeps u >= 0 */
            (void)_SSFBNRawSub(u.limbs, u.limbs, v.limbs, m->len);
            SSFBNModSub(&x1, &x1, &x2, m);
        }
        else
        {
            /* No, v -= u */
            (void)_SSFBNRawSub(v.limbs, v.limbs, u.limbs, m->len);
            SSFBNModSub(&x2, &x2, &x1, m);
        }
    }

    /* u reached 0, so v = gcd(a, m): an inverse exists exactly when it is 1 */
    ok = SSFBNIsOne(&v);
    if (ok) SSFBNCopy(r, &x2);

    /* Zeroize: a may be a secret (the RSA blinding factor) */
    SSFBNZeroize(&u);
    _SSF_BN_SCRUB_HOOK(u.limbs, (size_t)u.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&v);
    _SSF_BN_SCRUB_HOOK(v.limbs, (size_t)v.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&x1);
    _SSF_BN_SCRUB_HOOK(x1.limbs, (size_t)x1.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&x2);
    _SSF_BN_SCRUB_HOOK(x2.limbs, (size_t)x2.cap * sizeof(SSFBNLimb_t));
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* If a^(-1) mod m exists then writes r, returns true, else false.                               */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNModInvExt(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);

    _SSF_BN_COUNT(_SSFBNFullWidthCalls);

    /* Is m odd with 0 < a < m, the RSA blinding inverse's case (n is odd, r < n)? */
    if (((m->limbs[0] & 1u) != 0u) && (!SSFBNIsZero(a)) && (SSFBNCmp(a, m) < 0))
    {
        /* Yes, use the faster binary extended GCD */
        return _SSFBNModInvBinary(r, a, m);
    }
    /* No, extended Euclid handles even m (RSA keygen's lambda) and unreduced a */
    return _SSFBNModInvExtEuclid(r, a, m);
}

/* --------------------------------------------------------------------------------------------- */
/* If gcd(a, m) == 1 writes r = a^(-1) mod m and returns true, else false. Odd m, a < m only:    */
/* the binary path of SSFBNModInvExt without its Euclid fallback, so callers that never need an  */
/* even modulus do not link it (OPTIMIZE BN-07). Variable-time (see ssfbn.md).                   */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNModInvOdd(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u);
    SSF_REQUIRE(SSFBNCmp(a, m) < 0);

    _SSF_BN_COUNT(_SSFBNFullWidthCalls);

    /* Is a zero (never invertible)? */
    if (SSFBNIsZero(a)) return false;
    return _SSFBNModInvBinary(r, a, m);
}

#if SSF_BN_CONFIG_MAX_BITS >= 512
/* --------------------------------------------------------------------------------------------- */
/* Adds c * k (coefficients in {-1, 0, 1}) to n limbs of r in constant time; returns the carry.  */
/* --------------------------------------------------------------------------------------------- */
static int32_t _SSFBNNistFold(SSFBNLimb_t *r, const int8_t *coef, uint16_t n, int32_t c)
{
    int32_t carry = 0;
    uint64_t w;
    uint16_t i;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(coef != NULL);
    SSF_REQUIRE(n >= 1u);
    SSF_REQUIRE((c >= -8) && (c <= 8));

    /* k = 2^(32n) mod p; c is the reduction's net carry; the returned carry is signed */
    for (i = 0u; i < n; i++)
    {
        /* w = v + 64 for v = r[i] + coef * c + carry; the bias keeps every operand unsigned */
        w = (uint64_t)r[i] + (uint64_t)(uint32_t)((((int32_t)coef[i] * c) + carry) + 64);
        r[i] = (SSFBNLimb_t)(w - 64u);
        /* floor(v / 2^32) is -1, 0 or 1: no division and no shift of a negative value */
        carry = (int32_t)((w + 0xFFFFFFC0u) >> 32) - 1;
    }
    return carry;
}
#endif /* SSF_BN_CONFIG_MAX_BITS >= 512 */

/* --------------------------------------------------------------------------------------------- */
/* Reduces a 512-bit product (16 limbs) modulo NIST P-256 to 8 limbs. NIST SP 800-186 D.2.1.     */
/* --------------------------------------------------------------------------------------------- */
#if SSF_BN_CONFIG_MAX_BITS >= 512
static void _SSFBNReduceP256(SSFBN_t *r, const SSFBN_t *t)
{
    /* Name the 32-bit words: t = (c15 c14 ... c1 c0) where c0 = t->limbs[0] etc. */
    const SSFBNLimb_t *c;
    SSFBNLimb_t carry;
    SSFBNLimb_t borrow;
    SSFBN_DEFINE(s, 8u); /* P-256 width, not the BN cap */
    SSFBN_DEFINE(tmp, 8u);

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

    /* r + (carry - borrow) * 2^256 is the value, carry - borrow in [-4, 6]; 2^256 == k mod p */
    {
        static const int8_t k256[8] = { 1, 0, 0, -1, 0, 0, -1, 1 };
        SSFBNLimb_t subBorrow;
        SSFBNLimb_t mask;
        int32_t e;
        uint16_t j;

        /* k = 2^224 - 2^192 - 2^96 + 1; |net * k| < 2^227, so e is -1, 0 or 1 */
        _SSF_BN_COUNT(_SSFBNNistCorrPasses);
        e = _SSFBNNistFold(r->limbs, k256, 8u, (int32_t)carry - (int32_t)borrow);

        /* Folding e cannot carry again: r + e * k stays in [0, 2^256) */
        _SSF_BN_COUNT(_SSFBNNistCorrPasses);
        e = _SSFBNNistFold(r->limbs, k256, 8u, e);
        SSF_ASSERT(e == 0);

        /* r < 2^256 < 2p: one masked conditional subtraction gives [0, p) */
        _SSF_BN_COUNT(_SSFBNNistCorrPasses);
        tmp.len = 8;
        subBorrow = _SSFBNRawSub(tmp.limbs, r->limbs, SSF_BN_NIST_P256.limbs, 8);
        mask = (SSFBNLimb_t)(subBorrow - 1u);
        for (j = 0u; j < 8u; j++)
        {
            r->limbs[j] = (tmp.limbs[j] & mask) | (r->limbs[j] & ~mask);
        }
    }
}
#endif /* SSF_BN_CONFIG_MAX_BITS >= 512 */

/* --------------------------------------------------------------------------------------------- */
/* Reduces a 768-bit product (24 limbs) modulo NIST P-384 to 12 limbs. NIST SP 800-186 D.2.2.    */
/* --------------------------------------------------------------------------------------------- */
#if SSF_BN_CONFIG_MAX_BITS >= 768
static void _SSFBNReduceP384(SSFBN_t *r, const SSFBN_t *t)
{
    const SSFBNLimb_t *c;
    SSFBNLimb_t carry = 0;
    SSFBNLimb_t borrow = 0;
    SSFBN_DEFINE(s, 12u); /* P-384 width, not the BN cap */
    SSFBN_DEFINE(tmp, 12u);

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

    /* r + (carry - borrow) * 2^384 is the value, carry - borrow in [-3, 7]; 2^384 == k mod p */
    {
        static const int8_t k384[12] = { 1, -1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0 };
        SSFBNLimb_t subBorrow;
        SSFBNLimb_t mask;
        int32_t e;
        uint16_t j;

        /* k = 2^128 + 2^96 - 2^32 + 1; |net * k| < 2^132, so e is -1, 0 or 1 */
        _SSF_BN_COUNT(_SSFBNNistCorrPasses);
        e = _SSFBNNistFold(r->limbs, k384, 12u, (int32_t)carry - (int32_t)borrow);

        /* Folding e cannot carry again: r + e * k stays in [0, 2^384) */
        _SSF_BN_COUNT(_SSFBNNistCorrPasses);
        e = _SSFBNNistFold(r->limbs, k384, 12u, e);
        SSF_ASSERT(e == 0);

        /* r < 2^384 < 2p: one masked conditional subtraction gives [0, p) */
        _SSF_BN_COUNT(_SSFBNNistCorrPasses);
        tmp.len = 12;
        subBorrow = _SSFBNRawSub(tmp.limbs, r->limbs, SSF_BN_NIST_P384.limbs, 12);
        mask = (SSFBNLimb_t)(subBorrow - 1u);
        for (j = 0u; j < 12u; j++)
        {
            r->limbs[j] = (tmp.limbs[j] & mask) | (r->limbs[j] & ~mask);
        }
    }
}
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */

#if SSF_CONFIG_BN_UNIT_TEST == 1
/* --------------------------------------------------------------------------------------------- */
/* Test-only: r = t mod m via the P-256 / P-384 fast reduction; m must be one of the two.        */
/* --------------------------------------------------------------------------------------------- */
void _SSFBNReduceNISTForTest(SSFBN_t *r, const SSFBN_t *t, const SSFBN_t *m)
{
    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(t != NULL);
    SSF_REQUIRE(m != NULL);

#if SSF_BN_CONFIG_MAX_BITS >= 512
    /* Is m the P-256 prime? */
    if ((m->len == 8u) && (_SSFBNRawCmp(m->limbs, SSF_BN_NIST_P256.limbs, 8) == 0))
    {
        /* Yes */
        _SSFBNReduceP256(r, t);
        return;
    }
#endif /* SSF_BN_CONFIG_MAX_BITS >= 512 */
#if SSF_BN_CONFIG_MAX_BITS >= 768
    /* Is m the P-384 prime? */
    if ((m->len == 12u) && (_SSFBNRawCmp(m->limbs, SSF_BN_NIST_P384.limbs, 12) == 0))
    {
        /* Yes */
        _SSFBNReduceP384(r, t);
        return;
    }
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */
    /* No, not a supported prime */
    SSF_REQUIRE(false);
}
#endif /* SSF_CONFIG_BN_UNIT_TEST */

/* --------------------------------------------------------------------------------------------- */
/* True if the n-limb m is the NIST prime at p: by pointer, else by a counted limb compare.      */
/* --------------------------------------------------------------------------------------------- */
static bool _SSFBNIsNistPrime(const SSFBN_t *m, const SSFBN_t *p)
{
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(p != NULL);

    /* Is it the wrong width for this prime? */
    if (m->len != p->len) return false;

    /* No, is it the library's own prime storage, as every ssfec caller passes? */
    if (m->limbs == p->limbs) return true;

    /* No, a caller's copy: compare the limbs */
    _SSF_BN_COUNT(_SSFBNNistPrimeCmps);
    return (_SSFBNRawCmp(m->limbs, p->limbs, p->len) == 0);
}

/* --------------------------------------------------------------------------------------------- */
/* Returns &SSF_BN_NIST_P256 or &SSF_BN_NIST_P384 if m is that prime, else NULL (one compare).   */
/* --------------------------------------------------------------------------------------------- */
static const SSFBN_t *_SSFBNNistPrimeOf(const SSFBN_t *m)
{
#if SSF_BN_CONFIG_MAX_BITS >= 512
    if (_SSFBNIsNistPrime(m, &SSF_BN_NIST_P256)) return &SSF_BN_NIST_P256;
#endif /* SSF_BN_CONFIG_MAX_BITS >= 512 */
#if SSF_BN_CONFIG_MAX_BITS >= 768
    if (_SSFBNIsNistPrime(m, &SSF_BN_NIST_P384)) return &SSF_BN_NIST_P384;
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */
    (void)m;
    return NULL;
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod p for p, the NIST prime m equals (from _SSFBNNistPrimeOf), by fast reduction; */
/* the caller has checked the operands against m.                                                */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNModMulNISTFast(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b,
                                 const SSFBN_t *p)
{
#if SSF_BN_CONFIG_MAX_BITS >= 512
    /* Product of two curve-width operands: 2 x 12 limbs for P-384, 2 x 8 for P-256 */
#if SSF_BN_CONFIG_MAX_BITS >= 768
    SSFBN_DEFINE(prod, 24u);
#else
    SSFBN_DEFINE(prod, 16u);
#endif

    /* The public callers checked r, a, b and m; p has m's length */
    SSFBNMul(&prod, a, b);
#if SSF_BN_CONFIG_MAX_BITS >= 768
    if (p == &SSF_BN_NIST_P384)
    {
        _SSFBNReduceP384(r, &prod);
        return;
    }
#endif /* SSF_BN_CONFIG_MAX_BITS >= 768 */
    _SSFBNReduceP256(r, &prod);
#else
    /* No NIST prime is built at this cap, so _SSFBNNistPrimeOf never returns one */
    (void)r;
    (void)a;
    (void)b;
    (void)p;
    SSF_ERROR();
#endif /* SSF_BN_CONFIG_MAX_BITS >= 512 */
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m via NIST fast reduction for P-256/P-384, else falls back to SSFBNModMul.    */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMulNIST(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    const SSFBN_t *p;

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

    p = _SSFBNNistPrimeOf(m);
    /* Is m one of the NIST primes? */
    if (p != NULL)
    {
        /* Yes */
        _SSFBNModMulNISTFast(r, a, b, p);
    }
    else
    {
        /* No, fall back to generic */
        SSFBNModMul(r, a, b, m);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m for m the P-256 or P-384 prime only (SSF_REQUIRE): SSFBNModMulNIST without  */
/* its generic fallback, so ssfec does not link SSFBNModMul (OPTIMIZE BN-08).                    */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMulNISTPrime(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    const SSFBN_t *p;

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

    p = _SSFBNNistPrimeOf(m);
    SSF_REQUIRE(p != NULL);
    _SSFBNModMulNISTFast(r, a, b, p);
}

/* --------------------------------------------------------------------------------------------- */
/* If a^(-1) mod m exists for prime m and is verified then writes r, returns true, else false.   */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNModInv(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBN_DEFINE(t, SSF_BN_MAX_MOD_LIMBS); /* m - 2, then a * r mod m: both below m */
    bool ok;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);

    if (SSFBNIsZero(a)) return false;

    /* Is m even? (m is public in every caller, so this branch leaks nothing secret.) */
    if (SSFBNIsEven(m))
    {
        /* Yes, no Fermat inverse exists and Montgomery needs an odd modulus. */
        return false;
    }
    /* No, odd modulus; the a * r == 1 check below rejects non-prime / non-coprime cases. */

    (void)SSFBNSubUint32(&t, m, 2u);
    SSFBNModExp(r, a, &t, m);

    /* Verify a * r mod m == 1 in constant time (m is odd here; r < m meets the precondition) */
    SSFBNModMulCTOdd(&t, a, r, m);
    ok = SSFBNIsOne(&t);

    /* t held m - 2, secret when m is (RSA keygen's qInv mod p) */
    SSFBNZeroize(&t);
    _SSF_BN_SCRUB_HOOK(t.limbs, (size_t)t.cap * sizeof(SSFBNLimb_t));
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* If a^(-1) mod m exists for prime m of <= SSF_BN_SMALL_MAX_LIMBS limbs, sets r, returns true.  */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNModInvSmall(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(ctx, SSF_BN_SMALL_MAX_LIMBS);
    SSFBNLimb_t tableStorage[16][SSF_BN_SMALL_MAX_LIMBS];
    SSFBN_t table[16];
    SSFBN_DEFINE(e, SSF_BN_SMALL_MAX_LIMBS);
    SSFBN_DEFINE(acc, SSF_BN_SMALL_MAX_LIMBS);
    SSFBN_DEFINE(aR, SSF_BN_SMALL_MAX_LIMBS);
    uint16_t i;
    int32_t bit;
    uint32_t w;
    bool ok;

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= SSF_BN_SMALL_MAX_LIMBS);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(m->len <= r->cap);

    /* Is a zero, which has no inverse? */
    if (SSFBNIsZero(a))
    {
        /* Yes */
        return false;
    }
    /* No, is m even (no Fermat inverse, and Montgomery needs an odd modulus)? */
    if (SSFBNIsEven(m))
    {
        /* Yes, m is public in every caller, so this branch leaks nothing secret */
        return false;
    }
    /* No, is m one, which has no Fermat exponent m - 2 (rejected as SSFBNModInv rejects it)? */
    if (SSFBNIsOne(m))
    {
        /* Yes */
        return false;
    }
    /* No */

    /* r = a^(m - 2) mod m in Montgomery form at curve width, not the BN cap */
    SSFBNMontInit(&ctx, m);
    for (i = 0u; i < 16u; i++)
    {
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6001)
#endif
        table[i].limbs = tableStorage[i];
#ifdef _WIN32
#pragma warning(pop)
#endif
        table[i].cap = SSF_BN_SMALL_MAX_LIMBS;
        table[i].len = m->len;
    }

    /* table[w] = a^w in Montgomery form; table[0] is 1 (R mod m) */
    SSFBNMontConvertIn(&aR, a, &ctx);
    SSFBNSetOne(&e, m->len);
    SSFBNMontConvertIn(&table[0], &e, &ctx);
    SSFBNCopy(&table[1], &aR);
    for (i = 2u; i < 16u; i++)
    {
        SSFBNMontMul(&table[i], &table[i - 1u], &aR, &ctx);
    }

    /* 4-bit windows over public m - 2: squares and table reads depend only on m (CT for a) */
    (void)SSFBNSubUint32(&e, m, 2u);
    SSFBNCopy(&acc, &table[0]);
    for (bit = (int32_t)(((uint32_t)m->len * SSF_BN_LIMB_BITS) - 4u); bit >= 0; bit -= 4)
    {
        w = (uint32_t)((e.limbs[(uint32_t)bit / SSF_BN_LIMB_BITS] >>
                        ((uint32_t)bit % SSF_BN_LIMB_BITS)) & 0xFu);
        SSFBNMontSquare(&acc, &acc, &ctx);
        SSFBNMontSquare(&acc, &acc, &ctx);
        SSFBNMontSquare(&acc, &acc, &ctx);
        SSFBNMontSquare(&acc, &acc, &ctx);
        SSFBNMontMul(&acc, &acc, &table[w], &ctx);
    }

    /* a * r == 1 (mod m), checked in Montgomery form as aR * rR * R^-1 == R mod m */
    SSFBNMontMul(&e, &aR, &acc, &ctx);
    ok = (SSFBNCmp(&e, &table[0]) == 0);
    SSFBNMontConvertOut(r, &acc, &ctx);

    /* Zeroize everything derived from a, and the context in case m is a secret prime */
    SSFCryptSecureZero(tableStorage, sizeof(tableStorage));
    _SSF_BN_SCRUB_HOOK(tableStorage, sizeof(tableStorage));
    SSFBNZeroize(&acc);
    _SSF_BN_SCRUB_HOOK(acc.limbs, (size_t)acc.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&aR);
    _SSF_BN_SCRUB_HOOK(aR.limbs, (size_t)aR.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&e);
    _SSF_BN_SCRUB_HOOK(e.limbs, (size_t)e.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&ctx.mod);
    _SSF_BN_SCRUB_HOOK(ctx.mod.limbs, (size_t)ctx.mod.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&ctx.rr);
    _SSF_BN_SCRUB_HOOK(ctx.rr.limbs, (size_t)ctx.rr.cap * sizeof(SSFBNLimb_t));
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* r = (a * b) mod m for odd m of <= SSF_BN_SMALL_MAX_LIMBS limbs and b < m; constant-time.      */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModMulSmall(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(ctx, SSF_BN_SMALL_MAX_LIMBS);
    SSFBN_DEFINE(t, SSF_BN_SMALL_MAX_LIMBS);

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(b != NULL);
    SSF_REQUIRE(b->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= SSF_BN_SMALL_MAX_LIMBS);
    SSF_REQUIRE(a->len == m->len);
    SSF_REQUIRE(b->len == m->len);
    SSF_REQUIRE(m->len <= r->cap);
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u);

    /* a * b * R^-1, then times R^2 * R^-1: exact for any a < R when b < m */
    SSFBNMontInit(&ctx, m);
    SSFBNMontMul(&t, a, b, &ctx);
    SSFBNMontMul(r, &t, &ctx.rr, &ctx);

    /* Zeroize the intermediate, and the context in case m is a secret prime */
    SSFBNZeroize(&t);
    _SSF_BN_SCRUB_HOOK(t.limbs, (size_t)t.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&ctx.mod);
    _SSF_BN_SCRUB_HOOK(ctx.mod.limbs, (size_t)ctx.mod.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&ctx.rr);
    _SSF_BN_SCRUB_HOOK(ctx.rr.limbs, (size_t)ctx.rr.cap * sizeof(SSFBNLimb_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Initializes Montgomery context for the given odd modulus m.                                   */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontInit(SSFBNMont_t *ctx, const SSFBN_t *m)
{
    uint16_t i;
    uint32_t k;
    uint32_t w;
    uint32_t bitLen;
    uint32_t j;
    uint32_t s;
    SSFBN_t *r2 = &ctx->rr; /* built in place: MontSquare reads ctx->mod and mp, not rr */

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->rr.limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= ctx->mod.cap);
    SSF_REQUIRE(m->len <= ctx->rr.cap);
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);
    SSF_REQUIRE((m->limbs[0] & 1u) != 0u);

    SSFBNCopy(&ctx->mod, m);
    ctx->len = m->len;

    /* mp = -m^(-1) mod 2^32 via Newton iteration; 5 iters reach 32-bit accuracy. */
    {
        SSFBNLimb_t x = 1;
        SSFBNLimb_t m0 = ctx->mod.limbs[0];

        for (i = 0; i < 5; i++)
        {
            x = x * (2u - (m0 * x));
        }
        ctx->mp = (SSFBNLimb_t)(-(int32_t)x);
    }

    /* R^2 mod m for R = 2^w, w = 32 * len = j * 2^s (j odd); w can exceed 16 bits */
    w = (uint32_t)ctx->len * SSF_BN_LIMB_BITS;
    bitLen = SSFBNBitLen(&ctx->mod);
    /* From here only ctx->mod is read, so m may alias ctx->rr */
    SSFBNSetZero(r2, ctx->len);

    /* Is m == 1, where R^2 mod m is 0? */
    if (bitLen > 1u)
    {
        /* No, start at 2^(bitLen - 1), the largest power of two below m */
        r2->limbs[(bitLen - 1u) / SSF_BN_LIMB_BITS] =
            (SSFBNLimb_t)((SSFBNLimb_t)1u << ((bitLen - 1u) % SSF_BN_LIMB_BITS));

        /* Split w into its odd part j and power-of-two exponent s */
        j = w;
        s = 0u;
        while ((j & 1u) == 0u)
        {
            j >>= 1;
            s++;
        }

        /* Double to 2^(w + j) mod m, which is 2^j in Montgomery form */
        for (k = 0u; k < (((w - bitLen) + 1u) + j); k++)
        {
            SSFBNModAdd(r2, r2, r2, &ctx->mod);
            _SSF_BN_COUNT(_SSFBNMontInitDoublings);
        }

        /* Each Montgomery square doubles the offset: 2^(w + j) to 2^(w + j * 2^s) = 2^(2w) */
        for (k = 0u; k < s; k++)
        {
            SSFBNMontSquare(r2, r2, ctx);
        }
    }
    /* Yes, r2 stays 0 */
}

/* --------------------------------------------------------------------------------------------- */
/* Zeroes len limbs through a volatile pointer so the stores cannot be optimized away.           */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNWipeLimbs(SSFBNLimb_t *p, size_t len)
{
    volatile SSFBNLimb_t *v = (volatile SSFBNLimb_t *)p;

    SSF_REQUIRE(p != NULL);

    while (len > 0u) { *v++ = 0u; len--; }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a * b * R^(-1) mod m. a and b must be in Montgomery form. CIOS algorithm.                 */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontMul(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *b, const SSFBNMont_t *ctx)
{
    SSFBNLimb_t t[SSF_BN_MAX_MOD_LIMBS + 2]; /* modulus width, not the BN cap */
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
    SSF_REQUIRE(ctx->len <= SSF_BN_MAX_MOD_LIMBS);
    SSF_REQUIRE(ctx->len <= r->cap);
    SSF_REQUIRE(ctx->len <= a->cap);
    SSF_REQUIRE(ctx->len <= b->cap);
    SSF_REQUIRE(a->len == ctx->len);
    SSF_REQUIRE(b->len == ctx->len);

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
            SSFBNDLimb_t prod = (((SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)b->limbs[j]) +
                                 (SSFBNDLimb_t)t[j]) + carry;
            t[j] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
            _SSF_BN_COUNT(_SSFBNMontMulIters);
        }
        t[n] += (SSFBNLimb_t)carry;
        t[n + 1u] = (SSFBNLimb_t)(((SSFBNDLimb_t)t[n] < carry) ? 1u : 0u);

        /* t = (t + (t[0] * mp mod 2^32) * m) / 2^32, the word shift fused in */
        u = t[0] * ctx->mp;

        /* Word 0 of t + u * m is zero by the choice of u; only its carry is kept */
        carry = (((SSFBNDLimb_t)u * (SSFBNDLimb_t)ctx->mod.limbs[0]) + (SSFBNDLimb_t)t[0]) >>
                SSF_BN_LIMB_BITS;
        for (j = 1u; j < n; j++)
        {
            SSFBNDLimb_t prod = (((SSFBNDLimb_t)u * (SSFBNDLimb_t)ctx->mod.limbs[j]) +
                                 (SSFBNDLimb_t)t[j]) + carry;
            t[j - 1u] = (SSFBNLimb_t)prod;
            carry = prod >> SSF_BN_LIMB_BITS;
            _SSF_BN_COUNT(_SSFBNMontMulIters);
        }
        {
            SSFBNDLimb_t sum = (SSFBNDLimb_t)t[n] + carry;
            t[n - 1u] = (SSFBNLimb_t)sum;
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
            t[n] = t[n + 1u] + (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);
            t[n + 1u] = 0;
#ifdef _WIN32
#pragma warning(pop)
#endif
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
            addCarry += ((SSFBNDLimb_t)r->limbs[i] + (SSFBNDLimb_t)(ctx->mod.limbs[i] & mask));
            r->limbs[i] = (SSFBNLimb_t)addCarry;
            addCarry >>= SSF_BN_LIMB_BITS;
        }
    }

    /* t ends holding the unreduced result, secret whenever m or an operand is */
    _SSFBNWipeLimbs(t, (size_t)n + 2u);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a * a * R^(-1) mod m using SOS squaring (faster than SSFBNMontMul(r, a, a, ctx)).         */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontSquare(SSFBN_t *r, const SSFBN_t *a, const SSFBNMont_t *ctx)
{
    /* Local square: SSFBNSquare's rLen <= MAX_LIMBS requirement caps n at MAX_LIMBS / 2 */
    SSFBNLimb_t t[(2u * SSF_BN_MAX_MOD_LIMBS) + 1u]; /* modulus width */
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
    SSF_REQUIRE(n <= SSF_BN_MAX_MOD_LIMBS);
    SSF_REQUIRE(n <= r->cap);
    SSF_REQUIRE(n <= a->cap);
    SSF_REQUIRE(a->len == n);

    memset(t, 0, (size_t)((2u * n) + 1u) * sizeof(SSFBNLimb_t));

    /* Triangular full square: t = a * a (2n limbs) */

    /* Step 1: accumulate strict upper triangle a[i]*a[j] (i<j) without doubling. */
    for (i = 0; (uint16_t)(i + 1u) < n; i++)
    {
        SSFBNDLimb_t carry = 0;
        uint16_t j;
        SSFBNLimb_t ai = a->limbs[i];

        /* No zero-limb skip -- see _SSFBNSchoolbookMulRaw for rationale. */
        for (j = (uint16_t)(i + 1u); j < n; j++)
        {
            SSFBNDLimb_t prod = (((SSFBNDLimb_t)ai * (SSFBNDLimb_t)a->limbs[j]) +
                                 (SSFBNDLimb_t)t[i + j]) + carry;
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

    /* Step 3: add the a[i]*a[i] diagonal with one running carry (fixed length) */
    {
        SSFBNLimb_t carry = 0;

        for (i = 0; i < n; i++)
        {
            SSFBNDLimb_t sq = (SSFBNDLimb_t)a->limbs[i] * (SSFBNDLimb_t)a->limbs[i];
            SSFBNDLimb_t sum;

            sum = ((SSFBNDLimb_t)t[2u * i] + (SSFBNDLimb_t)(SSFBNLimb_t)sq) +
                  (SSFBNDLimb_t)carry;
            t[2u * i] = (SSFBNLimb_t)sum;
/* Disable false positive Visual Studio Code Analysis warning */
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:6385)
#endif
            sum = ((SSFBNDLimb_t)t[(2u * i) + 1u] + (sq >> SSF_BN_LIMB_BITS)) +
                  (sum >> SSF_BN_LIMB_BITS);
#ifdef _WIN32
#pragma warning(pop)
#endif
            t[(2u * i) + 1u] = (SSFBNLimb_t)sum;
            carry = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);
            _SSF_BN_COUNT(_SSFBNMontSqrCarryIters);
        }
        /* a * a < R^2 fits in 2n limbs, so the final carry is 0 */
    }

    /* SOS reduction to a*a*R^-1 (+ at most m) in the upper half; row carries deferred, fixed */
    {
        SSFBNLimb_t hi = 0;

        for (i = 0; i < n; i++)
        {
            SSFBNLimb_t u = (SSFBNLimb_t)(t[i] * ctx->mp);
            SSFBNDLimb_t carry = 0;
            SSFBNDLimb_t sum;
            uint16_t j;

            /* t[i..i+n-1] += u * m (low n limbs of the product). */
            for (j = 0; j < n; j++)
            {
                SSFBNDLimb_t prod = (((SSFBNDLimb_t)u * (SSFBNDLimb_t)ctx->mod.limbs[j]) +
                                     (SSFBNDLimb_t)t[i + j]) + carry;
                t[i + j] = (SSFBNLimb_t)prod;
                carry = prod >> SSF_BN_LIMB_BITS;
            }
            /* Add this row's carry and the previous row's deferred carry at t[i + n] */
            sum = ((SSFBNDLimb_t)t[i + n] + carry) + (SSFBNDLimb_t)hi;
            t[i + n] = (SSFBNLimb_t)sum;
            hi = (SSFBNLimb_t)(sum >> SSF_BN_LIMB_BITS);
            _SSF_BN_COUNT(_SSFBNMontSqrCarryIters);
        }
        /* The result is < 2m < 2R, so the last deferred carry is t[2n]'s only bit */
        t[2u * n] = (SSFBNLimb_t)(t[2u * n] + hi);
    }

    /* Final conditional subtraction to [0, m); a is not read past here, so r may alias a */
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
            addCarry += ((SSFBNDLimb_t)r->limbs[i] + (SSFBNDLimb_t)(ctx->mod.limbs[i] & mask));
            r->limbs[i] = (SSFBNLimb_t)addCarry;
            addCarry >>= SSF_BN_LIMB_BITS;
        }
    }

    /* t ends holding the unreduced result, secret whenever m or an operand is */
    _SSFBNWipeLimbs(t, (2u * (size_t)n) + 1u);
}

/* --------------------------------------------------------------------------------------------- */
/* Converts a to Montgomery form: aR = a * R mod m.                                              */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontConvertIn(SSFBN_t *aR, const SSFBN_t *a, const SSFBNMont_t *ctx)
{
    uint16_t i;

    SSF_REQUIRE(aR != NULL);
    SSF_REQUIRE(aR->limbs != NULL);
    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->rr.limbs != NULL);
    SSF_REQUIRE(ctx->len >= 1u);
    SSF_REQUIRE(ctx->len <= aR->cap);
    SSF_REQUIRE(a->len <= ctx->len);

    /* Zero-extend a into aR in place; safe when aR aliases a */
    for (i = 0u; i < a->len; i++) aR->limbs[i] = a->limbs[i];
    for (; i < ctx->len; i++) aR->limbs[i] = 0u;
    aR->len = ctx->len;

    /* aR = MontMul(a, R^2) = a * R^2 * R^(-1) mod m = a * R mod m (MontMul allows r == a) */
    SSFBNMontMul(aR, aR, &ctx->rr, ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Converts aR from Montgomery form: a = aR * R^(-1) mod m.                                      */
/* --------------------------------------------------------------------------------------------- */
void SSFBNMontConvertOut(SSFBN_t *a, const SSFBN_t *aR, const SSFBNMont_t *ctx)
{
    SSFBN_DEFINE(one, SSF_BN_MAX_MOD_LIMBS); /* at ctx->len, never above it */

    SSF_REQUIRE(a != NULL);
    SSF_REQUIRE(a->limbs != NULL);
    SSF_REQUIRE(aR != NULL);
    SSF_REQUIRE(aR->limbs != NULL);
    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->mod.limbs != NULL);
    SSF_REQUIRE(ctx->len >= 1u);
    SSF_REQUIRE(ctx->len <= a->cap);
    SSF_REQUIRE(aR->len == ctx->len);

    /* a = MontMul(aR, 1) = aR * 1 * R^(-1) mod m = a */
    SSFBNSetOne(&one, ctx->len);
    SSFBNMontMul(a, aR, &one, ctx);
}

/* --------------------------------------------------------------------------------------------- */
/* Internal: r = a^e mod ctx->mod; constant-time fixed-window (k=4) over caller storage of       */
/* (SSF_BN_MODEXP_TBL_N + 2) zeroed residues of cap limbs each, all wiped before return.         */
/* --------------------------------------------------------------------------------------------- */
static void _SSFBNModExpMontCore(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e,
                                 const SSFBNMont_t *ctx, SSFBNLimb_t *store, uint16_t cap)
{
    SSFBN_t table[SSF_BN_MODEXP_TBL_N];
    SSFBN_t result;
    SSFBN_t picked;
    uint32_t nWindows;
    uint32_t winIdx;
    uint32_t w;
    uint32_t k;
    uint32_t bp;
    uint32_t bitOffset;
    int32_t i;

    _SSF_BN_COUNT(_SSFBNFullWidthCalls);

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
    SSF_REQUIRE(store != NULL);
    SSF_REQUIRE(ctx->len <= cap);

    /* Wire up the table and working descriptors over the caller's storage. */
    for (w = 0u; w < SSF_BN_MODEXP_TBL_N; w++)
    {
        table[w].limbs = &store[(size_t)w * cap];
        table[w].len = 0u;
        table[w].cap = cap;
    }
    result.limbs = &store[(size_t)SSF_BN_MODEXP_TBL_N * cap];
    result.len = 0u;
    result.cap = cap;
    picked.limbs = &store[(size_t)(SSF_BN_MODEXP_TBL_N + 1u) * cap];
    picked.len = 0u;
    picked.cap = cap;

    /* table[1] = Mont(a); table[0] = Mont(1) for zero-windows, converted in place */
    /* (ConvertIn allows aR == a); table[i] = Mont(a)^i for i = 2..15.            */
    SSFBNMontConvertIn(&table[1], a, ctx);
    SSFBNSetOne(&table[0], ctx->len);
    SSFBNMontConvertIn(&table[0], &table[0], ctx);
    for (w = 2u; w < SSF_BN_MODEXP_TBL_N; w++)
    {
        SSFBNMontMul(&table[w], &table[w - 1u], &table[1], ctx);
    }

    /* Init result = Mont(1); seed picked with table[0] so its len matches for CondCopy. */
    SSFBNCopy(&result, &table[0]);
    SSFBNCopy(&picked, &table[0]);

    /* nWindows = ceil(max(e->len, ctx->len) * 32 / k): fixed by public lengths, so the loop */
    /* count is e-independent; for k not dividing 32 the top window reads bits past e->len,  */
    /* which SSFBNGetBit returns as 0 (SAFE-03).                                              */
    {
        uint16_t expLen = (e->len > ctx->len) ? e->len : ctx->len;
        nWindows = (((uint32_t)expLen * SSF_BN_LIMB_BITS) + (SSF_BN_MODEXP_WIN_K - 1u)) /
                   SSF_BN_MODEXP_WIN_K;
    }
    for (winIdx = 0u; winIdx < nWindows; winIdx++)
    {
        /* Square k times. */
        for (k = 0u; k < SSF_BN_MODEXP_WIN_K; k++)
        {
            SSFBNMontSquare(&result, &result, ctx);
        }

        /* Decode this window's k-bit value (MSB first). */
        bitOffset = ((nWindows - 1u) - winIdx) * SSF_BN_MODEXP_WIN_K;
        w = 0u;
        for (k = 0u; k < SSF_BN_MODEXP_WIN_K; k++)
        {
            bp = bitOffset + ((SSF_BN_MODEXP_WIN_K - 1u) - k);
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
    SSFBNZeroize(&result);
    SSFBNZeroize(&picked);
    for (w = 0u; w < SSF_BN_MODEXP_TBL_N; w++)
    {
        SSFBNZeroize(&table[w]);
    }
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^e mod m. Constant-time fixed-window via SSFBNModExpMont.                                */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExp(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_MOD_LIMBS); /* a modulus is at most this wide */

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
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);

    SSFBNMontInit(&mont, m);
    SSFBNModExpMont(r, a, e, &mont);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^e mod m using precomputed Montgomery context; constant-time fixed-window (k=4).         */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExpMont(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx)
{
    /* Residues only -- never the 2N raw-mul intermediate. See ssfbn.md "MAX_MOD_LIMBS". */
    SSFBNLimb_t store[(SSF_BN_MODEXP_TBL_N + 2u) * SSF_BN_MAX_MOD_LIMBS] = {0u};

    SSF_REQUIRE(ctx != NULL);
    SSF_REQUIRE(ctx->len <= SSF_BN_MAX_MOD_LIMBS);

    _SSFBNModExpMontCore(r, a, e, ctx, store, SSF_BN_MAX_MOD_LIMBS);
}

/* --------------------------------------------------------------------------------------------- */
/* r = a^e mod m for m of at most SSF_BN_HALF_MOD_LIMBS limbs (an RSA CRT prime); constant-time  */
/* fixed-window (k=4), the same algorithm as SSFBNModExp on half-width storage.                  */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExpHalf(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(mont, SSF_BN_HALF_MOD_LIMBS);
    SSFBNLimb_t store[(SSF_BN_MODEXP_TBL_N + 2u) * SSF_BN_HALF_MOD_LIMBS] = {0u};

    SSF_REQUIRE(r != NULL);
    SSF_REQUIRE(r->limbs != NULL);
    SSF_REQUIRE(m != NULL);
    SSF_REQUIRE(m->limbs != NULL);
    SSF_REQUIRE(m->len >= 1u);
    SSF_REQUIRE(m->len <= r->cap);
    SSF_REQUIRE(m->len <= SSF_BN_HALF_MOD_LIMBS);

    SSFBNMontInit(&mont, m);
    _SSFBNModExpMontCore(r, a, e, &mont, store, SSF_BN_HALF_MOD_LIMBS);
    _SSF_BN_SCRUB_HOOK(store, sizeof(store));

    /* The context holds m (an RSA prime) and R^2 mod m: wipe them too */
    SSFBNZeroize(&mont.mod);
    _SSF_BN_SCRUB_HOOK(mont.mod.limbs, (size_t)mont.mod.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&mont.rr);
    _SSF_BN_SCRUB_HOOK(mont.rr.limbs, (size_t)mont.rr.cap * sizeof(SSFBNLimb_t));
}

/* --------------------------------------------------------------------------------------------- */
/* Variable-time r = a^e mod m; PUBLIC-EXPONENT USE ONLY (see ssfbn.md).                         */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExpPub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBN_t *m)
{
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_MOD_LIMBS); /* a modulus is at most this wide */

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
    SSF_REQUIRE(m->len <= SSF_BN_MAX_MOD_LIMBS);

    SSFBNMontInit(&mont, m);
    SSFBNModExpMontPub(r, a, e, &mont);
}

/* --------------------------------------------------------------------------------------------- */
/* Variable-time ModExp with precomputed Montgomery context; left-to-right binary method.        */
/* --------------------------------------------------------------------------------------------- */
void SSFBNModExpMontPub(SSFBN_t *r, const SSFBN_t *a, const SSFBN_t *e, const SSFBNMont_t *ctx)
{
    SSFBN_DEFINE(result, SSF_BN_MAX_MOD_LIMBS); /* residues: at ctx->len, never above it */
    SSFBN_DEFINE(aM, SSF_BN_MAX_MOD_LIMBS);
    uint32_t eBits;
    int32_t i;

    _SSF_BN_COUNT(_SSFBNFullWidthCalls);

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
    SSF_REQUIRE(ctx->len <= SSF_BN_MAX_MOD_LIMBS);

    eBits = SSFBNBitLen(e);

    /* Is the exponent zero? */
    if (eBits == 0u)
    {
        /* Yes, a^0 mod m = 1 mod m, which matches SSFBNModExpMont. */
        SSFBNSetOne(r, ctx->len);

        /* Is the modulus 1? (public value) */
        if (SSFBNCmpUint32(&ctx->mod, 1u) == 0)
        {
            /* Yes, everything is 0 mod 1. */
            SSFBNSetZero(r, ctx->len);
        }
        return;
    }

    /* Convert a to Montgomery form once; every subsequent MontMul keeps result in Mont form. */
    SSFBNMontConvertIn(&aM, a, ctx);

    /* The top bit of e is set: starting from Mont(1) would square it and multiply by aM, */
    /* giving aM, so start there and process the remaining bits. */
    SSFBNCopy(&result, &aM);

    /* Left-to-right binary square-and-multiply; leaks Hamming weight of e (public-only). */
    for (i = (int32_t)eBits - 2; i >= 0; i--)
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
/* If a uniform random a in [0, bound) is drawn within the retry cap returns true, else false.   */
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
    SSFBN_DEFINE(nm1, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(d, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(a, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(x, SSF_BN_MAX_MOD_LIMBS);
    SSFBN_DEFINE(nm3, SSF_BN_MAX_MOD_LIMBS);
    SSFBNMONT_DEFINE(mont, SSF_BN_MAX_MOD_LIMBS); /* candidate is a Montgomery modulus */
    uint32_t s = 0;
    uint16_t round;
    bool ok = false;

    SSF_REQUIRE(n != NULL);
    SSF_REQUIRE(n->limbs != NULL);
    SSF_REQUIRE(n->len <= SSF_BN_MAX_MOD_LIMBS);
    SSF_REQUIRE(prng != NULL);

    /* Small cases: the witness range [2, n-2] is empty for n <= 3, so handle 0..3 directly */
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
                    a.limbs[topLimb] &= (((SSFBNLimb_t)1u << topBit) - 1u);
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
        if ((SSFBNIsOne(&x)) || (SSFBNCmp(&x, &nm1) == 0))
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
                goto cleanup;
            }
        }

        /* Did we find a pass condition inside the inner loop? */
        if (cont == false)
        {
            /* No, this witness proves n composite. */
            goto cleanup;
        }
    }

    ok = true;

cleanup:
    /* Wipe every working value derived from the candidate */
    SSFBNZeroize(&nm1);
    _SSF_BN_SCRUB_HOOK(nm1.limbs, (size_t)nm1.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&d);
    _SSF_BN_SCRUB_HOOK(d.limbs, (size_t)d.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&a);
    _SSF_BN_SCRUB_HOOK(a.limbs, (size_t)a.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&x);
    _SSF_BN_SCRUB_HOOK(x.limbs, (size_t)x.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&nm3);
    _SSF_BN_SCRUB_HOOK(nm3.limbs, (size_t)nm3.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&mont.mod);
    _SSF_BN_SCRUB_HOOK(mont.mod.limbs, (size_t)mont.mod.cap * sizeof(SSFBNLimb_t));
    SSFBNZeroize(&mont.rr);
    _SSF_BN_SCRUB_HOOK(mont.rr.limbs, (size_t)mont.rr.cap * sizeof(SSFBNLimb_t));
    return ok;
}

/* --------------------------------------------------------------------------------------------- */
/* If a random bitLen-bit prime is found within the cap then writes p, returns true, else false. */
/* --------------------------------------------------------------------------------------------- */
bool SSFBNGenPrime(SSFBN_t *p, uint16_t bitLen, uint16_t rounds, SSFPRNGContext_t *prng)
{
    uint16_t limbs;
    uint16_t topBit;
    uint16_t nextBit;
    uint32_t attempts;

    SSF_REQUIRE(p != NULL);
    SSF_REQUIRE(p->limbs != NULL);
    SSF_REQUIRE(bitLen >= 16u);
    SSF_REQUIRE(bitLen <= (SSF_BN_CONFIG_MAX_BITS / 2u));
    SSF_REQUIRE(bitLen <= (SSF_BN_MAX_MOD_LIMBS * SSF_BN_LIMB_BITS));
    SSF_REQUIRE(prng != NULL);

    limbs = (uint16_t)SSF_BN_BITS_TO_LIMBS(bitLen);
    SSF_REQUIRE(limbs <= p->cap);
    topBit = (uint16_t)(bitLen - 1u);
    nextBit = (uint16_t)(bitLen - 2u);

    for (attempts = 0; attempts < 50000u; attempts++)
    {
        uint16_t i;
        bool trialPass;

        /* Draw the candidate straight into p, keep bitLen bits, force the top two and the low */
        SSFBNRandom(p, limbs, prng);
        if ((bitLen % SSF_BN_LIMB_BITS) != 0u)
        {
            p->limbs[limbs - 1u] &=
                (SSFBNLimb_t)(((SSFBNLimb_t)1u << (bitLen % SSF_BN_LIMB_BITS)) - 1u);
        }
        p->limbs[topBit / SSF_BN_LIMB_BITS] |= (SSFBNLimb_t)1u << (topBit % SSF_BN_LIMB_BITS);
        p->limbs[nextBit / SSF_BN_LIMB_BITS] |= (SSFBNLimb_t)1u << (nextBit % SSF_BN_LIMB_BITS);
        p->limbs[0] |= 1u;

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

        /* Yes, is the candidate a probable prime by Miller-Rabin? */
        if (SSFBNIsProbablePrime(p, rounds, prng))
        {
            /* Yes, accept */
            return true;
        }
        /* No, draw another candidate */
    }

    /* No prime found: wipe the last candidate */
    SSFBNZeroize(p);
    return false;
}

