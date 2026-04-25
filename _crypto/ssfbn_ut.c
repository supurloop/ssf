/* --------------------------------------------------------------------------------------------- */
/* Small System Framework                                                                        */
/*                                                                                               */
/* ssfbn_ut.c                                                                                    */
/* Provides unit tests for the ssfbn big number arithmetic module.                               */
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
#include "ssfprng.h"
#if SSF_CONFIG_BN_MICROBENCH == 1
#include "ssfport.h"
#include <stdio.h>
#endif

#if SSF_CONFIG_BN_UNIT_TEST == 1

void SSFBNUnitTest(void)
{
    /* ---- SetZero, SetUint32, IsZero, IsOne ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == true);
        SSF_ASSERT(SSFBNIsOne(&a) == false);
        SSF_ASSERT(a.len == 4);

        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == false);
        SSF_ASSERT(SSFBNIsOne(&a) == true);

        SSFBNSetUint32(&a, 42u, 4);
        SSF_ASSERT(SSFBNIsZero(&a) == false);
        SSF_ASSERT(SSFBNIsOne(&a) == false);
        SSF_ASSERT(SSFBNIsEven(&a) == true);

        SSFBNSetUint32(&a, 43u, 4);
        SSF_ASSERT(SSFBNIsEven(&a) == false);
    }

    /* ---- FromBytes / ToBytes roundtrip ---- */
    {
        static const uint8_t data[] = { 0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu };
        uint8_t out[8];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytes(&a, data, sizeof(data), 4) == true);
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);
        SSF_ASSERT(memcmp(data, out, sizeof(data)) == 0);
    }

    /* ---- FromBytesLE / ToBytesLE: round-trip + parity against BE via byte reversal ---- */
    {
        static const uint8_t le[] = { 0xEFu, 0xCDu, 0xABu, 0x89u, 0x67u, 0x45u, 0x23u, 0x01u };
        static const uint8_t be[] = { 0x01u, 0x23u, 0x45u, 0x67u, 0x89u, 0xABu, 0xCDu, 0xEFu };
        uint8_t out[8];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);

        /* LE from the reversed BE bytes must yield the same numeric value as BE from the BE. */
        SSF_ASSERT(SSFBNFromBytesLE(&a, le, sizeof(le), 2) == true);
        SSF_ASSERT(SSFBNFromBytes(&b, be, sizeof(be), 2) == true);
        SSF_ASSERT(SSFBNCmp(&a, &b) == 0);

        /* Limb layout: limb[0] = 0x89ABCDEF, limb[1] = 0x01234567. */
        SSF_ASSERT(a.limbs[0] == 0x89ABCDEFul);
        SSF_ASSERT(a.limbs[1] == 0x01234567ul);

        /* Round-trip: LE → BN → LE == original. */
        SSF_ASSERT(SSFBNToBytesLE(&a, out, sizeof(out)) == true);
        SSF_ASSERT(memcmp(out, le, sizeof(le)) == 0);
    }

    /* ---- FromBytesLE with dataLen shorter than numLimbs*4 (zero-pad high limbs) ---- */
    {
        static const uint8_t data[] = { 0xFFu };
        uint8_t out[4];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytesLE(&a, data, 1, 2) == true);
        /* LE: low byte is 0xFF → limb[0] = 0x000000FF, limb[1] = 0. */
        SSF_ASSERT(a.limbs[0] == 0x000000FFul);
        SSF_ASSERT(a.limbs[1] == 0x00000000ul);

        SSF_ASSERT(SSFBNToBytesLE(&a, out, sizeof(out)) == true);
        /* LE export: low byte first, then zeros. */
        SSF_ASSERT(out[0] == 0xFFu);
        SSF_ASSERT(out[1] == 0x00u);
        SSF_ASSERT(out[2] == 0x00u);
        SSF_ASSERT(out[3] == 0x00u);
    }

    /* ---- FromBytes / ToBytes with leading zero pad ---- */
    {
        static const uint8_t data[] = { 0xFFu };
        uint8_t out[4];
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSF_ASSERT(SSFBNFromBytes(&a, data, 1, 2) == true);
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);
        SSF_ASSERT(out[0] == 0x00u);
        SSF_ASSERT(out[1] == 0x00u);
        SSF_ASSERT(out[2] == 0x00u);
        SSF_ASSERT(out[3] == 0xFFu);
    }

    /* ---- ToBytes regression: outSize smaller than a->len * limb-size must not corrupt  */
    /* the stack. Uses canary bytes around `out` and checks them afterward; this caught    */
    /* an earlier underflow in the limb-offset computation that wrote to out[SIZE_MAX].    */
    {
        volatile uint8_t canaryLo = 0xA5u;
        uint8_t out[6];
        volatile uint8_t canaryHi = 0x5Au;
        static const uint8_t data[] = { 0x01u, 0x23u };
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        /* 4 limbs * 4 bytes = 16 total limb bytes, written into a 6-byte buffer.          */
        SSF_ASSERT(SSFBNFromBytes(&a, data, sizeof(data), 4) == true);
        SSF_ASSERT(SSFBNToBytes(&a, out, sizeof(out)) == true);

        /* Low bytes zero-padded, tail carries the value. */
        SSF_ASSERT(out[0] == 0x00u);
        SSF_ASSERT(out[1] == 0x00u);
        SSF_ASSERT(out[2] == 0x00u);
        SSF_ASSERT(out[3] == 0x00u);
        SSF_ASSERT(out[4] == 0x01u);
        SSF_ASSERT(out[5] == 0x23u);
        /* Canaries intact → no stack corruption. */
        SSF_ASSERT(canaryLo == 0xA5u);
        SSF_ASSERT(canaryHi == 0x5Au);
    }

    /* ---- Comparison ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 200u, 4);
        SSF_ASSERT(SSFBNCmp(&a, &b) == -1);
        SSF_ASSERT(SSFBNCmp(&b, &a) == 1);
        SSF_ASSERT(SSFBNCmp(&a, &a) == 0);
    }

    /* ---- Add / Sub ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 200u, 4);
        SSF_ASSERT(SSFBNAdd(&r, &a, &b) == 0);
        {
            SSFBN_DEFINE(expected, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&expected, 300u, 4);
            SSF_ASSERT(SSFBNCmp(&r, &expected) == 0);
        }

        SSF_ASSERT(SSFBNSub(&r, &b, &a) == 0);
        {
            SSFBN_DEFINE(expected, SSF_BN_MAX_LIMBS);
            SSFBNSetUint32(&expected, 100u, 4);
            SSF_ASSERT(SSFBNCmp(&r, &expected) == 0);
        }
    }

    /* ---- Multiplication ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* 7 * 6 = 42 */
        SSFBNSetUint32(&a, 7u, 2);
        SSFBNSetUint32(&b, 6u, 2);
        SSFBNMul(&r, &a, &b);
        SSF_ASSERT(r.len == 4);
        SSF_ASSERT(r.limbs[0] == 42u);
        SSF_ASSERT(r.limbs[1] == 0u);
    }

    /* ---- BitLen and GetBit ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 0u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 0);

        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 1);

        SSFBNSetUint32(&a, 255u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 8);

        SSFBNSetUint32(&a, 256u, 4);
        SSF_ASSERT(SSFBNBitLen(&a) == 9);

        /* GetBit: 0b1010 = 10 */
        SSFBNSetUint32(&a, 10u, 4);
        SSF_ASSERT(SSFBNGetBit(&a, 0) == 0);
        SSF_ASSERT(SSFBNGetBit(&a, 1) == 1);
        SSF_ASSERT(SSFBNGetBit(&a, 2) == 0);
        SSF_ASSERT(SSFBNGetBit(&a, 3) == 1);
        SSF_ASSERT(SSFBNGetBit(&a, 4) == 0);
    }

    /* ---- Shift left / right ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 1u, 4);
        SSFBNShiftLeft1(&a);
        SSF_ASSERT(a.limbs[0] == 2u);
        SSFBNShiftLeft1(&a);
        SSF_ASSERT(a.limbs[0] == 4u);

        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 2u);
        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 1u);
        SSFBNShiftRight1(&a);
        SSF_ASSERT(a.limbs[0] == 0u);
    }

    /* ---- Multi-bit ShiftLeft / ShiftRight: must match N iterations of Shift*1 ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        uint32_t nBits;
        uint32_t s;

        /* n == 0 is a no-op on any value. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSFBNCopy(&b, &a);
        SSFBNShiftLeft(&a, 0u);
        SSF_ASSERT(SSFBNCmp(&a, &b) == 0);
        SSFBNShiftRight(&a, 0u);
        SSF_ASSERT(SSFBNCmp(&a, &b) == 0);

        /* Parity sweep: for 0 <= nBits <= 160, SSFBNShiftLeft(a, nBits) must equal nBits       */
        /* applications of SSFBNShiftLeft1 starting from the same a. Same for ShiftRight.       */
        for (nBits = 0; nBits <= 160u; nBits++)
        {
            /* Seed a and b with an identical pseudo-random value wide enough to exercise       */
            /* limb-boundary crossings at 32, 64, 96, 128 bits.                                  */
            uint8_t data[20] = {
                0x12u, 0x34u, 0x56u, 0x78u, 0x9Au, 0xBCu, 0xDEu, 0xF0u,
                0x0Fu, 0xEDu, 0xCBu, 0xA9u, 0x87u, 0x65u, 0x43u, 0x21u,
                0xA5u, 0x5Au, 0xC3u, 0x3Cu
            };
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNFromBytes(&b, data, sizeof(data), 8);

            /* Left parity. */
            SSFBNShiftLeft(&a, nBits);
            for (s = 0; s < nBits; s++) SSFBNShiftLeft1(&b);
            SSF_ASSERT(SSFBNCmp(&a, &b) == 0);

            /* Right parity (reset). */
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNFromBytes(&b, data, sizeof(data), 8);
            SSFBNShiftRight(&a, nBits);
            for (s = 0; s < nBits; s++) SSFBNShiftRight1(&b);
            SSF_ASSERT(SSFBNCmp(&a, &b) == 0);
        }

        /* Shift by exactly the value's bit length zeroes it. */
        SSFBNSetUint32(&a, 1u, 4);
        SSFBNShiftLeft(&a, 4u * 32u);
        SSF_ASSERT(SSFBNIsZero(&a) == true);

        /* Shift by more than the value's bit length still zeroes (no UB, no wraparound). */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNShiftLeft(&a, 10000u);
        SSF_ASSERT(SSFBNIsZero(&a) == true);

        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNShiftRight(&a, 10000u);
        SSF_ASSERT(SSFBNIsZero(&a) == true);

        /* Exact limb-boundary shift: shift of 32 bits. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSFBNShiftLeft(&a, 32u);
        SSF_ASSERT(a.limbs[0] == 0u);
        SSF_ASSERT(a.limbs[1] == 0xDEADBEEFul);
        SSFBNShiftRight(&a, 32u);
        SSF_ASSERT(a.limbs[0] == 0xDEADBEEFul);
        SSF_ASSERT(a.limbs[1] == 0u);

        /* Sub-limb shift that crosses a limb boundary (shift 0xFFFFFFFF left by 20 yields       */
        /* 0x000FFFFF_FFF00000: limb[0]=0xFFF00000, limb[1]=0x000FFFFF).                          */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNShiftLeft(&a, 20u);
        SSF_ASSERT(a.limbs[0] == 0xFFF00000ul);
        SSF_ASSERT(a.limbs[1] == 0x000FFFFFul);
    }

    /* ---- SSFBNSetOne: sets to multiplicative identity ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetOne(&a, 4);
        SSF_ASSERT(SSFBNIsOne(&a) == true);
        SSF_ASSERT(SSFBNIsZero(&a) == false);
        SSF_ASSERT(a.len == 4u);
        SSF_ASSERT(a.limbs[0] == 1u);
        SSF_ASSERT(a.limbs[1] == 0u);
        SSF_ASSERT(a.limbs[2] == 0u);
        SSF_ASSERT(a.limbs[3] == 0u);

        /* Overwrites prior content. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSFBNSetOne(&a, 4);
        SSF_ASSERT(SSFBNIsOne(&a) == true);
    }

    /* ---- SSFBNIsOdd: complement of IsEven ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNIsOdd(&a) == false);

        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNIsOdd(&a) == true);

        SSFBNSetUint32(&a, 2u, 4);
        SSF_ASSERT(SSFBNIsOdd(&a) == false);

        SSFBNSetUint32(&a, 3u, 4);
        SSF_ASSERT(SSFBNIsOdd(&a) == true);

        /* High limb parity does not affect IsOdd — only the low bit of limb[0] matters. */
        SSFBNSetZero(&a, 4);
        a.limbs[3] = 0x80000001ul;
        SSF_ASSERT(SSFBNIsOdd(&a) == false); /* limb[0] = 0 → even */

        a.limbs[0] = 0xFFFFFFFEul;
        SSF_ASSERT(SSFBNIsOdd(&a) == false);

        a.limbs[0] = 0xFFFFFFFFul;
        SSF_ASSERT(SSFBNIsOdd(&a) == true);

        /* IsOdd == !IsEven across the sweep. */
        {
            uint32_t k;
            for (k = 0; k < 100u; k++)
            {
                SSFBNSetUint32(&a, k, 4);
                SSF_ASSERT((SSFBNIsOdd(&a) ? true : false) != SSFBNIsEven(&a));
            }
        }
    }

    /* ---- SSFBNCmpUint32: a vs small integer ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNCmpUint32(&a, 0u) == 0);
        SSF_ASSERT(SSFBNCmpUint32(&a, 1u) == -1);

        SSFBNSetUint32(&a, 5u, 4);
        SSF_ASSERT(SSFBNCmpUint32(&a, 5u) == 0);
        SSF_ASSERT(SSFBNCmpUint32(&a, 4u) == 1);
        SSF_ASSERT(SSFBNCmpUint32(&a, 6u) == -1);

        /* a > any uint32_t when a has nonzero high limbs. */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 1u;
        SSF_ASSERT(SSFBNCmpUint32(&a, 0u) == 1);
        SSF_ASSERT(SSFBNCmpUint32(&a, 0xFFFFFFFFul) == 1);

        /* Exact-boundary: a == UINT32_MAX. */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSF_ASSERT(SSFBNCmpUint32(&a, 0xFFFFFFFFul) == 0);
        SSF_ASSERT(SSFBNCmpUint32(&a, 0xFFFFFFFEul) == 1);
    }

    /* ---- SSFBNSetBit / SSFBNClearBit: single-bit mutation ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        uint32_t pos;

        /* SetBit at 0 on zero turns the value into 1. */
        SSFBNSetZero(&a, 4);
        SSFBNSetBit(&a, 0u);
        SSF_ASSERT(SSFBNIsOne(&a) == true);

        /* ClearBit at 0 on 1 turns it back to zero. */
        SSFBNClearBit(&a, 0u);
        SSF_ASSERT(SSFBNIsZero(&a) == true);

        /* Set a selection of bits spanning limb boundaries and verify via GetBit. */
        SSFBNSetZero(&a, 4);
        {
            static const uint32_t targets[] = { 0u, 1u, 31u, 32u, 47u, 63u, 64u, 96u, 127u };
            uint32_t k;

            for (k = 0; k < (sizeof(targets) / sizeof(targets[0])); k++)
            {
                SSFBNSetBit(&a, targets[k]);
            }
            for (pos = 0; pos < 128u; pos++)
            {
                uint8_t expected = 0u;
                for (k = 0; k < (sizeof(targets) / sizeof(targets[0])); k++)
                {
                    if (targets[k] == pos) { expected = 1u; break; }
                }
                SSF_ASSERT(SSFBNGetBit(&a, pos) == expected);
            }

            /* Clearing every target restores zero. */
            for (k = 0; k < (sizeof(targets) / sizeof(targets[0])); k++)
            {
                SSFBNClearBit(&a, targets[k]);
            }
            SSF_ASSERT(SSFBNIsZero(&a) == true);
        }

        /* SetBit on an already-set bit is a no-op. */
        SSFBNSetZero(&a, 4);
        SSFBNSetBit(&a, 20u);
        SSF_ASSERT(a.limbs[0] == (1ul << 20));
        SSFBNSetBit(&a, 20u);
        SSF_ASSERT(a.limbs[0] == (1ul << 20));

        /* ClearBit on an already-clear bit is a no-op. */
        SSFBNClearBit(&a, 5u);
        SSF_ASSERT(a.limbs[0] == (1ul << 20));

        /* Setting the top bit of a non-empty value doesn't clobber other bits. */
        SSFBNSetUint32(&a, 0x12345678ul, 4);
        SSFBNSetBit(&a, 127u);
        SSF_ASSERT(a.limbs[0] == 0x12345678ul);
        SSF_ASSERT(a.limbs[3] == 0x80000000ul);
    }

    /* ---- SSFBNTrailingZeros: count low-order zero bits ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        /* a = 1 → tz = 0 */
        SSFBNSetUint32(&a, 1u, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 0u);

        /* a = 2 → tz = 1 */
        SSFBNSetUint32(&a, 2u, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 1u);

        /* a = 0x80000000 (bit 31) → tz = 31 (top of limb 0) */
        SSFBNSetUint32(&a, 0x80000000ul, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 31u);

        /* a = 2^32 (bit 32, start of limb 1) → tz = 32 */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 1u;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 32u);

        /* a = 2^47 (mid-limb 1) → tz = 47 */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 0x00008000ul;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 47u);

        /* a = 2^96 (start of limb 3) → tz = 96 */
        SSFBNSetZero(&a, 4);
        a.limbs[3] = 1u;
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 96u);

        /* Mixed value: low limb zero, limb[1] has a low set bit and other high bits — must      */
        /* return the position of the lowest set bit only.                                       */
        SSFBNSetZero(&a, 4);
        a.limbs[1] = 0xFF00FF10ul; /* lowest set bit is bit 4 of limb 1 → global bit 36 */
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 36u);

        /* After a left shift by k, tz grows by k. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 0u); /* 0xDEADBEEF has bit 0 set */
        SSFBNShiftLeft(&a, 17u);
        SSF_ASSERT(SSFBNTrailingZeros(&a) == 17u);
    }

    /* ---- ModAdd / ModSub with small modulus ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* (5 + 6) mod 7 = 4 */
        SSFBNSetUint32(&a, 5u, 4);
        SSFBNSetUint32(&b, 6u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModAdd(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 4u);

        /* (2 - 5) mod 7 = 4 */
        SSFBNSetUint32(&a, 2u, 4);
        SSFBNSetUint32(&b, 5u, 4);
        SSFBNModSub(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModMul with small modulus ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* (5 * 6) mod 7 = 30 mod 7 = 2 */
        SSFBNSetUint32(&a, 5u, 4);
        SSFBNSetUint32(&b, 6u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModMul(&r, &a, &b, &m);
        SSF_ASSERT(r.limbs[0] == 2u);
    }

    /* ---- ModExp: 3^10 mod 7 = 59049 mod 7 = 4 ---- */
    {
        SSFBN_DEFINE(base, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(exp, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&base, 3u, 4);
        SSFBNSetUint32(&exp, 10u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSFBNModExp(&r, &base, &exp, &m);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModInv: 2^(-1) mod 7 = 4 (since 2*4 = 8 = 1 mod 7) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 2u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == true);
        SSF_ASSERT(r.limbs[0] == 4u);
    }

    /* ---- ModInv: 0 has no inverse ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(m, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 0u, 4);
        SSFBNSetUint32(&m, 7u, 4);
        SSF_ASSERT(SSFBNModInv(&r, &a, &m) == false);
    }

    /* ---- CondSwap ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 10u, 4);
        SSFBNSetUint32(&b, 20u, 4);
        SSFBNCondSwap(&a, &b, 0u);
        SSF_ASSERT(a.limbs[0] == 10u);
        SSF_ASSERT(b.limbs[0] == 20u);
        SSFBNCondSwap(&a, &b, 1u);
        SSF_ASSERT(a.limbs[0] == 20u);
        SSF_ASSERT(b.limbs[0] == 10u);
    }

    /* ---- Zeroize ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBNSetUint32(&a, 0xDEADBEEFu, 4);
        SSFBNZeroize(&a);
        SSF_ASSERT(a.limbs[0] == 0u);
        SSF_ASSERT(a.len == 0);
    }

    /* ---- SSFSecureZero ---- */
    {
        uint8_t buf[37];
        size_t i;

        for (i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)(i + 1u);
        SSFSecureZero(buf, sizeof(buf));
        for (i = 0; i < sizeof(buf); i++) SSF_ASSERT(buf[i] == 0u);

        /* n == 0 must be a no-op (loop body never executes). */
        buf[0] = 0xA5u;
        SSFSecureZero(buf, 0);
        SSF_ASSERT(buf[0] == 0xA5u);

        /* p == NULL must trip SSF_REQUIRE. */
        SSF_ASSERT_TEST(SSFSecureZero(NULL, 1));
    }

    /* ---- NIST P-256: verify p is consistent with SSF_BN_NIST_P256 ---- */
    {
        SSF_ASSERT(SSFBNCmp(&SSF_BN_NIST_P256, &SSF_BN_NIST_P256) == 0);
        SSF_ASSERT(SSFBNIsZero(&SSF_BN_NIST_P256) == false);
        SSF_ASSERT(SSFBNBitLen(&SSF_BN_NIST_P256) == 256u);
    }

    /* ---- ModMulNIST: a * 1 mod p = a ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 42u, 8);
        SSFBNSetUint32(&one, 1u, 8);
        SSFBNModMulNIST(&r, &a, &one, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNCmp(&r, &a) == 0);
    }

    /* ---- ModMulNIST: a * 0 mod p = 0 ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(zero, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 42u, 8);
        SSFBNSetZero(&zero, 8);
        SSFBNModMulNIST(&r, &a, &zero, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsZero(&r) == true);
    }

    /* ---- Montgomery: roundtrip convert in/out ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aBack, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);

        SSFBNSetUint32(&a, 12345u, 8);
        SSFBNMontInit(&mont, &SSF_BN_NIST_P256);
        SSFBNMontConvertIn(&aM, &a, &mont);
        SSFBNMontConvertOut(&aBack, &aM, &mont);
        SSF_ASSERT(SSFBNCmp(&a, &aBack) == 0);
    }

    /* ====================================================================================== */
    /* Primality-related API (hoisted from ssfrsa)                                              */
    /* ====================================================================================== */

    /* ---- SSFBNModUint32: basic reductions ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);

        /* 123456789 mod 7 = 1 */
        SSFBNSetUint32(&a, 123456789u, 4);
        SSF_ASSERT(SSFBNModUint32(&a, 7u) == 1u);

        /* A large BN: (2^64) mod 3 == 1 since 2^64 = 4 * 2^62, and 2 mod 3 == 2, 4 mod 3 == 1  */
        /* Build 2^64 via FromBytes: big-endian 0x00..01 0x00..00. */
        {
            static const uint8_t data[9] = { 0x01u, 0,0,0,0, 0,0,0,0 };
            SSFBNFromBytes(&a, data, sizeof(data), 4);
            SSF_ASSERT(SSFBNModUint32(&a, 3u) == 1u);
        }

        /* Zero mod anything == 0. */
        SSFBNSetZero(&a, 4);
        SSF_ASSERT(SSFBNModUint32(&a, 17u) == 0u);

        /* Dividing by the value itself gives 0. */
        SSFBNSetUint32(&a, 42u, 4);
        SSF_ASSERT(SSFBNModUint32(&a, 42u) == 0u);
    }

    /* ---- SSFBNRandom: populates without corrupting beyond numLimbs ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;
        bool sawNonZero = false;

        /* Deterministic seed so the test is reproducible. */
        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)i;
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        /* Fill 4 limbs of a that has capacity SSF_BN_MAX_LIMBS. */
        SSFBNSetZero(&a, SSF_BN_MAX_LIMBS);
        SSFBNRandom(&a, 4u, &prng);
        SSF_ASSERT(a.len == 4u);

        /* At least one limb should be non-zero (vanishingly unlikely to be all zero). */
        for (i = 0; i < 4u; i++)
        {
            if (a.limbs[i] != 0u) { sawNonZero = true; break; }
        }
        SSF_ASSERT(sawNonZero);

        /* Limbs past numLimbs must not have been touched. */
        for (i = 4u; i < SSF_BN_MAX_LIMBS; i++)
        {
            SSF_ASSERT(a.limbs[i] == 0u);
        }

        SSFPRNGDeInitContext(&prng);
    }

    /* ---- SSFBNRandomBelow: uniform draw in [0, bound) ---- */
    {
        SSFBN_DEFINE(bound, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x71u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        /* Small bound: 100 draws all land in [0, 1000). */
        SSFBNSetUint32(&bound, 1000u, 4);
        for (i = 0; i < 100u; i++)
        {
            SSF_ASSERT(SSFBNRandomBelow(&r, &bound, &prng) == true);
            SSF_ASSERT(SSFBNCmp(&r, &bound) < 0);
        }

        /* Large bound (P-256 prime): draws are well-distributed and always < bound. */
        for (i = 0; i < 16u; i++)
        {
            SSF_ASSERT(SSFBNRandomBelow(&r, &SSF_BN_NIST_P256, &prng) == true);
            SSF_ASSERT(SSFBNCmp(&r, &SSF_BN_NIST_P256) < 0);
        }

        /* Bound = 1: the only valid draw is 0. */
        SSFBNSetOne(&bound, 4);
        SSF_ASSERT(SSFBNRandomBelow(&r, &bound, &prng) == true);
        SSF_ASSERT(SSFBNIsZero(&r) == true);

        /* Bound = 2: draws are 0 or 1. Check we see both in a few hundred draws. */
        {
            SSFBNSetUint32(&bound, 2u, 4);
            bool sawZero = false;
            bool sawOne = false;
            for (i = 0; i < 200u; i++)
            {
                SSF_ASSERT(SSFBNRandomBelow(&r, &bound, &prng) == true);
                SSF_ASSERT(SSFBNCmp(&r, &bound) < 0);
                if (SSFBNIsZero(&r)) sawZero = true;
                else sawOne = true;
            }
            SSF_ASSERT(sawZero);
            SSF_ASSERT(sawOne);
        }

        SSFPRNGDeInitContext(&prng);
    }

    /* ---- SSFBNIsProbablePrime: known prime accepted, composite rejected ---- */
    {
        SSFBN_DEFINE(n, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0xA5u ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        /* 2^31 - 1 = 2147483647 is a Mersenne prime. */
        SSFBNSetUint32(&n, 2147483647u, 4);
        SSF_ASSERT(SSFBNIsProbablePrime(&n, 5u, &prng) == true);

        /* 2^31 - 3 = 2147483645 = 5 * 429496729, composite. */
        SSFBNSetUint32(&n, 2147483645u, 4);
        SSF_ASSERT(SSFBNIsProbablePrime(&n, 5u, &prng) == false);

        /* 91 = 7 * 13 — small composite that fools Fermat base-3 test but not MR. */
        SSFBNSetUint32(&n, 91u, 4);
        SSF_ASSERT(SSFBNIsProbablePrime(&n, 5u, &prng) == false);

        SSFPRNGDeInitContext(&prng);
    }

    /* ====================================================================================== */
    /* Squaring API — must agree bit-for-bit with the general multiply on every input.          */
    /* ====================================================================================== */

    /* ---- SSFBNSquare: parity with SSFBNMul(a, a) across small, mid, and large operands ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(sq, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(mul, SSF_BN_MAX_LIMBS);
        uint16_t k;

        /* 0^2 = 0 */
        SSFBNSetZero(&a, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(SSFBNIsZero(&sq) == true);
        SSF_ASSERT(sq.len == 8u);

        /* 1^2 = 1 */
        SSFBNSetUint32(&a, 1u, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(sq.limbs[0] == 1u);
        SSF_ASSERT(sq.limbs[1] == 0u);
        SSF_ASSERT(sq.limbs[2] == 0u);

        /* 7^2 = 49 */
        SSFBNSetUint32(&a, 7u, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(sq.limbs[0] == 49u);

        /* 65536^2 = 2^32 (crosses limb boundary) */
        SSFBNSetUint32(&a, 65536u, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(sq.limbs[0] == 0u);
        SSF_ASSERT(sq.limbs[1] == 1u);

        /* 0xFFFFFFFF^2 = 0xFFFFFFFE00000001 (largest single limb) */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNSquare(&sq, &a);
        SSF_ASSERT(sq.limbs[0] == 0x00000001ul);
        SSF_ASSERT(sq.limbs[1] == 0xFFFFFFFEul);

        /* Parity against generic multiply for a range of multi-limb values. Build a from a      */
        /* pseudo-random byte sequence; the test is deterministic (no PRNG dependency).          */
        for (k = 1; k <= 8u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x5Au + (uint8_t)i * (uint8_t)k);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNSquare(&sq, &a);
            SSFBNMul(&mul, &a, &a);
            SSF_ASSERT(sq.len == mul.len);
            SSF_ASSERT(memcmp(sq.limbs, mul.limbs, (size_t)sq.len * sizeof(SSFBNLimb_t)) == 0);
        }
    }

    /* ---- SSFBNModSquare: parity with SSFBNModMul(a, a, m) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(modSq, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(modMul, SSF_BN_MAX_LIMBS);
        uint16_t k;

        for (k = 1; k <= 4u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0xA5u + (uint8_t)i * (uint8_t)k);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            /* Ensure a < p256 so the modular contract holds. */
            SSFBNMod(&a, &a, &SSF_BN_NIST_P256);

            SSFBNModSquare(&modSq, &a, &SSF_BN_NIST_P256);
            SSFBNModMul(&modMul, &a, &a, &SSF_BN_NIST_P256);
            SSF_ASSERT(SSFBNCmp(&modSq, &modMul) == 0);
        }

        /* ModSquare supports aliasing r == a. */
        SSFBNSetUint32(&a, 12345u, 8);
        SSFBNMod(&a, &a, &SSF_BN_NIST_P256);
        SSFBNModMul(&modMul, &a, &a, &SSF_BN_NIST_P256);
        SSFBNModSquare(&a, &a, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNCmp(&a, &modMul) == 0);
    }

    /* ---- SSFBNMontSquare: parity with SSFBNMontMul(a, a, ctx) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(sqM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(mulM, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
        uint16_t k;

        SSFBNMontInit(&mont, &SSF_BN_NIST_P256);

        for (k = 1; k <= 4u; k++)
        {
            SSFBNSetUint32(&a, 1000u * (uint32_t)k + (uint32_t)k, 8);
            SSFBNMontConvertIn(&aM, &a, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontMul(&mulM, &aM, &aM, &mont);
            SSF_ASSERT(SSFBNCmp(&sqM, &mulM) == 0);
        }

        /* MontSquare supports aliasing r == a. */
        SSFBNSetUint32(&a, 7777u, 8);
        SSFBNMontConvertIn(&aM, &a, &mont);
        SSFBNMontMul(&mulM, &aM, &aM, &mont);
        SSFBNMontSquare(&aM, &aM, &mont);
        SSF_ASSERT(SSFBNCmp(&aM, &mulM) == 0);

        /* Boundary: 0 in Montgomery form squared is 0. */
        SSFBNSetZero(&a, 8);
        SSFBNMontConvertIn(&aM, &a, &mont);
        SSFBNMontSquare(&sqM, &aM, &mont);
        SSF_ASSERT(SSFBNIsZero(&sqM) == true);

        /* Boundary: (p-1)^2 mod p = 1. Test through MontSquare + ConvertOut. */
        {
            SSFBN_DEFINE(pm1, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(one, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(result, SSF_BN_MAX_LIMBS);

            SSFBNSetUint32(&one, 1u, 8);
            SSFBNSub(&pm1, &SSF_BN_NIST_P256, &one);  /* pm1 = p - 1 */
            SSFBNMontConvertIn(&aM, &pm1, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontConvertOut(&result, &sqM, &mont);
            SSF_ASSERT(SSFBNIsOne(&result) == true);
        }

        /* Full sweep: 16 random-ish values, verify MontSquare == MontMul(a, a) bit-for-bit. */
        for (k = 0; k < 16u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x3Cu + (uint8_t)i * 7u + (uint8_t)k * 11u);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNMod(&a, &a, &SSF_BN_NIST_P256);
            SSFBNMontConvertIn(&aM, &a, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontMul(&mulM, &aM, &aM, &mont);
            SSF_ASSERT(SSFBNCmp(&sqM, &mulM) == 0);
        }
    }

    /* ====================================================================================== */
    /* Uint32 small-operand arithmetic — parity with matched 1-limb BN operand                  */
    /* ====================================================================================== */

    /* ---- SSFBNAddUint32: parity + carry return ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aCopy, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rSum, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rRef, SSF_BN_MAX_LIMBS);
        SSFBNLimb_t carrySum;
        SSFBNLimb_t carryRef;

        /* Simple: 100 + 25 == 125 */
        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 25u, 4);
        carryRef = SSFBNAdd(&rRef, &a, &b);
        carrySum = SSFBNAddUint32(&rSum, &a, 25u);
        SSF_ASSERT(carrySum == carryRef);
        SSF_ASSERT(SSFBNCmp(&rSum, &rRef) == 0);

        /* Carry propagates across limbs: 0xFFFFFFFF + 1 = 0x100000000 */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNAddUint32(&rSum, &a, 1u);
        SSF_ASSERT(rSum.limbs[0] == 0u);
        SSF_ASSERT(rSum.limbs[1] == 1u);

        /* Top-limb carry-out returned. */
        SSFBNSetZero(&a, 2);
        a.limbs[0] = 0xFFFFFFFFul;
        a.limbs[1] = 0xFFFFFFFFul;
        carrySum = SSFBNAddUint32(&rSum, &a, 1u);
        SSF_ASSERT(carrySum == 1u);
        SSF_ASSERT(rSum.limbs[0] == 0u);
        SSF_ASSERT(rSum.limbs[1] == 0u);

        /* Aliasing r == a works in place. */
        SSFBNSetUint32(&aCopy, 0x123456u, 4);
        SSFBNAddUint32(&aCopy, &aCopy, 0xFFFFu);
        SSF_ASSERT(aCopy.limbs[0] == 0x133455ul);

        /* Adding zero is a copy. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        carrySum = SSFBNAddUint32(&rSum, &a, 0u);
        SSF_ASSERT(carrySum == 0u);
        SSF_ASSERT(SSFBNCmp(&rSum, &a) == 0);
    }

    /* ---- SSFBNSubUint32: parity + borrow return ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aCopy, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rSub, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rRef, SSF_BN_MAX_LIMBS);
        SSFBNLimb_t borrowSub;
        SSFBNLimb_t borrowRef;

        /* 100 - 25 == 75 */
        SSFBNSetUint32(&a, 100u, 4);
        SSFBNSetUint32(&b, 25u, 4);
        borrowRef = SSFBNSub(&rRef, &a, &b);
        borrowSub = SSFBNSubUint32(&rSub, &a, 25u);
        SSF_ASSERT(borrowSub == borrowRef);
        SSF_ASSERT(SSFBNCmp(&rSub, &rRef) == 0);

        /* Borrow crosses limb boundary: 0x100000000 - 1 = 0xFFFFFFFF. */
        SSFBNSetZero(&a, 2);
        a.limbs[1] = 1u;
        SSFBNSubUint32(&rSub, &a, 1u);
        SSF_ASSERT(rSub.limbs[0] == 0xFFFFFFFFul);
        SSF_ASSERT(rSub.limbs[1] == 0u);

        /* Underflow returns borrow=1, result is two's-complement. */
        SSFBNSetZero(&a, 2);
        borrowSub = SSFBNSubUint32(&rSub, &a, 5u);
        SSF_ASSERT(borrowSub == 1u);
        SSF_ASSERT(rSub.limbs[0] == 0xFFFFFFFBul);
        SSF_ASSERT(rSub.limbs[1] == 0xFFFFFFFFul);

        /* Aliasing r == a. */
        SSFBNSetUint32(&aCopy, 0x12345678ul, 4);
        SSFBNSubUint32(&aCopy, &aCopy, 0x12340000ul);
        SSF_ASSERT(aCopy.limbs[0] == 0x5678u);
    }

    /* ---- SSFBNMulUint32: parity with full-width Mul against a 1-limb BN ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rProd, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rRef, SSF_BN_MAX_LIMBS);

        /* 7 * 6 = 42 */
        SSFBNSetUint32(&a, 7u, 4);
        SSFBNSetUint32(&b, 6u, 1);
        SSFBNMul(&rRef, &a, &b);
        SSFBNMulUint32(&rProd, &a, 6u);
        SSF_ASSERT(rProd.len == 5u);
        SSF_ASSERT(rProd.limbs[0] == 42u);

        /* Across limb boundary: 0xFFFFFFFF * 2 = 0x1_FFFFFFFE */
        SSFBNSetUint32(&a, 0xFFFFFFFFul, 4);
        SSFBNMulUint32(&rProd, &a, 2u);
        SSF_ASSERT(rProd.limbs[0] == 0xFFFFFFFEul);
        SSF_ASSERT(rProd.limbs[1] == 1u);

        /* Parity sweep against SSFBNMul(a, b-as-BN) for multi-limb a, small b. */
        {
            static const uint8_t data[8] = { 0x01u, 0x23u, 0x45u, 0x67u,
                                             0x89u, 0xABu, 0xCDu, 0xEFu };
            uint32_t k;
            SSFBNFromBytes(&a, data, sizeof(data), 4);
            for (k = 1u; k <= 100u; k += 7u)
            {
                SSFBNSetUint32(&b, k, 1);
                SSFBNMul(&rRef, &a, &b);
                SSFBNMulUint32(&rProd, &a, k);
                /* rRef is 5 limbs (4 + 1); rProd is also 5 limbs. */
                SSF_ASSERT(rProd.len == rRef.len);
                SSF_ASSERT(memcmp(rProd.limbs, rRef.limbs,
                                  (size_t)rProd.len * sizeof(SSFBNLimb_t)) == 0);
            }
        }

        /* Multiplying by zero yields zero. */
        SSFBNSetUint32(&a, 0xDEADBEEFul, 4);
        SSFBNMulUint32(&rProd, &a, 0u);
        SSF_ASSERT(SSFBNIsZero(&rProd) == true);
    }

    /* ====================================================================================== */
    /* Variable-time ModExp (public-exponent-only) — must match constant-time ModExp exactly    */
    /* ====================================================================================== */

    /* ---- SSFBNModExpPub: parity with SSFBNModExp across typical RSA public exponents ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rCT, SSF_BN_MAX_LIMBS); /* constant-time reference */
        SSFBN_DEFINE(rVT, SSF_BN_MAX_LIMBS); /* variable-time candidate */
        static const uint32_t pubExponents[] = { 0u, 1u, 2u, 3u, 17u, 65537u, 0xFFFFFFFFul };
        uint16_t k;

        /* Use P-256 as a convenient prime modulus for the parity sweep. */
        SSFBNSetUint32(&a, 12345u, 8);

        for (k = 0; k < (uint16_t)(sizeof(pubExponents) / sizeof(pubExponents[0])); k++)
        {
            SSFBNSetUint32(&e, pubExponents[k], 8);
            SSFBNModExp(&rCT, &a, &e, &SSF_BN_NIST_P256);
            SSFBNModExpPub(&rVT, &a, &e, &SSF_BN_NIST_P256);
            SSF_ASSERT(SSFBNCmp(&rCT, &rVT) == 0);
        }
    }

    /* ---- SSFBNModExpPub: parity across random bases for e = 65537 ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rCT, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rVT, SSF_BN_MAX_LIMBS);
        uint16_t k;

        SSFBNSetUint32(&e, 65537u, 8);

        for (k = 0; k < 8u; k++)
        {
            uint8_t data[32];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x2Bu + (uint8_t)i * 11u + (uint8_t)k * 19u);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 8);
            SSFBNMod(&a, &a, &SSF_BN_NIST_P256);

            SSFBNModExp(&rCT, &a, &e, &SSF_BN_NIST_P256);
            SSFBNModExpPub(&rVT, &a, &e, &SSF_BN_NIST_P256);
            SSF_ASSERT(SSFBNCmp(&rCT, &rVT) == 0);
        }
    }

    /* ---- SSFBNModExpPub: edge cases ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);

        /* a^0 = 1 for any a. */
        SSFBNSetUint32(&a, 42u, 8);
        SSFBNSetUint32(&e, 0u, 8);
        SSFBNModExpPub(&r, &a, &e, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsOne(&r) == true);

        /* 0^e = 0 for e >= 1. */
        SSFBNSetZero(&a, 8);
        SSFBNSetUint32(&e, 7u, 8);
        SSFBNModExpPub(&r, &a, &e, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsZero(&r) == true);

        /* 1^e = 1. */
        SSFBNSetUint32(&a, 1u, 8);
        SSFBNSetUint32(&e, 0x12345678ul, 8);
        SSFBNModExpPub(&r, &a, &e, &SSF_BN_NIST_P256);
        SSF_ASSERT(SSFBNIsOne(&r) == true);
    }

    /* ---- SSFBNModExpMontPub: parity with SSFBNModExpMont (precomputed ctx path) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(e, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rCT, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(rVT, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(ctx, SSF_BN_MAX_LIMBS);

        SSFBNMontInit(&ctx, &SSF_BN_NIST_P256);
        SSFBNSetUint32(&a, 99999u, 8);
        SSFBNSetUint32(&e, 65537u, 8);

        SSFBNModExpMont(&rCT, &a, &e, &ctx);
        SSFBNModExpMontPub(&rVT, &a, &e, &ctx);
        SSF_ASSERT(SSFBNCmp(&rCT, &rVT) == 0);
    }

    /* ---- SSFBNMontSquare on P-384 (larger modulus exercises more carry propagation) ---- */
    {
        SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(aM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(sqM, SSF_BN_MAX_LIMBS);
        SSFBN_DEFINE(mulM, SSF_BN_MAX_LIMBS);
        SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
        uint16_t k;

        SSFBNMontInit(&mont, &SSF_BN_NIST_P384);

        for (k = 0; k < 8u; k++)
        {
            uint8_t data[48];
            uint16_t i;

            for (i = 0; i < sizeof(data); i++)
            {
                data[i] = (uint8_t)(0x71u + (uint8_t)i * 13u + (uint8_t)k * 17u);
            }
            SSFBNFromBytes(&a, data, sizeof(data), 12);
            SSFBNMod(&a, &a, &SSF_BN_NIST_P384);
            SSFBNMontConvertIn(&aM, &a, &mont);
            SSFBNMontSquare(&sqM, &aM, &mont);
            SSFBNMontMul(&mulM, &aM, &aM, &mont);
            SSF_ASSERT(SSFBNCmp(&sqM, &mulM) == 0);
        }
    }

    /* ---- SSFBNGenPrime: produces a prime of the requested size ---- */
    {
        SSFBN_DEFINE(p, SSF_BN_MAX_LIMBS);
        SSFPRNGContext_t prng;
        uint8_t seed[SSF_PRNG_ENTROPY_SIZE];
        uint16_t i;

        for (i = 0; i < sizeof(seed); i++) seed[i] = (uint8_t)(0x5Au ^ i);
        SSFPRNGInitContext(&prng, seed, sizeof(seed));

        /* Small bit size keeps the test fast but still exercises the loop. */
        SSF_ASSERT(SSFBNGenPrime(&p, 64u, 5u, &prng) == true);
        SSF_ASSERT(SSFBNBitLen(&p) == 64u); /* Top two bits forced set → bit length exact. */
        SSF_ASSERT(SSFBNIsProbablePrime(&p, 5u, &prng) == true);

        SSFPRNGDeInitContext(&prng);
    }

#if SSF_CONFIG_BN_MICROBENCH == 1
    /* ====================================================================================== */
    /* Microbenchmark — MontMul / MontSquare (CIOS-based) and raw Mul / Square (schoolbook /    */
    /* triangular) throughput at representative operand sizes. Gated by SSF_CONFIG_BN_MICROBENCH*/
    /* so the normal test run stays quick; flip the macro in ssfport.h to 1 before measuring    */
    /* perf changes, then back to 0 after.                                                      */
    /*                                                                                          */
    /* Raw Mul/Square require 2*nLimbs <= SSF_BN_MAX_LIMBS, so n=128 is skipped for those.      */
    /* ====================================================================================== */
    {
        struct { uint16_t nLimbs; uint32_t mIters; uint32_t mulIters; const char *label; } bench[] = {
            {   8u, 4000000u, 20000000u, "P-256 (n= 8, RSA-256-eq) " },
            {  32u,  400000u,  5000000u, "RSA-1024     (n=32)      " },
            {  64u,  100000u,  1500000u, "RSA-2048     (n=64)      " },
            { 128u,   30000u,        0u, "RSA-4096     (n=128)     " },
        };
        uint16_t bi;

        printf("\n--- ssfbn microbenchmark (ms for iter count shown) ---\n");
        for (bi = 0; bi < (uint16_t)(sizeof(bench) / sizeof(bench[0])); bi++)
        {
            uint16_t n = bench[bi].nLimbs;
            uint32_t mIters = bench[bi].mIters;
            uint32_t mulIters = bench[bi].mulIters;
            uint32_t i;

            /* Build a Mont context with an odd, prime-ish modulus (use P-256 / P-384 constants  */
            /* where they fit; else synthesize an odd modulus with the high bit set and low bit  */
            /* set so MontInit accepts it).                                                      */
            SSFBN_DEFINE(mod, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(a, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(b, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(r, SSF_BN_MAX_LIMBS);
            SSFBN_DEFINE(rWide, SSF_BN_MAX_LIMBS); /* Width for raw Mul/Square (2n limbs). */
            SSFBNMONT_DEFINE(mont, SSF_BN_MAX_LIMBS);
            SSFPortTick_t t0, t1;

            if (n == 8u)
            {
                SSFBNCopy(&mod, &SSF_BN_NIST_P256);
            }
            else
            {
                SSFBNSetZero(&mod, n);
                for (i = 0; i < n; i++) mod.limbs[i] = 0xFFFFFFFFul;
                mod.limbs[0] ^= 0x58ul;              /* random-ish low bits, still odd */
                mod.limbs[n - 1u] = 0xFFFFFF00ul | 1u;
            }

            /* Fill every limb with pseudo-random non-zero data so SSFBNMul's `if (a[i]==0)` */
            /* shortcut does not artificially speed the baseline. Use a cheap LCG-style seed   */
            /* keyed on the limb index.                                                        */
            SSFBNSetZero(&a, n);
            SSFBNSetZero(&b, n);
            for (i = 0; i < n; i++)
            {
                a.limbs[i] = 0xA5A5A5A5ul ^ (i * 0x9E3779B9ul);
                b.limbs[i] = 0x5A5A5A5Aul ^ (i * 0x7F4A7C15ul);
            }
            a.len = n;
            b.len = n;
            SSFBNMod(&a, &a, &mod);
            SSFBNMod(&b, &b, &mod);

            SSFBNMontInit(&mont, &mod);

            /* --- Raw SSFBNMul / SSFBNSquare (non-Mont) at 2n-limb output. --- */
            if (mulIters > 0u)
            {
                t0 = SSFPortGetTick64();
                for (i = 0; i < mulIters; i++)
                {
                    SSFBNMul(&rWide, &a, &b);
                }
                t1 = SSFPortGetTick64();
                printf("  Mul        %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)mulIters,
                       (unsigned long long)(t1 - t0));

                t0 = SSFPortGetTick64();
                for (i = 0; i < mulIters; i++)
                {
                    SSFBNSquare(&rWide, &a);
                }
                t1 = SSFPortGetTick64();
                printf("  Square     %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)mulIters,
                       (unsigned long long)(t1 - t0));
            }

            /* --- ModExpMont (constant-time, dense full-Hamming exponent — worst case for the    */
            /* binary ladder) and ModExpMontPub (variable-time, e = 65537 = F4, the realistic     */
            /* RSA verify exponent). a is still in plain (non-Mont) form here.                    */
            {
                SSFBN_DEFINE(expPriv, SSF_BN_MAX_LIMBS);
                SSFBN_DEFINE(expPub, SSF_BN_MAX_LIMBS);
                SSFBN_DEFINE(rE, SSF_BN_MAX_LIMBS);
                uint32_t expIters = 0u;
                uint32_t expPubIters = 0u;

                /* Dense pseudo-random private-style exponent: full bit-width, both ends set. */
                SSFBNSetZero(&expPriv, n);
                for (i = 0; i < n; i++)
                {
                    expPriv.limbs[i] = 0xC9F1A8B7ul ^ (i * 0x517CC1B7ul);
                }
                expPriv.limbs[n - 1u] |= 0x80000000ul;   /* force full bit-length */
                expPriv.limbs[0] |= 1u;                  /* force odd */
                expPriv.len = n;

                /* Public exponent F4 = 65537. */
                SSFBNSetUint32(&expPub, 65537u, 1u);

                /* Iter counts tuned for ~0.5–2 s per measurement (Mont ladder is ~2*eBits ops). */
                if (n == 8u)        { expIters = 20000u;  expPubIters = 500000u; }
                else if (n == 32u)  { expIters = 400u;    expPubIters = 40000u;  }
                else if (n == 64u)  { expIters = 50u;     expPubIters = 10000u;  }
                else                { expIters = 10u;     expPubIters = 2000u;   }

                t0 = SSFPortGetTick64();
                for (i = 0; i < expIters; i++)
                {
                    SSFBNModExpMont(&rE, &a, &expPriv, &mont);
                }
                t1 = SSFPortGetTick64();
                printf("  ModExpMont %s %u iter: %llu ms\n",
                       bench[bi].label, (unsigned)expIters,
                       (unsigned long long)(t1 - t0));

                t0 = SSFPortGetTick64();
                for (i = 0; i < expPubIters; i++)
                {
                    SSFBNModExpMontPub(&rE, &a, &expPub, &mont);
                }
                t1 = SSFPortGetTick64();
                printf("  ModExpPub  %s %u iter: %llu ms (e=F4)\n",
                       bench[bi].label, (unsigned)expPubIters,
                       (unsigned long long)(t1 - t0));
            }

            /* --- Mont-form MontMul / MontSquare (CIOS / SOS). --- */
            SSFBNMontConvertIn(&a, &a, &mont);
            SSFBNMontConvertIn(&b, &b, &mont);

            t0 = SSFPortGetTick64();
            for (i = 0; i < mIters; i++)
            {
                SSFBNMontMul(&r, &a, &b, &mont);
            }
            t1 = SSFPortGetTick64();
            printf("  MontMul    %s %u iter: %llu ms\n",
                   bench[bi].label, (unsigned)mIters,
                   (unsigned long long)(t1 - t0));

            t0 = SSFPortGetTick64();
            for (i = 0; i < mIters; i++)
            {
                SSFBNMontSquare(&r, &a, &mont);
            }
            t1 = SSFPortGetTick64();
            printf("  MontSquare %s %u iter: %llu ms\n",
                   bench[bi].label, (unsigned)mIters,
                   (unsigned long long)(t1 - t0));
        }
        printf("--- end microbenchmark ---\n");
    }
#endif /* SSF_CONFIG_BN_MICROBENCH */
}
#endif /* SSF_CONFIG_BN_UNIT_TEST */
