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
}
#endif /* SSF_CONFIG_BN_UNIT_TEST */
